package sshutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// testPubKey returns a valid ed25519 public key in authorized_keys format,
// with a trailing comment.
func testPubKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	assert.NoError(t, err)
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(sshPub)), "\n") + " user@host"
}

func TestGenerateKnownHosts(t *testing.T) {
	line, err := GenerateKnownHosts("example.com", "22", testPubKey(t))
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, "@cert-authority example.com ssh-ed25519 "))
	// The trailing comment must be stripped and only one line produced.
	assert.NotContains(t, line, "user@host")
	assert.NotContains(t, line, "\n")
}

func TestGenerateKnownHostsNonStandardPort(t *testing.T) {
	line, err := GenerateKnownHosts("example.com", "2222", testPubKey(t))
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, "@cert-authority [example.com]:2222 "))
}

func TestGenerateKnownHostsRejectsInjection(t *testing.T) {
	// A CA must not be able to inject extra known_hosts lines (e.g. a global
	// "@cert-authority *") through a newline in the returned key.
	key := testPubKey(t)
	malicious := key + "\n@cert-authority * " + key

	line, err := GenerateKnownHosts("example.com", "22", malicious)
	assert.NoError(t, err)
	assert.NotContains(t, line, "@cert-authority *")
	assert.NotContains(t, line, "\n")
}

func TestGenerateKnownHostsRejectsBadKey(t *testing.T) {
	_, err := GenerateKnownHosts("example.com", "22", "not-a-real-key")
	assert.Error(t, err)
}

func TestGenerateKnownHostsRejectsBadHost(t *testing.T) {
	_, err := GenerateKnownHosts("example.com ssh-ed25519 AAAA evil", "22", testPubKey(t))
	assert.Error(t, err)
}

func TestCertificateValidAt(t *testing.T) {
	cert := &ssh.Certificate{ValidAfter: 100, ValidBefore: 200}

	assert.False(t, CertificateValidAt(nil, time.Unix(150, 0)))
	assert.False(t, CertificateValidAt(cert, time.Unix(99, 0)))
	assert.True(t, CertificateValidAt(cert, time.Unix(100, 0)))
	assert.True(t, CertificateValidAt(cert, time.Unix(199, 0)))
	assert.False(t, CertificateValidAt(cert, time.Unix(200, 0)))
}

// keyringAgent adapts the in-memory keyring to the ExtendedAgent interface.
type keyringAgent struct {
	agent.Agent
}

func (keyringAgent) SignWithFlags(ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, error) {
	return nil, errors.New("not implemented")
}

func (keyringAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func addTestCertificate(t *testing.T, keyring agent.Agent, validAfter, validBefore uint64) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	assert.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	assert.NoError(t, err)

	cert := &ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: []string{PRINCIPAL},
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
	}
	assert.NoError(t, cert.SignCert(rand.Reader, signer))
	assert.NoError(t, keyring.Add(agent.AddedKey{
		PrivateKey:  priv,
		Certificate: cert,
		Comment:     AgentCertComment("example.com"),
	}))
}

func TestAgentHasValidCertificate(t *testing.T) {
	now := uint64(time.Now().Unix())

	tests := []struct {
		name        string
		validAfter  uint64
		validBefore uint64
		want        bool
	}{
		{name: "expired certificate is not usable", validAfter: now - 100, validBefore: now - 50, want: false},
		{name: "not-yet-valid certificate is not usable", validAfter: now + 50, validBefore: now + 100, want: false},
		{name: "currently valid certificate is usable", validAfter: now - 10, validBefore: now + 100, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyring := agent.NewKeyring()
			extended := keyringAgent{keyring}
			addTestCertificate(t, keyring, tc.validAfter, tc.validBefore)

			got, err := AgentHasValidCertificate(extended, "example.com")
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)

			if !tc.want {
				assert.NoError(t, AgentRemoveCertificates(extended, "example.com"))
				keys, err := keyring.List()
				assert.NoError(t, err)
				assert.Empty(t, keys)
			}
		})
	}
}

func TestHasMatchBlock(t *testing.T) {
	present := []string{
		`Match exec "oinit match %h %p"`,
		`Match exec "/usr/bin/oinit match %h %p"`,
		`  Match exec "/opt/oinit/bin/oinit match %h %p"`,
		"match exec \"oinit match %h %p\"", // case-insensitive keywords
		`Match   exec   "oinit match %h %p"`,
		`Match exec 'oinit match %h %p'`,
	}
	absent := []string{
		`Host example.com`,
		`Match exec "true"`,
		`    User oinit`,
		`# Match exec "oinit match %h %p"`, // commented out
		`Match exec "oinitmatch %h %p"`,    // no space between oinit and match
		``,
	}

	for _, l := range present {
		if !hasMatchBlock(l) {
			t.Errorf("hasMatchBlock(%q) = false, want true", l)
		}
	}
	for _, l := range absent {
		if hasMatchBlock(l) {
			t.Errorf("hasMatchBlock(%q) = true, want false", l)
		}
	}
}
