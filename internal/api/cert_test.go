package api

import (
	"crypto/ed25519"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestGenerateUserCertificate(t *testing.T) {
	host := "example.com"

	pk, _, _ := ed25519.GenerateKey(nil)
	pubkey, _ := ssh.NewPublicKey(pk)

	username := "testuser"
	subject := "test-subject-123"
	issuer := "https://accounts.example.com"
	duration := uint64(3600)
	backdate := uint64(3600)
	principals := []string{"oinit", username}
	forceCommand := "oinit-switch " + username

	certificate := generateUserCertificate(host, pubkey, username, subject, issuer, duration, backdate, principals, forceCommand)

	if certificate.Serial != 0 {
		t.Error("Expected Serial to be 0")
	}

	if certificate.CertType != ssh.UserCert {
		t.Error("Expected CertType to be ssh.UserCert")
	}

	expectedKeyId := subject + " @ " + issuer + " -> " + username
	if certificate.KeyId != expectedKeyId {
		t.Errorf("Expected KeyId to be %s, but got %s", expectedKeyId, certificate.KeyId)
	}

	if !stringSlicesEqual(certificate.ValidPrincipals, principals) {
		t.Errorf("Expected ValidPrincipals to be %v, but got %v", principals, certificate.ValidPrincipals)
	}

	currentTime := uint64(time.Now().Unix())
	if !(certificate.ValidAfter <= currentTime && currentTime < certificate.ValidBefore) {
		t.Error("Invalid certificate validity period")
	}
	wantValidAfter := currentTime - backdate
	if diff := absDiff(certificate.ValidAfter, wantValidAfter); diff > 1 {
		t.Errorf("Expected ValidAfter to be about now-%d, got %d", backdate, certificate.ValidAfter)
	}
	wantValidBefore := currentTime + duration
	if diff := absDiff(certificate.ValidBefore, wantValidBefore); diff > 1 {
		t.Errorf("Expected ValidBefore to be about now+%d, got %d", duration, certificate.ValidBefore)
	}

	if certificate.Permissions.CriticalOptions["force-command"] != forceCommand {
		t.Errorf("Expected force-command to be %s, but got %s", forceCommand, certificate.Permissions.CriticalOptions["force-command"])
	}

	if _, ok := certificate.Permissions.Extensions["permit-agent-forwarding"]; !ok {
		t.Error("Expected permit-agent-forwarding extension to be present")
	}

	if _, ok := certificate.Permissions.Extensions["permit-pty"]; !ok {
		t.Error("Expected permit-pty extension to be present")
	}
}

func TestGenerateUserCertificateNoForceCommand(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(nil)
	pubkey, _ := ssh.NewPublicKey(pk)

	certificate := generateUserCertificate("example.com", pubkey, "git", "sub", "iss", 3600, 0, []string{"git"}, "")

	if _, ok := certificate.Permissions.CriticalOptions["force-command"]; ok {
		t.Error("Expected no force-command when forceCommand is empty")
	}

	if !stringSlicesEqual(certificate.ValidPrincipals, []string{"git"}) {
		t.Errorf("Expected ValidPrincipals to be [git], but got %v", certificate.ValidPrincipals)
	}
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

func stringSlicesEqual(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i, v := range slice1 {
		if v != slice2[i] {
			return false
		}
	}
	return true
}
