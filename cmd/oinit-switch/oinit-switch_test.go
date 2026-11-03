package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cfg(allow, block []string) switchConfig {
	c := switchConfig{allowUsers: map[string]bool{}, blockUsers: map[string]bool{}}
	for _, a := range allow {
		c.allowUsers[a] = true
	}
	for _, b := range block {
		c.blockUsers[b] = true
	}
	return c
}

func TestClassifyTarget(t *testing.T) {
	const curUid = 990 // the oinit service user

	tests := []struct {
		name     string
		username string
		uid      int
		cfg      switchConfig
		wantOK   bool
	}{
		{"regular user accepted", "alice", 1000, cfg(nil, nil), true},
		{"current user skipped", "oinit", curUid, cfg(nil, nil), false},
		{"system user not allowlisted refused", "daemon", 2, cfg([]string{"root"}, nil), false},
		{"root not allowlisted refused", "root", 0, cfg(nil, nil), false},
		{"root allowlisted accepted", "root", 0, cfg([]string{"root"}, nil), true},
		{"system user allowlisted accepted", "svc", 50, cfg([]string{"svc"}, nil), true},
		{"blocked regular user refused", "deploy", 1001, cfg(nil, []string{"deploy"}), false},
		{"block wins over allow for system user", "root", 0, cfg([]string{"root"}, []string{"root"}), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, _ := classifyTarget(tt.username, tt.uid, curUid, tt.cfg)
			if ok != tt.wantOK {
				t.Fatalf("classifyTarget(%q, uid=%d) ok=%v, want %v", tt.username, tt.uid, ok, tt.wantOK)
			}
		})
	}
}

func TestIsValidUsername(t *testing.T) {
	valid := []string{"alice", "git", "_svc", "a-b_c", "root", "alice.hertzog", "a..b", "alice."}
	invalid := []string{"", "Alice", "a b", "a;b", "a/b", "-a", "root$", ".alice", "..", "alice/..", strings.Repeat("a", 33)}
	for _, v := range valid {
		if !isValidUsername(v) {
			t.Errorf("isValidUsername(%q) = false, want true", v)
		}
	}
	for _, v := range invalid {
		if isValidUsername(v) {
			t.Errorf("isValidUsername(%q) = true, want false", v)
		}
	}
}

func TestParsePasswdEntry(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    passwdEntry
		wantErr bool
	}{
		{
			name: "regular entry",
			line: "alice:x:1000:1001:Alice:/home/alice:/bin/bash",
			want: passwdEntry{Name: "alice", Uid: 1000, Gid: 1001},
		},
		{
			name: "dotted Feudal username",
			line: "alice.hertzog:x:1002:1003:Alice Hertzog:/home/alice.hertzog:/bin/bash",
			want: passwdEntry{Name: "alice.hertzog", Uid: 1002, Gid: 1003},
		},
		{
			name: "empty gecos",
			line: "bob:x:1004:1004::/home/bob:/bin/sh",
			want: passwdEntry{Name: "bob", Uid: 1004, Gid: 1004},
		},
		{name: "too few fields", line: "alice:x:1000:1000::/home/alice", wantErr: true},
		{name: "too many fields", line: "alice:x:1000:1000:a:b:/home/alice:/bin/sh", wantErr: true},
		{name: "empty name", line: ":x:1000:1000::/home/alice:/bin/sh", wantErr: true},
		{name: "invalid uid", line: "alice:x:notanumber:1000::/home/alice:/bin/sh", wantErr: true},
		{name: "invalid gid", line: "alice:x:1000:notanumber::/home/alice:/bin/sh", wantErr: true},
		{name: "negative uid", line: "alice:x:-1:1000::/home/alice:/bin/sh", wantErr: true},
		{name: "negative gid", line: "alice:x:1000:-1::/home/alice:/bin/sh", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePasswdEntry(tt.line)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePasswdEntry(%q) error = %v, wantErr %v", tt.line, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("parsePasswdEntry(%q) = %+v, want %+v", tt.line, got, tt.want)
			}
		})
	}
}

func TestGetentPasswd(t *testing.T) {
	oldCandidates := getentCandidates
	defer func() { getentCandidates = oldCandidates }()

	writeFake := func(t *testing.T, script string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "getent")
		if err := os.WriteFile(path, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("found", func(t *testing.T) {
		getentCandidates = []string{writeFake(t, "#!/bin/sh\nprintf '%s\\n' 'alice.hertzog:x:1002:1003:Alice Hertzog:/home/alice.hertzog:/bin/bash'\n")}
		entries, err := getentPasswd("alice.hertzog")
		if err != nil {
			t.Fatal(err)
		}
		want := passwdEntry{Name: "alice.hertzog", Uid: 1002, Gid: 1003}
		if len(entries) != 1 || entries[0] != want {
			t.Fatalf("getentPasswd = %+v, want [%+v]", entries, want)
		}
	})

	t.Run("not found", func(t *testing.T) {
		getentCandidates = []string{writeFake(t, "#!/bin/sh\nexit 2\n")}
		_, err := getentPasswd("alice.hertzog")
		if !errors.Is(err, errUserNotFound) {
			t.Fatalf("getentPasswd error = %v, want errUserNotFound", err)
		}
	})

	t.Run("lookup failure", func(t *testing.T) {
		getentCandidates = []string{writeFake(t, "#!/bin/sh\necho 'nss unavailable' >&2\nexit 1\n")}
		_, err := getentPasswd("alice.hertzog")
		if err == nil || errors.Is(err, errUserNotFound) {
			t.Fatalf("getentPasswd error = %v, want operational failure", err)
		}
		if !strings.Contains(err.Error(), "nss unavailable") {
			t.Fatalf("getentPasswd error = %v, want stderr included", err)
		}
	})
}

func TestParseSwitchConfig(t *testing.T) {
	in := "# oinit-switch config\n" +
		"\n" +
		"allow-users = root, svc daemon\n" +
		"block-users = deploy, backup\n" +
		"# allow-users = should-be-ignored\n"
	got := parseSwitchConfig(strings.NewReader(in))

	for _, want := range []string{"root", "svc", "daemon"} {
		if !got.allowUsers[want] {
			t.Errorf("expected %q to be allowed", want)
		}
	}
	for _, want := range []string{"deploy", "backup"} {
		if !got.blockUsers[want] {
			t.Errorf("expected %q to be blocked", want)
		}
	}
	if got.allowUsers["should-be-ignored"] {
		t.Error("commented-out allow-users line was parsed")
	}
	if len(got.allowUsers) != 3 || len(got.blockUsers) != 2 {
		t.Errorf("got allow=%v block=%v", got.allowUsers, got.blockUsers)
	}
}

// TestSelectSessionSocket exercises the security-critical socket-selection
// logic: a forwarded oidc socket is only ever selected when its inode is held
// by this session's own sshd AND the path is owned by the current user. Any
// other case (a concurrent session's socket, an unowned path, no inode match)
// must yield "" so forwarding is disabled rather than a wrong socket chowned.
func TestSelectSessionSocket(t *testing.T) {
	ownedAll := func(string) bool { return true }
	ownedNone := func(string) bool { return false }

	mine := unixSocket{inode: "111", path: "/tmp/oidc-forward-1"}
	theirs := unixSocket{inode: "222", path: "/tmp/oidc-forward-2"}

	tests := []struct {
		name       string
		candidates []unixSocket
		sshdInodes map[string]bool
		owned      func(string) bool
		want       string
	}{
		{
			name:       "own session socket selected",
			candidates: []unixSocket{mine, theirs},
			sshdInodes: map[string]bool{"111": true},
			owned:      ownedAll,
			want:       "/tmp/oidc-forward-1",
		},
		{
			name:       "concurrent session socket never selected",
			candidates: []unixSocket{theirs},
			sshdInodes: map[string]bool{"111": true}, // our sshd does not hold 222
			owned:      ownedAll,
			want:       "",
		},
		{
			name:       "lone candidate not held by our sshd is rejected",
			candidates: []unixSocket{theirs},
			sshdInodes: map[string]bool{}, // no inode match at all
			owned:      ownedAll,
			want:       "",
		},
		{
			name:       "inode match but not owned is rejected",
			candidates: []unixSocket{mine},
			sshdInodes: map[string]bool{"111": true},
			owned:      ownedNone,
			want:       "",
		},
		{
			name:       "no candidates",
			candidates: nil,
			sshdInodes: map[string]bool{"111": true},
			owned:      ownedAll,
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectSessionSocket(tt.candidates, tt.sshdInodes, tt.owned); got != tt.want {
				t.Fatalf("selectSessionSocket = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestChooseForwardedSocket covers the selection policy layered on top of the
// inode match: prefer inode-bound; else fall back to a sole owned candidate;
// else refuse. The sole-owned fallback must never fire when more than one
// forwarded socket is owned (the concurrent-session case P0-2 must block).
func TestChooseForwardedSocket(t *testing.T) {
	ownedAll := func(string) bool { return true }

	mine := unixSocket{inode: "111", path: "/tmp/oidc-forward-1"}
	theirs := unixSocket{inode: "222", path: "/tmp/oidc-forward-2"}

	tests := []struct {
		name       string
		candidates []unixSocket
		sshdInodes map[string]bool
		owned      func(string) bool
		wantPath   string
		wantReason string
	}{
		{
			name:       "inode-bound wins even with multiple candidates",
			candidates: []unixSocket{mine, theirs},
			sshdInodes: map[string]bool{"111": true},
			owned:      ownedAll,
			wantPath:   "/tmp/oidc-forward-1",
			wantReason: "inode-bound",
		},
		{
			name:       "no inode match, single owned -> sole-owned fallback",
			candidates: []unixSocket{mine},
			sshdInodes: map[string]bool{}, // e.g. sshd fds not readable
			owned:      ownedAll,
			wantPath:   "/tmp/oidc-forward-1",
			wantReason: "sole-owned",
		},
		{
			name:       "no inode match, multiple owned -> refuse (concurrent sessions)",
			candidates: []unixSocket{mine, theirs},
			sshdInodes: map[string]bool{},
			owned:      ownedAll,
			wantPath:   "",
			wantReason: "ambiguous",
		},
		{
			name:       "no inode match, none owned -> refuse",
			candidates: []unixSocket{mine},
			sshdInodes: map[string]bool{},
			owned:      func(string) bool { return false },
			wantPath:   "",
			wantReason: "ambiguous",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, reason := chooseForwardedSocket(tt.candidates, tt.sshdInodes, tt.owned)
			if path != tt.wantPath || reason != tt.wantReason {
				t.Fatalf("chooseForwardedSocket = (%q, %q), want (%q, %q)", path, reason, tt.wantPath, tt.wantReason)
			}
		})
	}
}
