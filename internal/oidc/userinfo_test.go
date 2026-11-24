package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireHTTPS(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https ok", "https://op.example.com", false},
		{"https with path ok", "https://op.example.com/userinfo", false},
		{"plaintext http rejected", "http://op.example.com", true},
		{"other scheme rejected", "ftp://op.example.com", true},
		{"schemeless rejected", "op.example.com/userinfo", true},
		{"empty rejected", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireHTTPS(tt.url)
			if tt.wantErr && err == nil {
				t.Fatalf("requireHTTPS(%q) = nil, want error", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("requireHTTPS(%q) = %v, want nil", tt.url, err)
			}
		})
	}
}

func newRedirectTestRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()

	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

func TestCheckDiscoveryRedirect(t *testing.T) {
	originalURL := "https://op.example.com/.well-known/openid-configuration"

	tests := []struct {
		name     string
		method   string
		target   string
		viaCount int
		wantErr  bool
	}{
		{
			name:     "same-origin 303 target allowed",
			method:   http.MethodGet,
			target:   "https://op.example.com/idp/profile/oidc/configuration",
			viaCount: 1,
		},
		{
			name:     "explicit default port is same origin",
			method:   http.MethodGet,
			target:   "https://op.example.com:443/idp/profile/oidc/configuration",
			viaCount: 1,
		},
		{
			name:     "plaintext target rejected",
			method:   http.MethodGet,
			target:   "http://op.example.com/idp/profile/oidc/configuration",
			viaCount: 1,
			wantErr:  true,
		},
		{
			name:     "cross-origin target rejected",
			method:   http.MethodGet,
			target:   "https://evil.example.com/idp/profile/oidc/configuration",
			viaCount: 1,
			wantErr:  true,
		},
		{
			name:     "different port rejected",
			method:   http.MethodGet,
			target:   "https://op.example.com:8443/idp/profile/oidc/configuration",
			viaCount: 1,
			wantErr:  true,
		},
		{
			name:     "non-GET redirect rejected",
			method:   http.MethodPost,
			target:   "https://op.example.com/idp/profile/oidc/configuration",
			viaCount: 1,
			wantErr:  true,
		},
		{
			name:     "redirect limit enforced",
			method:   http.MethodGet,
			target:   "https://op.example.com/idp/profile/oidc/configuration",
			viaCount: MAX_REDIRECTS,
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := newRedirectTestRequest(t, http.MethodGet, originalURL)
			via := make([]*http.Request, tc.viaCount)
			for i := range via {
				via[i] = original
			}

			target := newRedirectTestRequest(t, tc.method, tc.target)
			err := checkDiscoveryRedirect(target, via)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestFetchDiscoveryFollowsSameOrigin303(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/idp/profile/oidc/configuration", http.StatusSeeOther)
	})
	mux.HandleFunc("/idp/profile/oidc/configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://op.example.com","userinfo_endpoint":"https://op.example.com/userinfo","jwks_uri":"https://op.example.com/keyset"}`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	oldClient := discoveryHTTPClient
	defer func() { discoveryHTTPClient = oldClient }()

	client := *srv.Client()
	client.CheckRedirect = checkDiscoveryRedirect
	discoveryHTTPClient = &client

	config, err := fetchDiscovery(srv.URL)
	if err != nil {
		t.Fatalf("fetchDiscovery: %v", err)
	}
	if config.UserinfoEndpoint != "https://op.example.com/userinfo" {
		t.Errorf("UserinfoEndpoint = %q", config.UserinfoEndpoint)
	}
}
