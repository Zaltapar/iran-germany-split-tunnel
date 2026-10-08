package dashboard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestBearerAuthConstantTime verifies the Bearer token comparison behavior
// after the constant-time fix. A wrong-length token and a prefix-match /
// different-suffix token are both rejected; the exact token is accepted.
func TestBearerAuthConstantTime(t *testing.T) {
	token := "s3cr3t-t0k3n-value"

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic abc", http.StatusUnauthorized},
		{"wrong length", "Bearer short", http.StatusUnauthorized},
		{"prefix match, different suffix", "Bearer s3cr3t-t0k3n-other", http.StatusUnauthorized},
		{"correct token", "Bearer s3cr3t-t0k3n-value", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			auth := NewBearerTokenAuthenticator(token)
			cfg := DefaultConfig()
			s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, auth)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rr := httptest.NewRecorder()
			s.Router().ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Errorf("%s: status = %d, want %d", tc.name, rr.Code, tc.want)
			}
		})
	}
}

// TestLoadAdminTokenFromFile verifies that LoadAdminToken trims the contents
// of the file named by SPLIT_TUNNELDASH_TOKEN_FILE.
func TestLoadAdminTokenFromFile(t *testing.T) {
	t.Setenv(EnvAdminToken, "")
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("my-token-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvAdminTokenFile, tokenFile)

	if got := LoadAdminToken(); got != "my-token-value" {
		t.Errorf("LoadAdminToken() = %q, want %q", got, "my-token-value")
	}
}

// TestLoadAdminTokenEnvWins verifies the env var takes precedence over the file.
func TestLoadAdminTokenEnvWins(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvAdminToken, "env-token")
	t.Setenv(EnvAdminTokenFile, tokenFile)

	if got := LoadAdminToken(); got != "env-token" {
		t.Errorf("LoadAdminToken() = %q, want %q (env var must win)", got, "env-token")
	}
}

// TestLoadAdminTokenEmptySources verifies both sources absent returns "".
func TestLoadAdminTokenEmptySources(t *testing.T) {
	t.Setenv(EnvAdminToken, "")
	t.Setenv(EnvAdminTokenFile, "")
	if got := LoadAdminToken(); got != "" {
		t.Errorf("LoadAdminToken() = %q, want empty", got)
	}
}
