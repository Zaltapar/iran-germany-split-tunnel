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

// TestAdminTokenConfigured (D1b) verifies the fail-closed predicate: it is
// true whenever a token source is configured (env value OR file path), even
// when the value later fails to resolve — that is exactly the case a public
// TLS build must refuse. It is false only when no source is present at all.
func TestAdminTokenConfigured(t *testing.T) {
	t.Run("no source -> false", func(t *testing.T) {
		t.Setenv(EnvAdminToken, "")
		t.Setenv(EnvAdminTokenFile, "")
		if AdminTokenConfigured() {
			t.Error("AdminTokenConfigured() = true, want false with no source")
		}
	})
	t.Run("env token set -> true", func(t *testing.T) {
		t.Setenv(EnvAdminToken, "abc")
		t.Setenv(EnvAdminTokenFile, "")
		if !AdminTokenConfigured() {
			t.Error("AdminTokenConfigured() = false, want true (env token set)")
		}
	})
	t.Run("file path set but file missing -> true", func(t *testing.T) {
		t.Setenv(EnvAdminToken, "")
		t.Setenv(EnvAdminTokenFile, "/no/such/token-file")
		if !AdminTokenConfigured() {
			t.Error("AdminTokenConfigured() = false, want true (configured source that failed to resolve)")
		}
		// The configured-but-unresolvable source still returns an empty token:
		// this is the misconfiguration a TLS build must fail closed on.
		if got := LoadAdminToken(); got != "" {
			t.Errorf("LoadAdminToken() = %q, want empty for a missing file", got)
		}
	})
	t.Run("whitespace-only env -> false", func(t *testing.T) {
		t.Setenv(EnvAdminToken, "   ")
		t.Setenv(EnvAdminTokenFile, "")
		if AdminTokenConfigured() {
			t.Error("AdminTokenConfigured() = true, want false (env token is whitespace-only)")
		}
	})
}
