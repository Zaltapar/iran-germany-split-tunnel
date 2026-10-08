package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// secureTestConfig builds a fully-secure TLS config (valid 32-hex basePath)
// for the routing/headers tests.
func secureTestConfig() *DashboardConfig {
	cfg := DefaultConfig()
	cfg.ListenAddr = "0.0.0.0:8443"
	cfg.TLS = &TLSConfig{
		Enabled:  true,
		CertFile: "/etc/split-tunnel/dashboard/tls/cert.pem",
		KeyFile:  "/etc/split-tunnel/dashboard/tls/key.pem",
		BasePath: "00112233445566778899aabbccddeeff",
	}
	return cfg
}

// newTLSTestServer builds a NewTLSServer-backed server for routing tests
// (no actual TLS handshake; we exercise the Router() surface).
func newTLSTestServer(cfg *DashboardConfig) *Server {
	if err := cfg.Validate(); err != nil {
		// config is already valid by construction in the fixtures
	}
	return NewTLSServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestTLSBasePathOutsideIs404: any request outside the random prefix must
// 404, even for the root "/" and the exact API path at the site root.
func TestTLSBasePathOutsideIs404(t *testing.T) {
	s := newTLSTestServer(secureTestConfig())
	h := s.Router()
	for _, path := range []string{
		"/",
		"/api/v1/overview",
		"/static/style.css",
		"/deadbeefdeadbeefdeadbeefdeadbeef/api/v1/overview", // wrong hex
		"/otherpath",
	} {
		rr := get(h, path)
		if rr.Code != http.StatusNotFound {
			t.Errorf("path %q outside basePath: status = %d, want 404", path, rr.Code)
		}
	}
}

// TestTLSBasePathInsideRoutes: a request under the valid 32-hex prefix is
// rewritten and reaches the inner router (200 overview); a 31-hex prefix is
// rejected as 404.
func TestTLSBasePathInsideRoutes(t *testing.T) {
	s := newTLSTestServer(secureTestConfig())
	h := s.Router()

	rrShort := get(h, "/00112233445566778899aabbccddeef/api/v1/overview") // 31 hex
	if rrShort.Code != http.StatusNotFound {
		t.Errorf("31-hex prefix: status = %d, want 404", rrShort.Code)
	}

	rr := get(h, "/00112233445566778899aabbccddeeff/api/v1/overview")
	if rr.Code != http.StatusOK {
		t.Errorf("inside basePath overview: status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

// TestTLSBarePrefixRedirects: the bare prefix (no trailing slash) 301s to
// the trailing-slash canonical form.
func TestTLSBarePrefixRedirects(t *testing.T) {
	s := newTLSTestServer(secureTestConfig())
	h := s.Router()
	rr := get(h, "/00112233445566778899aabbccddeeff")
	if rr.Code != http.StatusMovedPermanently {
		t.Fatalf("bare prefix: status = %d, want 301", rr.Code)
	}
	if got := rr.Header().Get("Location"); !strings.HasSuffix(got, "/00112233445566778899aabbccddeeff/") {
		t.Errorf("Location = %q, want trailing-slash form", got)
	}
}

// TestTLSSecurityHeadersPresent: the security header set is present on
// responses under the TLS basePath.
func TestTLSSecurityHeadersPresent(t *testing.T) {
	s := newTLSTestServer(secureTestConfig())
	h := s.Router()
	rr := get(h, "/00112233445566778899aabbccddeeff/api/v1/health")
	wantHeaders := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
	}
	for k, v := range wantHeaders {
		if got := rr.Header().Get(k); got != v {
			t.Errorf("header %q = %q, want %q", k, got, v)
		}
	}
}

// TestNoTLSNoSecurityHeaders: in local loopback mode (no TLS) the security
// headers are NOT emitted.
func TestNoTLSNoSecurityHeaders(t *testing.T) {
	cfg := DefaultConfig()
	s := newTestServer(cfg)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/health", "")
	if got := rr.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("loopback mode must not set CSP, got %q", got)
	}
}

// TestValidateTLSRequiresComplete: an enabled but incomplete TLS config
// (missing basePath) is a validation error.
func TestValidateTLSRequiresComplete(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS = &TLSConfig{Enabled: true, CertFile: "c.pem", KeyFile: "k.pem"} // no basePath
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("incomplete TLS config must fail validation")
	}
	if !strings.Contains(err.Error(), "basePath") {
		t.Errorf("error should mention basePath, got %v", err)
	}
}

// TestValidateTLSBadBasePath: a non-32-hex base path is rejected.
func TestValidateTLSBadBasePath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS = &TLSConfig{Enabled: true, CertFile: "c.pem", KeyFile: "k.pem", BasePath: "TOO-SHORT"}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("bad base path must fail validation")
	}
}

// TestGenerateBasePathShape: a generated base path is exactly 32 lowercase
// hex chars, and two generations differ.
func TestGenerateBasePathShape(t *testing.T) {
	p, err := GenerateBasePath()
	if err != nil {
		t.Fatalf("GenerateBasePath: %v", err)
	}
	if !validBasePath(p) {
		t.Fatalf("generated base path %q is not 32 lowercase hex", p)
	}
	p2, _ := GenerateBasePath()
	if p == p2 {
		t.Errorf("two base paths are identical: %q", p)
	}
}

// TestAdminTokenEnv: LoadAdminToken respects SPLIT_TUNNELDASH_TOKEN.
func TestAdminTokenEnv(t *testing.T) {
	t.Setenv(EnvAdminToken, "abc123token")
	if got := LoadAdminToken(); got != "abc123token" {
		t.Fatalf("LoadAdminToken = %q, want the env token", got)
	}
}

// TestAdminTokenEmpty: no token sources → empty (auth disabled).
func TestAdminTokenEmpty(t *testing.T) {
	t.Setenv(EnvAdminToken, "")
	t.Setenv(EnvAdminTokenFile, "")
	if got := LoadAdminToken(); got != "" {
		t.Fatalf("LoadAdminToken = %q, want empty when no source set", got)
	}
}
