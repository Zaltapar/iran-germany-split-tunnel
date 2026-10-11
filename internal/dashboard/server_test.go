package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestServer builds a fully-wired Server with a fixture cache.
func newTestServer(cfg *DashboardConfig) *Server {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		// cfg may already have been validated
	}
	cache := NewCache(cfg)
	audit := NewAuditLog(cfg.MaxAudit)
	return NewServer(cfg, cache, audit, nil, nil)
}

// doRequest performs a request against the Router and returns the response.
// For POST requests it automatically sets the C1 CSRF custom header so that
// existing v1 plan/apply tests keep working (the loopback test server has
// no Origin header; the custom header alone satisfies the C1 check).
func doRequest(t *testing.T, s *Server, method, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if method == http.MethodPost {
		req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	}
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	return rr
}

// --- /api/v1/overview ---

func TestAPIOverview(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/overview", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("overview status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body OverviewResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal overview: %v", err)
	}
	if !body.Healthy {
		t.Error("healthy should be true in overview")
	}
	if !body.ReadOnly {
		t.Error("readOnly should be true in default config")
	}
	if len(body.Servers) != 2 {
		t.Errorf("expected 2 servers in overview, got %d", len(body.Servers))
	}
	for _, srv := range body.Servers {
		if srv.ID == "" || srv.Role == "" {
			t.Errorf("server entry missing ID or Role: %+v", srv)
		}
	}
}

func TestAPIOverviewMethodNotAllowed(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodDelete, "/api/v1/overview", "")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE overview status = %d, want 405", rr.Code)
	}
}

// --- /api/v1/servers ---

func TestAPIServersList(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/servers", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("servers status = %d, want 200", rr.Code)
	}
	var body []map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body) != 2 {
		t.Errorf("expected 2 servers, got %d", len(body))
	}
}

// --- /api/v1/servers/{id} ---

func TestAPIServerSnapshot(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/servers/iran", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("snapshot status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body ServerSnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.ServerID != "iran" {
		t.Errorf("serverID = %q, want iran", body.ServerID)
	}
}

func TestAPIServerSnapshotNotFound(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/servers/unknown-server", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("unknown server status = %d, want 404", rr.Code)
	}
}

func TestAPIServerSnapshotPathTraversal(t *testing.T) {
	s := newTestServer(nil)
	// URL-encoded traversal attempts must be rejected or 404'd.
	for _, path := range []string{
		"/api/v1/servers/..%2f..%2fetc%2fpasswd",
		"/api/v1/servers/../../../etc/passwd",
		"/api/v1/servers/%2e%2e%2f%2e%2e%2fetc",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		// ServeMux cleans the path before our handler sees it.
		s.Router().ServeHTTP(rr, req)
		// Either 404, 400, or 405 — never 200 with file contents.
		if rr.Code == http.StatusOK {
			t.Errorf("path %q returned 200 (should not leak file): %s", path, rr.Body.String())
		}
	}
}

// --- /api/v1/servers/{id}/metrics ---

func TestAPIServerMetrics(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/servers/iran/metrics", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		ServerID string          `json:"serverId"`
		Source   string          `json:"source"`
		Status   SnapshotStatus  `json:"status"`
		Metrics  *ParsedMetrics  `json:"metrics"`
		Rates    map[string]Rate `json:"rates"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.ServerID != "iran" {
		t.Errorf("serverID = %q, want iran", body.ServerID)
	}
	if body.Metrics == nil || len(body.Metrics.Samples) == 0 {
		t.Error("metrics has no samples")
	}
}

// --- /api/v1/servers/{id}/logs ---

func TestAPIServerLogs(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/servers/iran/logs", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("logs status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		ServerID  string     `json:"serverId"`
		Entries   []LogEntry `json:"entries"`
		Truncated bool       `json:"truncated"`
		Warning   string     `json:"warning"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Entries) == 0 {
		t.Error("fixture logs should have entries")
	}
}

func TestAPIServerLogsBoundedLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxLogEntries = 3 // very small cap
	s := newTestServer(cfg)

	// Request a large limit — it must be clamped to MaxLogEntries.
	rr := doRequest(t, s, http.MethodGet, "/api/v1/servers/iran/logs?limit=9999", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Entries []LogEntry `json:"entries"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if len(body.Entries) > 3 {
		t.Errorf("limit not clamped: got %d entries, want ≤3", len(body.Entries))
	}
}

func TestAPIServerLogsUnknownSourceNoRemoteFetch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Servers[0].SourceType = "ssh"
	cfg.Servers[0].ID = "iran"
	s := newTestServer(cfg)

	rr := doRequest(t, s, http.MethodGet, "/api/v1/servers/iran/logs", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Warning string     `json:"warning"`
		Entries []LogEntry `json:"entries"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Warning == "" {
		t.Error("unsupported source should emit a warning about no remote fetch")
	}
}

// --- /api/v1/servers/{id}/config ---

func TestAPIServerConfigRedacted(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/servers/iran/config", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("config status = %d, want 200", rr.Code)
	}
	var body struct {
		Values   []ConfigValue `json:"values"`
		Warnings []string      `json:"warnings"`
		ReadOnly bool          `json:"readOnly"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !body.ReadOnly {
		t.Error("readOnly should be true")
	}
	// No value may contain an actual secret.
	for _, cv := range body.Values {
		if cv.Key == "SPLIT_SECRET" && cv.Value != "[REDACTED]" {
			t.Errorf("SPLIT_SECRET value = %q, want [REDACTED]", cv.Value)
		}
		if cv.Key == "SPLIT_SOCKS_PASS" && cv.Value != "[REDACTED]" {
			t.Errorf("SPLIT_SOCKS_PASS value = %q, want [REDACTED]", cv.Value)
		}
	}
}

// --- /api/v1/servers/{id}/config/plan ---

func TestAPIServerConfigPlan(t *testing.T) {
	s := newTestServer(nil)
	body := `{"planId":"t-plan-1","changes":[{"key":"SPLIT_METRICS_PORT","value":"9101"}]}`
	rr := doRequest(t, s, http.MethodPost, "/api/v1/servers/iran/config/plan", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("plan status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	var plan struct {
		ChangePlan
		Applied bool `json:"applied"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &plan); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if plan.PlanID != "t-plan-1" {
		t.Errorf("planID = %q, want t-plan-1", plan.PlanID)
	}
	if plan.Applied {
		t.Error("Applied must always be false in this release")
	}
	if len(plan.Changes) != 1 {
		t.Errorf("expected 1 change, got %d", len(plan.Changes))
	}
}

func TestAPIServerConfigPlanInvalidKey(t *testing.T) {
	s := newTestServer(nil)
	// Attempt to plan a secret key — must be rejected with 400.
	body := `{"changes":[{"key":"SPLIT_SECRET","value":"new"}]}`
	rr := doRequest(t, s, http.MethodPost, "/api/v1/servers/iran/config/plan", body)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("plan with secret key status = %d, want 400", rr.Code)
	}
}

func TestAPIServerConfigPlanEmptyBody(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodPost, "/api/v1/servers/iran/config/plan", "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("empty plan body status = %d, want 400", rr.Code)
	}
}

// --- /api/v1/servers/{id}/config/apply ---

// TestAPIServerConfigApplyRefused proves that in the default local build,
// the apply endpoint returns 403 and the nil mutator is never called.
func TestAPIServerConfigApplyRefused(t *testing.T) {
	cfg := DefaultConfig()
	// Build with a captured nil mutator so we can assert call count.
	nilMut := NewNilMutator()
	cache := NewCache(cfg)
	audit := NewAuditLog(cfg.MaxAudit)
	s := NewServer(cfg, cache, audit, nilMut, nil)

	// Create a valid plan first.
	planBody := `{"planId":"apply-test","changes":[{"key":"SPLIT_METRICS_PORT","value":"9101"}]}`
	rr := doRequest(t, s, http.MethodPost, "/api/v1/servers/iran/config/plan", planBody)
	if rr.Code != http.StatusCreated {
		t.Fatalf("plan setup failed: %d %s", rr.Code, rr.Body.String())
	}

	// Now attempt to apply it.
	applyBody := `{"planId":"apply-test"}`
	rr = doRequest(t, s, http.MethodPost, "/api/v1/servers/iran/config/apply", applyBody)
	if rr.Code != http.StatusForbidden {
		t.Errorf("apply status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "mutations disabled" {
		t.Errorf("apply error = %q, want 'mutations disabled'", resp["error"])
	}
	// The nil mutator must NOT have been called (the gate short-circuits).
	if got := nilMut.Attempts(); got != 0 {
		t.Errorf("nil mutator was called %d times — gate must short-circuit before the mutator", got)
	}
}

func TestAPIServerConfigApplyUnknownPlan(t *testing.T) {
	s := newTestServer(nil)
	body := `{"planId":"does-not-exist"}`
	rr := doRequest(t, s, http.MethodPost, "/api/v1/servers/iran/config/apply", body)
	if rr.Code != http.StatusConflict {
		t.Errorf("apply with unknown plan status = %d, want 409", rr.Code)
	}
}

func TestAPIServerConfigApplyMissingPlanID(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodPost, "/api/v1/servers/iran/config/apply", `{}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("apply without planId status = %d, want 400", rr.Code)
	}
}

// TestAPIServerConfigApplyMethodRejection proves that GET/PUT/DELETE on the
// apply endpoint are rejected with 405.
func TestAPIServerConfigApplyMethodRejection(t *testing.T) {
	s := newTestServer(nil)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/servers/iran/config/apply", nil)
		rr := httptest.NewRecorder()
		s.Router().ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("apply %s status = %d, want 405", method, rr.Code)
		}
	}
}

// --- /api/v1/audit ---

func TestAPIAudit(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/audit", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("audit status = %d, want 200", rr.Code)
	}
	var events []AuditEvent
	if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Empty audit log initially.
	if len(events) != 0 {
		t.Errorf("expected empty audit, got %d events", len(events))
	}
}

func TestAPIAuditAfterPlan(t *testing.T) {
	s := newTestServer(nil)
	body := `{"planId":"audit-test","changes":[{"key":"SPLIT_RELAY_BUF","value":"32768"}]}`
	_ = doRequest(t, s, http.MethodPost, "/api/v1/servers/iran/config/plan", body)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/audit", "")
	var events []AuditEvent
	_ = json.Unmarshal(rr.Body.Bytes(), &events)
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event after plan, got %d", len(events))
	}
	if events[0].EventType != "plan_created" {
		t.Errorf("eventType = %q, want plan_created", events[0].EventType)
	}
}

// --- /api/v1/health ---

func TestAPIHealth(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/health", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", rr.Code)
	}
	var body HealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
	if !body.ReadOnly {
		t.Error("readOnly should be true")
	}
}

// --- /api/v1/config-keys ---

func TestAPIConfigKeys(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/api/v1/config-keys", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("config-keys status = %d, want 200", rr.Code)
	}
	var keys []ConfigKeySpec
	if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(keys) == 0 {
		t.Error("no config keys returned")
	}
}

// --- Security tests ---

func TestAPIOversizedRequestBody(t *testing.T) {
	s := newTestServer(nil)
	// The limit is 64 KiB. Send a 1 MiB body — the decoder should fail or
	// the reader should return an error.
	big := strings.Repeat("a", 1<<20)
	rr := doRequest(t, s, http.MethodPost, "/api/v1/servers/iran/config/plan", big)
	// Should be 400 (bad JSON / oversized), not 500 or 200.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("oversized body status = %d, want 400", rr.Code)
	}
}

func TestAPINoCORSByDefault(t *testing.T) {
	s := newTestServer(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	// CORS headers must NOT be present by default (no wildcard CORS).
	for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Headers"} {
		if v := rr.Header().Get(h); v != "" {
			t.Errorf("CORS header %q = %q — wildcard CORS must not be enabled", h, v)
		}
	}
}

// TestAPIPathTraveralID rejects encoded dot-dot in server IDs.
func TestAPIPathTraversalServerID(t *testing.T) {
	s := newTestServer(nil)
	// URL path with encoded %2e%2e must not resolve to a valid server.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers/%2e%2e/metrics", nil)
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	// Should be 400 or 404, never 200.
	if rr.Code == http.StatusOK {
		t.Errorf("encoded dot-dot returned 200: %s", rr.Body.String())
	}
}

// TestAPIMethodNotAllowed verifies that PUT/PATCH/DELETE are rejected.
func TestAPIMethodNotAllowed(t *testing.T) {
	s := newTestServer(nil)
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/overview", nil)
		rr := httptest.NewRecorder()
		s.Router().ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/v1/overview status = %d, want 405", method, rr.Code)
		}
	}
}

// --- UI smoke test ---

func TestUIIndexContainsExpectedContent(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("UI status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	// Must contain the read-only banner (production + fixture deployments).
	for _, expected := range []string{
		"Read-only mode",
		"No secrets are displayed",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("UI index missing expected text %q", expected)
		}
	}
	// Must NOT contain external URLs or CDN references.
	for _, bad := range []string{
		"https://cdn.", "http://fonts.", "<script src=\"http",
		"googleapis.com", "unpkg.com", "cdn.",
	} {
		if strings.Contains(body, bad) {
			t.Errorf("UI index contains external reference %q — must be self-contained", bad)
		}
	}
	// Must reference the embedded JS (which in turn calls /api/v1). The
	// asset references may be absolute ("/static/...") in loopback mode or
	// relative ("static/...") so the same embedded bundle works under the
	// server-hosted TLS BasePath prefix; accept either form.
	if !strings.Contains(body, "static/app.js") {
		t.Error("UI index does not reference embedded app.js")
	}
	if !strings.Contains(body, "static/style.css") {
		t.Error("UI index does not reference embedded style.css")
	}
}

func TestUIAppJSReferencesAPI(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/static/app.js", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("app.js status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	// The JS must call the versioned API paths and must not load remote scripts.
	for _, expected := range []string{"/api/v1", "config/plan", "DRY-RUN", "disabled"} {
		if !strings.Contains(body, expected) {
			t.Errorf("app.js missing reference %q", expected)
		}
	}
	for _, bad := range []string{"https://cdn.", "http://fonts.", "googleapis.com"} {
		if strings.Contains(body, bad) {
			t.Errorf("app.js contains external reference %q", bad)
		}
	}
}

func TestUIStaticAssetsServe(t *testing.T) {
	s := newTestServer(nil)
	for _, asset := range []string{"/static/style.css", "/static/app.js"} {
		rr := doRequest(t, s, http.MethodGet, asset, "")
		if rr.Code != http.StatusOK {
			t.Errorf("asset %s status = %d, want 200", asset, rr.Code)
		}
	}
}

func TestUIUnknownPath404(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/static/nonexistent.js", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("unknown asset status = %d, want 404", rr.Code)
	}
}

// --- Concurrency / race test ---

func TestCacheConcurrentRefresh(t *testing.T) {
	cfg := DefaultConfig()
	cache := NewCache(cfg)
	// Use a fixed Now function to avoid real-time races in assertions.
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cache.SetNowFn(func() time.Time { return fixed })

	ctx := context.Background()
	// Run 100 concurrent refreshes.
	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			cache.Refresh(ctx)
			_ = cache.RefreshServer(ctx, "iran")
			_, _ = cache.Snapshot("iran")
			_ = cache.RatesFor("iran")
			_ = cache.AllSnapshots()
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
}

// --- Bearer auth test ---

func TestBearerAuthRejectsInvalidToken(t *testing.T) {
	cfg := DefaultConfig()
	cache := NewCache(cfg)
	audit := NewAuditLog(cfg.MaxAudit)
	bearer := NewBearerTokenAuthenticator("test-token-1234")
	s := NewServer(cfg, cache, audit, nil, bearer)

	// No token: must be rejected.
	rr := doRequest(t, s, http.MethodGet, "/api/v1/health", "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no token status = %d, want 401", rr.Code)
	}

	// Wrong token: must be rejected.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr2 := httptest.NewRecorder()
	s.Router().ServeHTTP(rr2, req)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("wrong token status = %d, want 401", rr2.Code)
	}

	// Correct token: must pass.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req2.Header.Set("Authorization", "Bearer test-token-1234")
	rr3 := httptest.NewRecorder()
	s.Router().ServeHTTP(rr3, req2)
	if rr3.Code != http.StatusOK {
		t.Errorf("correct token status = %d, want 200", rr3.Code)
	}
}

// TestNilMutatorNeverMutates verifies the nil mutator always returns an error
// and records its attempts.
func TestNilMutatorNeverMutates(t *testing.T) {
	m := NewNilMutator()
	ctx := context.Background()
	if err := m.ApplyPlan(ctx, "iran", "plan-1"); err == nil {
		t.Fatal("nil mutator must return an error")
	}
	if m.Attempts() != 1 {
		t.Errorf("Attempts() = %d, want 1", m.Attempts())
	}
}

// --- plan store concurrency / race tests ---

// TestServerPlanStoreConcurrent verifies that concurrent storePlan/getPlan
// calls do not race. Run with -race to detect data races.
func TestServerPlanStoreConcurrent(t *testing.T) {
	cfg := DefaultConfig()
	cache := NewCache(cfg)
	audit := NewAuditLog(cfg.MaxAudit)
	s := NewServer(cfg, cache, audit, nil, nil)

	// Inserting more plans than maxStoredPlans makes eviction part of the
	// contract, so a plan may legitimately be gone by the time another
	// goroutine reads it. The guarantees under concurrency are: no data race
	// (run with -race), no panic, and the stored map never exceeds the cap.
	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			planID := fmt.Sprintf("conc-plan-%d", idx)
			s.storePlan(&PlanResult{PlanID: planID, ServerID: "iran"})
			_, _ = s.getPlan(planID)
		}(i)
	}
	wg.Wait()

	s.planMu.RLock()
	stored := len(s.plans)
	s.planMu.RUnlock()
	if stored > maxStoredPlans {
		t.Errorf("stored %d plans, cap is %d", stored, maxStoredPlans)
	}
}

// TestServerPlanStoreCapEviction verifies the hard cap keeps at most
// maxStoredPlans entries. Since rapid insertion makes individual evictions
// non-deterministic (same-instant timestamps), the test asserts the invariant
// that matters: the map never exceeds the cap.
func TestServerPlanStoreCapEviction(t *testing.T) {
	cfg := DefaultConfig()
	cache := NewCache(cfg)
	audit := NewAuditLog(cfg.MaxAudit)
	s := NewServer(cfg, cache, audit, nil, nil)

	// Insert more plans than the cap allows.
	for i := 0; i < maxStoredPlans+50; i++ {
		s.storePlan(&PlanResult{PlanID: fmt.Sprintf("cap-plan-%d", i), ServerID: "iran"})
	}

	// After eviction the store must hold exactly maxStoredPlans entries.
	s.planMu.RLock()
	got := len(s.plans)
	s.planMu.RUnlock()
	if got != maxStoredPlans {
		t.Errorf("plan store holds %d entries, want exactly %d (hard cap)", got, maxStoredPlans)
	}

	// The last inserted plan must be present (it was just added).
	if _, ok := s.getPlan(fmt.Sprintf("cap-plan-%d", maxStoredPlans+49)); !ok {
		t.Error("most-recently-inserted plan should be present")
	}
}

// TestServerPlanStoreExpiry verifies plans older than planTTL are treated
// as absent.
func TestServerPlanStoreExpiry(t *testing.T) {
	cfg := DefaultConfig()
	cache := NewCache(cfg)
	audit := NewAuditLog(cfg.MaxAudit)
	s := NewServer(cfg, cache, audit, nil, nil)

	planID := "expiry-test"
	s.storePlan(&PlanResult{PlanID: planID, ServerID: "iran"})
	// Backdate the stored plan beyond the TTL.
	s.planMu.Lock()
	s.planTimes[planID] = time.Now().Add(-2 * time.Hour)
	s.planMu.Unlock()

	if _, ok := s.getPlan(planID); ok {
		t.Error("plan older than planTTL should be treated as absent")
	}
}

// TestServerSummaryRoleFallback verifies that buildSummary no longer falls
// back to ServerID when the config lookup misses.
func TestServerSummaryRoleFallback(t *testing.T) {
	cfg := DefaultConfig()
	cache := NewCache(cfg)
	audit := NewAuditLog(cfg.MaxAudit)
	s := NewServer(cfg, cache, audit, nil, nil)

	// A snapshot for a server ID not in the config should have Role == "".
	snap := &ServerSnapshot{ServerID: "unknown-server", Status: Fresh, CollectedAt: time.Now()}
	summary := s.buildSummary(snap)
	if summary.Role != "" {
		t.Errorf("summary.Role = %q for unknown server; want empty (no fallback to ServerID)", summary.Role)
	}
	if summary.ID != "unknown-server" {
		t.Errorf("summary.ID = %q, want unknown-server", summary.ID)
	}
}

// TestServerSummaryRoleFromConfig verifies that a known server gets its role
// from the config.
func TestServerSummaryRoleFromConfig(t *testing.T) {
	cfg := DefaultConfig()
	cache := NewCache(cfg)
	audit := NewAuditLog(cfg.MaxAudit)
	s := NewServer(cfg, cache, audit, nil, nil)

	snap := &ServerSnapshot{ServerID: "iran", Status: Fresh, CollectedAt: time.Now()}
	summary := s.buildSummary(snap)
	if summary.Role != "iran" {
		t.Errorf("summary.Role = %q for iran; want iran", summary.Role)
	}
	if summary.Name != "Iran Splitter" {
		t.Errorf("summary.Name = %q; want Iran Splitter", summary.Name)
	}
}

// --- UI asset assertion: verify the embedded app.js renders the new fields ---

func TestUIAppJSRendersNewFields(t *testing.T) {
	s := newTestServer(nil)
	rr := doRequest(t, s, http.MethodGet, "/static/app.js", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("app.js status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, expected := range []string{
		"services", "listeners", "memoryMB", "diskBytes", "uptimeSec",
		"mainPid", "enabled", "errors",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("app.js does not render field %q", expected)
		}
	}
}

// --- validateListenAddr tests ---

func TestValidateListenAddr(t *testing.T) {
	good := []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"}
	for _, addr := range good {
		if err := validateListenAddr(addr); err != nil {
			t.Errorf("validateListenAddr(%q) = %v, want nil", addr, err)
		}
	}
	bad := []string{"0.0.0.0:8080", "192.168.1.1:8080", "example.com:8080"}
	for _, addr := range bad {
		if err := validateListenAddr(addr); err == nil {
			t.Errorf("validateListenAddr(%q) = nil, want error", addr)
		}
	}
}

// TestServerListenAddrRefused confirms a non-loopback address fails at ListenAndServe.
func TestServerListenAddrRefused(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "0.0.0.0:8080"
	cache := NewCache(cfg)
	audit := NewAuditLog(cfg.MaxAudit)
	s := NewServer(cfg, cache, audit, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := s.ListenAndServe(ctx); err == nil {
		t.Error("ListenAndServe with non-loopback address should fail")
	}
}
