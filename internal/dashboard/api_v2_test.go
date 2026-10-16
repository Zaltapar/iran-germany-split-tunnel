package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// v2TestBasePath is the 32-hex prefix used by secureTestConfig.
const v2TestBasePath = "00112233445566778899aabbccddeeff"

// v2GETPaths lists every read-only v2 route, used by the shape, auth, and
// read-only tests.
var v2GETPaths = []string{
	"/api/v2/overview",
	"/api/v2/hosts",
	"/api/v2/carriers",
	"/api/v2/outbounds",
	"/api/v2/routing",
	"/api/v2/config",
	"/api/v2/events",
	"/api/v2/timeseries",
	"/api/v2/schema",
	"/api/v2/schema/outbound",
	"/api/v2/schema/routing-rule",
	"/api/v2/schema/routing-policy",
	"/api/v2/validate/outbound",
}

// funcCollector adapts a closure to the Collector interface for tests.
type funcCollector func(ctx context.Context, cfg ServerConfig) (*ServerSnapshot, error)

func (f funcCollector) Collect(ctx context.Context, cfg ServerConfig) (*ServerSnapshot, error) {
	return f(ctx, cfg)
}

// v2TLSServer builds a TLS-mode server (basePath, security headers) with the
// same HTTP Basic authenticator production uses (user "admin").
func v2TLSServer(t *testing.T, cfg *DashboardConfig) (*Server, string) {
	t.Helper()
	if cfg == nil {
		cfg = secureTestConfig()
	}
	auth := newBasicForTest(t, "admin", "secret-pass")
	s := NewTLSServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, auth)
	return s, "/" + cfg.TLS.BasePath + "/"
}

func v2Do(h http.Handler, method, path string, basic bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if basic {
		req.SetBasicAuth("admin", "secret-pass")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func v2DecodeObject(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not a JSON object: %v; body=%s", err, rr.Body.String())
	}
	return out
}

// --- auth, basePath, headers ----------------------------------------------

func TestV2RequiresBasicAuth(t *testing.T) {
	s, bp := v2TLSServer(t, nil)
	h := s.Router()
	for _, p := range v2GETPaths {
		path := bp + strings.TrimPrefix(p, "/")
		if rr := v2Do(h, http.MethodGet, path, false); rr.Code != http.StatusUnauthorized {
			t.Errorf("%s without auth: status %d, want 401", p, rr.Code)
		}
		if rr := v2Do(h, http.MethodGet, path, true); rr.Code != http.StatusOK {
			t.Errorf("%s with auth: status %d, want 200; body=%s", p, rr.Code, rr.Body.String())
		}
	}
}

func TestV2OutsideBasePathIs404(t *testing.T) {
	s, _ := v2TLSServer(t, nil)
	h := s.Router()
	for _, p := range v2GETPaths {
		if rr := v2Do(h, http.MethodGet, p, true); rr.Code != http.StatusNotFound {
			t.Errorf("%s outside basePath: status %d, want 404", p, rr.Code)
		}
	}
}

func TestV2SecurityHeadersPresent(t *testing.T) {
	s, bp := v2TLSServer(t, nil)
	rr := v2Do(s.Router(), http.MethodGet, bp+"api/v2/overview", true)
	want := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
	}
	for k, v := range want {
		if got := rr.Header().Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// --- read-only guarantee --------------------------------------------------

func TestV2IsReadOnly(t *testing.T) {
	s, bp := v2TLSServer(t, nil)
	h := s.Router()
	nm, ok := s.mutator.(*nilMutator)
	if !ok {
		t.Fatalf("default mutator is %T, want *nilMutator", s.mutator)
	}
	for _, p := range v2GETPaths {
		path := bp + strings.TrimPrefix(p, "/")
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			rr := v2Do(h, m, path, true)
			if rr.Code != http.StatusMethodNotAllowed && rr.Code != http.StatusForbidden {
				t.Errorf("%s %s: status %d, want 405 or 403", m, p, rr.Code)
			}
		}
	}
	if n := nm.Attempts(); n != 0 {
		t.Errorf("v2 requests reached the mutator %d time(s); want 0", n)
	}
}

func TestV2UnknownEndpoint404(t *testing.T) {
	s, bp := v2TLSServer(t, nil)
	for _, p := range []string{"api/v2/nope", "api/v2/overview/extra", "api/v2/schema/unknown", "api/v2/validate/unknown"} {
		if rr := v2Do(s.Router(), http.MethodGet, bp+p, true); rr.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, rr.Code)
		}
	}
}

// --- shape ----------------------------------------------------------------

func TestV2ResponseShapes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Outbounds = []OutboundConfig{{
		Name: "de-reality", Protocol: "vless-reality", Port: 443,
		ServerName: "www.example.com", Transport: "tcp", Enabled: true,
	}}
	s := newTestServer(cfg)
	want := map[string][]string{
		"/api/v2/overview":          {"meta", "counts", "routingMode", "hosts", "notes"},
		"/api/v2/hosts":             {"meta", "hosts"},
		"/api/v2/carriers":          {"meta", "carriers", "notes"},
		"/api/v2/outbounds":         {"meta", "outbounds"},
		"/api/v2/routing":           {"source", "declared", "liveRoutingCollected", "schema", "valid", "errors", "policy"},
		"/api/v2/config":            {"meta", "values", "notes"},
		"/api/v2/events":            {"meta", "events"},
		"/api/v2/timeseries":        {"meta", "series"},
		"/api/v2/validate/outbound": {"concept", "method", "status", "applied", "message", "schema", "fieldCount"},
	}
	for path, keys := range want {
		rr := doRequest(t, s, http.MethodGet, path, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d; body=%s", path, rr.Code, rr.Body.String())
		}
		obj := v2DecodeObject(t, rr)
		for _, k := range keys {
			if _, ok := obj[k]; !ok {
				t.Errorf("%s: missing key %q", path, k)
			}
		}
	}

	// Overview carries explicit gap reporting, never fabricated zeros.
	ov := v2DecodeObject(t, doRequest(t, s, http.MethodGet, "/api/v2/overview", ""))
	hosts, _ := ov["hosts"].([]any)
	if len(hosts) != 2 {
		t.Fatalf("overview hosts = %d, want 2", len(hosts))
	}
	h0 := hosts[0].(map[string]any)
	missing, _ := h0["missingMetrics"].([]any)
	if len(missing) == 0 || h0["cpuPercent"] != nil {
		t.Errorf("host must report cpuPercent as null with missingMetrics listed; got cpu=%v missing=%v", h0["cpuPercent"], missing)
	}

	// Outbound view: public identity only, validation present.
	ob := v2DecodeObject(t, doRequest(t, s, http.MethodGet, "/api/v2/outbounds", ""))
	list, _ := ob["outbounds"].([]any)
	if len(list) != 1 {
		t.Fatalf("outbounds = %d, want 1", len(list))
	}
	o0 := list[0].(map[string]any)
	if o0["name"] != "de-reality" || o0["serverName"] != "www.example.com" || o0["port"] != float64(443) {
		t.Errorf("outbound fields wrong: %+v", o0)
	}
	if v, ok := o0["validation"].([]any); !ok || len(v) != 0 {
		t.Errorf("valid outbound must have empty validation array, got %v", o0["validation"])
	}

	// Routing with no declared policy: explicit empty state, valid.
	rt := v2DecodeObject(t, doRequest(t, s, http.MethodGet, "/api/v2/routing", ""))
	if rt["declared"] != false || rt["valid"] != true {
		t.Errorf("undeclared routing: declared=%v valid=%v, want false/true", rt["declared"], rt["valid"])
	}
	if errs, ok := rt["errors"].([]any); !ok || errs == nil {
		t.Errorf("routing errors must be an array, got %v", rt["errors"])
	}

	// Schema list and per-concept schema.
	var schemas []map[string]any
	rr := doRequest(t, s, http.MethodGet, "/api/v2/schema", "")
	if err := json.Unmarshal(rr.Body.Bytes(), &schemas); err != nil || len(schemas) != 3 {
		t.Fatalf("schema list: err=%v len=%d", err, len(schemas))
	}
	for _, sc := range schemas {
		if sc["editable"] != false || sc["editDisabledReason"] != "editing lands in the next phase" {
			t.Errorf("concept %v must be non-editable with the next-phase reason: %+v", sc["concept"], sc)
		}
	}
}

func TestV2ValidateEndpointIsStub(t *testing.T) {
	s := newTestServer(nil)
	obj := v2DecodeObject(t, doRequest(t, s, http.MethodGet, "/api/v2/validate/outbound", ""))
	if obj["status"] != "stub" || obj["applied"] != false {
		t.Errorf("validate stub: status=%v applied=%v, want stub/false", obj["status"], obj["applied"])
	}
	if rr := doRequest(t, s, http.MethodPost, "/api/v2/validate/outbound", `{"name":"x"}`); rr.Code == http.StatusOK {
		t.Errorf("POST to validate stub must not succeed; got 200")
	}
}

// --- redaction ------------------------------------------------------------

func TestV2ResponsesContainNoSecrets(t *testing.T) {
	cfg := secureTestConfig()
	cfg.Servers[0].MetricsURL = "https://operator:hunter2@203.0.113.9:9101/tok123/metrics"
	cfg.Servers[0].Address = "203.0.113.9"
	cfg.Outbounds = []OutboundConfig{{
		Name: "de-reality", Protocol: "vless-reality", Port: 443,
		ServerName: "www.example.com", Transport: "tcp", Enabled: true,
	}}
	s, bp := v2TLSServer(t, cfg)
	s.audit.Add(AuditEvent{EventType: "apply_failed", Detail: "SPLIT_SECRET=topsecret123 failed"})
	h := s.Router()

	forbidden := []string{
		"hunter2", "tok123", "topsecret123", "secret-pass", v2TestBasePath,
		"/etc/split-tunnel", "cert.pem", "key.pem", "PRIVATE KEY", "operator:",
	}
	for _, p := range v2GETPaths {
		rr := v2Do(h, http.MethodGet, bp+strings.TrimPrefix(p, "/"), true)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d", p, rr.Code)
		}
		body := rr.Body.String()
		for _, bad := range forbidden {
			if strings.Contains(body, bad) {
				t.Errorf("%s leaked %q", p, bad)
			}
		}
	}
	// The non-secret endpoint host is still shown.
	cfgResp := v2Do(h, http.MethodGet, bp+"api/v2/config", true).Body.String()
	if !strings.Contains(cfgResp, "https://203.0.113.9:9101") {
		t.Errorf("config should show the scheme://host:port endpoint label")
	}
}

// --- collectors, carriers, timeseries, events ------------------------------

func TestV2CarriersHistoryAndMissingCollector(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HistoryPoints = 16
	cache := NewCache(cfg)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	cache.SetNowFn(func() time.Time { return now })

	step := 0
	cache.coll["iran"] = funcCollector(func(_ context.Context, sc ServerConfig) (*ServerSnapshot, error) {
		step++
		at := now
		carrier := map[string]string{"carrier": "carrier-a"}
		return &ServerSnapshot{
			ServerID: sc.ID, Status: Fresh, CollectedAt: at,
			Metrics: &ParsedMetrics{CollectedAt: at, Samples: []MetricSample{
				{Name: "active_sessions", Value: 3},
				{Name: "total_bytes_up", Value: float64(step) * 10 * histMiB},
				{Name: "carrier_health_state", Labels: carrier, Value: 1},
				{Name: "carrier_health_score", Labels: carrier, Value: 0.8},
				{Name: "carrier_health_goodput_mibps", Labels: carrier, Value: 2.5},
				{Name: "carrier_health_success_ratio", Labels: carrier, Value: 0.95},
				{Name: "carrier_health_eligible", Labels: carrier, Value: 1},
				{Name: "carrier_health_gate_reason", Labels: carrier, Value: 0},
			}},
		}, nil
	})
	cache.coll["germany"] = funcCollector(func(_ context.Context, sc ServerConfig) (*ServerSnapshot, error) {
		return &ServerSnapshot{
			ServerID: sc.ID, Status: Unsupported, CollectedAt: now,
			Errors: []string{"no metrics URL configured for server germany"},
		}, nil
	})

	cache.Refresh(context.Background())
	now = now.Add(10 * time.Second)
	cache.Refresh(context.Background())

	s := NewServer(cfg, cache, NewAuditLog(cfg.MaxAudit), nil, nil)

	car := v2DecodeObject(t, doRequest(t, s, http.MethodGet, "/api/v2/carriers", ""))
	list, _ := car["carriers"].([]any)
	if len(list) != 1 {
		t.Fatalf("carriers = %d, want 1", len(list))
	}
	c0 := list[0].(map[string]any)
	if c0["state"] != "active" || c0["score"] != 0.8 || c0["eligible"] != true {
		t.Errorf("carrier fields wrong: %+v", c0)
	}
	if u, _ := c0["unavailable"].([]any); len(u) == 0 {
		t.Errorf("carrier must list unavailable measurements explicitly")
	}

	ov := v2DecodeObject(t, doRequest(t, s, http.MethodGet, "/api/v2/overview", ""))
	counts := ov["counts"].(map[string]any)
	if counts["carriers"] != float64(1) || counts["carriersEligible"] != float64(1) || counts["hostsCollectorMissing"] != float64(1) {
		t.Errorf("overview counts wrong: %+v", counts)
	}

	hostsObj := v2DecodeObject(t, doRequest(t, s, http.MethodGet, "/api/v2/hosts", ""))
	hs := hostsObj["hosts"].([]any)
	germany := hs[1].(map[string]any)
	if germany["collectorMissing"] != true || germany["status"] != "unsupported" {
		t.Errorf("germany must surface a missing collector explicitly: %+v", germany)
	}

	ev := v2DecodeObject(t, doRequest(t, s, http.MethodGet, "/api/v2/events", ""))
	found := false
	for _, e := range ev["events"].([]any) {
		if e.(map[string]any)["type"] == "collector_missing" {
			found = true
		}
	}
	if !found {
		t.Error("events must include a collector_missing entry for germany")
	}

	// Rate history: first refresh has no window; second yields 1 MiB/s.
	ts := v2DecodeObject(t, doRequest(t, s, http.MethodGet,
		"/api/v2/timeseries?series=iran.carrier.carrier-a.score,iran.up_mibps&limit=10", ""))
	series := ts["series"].([]any)
	score := series[0].(map[string]any)
	if score["found"] != true || len(score["points"].([]any)) != 2 {
		t.Errorf("carrier score series: %+v", score)
	}
	up := series[1].(map[string]any)
	pts := up["points"].([]any)
	if len(pts) != 1 {
		t.Fatalf("up_mibps points = %d, want 1", len(pts))
	}
	if v := pts[0].(map[string]any)["v"].(float64); v < 0.999 || v > 1.001 {
		t.Errorf("up_mibps = %v, want ~1.0", v)
	}
}

func TestV2TimeseriesBoundsAndValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HistoryPoints = 5
	s := newTestServer(cfg)
	hist := s.cache.History()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 12; i++ {
		hist.Record("iran.sessions", base.Add(time.Duration(i)*time.Second), float64(i))
	}

	obj := v2DecodeObject(t, doRequest(t, s, http.MethodGet, "/api/v2/timeseries?series=iran.sessions&limit=100", ""))
	entry := obj["series"].([]any)[0].(map[string]any)
	pts := entry["points"].([]any)
	if len(pts) != 5 {
		t.Fatalf("retained %d points, want 5 (ring bound)", len(pts))
	}
	if first := pts[0].(map[string]any)["v"].(float64); first != 7 {
		t.Errorf("oldest retained = %v, want 7", first)
	}
	if last := pts[4].(map[string]any)["v"].(float64); last != 11 {
		t.Errorf("newest retained = %v, want 11", last)
	}

	for _, bad := range []string{
		"/api/v2/timeseries?series=bad%20key",
		"/api/v2/timeseries?series=a.b&limit=0",
		"/api/v2/timeseries?series=a.b&limit=-3",
		"/api/v2/timeseries?series=a.b&limit=abc",
		"/api/v2/timeseries?series=" + strings.TrimSuffix(strings.Repeat("a.b,", 17), ","),
	} {
		if rr := doRequest(t, s, http.MethodGet, bad, ""); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, rr.Code)
		}
	}
	// Unknown but well-formed key: 200 with found=false, never created.
	unk := v2DecodeObject(t, doRequest(t, s, http.MethodGet, "/api/v2/timeseries?series=nobody.here", ""))
	ent := unk["series"].([]any)[0].(map[string]any)
	if ent["found"] != false {
		t.Errorf("unknown series reported found=%v", ent["found"])
	}
	if hist.Has("nobody.here") {
		t.Error("reading an unknown series must not create it")
	}
}

func TestV2EventsLimitAndRedaction(t *testing.T) {
	cfg := DefaultConfig()
	s := newTestServer(cfg)
	s.audit.Add(AuditEvent{EventType: "apply_blocked", Detail: "password=hunter2 blocked"})
	rr := doRequest(t, s, http.MethodGet, "/api/v2/events?limit=0", "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("limit=0: status %d, want 400", rr.Code)
	}
	rr = doRequest(t, s, http.MethodGet, "/api/v2/events?limit=5", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("events: status %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "hunter2") {
		t.Error("events leaked an audit detail secret")
	}
}
