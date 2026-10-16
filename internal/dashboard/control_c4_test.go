// control_c4_test.go — the dashboard's C4 forwarding plane
// (plans/dashboard-control-design.md C4 requirements 5, 6, 7): the
// per-capability flag gating, the read-only schema that always works, the
// apply refused-when-flag-off guarantee (503 + a clear code, agent NOT
// called), the restart warning surfaced on a successful apply, the CSRF
// + confirm-token gates, the revisions/audit read-forwarding, and the
// invariant that NO secret value ever appears in any C4 response.
package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// c4TestServer builds a C4-ready server with the given per-capability flags
// and a fake agent wired, so the whole mapping layer is testable without a
// host socket.
func c4TestServer(t *testing.T, applyEnabled bool, flags c4ControlFlags) (*Server, *fakeC2Agent) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{
		ApplyEnabled: applyEnabled,
		SocketPath:   "/run/split-tunnel-ctl/control.sock",
		C3Flags:      c3ControlFlags{},
		C4Flags:      flags,
	}
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	fake := &fakeC2Agent{}
	s.SetControlAgent(fake)
	return s, fake
}

// c4Post posts to a C4 endpoint with the required headers.
func c4Post(t *testing.T, s *Server, path, body string, withControlHeader bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	if withControlHeader {
		req.Header.Set(c2ControlHeader, "1")
	}
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	return rr
}

// c4Get performs a GET on a C4 read-only endpoint.
func c4Get(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	return rr
}

// assertNoSecretValues scans a C4 response body for the closed secret
// markers: no raw key material, no secret-named field names, no basePath.
// (SNI / target-addr-policy / SOCKS allowlist values are operator config
// and MAY appear; the raw SOCKS allowlist is fingerprinted by the agent,
// so it must not appear here either.)
func assertNoSecretValues(t *testing.T, body string) {
	t.Helper()
	forbidden := []string{
		"SPLIT_SECRET",
		"SPLIT_SOCKS_USER",
		"SPLIT_SOCKS_PASS",
		"baseUrl",
		"basepath",
		`"privateKey"`,
		`"keyMaterial"`,
	}
	for _, f := range forbidden {
		if strings.Contains(body, f) {
			t.Fatalf("C4 response leaked a secret marker %q:\n%s", f, body)
		}
	}
}

// --- schema is always available (read-only) and public-field only ---
func TestC4RoutingSchemaAlwaysAvailableAndReadonly(t *testing.T) {
	s, _ := c4TestServer(t, true, c4ControlFlags{}) // C4 flags OFF
	rr := c4Get(t, s, "/api/v2/schema/routing-plane")
	if rr.Code != http.StatusOK {
		t.Fatalf("routing-plane schema status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var sc ConceptSchema
	if err := json.Unmarshal(rr.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Concept != c4ConceptRoutingPlane {
		t.Fatalf("concept = %q, want %q", sc.Concept, c4ConceptRoutingPlane)
	}
	if sc.Editable {
		t.Error("flag off: routing schema.Editable must be false (read-only)")
	}
	if sc.Status != "read-only" {
		t.Errorf("flag off: routing schema.Status = %q, want read-only", sc.Status)
	}
	if sc.EditDisabledReason == "" {
		t.Error("flag off: routing schema.EditDisabledReason must be set (the UI tooltip)")
	}
	assertNoSecretValues(t, rr.Body.String())
}

func TestC4MultiCarrierSchemaAlwaysAvailableAndReadonly(t *testing.T) {
	s, _ := c4TestServer(t, true, c4ControlFlags{})
	rr := c4Get(t, s, "/api/v2/schema/multi-carrier-control")
	if rr.Code != http.StatusOK {
		t.Fatalf("multi-carrier schema status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var sc ConceptSchema
	if err := json.Unmarshal(rr.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Concept != c4ConceptMultiCarrier {
		t.Fatalf("concept = %q, want %q", sc.Concept, c4ConceptMultiCarrier)
	}
	if sc.Editable || sc.Status != "read-only" {
		t.Errorf("flag off: multi-carrier schema must be read-only (Editable=%v Status=%q)", sc.Editable, sc.Status)
	}
	assertNoSecretValues(t, rr.Body.String())
}

// --- schema: flag on → editable ---
func TestC4SchemasEditableWhenFlagsOn(t *testing.T) {
	s, _ := c4TestServer(t, true, c4ControlFlags{RoutingApply: true, MultiCarrierApply: true})
	for concept := range map[string]bool{c4ConceptRoutingPlane: true, c4ConceptMultiCarrier: true} {
		rr := c4Get(t, s, "/api/v2/schema/"+concept)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s schema status = %d, want 200; body=%s", concept, rr.Code, rr.Body.String())
		}
		var sc ConceptSchema
		if err := json.Unmarshal(rr.Body.Bytes(), &sc); err != nil {
			t.Fatal(err)
		}
		if !sc.Editable || sc.Status != "editable" {
			t.Errorf("%s schema not editable when its flag is on (Editable=%v Status=%q)", concept, sc.Editable, sc.Status)
		}
	}
}

// --- schema: unknown concept → 404 ---
func TestC4SchemaUnknownConcept404s(t *testing.T) {
	s, _ := c4TestServer(t, true, c4ControlFlags{})
	rr := c4Get(t, s, "/api/v2/schema/bogus-c4-concept")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown C4 schema status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

// --- routing apply refused when the flag is off → 503 + code, agent NOT called ---
func TestC4RoutingApplyRefusedWhenFlagOff(t *testing.T) {
	s, fake := c4TestServer(t, true, c4ControlFlags{}) // C4 routing flag OFF
	rr := c4Post(t, s, "/api/v2/changes/germany/routing-apply",
		`{"role":"germany","set":{"`+config.EnvTargetAddrPolicy+`":"ipv4-only"},"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("routing flag off status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), c4RoutingFlagOffCode) {
		t.Fatalf("503 body must name %q: %s", c4RoutingFlagOffCode, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite the routing flag being off: %v", fake.calls)
	}
}

// --- multi-carrier apply refused when the flag is off → 503 + code, agent NOT called ---
func TestC4MultiCarrierApplyRefusedWhenFlagOff(t *testing.T) {
	s, fake := c4TestServer(t, true, c4ControlFlags{}) // C4 MC flag OFF
	rr := c4Post(t, s, "/api/v2/changes/germany/multicarrier-apply",
		`{"role":"germany","set":{"`+config.EnvMultiCarrierEnabled+`":"true"},"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("MC flag off status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), c4MultiCarrierFlagOffCode) {
		t.Fatalf("503 body must name %q: %s", c4MultiCarrierFlagOffCode, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite the MC flag being off: %v", fake.calls)
	}
}

// --- routing apply success when the flag is on: restart warning surfaced, agent called ---
func TestC4RoutingApplySuccessSurfacesRestartWarning(t *testing.T) {
	s, fake := c4TestServer(t, true, c4ControlFlags{RoutingApply: true})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{
		"outcome": "committed", "revision": "r-1", "prevRevision": "r-0",
	}}
	rr := c4Post(t, s, "/api/v2/changes/germany/routing-apply",
		`{"role":"germany","set":{"`+config.EnvTargetAddrPolicy+`":"prefer-ipv4"},"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("routing apply status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 1 || fake.calls[0] != "c4-routing-apply" {
		t.Fatalf("agent ops = %v, want [c4-routing-apply]", fake.calls)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "restartWarning") || !strings.Contains(body, "restarted") {
		t.Fatalf("routing apply must surface a restart warning: %s", body)
	}
	var resp c4ApplyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Outcome != "committed" || !resp.RestartRequired {
		t.Fatalf("response = %+v", resp)
	}
	assertNoSecretValues(t, body)
}

// --- multi-carrier apply success surfaces the xray restart + peer note ---
func TestC4MultiCarrierApplySuccessSurfacesXrayRestartAndPeerNote(t *testing.T) {
	s, fake := c4TestServer(t, true, c4ControlFlags{MultiCarrierApply: true})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{
		"outcome": "committed", "revision": "r-2", "prevRevision": "r-1",
		"xrayRestarted": true, "peerChangeRequired": "stage a Blob B export and carry it to the Iran host",
	}}
	rr := c4Post(t, s, "/api/v2/changes/germany/multicarrier-apply",
		`{"role":"germany","set":{"`+config.EnvMultiCarrierEnabled+`":"true","`+config.EnvDownListen2+`":"127.0.0.1:9003","`+config.EnvDownSNI2+`":"second.example.com"},"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("MC apply status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp c4ApplyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.XrayRestarted {
		t.Fatalf("xrayRestarted must be surfaced: %+v", resp)
	}
	if !strings.Contains(resp.PeerChangeRequired, "Iran host") {
		t.Fatalf("peerChangeRequired note missing: %+v", resp)
	}
	assertNoSecretValues(t, rr.Body.String())
}

// --- confirm token required → 400, agent NOT called ---
func TestC4ApplyRequiresConfirmToken(t *testing.T) {
	s, fake := c4TestServer(t, true, c4ControlFlags{RoutingApply: true})
	rr := c4Post(t, s, "/api/v2/changes/germany/routing-apply",
		`{"role":"germany","set":{"`+config.EnvTargetAddrPolicy+`":"ipv4-only"},"confirm":"NOPE"}`, true)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad confirm status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite a 400 confirm: %v", fake.calls)
	}
}

// --- missing control CSRF header → 403, agent NOT called ---
func TestC4ApplyRequiresControlCSRFHeader(t *testing.T) {
	s, fake := c4TestServer(t, true, c4ControlFlags{RoutingApply: true})
	rr := c4Post(t, s, "/api/v2/changes/germany/routing-apply",
		`{"role":"germany","set":{"`+config.EnvTargetAddrPolicy+`":"ipv4-only"},"confirm":"RESTART"}`, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing control header status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite a 403: %v", fake.calls)
	}
}

// --- validate endpoint: read-only, always works even when the flag is off ---
func TestC4ValidateAlwaysAvailableWhenFlagOff(t *testing.T) {
	s, fake := c4TestServer(t, true, c4ControlFlags{}) // routing flag OFF
	fake.result = c2AgentResult{OK: true, Data: map[string]any{
		"valid": true, "errors": []string{}, "restartRequired": true, "diff": []any{},
	}}
	rr := c4Post(t, s, "/api/v2/changes/germany/routing-validate",
		`{"role":"germany","set":{"`+config.EnvTargetAddrPolicy+`":"ipv4-only"}}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("routing validate (flag off) status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 1 || fake.calls[0] != "c4-routing-validate" {
		t.Fatalf("agent ops = %v, want [c4-routing-validate]", fake.calls)
	}
}

// --- the coordinated flag is OFF by default; the web plane must not
//
//	advertise a coordinated apply when it is off (requirement 5) ---
func TestC4CoordinatedFlagDefaultOff(t *testing.T) {
	s, _ := c4TestServer(t, true, c4ControlFlags{})
	if s.c4CoordinatedFlag() {
		t.Fatal("CoordinatedApply must default to false")
	}
	// The 503 refusal code is the closed, documented string.
	if c4CoordinatedFlagOffCode == "" {
		t.Fatal("coordinated flag-off code must be non-empty")
	}
}

// --- revisions / audit read-forwarding keeps working (C2 plane, C4 reuses
//
//	it); the forwarded content is redacted (no secret values) ---
func TestC4RevisionsAndAuditForwardRedacted(t *testing.T) {
	s, fake := c4TestServer(t, true, c4ControlFlags{RoutingApply: true})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{"revisions": []any{
		map[string]any{"id": "r-5", "kind": "routing", "diff": []any{
			map[string]any{"key": "SPLIT_TARGET_ADDR_POLICY", "before": "default", "after": "ipv4-only", "redacted": false},
			map[string]any{"key": "SPLIT_SOCKS_ALLOWED_SOURCES", "before": "(redacted)", "after": "sha256:abc123", "redacted": true},
		}},
	}}}
	rr := c4Get(t, s, "/api/v2/revisions")
	if rr.Code != http.StatusOK {
		t.Fatalf("revisions status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "ipv4-only") {
		t.Fatalf("revisions must carry the (non-secret) routing value: %s", body)
	}
	assertNoSecretValues(t, body)

	fake.result = c2AgentResult{OK: true, Data: map[string]any{"entries": []any{
		map[string]any{"op": "c4-routing-apply", "outcome": "committed", "actor": "web-abcd"},
	}}}
	rr = c4Get(t, s, "/api/v2/audit")
	if rr.Code != http.StatusOK {
		t.Fatalf("audit status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	assertNoSecretValues(t, rr.Body.String())
}
