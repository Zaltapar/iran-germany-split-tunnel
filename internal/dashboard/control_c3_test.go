// control_c3_test.go — the dashboard's C3 forwarding plane (design §4.2,
// §4.3, §8, §12 C3): the per-capability flag gating, the read-only schema
// that always works, the apply refused-when-flag-off guarantee, the restart
// warning surfaced on a successful apply, and the invariant that NO key
// material ever appears in any response (fingerprints only).
package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// c3TestServer builds a C2/C3-ready server with the given C3 per-capability
// flags and a fake agent wired, so the whole mapping layer is testable
// without a host socket.
func c3TestServer(t *testing.T, applyEnabled bool, flags c3ControlFlags) (*Server, *fakeC2Agent) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{
		ApplyEnabled: applyEnabled,
		SocketPath:   "/run/split-tunnel-ctl/control.sock",
		C3Flags:      flags,
	}
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	fake := &fakeC2Agent{}
	s.SetControlAgent(fake)
	return s, fake
}

// c3Post sends a POST to a C3 endpoint with the required headers.
func c3Post(t *testing.T, s *Server, path, body string, withControlHeader bool) *httptest.ResponseRecorder {
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

// c3Get performs a GET on a C3 read-only endpoint.
func c3Get(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	return rr
}

// assertNoKeyMaterial scans a response body for forbidden secret markers.
// Fingerprints (12-hex) are allowed; raw key material and the secret
// field-names are not (design §4.2, §7.5).
func assertNoKeyMaterial(t *testing.T, body string) {
	t.Helper()
	forbidden := []string{
		"privateKey",
		"private_key",
		"SECRET_KEY",
		"keyMaterial",
		"key_material",
		`"key":"`,
	}
	for _, f := range forbidden {
		if strings.Contains(body, f) {
			t.Fatalf("response leaked key material marker %q:\n%s", f, body)
		}
	}
}

// --- schema is public-field only and always available (read-only) ---
func TestC3SchemaAlwaysAvailableAndPublicOnly(t *testing.T) {
	s, _ := c3TestServer(t, false, c3ControlFlags{})
	rr := c3Get(t, s, "/api/v2/schema/germany-inbounds")
	if rr.Code != http.StatusOK {
		t.Fatalf("germany-inbounds schema status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var sc ConceptSchema
	if err := json.Unmarshal(rr.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Concept != c3ConceptGermanyInbounds {
		t.Fatalf("concept = %q, want %q", sc.Concept, c3ConceptGermanyInbounds)
	}
	// With the flag off the schema must advertise read-only + disabled reason.
	if sc.Editable {
		t.Error("flag off: schema.Editable must be false (read-only)")
	}
	if sc.Status != "read-only" {
		t.Errorf("flag off: schema.Status = %q, want read-only", sc.Status)
	}
	if sc.EditDisabledReason == "" {
		t.Error("flag off: schema.EditDisabledReason must be set (the UI tooltip)")
	}
	assertNoKeyMaterial(t, rr.Body.String())

	// The Iran concept works too.
	rr = c3Get(t, s, "/api/v2/schema/iran-inbounds")
	if rr.Code != http.StatusOK {
		t.Fatalf("iran-inbounds schema status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	assertNoKeyMaterial(t, rr.Body.String())
}

// --- schema: flag on → editable ---
func TestC3SchemaEditableWhenFlagOn(t *testing.T) {
	s, _ := c3TestServer(t, true, c3ControlFlags{GermanyInboundsApply: true})
	rr := c3Get(t, s, "/api/v2/schema/germany-inbounds")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var sc ConceptSchema
	if err := json.Unmarshal(rr.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	if !sc.Editable || sc.Status != "editable" {
		t.Fatalf("flag on: schema not editable (Editable=%v Status=%q)", sc.Editable, sc.Status)
	}
}

// --- schema: unknown concept → 404 ---
func TestC3SchemaUnknownConcept404s(t *testing.T) {
	s, _ := c3TestServer(t, true, c3ControlFlags{})
	rr := c3Get(t, s, "/api/v2/schema/bogus-concept")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown schema status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}

// --- apply refused when the per-capability flag is off → 503, agent NOT called ---
func TestC3ApplyRefusedWhenFlagOff(t *testing.T) {
	s, fake := c3TestServer(t, true, c3ControlFlags{}) // C2 apply on, C3 flag OFF
	rr := c3Post(t, s, "/api/v2/changes/germany/inbounds-apply",
		`{"role":"germany","inbounds":[],"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("flag off status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), c3InboundFlagOffError) {
		t.Fatalf("503 body must name %q: %s", c3InboundFlagOffError, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite the C3 flag being off: %v", fake.calls)
	}
}

// --- apply success when the flag is on: restart warning surfaced, no key material ---
func TestC3ApplySuccessSurfacesRestartWarning(t *testing.T) {
	s, fake := c3TestServer(t, true, c3ControlFlags{GermanyInboundsApply: true})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{
		"outcome":            "committed",
		"revision":           "r-4",
		"prevRevision":       "r-3",
		"peerChangeRequired": "blob B staged for the Iran host; import it there before the tunnel reaches steady state",
	}}
	rr := c3Post(t, s, "/api/v2/changes/germany/inbounds-apply",
		`{"role":"germany","inbounds":[],"confirm":"RESTART","reason":"censorship blocked current SNI"}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("flag on status = %d; body=%s", rr.Code, rr.Body.String())
	}
	var resp c3InboundsApplyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Outcome != "committed" || resp.Revision != "r-4" || resp.PrevRevision != "r-3" {
		t.Fatalf("response mismatch: %+v", resp)
	}
	if resp.RestartWarning == "" {
		t.Error("apply response must surface a restart warning (D11)")
	}
	if resp.EstimatedDowntimeSec != 10 {
		t.Errorf("estimatedDowntimeSec = %d, want 10 (D11)", resp.EstimatedDowntimeSec)
	}
	if resp.PeerChangeRequired == "" {
		t.Error("apply response must carry the peer-change-required note (D10)")
	}
	if len(fake.calls) != 1 || fake.calls[0] != "inbounds-apply" {
		t.Fatalf("agent ops = %v, want [inbounds-apply]", fake.calls)
	}
	assertNoKeyMaterial(t, rr.Body.String())
}

// --- apply: bad confirm token → 400, agent NOT called ---
func TestC3ApplyBadConfirm(t *testing.T) {
	s, fake := c3TestServer(t, true, c3ControlFlags{IranInboundsApply: true})
	rr := c3Post(t, s, "/api/v2/changes/iran/inbounds-apply",
		`{"role":"iran","inbounds":[],"confirm":"NO"}`, true)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad confirm status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite a 400 confirm: %v", fake.calls)
	}
}

// --- apply: missing the control CSRF header → 403 ---
func TestC3ApplyMissingControlHeader(t *testing.T) {
	s, fake := c3TestServer(t, true, c3ControlFlags{GermanyInboundsApply: true})
	rr := c3Post(t, s, "/api/v2/changes/germany/inbounds-apply",
		`{"role":"germany","inbounds":[],"confirm":"RESTART"}`, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing header status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite a 403: %v", fake.calls)
	}
}

// --- apply: agent error code → HTTP mapping (validation_failed → 422) ---
func TestC3ApplyAgentErrorCodeMapping(t *testing.T) {
	s, fake := c3TestServer(t, true, c3ControlFlags{GermanyInboundsApply: true})
	fake.result = c2AgentResult{OK: false, Error: &c2AgentError{Code: "validation_failed", Message: "port 8443 reserved"}}
	rr := c3Post(t, s, "/api/v2/changes/germany/inbounds-apply",
		`{"role":"germany","inbounds":[],"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("validation_failed → %d, want 422; body=%s", rr.Code, rr.Body.String())
	}
}

// --- validate is read-only: it works even when the apply flag is off ---
func TestC3ValidateWorksWhenFlagOff(t *testing.T) {
	s, fake := c3TestServer(t, false, c3ControlFlags{})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{}}
	rr := c3Post(t, s, "/api/v2/changes/germany/inbounds-validate",
		`{"role":"germany","inbounds":[{"instance":"main","enabled":true,"port":443,"sni":"example.com","keyRef":"0123456789ab"}]}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("validate with flag off = %d, want 200 (read-only); body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 1 || fake.calls[0] != "inbounds-validate" {
		t.Fatalf("agent ops = %v, want [inbounds-validate]", fake.calls)
	}
	assertNoKeyMaterial(t, rr.Body.String())
}

// --- validate: missing the control header → 403 ---
func TestC3ValidateMissingControlHeader(t *testing.T) {
	s, fake := c3TestServer(t, true, c3ControlFlags{})
	rr := c3Post(t, s, "/api/v2/changes/germany/inbounds-validate", `{"role":"germany","inbounds":[]}`, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("validate missing header status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite a 403: %v", fake.calls)
	}
}

// --- no agent wired → 503 agent_unavailable on both C3 POSTs ---
func TestC3NoAgentWired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{ApplyEnabled: true, C3Flags: c3ControlFlags{GermanyInboundsApply: true}}
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil) // no agent
	rr := c3Post(t, s, "/api/v2/changes/germany/inbounds-apply",
		`{"role":"germany","inbounds":[],"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("apply no-agent status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "agent_unavailable") {
		t.Fatalf("must name agent_unavailable: %s", rr.Body.String())
	}
	rr = c3Post(t, s, "/api/v2/changes/germany/inbounds-validate", `{"role":"germany","inbounds":[]}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("validate no-agent status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
}

// --- revisions/audit forwarding includes C3 inbound changes; no key material ---
func TestC3RevisionsAuditNoKeyMaterial(t *testing.T) {
	s, fake := c3TestServer(t, true, c3ControlFlags{})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{"revisions": []any{
		map[string]any{"id": "r-5", "op": "inbounds-apply", "keyRef": "0123456789ab", "diff": []any{}},
	}}}
	rr := c3Get(t, s, "/api/v2/revisions")
	if rr.Code != http.StatusOK {
		t.Fatalf("revisions status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	assertNoKeyMaterial(t, rr.Body.String())

	fake.result = c2AgentResult{OK: true, Data: map[string]any{"entries": []any{
		map[string]any{"op": "inbounds-rotate", "oldKeyRef": "0123456789ab", "newKeyRef": "abcdef012345", "outcome": "committed"},
	}}}
	rr = c3Get(t, s, "/api/v2/audit")
	if rr.Code != http.StatusOK {
		t.Fatalf("audit status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	assertNoKeyMaterial(t, rr.Body.String())
}
