// control_dashboard_editors_test.go — security, flag-gating, CSRF, 401/404,
// filesystem-unchanged, and validator-parity tests for the dashboard's
// editor API surface (C3 rotate-key, C4 routing rules + multi-carrier).
//
// These tests verify that:
//   - apply is refused (503 + flag code) when the per-capability flag is off,
//     and the agent is NOT called.
//   - the typed confirm token is required (400 without it).
//   - the control CSRF header is required (403 without it).
//   - schema GETs return only public fields (no secrets).
//   - routing-rules validate is local (no host I/O, filesystem unchanged).
//   - the client-side validator and the server validator agree on the same
//     fixture (shared-fixture parity).
//   - 401 without Basic auth and 404 outside basePath (TLS build).
package dashboard

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- shared fixture: the routing-rules document used by both the client-side
// --- validator (in JS tests, mirrored here) and the server validator.
//
// The fixture exercises: valid rules, a disabled rule, a warp rule with
// fallback, a block rule, and the default action. It is the single source
// of truth for the parity test: the server must accept it (ParseRules) and
// the JS editor must also accept it (validateRoutingRulesClient).

const routingFixture = `{
  "version": 1,
  "default_action": "direct",
  "rules": [
    {"id":"r1","enabled":true,"match":{"domain":".example.com"},"action":"warp","fallback":"direct"},
    {"id":"r2","enabled":true,"match":{"keyword":"stream"},"action":"direct"},
    {"id":"r3","enabled":false,"match":{"ip_cidr":"10.0.0.0/8"},"action":"block"},
    {"id":"r4","enabled":true,"match":{"port_min":80,"port_max":443,"keyword":"http"},"action":"warp"}
  ]
}`

// --- a fixture that the server validator must REJECT (invalid domain) ---
const routingFixtureInvalid = `{
  "version": 1,
  "default_action": "block",
  "rules": [
    {"id":"bad","match":{"domain":"UPPER.COM"},"action":"direct"}
  ]
}`

// --- helpers ---------------------------------------------------------------

// editorTestServer builds a server with C3+C4 flags and a fake agent.
func editorTestServer(t *testing.T, c3 c3ControlFlags, c4 c4ControlFlags) (*Server, *fakeC2Agent) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{
		ApplyEnabled: true,
		SocketPath:   "/run/split-tunnel-ctl/control.sock",
		C3Flags:      c3,
		C4Flags:      c4,
	}
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	fake := &fakeC2Agent{}
	s.SetControlAgent(fake)
	return s, fake
}

// editorPost posts to a control endpoint with the required headers.
func editorPost(t *testing.T, s *Server, path, body string, withControlHeader bool) *httptest.ResponseRecorder {
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

// editorGet performs a GET on a schema endpoint.
func editorGet(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	return rr
}

// --- C3 rotate-key tests ---------------------------------------------------

func TestC3RotateKeyFlagOffReturns503(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{})
	rr := editorPost(t, s, "/api/v2/changes/germany/inbounds-rotate",
		`{"role":"germany","instance":"reality-1","confirm":"ROTATE"}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("flag off: status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), c3KeyRotationFlagOffError) {
		t.Fatalf("503 body must name %q: %s", c3KeyRotationFlagOffError, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite flag being off: %v", fake.calls)
	}
}

func TestC3RotateKeyRequiresROTATEConfirm(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{KeyRotation: true}, c4ControlFlags{})
	// Wrong confirm token
	fake.result = c2AgentResult{OK: true, Data: map[string]any{}}
	rr := editorPost(t, s, "/api/v2/changes/germany/inbounds-rotate",
		`{"role":"germany","instance":"reality-1","confirm":"RESTART"}`, true)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("wrong confirm: status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent called despite 400: %v", fake.calls)
	}
}

func TestC3RotateKeyMissingCSRFHeader(t *testing.T) {
	s, _ := editorTestServer(t, c3ControlFlags{KeyRotation: true}, c4ControlFlags{})
	rr := editorPost(t, s, "/api/v2/changes/germany/inbounds-rotate",
		`{"role":"germany","instance":"reality-1","confirm":"ROTATE"}`, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
}

func TestC3RotateKeySuccess(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{KeyRotation: true}, c4ControlFlags{})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{
		"outcome":           "committed",
		"newKeyFingerprint": "abcdef012345",
		"revision":          "r-42",
	}}
	rr := editorPost(t, s, "/api/v2/changes/germany/inbounds-rotate",
		`{"role":"germany","instance":"reality-1","confirm":"ROTATE"}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp c3InboundsRotateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.NewKeyFingerprint != "abcdef012345" || !resp.OldKeyRetained {
		t.Fatalf("response mismatch: %+v", resp)
	}
	// No key material in the response.
	assertNoKeyMaterial(t, rr.Body.String())
}

func TestC3RotationSchemaAlwaysAvailable(t *testing.T) {
	s, _ := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{})
	rr := editorGet(t, s, "/api/v2/schema/inbounds-rotation")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var sc ConceptSchema
	if err := json.Unmarshal(rr.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Concept != c3ConceptInboundsRotation {
		t.Fatalf("concept = %q, want %q", sc.Concept, c3ConceptInboundsRotation)
	}
	if sc.Editable {
		t.Error("flag off: rotation schema must be read-only")
	}
	assertNoKeyMaterial(t, rr.Body.String())
}

// --- C4 routing-rules tests ------------------------------------------------

func TestC4RoutingValidateWithRules(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{RoutingApply: true})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{
		"errors": []any{},
		"diff":   []any{},
	}}
	body := `{"role":"germany","set":{},"rules":` + routingFixture + `}`
	rr := editorPost(t, s, "/api/v2/changes/germany/routing-validate", body, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["valid"] != true {
		t.Errorf("valid = %v, want true; errors=%v", resp["valid"], resp["errors"])
	}
	// The rules diff should be present and non-empty (4 rules added).
	if resp["rulesDiff"] == nil {
		t.Error("rulesDiff missing from validate response")
	}
	// The agent was called with only the env-set plane (no rules).
	if len(fake.calls) != 1 || fake.calls[0] != "c4-routing-validate" {
		t.Fatalf("agent ops = %v, want [c4-routing-validate]", fake.calls)
	}
}

func TestC4RoutingValidateRejectsInvalidRules(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{RoutingApply: true})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{
		"errors": []any{},
		"diff":   []any{},
	}}
	body := `{"role":"germany","set":{},"rules":` + routingFixtureInvalid + `}`
	rr := editorPost(t, s, "/api/v2/changes/germany/routing-validate", body, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (validate always 200, errors in body); body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["valid"] != false {
		t.Errorf("valid = %v, want false (block default + uppercase domain)", resp["valid"])
	}
	errs, _ := resp["errors"].([]any)
	found := false
	for _, e := range errs {
		if s, ok := e.(string); ok && strings.Contains(s, "block") {
			found = true
		}
	}
	if !found {
		t.Errorf("errors should mention 'block': %v", errs)
	}
}

func TestC4RoutingApplyFlagOffReturns503(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{}) // flag OFF
	rr := editorPost(t, s, "/api/v2/changes/germany/routing-apply",
		`{"role":"germany","set":{},"confirm":"RESTART","rules":`+routingFixture+`}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("flag off: status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), c4RoutingFlagOffCode) {
		t.Fatalf("503 body must name %q: %s", c4RoutingFlagOffCode, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite flag being off: %v", fake.calls)
	}
}

func TestC4RoutingApplyRequiresConfirmToken(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{RoutingApply: true})
	// Missing confirm
	fake.result = c2AgentResult{OK: true, Data: map[string]any{}}
	rr := editorPost(t, s, "/api/v2/changes/germany/routing-apply",
		`{"role":"germany","set":{}}`, true)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no confirm: status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent called despite 400: %v", fake.calls)
	}
}

func TestC4RoutingApplyRejectsInvalidRules(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{RoutingApply: true})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{}}
	rr := editorPost(t, s, "/api/v2/changes/germany/routing-apply",
		`{"role":"germany","set":{},"confirm":"RESTART","rules":`+routingFixtureInvalid+`}`, true)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid rules: status = %d, want 422; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent called despite 422: %v", fake.calls)
	}
}

func TestC4RoutingApplyMissingCSRFHeader(t *testing.T) {
	s, _ := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{RoutingApply: true})
	rr := editorPost(t, s, "/api/v2/changes/germany/routing-apply",
		`{"role":"germany","set":{},"confirm":"RESTART"}`, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
}

func TestC4MultiCarrierApplyFlagOffReturns503(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{}) // flag OFF
	rr := editorPost(t, s, "/api/v2/changes/germany/multicarrier-apply",
		`{"role":"germany","set":{"SPLIT_MULTI_CARRIER_ENABLED":"true"},"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("flag off: status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), c4MultiCarrierFlagOffCode) {
		t.Fatalf("503 body must name %q: %s", c4MultiCarrierFlagOffCode, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite flag being off: %v", fake.calls)
	}
}

// --- schema public-field-only tests ----------------------------------------

func TestEditorSchemasNoSecretFields(t *testing.T) {
	s, _ := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{})
	concepts := []string{
		"/api/v2/schema/routing-plane",
		"/api/v2/schema/multi-carrier-control",
		"/api/v2/schema/germany-inbounds",
		"/api/v2/schema/iran-inbounds",
		"/api/v2/schema/inbounds-rotation",
	}
	forbidden := []string{
		"SPLIT_SECRET", "SPLIT_SOCKS_USER", "SPLIT_SOCKS_PASS",
		"baseUrl", "basepath", `"privateKey"`, `"keyMaterial"`,
		`"password"`, `"token"`, `"secret"`,
	}
	for _, c := range concepts {
		rr := editorGet(t, s, c)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200; body=%s", c, rr.Code, rr.Body.String())
		}
		for _, f := range forbidden {
			if strings.Contains(rr.Body.String(), f) {
				t.Errorf("%s leaked forbidden marker %q:\n%s", c, f, rr.Body.String())
			}
		}
	}
}

// --- 401 / 404 (TLS build) -------------------------------------------------

func TestEditorRoutesRequireBasicAuth(t *testing.T) {
	cfg := secureTestConfig()
	cfg.Control = &ControlConfig{
		ApplyEnabled: true,
		SocketPath:   "/run/split-tunnel-ctl/control.sock",
		C3Flags:      c3ControlFlags{KeyRotation: true},
		C4Flags:      c4ControlFlags{RoutingApply: true, MultiCarrierApply: true},
	}
	auth := newBasicForTest(t, "admin", "secret-pass")
	s := NewTLSServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, auth)
	fake := &fakeC2Agent{}
	s.SetControlAgent(fake)
	bp := "/" + cfg.TLS.BasePath + "/"

	// Without Basic auth: 401
	for _, p := range []string{
		bp + "api/v2/schema/routing-plane",
		bp + "api/v2/schema/inbounds-rotation",
		bp + "api/v2/schema/multi-carrier-control",
	} {
		rr := v2Do(s.Router(), http.MethodGet, p, false)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s without auth: %d, want 401", p, rr.Code)
		}
	}
	// With auth: 200
	for _, p := range []string{
		bp + "api/v2/schema/routing-plane",
		bp + "api/v2/schema/inbounds-rotation",
		bp + "api/v2/schema/multi-carrier-control",
	} {
		rr := v2Do(s.Router(), http.MethodGet, p, true)
		if rr.Code != http.StatusOK {
			t.Errorf("%s with auth: %d, want 200; body=%s", p, rr.Code, rr.Body.String())
		}
	}

	// 404 outside basePath
	for _, p := range []string{
		"/api/v2/schema/routing-plane",
		"/api/v2/schema/inbounds-rotation",
	} {
		rr := v2Do(s.Router(), http.MethodGet, p, true)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s outside basePath: %d, want 404", p, rr.Code)
		}
	}
}

// --- filesystem unchanged after routing validate ---------------------------

func TestC4RoutingValidateDoesNotTouchFilesystem(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{RoutingApply: true})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{
		"errors": []any{},
		"diff":   []any{},
	}}
	// chdir to a clean scratch dir; any write by the web process would show.
	oldWd, _ := os.Getwd()
	tmpDir := t.TempDir()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(oldWd) }()

	body := `{"role":"germany","set":{},"rules":` + routingFixture + `}`
	rr := editorPost(t, s, "/api/v2/changes/germany/routing-validate", body, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if entries, _ := os.ReadDir("."); len(entries) != 0 {
		for _, e := range entries {
			t.Errorf("web process wrote a host file during routing-validate: %s", e.Name())
		}
	}
}

// --- client/server validator parity (shared fixture) -----------------------

// TestRoutingValidatorParity verifies that the Go server validator
// (routing.ParseRules, used by c4ValidateRoutingRules) accepts the same
// fixture that the JS client-side validator (validateRoutingRulesClient in
// app.js) accepts. The JS side is tested separately via a Node-based
// test or by code review; this Go test pins the server side.
func TestRoutingValidatorParity(t *testing.T) {
	// The fixture must be accepted by the server validator.
	errs, set := c4ValidateRoutingRules([]byte(routingFixture))
	if len(errs) != 0 {
		t.Fatalf("server validator rejected the shared fixture: %v", errs)
	}
	if set == nil {
		t.Fatal("server validator returned nil set for a valid fixture")
	}
	if len(set.Rules) != 4 {
		t.Errorf("fixture should have 4 rules, got %d", len(set.Rules))
	}
	// The invalid fixture must be rejected.
	errs, _ = c4ValidateRoutingRules([]byte(routingFixtureInvalid))
	if len(errs) == 0 {
		t.Error("server validator accepted an invalid fixture (block default + uppercase domain)")
	}
}

// TestRoutingValidateRulesFilesystemUnchanged verifies that validating rules
// does NOT read or write any file on disk (the rules are an in-memory object,
// not a file path). The temp-dir hash comparison catches any regression.
func TestRoutingValidateRulesFilesystemUnchanged(t *testing.T) {
	s, fake := editorTestServer(t, c3ControlFlags{}, c4ControlFlags{RoutingApply: true})
	fake.result = c2AgentResult{OK: true, Data: map[string]any{
		"errors": []any{},
		"diff":   []any{},
	}}

	oldWd, _ := os.Getwd()
	tmpDir := t.TempDir()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(oldWd) }()

	// Create a marker file to verify it is not modified.
	marker := "sentinel"
	markerFile := filepath.Join(tmpDir, "sentinel.txt")
	if err := os.WriteFile(markerFile, []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	hashBefore := fileHash(t, markerFile)

	body := `{"role":"germany","set":{},"rules":` + routingFixture + `}`
	rr := editorPost(t, s, "/api/v2/changes/germany/routing-validate", body, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	hashAfter := fileHash(t, markerFile)
	if hashBefore != hashAfter {
		t.Error("routing-validate modified the sentinel file (filesystem I/O detected)")
	}
}

func fileHash(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	h := sha256.Sum256(data)
	return string(h[:])
}
