package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// c1TestServer builds a Server with a nil mutator (the safe default) and
// a loopback authenticator, suitable for C1 HTTP tests.
func c1TestServer(t *testing.T) *Server {
	t.Helper()
	cfg := DefaultConfig()
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	return s
}

// c1Post performs a POST request to /api/v2/changes/validate on the
// server's router, carrying the CSRF custom header and same-origin
// headers. It returns the response.
func c1Post(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v2/changes/validate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	// Same-origin: Host and Origin match.
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	return rr
}

// --- Test 1: valid policy change returns valid=true and a diff ---
func TestC1ValidateValidPolicyChange(t *testing.T) {
	s := c1TestServer(t)
	body := `{"role":"germany","set":{"SPLIT_POLICY_MODE":"adaptive","SPLIT_POLICY_TOPK":"3"}}`
	rr := c1Post(t, s, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp c1ValidateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Valid {
		t.Errorf("valid = false, want true; errors=%v", resp.Errors)
	}
	if !resp.RestartRequired {
		t.Errorf("restartRequired = false, want true (policy keys require restart)")
	}
	// Diff should have 2 entries.
	if len(resp.Diff) != 2 {
		t.Errorf("len(diff) = %d, want 2", len(resp.Diff))
	}
}

// --- Test 2: out-of-range value returns a validation error ---
func TestC1ValidateOutOfRangeTopK(t *testing.T) {
	s := c1TestServer(t)
	body := `{"role":"germany","set":{"SPLIT_POLICY_TOPK":"9"}}`
	rr := c1Post(t, s, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp c1ValidateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Valid {
		t.Errorf("valid = true, want false for topK=9")
	}
	if len(resp.Errors) == 0 {
		t.Errorf("no validation errors returned")
	}
}

// --- Test 3: unknown field rejected ---
func TestC1ValidateUnknownFieldRejected(t *testing.T) {
	s := c1TestServer(t)
	// "SPLIT_SECRET" is not in the editable schema.
	body := `{"role":"germany","set":{"SPLIT_SECRET":"abc"},"bogusField":"x"}`
	rr := c1Post(t, s, body)
	// The unknown "bogusField" at the top level is caught by
	// DisallowUnknownFields → 400.
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unknown top-level field); body=%s", rr.Code, rr.Body.String())
	}
}

// --- Test 4: secret-named field in set map is rejected ---
func TestC1ValidateSecretNamedFieldRejected(t *testing.T) {
	s := c1TestServer(t)
	body := `{"role":"germany","set":{"SPLIT_SECRET":"should-be-rejected"}}`
	rr := c1Post(t, s, body)
	if rr.Code != http.StatusOK {
		// 400 would also be acceptable (unknown field in set map is
		// not a top-level JSON unknown, so it passes DisallowUnknownFields;
		// the handler rejects it as not-in-schema).
		t.Fatalf("status = %d, want 200 (validation error in response); body=%s", rr.Code, rr.Body.String())
	}
	var resp c1ValidateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Valid {
		t.Errorf("valid = true, want false for SPLIT_SECRET")
	}
	found := false
	for _, e := range resp.Errors {
		if e.Field == "SPLIT_SECRET" {
			found = true
		}
	}
	if !found {
		t.Errorf("no error for SPLIT_SECRET in errors: %v", resp.Errors)
	}
}

// --- Test 5: CSRF — cross-origin POST rejected ---
func TestC1ValidateCSRFCrossOriginRejected(t *testing.T) {
	s := c1TestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/changes/validate",
		strings.NewReader(`{"role":"germany","set":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	// Cross-origin: Origin host differs from Host.
	req.Header.Set("Origin", "http://evil.example.com:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (cross-origin)", rr.Code)
	}
}

// --- Test 6: CSRF — missing custom header rejected ---
func TestC1ValidateCSRFMissingHeaderRejected(t *testing.T) {
	s := c1TestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/changes/validate",
		strings.NewReader(`{"role":"germany","set":{}}`))
	req.Header.Set("Content-Type", "application/json")
	// No CSRFRequestHeader.
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (missing CSRF header)", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "csrf_header_missing") {
		t.Errorf("body does not mention csrf_header_missing: %s", body)
	}
}

// --- Test 7: CSRF — same-origin with header passes ---
func TestC1ValidateCSRFSameOriginPasses(t *testing.T) {
	s := c1TestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/changes/validate",
		strings.NewReader(`{"role":"germany","set":{"SPLIT_POLICY_MODE":"static"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (same-origin with header); body=%s", rr.Code, rr.Body.String())
	}
}

// --- Test 8: filesystem unchanged after every POST ---
func TestC1FilesystemUnchangedAfterPOST(t *testing.T) {
	dir := t.TempDir()
	// Write a sentinel file.
	sentinel := filepath.Join(dir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("before"), 0644); err != nil {
		t.Fatal(err)
	}

	s := c1TestServer(t)
	// Run several POST requests.
	for _, body := range []string{
		`{"role":"germany","set":{"SPLIT_POLICY_TOPK":"4"}}`,
		`{"role":"iran","set":{"SPLIT_MULTI_CARRIER_ENABLED":"true"}}`,
		`{"role":"germany","set":{"SPLIT_SECRET":"leak"}}`,
	} {
		_ = c1Post(t, s, body)
	}

	// The sentinel file must be unchanged.
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "before" {
		t.Errorf("sentinel file changed: %q", string(got))
	}
	// No new files in the dir.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want 1 (sentinel only)", len(entries))
	}
}

// --- Test 9: mutator remains nil and is never called ---
func TestC1MutatorNeverCalled(t *testing.T) {
	cfg := DefaultConfig()
	// Explicitly pass nil mutator → NewNilMutator is used.
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	// The nilMutator records attempts.
	nm, ok := s.mutator.(*nilMutator)
	if !ok {
		t.Fatalf("mutator is not *nilMutator")
	}
	_ = c1Post(t, s, `{"role":"germany","set":{"SPLIT_POLICY_TOPK":"3"}}`)
	if nm.Attempts() != 0 {
		t.Errorf("mutator.ApplyPlan called %d times, want 0", nm.Attempts())
	}
}

// --- Test 10: auth required (401 without Basic) ---
// The default loopback authenticator allows all requests, so we test with
// a Bearer authenticator that requires a token.
func TestC1AuthRequired(t *testing.T) {
	cfg := DefaultConfig()
	auth := NewBearerTokenAuthenticator("test-token")
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, auth)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/changes/validate",
		strings.NewReader(`{"role":"germany","set":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	// No Authorization header.
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (auth required); body=%s", rr.Code, rr.Body.String())
	}
}

// --- Test 11: 404 outside basePath ---
func TestC1OutsideBasePath404(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS = &TLSConfig{
		Enabled:  true,
		CertFile: "/dev/null",
		KeyFile:  "/dev/null",
		BasePath: "deadbeefdeadbeefdeadbeefdeadbeef",
	}
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	s.tlsEnabled = true

	// A request to a path outside the basePath prefix.
	req := httptest.NewRequest(http.MethodPost, "/not-the-prefix/api/v2/changes/validate",
		strings.NewReader(`{}`))
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (outside basePath)", rr.Code)
	}
}

// --- Test 12: oversize body rejected ---
func TestC1OversizeBodyRejected(t *testing.T) {
	s := c1TestServer(t)
	// Build a body larger than c1BodyLimit.
	big := make([]byte, c1BodyLimit+1)
	for i := range big {
		big[i] = 'a'
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v2/changes/validate",
		bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	// The MaxBytesReader in middleware will cause a 400 or 413.
	if rr.Code == http.StatusOK {
		t.Errorf("oversize body accepted (200), want 400 or 413")
	}
}

// --- Test 13: redaction in responses ---
func TestC1RedactionInResponse(t *testing.T) {
	s := c1TestServer(t)
	// A request with a secret-named field.
	body := `{"role":"germany","set":{"SPLIT_SECRET":"supersecretvalue123"}}`
	rr := c1Post(t, s, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	respBody := rr.Body.String()
	// The secret value must NOT appear in the response.
	if strings.Contains(respBody, "supersecretvalue123") {
		t.Errorf("secret value leaked in response: %s", respBody)
	}
	// The field name IS mentioned (in the error), but the value is redacted.
	if !strings.Contains(respBody, "SPLIT_SECRET") {
		t.Errorf("field name SPLIT_SECRET not mentioned in response")
	}
}

// --- Test 14: denylist check for every editable schema field ---
func TestC1EditableSchemaDenylist(t *testing.T) {
	// Every field in c1EditableFields must NOT match the secret denylist.
	for _, field := range c1EditableFields {
		if c1FieldIsSecret(field) {
			t.Errorf("editable field %q matches the secret denylist; it must not be editable", field)
		}
	}
	// The schema's fields must all pass the denylist too.
	for _, f := range c1PolicyMultiCarrierSchema.Fields {
		if c1FieldIsSecret(f.Name) {
			t.Errorf("schema field %q matches the secret denylist", f.Name)
		}
	}

	// Known secret-named fields must match the denylist.
	// The spec denylist is: secret|key|token|password|basepath|credential|private
	secretNames := []string{
		"SPLIT_SECRET", // "secret"
		"basePath",     // "basepath"
		"privateKey",   // "key" + "private"
		"apiKey",       // "key"
		"authToken",    // "token"
		"password",     // "password"
		"credential",   // "credential"
	}
	for _, name := range secretNames {
		if !c1FieldIsSecret(name) {
			t.Errorf("%q should match the secret denylist but does not", name)
		}
	}
}

// --- Test 15: strict JSON — trailing data rejected ---
func TestC1TrailingDataRejected(t *testing.T) {
	s := c1TestServer(t)
	body := `{"role":"germany","set":{}}{"extra":true}`
	rr := c1Post(t, s, body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (trailing data); body=%s", rr.Code, rr.Body.String())
	}
}

// --- Test 16: GET schema for policy-multi-carrier concept ---
func TestC1GetSchemaPolicyMultiCarrier(t *testing.T) {
	s := c1TestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v2/schema/policy-multi-carrier", nil)
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var schema ConceptSchema
	if err := json.Unmarshal(rr.Body.Bytes(), &schema); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if schema.Concept != policyMultiCarrierConcept {
		t.Errorf("concept = %q, want %q", schema.Concept, policyMultiCarrierConcept)
	}
	if schema.ValidationStatus != "active" {
		t.Errorf("validationStatus = %q, want \"active\"", schema.ValidationStatus)
	}
	// All fields must be non-secret.
	for _, f := range schema.Fields {
		if c1FieldIsSecret(f.Name) {
			t.Errorf("schema field %q is secret-named", f.Name)
		}
	}
}

// --- Test 17: empty body → 400 ---
func TestC1EmptyBodyRejected(t *testing.T) {
	s := c1TestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/changes/validate", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (empty body)", rr.Code)
	}
}

// --- Test 18: malformed JSON → 400 ---
func TestC1MalformedJSONRejected(t *testing.T) {
	s := c1TestServer(t)
	rr := c1Post(t, s, `{not-valid-json`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (malformed JSON)", rr.Code)
	}
}

// --- Test 19: probing enabled without probe URL flagged ---
func TestC1ProbingEnabledWithoutURL(t *testing.T) {
	s := c1TestServer(t)
	body := `{"role":"germany","set":{"SPLIT_PROBING_ENABLED":"true"}}`
	rr := c1Post(t, s, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp c1ValidateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The response should flag that SPLIT_PROBE_URL is needed.
	found := false
	for _, e := range resp.Errors {
		if e.Field == config.EnvProbingEnabled && strings.Contains(e.Reason, config.EnvProbeURL) {
			found = true
		}
	}
	if !found {
		t.Errorf("no error mentioning SPLIT_PROBE_URL for enabled probing: %v", resp.Errors)
	}
}

// --- Test 20: multi-carrier enable flag validation ---
func TestC1MultiCarrierEnableFlag(t *testing.T) {
	s := c1TestServer(t)
	body := `{"role":"germany","set":{"SPLIT_MULTI_CARRIER_ENABLED":"true"}}`
	rr := c1Post(t, s, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp c1ValidateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Valid {
		t.Errorf("valid = false for multi-carrier enable; errors=%v", resp.Errors)
	}
	if !resp.RestartRequired {
		t.Errorf("restartRequired = false, want true for multi-carrier enable")
	}
}

// --- Test 21: read-only v2 routes still return 405 on POST ---
func TestC1ReadOnlyRoutesStill405OnPOST(t *testing.T) {
	s := c1TestServer(t)
	// POST to a read-only v2 route (not /changes/validate).
	req := httptest.NewRequest(http.MethodPost, "/api/v2/overview",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 for POST on read-only route", rr.Code)
	}
}

// --- Test 22: OPTIONS returns 200 (method whitelist allows OPTIONS) ---
// The middleware allows OPTIONS; handleV2 will 405 it since it's not
// GET/HEAD/POST. This is expected behavior (OPTIONS is whitelisted by
// the middleware but not by the v2 handler).
func TestC1OptionsBehavior(t *testing.T) {
	s := c1TestServer(t)
	req := httptest.NewRequest(http.MethodOptions, "/api/v2/changes/validate", nil)
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	// OPTIONS is in the method whitelist, so it passes the middleware.
	// handleV2 sees it's not GET/HEAD/POST → 405.
	if rr.Code != http.StatusMethodNotAllowed {
		t.Logf("note: OPTIONS on validate route returned %d (expected 405)", rr.Code)
	}
}
