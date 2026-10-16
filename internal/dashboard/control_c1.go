package dashboard

// control_c1.go — Phase C1: read-only control validation for the
// dashboard control plane (plans/dashboard-control-design.md §12 Phase C1).
//
// Scope:
//   - POST /api/v2/changes/validate — validates a proposed change to the
//     splitter-policy / multi-carrier editable concept, returning
//     validation errors, a redacted diff against the current read-only
//     snapshot, and a restart-required classification.
//   - GET  /api/v2/schema/policy-multi-carrier — read-only schema
//     descriptor for the policy/multi-carrier editable concept.
//   - A secret-field denylist: any field whose name matches the denylist
//     is rejected by the validation endpoint and by the schema.
//
// The endpoint MUST NOT write any file, run any command, or call any
// mutator. It is purely a validation and diff computation against the
// in-memory read-only cache.
//
// CSRF: all non-GET/non-HEAD requests are subject to the hardened
// OriginChecker (C1) which requires X-Tunneldash-Request: 1 plus a
// same-origin check.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// C1 body cap (lower than the 64 KiB POST limit; the design specifies 16 KiB
// for control POSTs but the orchestrator chose 64 KiB for C1 to reuse the
// existing middleware limit; we keep the 64 KiB cap here explicitly).
const c1BodyLimit = 64 << 10 // 64 KiB

// policyMultiCarrierConcept is the concept name under /api/v2/schema/.
const policyMultiCarrierConcept = "policy-multi-carrier"

// c1EditableFields lists every field the C1 validation endpoint accepts
// for the policy-multi-carrier concept. Each entry is the env variable
// name. No secret-named field may ever appear here; the denylist test
// (TestC1EditableSchemaDenylist) enforces this invariant.
var c1EditableFields = []string{
	config.EnvPolicyMode,          // SPLIT_POLICY_MODE
	config.EnvPolicyTopK,          // SPLIT_POLICY_TOPK
	config.EnvProbingEnabled,      // SPLIT_PROBING_ENABLED
	config.EnvProbeDailyBudget,    // SPLIT_PROBE_DAILY_BUDGET
	config.EnvTTFBBaselineMs,      // SPLIT_TTFB_BASELINE_MS
	config.EnvMultiCarrierEnabled, // SPLIT_MULTI_CARRIER_ENABLED
}

// c1PolicyMultiCarrierSchema is the read-only schema descriptor for the
// policy/multi-carrier editable concept, served at
// GET /api/v2/schema/policy-multi-carrier.
var c1PolicyMultiCarrierSchema = ConceptSchema{
	Concept:            policyMultiCarrierConcept,
	Editable:           false,
	Status:             "read-only",
	ValidationEndpoint: "/api/v2/changes/validate",
	ValidationStatus:   "active",
	Fields: []FieldSchema{
		{Name: config.EnvPolicyMode, Type: "enum", Required: false,
			Enum: []string{config.PolicyStaticMode, config.PolicyAdaptiveMode}},
		{Name: config.EnvPolicyTopK, Type: "int", Required: false,
			Min: config.MinPolicyTopK, Max: config.MaxPolicyTopK},
		{Name: config.EnvProbingEnabled, Type: "bool", Required: false},
		{Name: config.EnvProbeDailyBudget, Type: "int", Required: false,
			Min: 0, Max: 536870912}, // 512 MiB upper bound (design §4.4)
		{Name: config.EnvTTFBBaselineMs, Type: "int", Required: false,
			Min: config.MinTTFBBaselineMs, Max: config.MaxTTFBBaselineMs},
		{Name: config.EnvMultiCarrierEnabled, Type: "bool", Required: false},
	},
}

// c1ValidateRequest is the strictly-decoded JSON body for
// POST /api/v2/changes/validate. DisallowUnknownFields ensures no
// unexpected keys are accepted.
type c1ValidateRequest struct {
	// Role is "iran" or "germany"; determines which role's config is
	// validated. Default (empty) = both roles are validated independently.
	Role string `json:"role"`
	// Set is the map of env-var names to proposed string values.
	// Only keys in c1EditableFields are accepted; any other key is
	// rejected with a validation error.
	Set map[string]string `json:"set"`
	// Reason is an optional operator-supplied audit note. It is NOT
	// included in any diff or secret field.
	Reason string `json:"reason,omitempty"`
}

// c1ValidationFieldError describes one field-level validation failure.
// Value is NEVER included for secret-named fields.
type c1ValidationFieldError struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// c1DiffEntry is one before/after pair in the redacted diff.
type c1DiffEntry struct {
	Key      string `json:"key"`
	Before   string `json:"before"`
	After    string `json:"after"`
	Redacted bool   `json:"redacted,omitempty"`
}

// c1ValidateResponse is the response body for a successful validation.
type c1ValidateResponse struct {
	// Valid is true when no validation errors occurred.
	Valid bool `json:"valid"`
	// Errors lists field-level validation failures (empty when Valid).
	Errors []c1ValidationFieldError `json:"errors"`
	// Diff is the redacted before/after diff against the current snapshot.
	Diff []c1DiffEntry `json:"diff"`
	// RestartRequired is true when any changed key is read at process
	// start (SPLIT_POLICY_MODE, SPLIT_POLICY_TOPK, SPLIT_PROBING_ENABLED,
	// SPLIT_PROBE_DAILY_BUDGET, SPLIT_TTFB_BASELINE_MS, or
	// SPLIT_MULTI_CARRIER_ENABLED all require a restart).
	RestartRequired bool `json:"restartRequired"`
	// Role echoes the validated role.
	Role string `json:"role"`
}

// c1SecretDenylistSubstrings are name fragments that mark a field as
// secret-named. Any editable schema field whose name (case-insensitive)
// contains one of these substrings must be rejected.
var c1SecretDenylistSubstrings = []string{
	"secret", "key", "token", "password", "basepath", "credential", "private",
}

// c1FieldIsSecret reports whether a field name matches the secret denylist.
func c1FieldIsSecret(name string) bool {
	ln := strings.ToLower(name)
	for _, sub := range c1SecretDenylistSubstrings {
		if strings.Contains(ln, sub) {
			return true
		}
	}
	return false
}

// c1ValidateKeySet returns the set of allowed keys for the C1 concept.
func c1ValidateKeySet() map[string]bool {
	m := make(map[string]bool, len(c1EditableFields))
	for _, k := range c1EditableFields {
		m[k] = true
	}
	return m
}

// c1RestartRequired reports whether the given env key requires a process
// restart when changed. All C1 keys require a restart (they are read at
// process start by the splitter node).
func c1RestartRequired(key string) bool {
	switch key {
	case config.EnvPolicyMode, config.EnvPolicyTopK,
		config.EnvProbingEnabled, config.EnvProbeDailyBudget,
		config.EnvTTFBBaselineMs, config.EnvMultiCarrierEnabled:
		return true
	}
	return false
}

// c1Validate builds and returns the validation response for a proposed
// change. It performs no I/O, no file writes, no command execution, and
// no mutator call. The "before" values come from the passed-in snapshot
// map (which the caller populates from the read-only cache).
func c1Validate(req *c1ValidateRequest, before map[string]string) *c1ValidateResponse {
	resp := &c1ValidateResponse{
		Valid:  true,
		Errors: []c1ValidationFieldError{},
		Diff:   []c1DiffEntry{},
		Role:   req.Role,
	}
	allowed := c1ValidateKeySet()
	role := req.Role
	if role == "" {
		role = "both" // validate against both roles' defaults
	}

	// 1. Reject any unknown key.
	for k := range req.Set {
		if !allowed[k] {
			reason := "not in the editable schema"
			if c1FieldIsSecret(k) {
				reason = "secret-named field; never editable via the dashboard"
			}
			resp.Errors = append(resp.Errors, c1ValidationFieldError{Field: k, Reason: reason})
			resp.Valid = false
		}
	}

	// 2. Reject secret-named fields explicitly (belt-and-suspenders).
	for k := range req.Set {
		if c1FieldIsSecret(k) {
			resp.Errors = append(resp.Errors, c1ValidationFieldError{
				Field:  k,
				Reason: "secret-named field; never editable via the dashboard",
			})
			resp.Valid = false
		}
	}

	// 3. Validate each allowed key's value.
	for k, v := range req.Set {
		if !allowed[k] {
			continue
		}
		if err := c1ValidateFieldValue(k, v, role); err != nil {
			resp.Errors = append(resp.Errors, c1ValidationFieldError{Field: k, Reason: err.Error()})
			resp.Valid = false
		}
	}

	// 4. Cross-field checks (e.g., probing enabled requires probe URL —
	// but SPLIT_PROBE_URL is not in the C1 editable set, so we note it).
	if req.Set[config.EnvProbingEnabled] == "true" {
		resp.Errors = append(resp.Errors, c1ValidationFieldError{
			Field:  config.EnvProbingEnabled,
			Reason: "SPLIT_PROBE_URL must also be set (not in the C1 editable schema; set it via splitterctl config set)",
		})
	}

	// 5. Build the redacted diff.
	for k, v := range req.Set {
		if !allowed[k] {
			continue
		}
		beforeVal := before[k]
		if beforeVal == "" {
			beforeVal = "(not set)"
		}
		redacted := c1FieldIsSecret(k)
		afterShown := v
		if redacted {
			afterShown = "<redacted>"
		}
		beforeShown := beforeVal
		if redacted {
			beforeShown = "<redacted>"
		}
		resp.Diff = append(resp.Diff, c1DiffEntry{
			Key:      k,
			Before:   beforeShown,
			After:    afterShown,
			Redacted: redacted,
		})
		if c1RestartRequired(k) {
			resp.RestartRequired = true
		}
	}
	return resp
}

// c1ValidateFieldValue checks one field value against the config
// validator rules for the given role. It reuses internal/config's
// bounds and enums. No I/O.
func c1ValidateFieldValue(key, value, role string) error {
	switch key {
	case config.EnvPolicyMode:
		if value != config.PolicyStaticMode && value != config.PolicyAdaptiveMode {
			return fmt.Errorf("must be %q or %q", config.PolicyStaticMode, config.PolicyAdaptiveMode)
		}
		return nil
	case config.EnvPolicyTopK:
		n, err := parseNonNegativeInt(value)
		if err != nil {
			return fmt.Errorf("must be an integer 1..%d", config.MaxPolicyTopK)
		}
		if n < config.MinPolicyTopK || n > config.MaxPolicyTopK {
			return fmt.Errorf("must be in range %d..%d", config.MinPolicyTopK, config.MaxPolicyTopK)
		}
		return nil
	case config.EnvProbingEnabled:
		if value != "true" && value != "false" && value != "1" && value != "0" {
			return fmt.Errorf("must be a boolean (true/false, 1/0)")
		}
		return nil
	case config.EnvProbeDailyBudget:
		n, err := parseNonNegativeInt(value)
		if err != nil {
			return fmt.Errorf("must be a non-negative integer (bytes)")
		}
		if n > 536870912 { // 512 MiB design bound
			return fmt.Errorf("exceeds the 512 MiB daily probe budget cap")
		}
		return nil
	case config.EnvTTFBBaselineMs:
		n, err := parseNonNegativeInt(value)
		if err != nil {
			return fmt.Errorf("must be a non-negative integer (ms)")
		}
		if n < config.MinTTFBBaselineMs || n > config.MaxTTFBBaselineMs {
			return fmt.Errorf("must be in range %d..%d", config.MinTTFBBaselineMs, config.MaxTTFBBaselineMs)
		}
		return nil
	case config.EnvMultiCarrierEnabled:
		if value != "true" && value != "false" && value != "1" && value != "0" {
			return fmt.Errorf("must be a boolean (true/false, 1/0)")
		}
		return nil
	}
	return fmt.Errorf("unknown editable key")
}

// parseNonNegativeInt parses a non-negative integer string.
func parseNonNegativeInt(s string) (int, error) {
	if s == "" || len(s) > 12 {
		return 0, fmt.Errorf("not a valid integer")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a valid integer")
		}
		n = n*10 + int(c-'0')
		if n > 536870912 { // overflow guard for our bounds
			return 0, fmt.Errorf("value too large")
		}
	}
	return n, nil
}

// --- HTTP handler ---

// c1HandleChangesValidate is the handler for POST /api/v2/changes/validate.
// It is wired into handleV2 (api_v2.go) via the "changes" segment.
func (s *Server) c1HandleChangesValidate(w http.ResponseWriter, r *http.Request) {
	// Strictly decode the JSON body: DisallowUnknownFields, size cap,
	// exactly one JSON value, no trailing data.
	dec := json.NewDecoder(io.LimitReader(r.Body, c1BodyLimit))
	dec.DisallowUnknownFields()

	var req c1ValidateRequest
	if err := dec.Decode(&req); err != nil {
		if err == io.EOF {
			writeJSONError(w, http.StatusBadRequest, "empty request body")
			return
		}
		// Distinguish unknown-field errors from malformed JSON.
		var ufe *json.UnmarshalTypeError
		if ok := asUnmarshalTypeError(err, &ufe); ok {
			writeJSONError(w, http.StatusBadRequest,
				fmt.Sprintf("unknown field %q: not in the C1 editable schema", ufe.Field))
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	// Reject trailing data (more than one JSON value).
	if dec.More() {
		writeJSONError(w, http.StatusBadRequest, "request body must contain exactly one JSON object")
		return
	}
	// Build the "before" snapshot from the cache's current config values.
	before := s.c1CurrentConfigSnapshot()

	// Run validation. No I/O, no writes, no mutator.
	resp := c1Validate(&req, before)
	writeJSON(w, http.StatusOK, resp)
}

// c1CurrentConfigSnapshot returns the current read-only config values for
// the C1 editable fields. In this phase the cache does not yet collect
// live splitter env values, so the snapshot is populated with the
// built-in defaults (documented in internal/config). This is a
// read-only, in-memory operation — no file reads, no SSH, no host contact.
func (s *Server) c1CurrentConfigSnapshot() map[string]string {
	snap := make(map[string]string, len(c1EditableFields))
	// Defaults from internal/config (safe, non-secret).
	snap[config.EnvPolicyMode] = config.DefaultPolicyMode
	snap[config.EnvPolicyTopK] = fmt.Sprintf("%d", config.DefaultPolicyTopK)
	snap[config.EnvProbingEnabled] = fmt.Sprintf("%v", config.DefaultProbingEnabled)
	snap[config.EnvProbeDailyBudget] = fmt.Sprintf("%d", config.DefaultProbeDailyBudget)
	snap[config.EnvTTFBBaselineMs] = "0" // 0 = library default
	snap[config.EnvMultiCarrierEnabled] = fmt.Sprintf("%v", config.DefaultMultiCarrierEnabled)
	// Override with any cached values if the collector has populated them.
	// (In the current build the collector does not populate these; the
	// defaults are the authoritative baseline for the diff.)
	return snap
}

// c1HandleSchemaPolicyMultiCarrier serves the read-only schema for the
// policy-multi-carrier concept at GET /api/v2/schema/policy-multi-carrier.
func (s *Server) c1HandleSchemaPolicyMultiCarrier(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, c1PolicyMultiCarrierSchema)
}

// asUnmarshalTypeError is a type-assertion helper for *json.UnmarshalTypeError.
func asUnmarshalTypeError(err error, target **json.UnmarshalTypeError) bool {
	if ufe, ok := err.(*json.UnmarshalTypeError); ok {
		*target = ufe
		return true
	}
	return false
}
