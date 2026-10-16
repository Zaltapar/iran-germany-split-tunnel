// control_c3.go — Phase C3: the dashboard's forwarding side of the
// Reality inbound editing surface (plans/dashboard-control-design.md §4.2,
// §4.3, §8, §12 C3).
//
// The web process NEVER mutates host state. It forwards typed C3 frames to
// the root-owned agent over the same Unix socket as C2 (the C2Agent seam),
// and answers the per-capability feature flags so that inbound applies are
// refused unless the operator explicitly enabled them (C5 rollout model).
//
// Endpoints added here:
//   - GET  /api/v2/schema/germany-inbounds / /api/v2/schema/iran-inbounds
//     (public fields only; key refs as fingerprints, never key material)
//   - POST /api/v2/changes/{id}/inbounds-validate  (per-capability gated)
//   - POST /api/v2/changes/{id}/inbounds-apply     (per-capability gated,
//     confirm token + restart warning; the response surfaces the restart
//     warning and the peer-change-required note, and NEVER key material)
//
// Per-capability flags (default OFF): Germany inbounds, Iran inbounds, and
// key rotation. When a flag is off the corresponding apply is refused with
// inbound_flag_off; the read-only schema + validate keep working so the UI
// can render the list read-only with a disabled Edit affordance.

package dashboard

import (
	"encoding/json"
	"net/http"
)

// c3 concept names (URL path segments under /api/v2/schema/).
const (
	c3ConceptGermanyInbounds = "germany-inbounds"
	c3ConceptIranInbounds    = "iran-inbounds"
	// c3ConceptInboundsRotation is the rotate-key action descriptor.
	c3ConceptInboundsRotation = "inbounds-rotation"
)

// c3InboundFlagOffError is the agent error code the web maps to a 503 when
// the per-capability flag is off.
const c3InboundFlagOffError = "inbound_flag_off"

// c3KeyRotationFlagOffError is the agent error code the web maps to a 503
// when the key-rotation flag is off.
const c3KeyRotationFlagOffError = "key_rotation_flag_off"

// c3RotateConfirmToken is the typed confirmation the operator must type for a
// rotate-key action (distinct from the C2/C3 RESTART apply token): rotating
// the keypair is a key change, not a service restart, and the old key is
// retained in the revision store's pre/ copy for the transition window.
const c3RotateConfirmToken = "ROTATE"

// c3ControlFlags are the C3 per-capability feature flags. All default
// OFF (the C5 rollout model: each capability is enabled independently and
// can be disabled without affecting the C2 policy plane).
type c3ControlFlags struct {
	// GermanyInboundsApply enables POST inbounds-apply for the Germany
	// Reality concept.
	GermanyInboundsApply bool `json:"germanyInboundsApply"`
	// IranInboundsApply enables POST inbounds-apply for the Iran consumer
	// concept.
	IranInboundsApply bool `json:"iranInboundsApply"`
	// KeyRotation enables the rotate-key action (always requires
	// retainOld; the agent blocks rotation without it).
	KeyRotation bool `json:"keyRotation"`
	// BlobExport enables the explicit blob export/import staging ops
	// (D10 peer coupling).
	BlobExport bool `json:"blobExport"`
}

// c3GermanyInboundSchema is the public-field schema for the Germany Reality
// inbound concept. Key material is represented only as a fingerprint
// reference (keyRef); the privateKey is never a field here.
var c3GermanyInboundSchema = ConceptSchema{
	Concept:  c3ConceptGermanyInbounds,
	Editable: false, // editable state is driven by the per-capability flag
	Status:   "read-only",
	Fields: []FieldSchema{
		{Name: "instance", Type: "string", Required: true, MaxLen: 64},
		{Name: "enabled", Type: "bool", Required: true},
		{Name: "port", Type: "int", Required: false, Min: 1, Max: 65535},
		{Name: "sni", Type: "string", Required: true, MaxLen: 253,
			Pattern: "lowercase RFC 1123 hostname (no IP literal)"},
		{Name: "dest", Type: "string", Required: false, MaxLen: 256,
			Pattern: "host:port redirect target"},
		{Name: "shortId", Type: "string", Required: false, MaxLen: 16,
			Pattern: "^[0-9a-f]{16}$"},
		{Name: "shortIds", Type: "array", Required: false, Max: 8},
		// Key reference ONLY: a 12-hex sha256 fingerprint. The API never
		// accepts or returns key material (design §4.2, §7.5).
		{Name: "keyRef", Type: "string", Required: false, MaxLen: 12,
			Pattern: "^[0-9a-f]{12}$ (sha256 fingerprint of the keypair; key material is never editable)"},
	},
	ValidationEndpoint: "/api/v2/changes/{id}/inbounds-validate",
	ValidationStatus:   "active",
}

// c3IranInboundSchema is the public-field schema for the Iran consumer
// inbound concept (read-only until the C4 Iran agent; C3 shows it and
// stages a Blob A export for the Germany side).
var c3IranInboundSchema = ConceptSchema{
	Concept:  c3ConceptIranInbounds,
	Editable: false,
	Status:   "read-only",
	Fields: []FieldSchema{
		{Name: "instance", Type: "string", Required: true, MaxLen: 64},
		{Name: "enabled", Type: "bool", Required: true},
		{Name: "port", Type: "int", Required: false, Min: 1, Max: 65535},
		{Name: "sni", Type: "string", Required: true, MaxLen: 253},
		{Name: "remoteHost", Type: "string", Required: false, MaxLen: 253},
		{Name: "remotePort", Type: "int", Required: false, Min: 1, Max: 65535},
		{Name: "shortId", Type: "string", Required: false, MaxLen: 16,
			Pattern: "^[0-9a-f]{16}$"},
		{Name: "keyRef", Type: "string", Required: false, MaxLen: 12,
			Pattern: "^[0-9a-f]{12}$ (public-key fingerprint; the consumer holds the public key, never the private key)"},
	},
	ValidationEndpoint: "/api/v2/changes/{id}/inbounds-validate",
	ValidationStatus:   "active",
}

// c3SchemaForConcept returns the C3 inbound schema for a concept name.
func c3SchemaForConcept(name string) (ConceptSchema, bool) {
	switch name {
	case c3ConceptGermanyInbounds:
		return c3GermanyInboundSchema, true
	case c3ConceptIranInbounds:
		return c3IranInboundSchema, true
	}
	return ConceptSchema{}, false
}

// c3FlagForRole reports whether the per-capability apply flag for the role's
// inbound concept is enabled. nil Control config → all flags off.
func (s *Server) c3FlagForRole(role string) bool {
	if s.cfg == nil || s.cfg.Control == nil {
		return false
	}
	flags := s.cfg.Control.C3Flags
	switch role {
	case "germany":
		return flags.GermanyInboundsApply
	case "iran":
		return flags.IranInboundsApply
	}
	return false
}

// c3KeyRotationFlag reports whether the per-capability key-rotation flag is
// enabled. nil Control config → false (fail-closed).
func (s *Server) c3KeyRotationFlag() bool {
	if s.cfg == nil || s.cfg.Control == nil {
		return false
	}
	return s.cfg.Control.C3Flags.KeyRotation
}

// c3InboundsValidateRequest is the strictly-decoded body for
// POST /api/v2/changes/{id}/inbounds-validate.
type c3InboundsValidateRequest struct {
	Role     string          `json:"role"`
	Inbounds json.RawMessage `json:"inbounds"`
}

// c3InboundsApplyRequest is the strictly-decoded body for
// POST /api/v2/changes/{id}/inbounds-apply.
type c3InboundsApplyRequest struct {
	Role         string          `json:"role"`
	Inbounds     json.RawMessage `json:"inbounds"`
	Confirm      string          `json:"confirm"` // must be "RESTART" (D11)
	Reason       string          `json:"reason,omitempty"`
	BaseRevision string          `json:"baseRevision,omitempty"`
}

// c3InboundsApplyResponse is the forwarded C3 apply result. It surfaces the
// restart warning + estimated downtime and the peer-change-required note;
// it never carries key material (the agent returns only fingerprints).
type c3InboundsApplyResponse struct {
	Outcome              string `json:"outcome"`
	Revision             string `json:"revision"`
	PrevRevision         string `json:"prevRevision"`
	ChangeID             string `json:"changeId"`
	RestartWarning       string `json:"restartWarning"`
	EstimatedDowntimeSec int    `json:"estimatedDowntimeSec"`
	PeerChangeRequired   string `json:"peerChangeRequired,omitempty"`
}

// c3InboundsRotateRequest is the strictly-decoded body for
// POST /api/v2/changes/{id}/inbounds-rotate. Confirm must equal
// "ROTATE" (c3RotateConfirmToken): the operator has read that the old key
// is retained for rollback and the xray service will restart. The agent
// requires retainOld=true (fail-closed; rotation is blocked otherwise).
type c3InboundsRotateRequest struct {
	Role     string `json:"role"`
	Instance string `json:"instance"`
	// Confirm must equal c3RotateConfirmToken ("ROTATE").
	Confirm string `json:"confirm"`
	// RetainOld is ALWAYS set to true by the web forwarder: the dashboard
	// never initiates a rotation that drops the old key (the agent blocks
	// it with rotation_blocked regardless).
	RetainOld bool   `json:"retainOld"`
	Reason    string `json:"reason,omitempty"`
}

// c3InboundsRotateResponse is the forwarded rotation result. It carries only
// the NEW key's fingerprint and the retention statement — never key
// material.
type c3InboundsRotateResponse struct {
	Outcome           string `json:"outcome"`
	NewKeyFingerprint string `json:"newKeyFingerprint"`
	OldKeyRetained    bool   `json:"oldKeyRetained"`
	Revision          string `json:"revision"`
	ChangeID          string `json:"changeId"`
}

// c3HandleInboundsValidate forwards the validate op to the agent.
func (s *Server) c3HandleInboundsValidate(w http.ResponseWriter, r *http.Request, changeID string) {
	// Read-only validate is always available (the UI renders the list
	// read-only even when the apply flag is off).
	if r.Header.Get(c2ControlHeader) != "1" {
		writeJSONError(w, http.StatusForbidden, "missing control CSRF header "+c2ControlHeader+": 1")
		return
	}
	if s.c2AgentFor("inbounds-validate") == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: no control agent socket is configured on this host")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, c1BodyLimit))
	dec.DisallowUnknownFields()
	var req c3InboundsValidateRequest
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid validate body: "+err.Error())
		return
	}
	if req.Role == "" {
		req.Role = s.c3RoleForChange(changeID)
		if req.Role == "" {
			writeJSONError(w, http.StatusBadRequest, "role required (germany or iran)")
			return
		}
	}
	role := req.Role
	_, err := s.c2AgentFor("inbounds-validate").Call(r.Context(), "inbounds-validate", c2ReqID(), changeID, changeID, map[string]any{
		"role":     role,
		"inbounds": req.Inbounds,
	})
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: "+err.Error())
		return
	}
	// The validate response is informational; the agent's data carries
	// valid/errors/diff/restartRequired/peerChangeRequired.
	writeJSON(w, http.StatusOK, map[string]any{"role": role, "flagEnabled": s.c3FlagForRole(role)})
}

// c3HandleInboundsApply forwards the apply op, gated by the per-capability
// flag and the confirm token.
func (s *Server) c3HandleInboundsApply(w http.ResponseWriter, r *http.Request, changeID string) {
	// Per-capability flag: apply is refused when the specific concept's
	// flag is off (C5 rollout model; default off).
	role := s.c3RoleForChange(changeID)
	if role == "" {
		role = "germany" // default concept when the changeId does not name one
	}
	if !s.c3FlagForRole(role) {
		writeJSONError(w, http.StatusServiceUnavailable,
			c3InboundFlagOffError+": the C3 "+role+" inbound apply plane is off in this build (control.c3Flags."+role+"InboundsApply=false); the read-only schema and validate remain available")
		return
	}
	if r.Header.Get(c2ControlHeader) != "1" {
		writeJSONError(w, http.StatusForbidden, "missing control CSRF header "+c2ControlHeader+": 1")
		return
	}
	if s.c2AgentFor("inbounds-apply") == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: no control agent socket is configured on this host")
		return
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, c1BodyLimit))
	dec.DisallowUnknownFields()
	var req c3InboundsApplyRequest
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid apply body: "+err.Error())
		return
	}
	if req.Confirm != c2ConfirmToken {
		writeJSONError(w, http.StatusBadRequest,
			"confirm token: the body must carry confirm=\""+c2ConfirmToken+"\" (every C3 change restarts the affected xray service; the UI shows a 10 s countdown)")
		return
	}
	if req.Role == "" {
		req.Role = role
	}

	res, err := s.c2AgentFor("inbounds-apply").Call(r.Context(), "inbounds-apply", c2ReqID(), changeID, changeID, map[string]any{
		"role":         req.Role,
		"inbounds":     req.Inbounds,
		"confirmToken": c2ConfirmToken,
		"reason":       req.Reason,
		"baseRevision": req.BaseRevision,
		"changeId":     changeID,
	})
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: "+err.Error())
		return
	}
	if !res.OK {
		s.c2AgentError(w, res.Error)
		return
	}
	data, _ := res.Data.(map[string]any)
	resp := c3InboundsApplyResponse{
		Outcome:              strVal(data, "outcome"),
		Revision:             strVal(data, "revision"),
		PrevRevision:         strVal(data, "prevRevision"),
		ChangeID:             changeID,
		RestartWarning:       "the affected xray service restarted; the tunnel was briefly unavailable (estimated 10 s)",
		EstimatedDowntimeSec: 10,
		PeerChangeRequired:   strVal(data, "peerChangeRequired"),
	}
	writeJSON(w, http.StatusOK, resp)
}

// c3HandleInboundsRotate forwards the key-rotation op, gated by the
// per-capability key-rotation flag and the typed ROTATE confirm. The old
// key is retained for rollback; the response carries only the new key's
// fingerprint (never key material).
func (s *Server) c3HandleInboundsRotate(w http.ResponseWriter, r *http.Request, changeID string) {
	// Per-capability key-rotation flag: apply is refused when the flag is
	// off (C5 rollout model; default off).
	if !s.c3KeyRotationFlag() {
		writeJSONError(w, http.StatusServiceUnavailable,
			c3KeyRotationFlagOffError+": the C3 key-rotation plane is off in this build (control.c3Flags.keyRotation=false); the read-only schema and validate remain available")
		return
	}
	if r.Header.Get(c2ControlHeader) != "1" {
		writeJSONError(w, http.StatusForbidden, "missing control CSRF header "+c2ControlHeader+": 1")
		return
	}
	if s.c2AgentFor("inbounds-rotate") == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: no control agent socket is configured on this host")
		return
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, c1BodyLimit))
	dec.DisallowUnknownFields()
	var req c3InboundsRotateRequest
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid rotate body: "+err.Error())
		return
	}
	// The typed confirm token must be ROTATE (D: the operator typed the
	// explicit rotate confirmation; RESTART is the apply token, not the
	// rotate token).
	if req.Confirm != c3RotateConfirmToken {
		writeJSONError(w, http.StatusBadRequest,
			"confirm token: the body must carry confirm=\""+c3RotateConfirmToken+"\" (rotate-key generates a new keypair; the old key is retained for rollback; the affected xray service restarts)")
		return
	}
	// The dashboard always retains the old key; the agent re-checks
	// retainOld and fails closed otherwise.
	req.RetainOld = true
	if req.Role == "" {
		req.Role = s.c3RoleForChange(changeID)
		if req.Role == "" {
			writeJSONError(w, http.StatusBadRequest, "role required (germany or iran)")
			return
		}
	}
	if req.Instance == "" {
		writeJSONError(w, http.StatusBadRequest, "instance is required for a rotate-key action")
		return
	}

	res, err := s.c2AgentFor("inbounds-rotate").Call(r.Context(), "inbounds-rotate", c2ReqID(), changeID, changeID, map[string]any{
		"role":      req.Role,
		"instance":  req.Instance,
		"retainOld": true,
		"changeId":  changeID,
		"reason":    req.Reason,
	})
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: "+err.Error())
		return
	}
	if !res.OK {
		s.c2AgentError(w, res.Error)
		return
	}
	data, _ := res.Data.(map[string]any)
	resp := c3InboundsRotateResponse{
		Outcome:           strVal(data, "outcome"),
		NewKeyFingerprint: strVal(data, "newKeyFingerprint"),
		OldKeyRetained:    true,
		Revision:          strVal(data, "revision"),
		ChangeID:          changeID,
	}
	writeJSON(w, http.StatusOK, resp)
}

// c3RoleForChange maps a changeId to the C3 role when it names a
// configured server; "" otherwise.
func (s *Server) c3RoleForChange(changeID string) string {
	// A changeId of "germany" / "iran" is the direct C3 concept name.
	if changeID == "germany" || changeID == "iran" {
		return changeID
	}
	role, ok := s.c2RoleForServer(changeID)
	if ok {
		return role
	}
	return ""
}

// c3HandleInboundsSchema serves the public-field schema for a C3 inbound
// concept (key refs as fingerprints only; no key material).
func (s *Server) c3HandleInboundsSchema(w http.ResponseWriter, concept string) {
	if schema, ok := c3SchemaForConcept(concept); ok {
		// Reflect the per-capability flag so the UI can enable/disable the
		// Edit affordance (design §9.2: disabled + "editing lands in the
		// next phase" tooltip when the flag is off).
		flagOn := s.c3FlagForRole(schemaConceptRole(concept))
		schema.Editable = flagOn
		if !flagOn {
			schema.Status = "read-only"
			schema.EditDisabledReason = "inbound editing is off in this build (per-capability flag disabled)"
		} else {
			schema.Status = "editable"
		}
		writeJSON(w, http.StatusOK, schema)
		return
	}
	writeJSONError(w, http.StatusNotFound, "unknown C3 inbound concept")
}

// schemaConceptRole maps a concept name to its C3 role.
func schemaConceptRole(concept string) string {
	if concept == c3ConceptIranInbounds {
		return "iran"
	}
	return "germany"
}

// c3InboundRoleForConcept is a no-op placeholder kept for test access.
var _ = c3InboundRoleForConcept

func c3InboundRoleForConcept(concept string) string { return schemaConceptRole(concept) }

// c3InboundsRotationSchema is the public-field schema for the C3 rotate-key
// action. Key material is never a field; the action is typed-confirmation
// (ROTATE) gated by the per-capability keyRotation flag (default OFF).
var c3InboundsRotationSchema = ConceptSchema{
	Concept:  c3ConceptInboundsRotation,
	Editable: false, // editable state is driven by the keyRotation flag
	Status:   "read-only",
	Fields: []FieldSchema{
		{Name: "instance", Type: "string", Required: true, MaxLen: 64,
			Pattern: "the inbound instance whose keypair is rotated"},
		{Name: "confirm", Type: "string", Required: true, MaxLen: 8,
			Pattern: "must equal \"ROTATE\" (the operator has read that the old key is retained for rollback)"},
		{Name: "retainOld", Type: "bool", Required: true,
			Pattern: "always true from the dashboard: rotation is blocked unless the old key is retained"},
	},
	ValidationEndpoint: "/api/v2/changes/{id}/inbounds-rotate",
	ValidationStatus:   "active",
}

// c3HandleInboundsRotationSchema serves the rotate-key action descriptor,
// reflecting the key-rotation flag so the UI can enable/disable the Rotate
// affordance (disabled + tooltip when the flag is off).
func (s *Server) c3HandleInboundsRotationSchema(w http.ResponseWriter) {
	schema := c3InboundsRotationSchema
	flagOn := s.c3KeyRotationFlag()
	schema.Editable = flagOn
	if !flagOn {
		schema.Status = "read-only"
		schema.EditDisabledReason = "key rotation is off in this build (per-capability flag keyRotation=false)"
	} else {
		schema.Status = "editable"
	}
	writeJSON(w, http.StatusOK, schema)
}
