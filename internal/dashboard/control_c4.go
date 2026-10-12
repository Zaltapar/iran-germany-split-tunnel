// control_c4.go — Phase C4: the dashboard's forwarding side of the
// routing plane and the multi-carrier control surface
// (plans/dashboard-control-design.md §4.4, §4.6, §12 C4).
//
// The web process NEVER mutates host state. It forwards typed C4 frames
// to the root-owned agent over the same Unix socket as C2/C3 (the C2Agent
// seam), and answers the per-capability feature flags so that routing and
// multi-carrier applies are refused unless the operator explicitly
// enabled them (C5 rollout model).
//
// Endpoints added here:
//   - GET  /api/v2/schema/routing-plane
//   - GET  /api/v2/schema/multi-carrier
//   - POST /api/v2/changes/{id}/routing-validate   (per-capability gated)
//   - POST /api/v2/changes/{id}/routing-apply      (per-capability gated)
//   - POST /api/v2/changes/{id}/multicarrier-validate
//   - POST /api/v2/changes/{id}/multicarrier-apply
//
// Per-capability flags (default OFF): RoutingApply, MultiCarrierApply,
// CoordinatedApply. When a flag is off the corresponding apply is refused
// with 503 + a clear code; the read-only schema + validate keep working
// so the UI can render the section read-only with a disabled Edit
// affordance (design §9.2).
//
// The C4 apply reuses the C2/C3 forwarding discipline: confirm token +
// CSRF header + restart warning surfaced in the response. The agent owns
// every host mutation (render → validate → xray gate → backup → swap →
// restart → verify → commit → auto-rollback); the dashboard never touches
// a live file or a service.

package dashboard

import (
	"encoding/json"
	"net/http"
)

// c4 concept names (URL path segments under /api/v2/schema/).
const (
	c4ConceptRoutingPlane = "routing-plane"
	c4ConceptMultiCarrier = "multi-carrier-control"
)

// c4 flag-off error codes (the web maps these to 503).
const (
	c4RoutingFlagOffCode      = "routing_flag_off"
	c4MultiCarrierFlagOffCode = "multicarrier_flag_off"
	c4CoordinatedFlagOffCode  = "coordinated_flag_off"
)

// c4ControlFlags are the C4 per-capability feature flags. All default OFF
// (the C5 rollout model: each capability is enabled independently and can
// be disabled without affecting the C2 policy plane or the C3 inbound
// plane).
type c4ControlFlags struct {
	// RoutingApply enables POST routing-apply (the C4 routing plane).
	RoutingApply bool `json:"routingApply"`
	// MultiCarrierApply enables POST multicarrier-apply (the C4
	// multi-carrier control).
	MultiCarrierApply bool `json:"multiCarrierApply"`
	// CoordinatedApply enables the coordinated two-host apply (the C4
	// coupled handshake; stages a Blob B when the peer has no agent).
	CoordinatedApply bool `json:"coordinatedApply"`
}

// c4RoutingSchema is the public-field schema for the C4 routing plane.
// Two keys, both env-driven and validated in internal/config; the
// dashboard's routing-policy / routing-rule concepts are display-only
// (design F-8/D9) and are NOT part of this schema.
var c4RoutingSchema = ConceptSchema{
	Concept:  c4ConceptRoutingPlane,
	Editable: false, // editable state is driven by the per-capability flag
	Status:   "read-only",
	Fields: []FieldSchema{
		{Name: "SPLIT_TARGET_ADDR_POLICY", Type: "string", Required: false,
			Pattern: "default|prefer-ipv4|ipv4-only (both roles; the egress-target address-family policy)"},
		{Name: "SPLIT_SOCKS_ALLOWED_SOURCES", Type: "string", Required: false,
			Pattern: "comma-separated IPv4/IPv6 addresses or CIDR blocks (Iran role only; empty = allow all)"},
	},
	ValidationEndpoint: "/api/v2/changes/{id}/routing-validate",
	ValidationStatus:   "active",
	// Deliberately excluded (documented in the C4 completion note):
	// xray routing-rule / RoutingPolicy editing (display-only, no live
	// routing engine consumes them), the legacy SPLIT_TARGET_ONLY_IPV4
	// flag (superseded by the policy enum; its contradiction with
	// prefer-ipv4 is still cross-checked by the agent), and every
	// secret-named key (F-6: SPLIT_SECRET, the SOCKS RFC 1929 pair).
}

// c4MultiCarrierSchema is the public-field schema for the C4 multi-carrier
// control concept.
var c4MultiCarrierSchema = ConceptSchema{
	Concept:  c4ConceptMultiCarrier,
	Editable: false,
	Status:   "read-only",
	Fields: []FieldSchema{
		{Name: "SPLIT_MULTI_CARRIER_ENABLED", Type: "bool", Required: false,
			Pattern: "true/false (both roles; the master toggle)"},
		{Name: "SPLIT_DOWN_LISTEN_2", Type: "string", Required: false,
			Pattern: "host:port (Germany role only; the second down listener)"},
		{Name: "SPLIT_DOWN_CARRIER_ADDR_2", Type: "string", Required: false,
			Pattern: "host:port (Iran role only; the second down dial target)"},
		{Name: "SPLIT_DOWN_CARRIER2_SNI", Type: "string", Required: false,
			Pattern: "lowercase RFC 1123 hostname (Germany role only; the second down carrier's TLS 1.3 SNI)"},
		{Name: "SPLIT_POLICY_MODE", Type: "string", Required: false,
			Pattern: "static|adaptive (both roles)"},
		{Name: "SPLIT_POLICY_TOP_K", Type: "int", Required: false, Min: 1, Max: 8},
		{Name: "SPLIT_PROBING_ENABLED", Type: "bool", Required: false},
		{Name: "SPLIT_PROBE_URL", Type: "string", Required: false,
			Pattern: "operator-owned http(s) URL with a host (no third-party default)"},
		{Name: "SPLIT_PROBE_DAILY_BUDGET", Type: "int", Required: false, Min: 0},
		{Name: "SPLIT_TTFB_BASELINE_MS", Type: "int", Required: false, Min: 0, Max: 30000},
	},
	ValidationEndpoint: "/api/v2/changes/{id}/multicarrier-validate",
	ValidationStatus:   "active",
}

// c4SchemaForConcept returns the C4 schema for a concept name.
func c4SchemaForConcept(name string) (ConceptSchema, bool) {
	switch name {
	case c4ConceptRoutingPlane:
		return c4RoutingSchema, true
	case c4ConceptMultiCarrier:
		return c4MultiCarrierSchema, true
	}
	return ConceptSchema{}, false
}

// c4Flag reports whether the C4 per-capability apply flag for the given
// concept is enabled. nil Control config → all flags off.
func (s *Server) c4Flag(concept string) bool {
	if s.cfg == nil || s.cfg.Control == nil {
		return false
	}
	flags := s.cfg.Control.C4Flags
	switch concept {
	case c4ConceptRoutingPlane:
		return flags.RoutingApply
	case c4ConceptMultiCarrier:
		return flags.MultiCarrierApply
	}
	return false
}

// c4CoordinatedFlag reports whether the coordinated-apply flag is on.
func (s *Server) c4CoordinatedFlag() bool {
	if s.cfg == nil || s.cfg.Control == nil {
		return false
	}
	return s.cfg.Control.C4Flags.CoordinatedApply
}

// ---------------------------------------------------------------------------
// request / response shapes (strict decode; the agent owns the truth)
// ---------------------------------------------------------------------------

// c4ValidateRequest is the strictly-decoded body for a C4 validate POST.
type c4ValidateRequest struct {
	Role string            `json:"role"`
	Set  map[string]string `json:"set"`
}

// c4ApplyRequest is the strictly-decoded body for a C4 apply POST.
type c4ApplyRequest struct {
	Role         string            `json:"role"`
	Set          map[string]string `json:"set"`
	Confirm      string            `json:"confirm"` // must be "RESTART"
	Reason       string            `json:"reason,omitempty"`
	BaseRevision string            `json:"baseRevision,omitempty"`
}

// c4ApplyResponse is the forwarded C4 apply result. It surfaces the
// restart warning and the peer-change-required note; it never carries
// secret values (the agent redacts at the source).
type c4ApplyResponse struct {
	Outcome            string `json:"outcome"`
	Revision           string `json:"revision"`
	PrevRevision       string `json:"prevRevision"`
	ChangeID           string `json:"changeId"`
	RestartRequired    bool   `json:"restartRequired"`
	RestartWarning     string `json:"restartWarning"`
	XrayRestarted      bool   `json:"xrayRestarted,omitempty"`
	PeerChangeRequired string `json:"peerChangeRequired,omitempty"`
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// c4HandleRoutingSchema serves the public-field schema for the routing
// plane concept.
func (s *Server) c4HandleRoutingSchema(w http.ResponseWriter) {
	schema := c4RoutingSchema
	flagOn := s.c4Flag(c4ConceptRoutingPlane)
	schema.Editable = flagOn
	if !flagOn {
		schema.Status = "read-only"
		schema.EditDisabledReason = "routing editing is off in this build (per-capability flag routingApply=false)"
	} else {
		schema.Status = "editable"
	}
	writeJSON(w, http.StatusOK, schema)
}

// c4HandleMultiCarrierSchema serves the public-field schema for the
// multi-carrier control concept.
func (s *Server) c4HandleMultiCarrierSchema(w http.ResponseWriter) {
	schema := c4MultiCarrierSchema
	flagOn := s.c4Flag(c4ConceptMultiCarrier)
	schema.Editable = flagOn
	if !flagOn {
		schema.Status = "read-only"
		schema.EditDisabledReason = "multi-carrier editing is off in this build (per-capability flag multiCarrierApply=false)"
	} else {
		schema.Status = "editable"
	}
	writeJSON(w, http.StatusOK, schema)
}

// c4HandleRoutingValidate forwards the routing validate op to the agent.
// Read-only validate is always available (the UI renders the section
// read-only even when the apply flag is off).
func (s *Server) c4HandleRoutingValidate(w http.ResponseWriter, r *http.Request, changeID string) {
	if r.Header.Get(c2ControlHeader) != "1" {
		writeJSONError(w, http.StatusForbidden, "missing control CSRF header "+c2ControlHeader+": 1")
		return
	}
	if s.c2AgentFor("c4-routing-validate") == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: no control agent socket is configured on this host")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, c1BodyLimit))
	dec.DisallowUnknownFields()
	var req c4ValidateRequest
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid validate body: "+err.Error())
		return
	}
	if req.Role == "" {
		role, ok := s.c2RoleForServer(changeID)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "role required (germany or iran)")
			return
		}
		req.Role = role
	}

	res, err := s.c2AgentFor("c4-routing-validate").Call(r.Context(), "c4-routing-validate", c2ReqID(), changeID, changeID, map[string]any{
		"role": req.Role,
		"set":  req.Set,
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
	writeJSON(w, http.StatusOK, map[string]any{
		"role":            req.Role,
		"flagEnabled":     s.c4Flag(c4ConceptRoutingPlane),
		"valid":           data["valid"],
		"errors":          data["errors"],
		"restartRequired": true,
		"diff":            data["diff"],
	})
}

// c4HandleRoutingApply forwards the routing apply op, gated by the
// per-capability flag and the confirm token.
func (s *Server) c4HandleRoutingApply(w http.ResponseWriter, r *http.Request, changeID string) {
	if !s.c4Flag(c4ConceptRoutingPlane) {
		writeJSONError(w, http.StatusServiceUnavailable,
			c4RoutingFlagOffCode+": the C4 routing apply plane is off in this build (control.c4Flags.routingApply=false); the read-only schema and validate remain available")
		return
	}
	if r.Header.Get(c2ControlHeader) != "1" {
		writeJSONError(w, http.StatusForbidden, "missing control CSRF header "+c2ControlHeader+": 1")
		return
	}
	if s.c2AgentFor("c4-routing-apply") == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: no control agent socket is configured on this host")
		return
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, c1BodyLimit))
	dec.DisallowUnknownFields()
	var req c4ApplyRequest
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid apply body: "+err.Error())
		return
	}
	if req.Confirm != c2ConfirmToken {
		writeJSONError(w, http.StatusBadRequest,
			"confirm token: the body must carry confirm=\""+c2ConfirmToken+"\" (every C4 routing change restarts the affected splitter service; the UI shows a 10 s countdown)")
		return
	}
	if req.Role == "" {
		role, ok := s.c2RoleForServer(changeID)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "role required (or changeId must name a configured server)")
			return
		}
		req.Role = role
	}

	res, err := s.c2AgentFor("c4-routing-apply").Call(r.Context(), "c4-routing-apply", c2ReqID(), changeID, changeID, map[string]any{
		"role":         req.Role,
		"set":          req.Set,
		"baseRevision": req.BaseRevision,
		"reason":       req.Reason,
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
	resp := c4ApplyResponse{
		Outcome:         strVal(data, "outcome"),
		Revision:        strVal(data, "revision"),
		PrevRevision:    strVal(data, "prevRevision"),
		ChangeID:        changeID,
		RestartRequired: true,
		RestartWarning:  "the splitter service restarted; the tunnel was briefly unavailable (estimated 10 s)",
	}
	writeJSON(w, http.StatusOK, resp)
}

// c4HandleMultiCarrierValidate forwards the multi-carrier validate op.
func (s *Server) c4HandleMultiCarrierValidate(w http.ResponseWriter, r *http.Request, changeID string) {
	if r.Header.Get(c2ControlHeader) != "1" {
		writeJSONError(w, http.StatusForbidden, "missing control CSRF header "+c2ControlHeader+": 1")
		return
	}
	if s.c2AgentFor("c4-mc-validate") == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: no control agent socket is configured on this host")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, c1BodyLimit))
	dec.DisallowUnknownFields()
	var req c4ValidateRequest
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid validate body: "+err.Error())
		return
	}
	if req.Role == "" {
		role, ok := s.c2RoleForServer(changeID)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "role required (germany or iran)")
			return
		}
		req.Role = role
	}

	res, err := s.c2AgentFor("c4-mc-validate").Call(r.Context(), "c4-mc-validate", c2ReqID(), changeID, changeID, map[string]any{
		"role": req.Role,
		"set":  req.Set,
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
	writeJSON(w, http.StatusOK, map[string]any{
		"role":            req.Role,
		"flagEnabled":     s.c4Flag(c4ConceptMultiCarrier),
		"valid":           data["valid"],
		"errors":          data["errors"],
		"restartRequired": true,
		"xrayAffected":    data["xrayAffected"],
		"diff":            data["diff"],
	})
}

// c4HandleMultiCarrierApply forwards the multi-carrier apply op, gated
// by the per-capability flag and the confirm token. An xray-affected
// change (SNI/listener/master flip) additionally restarts the xray unit
// and surfaces the peer-change-required note.
func (s *Server) c4HandleMultiCarrierApply(w http.ResponseWriter, r *http.Request, changeID string) {
	if !s.c4Flag(c4ConceptMultiCarrier) {
		writeJSONError(w, http.StatusServiceUnavailable,
			c4MultiCarrierFlagOffCode+": the C4 multi-carrier apply plane is off in this build (control.c4Flags.multiCarrierApply=false); the read-only schema and validate remain available")
		return
	}
	if r.Header.Get(c2ControlHeader) != "1" {
		writeJSONError(w, http.StatusForbidden, "missing control CSRF header "+c2ControlHeader+": 1")
		return
	}
	if s.c2AgentFor("c4-mc-apply") == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: no control agent socket is configured on this host")
		return
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, c1BodyLimit))
	dec.DisallowUnknownFields()
	var req c4ApplyRequest
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid apply body: "+err.Error())
		return
	}
	if req.Confirm != c2ConfirmToken {
		writeJSONError(w, http.StatusBadRequest,
			"confirm token: the body must carry confirm=\""+c2ConfirmToken+"\" (every C4 multi-carrier change restarts the affected splitter service; the UI shows a 10 s countdown)")
		return
	}
	if req.Role == "" {
		role, ok := s.c2RoleForServer(changeID)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "role required (or changeId must name a configured server)")
			return
		}
		req.Role = role
	}

	res, err := s.c2AgentFor("c4-mc-apply").Call(r.Context(), "c4-mc-apply", c2ReqID(), changeID, changeID, map[string]any{
		"role":         req.Role,
		"set":          req.Set,
		"baseRevision": req.BaseRevision,
		"reason":       req.Reason,
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
	resp := c4ApplyResponse{
		Outcome:         strVal(data, "outcome"),
		Revision:        strVal(data, "revision"),
		PrevRevision:    strVal(data, "prevRevision"),
		ChangeID:        changeID,
		RestartRequired: true,
		RestartWarning:  "the splitter service restarted; the tunnel was briefly unavailable (estimated 10 s)",
	}
	if xrayRestarted, ok := data["xrayRestarted"].(bool); ok {
		resp.XrayRestarted = xrayRestarted
		resp.RestartWarning = "the splitter AND xray services restarted; the tunnel was briefly unavailable (estimated 10 s)"
	}
	if peerNote, ok := data["peerChangeRequired"].(string); ok {
		resp.PeerChangeRequired = peerNote
	}
	writeJSON(w, http.StatusOK, resp)
}
