// control_c2.go — Phase C2: the dashboard's forwarding side of the
// control APPLY plane (plans/dashboard-control-design.md §3.2, §6, §8,
// §12 C2).
//
// The web process NEVER executes systemctl, writes /etc, or touches the
// revision store. Its only host-facing path for C2 is the ControlClient,
// which dials the root-owned agent's Unix socket and forwards one typed
// frame. When the socket is absent or the agent refuses the peer check,
// the endpoints answer 503 with a clear reason — the plane never fails
// open (design §3.2, §8).
//
// Endpoints added here:
//   - POST /api/v2/changes/{changeId}/apply  (confirm token + CSRF header)
//   - GET  /api/v2/revisions
//   - GET  /api/v2/audit
//   - POST /api/v2/rollback/lkg  is deliberately NOT added: revert-lkg
//     is callable from the agent and the CLI only, never the web process
//     (design §6.6).
//
// Feature flag: the whole apply plane is OFF unless the config
// explicitly enables it (Control.ApplyEnabled, default false). The C1
// read-only validation endpoint and every other read path keep working
// when the flag is off.

package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// c2DefaultSocketPath is where the systemd socket unit (control-agent)
// listens; it is group-0660 tunneldash-ctl so only the dashboard user
// can connect, and the agent's SO_PEERCRED check is the second gate.
const c2DefaultSocketPath = "/run/split-tunnel-ctl/control.sock"

// c2ConfirmToken is the typed confirmation the operator must send for a
// C2 apply (design §6.3). Every key in the C2 editable concept is read
// at splitter process start, so every C2 change restarts the affected
// splitter service; the token is the single "I read the restart
// warning" gate before the forward.
const c2ConfirmToken = "RESTART"

// c2ControlHeader is the control-plane CSRF header (design §7.1). It is
// IN ADDITION to the C1 X-Tunneldash-Request header the middleware
// already enforces: a cross-site script cannot set either.
const c2ControlHeader = "X-TunnelDash-Control"

// c2RequestTimeout bounds one socket round-trip; a wedged agent must
// never hold a web request forever.
const c2RequestTimeout = 60 * time.Second

// c2DialTimeout bounds the socket connect step.
const c2DialTimeout = 2 * time.Second

// ControlConfig is the dashboard's C2/C3 plane configuration.
type ControlConfig struct {
	// ApplyEnabled turns on the C2 apply plane on this web process.
	// Default (false): POST apply answers 503 control_apply_disabled;
	// the read-only revisions/audit forwarding still works when the
	// agent is reachable.
	ApplyEnabled bool `json:"applyEnabled"`
	// SocketPath is the agent's Unix socket. Default c2DefaultSocketPath.
	SocketPath string `json:"socketPath"`
	// C3Flags are the C3 per-capability feature flags for the Reality
	// inbound editing surface (all default false; the C5 rollout model
	// lets each capability be enabled/disabled independently of the C2
	// policy plane and of each other).
	C3Flags c3ControlFlags `json:"c3Flags,omitempty"`
	// C4Flags are the C4 per-capability feature flags for the routing
	// plane and the multi-carrier control surface (all default false;
	// the C5 rollout model).
	C4Flags c4ControlFlags `json:"c4Flags,omitempty"`
}

// C2Agent is the injectable forwarder seam. The production
// implementation is *ControlClient (the Unix socket); tests substitute
// an in-memory fake so the 4xx/5xx mapping is exercised without a
// socket or an agent process.
type C2Agent interface {
	// Call forwards one op and returns the decoded result. An error
	// means the agent was unreachable (the handler answers 503).
	Call(ctx context.Context, op, reqID, changeID, idemKey string, payload any) (c2AgentResult, error)
}

// c2AgentResult is one decoded agent response frame.
type c2AgentResult struct {
	OK    bool
	Data  any
	Error *c2AgentError
}

type c2AgentError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ControlClient speaks the agent's v1 newline-JSON protocol over a Unix
// socket. One frame per connection, size-bounded, strict decode — the
// exact contract the agent enforces (internal/controlagent/protocol.go).
type ControlClient struct {
	socketPath string
	// dialer is injectable for tests (a pipe pair or in-memory transport).
	dialer func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewControlClient binds the client to one socket path.
func NewControlClient(socketPath string) *ControlClient {
	if socketPath == "" {
		socketPath = c2DefaultSocketPath
	}
	return &ControlClient{socketPath: socketPath}
}

// Call implements C2Agent over the Unix socket.
func (c *ControlClient) Call(ctx context.Context, op, reqID, changeID, idemKey string, payload any) (c2AgentResult, error) {
	if c == nil {
		return c2AgentResult{}, errors.New("control plane not configured")
	}
	dial := c.dialer
	if dial == nil {
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			d.Timeout = c2DialTimeout
			return d.DialContext(ctx, network, address)
		}
	}
	conn, err := dial(ctx, "unix", c.socketPath)
	if err != nil {
		return c2AgentResult{}, fmt.Errorf("control agent socket %s unavailable: %w", c.socketPath, err)
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(c2RequestTimeout))

	req := c2WireFrame{
		V:              1,
		Op:             op,
		ReqID:          reqID,
		IdempotencyKey: idemKey,
		ChangeID:       changeID,
		Payload:        payload,
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return c2AgentResult{}, err
	}
	if len(raw) > 16<<10 {
		return c2AgentResult{}, errors.New("control frame exceeds 16 KiB")
	}
	if _, err := conn.Write(append(raw, '\n')); err != nil {
		return c2AgentResult{}, fmt.Errorf("control agent write: %w", err)
	}

	// Read one response line, size-bounded.
	buf := make([]byte, 16<<10+1)
	n, err := readUnixLine(conn, buf)
	if err != nil {
		// EOF with no data: the agent closed without a response —
		// the documented peer-check rejection (design §3.2). Map to
		// 503, never a success.
		return c2AgentResult{}, fmt.Errorf("control agent closed the connection (peer check or transport failure): %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	var resp c2WireFrame
	dec := json.NewDecoder(newByteReader(buf[:n]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resp); err != nil {
		return c2AgentResult{}, fmt.Errorf("control agent response: %w", err)
	}
	if dec.More() {
		return c2AgentResult{}, errors.New("control agent sent more than one frame")
	}
	out := c2AgentResult{OK: resp.OK, Data: resp.Data}
	if resp.Error != nil {
		out.Error = &c2AgentError{Code: resp.Error.Code, Message: resp.Error.Message}
	}
	return out, nil
}

// c2WireFrame mirrors the agent's Frame (internal/controlagent/protocol.go).
// It is re-declared here so the web process stays free of any import of
// the root-agent package: the wire contract is a small, stable JSON shape.
type c2WireFrame struct {
	V              int         `json:"v"`
	Op             string      `json:"op"`
	ReqID          string      `json:"reqId"`
	IdempotencyKey string      `json:"idempotencyKey,omitempty"`
	ChangeID       string      `json:"changeId,omitempty"`
	Payload        any         `json:"payload"`
	OK             bool        `json:"ok"`
	Data           any         `json:"data,omitempty"`
	Error          *c2AgentErr `json:"error,omitempty"`
}

type c2AgentErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// readUnixLine reads up to len(buf)-1 bytes of one newline-terminated
// frame from conn.
func readUnixLine(conn net.Conn, buf []byte) (int, error) {
	// The connect deadline was consumed by the write; arm a read
	// deadline for the response.
	_ = conn.SetReadDeadline(time.Now().Add(c2RequestTimeout))
	var got int
	for got < len(buf)-1 {
		n, err := conn.Read(buf[got:])
		if n > 0 {
			got += n
			if got > 0 && buf[got-1] == '\n' {
				return got, nil
			}
		}
		if err != nil {
			return got, err
		}
	}
	return got, errors.New("control frame exceeds 16 KiB")
}

// newByteReader / byteReader keep the strict-decode path in one place.
func newByteReader(b []byte) *byteReader { return &byteReader{b: b} }

type byteReader struct {
	b   []byte
	pos int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

// ---------------------------------------------------------------------------
// Server-side: flag + forwarding handlers
// ---------------------------------------------------------------------------

// c2ApplyRequest is the strictly-decoded body for
// POST /api/v2/changes/{changeId}/apply.
type c2ApplyRequest struct {
	Role         string            `json:"role"`
	Set          map[string]string `json:"set"`
	BaseRevision string            `json:"baseRevision,omitempty"`
	Reason       string            `json:"reason,omitempty"`
	// Confirm must equal c2ConfirmToken ("RESTART"): the operator has
	// read the restart warning (design §6.3).
	Confirm string `json:"confirm"`
}

// c2ApplyResponse is the forwarded success body.
type c2ApplyResponse struct {
	Outcome      string `json:"outcome"`
	Revision     string `json:"revision"`
	PrevRevision string `json:"prevRevision"`
	ChangeID     string `json:"changeId"`
}

// c2Enabled reports whether the C2 apply plane is explicitly turned on
// in this web process's config.
func (s *Server) c2Enabled() bool {
	if s.cfg == nil || s.cfg.Control == nil {
		return false
	}
	return s.cfg.Control.ApplyEnabled
}

// c2AgentFor returns the configured forwarder, or nil when no agent is
// wired (NewServer leaves it nil; the deploy path sets it).
func (s *Server) c2AgentFor(op string) C2Agent {
	return s.c2Agent
}

// SetControlAgent wires the C2 forwarder (nil keeps the plane inert).
func (s *Server) SetControlAgent(a C2Agent) { s.c2Agent = a }

// c2HandleChangesApply is the handler for POST /api/v2/changes/{id}/apply.
//
//   - flag off → 503 control_apply_disabled (read-only C1 keeps working)
//   - missing CSRF header → 403
//   - bad confirm token → 400
//   - agent error code mapping: validation_failed→422, frozen→423,
//     apply_in_progress/idempotency_conflict/stale_base→409,
//     rate_limited→429, recovery_required→423, else→502
//   - agent unreachable (dial/read failure or silent close) → 503
//     agent_unavailable (NEVER fail open)
func (s *Server) c2HandleChangesApply(w http.ResponseWriter, r *http.Request, changeID string) {
	if !s.c2Enabled() {
		writeJSONError(w, http.StatusServiceUnavailable,
			"control_apply_disabled: the C2 apply plane is off in this build (control.applyEnabled=false); validation remains available at /api/v2/changes/validate")
		return
	}
	if r.Header.Get(c2ControlHeader) != "1" {
		writeJSONError(w, http.StatusForbidden, "missing control CSRF header "+c2ControlHeader+": 1")
		return
	}
	if s.c2AgentFor("apply") == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: no control agent socket is configured on this host")
		return
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, c1BodyLimit))
	dec.DisallowUnknownFields()
	var req c2ApplyRequest
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid apply body: "+err.Error())
		return
	}
	if req.Confirm != c2ConfirmToken {
		writeJSONError(w, http.StatusBadRequest,
			fmt.Sprintf("confirm token: the body must carry confirm=%q (every C2 change restarts the affected splitter service)", c2ConfirmToken))
		return
	}
	if req.Role == "" {
		// Derive the role from the configured server list when the body
		// omits it: the C2 concept is per-role.
		role, ok := s.c2RoleForServer(changeID)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "role required (or changeId must name a configured server)")
			return
		}
		req.Role = role
	}

	res, err := s.c2AgentFor("apply").Call(r.Context(), "apply", c2ReqID(), changeID, changeID, map[string]any{
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
	writeJSON(w, http.StatusOK, c2ApplyResponse{
		Outcome:      strVal(data, "outcome"),
		Revision:     strVal(data, "revision"),
		PrevRevision: strVal(data, "prevRevision"),
		ChangeID:     changeID,
	})
}

// c2RoleForServer maps a changeId that names a configured server to that
// server's role.
func (s *Server) c2RoleForServer(changeID string) (string, bool) {
	for _, srv := range s.cfg.Servers {
		if changeID == srv.ID {
			return srv.Role, true
		}
	}
	return "", false
}

// c2AgentError maps the agent's closed error-code space onto HTTP.
func (s *Server) c2AgentError(w http.ResponseWriter, e *c2AgentError) {
	if e == nil {
		writeJSONError(w, http.StatusBadGateway, "agent reported a failure with no code")
		return
	}
	switch e.Code {
	case "validation_failed":
		writeJSONError(w, http.StatusUnprocessableEntity, e.Message)
	case "frozen", "recovery_required":
		// 423 Locked: the agent is deliberately refusing mutation.
		writeJSONError(w, http.StatusLocked, e.Message)
	case "apply_in_progress", "idempotency_conflict", "stale_base":
		writeJSONError(w, http.StatusConflict, e.Message)
	case "rate_limited":
		writeJSONError(w, http.StatusTooManyRequests, e.Message)
	case "invalid_json", "unknown_field", "unknown_op":
		writeJSONError(w, http.StatusBadRequest, e.Message)
	default:
		writeJSONError(w, http.StatusBadGateway, "agent error ("+e.Code+"): "+e.Message)
	}
}

// c2HandleRevisions is the handler for GET /api/v2/revisions (read-only
// forwarding; works even when the apply flag is off — design §12 C2:
// read-only endpoints keep working).
func (s *Server) c2HandleRevisions(w http.ResponseWriter, r *http.Request) {
	s.c2HandleReadForward(w, r, "revisions")
}

// c2HandleAudit is the handler for GET /api/v2/audit (read-only
// forwarding of the redacted agent audit tail).
func (s *Server) c2HandleAudit(w http.ResponseWriter, r *http.Request) {
	s.c2HandleReadForward(w, r, "audit")
}

// c2HandleReadForward is the shared GET forwarder: 503 when no agent is
// wired/reachable, the agent's data otherwise (never a fabricated list).
func (s *Server) c2HandleReadForward(w http.ResponseWriter, r *http.Request, op string) {
	a := s.c2AgentFor(op)
	if a == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: no control agent socket is configured on this host")
		return
	}
	res, err := a.Call(r.Context(), op, c2ReqID(), "", "", map[string]any{})
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "agent_unavailable: "+err.Error())
		return
	}
	if !res.OK {
		s.c2AgentError(w, res.Error)
		return
	}
	writeJSON(w, http.StatusOK, res.Data)
}

// c2ReqID mints a short random request id (the agent records it as the
// audit actor for forwarded ops).
func c2ReqID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "web-" + hex.EncodeToString(b)
}

// strVal plucks a string out of an any-map ("" when absent/non-string).
func strVal(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
