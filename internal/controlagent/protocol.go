// Package controlagent implements the C2 apply plane of the dashboard
// control design (plans/dashboard-control-design.md §3, §5, §8, §12 C2):
// a root-owned, socket-activated helper that validates, snapshots,
// atomically swaps, restarts, verifies and auto-rolls-back a strictly
// typed set of splitter-policy changes, driven over a Unix socket with
// a SO_PEERCRED peer check. The web process never calls into this
// package directly to mutate state; it only forwards typed requests and
// reads back results, revisions and audit entries.
//
// Scope of C2: the splitter-policy / multi-carrier env set only
// (SPLIT_POLICY_MODE, SPLIT_POLICY_TOPK, SPLIT_TTFB_BASELINE_MS,
// SPLIT_PROBE_DAILY_BUDGET). No Reality inbound editing, no routing.
// No xray restart. No host file changes outside the agent's own
// revision store, its kill-switch file, its audit log, and the
// splitter's live env file that a transaction owns.
package controlagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ProtocolVersion is the only supported wire version for C2.
const ProtocolVersion = 1

// MaxFrameBytes bounds one request frame (the design specifies 16 KiB
// for control requests; the dashboard middleware already caps POST
// bodies lower, and the agent re-checks here as its own boundary).
const MaxFrameBytes = 16 << 10

// ErrClosed is returned to callers on any connection closed mid-frame
// or refused by the peer check. It is a sentinel so the dashboard
// client can map it to a 503 "agent_unavailable" response without
// leaking internals.
var ErrClosed = errors.New("controlagent: connection closed")

// ErrPeerRejected is returned when the SO_PEERCRED peer check fails
// (uid/gid/exe mismatch, or the check is unavailable on this platform
// and is therefore failing closed, per the design's fail-closed
// stance on any missing attestation).
var ErrPeerRejected = errors.New("controlagent: peer identity rejected")

// Op names. The set is intentionally closed and small: exactly what
// the design lists for C2. "validate" is the pre-check; "apply" is
// the heavy op; "rollback-lkg" is the kill-switch companion;
// "status"/"revisions"/"audit" are read paths.
const (
	OpValidate    = "validate"
	OpApply       = "apply"
	OpRollbackLKG = "rollback-lkg"
	OpStatus      = "status"
	OpRevisions   = "revisions"
	OpAudit       = "audit"
	// C3 inbound editing surface (inbounds.go).
	OpInboundsValidate   = "inbounds-validate"
	OpInboundsApply      = "inbounds-apply"
	OpInboundsRotate     = "inbounds-rotate"
	OpInboundsExportBlob = "inbounds-export-blob"
	OpInboundsImportBlob = "inbounds-import-blob"
	// C4 routing plane + multi-carrier control (c4.go). The C4
	// coordinated two-host flow is built on these: each host runs
	// prepare (validate + xray -test where applicable, no writes), then
	// a two-phase commit/abort handshake; a single-agent host stages a
	// peer Blob B export instead of the handshake (peerChangeRequired).
	OpC4RoutingValidate = "c4-routing-validate"
	OpC4RoutingApply    = "c4-routing-apply"
	OpC4MCValidate      = "c4-mc-validate"
	OpC4MCApply         = "c4-mc-apply"
)

// knownOps is the closed set of op names the agent accepts on the
// socket. Anything else is a protocol error (400), not a silent
// pass-through.
var knownOps = map[string]bool{
	OpValidate:    true,
	OpApply:       true,
	OpRollbackLKG: true,
	OpStatus:      true,
	OpRevisions:   true,
	OpAudit:       true,
	// C3
	OpInboundsValidate:   true,
	OpInboundsApply:      true,
	OpInboundsRotate:     true,
	OpInboundsExportBlob: true,
	OpInboundsImportBlob: true,
	// C4
	OpC4RoutingValidate: true,
	OpC4RoutingApply:    true,
	OpC4MCValidate:      true,
	OpC4MCApply:         true,
}

// Frame is one newline-delimited JSON request or response. Exactly
// one frame per connection (the design's v1 protocol: one request,
// one response, close). Unknown fields are rejected (Strict decode,
// DisallowUnknownFields) so a forward-compat drift never becomes a
// silent acceptance.
type Frame struct {
	V              int         `json:"v"`
	Op             string      `json:"op"`
	ReqID          string      `json:"reqId"`
	IdempotencyKey string      `json:"idempotencyKey,omitempty"`
	ChangeID       string      `json:"changeId,omitempty"`
	Payload        interface{} `json:"payload"`
	OK             bool        `json:"ok"`
	Data           interface{} `json:"data,omitempty"`
	Error          *FrameError `json:"error,omitempty"`
}

// FrameError is the response-side error shape. Message never
// contains a secret value (see transaction redaction).
type FrameError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrorCodes are the closed, documented error codes the agent emits.
// They intentionally mirror the HTTP taxonomy in the design (§8) so
// the dashboard can map them 1:1 without a second vocabulary.
const (
	ErrCodeInvalidJSON      = "invalid_json"
	ErrCodeUnknownField     = "unknown_field"
	ErrCodeUnknownOp        = "unknown_op"
	ErrCodeValidation       = "validation_failed"
	ErrCodeFrozen           = "frozen"
	ErrCodeApplyInProgress  = "apply_in_progress"
	ErrCodeStaleBase        = "stale_base"
	ErrCodeIdempotency      = "idempotency_conflict"
	ErrCodeRateLimited      = "rate_limited"
	ErrCodeMinHealthy       = "min_healthy_violated"
	ErrCodeRecoveryRequired = "recovery_required"
	ErrCodeInternal         = "internal"
)

// decodeFrame parses one frame strictly.
func decodeFrame(raw []byte) (*Frame, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty frame", ErrClosed)
	}
	if len(raw) > MaxFrameBytes {
		return nil, fmt.Errorf("%w: frame exceeds %d bytes", ErrClosed, MaxFrameBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f Frame
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClosed, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: more than one JSON value in frame", ErrClosed)
	}
	return &f, nil
}

// encodeFrame serializes one response frame.
func encodeFrame(f *Frame) ([]byte, error) {
	return json.Marshal(f)
}

// validate checks version and op membership. It does NOT check the
// payload: that is the ControlPlane's job, keeping the transport layer
// free of business logic.
func (f *Frame) validate() error {
	if f.V != ProtocolVersion {
		return fmt.Errorf("%w: unsupported protocol version %d", ErrClosed, f.V)
	}
	if !knownOps[f.Op] {
		return fmt.Errorf("%w: unknown op %q", ErrClosed, f.Op)
	}
	return nil
}

// opResponseCode maps an unknown-op / malformed-frame error to the
// closed code space.
func opResponseCode(err error) string {
	if errors.Is(err, ErrClosed) {
		return ErrCodeInvalidJSON
	}
	return ErrCodeInternal
}
