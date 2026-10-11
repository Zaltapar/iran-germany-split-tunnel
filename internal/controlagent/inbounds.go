// inbounds.go — C3 Reality inbound editing surface
// (plans/dashboard-control-design.md §4.2, §4.3, §12 C3).
//
// Scope:
//   - Editable concepts: Germany Reality inbounds (listen port, SNI,
//     dest/redirect target, shortIds, enabled) and Iran consumer inbounds
//     (local port, remote host:port, publicKey ref, SNI, shortId, enabled).
//   - Keys are NEVER editable and NEVER returned: the API accepts a key
//     REFERENCE (a 12-hex sha256 fingerprint) only. A separate rotate-key
//     action generates a new keypair server-side on the host (pinned xray
//     x25519 equivalent, output redirected to a 0600 file, never in argv,
//     never returned to the browser). The old key is retained in the
//     revision store's pre/ copy during the transition; rotation is
//     blocked unless retainOld is set.
//   - Validation: port range, reserved ports (8443 + SSH 22 + any
//     operator-configured extras), intra-change port conflict, non-empty
//     valid SNI, shortId 16-lowercase-hex format, min-one-healthy
//     invariant (non-empty list, at least one enabled), secret-denylist
//     on field names.
//   - Apply path: reuses the C2 transaction discipline (lock, journal,
//     pre-snapshot, atomic swap, verify, auto-rollback) extended with a
//     ConfigTest hook (the equivalent of `xray run -test` on the
//     candidate — on Linux the agent invokes the pinned xray binary; in
//     tests it is faked). If the test fails, no swap occurs. After the
//     swap, only the affected xray service is restarted (xray-germany or
//     xray-consumer).
//   - Peer coupling: a Germany-side edit stages a Blob B export for the
//     Iran side; an Iran-side edit stages a Blob A export, until the C4
//     agent exists on both hosts. Export/import are explicit ops that
//     write only to operator-chosen 0600 files and never print the blob.
//
// The InboundSeam is optional: when nil on the Agent, every C3 inbound
// op fails closed with inbound_not_configured, so C2 behaviour is
// unchanged when C3 is not wired.

package controlagent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
)

// ---------------------------------------------------------------------------
// Error codes (C3-specific; extend the closed C2 set)
// ---------------------------------------------------------------------------

const (
	// ErrCodeInboundNotConfigured is returned when InboundSeam is nil.
	ErrCodeInboundNotConfigured = "inbound_not_configured"
	// ErrCodeConfigTestFailed is returned when xray run -test rejects the
	// candidate (design §5.2 F6). No swap occurred.
	ErrCodeConfigTestFailed = "config_test_failed"
	// ErrCodeRotationBlocked is returned when key rotation is attempted
	// without retaining the old key (design: rotation blocked unless the
	// old key is retained).
	ErrCodeRotationBlocked = "rotation_blocked"
)

// c3ConfirmToken is the typed restart confirmation for C3 applies
// (design D11: typed RESTART + 10 s countdown on the UI side).
const c3ConfirmToken = "RESTART"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// InboundSpec is one editable inbound concept (public fields only).
// KeyRef holds a 12-hex sha256 fingerprint prefix of the keypair —
// NEVER the key material itself.
type InboundSpec struct {
	// Instance is the stable identity: "a"/"b" (Germany) or
	// "consumer-a"/"consumer-b" (Iran).
	Instance string `json:"instance"`
	// Enabled is the per-inbound enable flag.
	Enabled bool `json:"enabled"`
	// Port is the Germany public listen port, or the Iran local
	// loopback listen port.
	Port int `json:"port,omitempty"`
	// SNI is the Reality TLS ServerName (required, non-empty).
	SNI string `json:"sni,omitempty"`
	// Dest is the Germany redirect/dest target (host:port).
	Dest string `json:"dest,omitempty"`
	// RemoteHost / RemotePort are the Iran consumer's Germany-side
	// down target.
	RemoteHost string `json:"remoteHost,omitempty"`
	RemotePort int    `json:"remotePort,omitempty"`
	// ShortID is the single 16-hex shortId (kept for the single-entry
	// schema; ShortIDs carries the multi form).
	ShortID string `json:"shortId,omitempty"`
	// ShortIDs is the multi-shortId list (each 16 lowercase hex chars).
	ShortIDs []string `json:"shortIds,omitempty"`
	// KeyRef is a 12-hex sha256 fingerprint of the keypair reference.
	// Key material is never accepted, stored, or returned by C3.
	KeyRef string `json:"keyRef,omitempty"`
}

// InboundChange is one inbound editing proposal (the wire payload for the
// C3 inbounds-validate / inbounds-apply ops).
type InboundChange struct {
	Role string `json:"role"` // "germany" or "iran"
	// Inbounds is the full desired inbound list (not a patch: the
	// min-one-healthy invariant is checked over the whole list).
	Inbounds []InboundSpec `json:"inbounds"`
	// BaseRevision is the optimistic-concurrency token (the current head).
	BaseRevision string `json:"baseRevision,omitempty"`
	// ChangeID is the operator/client-supplied change identifier; the
	// agent mints one when absent.
	ChangeID string `json:"changeId,omitempty"`
	// Reason is an operator audit note (never secret-bearing).
	Reason string `json:"reason,omitempty"`
	// ConfirmToken must equal "RESTART" for apply (design D11).
	ConfirmToken string `json:"confirmToken,omitempty"`
}

// RotateRequest is the key-rotation wire payload.
type RotateRequest struct {
	Role     string `json:"role"`
	Instance string `json:"instance"`
	// RetainOld MUST be true: rotation is blocked unless the old key is
	// retained in the revision store for the transition window.
	RetainOld bool   `json:"retainOld"`
	ChangeID  string `json:"changeId,omitempty"`
}

// RotateResponse is the rotation result. No key material: only a
// fingerprint of the NEW public key and a retention statement.
type RotateResponse struct {
	NewKeyFingerprint string `json:"newKeyFingerprint"`
	OldKeyRetained    bool   `json:"oldKeyRetained"`
	Revision          string `json:"revision"`
	Outcome           string `json:"outcome"`
}

// BlobExportRequest is the blob-export wire payload (C3 staging ops, D10).
type BlobExportRequest struct {
	Role     string `json:"role"`     // "germany" (blob b) or "iran" (blob a)
	BlobKind string `json:"blobKind"` // "a" or "b"
	// OutPath is the operator-chosen absolute 0600 file; the blob is
	// written there and never returned to the caller.
	OutPath  string `json:"outPath"`
	ChangeID string `json:"changeId,omitempty"`
}

// BlobExportResponse is the export result: fingerprint only.
type BlobExportResponse struct {
	Fingerprint string `json:"fingerprint"`
	OutPath     string `json:"outPath"`
	Outcome     string `json:"outcome"`
}

// BlobImportRequest is the blob-import wire payload.
type BlobImportRequest struct {
	Role     string `json:"role"`
	BlobKind string `json:"blobKind"` // "a" or "b"
	// InPath is the operator-chosen absolute 0600 file to import.
	InPath   string `json:"inPath"`
	ChangeID string `json:"changeId,omitempty"`
}

// BlobImportResponse is the import result.
type BlobImportResponse struct {
	Revision string `json:"revision"`
	Outcome  string `json:"outcome"`
}

// InboundApplyOp is one inbound apply request (decoded from the frame).
type InboundApplyOp struct {
	Change         InboundChange
	IdempotencyKey string
	Actor          string
}

// ---------------------------------------------------------------------------
// InboundSeam — the C3 host-facing executor
// ---------------------------------------------------------------------------

// InboundSeam is the C3 host-facing executor. Production (splitterctl)
// wires it to the live xray config paths, the pinned xray binary for the
// -test gate and x25519 keygen, and the xray systemd units. Tests inject
// a fake that records calls and can fail on demand.
//
// No method may return, log, or print key material. RotateKeypair
// returns only a fingerprint; ExportBlob writes to a 0600 file and
// returns only the blob's fingerprint.
type InboundSeam interface {
	// LiveXrayConfigPath is the absolute live xray config for the role
	// ("" when the role has no live file yet — the agent still
	// snapshots an empty baseline so rollback is defined).
	LiveXrayConfigPath(role string) string
	// BaseInbounds returns the current inbound specs (public fields only;
	// key refs as fingerprints) for diff baselines.
	BaseInbounds(role string) ([]InboundSpec, error)
	// WriteXrayCandidate renders the desired inbound list into a sandbox
	// xray config file and returns its path.
	WriteXrayCandidate(role string, inbounds []InboundSpec) (string, error)
	// ConfigTest runs the equivalent of `xray run -test -config <path>`
	// on the candidate. On Linux the agent invokes the pinned xray
	// binary; tests inject a fake. A failure here means NO swap.
	ConfigTest(role, candidatePath string) error
	// RestartXray restarts ONLY the affected xray service
	// (xray-germany for role=germany, xray-consumer for role=iran).
	RestartXray(role string) error
	// VerifyXray confirms the service is active and the expected
	// listeners respond.
	VerifyXray(role string) error
	// RestoreXrayFile restores the live xray config from a backup path
	// (the rollback step).
	RestoreXrayFile(role, livePath, backupPath string) error
	// RotateKeypair generates a new keypair on the host via the pinned
	// xray x25519 equivalent. The binary's output is redirected into a
	// 0600 file (never argv, never printed to the browser). The caller
	// is responsible for PreSnapshot'ing the live config first so the
	// old key remains in the revision store's pre/ copy. Only the new
	// key's sha256 fingerprint prefix is returned.
	RotateKeypair(role, instance string) (newKeyFingerprint string, err error)
	// ExportBlob writes Blob A (role=iran) or Blob B (role=germany) to
	// outPath (0600, operator-chosen absolute path). Returns the blob's
	// sha256 fingerprint; the blob content is never returned.
	ExportBlob(role, blobKind, outPath string) (fingerprint string, err error)
	// ImportBlob validates and stages a blob from inPath into the
	// revision store (fingerprint only in the meta; the blob bytes are
	// copied 0600 into the revision's files/ dir). Returns the new
	// revision id. The peer host applies it with its own C3/C4 flow.
	ImportBlob(role, blobKind, inPath string) (revision string, err error)
}

// ---------------------------------------------------------------------------
// Validators (C3 inbound rules)
// ---------------------------------------------------------------------------

// c3DefaultReservedPorts is the built-in reserved-port set (the
// dashboard-reserved 8443 from config.ReservedPort and SSH 22).
// Operator-configured extras are passed per call.
var c3DefaultReservedPorts = map[int]bool{
	8443: true, // dashboard TLS listener (config.ReservedPort)
	22:   true, // SSH
}

// c3SecretDenylist rejects any field name matching a secret fragment
// (design §7.5, F-6): secret-named fields are refused at validation.
var c3SecretDenylist = []string{
	"secret", "key", "token", "password", "basepath", "credential", "private",
}

// c3FieldIsSecret reports whether a field name matches the secret denylist.
func c3FieldIsSecret(name string) bool {
	ln := strings.ToLower(name)
	for _, sub := range c3SecretDenylist {
		if strings.Contains(ln, sub) {
			return true
		}
	}
	return false
}

// c3ShortIDRe is the 16-hex lowercase pattern (pairing.ValidShortID).
var c3ShortIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// c3KeyFingerprintRe is the 12-hex sha256 prefix shape for key refs.
var c3KeyFingerprintRe = regexp.MustCompile(`^[0-9a-f]{12}$`)

// ValidateInboundChange runs the pure C3 inbound gates over one candidate:
// (1) role known, (2) non-empty inbound list with at least one enabled
// (min-one-healthy), (3) port range + reserved-port + intra-change
// conflict, (4) SNI non-empty and valid, (5) shortId format, (6) key ref
// shape, (7) Iran remote target shape, (8) secret-denylist over every
// supplied field name. It returns a closed list of field-level errors
// (empty = valid). Every xray change restarts the affected service, so
// restartRequired is always true for this concept.
func ValidateInboundChange(change InboundChange, reservedPorts []int, suppliedFieldNames []string) []string {
	var errs []string

	// (1) Role.
	if change.Role != "germany" && change.Role != "iran" {
		errs = append(errs, "role: must be \"germany\" or \"iran\"")
		return errs
	}

	// (2) min-one-healthy: the list must not be empty.
	if len(change.Inbounds) == 0 {
		errs = append(errs, "inbounds: at least one inbound is required (min-one-healthy invariant)")
		return errs
	}

	// (8) Secret-denylist over every operator-supplied field name. The
	// wire payload is strictly decoded (unknown fields rejected), so any
	// secret-named field reaching the validator here was smuggled via a
	// known wrapper; refusing it explicitly is the fail-closed rule.
	for _, name := range suppliedFieldNames {
		if c3FieldIsSecret(name) {
			errs = append(errs, fmt.Sprintf("%s: secret-named field, never editable via the dashboard", name))
		}
	}

	// Reserved set = built-ins + operator extras.
	reserved := make(map[int]bool, len(c3DefaultReservedPorts)+len(reservedPorts))
	for p := range c3DefaultReservedPorts {
		reserved[p] = true
	}
	for _, p := range reservedPorts {
		reserved[p] = true
	}

	usedPorts := map[int]string{} // port → instance

	for i, in := range change.Inbounds {
		prefix := fmt.Sprintf("inbounds[%d]", i)

		if in.Instance == "" {
			errs = append(errs, prefix+".instance: must be non-empty")
			continue
		}

		// (3) Ports.
		if in.Port != 0 {
			if in.Port < 1 || in.Port > 65535 {
				errs = append(errs, prefix+".port: must be 1..65535")
			} else if reserved[in.Port] {
				errs = append(errs, fmt.Sprintf("%s.port: port %d is reserved; cannot be used for a Reality inbound", prefix, in.Port))
			} else if prev, conflict := usedPorts[in.Port]; conflict {
				errs = append(errs, fmt.Sprintf("%s.port: port %d conflicts with instance %q", prefix, in.Port, prev))
			} else {
				usedPorts[in.Port] = in.Instance
			}
		}

		// (4) SNI: required and valid (no IP literals).
		if in.SNI == "" {
			errs = append(errs, prefix+".sni: must be a non-empty SNI (TLS ServerName)")
		} else if !pairing.ValidSNI(in.SNI) {
			errs = append(errs, prefix+".sni: must be a lowercase RFC 1123 hostname (no IP literal, no port)")
		}

		// (5) shortId format.
		if in.ShortID != "" && !c3ShortIDRe.MatchString(in.ShortID) {
			errs = append(errs, prefix+".shortId: must be 16 lowercase hex characters")
		}
		for j, sid := range in.ShortIDs {
			if !c3ShortIDRe.MatchString(sid) {
				errs = append(errs, fmt.Sprintf("%s.shortIds[%d]: must be 16 lowercase hex characters", prefix, j))
			}
		}

		// (6) Key reference shape (fingerprint only, never material).
		if in.KeyRef != "" && !c3KeyFingerprintRe.MatchString(in.KeyRef) {
			errs = append(errs, prefix+".keyRef: must be a 12-hex sha256 fingerprint (key material is never accepted or returned)")
		}

		// (7) Iran remote target.
		if change.Role == "iran" {
			if in.RemotePort != 0 && (in.RemotePort < 1 || in.RemotePort > 65535) {
				errs = append(errs, prefix+".remotePort: must be 1..65535")
			}
			if in.RemoteHost != "" && !pairing.ValidUploadDomain(in.RemoteHost) {
				errs = append(errs, prefix+".remoteHost: must be a valid public host (IP or RFC 1123 domain)")
			}
		}

		// Dest shape (Germany): host:port.
		if in.Dest != "" {
			host, portStr, ok := splitHostPort(in.Dest)
			if !ok {
				errs = append(errs, prefix+".dest: must be a valid host:port string")
			} else {
				p, aerr := strconv.Atoi(portStr)
				if aerr != nil || p < 1 || p > 65535 {
					errs = append(errs, prefix+".dest: port component must be 1..65535")
				} else if reserved[p] {
					errs = append(errs, fmt.Sprintf("%s.dest: redirect target port %d is reserved", prefix, p))
				}
				_ = host
			}
		}
	}

	// (2b) min-one-healthy: at least one inbound must be enabled.
	anyEnabled := false
	for _, in := range change.Inbounds {
		if in.Enabled {
			anyEnabled = true
			break
		}
	}
	if !anyEnabled {
		errs = append(errs, "inbounds: at least one inbound must be enabled (min-one-healthy invariant)")
	}

	return errs
}

// splitHostPort splits "host:port" at the LAST colon (IPv6-aware enough
// for this project's host:port topology; IPv6 literals are not supported
// as dests).
func splitHostPort(s string) (host, port string, ok bool) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 || idx == 0 || idx == len(s)-1 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

// BuildInboundDiff produces the redacted before/after diff for a C3
// inbound change against the current base list. Key references are
// fingerprinted (Redacted=true); no key material ever appears.
func BuildInboundDiff(base, override []InboundSpec) []DiffEntry {
	var out []DiffEntry
	for _, o := range override {
		var b *InboundSpec
		for i := range base {
			if base[i].Instance == o.Instance {
				b = &base[i]
				break
			}
		}
		baseVal := func(get func(InboundSpec) string) string {
			if b == nil {
				return "(not set)"
			}
			v := get(*b)
			if v == "" {
				return "(not set)"
			}
			return v
		}
		intVal := func(get func(InboundSpec) int) string {
			if b == nil || get(*b) == 0 {
				return "(not set)"
			}
			return strconv.Itoa(get(*b))
		}

		if o.Port != 0 {
			out = append(out, DiffEntry{
				Key:    "inbounds." + o.Instance + ".port",
				Before: intVal(func(s InboundSpec) int { return s.Port }),
				After:  strconv.Itoa(o.Port),
			})
		}
		if o.SNI != "" {
			out = append(out, DiffEntry{
				Key:    "inbounds." + o.Instance + ".sni",
				Before: baseVal(func(s InboundSpec) string { return s.SNI }),
				After:  o.SNI,
			})
		}
		if o.Dest != "" {
			out = append(out, DiffEntry{
				Key:    "inbounds." + o.Instance + ".dest",
				Before: baseVal(func(s InboundSpec) string { return s.Dest }),
				After:  o.Dest,
			})
		}
		if o.ShortID != "" {
			out = append(out, DiffEntry{
				Key:    "inbounds." + o.Instance + ".shortId",
				Before: baseVal(func(s InboundSpec) string { return s.ShortID }),
				After:  o.ShortID,
			})
		}
		if len(o.ShortIDs) > 0 {
			out = append(out, DiffEntry{
				Key:    "inbounds." + o.Instance + ".shortIds",
				Before: fmt.Sprintf("count=%d", lenShortIds(base)),
				After:  fmt.Sprintf("count=%d", len(o.ShortIDs)),
			})
		}
		{
			before := "false"
			if b != nil && b.Enabled {
				before = "true"
			}
			out = append(out, DiffEntry{
				Key:    "inbounds." + o.Instance + ".enabled",
				Before: before,
				After:  strconv.FormatBool(o.Enabled),
			})
		}
		if o.KeyRef != "" {
			before := "(not set)"
			if b != nil && b.KeyRef != "" {
				before = b.KeyRef
			}
			out = append(out, DiffEntry{
				Key:      "inbounds." + o.Instance + ".keyRef",
				Before:   before,
				After:    o.KeyRef,
				Redacted: true,
			})
		}
	}
	return out
}

func lenShortIds(base []InboundSpec) int {
	n := 0
	for _, s := range base {
		n += len(s.ShortIDs)
	}
	return n
}

// ---------------------------------------------------------------------------
// Agent: C3 op implementations
// ---------------------------------------------------------------------------

// opInboundsValidate runs the pure C3 inbound validation and returns the
// redacted diff + restart classification. No host mutation.
func (a *Agent) opInboundsValidate(conn net.Conn, frame *Frame) error {
	if err := a.requireInboundSeam(conn, frame); err != nil {
		return err
	}
	var change InboundChange
	if err := framePayload(frame, &change); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	errs := ValidateInboundChange(change, nil, nil)
	base, _ := a.InboundSeam.BaseInbounds(change.Role)
	data := map[string]any{
		"valid":                len(errs) == 0,
		"errors":               errs,
		"restartRequired":      true, // any xray change restarts the affected service
		"estimatedDowntimeSec": 10,
		"peerChangeRequired":   peerChangeForRole(change.Role),
		"diff":                 BuildInboundDiff(base, change.Inbounds),
	}
	return a.reply(conn, frame, true, data, "", "")
}

// opInboundsApply runs the full C3 inbound apply transaction (the C2
// state machine extended with the ConfigTest gate and the xray service
// restart path). Fault points: render, configtest, backup, swap,
// restart, verify, commit.
func (a *Agent) opInboundsApply(conn net.Conn, frame *Frame) error {
	if err := a.requireInboundSeam(conn, frame); err != nil {
		return err
	}
	op := InboundApplyOp{IdempotencyKey: frame.IdempotencyKey, Actor: frame.ReqID}
	if err := framePayload(frame, &op.Change); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	if frame.ChangeID != "" {
		op.Change.ChangeID = frame.ChangeID
	}

	// Idempotency replay (same discipline as C2).
	if entry, conflict := a.inboundIdempotencyLookup(op); conflict {
		return a.reply(conn, frame, false, nil, ErrCodeIdempotency, "idempotency key was used with a different request")
	} else if entry != nil {
		return a.reply(conn, frame, true, entry.result, "", "")
	}

	res, code, errMsg := a.runInboundApply(op, nil)
	a.inboundIdempotencyStore(op, &res)
	if code != "" {
		return a.reply(conn, frame, false, nil, code, errMsg)
	}
	return a.reply(conn, frame, true, res.ToResponse(), "", "")
}

// opInboundsRotate runs the key-rotation flow.
func (a *Agent) opInboundsRotate(conn net.Conn, frame *Frame) error {
	if err := a.requireInboundSeam(conn, frame); err != nil {
		return err
	}
	var req RotateRequest
	if err := framePayload(frame, &req); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}

	// Rotation is blocked unless the old key is retained in the
	// revision store (design: the transition window must keep the old
	// key usable for rollback).
	if !req.RetainOld {
		return a.reply(conn, frame, false, nil, ErrCodeRotationBlocked,
			"key rotation is blocked: the old key must be retained during the transition (set retainOld=true)")
	}

	if !a.acquireApplyLock() {
		return a.reply(conn, frame, false, nil, ErrCodeApplyInProgress, "another apply is in progress")
	}
	defer a.releaseApplyLock()
	if a.Store.IsFrozen() {
		return a.reply(conn, frame, false, nil, ErrCodeFrozen, "kill switch engaged")
	}

	// Pre-snapshot the live config FIRST: the pre/ copy is what retains
	// the old private key for the transition window.
	head, _ := a.Store.Head()
	revID, err := a.Store.NewRevisionID()
	if err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInternal, err.Error())
	}
	livePath := a.InboundSeam.LiveXrayConfigPath(req.Role)
	pre := map[string]string{}
	if livePath != "" {
		pre[baseName(livePath)] = livePath
	}
	if err := a.Store.PreSnapshot(revID, pre); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInternal, "pre-snapshot (old-key retention): "+err.Error())
	}

	// Generate the new keypair server-side (output to a 0600 file, never
	// in argv, never returned — only the fingerprint is returned). The
	// seam updates the live config to the new key; the old key stays in
	// the pre/ snapshot taken above.
	newFp, err := a.InboundSeam.RotateKeypair(req.Role, req.Instance)
	if err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInternal, "keygen: "+err.Error())
	}

	// Commit: the revision's files/ is the post-rotation live config
	// (a valid source path); the new-key fingerprint is carried in the
	// audit entry, not in files/. When the role has no live file yet the
	// files map is empty (an empty baseline keeps rollback defined).
	files := map[string]string{}
	if livePath != "" {
		files[baseName(livePath)] = livePath
	}
	meta := RevisionMeta{
		ID:       revID,
		Parent:   head,
		ChangeID: req.ChangeID,
		Actor:    frame.ReqID,
		Role:     req.Role,
		Kind:     "inbounds-rotate",
		Outcome:  "committed",
	}
	if err := a.Store.CommitRevision(meta, files, head); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInternal, "commit rotation: "+err.Error())
	}
	if head != "" {
		_ = a.Store.PromoteLKG(head)
	}

	if a.Audit != nil {
		_ = a.Audit.Record(AuditEntry{
			Actor:    frame.ReqID,
			Concept:  "inbounds-rotate",
			ChangeID: req.ChangeID,
			RevTo:    revID,
			Diff: []DiffEntry{{
				Key:      "inbounds." + req.Instance + ".keyRef",
				Before:   "(old key retained in revision pre/)",
				After:    newFp,
				Redacted: true,
			}},
			Outcome: "committed",
		})
	}

	resp := RotateResponse{
		NewKeyFingerprint: newFp,
		OldKeyRetained:    true,
		Revision:          revID,
		Outcome:           "committed",
	}
	return a.reply(conn, frame, true, resp, "", "")
}

// opInboundsExportBlob stages a Blob A/B export for the peer host (D10).
func (a *Agent) opInboundsExportBlob(conn net.Conn, frame *Frame) error {
	if err := a.requireInboundSeam(conn, frame); err != nil {
		return err
	}
	var req BlobExportRequest
	if err := framePayload(frame, &req); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	if !isAbsPath(req.OutPath) {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, "outPath must be an absolute path (operator-chosen 0600 file)")
	}
	if err := validateBlobKindPair(req.Role, req.BlobKind); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	fp, err := a.InboundSeam.ExportBlob(req.Role, req.BlobKind, req.OutPath)
	if err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInternal, "export-blob: "+err.Error())
	}
	if a.Audit != nil {
		_ = a.Audit.Record(AuditEntry{
			Actor:    frame.ReqID,
			Concept:  "inbounds-export-blob",
			ChangeID: req.ChangeID,
			Diff: []DiffEntry{{
				Key:      "blob." + req.BlobKind + ".fingerprint",
				Before:   "(not set)",
				After:    fp,
				Redacted: true,
			}},
			Outcome: "exported",
		})
	}
	resp := BlobExportResponse{Fingerprint: fp, OutPath: req.OutPath, Outcome: "exported"}
	return a.reply(conn, frame, true, resp, "", "")
}

// opInboundsImportBlob stages a Blob A/B import for this host (D10).
func (a *Agent) opInboundsImportBlob(conn net.Conn, frame *Frame) error {
	if err := a.requireInboundSeam(conn, frame); err != nil {
		return err
	}
	var req BlobImportRequest
	if err := framePayload(frame, &req); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	if !isAbsPath(req.InPath) {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, "inPath must be an absolute path (operator-chosen 0600 file)")
	}
	if err := validateBlobKindPair(req.Role, req.BlobKind); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}

	if !a.acquireApplyLock() {
		return a.reply(conn, frame, false, nil, ErrCodeApplyInProgress, "another apply is in progress")
	}
	defer a.releaseApplyLock()
	if a.Store.IsFrozen() {
		return a.reply(conn, frame, false, nil, ErrCodeFrozen, "kill switch engaged")
	}

	revID, err := a.InboundSeam.ImportBlob(req.Role, req.BlobKind, req.InPath)
	if err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInternal, "import-blob: "+err.Error())
	}
	if a.Audit != nil {
		_ = a.Audit.Record(AuditEntry{
			Actor:    frame.ReqID,
			Concept:  "inbounds-import-blob",
			ChangeID: req.ChangeID,
			RevTo:    revID,
			Outcome:  "committed",
		})
	}
	resp := BlobImportResponse{Revision: revID, Outcome: "committed"}
	return a.reply(conn, frame, true, resp, "", "")
}

// requireInboundSeam fails closed when the C3 seam is not wired. It
// writes the reply AND returns a sentinel so the caller stops.
func (a *Agent) requireInboundSeam(conn net.Conn, frame *Frame) error {
	if a.InboundSeam == nil {
		_ = a.reply(conn, frame, false, nil, ErrCodeInboundNotConfigured,
			"C3 inbound ops are not configured on this host (InboundSeam is nil)")
		return errors.New("inbound_not_configured")
	}
	return nil
}

// runInboundApply executes the C3 inbound state machine with an injected
// fault map. Fault points: "render", "configtest", "backup", "swap",
// "restart", "verify", "commit". Post-swap failures auto-rollback
// (restore the pre copy, restart, point head back at the parent) — the
// same guarantee as C2.
func (a *Agent) runInboundApply(op InboundApplyOp, faults Faults) (res TxResult, code string, errMsg string) {
	change := op.Change
	role := change.Role

	// Audit every terminal outcome with the redacted diff (design §7.6).
	defer func() {
		if a.Audit != nil {
			base, _ := a.InboundSeam.BaseInbounds(role)
			_ = a.Audit.Record(AuditEntry{
				Actor:    op.Actor,
				Concept:  "inbounds",
				ChangeID: change.ChangeID,
				RevTo:    res.RevisionID,
				Diff:     BuildInboundDiff(base, change.Inbounds),
				Outcome:  res.Outcome,
			})
		}
	}()

	// F1: concurrency lock.
	if !a.acquireApplyLock() {
		return res, ErrCodeApplyInProgress, "another apply is in progress"
	}
	defer a.releaseApplyLock()

	// F2: in-flight journal.
	if a.Journal != nil {
		_, inFlight, rerr := a.Journal.Read()
		if rerr != nil || inFlight {
			return res, ErrCodeRecoveryRequired, "an in-flight journal is present; run recovery first"
		}
	}

	// F3: kill switch.
	if a.Store.IsFrozen() {
		return res, ErrCodeFrozen, "kill switch engaged; unfreeze via the CLI before applying"
	}

	// F5: validate (authoritative; the web's validate is re-checked).
	if errs := ValidateInboundChange(change, nil, nil); len(errs) > 0 {
		res.Err = fmt.Errorf("%s", joinErrs(errs))
		return res, ErrCodeValidation, joinErrs(errs)
	}

	// F6: optimistic concurrency.
	head, _ := a.Store.Head()
	if change.BaseRevision != "" && change.BaseRevision != head {
		return res, ErrCodeStaleBase, "baseRevision does not match the current head"
	}
	if change.ChangeID == "" {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		change.ChangeID = "c3-" + hex.EncodeToString(b)
	}

	revID, err := a.Store.NewRevisionID()
	if err != nil {
		res.Err = err
		return res, ErrCodeInternal, err.Error()
	}

	// F7: pre-snapshot the live xray config.
	livePath := a.InboundSeam.LiveXrayConfigPath(role)
	pre := map[string]string{}
	if livePath != "" {
		pre[baseName(livePath)] = livePath
	}
	if err := a.Store.PreSnapshot(revID, pre); err != nil {
		res.Err = err
		return res, ErrCodeInternal, "pre-snapshot: " + err.Error()
	}

	// F8: journal prepared (before the first mutation).
	preHash := ""
	if livePath != "" {
		if h, herr := a.Store.HashFile(livePath); herr == nil {
			preHash = h
		}
	}
	if a.Journal != nil {
		if err := a.Journal.Write(ControlJournalEntry{
			ChangeID: change.ChangeID,
			Role:     role,
			State:    JournalPrepared,
			Revision: revID,
			Parent:   head,
			PreHash:  preHash,
		}); err != nil {
			res.Err = err
			return res, ErrCodeInternal, "write journal: " + err.Error()
		}
	}

	// F9: render the candidate into the sandbox.
	cand, err := faultInject(faults, "render", func() (string, error) {
		return a.InboundSeam.WriteXrayCandidate(role, change.Inbounds)
	})
	if err != nil {
		a.clearJournal()
		res.Err = err
		return res, ErrCodeValidation, "render: " + err.Error()
	}
	if a.Journal != nil {
		if j, ok, _ := a.Journal.Read(); ok {
			if h, herr := a.Store.HashFile(cand); herr == nil {
				j.NewHash = h
			}
			_ = a.Journal.Write(j)
		}
	}

	// C3 gate: xray run -test on the candidate (design §5.2 F6). On
	// Linux the seam invokes the pinned xray binary; tests inject a
	// fake. On failure NO swap occurs.
	if err := faultInjectErr(faults, "configtest", func() error {
		return a.InboundSeam.ConfigTest(role, cand)
	}); err != nil {
		a.clearJournal()
		res.Err = err
		res.Outcome = "config-test-failed"
		return res, ErrCodeConfigTestFailed, "candidate rejected by xray run -test: " + err.Error()
	}

	// F11: back up the live file.
	if _, err := faultInject(faults, "backup", func() (string, error) {
		if livePath == "" {
			return "", nil
		}
		data, rerr := os.ReadFile(livePath)
		if rerr != nil {
			return "", rerr
		}
		backup := livePath + ".c3-backup"
		if werr := os.WriteFile(backup, data, 0o600); werr != nil {
			return "", werr
		}
		return backup, nil
	}); err != nil {
		a.clearJournal()
		res.Err = err
		return res, ErrCodeInternal, "backup: " + err.Error()
	}

	// From here on, every failure restores the previous state.
	failPostSwap := func(step string, cause error) (TxResult, string, string) {
		a.rollbackInbound(role, revID, head)
		res.Err = cause
		res.Outcome = "rolled-back"
		return res, "", "auto-rollback after " + step + ": " + cause.Error()
	}

	// F12: atomic swap.
	if err := faultInjectErr(faults, "swap", func() error {
		if livePath == "" {
			return nil
		}
		return a.swapInboundFile(cand, livePath)
	}); err != nil {
		return failPostSwap("swap", err)
	}
	a.journalState("swapped")

	// F13: restart ONLY the affected xray service (xray-germany or
	// xray-consumer) — a tunnel-visible event surfaced to the operator
	// as a restart warning with estimated downtime.
	if err := faultInjectErr(faults, "restart", func() error {
		return a.InboundSeam.RestartXray(role)
	}); err != nil {
		return failPostSwap("restart", err)
	}
	a.journalState("restarted")

	// F14: verify (service active + listeners up).
	if err := faultInjectErr(faults, "verify", func() error {
		return a.InboundSeam.VerifyXray(role)
	}); err != nil {
		return failPostSwap("verify", err)
	}
	a.journalState("verified")

	// F15: commit.
	post := map[string]string{}
	if livePath != "" {
		post[baseName(livePath)] = cand
	} else {
		post["xray-config"] = cand
	}
	meta := RevisionMeta{
		ID:       revID,
		Parent:   head,
		ChangeID: change.ChangeID,
		Actor:    op.Actor,
		Role:     role,
		Kind:     "inbounds",
		Outcome:  "committed",
	}
	if err := faultInjectErr(faults, "commit", func() error {
		return a.Store.CommitRevision(meta, post, head)
	}); err != nil {
		return failPostSwap("commit", err)
	}
	a.clearJournal()
	if head != "" {
		_ = a.Store.PromoteLKG(head)
	}
	res.Outcome = "committed"
	res.RevisionID = revID
	res.PrevRevisionID = head
	return res, "", ""
}

// InboundTxResultToResponse adds the C3-specific peer-coupling note to the
// apply response (the operator must carry the staged blob to the peer
// host until the C4 agent exists on both sides).
func (r TxResult) InboundToResponse(role string) map[string]any {
	out := r.ToResponse()
	out["peerChangeRequired"] = peerChangeForRole(role)
	out["restartWarning"] = "the affected xray service restarted; the tunnel was briefly unavailable (estimated 10 s)"
	return out
}

// rollbackInbound restores the revision's pre/ copies onto the live xray
// config, restarts the service, and points head back at the parent.
func (a *Agent) rollbackInbound(role, revID, parent string) {
	a.journalState("rolling-back")
	if pre, err := a.Store.LoadPreCopies(revID); err == nil && len(pre) > 0 {
		livePath := a.InboundSeam.LiveXrayConfigPath(role)
		if livePath != "" {
			_ = a.InboundSeam.RestoreXrayFile(role, livePath, firstVal(pre))
		}
	}
	_ = a.InboundSeam.RestartXray(role)
	_ = a.Store.writePointer("head", parent)
	a.journalState("rolled-back")
	a.clearJournal()
}

// swapInboundFile atomically moves the candidate over the live xray
// config (tmp + fsync + rename, 0600 — the D4 discipline).
func (a *Agent) swapInboundFile(candidatePath, livePath string) error {
	data, err := os.ReadFile(candidatePath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(livePath)
	tmp := filepath.Join(dir, baseName(livePath)+".c3-tmp-"+strconv.Itoa(os.Getpid()))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, werr := f.Write(data); werr != nil {
		return werr
	}
	if serr := f.Sync(); serr != nil {
		return serr
	}
	if cerr := f.Close(); cerr != nil {
		return cerr
	}
	if rerr := os.Rename(tmp, livePath); rerr != nil {
		return rerr
	}
	ok = true
	return nil
}

// ---------------------------------------------------------------------------
// Helpers + C3 idempotency (separate key space from C2 to keep the C2
// request-hash shape stable)
// ---------------------------------------------------------------------------

// peerChangeForRole states the peer-coupling note (design D10): a
// Germany edit stages a Blob B for Iran; an Iran edit stages a Blob A
// for Germany. The dashboard must show "peer change required" and never
// imply a coordinated apply.
func peerChangeForRole(role string) string {
	switch role {
	case "germany":
		return "stage a Blob B export and carry it to the Iran host (Iran-side apply lands with the C4 agent)"
	case "iran":
		return "stage a Blob A export and carry it to the Germany host (Germany-side apply lands with the C4 agent)"
	}
	return ""
}

// validateBlobKindPair enforces the role↔blobKind pairing: Germany
// exports/imports Blob B; Iran exports/imports Blob A.
func validateBlobKindPair(role, kind string) error {
	switch role {
	case "germany":
		if kind != "b" {
			return fmt.Errorf("role %q pairs with blob kind %q, got %q", role, "b", kind)
		}
	case "iran":
		if kind != "a" {
			return fmt.Errorf("role %q pairs with blob kind %q, got %q", role, "a", kind)
		}
	default:
		return fmt.Errorf("role must be \"germany\" or \"iran\", got %q", role)
	}
	return nil
}

// isAbsPath reports whether p is an absolute path (POSIX or Windows).
func isAbsPath(p string) bool {
	if p == "" {
		return false
	}
	if p[0] == '/' {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return filepath.IsAbs(p)
}

// inboundIdempotencyHash is a stable hash of one inbound apply request.
func inboundIdempotencyHash(op InboundApplyOp) string {
	specs := make([]string, 0, len(op.Change.Inbounds))
	for _, in := range op.Change.Inbounds {
		specs = append(specs, in.Instance+strconv.Itoa(in.Port)+in.SNI+in.ShortID)
	}
	h := sha256.Sum256([]byte(op.Change.Role + "|" + stableSet(map[string]string{"specs": strings.Join(specs, ";")}) + "|" +
		op.Change.BaseRevision + "|" + op.Change.ChangeID))
	return hex.EncodeToString(h[:])
}

// inbound idempotency cache (in-process; the durable version is
// IdempotencyCache, C5).
func (a *Agent) inboundIdempotencyLookup(op InboundApplyOp) (*idemEntry, bool) {
	if op.IdempotencyKey == "" {
		return nil, false
	}
	a.idemMu.Lock()
	defer a.idemMu.Unlock()
	e, ok := a.idemInbound[op.IdempotencyKey]
	if !ok {
		return nil, false
	}
	if e.requestHash != inboundIdempotencyHash(op) {
		return nil, true
	}
	return e, false
}

func (a *Agent) inboundIdempotencyStore(op InboundApplyOp, res *TxResult) {
	if op.IdempotencyKey == "" {
		return
	}
	a.idemMu.Lock()
	defer a.idemMu.Unlock()
	if a.idemInbound == nil {
		a.idemInbound = map[string]*idemEntry{}
	}
	a.idemInbound[op.IdempotencyKey] = &idemEntry{requestHash: inboundIdempotencyHash(op), result: res.ToResponse()}
}
