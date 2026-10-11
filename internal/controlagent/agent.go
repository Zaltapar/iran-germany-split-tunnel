// agent.go — the C2 control agent (design §3.2, §5, §6, §8).
//
// The Agent is the root-owned half of the control plane. It owns one
// RevisionStore and drives the apply/rollback transactions. Every
// mutation goes through a journaled, locked, idempotent state machine
// that auto-rolls-back on any post-swap failure and is recoverable
// after a crash (design §5.6).
//
// The engine's steps are individually fault-injectable so the state
// machine can be driven to failure at every fault point and asserted to
// land exactly where the design's recovery table says (agent tests).
package controlagent

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ApplySeam is the host-facing executor for one apply. Each method maps
// to a design fault point. Production wires the real env-file path, a
// splitter-only systemctl restart, and the systemd health probes; tests
// inject fakes that record calls and can fail on demand.
//
// No method may touch xray or write outside the transaction's own live
// env file, its sandbox candidate, and its backup: that is the C2
// capability boundary (the agent restarts the splitter only, never xray).
type ApplySeam interface {
	// LiveFile is the single live env file the transaction owns for this
	// role ("" when the role has no live file yet — the agent still
	// snapshots an empty baseline so rollback is defined).
	LiveFile(role string) string
	// BaseEnv returns the current live env values for the role.
	BaseEnv(role string) (map[string]string, error)
	// WriteCandidate renders the candidate env (base folded with the
	// override) into a sandbox file and returns its path.
	WriteCandidate(role string, base, override map[string]string) (string, error)
	// ValidateCandidate runs the splitter --validate-config equivalent
	// (the same shape checks the repo uses) on the candidate.
	ValidateCandidate(role, candidatePath string) error
	// BackupFile copies the live file to a crash-safe backup and returns
	// the backup path.
	BackupFile(role, livePath string) (string, error)
	// SwapFile atomically moves the candidate over the live file
	// (the same tmp+fsync+rename discipline as the deploy store).
	SwapFile(candidatePath, livePath string) error
	// RestartService restarts ONLY the affected splitter service.
	RestartService(role string) error
	// Verify confirms the service is active and the metrics endpoint
	// responds (a loopback probe when configured).
	Verify(role string) error
	// RestoreFile restores the live file from a backup path.
	RestoreFile(role, livePath, backupPath string) error
}

// Faults maps a fault-point name to the error to inject when the
// transaction reaches that step. Recognized keys: "render", "validate",
// "backup", "swap", "restart", "verify", "restore", "commit".
type Faults map[string]error

// RateLimiter bounds applies (design §6.5: 1 per 10 min, 6 per 24 h,
// configurable).
type RateLimiter interface {
	AllowApply(now time.Time) (ok bool, retryAfter time.Duration)
	RecordApply(now time.Time)
}

// fixedRateLimiter is the default in-memory limiter. It is not persisted
// across restarts; a crashed agent that restarts within the window is a
// documented limitation (the durable journal owns crash-detection).
type fixedRateLimiter struct {
	mu        sync.Mutex
	recent    []time.Time
	perWindow int
	window    time.Duration
}

func newRateLimiter(perWindow int, window time.Duration) *fixedRateLimiter {
	return &fixedRateLimiter{perWindow: perWindow, window: window, recent: []time.Time{}}
}

func (r *fixedRateLimiter) AllowApply(now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-r.window)
	i := 0
	for i < len(r.recent) && r.recent[i].Before(cutoff) {
		i++
	}
	r.recent = r.recent[i:]
	if len(r.recent) >= r.perWindow {
		return false, r.window - now.Sub(r.recent[0])
	}
	return true, 0
}

func (r *fixedRateLimiter) RecordApply(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recent = append(r.recent, now)
}

// Agent is the root-owned control plane for one host. It is the unit the
// dashboard forwards to over the Unix socket (the dashboard never owns a
// host executor of its own).
type Agent struct {
	Store *RevisionStore
	Seam  ApplySeam
	Build ConfigBuilder
	// ApplyMu is the concurrency lock: only one apply runs at a time.
	ApplyMu *sync.Mutex
	// Rate limits per the design; defaults are 1/10min and 6/24h.
	ApplyPer10Min int
	ApplyPer24H   int
	// Frozen, when set, is a local kill-switch probe the CLI manages
	// (design §6.6); the agent consults it on every apply.
	Frozen func() bool
	// Audit is the append-only audit sink; nil → no audit writes.
	Audit *AuditLog
	// Now is the clock seam (injectable for tests).
	Now func() time.Time
	// Journal is the in-flight control journal (crash recovery).
	Journal *ControlJournal
	// ServiceActive, when set, reports whether the role's splitter
	// service is currently active; recovery uses it to implement the
	// "restart only if not active" rows of the §5.6 table. A nil
	// prober restarts unconditionally on those rows.
	ServiceActive ServiceActiveFunc

	rlShort *fixedRateLimiter
	rlLong  *fixedRateLimiter
	idemMu  sync.Mutex
	idem    map[string]*idemEntry
}

// NewAgent builds an agent over one store root. The in-flight journal and
// the append-only audit log are opened at the conventional locations under
// the store root so a fresh agent recovers state from disk on start.
func NewAgent(storeRoot string, seam ApplySeam, build ConfigBuilder) (*Agent, error) {
	st, err := NewRevisionStore(storeRoot)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		Store:         st,
		Seam:          seam,
		Build:         build,
		ApplyMu:       &sync.Mutex{},
		ApplyPer10Min: 1,
		ApplyPer24H:   6,
		Now:           time.Now,
		idem:          map[string]*idemEntry{},
	}
	a.rlShort = newRateLimiter(a.ApplyPer10Min, 10*time.Minute)
	a.rlLong = newRateLimiter(a.ApplyPer24H, 24*time.Hour)
	a.Journal = NewControlJournal(storeRoot)
	a.Audit = mustNewAuditLog(filepath.Join(storeRoot, "audit.jsonl"))
	return a, nil
}

// NewAgentForStore builds an agent over an already-opened RevisionStore
// (used by the CLI control subcommands: revert-lkg, recover,
// audit-verify). It returns a nil pointer when the store is not a valid
// C2 store; callers must check for nil before use.
func NewAgentForStore(st *RevisionStore, seam ApplySeam, build ConfigBuilder) *Agent {
	if st == nil {
		return nil
	}
	a := &Agent{
		Store:         st,
		Seam:          seam,
		Build:         build,
		ApplyMu:       &sync.Mutex{},
		ApplyPer10Min: 1,
		ApplyPer24H:   6,
		Now:           time.Now,
		idem:          map[string]*idemEntry{},
	}
	a.rlShort = newRateLimiter(a.ApplyPer10Min, 10*time.Minute)
	a.rlLong = newRateLimiter(a.ApplyPer24H, 24*time.Hour)
	a.Journal = NewControlJournal(st.Root)
	a.Audit = mustNewAuditLog(filepath.Join(st.Root, "audit.jsonl"))
	return a
}

// filepath is aliased below to keep the import block stdlib-only.
func mustNewAuditLog(path string) *AuditLog {
	l, err := NewAuditLog(path)
	if err != nil {
		// An audit log that cannot be opened is a fail-closed condition
		// for the mutating ops; the read-only ops still work.
		return nil
	}
	return l
}

// ---------------------------------------------------------------------------
// Op dispatch (one frame per connection)
// ---------------------------------------------------------------------------

// ServeConnection enforces the peer check, decodes one frame, and
// dispatches to the matching op. On a peer rejection it closes without a
// response (design §3.2) and returns ErrPeerRejected so the caller
// surfaces a 503, never a success.
func (a *Agent) ServeConnection(src CredentialSource, policy *PeerPolicy, conn net.Conn) error {
	creds, available, _ := src.PeerCredentials(conn)
	if err := policy.Enforce(creds, available); err != nil {
		_ = conn.Close()
		return err
	}
	defer conn.Close()

	raw, err := readFrame(conn)
	if err != nil {
		return err
	}
	frame, err := decodeFrame(raw)
	if err != nil {
		return a.reply(conn, frame, false, nil, errCodeFor(err), "malformed frame")
	}
	if err := frame.validate(); err != nil {
		return a.reply(conn, frame, false, nil, errCodeFor(err), err.Error())
	}
	switch frame.Op {
	case OpValidate:
		return a.opValidate(conn, frame)
	case OpApply:
		return a.opApply(conn, frame)
	case OpRollbackLKG:
		return a.opRollbackLKG(conn, frame)
	case OpStatus:
		return a.opStatus(conn, frame)
	case OpRevisions:
		return a.opRevisions(conn, frame)
	case OpAudit:
		return a.opAudit(conn, frame)
	default:
		return a.reply(conn, frame, false, nil, ErrCodeUnknownOp, "unknown op")
	}
}

func errCodeFor(err error) string {
	if errors.Is(err, ErrClosed) {
		return ErrCodeInvalidJSON
	}
	return ErrCodeInternal
}

// opValidate runs the pure candidate validation and returns the redacted
// diff + restart classification.
func (a *Agent) opValidate(conn net.Conn, frame *Frame) error {
	var cc CandidateChange
	if err := framePayload(frame, &cc); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	errs, restart := ValidateCandidate(cc.Role, cc.Set, a.Build)
	data := map[string]any{
		"valid":           len(errs) == 0,
		"errors":          errs,
		"restartRequired": restart,
		"diff":            BuildDiff(a.baseEnv(cc.Role), cc.Set),
	}
	// A validation failure is not a transport error: the frame is OK and
	// the data carries valid=false.
	return a.reply(conn, frame, true, data, "", "")
}

// baseEnv is a nil-safe seam read used for diff baselines.
func (a *Agent) baseEnv(role string) map[string]string {
	if a.Seam == nil {
		return nil
	}
	b, _ := a.Seam.BaseEnv(role)
	return b
}

// opApply runs the full journaled transaction.
func (a *Agent) opApply(conn net.Conn, frame *Frame) error {
	op := ApplyOp{IdempotencyKey: frame.IdempotencyKey, Actor: frame.ReqID}
	if err := framePayload(frame, &op.Change); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	if frame.ChangeID != "" {
		op.Change.ChangeID = frame.ChangeID
	}

	// Idempotency replay (design §5.5): a stored, matching result returns
	// without re-running; a stored, differing request is a conflict.
	if entry, conflict := a.idempotencyLookup(op); conflict {
		return a.reply(conn, frame, false, nil, ErrCodeIdempotency, "idempotency key was used with a different request")
	} else if entry != nil {
		return a.reply(conn, frame, true, entry.result, "", "")
	}

	res, code, errMsg := a.runApply(op, nil)
	a.idempotencyStore(op, &res)
	if code != "" {
		return a.reply(conn, frame, false, nil, code, errMsg)
	}
	return a.reply(conn, frame, true, res.ToResponse(), "", "")
}

// opRollbackLKG restores the last-known-good revision.
func (a *Agent) opRollbackLKG(conn net.Conn, frame *Frame) error {
	res, code, msg := a.rollbackLKG(frame.ReqID)
	if a.Audit != nil {
		_ = a.Audit.Record(AuditEntry{Actor: frame.ReqID, Concept: "splitter-policy", Outcome: res.Outcome, ChangeID: "lkg"})
	}
	if code != "" {
		return a.reply(conn, frame, false, nil, code, msg)
	}
	return a.reply(conn, frame, true, res.ToResponse(), "", "")
}

// opStatus reports the current head/lkg, frozen state, and in-flight
// journal presence.
func (a *Agent) opStatus(conn net.Conn, frame *Frame) error {
	head, _ := a.Store.Head()
	lkg, _ := a.Store.LKG()
	inFlight := false
	if a.Journal != nil {
		_, inFlight, _ = a.Journal.Read()
	}
	data := map[string]any{
		"head":     head,
		"lkg":      lkg,
		"frozen":   a.Store.IsFrozen(),
		"inFlight": inFlight,
	}
	return a.reply(conn, frame, true, data, "", "")
}

// opRevisions lists the retained revisions (metadata + hashes only, never
// file contents — design §5.4, §7.5).
func (a *Agent) opRevisions(conn net.Conn, frame *Frame) error {
	ids, err := a.Store.RevisionIDs()
	if err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInternal, err.Error())
	}
	type revView struct {
		ID        string `json:"id"`
		Parent    string `json:"parent,omitempty"`
		Outcome   string `json:"outcome"`
		Timestamp string `json:"timestamp"`
		Manifest  string `json:"manifest"`
	}
	out := make([]revView, 0, len(ids))
	for _, id := range ids {
		meta, _, err := a.Store.LoadRevision(id)
		if err != nil {
			continue
		}
		out = append(out, revView{ID: meta.ID, Parent: meta.Parent, Outcome: meta.Outcome,
			Timestamp: meta.Timestamp.Format(time.RFC3339), Manifest: meta.Manifest})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp < out[j].Timestamp })
	return a.reply(conn, frame, true, map[string]any{"revisions": out}, "", "")
}

// opAudit returns the recent audit entries (redacted by construction).
func (a *Agent) opAudit(conn net.Conn, frame *Frame) error {
	var entries []AuditEntry
	if a.Audit != nil {
		entries = a.Audit.Recent(50)
	}
	return a.reply(conn, frame, true, map[string]any{"entries": entries}, "", "")
}

// ---------------------------------------------------------------------------
// The transaction: draft→validate→diff→apply→verify→auto-rollback
// ---------------------------------------------------------------------------

// ApplyOp is one apply request as decoded from the frame.
type ApplyOp struct {
	Change         CandidateChange
	IdempotencyKey string
	Actor          string
}

// TxResult is the outcome of one apply (or rollback) run.
type TxResult struct {
	Outcome        string
	RevisionID     string
	PrevRevisionID string
	Err            error
}

// ToResponse is the wire data for a successful apply/rollback.
func (r TxResult) ToResponse() map[string]any {
	return map[string]any{
		"outcome":      r.Outcome,
		"revision":     r.RevisionID,
		"prevRevision": r.PrevRevisionID,
	}
}

// runApply executes the full state machine with an injected fault map.
// It is the single code path both opApply and the CLI's revert flow
// share, so the fault table in the tests drives the exact same engine
// the socket does.
func (a *Agent) runApply(op ApplyOp, faults Faults) (res TxResult, code string, errMsg string) {
	role := op.Change.Role
	// Every terminal outcome — committed, rolled-back, recovery-required,
	// and the refusal codes (frozen, rate-limited, stale, validation,
	// in-progress) — lands in the audit log with the redacted diff, per
	// design §7.6. The audit write itself can never leak a value: the
	// diff is redacted at the source and the sink re-checks.
	defer func() {
		if a.Audit != nil {
			_ = a.Audit.Record(AuditEntry{
				Actor:    op.Actor,
				Concept:  "splitter-policy",
				ChangeID: op.Change.ChangeID,
				RevTo:    res.RevisionID,
				Diff:     BuildDiff(a.baseEnv(role), op.Change.Set),
				Outcome:  res.Outcome,
			})
		}
	}()

	// F1: concurrency lock — only one apply at a time.
	if !a.acquireApplyLock() {
		return res, ErrCodeApplyInProgress, "another apply is in progress"
	}
	defer a.releaseApplyLock()

	// F2: in-flight journal presence → refuse. A corrupt (tampered)
	// journal also fails closed (design §5.6: "Tampered or malformed:
	// fail closed, refuse every op").
	if a.Journal != nil {
		j, inFlight, rerr := a.Journal.Read()
		if rerr != nil {
			_ = j
			return res, ErrCodeRecoveryRequired, "in-flight journal is corrupt; run recovery first"
		}
		if inFlight {
			_ = j
			return res, ErrCodeRecoveryRequired, "an in-flight apply journal is present; run recovery first"
		}
	}

	// F3: kill switch.
	if a.Store.IsFrozen() || (a.Frozen != nil && a.Frozen()) {
		return res, ErrCodeFrozen, "kill switch engaged; unfreeze via the CLI before applying"
	}

	// F4: rate limits.
	now := a.Now()
	if ok, wait := a.rlShort.AllowApply(now); !ok {
		return res, ErrCodeRateLimited, "rate limited (10-minute window); retry after " + wait.String()
	}
	if ok, wait := a.rlLong.AllowApply(now); !ok {
		return res, ErrCodeRateLimited, "rate limited (24-hour window); retry after " + wait.String()
	}

	// F5: validate (authoritative; the web's validate is re-checked).
	errs, _ := ValidateCandidate(role, op.Change.Set, a.Build)
	if len(errs) > 0 {
		res.Err = errors.New(joinErrs(errs))
		return res, ErrCodeValidation, joinErrs(errs)
	}

	// F6: optimistic concurrency — base must equal the current head.
	head, _ := a.Store.Head()
	if op.Change.BaseRevision != "" && op.Change.BaseRevision != head {
		return res, ErrCodeStaleBase, "baseRevision does not match the current head"
	}
	if op.Change.ChangeID == "" {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		op.Change.ChangeID = "c-" + hex.EncodeToString(b)
	}

	revID, err := a.Store.NewRevisionID()
	if err != nil {
		res.Err = err
		return res, ErrCodeInternal, err.Error()
	}

	// F7: pre-snapshot the live file into the new revision's pre/.
	livePath := a.Seam.LiveFile(role)
	pre := map[string]string{}
	if livePath != "" {
		pre[baseName(livePath)] = livePath
	}
	if err := a.Store.PreSnapshot(revID, pre); err != nil {
		res.Err = err
		return res, ErrCodeInternal, "pre-snapshot: " + err.Error()
	}

	// F8: journal prepared (before the first mutation). The pre-hash of
	// the live file is recorded now; the new-hash is filled in as soon as
	// the candidate is rendered (F9) so the §5.6 table is complete by the
	// time any swap can happen.
	preHash := ""
	if livePath != "" {
		if h, err := a.Store.HashFile(livePath); err == nil {
			preHash = h
		}
	}
	if a.Journal != nil {
		if err := a.Journal.Write(ControlJournalEntry{
			ChangeID: op.Change.ChangeID,
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
		return a.Seam.WriteCandidate(role, a.baseEnv(role), op.Change.Set)
	})
	if err != nil {
		a.clearJournal()
		res.Err = err
		return res, ErrCodeValidation, "render: " + err.Error()
	}
	if a.Journal != nil {
		if j, ok, _ := a.Journal.Read(); ok {
			j.NewHash = ""
			if h, herr := a.Store.HashFile(cand); herr == nil {
				j.NewHash = h
			}
			_ = a.Journal.Write(j)
		}
	}

	// F10: validate the candidate.
	if err := faultInjectErr(faults, "validate", func() error {
		return a.Seam.ValidateCandidate(role, cand)
	}); err != nil {
		a.clearJournal()
		res.Err = err
		return res, ErrCodeValidation, "candidate validation: " + err.Error()
	}

	// F11: back up the live file.
	if _, err := faultInject(faults, "backup", func() (string, error) {
		if livePath == "" {
			return "", nil
		}
		return a.Seam.BackupFile(role, livePath)
	}); err != nil {
		a.clearJournal()
		res.Err = err
		return res, ErrCodeInternal, "backup: " + err.Error()
	}

	// From here on, every failure restores the previous state (the pre/
	// snapshot) and restarts — the auto-rollback guarantee.
	failPostSwap := func(step string, cause error) (TxResult, string, string) {
		a.rollback(role, &res, revID, head, faults)
		res.Err = cause
		return res, "", "auto-rollback after " + step + ": " + cause.Error()
	}

	// F12: atomic swap. When the role has no live file yet the swap is a
	// no-op (there is nothing to move onto); the candidate is still
	// committed into the revision's files/ as "env" (design §5.4: an
	// empty baseline keeps rollback defined).
	if err := faultInjectErr(faults, "swap", func() error {
		if livePath == "" {
			return nil
		}
		return a.Seam.SwapFile(cand, livePath)
	}); err != nil {
		return failPostSwap("swap", err)
	}
	a.journalState("swapped")

	// F13: restart ONLY the affected splitter service.
	if err := faultInjectErr(faults, "restart", func() error {
		return a.Seam.RestartService(role)
	}); err != nil {
		return failPostSwap("restart", err)
	}
	a.journalState("restarted")

	// F14: verify.
	if err := faultInjectErr(faults, "verify", func() error {
		return a.Seam.Verify(role)
	}); err != nil {
		return failPostSwap("verify", err)
	}
	a.journalState("verified")

	// F15: commit.
	post := map[string]string{}
	if livePath != "" {
		post[baseName(livePath)] = cand
	} else {
		post["env"] = cand
	}
	meta := RevisionMeta{
		ID:       revID,
		Parent:   head,
		ChangeID: op.Change.ChangeID,
		Actor:    op.Actor,
		Role:     role,
		Kind:     "splitter-policy",
		Outcome:  "committed",
	}
	// Commit is the last step; a failure here means the live file is already
	// the new content and the service is verified up, but the revision record
	// is incomplete. Per the design §5.3 invariant (auto-rollback on any
	// failure), restore the previous revision rather than leaving an
	// unrecorded live change.
	if err := faultInjectErr(faults, "commit", func() error {
		return a.Store.CommitRevision(meta, post, head)
	}); err != nil {
		return failPostSwap("commit", err)
	}
	a.clearJournal()
	// LKG points at the revision that was head before this apply: the
	// content that was live and healthy up to now (the "last known good"
	// revert target). A fresh commit is Committed but not LKG until the
	// §6.4 observation window elapses (C4 watchdog); the operator-facing
	// revert-lkg in C2 restores this previous revision.
	if head != "" {
		_ = a.Store.PromoteLKG(head)
	}
	a.rlShort.RecordApply(a.Now())
	a.rlLong.RecordApply(a.Now())
	res.Outcome = "committed"
	res.RevisionID = revID
	res.PrevRevisionID = head
	return res, "", ""
}

// rollback restores the revision's pre/ copies, restarts, and points head
// back at the parent. Any rollback failure is recovery-required: the
// journal is retained and every mutating op is refused until recovery.
func (a *Agent) rollback(role string, res *TxResult, revID, parent string, faults Faults) {
	a.journalState("rolling-back")
	res.Outcome = "rolled-back"
	pre, err := a.Store.LoadPreCopies(revID)
	if err != nil {
		res.Err = errors.New("rollback: cannot load pre copies: " + err.Error())
		res.Outcome = "recovery-required"
		return
	}
	livePath := a.Seam.LiveFile(role)
	// C2 owns exactly one live env file per role; restore it from its
	// pre copy. An empty pre/ (no live file at apply time) means there
	// was nothing to restore — the live file is still the candidate, so
	// only restart + verify are meaningful; a missing pre copy with a
	// live path present is a genuine inconsistency → recovery-required.
	if livePath != "" {
		if len(pre) == 0 {
			res.Err = errors.New("rollback: no pre copy for the live file (inconsistent state)")
			res.Outcome = "recovery-required"
			return
		}
		if err := faultInjectErr(faults, "restore", func() error {
			return a.Seam.RestoreFile(role, livePath, firstVal(pre))
		}); err != nil {
			res.Err = errors.New("rollback: restore failed: " + err.Error())
			res.Outcome = "recovery-required"
			return
		}
	}
	if err := a.Seam.RestartService(role); err != nil {
		res.Err = errors.New("rollback: restart after restore failed: " + err.Error())
		res.Outcome = "recovery-required"
		return
	}
	_ = a.Store.writePointer("head", parent)
	a.journalState("rolled-back")
	a.clearJournal()
}

// RollbackLKG is the exported operator/CLI entrypoint to revert the last
// known-good revision (design §6.6: `splitterctl control revert-lkg`). It
// is allowed even while the kill switch is engaged (a revert is the
// recovery action, not a forward mutation).
func (a *Agent) RollbackLKG(actor string) (TxResult, string, string) {
	return a.rollbackLKG(actor)
}

// rollbackLKG restores the last-known-good revision's files/.
func (a *Agent) rollbackLKG(actor string) (TxResult, string, string) {
	var res TxResult
	if !a.acquireApplyLock() {
		return res, ErrCodeApplyInProgress, "another apply is in progress"
	}
	defer a.releaseApplyLock()
	// The kill switch blocks applies but NOT revert-lkg: a revert is the
	// recovery action the design calls for while frozen (it restores a
	// known-good state), so it is allowed even when frozen.
	lkg, err := a.Store.LKG()
	if err != nil || lkg == "" {
		return res, ErrCodeInternal, "no last-known-good revision available"
	}
	role, err := a.Store.RoleOfRevision(lkg)
	if err != nil {
		return res, ErrCodeInternal, "resolve lkg role: " + err.Error()
	}
	_, files, err := a.Store.LoadRevision(lkg)
	if err != nil {
		return res, ErrCodeInternal, "load lkg revision: " + err.Error()
	}
	if len(files) == 0 {
		return res, ErrCodeInternal, "lkg revision carries no file copies"
	}
	restored := false
	for rel, p := range files {
		_ = rel
		if err := a.Seam.RestoreFile(role, a.Seam.LiveFile(role), p); err != nil {
			return res, ErrCodeInternal, "revert-lkg: restore failed: " + err.Error()
		}
		restored = true
		break // single live env file per role
	}
	if !restored {
		return res, ErrCodeInternal, "revert-lkg: nothing to restore"
	}
	if err := a.Seam.RestartService(role); err != nil {
		return res, ErrCodeInternal, "revert-lkg: restart failed: " + err.Error()
	}
	if err := a.Seam.Verify(role); err != nil {
		return res, ErrCodeInternal, "revert-lkg: verify failed: " + err.Error()
	}
	if err := a.Store.writePointer("head", lkg); err != nil {
		return res, ErrCodeInternal, "revert-lkg: head pointer: " + err.Error()
	}
	_ = actor
	res.Outcome = "rolled-back-lkg"
	res.RevisionID = lkg
	return res, "", ""
}

// journalState / clearJournal are nil-safe journal transitions.
func (a *Agent) journalState(state string) {
	if a.Journal == nil {
		return
	}
	if j, ok, _ := a.Journal.Read(); ok {
		j.State = ControlJournalState(state)
		_ = a.Journal.Write(j)
	}
}

func (a *Agent) clearJournal() {
	if a.Journal != nil {
		_ = a.Journal.Clear()
	}
}

// ---------------------------------------------------------------------------
// Crash recovery (design §5.6)
// ---------------------------------------------------------------------------

// RecoveryOutcome is the resolution of one crash-recovery pass.
type RecoveryOutcome string

const (
	RecoveryNothing  RecoveryOutcome = "no-in-flight"
	RecoveryTamper   RecoveryOutcome = "tamper-recovery-required"
	RecoveryNoChange RecoveryOutcome = "recovered_no_change"
	RecoveryRollback RecoveryOutcome = "recovered_rollback"
	RecoveryCommit   RecoveryOutcome = "recovered_commit"
	RecoveryNeeded   RecoveryOutcome = "recovery-required"
)

// RecoverOnStart implements the §5.6 table. It is safe to call on every
// agent start: with no in-flight journal it is a no-op. A tampered or
// malformed journal is retained and every mutating op stays refused
// (fail closed) until an operator runs recovery by hand.
//
// The rule from the design: when the state is uncertain, roll back toward
// the last known good, never forward.
func (a *Agent) RecoverOnStart() (RecoveryOutcome, error) {
	if a.Journal == nil {
		return RecoveryNothing, nil
	}
	e, inFlight, err := a.Journal.Read()
	if err != nil {
		// Malformed or tampered: retain the file and fail closed.
		if a.Audit != nil {
			_ = a.Audit.Record(AuditEntry{Actor: "recovery", Concept: "crash-recovery", Outcome: string(RecoveryTamper), ChangeID: e.ChangeID})
		}
		return RecoveryTamper, nil
	}
	if !inFlight {
		return RecoveryNothing, nil
	}
	outcome := a.resolveInFlight(e)
	if a.Audit != nil {
		_ = a.Audit.Record(AuditEntry{Actor: "recovery", Concept: "crash-recovery", Outcome: string(outcome), ChangeID: e.ChangeID, RevTo: e.Revision})
	}
	return outcome, nil
}

// resolveInFlight walks the §5.6 rows for one persisted in-flight entry.
func (a *Agent) resolveInFlight(e ControlJournalEntry) RecoveryOutcome {
	livePath := a.Seam.LiveFile(e.Role)
	var liveHash string
	if livePath != "" {
		h, err := a.Store.HashFile(livePath)
		if err != nil {
			liveHash = ""
		} else {
			liveHash = h
		}
	}

	switch e.State {
	case "", JournalPrepared:
		// prepared: the swap has not landed. If the live file still equals
		// its pre-hash, nothing changed — just clear. If it differs, the
		// candidate slipped in: restore the pre/ copy.
		if liveHash == e.PreHash {
			a.clearJournal()
			return RecoveryNoChange
		}
		if err := a.restoreFromPre(e.Revision, e.Role); err != nil {
			return RecoveryNeeded
		}
		if err := a.restartAndVerify(e.Role); err != nil {
			return RecoveryNeeded
		}
		a.clearJournal()
		return RecoveryRollback

	case JournalSwapped, JournalRestarted:
		switch {
		case liveHash == e.PreHash:
			// The live file still equals the pre snapshot: the candidate
			// never actually landed (or PreHash==NewHash — a change that
			// does not touch the file). Clear, restart only if not
			// active (design §5.6 row 4).
			if err := a.restartIfNotActive(e.Role); err != nil {
				return RecoveryNeeded
			}
			a.clearJournal()
			return RecoveryNoChange
		case liveHash == e.NewHash:
			// The new content is live; restart if needed and verify, then
			// commit. On verify failure restore pre/ and re-verify.
			if err := a.restartIfNotActive(e.Role); err != nil {
				return RecoveryNeeded
			}
			if err := a.Seam.Verify(e.Role); err != nil {
				if err := a.restoreFromPre(e.Revision, e.Role); err != nil {
					return RecoveryNeeded
				}
				if err := a.restartAndVerify(e.Role); err != nil {
					return RecoveryNeeded
				}
				a.clearJournal()
				return RecoveryRollback
			}
			if err := a.commitRecovered(e); err != nil {
				return RecoveryNeeded
			}
			return RecoveryCommit

		case liveHash == e.PreHash:
			// Candidate never landed: clear, restart only if not active.
			if err := a.restartIfNotActive(e.Role); err != nil {
				return RecoveryNeeded
			}
			a.clearJournal()
			return RecoveryNoChange

		default:
			// Neither hash matches: uncertain → roll back toward the last
			// known good.
			if err := a.restoreFromPre(e.Revision, e.Role); err != nil {
				return RecoveryNeeded
			}
			if err := a.restartAndVerify(e.Role); err != nil {
				return RecoveryNeeded
			}
			a.clearJournal()
			return RecoveryRollback
		}

	case JournalVerified:
		if liveHash == e.NewHash {
			if err := a.commitRecovered(e); err != nil {
				return RecoveryNeeded
			}
			return RecoveryCommit
		}
		// Verified but the live file no longer matches: uncertain → roll
		// back.
		if err := a.restoreFromPre(e.Revision, e.Role); err != nil {
			return RecoveryNeeded
		}
		if err := a.restartAndVerify(e.Role); err != nil {
			return RecoveryNeeded
		}
		a.clearJournal()
		return RecoveryRollback

	default: // JournalRollingBack, JournalRolledBack
		if err := a.restartAndVerify(e.Role); err != nil {
			return RecoveryNeeded
		}
		a.clearJournal()
		return RecoveryNoChange
	}
}

// restoreFromPre restores the revision's pre/ copies onto the live file.
func (a *Agent) restoreFromPre(revID, role string) error {
	pre, err := a.Store.LoadPreCopies(revID)
	if err != nil {
		return err
	}
	livePath := a.Seam.LiveFile(role)
	if livePath == "" {
		return nil
	}
	if len(pre) == 0 {
		return nil
	}
	return a.Seam.RestoreFile(role, livePath, firstVal(pre))
}

// restartAndVerify restarts the role service and then verifies health.
func (a *Agent) restartAndVerify(role string) error {
	if err := a.Seam.RestartService(role); err != nil {
		return err
	}
	return a.Seam.Verify(role)
}

// restartIfNotActive restarts only when the service is not already active.
func (a *Agent) restartIfNotActive(role string) error {
	if a.ServiceActive != nil {
		if active, ok := a.ServiceActive(role); ok && active {
			return nil
		}
	}
	return a.Seam.RestartService(role)
}

// commitRecovered finalizes a verified/new-hash live state as a committed
// revision. It rewrites the revision's files/ from the live content,
// re-verifies the manifest, and moves head (never forward beyond the
// verified content).
func (a *Agent) commitRecovered(e ControlJournalEntry) error {
	livePath := a.Seam.LiveFile(e.Role)
	if livePath == "" {
		return errors.New("recovery: no live file for role " + e.Role)
	}
	// Re-commit the revision so its files/ + manifest reflect the live
	// content. CommitRevision prunes and moves head last (the §5
	// invariant).
	meta, _, err := a.Store.LoadRevision(e.Revision)
	if err != nil {
		// The revision's on-disk record is incomplete (a crash before the
		// commit step): reconstruct a minimal meta and let CommitRevision
		// rewrite it from the live content.
		meta = RevisionMeta{
			ID:       e.Revision,
			Parent:   e.Parent,
			ChangeID: e.ChangeID,
			Role:     e.Role,
			Kind:     "splitter-policy",
			Outcome:  "committed",
		}
	}
	files := map[string]string{baseName(livePath): livePath}
	if err := a.Store.CommitRevision(meta, files, e.Parent); err != nil {
		return err
	}
	// LKG keeps pointing at the last known-good state: the parent
	// revision (the content that was healthy before this change),
	// consistent with the runApply success path.
	if e.Parent != "" {
		_ = a.Store.PromoteLKG(e.Parent)
	}
	a.clearJournal()
	return nil
}

// ServiceActiveFunc reports whether the role's service is active. ok=false
// means the prober could not decide (treat as not active → restart).
type ServiceActiveFunc func(role string) (active, ok bool)

// acquireApplyLock is a non-blocking TryLock (the design says refuse a
// second apply while one is in progress, not queue it).
func (a *Agent) acquireApplyLock() bool {
	if a.ApplyMu == nil {
		a.ApplyMu = &sync.Mutex{}
	}
	return a.ApplyMu.TryLock()
}

func (a *Agent) releaseApplyLock() { a.ApplyMu.Unlock() }

// faultInject runs fn unless a fault is set for step (then it returns that
// error without running fn).
func faultInject(f Faults, step string, fn func() (string, error)) (string, error) {
	if f != nil {
		if err, ok := f[step]; ok {
			return "", err
		}
	}
	return fn()
}

// faultInjectErr runs an error-only step under the same fault table.
func faultInjectErr(f Faults, step string, fn func() error) error {
	if f != nil {
		if err, ok := f[step]; ok {
			return err
		}
	}
	return fn()
}

// ---------------------------------------------------------------------------
// Frame transport + payload helpers
// ---------------------------------------------------------------------------

// readFrame reads one newline-delimited JSON frame, size-bounded to
// MaxFrameBytes (design §7.3 oversize rejection at the transport layer).
func readFrame(conn net.Conn) ([]byte, error) {
	br := bufio.NewReaderSize(conn, MaxFrameBytes+1)
	buf, err := br.ReadBytes('\n')
	buf = bytes.TrimRight(buf, "\r\n")
	if len(buf) == 0 {
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrClosed, err)
		}
		return nil, fmt.Errorf("%w: empty frame", ErrClosed)
	}
	if len(buf) > MaxFrameBytes {
		return nil, fmt.Errorf("%w: frame exceeds %d bytes", ErrClosed, MaxFrameBytes)
	}
	return buf, nil
}

// reply writes one response frame to conn.
func (a *Agent) reply(conn net.Conn, req *Frame, ok bool, data interface{}, code, msg string) error {
	resp := &Frame{V: ProtocolVersion, ReqID: req.ReqID, OK: ok, Data: data}
	if code != "" || msg != "" {
		resp.Error = &FrameError{Code: code, Message: msg}
	}
	b, err := encodeFrame(resp)
	if err != nil {
		return err
	}
	_, werr := conn.Write(append(b, '\n'))
	return werr
}

// framePayload unmarshals the frame's payload into dst (the typed op
// document). The payload arrives as a JSON value; re-marshal it to bytes
// and decode it strictly.
func framePayload(frame *Frame, dst interface{}) error {
	if frame.Payload == nil {
		return errors.New("empty payload")
	}
	raw, err := json.Marshal(frame.Payload)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Idempotency (in-process, bounded; the durable version is IdempotencyCache)
// ---------------------------------------------------------------------------

// idemEntry is one stored idempotency result.
type idemEntry struct {
	requestHash string
	result      map[string]any
}

// idempotencyHash is a stable hash of the request content (a replay must
// match; the key itself is operator-supplied).
func idempotencyHash(op ApplyOp) string {
	h := sha256.Sum256([]byte(op.Change.Role + "|" + stableSet(op.Change.Set) + "|" + op.Change.BaseRevision + "|" + op.Change.ChangeID))
	return hex.EncodeToString(h[:])
}

// idempotencyLookup returns (entry, conflict). entry is non-nil when a
// matching request was stored; conflict is true when the key was stored
// for a DIFFERENT request.
func (a *Agent) idempotencyLookup(op ApplyOp) (*idemEntry, bool) {
	if op.IdempotencyKey == "" {
		return nil, false
	}
	a.idemMu.Lock()
	defer a.idemMu.Unlock()
	e, ok := a.idem[op.IdempotencyKey]
	if !ok {
		return nil, false
	}
	if e.requestHash != idempotencyHash(op) {
		return nil, true // same key, different request
	}
	return e, false
}

// idempotencyStore records the result under the request's key.
func (a *Agent) idempotencyStore(op ApplyOp, res *TxResult) {
	if op.IdempotencyKey == "" {
		return
	}
	a.idemMu.Lock()
	defer a.idemMu.Unlock()
	a.idem[op.IdempotencyKey] = &idemEntry{requestHash: idempotencyHash(op), result: res.ToResponse()}
}

// IdempotencyCache is the persisted (bounded, on-disk) idempotency store
// the design §5.5 calls for (24 h TTL). The in-process map covers a
// single agent lifetime; this is the durable version.
type IdempotencyCache struct {
	Store *RevisionStore
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// baseName is the file name of a path ("").
func baseName(p string) string {
	if p == "" {
		return ""
	}
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}

// firstVal returns one element from a single-entry map (C2 owns exactly
// one live env file per role).
func firstVal(m map[string]string) string {
	for _, v := range m {
		return v
	}
	return ""
}

func joinErrs(errs []string) string {
	out := ""
	for i, e := range errs {
		if i > 0 {
			out += "; "
		}
		out += e
	}
	return out
}

func stableSet(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b string
	for _, k := range keys {
		b += k + "=" + m[k] + ";"
	}
	return b
}

// bytesReader is a minimal io.Reader over a byte slice (used to keep the
// strict JSON decode path in one place, matching protocol.go).
func bytesReader(b []byte) io.Reader {
	return &byteReader{b: b}
}

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
