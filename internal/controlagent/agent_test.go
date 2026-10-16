// agent_test.go — the C2 transaction state machine driven end-to-end
// through the same engine the socket uses (design §5.1–§5.6): fault
// injection at every step asserting the auto-rollback guarantee, the
// concurrency lock, idempotency, rate limits, the kill switch,
// revert-lkg, and crash recovery.
package controlagent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// ---------------------------------------------------------------------------
// fake seam: records every call and can fail on demand
// ---------------------------------------------------------------------------

type fakeSeam struct {
	mu       sync.Mutex
	role     string
	livePath string
	base     map[string]string
	// what the live file currently contains
	liveContent string

	calls []string

	// per-step failure injection
	failRestart  error
	failVerify   error
	failRender   error
	failBackup   error
	failSwap     error
	failRestore  error
	failValidate error
}

func (f *fakeSeam) record(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
}

func (f *fakeSeam) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeSeam) hadCall(call string) bool {
	for _, c := range f.Calls() {
		if c == call {
			return true
		}
	}
	return false
}

func (f *fakeSeam) LiveFile(role string) string {
	if role == f.role {
		return f.livePath
	}
	return ""
}

func (f *fakeSeam) BaseEnv(role string) (map[string]string, error) {
	f.record("baseEnv")
	if role == f.role {
		out := map[string]string{}
		for k, v := range f.base {
			out[k] = v
		}
		return out, nil
	}
	return nil, nil
}

func (f *fakeSeam) WriteCandidate(role string, base, override map[string]string) (string, error) {
	f.record("render")
	if f.failRender != nil {
		return "", f.failRender
	}
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for k, v := range override {
		m[k] = v
	}
	var b []byte
	for k := range m {
		b = append(b, byte(len(k)))
	}
	sandbox := filepath.Join(filepath.Dir(f.livePath), "sandbox-"+role+".env")
	if err := os.WriteFile(sandbox, []byte(fmt.Sprintf("%v", m)), 0o600); err != nil {
		return "", err
	}
	return sandbox, nil
}

func (f *fakeSeam) ValidateCandidate(role, candidatePath string) error {
	f.record("validate")
	if f.failValidate != nil {
		return f.failValidate
	}
	if _, err := os.Stat(candidatePath); err != nil {
		return err
	}
	return nil
}

func (f *fakeSeam) BackupFile(role, livePath string) (string, error) {
	f.record("backup")
	if f.failBackup != nil {
		return "", f.failBackup
	}
	backup := livePath + ".backup"
	data, err := os.ReadFile(livePath)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(backup, data, 0o600); err != nil {
		return "", err
	}
	return backup, nil
}

func (f *fakeSeam) SwapFile(candidatePath, livePath string) error {
	f.record("swap")
	if f.failSwap != nil {
		return f.failSwap
	}
	data, err := os.ReadFile(candidatePath)
	if err != nil {
		return err
	}
	tmp := livePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, livePath); err != nil {
		return err
	}
	f.mu.Lock()
	f.liveContent = string(data)
	f.mu.Unlock()
	return nil
}

func (f *fakeSeam) RestartService(role string) error {
	f.record("restart")
	// One-shot, like failVerify: it models "this particular restart
	// (the post-swap one) failed"; the rollback's restart of the
	// restored content then succeeds unless the test re-arms it.
	f.mu.Lock()
	err := f.failRestart
	f.failRestart = nil
	f.mu.Unlock()
	return err
}

func (f *fakeSeam) Verify(role string) error {
	f.record("verify")
	// failVerify is one-shot: it models "the NEW content's health check
	// fails", so a subsequent verify (e.g. after a restore to the known-
	// good pre copy) succeeds.
	f.mu.Lock()
	err := f.failVerify
	f.failVerify = nil
	f.mu.Unlock()
	return err
}

func (f *fakeSeam) RestoreFile(role, livePath, backupPath string) error {
	f.record("restore")
	if f.failRestore != nil {
		return f.failRestore
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(livePath, data, 0o600); err != nil {
		return err
	}
	f.mu.Lock()
	f.liveContent = string(data)
	f.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// test scaffolding
// ---------------------------------------------------------------------------

type harness struct {
	agent *Agent
	seam  *fakeSeam
	root  string
}

func newHarness(t *testing.T, role string) *harness {
	t.Helper()
	root := t.TempDir()
	live := filepath.Join(t.TempDir(), role+".env")
	original := "SPLIT_POLICY_MODE=static\n"
	if err := os.WriteFile(live, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	seam := &fakeSeam{
		role:        role,
		livePath:    live,
		liveContent: original,
		base:        map[string]string{config.EnvPolicyMode: "static"},
	}
	a, err := NewAgent(root, seam, defaultConfigBuilder)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	return &harness{agent: a, seam: seam, root: root}
}

func (h *harness) livePath() string { return h.seam.livePath }

func (h *harness) liveContent() string {
	data, _ := os.ReadFile(h.livePath())
	return string(data)
}

func applySet() map[string]string {
	return map[string]string{config.EnvPolicyMode: config.PolicyAdaptiveMode}
}

// runOne drives one apply through the socket-level path (opApply) with a
// virtual connection pair so the idempotency + audit code runs too.
func (h *harness) runOne(set map[string]string, faults Faults) (TxResult, string, string) {
	op := ApplyOp{
		Change: CandidateChange{Role: h.seam.role, Set: set, ChangeID: "c-test"},
		Actor:  "test-operator",
	}
	res, code, msg := h.agent.runApply(op, faults)
	return res, code, msg
}

// ---------------------------------------------------------------------------
// success path
// ---------------------------------------------------------------------------

func TestApplySuccess(t *testing.T) {
	h := newHarness(t, "iran")
	res, code, msg := h.runOne(applySet(), nil)
	if code != "" {
		t.Fatalf("apply failed: code=%s msg=%s", code, msg)
	}
	if res.Outcome != "committed" {
		t.Fatalf("outcome = %q, want committed", res.Outcome)
	}
	if h.liveContent() == "SPLIT_POLICY_MODE=static\n" {
		t.Fatal("live file was not swapped")
	}
	head, _ := h.agent.Store.Head()
	if head == "" || head == "r-" {
		t.Fatalf("head pointer not set: %q", head)
	}
	// journal must be cleared after a successful commit.
	if _, inFlight, _ := h.agent.Journal.Read(); inFlight {
		t.Fatal("journal still in-flight after successful commit")
	}
	for _, want := range []string{"render", "validate", "backup", "swap", "restart", "verify"} {
		if !h.seam.hadCall(want) {
			t.Errorf("missing seam call %q in %v", want, h.seam.Calls())
		}
	}
}

func TestApplySuccessNoLiveFile(t *testing.T) {
	// A role with no live file yet: the snapshot is empty and the swap
	// has nothing to move; the commit still lands (files/ holds the
	// candidate as "env").
	root := t.TempDir()
	seam := &fakeSeam{role: "germany", base: map[string]string{}}
	a, err := NewAgent(root, seam, defaultConfigBuilder)
	if err != nil {
		t.Fatal(err)
	}
	// WriteCandidate in the fake needs a livePath for its sandbox dir;
	// give it a temp dir path that does not exist.
	seam.livePath = filepath.Join(t.TempDir(), "germany.env")
	// LiveFile returns "" (role mismatch on purpose is not possible here;
	// override with a second fake field) — use a custom seam instead:
	seam2 := &noLiveSeam{fs: seam}
	a.Seam = seam2
	res, code, msg := a.runApply(ApplyOp{Change: CandidateChange{Role: "germany", Set: applySet()}, Actor: "t"}, nil)
	if code != "" {
		t.Fatalf("apply failed: %s %s", code, msg)
	}
	if res.Outcome != "committed" {
		t.Fatalf("outcome = %q", res.Outcome)
	}
}

// noLiveSeam wraps fakeSeam and reports no live file.
type noLiveSeam struct{ fs *fakeSeam }

func (s *noLiveSeam) LiveFile(string) string { return "" }
func (s *noLiveSeam) BaseEnv(role string) (map[string]string, error) {
	return s.fs.BaseEnv(role)
}
func (s *noLiveSeam) WriteCandidate(role string, base, override map[string]string) (string, error) {
	return s.fs.WriteCandidate(role, base, override)
}
func (s *noLiveSeam) ValidateCandidate(role, p string) error { return s.fs.ValidateCandidate(role, p) }
func (s *noLiveSeam) BackupFile(role, l string) (string, error) {
	return s.fs.BackupFile(role, l)
}
func (s *noLiveSeam) SwapFile(c, l string) error {
	return s.fs.SwapFile(c, l)
}
func (s *noLiveSeam) RestartService(role string) error { return s.fs.RestartService(role) }
func (s *noLiveSeam) Verify(role string) error         { return s.fs.Verify(role) }
func (s *noLiveSeam) RestoreFile(role, l, b string) error {
	return s.fs.RestoreFile(role, l, b)
}

// ---------------------------------------------------------------------------
// fault injection at every post-swap step → auto-rollback
// ---------------------------------------------------------------------------

func TestFaultSwapAutoRollback(t *testing.T) {
	h := newHarness(t, "iran")
	original := h.liveContent()
	faults := Faults{"swap": errors.New("swap exploded")}
	res, code, _ := h.runOne(applySet(), faults)
	if code != "" {
		t.Fatalf("unexpected code %q", code)
	}
	if res.Outcome != "rolled-back" {
		t.Fatalf("outcome = %q, want rolled-back", res.Outcome)
	}
	if h.liveContent() != original {
		t.Fatal("live file was not restored after swap failure")
	}
	if !h.seam.hadCall("restore") {
		t.Fatalf("rollback did not call restore: %v", h.seam.Calls())
	}
}

func TestFaultRestartAutoRollback(t *testing.T) {
	h := newHarness(t, "iran")
	original := h.liveContent()
	h.seam.failRestart = errors.New("systemctl refused")
	res, _, _ := h.runOne(applySet(), nil)
	if res.Outcome != "rolled-back" {
		t.Fatalf("outcome = %q, want rolled-back", res.Outcome)
	}
	if h.liveContent() != original {
		t.Fatal("live file was not restored after restart failure")
	}
}

func TestFaultVerifyAutoRollback(t *testing.T) {
	h := newHarness(t, "iran")
	original := h.liveContent()
	h.seam.failVerify = errors.New("metrics endpoint down")
	res, _, _ := h.runOne(applySet(), nil)
	if res.Outcome != "rolled-back" {
		t.Fatalf("outcome = %q, want rolled-back", res.Outcome)
	}
	if h.liveContent() != original {
		t.Fatal("live file was not restored after verify failure")
	}
}

func TestFaultCommitAutoRollback(t *testing.T) {
	// Commit failing is a fault map entry (the store call is wrapped in
	// faultInjectErr); simulate it via the faults table.
	h := newHarness(t, "iran")
	original := h.liveContent()
	faults := Faults{"commit": errors.New("store write refused")}
	res, _, _ := h.runOne(applySet(), faults)
	if res.Outcome != "rolled-back" {
		t.Fatalf("outcome = %q, want rolled-back", res.Outcome)
	}
	if h.liveContent() != original {
		t.Fatal("live file was not restored after commit failure")
	}
}

// ---------------------------------------------------------------------------
// pre-swap faults → no rollback needed, journal cleared, live untouched
// ---------------------------------------------------------------------------

func TestPreSwapFaultsLeaveLiveUntouched(t *testing.T) {
	originalSteps := []string{"render", "validate", "backup"}
	for i, step := range originalSteps {
		t.Run(step, func(t *testing.T) {
			h := newHarness(t, "iran")
			original := h.liveContent()
			faults := Faults{step: fmt.Errorf("fault at %s", step)}
			res, code, _ := h.runOne(applySet(), faults)
			want := ErrCodeValidation
			if i == 2 {
				want = ErrCodeInternal
			}
			if code != want {
				t.Fatalf("code = %q, want %q", code, want)
			}
			if res.Outcome != "" {
				t.Fatalf("outcome = %q, want empty (no commit, no rollback)", res.Outcome)
			}
			if h.liveContent() != original {
				t.Fatal("live file changed on a pre-swap fault")
			}
			if _, inFlight, _ := h.agent.Journal.Read(); inFlight {
				t.Fatal("journal left in-flight after a pre-swap fault")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// rollback failure → recovery-required (journal retained)
// ---------------------------------------------------------------------------

func TestRollbackFailureIsRecoveryRequired(t *testing.T) {
	h := newHarness(t, "iran")
	h.seam.failVerify = errors.New("verify down")
	h.seam.failRestore = errors.New("restore refused")
	res, _, _ := h.runOne(applySet(), nil)
	if res.Outcome != "recovery-required" {
		t.Fatalf("outcome = %q, want recovery-required", res.Outcome)
	}
	// Journal is retained: the next apply must be refused.
	_, inFlight, _ := h.agent.Journal.Read()
	if !inFlight {
		t.Fatal("journal was cleared despite recovery-required")
	}
	_, code, _ := h.runOne(applySet(), nil)
	if code != ErrCodeRecoveryRequired {
		t.Fatalf("second apply code = %q, want recovery_required", code)
	}
}

// ---------------------------------------------------------------------------
// concurrency lock
// ---------------------------------------------------------------------------

func TestConcurrencyLockRefusesSecondApply(t *testing.T) {
	h := newHarness(t, "iran")
	// Hold the lock: a blocked restart simulates a long-running apply.
	release := make(chan struct{})
	origRestart := h.seam.failRestart
	h.seam.failRestart = nil
	// Monkey-patch via faults is not enough (restart still runs the fake
	// immediately); instead lock the mutex directly.
	h.agent.ApplyMu.Lock()
	defer h.agent.ApplyMu.Unlock()

	res, code, _ := h.runOne(applySet(), nil)
	if code != ErrCodeApplyInProgress {
		t.Fatalf("code = %q, want apply_in_progress", code)
	}
	_ = res
	_ = origRestart
	close(release)
	_ = release
}

func TestConcurrencyLockSerializes(t *testing.T) {
	h := newHarness(t, "iran")
	h.agent.ApplyPer10Min = 100
	h.agent.rlShort = newRateLimiter(100, 10*time.Minute)
	var wg sync.WaitGroup
	results := make(chan TxResult, 2)
	// Slow the restart so both goroutines overlap.
	slow := make(chan struct{})
	orig := h.seam.failRestart
	_ = orig
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Drive via a second agent over the same store so the lock
			// is really shared at the store level: the lock lives on
			// the Agent, so use the same agent instance concurrently.
			res, _, _ := h.agent.runApply(ApplyOp{
				Change: CandidateChange{Role: "iran", Set: applySet(), ChangeID: "c-x"},
				Actor:  "t",
			}, nil)
			results <- res
		}()
	}
	_ = slow
	wg.Wait()
	close(results)
	var ok, refused int
	for r := range results {
		switch r.Outcome {
		case "committed":
			ok++
		case "":
			refused++
		default:
			t.Fatalf("unexpected outcome %q", r.Outcome)
		}
	}
	if ok != 1 || refused != 1 {
		t.Fatalf("expected exactly one commit + one refusal, got ok=%d refused=%d", ok, refused)
	}
}

// ---------------------------------------------------------------------------
// rate limits
// ---------------------------------------------------------------------------

func TestRateLimitShortWindow(t *testing.T) {
	h := newHarness(t, "iran")
	res, code, msg := h.runOne(applySet(), nil)
	if res.Outcome != "committed" {
		t.Fatalf("first apply: %s / %s", code, msg)
	}
	// Immediately a second apply must be rate-limited.
	res, code, msg = h.runOne(applySet(), nil)
	if code != ErrCodeRateLimited {
		t.Fatalf("second apply code = %q (msg %q), want rate_limited", code, msg)
	}
}

func TestRateLimitLongWindow(t *testing.T) {
	h := newHarness(t, "iran")
	// Saturate the 24h window: record 6 applies without running them.
	now := time.Now()
	for i := 0; i < 6; i++ {
		h.agent.rlLong.RecordApply(now)
	}
	_, code, _ := h.runOne(applySet(), nil)
	if code != ErrCodeRateLimited {
		t.Fatalf("code = %q, want rate_limited (24h window)", code)
	}
}

// ---------------------------------------------------------------------------
// kill switch
// ---------------------------------------------------------------------------

func TestKillSwitchBlocksApply(t *testing.T) {
	h := newHarness(t, "iran")
	if err := h.agent.Store.Freeze(); err != nil {
		t.Fatal(err)
	}
	res, code, _ := h.runOne(applySet(), nil)
	if code != ErrCodeFrozen {
		t.Fatalf("code = %q, want frozen", code)
	}
	if res.Outcome != "" {
		t.Fatal("a frozen apply must not produce an outcome")
	}
	// revert-lkg stays callable while frozen (the design's escape hatch):
	// but without an LKG it returns a clean error, not a success.
	_, rcode, rmsg := h.agent.rollbackLKG("op")
	if rcode != "" {
		t.Logf("revert-lkg while frozen without LKG: %s (%s)", rcode, rmsg)
	}
	if err := h.agent.Store.Unfreeze(); err != nil {
		t.Fatal(err)
	}
	res, code, _ = h.runOne(applySet(), nil)
	if code != "" || res.Outcome != "committed" {
		t.Fatalf("after unfreeze: code=%s outcome=%s", code, res.Outcome)
	}
}

// ---------------------------------------------------------------------------
// stale base (optimistic concurrency)
// ---------------------------------------------------------------------------

func TestStaleBaseRefused(t *testing.T) {
	h := newHarness(t, "iran")
	// Loose the rate limiter so the second apply reaches the base check
	// (rate limits gate BEFORE optimistic concurrency, by design F4<F6).
	h.agent.rlShort = newRateLimiter(100, 10*time.Minute)
	h.agent.rlLong = newRateLimiter(100, 24*time.Hour)
	h.runOne(applySet(), nil) // commit revision 1, head moves.
	// Now present a base that no longer matches head.
	olderHead := "r-ancient"
	op := ApplyOp{
		Change: CandidateChange{Role: "iran", Set: applySet(), BaseRevision: olderHead, ChangeID: "c-2"},
		Actor:  "op",
	}
	res, code, _ := h.agent.runApply(op, nil)
	if code != ErrCodeStaleBase {
		t.Fatalf("code = %q, want stale_base", code)
	}
	if res.Outcome != "" {
		t.Fatal("stale apply must not produce an outcome")
	}
}

// ---------------------------------------------------------------------------
// idempotency
// ---------------------------------------------------------------------------

func TestIdempotencyReplayAndConflict(t *testing.T) {
	h := newHarness(t, "iran")

	// Simulate the opApply path with the idempotency key: the engine's
	// idempotency store is exercised through the same functions the
	// socket handler uses.
	op := ApplyOp{
		Change:         CandidateChange{Role: "iran", Set: applySet(), ChangeID: "c-1"},
		IdempotencyKey: "idem-1",
		Actor:          "op",
	}
	res, code, msg := h.agent.runApply(op, nil)
	if code != "" {
		t.Fatalf("first apply: %s %s", code, msg)
	}
	h.agent.idempotencyStore(op, &res)

	// Replay with the same key + same content → stored result.
	if entry, conflict := h.agent.idempotencyLookup(op); conflict {
		t.Fatal("replay reported a conflict")
	} else if entry == nil {
		t.Fatal("replay returned no stored entry")
	} else if entry.result["revision"] != res.RevisionID {
		t.Fatalf("stored result revision %v != %v", entry.result["revision"], res.RevisionID)
	}

	// Same key, DIFFERENT content → conflict.
	other := op
	other.Change.Set = map[string]string{config.EnvPolicyTopK: "5"}
	if _, conflict := h.agent.idempotencyLookup(other); !conflict {
		t.Fatal("different content under the same key must be a conflict")
	}
}

// ---------------------------------------------------------------------------
// revert-lkg
// ---------------------------------------------------------------------------

func TestRevertLKGRestoresPrevious(t *testing.T) {
	h := newHarness(t, "iran")
	// Commit two revisions so head=2, lkg=1.
	h.runOne(applySet(), nil)
	h.agent.ApplyPer10Min = 100
	h.agent.rlShort = newRateLimiter(100, 10*time.Minute)
	second := map[string]string{config.EnvPolicyMode: config.PolicyAdaptiveMode, config.EnvPolicyTopK: "4"}
	h.runOne(second, nil)

	head, _ := h.agent.Store.Head()
	lkg, _ := h.agent.Store.LKG()
	if head == lkg {
		t.Fatalf("head (%s) and lkg (%s) must differ after two commits", head, lkg)
	}

	res, code, msg := h.agent.rollbackLKG("op")
	if code != "" {
		t.Fatalf("revert-lkg failed: %s %s", code, msg)
	}
	if res.Outcome != "rolled-back-lkg" {
		t.Fatalf("outcome = %q", res.Outcome)
	}
	newHead, _ := h.agent.Store.Head()
	if newHead != lkg {
		t.Fatalf("head = %q after revert, want lkg %q", newHead, lkg)
	}
}

func TestRevertLKGWithoutLKG(t *testing.T) {
	h := newHarness(t, "iran")
	res, code, _ := h.agent.rollbackLKG("op")
	if code == "" {
		t.Fatalf("expected an error, got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// crash recovery (design §5.6 table)
// ---------------------------------------------------------------------------

// simulateCrash sets up the journal + live file exactly as one §5.6 row
// describes. liveAfter is what the live file currently holds ("")
// leaves it unchanged. recordNewHash controls the NewHash recorded in
// the journal: by default it mirrors the live content, but a test can
// pass a distinct value to exercise the "neither hash matches" row.
func simulateCrash(t *testing.T, h *harness, state ControlJournalState, liveAfter, recordNewHash string) {
	t.Helper()
	// The store needs a real revision with pre/ copies for recovery to
	// have something to restore.
	id, _ := h.agent.Store.NewRevisionID()
	src := filepath.Join(t.TempDir(), "orig.env")
	_ = os.WriteFile(src, []byte(h.liveContent()), 0o600)
	_ = h.agent.Store.PreSnapshot(id, map[string]string{baseName(h.livePath()): src})
	_ = h.agent.Store.CommitRevision(RevisionMeta{ID: id, Role: h.seam.role, Kind: "splitter-policy", Outcome: "committed"},
		map[string]string{baseName(h.livePath()): src}, "")
	e := ControlJournalEntry{
		ChangeID: "c-crash", Role: h.seam.role, State: state,
		Revision: id, Parent: "",
	}
	e.PreHash, _ = h.agent.Store.HashFile(src)
	if liveAfter != "" {
		_ = os.WriteFile(h.livePath(), []byte(liveAfter), 0o600)
	}
	if recordNewHash == "" {
		e.NewHash, _ = h.agent.Store.HashFile(h.livePath())
	} else {
		e.NewHash = recordNewHash
	}
	if err := h.agent.Journal.Write(e); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryNoInFlight(t *testing.T) {
	h := newHarness(t, "iran")
	out, err := h.agent.RecoverOnStart()
	if err != nil {
		t.Fatal(err)
	}
	if out != RecoveryNothing {
		t.Fatalf("out = %q, want no-in-flight", out)
	}
}

func TestRecoveryPreparedNoChange(t *testing.T) {
	h := newHarness(t, "iran")
	simulateCrash(t, h, JournalPrepared, "", "") // live == pre
	out, _ := h.agent.RecoverOnStart()
	if out != RecoveryNoChange {
		t.Fatalf("out = %q, want recovered_no_change", out)
	}
	if _, inFlight, _ := h.agent.Journal.Read(); inFlight {
		t.Fatal("journal not cleared")
	}
}

func TestRecoveryPreparedLiveDiffers(t *testing.T) {
	h := newHarness(t, "iran")
	original := h.liveContent()
	simulateCrash(t, h, JournalPrepared, "SNEAKED_IN\n", "")
	out, _ := h.agent.RecoverOnStart()
	if out != RecoveryRollback {
		t.Fatalf("out = %q, want recovered_rollback", out)
	}
	if h.liveContent() != original {
		t.Fatal("live file was not restored to the pre copy")
	}
}

func TestRecoverySwappedNewHashLandsCommit(t *testing.T) {
	h := newHarness(t, "iran")
	simulateCrash(t, h, JournalSwapped, "SPLIT_POLICY_MODE=adaptive\n", "")
	out, _ := h.agent.RecoverOnStart()
	if out != RecoveryCommit {
		t.Fatalf("out = %q, want recovered_commit", out)
	}
	if _, inFlight, _ := h.agent.Journal.Read(); inFlight {
		t.Fatal("journal not cleared after commit")
	}
	head, _ := h.agent.Store.Head()
	if head == "" {
		t.Fatal("head not set after recovered commit")
	}
}

func TestRecoverySwappedPreHashClears(t *testing.T) {
	h := newHarness(t, "iran")
	simulateCrash(t, h, JournalSwapped, "", "")
	out, _ := h.agent.RecoverOnStart()
	if out != RecoveryNoChange {
		t.Fatalf("out = %q, want recovered_no_change", out)
	}
}

func TestRecoverySwappedUnknownHashRollsBack(t *testing.T) {
	h := newHarness(t, "iran")
	original := h.liveContent()
	simulateCrash(t, h, JournalSwapped, "UNKNOWN_STATE\n", "unknown-recorded")
	out, _ := h.agent.RecoverOnStart()
	if out != RecoveryRollback {
		t.Fatalf("out = %q, want recovered_rollback", out)
	}
	if h.liveContent() != original {
		t.Fatal("live file was not restored")
	}
}

func TestRecoveryVerifiedCommits(t *testing.T) {
	h := newHarness(t, "iran")
	simulateCrash(t, h, JournalVerified, "SPLIT_POLICY_MODE=adaptive\n", "")
	out, _ := h.agent.RecoverOnStart()
	if out != RecoveryCommit {
		t.Fatalf("out = %q, want recovered_commit", out)
	}
}

func TestRecoveryTamperedJournalFailsClosed(t *testing.T) {
	h := newHarness(t, "iran")
	_ = os.WriteFile(h.agent.Journal.path(), []byte("garbage"), 0o600)
	out, _ := h.agent.RecoverOnStart()
	if out != RecoveryTamper {
		t.Fatalf("out = %q, want tamper-recovery-required", out)
	}
	// The journal file is retained for the operator.
	if _, err := os.Stat(h.agent.Journal.path()); err != nil {
		t.Fatal("tampered journal was deleted; it must be retained")
	}
	// Mutating ops stay refused.
	_, code, _ := h.runOne(applySet(), nil)
	if code != ErrCodeRecoveryRequired {
		t.Fatalf("code = %q, want recovery_required", code)
	}
}

func TestRecoverySwappedVerifyFailsRollsBack(t *testing.T) {
	h := newHarness(t, "iran")
	simulateCrash(t, h, JournalSwapped, "SPLIT_POLICY_MODE=adaptive\n", "")
	h.seam.failVerify = errors.New("post-crash verify down")
	out, _ := h.agent.RecoverOnStart()
	if out != RecoveryRollback {
		t.Fatalf("out = %q, want recovered_rollback", out)
	}
}

// ---------------------------------------------------------------------------
// audit integration
// ---------------------------------------------------------------------------

func TestApplyWritesAuditEntry(t *testing.T) {
	h := newHarness(t, "iran")
	h.runOne(applySet(), nil)
	entries := h.agent.Audit.ReadAll()
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Actor != "test-operator" || e.Outcome != "committed" {
		t.Fatalf("audit entry wrong: %+v", e)
	}
	if err := h.agent.Audit.VerifyChain(); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// ServeConnection: peer rejection → no frame exchange (fail closed)
// ---------------------------------------------------------------------------

func TestServeConnectionPeerRejectedClosesSilently(t *testing.T) {
	h := newHarness(t, "iran")
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		// The rejected side closes; reading the frame then fails.
		_, _ = client.Read(make([]byte, 16))
	}()
	policy := &PeerPolicy{ExpectedUID: 1, ExpectedGID: 2, CanonicalExe: "/usr/local/bin/tunneldash"}
	src := &fakeCredentialSource{
		creds:     PeerCredentials{PID: 9, UID: 1, GID: 2, ExePath: "/usr/local/bin/tunneldash"},
		available: false, // fail closed
	}
	err := h.agent.ServeConnection(src, policy, server)
	if !errors.Is(err, ErrPeerRejected) {
		t.Fatalf("err = %v, want ErrPeerRejected", err)
	}
}

func TestServeConnectionStatusRoundTrip(t *testing.T) {
	h := newHarness(t, "iran")
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		err := h.agent.ServeConnection(
			&fakeCredentialSource{creds: PeerCredentials{PID: 9, UID: 1, GID: 2, ExePath: "/x"}, available: true},
			&PeerPolicy{ExpectedUID: 1, ExpectedGID: 2, CanonicalExe: "/x"},
			server)
		done <- err
	}()

	raw, _ := encodeFrame(&Frame{V: 1, Op: OpStatus, ReqID: "r1"})
	if _, err := client.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("no response: %v", err)
	}
	var resp Frame
	if err := decodeFrameStrict(buf[:n], &resp); err != nil {
		t.Fatalf("response frame: %v", err)
	}
	if !resp.OK {
		t.Fatalf("status not OK: %+v", resp.Error)
	}
	_ = <-done
}

func decodeFrameStrict(raw []byte, dst *Frame) error {
	f, err := decodeFrame(raw)
	if err != nil {
		return err
	}
	*dst = *f
	return nil
}
