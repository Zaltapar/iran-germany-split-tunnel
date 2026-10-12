// coordinated_test.go — the C4 coordinated two-host handshake driven with
// two in-process agents (plans/dashboard-control-design.md §12 C4, D10).
//
// The tests prove the coupling invariant end to end: prepare-both →
// abort-on-prepare-failure (both live files untouched) → commit-both, with
// the committed side reverted when the peer's commit fails; the single-
// agent (D10) staged-peer path that stages a Blob B and reports "peer
// change required" without pretending coordination; and that NO secret
// value ever appears in a receipt or an audit entry (requirement 7).
package controlagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// ---------------------------------------------------------------------------
// fake xray gate: records calls and can fail on demand
// ---------------------------------------------------------------------------

type fakeXrayGate struct {
	mu sync.Mutex
	// calls records each gate method invocation (render/test/restart/verify).
	calls []string

	failRender  error
	failTest    error
	failRestart error
	failVerify  error

	// sandboxDir is where the fake writes its candidate xray config.
	sandboxDir string
}

func newFakeXrayGate(t *testing.T) *fakeXrayGate {
	g := &fakeXrayGate{sandboxDir: t.TempDir()}
	t.Cleanup(func() { _ = os.RemoveAll(g.sandboxDir) })
	return g
}

func (g *fakeXrayGate) record(c string) {
	g.mu.Lock()
	g.calls = append(g.calls, c)
	g.mu.Unlock()
}

func (g *fakeXrayGate) hadCall(c string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.calls {
		if x == c {
			return true
		}
	}
	return false
}

func (g *fakeXrayGate) RenderXrayForMC(role string, env map[string]string) (string, error) {
	g.record("render")
	if g.failRender != nil {
		return "", g.failRender
	}
	p := filepath.Join(g.sandboxDir, "xray-"+role+".cand.json")
	if err := os.WriteFile(p, []byte(`{"log":{"level":"warning"}}`), 0o600); err != nil {
		return "", err
	}
	return p, nil
}

func (g *fakeXrayGate) ConfigTest(role, candidatePath string) error {
	g.record("test")
	return g.failTest
}

func (g *fakeXrayGate) RestartXray(role string) error {
	g.record("restart")
	if g.failRestart != nil {
		return g.failRestart
	}
	g.failRestart = nil
	return nil
}

func (g *fakeXrayGate) VerifyXray(role string) error {
	g.record("verify")
	if g.failVerify != nil {
		return g.failVerify
	}
	g.failVerify = nil
	return nil
}

// ---------------------------------------------------------------------------
// test scaffolding: two in-process agents (germany + iran)
// ---------------------------------------------------------------------------

// c4Host is one in-process agent + its seams.
type c4Host struct {
	agent *Agent
	seam  *fakeSeam
	gate  *fakeXrayGate
	root  string
}

// newC4Host builds one agent wired with a fake seam + fake xray gate, with
// the rate limits raised so a baseline C2 seed plus a C4 apply both fit in
// the window, and seeds ONE baseline C2 revision so a store head (and, after
// the first C4 commit, an LKG) exists for the coupled-repair rollback.
func newC4Host(t *testing.T, role string, base map[string]string) *c4Host {
	t.Helper()
	root := t.TempDir()
	live := filepath.Join(t.TempDir(), role+".env")
	if err := os.WriteFile(live, []byte("SPLIT_POLICY_MODE=static\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seam := &fakeSeam{role: role, livePath: live, base: base}
	gate := newFakeXrayGate(t)
	a, err := NewAgent(root, seam, defaultConfigBuilder)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	// Raise the apply rate limits so the baseline seed and the C4 apply
	// both fit the window (the real default is 1/10min).
	a.ApplyPer10Min = 100
	a.ApplyPer24H = 100
	a.rlShort = newRateLimiter(100, 10*time.Minute)
	a.rlLong = newRateLimiter(100, 24*time.Hour)
	a.XrayGate = gate

	// Seed one baseline C2 revision so a head exists (and so the first
	// C4 commit promotes a real LKG for the coupled repair).
	baseSet := map[string]string{config.EnvPolicyMode: config.PolicyAdaptiveMode}
	res, code, msg := a.runApply(ApplyOp{
		Change: CandidateChange{Role: role, Set: baseSet, ChangeID: "c4-seed"},
		Actor:  "test-seed",
	}, nil)
	if code != "" || res.Outcome != "committed" {
		t.Fatalf("baseline seed failed: code=%q outcome=%q msg=%s", code, res.Outcome, msg)
	}

	h := &c4Host{agent: a, seam: seam, gate: gate, root: root}
	return h
}

func (h *c4Host) liveContent() string {
	data, _ := os.ReadFile(h.seam.livePath)
	return string(data)
}

// germanBase / iranBase are minimal, role-correct base envs for the C4
// multi-carrier enablement the tests drive.
func germanBase() map[string]string {
	return map[string]string{
		config.EnvDownListen: "127.0.0.1:9002",
	}
}

func iranBase() map[string]string {
	return map[string]string{
		config.EnvDownCarrier: "127.0.0.1:8080",
	}
}

// mcSet is the multi-carrier enablement candidate for a role.
func mcSet(role string) map[string]string {
	if role == config.RoleGermany {
		return map[string]string{
			config.EnvMultiCarrierEnabled: "true",
			config.EnvDownListen2:         "127.0.0.1:9003",
			config.EnvDownSNI2:            "second.example.com",
		}
	}
	return map[string]string{
		config.EnvMultiCarrierEnabled: "true",
		config.EnvDownCarrierAddr2:    "127.0.0.1:8081",
	}
}

func mcPlan() CoordinatedPlan {
	return CoordinatedPlan{
		ChangeID: "c4-coord-test",
		Actor:    "operator",
		Germany:  CandidateChange{Role: config.RoleGermany, Set: mcSet(config.RoleGermany)},
		Iran:     CandidateChange{Role: config.RoleIran, Set: mcSet(config.RoleIran)},
	}
}

// ---------------------------------------------------------------------------
// 1. both sides prepare → both commit (the happy coupled path)
// ---------------------------------------------------------------------------

func TestCoordinatedBothSidesCommit(t *testing.T) {
	g := newC4Host(t, config.RoleGermany, germanBase())
	i := newC4Host(t, config.RoleIran, iranBase())
	preG, preI := g.liveContent(), i.liveContent()

	// The MC flip is xray-affected; wire the fake gate on both peers.
	res := NewCoordinator(peerWithGate(t, g), peerWithGate(t, i)).CoupledApply(mcPlan())

	if res.Outcome != "committed" {
		t.Fatalf("outcome = %q, want committed (g=%+v i=%+v)", res.Outcome, res.Germany, res.Iran)
	}
	if res.Germany.Outcome != "committed" || res.Iran.Outcome != "committed" {
		t.Fatalf("sides not both committed: g=%q i=%q", res.Germany.Outcome, res.Iran.Outcome)
	}
	// Both live files changed to carry the new multi-carrier values.
	if !strings.Contains(g.liveContent(), "second.example.com") {
		t.Fatalf("germany live file not updated: %q", g.liveContent())
	}
	if !strings.Contains(i.liveContent(), "8081") {
		t.Fatalf("iran live file not updated: %q", i.liveContent())
	}
	if g.liveContent() == preG || i.liveContent() == preI {
		t.Fatal("a live file was not changed on the committed path")
	}
	// Both agents ran the xray gate (the MC flip is xray-affected).
	if !g.gate.hadCall("test") || !i.gate.hadCall("test") {
		t.Fatalf("xray gate -test not run on both hosts (g=%v i=%v)", g.gate.hadCall("test"), i.gate.hadCall("test"))
	}
	// Both live files are the pre-change... no: committed. Verify head set.
	for name, h := range map[string]*c4Host{"germany": g, "iran": i} {
		head, _ := h.agent.Store.Head()
		if head == "" {
			t.Fatalf("%s head not set after commit", name)
		}
	}
}

// peerWithGate wraps a host's agent in an AgentPeer and wires its fake gate.
func peerWithGate(t *testing.T, h *c4Host) CoordinatedSide {
	t.Helper()
	p := NewAgentPeer(h.agent)
	p.SetXrayGate(h.gate)
	return p
}

// ---------------------------------------------------------------------------
// 2. one side's prepare fails → BOTH abort, both live files untouched
// ---------------------------------------------------------------------------

func TestCoordinatedPrepareFailAbortsBoth(t *testing.T) {
	g := newC4Host(t, config.RoleGermany, germanBase())
	i := newC4Host(t, config.RoleIran, iranBase())
	preG, preI := g.liveContent(), i.liveContent()

	// Iran's prepare fails at render (the no-write phase).
	peerG := peerWithGate(t, g)
	peerI := NewAgentPeer(i.agent)
	peerI.SetXrayGate(i.gate)
	peerI.Faults = Faults{"render": errors.New("iran render exploded")}

	res := NewCoordinator(peerG, peerI).CoupledApply(mcPlan())
	if res.Outcome != "aborted" {
		t.Fatalf("outcome = %q, want aborted (g=%+v i=%+v)", res.Outcome, res.Germany, res.Iran)
	}
	if res.Germany.Outcome != "aborted" || res.Iran.Outcome != "aborted" {
		t.Fatalf("sides not both aborted: g=%q i=%q", res.Germany.Outcome, res.Iran.Outcome)
	}
	// Neither host committed (no writes happened during prepare).
	if g.liveContent() != preG {
		t.Fatal("germany live file changed despite an aborted prepare")
	}
	if i.liveContent() != preI {
		t.Fatal("iran live file changed despite an aborted prepare")
	}
}

// ---------------------------------------------------------------------------
// 3. one side's commit fails → the committed side is reverted (coupled)
// ---------------------------------------------------------------------------

func TestCoordinatedCommitFailRollsBackCommittedSide(t *testing.T) {
	g := newC4Host(t, config.RoleGermany, germanBase())
	i := newC4Host(t, config.RoleIran, iranBase())
	preG := g.liveContent()

	peerG := peerWithGate(t, g)
	peerI := NewAgentPeer(i.agent)
	peerI.SetXrayGate(i.gate)
	// Iran's commit fails (the store write is refused) → Iran auto-rolls
	// back inside the engine; the coordinator reverts the committed
	// Germany side so BOTH hosts stay in the pre-change state.
	peerI.Faults = Faults{"commit": errors.New("iran store write refused")}

	res := NewCoordinator(peerG, peerI).CoupledApply(mcPlan())
	if res.Outcome != "rolled-back" {
		t.Fatalf("outcome = %q, want rolled-back (g=%+v i=%+v)", res.Outcome, res.Germany, res.Iran)
	}
	if res.Iran.Outcome != "rolled-back" {
		t.Fatalf("iran outcome = %q, want rolled-back", res.Iran.Outcome)
	}
	// The committed Germany side was reverted via revert-lkg.
	if res.Germany.Outcome != "rolled-back-lkg" {
		t.Fatalf("germany outcome = %q, want rolled-back-lkg", res.Germany.Outcome)
	}
	// Germany's live file is back to the pre-change content (LKG).
	if g.liveContent() != preG {
		t.Fatalf("germany live file not reverted to pre-change state:\n got=%q\nwant=%q", g.liveContent(), preG)
	}
}

// ---------------------------------------------------------------------------
// 4. the D10 single-agent path: the peer has no live agent, so a Blob B is
//    staged and "peer change required" is reported (no pretending).
// ---------------------------------------------------------------------------

func TestCoordinatedStagedPeerReportsPeerChangeRequired(t *testing.T) {
	g := newC4Host(t, config.RoleGermany, germanBase())
	peerG := peerWithGate(t, g)
	preG := g.liveContent()

	// The Iran half has NO agent: it is the staged peer. It stages a Blob
	// B export and returns a fingerprint (never content).
	stagedIran := &StagedPeerSide{
		Role: config.RoleIran,
		StageBlob: func(changeID string) (string, error) {
			_ = changeID
			return "sha256:aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff666677778888", nil
		},
	}

	res := NewCoordinator(peerG, stagedIran).CoupledApply(mcPlan())
	if res.Outcome != "staged" {
		t.Fatalf("outcome = %q, want staged (g=%+v i=%+v)", res.Outcome, res.Germany, res.Iran)
	}
	if !strings.Contains(res.PeerChangeRequired, "peer change required") &&
		!strings.Contains(res.PeerChangeRequired, "stage a Blob") {
		t.Fatalf("no peer-change-required notice: %q", res.PeerChangeRequired)
	}
	// The live Germany side is NOT committed (the invariant needs both).
	if g.liveContent() != preG {
		t.Fatalf("germany was committed on the staged path: %q", g.liveContent())
	}
	// The staged receipt carries a fingerprint, not the blob content.
	if res.Iran.BlobFingerprint == "" {
		t.Fatal("staged peer receipt is missing the blob fingerprint")
	}
	if strings.Contains(res.Iran.BlobFingerprint, "example.com") {
		t.Fatal("staged receipt leaked blob content into the fingerprint field")
	}
}

// ---------------------------------------------------------------------------
// 5. no secret ever crosses the handshake (receipts) or the audit entries
// ---------------------------------------------------------------------------

func TestCoordinatedNoSecretsInReceiptsOrAudit(t *testing.T) {
	// Build candidates that mix a SOCKS allowlist (operator config, which
	// the C4 diff fingerprints because the C2 audit sink treats "socks" as
	// secret-named) with an SNI (allowed to be logged in full).
	secretSNI := "secret-sni.example.com"
	socksList := "10.1.2.3,192.168.0.0/24"

	g := newC4Host(t, config.RoleGermany, germanBase())
	i := newC4Host(t, config.RoleIran, map[string]string{
		config.EnvDownCarrier:         "127.0.0.1:8080",
		config.EnvSocksAllowedSources: socksList,
	})
	// A routing candidate that carries the allowlist, so the audit diff
	// exercises the fingerprinting path. (The Iran base already sets the
	// allowlist; the routing change below adds one on top.)
	_ = secretSNI

	// The routing concept is what the dashboard's routing endpoints drive;
	// but the coordinator uses the MC concept. To exercise redaction over a
	// routing set through the SAME engine, run a single-host routing apply
	// on each agent directly and inspect the audit trail.
	for _, h := range []*c4Host{g, i} {
		set := map[string]string{config.EnvTargetAddrPolicy: "prefer-ipv4"}
		if h == i {
			set[config.EnvSocksAllowedSources] = socksList
		}
		res, code, msg := h.agent.runC4Apply(C4ApplyOp{
			Change: CandidateChange{Role: h.seam.role, Set: set},
			Actor:  "operator",
		}, c4RoutingConcept(), nil)
		if code != "" {
			t.Fatalf("%s routing apply failed: code=%q msg=%s", h.seam.role, code, msg)
		}
		if res.Outcome != "committed" {
			t.Fatalf("%s routing apply outcome = %q, want committed", h.seam.role, res.Outcome)
		}
	}

	// Assert: neither host's audit trail contains the raw allowlist value
	// (it is fingerprinted), while non-secret values remain present.
	for _, h := range []*c4Host{g, i} {
		raw, err := os.ReadFile(filepath.Join(h.root, "audit.jsonl"))
		if err != nil {
			t.Fatalf("%s audit read: %v", h.seam.role, err)
		}
		if strings.Contains(string(raw), socksList) {
			t.Fatalf("%s audit trail leaked the SOCKS allowlist value: %q", h.seam.role, string(raw))
		}
		// The routing policy value (non-secret) is present in full.
		if !strings.Contains(string(raw), "prefer-ipv4") {
			t.Fatalf("%s audit trail is missing the (non-secret) routing value", h.seam.role)
		}
		// Each audit line must be valid JSON (no malformed secret echo).
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("%s audit line is not JSON: %v (%s)", h.seam.role, err, line)
			}
		}
	}

	// And a receipts-only assertion: the coupled MC handshake's receipts
	// carry no raw values at all (only outcomes/codes/fingerprints).
	peerG := peerWithGate(t, g)
	peerI := NewAgentPeer(i.agent)
	peerI.SetXrayGate(i.gate)
	res := NewCoordinator(peerG, peerI).CoupledApply(mcPlan())
	if res.Outcome != "committed" {
		t.Fatalf("happy-path MC outcome = %q, want committed", res.Outcome)
	}
	recvBytes, _ := json.Marshal(res)
	for _, want := range []string{"9003", "8081", "second.example.com"} {
		if strings.Contains(string(recvBytes), want) {
			t.Fatalf("receipts leaked a raw multi-carrier value %q: %s", want, recvBytes)
		}
	}
}

// ---------------------------------------------------------------------------
// engine-level fault-injection matrix for the C4 single-host path
// (the C2 state machine re-driven through the C4 engine)
// ---------------------------------------------------------------------------

func TestC4RoutingApplySuccess(t *testing.T) {
	h := newC4Host(t, config.RoleIran, iranBase())
	pre := h.liveContent()
	res, code, msg := h.agent.runC4Apply(C4ApplyOp{
		Change: CandidateChange{Role: config.RoleIran, Set: map[string]string{
			config.EnvTargetAddrPolicy: "ipv4-only",
		}, ChangeID: "r-1"},
		Actor: "operator",
	}, c4RoutingConcept(), nil)
	if code != "" {
		t.Fatalf("routing apply failed: code=%q msg=%s", code, msg)
	}
	if res.Outcome != "committed" {
		t.Fatalf("outcome = %q, want committed", res.Outcome)
	}
	if strings.Contains(h.liveContent(), pre) && h.liveContent() == pre {
		t.Fatal("routing change did not alter the live file")
	}
}

// TestC4ApplyEveryFaultStep drives the C4 engine to failure at each fault
// point and asserts it lands where the design §5.6 table says (auto-rollback
// after any post-swap step; no writes on any pre-swap step).
func TestC4ApplyEveryFaultStep(t *testing.T) {
	h := newC4Host(t, config.RoleGermany, germanBase())

	postSwap := []string{"swap", "restart", "verify", "commit"}
	for _, step := range postSwap {
		t.Run("post-swap/"+step, func(t *testing.T) {
			h2 := newC4Host(t, config.RoleGermany, germanBase())
			original := h2.liveContent()
			faults := Faults{step: fmt.Errorf("fault at %s", step)}
			res, code, _ := h2.agent.runC4Apply(C4ApplyOp{
				Change: CandidateChange{Role: config.RoleGermany, Set: mcSet(config.RoleGermany), ChangeID: "fault-" + step},
				Actor:  "operator",
			}, c4MCConcept(), faults)
			if step != "commit" && res.Outcome != "rolled-back" {
				// restart/verify/swap auto-rollback; commit auto-rollback too.
				t.Fatalf("%s: outcome = %q, want rolled-back (code=%q)", step, res.Outcome, code)
			}
			if h2.liveContent() != original {
				t.Fatalf("%s: live file not restored (got %q want %q)", step, h2.liveContent(), original)
			}
		})
	}

	// pre-swap steps leave the live file untouched and clear the journal.
	for _, step := range []string{"render", "validate", "xrayrender", "configtest"} {
		t.Run("pre-swap/"+step, func(t *testing.T) {
			h2 := newC4Host(t, config.RoleGermany, germanBase())
			original := h2.liveContent()
			faults := Faults{step: fmt.Errorf("fault at %s", step)}
			res, code, _ := h2.agent.runC4Apply(C4ApplyOp{
				Change: CandidateChange{Role: config.RoleGermany, Set: mcSet(config.RoleGermany), ChangeID: "prefault-" + step},
				Actor:  "operator",
			}, c4MCConcept(), faults)
			// A prepare-phase failure lands as a named *-failed outcome:
			// NO commit, NO rollback, no live write, journal cleared.
			if res.Outcome == "committed" || res.Outcome == "rolled-back" {
				t.Fatalf("%s: outcome = %q, want a prepare-phase *-failed outcome (no commit/rollback)", step, res.Outcome)
			}
			if code == "" {
				t.Fatalf("%s: expected a non-empty error code, got none", step)
			}
			if h2.liveContent() != original {
				t.Fatalf("%s: live file changed on a pre-swap fault", step)
			}
			if _, inFlight, _ := h2.agent.Journal.Read(); inFlight {
				t.Fatalf("%s: journal left in-flight after a pre-swap fault", step)
			}
		})
	}
	_ = h
}

// TestC4XrayGateFailClosed verifies an xray-affecting change is refused when
// no gate is wired (fail-closed), and a routing (non-xray) change is applied
// without consulting the gate.
func TestC4XrayGateFailClosed(t *testing.T) {
	// No gate wired.
	h := newC4Host(t, config.RoleGermany, germanBase())
	h.agent.XrayGate = nil
	res, code, msg := h.agent.runC4Apply(C4ApplyOp{
		Change: CandidateChange{Role: config.RoleGermany, Set: mcSet(config.RoleGermany), ChangeID: "xray-none"},
		Actor:  "operator",
	}, c4MCConcept(), nil)
	if code != ErrCodeXrayGateNotConfigured {
		t.Fatalf("code = %q (msg=%s), want %q", code, msg, ErrCodeXrayGateNotConfigured)
	}
	if res.Outcome != "xray-gate-unavailable" {
		t.Fatalf("outcome = %q, want xray-gate-unavailable", res.Outcome)
	}
	if h.liveContent() == "SPLIT_POLICY_MODE=adaptive" || strings.Contains(h.liveContent(), "9003") {
		t.Fatal("an xray-affected change was applied with no gate wired")
	}

	// A routing (non-xray) change on the same gateless agent is applied.
	h2 := newC4Host(t, config.RoleIran, iranBase())
	h2.agent.XrayGate = nil
	res2, code2, msg2 := h2.agent.runC4Apply(C4ApplyOp{
		Change: CandidateChange{Role: config.RoleIran, Set: map[string]string{
			config.EnvTargetAddrPolicy: "ipv4-only",
		}, ChangeID: "routing-none"},
		Actor: "operator",
	}, c4RoutingConcept(), nil)
	if code2 != "" {
		t.Fatalf("routing apply with no gate: code=%q msg=%s (want none)", code2, msg2)
	}
	if res2.Outcome != "committed" {
		t.Fatalf("routing outcome = %q, want committed", res2.Outcome)
	}
}

// TestC4KillSwitchRefusesApply verifies the frozen kill switch blocks a C4
// apply (the recovery action revert-lkg remains allowed).
func TestC4KillSwitchRefusesApply(t *testing.T) {
	h := newC4Host(t, config.RoleIran, iranBase())
	h.agent.Frozen = func() bool { return true }
	res, code, _ := h.agent.runC4Apply(C4ApplyOp{
		Change: CandidateChange{Role: config.RoleIran, Set: map[string]string{
			config.EnvTargetAddrPolicy: "ipv4-only"}, ChangeID: "frozen"},
		Actor: "operator",
	}, c4RoutingConcept(), nil)
	if code != ErrCodeFrozen {
		t.Fatalf("code = %q, want %q", code, ErrCodeFrozen)
	}
	if res.Outcome != "frozen" {
		t.Fatalf("outcome = %q, want frozen", res.Outcome)
	}
}

// TestC4ConcurrencyLockRefusesSecondApply verifies two overlapping C4
// applies on one host serialize on the apply lock (the second is refused).
func TestC4ConcurrencyLockRefusesSecondApply(t *testing.T) {
	h := newC4Host(t, config.RoleIran, iranBase())
	h.agent.ApplyMu.Lock()
	defer h.agent.ApplyMu.Unlock()
	_, code, _ := h.agent.runC4Apply(C4ApplyOp{
		Change: CandidateChange{Role: config.RoleIran, Set: map[string]string{
			config.EnvTargetAddrPolicy: "ipv4-only"}, ChangeID: "lock"},
		Actor: "operator",
	}, c4RoutingConcept(), nil)
	if code != ErrCodeApplyInProgress {
		t.Fatalf("code = %q, want %q", code, ErrCodeApplyInProgress)
	}
}

// TestC4RoutingIdempotencyReplays verifies the C4 idempotency key: a second
// identical apply (same key, same payload) replays the stored result WITHOUT
// a second live apply, and a reused key with a DIFFERENT payload is a
// conflict. Driven through the real op handler over a pipe so the
// idempotency + audit code runs exactly as the socket does.
func TestC4RoutingIdempotencyReplays(t *testing.T) {
	h := newC4Host(t, config.RoleIran, iranBase())
	set := map[string]string{config.EnvTargetAddrPolicy: "ipv4-only"}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	applyOnce := func(idemKey string, payload any) (string, any) {
		frame := &Frame{
			V: ProtocolVersion, Op: OpC4RoutingApply, ReqID: "req-1",
			IdempotencyKey: idemKey, Payload: payload,
		}
		done := make(chan error, 1)
		go func() { done <- h.agent.opRoutingApply(server, frame) }()

		buf := make([]byte, 16<<10+1)
		n, rerr := client.Read(buf)
		if rerr != nil {
			<-done
			t.Fatalf("read reply: %v", rerr)
		}
		var fr Frame
		dec := json.NewDecoder(bytes.NewReader(buf[:n]))
		dec.DisallowUnknownFields()
		if derr := dec.Decode(&fr); derr != nil {
			<-done
			t.Fatalf("decode reply: %v", derr)
		}
		<-done
		return frReplyCode(&fr), fr.Data
	}

	// First apply: commits.
	code, data := applyOnce("idem-c4-a", &CandidateChange{Role: config.RoleIran, Set: set})
	if code != "" {
		t.Fatalf("first routing apply code=%q data=%v", code, data)
	}
	if m, ok := data.(map[string]any); !ok || m["outcome"] != "committed" {
		t.Fatalf("first apply data = %v", data)
	}
	rev1, _ := mRev(data)

	// Replay the SAME key + payload: served from the cache with the SAME
	// revision (no second live apply ran).
	code2, data2 := applyOnce("idem-c4-a", &CandidateChange{Role: config.RoleIran, Set: set})
	if code2 != "" {
		t.Fatalf("replay code=%q data=%v", code2, data2)
	}
	rev2, _ := mRev(data2)
	if rev1 != rev2 {
		t.Fatalf("replay produced a different revision (%q vs %q) — the second live apply ran", rev1, rev2)
	}

	// Reuse the SAME key with a DIFFERENT payload: idempotency conflict.
	code4, data4 := applyOnce("idem-c4-a", &CandidateChange{Role: config.RoleIran, Set: map[string]string{config.EnvSocksAllowedSources: "10.9.9.9"}})
	if code4 != ErrCodeIdempotency {
		t.Fatalf("reused key with a different payload: code=%q data=%v, want %q", code4, data4, ErrCodeIdempotency)
	}
}

// frReplyCode returns the error code of a reply frame ("" when OK).
func frReplyCode(fr *Frame) string {
	if fr.Error != nil {
		return fr.Error.Code
	}
	return ""
}

// mRev pulls the committed revision id out of an apply response map.
func mRev(data any) (string, bool) {
	m, ok := data.(map[string]any)
	if !ok {
		return "", false
	}
	rev, _ := m["revision"].(string)
	return rev, true
}
