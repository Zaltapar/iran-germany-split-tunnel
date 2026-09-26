package node

import (
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// This file is the Increment 2 (sender half) D4 test surface. It is
// authoritative from plans/architecture-checkpoint-backpressure.md §E, §F.2,
// §G.1 (M2, M3, M4, M8) and §H/§I. The integrity invariant is NOT
// weakened: every test below confirms that credit only ever PARKS the
// sender or leaves it unlimited; DATA is never dropped or a stream silently
// terminated by the credit machinery.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newCreditTestNode builds a bare Germany node (carriers installed on demand)
// with a small CreditFloorDrain so the floor drain is cheap to exercise, and
// a bounded aggregate session-buffer budget. KeepAlive is an hour so pings
// never interfere.
func newCreditTestNode(t *testing.T) *Node {
	t.Helper()
	cfg := Config{
		Role:                    RoleGermany,
		Grace:                   time.Second,
		RelayBufSize:            256,
		BufferBytes:             4096,
		KeepAliveInterval:       time.Hour,
		SessionBufferTotalBytes: 1 << 20,
		CreditFloorDrain:        32,
	}
	n := NewNode(cfg, log.New(io.Discard, "", 0), []byte("0123456789abcdef0123456789abcdef"))
	t.Cleanup(func() { n.Close() })
	return n
}

// attachDownSession builds a Germany-side session (down stream id) attached to
// an installed down carrier, with targetConn as its target socket. It
// installs a raw down carrier on n and returns the session, the target app
// side (write/EOF control) and the carrier generation the attachment is bound
// to.
func attachDownSession(t *testing.T, n *Node, id uint32, targetApp *testutil.MemConn) (*session.Session, uint64, *testutil.MemConn) {
	t.Helper()
	_, de := testutil.NewMemPipe()
	n.InstallDown(de, nil)
	h := n.current(session.DirDown)
	if h == nil {
		t.Fatal("down carrier not installed")
	}
	sess := session.NewSession(session.SessionID{}, &session.Destination{}, nil, targetApp, n.ctx)
	sess.StreamIDDown = id
	sess.DownAtt = session.NewAttachment(n.cfg.Grace, nil)
	if !sess.Activate() {
		t.Fatal("session activation failed")
	}
	if !sess.DownAtt.Attach(h.gen) {
		t.Fatal("down attach failed")
	}
	t.Cleanup(func() { sess.Close("test cleanup") })
	return sess, h.gen, de
}

// seedExhaustedCredit makes stream id, on gen, credit-gated with window 0:
// the sender has sent 100 bytes and the receiver has only popped 50, so the
// derived window is clamped to 0 (PARK, never wrap). This is the "credit == 0"
// precondition the gate and EOF-ordering tests need.
func seedExhaustedCredit(t *testing.T, n *Node, id uint32, gen uint64) {
	t.Helper()
	n.creditLedger.addSent(id, 100, gen)
	n.creditLedger.onCredit(id, 50, gen)
	if s := n.creditLedger.snapshot(id); !s.latched || s.window != 0 {
		t.Fatalf("seedExhaustedCredit: snapshot = %+v, want latched window 0", s)
	}
}

// ---------------------------------------------------------------------------
// Ledger state machine (B / §E.2, §E.4.1): un-latched → latched, clamp,
// rebind reset, generation validation.
// ---------------------------------------------------------------------------

// TestCreditLedgerUnlatchedThenLatches (part of M4 + §H/§I mixed-generation
// gate): a stream starts UN-LATCHED = unlimited (CreditInitial, A4) and only
// latches on the FIRST valid credit frame for its generation.
func TestCreditLedgerUnlatchedThenLatches(t *testing.T) {
	n := newCreditTestNode(t)
	l := n.creditLedger

	// Un-latched: unlimited, not gated, observed as "unlatched".
	gated, _, unlatched := n.creditGate(1, 5)
	if gated || !unlatched {
		t.Fatalf("fresh stream: gated=%v unlatched=%v, want gated=false unlatched=true (CreditInitial=unlimited)", gated, unlatched)
	}

	// No credit has arrived: the window is 0 but the stream is NOT latched,
	// so the gate must NOT park (it is unlimited). onCredit latches.
	l.onCredit(1, 100, 5)
	if s := l.snapshot(1); !s.latched || s.window != 100 {
		t.Fatalf("after first credit: snapshot = %+v, want latched window 100", s)
	}
	if gated, _, _ := n.creditGate(1, 5); gated {
		t.Fatal("window 100 must not gate, only exhaust (window 0) does")
	}
}

// TestCreditWindowClampNeverWraps (R2-3): if cumulativeBytesPopped <
// cumulativeSent the window clamps to 0 (PARK), never a wrapped uint64.
func TestCreditWindowClampNeverWraps(t *testing.T) {
	n := newCreditTestNode(t)
	n.creditLedger.addSent(1, 4000, 5) // sender ran ahead
	n.creditLedger.onCredit(1, 100, 5) // receiver behind → would wrap
	if s := n.creditLedger.snapshot(1); s.window != 0 || !s.latched {
		t.Fatalf("clamp: snapshot = %+v, want latched window 0 (no uint64 wrap)", s)
	}
	// A later catch-up credit re-derives the window as
	// cumulativeBytesPopped - cumulativeSent = 5000 - 4000 = 1000.
	n.creditLedger.onCredit(1, 5000, 5)
	if s := n.creditLedger.snapshot(1); s.window != 1000 {
		t.Fatalf("catch-up: window = %d, want 1000 (5000 popped - 4000 sent)", s.window)
	}
}

// TestCreditRebindResetsBothSidesToZero (§I Step 2 / §E.4.1): a rebind on a
// NEW generation deterministically re-anchors both counters to 0; a
// stale-generation credit never latches the current generation.
func TestCreditRebindResetsBothSidesToZero(t *testing.T) {
	n := newCreditTestNode(t)
	l := n.creditLedger

	// Generation 5: send a lot, latch with a real window.
	l.addSent(1, 200, 5)
	l.onCredit(1, 300, 5)
	if s := l.snapshot(1); s.window != 100 || s.cumulativeSent != 200 {
		t.Fatalf("gen5: snapshot = %+v, want window 100 sent 200", s)
	}

	// Rebind → new generation 6: BOTH sides anchor to 0. INCREMENT 3: the
	// rebind ANCHOR credit (popped = 0) now LATCHES the stream with the safe
	// initial window (the per-stream mailbox capacity) instead of leaving it
	// un-latched/unlimited — that is exactly the root-cause fix this change
	// makes, so the post-rebind expectation is deliberately reversed.
	l.onCredit(1, 0, 6)
	wantInitial := uint64(mux.DefaultStreamLimits.MaxBytesPerStream)
	if s := l.snapshot(1); !s.latched || s.cumulativeSent != 0 || s.gen != 6 || s.window != wantInitial {
		t.Fatalf("after rebind: snapshot = %+v, want latched gen 6 sent 0 window %d (initial)", s, wantInitial)
	}
	// Latched with a full initial window: the gate is open (not gated, and
	// NOT the "no credit yet" un-latched branch either).
	if gated, _, unlatched := n.creditGate(1, 6); gated || unlatched {
		t.Fatalf("post-rebind latched stream (initial window) must be open: gated=%v unlatched=%v", gated, unlatched)
	}

	// Generation validation: a credit still claiming gen 5 must NOT re-gate
	// the gen-6 stream (it is not the current generation the gate checks).
	l.onCredit(1, 999999, 5)
	if s := l.snapshot(1); s.gen != 5 {
		// it moved the entry to the stale gen; the gate against the REAL
		// current gen (6) must stay open (not gated, stale entry ≠ gen 6).
	}
	if gated, _, _ := n.creditGate(1, 6); gated {
		t.Fatal("stale-generation credit must not gate the current generation")
	}
}

// TestCreditGateUnlatchedIsUnlimited (M4, ledger level): with no credit ever
// received, the gate never parks — the stream runs at today's unlimited
// rate. The mixed-generation §H/§I gate is exactly this: an old peer that
// never emits credit leaves the new sender un-latched.
func TestCreditGateUnlatchedIsUnlimited(t *testing.T) {
	n := newCreditTestNode(t)
	// addSent with no credit: the stream stays un-latched.
	n.creditLedger.addSent(9, 1<<30, 5)
	gated, _, unlatched := n.creditGate(9, 5)
	if gated || !unlatched {
		t.Fatalf("no-credit stream: gated=%v unlatched=%v, want unlimited (unlatched=true)", gated, unlatched)
	}
}

// ---------------------------------------------------------------------------
// INCREMENT 3 — the on-attach anchor credit (popped = 0) LATCHES with a safe
// initial window (the per-stream mailbox capacity, MaxBytesPerStream) so the
// sender is bounded from the very first credit, not unlimited. This is the
// root-cause fix for the data_undeliverable pre-latch truncation.
// ---------------------------------------------------------------------------

// TestAnchorCreditLatchesWithInitialWindow: the on-attach ANCHOR credit
// (popped = 0) now LATCHES the stream with the safe initial window
// (= the per-stream mailbox capacity), NOT "unlatched / unlimited". This is
// the deliberate reversal of A4's old "anchor latches nothing" contract at
// this call site.
func TestAnchorCreditLatchesWithInitialWindow(t *testing.T) {
	n := newCreditTestNode(t)
	wantInitial := uint64(mux.DefaultStreamLimits.MaxBytesPerStream)

	// The on-attach anchor: a fresh down stream, no bytes popped yet.
	n.onCredit(1, mux.CreditFrameInfo{CreditVersion: mux.CreditVersion1, CumulativeBytesPopped: 0}, 5)

	if s := n.creditLedger.snapshot(1); !s.latched || s.gen != 5 || s.window != wantInitial {
		t.Fatalf("anchor: snapshot = %+v, want latched gen 5 window %d (initial = MaxBytesPerStream)", s, wantInitial)
	}
	// Latched (NOT the un-latched/unlimited branch) with a full window: the
	// gate is open through the latched path, not the "no credit yet" one.
	if gated, _, unlatched := n.creditGate(1, 5); gated || unlatched {
		t.Fatalf("anchor latch: gated=%v unlatched=%v, want gated=false unlatched=false (latched, initial window)", gated, unlatched)
	}
}

// TestLatchOnAnchorBoundsSender: after latching on the anchor, the sender is
// BOUNDED from the first credit. Once cumulativeSent advances to the
// initial window, the window is exhausted and creditGate reports gated (not
// unlatched) — the un-limited pre-latch runaway is gone.
func TestLatchOnAnchorBoundsSender(t *testing.T) {
	n := newCreditTestNode(t)
	wantInitial := uint64(mux.DefaultStreamLimits.MaxBytesPerStream)

	// Latch on the on-attach anchor (popped = 0).
	n.onCredit(1, mux.CreditFrameInfo{CreditVersion: mux.CreditVersion1, CumulativeBytesPopped: 0}, 5)
	if s := n.creditLedger.snapshot(1); !s.latched || s.window != wantInitial {
		t.Fatalf("anchor: snapshot = %+v, want latched window %d", s, wantInitial)
	}

	// Advance the sender's cumulativeSent to exactly the initial window:
	// addSent drains the live budget, so the window now sits at 0 (PARK).
	n.creditLedger.addSent(1, wantInitial, 5)
	if s := n.creditLedger.snapshot(1); !s.latched || s.window != 0 || s.cumulativeSent != wantInitial {
		t.Fatalf("after exhausting initial window: snapshot = %+v, want latched window 0 sent %d", s, wantInitial)
	}
	// Gated (window exhausted) and NOT the un-latched/unlimited branch —
	// the sender can no longer run free after the anchor.
	if gated, _, unlatched := n.creditGate(1, 5); !gated || unlatched {
		t.Fatalf("exhausted initial window: gated=%v unlatched=%v, want gated=true unlatched=false (bounded)", gated, unlatched)
	}
}

// TestDrainedCreditStillLatchesAndDerivesWindow: a drained credit
// (popped > 0) still latches and derives the window as
// popped - cumulativeSent, clamped at 0 (A5 / R2-3 behaviour, unchanged —
// only the anchor's fresh-latch path changed under INCREMENT 3).
func TestDrainedCreditStillLatchesAndDerivesWindow(t *testing.T) {
	n := newCreditTestNode(t)
	l := n.creditLedger
	// The sender has flushed 300 bytes before the drained credit arrives.
	l.addSent(1, 300, 5)
	// A drained credit pops 500: window = 500 - 300 = 200, latched.
	l.onCredit(1, 500, 5)
	if s := l.snapshot(1); !s.latched || s.window != 200 {
		t.Fatalf("drained: snapshot = %+v, want latched window 200 (500 popped - 300 sent)", s)
	}
	// Re-derive on a later drained credit after flushing more bytes.
	l.addSent(1, 200, 5)  // 500 sent total
	l.onCredit(1, 700, 5) // pops 700: window = 700 - 500 = 200
	if s := l.snapshot(1); s.window != 200 {
		t.Fatalf("drained re-derive: window = %d, want 200", s.window)
	}
}

// TestCreditNeverExceedsWindowAndClampsAtZero: if the sender has committed
// more than the receiver popped (cumulativeSent > popped), the derived window
// clamps to 0 (PARK), never wrapping to a huge positive (R2-3). An anchor
// whose seed would over-credit (cumSent >= initialWindow) also clamps to 0 —
// it never over-credits or wraps (CRITICAL SAFETY).
func TestCreditNeverExceedsWindowAndClampsAtZero(t *testing.T) {
	n := newCreditTestNode(t)
	l := n.creditLedger

	// Drained credit behind the sender: cumSent(4000) > popped(100) → 0.
	l.addSent(1, 4000, 5)
	l.onCredit(1, 100, 5)
	if s := l.snapshot(1); !s.latched || s.window != 0 {
		t.Fatalf("drained clamp: snapshot = %+v, want latched window 0 (no wrap)", s)
	}

	// Anchor over-credit guard (fresh stream id 2 / gen 6): the sender
	// already flushed more than the mailbox can hold before the anchor
	// arrived → the seed clamps to 0, never an over-credited window.
	initial := uint64(mux.DefaultStreamLimits.MaxBytesPerStream)
	l.addSent(2, initial+1, 6) // cumSent > initialWindow
	l.onCredit(2, 0, 6)        // anchor on a fresh latch
	if s := l.snapshot(2); !s.latched || s.window != 0 {
		t.Fatalf("anchor over-credit: snapshot = %+v, want latched window 0 (clamped, no over-credit)", s)
	}
}

// TestUnlatchedOnlyWhenNoCreditSeen: with NO credit frame at all for a
// generation (the mixed-generation / old-Iran fallback), the stream stays
// un-latched = unlimited. INCREMENT 3 only tightens the ANCHOR path; it
// never gates a stream that genuinely receives no credit frame.
func TestUnlatchedOnlyWhenNoCreditSeen(t *testing.T) {
	n := newCreditTestNode(t)
	// Flush a large amount with no credit frame ever arriving.
	n.creditLedger.addSent(7, 1<<30, 5)
	if s := n.creditLedger.snapshot(7); s.latched {
		t.Fatalf("no-credit stream must stay un-latched, snapshot = %+v", s)
	}
	if gated, _, unlatched := n.creditGate(7, 5); gated || !unlatched {
		t.Fatalf("no-credit stream: gated=%v unlatched=%v, want unlimited (unlatched=true)", gated, unlatched)
	}
}

// ---------------------------------------------------------------------------
// M2 — the credit gate must NEVER block the target-EOF half-close path.
// ---------------------------------------------------------------------------

// TestCreditGateDoesNotBlockTargetEOFHalfClose (M2): a credit-EXHAUSTED
// (window 0) DirDown stream whose target socket EOFs must still reach
// sendCloseFrame and fire MarkDirClosed(DirDown); the relay must not park
// forever on credit. The socketEOF branch of relayShapeA is structurally
// ungated (§E.3 / A1), so this is the load-bearing ordering test.
func TestCreditGateDoesNotBlockTargetEOFHalfClose(t *testing.T) {
	n := newCreditTestNode(t)
	targetApp, targetGe := testutil.NewMemPipe()
	sess, gen, _ := attachDownSession(t, n, 7, targetGe)

	// Credit exhausted (latched, window 0) — the gate WOULD park a live
	// stream; the point is the target EOF must bypass the gate entirely.
	seedExhaustedCredit(t, n, 7, gen)
	if gated, _, unlatched := n.creditGate(7, gen); !gated || unlatched {
		t.Fatalf("creditGate = gated %v unlatched %v, want gated=true (precondition)", gated, unlatched)
	}

	// Target produces a bounded amount, then EOFs (close the app side).
	if _, err := targetApp.Write([]byte("TARGET-DATA-then-EOF")); err != nil {
		t.Fatalf("target write: %v", err)
	}
	targetApp.Close()

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		n.relayShapeA(sess, session.DirDown, targetGe)
	}()

	select {
	case <-done:
		// The relay returned: it did not park forever on credit.
	case <-time.After(5 * time.Second):
		t.Fatal("credit-gated relay parked forever on target EOF (the EOF path is not credit-gated)")
	}

	if !sess.DirClosed(session.DirDown) {
		t.Fatal("target EOF did not half-close DirDown (sendCloseFrame + MarkDirClosed not reached)")
	}
	if sess.Reason() != "target EOF" {
		t.Fatalf("DirDown close reason = %q, want the target-EOF reason", sess.Reason())
	}
	// The integrity invariant: a credit-gated stream that EOFs still
	// half-closes CLEANLY (no corruption, no silent termination).
	if sess.Stats.DataUndeliverable.Load() {
		t.Fatal("target-EOF half-close must not be a data-undeliverable termination")
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// M3 — a lost first credit on rebind falls back to unlimited, bounded.
// ---------------------------------------------------------------------------

// TestRebindCreditLossFallsBackToUnlimited (M3, ledger level): on rebind the
// establishment timer is armed; if NO valid credit frame ever arrives on the
// new generation, the timer fires and the stream reverts to UN-LIMITED
// (un-latched), counting relay_credit_establish_timeout — it does NOT
// terminate, park forever, or corrupt. We assert the counter rather than
// wall-clock where possible.
//
// INCREMENT 3 note: the A4 "anchor latches nothing" contract is reversed at
// this call site (the on-attach anchor now latches with a safe initial
// window), so the "lost first credit" case can no longer be modelled as an
// anchor-then-lost sequence — an anchor is itself a valid credit that
// latches. This test therefore models the GENUINE no-credit case: no
// onCredit on the rebind generation, so the stream stays un-latched and the
// establishment timer's revert-to-unlimited fallback (the mixed-generation /
// old-peer path) is the path under test.
func TestRebindCreditLossFallsBackToUnlimited(t *testing.T) {
	n := newCreditTestNode(t)
	// A tiny establishment window so the timer fires quickly.
	n.cfg.CreditEstablishTimeout = 60 * time.Millisecond

	// Rebind-attach on a fresh generation with NO credit delivered: both
	// sides anchored to 0, the stream stays UN-LATCHED, and the
	// establishment timer is armed for the un-latched stream.
	n.armCreditEstablish(3, 9)

	// No credit frame arrives on this generation at all. The timer must
	// fire and revert to unlimited, counting the fallback.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s := n.creditLedger.snapshot(3)
		if m := n.metrics.Snapshot(); m.RelayCreditEstablishTimeout >= 1 {
			// Reverted: un-latched (unlimited) for this generation.
			if s.latched {
				t.Fatalf("fallback fired but stream is latched (snapshot %+v)", s)
			}
			// And the gate is open (unlimited): no forever-park.
			if gated, _, _ := n.creditGate(3, 9); gated {
				t.Fatal("post-fallback stream must be unlimited, not gated")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("relay_credit_establish_timeout did not fire: the un-latched stream did not revert to unlimited")
}

// ---------------------------------------------------------------------------
// M4 — new Germany / old Iran (no credit) runs unlimited, byte-exact.
// ---------------------------------------------------------------------------

// TestNewGermanyOldIranRunsUnlimited (M4, ledger + gate): the sender (Germany)
// has the full credit plumbing but the peer NEVER emits credit (an old Iran,
// or a suppressed emission). The stream therefore stays un-latched =
// unlimited, exactly today's behaviour: the gate never parks and cumulative
// sent advances without bound. This is the §H/§I mixed-generation gate:
// introduction is monotonic (no AuthVersion bump) and revert-to-unlimited
// ≡ pre-fix behaviour.
func TestNewGermanyOldIranRunsUnlimited(t *testing.T) {
	n := newCreditTestNode(t)
	// The sender flushes a large amount; no credit frame is ever received.
	for i := 0; i < 8; i++ {
		n.creditLedger.addSent(42, 65535, 5)
	}
	s := n.creditLedger.snapshot(42)
	if s.latched {
		t.Fatalf("no-credit peer must leave the stream un-latched, snapshot = %+v", s)
	}
	// Unlimited: the gate is open, so bytes keep flowing at today's rate.
	gated, floor, unlatched := n.creditGate(42, 5)
	if gated || !unlatched {
		t.Fatalf("no-credit stream must run unlimited: gated=%v unlatched=%v floor=%d", gated, unlatched, floor)
	}
	// Byte-exact: cumulative sent is exactly what was flushed (no clamp
	// applied while un-latched, so no spurious PARK).
	if s.cumulativeSent != uint64(8*65535) {
		t.Fatalf("cumulativeSent = %d, want %d (unlimited byte-exact accounting)", s.cumulativeSent, 8*65535)
	}
}

// ---------------------------------------------------------------------------
// M8 — a credit-parked relay holds ≤ CreditFloorDrain, and zero past it.
// ---------------------------------------------------------------------------

// TestCreditParkHoldsZeroAggregateBudget (M8): the credit floor drain is
// enforced against PENDING BYTES. A relay that is parked past the floor has
// already flushed its pending to the carrier (the ungated flush step runs
// before the gate), so it holds ZERO aggregate session-buffer budget. The
// floor bound is "≤ CreditFloorDrain at the floor, 0 past it" (R2-5):
// sampling the aggregate after the flush reports unchanged (zero for this
// relay).
func TestCreditParkHoldsZeroAggregateBudget(t *testing.T) {
	n := newCreditTestNode(t)
	// A target socket for the down session (its app side is unused here —
	// this test isolates the relay's AGGREGATE budget accounting, not the
	// wire).
	_, targetGe := testutil.NewMemPipe()
	sess, gen, _ := attachDownSession(t, n, 8, targetGe)
	seedExhaustedCredit(t, n, 8, gen)

	// Simulate the relay's aggregate accounting exactly as relayShapeA does:
	// charge read bytes to the node budget, then a successful flush refunds
	// them (the floor-drain flush step, §E.3 step 2) — past the floor the
	// relay holds zero.
	bk := bufKey{sess: sess, dir: session.DirDown}
	n.buf.begin(bk)
	defer func() { _ = n.buf.end(bk) }()

	atFloor := int64(n.cfg.CreditFloorDrain) // the parked relay holds at most this
	if !n.buf.chargeWait(bk, int(atFloor), sess.Ctx) {
		t.Fatal("charge at the floor must be admitted (within the node budget)")
	}
	if got := n.buf.AccountedBytes(); got != atFloor {
		t.Fatalf("at the floor: aggregate = %d, want %d (≤ CreditFloorDrain)", got, atFloor)
	}

	// The ungated flush step drains the floor of bytes to the carrier and
	// refunds them: past the floor the parked relay holds zero.
	if r := n.buf.refund(bk, int(atFloor)); r != atFloor {
		t.Fatalf("flush refund = %d, want %d", r, atFloor)
	}
	if got := n.buf.AccountedBytes(); got != 0 {
		t.Fatalf("past the floor: aggregate = %d, want 0 (parked relay holds zero budget)", got)
	}
}

// ---------------------------------------------------------------------------
// Install wiring (A + B): a real FrameCredit reaching a Germany down carrier
// through the installed OnStreamCredit callback latches the ledger on the
// attached generation. This is the end-to-end wiring the ledger-driven tests
// above intentionally leave open: it proves install() installs OnStreamCredit
// on the correct role/direction and pins the callback's generation, and that
// a rebind-attach re-anchors the ledger to the new generation.
// ---------------------------------------------------------------------------

// TestOnStreamCreditInstalledOnGermanyDown (A+B wiring): the install() split
// installs OnStreamCredit only on RoleGermany+DirDown; a drained credit
// (popped>0) reaches the installed callback and latches the ledger on the
// CURRENT down-carrier generation, and a rebind-attach re-anchors it to a
// fresh generation (§I Step 2).
func TestOnStreamCreditInstalledOnGermanyDown(t *testing.T) {
	n := newCreditTestNode(t)

	// Build a full Germany down carrier with a live session (stream 5).
	ir, de := testutil.NewMemPipe()
	n.InstallDown(de, nil)
	h := n.current(session.DirDown)
	if h == nil || h.carrier.OnStreamCredit == nil {
		t.Fatal("install did not wire OnStreamCredit on a Germany down carrier")
	}
	sess := session.NewSession(session.SessionID{}, &session.Destination{}, nil, de, n.ctx)
	sess.StreamIDDown = 5
	sess.DownAtt = session.NewAttachment(n.cfg.Grace, nil)
	sess.Activate()
	if !sess.DownAtt.Attach(h.gen) {
		t.Fatal("down attach failed")
	}
	t.Cleanup(func() { sess.Close("wiring cleanup") })

	// Sender has flushed bytes on this generation (the anchor credit
	// re-anchors both sides to 0 at attach, which is exactly what the
	// production attach path does via creditRebindAttach).
	n.creditRebindAttach(5, h.gen)
	n.addSent(session.DirDown, 5, 300, h.gen)

	// A DRAINED credit frame (popped>0) written from the PEER side
	// (ir.out → de.in → carrier readLoop) reaches the installed
	// OnStreamCredit callback and must latch the stream on the CURRENT
	// generation. FrameCredit is handled directly in the dispatcher's
	// credit arm — no Register required (it is not a data stream).
	if err := mux.WriteCreditFrame(ir, 5, mux.CreditFrameInfo{
		CreditVersion:         mux.CreditVersion1,
		CumulativeBytesPopped: 300,
	}); err != nil {
		t.Fatalf("WriteCreditFrame: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		s := n.creditLedger.snapshot(5)
		if s.latched && s.gen == h.gen && s.cumulativeSent == 300 && s.window == 0 {
			break // latched on the current gen; window clamped to 0 (300-300)
		}
		if time.Now().After(deadline) {
			t.Fatalf("drained credit did not latch on the current gen: snapshot = %+v", s)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Rebind to a NEW down generation: both sides re-anchor to 0 (un-latched).
	// (The old carrier's loss sweep would detach store-tracked sessions, but
	// this manually-created test session is not in the store, so we detach
	// the attachment from the old generation ourselves to model that step.)
	ir2, de2 := testutil.NewMemPipe()
	_ = ir2
	n.InstallDown(de2, nil)
	h2 := n.current(session.DirDown)
	if h2.gen == h.gen {
		t.Fatalf("expected a new generation, got the same %d", h2.gen)
	}
	if !sess.DownAtt.Detach(h.gen) {
		t.Fatal("could not detach the down attachment from the old generation")
	}
	if !sess.DownAtt.Attach(h2.gen) {
		t.Fatal("rebind down attach failed")
	}
	n.creditRebindAttach(5, h2.gen) // §I Step 2: re-anchor + re-arm on the new gen
	if s := n.creditLedger.snapshot(5); s.gen != h2.gen || s.latched || s.cumulativeSent != 0 {
		t.Fatalf("post-rebind snapshot = %+v, want re-anchored un-latched on gen %d", s, h2.gen)
	}
}
