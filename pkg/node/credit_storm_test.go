package node

// SUBTASK 25 — reproduces the down-carrier reconnect STORM that the f5bcaac
// credit-plane deploy exposed in production.
//
// Root cause (ranked #1, code-proven): the rebind-attach path emits an
// attach-time ANCHOR credit (go n.creditEmitter.emitAnchor) on the NEW
// down-carrier generation, from TWO sites:
//
//   - Node.rebindDirection (Iran, the down-receiver rebind sweep)
//   - Node.handleRebind    (Germany, the down rebind responder)
//
// The anchor is a FrameCredit written go-spawned the instant the carrier
// attaches. It races ahead of the PEER re-registering that stream on the new
// generation. The mux read loop enforces a hard rule (carrier.go:300-314): a
// FrameCredit that references a stream the receiving carrier has NOT yet
// created in c.streams is a CONNECTION-level FATAL — ErrCreditUnknownStream —
// which tears the peer's down carrier down. A stream is only created in
// c.streams by Dispatch's OnNewStream (carrier.go:958-959), which lags the
// faster read loop. So a credit that arrives before (or concurrently with)
// the rebind that would register the stream kills the carrier:
//
//   loss -> Iran reconnects (gen++) -> rebindDirection emits another anchor ->
//   another ErrCreditUnknownStream -> ...  == the 36->130 gen climb /
//   115 reconnects observed in production.
//
// Test 1 (TestCreditOnUnregisteredStreamTearsDownCarrier) is a DETERMINISTIC
// mux-level reproduction of the fatal rule itself: a credit for a stream the
// receiver never registered kills the carrier, exactly as the storm's anchor
// does.
//
// Test 2 (TestDownRebindSurvivesNoCarrierStorm) drives a real two-node down
// rebind with the credit plane enabled and asserts NO storm: a single
// rebind must not multiply the down-carrier loss/reconnect cycles, must not
// die Germany's down carrier from ErrCreditUnknownStream, and must still
// reattach + deliver data. It PASSES with the fix (no rebind-path anchor) and
// exercises the exact rebind-attach code the storm ran through. Because the
// wire race is scheduling-dependent, Test 2 can only catch the broken build
// when the anchor overtakes the rebind on the receiving carrier; Test 1 is
// the deterministic anchor of the proof.
import (
	"errors"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// TestCreditOnUnregisteredStreamTearsDownCarrier is the deterministic
// reproduction of the exact fatal rule the storm exploits: a FrameCredit that
// arrives BEFORE the peer has created the stream in c.streams is a
// connection-level failure (ErrCreditUnknownStream). This is precisely the
// ordering a rebind-path anchor produces (anchor go-spawned ahead of the
// peer's rebind/registration on the new generation).
func TestCreditOnUnregisteredStreamTearsDownCarrier(t *testing.T) {
	a, b := testutil.NewMemPipe()
	// c is the peer's down carrier (the receiving side of the storm). No
	// Dispatch, no Register: stream 42 is NOT in c.streams — the exact
	// "anchor arrived before the peer re-registered the stream" state.
	c := mux.NewCarrierConn(a, 0) // no liveness loop
	defer c.Close()

	p := mux.CreditPayload{
		Version:       mux.CreditVersion,
		Gen:           3,
		BytesConsumed: 0, // an attach-time anchor (zero consumption)
		WindowGranted: creditWindowMax,
	}
	if err := mux.WriteFrame(b, 42, mux.FrameCredit, mux.EncodeCreditPayload(&p)); err != nil {
		t.Fatalf("write anchor credit: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(c.ReadErr(), mux.ErrCreditUnknownStream) {
			return // the carrier was torn down by the credit — the rule fired
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("carrier survived a credit on an unregistered stream (ReadErr=%v); the fatal rule did not fire", c.ReadErr())
}

// TestCreditAfterRegistrationIsAccepted is the CONTROL that proves the storm
// is an ORDERING defect, not a credit defect: the same credit, once the peer
// has registered the stream (as happens after its rebind is processed), is
// accepted and the carrier stays alive. This is why dropping the rebind-path
// anchor (and relying on the 640 KiB pre-latch bound) is safe: no credit is
// ever sent for a stream the peer has not yet registered.
func TestCreditAfterRegistrationIsAccepted(t *testing.T) {
	a, b := testutil.NewMemPipe()
	c := mux.NewCarrierConn(a, 0)
	defer c.Close()
	// Register the stream FIRST (the rebind would have done this), so the
	// credit is no longer "unknown".
	if ch := c.Register(42); ch == nil {
		t.Fatal("Register returned nil on a live carrier")
	}

	p := mux.CreditPayload{
		Version:       mux.CreditVersion,
		Gen:           3,
		BytesConsumed: 0,
		WindowGranted: creditWindowMax,
	}
	if err := mux.WriteFrame(b, 42, mux.FrameCredit, mux.EncodeCreditPayload(&p)); err != nil {
		t.Fatalf("write credit: %v", err)
	}

	// The carrier must NOT die from this credit; give it a beat.
	time.Sleep(100 * time.Millisecond)
	if c.ReadErr() != nil {
		t.Fatalf("carrier died after a credit on a REGISTERED stream: %v", c.ReadErr())
	}
	if !c.Ready() {
		t.Fatalf("carrier not Ready after a credit on a registered stream")
	}
}

// TestDownRebindSurvivesNoCarrierStorm drives a real two-node down-carrier
// replacement with the credit plane ENABLED on both sides and asserts the
// down rebind does NOT enter a reconnect storm:
//
//   - a single rebind produces AT MOST ONE down-carrier reconnect on Germany
//     (a broken build multiplies it via ErrCreditUnknownStream);
//   - Germany's down carrier is NOT dead from ErrCreditUnknownStream;
//   - the session's down attachment reattaches;
//   - data still flows across the rebind.
//
// This is the production "no storm" acceptance. With the fix (no rebind-path
// anchor) it is deterministic; before the fix it exercises the exact
// rebind-attach path and catches the storm when the anchor overtakes the
// rebind on the receiving carrier.
func TestDownRebindSurvivesNoCarrierStorm(t *testing.T) {
	tp := newCreditTopo(t, true, 5*time.Second, 256<<10)
	tp.setup()
	clientApp, targetApp := tp.startSession(1)

	// Prime the session so a down attachment exists and is Active.
	if _, err := targetApp.Write([]byte("PRIME")); err != nil {
		t.Fatalf("prime write: %v", err)
	}
	if got := tp.readFull(clientApp, 5, 3*time.Second); string(got) != "PRIME" {
		t.Fatalf("prime read = %q, want PRIME", got)
	}

	base := tp.de.Metrics().Snapshot()

	// Drive a single down-carrier replacement (the rebind path): close both
	// down ends and reinstall, which runs Iran's rebindDirection (FrameRebind
	// + the credit-plane rebind-attach) on the NEW down-carrier generation.
	killDown(tp)
	tp.installDown()

	// Allow a would-be storm a bounded window to manifest. A broken build
	// loses/reconnects the DE down carrier repeatedly (each generation lives
	// <2s, as in production); a fixed one settles to exactly one replacement.
	time.Sleep(1500 * time.Millisecond)

	after := tp.de.Metrics().Snapshot()
	if reconns := after.CarrierReconnects - base.CarrierReconnects; reconns > 1 {
		dumpCreditState(t, tp, "down-rebind-storm")
		t.Fatalf("DE down-carrier reconnect storm after ONE rebind: reconnects=%d (want <=1); this is the production f5bcaac storm", reconns)
	}
	// The root symptom directly: Germany's down carrier must not be dead from
	// a credit-on-unregistered-stream.
	if h := tp.de.downReg.h; h != nil {
		if err := h.carrier.ReadErr(); errors.Is(err, mux.ErrCreditUnknownStream) {
			dumpCreditState(t, tp, "down-rebind-fatal")
			t.Fatalf("DE down carrier died from ErrCreditUnknownStream after a single rebind — the rebind-path anchor race")
		}
	}
	// The session's down attachment reattached (rebind accepted, not refused).
	eventuallyNode(t, 3*time.Second, "session down reattached after rebind", func() bool {
		for _, s := range tp.de.Store().Snapshot() {
			if att := s.Att(session.DirDown); att != nil {
				if st, _ := att.State(); st == session.AttAttached {
					return true
				}
			}
		}
		return false
	})
	// And data still flows across the rebind (the rebind actually worked).
	if _, err := targetApp.Write([]byte("POST")); err != nil {
		t.Fatalf("post-rebind write: %v", err)
	}
	if got := tp.readFull(clientApp, 4, 3*time.Second); string(got) != "POST" {
		t.Fatalf("post-rebind read = %q, want POST (down relay must survive the rebind)", got)
	}
	t.Logf("down rebind survived: reconns=%d, no ErrCreditUnknownStream, reattached, data flowed",
		after.CarrierReconnects-base.CarrierReconnects)
}

// killDown closes both ends of the current down carrier, driving the
// per-direction loss sweep on both nodes (mirrors node_test.killDown).
func killDown(tp *creditTopo) {
	tp.t.Helper()
	tp.downIr.Close()
	tp.downDe.Close()
}
