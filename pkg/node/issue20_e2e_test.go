// issue20_e2e_test.go — Issue #20 full two-node regression (package node_test).
//
// Covers the stranded-session loop end to end over the REAL two-node paths:
// lost FrameHeader outcome (Germany has no active session for the stream) →
// up-carrier drop → reconnect → Iran rebindDirection emits FrameRebind →
// Germany handleRebind refuses (unknown peer) with a FrameReset negative ack →
// Iran handleStreamReset terminates the stranded session.
//
// Asserts: bounded termination with the peer-reset reason, no rebind storm
// (exactly one rebind attempt, stable across a settle window and a second
// reconnect), zero leaked registrations (both stores empty, stream unindexed),
// exact-once cleanup, and client socket closed.
package node_test

import (
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

func TestIssue20_StrandedSessionTwoNodeReset(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)
	streamID := sc.sc.StreamIDUp

	// Both sides bootstrapped exactly one session.
	eventually(t, 3*time.Second, "both nodes bootstrapped", func() bool {
		return tp.iran.Store().Count() == 1 && tp.de.Store().Count() == 1
	})

	// Simulate the lost-FrameHeader outcome: Germany never bootstrapped this
	// stream, so its copy is gone while Iran's copy stays stranded Active.
	// (Closing the Germany-side session unindexes the stream there, exactly
	// as if bootstrapUpStream had dropped before creating it.)
	deSess := tp.de.Store().Snapshot()[0]
	deSess.Close("simulate lost header: germany never bootstrapped")
	eventually(t, 3*time.Second, "germany store drained", func() bool {
		return tp.de.Store().Count() == 0
	})
	if _, ok := tp.de.Store().GetByStream(streamID); ok {
		t.Fatal("germany still indexes the stream after the simulated header loss")
	}
	if sc.sc.State() != session.StateActive {
		t.Fatalf("iran session = %s, want Active (stranded) before the carrier drop", sc.sc.State())
	}

	iranRebindsBefore := tp.iran.Metrics().Snapshot().CarrierRebinds
	deUnknownBefore := tp.de.Metrics().Snapshot().RebindUnknownPeer
	iranResetsBefore := tp.iran.Metrics().Snapshot().StreamResetsReceived

	// Carrier drop + reconnect. Iran's loss sweep detaches; the fresh install
	// runs the rebind sweep which emits the FrameRebind for the stranded
	// stream on the new carrier.
	tp.killUp()
	tp.installUp()

	// Germany must refuse the unknown peer (exactly once) and Iran must
	// terminate the stranded session within a bounded time (grace 2s, not
	// hanging on a retry loop).
	eventually(t, 5*time.Second, "germany refuses the unknown-peer rebind", func() bool {
		return tp.de.Metrics().Snapshot().RebindUnknownPeer > deUnknownBefore
	})
	eventually(t, 5*time.Second, "iran stranded session terminated by the peer reset", func() bool {
		return sc.sc.State() == session.StateClosed
	})
	if got := sc.sc.Reason(); got != "peer reset (unknown_stream)" {
		t.Fatalf("iran close reason = %q, want %q", got, "peer reset (unknown_stream)")
	}
	if got := tp.iran.Metrics().Snapshot().StreamResetsReceived; got <= iranResetsBefore {
		t.Fatalf("iran StreamResetsReceived did not move (was %d)", iranResetsBefore)
	}

	// Exact-once cleanup: the stream is unindexed on Iran, both stores empty.
	if _, ok := tp.iran.Store().GetByStream(streamID); ok {
		t.Fatal("iran still indexes the stream after the reset close (cleanup must run exactly once)")
	}
	if c := tp.iran.Store().Count(); c != 0 {
		t.Fatalf("iran store count = %d, want 0 (no leaked registration)", c)
	}
	if c := tp.de.Store().Count(); c != 0 {
		t.Fatalf("germany store count = %d, want 0 (no leaked registration)", c)
	}

	// No rebind storm: exactly one rebind attempt for the stranded stream,
	// stable across a settle window.
	if got := tp.iran.Metrics().Snapshot().CarrierRebinds; got != iranRebindsBefore+1 {
		t.Fatalf("iran CarrierRebinds = %d, want exactly %d (one attempt, no storm)", got, iranRebindsBefore+1)
	}
	rebindsSettled := tp.iran.Metrics().Snapshot().CarrierRebinds
	time.Sleep(200 * time.Millisecond)
	if got := tp.iran.Metrics().Snapshot().CarrierRebinds; got != rebindsSettled {
		t.Fatalf("iran CarrierRebinds flapped %d -> %d after convergence (rebind storm)", rebindsSettled, got)
	}

	// A second drop/reconnect must not revive or rebind the closed session.
	tp.killUp()
	tp.installUp()
	time.Sleep(200 * time.Millisecond)
	if got := tp.iran.Metrics().Snapshot().CarrierRebinds; got != rebindsSettled {
		t.Fatalf("closed session rebound after a second reconnect (%d -> %d)", rebindsSettled, got)
	}
	if c := tp.iran.Store().Count(); c != 0 {
		t.Fatalf("iran store count after second reconnect = %d, want 0", c)
	}

	// Client socket closed by the authoritative teardown.
	sc.client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	n, err := sc.client.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("client read after reset close = (%d, %v), want (0, EOF/closed)", n, err)
	}
}
