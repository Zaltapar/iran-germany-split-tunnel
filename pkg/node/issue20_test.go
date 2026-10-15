// issue20_test.go — Issue #20 (stranded sessions & refused rebinds) node-level
// regression tests, in-package so the tests can drive the real mux dispatcher
// (OnStreamReset -> handleStreamReset) and the multi-down carrier-loss failover
// loop without spinning up a second node.
package node

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// newResetNode builds a bare Iran node (up + down carriers installed raw, no
// auth, hour keepalive so pings never interfere) with ONE live, store-
// registered session on streamID 1. It returns the node, the session, and the
// up-carrier PEER end (the test writes raw control frames here to reach the
// node's dispatcher).
func newResetNode(t *testing.T) (*Node, *session.Session, *testutil.MemConn) {
	t.Helper()
	cfg := Config{
		Role: RoleIran, Grace: 2 * time.Second,
		RelayBufSize: 256, BufferBytes: 4096,
		KeepAliveInterval: time.Hour, SessionBufferTotalBytes: 1 << 20,
	}
	n, err := NewNode(cfg, log.New(io.Discard, "", 0), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })

	upA, upB := testutil.NewMemPipe()
	downA, _ := testutil.NewMemPipe()
	upH := n.InstallUp(upA, nil)
	downH := n.InstallDown(downA, nil)
	if upH == nil || downH == nil {
		t.Fatal("carrier install returned nil handle")
	}

	var sid session.SessionID
	sid[0] = 1
	sess := session.NewSession(sid, &session.Destination{}, nil, nil, n.ctx)
	sess.StreamIDUp = 1
	sess.StreamIDDown = 1
	sess.UpAtt = session.NewAttachment(n.cfg.Grace, nil)
	sess.DownAtt = session.NewAttachment(n.cfg.Grace, nil)
	if !sess.Activate() {
		t.Fatal("activation failed")
	}
	if !sess.UpAtt.Attach(upH.gen) || !sess.DownAtt.Attach(downH.gen) {
		t.Fatal("attach failed")
	}
	// Register the same close hook the real StartSession path wires so the
	// authoritative Close unindexes the stream from the store (cleanup runs
	// exactly once) — the property under test.
	sess.OnClose(func() { n.onSessionClosed(sess) })
	n.store.Add(sid, sess)
	n.store.AddStream(sess)
	t.Cleanup(func() { sess.Close("test cleanup") })
	return n, sess, upB
}

// TestFrameResetTerminatesStrandedSession pins the Issue #20 receiver path:
// a peer FrameReset for a live stream terminates the local session through the
// authoritative Close path (the stranded-session fix), and the close is
// exact-once (the store unindexes the stream so a repeat/stale reset is a no-
// op and cannot kill an unrelated or newer session that owns a different
// stream ID).
func TestFrameResetTerminatesStrandedSession(t *testing.T) {
	n, sess, upB := newResetNode(t)

	// The peer (Germany) refuses the rebind and sends the terminal negative
	// ack on the same up carrier that delivered the rebind.
	if err := mux.WriteFrame(upB, 1, mux.FrameReset, mux.EncodeResetPayload(mux.ResetReasonRebindRefused, 42)); err != nil {
		t.Fatalf("write FrameReset: %v", err)
	}
	waitUntil(t, 3*time.Second, "stranded session terminated by FrameReset", func() bool {
		return sess.State() == session.StateClosed
	})
	if got := sess.Reason(); got != "peer reset (rebind_refused)" {
		t.Fatalf("close reason = %q, want the peer-reset reason", got)
	}
	if got := n.Metrics().Snapshot().StreamResetsReceived; got < 1 {
		t.Fatalf("StreamResetsReceived = %d, want >= 1", got)
	}
	// Exact-once: the stream is unindexed on close.
	if _, ok := n.store.ByStream(1); ok {
		t.Fatal("stream 1 still indexed after the reset close (cleanup must run exactly once)")
	}

	// A duplicate reset for the now-gone stream is a silent no-op (no panic,
	// no state change) — repeated/reordered frames are idempotent.
	if err := mux.WriteFrame(upB, 1, mux.FrameReset, mux.EncodeResetPayload(mux.ResetReasonRebindRefused, 42)); err != nil {
		t.Fatalf("write duplicate FrameReset: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	// Stale-frame safety: a NEW session on a DIFFERENT stream must NOT be
	// killed by a reset that names the OLD (already-closed) stream.
	var sid2 session.SessionID
	sid2[0] = 2
	sess2 := session.NewSession(sid2, &session.Destination{}, nil, nil, n.ctx)
	sess2.StreamIDUp = 2
	sess2.StreamIDDown = 2
	sess2.UpAtt = session.NewAttachment(n.cfg.Grace, nil)
	sess2.DownAtt = session.NewAttachment(n.cfg.Grace, nil)
	if !sess2.Activate() {
		t.Fatal("activation failed (sess2)")
	}
	ph := n.upReg.Primary()
	pd := n.downReg.Primary()
	if ph == nil || pd == nil {
		t.Fatal("primary up/down handles missing")
	}
	if !sess2.UpAtt.Attach(ph.gen) || !sess2.DownAtt.Attach(pd.gen) {
		t.Fatal("attach sess2 failed")
	}
	n.store.Add(sid2, sess2)
	n.store.AddStream(sess2)
	t.Cleanup(func() { sess2.Close("test cleanup") })

	// A reset for the OLD stream (1) must not touch sess2 (stream 2).
	if err := mux.WriteFrame(upB, 1, mux.FrameReset, mux.EncodeResetPayload(mux.ResetReasonUnknownStream, 99)); err != nil {
		t.Fatalf("write stale FrameReset: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if sess2.State() != session.StateActive {
		t.Fatalf("stale reset for stream 1 killed the newer stream-2 session (state %s)", sess2.State())
	}
}

// TestCarrierLossFailoverToSurvivorDown pins the Issue #20 onCarrierLost fix:
// when the HIGHEST-priority (primary) down carrier is lost, the loss sweep's
// survivor loop re-attaches the pinned session onto the surviving standby down
// carrier instead of leaving it stranded. The observable: the session stays
// Active and its down attachment moves to the standby's generation.
func TestCarrierLossFailoverToSurvivorDown(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)
	t.Cleanup(func() { n.Close() })

	primary, primaryPeer := pipePair(t)
	standby, _ := pipePair(t)
	if _, err := n.InstallDownOn(DefaultDownCarrierID, primary, nil); err != nil {
		t.Fatalf("install primary: %v", err)
	}
	standbyH, err := n.InstallDownOn(SecondDownCarrierID, standby, nil)
	if err != nil {
		t.Fatalf("install standby: %v", err)
	}

	// A live, store-registered session pinned to the PRIMARY down carrier.
	primaryH := n.downReg.Handle(DefaultDownCarrierID)
	if primaryH == nil {
		t.Fatal("primary down handle missing")
	}
	var sid session.SessionID
	sid[0] = 7
	sess := session.NewSession(sid, &session.Destination{}, nil, nil, n.ctx)
	sess.StreamIDDown = 7
	sess.DownAtt = session.NewAttachment(n.cfg.Grace, func() { n.onGraceTimeout(sess, session.DirDown) })
	if !sess.Activate() {
		t.Fatal("activation failed")
	}
	if !sess.DownAtt.Attach(primaryH.gen) {
		t.Fatal("attach to primary failed")
	}
	n.store.Add(sid, sess)
	n.store.AddStream(sess)
	t.Cleanup(func() { sess.Close("test cleanup") })

	// Kill the PRIMARY down carrier: the loss sweep must fail the pinned
	// session over to the surviving standby.
	primaryPeer.Close()
	waitUntil(t, 5*time.Second, "down session fails over to the surviving standby carrier", func() bool {
		if sess.State() != session.StateActive {
			return true // closed — treat as a failure below
		}
		if st, g := sess.DownAtt.State(); st == session.AttAttached && g == standbyH.gen {
			return true
		}
		return false
	})
	if sess.State() != session.StateActive {
		t.Fatalf("pinned session = %s after losing the primary down carrier, want Active (failed over)", sess.State())
	}
	if st, g := sess.DownAtt.State(); st != session.AttAttached || g != standbyH.gen {
		t.Fatalf("down attachment = (%s, gen %d), want Attached to standby gen %d", st, g, standbyH.gen)
	}
	// The recovery was counted (the pinned stream failed over and re-attached).
	if m := n.Metrics().Snapshot(); m.SessionsRecovered < 1 {
		t.Fatalf("SessionsRecovered = %d, want >= 1 (the pinned stream failed over)", m.SessionsRecovered)
	}
}

// TestFrameResetGenerationGuard locks the stale-reset guard in
// handleStreamReset (Issue #20, subtask 2): when a peer FrameReset carries a
// sender generation STRICTLY OLDER than the attachment's lastRebindGen (a
// reset replayed/reordered across a carrier rebind), the node must IGNORE it —
// the session survives and the stream stays registered. A reset at or above
// lastRebindGen remains authoritative and still terminates the session.
//
// newResetNode's session has LastRebindGen()==0, so this test first advances
// the attachment's accepted rebind generation (as a real rebind would via
// handleRebind/SetLastRebindGen) and then exercises both sides of the guard.
func TestFrameResetGenerationGuard(t *testing.T) {
	n, sess, upB := newResetNode(t)
	base := n.Metrics().Snapshot()

	// A real rebind on this direction would have recorded the sender's
	// generation; simulate the accepted higher generation.
	sess.UpAtt.SetLastRebindGen(50)

	// (a) STALE reset (gen 42 < 50): must be ignored — no close, no
	// unindexing, and the dedicated stale-generation refusal is counted.
	if err := mux.WriteFrame(upB, 1, mux.FrameReset, mux.EncodeResetPayload(mux.ResetReasonRebindRefused, 42)); err != nil {
		t.Fatalf("write stale FrameReset: %v", err)
	}
	waitUntil(t, 2*time.Second, "stale FrameReset accounted as a refusal", func() bool {
		return n.Metrics().Snapshot().RebindStaleGeneration > base.RebindStaleGeneration
	})
	if st := sess.State(); st != session.StateActive {
		t.Fatalf("stale FrameReset (gen 42 < lastRebindGen 50) closed the session (state %s); it must be ignored", st)
	}
	if _, ok := n.store.ByStream(1); !ok {
		t.Fatal("stale FrameReset unindexed the live stream 1")
	}

	// (b) NON-STALE reset (gen 50 == lastRebindGen): authoritative — the
	// stranded session is terminated through the exact-once close path.
	if err := mux.WriteFrame(upB, 1, mux.FrameReset, mux.EncodeResetPayload(mux.ResetReasonRebindRefused, 50)); err != nil {
		t.Fatalf("write FrameReset: %v", err)
	}
	waitUntil(t, 2*time.Second, "FrameReset terminates the stranded session", func() bool {
		return sess.State() == session.StateClosed
	})
	if got := sess.Reason(); got != "peer reset (rebind_refused)" {
		t.Fatalf("close reason = %q, want the peer-reset reason", got)
	}
	if _, ok := n.store.ByStream(1); ok {
		t.Fatal("stream 1 still indexed after the authoritative reset close (cleanup must run exactly once)")
	}
}
