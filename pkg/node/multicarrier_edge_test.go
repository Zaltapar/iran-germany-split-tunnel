// multicarrier_edge_test.go — Section 8: multi-carrier down-plane edge cases
// not covered by multicarrier_test.go (primary-loss scoping, wire version,
// failover). These pin the remaining registry/selection invariants: standby
// loss scoping, all-carriers-down, and new-stream selection falling back to
// the surviving carrier after the primary is lost (design §7.2: pinned
// streams are untouched; only NEW streams follow the selection, which after a
// primary loss names the standby).
package node

import (
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// TestMultiDown_StandbyLossScoping: the mirror of TestMultiDown_LossScoping
// with the roles reversed. Losing the STANDBY down carrier clears the
// standby slot and leaves the primary direction-Ready, so the direction
// stays Ready and only the standby's pinned streams would enter grace.
func TestMultiDown_StandbyLossScoping(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)
	defer n.Close()

	primary, _ := pipePair(t)
	standby, standbyPeer := pipePair(t)
	if _, err := n.InstallDownOn(DefaultDownCarrierID, primary, nil); err != nil {
		t.Fatalf("install primary: %v", err)
	}
	if _, err := n.InstallDownOn(SecondDownCarrierID, standby, nil); err != nil {
		t.Fatalf("install standby: %v", err)
	}

	// Kill the standby; the primary must survive.
	standbyPeer.Close()
	waitUntil(t, 5*time.Second, "standby slot cleared, primary still ready", func() bool {
		return !n.DownCarrierReady(SecondDownCarrierID) && n.DownCarrierReady(DefaultDownCarrierID)
	})
	if n.DownCarrierReady(SecondDownCarrierID) {
		t.Fatal("standby must not be ready after loss")
	}
	if !n.DownCarrierReady(DefaultDownCarrierID) {
		t.Fatal("primary must remain ready after the standby is lost")
	}
	if !n.DownReady() {
		t.Fatal("direction must stay Ready when the primary is still up")
	}
	if h := n.downReg.Handle(SecondDownCarrierID); h != nil {
		t.Fatalf("standby slot must be cleared after loss (got gen %d)", h.gen)
	}
}

// TestMultiDown_AllCarriersDown: when BOTH down carriers are lost, the
// direction is no longer Ready and every slot is cleared. New streams cannot
// be pinned to any surviving carrier, so pickDownForNewStream returns nil
// (the caller then falls back to the bounded waitCarriers wait).
func TestMultiDown_AllCarriersDown(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)
	defer n.Close()

	primary, primaryPeer := pipePair(t)
	standby, standbyPeer := pipePair(t)
	if _, err := n.InstallDownOn(DefaultDownCarrierID, primary, nil); err != nil {
		t.Fatalf("install primary: %v", err)
	}
	if _, err := n.InstallDownOn(SecondDownCarrierID, standby, nil); err != nil {
		t.Fatalf("install standby: %v", err)
	}

	primaryPeer.Close()
	standbyPeer.Close()
	waitUntil(t, 5*time.Second, "both down slots cleared and direction not ready", func() bool {
		return !n.DownCarrierReady(DefaultDownCarrierID) &&
			!n.DownCarrierReady(SecondDownCarrierID) &&
			!n.DownReady()
	})
	if n.DownReady() {
		t.Fatal("direction must NOT be ready when both carriers are down")
	}
	if h := n.downReg.Handle(DefaultDownCarrierID); h != nil {
		t.Fatalf("primary slot must be cleared (got gen %d)", h.gen)
	}
	if h := n.downReg.Handle(SecondDownCarrierID); h != nil {
		t.Fatalf("standby slot must be cleared (got gen %d)", h.gen)
	}
	// No survivor: new-stream selection must yield no handle (nil). The
	// Phase 3 static policy names the first ready carrier; none is ready, so
	// PickForNewStream returns "" and pickDownForNewStream's primary fallback
	// is also not ready → nil.
	if h := n.pickDownForNewStream(time.Now()); h != nil && !h.carrier.Ready() {
		t.Fatalf("pickDownForNewStream returned a not-ready handle %s (must be nil or ready)", h.id)
	}
}

// TestMultiDown_PrimaryLossPinsNewStreamToStandby: with both carriers up, a
// new stream pins to the primary (static priority, index 0). After the
// primary is lost, a NEW stream must pin to the surviving standby — the
// selection never returns an unready/stale primary handle (design §7.2: only
// new streams are affected; already-pinned streams are untouched).
func TestMultiDown_PrimaryLossPinsNewStreamToStandby(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)
	defer n.Close()

	primary, primaryPeer := pipePair(t)
	standby, _ := pipePair(t)
	if _, err := n.InstallDownOn(DefaultDownCarrierID, primary, nil); err != nil {
		t.Fatalf("install primary: %v", err)
	}
	sh, err := n.InstallDownOn(SecondDownCarrierID, standby, nil)
	if err != nil {
		t.Fatalf("install standby: %v", err)
	}

	// While both are up, a new stream pins to the primary (index 0).
	if h := n.pickDownForNewStream(time.Now()); h == nil || h.id != DefaultDownCarrierID {
		t.Fatalf("new stream with both up pinned to %v, want the primary", h)
	}

	// Pin a session to the primary (simulating an existing stream).
	primaryH := n.downReg.Handle(DefaultDownCarrierID)
	var sid session.SessionID
	sid[0] = 9
	sess := session.NewSession(sid, &session.Destination{}, nil, nil, n.ctx)
	sess.StreamIDDown = 9
	sess.DownAtt = session.NewAttachment(n.cfg.Grace, func() { n.onGraceTimeout(sess, session.DirDown) })
	if !sess.Activate() {
		t.Fatal("activation failed")
	}
	if !sess.DownAtt.Attach(primaryH.gen) {
		t.Fatal("attach to primary failed")
	}
	n.store.Add(sid, sess)
	n.store.AddStream(sess)
	defer sess.Close("test cleanup")

	// Kill the primary. The pinned session fails over to the standby; a NEW
	// stream now pins to the standby too.
	primaryPeer.Close()
	waitUntil(t, 5*time.Second, "primary lost, new streams pin to the surviving standby", func() bool {
		if h := n.pickDownForNewStream(time.Now()); h != nil && h.id == SecondDownCarrierID {
			return true
		}
		return false
	})
	if h := n.pickDownForNewStream(time.Now()); h == nil || h.id != SecondDownCarrierID {
		t.Fatalf("after primary loss a new stream pinned to %v, want the standby", h)
	}
	// The surviving standby handle is the one a new stream lands on.
	if h := n.pickDownForNewStream(time.Now()); h != nil && h.id == SecondDownCarrierID && h.carrier != sh.carrier {
		t.Fatalf("new stream pinned to a different standby handle than installed (gen mismatch)")
	}
	// The pinned session must have re-attached to the standby generation.
	if sess.State() != session.StateActive {
		t.Fatalf("pinned session = %s after primary loss, want Active (failed over)", sess.State())
	}
	if st, g := sess.DownAtt.State(); st != session.AttAttached || g != sh.gen {
		t.Fatalf("pinned down attachment = (%s, gen %d), want Attached to standby gen %d", st, g, sh.gen)
	}
}
