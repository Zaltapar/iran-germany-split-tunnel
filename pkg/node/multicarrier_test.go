package node

// multicarrier_test.go — Phase 2 (D1/D3/D5) unit tests for the multi-carrier
// down registry: per-CarrierID slots, per-carrier readiness, loss scoping
// (losing one down carrier leaves the other ready), the rebind wire version
// choice, and fail-closed unknown IDs.

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// newMultiTestNode builds a Node whose down registry holds two carriers
// (primary + standby) and whose up registry is the single up carrier.
func newMultiTestNode(t *testing.T, role Role) *Node {
	t.Helper()
	cfg := Config{
		Role:           role,
		Grace:          2 * time.Second,
		DownCarrierIDs: []CarrierID{DefaultDownCarrierID, SecondDownCarrierID},
	}
	if err := cfg.Sanitize(); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	n, err := NewNode(cfg, log.New(io.Discard, "", 0), secret)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	return n
}

// TestMultiDown_RegistryShape: two down slots, static priority, single up.
func TestMultiDown_RegistryShape(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)
	defer n.Close()

	if !n.multiDown() {
		t.Fatal("node must report multi-down when two DownCarrierIDs are set")
	}
	if got := len(n.DownCarrierIDs()); got != 2 {
		t.Fatalf("DownCarrierIDs() = %d, want 2", got)
	}
	// index 0 = primary, index 1 = standby (static priority, D1).
	if n.DownCarrierIDs()[0] != DefaultDownCarrierID || n.DownCarrierIDs()[1] != SecondDownCarrierID {
		t.Fatalf("down priority order = %v", n.DownCarrierIDs())
	}
	// Up is always single-carrier (D5).
	if !n.upReg.SingleEntry() {
		t.Fatal("up registry must remain single-carrier")
	}
	// Down is NOT a single entry.
	if n.downReg.SingleEntry() {
		t.Fatal("down registry must be multi-entry when two ids are configured")
	}
}

// TestMultiDown_InstallOnNamedID: installing each down carrier under its own
// id yields two simultaneously-ready down carriers; the direction stays Ready.
func TestMultiDown_InstallOnNamedID(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)
	defer n.Close()

	primary, _ := pipePair(t)
	standby, _ := pipePair(t)
	ph, err := n.InstallDownOn(DefaultDownCarrierID, primary, nil)
	if err != nil {
		t.Fatalf("install primary: %v", err)
	}
	sh, err := n.InstallDownOn(SecondDownCarrierID, standby, nil)
	if err != nil {
		t.Fatalf("install standby: %v", err)
	}
	if ph.id != DefaultDownCarrierID || sh.id != SecondDownCarrierID {
		t.Fatalf("handle ids = %q/%q, want primary/standby", ph.id, sh.id)
	}
	if !n.DownCarrierReady(DefaultDownCarrierID) || !n.DownCarrierReady(SecondDownCarrierID) {
		t.Fatal("both down carriers must report ready after install")
	}
	if !n.DownReady() {
		t.Fatal("direction-level DownReady must be true")
	}
	// Both instances are distinct generations (node-global lockstep).
	if ph.gen == sh.gen {
		t.Fatalf("primary and standby must have distinct generations (got %d)", ph.gen)
	}
}

// TestMultiDown_LossScoping: losing the primary down carrier leaves the
// standby direction-Ready (the lost carrier's slot clears, the other stays),
// so only the lost carrier's pinned streams enter grace.
func TestMultiDown_LossScoping(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)
	defer n.Close()

	primary, primaryPeer := pipePair(t)
	standby, _ := pipePair(t)
	if _, err := n.InstallDownOn(DefaultDownCarrierID, primary, nil); err != nil {
		t.Fatalf("install primary: %v", err)
	}
	if _, err := n.InstallDownOn(SecondDownCarrierID, standby, nil); err != nil {
		t.Fatalf("install standby: %v", err)
	}

	// Kill the primary carrier (closing the peer end tears down the pipe).
	primaryPeer.Close()
	// Wait for the loss sweep to clear the primary slot (bounded).
	waitUntil(t, 5*time.Second, "primary down slot cleared, standby still ready", func() bool {
		return !n.DownCarrierReady(DefaultDownCarrierID) && n.DownCarrierReady(SecondDownCarrierID)
	})
	if n.DownCarrierReady(DefaultDownCarrierID) {
		t.Fatal("primary must not be ready after loss")
	}
	if !n.DownCarrierReady(SecondDownCarrierID) {
		t.Fatal("standby must remain ready after the primary is lost")
	}
	// The direction stays Ready because the surviving carrier holds it.
	if !n.DownReady() {
		t.Fatal("direction must stay Ready when a standby is still up")
	}
	if h := n.downReg.Handle(DefaultDownCarrierID); h != nil {
		t.Fatalf("primary slot must be cleared after loss (got gen %d)", h.gen)
	}
}

// TestMultiDown_UnknownIDFailClosed: installing a down carrier under an id
// not in the registry's known set is rejected (fail-closed).
func TestMultiDown_UnknownIDFailClosed(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)
	defer n.Close()

	a, b := pipePair(t)
	_ = b
	_, err := n.InstallDownOn("down-reality-zz", a, nil)
	if err == nil {
		t.Fatal("install under an unknown carrier id must fail closed")
	}
}

// TestMultiDown_RebindWireVersion: when multi-down the node emits the v2
// rebind payload (with the carrier id); when single-down it emits v1.
func TestMultiDown_RebindWireVersion(t *testing.T) {
	// Multi-down node.
	n := newMultiTestNode(t, RoleIran)
	defer n.Close()
	a, b := pipePair(t)
	_ = b
	ph, err := n.InstallDownOn(DefaultDownCarrierID, a, nil)
	if err != nil {
		t.Fatalf("install primary: %v", err)
	}
	payload := n.encodeRebind(session.SessionID{}, ph)
	if len(payload) == 0 || payload[0] != session.RebindVersionV2 {
		t.Fatalf("multi-down rebind wire must be v2, got version byte %v", payload)
	}

	// Single-carrier node (default, no DownCarrierIDs).
	cfg := Config{Role: RoleIran, Grace: 2 * time.Second}
	if err := cfg.Sanitize(); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	single, err := NewNode(cfg, log.New(io.Discard, "", 0), make([]byte, 32))
	if err != nil {
		t.Fatalf("NewNode single: %v", err)
	}
	defer single.Close()
	sa, sb := pipePair(t)
	_ = sb
	sh, err := single.InstallDownOn(single.downReg.ID(), sa, nil)
	if err != nil {
		t.Fatalf("install single down: %v", err)
	}
	spayload := single.encodeRebind(session.SessionID{}, sh)
	if len(spayload) == 0 || spayload[0] != session.RebindVersion {
		t.Fatalf("single-down rebind wire must be v1 (byte-identical), got version byte %v", spayload)
	}
}

// TestMultiDown_NoCreditBeforeRegistration is exercised by the credit-storm
// and relay suites (F3); it is covered here only structurally: a stream's
// rebind anchor is omitted on the down path so no credit precedes the peer's
// registration of the stream on the new carrier. The invariant is asserted
// in the credit tests; this guard keeps the wire-version helper honest.
func TestMultiDown_EncodeRebindIncludesCarrierID(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)
	defer n.Close()
	a, b := pipePair(t)
	_ = b
	ph, _ := n.InstallDownOn(DefaultDownCarrierID, a, nil)
	p := n.encodeRebind(session.SessionID{}, ph)
	// v2 carries the carrier id: decode and confirm it names the primary.
	rb, ok := session.ParseRebindAny(p)
	if !ok {
		t.Fatal("rebind payload must parse")
	}
	if rb.CarrierID != string(DefaultDownCarrierID) {
		t.Fatalf("v2 rebind names carrier %q, want %q", rb.CarrierID, DefaultDownCarrierID)
	}
}
