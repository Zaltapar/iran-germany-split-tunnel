package node

import (
	"errors"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// makeTestHandle creates a minimal carrier handle with a ready mux carrier
// backed by an in-memory pipe. The caller must Close the returned carrier
// when done.
func makeTestHandle(t *testing.T, gen uint64) *carrierHandle {
	t.Helper()
	a, b := net.Pipe()
	_ = b // not used in these tests; just need a valid RWC
	c := mux.NewCarrierConn(a, 0)
	return &carrierHandle{
		carrier: c,
		gen:     gen,
		done:    make(chan struct{}),
		lost:    make(chan struct{}),
	}
}

// TestRegistry_AddRegistersCarrier verifies that Add stores the handle in
// the registry and that the sole entry is retrievable via Handle/Generation.
func TestRegistry_AddRegistersCarrier(t *testing.T) {
	reg := newCarrierRegistry(CarrierDescriptor{
		ID:     DefaultUpCarrierID,
		Dir:    session.DirUp,
		Family: FamilyCDNWS,
	})

	h1 := makeTestHandle(t, 1)
	t.Cleanup(func() { h1.carrier.Close() })

	_, err := reg.Add(DefaultUpCarrierID, h1)
	if err != nil {
		t.Fatalf("Add: unexpected error: %v", err)
	}
	if reg.Handle(DefaultUpCarrierID) != h1 {
		t.Fatal("Handle: expected the installed handle")
	}
	if reg.Generation(DefaultUpCarrierID) != 1 {
		t.Fatalf("Generation: got %d want 1", reg.Generation(DefaultUpCarrierID))
	}
	if !reg.Ready() {
		t.Fatal("Ready: expected true after install")
	}
	if reg.Count() != 1 {
		t.Fatalf("Count: got %d want 1", reg.Count())
	}
}

// TestRegistry_AddReplacesSameID verifies that installing the same
// CarrierID replaces the previous entry and the generation is visible
// through the new handle.
func TestRegistry_AddReplacesSameID(t *testing.T) {
	reg := newCarrierRegistry(CarrierDescriptor{
		ID:     DefaultDownCarrierID,
		Dir:    session.DirDown,
		Family: FamilyReality,
	})

	h1 := makeTestHandle(t, 1)
	t.Cleanup(func() { h1.carrier.Close() })
	_, err := reg.Add(DefaultDownCarrierID, h1)
	if err != nil {
		t.Fatalf("first Add: %v", err)
	}

	h2 := makeTestHandle(t, 2)
	t.Cleanup(func() { h2.carrier.Close() })
	old, err := reg.Add(DefaultDownCarrierID, h2)
	if err != nil {
		t.Fatalf("second Add: %v", err)
	}
	if old != h1 {
		t.Fatal("Add should return the previous handle")
	}
	if reg.Generation(DefaultDownCarrierID) != 2 {
		t.Fatalf("Generation: got %d want 2", reg.Generation(DefaultDownCarrierID))
	}
}

// TestRegistry_AddRejectsDifferentID verifies that a carrier with a
// DIFFERENT CarrierID is rejected (ErrUnknownCarrierID) and the current
// entry is untouched.
func TestRegistry_AddRejectsDifferentID(t *testing.T) {
	reg := newCarrierRegistry(CarrierDescriptor{
		ID:     DefaultUpCarrierID,
		Dir:    session.DirUp,
		Family: FamilyCDNWS,
	})

	h1 := makeTestHandle(t, 1)
	t.Cleanup(func() { h1.carrier.Close() })
	if _, err := reg.Add(DefaultUpCarrierID, h1); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Install a carrier with a different ID — must be rejected.
	h2 := makeTestHandle(t, 2)
	t.Cleanup(func() { h2.carrier.Close() })
	_, err := reg.Add("up-cdn-ws-b", h2)
	if !errors.Is(err, ErrUnknownCarrierID) {
		t.Fatalf("Add with foreign ID: got err=%v, want ErrUnknownCarrierID", err)
	}
	// The original entry must be unchanged.
	if reg.Handle(DefaultUpCarrierID) != h1 {
		t.Fatal("Add with foreign ID must not replace the current entry")
	}
	if reg.Generation(DefaultUpCarrierID) != 1 {
		t.Fatalf("Generation after rejected Add: got %d want 1", reg.Generation(DefaultUpCarrierID))
	}
}

// TestRegistry_ClearIf verifies that ClearIf only removes the entry when
// it points at the given handle, and is a no-op for a different handle.
func TestRegistry_ClearIf(t *testing.T) {
	reg := newCarrierRegistry(CarrierDescriptor{
		ID:     DefaultUpCarrierID,
		Dir:    session.DirUp,
		Family: FamilyCDNWS,
	})

	h1 := makeTestHandle(t, 1)
	t.Cleanup(func() { h1.carrier.Close() })
	if _, err := reg.Add(DefaultUpCarrierID, h1); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// ClearIf with a different handle: no-op.
	h2 := makeTestHandle(t, 2)
	t.Cleanup(func() { h2.carrier.Close() })
	reg.ClearIf(DefaultUpCarrierID, h2)
	if reg.Handle(DefaultUpCarrierID) != h1 {
		t.Fatal("ClearIf with wrong handle must not clear")
	}

	// ClearIf with the same handle: clears.
	reg.ClearIf(DefaultUpCarrierID, h1)
	if reg.Handle(DefaultUpCarrierID) != nil {
		t.Fatal("ClearIf with matching handle should clear the entry")
	}
	if reg.Generation(DefaultUpCarrierID) != 0 {
		t.Fatalf("Generation after Clear: got %d want 0", reg.Generation(DefaultUpCarrierID))
	}
}

// TestRegistry_Clear verifies that Clear unconditionally empties the slot.
func TestRegistry_Clear(t *testing.T) {
	reg := newCarrierRegistry(CarrierDescriptor{
		ID:     DefaultDownCarrierID,
		Dir:    session.DirDown,
		Family: FamilyReality,
	})

	h1 := makeTestHandle(t, 1)
	t.Cleanup(func() { h1.carrier.Close() })
	if _, err := reg.Add(DefaultDownCarrierID, h1); err != nil {
		t.Fatalf("Add: %v", err)
	}

	reg.Clear(DefaultDownCarrierID)
	if reg.Handle(DefaultDownCarrierID) != nil {
		t.Fatal("Clear should empty the registry")
	}
	if reg.Ready() {
		t.Fatal("Ready after Clear must be false")
	}
	if reg.Count() != 0 {
		t.Fatalf("Count after Clear: got %d want 0", reg.Count())
	}
}

// TestRegistry_Count verifies that Count returns 0 when empty and 1 when
// occupied, structurally impossible to exceed 1.
func TestRegistry_Count(t *testing.T) {
	reg := newCarrierRegistry(CarrierDescriptor{
		ID:     DefaultUpCarrierID,
		Dir:    session.DirUp,
		Family: FamilyCDNWS,
	})

	if reg.Count() != 0 {
		t.Fatalf("empty Count: got %d want 0", reg.Count())
	}

	h1 := makeTestHandle(t, 1)
	t.Cleanup(func() { h1.carrier.Close() })
	if _, err := reg.Add(DefaultUpCarrierID, h1); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if reg.Count() != 1 {
		t.Fatalf("Count after Add: got %d want 1", reg.Count())
	}
	// Even after a replace, Count stays at 1.
	h2 := makeTestHandle(t, 2)
	t.Cleanup(func() { h2.carrier.Close() })
	if _, err := reg.Add(DefaultUpCarrierID, h2); err != nil {
		t.Fatalf("second Add: %v", err)
	}
	if reg.Count() != 1 {
		t.Fatalf("Count after replace: got %d want 1 (single-entry invariant)", reg.Count())
	}
}

// TestNode_UpRegistry_Accessor verifies that UpReady / DownReady route
// through the registries and match the legacy semantics.
func TestNode_UpRegistry_Accessor(t *testing.T) {
	node, logger, _ := newTestNode(t, RoleIran)
	defer node.Close()
	_ = logger

	if node.UpReady() {
		t.Fatal("UpReady must be false before install")
	}
	if node.DownReady() {
		t.Fatal("DownReady must be false before install")
	}

	// Install a carrier through the public API.
	a, b := net.Pipe()
	_ = b
	node.InstallUp(a, nil)
	if !node.UpReady() {
		t.Fatal("UpReady must be true after InstallUp")
	}
	if node.DownReady() {
		t.Fatal("DownReady must remain false (only up installed)")
	}
}

// TestNode_InstallUp_RegGeneration verifies that successive InstallUp
// calls increment the generation (the Node's genSeq counter, kept
// node-global and lockstep across both sides).
func TestNode_InstallUp_RegGeneration(t *testing.T) {
	node, _, _ := newTestNode(t, RoleIran)
	defer node.Close()

	a1, b1 := net.Pipe()
	_ = b1
	h1 := node.InstallUp(a1, nil)
	g1 := h1.Gen()

	a2, b2 := net.Pipe()
	_ = b2
	h2 := node.InstallUp(a2, nil)
	g2 := h2.Gen()

	if g2 <= g1 {
		t.Fatalf("generation must increment on replace: g1=%d g2=%d", g1, g2)
	}
}

// TestNode_InstallDown_RegID verifies the down registry's fixed ID.
func TestNode_InstallDown_RegID(t *testing.T) {
	node, _, _ := newTestNode(t, RoleGermany)
	defer node.Close()

	a, b := net.Pipe()
	_ = b
	h := node.InstallDown(a, nil)
	if h == nil {
		t.Fatal("InstallDown returned nil")
	}
	if node.downReg.ID() != DefaultDownCarrierID {
		t.Fatalf("down registry ID: got %q want %q", node.downReg.ID(), DefaultDownCarrierID)
	}
}

// TestNode_UpReady_AfterLoss verifies that UpReady reports false after
// the carrier's read loop exits and dropIfCurrent clears the slot.
func TestNode_UpReady_AfterLoss(t *testing.T) {
	node, _, _ := newTestNode(t, RoleIran)
	defer node.Close()

	a, b := net.Pipe()
	_ = b
	node.InstallUp(a, nil)
	if !node.UpReady() {
		t.Fatal("UpReady must be true after InstallUp")
	}

	// Close the carrier to trigger the loss sweep.
	a.Close()
	// Wait for the loss sweep to complete (bounded).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !node.UpReady() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if node.UpReady() {
		t.Fatal("UpReady must be false after the carrier dies")
	}
}

// TestRegistry_String verifies the log prefix format.
func TestRegistry_String(t *testing.T) {
	desc := CarrierDescriptor{
		ID:     "down.reality.b",
		Dir:    session.DirDown,
		Family: "reality",
	}
	if got := desc.String(); got != "carrier[down/down.reality.b]" {
		t.Fatalf("String: got %q", got)
	}
}

// newTestNode is a shared helper for the registry tests. It creates a
// Node with a logger that discards output, the shared secret used by
// CarrierAuth, and a sanitized default config.
func newTestNode(t *testing.T, role Role) (*Node, *log.Logger, []byte) {
	t.Helper()
	cfg := Config{Role: role}
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
	return n, log.New(io.Discard, "", 0), secret
}
