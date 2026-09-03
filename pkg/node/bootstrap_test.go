package node

// Issue #7 — bounded bootstrap wait for a temporarily down carrier.
//
// White-box (in-package) tests for the carrier-ready signal and the
// signal-driven bootstrap waits, plus the new Config.BootstrapWait
// sanitization. The end-to-end behavior (a session bootstraps
// successfully when the opposite carrier returns within the window; it
// is dropped exactly once when it does not) is covered by
// bootstrap_integration_test.go over the full two-node topology.
//
// These tests reach the node's unexported helpers (waitCarriers,
// waitCarrierReady, readySig, currentIfReady), so they live in
// package node; the full-topology harness lives in package node_test
// (the two test packages coexist in this directory).

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// newSingleNode builds a bare Node (no carriers) with a configured
// bootstrap wait. KeepAliveInterval is an hour so keepalive pings never
// interfere with the test windows.
func newSingleNode(t *testing.T, role Role, bootWait time.Duration) *Node {
	t.Helper()
	cfg := Config{
		Role:              role,
		Grace:             time.Second,
		RelayBufSize:      4096,
		BufferBytes:       64 << 10,
		BootstrapWait:     bootWait,
		KeepAliveInterval: time.Hour,
	}
	return NewNode(cfg, log.New(io.Discard, "", 0), []byte("0123456789abcdef0123456789abcdef"))
}

// pipePair returns a fresh in-memory pipe pair, closed on cleanup
// (after the node's own cleanup has run — LIFO).
func pipePair(t *testing.T) (*testutil.MemConn, *testutil.MemConn) {
	t.Helper()
	a, b := testutil.NewMemPipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// waitUntil polls f until true or fails the test (bounded; the
// in-package analogue of the node_test harness' eventually).
func waitUntil(t *testing.T, timeout time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// TestBootstrapWaitSanitize: 0 lifts to the library default (30s); an
// explicit value is preserved.
func TestBootstrapWaitSanitize(t *testing.T) {
	var c Config
	c.Sanitize()
	if c.BootstrapWait != defaultBootstrapWait {
		t.Fatalf("BootstrapWait = %v after Sanitize, want default %v", c.BootstrapWait, defaultBootstrapWait)
	}
	if defaultBootstrapWait != 30*time.Second {
		t.Fatalf("defaultBootstrapWait = %v, want 30s", defaultBootstrapWait)
	}
	c2 := Config{BootstrapWait: 2500 * time.Millisecond}
	c2.Sanitize()
	if c2.BootstrapWait != 2500*time.Millisecond {
		t.Fatalf("explicit BootstrapWait = %v, want 2.5s (preserved)", c2.BootstrapWait)
	}
}

// TestWaitCarriersBothReadyImmediately: with both carriers installed
// and ready, waitCarriers returns at once (no wait is incurred).
func TestWaitCarriersBothReadyImmediately(t *testing.T) {
	n := newSingleNode(t, RoleIran, 100*time.Millisecond)
	defer n.Close()
	a, _ := pipePair(t)
	n.InstallUp(a, nil)
	b, _ := pipePair(t)
	n.InstallDown(b, nil)
	start := time.Now()
	upH, downH, err := n.waitCarriers()
	if err != nil {
		t.Fatalf("waitCarriers with both ready: %v", err)
	}
	if upH == nil || downH == nil {
		t.Fatalf("waitCarriers returned nil handle(s)")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("waitCarriers took %v with both carriers ready", elapsed)
	}
}

// TestWaitCarriersBlocksUntilDownCarrierInstalls (acceptance #4,
// Iran side): the up carrier is ready, the down carrier is absent.
// waitCarriers must block (NOT fail early), then succeed as soon as
// the down carrier is installed — the wait is signal-driven, so the
// return happens on the install, not on a poll tick.
func TestWaitCarriersBlocksUntilDownCarrierInstalls(t *testing.T) {
	n := newSingleNode(t, RoleIran, 5*time.Second)
	defer n.Close()
	a, _ := pipePair(t)
	n.InstallUp(a, nil)

	type res struct {
		upH, downH *carrierHandle
		err        error
	}
	resCh := make(chan res, 1)
	go func() {
		u, d, err := n.waitCarriers()
		resCh <- res{u, d, err}
	}()

	// Must NOT have returned yet (only the up carrier is installed).
	select {
	case r := <-resCh:
		t.Fatalf("waitCarriers returned early with only the up carrier: %+v", r.err)
	case <-time.After(150 * time.Millisecond): // observation window, not sync
	}

	// Install the down carrier: the signal wake must release the wait.
	b, _ := pipePair(t)
	n.InstallDown(b, nil)

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("waitCarriers after install: %v", r.err)
		}
		if r.upH == nil || r.downH == nil {
			t.Fatalf("waitCarriers returned nil handle(s) after install")
		}
		if r.downH != n.current(session.DirDown) {
			t.Fatal("waitCarriers returned a stale down carrier (not the current one)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitCarriers was not woken by the down carrier install")
	}
}

// TestWaitCarriersExpiry (acceptance #4, documented drop): with only
// the up carrier present and a short bootstrap wait, waitCarriers must
// fail at the deadline with a timeout error (no infinite wait). The
// busy-spin regression for this exact scenario (one carrier ready) is
// covered by TestWaitCarriersNoBusySpin.
func TestWaitCarriersExpiry(t *testing.T) {
	n := newSingleNode(t, RoleIran, 300*time.Millisecond)
	defer n.Close()
	a, _ := pipePair(t)
	n.InstallUp(a, nil)
	start := time.Now()
	_, _, err := n.waitCarriers()
	if err == nil {
		t.Fatal("waitCarriers must time out when the down carrier never arrives")
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("waitCarriers timed out at %v, want ~300ms (bounded)", elapsed)
	}
}

// TestWaitCarrierReadyWakesOnInstall: the single-direction wait blocks
// while the carrier is absent and is released exactly when the carrier
// is installed (signal-driven).
func TestWaitCarrierReadyWakesOnInstall(t *testing.T) {
	n := newSingleNode(t, RoleGermany, 5*time.Second)
	defer n.Close()

	resCh := make(chan *carrierHandle, 1)
	errCh := make(chan error, 1)
	go func() {
		h, err := n.waitCarrierReady(session.DirDown)
		if err != nil {
			errCh <- err
			return
		}
		resCh <- h
	}()

	select {
	case h := <-resCh:
		t.Fatalf("waitCarrierReady returned early: gen %d", h.gen)
	case <-errCh:
		t.Fatal("waitCarrierReady errored early")
	case <-time.After(150 * time.Millisecond): // observation window
	}

	b, _ := pipePair(t)
	n.InstallDown(b, nil)

	select {
	case h := <-resCh:
		if h != n.current(session.DirDown) {
			t.Fatal("waitCarrierReady returned a stale carrier")
		}
	case <-errCh:
		t.Fatal("waitCarrierReady errored after install")
	case <-time.After(2 * time.Second):
		t.Fatal("waitCarrierReady was not woken by the down carrier install")
	}
}

// TestWaitCarrierReadyExpiry: no carrier ever arrives → bounded
// failure at the deadline.
func TestWaitCarrierReadyExpiry(t *testing.T) {
	n := newSingleNode(t, RoleGermany, 250*time.Millisecond)
	defer n.Close()
	start := time.Now()
	h, err := n.waitCarrierReady(session.DirDown)
	if err == nil || h != nil {
		t.Fatalf("waitCarrierReady = (gen %v, %v), want (nil, error)", h, err)
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("waitCarrierReady bounded failure at %v, want ~250ms", elapsed)
	}
}

// TestWaitCarriersShutdownUnblocks: Node.Close during the wait returns
// immediately (ctx cancel), not at the deadline.
func TestWaitCarriersShutdownUnblocks(t *testing.T) {
	n := newSingleNode(t, RoleIran, 30*time.Second)
	a, _ := pipePair(t)
	n.InstallUp(a, nil)

	done := make(chan error, 1)
	go func() {
		_, _, err := n.waitCarriers()
		done <- err
	}()

	time.Sleep(100 * time.Millisecond) // let the wait park (observation)
	n.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("waitCarriers after Close must not succeed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Node.Close did not unblock waitCarriers immediately")
	}
}

// TestReadySignalLifecycle: the per-direction ready channel is open
// before any install, closed after install, and re-created (open) when
// the carrier is lost — the Attachment.ReadySignal pattern at node
// scope (Issue #7).
func TestReadySignalLifecycle(t *testing.T) {
	n := newSingleNode(t, RoleIran, time.Second)
	defer n.Close()

	assertOpen := func(ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
			t.Fatalf("%s ready channel closed before install", what)
		default:
		}
	}
	assertOpen(n.readySig(session.DirUp), "up")
	assertOpen(n.readySig(session.DirDown), "down")

	a, _ := pipePair(t)
	n.InstallUp(a, nil)
	select {
	case <-n.readySig(session.DirUp):
	case <-time.After(time.Second):
		t.Fatal("up ready channel not closed after install")
	}
	assertOpen(n.readySig(session.DirDown), "down")

	// Loss: the channel is re-created (open) again and the carrier is
	// dropped.
	a.Close()
	waitUntil(t, 2*time.Second, "up carrier loss processed", func() bool {
		if n.currentIfReady(session.DirUp) != nil {
			return false
		}
		select {
		case <-n.readySig(session.DirUp):
			return false // still the old closed channel — loss not processed
		default:
			return true
		}
	})
	if h := n.currentIfReady(session.DirUp); h != nil {
		t.Fatalf("currentIfReady(up) after loss = gen %d, want nil", h.gen)
	}

	// Re-install: closed again (a fresh channel), currentIfReady
	// returns the NEW generation (no stale-gen attachment).
	b, _ := pipePair(t)
	n.InstallUp(b, nil)
	waitUntil(t, 2*time.Second, "up ready channel closed after re-install", func() bool {
		select {
		case <-n.readySig(session.DirUp):
			return true
		default:
			return false
		}
	})
	if h := n.currentIfReady(session.DirUp); h == nil {
		t.Fatal("currentIfReady(up) after re-install = nil, want the new carrier")
	}
}
