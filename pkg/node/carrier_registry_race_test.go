package node

// carrier_registry_race_test.go — deterministic regression tests for the
// concurrent map access on carrierRegistry reported by the Linux -race gate
// (8 reports, one root cause): unsynchronized Handles() reads (the session
// OnClose sweep in onSessionClosed, which runs WITHOUT the Node mutex)
// racing the ClearIf/Add map writes of the carrier-loss and install paths
// (onCarrierLost / the install sweep triggered from bootstrapUpStream).
//
// Under -race these tests FAIL on the unfixed code (registry map had no
// lock of its own; every method relied on the caller holding n.mu, which
// the onSessionClosed hook does not):
//   - TestRegistry_ConcurrentHandlesVsClearIf: unsynchronized reader
//     goroutines (Handles/Primary/Ready/Count/Generation — the
//     onSessionClosed sweep shape) vs writer goroutines
//     (Add/ClearIf/Clear — the install/loss-sweep shape), asserting no
//     race and the correct final state.
//   - TestNode_ConcurrentSessionCloseVsLossSweeps: onSessionClosed-style
//     read sweeps (Deregister over Handles(), no n.mu) racing
//     onCarrierLost-style loss sweeps (ClearIf + ReadyExcept failover
//     snapshot) with a bounded soak window — proves the loss/failover
//     path (rebind/grace) does not deadlock against the session-close
//     path, and that a surviving standby keeps the direction Ready.
//
// Package node: reaches the unexported registry directly.

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// makeRawHandle builds a carrier handle whose mux carrier is NOT Dispatched.
// (An undispatched carrier's Close is non-blocking, so registry-level
// sweeps stay bounded in these unit tests; the lock discipline being tested
// lives at the registry.) The caller must Close the carrier when done.
func makeRawHandle(t *testing.T, gen uint64, id CarrierID) *carrierHandle {
	t.Helper()
	a, b := net.Pipe()
	_ = b
	c := mux.NewCarrierConn(a, 0)
	return &carrierHandle{carrier: c, gen: gen, id: id, done: make(chan struct{}), lost: make(chan struct{})}
}

// TestRegistry_ConcurrentHandlesVsClearIf hammers the registry's read path
// (Handles/Primary/Generation/Count — what onSessionClosed calls) against
// the write path (Add/ClearIf/Clear — what onCarrierLost + the install
// sweep call) from independent goroutines, exactly as the loss-swatcher
// goroutine and the session-close sweep race during test cleanup.
//
// Pre-fix the registry map had no lock at all: -race reports concurrent
// read/write on r.handles. Post-fix every method takes r.mu, and the
// final-state assertion verifies the ClearIf guard semantics held.
func TestRegistry_ConcurrentHandlesVsClearIf(t *testing.T) {
	reg := newMultiCarrierRegistry(session.DirDown, []CarrierID{DefaultDownCarrierID, SecondDownCarrierID})

	const iterations = 2000
	var wg sync.WaitGroup

	// Reader goroutines: the onSessionClosed sweep shape. Snapshot the
	// full handle list, then exercise per-id inspection.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				for _, h := range reg.Handles() {
					if h != nil {
						_ = h.gen // read the handle's identity from the snapshot
					}
				}
				_ = reg.Primary()
				_ = reg.Ready()
				_ = reg.Count()
				_ = reg.Generation(DefaultDownCarrierID)
			}
		}()
	}

	// Writer goroutines: the install/loss-sweep shape. Each writer owns ONE
	// slot exclusively so the per-iteration invariant ("the slot still points
	// at my handle when I run the stale ClearIf") is not invalidated by a
	// sibling writer repointing the same slot. Readers still span both
	// slots, which is what races the map.
	writerIDs := []CarrierID{DefaultDownCarrierID, SecondDownCarrierID}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(seed int, id CarrierID) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				h := makeRawHandle(t, uint64(seed*10000+j), id)
				old, err := reg.Add(id, h)
				if err != nil {
					t.Errorf("writer %d iter %d: Add: %v", seed, j, err)
					return
				}
				if old != nil {
					old.carrier.Close()
				}
				// ClearIf guard check: a stale handle must not clear
				// the slot that now points at h.
				if old != nil {
					reg.ClearIf(id, old)
					if got := reg.Handle(id); got != h {
						t.Errorf("writer %d iter %d: ClearIf(stale) cleared the new handle", seed, j)
						return
					}
				}
				// Now clear with the CURRENT handle: atomic guard holds.
				reg.ClearIf(id, h)
				h.carrier.Close()
			}
		}(i, writerIDs[i])
	}

	wg.Wait()

	// Final state: every ClearIf above used the current handle, so the
	// slots must be empty — the loss-sweep guard semantics are intact
	// under concurrency.
	if got := reg.Count(); got != 0 {
		t.Fatalf("Count after concurrent clear sweeps: got %d, want 0", got)
	}
	if h := reg.Handle(DefaultDownCarrierID); h != nil {
		t.Fatalf("primary slot not empty after sweep: gen %d", h.gen)
	}
	if h := reg.Handle(SecondDownCarrierID); h != nil {
		t.Fatalf("standby slot not empty after sweep: gen %d", h.gen)
	}
}

// TestRegistry_ConcurrentCloseAll verifies CloseAll's
// snapshot-then-close-outside-lock semantics: racing Add/CloseAll leaves
// no double-close panic (the carrier's closeOnce) and an empty map.
func TestRegistry_ConcurrentCloseAll(t *testing.T) {
	reg := newCarrierRegistry(CarrierDescriptor{ID: DefaultUpCarrierID, Dir: session.DirUp, Family: FamilyCDNWS})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				h := makeRawHandle(t, uint64(seed*1000+j), DefaultUpCarrierID)
				old, _ := reg.Add(DefaultUpCarrierID, h)
				if old != nil {
					old.carrier.Close()
				}
				reg.CloseAll() // snapshot+close; idempotent on an empty map
			}
		}(i)
	}
	wg.Wait()

	if got := reg.Count(); got != 0 {
		t.Fatalf("Count after concurrent CloseAll: got %d, want 0", got)
	}
}

// nodeLossSweep drives the Node-level loss path the way onCarrierLost does
// (registry scope only, not the channel close / detach of a live carrier):
// the ClearIf + direction-signal update under n.mu, then the ReadyExcept
// failover-set snapshot that the Iran failover sweep runs after the lock.
func nodeLossSweep(t *testing.T, n *Node, h *carrierHandle) {
	t.Helper()
	n.mu.Lock()
	reg := n.downReg
	reg.ClearIf(h.id, h)
	if !reg.Ready() {
		n.downReady = make(chan struct{})
		n.downReadyClosed = false
	}
	n.mu.Unlock()
	// The Iran failover-set snapshot (ReadyExcept shape of onCarrierLost):
	// the lost carrier's pinned streams re-attach onto a survivor.
	for range reg.ReadyExcept(h.id) {
	}
}

// TestNode_ConcurrentSessionCloseVsLossSweeps is the Node-level deadlock +
// race regression: onSessionClosed-style read sweeps (the carrier
// Deregister over Handles() WITHOUT n.mu held — the exact call site the
// gate flagged, since session OnClose hooks run on the session's
// goroutine) racing onCarrierLost-style loss sweeps (ClearIf +
// ReadyExcept failover), with a bounded soak window (no t.Parallel hang):
// every sweep is guaranteed to quiesce before the test finishes.
func TestNode_ConcurrentSessionCloseVsLossSweeps(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)
	defer n.Close()

	primary, primaryPeer := pipePair(t)
	standby, _ := pipePair(t)
	ph, err := n.InstallDownOn(DefaultDownCarrierID, primary, nil)
	if err != nil {
		t.Fatalf("install primary: %v", err)
	}
	if _, err := n.InstallDownOn(SecondDownCarrierID, standby, nil); err != nil {
		t.Fatalf("install standby: %v", err)
	}
	_ = primaryPeer

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Reader sweeps: the onSessionClosed shape — Deregister over the
	// registry snapshot without n.mu. Deregister on an absent stream is
	// quiet/idempotent, so hammering it is safe.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				for _, h := range n.downReg.Handles() {
					if h != nil {
						h.carrier.Deregister(0xCAFE)
					}
				}
				select {
				case <-stop:
					return
				case <-time.After(2 * time.Millisecond):
				}
			}
		}()
	}

	// Loss sweeps on the PRIMARY while the readers run: the ClearIf +
	// ReadyExcept failover path of onCarrierLost, idempotent after the
	// first sweep (the slot is already empty). Bounded by the stop channel.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			nodeLossSweep(t, n, ph)
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()

	// Bounded soak window, then quiesce.
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	// The primary slot was cleared by the sweep; the standby is still
	// Ready, so the direction must stay Ready (the multi-carrier
	// invariant the loss path must preserve).
	if got := n.downReg.Handle(DefaultDownCarrierID); got != nil {
		t.Fatalf("primary slot still held after loss sweep: gen %d", got.gen)
	}
	if !n.DownReady() {
		t.Fatal("direction must stay Ready while the standby is up")
	}
	if !n.DownCarrierReady(SecondDownCarrierID) {
		t.Fatal("standby carrier must remain ready after the primary loss sweep")
	}
}

// TestNode_CloseAllRacesInstallSweep verifies the shutdown CloseAll path
// (Node.Close taking n.mu + reg.CloseAll) does not deadlock, panic, or
// double-close against the install path's Add replacing a slot.
func TestNode_CloseAllRacesInstallSweep(t *testing.T) {
	n := newMultiTestNode(t, RoleIran)

	a, b := pipePair(t)
	_, err := n.InstallDownOn(DefaultDownCarrierID, a, nil)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	_ = b

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Fresh install in a loop; the shutdown sweep interleaves.
		for i := 0; i < 20; i++ {
			na, nb := net.Pipe()
			if _, err := n.InstallDownOn(DefaultDownCarrierID, na, nil); err != nil {
				_ = na.Close()
				_ = nb.Close()
				return
			}
			_ = nb
			// The Node.Close sweep shape: CloseAll under n.mu
			// (deferred n.Close() re-runs it idempotently, and the
			// carriers' closeOnce makes any double-close a no-op).
			n.mu.Lock()
			n.upReg.CloseAll()
			n.downReg.CloseAll()
			n.mu.Unlock()
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("CloseAll vs install sweep did not terminate (deadlock)")
	}
}
