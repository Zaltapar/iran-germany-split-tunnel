package session

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAttachmentInitialState: new attachments are Unavailable with no
// timer — a carrier loss detected before the first Attach must not start
// a grace window on its own.
func TestAttachmentInitialState(t *testing.T) {
	var timedOut int32
	a := NewAttachment(50*time.Millisecond, func() { atomic.AddInt32(&timedOut, 1) })
	st, gen := a.State()
	if st != AttUnavailable || gen != 0 {
		t.Fatalf("initial state = %v/%d, want Unavailable/0", st, gen)
	}
	// Detach on a never-attached attachment is a no-op (no grace timer).
	if a.Detach(1) {
		t.Fatal("Detach on initial attachment must be a no-op")
	}
	time.Sleep(80 * time.Millisecond)
	if got := atomic.LoadInt32(&timedOut); got != 0 {
		t.Fatalf("grace timer fired %d times, want 0", got)
	}
}

// TestAttachmentLifecycle: Unavailable → Attach(gen) → Detach(gen) →
// Rebinding → Attach; grace timer stops on Attach and cancels on Close.
func TestAttachmentLifecycle(t *testing.T) {
	var timedOut int32
	a := NewAttachment(100*time.Millisecond, func() { atomic.AddInt32(&timedOut, 1) })

	if !a.Attach(1) {
		t.Fatal("Attach(1) from Unavailable must succeed")
	}
	if a.Attach(2) {
		t.Fatal("Attach(2) while Attached must fail")
	}
	st, gen := a.State()
	if st != AttAttached || gen != 1 {
		t.Fatalf("state = %v/%d, want Attached/1", st, gen)
	}

	if !a.Detach(1) {
		t.Fatal("Detach(1) from Attached(1) must succeed")
	}
	if a.Detach(1) {
		t.Fatal("second Detach must be a no-op")
	}
	// Stale-carrier guard: a different (older/newer) generation cannot
	// detach.
	if a.Detach(2) {
		t.Fatal("Detach(2) from Unavailable must be a no-op")
	}

	if !a.BeginRebind() {
		t.Fatal("BeginRebind from Unavailable must succeed")
	}
	if a.BeginRebind() {
		t.Fatal("second BeginRebind must fail (claim race)")
	}
	if a.Detach(1) {
		t.Fatal("Detach while Rebinding must be a no-op (not Attached)")
	}
	if !a.Attach(2) {
		t.Fatal("Attach(2) from Rebinding must succeed")
	}
	time.Sleep(150 * time.Millisecond)
	if got := atomic.LoadInt32(&timedOut); got != 0 {
		t.Fatalf("grace timer fired %d times after Attach, want 0", got)
	}

	a.Close()
	st, _ = a.State()
	if st != AttClosed {
		t.Fatalf("state after Close = %v, want Closed", st)
	}
	if a.Attach(3) {
		t.Fatal("Attach on Closed attachment must fail")
	}
}

// TestAttachmentGraceTimeout: a Detach starts the grace window; if no
// rebind completes, onTimeout fires exactly once.
func TestAttachmentGraceTimeout(t *testing.T) {
	var mu sync.Mutex
	fires := 0
	a := NewAttachment(80*time.Millisecond, func() { mu.Lock(); fires++; mu.Unlock() })
	a.Attach(1)
	a.Detach(1)
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		f := fires
		mu.Unlock()
		if f > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if fires != 1 {
		t.Fatalf("onTimeout fired %d times, want exactly 1", fires)
	}
}

// TestAttachmentRebindCompletesWithinGrace: a rebind finishing before
// the grace deadline cancels the timeout.
func TestAttachmentRebindCompletesWithinGrace(t *testing.T) {
	var fires int32
	a := NewAttachment(150*time.Millisecond, func() { atomic.AddInt32(&fires, 1) })
	a.Attach(1)
	a.Detach(1)
	time.Sleep(30 * time.Millisecond)
	a.BeginRebind()
	a.Attach(2)
	time.Sleep(200 * time.Millisecond)
	if got := atomic.LoadInt32(&fires); got != 0 {
		t.Fatalf("onTimeout fired %d times after successful rebind, want 0", got)
	}
}

// TestAttachmentRebindExceedsGrace: a rebind that does not complete
// within the grace window still times out (the timer survives
// Rebinding).
func TestAttachmentRebindExceedsGrace(t *testing.T) {
	var fires int32
	a := NewAttachment(80*time.Millisecond, func() { atomic.AddInt32(&fires, 1) })
	a.Attach(1)
	a.Detach(1)
	a.BeginRebind()
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&fires) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&fires) != 1 {
		t.Fatalf("onTimeout fired %d times, want 1 (rebind exceeded grace)", fires)
	}
}

// TestAttachmentStaleDetach: the core stale-carrier guard — a session
// that already rebound to a NEWER carrier must not be detached by the
// death of the OLDER one.
func TestAttachmentStaleDetach(t *testing.T) {
	a := NewAttachment(time.Second, nil)
	a.Attach(5) // bound to carrier gen 5
	a.Detach(5)
	a.Attach(6) // rebound to carrier gen 6
	if a.Detach(5) {
		t.Fatal("stale Detach(5) after rebind to gen 6 must be a no-op")
	}
	st, gen := a.State()
	if st != AttAttached || gen != 6 {
		t.Fatalf("state = %v/%d, want Attached/6 (untouched)", st, gen)
	}
}

// TestAttachmentReadySignal: the ready signal closes on Attach and is
// re-created (open) on Detach, so parked relays wake on rebind.
func TestAttachmentReadySignal(t *testing.T) {
	a := NewAttachment(time.Second, nil)
	s1 := a.ReadySignal()
	select {
	case <-s1:
		t.Fatal("ready signal open in initial state")
	default:
	}
	a.Attach(1)
	select {
	case <-s1:
	default:
		t.Fatal("ready signal must be closed while Attached")
	}
	a.Detach(1)
	s2 := a.ReadySignal()
	if s1 == s2 {
		t.Fatal("Detach must install a fresh ready signal")
	}
	select {
	case <-s2:
		t.Fatal("fresh ready signal must be open after Detach")
	default:
	}
}

// TestAttachmentEpochJoin: JoinEpoch blocks on the recorded consumer's
// done channel and returns immediately when none is set.
func TestAttachmentEpochJoin(t *testing.T) {
	a := NewAttachment(time.Second, nil)
	if !a.JoinEpoch(time.Second) {
		t.Fatal("JoinEpoch with no epoch must succeed immediately")
	}
	done := make(chan struct{})
	a.SetEpochDone(done)
	ok := make(chan bool, 1)
	go func() { ok <- a.JoinEpoch(500 * time.Millisecond) }()
	time.Sleep(30 * time.Millisecond)
	close(done)
	select {
	case got := <-ok:
		if !got {
			t.Fatal("JoinEpoch must succeed when the epoch exits")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("JoinEpoch did not return after epoch close")
	}
	done2 := make(chan struct{}) // never closes
	a.SetEpochDone(done2)
	start := time.Now()
	if a.JoinEpoch(60 * time.Millisecond) {
		t.Fatal("JoinEpoch on a stuck epoch must time out")
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Fatal("JoinEpoch returned before the timeout")
	}
}

// TestRebindCodecRoundTrip: Encode/Parse are exact inverses; malformed
// payloads are rejected.
func TestRebindCodecRoundTrip(t *testing.T) {
	sid := SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	for _, gen := range []uint64{0, 1, 2, 1 << 40, ^uint64(0)} {
		b := EncodeRebind(sid, gen)
		if len(b) != RebindPayloadSize {
			t.Fatalf("payload size = %d, want %d", len(b), RebindPayloadSize)
		}
		gotSID, gotGen, ok := ParseRebind(b)
		if !ok {
			t.Fatalf("Parse(Encode) failed for gen %d", gen)
		}
		if gotSID != sid || gotGen != gen {
			t.Fatalf("round trip = (%v, %d), want (%v, %d)", gotSID, gotGen, sid, gen)
		}
	}
	if _, _, ok := ParseRebind(nil); ok {
		t.Fatal("nil payload must be rejected")
	}
	if _, _, ok := ParseRebind(make([]byte, RebindPayloadSize-1)); ok {
		t.Fatal("short payload must be rejected")
	}
	if _, _, ok := ParseRebind(make([]byte, RebindPayloadSize+1)); ok {
		t.Fatal("long payload must be rejected")
	}
	bad := EncodeRebind(sid, 1)
	bad[0] = 99 // unknown version
	if _, _, ok := ParseRebind(bad); ok {
		t.Fatal("unknown version must be rejected")
	}
}
