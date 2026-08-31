package mux

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// Regression tests for the "send on closed channel" crash:
//
//	streamWorker pops an item from the StreamQueue
//	        ↓
//	CarrierConn.Close closes s.ch (old step 5) under c.mu
//	        ↓
//	the worker later sends on s.ch (outside c.mu)
//	        ↓
//	panic: send on closed channel — the whole splitter process dies.
//
// The vulnerable window is the instant between the worker's Pop and its
// delivery select completing: if Close closes s.ch while the worker is in
// that window, the `s.ch <- it` arm is "ready" (sending on a closed
// channel is always ready) and the runtime panics the worker. A select
// cannot prevent this: the panic is delivered to the sending goroutine
// the moment the send arm is evaluated after the close, regardless of the
// `<-c.closed` arm.
//
// Two realistic ways the window is hit in production (both reproduced
// against the pre-fix code):
//
//  1. An ACTIVE flood: frames are flowing, workers continuously cycle
//     Pop → hand off → Pop. Close's close(s.ch) lands in any pop→send
//     gap of any worker and panics (near-certain with several streams —
//     this is the audit's production reproduction, crash at the data
//     send, carrier.go data-delivery select).
//  2. A PARKED worker: the consumer channel is full, the worker is
//     parked on the send, Close wakes it via c.closed — and if it is not
//     rescheduled before s.ch is closed, its select sees both arms ready
//     and picks the closed one (rarer per event, but real).
//
// The fix (Close step 5, sub-steps a/b/c) closes s.ch only AFTER
// workerWait.Wait() has confirmed every worker has exited, so no worker
// can be in the window when any s.ch is closed. The tests below drive
// both scenarios and assert the full post-Close contract: no panic,
// workers exited (ShutdownDone), channels closed, queued bytes reclaimed
// to zero, other carriers unaffected.

// queueLen returns the number of items currently in stream id's mailbox.
// White-box helper (same package as StreamQueue).
func queueLen(t *testing.T, c *CarrierConn, id uint32) int {
	t.Helper()
	c.mu.Lock()
	s, ok := c.streams[id]
	c.mu.Unlock()
	if !ok {
		t.Fatalf("stream %d not registered", id)
	}
	s.q.mu.Lock()
	defer s.q.mu.Unlock()
	return len(s.q.items)
}

// assertClosedCarrier asserts the full post-Close contract: every
// consumer channel is closed, queued-byte accounting is back to zero,
// and every carrier-owned goroutine (workers included) has exited
// (ShutdownDone).
func assertClosedCarrier(t *testing.T, c *CarrierConn, chs map[uint32]chan []byte) {
	t.Helper()
	for id, ch := range chs {
		done := make(chan struct{})
		go func() {
			for range ch {
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("stream %d consumer channel was not closed by Close", id)
		}
	}
	if n := atomic.LoadInt64(&c.queuedBytes); n != 0 {
		t.Fatalf("queuedBytes after Close = %d, want 0 (bytes must be reclaimed)", n)
	}
	select {
	case <-c.ShutdownDone():
	case <-time.After(3 * time.Second):
		t.Fatal("carrier-owned goroutines (stream workers?) did not all exit after Close")
	}
	if c.Ready() {
		t.Error("carrier reports Ready after Close")
	}
}

// TestCloseRacesActiveWorkerFlood is the production reproduction: a
// carrier with active traffic (consumers keeping up, workers cycling
// Pop → hand-off → Pop) is Closed while the flood is in progress.
// Pre-fix, Close closed s.ch while workers were mid-cycle and the test
// panicked "send on closed channel" at the data-delivery select on (nearly)
// every iteration. Post-fix, Close waits for the workers, so the close
// of s.ch can never race a send.
//
// Run with -count=100 (or more) to multiply the attempts.
func TestCloseRacesActiveWorkerFlood(t *testing.T) {
	const iterations = 200
	for i := 0; i < iterations; i++ {
		a, b := testutil.NewMemPipe()
		c := NewCarrierConn(a, 0)
		c.SetStreamLimits(bpLimits(16, 4096, 64*4096, 200*time.Millisecond))
		const streams = 8
		chs := make(map[uint32]chan []byte, streams)
		for id := uint32(1); id <= streams; id++ {
			ch := c.Register(id)
			chs[id] = ch
			go func(ch chan []byte) {
				for range ch { // keeps draining: workers stay active
				}
			}(ch)
		}
		go c.Dispatch()

		stop := make(chan struct{})
		go func() {
			id := uint32(1)
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = WriteFrame(b, id, FrameData, []byte("x"))
				id++
				if id > streams {
					id = 1
				}
			}
		}()
		// Let the flood run so workers are actively cycling.
		time.Sleep(2 * time.Millisecond)
		c.Close() // must not panic while workers deliver
		close(stop)
		a.Close()
		b.Close()
		assertClosedCarrier(t, c, chs)
	}
}

// parkWorkersInDelivery writes two FrameData frames to every stream and
// waits until the observable state proves that, for every stream:
//
//   - the consumer channel is FULL (first frame already handed to ch,
//     never read), and
//   - the mailbox is EMPTY (second frame already POPPED by the worker).
//
// In that state each worker is either inside the pop→send gap or parked
// on `s.ch <- item` — the parked-worker variant of the crash. The state
// is verified, not assumed, so the setup is deterministic.
func parkWorkersInDelivery(t *testing.T, b *testutil.MemConn, c *CarrierConn, chs map[uint32]chan []byte) {
	t.Helper()
	payload := []byte("x")
	for id := range chs {
		for i := 0; i < 2; i++ {
			if err := WriteFrame(b, id, FrameData, payload); err != nil {
				t.Fatalf("WriteFrame stream %d frame %d: %v", id, i, err)
			}
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		settled := true
		for id, ch := range chs {
			if len(ch) != 1 || queueLen(t, c, id) != 0 {
				settled = false
				break
			}
		}
		if settled {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("workers never reached the popped-not-yet-delivered state")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestCloseRacesWorkerDeliveryGap is the single-instance parked-worker
// regression: every worker has popped its second frame and is in the
// pop→send gap (or parked on the full consumer channel) when Close runs.
// Pre-fix, Close closed s.ch in that window and the worker's later send
// could panic the process (the parked-wakeup ordering of probe 1/3).
func TestCloseRacesWorkerDeliveryGap(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.SetStreamLimits(bpLimits(16, 4096, 64*4096, 200*time.Millisecond))
	chs := make(map[uint32]chan []byte)
	for id := uint32(1); id <= 8; id++ {
		chs[id] = c.Register(id)
	}
	go c.Dispatch()

	parkWorkersInDelivery(t, b, c, chs)
	c.Close()
	assertClosedCarrier(t, c, chs)
}

// TestCloseRacesWorkerDeliveryWithFrameClose is the same race on the
// FrameClose delivery path (worker delivering nil to a full consumer
// channel / in the gap).
func TestCloseRacesWorkerDeliveryWithFrameClose(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.SetStreamLimits(bpLimits(16, 4096, 64*4096, 200*time.Millisecond))
	ch1, ch2 := c.Register(1), c.Register(2)
	go c.Dispatch()

	for _, id := range []uint32{1, 2} {
		if err := WriteFrame(b, id, FrameData, []byte("x")); err != nil {
			t.Fatalf("WriteFrame data: %v", err)
		}
	}
	// Wait for the data frames to be handed to the (never-read) channels.
	deadline := time.Now().Add(3 * time.Second)
	for len(ch1) != 1 || len(ch2) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("data frames were never delivered to the consumer channels")
		}
		time.Sleep(time.Millisecond)
	}
	// Now a FrameClose per stream: the workers pop the (0-byte) close
	// items and must deliver nil to the already-full channels — the same
	// pop→send gap as for data frames.
	for _, id := range []uint32{1, 2} {
		if err := WriteFrame(b, id, FrameClose, nil); err != nil {
			t.Fatalf("WriteFrame close: %v", err)
		}
	}
	deadline = time.Now().Add(3 * time.Second)
	for queueLen(t, c, 1) != 0 || queueLen(t, c, 2) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("workers never popped the FrameClose items")
		}
		time.Sleep(time.Millisecond)
	}
	// Mailboxes empty + channels full: workers are in the gap or parked
	// on `s.ch <- nil`. Race Close.
	c.Close()
	assertClosedCarrier(t, c, map[uint32]chan []byte{1: ch1, 2: ch2})
}

// TestCloseReleasesWorkerParkedInPop covers the complementary state:
// the mailbox is EMPTY and the worker is parked in Pop (a common state
// for idle streams). Close's step 5(a) closes the mailbox, which is the
// only object that can wake such a worker; the worker must exit (no
// hang) and its bytes must be accounted.
func TestCloseReleasesWorkerParkedInPop(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.SetStreamLimits(bpLimits(16, 4096, 64*4096, 200*time.Millisecond))
	chs := make(map[uint32]chan []byte)
	for id := uint32(1); id <= 4; id++ {
		chs[id] = c.Register(id)
	}
	go c.Dispatch()

	// One frame per stream, fully delivered, then the worker parks in
	// Pop on the now-empty mailbox.
	payload := make([]byte, 64)
	for id := range chs {
		if err := WriteFrame(b, id, FrameData, payload); err != nil {
			t.Fatalf("WriteFrame stream %d: %v", id, err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		settled := true
		for id, ch := range chs {
			if len(ch) != 1 || queueLen(t, c, id) != 0 {
				settled = false
				break
			}
		}
		if settled && atomic.LoadInt64(&c.queuedBytes) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("workers never reached the parked-in-Pop state")
		}
		time.Sleep(time.Millisecond)
	}
	c.Close()
	assertClosedCarrier(t, c, chs)
}

// TestCloseReleasesDeregisteredStreamWorker verifies Close also shuts
// down a stream that was removed by Deregister before Close: its worker
// (parked in Pop, no longer reachable from c.streams) must still be
// released and its channel closed — otherwise Close's worker wait would
// hang on it (and, pre-fix, the worker leaked forever, keeping the
// live/shutdownDone accounting permanently wrong).
func TestCloseReleasesDeregisteredStreamWorker(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.SetStreamLimits(bpLimits(16, 4096, 64*4096, 200*time.Millisecond))
	ch1 := c.Register(1)
	ch2 := c.Register(2)
	go c.Dispatch()

	if err := WriteFrame(b, 2, FrameData, []byte("x")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// Let the frame be delivered (worker of stream 2 parks in Pop).
	deadline := time.Now().Add(3 * time.Second)
	for len(ch2) != 1 || queueLen(t, c, 2) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("stream 2 frame was never delivered")
		}
		time.Sleep(time.Millisecond)
	}
	// Stream 1: worker parked in Pop on an empty mailbox; deregister it.
	c.Deregister(1)
	if n := c.StreamCount(); n != 1 {
		t.Fatalf("StreamCount after Deregister = %d, want 1", n)
	}

	c.Close()
	// Both channels — including the deregistered stream's — must close.
	assertClosedCarrier(t, c, map[uint32]chan []byte{1: ch1, 2: ch2})
	if n := c.StreamCount(); n != 0 {
		t.Fatalf("StreamCount after Close = %d, want 0", n)
	}
}

// TestCloseRacesWorkerDeliveryStress hammers the parked-worker race:
// many iterations, several streams per carrier, workers parked in the
// pop→send gap when Close runs. Post-fix it must never panic.
//
// Run with -count=100 (or more) to multiply the attempts.
func TestCloseRacesWorkerDeliveryStress(t *testing.T) {
	const iterations = 200
	const streams = 16
	for i := 0; i < iterations; i++ {
		a, b := testutil.NewMemPipe()
		c := NewCarrierConn(a, 0)
		c.SetStreamLimits(bpLimits(16, 4096, 64*4096, 200*time.Millisecond))
		chs := make(map[uint32]chan []byte)
		for id := uint32(1); id <= streams; id++ {
			chs[id] = c.Register(id)
		}
		go c.Dispatch()

		parkWorkersInDelivery(t, b, c, chs)
		c.Close()
		assertClosedCarrier(t, c, chs)
		a.Close()
		b.Close()
	}
}

// TestCloseReleasesReboundStreamIDWorker covers the Phase 5 rebind case:
// a stream ID is Deregistered and then REGISTERED AGAIN (re-bind reuses
// the ID), creating a SECOND stream record while the first record's
// worker may still be parked in Pop. Close must release BOTH workers
// and close BOTH consumer channels — a map keyed by ID would lose the
// first record (and Close's worker wait would hang forever on its
// worker).
func TestCloseReleasesReboundStreamIDWorker(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.SetStreamLimits(bpLimits(16, 4096, 64*4096, 200*time.Millisecond))
	chOld := c.Register(1) // first generation: its worker will park in Pop
	go c.Dispatch()

	// One frame so the first worker does one delivery and parks in Pop.
	if err := WriteFrame(b, 1, FrameData, []byte("x")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(chOld) != 1 || queueLen(t, c, 1) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("first-generation frame was never delivered")
		}
		time.Sleep(time.Millisecond)
	}
	// Re-bind: deregister the ID and register it again (new record, new
	// worker, new channel).
	c.Deregister(1)
	chNew := c.Register(1)
	if chNew == nil {
		t.Fatal("re-Register returned nil")
	}
	// Both generations must be torn down by a single Close.
	c.Close()
	assertClosedCarrier(t, c, map[uint32]chan []byte{1: chNew})
	// The OLD channel must also be closed (its worker exited).
	done := make(chan struct{})
	go func() {
		for range chOld {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("previous rebind generation's channel was not closed by Close")
	}
}

// TestCloseOneCarrierLeavesOtherRunning verifies the fix does not
// couple carriers together: while carrier 1 is being closed with
// workers in the delivery gap, an independent carrier 2 keeps serving
// its stream.
func TestCloseOneCarrierLeavesOtherRunning(t *testing.T) {
	a1, b1 := testutil.NewMemPipe()
	defer a1.Close()
	defer b1.Close()
	a2, b2 := testutil.NewMemPipe()
	defer a2.Close()
	defer b2.Close()

	c1 := NewCarrierConn(a1, 0)
	c1.SetStreamLimits(bpLimits(16, 4096, 64*4096, 200*time.Millisecond))
	chs := make(map[uint32]chan []byte)
	for id := uint32(1); id <= 4; id++ {
		chs[id] = c1.Register(id)
	}
	go c1.Dispatch()

	c2 := NewCarrierConn(a2, 0)
	c2.SetStreamLimits(bpLimits(16, 4096, 64*4096, 200*time.Millisecond))
	other := c2.Register(1)
	go c2.Dispatch()
	defer c2.Close()

	parkWorkersInDelivery(t, b1, c1, chs)
	c1.Close()
	assertClosedCarrier(t, c1, chs)

	// Carrier 2 must be completely unaffected.
	if !c2.Ready() {
		t.Fatal("carrier 2 not Ready after closing carrier 1")
	}
	if err := WriteFrame(b2, 1, FrameData, []byte("still-alive")); err != nil {
		t.Fatalf("WriteFrame on carrier 2: %v", err)
	}
	select {
	case f := <-other:
		if string(f) != "still-alive" {
			t.Fatalf("carrier 2 payload = %q, want %q", f, "still-alive")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("carrier 2 stopped serving after carrier 1 closed")
	}
}
