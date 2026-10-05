package mux

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// These tests pin the deliver-or-fail invariant for in-order DATA frames:
//
//	an in-order DATA frame is either DELIVERED (queued and popped in order)
//	or the STREAM IS CLEANLY FAILED — it is never silently dropped while the
//	stream stays healthy. The dispatcher never blocks on a slow consumer
//	(Phase 3), so it cannot retry a refused frame in place; the moment a
//	FrameData push is refused it fails the stream deterministically and
//	records it as a dropped DATA frame.
//
// They drive deliver() single-threaded (playing the dispatcher's role) over a
// real streamRec mailbox with no worker, so the mailbox stays full and every
// observation is deterministic — no wall-clock polling.

// buildWorkerlessStream registers a stream whose mailbox is wired to the
// carrier's aggregate budget exactly as createStreamLocked does, but WITHOUT
// starting a worker goroutine. That is what keeps the mailbox full and lets
// the test play the dispatcher role deterministically.
func buildWorkerlessStream(t *testing.T, c *CarrierConn, stats *QueueStats, id uint32, frames, perStream int, total int) *streamRec {
	t.Helper()
	c.mu.Lock()
	s := &streamRec{id: id, q: NewStreamQueue(frames, perStream, &c.queuedBytes, int64(total)), ch: make(chan []byte, 1)}
	s.q.SetStats(stats)
	s.q.setQueuedItems(&c.queuedItems)
	c.streams[id] = s
	c.allStreams = append(c.allStreams, s)
	c.mu.Unlock()
	return s
}

// TestCarryExhaustionParksThenDeliversInOrder is the integrity-seam test
// for the SUBTASK-30 backpressure: when a consumer stalls so BOTH the
// primary mailbox AND the bounded carry region are full, the dispatcher no
// longer terminates the stream (the old "carry-then-abort" was the
// ~1 MB download-truncation bug). It now PARKS the delivering goroutine in
// PushPark until the consumer drains the mailbox (a Pop frees space and
// wakes the parked pusher), then delivers the full sequence IN ORDER with
// zero drops and zero terminations.
//
// Driven by a real dispatcher + a paced consumer over a mempipe, so the
// "the sender outpaces the consumer, the mailbox overflows, the dispatcher
// parks, the consumer catches up, the transfer completes" loop is exactly
// the production slow-client shape — but bounded and deterministic.
func TestCarryExhaustionParksThenDeliversInOrder(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	// Primary: 2 frames of 4 B (8 B byte cap) + carry 8 B (2 frames of 4 B)
	// = 16 B of mailbox. 24 frames of 4 B = 96 B >> 16 B: the dispatcher
	// MUST park repeatedly. MaxBytesTotal is large so only the PER-STREAM
	// path (the slow-consumer path) ever engages. ConsumerStall is set to a
	// generous 30 s so the SLOW (not dead) consumer below is never
	// reclaimed mid-transfer.
	limits := bpLimits(2, 8, 1<<20, 100*time.Millisecond)
	limits.ConsumerStall = 30 * time.Second
	_ = c.SetStreamLimits(limits)

	ch := c.Register(1)
	go c.Dispatch()

	const total = 24
	var undel atomic.Int32
	c.OnStreamDataUndeliverable = func(uint32) { undel.Add(1) }

	// SENDER: stream all frames, then close.
	go func() {
		for i := 0; i < total; i++ {
			buf := make([]byte, 4)
			for j := range buf {
				buf[j] = byte(i % 251)
			}
			if err := WriteFrame(b, 1, FrameData, buf); err != nil {
				return
			}
		}
		_ = WriteFrame(b, 1, FrameClose, nil)
	}()

	// CONSUMER: deliberately slow (reads a little, then pauses), always well
	// under ConsumerStall. The pause is long enough that the dispatcher's
	// mailbox (primary + carry) overflows and it parks; the resume drains it.
	received := 0
	terminated := false
	hardCap := time.After(30 * time.Second) // runaway backstop only
	closeSeen := false
	for !closeSeen {
		select {
		case f := <-ch:
			if f == nil {
				terminated = true
				closeSeen = true
				break
			}
			want := byte(received % 251)
			if len(f) != 4 || f[0] != want {
				t.Fatalf("frame %d: corrupt payload len=%d first=%d want=%d (reorder/loss)",
					received, len(f), f[0], want)
			}
			received++
			// Slow-but-alive: a bounded pause, always < ConsumerStall.
			time.Sleep(2 * time.Millisecond)
		case <-hardCap:
			t.Fatalf("consumer hung: received %d/%d frames (terminated=%v)", received, total, terminated)
		}
		if terminated {
			// A real stream-end only arrives AFTER every data frame; the
			// pre-fix signature was an EARLY nil (mid-transfer termination).
			if received != total {
				t.Fatalf("stream terminated after only %d/%d frames — pre-fix truncation", received, total)
			}
		}
	}

	// (1) The FULL transfer completed in order.
	if received != total {
		t.Fatalf("delivered %d/%d frames: the transfer truncated (pre-fix ~1 MB signature)", received, total)
	}
	// (2) NO DATA frame was dropped on the down carrier.
	if dropped := atomic.LoadInt64(&stats.DroppedDataFrames); dropped != 0 {
		t.Fatalf("dropped_data_frames = %d, want 0 (the park released every frame in order)", dropped)
	}
	// (3) The mailbox genuinely overflowed to its ceiling — this is what
	// makes the test a real overflow reproducer, not a trivial pass.
	if high := atomic.LoadInt64(&stats.StreamQueuedFramesHigh); high < 2 {
		t.Fatalf("stream_queued_frames_high = %d, want >= 2 (the mailbox must have overflowed to park)", high)
	}
	// (4) No data-undeliverable escalation fired (the stream stayed alive).
	if n := undel.Load(); n != 0 {
		t.Fatalf("OnStreamDataUndeliverable fired %d times, want 0 (no termination under a live slow consumer)", n)
	}
	t.Logf("carry-exhaustion park: %d/%d frames delivered in order, frames_high=%d, dropped=%d, undel=%d",
		received, total,
		atomic.LoadInt64(&stats.StreamQueuedFramesHigh),
		atomic.LoadInt64(&stats.DroppedDataFrames), undel.Load())
}

// TestHealthyStreamDeliversInOrderNoDrops is the other half of the invariant:
// when the consumer keeps up (the mailbox has room), every DATA frame is
// delivered in order and NOTHING is dropped or overflow-terminated. This is
// the mechanism-B analogue of "a sub-OverflowWait stall that recovers leaves
// the DATA delivered in order with no overflow-termination increments."
func TestHealthyStreamDeliversInOrderNoDrops(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	c.SetStreamLimits(bpLimits(4, 4096, 4096, 50*time.Millisecond))
	s := buildWorkerlessStream(t, c, stats, 1, 4, 4096, 4096)

	// Deliver four frames in order, draining between so the mailbox (cap 4)
	// never fills: each frame is DELIVERED, not dropped.
	for i := 0; i < 4; i++ {
		c.deliver(s, queueItem{payload: []byte{byte('a' + i)}})
		it, ok := s.q.Pop()
		if !ok || string(it.payload) != string([]byte{byte('a' + i)}) {
			t.Fatalf("frame %d = %q ok=%v, want %q (in-order delivery)", i, it.payload, ok, byte('a'+i))
		}
	}
	if s.terminated.Load() {
		t.Fatal("healthy stream was terminated")
	}
	if got := atomic.LoadInt64(&stats.DroppedDataFrames); got != 0 {
		t.Fatalf("dropped_data_frames = %d on a healthy stream, want 0", got)
	}
	if got := atomic.LoadInt64(&stats.OverflowTerminations); got != 0 {
		t.Fatalf("overflow_terminations = %d on a healthy stream, want 0", got)
	}
}

// TestStreamCloseCarriedPreservesFIFO guards the retry-grace close path:
// a refused FrameClose (because the primary mailbox is full) is CARRIED
// into the queue's bounded carry region so the consumer still sees it AFTER
// every preceding DATA frame — never overtaken, never dropped. The stream
// stays alive and no DATA frame is counted as dropped.
func TestStreamCloseCarriedPreservesFIFO(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	c.SetStreamLimits(bpLimits(1, 4096, 4096, 50*time.Millisecond))
	s := buildWorkerlessStream(t, c, stats, 1, 1, 4096, 4096)

	if !s.q.TryPush(queueItem{payload: []byte("x")}) {
		t.Fatal("seed push to a 1-frame mailbox refused")
	}
	// A FrameClose cannot be queued (mailbox full). The retry-grace CARRIES
	// it so the consumer still sees the ordered half-close after "x".
	c.deliver(s, queueItem{isClose: true})

	// The carry must have accepted the close (0 payload bytes, fits any cap).
	if n := s.q.OverflowLen(); n != 1 {
		t.Fatalf("overflow_len = %d, want 1 (the carried close)", n)
	}
	// The stream must NOT be terminated: the close was carried, not lost.
	if s.terminated.Load() {
		t.Fatal("a carried FrameClose terminated the stream; it should preserve FIFO")
	}
	// No DATA frame was dropped (the close carries no bytes).
	if got := atomic.LoadInt64(&stats.DroppedDataFrames); got != 0 {
		t.Fatalf("dropped_data_frames = %d after a carried FrameClose, want 0", got)
	}

	// Drain in order: primary "x" first, then the carried close.
	it, ok := s.q.Pop()
	if !ok || it.isClose || string(it.payload) != "x" {
		t.Fatalf("first Pop = %+v ok=%v, want primary \"x\"", it, ok)
	}
	it, ok = s.q.Pop()
	if !ok || !it.isClose {
		t.Fatalf("second Pop = %+v ok=%v, want the carried close", it, ok)
	}
}
