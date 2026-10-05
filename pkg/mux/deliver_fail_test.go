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

// TestRefusedDataFrameCarriedThenCarryCapExhaustedTerminatesNoHole is the
// integrity-seam test for the retry-grace: when the consumer stalls so the
// mailbox is full, refused DATA frames are CARRIED into the queue's bounded
// carry region (the stream stays alive — the ~1 MB download-truncation fix).
// Only when the carry cap itself is exhausted does the dispatcher escalate
// to a clean abort. Whatever the consumer has received is a contiguous,
// in-order PREFIX of what was sent — never a silent hole.
func TestRefusedDataFrameCarriedThenCarryCapExhaustedTerminatesNoHole(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	// Primary cap = 2 frames; carry cap = 8 payload bytes = 4 frames of 2 B.
	// This keeps the test deterministic without pushing thousands of frames.
	c.SetStreamLimits(bpLimits(2, 8, 64, 50*time.Millisecond))
	s := buildWorkerlessStream(t, c, stats, 1, 2, 8, 64)

	// The node wiring fires exactly one distinct callback when the data is
	// undeliverable (this is what classifies the close as data_undeliverable
	// instead of overflow).
	var undel atomic.Int32
	c.OnStreamDataUndeliverable = func(uint32) { undel.Add(1) }

	// Fill the mailbox to capacity with f0 f1.
	if !s.q.TryPush(queueItem{payload: []byte("f0")}) ||
		!s.q.TryPush(queueItem{payload: []byte("f1")}) {
		t.Fatal("seed pushes to a 2-frame mailbox refused")
	}

	// f2 is refused by the full mailbox → carried (retry-grace).
	if s.q.TryPush(queueItem{payload: []byte("f2")}) {
		t.Fatal("f2 unexpectedly fit the full mailbox")
	}
	c.deliver(s, queueItem{payload: []byte("f2")})

	// The first refusal must NOT terminate the stream (the ~1 MB truncation
	// was exactly this fail-fast); f2 sits in the carry, undropped.
	if s.terminated.Load() {
		t.Fatal("a single refused DATA frame terminated the stream; the retry-grace must carry it")
	}
	if got := atomic.LoadInt64(&stats.DroppedDataFrames); got != 0 {
		t.Fatalf("dropped_data_frames = %d, want 0 (f2 is carried, not dropped)", got)
	}
	if got := undel.Load(); got != 0 {
		t.Fatalf("OnStreamDataUndeliverable fired %d times, want 0 (no escalation yet)", got)
	}

	// f3 f4 f5: each is carried, filling the 8-byte carry cap to the brim.
	for _, p := range []string{"f3", "f4", "f5"} {
		c.deliver(s, queueItem{payload: []byte(p)})
		if s.terminated.Load() {
			t.Fatalf("frame %q terminated the stream before the carry cap was exhausted", p)
		}
	}
	// Carry now holds [f2 f3 f4 f5] = 8 bytes = cap.
	if n := s.q.OverflowDataLen(); n != 4 {
		t.Fatalf("overflow_data = %d, want 4 (f2..f5 carried)", n)
	}

	// f6 cannot be carried (8+2 > 8): the dispatcher escalates to a clean
	// abort. The 4 carried DATA frames are the lost bytes.
	c.deliver(s, queueItem{payload: []byte("f6")})

	// INVARIANT part 1 — the stream was cleanly failed.
	if !s.terminated.Load() {
		t.Fatal("exhausted carry cap did not terminate the stream")
	}
	s.q.mu.Lock()
	qclosed := s.q.closed
	s.q.mu.Unlock()
	if !qclosed {
		t.Fatal("the escalation did not close the mailbox")
	}

	// INVARIANT part 2 — accounting: 2 primary (f0 f1) + 4 carried (f2..f5)
	// + 1 triggering (f6) = 7 lost DATA frames.
	if got := atomic.LoadInt64(&stats.DroppedDataFrames); got != 7 {
		t.Fatalf("dropped_data_frames = %d, want 7 (2 primary + 4 carried + 1 triggering)", got)
	}
	if got := undel.Load(); got != 1 {
		t.Fatalf("OnStreamDataUndeliverable fired %d times, want 1", got)
	}
	// The consumer is notified of the clean stream end (nil), the same
	// signal as a FrameClose — so the down relay closes, not corrupts.
	select {
	case f := <-s.ch:
		if f != nil {
			t.Fatalf("stream end signal = %q, want nil", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("consumer never received the clean stream-end signal")
	}
	// The closed mailbox can resurface no bytes.
	if it, ok := s.q.Pop(); ok {
		t.Fatalf("Pop after termination returned %q, want closed", it.payload)
	}
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
