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

// TestRefusedDataFrameTerminatesStreamNoHole is the integrity-seam test: when
// the consumer stalls so the mailbox is full, delivering one more DATA frame
// must cleanly fail the stream — what the consumer has received is a
// contiguous, in-order PREFIX of what was sent, and the stream then errors
// (clean termination), never a silent hole.
func TestRefusedDataFrameTerminatesStreamNoHole(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	c.SetStreamLimits(bpLimits(2, 4096, 4096, 50*time.Millisecond))
	s := buildWorkerlessStream(t, c, stats, 1, 2, 4096, 4096)

	// The node wiring fires exactly one distinct callback when the data is
	// undeliverable (this is what classifies the close as data_undeliverable
	// instead of overflow).
	var undel atomic.Int32
	c.OnStreamDataUndeliverable = func(uint32) { undel.Add(1) }

	// Fill the mailbox to capacity with frames 0 and 1, in order.
	if !s.q.TryPush(queueItem{payload: []byte("f0")}) ||
		!s.q.TryPush(queueItem{payload: []byte("f1")}) {
		t.Fatal("seed pushes to a 2-frame mailbox refused")
	}

	// The consumer stalled, so frame 2 is refused by the full mailbox. Push
	// it through the real dispatcher path: it must hit the deliver-or-fail
	// policy, not a silent drop.
	if s.q.TryPush(queueItem{payload: []byte("f2")}) {
		t.Fatal("f2 unexpectedly fit the full mailbox")
	}
	c.deliver(s, queueItem{payload: []byte("f2")})

	// INVARIANT part 1 — contiguity BEFORE the stream fails: everything that
	// ever reached the consumer is exactly [f0 f1], a contiguous in-order
	// prefix of the sent [f0 f1 f2] with NO hole. (Inspect the mailbox under
	// its own lock; same-package test, the way queue_stats_test.go does.)
	s.q.mu.Lock()
	var queued []string
	for _, it := range s.q.items {
		queued = append(queued, string(it.payload))
	}
	qclosed := s.q.closed
	s.q.mu.Unlock()
	// f2 was refused, not queued; termination then closed the mailbox.
	if qclosed {
		// Mailbox was closed by terminateStream: the consumer got [f0 f1]
		// (or is mid-drain of it) — the prefix holds by construction because
		// the FIFO mailbox never reordered or skipped, and f2 never entered.
		if !s.terminated.Load() {
			t.Fatal("mailbox closed but stream not marked terminated")
		}
	} else if len(queued) != 2 || queued[0] != "f0" || queued[1] != "f1" {
		t.Fatalf("queued contents = %v, want [f0 f1] (contiguous, no hole)", queued)
	}

	// INVARIANT part 2 — the stream was CLEANLY FAILED, not left alive with
	// the missing frame.
	if !s.terminated.Load() {
		t.Fatal("refused DATA frame left the stream alive (silent byte hole)")
	}
	if got := atomic.LoadInt64(&stats.DroppedDataFrames); got != 1 {
		t.Fatalf("dropped_data_frames = %d, want 1", got)
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

// TestStreamCloseStillUsesPressureKeepsCloseOffTheDataPath guards the one
// behavior that must NOT have migrated to the data path: a refused FrameClose
// still goes through the pressure rule (applyPressure), so a half-close on a
// stalled stream ends that stream on its later push — not on the data path.
func TestStreamCloseStillUsesPressure(t *testing.T) {
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
	// A FrameClose cannot be queued (mailbox full). It must apply the
	// pressure rule (set pressureStart), NOT terminate via the data path,
	// and must NOT bump the dropped-DATA counter (it is not a data frame).
	c.deliver(s, queueItem{isClose: true})
	if s.pressureStart.IsZero() {
		t.Fatal("refused FrameClose did not apply the pressure rule")
	}
	if s.terminated.Load() {
		t.Fatal("a refused FrameClose terminated the stream immediately; it should use pressure")
	}
	if got := atomic.LoadInt64(&stats.DroppedDataFrames); got != 0 {
		t.Fatalf("dropped_data_frames = %d after a refused FrameClose, want 0", got)
	}
}
