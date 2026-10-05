package mux

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// These tests pin the consumer-stall behavior of the retry-grace DATA path
// across the OverflowWait boundary: a transient (zero-progress-bounded)
// refusal is CARRIED (the stream survives a brief stall — the ~1 MB
// download-truncation fix), while a SUSTAINED zero-progress stall (no
// carried frame makes it into the mailbox for the full OverflowWait)
// cleanly terminates the stream. They drive deliver() single-threaded
// (playing the dispatcher's role, exactly as deliver_fail_test.go does)
// over a workerless stream, so the consumer "stalls" by simply never
// calling Pop and every observation is deterministic — the bounded sleeps
// only model the stall durations.

// assertContiguousPrefix fails if got is not a CONTIGUOUS IN-ORDER PREFIX
// of sent — a hole/gap means a corrupted byte stream, the exact failure the
// deliver-or-fail policy exists to prevent.
func assertContiguousPrefix(t *testing.T, got, sent []string) {
	t.Helper()
	if len(got) > len(sent) {
		t.Fatalf("consumer received %d frames, %d sent", len(got), len(sent))
	}
	for i, g := range got {
		if g != sent[i] {
			t.Fatalf("consumer frame %d = %q, want %q (in-order prefix violated)", i, g, sent[i])
		}
	}
}

// seedStalledStream builds a workerless cap-4 stream (default byte
// budgets), pushes f0..f3, and pops f0 f1 in order (returned as got):
// the consumer is now stalled (no further Pop), the mailbox holds
// [f2 f3], and the full sent set is f0..f6 (f4 f5 f6 not yet pushed).
func seedStalledStream(t *testing.T, c *CarrierConn, stats *QueueStats) (*streamRec, [][]byte, []string, []string) {
	t.Helper()
	s := buildWorkerlessStream(t, c, stats, 1, 4, DefaultStreamLimits.MaxBytesPerStream, DefaultStreamLimits.MaxBytesTotal)
	payloads := make([][]byte, 7)
	sent := make([]string, 7)
	for i := 0; i < 7; i++ {
		payloads[i] = []byte{'f', byte('0' + i)}
		sent[i] = string(payloads[i])
	}
	for i := 0; i < 4; i++ {
		if !s.q.TryPush(queueItem{payload: payloads[i]}) {
			t.Fatalf("seed push %d to a 4-frame mailbox refused", i)
		}
	}
	var got []string
	for i := 0; i < 2; i++ {
		it, ok := s.q.Pop()
		if !ok {
			t.Fatal("Pop of the seeded mailbox returned closed")
		}
		if string(it.payload) != sent[i] {
			t.Fatalf("Pop %d = %q, want %q (in order)", i, it.payload, sent[i])
		}
		got = append(got, string(it.payload))
	}
	return s, payloads, sent, got
}

// pushToRefusal pushes f4 f5 (accepted: the mailbox reaches 4/4) and then
// drives f6 through the real dispatcher path, where the full mailbox
// refuses it — the deliver-or-fail trigger, never a silent drop.
func pushToRefusal(t *testing.T, c *CarrierConn, s *streamRec, payloads [][]byte) {
	t.Helper()
	for i := 4; i < 6; i++ {
		if !s.q.TryPush(queueItem{payload: payloads[i]}) {
			t.Fatalf("push %d refused while the mailbox had room", i)
		}
	}
	if s.q.TryPush(queueItem{payload: payloads[6]}) {
		t.Fatal("f6 unexpectedly fit the full mailbox")
	}
	c.deliver(s, queueItem{payload: payloads[6]})
}

// TestConsumerStallUnderOverflowWaitDeliversInOrderNoHole is the
// availability-regression tripwire for Mechanism B (fail-fast): stall the
// consumer (no Pop) for a fraction of OverflowWait (0.5x), let a DATA
// push be refused by mailbox capacity, then resume. The STRICT invariant
// that must always hold: whatever the consumer ultimately receives is a
// contiguous in-order PREFIX of what was sent — never a hole/gap — and,
// if the stream is aborted, the consumer observed the deterministic nil
// end.
func TestConsumerStallUnderOverflowWaitDeliversInOrderNoHole(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	// Default overflow wait with a tiny mailbox: the 0.5x stall below is
	// a fraction of the pressure deadline, so no pressure/worker
	// termination can have fired — only the DATA path may end the stream.
	limits := bpLimits(4, DefaultStreamLimits.MaxBytesPerStream, DefaultStreamLimits.MaxBytesTotal, DefaultStreamLimits.OverflowWait)
	c.SetStreamLimits(limits)

	s, payloads, sent, got := seedStalledStream(t, c, stats)

	var undel atomic.Int32
	c.OnStreamDataUndeliverable = func(uint32) { undel.Add(1) }
	// STALL: the consumer keeps not popping for 0.5 x OverflowWait. The
	// sleep is a bounded stall model, not an assertion dependency: after
	// it, the mailbox still holds [f2 f3] and nothing has terminated.
	time.Sleep(limits.OverflowWait / 2)

	// Resume + refusal: the next DATA frames fill the mailbox, and f6 is
	// refused by it. Drive it through the dispatcher path: the retry-grace
	// CARRIES f6 across the window instead of killing the stream.
	pushToRefusal(t, c, s, payloads)

	// The sub-wait refusal must LEAVE THE STREAM ALIVE and carry f6 — the
	// retry-grace (the FUTURE follow-up this test now pins). Nothing is
	// dropped and no undeliverable callback has fired.
	if s.terminated.Load() {
		t.Fatal("a sub-OverflowWait refusal terminated the stream; the retry-grace should have carried the frame")
	}
	if n := atomic.LoadInt64(&stats.DroppedDataFrames); n != 0 {
		t.Fatalf("dropped_data_frames = %d, want 0 (the refused frame was carried, not dropped)", n)
	}
	if n := undel.Load(); n != 0 {
		t.Fatalf("OnStreamDataUndeliverable fired %d times, want 0 (no escalation yet)", n)
	}

	// RESUME the consumer: drain the mailbox in order (f2..f5). While the
	// consumer is draining, the carried f6 sits in the overflow region and
	// must be served BEFORE anything newer. Pop drains the primary first
	// (f2..f5) and only then falls through to the carry.
	for i := 2; i < len(sent)-1; i++ {
		it, ok := s.q.Pop()
		if !ok {
			t.Fatalf("Pop %d returned closed", i)
		}
		if string(it.payload) != sent[i] {
			t.Fatalf("Pop %d = %q, want %q (in order)", i, it.payload, sent[i])
		}
		got = append(got, string(it.payload))
	}
	// With the primary drained, Pop falls through to the carry: the
	// carried f6 must surface NEXT — before the sender's close.
	it, ok := s.q.Pop()
	if !ok || string(it.payload) != sent[len(sent)-1] {
		t.Fatalf("carry flush: Pop = %q ok=%v, want the carried last frame %q", it.payload, ok, sent[len(sent)-1])
	}
	got = append(got, string(it.payload))
	// The sender's end-of-data close: both regions are now empty, so it is
	// pushed to the (empty) primary and must surface as the final item —
	// it can never overtake the already-drained carried f6.
	c.deliver(s, queueItem{isClose: true})
	it, ok = s.q.Pop()
	if !ok || !it.isClose {
		t.Fatalf("close flush: Pop = %+v ok=%v, want the carried close", it, ok)
	}

	// INVARIANT: everything delivered is the FULL in-order set — no hole,
	// no loss (the retry-grace's whole point: a transient stall survives).
	if len(got) != len(sent) {
		t.Fatalf("delivered %d of %d frames, want the FULL in-order set", len(got), len(sent))
	}
	for i, g := range got {
		if g != sent[i] {
			t.Fatalf("frame %d = %q, want %q (in-order delivery violated)", i, g, sent[i])
		}
	}
}

// TestDeadConsumerIsReclaimedNotDataUndeliverable pins the SUBTASK-30
// taxonomy: a consumer that STOPS READING its channel (a relay that exited
// or a session that closed — a DEAD consumer, not a slow-but-alive one) is
// reclaimed by the WORKER's ConsumerStall timer and classified as an
// OVERFLOW termination (OnStreamTerminated), NOT as a data-integrity loss
// (OnStreamDataUndeliverable). While the dispatcher is parked waiting for
// the (dead) consumer to drain the mailbox, the worker's clean reclaim
// closes the mailbox, releases the parked dispatcher, and its guard
// suppresses any data-undeliverable mislabel.
//
// This is the exact complement of TestCarryExhaustionParksThenDeliversIn
// Order: a SLOW-LIVE consumer parks and completes (no termination); a DEAD
// consumer is bounded-reclaimed (overflow, not data loss).
func TestDeadConsumerIsReclaimedNotDataUndeliverable(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	// Tiny mailbox (primary 2 frames of 4 B + carry 4 B) so the dispatcher
	// parks quickly; a small ConsumerStall so the DEAD consumer is reclaimed
	// fast and deterministically.
	limits := bpLimits(2, 4, 1<<20, 100*time.Millisecond)
	limits.ConsumerStall = 300 * time.Millisecond
	_ = c.SetStreamLimits(limits)

	var terminated, undel atomic.Int32
	c.OnStreamTerminated = func(uint32) { terminated.Add(1) }
	c.OnStreamDataUndeliverable = func(uint32) { undel.Add(1) }

	// A registered stream has a real worker (the reclaim path). The
	// consumer below is DEAD: it never reads ch, so ch (cap 1) fills and the
	// worker blocks, then reclaims the stream after ConsumerStall.
	_ = c.Register(1)
	go c.Dispatch()

	// SENDER: outpace the dead consumer so the mailbox (primary+carry)
	// fills and the dispatcher parks in PushPark.
	go func() {
		for i := 0; i < 16; i++ {
			if err := WriteFrame(b, 1, FrameData, []byte{byte(i), 0, 0, 0}); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	// Wait for the worker's ConsumerStall reclaim to terminate the stream.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		s, ok := c.streams[1]
		c.mu.Unlock()
		if ok && s.terminated.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.mu.Lock()
	s, ok := c.streams[1]
	c.mu.Unlock()
	if !ok || !s.terminated.Load() {
		t.Fatalf("dead consumer was not reclaimed within 2s (terminated=%v)", ok && s.terminated.Load())
	}

	// The reclaim was the WORKER's ConsumerStall path: exactly one worker
	// overflow termination, and the generic OnStreamTerminated fired.
	if n := atomic.LoadInt64(&stats.OverflowTerminationsWorker); n != 1 {
		t.Fatalf("overflow_terminations_worker = %d, want 1 (the dead-consumer reclaim)", n)
	}
	if n := terminated.Load(); n != 1 {
		t.Fatalf("OnStreamTerminated fired %d times, want exactly 1", n)
	}
	// The KEY assertion: a dead consumer is an OVERFLOW/stall, NOT a
	// data-integrity loss — the parked dispatcher's guard suppressed the
	// data-undeliverable classification.
	if n := undel.Load(); n != 0 {
		t.Fatalf("OnStreamDataUndeliverable fired %d times, want 0 (a dead consumer is a stall, not lost data)", n)
	}
}
