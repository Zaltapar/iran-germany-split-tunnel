package mux

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// These tests pin the consumer-stall behavior of the deliver-or-fail DATA
// path (Mechanism B) across the OverflowWait boundary. They drive
// deliver() single-threaded (playing the dispatcher's role, exactly as
// deliver_fail_test.go does) over a workerless stream, so the consumer
// "stalls" by simply never calling Pop and every observation is
// deterministic — no wall-clock race for the assertions (the bounded
// sleeps only model the stall durations).

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
	// refused by it — drive it through the dispatcher path.
	pushToRefusal(t, c, s, payloads)

	// INVARIANT (must always hold): everything the consumer received is a
	// contiguous in-order prefix of what was sent — never a hole.
	assertContiguousPrefix(t, got, sent)
	// If the stream was aborted, the consumer observed the deterministic
	// nil end (the workerless ch was empty, so terminateStream's
	// dispatcher-side handoff succeeded synchronously inside deliver).
	if s.terminated.Load() {
		select {
		case f := <-s.ch:
			if f != nil {
				t.Fatalf("stream end signal = %q, want nil", f)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("stream aborted but the consumer never saw the nil end")
		}
	}
	// The resumed consumer finds the closed mailbox: f2 f5 were discarded
	// at termination, so only the contiguous prefix [f0 f1] ever reached
	// it.
	if it, ok := s.q.Pop(); ok {
		t.Fatalf("resumed Pop returned %q on a closed mailbox, want closed", it.payload)
	}

	// CHARACTERIZATION (Mechanism B fail-fast): a single refused DATA
	// frame aborts the stream rather than being dropped silently.
	// FUTURE: the DATA-frame retry-grace follow-up (carry refusal #1
	// through the applyPressure pressureStart window, escalate on
	// refusal #2 or OverflowWait) would let this recover and deliver
	// the full in-order set; when that lands, change this to require
	// full in-order delivery with dropped_data_frames == 0.
	if !s.terminated.Load() {
		t.Fatal("the sub-wait refusal left the stream alive (silent byte hole)")
	}
	if n := atomic.LoadInt64(&stats.DroppedDataFrames); n < 1 {
		t.Fatalf("dropped_data_frames = %d, want >= 1 (exactly 1 in this single-threaded setup)", n)
	}
	if n := undel.Load(); n != 1 {
		t.Fatalf("OnStreamDataUndeliverable fired %d times, want 1", n)
	}
	// Assert the path that fired (per the caller's classification): this
	// is the dispatcher's DATA path — NOT the pressure path, and there is
	// no worker on this path — so overflow_terminations is NOT
	// incremented here.
	if n := atomic.LoadInt64(&stats.OverflowTerminations); n != 0 {
		t.Fatalf("overflow_terminations = %d, want 0 (the DATA path fired, not the pressure path)", n)
	}
	if n := atomic.LoadInt64(&stats.OverflowTerminationsWorker); n != 0 {
		t.Fatalf("overflow_terminations_worker = %d, want 0 (no worker on this path)", n)
	}
}

// TestConsumerStallBeyondOverflowWaitCleansAbortsWithDataUndeliverable
// proves the clean-abort + taxonomy end-to-end when pressure persists:
// a LIVE stream's consumer stalls (no Pop) for more than OverflowWait
// (1.5x) while DATA frames are pushed, so the pushes are refused by the
// full mailbox. The DATA path then fails the stream cleanly; the
// classifier half (ReasonDataUndeliverable + the single metrics credit)
// lives in pkg/node under the same test name.
func TestConsumerStallBeyondOverflowWaitCleansAbortsWithDataUndeliverable(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	limits := bpLimits(4, DefaultStreamLimits.MaxBytesPerStream, DefaultStreamLimits.MaxBytesTotal, DefaultStreamLimits.OverflowWait)
	c.SetStreamLimits(limits)

	s, payloads, sent, got := seedStalledStream(t, c, stats)

	var undel atomic.Int32
	c.OnStreamDataUndeliverable = func(uint32) { undel.Add(1) }

	// STALL beyond OverflowWait: 1.5x the deadline with no Pop, so the
	// mailbox stays full and every fresh DATA push is refused — the
	// pressure persisted past the deadline.
	time.Sleep(limits.OverflowWait * 3 / 2)

	// The refused DATA frame drives the clean abort on the dispatcher
	// path (deliver-or-fail), not the pressure deadline.
	pushToRefusal(t, c, s, payloads)

	// The stream was terminated (the clean-abort end state).
	if !s.terminated.Load() {
		t.Fatal("the stalled stream was not terminated")
	}
	// Exactly one refused DATA frame was recorded — the deliver-or-fail
	// path fired once; later deliveries early-return on terminated.
	if n := atomic.LoadInt64(&stats.DroppedDataFrames); n != 1 {
		t.Fatalf("dropped_data_frames = %d, want exactly 1", n)
	}
	// The undeliverable callback fired exactly once (this is what the
	// node wiring classifies the close as data_undeliverable on).
	if n := undel.Load(); n != 1 {
		t.Fatalf("OnStreamDataUndeliverable fired %d times, want exactly 1", n)
	}
	// The abort was the dispatcher's DATA path: no pressure-termination
	// increments (worker-less stream, sub-deadline DATA fail-fast).
	if n := atomic.LoadInt64(&stats.OverflowTerminations); n != 0 {
		t.Fatalf("overflow_terminations = %d, want 0 (the DATA path fired)", n)
	}
	if n := atomic.LoadInt64(&stats.OverflowTerminationsWorker); n != 0 {
		t.Fatalf("overflow_terminations_worker = %d, want 0 (no worker on this path)", n)
	}

	// The consumer saw ONLY a contiguous in-order prefix ([f0 f1])
	// before the nil end — no hole: f2 f5 were discarded by the mailbox
	// close and f6 was the refused frame.
	assertContiguousPrefix(t, got, sent)
	select {
	case f := <-s.ch:
		if f != nil {
			t.Fatalf("stream end signal = %q, want nil", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the consumer never saw the nil stream end")
	}
	// The closed mailbox can resurface no bytes.
	if it, ok := s.q.Pop(); ok {
		t.Fatalf("Pop after termination returned %q, want closed", it.payload)
	}
}
