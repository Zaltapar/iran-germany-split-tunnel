package mux

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// TestSlowConsumerParksNotTerminates is the SUBTASK-30 slow-consumer
// reproducer: a consumer that deliberately reads SLOWLY (a bounded pause
// between every frame, well under the 30 s ConsumerStall but long enough
// that a fast sender overflows the mailbox) is served a transfer large
// enough to overflow BOTH the primary mailbox AND the carry region many
// times over.
//
// Pre-fix: the dispatcher's carry-then-terminate escalation killed the
// stream the moment the carry cap filled, and the worker's 100 ms
// OverflowWait handoff deadline killed it too — the ~2–3.5 MB truncation.
// Post-fix: the dispatcher PARKS in PushPark and the worker's handoff is
// bounded by ConsumerStall, so the slow consumer is paced, NOT killed.
// The transfer COMPLETES with the full byte count, zero dropped frames,
// zero terminations.
//
// The assertion is on the FULL byte count delivered (the "the transfer
// COMPLETES" requirement), not just on invariants holding.
func TestSlowConsumerParksNotTerminates(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()

	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)

	// Production-shaped mailbox: 16 frames / 704 KiB per stream, 16 MiB
	// aggregate (the DefaultStreamLimits bounds). A 4 MiB transfer is 4×
	// the per-stream mailbox, so the dispatcher must park repeatedly.
	limits := DefaultStreamLimits
	limits.OverflowWait = 100 * time.Millisecond // sender pacing (unchanged)
	// ConsumerStall stays at the default 30 s: the slow consumer below is
	// ALWAYS well under it, so no reclaim can fire mid-transfer.
	_ = c.SetStreamLimits(limits)

	ch := c.Register(1)
	go c.Dispatch()

	// SENDER: stream 4 MiB (64 full frames of MaxPayload) outpacing the
	// consumer, then close.
	const totalFrames = 64
	go func() {
		for i := 0; i < totalFrames; i++ {
			buf := make([]byte, MaxPayload)
			for j := range buf {
				buf[j] = byte(i % 251)
			}
			if err := WriteFrame(b, 1, FrameData, buf); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
		_ = WriteFrame(b, 1, FrameClose, nil)
	}()

	// CONSUMER: deliberately slow — a 5 ms pause after every frame. The
	// pause is far under ConsumerStall (30 s) so the consumer is alive;
	// it is long enough that the 16-frame/704 KiB mailbox (primary + carry
	// ≈ 1.4 MiB) overflows many times over while 4 MiB is streamed, which
	// is exactly what forces the dispatcher into PushPark.
	const consumerPause = 5 * time.Millisecond
	received := 0
	terminated := false
	closeSeen := false
	hardCap := time.After(60 * time.Second) // runaway backstop only
	for !closeSeen {
		select {
		case f := <-ch:
			if f == nil {
				terminated = true
				closeSeen = true
				break
			}
			// Integrity: each frame is the correct per-frame signature.
			want := byte(received % 251)
			if len(f) != MaxPayload || f[0] != want || f[MaxPayload-1] != want {
				t.Fatalf("frame %d: wrong payload (len=%d, first=%d want=%d) — data corruption/reorder",
					received, len(f), f[0], want)
			}
			received++
			time.Sleep(consumerPause)
		case <-hardCap:
			t.Fatalf("consumer hung: received %d/%d frames (terminated=%v)", received, totalFrames, terminated)
		}
		if terminated {
			// A real stream-end only arrives AFTER every data frame; a
			// pre-fix signature was an EARLY nil (mid-transfer truncation).
			if received != totalFrames {
				t.Fatalf("stream terminated after only %d/%d frames — pre-fix slow-consumer truncation "+
					"(dropped_data_frames=%d)", received, totalFrames,
					atomic.LoadInt64(&stats.DroppedDataFrames))
			}
		}
	}

	// (1) The FULL 4 MiB transfer completed in order.
	if received != totalFrames {
		t.Fatalf("delivered %d/%d frames: the slow-consumer transfer truncated", received, totalFrames)
	}
	// (2) No in-order DATA frame was dropped on the down carrier.
	if dropped := atomic.LoadInt64(&stats.DroppedDataFrames); dropped != 0 {
		t.Fatalf("dropped_data_frames = %d, want 0 (the dispatcher parked and released every frame)", dropped)
	}
	// (3) The stream was never terminated (a slow-but-alive consumer is
	// paced, not killed).
	if n := atomic.LoadInt64(&stats.OverflowTerminationsWorker); n != 0 {
		t.Fatalf("overflow_terminations_worker = %d, want 0 (a live slow consumer is never reclaimed)", n)
	}
	// (4) The primary mailbox genuinely overflowed to near its byte ceiling —
	// this is what makes the test a real overflow reproducer (the park path
	// is exercised), not a trivial pass. The 704 KiB per-stream BYTE bound is
	// hit before the 16-frame bound (11 full frames = 720,885 bytes), so the
	// deterministic marker is the byte high-water mark reaching at least 10
	// full frames. Host-independent: the sender outpaces the consumer 5:1,
	// so the primary fills to its byte ceiling regardless of host speed.
	if high := atomic.LoadInt64(&stats.StreamQueuedBytesHigh); high < 10*MaxPayload {
		t.Fatalf("stream_queued_bytes_high = %d, want >= %d (10 full frames) — the mailbox must overflow to force the park",
			high, 10*MaxPayload)
	}
	t.Logf("slow-consumer park: %d/%d frames (%d MiB) delivered in order, "+
		"mailbox bytes_high=%d frames_high=%d, dropped=%d",
		received, totalFrames, totalFrames*MaxPayload>>20,
		atomic.LoadInt64(&stats.StreamQueuedBytesHigh),
		atomic.LoadInt64(&stats.StreamQueuedFramesHigh),
		atomic.LoadInt64(&stats.DroppedDataFrames))
}
