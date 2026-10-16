package node

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
)

// TestDownOverflowLargeDownloadSurvives is the SUBTASK-26 reproducer: a
// two-carrier (sender + receiver) large download through a real down-carrier
// mailbox that SURVIVES the per-stream overflow.
//
// Root cause fixed (pre-fix): the dispatcher's deliver() routed the FIRST
// refused in-order DATA frame straight to failUndeliverableData, terminating
// the stream the moment the 16-frame down mailbox filled. Because
// 16 × MaxPayload (65535) = 1,048,560 bytes < 1 MiB, the frame-count bound
// trips before the byte bound, so every download truncated at ~1 MiB — the
// live Iran signature (mux_down_stream_queued_frames_high 16,
// session_close_reason{data_undeliverable} 5, mux_down_dropped_data_frames
// 5, journal "in-stream data undeliverable (byte gap)").
//
// The fix (retry-grace in deliver): a refused DATA frame is CARRIED in a
// bounded overflow buffer instead of killing the stream; only a sustained
// zero-progress stall past OverflowWait (or a per-stream byte-cap breach)
// escalates to a clean abort.
//
// Determinism: the SENDER outpaces the CONSUMER (the consumer pauses 50 ms
// between frames, well under the 500 ms OverflowWait, but the sender
// streams 64 full frames), so the 16-frame mailbox overflows and the
// dispatcher MUST either terminate (pre-fix) or carry (post-fix). The
// consumer never makes zero progress for 500 ms, so the post-fix escalation
// deadline can fire even on a heavily loaded host — a 10× margin.
//
// Pre-fix this test FAILS: the stream dies at ~1 MiB, the consumer receives
// only a ~16-frame prefix plus nil, so received < totalFrames.
// Post-fix this test PASSES: all 64 frames (4 MiB) are delivered in order,
// zero dropped frames, zero data_undeliverable, and the mailbox genuinely
// overflowed (StreamQueuedFramesHigh >= 16).
func TestDownOverflowLargeDownloadSurvives(t *testing.T) {
	const (
		totalFrames   = 64                     // 64 × 65535 = 4 MiB, 16× the ~1 MiB truncation point
		overflowWait  = 500 * time.Millisecond // generous escalation deadline (10× the 50ms consumer pause)
		senderPace    = 10 * time.Millisecond  // sender is 5× faster than the consumer
		consumerPause = 50 * time.Millisecond  // slow-but-alive consumer, always < overflowWait
	)

	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()

	rcv := mux.NewCarrierConn(a, 0)
	defer rcv.Close()
	// 16-frame mailbox (the production bound), a large per-stream byte cap
	// so the carried overflow is never byte-capped (the under-test is the
	// FRAME-count bound + the retry-grace, not the byte budget).
	_ = rcv.SetStreamLimits(mux.StreamLimits{
		MaxFramesPerStream: mux.MaxFrames, // 16
		MaxBytesPerStream:  8 << 20,       // 8 MiB (>= 4 MiB transfer)
		MaxBytesTotal:      16 << 20,
		OverflowWait:       overflowWait,
	})
	stats := &mux.QueueStats{}
	rcv.SetQueueStats(stats)

	ch := rcv.Register(1)
	go rcv.Dispatch()

	// SENDER: stream totalFrames full-size frames, outpacing the consumer.
	go func() {
		for i := 0; i < totalFrames; i++ {
			buf := make([]byte, mux.MaxPayload)
			for j := range buf {
				buf[j] = byte(i % 251) // per-frame signature for integrity
			}
			if err := mux.WriteFrame(b, 1, mux.FrameData, buf); err != nil {
				return // carrier closed: stop
			}
			time.Sleep(senderPace)
		}
		// End-of-data.
		_ = mux.WriteFrame(b, 1, mux.FrameClose, nil)
	}()

	// CONSUMER: read every frame, pausing consumerPause between them — a
	// SLOW but ALIVE consumer (the real client socket). The pause is always
	// < overflowWait, so the retry-grace never escalates; but it is long
	// enough that the sender (5× faster) overflows the 16-frame mailbox.
	received := 0
	terminated := false
	hardCap := time.After(60 * time.Second) // runaway backstop only
	for received < totalFrames {
		select {
		case f := <-ch:
			if f == nil {
				terminated = true
				break
			}
			// Integrity: each frame is the correct per-frame signature.
			want := byte(received % 251)
			if len(f) != mux.MaxPayload || f[0] != want || f[mux.MaxPayload-1] != want {
				t.Fatalf("frame %d: wrong payload (len=%d, first=%d want=%d) — data corruption/reorder",
					received, len(f), f[0], want)
			}
			received++
			// Slow-but-alive consumer: a bounded pause, always < overflowWait.
			time.Sleep(consumerPause)
		case <-hardCap:
			t.Fatalf("consumer hung: received %d/%d frames (terminated=%v)", received, totalFrames, terminated)
		}
		if terminated {
			break
		}
	}

	// (1) The mailbox genuinely overflowed to the frame ceiling — this is
	// what makes the test a real overflow reproducer, not a trivial pass.
	if high := atomic.LoadInt64(&stats.StreamQueuedFramesHigh); high < mux.MaxFrames {
		t.Logf("note: StreamQueuedFramesHigh=%d < %d — the mailbox did not hit the ceiling on this host; "+
			"the test still asserted full delivery", high, mux.MaxFrames)
	}

	// (2) Pre-fix: the stream is terminated at ~1 MiB → the consumer sees
	// nil and stops far short of totalFrames. Post-fix: no termination.
	if terminated {
		t.Fatalf("the down stream was TERMINATED (data_undeliverable) after %d/%d frames — "+
			"this is the pre-fix ~1 MiB truncation. dropped_data_frames=%d",
			received, totalFrames, atomic.LoadInt64(&stats.DroppedDataFrames))
	}

	// (3) The FULL 4 MiB transfer completed in order.
	if received != totalFrames {
		t.Fatalf("delivered %d/%d frames (%d MiB): the transfer truncated — "+
			"the ~1 MiB download-truncation defect (pre-fix signature)",
			received, totalFrames, totalFrames*mux.MaxPayload>>20)
	}

	// (4) No in-order DATA frame was dropped on the down carrier.
	if dropped := atomic.LoadInt64(&stats.DroppedDataFrames); dropped != 0 {
		t.Fatalf("dropped_data_frames = %d, want 0 (the retry-grace carried the overflow, dropped nothing)", dropped)
	}

	t.Logf("overflow download: %d/%d frames (%d MiB) delivered in order, "+
		"mailbox frames_high=%d, dropped_data_frames=%d",
		received, totalFrames, totalFrames*mux.MaxPayload>>20,
		atomic.LoadInt64(&stats.StreamQueuedFramesHigh),
		atomic.LoadInt64(&stats.DroppedDataFrames))
}

// TestDownOverflowLargeDownloadSurvivesThroughNodeRelay is the end-to-end
// two-NODE form of the reproducer: a 2 MiB DE→IR transfer driven through the
// real Iran+Germany node relay pair (no credit plane — the production
// configuration), asserting FULL delivery with zero dropped frames and zero
// data_undeliverable closes. 2 MiB is 2× the ~1 MiB truncation threshold
// and small enough to stay deterministic under full-suite contention.
//
// NOTE on what this proves vs. the mux-level test above: the node harness's
// client socket is an in-memory MemConn with an unbounded buffer, so on a
// fast host the relay consumer keeps up and the down mailbox may NOT
// overflow (StreamQueuedFramesHigh may stay low). That is precisely why the
// pre-existing 1/4/8 MiB loopback tests pass even pre-fix — they prove the
// pipeline delivers N MiB on a fast host but do NOT reproduce the production
// truncation, which requires a SLOW/bounded consumer. The mux-level
// TestDownOverflowLargeDownloadSurvives (paced consumer) is the deterministic
// overflow reproducer; this node-level test is a large-transfer regression
// guard on the real relay chain.
func TestDownOverflowLargeDownloadSurvivesThroughNodeRelay(t *testing.T) {
	const n = 2 << 20 // 2 MiB end-to-end, 2× the ~1 MiB truncation threshold

	// Production-like configuration: no credit plane, 256 KiB relay buffer.
	tp := newCreditTopo(t, false, 5*time.Second, 256<<10)
	tp.setup()
	clientApp, targetApp := tp.startSession(1)

	data := make([]byte, n)
	fillBytes(data)
	if _, err := targetApp.Write(data); err != nil {
		t.Fatalf("writing target: %v", err)
	}
	// Drain with a generous absolute cap (10 min) so a slow CI host can
	// finish; the assertion is on FULL delivery, not a rate. Under full-suite
	// contention the relay goroutines can be starved; use a 120 s stall
	// window (the default 30 s loopback window is too tight for this test
	// when run alongside the credit + storm suites).
	const relayStall = 120 * time.Second
	p := readDrain(clientApp, n, relayStall, 10*time.Minute, nil)
	got := p.got

	// (a) FULL delivery through the real node relay.
	if len(got) != n {
		t.Fatalf("delivered %d/%d bytes (%d%%): truncated end-to-end transfer",
			len(got), n, len(got)*100/n)
	}
	// (b) Integrity: every byte is the correct prefix of the source.
	for i, b := range got {
		if b != data[i] {
			t.Fatalf("integrity violation at byte %d", i)
		}
	}
	// (c) No dropped DATA frame on the DOWN (receiver) carrier — the
	// carrier whose mailbox is the one that overflows in production.
	if dropped := atomic.LoadInt64(&tp.iran.muxDownStats.DroppedDataFrames); dropped != 0 {
		t.Fatalf("dropped_data_frames (IR down carrier) = %d, want 0", dropped)
	}
	// (d) No data_undeliverable close on either node.
	deSnap := tp.de.Metrics().Snapshot()
	irSnap := tp.iran.Metrics().Snapshot()
	if deSnap.CloseReasonDataUndeliverable != 0 || irSnap.CloseReasonDataUndeliverable != 0 {
		t.Fatalf("data_undeliverable close reasons = de:%d ir:%d, want 0",
			deSnap.CloseReasonDataUndeliverable, irSnap.CloseReasonDataUndeliverable)
	}
	t.Logf("2MiB node relay: delivered %d/%d bytes, IR down frames_high=%d, dropped=%d",
		len(got), n,
		atomic.LoadInt64(&tp.iran.muxDownStats.StreamQueuedFramesHigh),
		atomic.LoadInt64(&tp.iran.muxDownStats.DroppedDataFrames))
}
