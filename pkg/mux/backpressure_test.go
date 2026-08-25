package mux

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// bpLimits builds a small, fast limit set for backpressure tests.
func bpLimits(frames, perStream, total int, wait time.Duration) StreamLimits {
	return StreamLimits{
		MaxFramesPerStream: frames,
		MaxBytesPerStream:  perStream,
		MaxBytesTotal:      total,
		OverflowWait:       wait,
	}
}

// waitTerminated polls the stream's terminated flag until it is set (or the
// deadline) and returns the stream record for further assertions.
//
// A fully stalled consumer never observes the termination nil (the
// terminate send gives up after OverflowWait by design), so the flag is the
// deterministic observation point.
func waitTerminated(t *testing.T, c *CarrierConn, id uint32, timeout time.Duration) *streamRec {
	t.Helper()
	c.mu.Lock()
	s, ok := c.streams[id]
	c.mu.Unlock()
	if !ok {
		t.Fatalf("stream %d not registered", id)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.terminated.Load() {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("stream %d never terminated within %v", id, timeout)
	return nil
}

// feedFrames keeps pushing FrameData to stream id on peer until stop is
// closed (1 frame/ms), because pressure termination only re-evaluates on a
// later push for the pressured stream.
func feedFrames(b *testutil.MemConn, id uint32, stop <-chan struct{}) {
	tk := time.NewTicker(time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			_ = WriteFrame(b, id, FrameData, []byte("x"))
		}
	}
}

// assertStreamQuiet drains ch until it goes quiet for quietAfter (or at
// most max items land), and fails if items keep flowing. After a stream
// termination, the worker's in-flight handoffs and/or the termination nil
// may still be landing — each consumer read can free the cap-1 slot and
// release one more, so "quiet" is the meaningful end state, not an exact
// item count.
func assertStreamQuiet(t *testing.T, ch chan []byte, max int, quietAfter time.Duration) {
	t.Helper()
	for i := 0; i < max; i++ {
		select {
		case <-ch:
		case <-time.After(quietAfter):
			return
		}
	}
	t.Fatal("stream channel never went quiet (discarded frames resurfacing?)")
}

// TestSlowStreamDoesNotBlockDispatcher is the Phase 3 core property (Issue
// B): a stream whose consumer never reads fills its mailbox, goes under
// pressure, and is eventually terminated — while a second stream keeps
// being served and the carrier itself stays alive.
func TestSlowStreamDoesNotBlockDispatcher(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	c.SetStreamLimits(bpLimits(4, 1024, 4096, 50*time.Millisecond))
	c.Register(1) // stream 1: the consumer never reads its channel
	ch2 := c.Register(2)
	go c.Dispatch()

	// Fill stream 1's mailbox without ever reading its consumer channel.
	for i := 0; i < 8; i++ {
		if err := WriteFrame(b, 1, FrameData, []byte("x")); err != nil {
			t.Fatalf("WriteFrame s1: %v", err)
		}
	}
	// While stream 1 is under pressure, stream 2 must still be served.
	if err := WriteFrame(b, 2, FrameData, []byte("s2")); err != nil {
		t.Fatalf("WriteFrame s2: %v", err)
	}
	select {
	case f := <-ch2:
		if string(f) != "s2" {
			t.Fatalf("stream 2 payload = %q, want %q", f, "s2")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("slow stream 1 stalled the dispatcher: stream 2 was never delivered")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		feedFrames(b, 1, stop)
	}()
	waitTerminated(t, c, 1, 3*time.Second)
	close(stop)
	wg.Wait()

	if !c.Ready() {
		t.Fatal("carrier died over a slow stream — only the stream may terminate")
	}
}

// TestAggregateBudgetEnforced verifies the carrier-wide byte budget
// (StreamLimits.MaxBytesTotal) is checked per push: a frame that fits the
// target stream's mailbox is refused when it would take total queued bytes
// over the budget, and the pressure policy is applied to THAT stream.
func TestAggregateBudgetEnforced(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	const (
		frames    = 8
		perStream = 600
		total     = 1000
	)
	c.SetStreamLimits(bpLimits(frames, perStream, total, time.Millisecond))

	// Build the streams directly WITHOUT starting workers: this test drives
	// deliver() single-threaded (playing the dispatcher's role), so no
	// concurrent mailbox drain can perturb the queued-byte accounting.
	c.mu.Lock()
	mk := func(id uint32) *streamRec {
		s := &streamRec{id: id, q: NewStreamQueue(frames, perStream), ch: make(chan []byte, 1)}
		c.streams[id] = s
		return s
	}
	s1, s2, s3 := mk(1), mk(2), mk(3)
	c.mu.Unlock()

	// The aggregate budget binds ACROSS streams: two stalled streams hold
	// 900B together, leaving no room for a third. (SanitizeLimits requires
	// total > perStream, so a single stream can never trip it.)
	if !s1.q.TryPush(queueItem{payload: make([]byte, 500)}) ||
		!s2.q.TryPush(queueItem{payload: make([]byte, 400)}) {
		t.Fatal("seed pushes to the mailboxes failed")
	}
	atomic.AddInt64(&c.queuedBytes, 900)

	// A 200B frame for stream 3 fits ITS mailbox (200 <= 600) but would
	// take the carrier to 1100 > 1000: refuse and pressurize stream 3.
	c.deliver(s3, queueItem{payload: make([]byte, 200)})
	if s3.pressureStart.IsZero() {
		t.Fatal("aggregate overflow did not put the stream under pressure")
	}
	if n := atomic.LoadInt64(&c.queuedBytes); n != 900 {
		t.Fatalf("queuedBytes = %d, want 900 (refused push must not count)", n)
	}

	// A 100B frame landing exactly ON the budget boundary (900+100 =
	// 1000 <= 1000) must still be accepted.
	c.deliver(s3, queueItem{payload: make([]byte, 100)})
	if n := atomic.LoadInt64(&c.queuedBytes); n != 1000 {
		t.Fatalf("queuedBytes = %d, want 1000", n)
	}
}

// TestFrameCloseUnderPressure verifies a FrameClose for a stalled stream
// still ends that stream (the consumer sees nil) without touching the
// carrier or other streams.
func TestFrameCloseUnderPressure(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	c.SetStreamLimits(bpLimits(4, 1024, 4096, 50*time.Millisecond))
	ch1 := c.Register(1)
	ch2 := c.Register(2)
	go c.Dispatch()

	// Stall stream 1, then ask the peer to close it.
	for i := 0; i < 8; i++ {
		if err := WriteFrame(b, 1, FrameData, []byte("x")); err != nil {
			t.Fatalf("WriteFrame s1: %v", err)
		}
	}
	if err := WriteFrame(b, 1, FrameClose, nil); err != nil {
		t.Fatalf("WriteFrame FrameClose: %v", err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		feedFrames(b, 1, stop)
	}()
	waitTerminated(t, c, 1, 3*time.Second)
	close(stop)
	wg.Wait()

	// Whatever the worker's in-flight handoffs and the termination nil
	// still deliver, the channel must then go quiet: the discarded queued
	// frames (and the swallowed FrameClose) must not resurface as items.
	assertStreamQuiet(t, ch1, 16, 300*time.Millisecond)

	// Stream 2 must be unaffected and the carrier alive.
	if err := WriteFrame(b, 2, FrameData, []byte("ok")); err != nil {
		t.Fatalf("WriteFrame s2: %v", err)
	}
	select {
	case f := <-ch2:
		if string(f) != "ok" {
			t.Fatalf("stream 2 payload = %q, want %q", f, "ok")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream 2 stalled after stream 1 ended under pressure")
	}
	if !c.Ready() {
		t.Fatal("carrier not ready after a pressured FrameClose")
	}
}

// TestTerminatedStreamStaysRegistered verifies a stream ended by
// backpressure keeps its ID registered (later frames are dropped, and
// OnNewStream must NOT re-fire, which would re-dial a dead destination).
func TestTerminatedStreamStaysRegistered(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	c.SetStreamLimits(bpLimits(4, 1024, 4096, 20*time.Millisecond))
	ch1 := c.Register(1)
	go c.Dispatch()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		feedFrames(b, 1, stop)
	}()
	waitTerminated(t, c, 1, 3*time.Second)
	close(stop)
	wg.Wait()

	// Let the stalled consumer's channel go quiet (the worker's in-flight
	// handoffs and the termination nil may still be landing); only then
	// can "the late frame arrives nowhere" be asserted.
	assertStreamQuiet(t, ch1, 16, 300*time.Millisecond)

	if n := c.StreamCount(); n != 1 {
		t.Fatalf("StreamCount = %d, want 1 (terminated stream stays registered)", n)
	}

	var fired atomic.Int32
	c.OnNewStream = func(id uint32, ch chan []byte) { fired.Add(1) }
	if err := WriteFrame(b, 1, FrameData, []byte("late")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case f := <-ch1:
		t.Fatalf("late frame delivered to a terminated stream (payload=%v)", f)
	case <-time.After(300 * time.Millisecond):
	}
	if n := fired.Load(); n != 0 {
		t.Fatalf("OnNewStream fired %d times for a terminated stream", n)
	}
}

// readItem reads one item from ch with a deadline.
func readItem(t *testing.T, ch chan []byte, timeout time.Duration) []byte {
	t.Helper()
	select {
	case f := <-ch:
		return f
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a stream item")
		return nil
	}
}

// TestPerStreamOrderingPreserved verifies per-stream delivery order is
// preserved while other streams interleave on the wire (FIFO mailbox +
// single worker + single consumer channel).
func TestPerStreamOrderingPreserved(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	c.SetStreamLimits(bpLimits(16, 64*1024, 256*1024, 100*time.Millisecond))
	ch1 := c.Register(1)
	ch2 := c.Register(2)
	go c.Dispatch()

	const N = 50
	for i := 0; i < N; i++ {
		// Interleave one frame per stream on the wire, then consume both
		// in order. The consumer keeps up, so no mailbox pressure ever
		// builds (this test is about ORDER, not about drops).
		if err := WriteFrame(b, 1, FrameData, []byte(fmt.Sprintf("s1-%02d", i))); err != nil {
			t.Fatalf("WriteFrame s1: %v", err)
		}
		if err := WriteFrame(b, 2, FrameData, []byte{byte(i)}); err != nil {
			t.Fatalf("WriteFrame s2: %v", err)
		}
		if f := readItem(t, ch1, 3*time.Second); string(f) != fmt.Sprintf("s1-%02d", i) {
			t.Fatalf("stream 1 order broken at %d: got %q", i, f)
		}
		readItem(t, ch2, 3*time.Second)
	}
}

// TestShutdownWithQueuedStreams verifies Close with data still in
// mailboxes: consumer channels are closed, the aggregate byte budget is
// fully reclaimed, and every carrier goroutine exits.
func TestShutdownWithQueuedStreams(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.SetStreamLimits(bpLimits(4, 4096, 4096, 50*time.Millisecond))
	ch1 := c.Register(1)
	ch2 := c.Register(2)
	go c.Dispatch()

	for i := 0; i < 3; i++ {
		if err := WriteFrame(b, 1, FrameData, make([]byte, 100)); err != nil {
			t.Fatalf("WriteFrame s1: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := WriteFrame(b, 2, FrameData, make([]byte, 50)); err != nil {
			t.Fatalf("WriteFrame s2: %v", err)
		}
	}
	// Let the dispatcher queue the frames (no consumer reads ch1/ch2).
	deadline := time.Now().Add(time.Second)
	for atomic.LoadInt64(&c.queuedBytes) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := atomic.LoadInt64(&c.queuedBytes); n == 0 {
		t.Fatal("dispatcher never queued any frame")
	}

	c.Close()

	for name, ch := range map[string]chan []byte{"s1": ch1, "s2": ch2} {
		done := make(chan struct{})
		go func() {
			for range ch {
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("channel for stream %s not closed by Close", name)
		}
	}
	if n := atomic.LoadInt64(&c.queuedBytes); n != 0 {
		t.Fatalf("queuedBytes after Close = %d, want 0 (discarded bytes must be reclaimed)", n)
	}
	select {
	case <-c.ShutdownDone():
	case <-time.After(3 * time.Second):
		t.Fatal("carrier goroutines did not all exit after Close (worker leak?)")
	}
}

// TestTerminatedStreamWorkerExits verifies a worker of a stream ended by
// backpressure actually exits (counts out of the live set), so Close's
// ShutdownDone cannot hang on it.
func TestTerminatedStreamWorkerExits(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.SetStreamLimits(bpLimits(4, 1024, 4096, 20*time.Millisecond))
	c.Register(1) // stream 1: the consumer never reads its channel
	go c.Dispatch()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		feedFrames(b, 1, stop)
	}()
	waitTerminated(t, c, 1, 3*time.Second)
	close(stop)
	wg.Wait()

	c.Close()
	select {
	case <-c.ShutdownDone():
	case <-time.After(3 * time.Second):
		t.Fatal("terminated stream's worker never exited (goroutine leak)")
	}
}
