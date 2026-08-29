package mux

// Phase 2: carrier lifecycle tests.
//
// Invariant under test: after Close, every carrier-owned goroutine
// (readLoop, writeLoop, keepalive) has exited and every WriteFrame caller
// has been resolved — no goroutine or write stays blocked indefinitely.

import (
	"bufio"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// waitForShutdown blocks until all carrier-owned goroutines have exited.
func waitForShutdown(t *testing.T, c *CarrierConn) {
	t.Helper()
	select {
	case <-c.ShutdownDone():
	case <-time.After(5 * time.Second):
		t.Fatal("carrier-owned goroutines did not all exit after Close")
	}
}

// TestCloseResolvesAllQueuedWrites: the write queue is filled to capacity,
// then the carrier is closed. Every pending request must be resolved (by
// the writer, or by Close's drain with ErrCarrierClosed) — none may be
// left waiting on a dead writer.
func TestCloseResolvesAllQueuedWrites(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)

	const n = 256 // cap(writeCh)
	reqs := make([]writeReq, n)
	for i := range reqs {
		reqs[i] = writeReq{data: []byte{byte(i)}, done: make(chan error, 1)}
		c.writeCh <- reqs[i]
	}
	c.Close()

	for i, r := range reqs {
		select {
		case err := <-r.done:
			if err != nil && !errors.Is(err, ErrCarrierClosed) {
				t.Fatalf("queued write %d: unexpected error %v", i, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("queued write %d was never resolved", i)
		}
	}
	waitForShutdown(t, c)
}

// TestWriterExitsAfterClose: the writer goroutine terminates once the
// carrier is closed (previously it leaked on `range c.writeCh`).
func TestWriterExitsAfterClose(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)

	if err := c.WriteFrame(1, FrameData, []byte("x")); err != nil {
		t.Fatalf("pre-close write: %v", err)
	}
	c.Close()
	waitForShutdown(t, c)
	// A second Close is a no-op.
	c.Close()
	waitForShutdown(t, c)
}

// TestCloseWithKeepaliveActive: with a live keepalive ping loop, Close
// terminates the keepalive goroutine and stops its ticker (no leak).
func TestCloseWithKeepaliveActive(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 5*time.Millisecond)

	// Prove the keepalive is actually sending pings before we close.
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(b)
	sawPing := false
	for i := 0; i < 100 && !sawPing; i++ {
		f, err := ReadFrame(br)
		if err != nil {
			break
		}
		if f.Type == FramePing && f.StreamID == 0 {
			sawPing = true
		}
	}
	b.SetReadDeadline(time.Time{})
	if !sawPing {
		t.Fatal("keepalive ping not observed before Close")
	}

	c.Close()
	waitForShutdown(t, c)
}

// TestConcurrentClose: many goroutines call Close at once; it must be
// idempotent, panic-free, and still leave a fully shut-down carrier.
func TestConcurrentClose(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 5*time.Millisecond)
	go c.Dispatch()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Close()
		}()
	}
	wg.Wait()
	c.Close() // belt-and-braces: extra call must be a no-op
	waitForShutdown(t, c)

	if c.Ready() {
		t.Error("carrier reports Ready after Close")
	}
	if ch := c.Register(1); ch != nil {
		t.Error("Register succeeded after Close")
	}
}

// TestConcurrentWritesDuringClose: many writers race a Close. Every
// WriteFrame call must return — nil, a write error, or ErrCarrierClosed —
// and the whole carrier must shut down without leaking.
func TestConcurrentWritesDuringClose(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	go c.Dispatch()

	const workers = 8
	const perWorker = 1024
	results := make(chan error, workers*perWorker)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				results <- c.WriteFrame(uint32(id*perWorker+i), FrameData, []byte{byte(i)})
			}
		}(w)
	}
	time.Sleep(10 * time.Millisecond) // let some writes get in flight
	c.Close()
	wg.Wait()
	close(results)

	count := 0
	for err := range results {
		count++
		if err != nil && !errors.Is(err, ErrCarrierClosed) {
			t.Fatalf("write during close: unexpected error %v", err)
		}
	}
	if count != workers*perWorker {
		t.Fatalf("got %d results, want %d", count, workers*perWorker)
	}
	waitForShutdown(t, c)
}

// TestWriteAfterCloseFailsFast: once Close has returned, every
// WriteFrame rejects immediately with ErrCarrierClosed — after the
// carrier is closed, no WriteFrame caller is blocked.
func TestWriteAfterCloseFailsFast(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.Close()
	waitForShutdown(t, c)

	for i := 0; i < 100; i++ {
		if err := c.WriteFrame(1, FrameData, []byte("x")); !errors.Is(err, ErrCarrierClosed) {
			t.Fatalf("write %d after close: err = %v, want ErrCarrierClosed", i, err)
		}
	}
}

// TestCloseUnblocksIdleReadLoop: the read loop is blocked reading from a
// silent peer; Close must terminate it (via the connection close) and
// record a read error.
func TestCloseUnblocksIdleReadLoop(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	time.Sleep(5 * time.Millisecond) // read loop is now blocked in Read
	c.Close()
	waitForShutdown(t, c)

	if c.ReadErr() == nil {
		t.Error("ReadErr is nil after Close of a blocked read loop")
	}
	if c.Ready() {
		t.Error("carrier Ready after Close")
	}
}

// TestNoGoroutineLeaksAfterClose: full lifecycles (keepalive + registered
// stream + external Dispatch) must leave no goroutines behind.
func TestNoGoroutineLeaksAfterClose(t *testing.T) {
	base := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		a, b := testutil.NewMemPipe()
		c := NewCarrierConn(a, 2*time.Millisecond)
		_ = c.Register(1)
		go c.Dispatch()
		time.Sleep(3 * time.Millisecond) // let at least one keepalive fire
		c.Close()
		waitForShutdown(t, c)
		b.Close()
	}

	// Dispatch goroutines exit right after ShutdownDone; give the runtime
	// a moment to settle, then the count must be back at baseline.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if n := runtime.NumGoroutine(); n <= base+1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: base=%d now=%d", base, runtime.NumGoroutine())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
