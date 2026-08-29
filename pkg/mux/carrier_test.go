package mux

import (
	"bufio"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// TestRegisterDeregisterStreamCount pins the Register/Deregister/StreamCount
// contract.
func TestRegisterDeregisterStreamCount(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	if ch := c.Register(1); ch == nil {
		t.Fatal("Register returned nil on a live carrier")
	}
	if c.Register(2) == nil {
		t.Fatal("second Register returned nil")
	}
	if n := c.StreamCount(); n != 2 {
		t.Fatalf("StreamCount = %d, want 2", n)
	}
	c.Deregister(1)
	if n := c.StreamCount(); n != 1 {
		t.Fatalf("StreamCount after Deregister = %d, want 1", n)
	}
	// Deregister of an unknown id must be a no-op.
	c.Deregister(999)
	if n := c.StreamCount(); n != 1 {
		t.Fatalf("StreamCount after unknown Deregister = %d, want 1", n)
	}
}

// TestDeregisterDoesNotCloseChannel documents current semantics: Deregister
// only unregisters the stream; the channel itself is left open (only Close
// closes stream channels).
func TestDeregisterDoesNotCloseChannel(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	ch := c.Register(1)
	c.Deregister(1)
	select {
	case _, ok := <-ch:
		t.Fatalf("channel closed by Deregister (ok=%v)", ok)
	default:
	}
}

// TestRegisterWhileClosedReturnsNil documents that Register on a closed
// carrier yields nil and that Deregister stays safe after Close.
func TestRegisterWhileClosedReturnsNil(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.Close()
	if ch := c.Register(1); ch != nil {
		t.Fatal("Register succeeded on a closed carrier")
	}
	c.Deregister(1) // must not panic
}

// TestDispatchDeliversData verifies a FrameData for a registered stream is
// delivered to its channel.
func TestDispatchDeliversData(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	ch := c.Register(7)
	go c.Dispatch()

	if err := WriteFrame(b, 7, FrameData, []byte("hello")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case frame := <-ch:
		if frame == nil || string(frame) != "hello" {
			t.Fatalf("frame = %q, want %q", frame, "hello")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for stream data")
	}
}

// TestDispatchDeliversCloseAsNil documents that FrameClose is delivered as a
// nil payload (the half-close signal).
func TestDispatchDeliversCloseAsNil(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	ch := c.Register(3)
	go c.Dispatch()

	if err := WriteFrame(b, 3, FrameClose, nil); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case frame := <-ch:
		if frame != nil {
			t.Fatalf("FrameClose delivered payload %q, want nil", frame)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for FrameClose")
	}
}

// TestDispatchOnNewStream verifies the callback creates a stream on first
// contact and that the triggering frame is delivered on the new channel.
func TestDispatchOnNewStream(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	var newCh chan []byte
	fired := make(chan uint32, 1)
	c.OnNewStream = func(id uint32, firstType uint8, ch chan []byte) {
		if firstType != FrameHeader {
			t.Errorf("OnNewStream firstType = %d, want FrameHeader", firstType)
		}
		newCh = ch
		fired <- id
	}
	go c.Dispatch()

	hdr := []byte{0x03, 0x07, 'x', 0x01, 0xBB}
	if err := WriteFrame(b, 9, FrameHeader, hdr); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case id := <-fired:
		if id != 9 {
			t.Fatalf("OnNewStream id = %d, want 9", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnNewStream never fired")
	}
	if n := c.StreamCount(); n != 1 {
		t.Fatalf("StreamCount = %d, want 1", n)
	}
	select {
	case f := <-newCh:
		if string(f) != string(hdr) {
			t.Fatalf("header payload = %v, want %v", f, hdr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("header payload never delivered")
	}
}

// TestDispatchOnNewStreamRebind verifies FrameRebind opens a stream exactly
// like FrameHeader: OnNewStream fires with firstType == FrameRebind and the
// rebind payload is the first item on the new channel (Phase 5 — the
// receiver must be able to distinguish rebind from bootstrap).
func TestDispatchOnNewStreamRebind(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	var newCh chan []byte
	fired := make(chan struct{}, 1)
	c.OnNewStream = func(id uint32, firstType uint8, ch chan []byte) {
		if firstType != FrameRebind {
			t.Errorf("OnNewStream firstType = %d, want FrameRebind", firstType)
		}
		if id != 42 {
			t.Errorf("OnNewStream id = %d, want 42", id)
		}
		newCh = ch
		fired <- struct{}{}
	}
	go c.Dispatch()

	payload := []byte{0x01, 0xAA, 0xBB, 0xCC, 0x01, 0x02}
	if err := WriteFrame(b, 42, FrameRebind, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("OnNewStream never fired for FrameRebind")
	}
	select {
	case f := <-newCh:
		if string(f) != string(payload) {
			t.Fatalf("rebind payload = %v, want %v", f, payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rebind payload never delivered")
	}
}

// TestDispatchDropsUnknownStream verifies frames for unregistered streams
// (with no OnNewStream) are dropped without stalling the dispatcher.
func TestDispatchDropsUnknownStream(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	go c.Dispatch()

	if err := WriteFrame(b, 42, FrameData, []byte("orphan")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// Dispatcher must still be alive: a later registered stream works.
	ch := c.Register(1)
	if err := WriteFrame(b, 1, FrameData, []byte("ok")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case frame := <-ch:
		if string(frame) != "ok" {
			t.Fatalf("frame = %q, want %q", frame, "ok")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatcher stalled after dropping an unknown stream")
	}
	if n := c.StreamCount(); n != 1 {
		t.Fatalf("StreamCount = %d, want 1 (orphan must not be registered)", n)
	}
}

// TestCloseIdempotent verifies Close can be called any number of times.
func TestCloseIdempotent(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.Close()
	c.Close()
	c.Close()
}

// TestCloseUnblocksStreamConsumers verifies Close closes registered stream
// channels, waking consumers ranging over them.
func TestCloseUnblocksStreamConsumers(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	ch := c.Register(1)
	if ch == nil {
		t.Fatal("Register returned nil")
	}
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	c.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stream consumer not unblocked by Close")
	}
}

// TestWriteAfterClosedFails verifies writes after Close report an error
// (either "carrier closed" or the write itself failing on the closed conn).
func TestWriteAfterClosedFails(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	c.Close()
	if err := c.WriteFrame(1, FrameData, []byte("x")); err == nil {
		t.Fatal("WriteFrame after Close succeeded")
	}
}

// TestConcurrentWritesSerialized verifies the writer goroutine serializes
// concurrent WriteFrame callers: every frame arrives intact and exactly once.
func TestConcurrentWritesSerialized(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	const N = 64
	errs := make(chan error, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- c.WriteFrame(uint32(1000+i), FrameData, []byte{byte(i)})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent WriteFrame: %v", err)
		}
	}

	br := bufio.NewReader(b)
	seen := make(map[uint32]bool)
	for i := 0; i < N; i++ {
		f, err := ReadFrame(br)
		if err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		if seen[f.StreamID] {
			t.Fatalf("duplicate stream id %d on the wire", f.StreamID)
		}
		seen[f.StreamID] = true
	}
}

// TestKeepaliveSendsPings verifies the keepalive loop emits FramePing on
// StreamID 0 at the configured interval.
func TestKeepaliveSendsPings(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 20*time.Millisecond)
	defer c.Close()

	b.SetDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(b)
	sawPing := false
	for i := 0; i < 100 && !sawPing; i++ {
		f, err := ReadFrame(br)
		if err != nil {
			t.Fatalf("reading keepalive pings: %v", err)
		}
		if f.Type == FramePing && f.StreamID == 0 {
			sawPing = true
		}
	}
	b.SetDeadline(time.Time{})
	if !sawPing {
		t.Fatal("no keepalive ping observed within deadline")
	}
}

// TestReadyAndReadErrAfterPeerClose verifies Ready() flips to false and
// ReadErr() reports the read error after the peer goes away.
func TestReadyAndReadErrAfterPeerClose(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	if !c.Ready() {
		t.Fatal("fresh carrier is not Ready")
	}
	_ = b.Close()
	deadline := time.Now().Add(2 * time.Second)
	for c.Ready() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Ready() {
		t.Fatal("carrier still Ready after peer close")
	}
	if c.ReadErr() == nil {
		t.Fatal("ReadErr is nil after peer close")
	}
}

// TestCloseWhileDispatcherBlocked verifies Close terminates a dispatcher
// that is blocked delivering to a full stream channel.
func TestCloseWhileDispatcherBlocked(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	ch := c.Register(1)
	go c.Dispatch()

	// Burst more frames than the total internal capacity (stream channel 64
	// + frames channel 256) so the dispatcher is guaranteed to be blocked on
	// the full stream channel while the consumer never reads.
	for i := 0; i < 400; i++ {
		if err := WriteFrame(b, 1, FrameData, make([]byte, 8)); err != nil {
			t.Fatalf("WriteFrame %d: %v", i, err)
		}
	}

	done := make(chan struct{})
	go func() {
		c.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return while dispatcher was blocked")
	}
	// ch is closed by Close, so ranging over it terminates.
	go func() {
		for range ch {
		}
	}()
}
