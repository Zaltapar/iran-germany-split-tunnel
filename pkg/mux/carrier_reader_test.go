package mux

import (
	"bufio"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// TestWithReaderBindsReaderBeforeFirstRead pins the NewCarrierConnWithReader
// invariant that fixes the auth-reader handoff race: the carrier's read loop
// must consume the provided bufio.Reader from its very first read, so bytes
// the reader already pulled from the transport (e.g. a FrameRebind the peer
// wrote immediately after the auth handshake) are delivered, never orphaned
// in a second reader.
//
// Before the fix, the equivalent construction (NewCarrierConn followed by
// SetReadBuffer) raced the read loop's first read: if the read loop latched
// a fresh empty bufio first, the pre-buffered frame vanished silently.
func TestWithReaderBindsReaderBeforeFirstRead(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()

	// Simulate the post-auth state: the peer wrote a rebind (frame 1) and
	// one data frame (frame 2) to the transport, and the auth reader
	// (bufio over the same transport) has already consumed frame 1,
	// leaving the rest pre-buffered in br — exactly what CarrierAuth
	// returns when the peer writes right after the handshake.
	if err := WriteFrame(a, 7, FrameRebind, []byte("rebind-payload")); err != nil {
		t.Fatalf("write rebind: %v", err)
	}
	if err := WriteFrame(a, 7, FrameData, []byte("late-data")); err != nil {
		t.Fatalf("write data: %v", err)
	}
	br := bufio.NewReaderSize(b, 4096)
	if f, err := ReadFrame(br); err != nil || f.Type != FrameRebind {
		t.Fatalf("auth reader consumed frame: type=%v err=%v, want FrameRebind", f.Type, err)
	}
	if br.Buffered() != 7+len("late-data") {
		t.Fatalf("precondition: auth reader should hold the data frame (%d bytes), has %d",
			7+len("late-data"), br.Buffered())
	}

	// Construct the carrier on the pre-auth reader: the read loop must
	// latch br, never create a fresh bufio over b.
	c := NewCarrierConnWithReader(b, 0, br)
	defer c.Close()

	// Structural invariant: the carrier's active read buffer is br.
	if got := c.readBuffer(); got != br {
		t.Fatal("carrier read buffer is not the pre-auth reader (fresh bufio latched — the race lost)")
	}

	// Behavioral: the pre-buffered frame is delivered (stream 7 is
	// unknown to the carrier, so it surfaces as a new stream). OnNewStream
	// must not consume frames synchronously — Dispatch queues the
	// triggering frame's payload only AFTER the callback returns (the
	// node's own handlers spawn a goroutine for exactly this reason).
	type result struct {
		id      uint32
		typ     uint8
		payload []byte
	}
	resCh := make(chan result, 1)
	c.OnNewStream = func(id uint32, firstType uint8, ch chan []byte) {
		go func() {
			select {
			case p, ok := <-ch:
				if ok {
					resCh <- result{id, firstType, p}
				}
			case <-time.After(2 * time.Second):
				// The frame never reached the consumer channel: either
				// it was orphaned in a second reader, or the carrier is
				// already closing. Either way the invariant is violated.
				resCh <- result{id, firstType, nil}
			}
		}()
	}
	go c.Dispatch()

	select {
	case r := <-resCh:
		if r.id != 7 || r.typ != FrameData {
			t.Fatalf("delivered stream=%d type=0x%02x, want stream 7 FrameData", r.id, r.typ)
		}
		if string(r.payload) != "late-data" {
			t.Fatalf("delivered payload %q, want %q", r.payload, "late-data")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pre-buffered frame never reached OnNewStream (orphaned in a second reader)")
	}
}

// TestLateSetReadBufferOrphansPrebufferedFrame documents the bug the fix
// eliminates, reproduced deterministically: when the carrier is built with
// NewCarrierConn and the auth reader is installed with SetReadBuffer AFTER
// the read loop has already latched its buffer (the racy interleaving),
// the pre-buffered frame is orphaned and never delivered. The fix
// (NewCarrierConnWithReader) removes this interleaving entirely.
func TestLateSetReadBufferOrphansPrebufferedFrame(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()

	// Post-auth state: the rebind frame sits pre-buffered in the auth
	// reader (exactly as in the e2e trace), the pipe is otherwise empty.
	if err := WriteFrame(a, 7, FrameRebind, []byte("rebind-payload")); err != nil {
		t.Fatalf("write rebind: %v", err)
	}
	br := bufio.NewReaderSize(b, 4096)
	if f, err := ReadFrame(br); err != nil || f.Type != FrameRebind {
		t.Fatalf("auth reader consumed frame: type=%v err=%v", f.Type, err)
	}
	if br.Buffered() != 0 {
		t.Fatalf("precondition: expected the rebind fully consumed by the reader, has %d", br.Buffered())
	}

	// The racy construction: carrier first, reader installed late. Force
	// the losing interleaving deterministically by latching the read
	// buffer BEFORE SetReadBuffer — after this point the read loop can
	// only ever read the fresh bufio, never br.
	c := NewCarrierConn(b, 0)
	defer c.Close()
	// Latch the read buffer NOW: whichever goroutine reads c.buf first
	// wins, and readLoop will (or already did) latch this same fresh
	// bufio — deterministically reproducing the losing interleaving.
	c.readBuffer()
	c.SetReadBuffer(br) // too late: the read loop never uses br

	c.OnNewStream = func(uint32, uint8, chan []byte) {}
	go c.Dispatch()

	// The orphaned frame must NOT be delivered.
	select {
	case <-c.readDone:
		t.Fatal("read loop terminated; expected it to block on the empty fresh reader")
	case <-time.After(300 * time.Millisecond):
		// Expected: the read loop blocks on the fresh (empty) bufio;
		// the frame in br is unreachable.
	}
}

// TestNewCarrierConnWithoutReaderStillWorks guards the compatible path:
// with no pre-auth reader, the carrier creates and owns its own bufio
// over the transport and delivers frames written after construction.
func TestNewCarrierConnWithoutReaderStillWorks(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()

	c := NewCarrierConn(b, 0)
	defer c.Close()

	// A fresh reader was created (no reader was bound at construction).
	if c.readBuffer() == nil {
		t.Fatal("carrier without a reader has no read buffer")
	}

	ch := c.Register(3)
	if err := WriteFrame(a, 3, FrameData, []byte("after-construction")); err != nil {
		t.Fatalf("write: %v", err)
	}
	go c.Dispatch()
	select {
	case p, ok := <-ch:
		if !ok || string(p) != "after-construction" {
			t.Fatalf("delivered %q (ok=%v), want %q", p, ok, "after-construction")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("frame written after construction never delivered")
	}
}
