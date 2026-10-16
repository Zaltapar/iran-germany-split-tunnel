// terminate_test.go — up-carrier drop-storm fix, Part 1 (terminating
// semantics). These tests pin the mux-level contract that the node's
// bootstrap-dial drop path now relies on:
//
//	(a) after Terminate(id), peer retransmits of FrameData / FrameClose on the
//	    SAME id are dropped SILENTLY (the terminated record stays registered,
//	    so the dispatcher never re-creates it) and OnNewStream does NOT re-fire
//	    — which is exactly what stops the 0x00/0x04 re-drop storm;
//	(b) a brand-NEW stream with a NEW id for the same destination still works
//	    (the recovery path is preserved).
//
// NOTE: c.OnNewStream is read by the dispatcher goroutine without a lock, so
// these tests install the callback BEFORE starting Dispatch and gate the
// per-test tracking with a sync flag (no read/write race on the callback).
package mux

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// waitTerminatedID blocks until stream id is marked terminated (bounded).
func waitTerminatedID(t *testing.T, c *CarrierConn, id uint32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		s, ok := c.streams[id]
		term := ok && s.terminated.Load()
		c.mu.Unlock()
		if term {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("stream %d never terminated within deadline", id)
}

// TestTerminateStaysRegisteredAndDoesNotRefire pin part (a) of the report:
// a stream ended by Terminate keeps its id registered, so later frames for
// that id (FrameData and FrameClose) are dropped silently and OnNewStream does
// NOT re-fire. This is the invariant the node's terminating drop path needs.
func TestTerminateStaysRegisteredAndDoesNotRefire(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	c.SetStreamLimits(bpLimits(16, 64<<10, 256<<10, 100*time.Millisecond))
	ch1 := c.Register(1)

	// trackRefire is armed only AFTER the stream is terminated; before that,
	// OnNewStream would legitimately fire for the live prime frame and we must
	// NOT count it. The callback is installed before Dispatch so there is no
	// read/write race on c.OnNewStream.
	var trackRefire atomic.Bool
	var refire atomic.Int32
	c.OnNewStream = func(id uint32, firstType uint8, ch chan []byte) {
		if id == 1 && trackRefire.Load() {
			refire.Add(1)
		}
	}
	go c.Dispatch()

	// Prime the stream with one data frame so it is fully "live" before we
	// terminate it.
	if err := WriteFrame(b, 1, FrameData, []byte("live")); err != nil {
		t.Fatalf("WriteFrame prime: %v", err)
	}
	select {
	case f := <-ch1:
		if string(f) != "live" {
			t.Fatalf("prime payload = %q, want %q", f, "live")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("prime frame never delivered")
	}

	// Terminate the stream the way the node's dial-drop path does, then arm
	// the re-fire tracker for any SUBSEQUENT re-creation of id 1.
	c.Terminate(1)
	waitTerminatedID(t, c, 1)
	trackRefire.Store(true)

	// Terminate sends ONE nil (the termination marker) to the consumer
	// channel; drain it so the quietness assertion below is meaningful.
	assertStreamQuiet(t, ch1, 16, 300*time.Millisecond)

	// The terminated stream must remain registered (the invariant pinned by
	// TestTerminatedStreamStaysRegistered), so the dispatcher drops late
	// frames silently instead of re-opening them.
	if n := c.StreamCount(); n != 1 {
		t.Fatalf("StreamCount = %d, want 1 (terminated stream stays registered)", n)
	}

	// The peer retransmits FrameData on the SAME id, then its trailing
	// FrameClose on the SAME id. Both must be dropped silently.
	if err := WriteFrame(b, 1, FrameData, []byte("retransmit-data")); err != nil {
		t.Fatalf("WriteFrame retransmit data: %v", err)
	}
	if err := WriteFrame(b, 1, FrameClose, nil); err != nil {
		t.Fatalf("WriteFrame retransmit close: %v", err)
	}

	// The channel stays quiet and OnNewStream did not re-fire for id 1.
	assertStreamQuiet(t, ch1, 16, 300*time.Millisecond)
	if n := refire.Load(); n != 0 {
		t.Fatalf("OnNewStream re-fired %d times on the terminated id; want 0", n)
	}
}

// TestTerminateThenNewStreamRecovers pin part (b): a NEW stream id for the
// same destination is unaffected by a previous termination — the recovery
// path the report describes. Terminate stream 1, then have the peer open
// stream 2 to the same "destination"; stream 2 must bootstrap normally.
func TestTerminateThenNewStreamRecovers(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	c.SetStreamLimits(bpLimits(16, 64<<10, 256<<10, 100*time.Millisecond))
	ch1 := c.Register(1)

	// We do NOT pre-register stream 2: the dispatcher creates it on first
	// sight (its bootstrap FrameHeader) and hands us the channel — exactly the
	// recovery path this test proves. The callback is installed before
	// Dispatch so there is no read/write race on c.OnNewStream.
	var fired2 atomic.Int32
	var firstType2 atomic.Uint32
	var ch2Mu sync.Mutex
	var ch2 chan []byte
	c.OnNewStream = func(id uint32, firstType uint8, ch chan []byte) {
		if id == 2 {
			fired2.Add(1)
			firstType2.Store(uint32(firstType))
			ch2Mu.Lock()
			ch2 = ch
			ch2Mu.Unlock()
		}
	}
	go c.Dispatch()

	// Terminate stream 1 (as if its target dial failed).
	c.Terminate(1)
	waitTerminatedID(t, c, 1)
	// Drain the termination marker so later quietness is meaningful.
	assertStreamQuiet(t, ch1, 16, 300*time.Millisecond)

	// A NEW stream (id 2) for the same destination opens normally: the peer
	// writes its bootstrap FrameHeader; the dispatcher discovers it, fires
	// OnNewStream once, and delivers the payload on the fresh channel.
	if err := WriteFrame(b, 2, FrameHeader, []byte("dest-new")); err != nil {
		t.Fatalf("WriteFrame new stream header: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ch2Mu.Lock()
		gotCh := ch2
		ch2Mu.Unlock()
		if gotCh != nil {
			select {
			case f := <-gotCh:
				if string(f) != "dest-new" {
					t.Fatalf("new stream payload = %q, want %q", f, "dest-new")
				}
			}
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	ch2Mu.Lock()
	gotCh := ch2
	ch2Mu.Unlock()
	if gotCh == nil {
		t.Fatal("OnNewStream never delivered the channel for new stream 2")
	}
	// Allow a beat for the dispatcher to settle after delivering the frame.
	time.Sleep(50 * time.Millisecond)
	if n := fired2.Load(); n != 1 {
		t.Fatalf("OnNewStream fired %d times for new stream 2; want exactly 1", n)
	}
	if got := uint8(firstType2.Load()); got != FrameHeader {
		t.Fatalf("new stream firstType = 0x%02x, want 0x%02x (FrameHeader)", got, FrameHeader)
	}
	// Termination of 1 must not have poisoned 2: stream 2 is live (not
	// terminated).
	c.mu.Lock()
	s2, ok2 := c.streams[2]
	term2 := ok2 && s2.terminated.Load()
	c.mu.Unlock()
	if !ok2 || term2 {
		t.Fatalf("new stream 2 registered=%v terminated=%v; want registered+live", ok2, term2)
	}
}
