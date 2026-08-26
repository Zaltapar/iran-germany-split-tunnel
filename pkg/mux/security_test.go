package mux

import (
	"errors"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// waitForShutdownDone fails the test if the carrier's goroutines do not
// all exit within 5s.
func waitForShutdownDone(t *testing.T, c *CarrierConn) {
	t.Helper()
	select {
	case <-c.ShutdownDone():
	case <-time.After(5 * time.Second):
		t.Fatal("carrier goroutines did not shut down")
	}
}

// TestCarrierRejectsStreamZeroData verifies that an application frame on
// the reserved control stream 0 terminates the carrier (Phase 6,
// Section 10) instead of creating a phantom stream.
func TestCarrierRejectsStreamZeroData(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	done := make(chan struct{})
	go func() { defer close(done); c.Dispatch() }()

	if err := WriteFrame(b, 0, FrameData, []byte{1}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	<-done
	// The production contract: when the read loop dies, Dispatch returns
	// and the OWNER closes the carrier (node.go / cmd mains do exactly
	// this). We follow the same sequence.
	c.Close()
	waitForShutdownDone(t, c)
	if !errors.Is(c.ReadErr(), ErrProtocolViolation) {
		t.Fatalf("ReadErr = %v, want ErrProtocolViolation", c.ReadErr())
	}
}

// TestCarrierRejectsPostAuthFrameAuth verifies that a FrameAuth arriving
// after the handshake (v0 peer or attacker) terminates the carrier.
func TestCarrierRejectsPostAuthFrameAuth(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	done := make(chan struct{})
	go func() { defer close(done); c.Dispatch() }()

	if err := WriteFrame(b, 0, FrameAuth, make([]byte, 32)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	<-done
	c.Close()
	waitForShutdownDone(t, c)
	if !errors.Is(c.ReadErr(), ErrProtocolViolation) {
		t.Fatalf("ReadErr = %v, want ErrProtocolViolation", c.ReadErr())
	}
}

// TestCarrierAcceptsControlStreamZero verifies the exemption: FramePing on
// stream 0 is still accepted and answered with FramePong (keepalive), and
// a legitimate data frame on stream 1 is still delivered.
func TestCarrierAcceptsControlStreamZero(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	ch := c.Register(1)
	if ch == nil {
		t.Fatal("Register(1) returned nil on a live carrier")
	}
	done := make(chan struct{})
	go func() { defer close(done); c.Dispatch() }()

	// Ping on stream 0 → pong.
	if err := WriteFrame(b, 0, FramePing, nil); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	f, err := ReadFrame(mustBufRead(t, b))
	if err != nil {
		t.Fatalf("no pong: %v", err)
	}
	if f.Type != FramePong || f.StreamID != 0 {
		t.Fatalf("got frame %v on stream %d, want FramePong/0", f.Type, f.StreamID)
	}

	// Data on stream 1 → delivered.
	if err := WriteFrame(b, 1, FrameData, []byte{0xde, 0xad}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	p := <-ch
	if string(p) != "\xde\xad" {
		t.Fatalf("payload = %q, want the two bytes", p)
	}
}

// TestRegisterStreamZeroNil verifies stream 0 can never be registered as a
// stream (reserved for control frames).
func TestRegisterStreamZeroNil(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	if ch := c.Register(0); ch != nil {
		t.Fatal("Register(0) returned a channel; stream 0 must be reserved")
	}
	if ch := c.Register(1); ch == nil {
		t.Fatal("Register(1) returned nil on a live carrier")
	}
}
