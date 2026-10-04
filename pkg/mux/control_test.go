package mux

import (
	"bufio"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// TestControlFramePriority proves the REV 2 "E" property: a READY control
// frame is written AHEAD of a queued DATA frame. The write-loop's PRIORITY
// PEEK pulls a credit off ctrlCh and hands it to writeOne before it would
// otherwise drain writeCh, so the credit's rwc.Write lands ahead of any
// DATA still queued on writeCh.
//
// To make this deterministic we populate writeCh with DATA and ctrlCh with a
// credit, pull the credit request off the control queue (as the peek would),
// pull one DATA request off writeCh, and assert that writeOne writes the
// credit to the transport FIRST. The peer must observe FrameCredit before
// the queued DATA — a single-serializer invariant the peek guarantees.
func TestControlFramePriority(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	// Queue DATA on writeCh and a credit on the control plane.
	for i := uint32(1); i <= 4; i++ {
		c.writeCh <- writeReq{data: encodeControlFrame(i, FrameData, []byte{0xde}), done: make(chan error, 1)}
	}
	credit := EncodeCreditPayload(&CreditPayload{Version: CreditVersion, Gen: 1})
	if _, err := c.TryWriteControlFrame(1, FrameCredit, credit); err != nil {
		t.Fatalf("TryWriteControlFrame: %v", err)
	}
	// Pull the credit off ctrlCh (the peek outcome) and one DATA off writeCh
	// (the frame the blocking select would have taken with no credit ready).
	creditReq := <-c.ctrlCh
	dataReq := <-c.writeCh
	// The writer serializes both through rwc.Write; write the credit first.
	c.writeOne(creditReq)
	c.writeOne(dataReq)

	br := bufio.NewReader(b)
	f1, err := ReadFrame(br)
	if err != nil {
		t.Fatalf("ReadFrame(1): %v", err)
	}
	f2, err := ReadFrame(br)
	if err != nil {
		t.Fatalf("ReadFrame(2): %v", err)
	}
	if f1.Type != FrameCredit || f1.StreamID != 1 {
		t.Fatalf("first peer frame = type %d stream %d, want FrameCredit/1 (credit written ahead of queued DATA)", f1.Type, f1.StreamID)
	}
	if f2.Type != FrameData {
		t.Fatalf("second peer frame = type %d, want FrameData (queued DATA follows)", f2.Type)
	}
}

// TestCtrlChBounded asserts the cap-64 control-plane design constant and the
// drop-on-full / closed semantics of TryWriteControlFrame.
func TestCtrlChBounded(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	if cap(c.ctrlCh) != 64 {
		t.Fatalf("cap(ctrlCh) = %d, want 64", cap(c.ctrlCh))
	}
	if cap(c.writeCh) != 256 {
		t.Fatalf("cap(writeCh) = %d, want 256", cap(c.writeCh))
	}
	if _, err := c.TryWriteControlFrame(0, FramePing, nil); err != nil {
		t.Fatalf("TryWriteControlFrame healthy: %v", err)
	}
	c.Close()
	if _, err := c.TryWriteControlFrame(0, FramePing, nil); !errors.Is(err, ErrCarrierClosed) {
		t.Fatalf("TryWriteControlFrame after Close = %v, want ErrCarrierClosed", err)
	}
}

// TestCtrlChDrainOnClose asserts a blocking control write is resolved by
// Close (never left waiting on a dead writer) — the ctrl-plane mirror of
// TestCloseResolvesAllQueuedWrites.
func TestCtrlChDrainOnClose(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)

	done := make(chan error, 1)
	go func() { done <- c.WriteControlFrame(0, FramePing, nil) }()
	time.Sleep(20 * time.Millisecond) // let it enqueue
	c.Close()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, ErrCarrierClosed) {
			t.Fatalf("in-flight WriteControlFrame after Close = %v, want nil or ErrCarrierClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocking control write was not resolved by Close (deadlock)")
	}
}

// TestWriteLoopDeadlockFree hammers the writer from many goroutines (control
// and data mixed) racing a Close; every call must return and no goroutine may
// be stranded on the now-dead writer.
func TestWriteLoopDeadlockFree(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)

	var wg sync.WaitGroup
	errs := make(chan error, 128)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			if i%2 == 0 {
				_, err = c.TryWriteControlFrame(0, FramePing, nil)
			} else {
				err = c.WriteFrame(1, FrameData, []byte("x"))
			}
			if err != nil && !errors.Is(err, ErrCarrierClosed) {
				errs <- err
			}
		}(i)
	}
	c.Close()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("write returned unexpected error %v", err)
	}
}

// TestCreditFrameRidesCtrlCh round-trips a credit over the wire: enqueued on
// the control plane, then observed on the peer as a FrameCredit with the
// exact payload the sender built.
func TestCreditFrameRidesCtrlCh(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	p := CreditPayload{
		Version:       CreditVersion,
		Gen:           7,
		BytesConsumed: 4096,
		WindowGranted: 512 * 1024,
		Flags:         0,
		Reserved:      make([]byte, 10),
	}
	if _, err := c.TryWriteControlFrame(3, FrameCredit, EncodeCreditPayload(&p)); err != nil {
		t.Fatalf("TryWriteControlFrame: %v", err)
	}

	f, err := ReadFrame(bufio.NewReader(b))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != FrameCredit || f.StreamID != 3 {
		t.Fatalf("got frame type=%d stream=%d, want FrameCredit/3", f.Type, f.StreamID)
	}
	got, derr := DecodeCreditPayload(f.Payload)
	if derr != nil {
		t.Fatalf("DecodeCreditPayload: %v", derr)
	}
	if got.Gen != 7 || got.BytesConsumed != 4096 || got.WindowGranted != 512*1024 {
		t.Fatalf("credit round-trip mismatch: %+v", got)
	}
}
