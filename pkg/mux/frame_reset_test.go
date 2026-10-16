// frame_reset_test.go — Issue #20 (stream-level negative ack) and Issue #21
// (bootstrap result) mux-level regression tests. These pin the wire/protocol
// contract the node layer relies on:
//
//   - the versioned payload codecs round-trip and reject malformed input;
//   - FrameReset and FrameBootstrapAck are CONTROL frames: the dispatcher
//     routes them to the OnStreamReset / OnStreamBootstrapAck callbacks,
//     parses the payload structurally, and NEVER creates a phantom stream or
//     fires OnNewStream for them (a reset/ack for a stream this carrier does
//     not know about is expected mid-loss-window and must stay a quiet no-op
//     that cannot spawn a stream or tear the connection down).
package mux

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// ---------------------------------------------------------------------------
// Codec round-trips
// ---------------------------------------------------------------------------

func TestEncodeParseResetPayloadRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		reason byte
		gen    uint64
	}{
		{ResetReasonUnknownStream, 0},
		{ResetReasonSessionClosed, 1},
		{ResetReasonRebindRefused, 1 << 40},
		{ResetReasonTargetDialFailed, ^uint64(0)},
	} {
		payload := EncodeResetPayload(tc.reason, tc.gen)
		if len(payload) != ResetPayloadSize {
			t.Fatalf("reset payload size = %d, want %d", len(payload), ResetPayloadSize)
		}
		if payload[0] != ResetVersion {
			t.Fatalf("reset payload version byte = %d, want %d", payload[0], ResetVersion)
		}
		gotReason, gotGen, err := ParseResetPayload(payload)
		if err != nil {
			t.Fatalf("ParseResetPayload: %v", err)
		}
		if gotReason != tc.reason || gotGen != tc.gen {
			t.Fatalf("round-trip = (%d, %d), want (%d, %d)", gotReason, gotGen, tc.reason, tc.gen)
		}
	}
}

func TestParseResetPayloadRejectsMalformed(t *testing.T) {
	// Wrong length.
	if _, _, err := ParseResetPayload(EncodeResetPayload(ResetReasonUnknownStream, 5)[:4]); err == nil {
		t.Fatal("short reset payload must be rejected")
	}
	// Unknown version.
	p := EncodeResetPayload(ResetReasonUnknownStream, 7)
	p[0] = 99 // unknown version
	if _, _, err := ParseResetPayload(p); err == nil {
		t.Fatal("unknown-version reset payload must be rejected")
	}
	// Empty.
	if _, _, err := ParseResetPayload(nil); err == nil {
		t.Fatal("empty reset payload must be rejected")
	}
}

func TestEncodeParseBootstrapAckPayloadRoundTrip(t *testing.T) {
	for _, status := range []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0xFF} {
		payload := EncodeBootstrapAckPayload(status)
		if len(payload) != BootstrapAckPayloadSize {
			t.Fatalf("bootstrap-ack payload size = %d, want %d", len(payload), BootstrapAckPayloadSize)
		}
		got, err := ParseBootstrapAckPayload(payload)
		if err != nil {
			t.Fatalf("ParseBootstrapAckPayload(%d): %v", status, err)
		}
		if got != status {
			t.Fatalf("bootstrap-ack round-trip = 0x%02x, want 0x%02x", got, status)
		}
	}
}
func TestParseBootstrapAckPayloadRejectsMalformed(t *testing.T) {
	if _, err := ParseBootstrapAckPayload(EncodeBootstrapAckPayload(0x05)[:1]); err == nil {
		t.Fatal("short bootstrap-ack payload must be rejected")
	}
	p := EncodeBootstrapAckPayload(0x00)
	p[0] = 99 // unknown version
	if _, err := ParseBootstrapAckPayload(p); err == nil {
		t.Fatal("unknown-version bootstrap-ack payload must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Dispatcher routing: control frames never spawn streams
// ---------------------------------------------------------------------------

// TestResetFrameRoutesToCallbackNotStream pins part (a) of Issue #20 at the
// mux layer: a FrameReset for a stream the carrier does not know about is
// delivered to OnStreamReset with the parsed reason/generation, does NOT
// create a stream record, and does NOT fire OnNewStream.
func TestResetFrameRoutesToCallbackNotStream(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	type resetGot struct {
		streamID uint32
		reason   byte
		gen      uint64
	}
	var fired atomic.Bool
	c.OnStreamReset = func(streamID uint32, reason byte, gen uint64) {
		if streamID != 77 || reason != ResetReasonRebindRefused || gen != 1234 {
			t.Errorf("OnStreamReset = (%d, %d, %d), want (77, %d, 1234)", streamID, reason, gen, ResetReasonRebindRefused)
			return
		}
		fired.Store(true)
	}
	var newStreamFires atomic.Int32
	c.OnNewStream = func(uint32, uint8, chan []byte) { newStreamFires.Add(1) }
	go c.Dispatch()

	// A valid reset payload for an UNREGISTERED stream.
	if err := WriteFrame(b, 77, FrameReset, EncodeResetPayload(ResetReasonRebindRefused, 1234)); err != nil {
		t.Fatalf("write reset frame: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !fired.Load() {
		time.Sleep(2 * time.Millisecond)
	}
	if !fired.Load() {
		t.Fatal("OnStreamReset never fired for a valid FrameReset")
	}
	// Give the dispatcher a moment to (wrongly) create the stream, then assert
	// it did not.
	time.Sleep(10 * time.Millisecond)
	c.mu.Lock()
	_, known := c.streams[77]
	c.mu.Unlock()
	if known {
		t.Fatal("FrameReset created a phantom stream record (it is control-only)")
	}
	if newStreamFires.Load() != 0 {
		t.Fatalf("FrameReset fired OnNewStream %d times; control frames must not", newStreamFires.Load())
	}
}

// TestBootstrapAckFrameRoutesToCallbackNotStream pins Issue #21 at the mux
// layer: a FrameBootstrapAck for an unknown stream is delivered to
// OnStreamBootstrapAck and does not create a stream or fire OnNewStream.
func TestBootstrapAckFrameRoutesToCallbackNotStream(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()

	var ackStatus byte
	var acked atomic.Bool
	c.OnStreamBootstrapAck = func(streamID uint32, status byte) {
		if streamID != 5 {
			t.Errorf("OnStreamBootstrapAck stream = %d, want 5", streamID)
			return
		}
		ackStatus = status
		acked.Store(true)
	}
	go c.Dispatch()

	if err := WriteFrame(b, 5, FrameBootstrapAck, EncodeBootstrapAckPayload(0x05)); err != nil {
		t.Fatalf("write bootstrap-ack frame: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !acked.Load() {
		time.Sleep(2 * time.Millisecond)
	}
	if !acked.Load() {
		t.Fatal("OnStreamBootstrapAck never fired for a valid FrameBootstrapAck")
	}
	if ackStatus != 0x05 {
		t.Fatalf("bootstrap-ack status = 0x%02x, want 0x05", ackStatus)
	}
	time.Sleep(10 * time.Millisecond)
	c.mu.Lock()
	_, known := c.streams[5]
	c.mu.Unlock()
	if known {
		t.Fatal("FrameBootstrapAck created a phantom stream record (it is control-only)")
	}
}

// TestMalformedResetIgnored: a FrameReset whose payload fails the structural
// parse is dropped SILENTLY (no callback, no stream, no connection teardown)
// so a mixed-version or corrupted frame cannot wedge the carrier.
func TestMalformedResetIgnored(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	var resetFires atomic.Int32
	c.OnStreamReset = func(uint32, byte, uint64) { resetFires.Add(1) }
	go c.Dispatch()

	// Garbage payload (wrong size + version) must be ignored.
	if err := WriteFrame(b, 9, FrameReset, []byte{0x09, 0x00}); err != nil {
		t.Fatalf("write malformed reset: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if resetFires.Load() != 0 {
		t.Fatalf("malformed FrameReset fired the callback %d times; it must be ignored", resetFires.Load())
	}
	// The carrier must still be alive (not torn down by the bad frame).
	if !c.Ready() {
		t.Fatal("malformed FrameReset tore the carrier down (must stay alive)")
	}
}
