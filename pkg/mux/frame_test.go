package mux

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// memPair returns a connected in-memory byte-stream pair.
func memPair(t *testing.T) (*testutil.MemConn, *testutil.MemConn) {
	t.Helper()
	return testutil.NewMemPipe()
}

// TestFrameRoundTrip verifies WriteFrame/ReadFrame for every frame type,
// including empty payloads and the maximum payload size.
func TestFrameRoundTrip(t *testing.T) {
	payloads := []struct {
		name    string
		typ     uint8
		payload []byte
	}{
		{"data", FrameData, []byte("hello world")},
		{"auth", FrameAuth, make([]byte, 32)},
		{"ping", FramePing, nil},
		{"pong", FramePong, []byte{0}},
		{"close", FrameClose, nil},
		{"header", FrameHeader, []byte{0x03, 0x07, 'e', 0x01, 0xBB}},
		{"max", FrameData, make([]byte, MaxPayload)},
	}
	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, 0xDEAD_BEEF, tc.typ, tc.payload); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			br := bufio.NewReader(&buf)
			f, err := ReadFrame(br)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if f.StreamID != 0xDEAD_BEEF {
				t.Errorf("StreamID = %#x, want 0xDEADBEEF", f.StreamID)
			}
			if f.Type != tc.typ {
				t.Errorf("Type = %#x, want %#x", f.Type, tc.typ)
			}
			if f.Length != uint16(len(tc.payload)) {
				t.Errorf("Length = %d, want %d", f.Length, len(tc.payload))
			}
			if !bytes.Equal(f.Payload, tc.payload) {
				t.Errorf("Payload mismatch (len %d vs %d)", len(f.Payload), len(tc.payload))
			}
		})
	}
}

// TestFrameHeaderWireLayout pins the exact on-wire header encoding so a
// protocol change is always an explicit, visible edit.
func TestFrameHeaderWireLayout(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, 1, FrameClose, nil); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	raw := buf.Bytes()
	want := []byte{0x00, 0x00, 0x00, 0x01, FrameClose, 0x00, 0x00}
	if !bytes.Equal(raw, want) {
		t.Errorf("wire layout = %v, want %v", raw, want)
	}
}

// TestFrameOversizeRejected verifies both encoders reject payloads above
// the 16-bit Length field.
func TestFrameOversizeRejected(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, 1, FrameData, make([]byte, MaxPayload+1))
	if err == nil {
		t.Fatal("WriteFrame accepted oversized payload")
	}
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("err = %v, want ErrPayloadTooLarge", err)
	}
}

// TestFrameTruncatedHeader verifies ReadFrame fails on a short header.
func TestFrameTruncatedHeader(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte{0x00, 0x00}))
	if _, err := ReadFrame(br); err == nil {
		t.Fatal("ReadFrame accepted truncated header")
	}
}

// TestFrameTruncatedPayload verifies ReadFrame fails when the payload is
// shorter than the declared Length.
func TestFrameTruncatedPayload(t *testing.T) {
	hdr := []byte{0x00, 0x00, 0x00, 0x01, FrameData, 0x00, 0x0A} // Length = 10
	br := bufio.NewReader(bytes.NewReader(append(hdr, 1, 2, 3))) // only 3 bytes
	if _, err := ReadFrame(br); err == nil {
		t.Fatal("ReadFrame accepted truncated payload")
	}
}

// TestFrameSequenceOrder verifies consecutive frames decode in order.
func TestFrameSequenceOrder(t *testing.T) {
	var buf bytes.Buffer
	for i := uint32(0); i < 5; i++ {
		if err := WriteFrame(&buf, i, FrameData, []byte{byte(i)}); err != nil {
			t.Fatalf("WriteFrame %d: %v", i, err)
		}
	}
	br := bufio.NewReader(&buf)
	for i := uint32(0); i < 5; i++ {
		f, err := ReadFrame(br)
		if err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		if f.StreamID != i || len(f.Payload) != 1 || f.Payload[0] != byte(i) {
			t.Errorf("frame %d: got id=%d payload=%v", i, f.StreamID, f.Payload)
		}
	}
	if _, err := ReadFrame(br); !errors.Is(err, io.EOF) {
		t.Errorf("ReadFrame after end: err = %v, want EOF", err)
	}
}

// TestFrameReadFromClosedStream verifies ReadFrame returns an error when the
// underlying stream ends mid-frame.
func TestFrameReadFromClosedStream(t *testing.T) {
	a, b := memPair(t)
	go func() {
		_, _ = b.Write([]byte{0x00, 0x00}) // half a header
		_ = b.Close()
	}()
	br := bufio.NewReader(a)
	if _, err := ReadFrame(br); err == nil {
		t.Fatal("ReadFrame accepted a closed stream with partial header")
	}
}
