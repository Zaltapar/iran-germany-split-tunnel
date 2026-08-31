package node

// White-box tests for stream-ID allocation (package node, unlike the
// scenario tests in node_test.go which are external).

import (
	"io"
	"log"
	"testing"
)

func testLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// TestNextStreamIDSkipsZeroOnWrap is the regression test for the
// uint32 wrap-around of the stream-ID counter: the counter passes
// through 0 — the ID reserved for protocol/control frames (FrameAuth,
// FramePing/FramePong on stream 0) — and a session must NEVER be
// allocated stream 0 (Register(0) is refused by the carrier, and a
// session on ID 0 would collide with control traffic). Before the fix
// nextStreamID returned atomic.AddUint32(...,1) verbatim, so the value
// after a wrap was 0.
func TestNextStreamIDSkipsZeroOnWrap(t *testing.T) {
	n := NewNode(Config{}, testLogger(), []byte("0123456789abcdef0123456789abcdef"))

	// Normal allocation: starts at 1, monotonic.
	if id := n.nextStreamID(); id != 1 {
		t.Fatalf("first stream ID = %d, want 1", id)
	}
	if id := n.nextStreamID(); id != 2 {
		t.Fatalf("second stream ID = %d, want 2", id)
	}

	// Force the counter to the value just before the wrap.
	n.streamSeq = 0xFFFFFFFE
	if id := n.nextStreamID(); id != 0xFFFFFFFF {
		t.Fatalf("ID at pre-wrap = %x, want ffffffff", id)
	}
	// The next allocation crosses the wrap: 0 is skipped, 1 is returned.
	if id := n.nextStreamID(); id != 1 {
		t.Fatalf("ID after wrap = %d, want 1 (0 must be skipped)", id)
	}

	// Exhaustive sweep around the wrap point: no 0, no repeats.
	n.streamSeq = 0xFFFFFFFD
	seen := map[uint32]bool{}
	for i := 0; i < 4; i++ {
		id := n.nextStreamID()
		if id == 0 {
			t.Fatalf("allocated reserved stream ID 0 (iteration %d)", i)
		}
		if seen[id] {
			t.Fatalf("duplicate stream ID %d near wrap", id)
		}
		seen[id] = true
	}
}
