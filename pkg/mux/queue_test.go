package mux

import (
	"testing"
	"time"
)

// TestStreamQueueFrameBound verifies the mailbox enforces MaxFrames even
// for tiny payloads (the frame bound is a hard ceiling on item count).
func TestStreamQueueFrameBound(t *testing.T) {
	q := NewStreamQueue(3, 1<<20, nil, 0)
	for i := 0; i < 3; i++ {
		if !q.TryPush(queueItem{payload: []byte("x")}) {
			t.Fatalf("push %d refused before the frame bound was reached", i)
		}
	}
	if q.TryPush(queueItem{payload: []byte("x")}) {
		t.Fatal("push beyond MaxFrames accepted")
	}
	// A FrameClose item still counts as one frame.
	if q.TryPush(queueItem{isClose: true}) {
		t.Fatal("FrameClose accepted beyond MaxFrames")
	}
}

// TestStreamQueueByteBound verifies the mailbox enforces MaxBytes even for
// short payloads (the byte bound is what actually caps memory).
func TestStreamQueueByteBound(t *testing.T) {
	q := NewStreamQueue(1<<20, 4, nil, 0)
	if !q.TryPush(queueItem{payload: []byte("ab")}) {
		t.Fatal("first 2-byte push refused")
	}
	if !q.TryPush(queueItem{payload: []byte("cd")}) {
		t.Fatal("push up to exactly MaxBytes refused")
	}
	if q.TryPush(queueItem{payload: []byte("e")}) {
		t.Fatal("push beyond MaxBytes accepted")
	}
	// FrameClose costs 0 bytes, so it still fits at the byte bound.
	if !q.TryPush(queueItem{isClose: true}) {
		t.Fatal("zero-byte FrameClose refused at the byte bound")
	}
}

// TestStreamQueueFIFOAndWake verifies Pop returns items in push order and
// that a parked Pop is woken by a later TryPush.
func TestStreamQueueFIFOAndWake(t *testing.T) {
	q := NewStreamQueue(8, 1<<20, nil, 0)
	want := []string{"a", "b", "c"}
	for _, s := range want {
		if !q.TryPush(queueItem{payload: []byte(s)}) {
			t.Fatalf("push %q refused", s)
		}
	}
	for _, s := range want {
		it, ok := q.Pop()
		if !ok || string(it.payload) != s {
			t.Fatalf("Pop = (%q, %v), want (%q, true)", it.payload, ok, s)
		}
	}

	itCh := make(chan queueItem, 1)
	okCh := make(chan bool, 1)
	go func() { it, ok := q.Pop(); itCh <- it; okCh <- ok }()
	select {
	case <-itCh:
		t.Fatal("Pop returned from an empty open queue")
	case <-time.After(50 * time.Millisecond):
	}
	if !q.TryPush(queueItem{payload: []byte("wake")}) {
		t.Fatal("push to wake a parked Pop failed")
	}
	select {
	case it := <-itCh:
		if ok := <-okCh; !ok {
			t.Fatal("Pop ok=false after TryPush")
		}
		if string(it.payload) != "wake" {
			t.Fatalf("Pop = %q, want %q", it.payload, "wake")
		}
	case <-time.After(time.Second):
		t.Fatal("parked Pop not woken by TryPush")
	}
}

// TestStreamQueueCloseAccountsBytes verifies Close discards queued items,
// returns their payload bytes exactly once, and leaves the queue unusable.
func TestStreamQueueCloseAccountsBytes(t *testing.T) {
	q := NewStreamQueue(8, 1<<20, nil, 0)
	q.TryPush(queueItem{payload: make([]byte, 3)})
	q.TryPush(queueItem{payload: make([]byte, 4)})
	if n := q.Close(); n != 7 {
		t.Fatalf("Close discarded = %d, want 7", n)
	}
	if n := q.Close(); n != 0 {
		t.Fatalf("second Close = %d, want 0", n)
	}
	if _, ok := q.Pop(); ok {
		t.Fatal("Pop after Close returned ok=true")
	}
	if q.TryPush(queueItem{payload: []byte("x")}) {
		t.Fatal("TryPush after Close succeeded")
	}
}

// TestStreamQueueCloseWakesParkedPop verifies a Pop parked on an empty
// queue is released by Close with ok=false.
func TestStreamQueueCloseWakesParkedPop(t *testing.T) {
	q := NewStreamQueue(8, 1<<20, nil, 0)
	okCh := make(chan bool, 1)
	go func() { _, ok := q.Pop(); okCh <- ok }()
	time.Sleep(20 * time.Millisecond) // let Pop park
	q.Close()
	select {
	case ok := <-okCh:
		if ok {
			t.Fatal("parked Pop got ok=true after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("parked Pop not woken by Close")
	}
}

// TestSanitizeLimits pins the normalization contract: zero fields fall
// back to defaults, the frame bound is clamped to MaxFrames, and an
// aggregate below the per-stream bound is rejected.
func TestSanitizeLimits(t *testing.T) {
	d := DefaultStreamLimits
	if l := SanitizeLimits(StreamLimits{}); l != d {
		t.Fatalf("SanitizeLimits(zero) = %+v, want defaults %+v", l, d)
	}

	l := SanitizeLimits(StreamLimits{
		MaxFramesPerStream: MaxFrames + 1,
		MaxBytesPerStream:  100,
		MaxBytesTotal:      1000,
		OverflowWait:       time.Millisecond,
	})
	if l.MaxFramesPerStream != MaxFrames {
		t.Fatalf("MaxFramesPerStream = %d, want clamp to %d", l.MaxFramesPerStream, MaxFrames)
	}

	l = SanitizeLimits(StreamLimits{
		MaxFramesPerStream: 4,
		MaxBytesPerStream:  100,
		MaxBytesTotal:      50, // below the per-stream bound
		OverflowWait:       time.Millisecond,
	})
	if l.MaxBytesTotal != d.MaxBytesTotal {
		t.Fatalf("MaxBytesTotal = %d, want default %d", l.MaxBytesTotal, d.MaxBytesTotal)
	}

	l = SanitizeLimits(StreamLimits{
		MaxFramesPerStream: 4,
		MaxBytesPerStream:  100,
		MaxBytesTotal:      1000,
		OverflowWait:       5 * time.Millisecond,
	})
	want := StreamLimits{
		MaxFramesPerStream: 4,
		MaxBytesPerStream:  100,
		MaxBytesTotal:      1000,
		OverflowWait:       5 * time.Millisecond,
	}
	if l != want {
		t.Fatalf("SanitizeLimits(valid) = %+v, want unchanged %+v", l, want)
	}
}
