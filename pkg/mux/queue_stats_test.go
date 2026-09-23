package mux

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

func TestQueueStatsRejectReasons(t *testing.T) {
	t.Run("stream frames", func(t *testing.T) {
		stats := &QueueStats{}
		q := NewStreamQueue(1, 1024, nil, 0)
		q.SetStats(stats)
		if !q.TryPush(queueItem{payload: []byte("a")}) {
			t.Fatal("seed push refused")
		}
		q.mu.Lock()
		reason := q.rejectReasonLocked(queueItem{payload: []byte("b")})
		q.mu.Unlock()
		if reason != rejectStreamFrames {
			t.Fatalf("reject reason = %d, want stream frames", reason)
		}
		if q.TryPush(queueItem{payload: []byte("b")}) {
			t.Fatal("frame-bound push accepted")
		}
		if got := atomic.LoadInt64(&stats.PushRejectedStream); got != 1 {
			t.Fatalf("PushRejectedStream = %d, want 1", got)
		}
	})

	t.Run("stream bytes", func(t *testing.T) {
		stats := &QueueStats{}
		q := NewStreamQueue(8, 4, nil, 0)
		q.SetStats(stats)
		if !q.TryPush(queueItem{payload: []byte("abcd")}) {
			t.Fatal("seed push refused")
		}
		q.mu.Lock()
		reason := q.rejectReasonLocked(queueItem{payload: []byte("e")})
		q.mu.Unlock()
		if reason != rejectStreamBytes {
			t.Fatalf("reject reason = %d, want stream bytes", reason)
		}
		if q.TryPush(queueItem{payload: []byte("e")}) {
			t.Fatal("byte-bound push accepted")
		}
		if got := atomic.LoadInt64(&stats.PushRejectedStream); got != 1 {
			t.Fatalf("PushRejectedStream = %d, want 1", got)
		}
	})

	t.Run("aggregate budget", func(t *testing.T) {
		stats := &QueueStats{}
		var budget int64
		q := NewStreamQueue(8, 1024, &budget, 4)
		q.SetStats(stats)
		if !q.TryPush(queueItem{payload: []byte("abcd")}) {
			t.Fatal("seed push refused")
		}
		if q.TryPush(queueItem{payload: []byte("e")}) {
			t.Fatal("aggregate-bound push accepted")
		}
		if got := atomic.LoadInt64(&stats.PushRejectedTotal); got != 1 {
			t.Fatalf("PushRejectedTotal = %d, want 1", got)
		}
	})

	t.Run("closed", func(t *testing.T) {
		stats := &QueueStats{}
		q := NewStreamQueue(8, 1024, nil, 0)
		q.SetStats(stats)
		q.Close()
		if q.TryPush(queueItem{payload: []byte("closed")}) {
			t.Fatal("push to closed queue accepted")
		}
		if got := atomic.LoadInt64(&stats.PushRejectedClosed); got != 1 {
			t.Fatalf("PushRejectedClosed = %d, want 1", got)
		}
	})
}

func TestQueueStatsHighWaterBytes(t *testing.T) {
	stats := &QueueStats{}
	q := NewStreamQueue(4, 1024, nil, 0)
	q.SetStats(stats)
	for i, n := range []int{400, 400, 200} {
		if !q.TryPush(queueItem{payload: make([]byte, n)}) {
			t.Fatalf("push %d refused", i)
		}
		want := int64(400 + 400)
		if i == 0 {
			want = 400
		} else if i == 2 {
			want = 1000
		}
		if got := atomic.LoadInt64(&stats.StreamQueuedBytesHigh); got != want {
			t.Fatalf("stream byte high-water after push %d = %d, want %d", i, got, want)
		}
	}
	for i := 0; i < 3; i++ {
		if _, ok := q.Pop(); !ok {
			t.Fatalf("Pop %d returned closed", i)
		}
	}
	if got := atomic.LoadInt64(&stats.StreamQueuedBytesHigh); got != 1000 {
		t.Fatalf("stream byte high-water after pops = %d, want 1000", got)
	}
	if got := atomic.LoadInt64(&stats.QueuedBytesNow); got != 0 {
		t.Fatalf("queued bytes now = %d, want 0", got)
	}
}

func TestQueueStatsHighWaterFrames(t *testing.T) {
	stats := &QueueStats{}
	q := NewStreamQueue(4, 1024, nil, 0)
	q.SetStats(stats)
	for i := 0; i < 4; i++ {
		if !q.TryPush(queueItem{payload: []byte{byte(i)}}) {
			t.Fatalf("push %d refused", i)
		}
	}
	if got := atomic.LoadInt64(&stats.StreamQueuedFramesHigh); got != 4 {
		t.Fatalf("stream frame high-water = %d, want 4", got)
	}
	for i := 0; i < 4; i++ {
		if _, ok := q.Pop(); !ok {
			t.Fatalf("Pop %d returned closed", i)
		}
	}
	if got := atomic.LoadInt64(&stats.StreamQueuedFramesHigh); got != 4 {
		t.Fatalf("stream frame high-water after pops = %d, want 4", got)
	}
}

func TestQueueStatsHighWaterAggregate(t *testing.T) {
	stats := &QueueStats{}
	var budget int64
	q1 := NewStreamQueue(8, 1024, &budget, 1000)
	q2 := NewStreamQueue(8, 1024, &budget, 1000)
	q3 := NewStreamQueue(8, 1024, &budget, 1000)
	q1.SetStats(stats)
	q2.SetStats(stats)
	q3.SetStats(stats)
	if !q1.TryPush(queueItem{payload: make([]byte, 500)}) ||
		!q2.TryPush(queueItem{payload: make([]byte, 400)}) {
		t.Fatal("seed push refused")
	}
	if got := atomic.LoadInt64(&stats.QueuedBytesHigh); got != 900 {
		t.Fatalf("aggregate high-water = %d, want 900", got)
	}
	if q3.TryPush(queueItem{payload: make([]byte, 200)}) {
		t.Fatal("refused aggregate push accepted")
	}
	if got := atomic.LoadInt64(&stats.QueuedBytesHigh); got != 900 {
		t.Fatalf("aggregate high-water after refusal = %d, want 900", got)
	}
	if got := atomic.LoadInt64(&stats.QueuedBytesNow); got != 900 {
		t.Fatalf("aggregate current after refusal = %d, want 900", got)
	}
	if !q3.TryPush(queueItem{payload: make([]byte, 100)}) {
		t.Fatal("boundary aggregate push refused")
	}
	if got := atomic.LoadInt64(&stats.QueuedBytesHigh); got != 1000 {
		t.Fatalf("aggregate high-water = %d, want 1000", got)
	}
}

func TestQueueStatsNilSafe(t *testing.T) {
	var budget int64
	q := NewStreamQueue(2, 4, &budget, 4)
	if !q.TryPush(queueItem{payload: []byte("ab")}) ||
		!q.TryPush(queueItem{payload: []byte("cd")}) {
		t.Fatal("nil-stats seed push refused")
	}
	if q.TryPush(queueItem{payload: []byte("e")}) {
		t.Fatal("nil-stats aggregate/stream-bound push accepted")
	}
	if got := atomic.LoadInt64(&budget); got != 4 {
		t.Fatalf("budget before pop = %d, want 4", got)
	}
	if _, ok := q.Pop(); !ok {
		t.Fatal("nil-stats Pop returned closed")
	}
	q.Close()
	if got := atomic.LoadInt64(&budget); got != 0 {
		t.Fatalf("budget after Close = %d, want 0", got)
	}
}

func TestOverflowTerminationCounts(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	c.SetStreamLimits(bpLimits(1, 1024, 4096, 20*time.Millisecond))
	q := NewStreamQueue(1, 1024, &c.queuedBytes, 4096)
	q.SetStats(stats)
	q.setQueuedItems(&c.queuedItems)
	s := &streamRec{id: 1, q: q, ch: make(chan []byte, 1)}
	c.mu.Lock()
	c.streams[s.id] = s
	c.allStreams = append(c.allStreams, s)
	c.mu.Unlock()
	if !q.TryPush(queueItem{payload: []byte("x")}) {
		t.Fatal("seed push refused")
	}
	c.applyPressure(s)
	time.Sleep(25 * time.Millisecond)
	c.applyPressure(s)
	if !s.terminated.Load() {
		t.Fatal("dispatcher did not terminate pressured stream")
	}
	if got := atomic.LoadInt64(&stats.OverflowTerminations); got != 1 {
		t.Fatalf("dispatcher overflow terminations = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&stats.OverflowWaitCount); got != 1 {
		t.Fatalf("overflow wait count = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&stats.OverflowWaitMaxNanos); got < (20 * time.Millisecond).Nanoseconds() {
		t.Fatalf("overflow wait max = %d ns, want at least %d ns", got, (20 * time.Millisecond).Nanoseconds())
	}
	if !c.Ready() {
		t.Fatal("carrier was terminated with the stream")
	}
	c.Close()
}

func TestWorkerOverflowTerminationCounts(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	c.SetStreamLimits(bpLimits(4, 1024, 4096, 20*time.Millisecond))
	ch := c.Register(1)
	if ch == nil {
		t.Fatal("Register returned nil")
	}
	c.mu.Lock()
	s := c.streams[1]
	c.mu.Unlock()
	ch <- []byte("occupied")
	if !s.q.TryPush(queueItem{payload: []byte("blocked")}) {
		t.Fatal("worker seed push refused")
	}
	deadline := time.Now().Add(time.Second)
	for !s.terminated.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !s.terminated.Load() {
		t.Fatal("worker did not terminate blocked stream")
	}
	if got := atomic.LoadInt64(&stats.OverflowTerminationsWorker); got != 1 {
		t.Fatalf("worker overflow terminations = %d, want 1", got)
	}
}
