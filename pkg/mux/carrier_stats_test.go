package mux

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

type writeErrorConn struct {
	*testutil.MemConn
	err error
}

func (c *writeErrorConn) Write([]byte) (int, error) { return 0, c.err }

type controlledReadConn struct {
	release chan struct{}
	err     error
	once    sync.Once
}

func newControlledReadConn(err error) *controlledReadConn {
	return &controlledReadConn{release: make(chan struct{}), err: err}
}

func (c *controlledReadConn) Read([]byte) (int, error) {
	<-c.release
	return 0, c.err
}

func (c *controlledReadConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *controlledReadConn) Close() error {
	c.once.Do(func() { close(c.release) })
	return nil
}

func TestCarrierWriteFailureCounted(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer b.Close()
	wantErr := errors.New("write failed")
	c := NewCarrierConn(&writeErrorConn{MemConn: a, err: wantErr}, 0)
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	if err := c.WriteFrame(1, FrameData, []byte("x")); !errors.Is(err, wantErr) {
		t.Fatalf("WriteFrame error = %v, want %v", err, wantErr)
	}
	if got := atomic.LoadInt64(&stats.WriteFailures); got != 1 {
		t.Fatalf("write failures = %d, want 1", got)
	}
	c.Close()
}

func TestCarrierReadFailureAndEOFCounted(t *testing.T) {
	t.Run("eof", func(t *testing.T) {
		a, b := testutil.NewMemPipe()
		c := NewCarrierConn(a, 0)
		stats := &QueueStats{}
		c.SetQueueStats(stats)
		_ = b.Close()
		select {
		case <-c.readDone:
		case <-time.After(time.Second):
			t.Fatal("read loop did not exit after peer close")
		}
		if got := atomic.LoadInt64(&stats.ReadEOF); got != 1 {
			t.Fatalf("read EOF = %d, want 1", got)
		}
		c.Close()
	})

	t.Run("failure", func(t *testing.T) {
		wantErr := errors.New("read failed")
		conn := newControlledReadConn(wantErr)
		c := NewCarrierConn(conn, 0)
		stats := &QueueStats{}
		c.SetQueueStats(stats)
		_ = conn.Close()
		select {
		case <-c.readDone:
		case <-time.After(time.Second):
			t.Fatal("read loop did not exit after injected read failure")
		}
		if got := atomic.LoadInt64(&stats.ReadFailures); got != 1 {
			t.Fatalf("read failures = %d, want 1", got)
		}
		c.Close()
	})
}

func TestBlackholeDeathCounted(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 5*time.Millisecond)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	c.SetLivenessRounds(1)
	go c.Dispatch()
	b.Blackhole()
	deadline := time.Now().Add(2 * time.Second)
	for c.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Ready() {
		t.Fatal("blackholed carrier remained ready")
	}
	select {
	case <-c.ShutdownDone():
	case <-time.After(2 * time.Second):
		t.Fatal("blackholed carrier did not shut down")
	}
	if got := atomic.LoadInt64(&stats.BlackholeDeaths); got != 1 {
		t.Fatalf("blackhole deaths = %d, want 1", got)
	}
}

func TestZeroPushRejectedWhenDrained(t *testing.T) {
	stats := &QueueStats{}
	q := NewStreamQueue(4, 1024, nil, 0)
	q.SetStats(stats)
	for i := 0; i < 100; i++ {
		if !q.TryPush(queueItem{payload: []byte("x")}) {
			t.Fatalf("healthy push %d refused", i)
		}
		if _, ok := q.Pop(); !ok {
			t.Fatal("healthy queue unexpectedly closed")
		}
	}
	if got := atomic.LoadInt64(&stats.PushRejectedStream); got != 0 {
		t.Fatalf("stream rejections = %d, want 0", got)
	}
	if got := atomic.LoadInt64(&stats.PushRejectedTotal); got != 0 {
		t.Fatalf("aggregate rejections = %d, want 0", got)
	}
	if got := atomic.LoadInt64(&stats.StreamQueuedBytesHigh); got >= 1024 {
		t.Fatalf("stream byte high-water = %d, want less than 1024", got)
	}
}

func TestStatsConcurrentNoRace(t *testing.T) {
	stats := &QueueStats{}
	q := NewStreamQueue(10000, 10<<20, nil, 0)
	q.SetStats(stats)
	var accepted atomic.Int64
	var producers sync.WaitGroup
	for i := 0; i < 8; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for j := 0; j < 500; j++ {
				if q.TryPush(queueItem{payload: []byte("payload")}) {
					accepted.Add(1)
				}
			}
		}()
	}
	producers.Wait()
	q.mu.Lock()
	queued := int64(len(q.items))
	q.mu.Unlock()
	q.Close()
	if got := accepted.Load(); got != queued {
		t.Fatalf("accepted = %d, discarded = %d, want identity", got, queued)
	}
	if got := atomic.LoadInt64(&stats.PushAccepted); got != accepted.Load() {
		t.Fatalf("stats accepted = %d, test accepted = %d", got, accepted.Load())
	}
	if got := atomic.LoadInt64(&stats.QueuedBytesNow); got != 0 {
		t.Fatalf("queued bytes after close = %d, want 0", got)
	}
	if got := atomic.LoadInt64(&stats.QueuedFramesNow); got != 0 {
		t.Fatalf("queued frames after close = %d, want 0", got)
	}
	_ = io.EOF
}
