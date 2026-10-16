// Package testutil provides in-memory network primitives for tests.
//
// MemPipe is an unbounded in-memory bidirectional byte stream pair that
// implements io.ReadWriteCloser plus SetDeadline. Unlike net.Pipe it never
// blocks writers, which makes protocol tests deterministic.
//
// Blocking reads use a sync.Cond (not a 1 ms sleep poll), so the harness
// does not artificially cap throughput. A reader that blocks on an empty
// queue is woken by the writer's push (or by deadline expiry), giving
// effective line-rate delivery on in-memory pipes.
package testutil

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type queue struct {
	mu            sync.Mutex
	cond          *sync.Cond
	buf           []byte
	closed        bool
	blackhole     bool      // swallow writes; reads block until closed (see Blackhole)
	readDeadline  time.Time // enforced by take (the peer's read side)
	writeDeadline time.Time // enforced by push (the writer's write side)
}

func newQueue() *queue {
	q := &queue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *queue) push(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0, errClosed
	}
	if q.blackhole {
		return len(p), nil // dropped: the write "succeeds" into the void
	}
	if !q.writeDeadline.IsZero() && !time.Now().Before(q.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	q.buf = append(q.buf, p...)
	q.cond.Broadcast() // wake any blocked reader
	return len(p), nil
}

func (q *queue) take(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if q.blackhole {
			// A blackholed read blocks forever (no error, no EOF) —
			// exactly like a dropped network path. Close() ends the
			// block (the carrier's liveness teardown relies on this).
			if q.closed {
				return 0, io.EOF
			}
			q.cond.Wait()
			continue
		}
		if len(q.buf) > 0 {
			n := copy(p, q.buf)
			q.buf = q.buf[n:]
			return n, nil
		}
		if q.closed {
			return 0, io.EOF
		}
		if !q.readDeadline.IsZero() {
			if !time.Now().Before(q.readDeadline) {
				return 0, os.ErrDeadlineExceeded
			}
			// Block until data arrives, the queue is closed, or the
			// deadline expires. The timer's Broadcast wakes the Wait;
			// the loop re-checks all conditions. A timer that already
			// fired but is still waiting on q.mu (held by this goroutine)
			// will complete harmlessly after the unlock.
			remaining := time.Until(q.readDeadline)
			timer := time.AfterFunc(remaining, func() {
				q.mu.Lock()
				q.cond.Broadcast()
				q.mu.Unlock()
			})
			q.cond.Wait()
			timer.Stop()
			// Re-loop: data may have arrived, or the deadline may now
			// have passed (handled at the top of the next iteration).
			continue
		}
		// No data, not closed, no deadline: block until woken.
		q.cond.Wait()
	}
}

func (q *queue) setReadDeadline(t time.Time) {
	q.mu.Lock()
	q.readDeadline = t
	if !t.IsZero() {
		q.cond.Broadcast() // wake any blocked reader to re-check the new deadline
	}
	q.mu.Unlock()
}

func (q *queue) setBlackhole() {
	q.mu.Lock()
	q.blackhole = true
	q.cond.Broadcast() // wake any blocked reader into the blackhole loop
	q.mu.Unlock()
}

func (q *queue) setWriteDeadline(t time.Time) {
	q.mu.Lock()
	q.writeDeadline = t
	q.mu.Unlock()
}

func (q *queue) markClosed() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast() // wake any blocked reader
	q.mu.Unlock()
}

var errClosed = errors.New("testutil: mempipe closed")

// MemConn is one end of an in-memory bidirectional byte stream.
type MemConn struct {
	in  *queue // bytes written by the peer
	out *queue // bytes this side writes (the peer reads them)
}

// NewMemPipe returns a connected pair of MemConns: writes on a are readable
// on b and vice versa. Closing either end ends both directions.
func NewMemPipe() (*MemConn, *MemConn) {
	a, b := newQueue(), newQueue()
	return &MemConn{in: a, out: b}, &MemConn{in: b, out: a}
}

func (m *MemConn) Read(p []byte) (int, error)  { return m.in.take(p) }
func (m *MemConn) Write(p []byte) (int, error) { return m.out.push(p) }

func (m *MemConn) Close() error {
	m.in.markClosed()
	m.out.markClosed()
	return nil
}

// SetDeadline sets the read and write deadline on THIS end of the pipe only
// (matching net.Conn semantics: it never affects the peer's queues).
func (m *MemConn) SetDeadline(t time.Time) error {
	m.SetReadDeadline(t)
	return m.SetWriteDeadline(t)
}

// Blackhole makes this end simulate a DROPPED network path in both
// directions: every subsequent write succeeds but the bytes vanish, and
// every subsequent read blocks forever — no error, no EOF, no RST/FIN
// (a blackholed connection the OS will never time out on its own).
// Close still ends both directions, which is how the carrier's
// liveness teardown interrupts a blackholed read. Test-only primitive;
// used to exercise liveness detection deterministically.
func (m *MemConn) Blackhole() {
	m.in.setBlackhole()
	m.out.setBlackhole()
}

// SetReadDeadline bounds reads from this end.
func (m *MemConn) SetReadDeadline(t time.Time) error {
	m.in.setReadDeadline(t)
	return nil
}

// SetWriteDeadline bounds writes on this end.
func (m *MemConn) SetWriteDeadline(t time.Time) error {
	m.out.setWriteDeadline(t)
	return nil
}

type memAddr struct{}

func (memAddr) Network() string { return "mem" }
func (memAddr) String() string  { return "mem" }

// LocalAddr is part of net.Conn (the in-memory pipe has no real address).
func (m *MemConn) LocalAddr() net.Addr { return memAddr{} }

// RemoteAddr is part of net.Conn (the in-memory pipe has no real address).
func (m *MemConn) RemoteAddr() net.Addr { return memAddr{} }
