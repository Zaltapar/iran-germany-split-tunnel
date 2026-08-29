// Phase 4: session lifecycle tests.
//
// The invariant under test: no matter how many termination directions
// fire at the same time, cleanup (context cancel, owned-conn closes,
// OnClose hooks) happens exactly once, the state machine never
// regresses, and no goroutine leaks.

package session

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// pipeConn is a testutil.MemConn with the net.Conn shape and a Close counter.
type pipeConn struct {
	*testutil.MemConn
	closes atomic.Int32
}

func (p *pipeConn) Close() error {
	p.closes.Add(1)
	return p.MemConn.Close()
}

func (p *pipeConn) LocalAddr() net.Addr  { return nil }
func (p *pipeConn) RemoteAddr() net.Addr { return nil }

// newPipePair returns (sessionSide, testSide) of one in-memory pipe.
func newPipePair() (sessionSide, testSide *pipeConn) {
	a, b := testutil.NewMemPipe()
	return &pipeConn{MemConn: a}, &pipeConn{MemConn: b}
}

func mustWait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func mustCtxDone(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("session context was not cancelled")
	}
}

// newLifecycleSession builds a session owning both a client and a target
// pipe, plus the two test-side peers.
func newLifecycleSession(t *testing.T) (*Session, *pipeConn, *pipeConn) {
	t.Helper()
	client, _ := newPipePair()
	target, _ := newPipePair()
	var sid SessionID
	sid[0] = 0x41
	s := NewSession(sid, &Destination{AddrType: AddrTypeDomain, Addr: "example.com", Port: 443}, client, target, context.Background())
	return s, client, target
}

func TestSessionNormalLifecycle(t *testing.T) {
	s, client, target := newLifecycleSession(t)
	if s.State() != StatePending {
		t.Fatalf("new session state = %s, want Pending", s.State())
	}
	if !s.Activate() {
		t.Fatal("Activate from Pending failed")
	}
	if s.State() != StateActive {
		t.Fatalf("state = %s, want Active", s.State())
	}

	hooks := 0
	s.OnClose(func() { hooks++ })

	if s.MarkDirClosed(DirUp, "client EOF") {
		t.Fatal("half-closing one direction must not complete the session")
	}
	if s.State() != StateActive || !s.DirClosed(DirUp) || s.DirClosed(DirDown) {
		t.Fatalf("after up half-close: state=%s up=%v down=%v", s.State(), s.DirClosed(DirUp), s.DirClosed(DirDown))
	}
	if !s.MarkDirClosed(DirDown, "target EOF") {
		t.Fatal("closing the second direction must complete the session")
	}
	if s.State() != StateClosed {
		t.Fatalf("state = %s, want Closed", s.State())
	}
	mustWait(t, s.Done(), "teardown")
	if client.closes.Load() != 1 || target.closes.Load() != 1 {
		t.Fatalf("owned conns must be closed exactly once: client=%d target=%d", client.closes.Load(), target.closes.Load())
	}
	mustCtxDone(t, s.Ctx)
	if hooks != 1 {
		t.Fatalf("teardown hooks ran %d times, want 1", hooks)
	}
	if s.Reason() == "" {
		t.Error("no close reason recorded")
	}
}

func TestSessionClientClosesFirst(t *testing.T) {
	s, client, target := newLifecycleSession(t)
	s.Activate()

	if s.MarkDirClosed(DirUp, "client EOF") {
		t.Fatal("client close alone must not complete the session")
	}
	// The target may still send response data toward the client: both
	// owned conns must remain open after the upload half-close.
	if _, err := target.Write([]byte("response")); err != nil {
		t.Fatalf("target conn closed after upload half-close: %v", err)
	}
	if s.State() != StateActive {
		t.Fatalf("state = %s, want Active", s.State())
	}

	if !s.MarkDirClosed(DirDown, "target EOF") {
		t.Fatal("target close must complete the session")
	}
	mustWait(t, s.Done(), "teardown")
	if client.closes.Load() != 1 || target.closes.Load() != 1 {
		t.Fatal("owned conns not closed exactly once")
	}
}

func TestSessionTargetClosesFirst(t *testing.T) {
	s, _, _ := newLifecycleSession(t)
	s.Activate()
	if s.MarkDirClosed(DirDown, "target EOF") {
		t.Fatal("target close alone must not complete the session")
	}
	if !s.MarkDirClosed(DirUp, "client EOF") {
		t.Fatal("client close must complete the session")
	}
	mustWait(t, s.Done(), "teardown")
	if s.State() != StateClosed {
		t.Fatalf("state = %s, want Closed", s.State())
	}
}

func TestSessionUploadHalfClose(t *testing.T) {
	s, _, _ := newLifecycleSession(t)
	s.Activate()
	if s.MarkDirClosed(DirUp, "client EOF") {
		t.Fatal("first up half-close must not complete the session")
	}
	if s.MarkDirClosed(DirUp, "client EOF again") {
		t.Fatal("re-marking the same direction must be a no-op")
	}
	if !s.DirClosed(DirUp) || s.DirClosed(DirDown) {
		t.Fatal("direction flags wrong after up half-close")
	}
	s.Close("test")
	mustWait(t, s.Done(), "teardown")
}

func TestSessionDownloadHalfClose(t *testing.T) {
	s, _, _ := newLifecycleSession(t)
	s.Activate()
	if s.MarkDirClosed(DirDown, "target EOF") {
		t.Fatal("first down half-close must not complete the session")
	}
	if s.MarkDirClosed(DirDown, "target EOF again") {
		t.Fatal("re-marking the same direction must be a no-op")
	}
	if s.DirClosed(DirUp) || !s.DirClosed(DirDown) {
		t.Fatal("direction flags wrong after down half-close")
	}
	s.Close("test")
	mustWait(t, s.Done(), "teardown")
}

func TestSessionBothDirectionsCloseSimultaneously(t *testing.T) {
	s, client, target := newLifecycleSession(t)
	s.Activate()
	var hooks int32
	s.OnClose(func() { atomic.AddInt32(&hooks, 1) })

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.MarkDirClosed(DirUp, "client close") }()
	go func() { defer wg.Done(); s.MarkDirClosed(DirDown, "target close") }()
	wg.Wait()

	if s.State() != StateClosed {
		t.Fatalf("state = %s, want Closed", s.State())
	}
	mustWait(t, s.Done(), "teardown")
	if hooks != 1 {
		t.Fatalf("teardown ran %d times, want 1", hooks)
	}
	if client.closes.Load() != 1 || target.closes.Load() != 1 {
		t.Fatal("owned conns not closed exactly once")
	}
}

func TestSessionCarrierClosesWhileActive(t *testing.T) {
	s, client, target := newLifecycleSession(t)
	s.Activate()
	var hooks int32
	s.OnClose(func() { atomic.AddInt32(&hooks, 1) })

	// Two relays parked in Read.
	var wg sync.WaitGroup
	for _, c := range []*pipeConn{client, target} {
		wg.Add(1)
		go func(c *pipeConn) {
			defer wg.Done()
			buf := make([]byte, 8)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}(c)
	}
	time.Sleep(50 * time.Millisecond)

	s.Close("carrier closed")
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	mustWait(t, done, "relays to unblock")
	if hooks != 1 {
		t.Fatalf("teardown ran %d times, want 1", hooks)
	}
	if s.Reason() != "carrier closed" {
		t.Fatalf("reason = %q, want %q", s.Reason(), "carrier closed")
	}
	mustCtxDone(t, s.Ctx)
}

func TestSessionTimeoutFiresWhileRelayBlocked(t *testing.T) {
	s, client, _ := newLifecycleSession(t)
	s.Activate()
	var hooks int32
	s.OnClose(func() { atomic.AddInt32(&hooks, 1) })

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 8)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)

	// A session timeout is just another termination direction.
	time.AfterFunc(100*time.Millisecond, func() { s.Close("session timeout") })

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	mustWait(t, done, "relay to unblock")
	mustWait(t, s.Done(), "teardown")
	if hooks != 1 {
		t.Fatalf("teardown ran %d times, want 1", hooks)
	}
}

func TestSessionDoubleClose(t *testing.T) {
	s, client, target := newLifecycleSession(t)
	s.Activate()
	var hooks int32
	s.OnClose(func() { atomic.AddInt32(&hooks, 1) })

	s.Close("first")
	s.Close("second")
	if hooks != 1 {
		t.Fatalf("teardown ran %d times, want 1", hooks)
	}
	if client.closes.Load() != 1 || target.closes.Load() != 1 {
		t.Fatal("owned conns not closed exactly once")
	}
	if s.Reason() != "first" {
		t.Fatalf("reason = %q, want the first reason", s.Reason())
	}
}

func TestSessionConcurrentCloseManyGoroutines(t *testing.T) {
	s, client, target := newLifecycleSession(t)
	s.Activate()
	var hooks int32
	s.OnClose(func() { atomic.AddInt32(&hooks, 1) })

	const n = 12
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); s.Close("close reason") }(i)
	}
	wg.Wait()
	mustWait(t, s.Done(), "teardown")
	if hooks != 1 {
		t.Fatalf("teardown ran %d times, want 1", hooks)
	}
	if client.closes.Load() != 1 || target.closes.Load() != 1 {
		t.Fatal("owned conns not closed exactly once")
	}
}

func TestSessionNoGoroutineLeak(t *testing.T) {
	s, client, _ := newLifecycleSession(t)
	s.Activate()

	const relays = 8
	var wg sync.WaitGroup
	for i := 0; i < relays; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 16)
			for {
				select {
				case <-s.Ctx.Done():
					return
				default:
				}
				if _, err := client.Read(buf); err != nil {
					return
				}
			}
		}()
	}
	time.Sleep(30 * time.Millisecond)
	s.Close("shutdown")

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay goroutines leaked after session close")
	}
}

func TestClosedCannotBecomeActiveAgain(t *testing.T) {
	s, _, _ := newLifecycleSession(t)
	s.Activate()
	var hooks int32
	s.OnClose(func() { atomic.AddInt32(&hooks, 1) })
	s.Close("test")
	mustWait(t, s.Done(), "teardown")

	if s.Activate() {
		t.Fatal("a Closed session was reactivated")
	}
	if s.MarkDirClosed(DirUp, "late") {
		t.Fatal("MarkDirClosed on a Closed session must be a no-op")
	}
	s.Close("again")
	if hooks != 1 {
		t.Fatalf("teardown ran %d times, want 1", hooks)
	}
	if s.State() != StateClosed {
		t.Fatalf("state = %s, want Closed", s.State())
	}
}

func TestMarkDirClosedBeforeActivateIsNoop(t *testing.T) {
	s, client, target := newLifecycleSession(t)
	if s.MarkDirClosed(DirUp, "early") {
		t.Fatal("half-close from Pending must be a no-op")
	}
	if s.State() != StatePending {
		t.Fatalf("state = %s, want Pending", s.State())
	}
	// Closing from Pending is valid (e.g. aborted during setup).
	s.Close("aborted")
	mustWait(t, s.Done(), "teardown")
	if client.closes.Load() != 1 || target.closes.Load() != 1 {
		t.Fatal("owned conns not closed exactly once")
	}
}

func TestOnCloseAfterCloseRunsImmediately(t *testing.T) {
	s, _, _ := newLifecycleSession(t)
	s.Activate()
	s.Close("test")
	mustWait(t, s.Done(), "teardown")

	ran := false
	s.OnClose(func() { ran = true })
	if !ran {
		t.Fatal("a hook registered after close must run immediately")
	}
}

func TestCombinedSimultaneousTermination(t *testing.T) {
	s, client, target := newLifecycleSession(t)
	s.Activate()
	var hooks int32
	s.OnClose(func() { atomic.AddInt32(&hooks, 1) })

	// All termination directions fire at once: two half-closes
	// (client, target), three hard closes (up relay, down relay,
	// carrier) and a timeout timer.
	var wg sync.WaitGroup
	for _, reason := range []string{"up relay exit", "down relay exit", "carrier closed"} {
		wg.Add(1)
		go func(r string) { defer wg.Done(); s.Close(r) }(reason)
	}
	wg.Add(2)
	go func() { defer wg.Done(); s.MarkDirClosed(DirUp, "client close") }()
	go func() { defer wg.Done(); s.MarkDirClosed(DirDown, "target close") }()
	go time.AfterFunc(25*time.Millisecond, func() { s.Close("session timeout") })
	wg.Wait()

	mustWait(t, s.Done(), "teardown")
	if hooks != 1 {
		t.Fatalf("cleanup ran %d times, want exactly 1", hooks)
	}
	if client.closes.Load() != 1 || target.closes.Load() != 1 {
		t.Fatalf("owned conns not closed exactly once: client=%d target=%d", client.closes.Load(), target.closes.Load())
	}
	if s.State() != StateClosed {
		t.Fatalf("state = %s, want Closed", s.State())
	}
}

func TestHalfCloseClientEOFKeepsDownloadFlowing(t *testing.T) {
	// Integration shape of the production relays: the client FIN must
	// half-close the upload direction while the target's in-flight
	// response keeps flowing over the download direction.
	client, clientPeer := newPipePair()
	target, targetPeer := newPipePair()
	var sid SessionID
	sid[0] = 0x42
	s := NewSession(sid, nil, client, target, context.Background())
	s.Activate()

	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		buf := make([]byte, 8)
		for {
			if _, err := client.Read(buf); err != nil {
				s.MarkDirClosed(DirUp, "client EOF")
				return
			}
		}
	}()
	downDone := make(chan struct{})
	var got []byte
	go func() {
		defer close(downDone)
		buf := make([]byte, 16)
		for {
			n, err := target.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				s.MarkDirClosed(DirDown, "target EOF")
				return
			}
		}
	}()

	// Client FIN.
	clientPeer.Close()
	mustWait(t, upDone, "up relay to see the client FIN")
	if s.IsClosed() || s.State() == StateClosing {
		t.Fatal("a client FIN must not hard-close a session with an open download")
	}

	// The target may still send the response after the client FIN.
	if _, err := targetPeer.Write([]byte("late-response")); err != nil {
		t.Fatalf("target write after client FIN failed: %v", err)
	}
	targetPeer.Close()
	mustWait(t, downDone, "down relay to see the target EOF")

	mustWait(t, s.Done(), "teardown")
	if string(got) != "late-response" {
		t.Fatalf("down relay lost data buffered toward the client: %q", got)
	}
	if client.closes.Load() != 1 || target.closes.Load() != 1 {
		t.Fatal("owned conns not closed exactly once")
	}
}

func TestStoreCleanupWhileRegistering(t *testing.T) {
	ss := NewSessionStore()
	client, _ := newPipePair()
	target, _ := newPipePair()
	var sid SessionID
	sid[0] = 0x51
	s := NewSession(sid, nil, client, target, context.Background())
	s.StreamIDUp, s.StreamIDDown = 7, 8
	s.Activate()
	s.OnClose(func() { ss.Remove(sid) })

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			ss.Add(sid, s)
			ss.AddStream(s)
		}
	}()
	go func() {
		defer wg.Done()
		s.Close("carrier closed")
	}()
	wg.Wait()
	mustWait(t, s.Done(), "teardown")

	// Teardown unindexed the session and the closing-guard in
	// Add/AddStream rejected every late registration: nothing may leak.
	if n := ss.Count(); n != 0 {
		t.Fatalf("late registration leaked %d session(s)", n)
	}
	if _, ok := ss.GetByStream(7); ok {
		t.Error("late registration leaked the up stream index")
	}
	if _, ok := ss.GetByStream(8); ok {
		t.Error("late registration leaked the down stream index")
	}
}

func TestStoreCleanupWhileDeregistering(t *testing.T) {
	ss := NewSessionStore()
	client, _ := newPipePair()
	target, _ := newPipePair()
	var sid SessionID
	sid[0] = 0x52
	s := NewSession(sid, nil, client, target, context.Background())
	s.StreamIDUp, s.StreamIDDown = 9, 10
	s.Activate()
	ss.Add(sid, s)
	ss.AddStream(s)
	var hooks int32
	s.OnClose(func() {
		atomic.AddInt32(&hooks, 1)
		ss.Remove(sid)
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			ss.Remove(sid)
			ss.RemoveStream(s)
		}
	}()
	go func() {
		defer wg.Done()
		s.Close("session ended")
	}()
	wg.Wait()
	mustWait(t, s.Done(), "teardown")

	if hooks != 1 {
		t.Fatalf("teardown ran %d times, want 1", hooks)
	}
	if n := ss.Count(); n != 0 {
		t.Fatalf("store count = %d, want 0", n)
	}
	if _, ok := ss.GetByStream(9); ok {
		t.Error("up stream index still present")
	}
	if _, ok := ss.GetByStream(10); ok {
		t.Error("down stream index still present")
	}
	if client.closes.Load() != 1 || target.closes.Load() != 1 {
		t.Fatal("owned conns not closed exactly once")
	}
}

func TestMetricsNoDoubleDecrement(t *testing.T) {
	// Model of the production metrics invariant: one incSession at
	// creation, one decSession in the teardown hook, no matter how many
	// close attempts race in.
	s, _, _ := newLifecycleSession(t)
	s.Activate()
	var active int32
	atomic.StoreInt32(&active, 1)
	s.OnClose(func() { atomic.AddInt32(&active, -1) })

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); s.Close("close attempt") }()
		go func() { defer wg.Done(); s.MarkDirClosed(DirUp, "half close up") }()
		go func() { defer wg.Done(); s.MarkDirClosed(DirDown, "half close down") }()
	}
	wg.Wait()
	mustWait(t, s.Done(), "teardown")

	if got := atomic.LoadInt32(&active); got != 0 {
		t.Fatalf("active sessions = %d, want 0 (double decrement or missed increment)", got)
	}
}
