package mux

import (
	"context"
	"errors"
	"io"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// testNoDeadline wraps an io.ReadWriteCloser WITHOUT any deadline methods,
// mirroring the production WebSocket adapter (wsConn exposes only
// Read/Write/Close). CarrierAuth's SetDeadline type assertion therefore
// fails, and the handshake bound must be enforced by CarrierAuth itself.
type testNoDeadline struct {
	inner  io.ReadWriteCloser
	closed *int32
}

func (w *testNoDeadline) Read(p []byte) (int, error)  { return w.inner.Read(p) }
func (w *testNoDeadline) Write(p []byte) (int, error) { return w.inner.Write(p) }
func (w *testNoDeadline) Close() error {
	atomic.StoreInt32(w.closed, 1)
	return w.inner.Close()
}

// settleGoroutines waits (bounded) for the goroutine count to return to
// the baseline, proving the auth reader goroutine exited after its read
// was interrupted by the connection close.
func settleGoroutines(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for n := runtime.NumGoroutine(); n > baseline; {
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: baseline=%d, now=%d", baseline, n)
		}
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
}

// TestCarrierAuthTimeoutSilentPeerNoDeadline verifies that on a
// deadline-less transport (the WebSocket adapter shape), a silent peer
// cannot hold the handshake forever: the AuthTimeout bound fires, the
// connection is closed, and no reader goroutine leaks.
func TestCarrierAuthTimeoutSilentPeerNoDeadline(t *testing.T) {
	orig := AuthTimeout
	AuthTimeout = 300 * time.Millisecond
	defer func() { AuthTimeout = orig }()

	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	// b is never driven: silent peer.
	closed := int32(0)
	w := &testNoDeadline{inner: a, closed: &closed}

	baseline := runtime.NumGoroutine()
	start := time.Now()
	_, err := CarrierAuth(context.Background(), w, true, RoleUpload, DeriveSecret("timeout"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("client auth succeeded against a silent peer")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("auth took %v; AuthTimeout was not enforced on a deadline-less transport", elapsed)
	}
	if atomic.LoadInt32(&closed) == 0 {
		t.Fatal("connection was not closed after the handshake bound expired")
	}
	settleGoroutines(t, baseline)
}

// TestCarrierAuthContextDeadlineSilentPeerNoDeadline verifies the bound
// respects the CALLER'S shorter context deadline (min of ctx and
// AuthTimeout) on a deadline-less transport.
func TestCarrierAuthContextDeadlineSilentPeerNoDeadline(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	closed := int32(0)
	w := &testNoDeadline{inner: a, closed: &closed}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := CarrierAuth(ctx, w, true, RoleUpload, DeriveSecret("ctx-deadline"))
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("auth took %v; context deadline was not enforced", elapsed)
	}
	if atomic.LoadInt32(&closed) == 0 {
		t.Fatal("connection was not closed after the context deadline")
	}
}

// TestCarrierAuthCancelSilentPeerNoDeadline verifies that context
// CANCELLATION (not just its deadline) interrupts a blocked handshake on
// a deadline-less transport — this is the shutdown path: even with the
// full 15 s AuthTimeout in effect, a cancelled context ends the handshake
// promptly and closes the connection.
func TestCarrierAuthCancelSilentPeerNoDeadline(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	closed := int32(0)
	w := &testNoDeadline{inner: a, closed: &closed}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	baseline := runtime.NumGoroutine()
	start := time.Now()
	_, err := CarrierAuth(ctx, w, true, RoleUpload, DeriveSecret("cancel"))
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("auth took %v; cancellation did not interrupt the blocked read", elapsed)
	}
	if atomic.LoadInt32(&closed) == 0 {
		t.Fatal("connection was not closed after context cancellation")
	}
	settleGoroutines(t, baseline)
}
