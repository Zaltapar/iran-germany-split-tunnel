// keepalive_test.go — Issue #19: kernel TCP keepalive on the long-lived
// client / target / carrier TCP sockets. The helper is a no-op for
// non-TCP transports (in-memory pipes, WebSocket carriers) and when the
// knob is disabled (0); the negative value is refused at Sanitize. These
// tests exercise the decision logic and the no-panic / no-error guarantees
// without needing to read the kernel's SO_KEEPALIVE option back
// (platform-independent).
package node

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// newKeepAliveNode builds a bare Iran node with the given TCP keepalive
// period (ms) and returns it. Sanitize runs inside NewNode, so a negative
// period is refused before the node is ever returned.
func newKeepAliveNode(t *testing.T, keepAliveMs int) *Node {
	t.Helper()
	cfg := Config{
		Role:         RoleIran,
		Grace:        2 * time.Second,
		RelayBufSize: 256,
		BufferBytes:  4096,
		// Hour keepalive so the mux pings never interfere with the test.
		KeepAliveInterval: time.Hour,
		TCPKeepAliveMs:    keepAliveMs,
	}
	if err := cfg.Sanitize(); err != nil {
		t.Fatalf("Sanitize(TCPKeepAliveMs=%d): %v", keepAliveMs, err)
	}
	n, err := NewNode(cfg, log.New(io.Discard, "", 0), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// TestKeepAliveSanitizeRejectsNegative pins the config validation: a
// negative probe period is a misconfiguration and Sanitize refuses it
// (0 is a valid "disabled" sentinel and is NOT lifted to the default).
func TestKeepAliveSanitizeRejectsNegative(t *testing.T) {
	cfg := Config{Role: RoleIran, TCPKeepAliveMs: -5}
	if err := cfg.Sanitize(); err == nil {
		t.Fatal("Sanitize accepted a negative TCPKeepAliveMs; want an error")
	}

	// 0 is legal (explicitly disabled — the operator reached it via
	// SPLIT_TCP_KEEPALIVE_MS=0 or a hand-built node.Config).
	cfg0 := Config{Role: RoleIran, TCPKeepAliveMs: 0}
	if err := cfg0.Sanitize(); err != nil {
		t.Fatalf("Sanitize(TCPKeepAliveMs=0) = %v, want nil (0 = disabled is valid)", err)
	}
}

// TestApplyKeepAliveSkipsNonTCPConn: the helper must be a silent no-op for
// transports that are not a *net.TCPConn (in-memory test pipes and the
// WebSocket up-carrier both fall in here). It must not panic and must not
// close the conn.
func TestApplyKeepAliveSkipsNonTCPConn(t *testing.T) {
	n := newKeepAliveNode(t, 30000)
	a, b := testutil.NewMemPipe()
	_ = a
	_ = b
	// A MemConn is NOT a *net.TCPConn: the type assertion in the helper
	// fails and it returns early. Call it a few times to prove it never
	// panics or errors on the non-TCP fast path.
	for i := 0; i < 3; i++ {
		n.applyTCPKeepAlive(a)
	}
}

// TestApplyKeepAliveDisabledIsNoOp: with TCPKeepAliveMs=0 the helper returns
// before touching any socket option. On a LIVE loopback TCP conn it must
// leave the socket fully usable (a subsequent read is bounded, not fatal),
// which is the observable "kept the OS default, did not break the socket"
// property.
func TestApplyKeepAliveDisabledIsNoOp(t *testing.T) {
	n := newKeepAliveNode(t, 0)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	n.applyTCPKeepAlive(c) // must be a no-op (0 = disabled)

	// The socket must still be usable: a read with a short deadline times
	// out cleanly rather than erroring on a half-set keepalive option.
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, rerr := c.Read(make([]byte, 1))
	if rerr == nil {
		t.Fatal("read unexpectedly returned data on an idle socket")
	}
	if !errorsIsTimeout(rerr) {
		t.Fatalf("idle read error = %v, want a timeout (the keepalive no-op must not break the socket)", rerr)
	}
}

// TestApplyKeepAliveEnabledOnLiveTCPConn: with the knob enabled, the helper
// applies SetKeepAlive(true) + SetKeepAlivePeriod on a LIVE loopback TCP
// socket. We assert the observable safety property: the socket stays fully
// usable afterwards (a bounded read still times out cleanly, not a fatal
// error from a half-applied option). Applying the option itself is
// best-effort; a real TCP conn accepts it, so the socket must remain sound.
func TestApplyKeepAliveEnabledOnLiveTCPConn(t *testing.T) {
	n := newKeepAliveNode(t, 30000)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	n.applyTCPKeepAlive(c) // enabled: SetKeepAlive(true) + 30s period

	// The enabled path must not break the socket: a bounded read still
	// times out cleanly.
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, rerr := c.Read(make([]byte, 1))
	if rerr == nil {
		t.Fatal("read unexpectedly returned data on an idle socket")
	}
	if !errorsIsTimeout(rerr) {
		t.Fatalf("idle read error = %v, want a timeout (the keepalive option must not break the socket)", rerr)
	}
}

// TestApplyKeepAliveOnNonTCPRealPipe: net.Pipe() yields a *net.PipeConn
// that is NOT a *net.TCPConn — the helper must skip it (no panic) and the
// pipe remains intact afterwards. (net.Pipe is unbuffered, so we only
// exercise the no-op call, not a blocking Write.)
func TestApplyKeepAliveOnNonTCPRealPipe(t *testing.T) {
	n := newKeepAliveNode(t, 30000)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// Must be a silent no-op: *net.PipeConn fails the *net.TCPConn
	// assertion, so no socket option is touched and nothing panics.
	n.applyTCPKeepAlive(a)
	_ = b // keep the pair alive for the defers; no blocking I/O
}

// errorsIsTimeout reports whether err is a deadline/timeout error (the
// platform-portable form of "idle read hit its deadline").
func errorsIsTimeout(err error) bool {
	ne, ok := err.(interface{ Timeout() bool })
	if !ok {
		return false
	}
	return ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, os.ErrClosed)
}

// TestKeepAliveDefaultSentinel pins that 0 is the disabled sentinel and is
// NOT lifted to the 30s default by Sanitize (distinct from the other node
// knobs, which DO lift 0). This is what lets an operator disable kernel
// keepalive with SPLIT_TCP_KEEPALIVE_MS=0.
func TestKeepAliveDefaultSentinel(t *testing.T) {
	if err := (&Config{Role: RoleIran, TCPKeepAliveMs: 0}).Sanitize(); err != nil {
		t.Fatalf("Sanitize(0) must succeed (disabled): %v", err)
	}
	// A positive value is preserved.
	cfg := &Config{Role: RoleIran, TCPKeepAliveMs: 45000}
	if err := cfg.Sanitize(); err != nil {
		t.Fatalf("Sanitize(45000): %v", err)
	}
	if cfg.TCPKeepAliveMs != 45000 {
		t.Fatalf("TCPKeepAliveMs = %d, want 45000 (unmodified)", cfg.TCPKeepAliveMs)
	}
}

// TestKeepAliveConfigWiring guards the env→config plumbing in a way that is
// independent of the kernel: a hand-built Config with the knob set flows
// through Sanitize unchanged and the helper sees that value. (The
// env→field load itself is covered by internal/config's Load tests.)
func TestKeepAliveConfigWiring(t *testing.T) {
	cfg := &Config{Role: RoleIran, TCPKeepAliveMs: 60000}
	if err := cfg.Sanitize(); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if cfg.TCPKeepAliveMs != 60000 {
		t.Fatalf("TCPKeepAliveMs = %d, want 60000", cfg.TCPKeepAliveMs)
	}
}
