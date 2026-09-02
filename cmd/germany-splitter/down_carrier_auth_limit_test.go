package main

import (
	"context"
	"io"
	"log"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
)

// Issue #5: the Germany down-carrier TCP listener bounds concurrent
// UNAUTHENTICATED handshakes. The bound is a non-blocking gate in the accept
// loop (a buffered channel on the Splitter); saturated connections are closed
// promptly in the accept loop without consuming an auth goroutine.
//
// Production uses a bound of 16 (maxDownHandshakes, a const). The gate is
// per-Splitter state: each test creates its own gate sized to a small N (via
// startDownCarrier's gateCap) so saturation/rejection/leak assertions are
// deterministic and fast. There is no mutable global to shrink — the accept
// loop reads the bound as cap(s.downAuthGate), immutable instance state.
// Tests also shorten mux.AuthTimeout so stalling peers do not hold a slot
// for the full 15 s; that write happens before the accept-loop goroutine is
// spawned (a `go` statement), so it is ordered before every handler's read.
//
// The test plays the DIALING Iran CLIENT. A "silent" peer reads the server's
// auth challenge and then NEVER sends the response, so the server blocks in
// CarrierAuth (reading the response) and holds a gate slot for the duration
// of the auth bound — this is the attack shape the bound must contain.
//
// Observation model (race-free): the test NEVER reads the gate channel or a
// shared net.Conn from a second goroutine. Instead each silent peer exposes
// two signals:
//   - "admitted": closed once the peer has read the server's auth CHALLENGE.
//     The server only sends the challenge from inside CarrierAuth, which runs
//     only after the accept loop acquired a gate slot — so "admitted" proves
//     a slot was acquired for that connection.
//   - "closed": closed when the server closes the connection (auth timeout,
//     DownReady rejection, gate rejection, or shutdown).
// Gate-full is therefore detected by waiting for N "admitted" signals, and a
// gate REJECTION is proven by a connection that is "closed" WITHOUT ever
// being "admitted" (no challenge was sent, so no slot was consumed).

// defaultSecret is a long enough secret for mux.DeriveSecret (the test node
// is built directly, bypassing config's secret policy).
const defaultSecret = "germany-down-test-secret-01234567890123456789"

// newTestDownNode builds a Germany-role node with inert dependencies.
func newTestDownNode(t *testing.T) *node.Node {
	t.Helper()
	cfg := config.Defaults()
	logger := log.New(io.Discard, "", 0)
	n := node.NewNode(node.Config{
		Role:              node.RoleGermany,
		Grace:             time.Duration(cfg.CarrierGraceMs) * time.Millisecond,
		BufferBytes:       cfg.SessionBufBytes,
		RelayBufSize:      cfg.RelayBufSize,
		KeepAliveInterval: cfg.KeepAliveInterval,
		StreamLimits:      streamLimits(cfg),
	}, logger, mux.DeriveSecret(defaultSecret))
	t.Cleanup(n.Close)
	return n
}

// newTestDownSplitter builds a Germany-role Splitter wrapping a fresh node.
func newTestDownSplitter(t *testing.T) *Splitter {
	t.Helper()
	return &Splitter{
		config: config.Defaults(),
		node:   newTestDownNode(t),
		logger: log.New(io.Discard, "", 0),
	}
}

// startDownCarrier starts runDownCarrier against a fresh loopback listener
// (port 0) so tests never contend for the real :9002. It creates the
// unauthenticated-handshake gate HERE (the spawning goroutine) so the gate
// field write happens-before the accept loop and any handler read it; the
// gate's CAPACITY is the unauthenticated-handshake bound (main sizes it to
// maxDownHandshakes, tests pass a smaller one) — there is no mutable global
// to shrink, so no test ever races the accept loop on the bound. Closing the
// returned listener unblocks the accept loop; a cleanup also closes it so the
// accept goroutine can never leak.
func startDownCarrier(t *testing.T, s *Splitter, gateCap int) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.downLn = ln
	s.downAuthGate = make(chan struct{}, gateCap)
	go s.runDownCarrier()
	t.Cleanup(func() { ln.Close() })
	return ln
}

// peerSignal carries the two observation channels for one test-side peer.
type peerSignal struct {
	admitted <-chan struct{} // server sent the challenge (a gate slot was taken)
	closed   <-chan struct{} // server closed the connection
}

// trustedCarrier dials ln and runs a complete (trusted) client handshake in
// a goroutine, then KEEPS the connection open like a real Iran down-carrier
// (which stays up as a long-lived carrier after auth). It returns a done
// channel closed when the connection closes (carrier teardown or rejection).
func trustedCarrier(t *testing.T, ln net.Listener, secret []byte) <-chan struct{} {
	t.Helper()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c.Close()
		if _, err := mux.CarrierAuth(context.Background(), c, true, mux.RoleDownload, secret); err != nil {
			return // handshake failed or the connection was rejected
		}
		// Authenticated: hold the connection open as a live carrier (read
		// until the server closes it) so the down-carrier stays Ready().
		buf := make([]byte, 4096)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
	return done
}

// silentPeer dials ln and models a peer that stalls inside the server's auth
// handshake: it reads the challenge and never sends the response. It returns
// an "admitted" signal (challenge received ⇒ a gate slot was acquired for it)
// and a "closed" signal (server closed the connection).
func silentPeer(t *testing.T, ln net.Listener) peerSignal {
	t.Helper()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	admitted := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		defer c.Close()
		buf := make([]byte, mux.HeaderSize+22)
		if _, err := io.ReadFull(c, buf); err != nil {
			// No challenge (rejected before auth) or already closed.
			return
		}
		close(admitted) // server sent the challenge: a gate slot was acquired
		// Never send a response. Hold until the server closes (auth timeout,
		// DownReady rejection, or shutdown), which makes this read return.
		_, _ = c.Read(buf)
	}()
	return peerSignal{admitted: admitted, closed: closed}
}

// firesWithin reports whether ch is closed within d.
func firesWithin(ch <-chan struct{}, d time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

// waitDone fails the test if done is not closed within timeout.
func waitDone(t *testing.T, done <-chan struct{}, timeout time.Duration, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("%s was not closed within %v", what, timeout)
	}
}

// settledGoroutines returns runtime.NumGoroutine() once it stops moving (the
// repo's standard leak-check idiom, see pkg/node/node_test.go).
func settledGoroutines(t *testing.T, settle time.Duration) int {
	t.Helper()
	var last int
	for i := 0; i < 60; i++ {
		n := runtime.NumGoroutine()
		if n == last && i > 5 {
			return n
		}
		last = n
		time.Sleep(settle)
	}
	return last
}

// TestDownCarrierNormalAuth verifies the normal authenticated path is
// unaffected by the gate: a single legitimate client passes the gate,
// completes the v1 handshake, and the handler installs it (DownReady becomes
// true). A follow-up stalling connection is then rejected by the (unchanged)
// single-carrier DownReady rule, not by the gate.
func TestDownCarrierNormalAuth(t *testing.T) {
	orig := mux.AuthTimeout
	mux.AuthTimeout = 1 * time.Second
	defer func() { mux.AuthTimeout = orig }()

	s := newTestDownSplitter(t)
	ln := startDownCarrier(t, s, maxDownHandshakes)

	// A single legitimate client: the gate admits it, the handshake
	// completes, and the handler installs the carrier.
	trustedCarrier(t, ln, s.node.Secret())
	deadline := time.Now().Add(2 * time.Second)
	for !s.node.DownReady() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.node.DownReady() {
		t.Fatal("DownReady() never became true after a valid install")
	}

	// A second STALLING connection must be rejected by the DownReady rule:
	// the handler acquires a slot, sees DownReady, and closes it promptly
	// before auth (no challenge is sent).
	sec := silentPeer(t, ln)
	waitDone(t, sec.closed, 3*time.Second, "secondary (DownReady) connection")
}

// TestDownCarrierSaturationRejects verifies that at most N unauthenticated
// handshakes are active: N stalling clients fill the gate, and the N+1th
// connection is rejected promptly WITHOUT consuming an auth slot — proven by
// the fact that it is closed WITHOUT ever being admitted (no challenge sent,
// so no gate slot was acquired for it).
func TestDownCarrierSaturationRejects(t *testing.T) {
	const N = 2
	orig := mux.AuthTimeout
	mux.AuthTimeout = 1 * time.Second
	defer func() { mux.AuthTimeout = orig }()

	s := newTestDownSplitter(t)
	ln := startDownCarrier(t, s, N)

	// N stalling clients: each is admitted (reads the challenge ⇒ holds a
	// gate slot). Wait for all N to be admitted, which means the gate is full.
	peers := make([]peerSignal, N)
	for i := range peers {
		peers[i] = silentPeer(t, ln)
	}
	for i, p := range peers {
		if !firesWithin(p.admitted, 5*time.Second) {
			t.Fatalf("peer %d never admitted (no challenge sent); gate not full", i)
		}
	}

	// N+1th connection: the accept loop's non-blocking select must reject it
	// immediately (no slot, no handler, no auth goroutine).
	extra := silentPeer(t, ln)
	waitDone(t, extra.closed, 3*time.Second, "N+1 (saturation) connection")
	// Rejection must not have consumed a slot: no challenge was sent, so it
	// was never admitted (a gate-full rejection closes the conn before auth,
	// i.e. it did not displace or consume any of the N held slots).
	if firesWithin(extra.admitted, 200*time.Millisecond) {
		t.Fatal("N+1 connection was admitted (acquired a gate slot) despite saturation")
	}
}

// TestDownCarrierDownReadyUnchanged verifies the single-carrier DownReady()
// rejection is preserved with the gate in place. The gate is left at its
// default (16), so with only one installed carrier the gate has ample room
// and CANNOT be the cause of the rejection: a complete second carrier is
// still closed before it can install, proving the rule (not the gate) is in
// force and unchanged.
func TestDownCarrierDownReadyUnchanged(t *testing.T) {
	orig := mux.AuthTimeout
	mux.AuthTimeout = 1 * time.Second
	defer func() { mux.AuthTimeout = orig }()

	s := newTestDownSplitter(t) // gate kept at the production bound (16)
	ln := startDownCarrier(t, s, maxDownHandshakes)

	// Complete first carrier.
	trustedCarrier(t, ln, s.node.Secret())
	deadline := time.Now().Add(2 * time.Second)
	for !s.node.DownReady() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.node.DownReady() {
		t.Fatal("DownReady() never became true after a valid install")
	}

	// A COMPLETE second carrier (real handshake) must be rejected by the
	// unchanged DownReady rule: the handler closes it before auth completes.
	// Because the gate (16) has room, only DownReady can be the cause.
	waitDone(t, trustedCarrier(t, ln, s.node.Secret()), 3*time.Second, "second (DownReady) carrier")
	// The first carrier is still the installed one (the second was rejected,
	// never installed — an install would have replaced and closed it).
	if !s.node.DownReady() {
		t.Fatal("first carrier no longer ready after a rejected second carrier")
	}
}

// TestDownCarrierShutdownTerminatesInFlight verifies shutdown terminates all
// in-flight unauthenticated handshakes: with N stalling peers holding the
// gate, closing the listener + node causes the accept loop to return and
// every in-flight connection to be closed promptly (via the auth deadline /
// cancelled context), with no handler goroutine leaked.
func TestDownCarrierShutdownTerminatesInFlight(t *testing.T) {
	const N = 3
	orig := mux.AuthTimeout
	mux.AuthTimeout = 1 * time.Second
	defer func() { mux.AuthTimeout = orig }()

	baseline := runtime.NumGoroutine()
	s := newTestDownSplitter(t)
	ln := startDownCarrier(t, s, N)

	peers := make([]peerSignal, N)
	for i := range peers {
		peers[i] = silentPeer(t, ln)
	}
	// Gate full: all N admitted (each holds a slot).
	for i, p := range peers {
		if !firesWithin(p.admitted, 5*time.Second) {
			t.Fatalf("peer %d never admitted; gate not full", i)
		}
	}

	// Shutdown: close the listener (accept loop returns) and the node (auth
	// context cancels; the TCP auth deadline also expires within the 1 s
	// test AuthTimeout).
	ln.Close()
	s.node.Close()

	// Every in-flight connection must be closed promptly.
	for _, p := range peers {
		waitDone(t, p.closed, 5*time.Second, "in-flight peer")
	}

	// No handler/auth goroutine leaked: the accept loop has exited and every
	// handler has returned, so the goroutine count settles back near the
	// pre-test baseline.
	if n := settledGoroutines(t, 10*time.Millisecond); n > baseline+2 {
		t.Fatalf("goroutine leak: %d after shutdown, %d before", n, baseline)
	}
}

// TestDownCarrierStressNoLeak stresses the listener with many concurrent
// stalling peers (well above the bound), verifies every connection is closed
// promptly and no handler/auth goroutine leaks after teardown.
func TestDownCarrierStressNoLeak(t *testing.T) {
	const N = 4
	const K = 60
	orig := mux.AuthTimeout
	mux.AuthTimeout = 500 * time.Millisecond
	defer func() { mux.AuthTimeout = orig }()

	baseline := runtime.NumGoroutine()
	s := newTestDownSplitter(t)
	ln := startDownCarrier(t, s, N)

	// K stalling peers. The first N hold slots until the auth timeout; the
	// rest are rejected immediately at the gate. All K connections are closed
	// promptly; every peer's "closed" signal fires when the server closes it.
	peers := make([]peerSignal, K)
	for i := range peers {
		peers[i] = silentPeer(t, ln)
	}
	for _, p := range peers {
		waitDone(t, p.closed, 8*time.Second, "stressed peer")
	}

	// Teardown: stop the accept loop and close the node (also via cleanup).
	ln.Close()
	s.node.Close()

	if n := settledGoroutines(t, 10*time.Millisecond); n > baseline+2 {
		t.Fatalf("goroutine leak: %d after stress teardown, %d before", n, baseline)
	}
}
