// Issue #21 end-to-end regression: the Iran SOCKS5
// originator (StartSessionAndWait) must wait for Germany's bootstrap verdict
// (the FrameBootstrapAck) and return the ACCURATE RFC 1928 status byte, not a
// premature 0x00. Drives the real two-node production paths: Iran's
// startSessionCore (adoptConn=false) writes the up FrameHeader, Germany's
// bootstrapUpStream runs TargetDial + the bounded down-carrier wait, emits
// FrameBootstrapAck(success | classified-failure), and Iran's WaitBootstrap
// resolves with that byte.
package node

import (
	"context"
	"io"
	"log"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// e2eTopo is a minimal two-node harness with a controllable German dialer.
type e2eTopo struct {
	t      *testing.T
	secret []byte
	iran   *Node
	de     *Node
	// dialResult is what the German TargetDial returns when next invoked.
	dialResult atomic.Pointer[e2eDial]
	// The German-side carrier pipe ends, retained so a test can DROP a
	// carrier mid-bootstrap (close upGe or downGe) and observe the
	// bounded-failure / no-0x00 / prompt-cleanup behavior.
	upGe   *testutil.MemConn
	downGe *testutil.MemConn
}

type e2eDial struct {
	conn net.Conn
	err  error
	// delay simulates a slow target dial: the German TargetDial sleeps this
	// long BEFORE returning conn/err, so the bootstrap window overlaps the
	// target dial (the "slow target dial" edge cases).
	delay time.Duration
}

func (d *e2eDial) target() (net.Conn, error) {
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	return d.conn, d.err
}

func newE2ETopo(t *testing.T) *e2eTopo {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	nt := &e2eTopo{t: t, secret: secret}
	logger := log.New(io.Discard, "", 0)

	// Germany: TargetDial is controllable via nt.dialResult.
	var err error
	nt.de, err = NewNode(Config{
		Role: RoleGermany, Grace: 2 * time.Second,
		RelayBufSize: 4096, BufferBytes: 256 << 10, KeepAliveInterval: time.Hour,
		TargetDial: func(addr string) (net.Conn, error) {
			d := nt.dialResult.Load()
			if d == nil {
				return nil, syscall.ECONNREFUSED
			}
			return d.target() // honors d.delay (slow-dial simulation)
		},
	}, logger, secret)
	if err != nil {
		t.Fatalf("NewNode(germany): %v", err)
	}
	nt.iran, err = NewNode(Config{
		Role: RoleIran, Grace: 2 * time.Second,
		RelayBufSize: 4096, BufferBytes: 256 << 10, KeepAliveInterval: time.Hour,
		BootstrapWait: 3 * time.Second,
	}, logger, secret)
	if err != nil {
		t.Fatalf("NewNode(iran): %v", err)
	}
	t.Cleanup(func() { nt.de.Close(); nt.iran.Close() })
	nt.wire()
	return nt
}

// wire installs both carriers (up: Iran=server, Germany=client; down:
// Iran=client, Germany=server) over in-memory pipes and blocks until both are
// ready on both nodes.
func (nt *e2eTopo) wire() {
	nt.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	upIr, upDe := testutil.NewMemPipe()
	downIr, downDe := testutil.NewMemPipe()
	nt.upGe, nt.downGe = upDe, downDe // German-side ends, retained for drop tests
	deReady := make(chan struct{})
	irReady := make(chan struct{})
	go func() {
		defer close(deReady)
		br, err := mux.CarrierAuth(ctx, upDe, true, mux.RoleUpload, nt.secret)
		if err != nil {
			return
		}
		nt.de.InstallUp(upDe, br)
		br2, err := mux.CarrierAuth(ctx, downDe, false, mux.RoleDownload, nt.secret)
		if err != nil {
			return
		}
		nt.de.InstallDown(downDe, br2)
	}()
	go func() {
		defer close(irReady)
		br, err := mux.CarrierAuth(ctx, upIr, false, mux.RoleUpload, nt.secret)
		if err != nil {
			return
		}
		nt.iran.InstallUp(upIr, br)
		br2, err := mux.CarrierAuth(ctx, downIr, true, mux.RoleDownload, nt.secret)
		if err != nil {
			return
		}
		nt.iran.InstallDown(downIr, br2)
	}()
	nt.waitReady(deReady, "germany carriers ready")
	nt.waitReady(irReady, "iran carriers ready")
}

func (nt *e2eTopo) waitReady(ch chan struct{}, what string) {
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		nt.t.Fatalf("timed out waiting for %s", what)
	}
}

// startAndWait runs Iran's bootstrap-result StartSession and asserts the
// returned status byte equals want. It returns the session plus the Iran-side
// client conn (still caller-owned on the AndWait path) so the caller can adopt
// it on success or close it on failure.
func (nt *e2eTopo) startAndWait(dial *e2eDial, want byte) (*session.Session, *testutil.MemConn) {
	nt.t.Helper()
	nt.dialResult.Store(dial)
	clientNode, clientIr := testutil.NewMemPipe()
	nt.t.Cleanup(func() { clientNode.Close(); clientIr.Close() })
	dest := &session.Destination{AddrType: session.AddrTypeIPv4, Addr: "93.184.215.14", Port: 443}

	sess, got := nt.iran.StartSessionAndWait(clientIr, dest)
	if got != want {
		nt.t.Fatalf("StartSessionAndWait status = 0x%02x, want 0x%02x", got, want)
	}
	return sess, clientIr
}

// TestStartSessionAndWaitSuccess: the target accepts (a live conn is queued) ->
// 0x00, and the session is Active with the client conn still caller-owned so
// the caller can adopt it (mirroring the Iran SOCKS5 handler's success path).
func TestStartSessionAndWaitSuccess(t *testing.T) {
	nt := newE2ETopo(t)
	targetApp, targetGe := testutil.NewMemPipe()
	nt.t.Cleanup(func() { targetApp.Close(); targetGe.Close() })

	sess, clientIr := nt.startAndWait(&e2eDial{conn: targetGe}, 0x00)
	if sess == nil || sess.State() != session.StateActive {
		t.Fatalf("after a 0x00 verdict the Iran session = %v, want Active", sess)
	}
	// On success the caller hands the client conn to the session (the handler's
	// exact step). It is not yet session-owned (adoptConn=false), so this
	// succeeds.
	if !sess.AdoptConn(clientIr) {
		t.Fatal("success path: the caller could not adopt the client conn (it should be free until adoption)")
	}
	// The verdict was received exactly once on the Iran side (the ack resolved
	// the bootstrap wait) — never 0, and the metric fired at least once.
	if got := nt.iran.Metrics().Snapshot().BootstrapAcksReceived; got < 1 {
		t.Fatalf("Iran BootstrapAcksReceived = %d, want >= 1 (the 0x00 verdict)", got)
	}
}

// TestStartSessionAndWaitTargetRefused: the target refuses (ECONNREFUSED) ->
// 0x05, NOT a false 0x00. The session is torn down locally after the verdict.
func TestStartSessionAndWaitTargetRefused(t *testing.T) {
	nt := newE2ETopo(t)
	sess, clientIr := nt.startAndWait(&e2eDial{err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}, 0x05)
	// After a failure verdict the Iran session is closed (the peer's
	// terminating FrameClose on the up stream) and the caller owns the conn.
	waitUntil(t, 3*time.Second, "iran session closed after refused verdict", func() bool {
		return sess.State() == session.StateClosed
	})
	// The conn is NOT session-owned on the failure path (adoptConn=false + the
	// session tore down before any adoption), so the caller closes it.
	clientIr.Close()
	if got := nt.iran.Metrics().Snapshot().BootstrapAcksReceived; got < 1 {
		t.Fatalf("Iran BootstrapAcksReceived = %d, want >= 1 (the 0x05 verdict)", got)
	}
}

// TestStartSessionAndWaitDNSFailure: a DNS/NoHostError -> 0x04.
func TestStartSessionAndWaitDNSFailure(t *testing.T) {
	nt := newE2ETopo(t)
	nt.startAndWait(&e2eDial{err: &net.DNSError{Err: "no such host", Name: "dead.example", IsNotFound: true}}, 0x04)
}

// TestStartSessionAndWaitDialTimeout: a bounded dial timeout -> 0x06.
func TestStartSessionAndWaitDialTimeout(t *testing.T) {
	nt := newE2ETopo(t)
	nt.startAndWait(&e2eDial{err: &net.OpError{Op: "dial", Err: fakeTimeoutNetErr{timeout: true}}}, 0x06)
}

// TestStartSessionAndWaitBreakerOpen: the per-target breaker open -> 0x01
// (general failure; never a false success).
func TestStartSessionAndWaitBreakerOpen(t *testing.T) {
	nt := newE2ETopo(t)
	nt.startAndWait(&e2eDial{err: ErrTargetBreakerOpen}, 0x01)
}

// readAllBytes reads from r until it has received want (as a prefix) or the
// read deadline set on r fires. It drives the deterministic in-memory pipes:
// the relay writes the bytes per-frame, so one Read usually returns them all.
func readAllBytes(t *testing.T, r *testutil.MemConn, want []byte, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	got := make([]byte, 0, len(want))
	buf := make([]byte, 4096)
	for len(got) < len(want) {
		r.SetReadDeadline(deadline)
		n, err := r.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			return got // timeout or EOF: return what we have (the test asserts)
		}
	}
	return got
}

// TestStartSessionAndWaitBidirectionalPayload: after a 0x00 verdict and the
// caller's AdoptConn (which un-gates the down relay), application bytes flow
// both ways end to end: client -> up -> target (request) and target -> down
// -> client (response). This locks the Issue #21 relay lifecycle: the 0x00
// reply is written before any down payload reaches the client.
func TestStartSessionAndWaitBidirectionalPayload(t *testing.T) {
	nt := newE2ETopo(t)
	targetApp, targetGe := testutil.NewMemPipe()
	nt.t.Cleanup(func() { targetApp.Close(); targetGe.Close() })
	clientNode, clientIr := testutil.NewMemPipe()
	nt.t.Cleanup(func() { clientNode.Close(); clientIr.Close() })
	nt.dialResult.Store(&e2eDial{conn: targetGe})
	dest := &session.Destination{AddrType: session.AddrTypeIPv4, Addr: "93.184.215.14", Port: 443}
	sess, status := nt.iran.StartSessionAndWait(clientIr, dest)
	if status != 0x00 {
		t.Fatalf("status = 0x%02x, want 0x00 for a live target", status)
	}
	// Mirror the Iran SOCKS5 handler's exact success step: adopt the conn,
	// which closes the bootstrap gate and lets the down relay deliver payload.
	if !sess.AdoptConn(clientIr) {
		t.Fatal("success path: could not adopt the client conn")
	}

	req := []byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	// clientNode is the app-side peer of clientIr: the Iran up relay reads the
	// client bytes from clientIr, which is fed by writing to its peer.
	if _, err := clientNode.Write(req); err != nil {
		t.Fatalf("write request to client conn: %v", err)
	}
	gotReq := readAllBytes(t, targetApp, req, 2*time.Second)
	if string(gotReq[:len(req)]) != string(req) {
		t.Fatalf("target received %q, want request %q", gotReq, req)
	}
	resp := []byte("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	if _, err := targetApp.Write(resp); err != nil {
		t.Fatalf("write response on target app side: %v", err)
	}
	gotResp := readAllBytes(t, clientNode, resp, 2*time.Second)
	if string(gotResp[:len(resp)]) != string(resp) {
		t.Fatalf("client received %q, want response %q", gotResp, resp)
	}
}

// TestStartSessionAndWaitCarrierDropNoSuccess: with a slow target dial, the
// up carrier is dropped mid-bootstrap. Germany cannot deliver its 0x00 ack
// over the dead up carrier, so the originator's WaitBootstrap is resolved by
// the local teardown backstop (BootstrapEndedWithoutResult -> 0x01) — a
// bounded failure, NEVER a false 0x00.
func TestStartSessionAndWaitCarrierDropNoSuccess(t *testing.T) {
	nt := newE2ETopo(t)
	targetApp, targetGe := testutil.NewMemPipe()
	nt.t.Cleanup(func() { targetApp.Close(); targetGe.Close() })
	nt.dialResult.Store(&e2eDial{conn: targetGe, delay: 150 * time.Millisecond})
	clientNode, clientIr := testutil.NewMemPipe()
	nt.t.Cleanup(func() { clientNode.Close(); clientIr.Close() })
	dest := &session.Destination{AddrType: session.AddrTypeIPv4, Addr: "93.184.215.14", Port: 443}

	type res struct {
		sess *session.Session
		st   byte
	}
	done := make(chan res, 1)
	go func() {
		s, st := nt.iran.StartSessionAndWait(clientIr, dest)
		done <- res{s, st}
	}()
	time.Sleep(50 * time.Millisecond) // let Iran write the up header + Germany start the slow dial
	nt.upGe.Close()                   // drop the up carrier: Germany can no longer send its 0x00 ack

	select {
	case r := <-done:
		// The up-carrier loss detaches Iran's up attachment; the grace
		// window (2s) then tears the session down, resolving the bootstrap
		// wait with the local sentinel (0xFF -> mapped to 0x01). Bounded.
		if r.st == 0x00 {
			t.Fatal("carrier dropped mid-bootstrap returned a false 0x00 success")
		}
		clientIr.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("StartSessionAndWait did not return after the carrier drop (must be bounded by grace, not the 30s bootstrap wait)")
	}
}

// TestStartSessionAndWaitClientDisconnectBeforeBootstrap: with a slow target
// dial, the SOCKS5 client closes its socket BEFORE the remote verdict. The up
// relay observes the EOF while the bootstrap gate is still open (the caller
// has not adopted the conn), closes the session, and the WaitBootstrap
// resolves PROMPTLY (via the local backstop) instead of waiting for the slow
// dial to finish. Asserts a bounded, prompt return with no leaked target conn.
func TestStartSessionAndWaitClientDisconnectBeforeBootstrap(t *testing.T) {
	nt := newE2ETopo(t)
	targetApp, targetGe := testutil.NewMemPipe()
	nt.t.Cleanup(func() { targetApp.Close(); targetGe.Close() })
	// A slow dial far longer than the client's patience: proves the abort is
	// driven by the client, not by the dial completing.
	nt.dialResult.Store(&e2eDial{conn: targetGe, delay: 1500 * time.Millisecond})
	clientNode, clientIr := testutil.NewMemPipe()
	nt.t.Cleanup(func() { clientNode.Close(); clientIr.Close() })
	dest := &session.Destination{AddrType: session.AddrTypeIPv4, Addr: "93.184.215.14", Port: 443}

	type res struct {
		sess *session.Session
		st   byte
	}
	done := make(chan res, 1)
	start := time.Now()
	go func() {
		s, st := nt.iran.StartSessionAndWait(clientIr, dest)
		done <- res{s, st}
	}()
	// The client gives up waiting for the 0x00 reply and closes the socket.
	time.Sleep(50 * time.Millisecond)
	clientNode.Close() // the "app" side closes -> Iran's client conn sees EOF

	select {
	case r := <-done:
		if r.st == 0x00 {
			t.Fatal("client disconnected before bootstrap returned a false 0x00")
		}
		elapsed := time.Since(start)
		if elapsed > 400*time.Millisecond {
			t.Fatalf("StartSessionAndWait took %v after the client disconnect; the abort must be prompt (bounded), not wait out the 1.5s dial", elapsed)
		}
		// The session must have torn down, releasing Germany's target conn
		// (no leak): the remote session closes once the up stream's
		// half-close/frame-close propagates, or the carrier loss does.
		waitUntil(t, 3*time.Second, "remote target conn released after client abort", func() bool {
			return r.sess.State() == session.StateClosed
		})
	case <-time.After(5 * time.Second):
		t.Fatal("StartSessionAndWait did not return promptly after the client disconnected")
	}
}
