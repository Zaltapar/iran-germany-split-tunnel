// Issue #21: byte-level regression for the Iran SOCKS5 handler
// (handleSOCKS5Conn). Drives the REAL handleSOCKS5Conn over a two-node in-
// memory topology and asserts the EXACT 10-byte SOCKS5 reply the client
// receives for each bootstrap outcome: 0x00 on a live target, and the
// accurate RFC 1928 error codes (refused 0x05, DNS 0x04, timeout 0x06)
// otherwise. This locks the guarantee that the 0x00 reply is written only
// after Germany's 0x00 verdict, and that a failed target NEVER yields a
// false 0x00.
package main

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
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
)

// errConnRefused drives the 0x05 branch of the SOCKS5 reply classification.
var errConnRefused = syscall.ECONNREFUSED

// errDialTimeout drives the 0x06 branch (net.Error with Timeout()=true).
var errDialTimeout = timeoutErr{}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// socksTopo wires a real Iran node (RoleIran) against a controllable German
// node (RoleGermany) over in-memory carriers, exactly like the pkg/node e2e
// harness, and returns a Splitter whose handleSOCKS5Conn can be driven by a
// SOCKS5 request. The German TargetDial is governed by the returned
// setDial function.
type socksTopo struct {
	t            *testing.T
	secret       []byte
	iran         *node.Node
	de           *node.Node
	upGe, downGe *testutil.MemConn
	upIr, downIr *testutil.MemConn
	dialResult   atomic.Pointer[dialResult]
}

type dialResult struct {
	conn net.Conn
	err  error
}

func newSocksTopo(t *testing.T) (*socksTopo, *Splitter, func(*dialResult)) {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	nt := &socksTopo{t: t, secret: secret}
	nt.dialResult.Store(&dialResult{})
	logger := log.New(io.Discard, "", 0)

	var err error
	nt.de, err = node.NewNode(node.Config{
		Role: node.RoleGermany, Grace: 2 * time.Second,
		RelayBufSize: 4096, BufferBytes: 256 << 10, KeepAliveInterval: time.Hour,
		TargetDial: func(addr string) (net.Conn, error) {
			d := nt.dialResult.Load()
			if d == nil {
				return nil, nil
			}
			return d.conn, d.err
		},
	}, logger, secret)
	if err != nil {
		t.Fatalf("NewNode(germany): %v", err)
	}
	nt.iran, err = node.NewNode(node.Config{
		Role: node.RoleIran, Grace: 2 * time.Second,
		RelayBufSize: 4096, BufferBytes: 256 << 10, KeepAliveInterval: time.Hour,
		BootstrapWait: 3 * time.Second,
	}, logger, secret)
	if err != nil {
		t.Fatalf("NewNode(iran): %v", err)
	}
	t.Cleanup(func() { nt.de.Close(); nt.iran.Close() })

	nt.wire()

	// setDial publishes the next German TargetDial result.
	setDial := func(d *dialResult) { nt.dialResult.Store(d) }
	return nt, &Splitter{node: nt.iran, logger: logger}, setDial
}

func (nt *socksTopo) wire() {
	nt.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	nt.upIr, nt.upGe = testutil.NewMemPipe()
	nt.downIr, nt.downGe = testutil.NewMemPipe()
	deReady := make(chan struct{})
	irReady := make(chan struct{})
	go func() {
		defer close(deReady)
		br, err := mux.CarrierAuth(ctx, nt.upGe, true, mux.RoleUpload, nt.secret)
		if err != nil {
			return
		}
		nt.de.InstallUp(nt.upGe, br)
		br2, err := mux.CarrierAuth(ctx, nt.downGe, false, mux.RoleDownload, nt.secret)
		if err != nil {
			return
		}
		nt.de.InstallDown(nt.downGe, br2)
	}()
	go func() {
		defer close(irReady)
		br, err := mux.CarrierAuth(ctx, nt.upIr, false, mux.RoleUpload, nt.secret)
		if err != nil {
			return
		}
		nt.iran.InstallUp(nt.upIr, br)
		br2, err := mux.CarrierAuth(ctx, nt.downIr, true, mux.RoleDownload, nt.secret)
		if err != nil {
			return
		}
		nt.iran.InstallDown(nt.downIr, br2)
	}()
	waitReady(nt.t, deReady, "germany carriers ready")
	waitReady(nt.t, irReady, "iran carriers ready")
}

func waitReady(t *testing.T, ch chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// socksSuccessReply / socksErrReply are the exact 10-byte SOCKS5 reply frames
// (bind addr 0.0.0.0:0, atyp IPv4) the client expects for a given status.
func socksReplyBytes(status byte) []byte {
	return []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}

// driveSocks runs handleSOCKS5Conn against a client pipe carrying a no-auth
// CONNECT for the given IPv4 address. It reads and discards the 2-byte method-
// selection reply, then returns the 10-byte SOCKS5 CONNECT reply the client
// receives, bounded by the timeout.
func driveSocks(t *testing.T, s *Splitter, addr []byte, port uint16, timeout time.Duration) []byte {
	t.Helper()
	clientSrv, clientCli := testutil.NewMemPipe()
	t.Cleanup(func() { clientSrv.Close(); clientCli.Close() })
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x01, 0x01, addr, port)...)
	if _, err := clientCli.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}
	go s.handleSOCKS5Conn(clientSrv)
	clientCli.SetReadDeadline(time.Now().Add(timeout))
	// Read and discard the 2-byte method-selection reply [0x05 0x00].
	_ = readBytes(t, clientCli, 2)
	// Now read the 10-byte CONNECT reply.
	return readBytes(t, clientCli, 10)
}

// TestHandleSOCKS5SuccessPayload: live target -> the client receives the
// exact 0x00 reply (10 bytes, bind 0.0.0.0:0), and application data flows
// both ways through the tunnel.
func TestHandleSOCKS5SuccessPayload(t *testing.T) {
	_, s, setDial := newSocksTopo(t)
	targetApp, targetGe := testutil.NewMemPipe()
	t.Cleanup(func() { targetApp.Close(); targetGe.Close() })
	setDial(&dialResult{conn: targetGe})

	clientSrv, clientCli := testutil.NewMemPipe()
	t.Cleanup(func() { clientSrv.Close(); clientCli.Close() })
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x01, 0x01, []byte{93, 184, 215, 14}, 443)...)
	if _, err := clientCli.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}
	go s.handleSOCKS5Conn(clientSrv)
	clientCli.SetReadDeadline(time.Now().Add(3 * time.Second))
	// Read and discard the 2-byte method-selection reply [0x05 0x00].
	method := readBytes(t, clientCli, 2)
	if want := []byte{0x05, 0x00}; bytesDiffer(method, want) {
		t.Fatalf("method reply = %v, want [0x05 0x00]", method)
	}
	// Now read the 10-byte CONNECT reply.
	reply := readBytes(t, clientCli, 10)
	if want := socksReplyBytes(0x00); len(reply) != 10 || bytesDiffer(reply, want) {
		t.Fatalf("SOCKS5 success reply = %v, want %v (0x00)", reply, want)
	}
	// Application payload now flows both ways through the tunnel.
	appReq := []byte("PING")
	if _, err := clientCli.Write(appReq); err != nil {
		t.Fatalf("write app request: %v", err)
	}
	gotReq := readBytes(t, targetApp, len(appReq))
	if string(gotReq) != string(appReq) {
		t.Fatalf("target got %q, want request %q", gotReq, appReq)
	}
	appResp := []byte("PONG!")
	if _, err := targetApp.Write(appResp); err != nil {
		t.Fatalf("write app response: %v", err)
	}
	gotResp := readBytes(t, clientCli, len(appResp))
	if string(gotResp) != string(appResp) {
		t.Fatalf("client got %q, want response %q", gotResp, appResp)
	}
}

// TestHandleSOCKS5TargetRefused: a refused target yields the exact 0x05 reply
// (NOT a false 0x00).
func TestHandleSOCKS5TargetRefused(t *testing.T) {
	nt, s, setDial := newSocksTopo(t)
	_ = nt
	setDial(&dialResult{err: &net.OpError{Op: "dial", Err: errConnRefused}})
	got := driveSocks(t, s, []byte{93, 184, 215, 14}, 443, 3*time.Second)
	if want := socksReplyBytes(0x05); len(got) < 10 || bytesDiffer(got[:10], want) {
		t.Fatalf("SOCKS5 refused reply = %v, want %v (0x05)", got, want)
	}
}

// TestHandleSOCKS5DNSFailure: a DNS failure yields the exact 0x04 reply.
func TestHandleSOCKS5DNSFailure(t *testing.T) {
	nt, s, setDial := newSocksTopo(t)
	_ = nt
	setDial(&dialResult{err: &net.DNSError{Err: "no such host", Name: "dead.example", IsNotFound: true}})
	got := driveSocks(t, s, []byte{93, 184, 215, 14}, 443, 3*time.Second)
	if want := socksReplyBytes(0x04); len(got) < 10 || bytesDiffer(got[:10], want) {
		t.Fatalf("SOCKS5 DNS-failure reply = %v, want %v (0x04)", got, want)
	}
}

// TestHandleSOCKS5Timeout: a dial timeout yields the exact 0x06 reply.
func TestHandleSOCKS5Timeout(t *testing.T) {
	nt, s, setDial := newSocksTopo(t)
	_ = nt
	setDial(&dialResult{err: &net.OpError{Op: "dial", Err: errDialTimeout}})
	got := driveSocks(t, s, []byte{93, 184, 215, 14}, 443, 3*time.Second)
	if want := socksReplyBytes(0x06); len(got) < 10 || bytesDiffer(got[:10], want) {
		t.Fatalf("SOCKS5 timeout reply = %v, want %v (0x06)", got, want)
	}
}

func readBytes(t *testing.T, c *testutil.MemConn, n int) []byte {
	t.Helper()
	out := make([]byte, 0, n)
	tmp := make([]byte, n)
	for len(out) < n {
		got, err := c.Read(tmp[len(out):])
		if got > 0 {
			out = append(out, tmp[:got]...)
		}
		if err != nil {
			break
		}
	}
	return out
}

func bytesDiffer(a, b []byte) bool {
	if len(a) != len(b) {
		return true
	}
	for i := range a {
		if a[i] != b[i] {
			return true
		}
	}
	return false
}
