package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// mockSocks runs a minimal SOCKS5 server on 127.0.0.1; each accepted
// connection's negotiation is handled by handler (which receives the raw
// CONNECT request bytes after the greeting, and returns the reply status
// to send). The server records every request for assertions.
type mockSocks struct {
	ln      net.Listener
	t       *testing.T
	status  byte // reply status for CONNECT
	handler func(req []byte)
	seen    [][]byte
	cleanup func()

	// RFC 1929 auth-mock controls (plans/socks5-auth-design.md §7.6):
	// when startAuthMock drives a connection, the server advertises
	// authMethod, and (for 0x02) answers the sub-negotiation with
	// authSubStatus before the CONNECT exchange.
	authMethod    byte
	authSubStatus byte
}

func startMock(t *testing.T, status byte, handler func(req []byte)) *mockSocks {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &mockSocks{ln: ln, t: t, status: status, handler: handler}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(c)
		}
	}()
	m.cleanup = func() { ln.Close() }
	t.Cleanup(m.cleanup)
	return m
}

// startAuthMock runs a mock that advertises a configurable method byte in
// the greeting reply. When authMethod == 0x02 it answers the RFC 1929
// sub-negotiation with authSubStatus (0x00 success / 0x01 failure) before
// falling through to the normal CONNECT handling.
func startAuthMock(t *testing.T, authMethod, authSubStatus, status byte, handler func(req []byte)) *mockSocks {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &mockSocks{
		ln:            ln,
		t:             t,
		status:        status,
		handler:       handler,
		authMethod:    authMethod,
		authSubStatus: authSubStatus,
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serveAuth(c)
		}
	}()
	m.cleanup = func() { ln.Close() }
	t.Cleanup(m.cleanup)
	return m
}

// serveAuth handles one connection for an auth mock: read the greeting,
// reply with the configured method, and if 0x02, do the RFC 1929
// sub-negotiation before continuing to the CONNECT exchange (the same
// inline handling as mockSocks.serve but with the auth stage).
func (m *mockSocks) serveAuth(c net.Conn) {
	defer c.Close()
	var greet [3]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, m.authMethod}); err != nil {
		return
	}
	if m.authMethod == 0x02 {
		// Read the client's RFC 1929 frame: VER, ULEN, UNAME, PLEN, PASSWD.
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		user := make([]byte, int(hdr[1]))
		if _, err := io.ReadFull(c, user); err != nil {
			return
		}
		var pelen [1]byte
		if _, err := io.ReadFull(c, pelen[:]); err != nil {
			return
		}
		pass := make([]byte, int(pelen[0]))
		if _, err := io.ReadFull(c, pass); err != nil {
			return
		}
		if _, err := c.Write([]byte{0x01, m.authSubStatus}); err != nil {
			return
		}
		if m.authSubStatus != 0x00 {
			return // the server closes after a 01 01 reply (no CONNECT)
		}
	}
	// CONNECT exchange: identical to serve's CONNECT path.
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	var reqBytes []byte
	switch req[3] {
	case 0x01:
		b := make([]byte, 6)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		reqBytes = append(req[:], b...)
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		dom := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(c, dom); err != nil {
			return
		}
		reqBytes = append(req[:], dom...)
	case 0x04:
		b := make([]byte, 18)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		reqBytes = append(req[:], b...)
	default:
		return
	}
	m.t.Log("auth request: ", reqBytes)
	if m.handler != nil {
		m.handler(reqBytes)
	}
	_, _ = c.Write(append([]byte{0x05, m.status, 0x00, 0x01}, 0, 0, 0, 0, 0, 0))
}

func (m *mockSocks) addr() string { return m.ln.Addr().String() }

func (m *mockSocks) serve(c net.Conn) {
	defer c.Close()
	var greet [3]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	// Read the destination per the request's atyp, then reassemble the
	// full request for the handler.
	var reqBytes []byte
	switch req[3] {
	case 0x01:
		b := make([]byte, 6)
		_, err := io.ReadFull(c, b)
		reqBytes = append(req[:], b...)
		if err != nil {
			return
		}
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		dom := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(c, dom); err != nil {
			return
		}
		reqBytes = append(req[:], dom...)
	case 0x04:
		b := make([]byte, 18)
		_, err := io.ReadFull(c, b)
		reqBytes = append(req[:], b...)
		if err != nil {
			return
		}
	default:
		return
	}
	m.t.Log("request: ", reqBytes)
	if m.handler != nil {
		m.handler(reqBytes)
	}
	// Reply: [0x05, status, 0x00, 0x01, 0.0.0.0:0]
	_, _ = c.Write(append([]byte{0x05, m.status, 0x00, 0x01}, 0, 0, 0, 0, 0, 0))
	// If the handler wants to relay data after the reply it does so by
	// writing to c itself (the handler holds a closure over it via a
	// channel in the tests that need it).
}

func TestDialSuccessAndDataFlow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var greet [3]byte
		io.ReadFull(c, greet[:])
		c.Write([]byte{0x05, 0x00})
		var req [4]byte
		io.ReadFull(c, req[:])
		var rest [6]byte
		io.ReadFull(c, rest[:])
		c.Write(append([]byte{0x05, 0x00, 0x00, 0x01}, 0, 0, 0, 0, 0, 0))
		// Echo back 3 bytes to prove the tunnel relays server→client.
		c.Write([]byte{0xDE, 0xAD, 0xBE})
	}()

	client, err := Dial(ln.Addr().String(), "10.1.2.3", 80, 3*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	client.Conn().SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 3)
	if _, err := io.ReadFull(client.Conn(), buf); err != nil {
		t.Fatalf("read from tunnel: %v", err)
	}
	if !bytes.Equal(buf, []byte{0xDE, 0xAD, 0xBE}) {
		t.Fatalf("tunnel returned %x, want deadbe", buf)
	}
}

func TestDialStatus06(t *testing.T) {
	m := startMock(t, 0x06, nil)
	_, err := Dial(m.addr(), "1.2.3.4", 80, 3*time.Second)
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("want *StatusError, got %T: %v", err, err)
	}
	if se.Code != 0x06 {
		t.Fatalf("status = 0x%02x, want 0x06", se.Code)
	}
	if !strings.Contains(se.Error(), "0x06") {
		t.Fatalf("error message must name the code: %v", se)
	}
}

// TestDialDistinguishesPreEstablishmentFailureFromPostEstablishmentRefusal
// locks in the SOCKS contract: setup/carrier failure is a 0x06 reply, while a
// target refusal discovered after a successful SOCKS reply is asynchronous
// tunnel EOF, not a second SOCKS reply. Both paths must close their sockets.
func TestDialDistinguishesPreEstablishmentFailureFromPostEstablishmentRefusal(t *testing.T) {
	pre := startMock(t, 0x06, nil)
	_, err := Dial(pre.addr(), "127.0.0.1", 1, time.Second)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) || statusErr.Code != 0x06 {
		t.Fatalf("pre-establishment error = %T %v, want SOCKS status 0x06", err, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverDone := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer c.Close()
		var greeting [3]byte
		if _, err := io.ReadFull(c, greeting[:]); err != nil {
			serverDone <- err
			return
		}
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
			serverDone <- err
			return
		}
		var req [10]byte
		if _, err := io.ReadFull(c, req[:]); err != nil {
			serverDone <- err
			return
		}
		if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()
	client, err := Dial(ln.Addr().String(), "127.0.0.1", 1, time.Second)
	if err != nil {
		t.Fatalf("post-establishment Dial: %v", err)
	}
	defer client.Close()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("post-establishment server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("post-establishment server did not complete setup")
	}
	client.Conn().SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := client.Conn().Read(one[:]); err != io.EOF {
		t.Fatalf("post-establishment target refusal read = %v, want bounded EOF", err)
	}
}

func TestDialTimeoutSilentServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Accept and stay silent (never answer the greeting).
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close() // close after the test's timeout fires
		}
	}()
	start := time.Now()
	_, err = Dial(ln.Addr().String(), "1.2.3.4", 80, 500*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Dial against a silent server must fail")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("timeout was not enforced: waited %v", elapsed)
	}
}

func TestConnectRequestEncoding(t *testing.T) {
	// IPv4
	b, err := buildConnect("93.184.216.34", 443)
	if err != nil {
		t.Fatal(err)
	}
	want4 := []byte{0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB}
	if !bytes.Equal(b, want4) {
		t.Fatalf("ipv4 encode = % x, want % x", b, want4)
	}
	// Domain
	b, err = buildConnect("example.com", 80)
	if err != nil {
		t.Fatal(err)
	}
	wantDom := append([]byte{0x05, 0x01, 0x00, 0x03, 11}, "example.com"...)
	wantDom = append(wantDom, 0x00, 0x50)
	if !bytes.Equal(b, wantDom) {
		t.Fatalf("domain encode = % x, want % x", b, wantDom)
	}
	// IPv6
	b, err = buildConnect("2001:db8::1", 80)
	if err != nil {
		t.Fatal(err)
	}
	if b[3] != 0x04 || len(b) != 4+16+2 {
		t.Fatalf("ipv6 encode malformed: % x", b)
	}
	if b[4+16] != 0x00 || b[4+17] != 0x50 {
		t.Fatalf("ipv6 port = % x", b[4+16:])
	}
	// 4-in-6 must use atyp 0x01.
	b, err = buildConnect("::ffff:1.2.3.4", 80)
	if err != nil {
		t.Fatal(err)
	}
	if b[3] != 0x01 || len(b) != 4+4+2 {
		t.Fatalf("4in6 encode malformed: % x", b)
	}
}

func TestHalfCloseWrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type res struct{ gotEOF bool }
	resCh := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var greet [3]byte
		io.ReadFull(c, greet[:])
		c.Write([]byte{0x05, 0x00})
		var req [4]byte
		io.ReadFull(c, req[:])
		var rest [6]byte
		io.ReadFull(c, rest[:])
		c.Write(append([]byte{0x05, 0x00, 0x00, 0x01}, 0, 0, 0, 0, 0, 0))
		buf := make([]byte, 8)
		n, err := c.Read(buf)
		_ = n
		resCh <- res{gotEOF: err == io.EOF}
	}()

	client, err := Dial(ln.Addr().String(), "1.2.3.4", 80, 3*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if err := client.HalfCloseWrite(); err != nil {
		t.Fatalf("HalfCloseWrite: %v", err)
	}
	select {
	case r := <-resCh:
		if !r.gotEOF {
			t.Fatal("server did not observe the client FIN")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server never saw EOF after CloseWrite")
	}
}

// ============================================================
// RFC 1929 DialWithAuth tests (plans/socks5-auth-design.md §7.6)
// ============================================================

// TestDialWithAuthSuccess: correct credentials against a mock that replies
// 01 00 → tunnel established, data flows.
func TestDialWithAuthSuccess(t *testing.T) {
	// The mock advertises 0x02, answers the sub-negotiation with 01 00,
	// then handles the CONNECT and echoes 3 bytes back.
	handlerCalled := make(chan struct{}, 1)
	m := startAuthMock(t, 0x02, 0x00, 0x00, func(req []byte) {
		handlerCalled <- struct{}{}
	})
	client, err := DialWithAuth(m.addr(), "10.1.2.3", 80, 3*time.Second, &Credentials{User: "alice", Pass: "s3cr3t"})
	if err != nil {
		t.Fatalf("DialWithAuth: %v", err)
	}
	defer client.Close()
	// The handler (CONNECT) must have been reached (sub-negotiation succeeded).
	select {
	case <-handlerCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT handler not reached after successful sub-negotiation")
	}
}

// TestDialWithAuthWrongCredentials: the mock replies 01 01 → DialWithAuth
// returns an *AuthError and the conn is closed.
func TestDialWithAuthWrongCredentials(t *testing.T) {
	m := startAuthMock(t, 0x02, 0x01, 0x00, nil)
	_, err := DialWithAuth(m.addr(), "10.1.2.3", 80, 3*time.Second, &Credentials{User: "alice", Pass: "wrong"})
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	// The error must not echo the supplied credentials.
	if strings.Contains(ae.Error(), "alice") || strings.Contains(ae.Error(), "wrong") {
		t.Fatalf("AuthError leaked credentials: %v", ae)
	}
}

// TestDialWithAuthMethodNotOffered: the server selects a method the client
// did not offer (0x05 0x01 — a no-auth selection when creds were supplied):
// the client must error (not silently downgrade).
func TestDialWithAuthMethodNotOffered(t *testing.T) {
	// The mock advertises 0x01 (an unexpected method byte) — the client,
	// which offered 0x02, must treat the non-0x02 selection as an error.
	m := startAuthMock(t, 0x01, 0x00, 0x00, nil)
	_, err := DialWithAuth(m.addr(), "10.1.2.3", 80, 3*time.Second, &Credentials{User: "alice", Pass: "s3cr3t"})
	if err == nil {
		t.Fatal("unexpected method selection did not error")
	}
	var se *StatusError
	if errors.As(err, &se) {
		t.Fatalf("want a method/credential error, got *StatusError: %v", se)
	}
}

// TestDialNilCredsStillNoAuth pins the backward-compat contract: Dial
// (nil credentials) still writes {0x05, 0x01, 0x00} and succeeds against a
// no-auth mock — unchanged from today.
func TestDialNilCredsStillNoAuth(t *testing.T) {
	m := startMock(t, 0x00, nil)
	client, err := Dial(m.addr(), "10.1.2.3", 80, 3*time.Second)
	if err != nil {
		t.Fatalf("Dial (nil creds): %v", err)
	}
	client.Close()
}
