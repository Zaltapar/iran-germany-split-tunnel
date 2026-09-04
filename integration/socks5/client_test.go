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
