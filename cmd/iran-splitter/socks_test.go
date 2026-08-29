package main

import (
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// socksGreetingNoAuth is [version 5, 1 method, no-authentication].
var socksGreetingNoAuth = []byte{0x05, 0x01, 0x00}

// buildSocksRequest assembles a SOCKS5 request: [0x05, CMD, 0x00, ATYP, ...].
// For domain address type (0x03) the domain is prefixed with its length
// byte, as required by the SOCKS5 spec.
func buildSocksRequest(cmd, atyp byte, addr []byte, port uint16) []byte {
	req := []byte{0x05, cmd, 0x00, atyp}
	if atyp == 0x03 {
		req = append(req, byte(len(addr)))
	}
	req = append(req, addr...)
	return append(req, byte(port>>8), byte(port))
}

// negotiate drives socksNegotiate with the given client bytes and returns
// the result plus whatever reply bytes the server wrote.
func negotiate(t *testing.T, request []byte) (*session.Destination, error, []byte) {
	t.Helper()
	srv, cli := testutil.NewMemPipe()
	defer srv.Close()
	defer cli.Close()
	if _, err := cli.Write(request); err != nil {
		t.Fatalf("client write: %v", err)
	}
	dest, err := socksNegotiate(srv)

	cli.SetDeadline(time.Now().Add(200 * time.Millisecond))
	var reply []byte
	tmp := make([]byte, 16)
	if n, _ := cli.Read(tmp); n > 0 {
		reply = append(reply, tmp[:n]...)
	}
	return dest, err, reply
}

func TestSocksNegotiateDomain(t *testing.T) {
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x01, 0x03, []byte("example.com"), 443)...)
	dest, err, reply := negotiate(t, req)
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if dest.AddrType != session.AddrTypeDomain || dest.Addr != "example.com" || dest.Port != 443 {
		t.Fatalf("dest = %+v", dest)
	}
	// Method selection reply: [0x05, 0x00].
	if len(reply) < 2 || reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("reply = %v, want method-OK prefix", reply)
	}
}

func TestSocksNegotiateIPv4(t *testing.T) {
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x01, 0x01, []byte{8, 8, 8, 8}, 53)...)
	dest, err, _ := negotiate(t, req)
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if dest.AddrType != session.AddrTypeIPv4 || dest.Addr != "8.8.8.8" || dest.Port != 53 {
		t.Fatalf("dest = %+v", dest)
	}
}

func TestSocksNegotiateIPv6(t *testing.T) {
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x01, 0x04, []byte{
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
		}, 443)...)
	dest, err, _ := negotiate(t, req)
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if dest.AddrType != session.AddrTypeIPv6 || dest.Addr != "2001:db8::1" || dest.Port != 443 {
		t.Fatalf("dest = %+v", dest)
	}
}

func TestSocksNegotiateBadVersion(t *testing.T) {
	req := []byte{0x04, 0x01, 0x00} // SOCKS version 4
	_, err, reply := negotiate(t, req)
	if err == nil {
		t.Fatal("bad SOCKS version accepted")
	}
	// No reply is written on a version mismatch.
	if len(reply) != 0 {
		t.Fatalf("unexpected reply %v for bad version", reply)
	}
}

func TestSocksNegotiateNoMethod(t *testing.T) {
	// Offer only user/password (0x02): no no-auth method.
	req := []byte{0x05, 0x01, 0x02}
	_, err, reply := negotiate(t, req)
	if err == nil {
		t.Fatal("unacceptable method set accepted")
	}
	if len(reply) < 2 || reply[0] != 0x05 || reply[1] != 0xFF {
		t.Fatalf("reply = %v, want [0x05 0xFF]", reply)
	}
}

func TestSocksNegotiateZeroMethods(t *testing.T) {
	// NMETHODS = 0 means no method is offered.
	req := []byte{0x05, 0x00}
	_, err, reply := negotiate(t, req)
	if err == nil {
		t.Fatal("zero-method greeting accepted")
	}
	if len(reply) < 2 || reply[1] != 0xFF {
		t.Fatalf("reply = %v, want [0x05 0xFF]", reply)
	}
}

func TestSocksNegotiateBadCommand(t *testing.T) {
	// BIND (0x02) instead of CONNECT (0x01).
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x02, 0x01, []byte{8, 8, 8, 8}, 53)...)
	_, err, reply := negotiate(t, req)
	if err == nil {
		t.Fatal("non-CONNECT command accepted")
	}
	// The server wrote the 2-byte method-OK reply first, then the 10-byte
	// socksReply with status 0x07.
	if len(reply) < 12 {
		t.Fatalf("reply too short: %v", reply)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("method-OK prefix missing: %v", reply)
	}
	if reply[2] != 0x05 || reply[3] != 0x07 {
		t.Fatalf("reply = %v, want status 0x07 after method-OK", reply)
	}
}

func TestSocksNegotiateTruncatedGreeting(t *testing.T) {
	srv, cli := testutil.NewMemPipe()
	defer srv.Close()
	defer cli.Close()
	srv.SetDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := cli.Write([]byte{0x05}); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if _, err := socksNegotiate(srv); err == nil {
		t.Fatal("truncated greeting accepted")
	}
}

func TestSocksNegotiateTruncatedDestination(t *testing.T) {
	// IPv4 request with only 2 of 4 address bytes and no port.
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x01, 0x01, []byte{8, 8}, 53)...)
	srv, cli := testutil.NewMemPipe()
	defer srv.Close()
	defer cli.Close()
	srv.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := cli.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if _, err := socksNegotiate(srv); err == nil {
		t.Fatal("truncated destination accepted")
	}
}
