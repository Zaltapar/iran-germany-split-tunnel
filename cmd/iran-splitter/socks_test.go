package main

import (
	"errors"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// socksGreetingNoAuth is [version 5, 1 method, no-authentication].
var socksGreetingNoAuth = []byte{0x05, 0x01, 0x00}

// socksGreetingUserPass offers both methods as a conforming client would
// when the server advertises {0x00, 0x02} (plans/socks5-auth-design.md
// §2.2: the server's full policy; selection is 0x02).
var socksGreetingUserPass = []byte{0x05, 0x02, 0x00, 0x02}

// authTestUser / authTestPass are the test credentials for the
// auth-configured tests (plans/socks5-auth-design.md §7.1).
const (
	authTestUser = "alice"
	authTestPass = "s3cr3t-password-value"
)

// testCredsEnabled returns the configured-credentials view used by the
// auth tests.
func testCredsEnabled() *socksCredentials {
	return &socksCredentials{enabled: true, user: authTestUser, pass: authTestPass}
}

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

// negotiate drives socksNegotiate with the given client bytes and creds,
// and returns the result plus whatever reply bytes the server wrote.
func negotiate(t *testing.T, request []byte, creds *socksCredentials) (*session.Destination, error, []byte) {
	t.Helper()
	srv, cli := testutil.NewMemPipe()
	defer srv.Close()
	defer cli.Close()
	if _, err := cli.Write(request); err != nil {
		t.Fatalf("client write: %v", err)
	}
	dest, err := socksNegotiate(srv, creds)

	cli.SetDeadline(time.Now().Add(200 * time.Millisecond))
	var reply []byte
	tmp := make([]byte, 16)
	if n, _ := cli.Read(tmp); n > 0 {
		reply = append(reply, tmp[:n]...)
	}
	return dest, err, reply
}

// negotiateNoAuth is today's negotiate(t, req) — auth not configured.
func negotiateNoAuth(t *testing.T, request []byte) (*session.Destination, error, []byte) {
	return negotiate(t, request, &socksCredentials{})
}

func TestSocksNegotiateDomain(t *testing.T) {
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x01, 0x03, []byte("example.com"), 443)...)
	dest, err, reply := negotiateNoAuth(t, req)
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
	dest, err, _ := negotiateNoAuth(t, req)
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
	dest, err, _ := negotiateNoAuth(t, req)
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if dest.AddrType != session.AddrTypeIPv6 || dest.Addr != "2001:db8::1" || dest.Port != 443 {
		t.Fatalf("dest = %+v", dest)
	}
}

func TestSocksNegotiateBadVersion(t *testing.T) {
	req := []byte{0x04, 0x01, 0x00} // SOCKS version 4
	_, err, reply := negotiateNoAuth(t, req)
	if err == nil {
		t.Fatal("bad SOCKS version accepted")
	}
	// No reply is written on a version mismatch.
	if len(reply) != 0 {
		t.Fatalf("unexpected reply %v for bad version", reply)
	}
}

func TestSocksNegotiateNoMethod(t *testing.T) {
	// Offer only user/password (0x02) with auth NOT configured: no
	// no-auth method is available, so the method stage must reject.
	// (When auth IS configured the very same client bytes are answered
	// with 0x05 0x02 and reach the sub-negotiation — see
	// TestSocksAuthConfiguredCorrectCredentials.)
	// [plans/socks5-auth-design.md §7.1 pinned test]
	req := []byte{0x05, 0x01, 0x02}
	_, err, reply := negotiateNoAuth(t, req)
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
	_, err, reply := negotiateNoAuth(t, req)
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
	_, err, reply := negotiateNoAuth(t, req)
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
	if _, err := socksNegotiate(srv, &socksCredentials{}); err == nil {
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
	if _, err := socksNegotiate(srv, &socksCredentials{}); err == nil {
		t.Fatal("truncated destination accepted")
	}
}

// TestSocksNegotiateMaxDomainLength pins the SOCKS5 domain-length
// boundary: the domain length is a single uint8 field, so 255 bytes is
// the protocol maximum and must be accepted. A domain longer than 255
// bytes is NOT representable in a SOCKS5 request (the parser reads the
// length byte and then exactly that many bytes), so no separate
// "domain too long" rejection exists in socksNegotiate — the protocol
// itself makes the audit's `len(dest.Addr) > 255` check unreachable.
func TestSocksNegotiateMaxDomainLength(t *testing.T) {
	domain := make([]byte, 255)
	for i := range domain {
		domain[i] = 'a'
	}
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x01, 0x03, domain, 443)...)
	dest, err, reply := negotiateNoAuth(t, req)
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if dest.AddrType != session.AddrTypeDomain || len(dest.Addr) != 255 || dest.Port != 443 {
		t.Fatalf("dest = %+v, want 255-byte domain on port 443", dest)
	}
	if len(reply) < 2 || reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("reply = %v, want method-OK prefix", reply)
	}
}

// ============================================================
// RFC 1929 auth-configured tests (plans/socks5-auth-design.md §7.1)
// ============================================================

// authRequest assembles a full authenticated client stream: the
// two-method greeting, the RFC 1929 sub-negotiation frame
// (VER=0x01, ULEN, UNAME, PLEN, PASSWD), and a SOCKS request.
func authRequest(user, pass string, cmd, atyp byte, addr []byte, port uint16) []byte {
	req := make([]byte, 0, 64)
	req = append(req, socksGreetingUserPass...)
	frame := append([]byte{0x01, byte(len(user))}, []byte(user)...)
	frame = append(frame, byte(len(pass)))
	frame = append(frame, []byte(pass)...)
	req = append(req, frame...)
	req = append(req, buildSocksRequest(cmd, atyp, addr, port)...)
	return req
}

func TestSocksAuthConfiguredCorrectCredentials(t *testing.T) {
	req := authRequest(authTestUser, authTestPass, 0x01, 0x03, []byte("example.com"), 443)
	dest, err, reply := negotiate(t, req, testCredsEnabled())
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if dest.AddrType != session.AddrTypeDomain || dest.Addr != "example.com" || dest.Port != 443 {
		t.Fatalf("dest = %+v", dest)
	}
	// Reply: [0x05, 0x02] method selection, then [0x01, 0x00] sub-
	// negotiation success.
	if len(reply) < 4 || reply[0] != 0x05 || reply[1] != 0x02 || reply[2] != 0x01 || reply[3] != 0x00 {
		t.Fatalf("reply = %v, want [05 02 01 00] prefix", reply)
	}
}

func TestSocksAuthConfiguredWrongPassword(t *testing.T) {
	req := authRequest(authTestUser, "wrong-password-value", 0x01, 0x03, []byte("example.com"), 443)
	dest, err, reply := negotiate(t, req, testCredsEnabled())
	if !errors.Is(err, errSocksAuthFailed) {
		t.Fatalf("err = %v, want errSocksAuthFailed", err)
	}
	if dest != nil {
		t.Fatalf("dest = %+v, want nil on auth failure", dest)
	}
	// Exactly [0x05, 0x02] + [0x01, 0x01] and nothing after (one attempt,
	// no CONNECT, no retry).
	if len(reply) != 4 || reply[0] != 0x05 || reply[1] != 0x02 || reply[2] != 0x01 || reply[3] != 0x01 {
		t.Fatalf("reply = %v, want exactly [05 02 01 01]", reply)
	}
}

func TestSocksAuthConfiguredWrongUsername(t *testing.T) {
	// Identical shape to the wrong-password case: proves no field-specific
	// behavior leaks (plans/socks5-auth-design.md §3 rule 3).
	req := authRequest("bob", authTestPass, 0x01, 0x03, []byte("example.com"), 443)
	dest, err, reply := negotiate(t, req, testCredsEnabled())
	if !errors.Is(err, errSocksAuthFailed) {
		t.Fatalf("err = %v, want errSocksAuthFailed", err)
	}
	if dest != nil {
		t.Fatalf("dest = %+v, want nil on auth failure", dest)
	}
	if len(reply) != 4 || reply[0] != 0x05 || reply[1] != 0x02 || reply[2] != 0x01 || reply[3] != 0x01 {
		t.Fatalf("reply = %v, want exactly [05 02 01 01]", reply)
	}
}

func TestSocksAuthConfiguredMethodNotOffered(t *testing.T) {
	// Client offers ONLY no-auth (0x00) while auth is configured:
	// 0x00 must NOT be selected — the method stage rejects with 0x05 0xFF
	// (plans/socks5-auth-design.md §2.2, §2.5).
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x01, 0x03, []byte("example.com"), 443)...)
	dest, err, reply := negotiate(t, req, testCredsEnabled())
	if err == nil {
		t.Fatal("no-auth method accepted with auth configured")
	}
	if dest != nil {
		t.Fatalf("dest = %+v, want nil", dest)
	}
	if len(reply) != 2 || reply[0] != 0x05 || reply[1] != 0xFF {
		t.Fatalf("reply = %v, want exactly [05 FF]", reply)
	}
}

func TestSocksAuthMalformedSubNegotiationVersion(t *testing.T) {
	// VER=0x02 (a SOCKS version byte, not the RFC 1929 0x01): malformed
	// frame → error, no sub-negotiation reply, no panic
	// (plans/socks5-auth-design.md §2.4, §2.6).
	req := append(append([]byte{}, socksGreetingUserPass...),
		0x02, 0x01, 0x01, 'a')
	dest, err, reply := negotiate(t, req, testCredsEnabled())
	if err == nil {
		t.Fatal("bad sub-negotiation version accepted")
	}
	if dest != nil {
		t.Fatalf("dest = %+v, want nil", dest)
	}
	// No 01 00 / 01 01 reply: only the [05 02] method selection.
	if len(reply) != 2 || reply[0] != 0x05 || reply[1] != 0x02 {
		t.Fatalf("reply = %v, want exactly [05 02] (no sub-negotiation reply)", reply)
	}
}

func TestSocksAuthMalformedSubNegotiationTruncatedUser(t *testing.T) {
	// ULEN declares 5 bytes; only 1 is sent. The server-side deadline is
	// what turns the blocking read into an error (MemConn blocks forever
	// otherwise; mirrors TestSocksNegotiateTruncatedGreeting).
	srv, cli := testutil.NewMemPipe()
	defer srv.Close()
	defer cli.Close()
	srv.SetDeadline(time.Now().Add(150 * time.Millisecond))
	req := append(append([]byte{}, socksGreetingUserPass...), 0x01, 0x05, 'a')
	if _, err := cli.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if _, err := socksNegotiate(srv, testCredsEnabled()); err == nil {
		t.Fatal("truncated username accepted")
	}
}

func TestSocksAuthMalformedSubNegotiationTruncatedPass(t *testing.T) {
	// Username read fine; PLEN declares 10 but only 2 password bytes arrive.
	srv, cli := testutil.NewMemPipe()
	defer srv.Close()
	defer cli.Close()
	srv.SetDeadline(time.Now().Add(150 * time.Millisecond))
	// Frame: [05 02 00 02] greeting + [VER=01, ULEN=5, "alice", PLEN=10, "xy"]
	// then the CONNECT request. The PLEN declares 10 but only 2 bytes are
	// sent, so the read blocks until the server-side deadline.
	frame := append([]byte{0x01, 5}, []byte(authTestUser)...)
	frame = append(frame, 10)
	frame = append(frame, []byte("xy")...)
	full := append(append([]byte{}, socksGreetingUserPass...), frame...)
	full = append(full, buildSocksRequest(0x01, 0x03, []byte("example.com"), 443)...)
	if _, err := cli.Write(full); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if _, err := socksNegotiate(srv, testCredsEnabled()); err == nil {
		t.Fatal("truncated password accepted")
	}
}

func TestSocksAuthZeroLengthUsername(t *testing.T) {
	// ULEN=0: a 0-length username cannot match a configured 1..255
	// username — rejected as a malformed frame (no success, no 01 01).
	req := append(append([]byte{}, socksGreetingUserPass...),
		0x01, 0x00, 0x05, 's', '3', 'c', 'r', 'e', 't')
	// [VER=01, ULEN=0, PLEN=5, PASS=5 bytes]: without UNAME, the PLEN
	// byte is the 5 raw bytes; the frame the server parses is
	// VER=01 ULEN=0 → rejected before PLEN is even read.
	dest, err, reply := negotiate(t, req, testCredsEnabled())
	if err == nil {
		t.Fatal("zero-length username accepted")
	}
	if dest != nil {
		t.Fatalf("dest = %+v, want nil", dest)
	}
	if len(reply) != 2 || reply[0] != 0x05 || reply[1] != 0x02 {
		t.Fatalf("reply = %v, want exactly [05 02] (no sub-negotiation reply)", reply)
	}
}

func TestSocksAuthMaxLengthCredentials(t *testing.T) {
	// 255-byte user / 255-byte password: the 1-byte length fields carry
	// the protocol maximum, so the correct value must be accepted.
	user := make([]byte, 255)
	pass := make([]byte, 255)
	for i := range user {
		user[i] = 'u'
	}
	for i := range pass {
		pass[i] = 'p'
	}
	creds := &socksCredentials{enabled: true, user: string(user), pass: string(pass)}
	req := authRequest(string(user), string(pass), 0x01, 0x03, []byte("example.com"), 443)
	dest, err, reply := negotiate(t, req, creds)
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if dest.Addr != "example.com" || dest.Port != 443 {
		t.Fatalf("dest = %+v", dest)
	}
	if len(reply) < 4 || reply[2] != 0x01 || reply[3] != 0x00 {
		t.Fatalf("reply = %v, want [05 02 01 00] prefix", reply)
	}
}

func TestSocksNegotiateNoAuthStillMethod00(t *testing.T) {
	// The explicit backward-compat pin (plans/socks5-auth-design.md §8.1):
	// with creds {} the pre-change behavior is byte-for-byte — [0x05,
	// 0x00] method selection and the full CONNECT exchange.
	req := append(append([]byte{}, socksGreetingNoAuth...),
		buildSocksRequest(0x01, 0x03, []byte("example.com"), 443)...)
	dest, err, reply := negotiateNoAuth(t, req)
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if dest.Addr != "example.com" || dest.Port != 443 {
		t.Fatalf("dest = %+v", dest)
	}
	if len(reply) < 2 || reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("reply = %v, want [05 00] method-OK", reply)
	}
}

func TestSocksNegotiateBadCommandWithAuth(t *testing.T) {
	// Valid auth, then BIND instead of CONNECT: the command-not-supported
	// path is unchanged by auth (mirrors TestSocksNegotiateBadCommand).
	req := authRequest(authTestUser, authTestPass, 0x02, 0x01, []byte{8, 8, 8, 8}, 53)
	_, err, reply := negotiate(t, req, testCredsEnabled())
	if err == nil {
		t.Fatal("non-CONNECT command accepted")
	}
	// [05 02] method, [01 00] sub-negotiation success, then the 10-byte
	// socksReply with status 0x07.
	if len(reply) < 14 {
		t.Fatalf("reply too short: %v", reply)
	}
	if reply[0] != 0x05 || reply[1] != 0x02 {
		t.Fatalf("method-OK prefix missing: %v", reply)
	}
	if reply[2] != 0x01 || reply[3] != 0x00 {
		t.Fatalf("sub-negotiation success missing: %v", reply)
	}
	if reply[4] != 0x05 || reply[5] != 0x07 {
		t.Fatalf("reply = %v, want status 0x07 after sub-negotiation", reply)
	}
}

func TestSocksCredsMatchTimingShape(t *testing.T) {
	// Boolean-correctness table for socksCredsMatch: every correct pair is
	// true; any single-field mismatch is false; a correct username with a
	// wrong password (the "no short-circuit" documentation case) is false.
	cases := []struct {
		gotUser, gotPass, wantUser, wantPass string
		want                                 bool
	}{
		{"alice", "p", "alice", "p", true},
		{"alice", "p", "alice", "q", false}, // same user, wrong pass
		{"bob", "p", "alice", "p", false},   // wrong user, same pass
		{"", "", "", "", true},              // two empties are equal (ConstantTimeCompare == 1);
		// unreachable in production: config validation keeps both fields non-empty when auth is enabled
		{"alice", "short", "alice", "longer-password", false}, // length mismatch
		{"al", "p", "alice", "p", false},                      // user length mismatch
	}
	for i, tc := range cases {
		if got := socksCredsMatch(tc.gotUser, tc.gotPass, tc.wantUser, tc.wantPass); got != tc.want {
			t.Errorf("case %d: socksCredsMatch = %v, want %v", i, got, tc.want)
		}
	}
}
