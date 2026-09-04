// Package socks5 is a minimal, dependency-free SOCKS5 client used ONLY by
// the integration harness (Issue #9, L4/L5). It implements the subset of
// RFC 1928 that the iran-splitter supports: no-authentication negotiation
// and CONNECT to an IPv4, domain, or IPv6 destination.
//
// It is intentionally NOT a general-purpose SOCKS5 library, NOT production
// code, and NOT part of the relay. The relay's own SOCKS5 server lives in
// cmd/iran-splitter/socks.go; this client exists to exercise that server
// (and the full tunnel behind it) as a real client would.
package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// Client is an established SOCKS5 tunnel: a connected net.Conn on which
// bytes flow to the requested destination.
type Client struct {
	conn net.Conn
	dest string // "host:port" as requested
}

// Conn returns the underlying tunnel connection.
func (c *Client) Conn() net.Conn { return c.conn }

// HalfCloseWrite half-closes the tunnel (client → destination FIN).
// Supported when the underlying conn is a *net.TCPConn; the SOCKS5 reply
// carries no information that would make this impossible otherwise, but
// the OS-level half-close is what is under test.
func (c *Client) HalfCloseWrite() error {
	if tc, ok := c.conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return fmt.Errorf("socks5: HalfCloseWrite requires a TCP conn (got %T)", c.conn)
}

// Close closes the tunnel connection.
func (c *Client) Close() error { return c.conn.Close() }

// StatusError is a non-zero SOCKS5 reply status from the server.
type StatusError struct{ Code byte }

func (e *StatusError) Error() string {
	name, ok := statusNames[e.Code]
	if !ok {
		name = "unknown"
	}
	return fmt.Sprintf("socks5: server rejected CONNECT with status 0x%02x (%s)", e.Code, name)
}

var statusNames = map[byte]string{
	0x01: "general SOCKS server failure",
	0x02: "connection not allowed by ruleset",
	0x03: "network unreachable",
	0x04: "host unreachable",
	0x05: "connection refused",
	0x06: "TL/TD exceeded / general failure (relay: carriers not ready within bootstrap wait)",
	0x07: "command not supported",
	0x08: "address type not supported",
}

// Dial connects to the SOCKS5 server at socksAddr and issues a CONNECT to
// dest:port. The entire negotiation (dial + greeting + request + reply) is
// bounded by timeout; after a successful reply the connection has NO
// deadline (the tunnel phase is deadline-free, mirroring the server).
//
// dest may be an IPv4 literal, an IPv6 literal, or a domain name (sent as
// atyp 0x03, which is what the relay forwards to the target dialer).
func Dial(socksAddr, dest string, port int, timeout time.Duration) (*Client, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial %s: %w", socksAddr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	// --- Greeting: [0x05, 1, 0x00] (no authentication) ---
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: greeting: %w", err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(conn, greet[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: greeting reply: %w", err)
	}
	if greet[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5: bad greeting reply version 0x%02x", greet[0])
	}
	if greet[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: server requires auth method 0x%02x (only no-auth is supported)", greet[1])
	}

	// --- CONNECT request ---
	req, err := buildConnect(dest, port)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: connect request: %w", err)
	}

	// --- Reply: [0x05, rep, 0x00, atyp, bind...] ---
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: reply header: %w", err)
	}
	if hdr[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5: bad reply version 0x%02x", hdr[0])
	}
	if hdr[1] != 0x00 {
		// Drain the (ignored) bound address so the close is clean, then
		// report the status. The server closes the conn after the reply
		// anyway (see cmd/iran-splitter handleSOCKS5Conn).
		_ = skipBound(conn, hdr[3])
		conn.SetDeadline(time.Time{})
		return nil, &StatusError{Code: hdr[1]}
	}
	if err := skipBound(conn, hdr[3]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: reply bound address: %w", err)
	}

	// Tunnel phase: no deadline.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return &Client{conn: conn, dest: dest}, nil
}

// buildConnect encodes the SOCKS5 CONNECT request, choosing the address
// type from the destination string.
func buildConnect(dest string, port int) ([]byte, error) {
	var atyp byte
	var addr []byte
	if p, err := netip.ParseAddr(dest); err == nil {
		if p.Is4() || (p.Is6() && p.Is4In6()) {
			atyp = 0x01
			a4 := p.As4()
			addr = a4[:]
		} else {
			atyp = 0x04
			a16 := p.As16()
			addr = a16[:]
		}
	} else {
		if len(dest) > 255 {
			return nil, fmt.Errorf("socks5: domain too long: %d", len(dest))
		}
		atyp = 0x03
		addr = append([]byte{byte(len(dest))}, []byte(dest)...)
	}
	var b bytes.Buffer
	b.WriteByte(0x05) // version
	b.WriteByte(0x01) // CMD: CONNECT
	b.WriteByte(0x00) // RSV
	b.WriteByte(atyp)
	b.Write(addr)
	var portB [2]byte
	binary.BigEndian.PutUint16(portB[:], uint16(port))
	b.Write(portB[:])
	return b.Bytes(), nil
}

// skipBound reads (and discards) the server's bound address+port from the
// CONNECT reply, using the reply's atyp.
func skipBound(r io.Reader, atyp byte) error {
	switch atyp {
	case 0x01: // IPv4
		var buf [6]byte
		_, err := io.ReadFull(r, buf[:])
		return err
	case 0x03: // domain
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return err
		}
		_, err := io.ReadFull(r, make([]byte, l[0]+2))
		return err
	case 0x04: // IPv6
		_, err := io.ReadFull(r, make([]byte, 16+2))
		return err
	default:
		return fmt.Errorf("unsupported address type 0x%02x in reply", atyp)
	}
}
