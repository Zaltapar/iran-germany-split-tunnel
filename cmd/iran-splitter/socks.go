package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// socksNegotiate performs the SOCKS5 greeting + CONNECT request exchange on
// rw and returns the requested destination.
//
// On rejection it writes the protocol-mandated reply before returning an
// error:
//
//	0x05 0xFF  no acceptable authentication methods
//	0x05 0x07  command not supported
//
// A nil destination therefore always means "rejected" (or a transport
// error on the request itself, which leaves no reply to send).
//
// The caller owns the connection deadline: set it before calling, clear it
// after a successful negotiation (the relay phase must be deadline-free).
//
// This is a behavior-preserving extraction of the inline parsing in
// handleSOCKS5Conn, so it is directly unit-testable.
func socksNegotiate(rw io.ReadWriteCloser) (*session.Destination, error) {
	// --- SOCKS5 greeting: [0x05, NMETHODS, methods...] ---
	greet := make([]byte, 2)
	if _, err := io.ReadFull(rw, greet); err != nil {
		return nil, err
	}
	if greet[0] != 0x05 {
		return nil, errors.New("unsupported SOCKS version")
	}
	methods := make([]byte, int(greet[1]))
	if _, err := io.ReadFull(rw, methods); err != nil {
		return nil, err
	}
	methodOK := false
	for _, m := range methods {
		if m == 0x00 {
			methodOK = true
			break
		}
	}
	if !methodOK {
		_, _ = rw.Write([]byte{0x05, 0xFF}) // no acceptable authentication methods
		return nil, errors.New("no acceptable auth method")
	}
	if _, err := rw.Write([]byte{0x05, 0x00}); err != nil {
		return nil, err
	}

	// --- SOCKS5 request: [0x05, CMD, 0x00 (rsvd), ATYP, ...] ---
	req := make([]byte, 4)
	if _, err := io.ReadFull(rw, req); err != nil {
		return nil, err
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		socksReply(rw, 0x07) // command not supported
		return nil, errors.New("unsupported SOCKS command")
	}
	dest, err := session.ReadDestinationEx(rw, req[3])
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	if dest.AddrType == session.AddrTypeDomain && len(dest.Addr) > 255 {
		socksReply(rw, 0x01) // general failure
		return nil, errors.New("domain name exceeds 255 bytes")
	}
	return dest, nil
}
