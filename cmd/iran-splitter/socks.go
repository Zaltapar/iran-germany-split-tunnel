package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// SOCKS5 / RFC 1929 protocol constants (plans/socks5-auth-design.md §2, §3).
const (
	socksVersion        byte = 0x05 // SOCKS protocol version
	socksMethodNoAuth   byte = 0x00 // "no authentication" method
	socksMethodUserPass byte = 0x02 // username/password (RFC 1929) method
	socksMethodReject   byte = 0xFF // "no acceptable method" (method stage)

	socksAuthVersion byte = 0x01 // RFC 1929 sub-negotiation version (distinct from 0x05)
	socksAuthSuccess byte = 0x00 // sub-negotiation status: credentials accepted
	socksAuthFailure byte = 0x01 // sub-negotiation status: credentials rejected (only failure status)

	socksCmdConnect  byte = 0x01
	socksCmdReplyCmd byte = 0x07 // "command not supported" reply status
)

// errSocksAuthFailed is the single terminal error for a rejected credential
// pair. It carries no credential content (plans/socks5-auth-design.md §4.2)
// so the caller can distinguish "credentials wrong" (write 01 01, close)
// from "malformed frame / I/O" (write nothing, close) with errors.Is.
var errSocksAuthFailed = errors.New("socks: authentication failed")

// socksCredentials is the configured RFC 1929 pair. The zero value means
// "authentication is not configured" (pre-RFC-1929 behavior). It is built
// once at startup (newSocksCredentials) so the per-connection hot path does
// no config lookups and every field is immutable after construction
// (plans/socks5-auth-design.md §7.7: no new shared mutable state, -race safe).
type socksCredentials struct {
	enabled bool
	user    string
	pass    string
}

// newSocksCredentials builds the immutable credential view for the hot path
// from a loaded config. A half-set or empty pair yields the zero (disabled)
// value; a fully-set pair enables RFC 1929.
func newSocksCredentials(cfg *config.Config) socksCredentials {
	if cfg == nil || !cfg.SocksAuthEnabled() {
		return socksCredentials{}
	}
	return socksCredentials{enabled: true, user: cfg.SocksUser, pass: cfg.SocksPass}
}

// socksNegotiate performs the SOCKS5 greeting, the RFC 1929 sub-negotiation
// (when auth is configured and the client selects 0x02), and the CONNECT
// request exchange on rw, returning the requested destination.
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
func socksNegotiate(rw io.ReadWriteCloser, creds *socksCredentials) (*session.Destination, error) {
	// --- SOCKS5 greeting: [0x05, NMETHODS, methods...] ---
	greet := make([]byte, 2)
	if _, err := io.ReadFull(rw, greet); err != nil {
		return nil, err
	}
	if greet[0] != socksVersion {
		return nil, errors.New("unsupported SOCKS version")
	}
	methods := make([]byte, int(greet[1]))
	if _, err := io.ReadFull(rw, methods); err != nil {
		return nil, err
	}

	// Method selection (plans/socks5-auth-design.md §2.2, §2.5):
	//   auth off → the server accepts only 0x00; selecting it writes
	//              {0x05, 0x00} (today's bytes, byte-for-byte preserved).
	//   auth on  → the server advertises {0x00, 0x02} but ONLY 0x02 may be
	//              selected: a client offering 0x02 gets {0x05, 0x02} and
	//              must pay the sub-negotiation; a client offering only 0x00
	//              gets {0x05, 0xFF} (no no-auth bypass on a gated port).
	offered := func(m byte) bool {
		for _, om := range methods {
			if om == m {
				return true
			}
		}
		return false
	}

	enabled := creds != nil && creds.enabled
	var selected byte
	switch {
	case enabled && offered(socksMethodUserPass):
		// Auth configured and 0x02 offered: select the credential method
		// even if 0x00 is also offered (0x02 takes precedence).
		selected = socksMethodUserPass
	case offered(socksMethodNoAuth) && !enabled:
		// No auth configured: today's behavior — select 0x00.
		selected = socksMethodNoAuth
	default:
		// No acceptable method: auth is configured but the client offered
		// only 0x00 / nothing, or no-auth config and the client offered no
		// 0x00. Uniform method-stage rejection bytes (unchanged string and
		// reply so TestSocksNegotiateNoMethod keeps passing).
		_, _ = rw.Write([]byte{socksVersion, socksMethodReject})
		return nil, errors.New("no acceptable auth method")
	}

	if _, err := rw.Write([]byte{socksVersion, selected}); err != nil {
		return nil, err
	}

	// RFC 1929 sub-negotiation runs before the CONNECT stage once 0x02 is
	// selected (plans/socks5-auth-design.md §2.4).
	if selected == socksMethodUserPass {
		if err := socksAuthNegotiate(rw, creds.user, creds.pass); err != nil {
			return nil, err
		}
	}

	// --- SOCKS5 request: [0x05, CMD, 0x00 (rsvd), ATYP, ...] ---
	req := make([]byte, 4)
	if _, err := io.ReadFull(rw, req); err != nil {
		return nil, err
	}
	if req[0] != socksVersion || req[1] != socksCmdConnect {
		socksReply(rw, socksCmdReplyCmd) // command not supported
		return nil, errors.New("unsupported SOCKS command")
	}
	dest, err := session.ReadDestinationEx(rw, req[3])
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	return dest, nil
}

// socksAuthNegotiate implements the RFC 1929 username/password sub-
// negotiation (plans/socks5-auth-design.md §2.4): read VER/ULEN/UNAME/PLEN/
// PASSWD, verify with socksCredsMatch (constant-time), and reply 01 00
// (success) or 01 01 (failure).
//
// Malformed frames (bad VER, truncated user/pass, I/O error) return an
// error and write NOTHING, because no valid RFC 1929 status encodes a
// malformed frame; wrong credentials write 01 01 and return
// errSocksAuthFailed. One attempt, no retry (§2.6).
//
// No allocation is driven by an untrusted length beyond the single 255
// bound the 1-byte field imposes (make([]byte, byte) is bounded by 255), so
// no oversized-length DoS is expressible and a malformed stream can never
// panic — only return an error and a close reason.
func socksAuthNegotiate(rw io.ReadWriteCloser, wantUser, wantPass string) error {
	// 2-byte header: VER, ULEN.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return err // short stream / I/O error: caller closes
	}
	if hdr[0] != socksAuthVersion {
		return errors.New("rfc1929: sub-negotiation version is not 0x01")
	}
	ulen := int(hdr[1])
	if ulen == 0 {
		// A 0-length username cannot match a configured 1..255 username;
		// treat as a malformed frame (no success reply, no 01 01, no panic).
		return errors.New("rfc1929: zero-length username")
	}
	user := make([]byte, ulen)
	if _, err := io.ReadFull(rw, user); err != nil {
		return err
	}
	// 1-byte PLEN, then PLEN password bytes (a 0 PLEN is a valid empty
	// password; it simply cannot match a non-empty configured one).
	plenB := make([]byte, 1)
	if _, err := io.ReadFull(rw, plenB); err != nil {
		return err
	}
	pass := make([]byte, int(plenB[0]))
	if _, err := io.ReadFull(rw, pass); err != nil {
		return err
	}

	if !socksCredsMatch(string(user), string(pass), wantUser, wantPass) {
		// Wrong credentials: the only RFC 1929 failure status, then close.
		if _, werr := rw.Write([]byte{socksAuthVersion, socksAuthFailure}); werr != nil {
			return werr
		}
		return errSocksAuthFailed
	}
	if _, err := rw.Write([]byte{socksAuthVersion, socksAuthSuccess}); err != nil {
		return err
	}
	return nil
}

// socksCredsMatch reports whether the supplied username/password match the
// configured pair. Both fields are compared in constant time; a length
// mismatch is a plain rejection, not a slow path
// (plans/socks5-auth-design.md §3).
//
// Both comparisons ALWAYS run — no short-circuit on the username — so the
// timing of "wrong user" vs "wrong password" is indistinguishable, and the
// two boolean results are ANDed. The primitive is
// subtle.ConstantTimeCompare, the same one pkg/mux already uses for the
// carrier secret (§3 rule 4: reuse the primitive, not the derived-bytes
// helper, because the configured values are the exact wire bytes here).
func socksCredsMatch(gotUser, gotPass, wantUser, wantPass string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(gotUser), []byte(wantUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(gotPass), []byte(wantPass)) == 1
	return userOK && passOK
}
