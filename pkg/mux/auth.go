package mux

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// ============================================================
// Carrier authentication protocol v1 (Phase 6)
// ============================================================
//
// v0 (pre-Phase-6) sent the derived shared secret itself as the
// authentication token; anyone who captured a valid handshake could
// replay it forever. v1 is a three-message challenge/response exchange
// that authenticates BOTH ends, binds the CARRIER ROLE and the protocol
// VERSION into the MAC transcript, and is replay-resistant through
// fresh random nonces. The raw secret (or any function of it) is NEVER
// put on the wire — only HMAC-SHA256 tags over fresh per-handshake data.
//
// All three messages are FrameAuth frames on stream 0:
//
//  1. Challenge (server → client), 22 bytes:
//     [0] AuthVersion (1)  [1] role
//     [2:6] ts_s (uint32 BE Unix)  [6:22] nonce_s (16B, crypto/rand)
//
//  2. Response (client → server), 74 bytes:
//     [0] version  [1] role
//     [2:6] ts_c  [6:10] ts_s echo  [10:26] nonce_s echo
//     [26:42] nonce_c (16B, crypto/rand)
//     [42:74] mac_c = HMAC-SHA256(secret, challenge || ts_c || nonce_c)
//
//  3. Confirmation (server → client), 50 bytes:
//     [0] version  [1] role  [2:18] nonce_s2 (16B)
//     [18:50] mac_s = HMAC-SHA256(secret, challenge || response || nonce_s2)
//
// Security properties:
//
//   - Mutual: the client proves the secret (mac_c), the server proves
//     it (mac_s). A MITM that cannot compute the HMAC cannot complete
//     either direction.
//   - Replay-resistant WITHOUT any nonce store: every handshake starts
//     with a fresh 128-bit server nonce and both MACs cover it (mac_c
//     covers the challenge, mac_s covers challenge+response), so a
//     captured response or confirmation cannot be reused against a new
//     challenge. Nonces never need to be remembered (no unbounded cache).
//   - Role-bound: the role byte is inside both MAC transcripts, so a
//     valid secret alone cannot authenticate the wrong carrier role
//     (an upload handshake cannot be replayed as a download handshake).
//   - Version-bound: unknown versions are rejected before MAC
//     verification; future versions must not reuse this transcript.
//   - Freshness: both ends check the peer's timestamp within
//     AuthMaxClockSkew (60 s, generous for NTP-synced hosts); defense
//     in depth, since the nonces already defeat replay.
//
// Failure handling: every verification failure is a CONNECTION-LEVEL
// failure — the connection is closed with no protocol error message
// sent to the peer, so no information about which check failed is
// leaked. The returned error is for LOCAL logging only.
//
// Compatibility: v0 and v1 are NOT interoperable (a v0 client sends a
// 32-byte raw secret where a 74-byte response is expected, and a v0
// server never sends a challenge). Both ends must be upgraded together.
//
// Timeout: the whole handshake is bounded by AuthTimeout even when the
// caller's context has no deadline, and the bound is also applied to
// the socket (SetDeadline, where supported), so an attacker that opens
// a connection and stalls or goes silent cannot hold resources.

// AuthVersion is the current authentication protocol version.
const AuthVersion = 1

// CarrierRole identifies which carrier a handshake establishes. Both
// ends of a given carrier use the SAME role, and the role is bound into
// both MACs. Each direction has exactly one client-side node (Germany
// dials the upload carrier, Iran dials the download carrier), so the
// role also identifies the expected node on each side.
type CarrierRole uint8

const (
	// RoleUpload is the upload carrier (Germany → Iran WebSocket
	// server, path /upload).
	RoleUpload CarrierRole = 'U'
	// RoleDownload is the download carrier (Iran → Germany TCP
	// listener).
	RoleDownload CarrierRole = 'D'
)

func (r CarrierRole) valid() bool {
	return r == RoleUpload || r == RoleDownload
}

// Handshake payload sizes (FrameAuth payloads on stream 0).
const (
	authChallengeSize = 22 // version + role + ts_s + nonce_s
	authResponseSize  = 74 // version + role + ts_c + ts_s + nonce_s + nonce_c + mac_c
	authConfirmSize   = 50 // version + role + nonce_s2 + mac_s
	authNonceSize     = 16
)

// AuthTimeout is the hard bound for the ENTIRE handshake. It is the
// ceiling even when the caller's context has no (or a longer) deadline.
// It is a variable (not a constant) so tests can shorten it.
var AuthTimeout = 15 * time.Second

// AuthMaxClockSkew is the maximum accepted clock skew between the two
// nodes. Both ends check the peer's timestamp; 60 s is generous for
// NTP-synced hosts while still bounding how stale a timestamp may be.
const AuthMaxClockSkew = 60 * time.Second

// Authentication errors (local logging only — none of these details is
// ever transmitted to the peer; the connection is simply closed).
var (
	ErrAuthInvalidRole  = errors.New("mux: auth: invalid carrier role")
	ErrAuthProtocol     = errors.New("mux: auth protocol violation")
	ErrAuthVersion      = errors.New("mux: auth: unsupported version")
	ErrAuthRoleMismatch = errors.New("mux: auth: carrier role mismatch")
	ErrAuthFreshness    = errors.New("mux: auth: timestamp outside allowed skew")
	ErrAuthMAC          = errors.New("mux: auth: MAC verification failed")
)

func authMAC(secret []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, secret)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func authNonce() []byte {
	b := make([]byte, authNonceSize)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure means the process cannot operate
		// securely; fail loudly instead of weakening the protocol.
		panic("mux: crypto/rand unavailable: " + err.Error())
	}
	return b
}

func authNow() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(time.Now().Unix()))
	return b
}

// authClockOK reports whether ts (uint32 BE Unix seconds) is within
// AuthMaxClockSkew of the local clock.
func authClockOK(ts []byte) bool {
	d := time.Since(time.Unix(int64(binary.BigEndian.Uint32(ts)), 0))
	if d < 0 {
		d = -d
	}
	return d <= AuthMaxClockSkew
}

// buildChallenge assembles the 22-byte server challenge.
func buildChallenge(role CarrierRole) []byte {
	c := make([]byte, authChallengeSize)
	c[0] = AuthVersion
	c[1] = byte(role)
	copy(c[2:6], authNow())
	copy(c[6:], authNonce())
	return c
}

// buildResponse assembles the 74-byte client response. tsC and nonceC
// must be fresh values chosen by the client.
func buildResponse(secret []byte, role CarrierRole, challenge, tsC, nonceC []byte) []byte {
	r := make([]byte, authResponseSize)
	r[0] = AuthVersion
	r[1] = byte(role)
	copy(r[2:6], tsC)
	copy(r[6:10], challenge[2:6]) // ts_s echo
	copy(r[10:26], challenge[6:]) // nonce_s echo
	copy(r[26:42], nonceC)
	copy(r[42:], authMAC(secret, challenge, tsC, nonceC))
	return r
}

// buildConfirm assembles the 50-byte server confirmation. nonceS2 must
// be a fresh value chosen by the server.
func buildConfirm(secret []byte, role CarrierRole, challenge, response, nonceS2 []byte) []byte {
	k := make([]byte, authConfirmSize)
	k[0] = AuthVersion
	k[1] = byte(role)
	copy(k[2:18], nonceS2)
	copy(k[18:], authMAC(secret, challenge, response, nonceS2))
	return k
}

// verifyResponse checks a client response against the challenge the
// server sent. Checks are ordered so cheap, secret-independent failures
// (version, role, echo, freshness) are caught before the MAC.
func verifyResponse(secret []byte, role CarrierRole, challenge, r []byte) error {
	if r[0] != AuthVersion {
		return ErrAuthVersion
	}
	if CarrierRole(r[1]) != role {
		return ErrAuthRoleMismatch
	}
	// Echo check: the response must carry back the exact ts_s and
	// nonce_s of THIS challenge. A replayed response (from an earlier
	// handshake) fails here even before MAC verification.
	if subtle.ConstantTimeCompare(r[6:10], challenge[2:6]) != 1 ||
		subtle.ConstantTimeCompare(r[10:26], challenge[6:]) != 1 {
		return ErrAuthProtocol
	}
	if !authClockOK(r[2:6]) {
		return ErrAuthFreshness
	}
	expected := authMAC(secret, challenge, r[2:6], r[26:42])
	if subtle.ConstantTimeCompare(expected, r[42:]) != 1 {
		return ErrAuthMAC
	}
	return nil
}

// CarrierAuth performs the v1 challenge/response handshake on rwc.
// isClient selects the initiator (the dialing side); the responder
// (server side) sends the challenge first. role must be the carrier's
// role (RoleUpload / RoleDownload) and is bound into both MACs.
//
// No application frame of any kind is accepted during the handshake:
// only FrameAuth on stream 0 in the expected phase. Any other frame
// (FrameData/Header/Rebind/Close/Ping, or a non-zero stream) is a
// protocol violation and the connection is terminated — a usable
// stream can never be established before authentication completes.
//
// On success the returned bufio.Reader holds any bytes already
// buffered from rwc — pass it to NewCarrierConnWithReader (the carrier
// must start its read loop on that reader, so pre-buffered frames are
// not orphaned). On any failure the caller must close rwc.
func CarrierAuth(ctx context.Context, rwc io.ReadWriteCloser, isClient bool, role CarrierRole, secret []byte) (*bufio.Reader, error) {
	if !role.valid() {
		return nil, ErrAuthInvalidRole
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Hard handshake bound: min(ctx deadline, now+AuthTimeout), applied
	// to the socket too (where supported) so a silent/stalling peer
	// cannot hold the connection past the bound.
	deadline := time.Now().Add(AuthTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	type deadlineer interface{ SetDeadline(time.Time) error }
	if dl, ok := rwc.(deadlineer); ok {
		_ = dl.SetDeadline(deadline)
	}
	br := bufio.NewReader(rwc)
	if dl, ok := rwc.(deadlineer); ok {
		defer func() { _ = dl.SetDeadline(time.Time{}) }()
	}

	// readAuthFrame reads the next frame and enforces the handshake
	// context: FrameAuth on stream 0 with exactly wantLen payload bytes.
	readAuthFrame := func(wantLen int) ([]byte, error) {
		f, err := ReadFrame(br)
		if err != nil {
			return nil, err
		}
		if f.Type != FrameAuth || f.StreamID != 0 {
			return nil, ErrAuthProtocol
		}
		if len(f.Payload) != wantLen {
			return nil, ErrAuthProtocol
		}
		return f.Payload, nil
	}
	writeAuth := func(payload []byte) error {
		return WriteFrame(rwc, 0, FrameAuth, payload)
	}

	if !isClient {
		// Responder (server): challenge → verify response → confirm.
		challenge := buildChallenge(role)
		if err := writeAuth(challenge); err != nil {
			return nil, err
		}
		resp, err := readAuthFrame(authResponseSize)
		if err != nil {
			return nil, err
		}
		if err := verifyResponse(secret, role, challenge, resp); err != nil {
			return nil, err
		}
		confirm := buildConfirm(secret, role, challenge, resp, authNonce())
		if err := writeAuth(confirm); err != nil {
			return nil, err
		}
		return br, nil
	}

	// Initiator (client): verify challenge → respond → verify confirm.
	challenge, err := readAuthFrame(authChallengeSize)
	if err != nil {
		return nil, err
	}
	if challenge[0] != AuthVersion {
		return nil, ErrAuthVersion
	}
	if CarrierRole(challenge[1]) != role {
		return nil, ErrAuthRoleMismatch
	}
	if !authClockOK(challenge[2:6]) {
		return nil, ErrAuthFreshness
	}
	resp := buildResponse(secret, role, challenge, authNow(), authNonce())
	if err := writeAuth(resp); err != nil {
		return nil, err
	}
	confirm, err := readAuthFrame(authConfirmSize)
	if err != nil {
		return nil, err
	}
	if confirm[0] != AuthVersion {
		return nil, ErrAuthVersion
	}
	if CarrierRole(confirm[1]) != role {
		return nil, ErrAuthRoleMismatch
	}
	expected := authMAC(secret, challenge, resp, confirm[2:18])
	if subtle.ConstantTimeCompare(expected, confirm[18:]) != 1 {
		return nil, ErrAuthMAC
	}
	return br, nil
}
