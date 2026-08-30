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
//   - Mutual authentication: both sides prove knowledge of the secret
//     (client via mac_c, server via mac_s).
//   - Replay resistance: each handshake starts with fresh server and
//     client nonces covered by the MACs; an attacker echoing a captured
//     response or confirmation fails MAC verification against any new
//     challenge nonce.
//   - Role binding: role is included in both MAC transcripts ('U' upload,
//     'D' download); a valid secret cannot authenticate the wrong carrier
//     direction.
//   - Versioning: AuthVersion is validated on every message before MAC
//     checks, so future versions can be distinguished cleanly.
//   - Freshness: both ends reject timestamps outside AuthMaxClockSkew (60s).
//   - Zero secret leakage: raw secret never on the wire; constant-time MAC
//     comparison (subtle.ConstantTimeCompare).
//   - Transport safety: all IO during auth is bounded by AuthTimeout
//     (applied via net.Conn.SetDeadline where available) so a silent peer
//     cannot hang the connection indefinitely.
//
// Interoperability:
//
//	v0 ⇄ v1 is NOT interoperable by design. Both Iran and Germany nodes
//	must be upgraded together.

// CarrierRole distinguishes upload ('U') and download ('D') carriers in
// the auth transcript.
type CarrierRole byte

const (
	RoleUpload   CarrierRole = 'U'
	RoleDownload CarrierRole = 'D'
)

func (r CarrierRole) String() string {
	switch r {
	case RoleUpload:
		return "upload"
	case RoleDownload:
		return "download"
	default:
		return "unknown"
	}
}

// Protocol constants.
const (
	AuthVersion = 1

	ChallengeSize    = 22
	ResponseSize     = 74
	ConfirmationSize = 50

	NonceSize = 16
	MACSize   = 32

	// AuthTimeout is the maximum duration allowed for the entire
	// three-message exchange. Applied as a socket deadline.
	AuthTimeout = 15 * time.Second
)

// AuthMaxClockSkew is the maximum tolerated drift between the server and
// client timestamps. 300s (5 minutes) accommodates slight NTP drift on
// cross-border servers while 128-bit random nonces ensure replay immunity.
const AuthMaxClockSkew = 300 * time.Second

// Authentication errors (local logging only — none of these details is
// ever transmitted to the peer; the connection is simply closed).
var (
	ErrAuthVersion    = errors.New("mux/auth: unsupported version")
	ErrAuthRole       = errors.New("mux/auth: role mismatch")
	ErrAuthFreshness  = errors.New("mux/auth: timestamp outside skew tolerance")
	ErrAuthEcho       = errors.New("mux/auth: challenge echo mismatch")
	ErrAuthMAC        = errors.New("mux/auth: MAC verification failed")
	ErrAuthFrameType  = errors.New("mux/auth: unexpected frame type during auth")
	ErrAuthStreamID   = errors.New("mux/auth: non-zero stream ID during auth")
	ErrAuthTimeout    = errors.New("mux/auth: handshake timed out")
	ErrAuthTruncated  = errors.New("mux/auth: truncated auth payload")
	ErrAuthNilSecret  = errors.New("mux/auth: empty secret")
	ErrAuthRoleBad    = errors.New("mux/auth: invalid carrier role")
)

// ============================================================
// Message builders and verifiers
// ============================================================

func buildChallenge(role CarrierRole) []byte {
	buf := make([]byte, ChallengeSize)
	buf[0] = AuthVersion
	buf[1] = byte(role)
	binary.BigEndian.PutUint32(buf[2:6], uint32(time.Now().Unix()))
	if _, err := io.ReadFull(rand.Reader, buf[6:22]); err != nil {
		panic("mux/auth: crypto/rand failure: " + err.Error())
	}
	return buf
}

func verifyChallenge(role CarrierRole, ch []byte) error {
	if len(ch) != ChallengeSize {
		return ErrAuthTruncated
	}
	if ch[0] != AuthVersion {
		return ErrAuthVersion
	}
	if CarrierRole(ch[1]) != role {
		return ErrAuthRole
	}
	ts := int64(binary.BigEndian.Uint32(ch[2:6]))
	now := time.Now().Unix()
	if absDiff(ts, now) > int64(AuthMaxClockSkew/time.Second) {
		return ErrAuthFreshness
	}
	return nil
}

func buildResponse(secret []byte, role CarrierRole, challenge []byte) []byte {
	buf := make([]byte, ResponseSize)
	buf[0] = AuthVersion
	buf[1] = byte(role)
	tsClient := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(buf[2:6], tsClient)
	copy(buf[6:10], challenge[2:6])   // echo server ts
	copy(buf[10:26], challenge[6:22]) // echo server nonce_s
	if _, err := io.ReadFull(rand.Reader, buf[26:42]); err != nil {
		panic("mux/auth: crypto/rand failure: " + err.Error())
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(challenge)
	mac.Write(buf[2:6])   // ts_c
	mac.Write(buf[26:42]) // nonce_c
	copy(buf[42:74], mac.Sum(nil))
	return buf
}

func verifyResponse(secret []byte, role CarrierRole, challenge, r []byte) error {
	if len(r) != ResponseSize {
		return ErrAuthTruncated
	}
	if r[0] != AuthVersion {
		return ErrAuthVersion
	}
	if CarrierRole(r[1]) != role {
		return ErrAuthRole
	}
	tsClient := int64(binary.BigEndian.Uint32(r[2:6]))
	now := time.Now().Unix()
	if absDiff(tsClient, now) > int64(AuthMaxClockSkew/time.Second) {
		return ErrAuthFreshness
	}
	// Echo check: ts_s and nonce_s must match the challenge we sent.
	if subtle.ConstantTimeCompare(r[6:10], challenge[2:6]) != 1 ||
		subtle.ConstantTimeCompare(r[10:26], challenge[6:22]) != 1 {
		return ErrAuthEcho
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(challenge)
	mac.Write(r[2:6])   // ts_c
	mac.Write(r[26:42]) // nonce_c
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(r[42:74], expected) != 1 {
		return ErrAuthMAC
	}
	return nil
}

func buildConfirmation(secret []byte, role CarrierRole, challenge, response []byte) []byte {
	buf := make([]byte, ConfirmationSize)
	buf[0] = AuthVersion
	buf[1] = byte(role)
	if _, err := io.ReadFull(rand.Reader, buf[2:18]); err != nil {
		panic("mux/auth: crypto/rand failure: " + err.Error())
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(challenge)
	mac.Write(response)
	mac.Write(buf[2:18]) // nonce_s2
	copy(buf[18:50], mac.Sum(nil))
	return buf
}

func verifyConfirmation(secret []byte, role CarrierRole, challenge, response, c []byte) error {
	if len(c) != ConfirmationSize {
		return ErrAuthTruncated
	}
	if c[0] != AuthVersion {
		return ErrAuthVersion
	}
	if CarrierRole(c[1]) != role {
		return ErrAuthRole
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(challenge)
	mac.Write(response)
	mac.Write(c[2:18]) // nonce_s2
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(c[18:50], expected) != 1 {
		return ErrAuthMAC
	}
	return nil
}

func absDiff(a, b int64) int64 {
	d := a - b
	if d < 0 {
		return -d
	}
	return d
}

// ============================================================
// CarrierAuth handshake entry point
// ============================================================

// CarrierAuth performs the mutual v1 challenge/response authentication
// on rwc.
//
// Handshake roles:
//   - Server (isClient = false): sends Challenge, verifies Response, sends Confirmation.
//   - Client (isClient = true):  receives Challenge, sends Response, verifies Confirmation.
//
// Carrier direction roles:
//   - role = RoleUpload ('U'): up-carrier (Germany WS client → Iran WS server).
//   - role = RoleDownload ('D'): down-carrier (Iran TCP client → Germany TCP server).
//
// During the handshake, ONLY FrameAuth frames on StreamID 0 are accepted.
// Any other frame type, non-zero stream ID, truncation or MAC failure
// immediately aborts the connection with a connection-level error; no usable
// stream can never be established before authentication completes.
//
// On success the returned bufio.Reader holds any bytes already
// buffered from rwc — pass it to NewCarrierConnWithReader (the carrier
// must start its read loop on that reader, so pre-buffered frames are
// not orphaned). On any failure the caller must close rwc.
func CarrierAuth(ctx context.Context, rwc io.ReadWriteCloser, isClient bool, role CarrierRole, secret []byte) (*bufio.Reader, error) {
	if len(secret) == 0 {
		return nil, ErrAuthNilSecret
	}
	if role != RoleUpload && role != RoleDownload {
		return nil, ErrAuthRoleBad
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ds, hasDeadline := rwc.(interface {
		SetDeadline(time.Time) error
	})
	resetDeadline := func() {
		if hasDeadline {
			_ = ds.SetDeadline(time.Time{})
		}
	}
	if hasDeadline {
		timeout := AuthTimeout
		if d, ok := ctx.Deadline(); ok {
			if remain := time.Until(d); remain > 0 && remain < timeout {
				timeout = remain
			}
		}
		_ = ds.SetDeadline(time.Now().Add(timeout))
	}
	defer resetDeadline()

	br := bufio.NewReader(rwc)

	readAuthFrame := func() ([]byte, error) {
		f, err := ReadFrame(br)
		if err != nil {
			return nil, err
		}
		if f.StreamID != 0 {
			return nil, ErrAuthStreamID
		}
		if f.Type != FrameAuth {
			return nil, ErrAuthFrameType
		}
		return f.Payload, nil
	}

	if isClient {
		// Client flow: receive Challenge → send Response → receive Confirmation.
		chPayload, err := readAuthFrame()
		if err != nil {
			return nil, err
		}
		if err := verifyChallenge(role, chPayload); err != nil {
			return nil, err
		}
		resp := buildResponse(secret, role, chPayload)
		if err := WriteFrame(rwc, 0, FrameAuth, resp); err != nil {
			return nil, err
		}
		confPayload, err := readAuthFrame()
		if err != nil {
			return nil, err
		}
		if err := verifyConfirmation(secret, role, chPayload, resp, confPayload); err != nil {
			return nil, err
		}
		return br, nil
	}

	// Server flow: send Challenge → receive Response → send Confirmation.
	challenge := buildChallenge(role)
	if err := WriteFrame(rwc, 0, FrameAuth, challenge); err != nil {
		return nil, err
	}
	respPayload, err := readAuthFrame()
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(secret, role, challenge, respPayload); err != nil {
		return nil, err
	}
	conf := buildConfirmation(secret, role, challenge, respPayload)
	if err := WriteFrame(rwc, 0, FrameAuth, conf); err != nil {
		return nil, err
	}
	return br, nil
}
