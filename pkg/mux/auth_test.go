package mux

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

type authResult struct {
	br  *bufio.Reader
	err error
}

// mustBufRead wraps conn in a bufio.Reader for tests.
func mustBufRead(t *testing.T, r interface{ Read([]byte) (int, error) }) *bufio.Reader {
	t.Helper()
	return bufio.NewReader(r)
}

// runAuthPair runs the v1 handshake on both ends of a fresh mem pipe.
func runAuthPair(t *testing.T, role CarrierRole, clientSecret, serverSecret []byte, clientTimeout time.Duration) (authResult, authResult) {
	t.Helper()
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()

	cr := make(chan authResult, 1)
	sr := make(chan authResult, 1)
	go func() {
		br, err := CarrierAuth(ctx, a, true, role, clientSecret)
		cr <- authResult{br, err}
	}()
	br, err := CarrierAuth(context.Background(), b, false, role, serverSecret)
	sr <- authResult{br, err}

	cRes := <-cr
	// The server side may already have returned; the client goroutine has a
	// buffered channel, so draining it is safe.
	sRes := <-sr
	return cRes, sRes
}

// TestCarrierAuthSuccess verifies the v1 challenge/response completes with a
// shared secret and role on both ends.
func TestCarrierAuthSuccess(t *testing.T) {
	secret := DeriveSecret("e2e-auth-secret")
	cRes, sRes := runAuthPair(t, RoleUpload, secret, secret, 2*time.Second)
	if cRes.err != nil {
		t.Fatalf("client auth: %v", cRes.err)
	}
	if sRes.err != nil {
		t.Fatalf("server auth: %v", sRes.err)
	}
	if cRes.br == nil || sRes.br == nil {
		t.Fatal("auth did not return read buffers")
	}
}

// TestCarrierAuthSuccessBothRoles verifies both carrier roles authenticate.
func TestCarrierAuthSuccessBothRoles(t *testing.T) {
	secret := DeriveSecret("roles")
	for _, role := range []CarrierRole{RoleUpload, RoleDownload} {
		cRes, sRes := runAuthPair(t, role, secret, secret, 2*time.Second)
		if cRes.err != nil || sRes.err != nil {
			t.Fatalf("role %c: client=%v server=%v", role, cRes.err, sRes.err)
		}
	}
}

// TestCarrierAuthWrongSecret verifies the responder rejects a response whose
// MAC was computed with a different secret.
func TestCarrierAuthWrongSecret(t *testing.T) {
	cRes, sRes := runAuthPair(t, RoleUpload, DeriveSecret("client-secret"), DeriveSecret("server-secret"), 500*time.Millisecond)
	if !errors.Is(sRes.err, ErrAuthMAC) {
		t.Fatalf("server err = %v, want ErrAuthMAC", sRes.err)
	}
	if cRes.err == nil {
		t.Fatal("client succeeded despite server rejecting the secret")
	}
}

// TestCarrierAuthWrongRole verifies a carrier cannot authenticate the wrong
// role with a valid secret: the client sees the role mismatch on the
// challenge, and a wrong-role response is rejected by the responder.
func TestCarrierAuthWrongRole(t *testing.T) {
	secret := DeriveSecret("role-confusion")

	// Client side: peer (responder, RoleUpload) sends a RoleUpload challenge
	// to a client expecting RoleDownload.
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_, _ = CarrierAuth(context.Background(), b, false, RoleUpload, secret)
	}()
	_, err := CarrierAuth(context.Background(), a, true, RoleDownload, secret)
	if !errors.Is(err, ErrAuthRoleMismatch) {
		t.Fatalf("client err = %v, want ErrAuthRoleMismatch", err)
	}

	// Server side: a response claiming RoleDownload is rejected by a
	// RoleUpload responder.
	a2, b2 := testutil.NewMemPipe()
	defer a2.Close()
	defer b2.Close()
	sErr := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), b2, false, RoleUpload, secret)
		sErr <- e
	}()
	ch, err := ReadFrame(mustBufRead(t, a2))
	if err != nil || ch.Type != FrameAuth {
		t.Fatalf("did not receive challenge: %v %v", ch, err)
	}
	resp := buildResponse(secret, RoleDownload, ch.Payload, authNow(), authNonce())
	if err := WriteFrame(a2, 0, FrameAuth, resp); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-sErr:
		if !errors.Is(e, ErrAuthRoleMismatch) {
			t.Fatalf("server err = %v, want ErrAuthRoleMismatch", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("responder did not fail on wrong-role response")
	}
}

// TestCarrierAuthWrongVersion verifies both ends reject an unknown protocol
// version before any MAC verification.
func TestCarrierAuthWrongVersion(t *testing.T) {
	secret := DeriveSecret("version")

	// Client sees a version-99 challenge (fake server drives the exchange).
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	res := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), a, true, RoleUpload, secret)
		res <- e
	}()
	ch := buildChallenge(RoleUpload)
	ch[0] = 99
	if err := WriteFrame(b, 0, FrameAuth, ch); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-res:
		if !errors.Is(e, ErrAuthVersion) {
			t.Fatalf("client err = %v, want ErrAuthVersion", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not fail on unknown challenge version")
	}

	// Server sees a version-99 response.
	a2, b2 := testutil.NewMemPipe()
	defer a2.Close()
	defer b2.Close()
	sErr := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), b2, false, RoleUpload, secret)
		sErr <- e
	}()
	ch2, err := ReadFrame(mustBufRead(t, a2))
	if err != nil || ch2.Type != FrameAuth {
		t.Fatalf("did not receive challenge: %v %v", ch2, err)
	}
	resp := buildResponse(secret, RoleUpload, ch2.Payload, authNow(), authNonce())
	resp[0] = 99
	if err := WriteFrame(a2, 0, FrameAuth, resp); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-sErr:
		if !errors.Is(e, ErrAuthVersion) {
			t.Fatalf("server err = %v, want ErrAuthVersion", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("responder did not fail on unknown response version")
	}
}

// TestCarrierAuthBadMAC verifies the responder rejects a response with a
// corrupted MAC (echo fields intact).
func TestCarrierAuthBadMAC(t *testing.T) {
	secret := DeriveSecret("badmac")
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	sErr := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), b, false, RoleUpload, secret)
		sErr <- e
	}()
	ch, err := ReadFrame(mustBufRead(t, a))
	if err != nil || ch.Type != FrameAuth {
		t.Fatalf("did not receive challenge: %v %v", ch, err)
	}
	resp := buildResponse(secret, RoleUpload, ch.Payload, authNow(), authNonce())
	resp[42] ^= 0xFF // corrupt the MAC
	if err := WriteFrame(a, 0, FrameAuth, resp); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-sErr:
		if !errors.Is(e, ErrAuthMAC) {
			t.Fatalf("server err = %v, want ErrAuthMAC", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("responder did not fail on bad MAC")
	}
}

// TestCarrierAuthBadConfirmMAC verifies the client rejects a confirmation
// whose MAC does not match (server-side proof of secret).
func TestCarrierAuthBadConfirmMAC(t *testing.T) {
	secret := DeriveSecret("badconfirm")
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	res := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), a, true, RoleUpload, secret)
		res <- e
	}()
	// Fake server: challenge, read the client response, corrupted confirm.
	ch := buildChallenge(RoleUpload)
	if err := WriteFrame(b, 0, FrameAuth, ch); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	respF, err := ReadFrame(mustBufRead(t, b))
	if err != nil || respF.Type != FrameAuth {
		t.Fatalf("did not receive response: %v %v", respF, err)
	}
	confirm := buildConfirm(secret, RoleUpload, ch, respF.Payload, authNonce())
	confirm[18] ^= 0xFF // corrupt the MAC
	if err := WriteFrame(b, 0, FrameAuth, confirm); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-res:
		if !errors.Is(e, ErrAuthMAC) {
			t.Fatalf("client err = %v, want ErrAuthMAC", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not fail on bad confirm MAC")
	}
}

// TestCarrierAuthTruncatedChallenge verifies the client rejects a challenge
// whose payload is not authChallengeSize bytes.
func TestCarrierAuthTruncatedChallenge(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	if err := WriteFrame(b, 0, FrameAuth, []byte("short")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if _, err := CarrierAuth(context.Background(), a, true, RoleUpload, DeriveSecret("x")); !errors.Is(err, ErrAuthProtocol) {
		t.Fatalf("err = %v, want ErrAuthProtocol", err)
	}
}

// TestCarrierAuthTruncatedResponse verifies the responder rejects a response
// whose payload is not authResponseSize bytes.
func TestCarrierAuthTruncatedResponse(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	sErr := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), b, false, RoleUpload, DeriveSecret("x"))
		sErr <- e
	}()
	// Drain the challenge, then send a short response.
	if _, err := ReadFrame(mustBufRead(t, a)); err != nil {
		t.Fatalf("no challenge: %v", err)
	}
	if err := WriteFrame(a, 0, FrameAuth, make([]byte, 50)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-sErr:
		if !errors.Is(e, ErrAuthProtocol) {
			t.Fatalf("server err = %v, want ErrAuthProtocol", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("responder did not fail on truncated response")
	}
}

// TestCarrierAuthFreshness verifies timestamps outside AuthMaxClockSkew are
// rejected: a stale challenge, a future challenge, and a stale response.
func TestCarrierAuthFreshness(t *testing.T) {
	secret := DeriveSecret("freshness")

	// Client sees a bad challenge.
	for _, tc := range []struct {
		name string
		ts   time.Time
	}{
		{"stale challenge", time.Now().Add(-2 * time.Hour)},
		{"future challenge", time.Now().Add(2 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := testutil.NewMemPipe()
			defer a.Close()
			defer b.Close()
			res := make(chan error, 1)
			go func() {
				_, e := CarrierAuth(context.Background(), a, true, RoleUpload, secret)
				res <- e
			}()
			ch := buildChallenge(RoleUpload)
			binary.BigEndian.PutUint32(ch[2:6], uint32(tc.ts.Unix()))
			if err := WriteFrame(b, 0, FrameAuth, ch); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			select {
			case e := <-res:
				if !errors.Is(e, ErrAuthFreshness) {
					t.Fatalf("client err = %v, want ErrAuthFreshness", e)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("client did not fail on out-of-skew challenge")
			}
		})
	}

	// Server sees a stale response ts_c.
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	sErr := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), b, false, RoleUpload, secret)
		sErr <- e
	}()
	ch, err := ReadFrame(mustBufRead(t, a))
	if err != nil || ch.Type != FrameAuth {
		t.Fatalf("no challenge: %v %v", ch, err)
	}
	resp := buildResponse(secret, RoleUpload, ch.Payload, authNow(), authNonce())
	binary.BigEndian.PutUint32(resp[2:6], uint32(time.Now().Add(-2*time.Hour).Unix()))
	if err := WriteFrame(a, 0, FrameAuth, resp); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-sErr:
		if !errors.Is(e, ErrAuthFreshness) {
			t.Fatalf("server err = %v, want ErrAuthFreshness", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("responder did not fail on stale response")
	}
}

// TestCarrierAuthReplay verifies that a response captured from one
// handshake cannot be replayed against a fresh challenge: the challenge
// echo (ts_s, nonce_s) no longer matches, so the responder rejects it.
func TestCarrierAuthReplay(t *testing.T) {
	secret := DeriveSecret("replay")
	// A response that was valid for this (old) challenge:
	oldChallenge := buildChallenge(RoleUpload)
	capturedResp := buildResponse(secret, RoleUpload, oldChallenge, authNow(), authNonce())

	// Fresh handshake with a NEW challenge; attacker replays capturedResp.
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	sErr := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), b, false, RoleUpload, secret)
		sErr <- e
	}()
	ch, err := ReadFrame(mustBufRead(t, a))
	if err != nil || ch.Type != FrameAuth {
		t.Fatalf("no fresh challenge: %v %v", ch, err)
	}
	if string(ch.Payload[6:]) == string(oldChallenge[6:]) {
		t.Fatal("test setup: fresh challenge nonce collided with old")
	}
	if err := WriteFrame(a, 0, FrameAuth, capturedResp); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-sErr:
		if !errors.Is(e, ErrAuthProtocol) {
			t.Fatalf("server err = %v, want ErrAuthProtocol (echo mismatch)", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("responder accepted replayed response")
	}
}

// TestCarrierAuthDataBeforeAuth verifies no application frame is accepted
// during the handshake: FrameData (stream 0 and stream 5) and FrameRebind
// are all rejected by the responder with a protocol error.
func TestCarrierAuthDataBeforeAuth(t *testing.T) {
	secret := DeriveSecret("premature")
	cases := []struct {
		name     string
		streamID uint32
		ftype    uint8
		payload  []byte
	}{
		{"data stream 0", 0, FrameData, []byte{1}},
		{"data stream 5", 5, FrameData, []byte{1}},
		{"rebind before auth", 7, FrameRebind, []byte{0, 0, 0, 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := testutil.NewMemPipe()
			defer a.Close()
			defer b.Close()
			sErr := make(chan error, 1)
			go func() {
				_, e := CarrierAuth(context.Background(), b, false, RoleUpload, secret)
				sErr <- e
			}()
			if err := WriteFrame(a, tc.streamID, tc.ftype, tc.payload); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			select {
			case e := <-sErr:
				if !errors.Is(e, ErrAuthProtocol) {
					t.Fatalf("server err = %v, want ErrAuthProtocol", e)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("responder accepted an application frame before auth")
			}
		})
	}
}

// TestCarrierAuthTimeoutSilentPeer verifies the handshake has a hard bound
// (AuthTimeout) even when the caller's context has no deadline: an attacker
// that connects and goes silent cannot hold the connection forever.
func TestCarrierAuthTimeoutSilentPeer(t *testing.T) {
	orig := AuthTimeout
	AuthTimeout = 300 * time.Millisecond
	defer func() { AuthTimeout = orig }()

	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	// b is never driven: silent peer.
	start := time.Now()
	_, err := CarrierAuth(context.Background(), a, true, RoleUpload, DeriveSecret("timeout"))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("client auth succeeded against a silent peer")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("auth took %v; AuthTimeout was not enforced", elapsed)
	}
}

// TestCarrierAuthInvalidRole verifies invalid role values are rejected
// before any I/O.
func TestCarrierAuthInvalidRole(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	if _, err := CarrierAuth(context.Background(), a, true, CarrierRole(0), DeriveSecret("x")); !errors.Is(err, ErrAuthInvalidRole) {
		t.Fatalf("err = %v, want ErrAuthInvalidRole", err)
	}
}
