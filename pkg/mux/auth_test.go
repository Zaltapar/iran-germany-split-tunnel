package mux

import (
	"bufio"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

type authResult struct {
	br  *bufio.Reader
	err error
}

// runAuthPair runs CarrierAuth on both ends of a fresh mem pipe.
func runAuthPair(t *testing.T, clientSecret, serverSecret []byte, clientTimeout time.Duration) (authResult, authResult) {
	t.Helper()
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()

	cr := make(chan authResult, 1)
	sr := make(chan authResult, 1)
	go func() {
		br, err := CarrierAuth(ctx, a, true, clientSecret)
		cr <- authResult{br, err}
	}()
	br, err := CarrierAuth(context.Background(), b, false, serverSecret)
	sr <- authResult{br, err}

	cRes := <-cr
	// The server side may already have returned; the client goroutine has a
	// buffered channel, so draining it is safe.
	sRes := <-sr
	return cRes, sRes
}

// TestCarrierAuthSuccess verifies the symmetric handshake completes with a
// shared secret on both ends.
func TestCarrierAuthSuccess(t *testing.T) {
	secret := DeriveSecret("e2e-auth-secret")
	cRes, sRes := runAuthPair(t, secret, secret, 2*time.Second)
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

// TestCarrierAuthWrongSecret verifies the responder rejects a mismatched
// secret and the client eventually fails (here via its deadline).
func TestCarrierAuthWrongSecret(t *testing.T) {
	cRes, sRes := runAuthPair(t, DeriveSecret("client-secret"), DeriveSecret("server-secret"), 300*time.Millisecond)
	if sRes.err == nil || !strings.Contains(sRes.err.Error(), "mismatch") {
		t.Fatalf("server err = %v, want secret mismatch", sRes.err)
	}
	if cRes.err == nil {
		t.Fatal("client succeeded despite server rejecting the secret")
	}
}

// TestCarrierAuthTruncatedPayload verifies the responder rejects an auth
// frame whose payload is not 32 bytes.
func TestCarrierAuthTruncatedPayload(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	if err := WriteFrame(a, 0, FrameAuth, []byte("short")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if _, err := CarrierAuth(context.Background(), b, false, DeriveSecret("x")); err == nil {
		t.Fatal("responder accepted truncated auth payload")
	}
}

// TestCarrierAuthUnexpectedFrame verifies the responder rejects any non-auth
// frame arriving during the handshake.
func TestCarrierAuthUnexpectedFrame(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	if err := WriteFrame(a, 0, FramePing, nil); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	_, err := CarrierAuth(context.Background(), b, false, DeriveSecret("x"))
	if err == nil || !strings.Contains(err.Error(), "unexpected frame") {
		t.Fatalf("err = %v, want unexpected-frame rejection", err)
	}
}

// TestCarrierAuthBadPong verifies the client rejects a pong whose payload is
// not [0].
func TestCarrierAuthBadPong(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	secret := DeriveSecret("pong-test")
	// Peer plays the server: echo auth, then a malformed pong.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = WriteFrame(b, 0, FrameAuth, secret)
		_ = WriteFrame(b, 0, FramePong, []byte{1})
	}()
	_, err := CarrierAuth(context.Background(), a, true, secret)
	if err == nil || !strings.Contains(err.Error(), "bad auth pong") {
		t.Fatalf("err = %v, want bad-auth-pong rejection", err)
	}
	wg.Wait()
}

// TestCarrierAuthContextTimeout verifies the client fails (instead of
// hanging forever) when the peer never completes the handshake.
func TestCarrierAuthContextTimeout(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	// b (the "server") is never driven: it stays silent.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := CarrierAuth(ctx, a, true, DeriveSecret("timeout"))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("client auth succeeded against a silent peer")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("auth took %v; deadline was not enforced", elapsed)
	}
}
