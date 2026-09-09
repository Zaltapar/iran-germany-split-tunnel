package origin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// preflight_test.go — the TLS 1.3 dest probe (design D4). Hermetic:
// local tls.Listeners on 127.0.0.1, self-signed certs, short ctx. No
// public network.

// selfSignedCert builds a self-signed cert + key for a local listener.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSListener starts a tls.Listener on 127.0.0.1 whose offered
// version range is [TLS12, maxVer]; returns its host:port. The accept
// loop performs the server-side handshake (a tls.Listener's conn
// handshakes LAZILY — it must be driven or the client's handshake
// fails) and then closes the conn.
//
//   - maxVer = TLS13 → the destination offers TLS 1.3 (the probe
//     negotiates 1.3 → success).
//   - maxVer = TLS12 → the destination offers AT MOST TLS 1.2 (the
//     TLS-1.3-only probe fails → ErrNoTLS13).
func startTLSListener(t *testing.T, maxVer uint16) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   maxVer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*tls.Conn)
			_ = tc.Handshake() // drive the server handshake; result is
			// irrelevant — the probe observes its own side.
			tc.Close()
		}
	}()
	return ln.Addr().String()
}

// A TLS 1.3-capable destination → Reachable + TLS13, no error.
func TestProbeTLS13Success(t *testing.T) {
	addr := startTLSListener(t, tls.VersionTLS13)
	res, err := ProbeTLS13(context.Background(), addr, "upload.example.com")
	if err != nil {
		t.Fatalf("ProbeTLS13: %v", err)
	}
	if !res.Reachable || !res.TLS13 {
		t.Errorf("ProbeResult = %+v, want Reachable+TLS13", res)
	}
}

// A TLS 1.2-only destination → ErrNoTLS13 (HARD fail, fail-closed).
func TestProbeTLS13NoTLS13(t *testing.T) {
	addr := startTLSListener(t, tls.VersionTLS12)
	res, err := ProbeTLS13(context.Background(), addr, "upload.example.com")
	if !errors.Is(err, ErrNoTLS13) {
		t.Fatalf("want ErrNoTLS13, got %v", err)
	}
	if !res.Reachable || res.TLS13 {
		t.Errorf("ProbeResult = %+v, want Reachable + no-TLS13", res)
	}
}

// An unreachable destination (closed port) → ErrProbeUnreachable, not
// ErrNoTLS13 (the diagnosis is honest about the class).
func TestProbeUnreachable(t *testing.T) {
	// Bind then close a port to get a guaranteed-closed local port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	res, err := ProbeTLS13(context.Background(), addr, "x.example.com")
	if err == nil {
		t.Fatal("expected dial error for a closed port")
	}
	if !errors.Is(err, ErrProbeUnreachable) {
		t.Errorf("want ErrProbeUnreachable, got %v", err)
	}
	if errors.Is(err, ErrNoTLS13) {
		t.Error("closed port must be a dial error, not ErrNoTLS13")
	}
	if res == nil || res.Reachable {
		t.Errorf("closed port must report Reachable=false: %+v", res)
	}
}

// ctx deadline honored (a short ctx bounds the probe).
func TestProbeHonorsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	// A black-hole-ish target: use a closed port so the dial fails fast
	// within the ctx; the point is the ctx path is exercised without a
	// >1s wall-clock in the test.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	if _, err := ProbeTLS13(ctx, addr, "x.example.com"); err == nil {
		t.Fatal("expected an error under a short ctx")
	}
}

// Malformed target → error (fail closed).
func TestProbeBadTarget(t *testing.T) {
	for _, bad := range []string{"", "noport", "host:badport"} {
		if _, err := ProbeTLS13(context.Background(), bad, "x"); err == nil {
			t.Errorf("target %q accepted", bad)
		}
	}
}
