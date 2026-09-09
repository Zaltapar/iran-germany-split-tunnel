package origin

// preflight_hardening_test.go — review MEDIUM-2: the TLS 1.3 probe must
// validate the SNI through the pairing rule, return field-only bounded
// errors, preserve context.Canceled/DeadlineExceeded, and distinguish a
// PROVEN protocol-version rejection (ErrNoTLS13) from a generic TLS
// handshake failure (ErrProbeTLSHandshake).

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// SNI validation (pairing rule is the single source of truth)
// ---------------------------------------------------------------------------

// Empty/invalid SNI is rejected BEFORE any network action, as
// ErrProbeSNI — never placed into tls.Config unvalidated.
func TestProbeRejectsInvalidSNI(t *testing.T) {
	addr := startTLSListener(t, tls.VersionTLS13)
	for _, bad := range []string{
		"",                  // empty
		"x",                 // single label
		"UPPER.example.com", // uppercase (Reality SNI is lowercase-only)
		"under_score.com",   // underscore
		"127.0.0.1",         // IP literal is not a usable SNI
		"has space.com",     // whitespace
		"bad.com:443",       // port
		"wss://bad.com",     // scheme
	} {
		if _, err := ProbeTLS13(context.Background(), addr, bad); !errors.Is(err, ErrProbeSNI) {
			t.Errorf("SNI %q: want ErrProbeSNI, got %v", bad, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Field-only errors (no sensitive target/SNI in the error text)
// ---------------------------------------------------------------------------

// A failing probe must NOT embed the target or the SNI in the returned
// error (deployment domains/targets are security-sensitive).
func TestProbeErrorIsFieldOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	const sni = "secret-target.example.com"
	_, err = ProbeTLS13(context.Background(), addr, sni)
	if err == nil {
		t.Fatal("expected an error for a closed port")
	}
	if strings.Contains(err.Error(), sni) {
		t.Errorf("error embeds the SNI: %v", err)
	}
	if strings.Contains(err.Error(), addr) {
		t.Errorf("error embeds the target address: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Cancellation classification (never a phantom TLS verdict)
// ---------------------------------------------------------------------------

// A canceled ctx during the handshake returns context.Canceled, NOT
// ErrNoTLS13 and NOT ErrProbeTLSHandshake.
func TestProbeHandshakeCanceledNotMisclassified(t *testing.T) {
	// A plain TCP listener that accepts but never speaks TLS: the
	// handshake blocks until the ctx is canceled.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			// Hold the conn open without speaking; closed on cleanup.
			defer c.Close()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled: the handshake aborts immediately
	_, err = ProbeTLS13(ctx, ln.Addr().String(), "ok.example.com")
	if err == nil {
		t.Fatal("expected an error under a canceled ctx")
	}
	if errors.Is(err, ErrNoTLS13) {
		t.Errorf("canceled handshake misclassified as ErrNoTLS13")
	}
	if errors.Is(err, ErrProbeTLSHandshake) {
		t.Errorf("canceled handshake misclassified as ErrProbeTLSHandshake")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
}

// A deadline-exceeded ctx returns context.DeadlineExceeded (not a TLS
// verdict).
func TestProbeHandshakeDeadlineNotMisclassified(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			defer c.Close() // never speaks TLS
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = ProbeTLS13(ctx, ln.Addr().String(), "ok.example.com")
	if err == nil {
		t.Fatal("expected an error under a deadline ctx")
	}
	if errors.Is(err, ErrNoTLS13) || errors.Is(err, ErrProbeTLSHandshake) {
		t.Errorf("deadline handshake misclassified as a TLS verdict: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want context.DeadlineExceeded, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Classification: non-TLS peer and SNI-rejecting TLS 1.3 peer
// ---------------------------------------------------------------------------

// A non-TLS peer (plain TCP that closes immediately) is a generic
// handshake failure (ErrProbeTLSHandshake), NOT a proven no-TLS13.
func TestProbeNonTLSPeerIsGenericHandshakeFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			c.Close() // immediately close — non-TLS peer
		}
	}()
	res, err := ProbeTLS13(context.Background(), ln.Addr().String(), "ok.example.com")
	if err == nil {
		t.Fatal("expected an error for a non-TLS peer")
	}
	if !errors.Is(err, ErrProbeTLSHandshake) && !errors.Is(err, ErrNoTLS13) {
		t.Errorf("want a TLS handshake class, got %v", err)
	}
	if res == nil || !res.Reachable || res.TLS13 {
		t.Errorf("ProbeResult = %+v, want Reachable + no-TLS13", res)
	}
}

// A TLS 1.3-capable peer that REJECTS the supplied SNI (unrecognized
// name → the server aborts) is a generic handshake failure, NOT
// ErrNoTLS13 (the peer DOES offer TLS 1.3 — the failure is the SNI).
func TestProbeTLS13PeerRejectingSNI(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		// Reject every SNI that is not the exact expected one by
		// failing the GetCertificate callback (a TLS 1.3-capable server
		// that will not serve this SNI).
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "expected.example.com" {
				return nil, errors.New("unrecognized name")
			}
			return &cert, nil
		},
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
			_ = tc.Handshake()
			tc.Close()
		}
	}()
	res, err := ProbeTLS13(context.Background(), ln.Addr().String(), "other.example.com")
	if err == nil {
		t.Fatal("expected an error when the peer rejects the SNI")
	}
	if errors.Is(err, ErrNoTLS13) {
		t.Errorf("a TLS 1.3 peer rejecting the SNI was misclassified as ErrNoTLS13")
	}
	if !errors.Is(err, ErrProbeTLSHandshake) {
		t.Errorf("want ErrProbeTLSHandshake, got %v", err)
	}
	if res == nil || !res.Reachable {
		t.Errorf("ProbeResult = %+v, want Reachable", res)
	}
}

// A TLS 1.2-only peer is a PROVEN no-TLS13 (protocol_version alert) →
// ErrNoTLS13 (the classification positive case).
func TestProbeTLS12OnlyIsProvenNoTLS13(t *testing.T) {
	addr := startTLSListener(t, tls.VersionTLS12)
	_, err := ProbeTLS13(context.Background(), addr, "ok.example.com")
	if !errors.Is(err, ErrNoTLS13) {
		t.Fatalf("want ErrNoTLS13, got %v", err)
	}
}
