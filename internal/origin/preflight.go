package origin

// preflight.go — the TLS 1.3 destination probe (doc §4.5, design D4).
//
// A Reality/vision impersonation target MUST offer TLS 1.3 (the SNI
// is matched against the target's cert at handshake time, and Reality
// requires TLS 1.3). A destination that does not offer TLS 1.3 will
// fail at RUNTIME — so it is probed at INSTALL time, fail-closed:
//
//   - unreachable destination → error (the install fails);
//   - reachable but no TLS 1.3 → ErrNoTLS13 (HARD fail).
//
// The probe is pure stdlib (net + crypto/tls), Caddy-free, and reused
// for the Germany Reality destination validation (T8/T10 call it with
// dest + SNI). It is bounded (10s total) and makes NO unbounded retry.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrNoTLS13: the destination is reachable but does not offer TLS 1.3.
// Reality/vision requires TLS 1.3, so a suboptimal destination fails
// HARD at install time rather than at runtime.
var ErrNoTLS13 = errors.New("origin: destination does not offer TLS 1.3 (Reality/vision requires TLS 1.3)")

// probeBudget is the TOTAL time budget for a probe (dial + handshake).
const probeBudget = 10 * time.Second

// ProbeResult is the outcome of a TLS 1.3 destination probe.
type ProbeResult struct {
	Reachable bool // the destination accepted a TCP connection
	TLS13     bool // the handshake negotiated TLS 1.3
}

// ProbeTLS13 dials target (host:port), performs a TLS ClientHello
// offering ONLY TLS 1.3 (MinVersion = MaxVersion = TLS13) with the
// given SNI, and reports whether the destination offers TLS 1.3.
//
// Fail-closed: an unreachable destination returns a dial error; a
// reachable destination that negotiates < TLS 1.3 returns ErrNoTLS13.
// The ctx (or the 10s budget, whichever is shorter) bounds the probe.
func ProbeTLS13(ctx context.Context, target, sni string) (*ProbeResult, error) {
	if target == "" {
		return nil, fmt.Errorf("origin: empty probe target")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("origin: probe target must be host:port: %v", err)
	}
	if port == "" {
		return nil, fmt.Errorf("origin: probe target must be host:port (missing port)")
	}

	// Bound the probe by the ctx and the 10s budget (whichever ends
	// first). If the caller gave no deadline, impose the budget.
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, probeBudget)
		defer cancel()
	} else if time.Until(deadline) > probeBudget {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, probeBudget)
		defer cancel()
	}

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return &ProbeResult{Reachable: false, TLS13: false}, fmt.Errorf("origin: destination %s unreachable: %v", target, err)
	}
	defer conn.Close()

	// Offer ONLY TLS 1.3: if the server cannot do 1.3, the handshake
	// fails with a protocol error → we report no-TLS13 (hard fail).
	tlsConn := tls.Client(conn, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         sni,
		InsecureSkipVerify: true, // dest validation is about the PROTOCOL
		// version, not the cert chain (the SNI is matched by Reality
		// at runtime against the impersonation target's real cert).
	})
	herr := tlsConn.HandshakeContext(ctx)
	if herr != nil {
		tlsConn.Close()
		return &ProbeResult{Reachable: true, TLS13: false}, fmt.Errorf("%w: %s: %v", ErrNoTLS13, target, herr)
	}
	// Success: the server negotiated TLS 1.3.
	ver := tlsConn.ConnectionState().Version
	tlsConn.Close()
	if ver != tls.VersionTLS13 {
		return &ProbeResult{Reachable: true, TLS13: false}, fmt.Errorf("%w: negotiated version 0x%x", ErrNoTLS13, ver)
	}
	return &ProbeResult{Reachable: true, TLS13: true}, nil
}
