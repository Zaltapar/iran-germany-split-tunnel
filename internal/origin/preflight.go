package origin

// preflight.go — the TLS 1.3 destination probe (doc §4.5, design D4).
//
// A Reality/vision impersonation target MUST offer TLS 1.3 (the SNI
// is matched against the target's cert at handshake time, and Reality
// requires TLS 1.3). A destination that does not offer TLS 1.3 will
// fail at RUNTIME — so it is probed at INSTALL time, fail-closed:
//
//   - unreachable destination → ErrProbeUnreachable (the install fails);
//   - reachable but TLS handshake fails without proof of the cause →
//     ErrProbeTLSHandshake (fail-closed, honestly generic);
//   - reachable, handshake fails, and the peer PROVABLY lacks TLS 1.3 →
//     ErrNoTLS13 (HARD fail, diagnosed).
//
// The probe is pure stdlib (net + crypto/tls), Caddy-free, and reused
// for the Germany Reality destination validation (T8/T10 call it with
// dest + SNI). It is bounded (10s total) and makes NO unbounded retry.
//
// Secret hygiene (review MEDIUM-2): the deployment target and SNI are
// security-sensitive (they identify the impersonation destination), so
// errors are FIELD-ONLY and bounded — they never embed the target, the
// SNI, or the underlying network/TLS error text.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
)

var (
	// ErrNoTLS13: the destination is reachable and PROVABLY does not
	// offer TLS 1.3 (a recognized protocol-version rejection, or the
	// negotiated version is below 1.3). Reality/vision requires TLS 1.3,
	// so a suboptimal destination fails HARD at install time rather than
	// at runtime.
	ErrNoTLS13 = errors.New("origin: destination does not offer TLS 1.3 (Reality/vision requires TLS 1.3)")
	// ErrProbeUnreachable: the destination did not accept a TCP
	// connection within the probe budget.
	ErrProbeUnreachable = errors.New("origin: destination unreachable (TCP connect failed)")
	// ErrProbeTLSHandshake: the destination accepted TCP but the TLS
	// handshake failed WITHOUT proof that the cause is a missing
	// TLS 1.3 (e.g. SNI rejection, a client-cert request, an immediate
	// close, or a non-TLS peer). Fail-closed, honestly generic (review
	// MEDIUM-2): the probe reports a handshake failure, not a phantom
	// TLS-version diagnosis.
	ErrProbeTLSHandshake = errors.New("origin: destination accepted TCP but the TLS 1.3 handshake failed (cause not provably the TLS version)")
	// ErrProbeSNI: the supplied SNI is not a valid Reality SNI (the
	// pairing rule is the single source of truth — MEDIUM-2).
	ErrProbeSNI = errors.New("origin: invalid probe SNI")
)

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
// Fail-closed: an unreachable destination returns ErrProbeUnreachable;
// a reachable destination that negotiates < TLS 1.3 returns ErrNoTLS13;
// a reachable destination whose handshake fails for another reason
// returns ErrProbeTLSHandshake. The ctx (or the 10s budget, whichever
// is shorter) bounds the probe, and a canceled/deadline-exceeded ctx is
// returned as context.Canceled / context.DeadlineExceeded — NOT
// misclassified as a TLS failure (review MEDIUM-2). Errors are
// field-only and bounded: they never embed the target or SNI.
func ProbeTLS13(ctx context.Context, target, sni string) (*ProbeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if target == "" {
		return nil, fmt.Errorf("origin: empty probe target")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("origin: probe target must be host:port")
	}
	if port == "" {
		return nil, fmt.Errorf("origin: probe target must be host:port (missing port)")
	}
	// Validate the SNI through the pairing/Xray rule (single source of
	// truth) BEFORE it is placed into tls.Config (MEDIUM-2): an empty or
	// malformed SNI is a configuration error, not a network probe.
	if !pairing.ValidSNI(sni) {
		return nil, ErrProbeSNI
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
		// Cancellation/deadline during the dial is its own class, never
		// a "destination down" verdict.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return &ProbeResult{Reachable: false, TLS13: false}, ctxErr
		}
		return &ProbeResult{Reachable: false, TLS13: false}, ErrProbeUnreachable
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
		// Cancellation/deadline during the handshake is its own class,
		// NOT a TLS verdict (MEDIUM-2).
		if ctxErr := ctx.Err(); ctxErr != nil {
			return &ProbeResult{Reachable: true, TLS13: false}, ctxErr
		}
		if isTLSVersionRejection(herr) {
			return &ProbeResult{Reachable: true, TLS13: false}, ErrNoTLS13
		}
		return &ProbeResult{Reachable: true, TLS13: false}, ErrProbeTLSHandshake
	}
	// Success: the server negotiated TLS 1.3.
	ver := tlsConn.ConnectionState().Version
	tlsConn.Close()
	if ver != tls.VersionTLS13 {
		return &ProbeResult{Reachable: true, TLS13: false}, ErrNoTLS13
	}
	return &ProbeResult{Reachable: true, TLS13: true}, nil
}

// tlsAlertProtocolVersion is the wire value of the TLS
// protocol_version alert (RFC 8446 §6: 70). crypto/tls keeps the
// constant unexported, so it is named here (verified: alert.go
// alertProtocolVersion = 70; AlertError carries the same value).
const tlsAlertProtocolVersion = 70

// isTLSVersionRejection reports whether a TLS handshake error PROVES
// the peer cannot offer TLS 1.3: a protocol_version alert from the wire
// (tls.AlertError value 70), or an explicit "no/unsupported versions"
// error produced by the Go TLS stack when the peer cannot negotiate a
// version. Every other handshake failure (SNI rejection — the
// unrecognized_name alert, a client-cert request, an immediate close,
// a non-TLS peer, cancellation) is deliberately NOT classified here
// (review MEDIUM-2: do not claim a missing TLS version without proof).
func isTLSVersionRejection(err error) bool {
	if err == nil {
		return false
	}
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) && uint8(alertErr) == tlsAlertProtocolVersion {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "protocol version") ||
		strings.Contains(msg, "no supported versions") ||
		strings.Contains(msg, "unsupported versions")
}
