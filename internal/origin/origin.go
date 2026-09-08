// Package origin is the managed TLS-origin provider for the Iran-side
// up-carrier (architecture doc §5): it turns the public
// wss://<upload-domain>/upload endpoint into the local WebSocket
// listener the splitter serves on 127.0.0.1:9001. Three providers:
//
//   - caddy: install the pinned Caddy, generate + validate + activate a
//     0600 Caddyfile that fronts the local WS listener (ACME TLS);
//   - cdn:  the operator's CDN fronts the origin (mode A: TLS-terminating
//     Caddy on the origin; mode B: plain origin, no Caddy);
//   - none: testing only — the carrier dials the local WS listener
//     directly (ws://, no TLS); rejected for public deployments.
//
// Design doc: plans/t4-design.md. The Caddy binary is installed like the
// Xray binary (internal/xray, T2/T3): pinned version, upstream-published
// SHA-512 checksum, fail-closed verification, versioned prefix layout,
// `caddy version` smoke check, `caddy validate --config` gate. T4 does
// NOT start the service (T5), open the firewall (T6), or talk to ACME
// (Caddy runtime, design decision D6).
package origin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------
//
// None of them include operator-supplied VALUES (the plan is validated
// fail-closed and errors name fields, mirroring xray.RealityParams and
// pairing.fieldErr).

var (
	// ErrNoCaddyfile: the requested mode generates no Caddyfile (none
	// mode, cdn mode B). Callers must not expect a rendered file.
	ErrNoCaddyfile = errors.New("origin: this mode generates no Caddyfile")
	// ErrInvalidPlan: the Plan failed validation (field names included,
	// values never).
	ErrInvalidPlan = errors.New("origin: invalid plan")
	// ErrNoBinary: the pinned Caddy binary is not installed at the
	// versioned path (install it first via Installer.Install).
	ErrNoBinary = errors.New("origin: pinned Caddy binary not installed")
	// ErrNoCaddyfileOnDisk: the activated Caddyfile is missing.
	ErrNoCaddyfileOnDisk = errors.New("origin: activated Caddyfile is missing")
	// ErrVersionMismatch: the installed binary reports a different
	// version than the pin.
	ErrVersionMismatch = errors.New("origin: installed Caddy version does not match the pin")
)

// ---------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------

// Mode selects the origin provider (doc §5.1).
type Mode string

// The three supported origin modes.
const (
	ModeCaddy Mode = "caddy" // Caddy in front of the local WS listener (ACME)
	ModeCDN   Mode = "cdn"   // operator CDN in front of the origin
	ModeNone  Mode = "none"  // testing only: direct ws:// to the local listener
)

// ACMEChallenge selects the ACME challenge method for caddy mode.
type ACMEChallenge string

const (
	// ACMEHTTP01: default. Let's Encrypt HTTP-01 (port 80 reachable).
	ACMEHTTP01 ACMEChallenge = "http01"
	// ACMETLSALPN01: fallback for hosts without a reachable port 80.
	ACMETLSALPN01 ACMEChallenge = "tlsalpn01"
)

// CDNSecurity selects how the CDN talks to the origin (cdn mode).
type CDNSecurity string

const (
	// CDNTLSOrigin (mode A): the CDN terminates TLS publicly and talks
	// to the origin over TLS (the origin runs Caddy with `tls internal`).
	CDNTLSOrigin CDNSecurity = "tlsOrigin"
	// CDNPlainOrigin (mode B): the CDN talks to the origin in the clear
	// (no Caddy; the origin leg is unencrypted — auth v1 still
	// authenticates the carrier, but no key material may ride it clear).
	CDNPlainOrigin CDNSecurity = "plainOrigin"
)

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

// Plan is the validated operator input to every provider (one shape,
// doc §5.1). It is the convergence unit for T7: an unchanged Plan must
// produce a byte-identical no-op.
type Plan struct {
	Mode          Mode          // caddy | cdn | none
	Domain        string        // upload domain (ValidDomain); empty for none
	UpstreamAddr  string        // "127.0.0.1:9001" — the local WS listener
	OriginPort    int           // cdn mode origin port (caddy = 443 fixed)
	ACMEChallenge ACMEChallenge // http01 (default) | tlsalpn01 (caddy only)
	ACMEEmail     string        // ACME contact (optional, caddy only)
	CDNSecurity   CDNSecurity   // tlsOrigin (A) | plainOrigin (B), cdn only
}

// validate is fail-closed: it returns a single error naming the
// offending fields (never their values). Mirrors xray and pairing.
func (p Plan) validate() error {
	var problems []string
	switch p.Mode {
	case ModeCaddy:
		problems = append(problems, validateDomain(p.Domain, "domain")...)
		problems = append(problems, validateUpstream(p.UpstreamAddr)...)
		if p.OriginPort != 0 && p.OriginPort != 443 {
			problems = append(problems, "originPort: caddy mode is fixed to 443 (ACME)")
		}
		switch p.ACMEChallenge {
		case "", ACMEHTTP01, ACMETLSALPN01:
		default:
			problems = append(problems, "acmeChallenge: must be http01 or tlsalpn01")
		}
		problems = append(problems, validateACMEEmail(p.ACMEEmail)...)
		if p.CDNSecurity != "" {
			problems = append(problems, "cdnSecurity: only for cdn mode")
		}
	case ModeCDN:
		problems = append(problems, validateDomain(p.Domain, "domain")...)
		if p.CDNSecurity == CDNTLSOrigin {
			// Mode A: the origin runs Caddy in front of the LOCAL WS
			// listener → the upstream must be loopback.
			problems = append(problems, validateUpstream(p.UpstreamAddr)...)
			if p.OriginPort < 1 || p.OriginPort > 65535 {
				problems = append(problems, "originPort: must be 1..65535")
			}
		} else if p.CDNSecurity == CDNPlainOrigin {
			// Mode B: no Caddy, no upstream (the CDN talks straight to
			// the splitter's own public listener) — UpstreamAddr is
			// ignored (design §3.3).
			if p.OriginPort < 1 || p.OriginPort > 65535 {
				problems = append(problems, "originPort: must be 1..65535")
			}
		} else {
			problems = append(problems, "cdnSecurity: must be tlsOrigin or plainOrigin")
		}
		if p.ACMEChallenge != "" || p.ACMEEmail != "" {
			problems = append(problems, "acme fields: only for caddy mode")
		}
	case ModeNone:
		// Domain stays empty (ws:// test URL, no public name).
		if p.Domain != "" {
			problems = append(problems, "domain: must be empty for none mode")
		}
		problems = append(problems, validateUpstream(p.UpstreamAddr)...)
		if p.OriginPort != 0 || p.ACMEChallenge != "" || p.ACMEEmail != "" || p.CDNSecurity != "" {
			problems = append(problems, "caddy/cdn fields: not for none mode")
		}
	default:
		problems = append(problems, "mode: must be caddy, cdn, or none")
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInvalidPlan, strings.Join(problems, "; "))
}

// validateDomain checks the upload domain (single source of truth:
// pairing.ValidUploadDomain — the SAME rule blob A applies; the rule is
// NOT re-implemented here, design §3.3).
func validateDomain(d, field string) []string {
	if d == "" || !ValidDomain(d) {
		return []string{field + ": invalid public domain"}
	}
	return nil
}

// validateUpstream checks host:port with a LOOPBACK host requirement
// (the origin fronts the local splitter, never dials out; design §3.3,
// security checklist item 8).
func validateUpstream(addr string) []string {
	if addr == "" {
		return []string{"upstreamAddr: required"}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{"upstreamAddr: must be host:port"}
	}
	if port == "" {
		return []string{"upstreamAddr: port required"}
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return []string{"upstreamAddr: must be a loopback address (127.0.0.1/::1) — the origin fronts the local splitter"}
	}
	return nil
}

// validateACMEEmail is a SYNTACTIC check (Caddy only needs the address
// as the ACME contact): exactly one '@', non-empty both sides, no
// whitespace. Not a full RFC mailbox check (design §3.3).
func validateACMEEmail(e string) []string {
	if e == "" {
		return nil // optional
	}
	if strings.Count(e, "@") != 1 || strings.TrimSpace(e) != e {
		return []string{"acmeEmail: invalid (expected a simple user@host address)"}
	}
	_, rest, _ := strings.Cut(e, "@")
	if e[0] == '@' || e[len(e)-1] == '@' || rest == "" {
		return []string{"acmeEmail: invalid (expected a simple user@host address)"}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ValidDomain
// ---------------------------------------------------------------------------

// ValidDomain reports whether d is an acceptable public upload domain.
// It delegates to pairing.ValidUploadDomain (the single source of truth
// shared with blob A — the rule is not re-implemented, design §3.3).
func ValidDomain(d string) bool { return pairing.ValidUploadDomain(d) }

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

// Health is the provider's liveness report (D8: FILE-level liveness —
// binary present + version pinned + Caddyfile present and valid. It
// does NOT probe systemd (T5) and does NOT open sockets, so it is safe
// pre-service-start and in tests without root).
type Health struct {
	Mode   Mode   `json:"mode"`
	Live   bool   `json:"live"` // file-level: binary + Caddyfile OK
	Detail string `json:"detail"`
}

// ---------------------------------------------------------------------------
// OriginProvider (doc §5.1, exact)
// ---------------------------------------------------------------------------

// OriginProvider converges the up-carrier origin to a desired state.
type OriginProvider interface {
	// Configure is idempotent: unchanged plan → byte-no-op; changed
	// plan → re-render + re-activate behind the validate gate.
	Configure(ctx context.Context, plan Plan) error
	// Status is read-only (no mutation) and never returns a secret.
	Status(ctx context.Context) (Health, error)
}

// ---------------------------------------------------------------------------
// The shared upstream path
// ---------------------------------------------------------------------------

// UpstreamPath is the only path the Iran-side WS server serves — the
// SAME constant internal/config enforces on the carrier URL (no rule
// duplicated: origin imports the value, it does not re-declare it).
const UpstreamPath = config.ExpectedCarrierPath
