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
	"strconv"
	"strings"
	"unicode"

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
	// ErrUnmanagedState: a CDN submode transition would delete or
	// overwrite an operator-owned file (one that does NOT carry the
	// exact project-managed marker). Ownership is fail-closed.
	ErrUnmanagedState = errors.New("origin: refusing to touch an unmanaged (operator-owned) file")
	// ErrCDNTrustUndeclared: a CDN mode A plan did not declare how the
	// CDN authenticates the origin certificate (decision D9). Mode A
	// fails CLOSED on an undeclared capability: a Caddy-internal
	// certificate is NOT automatically trusted by a generic CDN.
	ErrCDNTrustUndeclared = errors.New("origin: cdn mode A requires the explicit origin certificate trust declaration (D9)")
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
	// Requires CDNOriginTrust on the Plan (D9).
	CDNTLSOrigin CDNSecurity = "tlsOrigin"
	// CDNPlainOrigin (mode B): the CDN talks to the origin in the clear
	// (no Caddy; the origin leg is unencrypted — auth v1 still
	// authenticates the carrier, but no key material may ride it clear).
	CDNPlainOrigin CDNSecurity = "plainOrigin"
)

// CDNOriginTrust declares how the CDN authenticates the ORIGIN
// certificate in cdn mode A (decision D9, architecture §5.1): a
// Caddy-internal (private-CA) certificate is NOT automatically trusted
// by a generic CDN, so the operator MUST declare the CDN's capability
// explicitly. Mode A fails closed when this is unset.
type CDNOriginTrust string

const (
	// CDNOriginTrustPullCA (contract 2 of D9): the operator exports the
	// Caddy local root CA certificate (printed by CDNOriginInstructions)
	// and installs it into the CDN's custom-trust / authenticated-origin
	// configuration (e.g. Cloudflare "Authenticated Origin Pulls" with an
	// uploaded CA, or an equivalent custom-CA feature). The CDN
	// AUTHENTICATES the origin certificate against that CA. The CA
	// PRIVATE key never leaves the host (Caddy's own storage; this
	// package never reads it — only the public root CERTIFICATE is
	// exported).
	CDNOriginTrustPullCA CDNOriginTrust = "pullCA"
	// CDNOriginTrustUnauthenticated (contract 1 of D9): the CDN's origin
	// pull is set to a mode that ACCEPTS any certificate ("TLS but no
	// origin verification" / "Full (not strict)"). The CDN does NOT
	// authenticate the origin certificate: the CDN→origin leg is
	// ENCRYPTED against passive observers but NOT authenticated — an
	// active MITM between the CDN and the origin can present its own
	// certificate. The operator acknowledges this explicitly.
	CDNOriginTrustUnauthenticated CDNOriginTrust = "unauthenticatedTLS"
)

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

// Plan is the validated operator input to every provider (one shape,
// doc §5.1). It is the convergence unit for T7: an unchanged Plan must
// produce a byte-identical no-op.
type Plan struct {
	Mode           Mode           // caddy | cdn | none
	Domain         string         // upload domain (ValidDomain); empty for none
	UpstreamAddr   string         // "127.0.0.1:9001" — the local WS listener
	OriginPort     int            // cdn mode origin port (caddy = 443 fixed)
	ACMEChallenge  ACMEChallenge  // http01 (default) | tlsalpn01 (caddy only)
	ACMEEmail      string         // ACME contact (optional, caddy only)
	CDNSecurity    CDNSecurity    // tlsOrigin (A) | plainOrigin (B), cdn only
	CDNOriginTrust CDNOriginTrust // pullCA | unauthenticatedTLS — REQUIRED for cdn mode A (D9)
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
		if p.CDNSecurity != "" || p.CDNOriginTrust != "" {
			problems = append(problems, "cdn fields: only for cdn mode")
		}
	case ModeCDN:
		problems = append(problems, validateDomain(p.Domain, "domain")...)
		switch p.CDNSecurity {
		case CDNTLSOrigin:
			// Mode A: the origin runs Caddy in front of the LOCAL WS
			// listener → the upstream must be loopback.
			problems = append(problems, validateUpstream(p.UpstreamAddr)...)
			if p.OriginPort < 1 || p.OriginPort > 65535 {
				problems = append(problems, "originPort: must be 1..65535")
			}
			// D9 fail-closed: mode A requires the operator to declare
			// how the CDN authenticates the origin certificate. Without
			// a declaration, deploy would either fail at runtime (a
			// strict CDN rejects the private-CA cert) or silently
			// disable origin authentication.
			switch p.CDNOriginTrust {
			case CDNOriginTrustPullCA, CDNOriginTrustUnauthenticated:
			default:
				problems = append(problems, "cdnOriginTrust: required for cdn mode A — must be pullCA (CDN authenticates the exported Caddy root CA) or unauthenticatedTLS (operator acknowledges an unauthenticated origin leg, MITM possible)")
			}
		case CDNPlainOrigin:
			// Mode B: no Caddy, no upstream (the CDN talks straight to
			// the splitter's own public listener) — UpstreamAddr is
			// ignored (design §3.3).
			if p.OriginPort < 1 || p.OriginPort > 65535 {
				problems = append(problems, "originPort: must be 1..65535")
			}
			if p.CDNOriginTrust != "" {
				problems = append(problems, "cdnOriginTrust: only for cdn mode A (tlsOrigin)")
			}
		default:
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
		if p.OriginPort != 0 || p.ACMEChallenge != "" || p.ACMEEmail != "" || p.CDNSecurity != "" || p.CDNOriginTrust != "" {
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
//
// CRITICAL (review CRITICAL-1): the port must additionally PARSE as a
// decimal integer in 1..65535. net.SplitHostPort is a structural
// splitter, NOT a port-token validator — it accepts "9001\n{evil}" as a
// port string. Renderers therefore NEVER use the raw UpstreamAddr: they
// reconstruct it from the parsed pieces via canonicalUpstream.
func validateUpstream(addr string) []string {
	if addr == "" {
		return []string{"upstreamAddr: required"}
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{"upstreamAddr: must be host:port"}
	}
	if portStr == "" {
		return []string{"upstreamAddr: port required"}
	}
	if _, err := parseUpstreamPort(portStr); err != nil {
		return []string{"upstreamAddr: port must be a decimal number in 1..65535"}
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return []string{"upstreamAddr: must be a loopback address (127.0.0.1/::1) — the origin fronts the local splitter"}
	}
	return nil
}

// parseUpstreamPort parses a port token strictly: decimal digits only,
// range 1..65535. It rejects every non-digit byte (whitespace, control
// characters, signs, hex, decorated numbers) — the token ends up inside
// a Caddyfile line, so anything that is not a bare decimal port is
// refused.
func parseUpstreamPort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty port")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("non-digit in port")
		}
	}
	// 5 digits max (65535); reject longer strings before ParseUint to
	// avoid overflow noise.
	if len(s) > 5 {
		return 0, fmt.Errorf("port out of range")
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("port out of range")
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port out of range")
	}
	return int(n), nil
}

// canonicalUpstream re-derives the upstream address from a VALIDATED
// host:port pair and returns it in the exact form written into the
// Caddyfile: net.JoinHostPort(parsedLoopbackIP.String(), port). The raw
// operator string NEVER reaches the rendered output (review CRITICAL-1).
//
// It returns an error when addr does not pass the validateUpstream
// rule; renderers call it only after validate, so an error here is a
// defensive bug guard, not an operator-facing path.
func canonicalUpstream(addr string) (string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("origin: upstream must be host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("origin: upstream host must be a loopback IP")
	}
	port, err := parseUpstreamPort(portStr)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

// canonicalACMEEmail re-validates the ACME contact address and returns
// the canonical token written into the Caddyfile. Renderers use this —
// never the raw plan field (review CRITICAL-1).
func canonicalACMEEmail(e string) (string, error) {
	if len(validateACMEEmail(e)) > 0 {
		return "", fmt.Errorf("origin: acmeEmail is not a Caddy-safe token")
	}
	return e, nil
}

// validateACMEEmail is a SYNTACTIC, Caddy-token check (Caddy only needs
// the address as the ACME contact): exactly one '@', non-empty both
// sides, and NO whitespace or control character anywhere in the value
// (leading, trailing, or internal). A newline/tab/space would let the
// value escape its `tls`/`email` Caddyfile token and inject directives
// or blocks (review CRITICAL-1), so EVERY ASCII and Unicode
// whitespace/control rune is rejected — not just TrimSpace on the
// ends. Additionally the local part and host part must be single
// tokens: no braces, quotes, backslashes, semicolons, or '#'.
//
// Not a full RFC mailbox check (design §3.3): the rule is deliberately
// narrower than RFC 5322 because the value is rendered verbatim into a
// line-oriented config file.
func validateACMEEmail(e string) []string {
	if e == "" {
		return nil // optional
	}
	const msg = "acmeEmail: invalid (expected a simple user@host address)"
	// Reject EVERY whitespace/control rune (Unicode-aware): a single
	// '\n', '\r', '\t', ' ' or control byte anywhere in the value is an
	// injection vector into the line-oriented Caddyfile.
	for _, r := range e {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return []string{msg}
		}
	}
	// Reject Caddyfile-significant punctuation (braces open blocks,
	// '#' starts a comment, quotes/backslashes re-tokenize a line).
	if strings.ContainsAny(e, "{}#\"'`\\;") {
		return []string{msg}
	}
	if strings.Count(e, "@") != 1 {
		return []string{msg}
	}
	local, host, _ := strings.Cut(e, "@")
	if local == "" || host == "" {
		return []string{msg}
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
	// plan → re-render + re-activate behind the validate gate. The ctx
	// bounds every external action (downloads, binary invocations);
	// a canceled ctx aborts before any new mutation begins and returns
	// context.Canceled/context.DeadlineExceeded.
	Configure(ctx context.Context, plan Plan) error
	// Status is read-only (no mutation) and never returns a secret. A
	// canceled ctx is honored before any binary invocation.
	Status(ctx context.Context) (Health, error)
}

// ---------------------------------------------------------------------------
// The shared upstream path
// ---------------------------------------------------------------------------

// UpstreamPath is the only path the Iran-side WS server serves — the
// SAME constant internal/config enforces on the carrier URL (no rule
// duplicated: origin imports the value, it does not re-declare it).
const UpstreamPath = config.ExpectedCarrierPath
