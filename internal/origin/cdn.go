package origin

// cdn.go — the `cdn` provider: the operator's CDN fronts the origin
// (doc §5.1). Two sub-modes (CDNSecurity):
//
//   - A (CDNTLSOrigin): the CDN talks to the origin over TLS; the
//     origin runs the pinned Caddy with `tls internal` (Caddy's private
//     issuer — the CDN supplies the public certificate). Configure
//     installs Caddy + activates the §2.3.3 Caddyfile (reuses the
//     shared caddyCore — no duplicate install/activate logic).
//   - B (CDNPlainOrigin): the CDN talks to the origin in the clear;
//     NO Caddy, NO Caddyfile. Configure is a no-op; the operator
//     points the splitter's own public listener at the CDN via
//     SplitterEnv, and the leg is unencrypted (auth v1 still
//     authenticates the carrier — challenge/nonces/keyed MAC only, no
//     key material in clear).
//
// No provider-specific API calls in v1 (doc §5.1): the interface
// isolates future adapters; v1 emits deterministic operator-facing
// instructions only.
import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// CDNProvider is the `cdn` origin provider.
type CDNProvider struct{ core *caddyCore }

// Configure implements OriginProvider (cdn mode A or B).
func (p *CDNProvider) Configure(ctx context.Context, plan Plan) error {
	if plan.Mode != ModeCDN {
		return fmt.Errorf("%w: cdn provider requires mode cdn, got %q", ErrInvalidPlan, plan.Mode)
	}
	if plan.CDNSecurity == CDNPlainOrigin {
		// Mode B: no Caddy, no file. Validate the plan (names the
		// fields) but write nothing.
		return plan.validate()
	}
	// Mode A: TLS origin — install Caddy + activate the tls-internal
	// Caddyfile (shared core).
	return p.core.configure(ctx, plan)
}

// Status implements OriginProvider. With an activated Caddyfile it is
// the D8 file-level check (Caddy binary + tls-internal Caddyfile, mode
// A). Without one it reports the mode B resting state (no Caddy
// expected — the splitter serves the CDN directly).
func (p *CDNProvider) Status(ctx context.Context) (Health, error) {
	h := Health{Mode: ModeCDN}
	live := filepath.Join(p.core.Dir, p.core.fileName())
	if st, err := os.Lstat(live); err != nil || !st.Mode().IsRegular() {
		h.Live = false
		h.Detail = "no Caddyfile at " + live + " (cdn mode B plain origin — no Caddy expected — or mode A not configured)"
		return h, nil
	}
	return p.core.fileStatus(ModeCDN)
}

// cdnOriginPort returns the effective origin port (default 443).
func cdnOriginPort(plan Plan) int {
	if plan.OriginPort != 0 {
		return plan.OriginPort
	}
	return 443
}

// SplitterEnv returns the splitter environment line for cdn mode B
// (plain origin): the splitter's own public WS listener address. The
// CDN points the origin here; the leg is unencrypted (see the security
// note in CDNOriginInstructions).
func (p *CDNProvider) SplitterEnv(plan Plan) (string, error) {
	if plan.Mode != ModeCDN || plan.CDNSecurity != CDNPlainOrigin {
		return "", fmt.Errorf("origin: SplitterEnv requires cdn mode B (plainOrigin)")
	}
	if err := plan.validate(); err != nil {
		return "", err
	}
	return "SPLIT_WS_LISTEN=0.0.0.0:" + strconv.Itoa(cdnOriginPort(plan)), nil
}

// CDNOriginInstructions is the deterministic, operator-facing CDN
// origin configuration for the plan (v1: instructions, no provider API
// calls). It names every field the CDN admin must set: origin host +
// port, TLS, path, WebSocket, idle timeout, and the DNS record.
func (p *CDNProvider) CDNOriginInstructions(plan Plan) (string, error) {
	if plan.Mode != ModeCDN {
		return "", fmt.Errorf("origin: CDNOriginInstructions requires cdn mode, got %q", plan.Mode)
	}
	if err := plan.validate(); err != nil {
		return "", err
	}
	port := cdnOriginPort(plan)
	var out string
	switch plan.CDNSecurity {
	case CDNTLSOrigin:
		out = deterministicInstructionsA(plan, port)
	case CDNPlainOrigin:
		out = deterministicInstructionsB(plan, port)
	default:
		return "", fmt.Errorf("%w: cdnSecurity must be tlsOrigin or plainOrigin", ErrInvalidPlan)
	}
	return out, nil
}

// deterministicInstructionsA renders mode A (TLS origin).
func deterministicInstructionsA(plan Plan, port int) string {
	return "CDN origin configuration (mode A: TLS origin)\n" +
		"  Origin host:   " + plan.Domain + "\n" +
		"  Origin port:   " + strconv.Itoa(port) + "\n" +
		"  TLS:           ON (the origin presents a Caddy-internal certificate; the public\n" +
		"                  certificate for " + plan.Domain + " is issued by the CDN's own CA chain)\n" +
		"  Path:          /upload (exact; the WS listener serves only this path)\n" +
		"  WebSocket:     ENABLED (forward Upgrade + Connection headers verbatim)\n" +
		"  Idle timeout:  >= 3600s (the origin idles long-lived carriers; a shorter\n" +
		"                  CDN idle timeout would cut live sessions)\n" +
		"  DNS:           point the CDN's origin-pool entry at the Iran host\n" +
		"                  (A/AAAA record for " + plan.Domain + " → Iran origin IP; the CDN fronts the public name)\n"
}

// deterministicInstructionsB renders mode B (plain origin) with the
// explicit security note.
func deterministicInstructionsB(plan Plan, port int) string {
	return "CDN origin configuration (mode B: plain origin, NO Caddy)\n" +
		"  Origin host:   the Iran server's public address (CDN origin pool entry)\n" +
		"  Origin port:   " + strconv.Itoa(port) + "\n" +
		"  TLS:           OFF on the CDN→origin leg (set the CDN origin protocol to http)\n" +
		"  Path:          /upload (exact; the WS listener serves only this path)\n" +
		"  WebSocket:     ENABLED (forward Upgrade + Connection headers verbatim)\n" +
		"  Idle timeout:  >= 3600s (the origin idles long-lived carriers)\n" +
		"  DNS:           CNAME " + plan.Domain + " → the CDN's public hostname (the CDN fronts the public name)\n" +
		"  SECURITY NOTE: the CDN→origin leg is UNENCRYPTED. Auth v1 still\n" +
		"                  authenticates the carrier (challenge/nonces/keyed MAC), but NO key\n" +
		"                  material may ride this leg in the clear.\n"
}
