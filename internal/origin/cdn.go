package origin

// cdn.go — the `cdn` provider: the operator's CDN fronts the origin
// (doc §5.1). Two sub-modes (CDNSecurity):
//
//   - A (CDNTLSOrigin): the CDN talks to the origin over TLS; the
//     origin runs the pinned Caddy with `tls internal` (Caddy's private
//     issuer — the CDN supplies the public certificate). Configure
//     installs Caddy + activates the §2.3.3 Caddyfile (reuses the
//     shared caddyCore — no duplicate install/activate logic) and
//     persists the desired submode in a small project-owned state file.
//     Mode A REQUIRES Plan.CDNOriginTrust (decision D9): a Caddy-
//     internal certificate is NOT automatically trusted by a generic
//     CDN, so the trust contract must be declared explicitly and mode A
//     fails closed when it is not.
//   - B (CDNPlainOrigin): the CDN talks to the origin in the clear;
//     NO Caddy, NO Caddyfile. Configure DEACTIVATES a project-managed
//     Caddyfile (exact-marker ownership check, transactional with
//     rollback metadata) and refuses to touch an operator-owned file
//     (review HIGH-5); it never deletes state it does not own.
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
	"strings"
	"sync/atomic"
)

// cdnStateFileName is the project-owned desired-submode record inside
// the config dir (HIGH-5: the desired CDN submode is EXPLICIT state,
// not inferred from whether a Caddyfile happens to exist). The file is
// a single line: "mode=<tlsOrigin|plainOrigin>". It is written only for
// cdn plans; the caddy/none providers do not create it.
const cdnStateFileName = "cdn-origin.state"

// CDNProvider is the `cdn` origin provider.
type CDNProvider struct{ core *caddyCore }

// Configure implements OriginProvider (cdn mode A or B). It converges
// the origin to the selected sub-mode and records the desired sub-mode
// so Status reports the SELECTION, not file-existence (HIGH-5). A
// canceled ctx aborts before any mutation (HIGH-2).
func (p *CDNProvider) Configure(ctx context.Context, plan Plan) error {
	if plan.Mode != ModeCDN {
		return fmt.Errorf("%w: cdn provider requires mode cdn, got %q", ErrInvalidPlan, plan.Mode)
	}
	// Validate FIRST (fail closed): mode A additionally requires the
	// explicit origin-trust declaration (D9).
	if err := plan.validate(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if plan.CDNSecurity == CDNPlainOrigin {
		// Mode B: deactivate any MANAGED Caddy state (transactional,
		// ownership-checked), then persist the desired sub-mode. Never
		// deletes an operator-owned file (ErrUnmanagedState).
		if err := p.core.deactivateManagedCaddyfile(ctx); err != nil {
			return err
		}
		return p.core.writeCDNState(ctx, CDNPlainOrigin)
	}
	// Mode A: TLS origin — install Caddy + activate the tls-internal
	// Caddyfile (shared core), then persist the desired sub-mode.
	if err := p.core.configure(ctx, plan); err != nil {
		return err
	}
	return p.core.writeCDNState(ctx, CDNTLSOrigin)
}

// Status implements OriginProvider. It reports the SELECTED sub-mode
// from the persisted state record (HIGH-5) rather than inferring it
// from whether a Caddyfile happens to exist:
//   - state=tlsOrigin (A): the D8 file-level check (Caddy binary +
//     tls-internal Caddyfile present and valid);
//   - state=plainOrigin (B): the mode B SELECTED resting state (no
//     Caddy expected). This package performs FILE-level health only
//     (D8): mode B has no origin file to check, and it has NOT
//     observed the splitter listener, service, or CDN, so it reports
//     Live=false with an explicit "selected, liveness unverified by
//     this provider" detail — runtime liveness belongs to the T7
//     deploy/doctor health probe, not to a file-existence inference
//     (review MEDIUM-R2-2);
//   - no state record: unconfigured (legacy / fresh) — falls back to a
//     file-presence hint so a pre-state-file deployment still reports
//     something meaningful;
//   - corrupt/unreadable state record: a state-integrity ERROR is
//     returned (never merged into the no-record hint, which would
//     mislead the operator into a fresh Configure on a damaged
//     deployment) (review MEDIUM-R2-3).
func (p *CDNProvider) Status(ctx context.Context) (Health, error) {
	h := Health{Mode: ModeCDN}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return h, err
	}
	state, serr := p.core.readCDNState()
	switch {
	case serr == nil && state == CDNTLSOrigin:
		return p.core.fileStatus(ctx, ModeCDN)
	case serr == nil && state == CDNPlainOrigin:
		// Selected, converged, but NOT probed: no liveness claim
		// (MEDIUM-R2-2).
		h.Live = false
		h.Detail = "cdn mode B (plainOrigin) SELECTED — no Caddy on the origin; the splitter's own public listener serves the CDN (the CDN→origin leg is unencrypted). Liveness is not verified by this provider (T7 doctor owns runtime checks)"
		return h, nil
	case os.IsNotExist(serr):
		// No state record (legacy deployment or never configured):
		// report the file-level hint so the operator sees the actual
		// disk state.
		live := filepath.Join(p.core.Dir, p.core.fileName())
		if st, err := os.Lstat(live); err != nil || !st.Mode().IsRegular() {
			h.Live = false
			h.Detail = "no cdn state record and no Caddyfile at " + live + " (not configured — run Configure)"
			return h, nil
		}
		return p.core.fileStatus(ctx, ModeCDN)
	default:
		// Corrupt or unreadable record: fail closed with the
		// state-integrity error (MEDIUM-R2-3).
		return h, serr
	}
}

// ---------------------------------------------------------------------------
// CDN desired-submode state record (project-owned; coordinates with the
// T7 manifest rather than duplicating it — see writeCDNState).
// ---------------------------------------------------------------------------

func (c *caddyCore) cdnStatePath() string {
	return filepath.Join(c.Dir, cdnStateFileName)
}

// writeCDNState persists the desired CDN sub-mode (0600, tmp+rename).
// It is intentionally a MINIMAL record, not a second manifest: the
// authoritative deployment manifest is internal/deploy (T7), which can
// consume this field; this package only needs the sub-mode to converge
// and to answer Status honestly between Configure calls.
func (c *caddyCore) writeCDNState(ctx context.Context, sec CDNSecurity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	body := []byte("mode=" + string(sec) + "\n")
	if err := writeFile0600(c.cdnStatePath(), body); err != nil {
		return fmt.Errorf("origin: cannot record cdn sub-mode: %w", err)
	}
	return nil
}

// readCDNState reads the desired CDN sub-mode record. os.IsNotExist is
// returned unwrapped for the legacy/no-record case.
func (c *caddyCore) readCDNState() (CDNSecurity, error) {
	b, err := os.ReadFile(c.cdnStatePath())
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	switch s {
	case "mode=" + string(CDNTLSOrigin):
		return CDNTLSOrigin, nil
	case "mode=" + string(CDNPlainOrigin):
		return CDNPlainOrigin, nil
	}
	return "", fmt.Errorf("origin: cdn state record is corrupt (not a recognized mode)")
}

// ---------------------------------------------------------------------------
// Managed-Caddyfile deactivation (A → B transition, review HIGH-5)
// ---------------------------------------------------------------------------

// deactivateManagedCaddyfile removes the activated Caddyfile ONLY when
// it carries the exact project-managed marker, transactionally and with
// rollback metadata:
//
//   - no Caddyfile           → no-op (converged);
//   - Caddyfile WITHOUT the marker → ErrUnmanagedState (operator-owned;
//     NEVER deleted);
//   - symlink / special      → ErrActivateTarget (planted object);
//   - managed Caddyfile      → the file + its .prev rollback artifact
//     are moved aside into a timestamped transaction dir
//     (.cdn-deactivate-<unixnano>/) inside the config dir, then the
//     live path is clear. The aside dir is the rollback metadata: the
//     bytes are preserved, not destroyed.
//
// A canceled ctx aborts before any move (HIGH-2). The Caddy BINARY is
// intentionally left installed (the version dir is shared with caddy
// mode and removing it is a separate, explicit operation).
func (c *caddyCore) deactivateManagedCaddyfile(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	live := filepath.Join(c.Dir, c.fileName())
	st, err := os.Lstat(live)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already converged (no Caddyfile)
		}
		return fmt.Errorf("origin: cannot stat Caddyfile: %w", err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is a symlink or special file", ErrActivateTarget, live)
	}
	b, err := os.ReadFile(live)
	if err != nil {
		return fmt.Errorf("origin: cannot read Caddyfile: %w", err)
	}
	// Ownership is fail-closed: only a file whose FIRST line is the
	// exact managed marker is ours to deactivate.
	firstLine, _, _ := strings.Cut(string(b), "\n")
	if firstLine != managedMarker {
		return fmt.Errorf("%w: %s does not carry the project managed marker (operator-owned file, not deactivated)", ErrUnmanagedState, live)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Transactional move-aside (rollback metadata): live + .prev go
	// into a fresh aside dir. If the live move fails, whatever was
	// moved is moved back so the directory is left as found.
	aside, err := allocateDeactivateDir(c)
	if err != nil {
		return err
	}
	rename := c.Rename
	if rename == nil {
		rename = os.Rename
	}
	movedLive := false
	movedPrev := false
	rollback := func() {
		if movedPrev {
			_ = rename(filepath.Join(aside, c.fileName()+".prev"), live+".prev")
		}
		if movedLive {
			_ = rename(filepath.Join(aside, c.fileName()), live)
		}
		_ = os.Remove(aside)
	}
	if err := rename(live, filepath.Join(aside, c.fileName())); err != nil {
		_ = os.Remove(aside)
		return fmt.Errorf("origin: cannot deactivate managed Caddyfile: %w", err)
	}
	movedLive = true
	if _, err := os.Lstat(live + ".prev"); err == nil {
		st2, err := os.Lstat(live + ".prev")
		if err == nil {
			if !st2.Mode().IsRegular() {
				rollback()
				return fmt.Errorf("%w: %s is a symlink or special file", ErrActivateTarget, live+".prev")
			}
			if err := rename(live+".prev", filepath.Join(aside, c.fileName()+".prev")); err != nil {
				rollback()
				return fmt.Errorf("origin: cannot move rollback artifact aside: %w", err)
			}
			movedPrev = true
		}
	}
	// Converged: the aside dir keeps the bytes as rollback metadata.
	return nil
}

// allocateDeactivateDir picks a fresh .cdn-deactivate-<n> name inside
// the config dir. The counter is a starting hint only; because it
// resets on every process start, an EXISTING aside dir (rollback
// metadata preserved from a prior run) would otherwise collide with
// os.Mkdir's EEXIST and permanently block the A → B convergence after
// a restart (review MEDIUM-R2-1). Each candidate is Lstat-checked:
// absent → claim it; an empty regular directory is a stale residue of
// a crashed deactivation and is replaced; any non-empty or unsafe
// object is skipped and the search continues.
func allocateDeactivateDir(c *caddyCore) (string, error) {
	for i := 0; i < 1024; i++ {
		n := deactivationCounter.Add(1)
		candidate := filepath.Join(c.Dir, ".cdn-deactivate-"+strconv.FormatInt(n, 10))
		st, err := os.Lstat(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				if err := os.Mkdir(candidate, 0o700); err != nil {
					return "", fmt.Errorf("origin: cannot create deactivation dir: %w", err)
				}
				return candidate, nil
			}
			return "", fmt.Errorf("origin: cannot inspect deactivation dir %s: %w", candidate, err)
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			// Planted object at the name: skip, do not touch.
			continue
		}
		// An empty regular dir is residue of a crashed deactivation
		// (nothing was ever moved in): safe to reclaim. Non-empty
		// dirs hold rollback metadata and are NEVER touched.
		entries, rerr := os.ReadDir(candidate)
		if rerr != nil {
			return "", fmt.Errorf("origin: cannot inspect deactivation residue %s: %w", candidate, rerr)
		}
		if len(entries) == 0 {
			if err := os.Remove(candidate); err != nil {
				return "", fmt.Errorf("origin: cannot reclaim empty deactivation residue %s: %w", candidate, err)
			}
			if err := os.Mkdir(candidate, 0o700); err != nil {
				return "", fmt.Errorf("origin: cannot create deactivation dir: %w", err)
			}
			return candidate, nil
		}
	}
	return "", fmt.Errorf("origin: cannot allocate a free deactivation dir name (too many existing rollback dirs)")
}

var deactivationCounter atomic.Int64

// ---------------------------------------------------------------------------
// Operator-facing instructions (deterministic, no provider API calls)
// ---------------------------------------------------------------------------

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
// port, TLS, path, WebSocket, idle timeout, the DNS record, and — for
// mode A — the DECLARED origin-certificate trust contract (D9). It
// never implies a Caddy-internal certificate is automatically trusted
// by a generic CDN.
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

// deterministicInstructionsA renders mode A (TLS origin) with the
// explicit, DECLARED trust contract (D9). Mode A plans are validated
// fail-closed before this runs, so plan.CDNOriginTrust is always one of
// the two declared contracts here.
func deterministicInstructionsA(plan Plan, port int) string {
	base := "CDN origin configuration (mode A: TLS origin)\n" +
		"  Origin host:   " + plan.Domain + "\n" +
		"  Origin port:   " + strconv.Itoa(port) + "\n" +
		"  TLS:           ON. IMPORTANT (origin certificate trust): the origin presents a\n" +
		"                 certificate rooted in CADDY'S PRIVATE (local) CA. A generic CDN in\n" +
		"                 strict origin-verification mode does NOT trust it automatically.\n" +
		"                 The public certificate for " + plan.Domain + " is issued by the CDN's\n" +
		"                 own chain — that is the USER-facing cert, NOT the origin cert.\n"
	var trust string
	switch plan.CDNOriginTrust {
	case CDNOriginTrustPullCA:
		trust = "  Trust model:   AUTHENTICATED private-CA origin TLS (declared: pullCA).\n" +
			"                 Export the Caddy local ROOT CA CERTIFICATE (public half only):\n" +
			"                   " + CaddyRootCACertPathHint + "\n" +
			"                 after the first Caddy run, and install it into the CDN's\n" +
			"                 custom-trust / authenticated-origin config (e.g. Cloudflare\n" +
			"                 'Authenticated Origin Pulls' with an uploaded CA, or the\n" +
			"                 provider's equivalent). The CA PRIVATE key never leaves the host\n" +
			"                 (Caddy storage; this package never reads it). REQUIRED CDN\n" +
			"                 capability: custom origin CA trust. If the CDN lacks it, use the\n" +
			"                 unauthenticatedTLS declaration or cdn mode B.\n"
	case CDNOriginTrustUnauthenticated:
		trust = "  Trust model:   ENCRYPTED but NON-AUTHENTICATED origin TLS (declared:\n" +
			"                 unauthenticatedTLS). Set the CDN origin pull to a mode that ACCEPTS\n" +
			"                 ANY certificate ('TLS, no origin verification' / 'Full (not strict)').\n" +
			"                 The CDN does NOT authenticate the origin certificate: the\n" +
			"                 CDN→origin leg is encrypted against PASSIVE observers, but an\n" +
			"                 ACTIVE MITM between the CDN and the origin can present its own\n" +
			"                 certificate. You acknowledged this by declaring unauthenticatedTLS.\n"
	}
	tail := "  Path:          /upload (exact; the WS listener serves only this path)\n" +
		"  WebSocket:     ENABLED (forward Upgrade + Connection headers verbatim)\n" +
		"  Idle timeout:  >= 3600s (the origin idles long-lived carriers; a shorter\n" +
		"                  CDN idle timeout would cut live sessions)\n" +
		"  DNS:           point the CDN's origin-pool entry at the Iran host\n" +
		"                  (A/AAAA record for " + plan.Domain + " → Iran origin IP; the CDN fronts the public name)\n"
	return base + trust + tail
}

// CaddyRootCACertPathHint is the operator-facing hint for where Caddy's
// internal root CA CERTIFICATE lives after the first run (public half
// only — never the key). The path is Caddy's conventional storage
// location; it is a hint, not a file this package reads.
const CaddyRootCACertPathHint = "<caddy-storage>/pki/authorities/local/root.crt (typically /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt)"

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
