package origin

// caddy.go — the `caddy` provider + the shared Caddy core (install-if-
// missing + transactional Caddyfile activation) that the `cdn` mode A
// provider reuses (design: no duplicate install/activate
// implementations).

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// Deps is the constructor input for the providers that need Caddy
// (caddy + cdn mode A). Prefix is the install prefix (e.g.
// /opt/split-tunnel → <prefix>/caddy/<version>/caddy); Dir is the
// project config directory the Caddyfile is activated into (T5:
// /etc/split-tunnel, 0700 — T4 never creates it).
type Deps struct {
	Prefix   string
	Dir      string
	FileName string // default "Caddyfile"
	DL       Downloader
	Exec     Executor
	Chmod    func(path string, mode os.FileMode) error
	// Rename is the activation/exchange seam (default os.Rename),
	// threaded into ActivateCaddyfile and Installer for deterministic
	// failure injection in tests (review HIGH-1/HIGH-3).
	Rename func(oldpath, newpath string) error
}

// New is the provider registry (doc §5.1). It validates the mode and
// returns the matching provider. The `none` provider needs no deps.
func New(m Mode, d Deps) (OriginProvider, error) {
	switch m {
	case ModeCaddy:
		return &CaddyProvider{core: newCaddyCore(d)}, nil
	case ModeCDN:
		return &CDNProvider{core: newCaddyCore(d)}, nil
	case ModeNone:
		return &NoneProvider{}, nil
	default:
		return nil, fmt.Errorf("origin: unknown mode %q (want caddy, cdn, or none)", m)
	}
}

// caddyCore is the shared engine behind the `caddy` provider and the
// `cdn` mode A (TLS origin) provider: ensure the pinned binary is
// installed (idempotent), then render + activate the Caddyfile behind
// the `caddy validate` gate. Keeping it in ONE place is the
// anti-duplication guarantee (project rule).
type caddyCore struct {
	Deps
}

func newCaddyCore(d Deps) *caddyCore { return &caddyCore{Deps: d} }

func (c *caddyCore) exec() Executor {
	if c.Exec != nil {
		return c.Exec
	}
	return OSExecutor{}
}

func (c *caddyCore) fileName() string {
	if c.FileName != "" {
		return c.FileName
	}
	return defaultCaddyFileName
}

// configure runs the provider flow: (install-if-missing) → (render +
// activate behind the validate gate). Idempotent: an unchanged plan is
// a byte-no-op (marker + content compare), and an already-installed
// pinned binary skips the download entirely (design §3.2/§3.5). The ctx
// bounds every external action (HIGH-2) and is checked before the
// activation begins a new mutation.
func (c *caddyCore) configure(ctx context.Context, plan Plan) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := plan.validate(); err != nil {
		return err
	}
	// Cancellation must abort before ANY mutation (install or
	// activation) begins (HIGH-2).
	if err := ctx.Err(); err != nil {
		return err
	}
	bin, err := c.ensureInstalled(ctx)
	if err != nil {
		return err
	}
	want, err := RenderCaddyfile(plan)
	if err != nil {
		return err
	}
	live := filepath.Join(c.Dir, c.fileName())
	// Idempotence: identical bytes already live → byte-no-op (no write,
	// no .prev churn, no re-gate).
	if b, rerr := os.ReadFile(live); rerr == nil && bytes.Equal(b, want) {
		return nil
	}
	// Cancellation must abort before the activation transaction begins
	// (the idempotence read above is read-only).
	if err := ctx.Err(); err != nil {
		return err
	}
	_, aerr := ActivateCaddyfile(ActivateParams{
		Plan:     plan,
		Dir:      c.Dir,
		FileName: c.fileName(),
		Bin:      bin,
		Exec:     c.exec(),
		Rename:   c.Rename,
		Ctx:      ctx,
	})
	return aerr
}

// ensureInstalled returns the path of the pinned binary, installing it
// if missing (idempotent: an existing version dir whose FIRST-FIELD
// version matches the pin is reused — no download on re-Configure).
//
// Integrity note (review MEDIUM-1): the reuse check is a VERSION check,
// not an integrity proof — `caddy version` is a forgeable self-report.
// This package deliberately does NOT persist a per-binary SHA-512
// manifest of its own: internal/deploy (T7) is the authoritative
// manifest owner, and drift detection of an already-installed binary is
// the doctor/manifest job. Callers that need a hard integrity gate must
// verify the binary against the deployment manifest before calling
// Configure. Do not read "reused" as "verified unmodified".
func (c *caddyCore) ensureInstalled(ctx context.Context) (string, error) {
	if c.Prefix == "" {
		return "", fmt.Errorf("origin: empty install prefix")
	}
	if c.Dir == "" {
		return "", fmt.Errorf("origin: empty config dir")
	}
	arch, err := DefaultArch()
	if err != nil {
		return "", err
	}
	verdir, err := VersionDir(c.Prefix, PinnedVersion)
	if err != nil {
		return "", err
	}
	bin := filepath.Join(verdir, "caddy")
	exec := c.exec()
	if _, serr := os.Stat(bin); serr == nil {
		// Idempotence: reuse the installed binary, but only if it
		// reports the pinned version (a FOREIGN binary must not be
		// trusted). Cancellation of a wedged `caddy version` is honored
		// via the executor ctx (HIGH-2).
		out, verr := exec.VersionOutput(ctx, bin)
		if verr != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", fmt.Errorf("%w: %s does not report %s (remove it or reinstall with Force)", ErrVersionMismatch, bin, PinnedVersion)
		}
		if firstField(out) == PinnedVersion {
			return bin, nil
		}
		return "", fmt.Errorf("%w: %s does not report %s (remove it or reinstall with Force)", ErrVersionMismatch, bin, PinnedVersion)
	}
	// Not installed: run the full install pipeline. The install's own
	// config gate is NOT used here (testConfig=""): the Caddyfile gate
	// is the activation's job (activate.go), so validation is performed
	// exactly once, against the live path.
	ins := &Installer{Prefix: c.Prefix, DL: c.DL, Exec: exec, Chmod: c.Chmod, Rename: c.Rename}
	if _, err := ins.Install(ctx, PinnedVersion, arch, ""); err != nil {
		return "", err
	}
	return bin, nil
}

// fileStatus is the shared D8 file-level liveness check: binary present
// at the versioned path + version == pinned + Caddyfile present and
// `caddy validate` passes. No systemd probe (T5), no sockets — safe
// pre-service-start and in tests without root. A canceled ctx is
// honored before each binary invocation (HIGH-2).
func (c *caddyCore) fileStatus(ctx context.Context, mode Mode) (Health, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	h := Health{Mode: mode}
	verdir, err := VersionDir(c.Prefix, PinnedVersion)
	if err != nil {
		return h, err
	}
	bin := filepath.Join(verdir, "caddy")
	if _, err := os.Stat(bin); err != nil {
		h.Live = false
		h.Detail = "caddy binary not installed at " + bin
		return h, nil
	}
	if err := ctx.Err(); err != nil {
		return h, err
	}
	out, err := c.exec().VersionOutput(ctx, bin)
	if err != nil {
		if ctx.Err() != nil {
			return h, ctx.Err()
		}
		h.Live = false
		h.Detail = "caddy binary version does not match the pin " + PinnedVersion
		return h, nil
	}
	if firstField(out) != PinnedVersion {
		h.Live = false
		h.Detail = "caddy binary version does not match the pin " + PinnedVersion
		return h, nil
	}
	live := filepath.Join(c.Dir, c.fileName())
	if st, err := os.Lstat(live); err != nil || !st.Mode().IsRegular() {
		h.Live = false
		h.Detail = "Caddyfile not present at " + live
		return h, nil
	}
	if err := ctx.Err(); err != nil {
		return h, err
	}
	if out, err := c.exec().Validate(ctx, bin, live); err != nil {
		if ctx.Err() != nil {
			return h, ctx.Err()
		}
		h.Live = false
		h.Detail = "caddy validate failed on " + live + ": " + excerpt(out)
		return h, nil
	}
	h.Live = true
	h.Detail = "caddy " + PinnedVersion + " installed; Caddyfile present and valid"
	return h, nil
}

// ---------------------------------------------------------------------------
// caddy provider
// ---------------------------------------------------------------------------

// CaddyProvider fronts the local WS listener with the pinned Caddy
// (ACME TLS) — the default production origin.
type CaddyProvider struct{ core *caddyCore }

// Configure implements OriginProvider (caddy mode).
func (p *CaddyProvider) Configure(ctx context.Context, plan Plan) error {
	if plan.Mode != ModeCaddy {
		return fmt.Errorf("%w: caddy provider requires mode caddy, got %q", ErrInvalidPlan, plan.Mode)
	}
	return p.core.configure(ctx, plan)
}

// Status implements OriginProvider (D8 file-level liveness).
func (p *CaddyProvider) Status(ctx context.Context) (Health, error) {
	return p.core.fileStatus(ctx, ModeCaddy)
}
