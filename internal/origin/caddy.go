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
// pinned binary skips the download entirely (design §3.2/§3.5).
func (c *caddyCore) configure(ctx context.Context, plan Plan) error {
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
	_, aerr := ActivateCaddyfile(ActivateParams{
		Plan:     plan,
		Dir:      c.Dir,
		FileName: c.fileName(),
		Bin:      bin,
		Exec:     c.exec(),
	})
	return aerr
}

// ensureInstalled returns the path of the pinned binary, installing it
// if missing (idempotent: an existing version dir that passes the
// smoke check is reused — no download on re-Configure).
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
		// Idempotence: reuse the installed binary, but only if it is
		// actually the pinned version (a poisoned or foreign binary
		// must not be trusted).
		if out, verr := exec.VersionOutput(bin); verr == nil && firstField(out) == PinnedVersion {
			return bin, nil
		}
		return "", fmt.Errorf("%w: %s does not report %s (remove it or reinstall with Force)", ErrVersionMismatch, bin, PinnedVersion)
	}
	// Not installed: run the full install pipeline. The install's own
	// config gate (step 8) is NOT used here (testConfig=""): the
	// Caddyfile gate is the activation's job (activate.go step 3), so
	// validation is performed exactly once, against the live path.
	ins := &Installer{Prefix: c.Prefix, DL: c.DL, Exec: exec, Chmod: c.Chmod}
	if _, err := ins.Install(PinnedVersion, arch, ""); err != nil {
		return "", err
	}
	return bin, nil
}

// fileStatus is the shared D8 file-level liveness check: binary present
// at the versioned path + version == pinned + Caddyfile present and
// `caddy validate` passes. No systemd probe (T5), no sockets — safe
// pre-service-start and in tests without root.
func (c *caddyCore) fileStatus(mode Mode) (Health, error) {
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
	out, err := c.exec().VersionOutput(bin)
	if err != nil || firstField(out) != PinnedVersion {
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
	if out, err := c.exec().Validate(bin, live); err != nil {
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
	return p.core.fileStatus(ModeCaddy)
}
