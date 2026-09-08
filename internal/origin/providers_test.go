package origin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// providers_test.go — the three providers (design §3.1). Hermetic:
// fake Downloader/Executor, t.TempDir() prefix + config dir.

// wireCore builds a caddyCore with a fake install (a real versioned
// binary written by hand, so ensureInstalled's idempotent path is
// exercised without a download) and a config dir.
func wireCore(t *testing.T) (*caddyCore, string, *fakeExec) {
	t.Helper()
	prefix := t.TempDir()
	dir := t.TempDir()
	verdir, err := VersionDir(prefix, PinnedVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(verdir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(verdir, "caddy")
	if err := os.WriteFile(bin, []byte("FAKE"), 0o755); err != nil {
		t.Fatal(err)
	}
	fe := &fakeExec{versionOut: PinnedVersion + " h1:fakebuildhash"}
	core := &caddyCore{Deps: Deps{Prefix: prefix, Dir: dir, Exec: fe}}
	return core, dir, fe
}

// New() registry.
func TestNewRegistry(t *testing.T) {
	d := Deps{Prefix: t.TempDir(), Dir: t.TempDir()}
	if _, err := New(ModeCaddy, d); err != nil {
		t.Errorf("New(caddy): %v", err)
	}
	if _, err := New(ModeCDN, d); err != nil {
		t.Errorf("New(cdn): %v", err)
	}
	if _, err := New(ModeNone, Deps{}); err != nil {
		t.Errorf("New(none): %v", err)
	}
	if _, err := New("nginx", d); err == nil {
		t.Error("New(nginx) accepted")
	}
}

// caddy.Configure installs-if-missing + activates behind the gate.
func TestCaddyConfigureActivates(t *testing.T) {
	core, dir, fe := wireCore(t)
	p := &CaddyProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCaddy()); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	live := filepath.Join(dir, "Caddyfile")
	b, err := os.ReadFile(live)
	if err != nil {
		t.Fatalf("live missing: %v", err)
	}
	want, _ := RenderCaddyfile(goldenPlanCaddy())
	if string(b) != string(want) {
		t.Errorf("live != rendered")
	}
	// The gate ran.
	found := false
	for _, c := range fe.calls {
		if strings.HasPrefix(c, "validate:") {
			found = true
		}
	}
	if !found {
		t.Errorf("gate not run; calls=%v", fe.calls)
	}
}

// caddy.Configure is idempotent: unchanged plan → byte-no-op (no extra
// gate run, no .prev).
func TestCaddyConfigureIdempotent(t *testing.T) {
	core, dir, fe := wireCore(t)
	p := &CaddyProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCaddy()); err != nil {
		t.Fatal(err)
	}
	gateBefore := countGates(fe)
	live := filepath.Join(dir, "Caddyfile")
	before, _ := os.ReadFile(live)
	if err := p.Configure(context.Background(), goldenPlanCaddy()); err != nil {
		t.Fatal(err)
	}
	// The byte-no-op means NO re-gate (the `version:` smoke from
	// ensureInstalled still runs each Configure — that is expected).
	if got := countGates(fe); got != gateBefore {
		t.Errorf("idempotent re-Configure re-ran the validate gate (%d -> %d); calls=%v", gateBefore, got, fe.calls)
	}
	after, _ := os.ReadFile(live)
	if string(before) != string(after) {
		t.Error("byte-no-op violated")
	}
	if _, err := os.Stat(live + ".prev"); !os.IsNotExist(err) {
		t.Error("prev created on idempotent re-Configure")
	}
}

// caddy.Configure with a CHANGED plan re-activates + backs up.
func TestCaddyConfigureChangedPlanReactivates(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CaddyProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCaddy()); err != nil {
		t.Fatal(err)
	}
	if err := p.Configure(context.Background(), goldenPlanALPN()); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "Caddyfile")
	b, _ := os.ReadFile(live)
	want, _ := RenderCaddyfile(goldenPlanALPN())
	if string(b) != string(want) {
		t.Error("live not re-rendered for the changed plan")
	}
	if _, err := os.Stat(live + ".prev"); err != nil {
		t.Errorf("prev missing after changed plan: %v", err)
	}
}

// caddy.Configure rejects a non-caddy plan.
func TestCaddyConfigureRejectsWrongMode(t *testing.T) {
	core, _, _ := wireCore(t)
	p := &CaddyProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCDN()); !errors.Is(err, ErrInvalidPlan) {
		t.Errorf("want ErrInvalidPlan, got %v", err)
	}
}

// caddy.Status is D8 file-level liveness: binary + version + Caddyfile.
func TestCaddyStatus(t *testing.T) {
	core, _, fe := wireCore(t)
	p := &CaddyProvider{core: core}
	// No Caddyfile yet → not live (file-level), no error.
	h, err := p.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if h.Live || h.Mode != ModeCaddy {
		t.Errorf("Status = %+v, want not-live caddy", h)
	}
	// With a valid Caddyfile → live.
	if err := p.Configure(context.Background(), goldenPlanCaddy()); err != nil {
		t.Fatal(err)
	}
	h, err = p.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !h.Live {
		t.Errorf("Status not live after configure: %+v", h)
	}
	// A validate failure → not live.
	fe.validateErr = errors.New("broken")
	h, _ = p.Status(context.Background())
	if h.Live {
		t.Errorf("Status live despite validate failure")
	}
}

// ensureInstalled trusts an existing binary only if it reports the pin.
func TestEnsureInstalledForeignBinaryRefused(t *testing.T) {
	core, _, fe := wireCore(t)
	fe.versionOut = "v9.9.9 h1:foreign" // foreign version
	if err := core.configure(context.Background(), goldenPlanCaddy()); err == nil {
		t.Fatal("expected ErrVersionMismatch")
	}
}

// cdn mode A: installs Caddy + activates the tls-internal Caddyfile.
func TestCDNModeAConfigures(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "Caddyfile"))
	if err != nil {
		t.Fatalf("live missing: %v", err)
	}
	want, _ := RenderCaddyfile(goldenPlanCDN())
	if string(b) != string(want) {
		t.Error("live != rendered tls-internal Caddyfile")
	}
}

// cdn mode B: no Caddy, no file; SplitterEnv returns the listener env.
func TestCDNModeBNoCaddy(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	planB := Plan{Mode: ModeCDN, Domain: "upload.example.com", CDNSecurity: CDNPlainOrigin, OriginPort: 8443}
	if err := p.Configure(context.Background(), planB); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Caddyfile")); !os.IsNotExist(err) {
		t.Error("mode B wrote a Caddyfile")
	}
	env, err := p.SplitterEnv(planB)
	if err != nil {
		t.Fatalf("SplitterEnv: %v", err)
	}
	if env != "SPLIT_WS_LISTEN=0.0.0.0:8443" {
		t.Errorf("SplitterEnv = %q", env)
	}
	// Status reports the mode B resting state (no Caddy expected).
	h, err := p.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Live {
		t.Errorf("mode B Status should be not-live (no Caddy): %+v", h)
	}
}

// CDNOriginInstructions is deterministic + names the required fields.
func TestCDNOriginInstructions(t *testing.T) {
	core, _, _ := wireCore(t)
	p := &CDNProvider{core: core}
	planA := goldenPlanCDN()
	planB := Plan{Mode: ModeCDN, Domain: "upload.example.com", CDNSecurity: CDNPlainOrigin, OriginPort: 443}
	for name, plan := range map[string]Plan{"A": planA, "B": planB} {
		s1, err := p.CDNOriginInstructions(plan)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		s2, _ := p.CDNOriginInstructions(plan)
		if s1 != s2 {
			t.Errorf("%s: instructions not deterministic", name)
		}
		for _, want := range []string{"/upload", "WebSocket", "3600s", "DNS"} {
			if !strings.Contains(s1, want) {
				t.Errorf("%s: instructions missing %q:\n%s", name, want, s1)
			}
		}
		if name == "B" && !strings.Contains(s1, "UNENCRYPTED") {
			t.Errorf("B: missing the security note:\n%s", s1)
		}
		if name == "A" && !strings.Contains(s1, "TLS origin") {
			t.Errorf("A: missing the TLS-origin marker:\n%s", s1)
		}
	}
	// Non-cdn plan rejected.
	if _, err := p.CDNOriginInstructions(goldenPlanCaddy()); err == nil {
		t.Error("non-cdn plan accepted")
	}
}

// none: Configure validates, DirectWSURL returns the direct ws URL.
func TestNoneProvider(t *testing.T) {
	p := &NoneProvider{}
	plan := Plan{Mode: ModeNone, UpstreamAddr: "127.0.0.1:9001"}
	if err := p.Configure(context.Background(), plan); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	url, err := p.DirectWSURL(plan)
	if err != nil {
		t.Fatal(err)
	}
	if want := "ws://127.0.0.1:9001/upload"; url != want {
		t.Errorf("DirectWSURL = %q, want %q", url, want)
	}
	h, err := p.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Live || h.Mode != ModeNone {
		t.Errorf("Status = %+v", h)
	}
	// Rejects a non-loopback upstream (testing-only).
	if err := p.Configure(context.Background(), Plan{Mode: ModeNone, UpstreamAddr: "8.8.8.8:9001"}); err == nil {
		t.Error("public upstream accepted for none")
	}
}

// countGates counts the validate-gate calls (not the version smoke).
func countGates(fe *fakeExec) int {
	n := 0
	for _, c := range fe.calls {
		if strings.HasPrefix(c, "validate:") {
			n++
		}
	}
	return n
}

// RejectForPublicDeploy: none is testing-only.
func TestNoneRejectForPublicDeploy(t *testing.T) {
	p := &NoneProvider{}
	if err := p.RejectForPublicDeploy("upload.example.com"); err == nil {
		t.Fatal("expected rejection for a public domain")
	}
	if err := p.RejectForPublicDeploy(""); err == nil {
		t.Fatal("expected rejection with no domain")
	}
}
