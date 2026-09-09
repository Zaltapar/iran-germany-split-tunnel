package origin

// cdn_transition_test.go — review HIGH-5: CDN sub-mode transitions must
// CONVERGE. A → B removes ONLY a project-managed Caddyfile (exact-marker
// ownership), transactionally, with rollback metadata, and never deletes
// an operator-owned file. B → A re-installs + re-activates. Status
// reports the SELECTED sub-mode, not file existence.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func planB() Plan {
	return Plan{Mode: ModeCDN, Domain: "upload.example.com", CDNSecurity: CDNPlainOrigin, OriginPort: 8443}
}

// A → B: the managed Caddyfile is deactivated (moved aside with rollback
// metadata) and Status reports plainOrigin.
func TestCDNTransitionAtoBConverges(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatalf("configure A: %v", err)
	}
	live := filepath.Join(dir, "Caddyfile")
	if _, err := os.Lstat(live); err != nil {
		t.Fatalf("A did not leave a Caddyfile: %v", err)
	}
	// A → B.
	if err := p.Configure(context.Background(), planB()); err != nil {
		t.Fatalf("configure B: %v", err)
	}
	if _, err := os.Lstat(live); !os.IsNotExist(err) {
		t.Errorf("managed Caddyfile still live after A→B")
	}
	// The bytes were moved aside (rollback metadata preserved), not
	// destroyed.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	aside := ""
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), ".cdn-deactivate-") {
			aside = filepath.Join(dir, e.Name())
		}
	}
	if aside == "" {
		t.Fatalf("no deactivation rollback dir in %v", entries)
	}
	if b, err := os.ReadFile(filepath.Join(aside, "Caddyfile")); err != nil || !strings.HasPrefix(string(b), managedMarker) {
		t.Errorf("deactivated Caddyfile bytes not preserved: %v", err)
	}
	// Status reports the SELECTED sub-mode honestly (MEDIUM-R2-2): it
	// names plainOrigin but does not claim liveness (no probe here).
	h, err := p.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Live || !strings.Contains(h.Detail, "plainOrigin") {
		t.Errorf("A→B Status should report selected plainOrigin without liveness: %+v", h)
	}
}

// B → A: Caddy is installed and the tls-internal Caddyfile is activated
// again; Status reports the file-level A health.
func TestCDNTransitionBtoAConverges(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	if err := p.Configure(context.Background(), planB()); err != nil {
		t.Fatalf("configure B: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "Caddyfile")); !os.IsNotExist(err) {
		t.Fatalf("B wrote a Caddyfile")
	}
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatalf("configure A: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "Caddyfile"))
	if err != nil {
		t.Fatalf("A did not activate a Caddyfile: %v", err)
	}
	want, _ := RenderCaddyfile(goldenPlanCDN())
	if string(b) != string(want) {
		t.Errorf("B→A live Caddyfile != tls-internal render")
	}
	h, err := p.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !h.Live {
		t.Errorf("B→A Status should report the live mode A state: %+v", h)
	}
}

// A → B → A converges (full round trip) and is repeatable.
func TestCDNTransitionRoundTrip(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	live := filepath.Join(dir, "Caddyfile")
	for i := 0; i < 2; i++ {
		if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
			t.Fatalf("iter %d configure A: %v", i, err)
		}
		if _, err := os.Lstat(live); err != nil {
			t.Fatalf("iter %d A: no Caddyfile: %v", i, err)
		}
		if err := p.Configure(context.Background(), planB()); err != nil {
			t.Fatalf("iter %d configure B: %v", i, err)
		}
		if _, err := os.Lstat(live); !os.IsNotExist(err) {
			t.Fatalf("iter %d B: Caddyfile still live", i)
		}
	}
}

// Repeated application of the SAME sub-mode is a byte-no-op
// (idempotent): A → A does not churn the Caddyfile, B → B does not
// create a second deactivation dir.
func TestCDNTransitionIdempotent(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "Caddyfile")
	before, _ := os.ReadFile(live)
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(live)
	if string(before) != string(after) {
		t.Errorf("A→A not a byte-no-op")
	}
	if err := p.Configure(context.Background(), planB()); err != nil {
		t.Fatal(err)
	}
	entries1, _ := os.ReadDir(dir)
	if err := p.Configure(context.Background(), planB()); err != nil {
		t.Fatal(err)
	}
	entries2, _ := os.ReadDir(dir)
	if len(entries1) != len(entries2) {
		t.Errorf("B→B created new residue: %d → %d entries", len(entries1), len(entries2))
	}
}

// An operator-owned Caddyfile (no managed marker) is NEVER deleted by
// the A → B transition.
func TestCDNTransitionRefusesUnmanagedFile(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	live := filepath.Join(dir, "Caddyfile")
	operator := "# my own caddy config\nexample.com {\n\trespond ok\n}\n"
	if err := os.WriteFile(live, []byte(operator), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Configure(context.Background(), planB()); !errors.Is(err, ErrUnmanagedState) {
		t.Fatalf("want ErrUnmanagedState, got %v", err)
	}
	b, err := os.ReadFile(live)
	if err != nil || string(b) != operator {
		t.Errorf("operator-owned Caddyfile disturbed: %v", err)
	}
}

// A symlinked Caddyfile is refused by the deactivation (planted object).
func TestCDNTransitionRefusesSymlinkLive(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	live := filepath.Join(dir, "Caddyfile")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), live); err != nil {
		t.Skip("symlinks not available: " + err.Error())
	}
	if err := p.Configure(context.Background(), planB()); !errors.Is(err, ErrActivateTarget) {
		t.Fatalf("want ErrActivateTarget, got %v", err)
	}
}

// A canceled ctx aborts the A → B transition before any move.
func TestCDNTransitionCanceled(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "Caddyfile")
	before, _ := os.ReadFile(live)
	if err := p.Configure(canceledCtx(), planB()); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	after, _ := os.ReadFile(live)
	if string(before) != string(after) {
		t.Errorf("Caddyfile changed under a canceled transition")
	}
}

// A failure DURING the deactivation (the live move fails) leaves the
// directory exactly as found (rollback).
func TestCDNTransitionFailureRollback(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "Caddyfile")
	before := dirSnapshot(t, dir)
	// Inject a failing Rename into the core (the deactivation seam).
	core.Rename = func(oldpath, newpath string) error {
		if oldpath == live {
			return errors.New("forced deactivate move failure")
		}
		return os.Rename(oldpath, newpath)
	}
	if err := p.Configure(context.Background(), planB()); err == nil {
		t.Fatal("expected the injected deactivation failure")
	}
	// The Caddyfile is still live and byte-identical; no residue.
	assertSnapshotEqual(t, dir, before)
	if _, err := os.Lstat(live); err != nil {
		t.Errorf("Caddyfile lost after the failed deactivation: %v", err)
	}
	// No aside dir left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".cdn-deactivate-") {
			t.Errorf("deactivation residue left behind: %s", e.Name())
		}
	}
}

// Status falls back to the file-level hint when no state record exists
// (legacy deployment), and honors a canceled ctx.
func TestCDNStatusNoStateRecord(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	// Fresh dir: no state record, no Caddyfile.
	h, err := p.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Live {
		t.Errorf("unconfigured Status should be not-live: %+v", h)
	}
	if !strings.Contains(h.Detail, "no cdn state record") {
		t.Errorf("unconfigured Status detail should name the missing state record: %+v", h)
	}
	// A Caddyfile without a state record (legacy A) → file-level check.
	if _, err := ActivateCaddyfile(ActivateParams{Plan: goldenPlanCDN(), Dir: dir, Bin: "/fake/caddy", Exec: &fakeExec{}}); err != nil {
		t.Fatal(err)
	}
	h, err = p.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !h.Live {
		t.Errorf("legacy A Status should be live: %+v", h)
	}
}

// A state record survives a canceled Status call unchanged.
func TestCDNStatusCanceledCtx(t *testing.T) {
	core, _, _ := wireCore(t)
	p := &CDNProvider{core: core}
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Status(canceledCtx()); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// The state file is project-owned and written 0600 (POSIX-only perm
// assertion; Windows has no user-readable POSIX mode bits).
func TestCDNStateFilePerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not meaningful on Windows")
	}
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	if err := p.Configure(context.Background(), planB()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(filepath.Join(dir, cdnStateFileName))
	if err != nil {
		t.Fatalf("state record missing: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("state record perms = %o, want 0600", st.Mode().Perm())
	}
}

// MEDIUM-R2-2 (part 2): a canceled ctx is reported for the mode B
// Status path exactly as for every other Status path — the selection
// detail must not be returned once the caller has aborted.
func TestCDNStatusModeBCanceledCtx(t *testing.T) {
	core, _, _ := wireCore(t)
	p := &CDNProvider{core: core}
	if err := p.Configure(context.Background(), planB()); err != nil {
		t.Fatalf("configure B: %v", err)
	}
	if _, err := p.Status(canceledCtx()); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled from mode B Status, got %v", err)
	}
}

// MEDIUM-R2-3: a corrupt desired-sub-mode record is a state-integrity
// ERROR. It must never be merged into the no-record hint (which would
// send the operator into a fresh Configure on a damaged deployment),
// whether or not a Caddyfile is also on disk.
func TestCDNStatusCorruptStateFailsClosed(t *testing.T) {
	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	// Subcase 1: corrupt record + a live managed Caddyfile (legacy A on
	// disk). The old fallback would have reported the file-level state
	// (Live); the record is authoritative and damaged → fail closed.
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatalf("configure A: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, cdnStateFileName), []byte("mode=bogus\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Status(context.Background()); err == nil {
		t.Fatal("corrupt state record accepted (no error)")
	} else if !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt state must report the state-integrity error, got %v", err)
	}
	// Subcase 2: corrupt record + no Caddyfile. The old code merged this
	// into the "no cdn state record" hint; it must not.
	if err := os.Remove(filepath.Join(dir, "Caddyfile")); err != nil {
		t.Fatal(err)
	}
	_, err := p.Status(context.Background())
	if err == nil {
		t.Fatal("corrupt state record accepted (no error)")
	}
	if strings.Contains(err.Error(), "no cdn state record") {
		t.Fatalf("corrupt record misreported as unconfigured: %v", err)
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt state must report the state-integrity error, got %v", err)
	}
}

// MEDIUM-R2-1: the deactivation counter is a per-process hint that
// resets to zero on every start. After a restart, aside dirs preserved
// from the previous run must not block A → B convergence: a NON-EMPTY
// preserved aside (rollback metadata) is skipped and left byte-identical,
// and the new deactivation takes a different name.
func TestCDNDeactivateRestartCollision(t *testing.T) {
	// Simulate a fresh process: the counter is back at zero.
	deactivationCounter.Store(0)
	defer deactivationCounter.Store(0)

	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	// Pre-run residue: the prior process deactivated into
	// .cdn-deactivate-1 and its rollback metadata survived the restart.
	preserved := filepath.Join(dir, ".cdn-deactivate-1")
	if err := os.Mkdir(preserved, 0o700); err != nil {
		t.Fatal(err)
	}
	planted := "preserved-rollback-metadata"
	if err := os.WriteFile(filepath.Join(preserved, "Caddyfile"), []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatalf("configure A: %v", err)
	}
	// A → B with the counter reset: the old EEXIST-on-first-candidate
	// behavior would fail here; the allocator must skip the preserved
	// dir and claim the next name.
	if err := p.Configure(context.Background(), planB()); err != nil {
		t.Fatalf("A→B blocked by preserved aside dir (restart collision not handled): %v", err)
	}
	// The preserved rollback metadata is byte-identical.
	if b, err := os.ReadFile(filepath.Join(preserved, "Caddyfile")); err != nil || string(b) != planted {
		t.Errorf("preserved rollback metadata disturbed: %v", err)
	}
	// Exactly two deactivation dirs now: the preserved one and a NEW
	// one (different name) holding the deactivated managed Caddyfile.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	newAside := ""
	n := 0
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), ".cdn-deactivate-") {
			n++
			if e.Name() != ".cdn-deactivate-1" {
				newAside = filepath.Join(dir, e.Name())
			}
		}
	}
	if n != 2 {
		t.Fatalf("want 2 deactivation dirs (preserved + new), got %d: %v", n, entries)
	}
	if newAside == "" {
		t.Fatal("no new deactivation dir allocated")
	}
	if b, err := os.ReadFile(filepath.Join(newAside, "Caddyfile")); err != nil || !strings.HasPrefix(string(b), managedMarker) {
		t.Errorf("deactivated Caddyfile not preserved in the new aside: %v", err)
	}
}

// MEDIUM-R2-1 (crash subcase): an EMPTY aside dir is residue of a
// deactivation that crashed before anything was moved in; the allocator
// reclaims it instead of being blocked by it.
func TestCDNDeactivateReclaimsEmptyResidue(t *testing.T) {
	deactivationCounter.Store(0)
	defer deactivationCounter.Store(0)

	core, dir, _ := wireCore(t)
	p := &CDNProvider{core: core}
	residue := filepath.Join(dir, ".cdn-deactivate-1")
	if err := os.Mkdir(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.Configure(context.Background(), goldenPlanCDN()); err != nil {
		t.Fatalf("configure A: %v", err)
	}
	if err := p.Configure(context.Background(), planB()); err != nil {
		t.Fatalf("A→B blocked by empty residue dir: %v", err)
	}
	// The empty residue name is reclaimed for the new deactivation.
	if b, err := os.ReadFile(filepath.Join(residue, "Caddyfile")); err != nil || !strings.HasPrefix(string(b), managedMarker) {
		t.Errorf("expected the empty residue dir to be reclaimed for the new deactivation: %v", err)
	}
}
