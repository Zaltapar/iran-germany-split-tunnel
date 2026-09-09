package origin

// activate_rollback_test.go — review HIGH-3: a failed final swap must
// restore the ENTIRE pre-activation file set byte-identically — the
// live Caddyfile, a PRE-EXISTING .prev rollback artifact, and no
// leftover candidate/temp/aside residue. The Rename seam forces the
// deterministic final-swap failure.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dirSnapshot returns name→bytes for every regular file in dir
// (the byte-identity check).
func dirSnapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			// aside dirs are transaction residue: record their members
			// so a leak is caught as a snapshot difference.
			sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, se := range sub {
				b, err := os.ReadFile(filepath.Join(dir, e.Name(), se.Name()))
				if err != nil {
					t.Fatal(err)
				}
				out[e.Name()+"/"+se.Name()] = b
			}
			out[e.Name()+"/"] = []byte{}
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = b
	}
	return out
}

func assertSnapshotEqual(t *testing.T, dir string, before map[string][]byte) {
	t.Helper()
	after := dirSnapshot(t, dir)
	if len(after) != len(before) {
		t.Fatalf("file set changed: before %d entries %v, after %d entries %v", len(before), keysOf(before), len(after), keysOf(after))
	}
	for name, want := range before {
		got, ok := after[name]
		if !ok {
			t.Fatalf("file lost after failure: %s (after=%v)", name, keysOf(after))
		}
		if !bytes.Equal(got, want) {
			t.Errorf("file %s changed after failure", name)
		}
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// forceFinalSwapFailure returns a Rename that fails ONLY the final
// tmp→live swap (all other renames pass through to os.Rename).
func forceFinalSwapFailure(live string) func(string, string) error {
	tmp := live + ".tmp"
	return func(oldpath, newpath string) error {
		if oldpath == tmp && newpath == live {
			return errors.New("forced final-swap failure")
		}
		return os.Rename(oldpath, newpath)
	}
}

// No pre-existing .prev, failed final swap → the live file is unchanged
// and no .prev/.tmp/.old residue is left.
func TestActivateFinalSwapFailureNoPrev(t *testing.T) {
	fe := &fakeExec{}
	dir := t.TempDir()
	// First activation succeeds (creates the live file, no .prev).
	live, err := ActivateCaddyfile(ActivateParams{Plan: goldenPlanCaddy(), Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if err != nil {
		t.Fatal(err)
	}
	before := dirSnapshot(t, dir)

	// Second activation with a changed plan, final swap forced to fail.
	_, err = ActivateCaddyfile(ActivateParams{
		Plan:   goldenPlanALPN(),
		Dir:    dir,
		Bin:    "/fake/caddy",
		Exec:   fe,
		Rename: forceFinalSwapFailure(live),
	})
	if !errors.Is(err, ErrActivateRename) {
		t.Fatalf("want ErrActivateRename, got %v", err)
	}
	assertSnapshotEqual(t, dir, before)
	// No .prev existed before; none may be left behind.
	if _, serr := os.Lstat(live + ".prev"); !os.IsNotExist(serr) {
		t.Errorf(".prev created despite the failed swap")
	}
}

// A PRE-EXISTING .prev with distinct bytes must survive a failed final
// swap byte-identically (this is the exact Round-1 HIGH-3 hole).
func TestActivateFinalSwapFailurePreservesExistingPrev(t *testing.T) {
	fe := &fakeExec{}
	dir := t.TempDir()
	// Two successful activations → live = plan2 bytes, .prev = plan1 bytes.
	if _, err := ActivateCaddyfile(ActivateParams{Plan: goldenPlanCaddy(), Dir: dir, Bin: "/fake/caddy", Exec: fe}); err != nil {
		t.Fatal(err)
	}
	live, err := ActivateCaddyfile(ActivateParams{Plan: goldenPlanALPN(), Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if err != nil {
		t.Fatal(err)
	}
	prevBytes, err := os.ReadFile(live + ".prev")
	if err != nil {
		t.Fatalf(".prev missing after the second activation: %v", err)
	}
	liveBytes, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	before := dirSnapshot(t, dir)

	// Third activation (a distinct third plan shape: cdn mode A renders
	// a different byte string) with the final swap forced to fail.
	plan3 := goldenPlanCDN()
	_, err = ActivateCaddyfile(ActivateParams{
		Plan:   plan3,
		Dir:    dir,
		Bin:    "/fake/caddy",
		Exec:   fe,
		Rename: forceFinalSwapFailure(live),
	})
	if !errors.Is(err, ErrActivateRename) {
		t.Fatalf("want ErrActivateRename, got %v", err)
	}
	// Byte-identity of the WHOLE directory: live AND the pre-existing
	// .prev must be exactly as before, no .old/.tmp/aside residue.
	assertSnapshotEqual(t, dir, before)
	gotPrev, err := os.ReadFile(live + ".prev")
	if err != nil {
		t.Fatalf(".prev lost after the failed swap: %v", err)
	}
	if !bytes.Equal(gotPrev, prevBytes) {
		t.Errorf("pre-existing .prev bytes changed (rollback artifact destroyed)")
	}
	gotLive, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotLive, liveBytes) {
		t.Errorf("live bytes changed after the failed swap")
	}
	// No transaction residue.
	for _, residue := range []string{live + ".tmp", live + ".prev.old", live + ".prev.tmp"} {
		if _, serr := os.Lstat(residue); !os.IsNotExist(serr) {
			t.Errorf("transaction residue left behind: %s", residue)
		}
	}
}

// A symlink planted at .prev is refused BEFORE any mutation.
func TestActivateRefusesSymlinkPrev(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	fe := &fakeExec{}
	dir := t.TempDir()
	live := filepath.Join(dir, "Caddyfile")
	// A real live file + a symlink .prev.
	if err := os.WriteFile(live, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), live+".prev"); err != nil {
		t.Skip("symlinks not available: " + err.Error())
	}
	_, err := ActivateCaddyfile(ActivateParams{Plan: goldenPlanALPN(), Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if !errors.Is(err, ErrActivateTarget) {
		t.Errorf("want ErrActivateTarget, got %v", err)
	}
	// The live file must be untouched.
	if b, _ := os.ReadFile(live); string(b) != "live" {
		t.Errorf("live disturbed by a refused symlink .prev")
	}
}

// A symlink planted at .prev.tmp (the rollback-temp path) is refused.
func TestActivateRefusesSymlinkPrevTmp(t *testing.T) {
	fe := &fakeExec{}
	dir := t.TempDir()
	live := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(live, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), live+".prev.tmp"); err != nil {
		t.Skip("symlinks not available: " + err.Error())
	}
	_, err := ActivateCaddyfile(ActivateParams{Plan: goldenPlanALPN(), Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if !errors.Is(err, ErrActivateTarget) {
		t.Errorf("want ErrActivateTarget, got %v", err)
	}
}

// A stale REGULAR .prev.tmp (crash residue) is swept and the activation
// proceeds (not a planted-object refusal).
func TestActivateSweepsStalePrevTmp(t *testing.T) {
	fe := &fakeExec{}
	dir := t.TempDir()
	live := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(live, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live+".prev.tmp", []byte("crash residue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateCaddyfile(ActivateParams{Plan: goldenPlanALPN(), Dir: dir, Bin: "/fake/caddy", Exec: fe}); err != nil {
		t.Fatalf("activation with a stale regular .prev.tmp: %v", err)
	}
	if _, serr := os.Lstat(live + ".prev.tmp"); !os.IsNotExist(serr) {
		t.Errorf("stale .prev.tmp not swept")
	}
}

// Cancellation BEFORE the transaction begins leaves the directory
// byte-identical (HIGH-2 interaction with HIGH-3).
func TestActivateCanceledCtxNoMutation(t *testing.T) {
	fe := &fakeExec{}
	dir := t.TempDir()
	live := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(live, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := dirSnapshot(t, dir)
	ctx := canceledCtx()
	_, err := ActivateCaddyfile(ActivateParams{Plan: goldenPlanALPN(), Dir: dir, Bin: "/fake/caddy", Exec: fe, Ctx: ctx})
	if !errors.Is(err, errContextCanceled()) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	assertSnapshotEqual(t, dir, before)
	if len(fe.calls) != 0 {
		t.Errorf("gate called under a canceled ctx: %v", fe.calls)
	}
	if !strings.Contains(live, "Caddyfile") {
		t.Errorf("unexpected live path %q", live)
	}
}
