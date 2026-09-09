package origin

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// activate_test.go — transactional activation of the Caddyfile (design
// §3.1). Hermetic: fake executor, t.TempDir() dirs, no real binary.

func activateFixture(t *testing.T, fe *fakeExec) (string, *fakeExec) {
	t.Helper()
	dir := t.TempDir()
	return dir, fe
}

func testPlan() Plan { return goldenPlanCaddy() }

// gate-pass → live Caddyfile with the rendered bytes + 0600.
func TestActivateGatePass(t *testing.T) {
	fe := &fakeExec{}
	dir, _ := activateFixture(t, fe)
	live, err := ActivateCaddyfile(ActivateParams{Plan: testPlan(), Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	want, _ := RenderCaddyfile(testPlan())
	b, err := os.ReadFile(live)
	if err != nil {
		t.Fatalf("read live: %v", err)
	}
	if !bytes.Equal(b, want) {
		t.Errorf("live bytes != rendered bytes")
	}
	if !strings.Contains(live, "Caddyfile") {
		t.Errorf("live path = %q", live)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(live)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("live perms = %o, want 0600", st.Mode().Perm())
		}
	}
	// The gate ran against the TMP path (before the swap).
	foundGate := false
	for _, c := range fe.calls {
		if strings.HasPrefix(c, "validate:") && strings.HasSuffix(c, ".tmp") {
			foundGate = true
		}
	}
	if !foundGate {
		t.Errorf("gate not run on the tmp path; calls=%v", fe.calls)
	}
	// No tmp/prev left behind on a fresh activation.
	if _, err := os.Stat(live + ".tmp"); !os.IsNotExist(err) {
		t.Error("tmp left behind")
	}
	if _, err := os.Stat(live + ".prev"); !os.IsNotExist(err) {
		t.Error("prev created on first activation")
	}
}

// gate-fail → dir byte-identical (no tmp, no live), error names the gate.
func TestActivateGateFailLeavesDirIdentical(t *testing.T) {
	fe := &fakeExec{validateErr: errors.New("exit status 1"), validateOut: "error: unknown directive"}
	dir, _ := activateFixture(t, fe)
	_, err := ActivateCaddyfile(ActivateParams{Plan: testPlan(), Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if err == nil {
		t.Fatal("expected gate failure")
	}
	if !errors.Is(err, ErrConfigGate) {
		t.Errorf("want ErrConfigGate, got %v", err)
	}
	if !strings.Contains(err.Error(), "unknown directive") {
		t.Errorf("gate error should include the caddy output: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("dir not empty after gate failure: %v", entries)
	}
}

// re-activation with a changed plan → .prev of the old + new live.
func TestActivateBackupOnChange(t *testing.T) {
	fe := &fakeExec{}
	dir, _ := activateFixture(t, fe)
	first, err := ActivateCaddyfile(ActivateParams{Plan: testPlan(), Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if err != nil {
		t.Fatal(err)
	}
	// A changed plan (alpn01) re-activates.
	changed := goldenPlanALPN()
	second, err := ActivateCaddyfile(ActivateParams{Plan: changed, Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("live path changed: %q -> %q", first, second)
	}
	prev, err := os.ReadFile(second + ".prev")
	if err != nil {
		t.Fatalf("prev missing: %v", err)
	}
	wantFirst, _ := RenderCaddyfile(testPlan())
	if !bytes.Equal(prev, wantFirst) {
		t.Errorf("prev != first rendered bytes")
	}
	live, _ := os.ReadFile(second)
	wantSecond, _ := RenderCaddyfile(changed)
	if !bytes.Equal(live, wantSecond) {
		t.Errorf("live != second rendered bytes")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(second + ".prev")
		if st.Mode().Perm() != 0o600 {
			t.Errorf("prev perms = %o, want 0600", st.Mode().Perm())
		}
	}
}

// A pre-planted SYMLINK at the live path is refused.
func TestActivateRefusesSymlinkLive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks not available in this environment")
	}
	fe := &fakeExec{}
	dir, _ := activateFixture(t, fe)
	live := filepath.Join(dir, "Caddyfile")
	if err := os.Symlink("/etc/passwd", live); err != nil {
		t.Skip("cannot create symlink: " + err.Error())
	}
	_, err := ActivateCaddyfile(ActivateParams{Plan: testPlan(), Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if !errors.Is(err, ErrActivateTarget) {
		t.Errorf("want ErrActivateTarget, got %v", err)
	}
}

// A pre-planted SYMLINK at the tmp path is refused.
func TestActivateRefusesSymlinkTmp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks not available in this environment")
	}
	fe := &fakeExec{}
	dir, _ := activateFixture(t, fe)
	tmp := filepath.Join(dir, "Caddyfile.tmp")
	if err := os.Symlink("/etc/passwd", tmp); err != nil {
		t.Skip("cannot create symlink: " + err.Error())
	}
	_, err := ActivateCaddyfile(ActivateParams{Plan: testPlan(), Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if !errors.Is(err, ErrActivateTarget) {
		t.Errorf("want ErrActivateTarget, got %v", err)
	}
}

// Traversal / bad dir / bad file name are refused (fail closed).
func TestActivateDirGuard(t *testing.T) {
	fe := &fakeExec{}
	realDir := t.TempDir()
	for _, tc := range []struct {
		name string
		dir  string
		file string
	}{
		{"empty dir", "", ""},
		{"dot dir", ".", ""},
		{"missing dir", filepath.Join(t.TempDir(), "nope"), ""},
		{"dotdot dir", realDir + "/sub/..", ""},
		{"file with path", realDir, "sub/Caddyfile"},
		{"file dot", realDir, "."},
		{"file dotdot", realDir, ".."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ActivateCaddyfile(ActivateParams{Plan: testPlan(), Dir: tc.dir, FileName: tc.file, Bin: "/fake/caddy", Exec: fe})
			if !errors.Is(err, ErrActivateDir) && !errors.Is(err, ErrActivateTarget) {
				t.Errorf("want ErrActivateDir/Target, got %v", err)
			}
		})
	}
}

// Crash recovery (the in-model case, single-writer deploy user): a
// stale REGULAR tmp left by a crashed activation is cleaned up and the
// activation proceeds. A pre-planted SYMLINK tmp is refused (covered by
// TestActivateRefusesSymlinkTmp). T4 has no goroutines; activations are
// serial in production, so the guarantee tested here is deterministic
// (no racy multi-goroutine assertion — that is out-of-model, same as T3).
func TestActivateStaleTmpCrashRecovery(t *testing.T) {
	fe := &fakeExec{}
	dir, _ := activateFixture(t, fe)
	tmp := filepath.Join(dir, "Caddyfile.tmp")
	if err := os.WriteFile(tmp, []byte("stale leftover from a crashed run"), 0o600); err != nil {
		t.Fatal(err)
	}
	live, err := ActivateCaddyfile(ActivateParams{Plan: testPlan(), Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if err != nil {
		t.Fatalf("activate with a stale regular tmp: %v", err)
	}
	want, _ := RenderCaddyfile(testPlan())
	b, err := os.ReadFile(live)
	if err != nil {
		t.Fatalf("live missing: %v", err)
	}
	if !bytes.Equal(b, want) {
		t.Error("live != rendered bytes")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("stale tmp not cleaned up")
	}
}

// Invalid plan → nothing written, error is ErrInvalidPlan.
func TestActivateInvalidPlanWritesNothing(t *testing.T) {
	fe := &fakeExec{}
	dir, _ := activateFixture(t, fe)
	_, err := ActivateCaddyfile(ActivateParams{Plan: Plan{Mode: ModeCaddy, Domain: "bad domain", UpstreamAddr: "127.0.0.1:9001"}, Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if !errors.Is(err, ErrInvalidPlan) {
		t.Errorf("want ErrInvalidPlan, got %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("dir not empty: %v", entries)
	}
}
