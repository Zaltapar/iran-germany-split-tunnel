package xray

// activate_test.go — transactional activation tests (design doc
// plans/t3-design.md §5 items 9/11). Hermetic: fake Executor, temp
// directories, no real binary, no network.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// activateFake is a controllable Executor for the activation gate.
type activateFake struct {
	runTestErr error
	runTestOut string
	calls      []string
}

func (f *activateFake) VersionOutput(string) (string, error) { return "Xray 26.3.27", nil }
func (f *activateFake) Keypair(string) (string, error)       { return "", nil }
func (f *activateFake) RunTest(bin, cfg string) (string, error) {
	f.calls = append(f.calls, "run-test:"+bin+":"+cfg)
	return f.runTestOut, f.runTestErr
}

// dirSnapshot maps every regular file in dir to its content (relative
// paths) — the mtime-free byte comparison used to prove "nothing changed".
func dirSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("snapshot read %s: %v", p, err)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			t.Fatalf("snapshot rel %s: %v", p, err)
		}
		snap[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot walk: %v", err)
	}
	return snap
}

func newActivateFake() *activateFake { return &activateFake{} }

func activateBase(t *testing.T, dir string) ActivateParams {
	t.Helper()
	return ActivateParams{
		Params:   goldenParams(),
		Keypair:  goldenKeypair(),
		Dir:      dir,
		FileName: "xray-germany.json",
		Bin:      "/opt/split-tunnel/xray/current/xray",
		Exec:     newActivateFake(),
	}
}

// Gate PASS, no previous config: live file created with the rendered
// bytes; no .prev, no .tmp; the gate ran against the TMP path (never the
// live path).
func TestActivateFirstRun(t *testing.T) {
	dir := t.TempDir()
	a := activateBase(t, dir)
	fake := a.Exec.(*activateFake)

	live, err := ActivateGermanyConfig(a)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if live != filepath.Join(dir, "xray-germany.json") {
		t.Errorf("live path = %q", live)
	}
	got, err := os.ReadFile(live)
	if err != nil {
		t.Fatalf("read live: %v", err)
	}
	want, err := RenderGermanyConfig(a.Params, a.Keypair)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Error("live config differs from rendered bytes")
	}
	if _, err := os.Stat(live + ".prev"); !errors.Is(err, os.ErrNotExist) {
		t.Error(".prev must not exist on first activation")
	}
	if _, err := os.Stat(live + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Error("tmp must be gone after activation")
	}
	// The gate must have validated the tmp, not the live path.
	if len(fake.calls) != 1 || !strings.HasSuffix(fake.calls[0], ".tmp") {
		t.Errorf("gate calls = %v, want exactly one against the .tmp path", fake.calls)
	}
	assertPerm0600(t, live)
}

// Gate PASS, previous config present: the old bytes are preserved
// byte-identical in .prev (rollback artifact), .prev is 0600, and the
// live file now carries the new bytes.
func TestActivateRollbackBackup(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "xray-germany.json")
	old := []byte(`{"old":"config with previous private key"}`)
	if err := os.WriteFile(live, old, 0o600); err != nil {
		t.Fatal(err)
	}

	a := activateBase(t, dir)
	if _, err := ActivateGermanyConfig(a); err != nil {
		t.Fatalf("activate: %v", err)
	}
	prev, err := os.ReadFile(live + ".prev")
	if err != nil {
		t.Fatalf(".prev missing: %v", err)
	}
	if string(prev) != string(old) {
		t.Errorf(".prev does not preserve the previous config byte-identically")
	}
	newLive, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(newLive), `"old"`) {
		t.Error("live config was not replaced")
	}
	assertPerm0600(t, live+".prev")
}

// Gate FAIL: the directory must be byte-identical to before (no live
// change, no tmp left, no .prev created) and the error must be the gate
// sentinel.
func TestActivateGateFailChangesNothing(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "xray-germany.json")
	old := []byte(`{"old":"keep me"}`)
	if err := os.WriteFile(live, old, 0o600); err != nil {
		t.Fatal(err)
	}
	before := dirSnapshot(t, dir)

	a := activateBase(t, dir)
	fake := a.Exec.(*activateFake)
	fake.runTestErr = errors.New("xray: exit status 1")
	fake.runTestOut = "xray: failed"

	_, err := ActivateGermanyConfig(a)
	if !errors.Is(err, ErrConfigGate) {
		t.Fatalf("want ErrConfigGate, got %v", err)
	}
	if after := dirSnapshot(t, dir); len(before) != len(after) || after[filepath.Base(live)] != string(old) {
		t.Errorf("gate failure changed the directory: before=%v after=%v", before, after)
	}
	if _, err := os.Stat(live + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Error("tmp leaked after gate failure")
	}
	if _, err := os.Stat(live + ".prev"); !errors.Is(err, os.ErrNotExist) {
		t.Error(".prev must not be created when the gate fails")
	}
}

// The one real leak vector: xray's privateKey decode error ECHOES the key
// value. The activation error must return a masked excerpt — never the
// key bytes.
func TestActivateGateFailureMasksPrivateKey(t *testing.T) {
	dir := t.TempDir()
	a := activateBase(t, dir)
	fake := a.Exec.(*activateFake)
	priv := a.Keypair.PrivateRaw
	fake.runTestErr = errors.New("xray: exit status 1")
	fake.runTestOut = `Config: failed to decode config: invalid "privateKey": ` + priv

	_, err := ActivateGermanyConfig(a)
	if !errors.Is(err, ErrConfigGate) {
		t.Fatalf("want ErrConfigGate, got %v", err)
	}
	if strings.Contains(err.Error(), priv) {
		t.Fatalf("activation error leaks the private key: %v", err)
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Errorf("expected masked excerpt, got: %v", err)
	}
	// The public key is also masked (defence in depth).
	if strings.Contains(err.Error(), a.Keypair.PublicRaw) {
		t.Fatalf("activation error leaks the public key: %v", err)
	}
}

// Validation failure (bad operator input) must not even reach the gate:
// no tmp, no RunTest call, nothing on disk.
func TestActivateValidationFailChangesNothing(t *testing.T) {
	dir := t.TempDir()
	before := dirSnapshot(t, dir)
	a := activateBase(t, dir)
	a.Params.SNI = "NOT VALID"
	fake := a.Exec.(*activateFake)

	_, err := ActivateGermanyConfig(a)
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("want ErrInvalidParams, got %v", err)
	}
	if len(fake.calls) != 0 {
		t.Errorf("gate must not run on invalid input, calls=%v", fake.calls)
	}
	if after := dirSnapshot(t, dir); len(before) != len(after) {
		t.Errorf("invalid input changed the directory: %v", after)
	}
}

// Invalid target directory / file name fail fast, before any write.
func TestActivateBadTargets(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		mut  func(*ActivateParams)
	}{
		{"dir missing", func(a *ActivateParams) { a.Dir = filepath.Join(dir, "nope") }},
		// Raw ".." component (NOT via filepath.Join, which would clean it
		// away before the guard sees it).
		{"dir traversal", func(a *ActivateParams) { a.Dir = dir + string(filepath.Separator) + ".." }},
		{"dir is a file", func(a *ActivateParams) { a.Dir = dir + string(filepath.Separator) + "somefile" }},
		{"file name with path", func(a *ActivateParams) { a.FileName = "sub/x.json" }},
		{"file name dotdot", func(a *ActivateParams) { a.FileName = ".." }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "dir is a file" {
				if err := os.WriteFile(filepath.Join(dir, "somefile"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a := activateBase(t, dir)
			c.mut(&a)
			if _, err := ActivateGermanyConfig(a); !errors.Is(err, ErrActivateDir) {
				t.Errorf("want ErrActivateDir, got %v", err)
			}
		})
	}
}

// A pre-planted SYMLINK at the live target must be refused (the 0600
// write must never follow a link). Skipped on Windows (requires
// developer mode); Linux CI is authoritative for the symlink path.
func TestActivateRefusesSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
	}
	dir := t.TempDir()
	live := filepath.Join(dir, "xray-germany.json")
	if err := os.Symlink("/etc/passwd", live); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	a := activateBase(t, dir)
	if _, err := ActivateGermanyConfig(a); !errors.Is(err, ErrActivateTarget) {
		t.Fatalf("want ErrActivateTarget, got %v", err)
	}
	// The link itself must be untouched.
	if st, err := os.Lstat(live); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink was modified: %v %v", st, err)
	}
}

// A stale regular .tmp from a crashed run is cleaned and activation
// proceeds; a stale .tmp that is a symlink is refused.
func TestActivateStaleTmp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
	}
	dir := t.TempDir()
	live := filepath.Join(dir, "xray-germany.json")
	tmp := live + ".tmp"
	if err := os.WriteFile(tmp, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := activateBase(t, dir)
	if _, err := ActivateGermanyConfig(a); err != nil {
		t.Fatalf("stale regular tmp should be cleaned, got %v", err)
	}

	// Now plant a symlink at the tmp path.
	os.Remove(tmp)
	if err := os.Symlink("/etc/passwd", tmp); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	a2 := activateBase(t, dir)
	if _, err := ActivateGermanyConfig(a2); !errors.Is(err, ErrActivateTarget) {
		t.Fatalf("want ErrActivateTarget for symlink tmp, got %v", err)
	}
}

// maskSecrets unit checks.
func TestMaskSecrets(t *testing.T) {
	priv := "gAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHiA"
	pub := "oAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd"
	got := maskSecrets("err: privateKey="+priv+" pub="+pub, priv, pub)
	if strings.Contains(got, priv) || strings.Contains(got, pub) {
		t.Errorf("maskSecrets left secret material: %q", got)
	}
	if !strings.Contains(got, "<redacted>") {
		t.Errorf("maskSecrets did not mark: %q", got)
	}
	// Empty secrets are ignored (no spurious replacement).
	if got := maskSecrets("plain", "", ""); got != "plain" {
		t.Errorf("empty secrets must be ignored: %q", got)
	}
}

// assertPerm0600 checks the file's permission bits on Unix; on Windows
// the ACL model does not expose POSIX bits, so the check is skipped there
// (the Linux CI run is authoritative).
func assertPerm0600(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("%s: mode = %o, want 600", path, perm)
	}
}
