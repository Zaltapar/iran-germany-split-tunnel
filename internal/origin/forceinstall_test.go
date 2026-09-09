package origin

// forceinstall_test.go — review HIGH-1: a FORCED reinstall must preserve
// the pre-existing working version byte-identically under EVERY injected
// failure (chmod, smoke check, config gate, first exchange rename,
// second exchange rename, download). The known-good pinned version must
// remain runnable after every failure.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installThenTamperDL installs the pinned version once, then swaps the
// Downloader to a fresh candidate payload so the FORCED reinstall is a
// real replacement (different bytes).
func installThenTamperDL(t *testing.T) (prefix string, versionDir string, origBin []byte) {
	t.Helper()
	tarBytes := makeTarGz(t)
	in, _, pfx := installFixture(t, tarBytes)
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); err != nil {
		t.Fatalf("initial install: %v", err)
	}
	vd, err := VersionDir(pfx, PinnedVersion)
	if err != nil {
		t.Fatal(err)
	}
	origBin, err = os.ReadFile(filepath.Join(vd, "caddy"))
	if err != nil {
		t.Fatal(err)
	}
	return pfx, vd, origBin
}

// forcedInstaller returns an Installer over the SAME prefix (existing
// version present) with Force=true and a candidate payload.
func forcedInstaller(t *testing.T, prefix string) (*Installer, *fakeExec) {
	t.Helper()
	cand := makeTarGz(t)
	ta, err := TarURL(PinnedVersion, CaddyArchLinuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ChecksumURL(PinnedVersion)
	if err != nil {
		t.Fatal(err)
	}
	dl := staticDL{files: map[string][]byte{ta: cand, ca: checksumsFor(t, cand)}}
	fe := &fakeExec{versionOut: PinnedVersion + " h1:newbuild"}
	return &Installer{Prefix: prefix, DL: dl, Exec: fe, Force: true}, fe
}

// assertVersionIntact fails unless the version dir still holds the
// original binary bytes and the directory has no transaction residue.
func assertVersionIntact(t *testing.T, prefix, versionDir string, origBin []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(versionDir, "caddy"))
	if err != nil {
		t.Fatalf("pre-existing binary lost after failure: %v", err)
	}
	if string(got) != string(origBin) {
		t.Errorf("pre-existing binary bytes changed after failure")
	}
	// No candidate/backup residue may survive next to the version dir.
	root := filepath.Dir(versionDir)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".new") || strings.HasSuffix(e.Name(), ".old") {
			t.Errorf("transaction residue left behind: %s", e.Name())
		}
	}
	assertNoStageDirs(t, prefix)
}

func TestForcePreservesExistingOnDownloadFailure(t *testing.T) {
	prefix, versionDir, origBin := installThenTamperDL(t)
	dl := staticDL{err: errors.New("network down")}
	fe := &fakeExec{versionOut: PinnedVersion + " h1:newbuild"}
	in := &Installer{Prefix: prefix, DL: dl, Exec: fe, Force: true}
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); err == nil {
		t.Fatal("expected download failure")
	}
	assertVersionIntact(t, prefix, versionDir, origBin)
}

func TestForcePreservesExistingOnChmodFailure(t *testing.T) {
	prefix, versionDir, origBin := installThenTamperDL(t)
	in, _ := forcedInstaller(t, prefix)
	in.Chmod = func(string, os.FileMode) error { return errors.New("chmod denied") }
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); err == nil {
		t.Fatal("expected chmod failure")
	}
	assertVersionIntact(t, prefix, versionDir, origBin)
}

func TestForcePreservesExistingOnSmokeFailure(t *testing.T) {
	prefix, versionDir, origBin := installThenTamperDL(t)
	in, fe := forcedInstaller(t, prefix)
	fe.versionOut = "v0.0.0 h1:wrong" // candidate fails the smoke check
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); !errors.Is(err, ErrSmokeCheck) {
		t.Fatalf("want ErrSmokeCheck, got %v", err)
	}
	assertVersionIntact(t, prefix, versionDir, origBin)
}

func TestForcePreservesExistingOnConfigGateFailure(t *testing.T) {
	prefix, versionDir, origBin := installThenTamperDL(t)
	in, fe := forcedInstaller(t, prefix)
	fe.validateErr = errors.New("config rejected")
	cfg := filepath.Join(t.TempDir(), "Caddyfile")
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, cfg); !errors.Is(err, ErrConfigGate) {
		t.Fatalf("want ErrConfigGate, got %v", err)
	}
	assertVersionIntact(t, prefix, versionDir, origBin)
}

// First exchange rename (existing → backup) fails: the candidate is
// cleaned up, the existing dir never moved.
func TestForcePreservesExistingOnFirstRenameFailure(t *testing.T) {
	prefix, versionDir, origBin := installThenTamperDL(t)
	in, _ := forcedInstaller(t, prefix)
	in.Rename = func(oldpath, newpath string) error {
		// Fail only the live→backup exchange rename; allow the earlier
		// stage→candidate rename.
		if strings.HasSuffix(newpath, ".old") && filepath.Base(oldpath) == PinnedVersion {
			return errors.New("rename locked")
		}
		return os.Rename(oldpath, newpath)
	}
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); !errors.Is(err, ErrInstallAborted) {
		t.Fatalf("want ErrInstallAborted, got %v", err)
	}
	assertVersionIntact(t, prefix, versionDir, origBin)
}

// Second exchange rename (candidate → live) fails AFTER the existing
// dir was moved aside: the existing dir must be restored byte-identical.
func TestForcePreservesExistingOnSecondRenameFailure(t *testing.T) {
	prefix, versionDir, origBin := installThenTamperDL(t)
	in, _ := forcedInstaller(t, prefix)
	backupDir := versionDir + ".old"
	in.Rename = func(oldpath, newpath string) error {
		// Fail only the candidate→live exchange rename; allow stage→
		// candidate and live→backup.
		if oldpath == versionDir+".new" && newpath == versionDir {
			return errors.New("rename cross-device wedged")
		}
		return os.Rename(oldpath, newpath)
	}
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); !errors.Is(err, ErrInstallAborted) {
		t.Fatalf("want ErrInstallAborted, got %v", err)
	}
	// The existing dir was moved aside and MUST have been restored.
	assertVersionIntact(t, prefix, versionDir, origBin)
	if _, err := os.Lstat(backupDir); !os.IsNotExist(err) {
		t.Errorf("backup dir left behind after restore: %v", err)
	}
}

// A symlink planted at the version dir path is refused BEFORE any
// recursive removal or rename (HIGH-1: no unsafe existing version path).
func TestForceRefusesSymlinkVersionDir(t *testing.T) {
	prefix, versionDir, _ := installThenTamperDL(t)
	// Replace the version dir with a symlink to a decoy target.
	if err := os.RemoveAll(versionDir); err != nil {
		t.Fatal(err)
	}
	decoy := t.TempDir()
	if err := os.WriteFile(filepath.Join(decoy, "caddy"), []byte("DECOY"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, versionDir); err != nil {
		t.Skip("symlinks not available: " + err.Error())
	}
	in, _ := forcedInstaller(t, prefix)
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); err == nil {
		t.Fatal("symlink version dir accepted for Force")
	}
	// The decoy target must be untouched.
	if b, err := os.ReadFile(filepath.Join(decoy, "caddy")); err != nil || string(b) != "DECOY" {
		t.Errorf("decoy target disturbed: %v %q", err, b)
	}
}

// RemoveVersion refuses to follow a planted symlink (HIGH-1).
func TestRemoveVersionRefusesSymlink(t *testing.T) {
	prefix := t.TempDir()
	in := &Installer{Prefix: prefix}
	versionDir, err := VersionDir(prefix, "v9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(versionDir), 0o755); err != nil {
		t.Fatal(err)
	}
	decoy := t.TempDir()
	if err := os.WriteFile(filepath.Join(decoy, "caddy"), []byte("DECOY"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, versionDir); err != nil {
		t.Skip("symlinks not available: " + err.Error())
	}
	if err := in.RemoveVersion("v9.9.9"); err == nil {
		t.Fatal("RemoveVersion followed a planted symlink")
	}
	if b, err := os.ReadFile(filepath.Join(decoy, "caddy")); err != nil || string(b) != "DECOY" {
		t.Errorf("decoy target disturbed: %v %q", err, b)
	}
}

// A symlink planted at the CANDIDATE name is refused before the
// exchange (HIGH-1).
func TestForceRefusesSymlinkCandidatePath(t *testing.T) {
	prefix, versionDir, _ := installThenTamperDL(t)
	candidateDir := versionDir + ".new"
	if err := os.MkdirAll(filepath.Dir(candidateDir), 0o755); err != nil {
		t.Fatal(err)
	}
	decoy := t.TempDir()
	if err := os.Symlink(decoy, candidateDir); err != nil {
		t.Skip("symlinks not available: " + err.Error())
	}
	in, _ := forcedInstaller(t, prefix)
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); err == nil {
		t.Fatal("symlink candidate path accepted")
	}
	if _, err := os.Lstat(filepath.Join(decoy, "caddy")); !os.IsNotExist(err) {
		t.Errorf("candidate write escaped into the decoy dir")
	}
}

// Happy-path forced reinstall still replaces the version dir (regression
// guard: the transactional path still converges).
func TestForceReinstallConverges(t *testing.T) {
	prefix, versionDir, _ := installThenTamperDL(t)
	in, _ := forcedInstaller(t, prefix)
	got, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, "")
	if err != nil {
		t.Fatalf("forced reinstall: %v", err)
	}
	if got.Path != filepath.Join(versionDir, "caddy") {
		t.Errorf("Path = %q", got.Path)
	}
	// The candidate binary (FAKE-CADDY-BINARY-v2.11.4) is in place.
	b, err := os.ReadFile(got.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "FAKE-CADDY-BINARY-v2.11.4" {
		t.Errorf("binary content = %q", b)
	}
	// No backup residue.
	if _, err := os.Lstat(versionDir + ".old"); !os.IsNotExist(err) {
		t.Errorf("backup dir left after a successful exchange: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Review HIGH-R2-1: crash-state recovery of the force exchange.
// A crash between the live→backup rename and the candidate→live rename
// leaves <version>.old as the ONLY copy of the previously working
// version. The next Install must restore it (or fail closed), never
// sweep it away.
// ---------------------------------------------------------------------------

// crashAfterLiveRename simulates the exact crash window: the live
// version dir is moved aside to .old and the process dies before the
// candidate rename. Returns the prefix + the surviving backup bytes.
func crashAfterLiveRename(t *testing.T) (prefix, versionDir, backupDir string) {
	t.Helper()
	prefix, versionDir, _ = installThenTamperDL(t)
	backupDir = versionDir + ".old"
	if err := os.Rename(versionDir, backupDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(versionDir); !os.IsNotExist(err) {
		t.Fatalf("crash simulation left the live dir in place")
	}
	return prefix, versionDir, backupDir
}

func readBin(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "caddy"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Lone .old (no live peer) is restored to the live name before the
// install proceeds; the original binary bytes are byte-identical.
func TestCrashStateLoneBackupRestored(t *testing.T) {
	prefix, versionDir, backupDir := crashAfterLiveRename(t)
	orig := readBin(t, backupDir)
	in := &Installer{Prefix: prefix, DL: staticDL{err: errors.New("unused")}, Exec: &fakeExec{}}
	if err := in.reconcileInstallResidue(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := readBin(t, versionDir)
	if string(got) != string(orig) {
		t.Errorf("restored binary bytes differ from the backup")
	}
	if _, err := os.Lstat(backupDir); !os.IsNotExist(err) {
		t.Errorf("backup dir still present after restore: %v", err)
	}
}

// A download failure AFTER the crash must not destroy the working
// version (the end-to-end HIGH-R2-1 scenario: before the fix,
// prepareStageDir swept <version>.old and the binary was lost).
func TestCrashStateSurvivesNextInstallFailure(t *testing.T) {
	prefix, versionDir, _ := crashAfterLiveRename(t)
	orig := readBin(t, versionDir+".old")
	in := &Installer{Prefix: prefix, DL: staticDL{err: errors.New("network down")}, Exec: &fakeExec{}}
	if _, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, ""); err == nil {
		t.Fatal("expected download failure")
	}
	assertVersionIntact(t, prefix, versionDir, orig)
}

// A full forced reinstall after the crash converges to the NEW
// candidate (the restored working version is the transaction input,
// not a leftover).
func TestCrashStateForcedReinstallConverges(t *testing.T) {
	prefix, versionDir, _ := crashAfterLiveRename(t)
	in, _ := forcedInstaller(t, prefix)
	got, err := in.Install(context.Background(), PinnedVersion, CaddyArchLinuxAMD64, "")
	if err != nil {
		t.Fatalf("forced reinstall after crash: %v", err)
	}
	if b, _ := os.ReadFile(got.Path); string(b) != "FAKE-CADDY-BINARY-v2.11.4" {
		t.Errorf("binary content = %q", b)
	}
	if _, err := os.Lstat(versionDir + ".old"); !os.IsNotExist(err) {
		t.Errorf("backup residue after the exchange: %v", err)
	}
}

// Ambiguous state (live AND .old both present) fails closed: neither
// artifact is touched.
func TestCrashStateAmbiguousFailsClosed(t *testing.T) {
	prefix, versionDir, _ := installThenTamperDL(t)
	backupDir := versionDir + ".old"
	// A .old with DISTINCT bytes next to a live dir: ambiguous — the
	// candidate may already have become live in the crashed run.
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "caddy"), []byte("AMBIGUOUS-OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	liveBefore := readBin(t, versionDir)
	in := &Installer{Prefix: prefix, DL: staticDL{}, Exec: &fakeExec{}}
	if err := in.reconcileInstallResidue(); err == nil {
		t.Fatal("ambiguous state accepted (live + .old both present)")
	}
	if got := readBin(t, versionDir); string(got) != string(liveBefore) {
		t.Errorf("live dir disturbed by the failed reconciliation")
	}
	if b, err := os.ReadFile(filepath.Join(backupDir, "caddy")); err != nil || string(b) != "AMBIGUOUS-OLD" {
		t.Errorf("ambiguous backup disturbed: %v %q", err, b)
	}
}

// A symlink planted at the .old name is refused (never followed, never
// removed); the decoy target is untouched.
func TestCrashStateSymlinkBackupRefused(t *testing.T) {
	prefix, versionDir, _ := installThenTamperDL(t)
	backupDir := versionDir + ".old"
	decoy := t.TempDir()
	if err := os.WriteFile(filepath.Join(decoy, "caddy"), []byte("DECOY"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, backupDir); err != nil {
		t.Skip("symlinks not available: " + err.Error())
	}
	in := &Installer{Prefix: prefix, DL: staticDL{}, Exec: &fakeExec{}}
	if err := in.reconcileInstallResidue(); err == nil {
		t.Fatal("symlink .old accepted for reconciliation")
	}
	if b, err := os.ReadFile(filepath.Join(decoy, "caddy")); err != nil || string(b) != "DECOY" {
		t.Errorf("decoy target disturbed: %v %q", err, b)
	}
}

// A symlink planted at the .new (abandoned-candidate) name is refused;
// the decoy is untouched and the error propagates.
func TestCrashStateSymlinkCandidateRefused(t *testing.T) {
	prefix, _, _ := installThenTamperDL(t)
	candDir, err := VersionDir(prefix, PinnedVersion)
	if err != nil {
		t.Fatal(err)
	}
	candDir += ".new"
	decoy := t.TempDir()
	if err := os.Symlink(decoy, candDir); err != nil {
		t.Skip("symlinks not available: " + err.Error())
	}
	if err := os.WriteFile(filepath.Join(decoy, "caddy"), []byte("DECOY"), 0o755); err != nil {
		t.Fatal(err)
	}
	in := &Installer{Prefix: prefix, DL: staticDL{}, Exec: &fakeExec{}}
	if err := in.reconcileInstallResidue(); err == nil {
		t.Fatal("symlink .new accepted for reconciliation")
	}
	if b, err := os.ReadFile(filepath.Join(decoy, "caddy")); err != nil || string(b) != "DECOY" {
		t.Errorf("decoy target disturbed: %v %q", err, b)
	}
}

// fmt reference guard (the file imports fmt for the exchange messages).
var _ = fmt.Sprintf
