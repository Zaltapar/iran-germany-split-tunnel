package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

// ---------------------------------------------------------------------------
// Regression tests for the Xray version-pointer symlink fix.
//
// On a healthy Germany host the managed pointer
// /opt/split-tunnel/xray/current is a SYMLINK to a pinned version directory
// (e.g. current → v26.3.27). The 1a202b1 auditLiveDriftCore used os.Lstat
// which does NOT follow symlinks, so st.IsDir() was always false on a
// healthy host → permanent false "drift" → every install/upgrade/config
// set/rollback committed a spurious generation and rotated the Reality
// keypair.
//
// The fix changes the pointer check to os.Stat (follows symlinks) while
// keeping fail-closed semantics. These tests pin that behavior.
// ---------------------------------------------------------------------------

// symlinkPointerFX sets up an auditCoreFixture where the xray pointer is a
// symlink to a real pinned version directory, with all other managed objects
// clean. The caller must NOT call fx.writeClean (which would create
// pointer as a real directory).
func symlinkPointerFX(t *testing.T) *auditCoreFixture {
	t.Helper()
	fx := newAuditCoreFixture(t)

	// Write clean unit files and managed binary, but skip the pointer.
	if err := os.WriteFile(fx.liveXray, fx.renderXray, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fx.liveSplit, fx.renderSplit, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.binDir, "germany-splitter"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Create the pinned version directory, its regular xray binary, and the
	// symlink. The managed shape is current → <prefix>/xray/<version> holding a
	// regular 0755 xray binary — exactly what the M-3 pointer contract demands.
	parent := filepath.Dir(fx.pointer)
	pinnedDir := filepath.Join(parent, "v26.3.27")
	if err := os.MkdirAll(pinnedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pinnedDir, "xray"), []byte("xray"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(pinnedDir, fx.pointer); err != nil {
		t.Fatal(err)
	}
	return fx
}

// pinnedDir returns the path of the pinned version directory inside the
// fixture's xray parent.
func pinnedDirOf(fx *auditCoreFixture) string {
	return filepath.Join(filepath.Dir(fx.pointer), "v26.3.27")
}

// TestSymlinkPointerHealthyIsNoDrift (regression test 1)
//
// The xray version pointer is a healthy symlink to a pinned version
// directory. All other managed objects are clean. The audit must report
// NO drift, so a clean install/upgrade is a true no-op (zero adapter
// mutation, no keypair regen).
func TestSymlinkPointerHealthyIsNoDrift(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
	}
	fx := symlinkPointerFX(t)
	drifted, _ := fx.audit(t)
	if drifted {
		t.Fatal("healthy symlink pointer classified as drift (the 1a202b1 Lstat bug)")
	}
}

// TestSymlinkPointerDanglingIsDrift (regression tests 2 + 3)
//
// The xray version pointer is a DANGLING symlink (target removed).
// os.Stat returns ENOENT → os.IsNotExist → audit reports drift
// (fail-closed). A broken symlink must NOT be silently treated as a valid
// directory.
func TestSymlinkPointerDanglingIsDrift(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
	}
	fx := symlinkPointerFX(t)
	// Remove the target directory so the symlink is now dangling.
	if err := os.RemoveAll(pinnedDirOf(fx)); err != nil {
		t.Fatal(err)
	}
	drifted, _ := fx.audit(t)
	if !drifted {
		t.Fatal("dangling symlink pointer not classified as drift (fail-closed violation)")
	}
}

// TestSymlinkPointerOutsidePrefixIsDrift (M-3)
//
// The xray version pointer is a healthy symlink whose target escapes the
// managed <prefix>/xray directory (e.g. current → /etc/evil). The M-3
// containment check must reject an out-of-prefix target as drift even when
// the target is a real directory carrying a regular binary.
func TestSymlinkPointerOutsidePrefixIsDrift(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
	}
	fx := symlinkPointerFX(t)
	// Plant an out-of-prefix directory with a binary, then repoint.
	evil := filepath.Join(t.TempDir(), "evil-xray")
	if err := os.MkdirAll(evil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evil, "xray"), []byte("evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fx.pointer); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, fx.pointer); err != nil {
		t.Fatal(err)
	}
	drifted, _ := fx.audit(t)
	if !drifted {
		t.Fatal("out-of-prefix symlink target not classified as drift (containment violation)")
	}
}

// TestSymlinkPointerWrongVersionIsDrift (M-3)
//
// The xray version pointer resolves to a version directory INSIDE the managed
// prefix, but a version other than the one committed in the manifest. The
// M-3 wrong-version check must flag this as drift (the committed manifest
// pins v26.3.27; pointing at v9.9.9 is a pointer mismatch).
func TestSymlinkPointerWrongVersionIsDrift(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
	}
	fx := symlinkPointerFX(t)
	parent := filepath.Dir(fx.pointer)
	wrong := filepath.Join(parent, "v9.9.9")
	if err := os.MkdirAll(wrong, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wrong, "xray"), []byte("xray"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fx.pointer); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(wrong, fx.pointer); err != nil {
		t.Fatal(err)
	}
	drifted, _ := fx.audit(t)
	if !drifted {
		t.Fatal("wrong-version symlink target not classified as drift")
	}
}

// TestSymlinkPointerToNonDirIsDrift (regression test 2 variant)
//
// The xray version pointer is a symlink to a REGULAR FILE, not a
// directory. os.Stat succeeds (follows the link), resolves to a file,
// !st.IsDir() → audit reports drift.
func TestSymlinkPointerToNonDirIsDrift(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
	}
	fx := symlinkPointerFX(t)
	// Replace the target directory with a regular file (symlink still points there).
	pd := pinnedDirOf(fx)
	if err := os.RemoveAll(pd); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pd, []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	drifted, _ := fx.audit(t)
	if !drifted {
		t.Fatal("symlink to a regular file not classified as drift")
	}
}

// TestSymlinkUnitStillRefused (regression test 4)
//
// A SYMLINK where a committed UNIT file must be is still drift. The fix
// must NOT have loosened symlink-refusal for unit paths.
func TestSymlinkUnitStillRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
	}
	fx := newAuditCoreFixture(t)
	fx.writeClean(t)
	// Replace the splitter unit with a dangling symlink.
	if err := os.Remove(fx.liveSplit); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(fx.unitDir, "nowhere"), fx.liveSplit); err != nil {
		t.Fatal(err)
	}
	drifted, _ := fx.audit(t)
	if !drifted {
		t.Fatal("symlink at unit path not classified as drift (unsafe-target contract violated)")
	}
}

// TestSymlinkSplitterBinStillRefused (regression test 4 variant)
//
// A SYMLINK where the managed SPLITTER BINARY must be is still drift. The
// fix must NOT have loosened symlink-refusal for the binary path.
func TestSymlinkSplitterBinStillRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
	}
	fx := newAuditCoreFixture(t)
	fx.writeClean(t)
	binPath := filepath.Join(fx.binDir, "germany-splitter")
	if err := os.Remove(binPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(fx.binDir, "nowhere"), binPath); err != nil {
		t.Fatal(err)
	}
	drifted, _ := fx.audit(t)
	if !drifted {
		t.Fatal("symlink at splitter-bin path not classified as drift (unsafe-target contract violated)")
	}
}

// TestSymlinkPointerNoOpTransaction (regression test 5)
//
// On a fully-clean Germany host where the xray pointer is a healthy symlink
// to a pinned version directory, a no-op transaction must:
//   - report Plan.Unchanged = true, result.Changed = false
//   - NOT commit a new generation (identical state.json sha)
//   - run ZERO adapter phases (no keypair regen, no restart)
//
// This mirrors TestNoOpInstallAuditsLiveDrift but exercises the REAL
// auditLiveDriftCore (not a scripted fake) so the symlink-pointer case is
// the no-drift one.
func TestSymlinkPointerNoOpTransaction(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	withManagedPrefix(t, binDir)

	request := requestIn(t, store, renderSafeRequest(validGermanyRequest()))
	desired, err := request.Desired()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildSystemdPlan(request)
	if err != nil {
		t.Fatal(err)
	}
	renderXray, err := systemd.RenderUnit(applyReadySpec(plan.Specs[0]))
	if err != nil {
		t.Fatal(err)
	}
	renderSplit, err := systemd.RenderUnit(applyReadySpec(plan.Specs[1]))
	if err != nil {
		t.Fatal(err)
	}

	unitDir := t.TempDir()
	liveXray := filepath.Join(unitDir, "xray-germany.service")
	liveSplit := filepath.Join(unitDir, "germany-splitter.service")

	// Create the pinned version directory, its regular xray binary, and the
	// symlink — the healthy managed shape the M-3 pointer contract accepts.
	xrayParent := filepath.Join(t.TempDir(), "xray")
	pinnedDir := filepath.Join(xrayParent, "v26.3.27")
	if err := os.MkdirAll(pinnedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pinnedDir, "xray"), []byte("xray"), 0o755); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(xrayParent, "current")
	if err := os.Symlink(pinnedDir, pointer); err != nil {
		t.Fatal(err)
	}

	// Redirect the desired + committed state to the temp tree.
	desired.Paths.UnitFiles = []string{liveXray, liveSplit}
	desired.Paths.BinaryPointer = pointer
	previous := manifestFromDesired(desired, "g1")
	if _, err := store.Commit(previous, "install"); err != nil {
		t.Fatal(err)
	}

	// Write clean live objects (unit bytes match, binary 0755).
	if err := os.WriteFile(liveXray, renderXray, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(liveSplit, renderSplit, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "germany-splitter"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Capture the state.json sha before the no-op.
	stateFile := store.Root + "/state.json"
	shaBefore := fileSHA256Hex(t, stateFile)

	// Wire the REAL audit on the inner adapter and run the no-op transaction.
	inner := &LinuxAdapter{
		Request:          request,
		Store:            store,
		Services:         systemd.NewServiceManager(nil),
		Firewall:         &firewallFake{},
		convergeStateDir: func(context.Context) error { return nil },
	}
	inner.units = plan.Specs
	inner.liveAudit = inner.auditLiveDriftCore
	adapter := &healAuditAdapter{activateOnlyAdapter{inner: inner}}

	tx := Transaction{
		Store:     store,
		Previous:  previous,
		Desired:   desired,
		AuditLive: adapter.AuditLiveDrift,
		Recover:   func(ctx context.Context, old Manifest) error { return nil },
		Steps: []Step{
			{Phase: PhasePreflight, Name: "prepare", Run: func(context.Context) error { return nil }},
			{Phase: PhaseValidate, Name: "validate", Run: func(context.Context) error { return nil }},
			{Phase: PhaseBackup, Name: "backup", Run: func(context.Context) error { return nil }},
			{Phase: PhaseActivate, Name: "activate", Run: func(context.Context) error { return nil }},
			{Phase: PhaseTransition, Name: "transition", Run: func(context.Context) error { return nil }},
			{Phase: PhaseHealth, Name: "health", Run: func(context.Context) error { return nil }},
		},
	}
	result, err := tx.Apply(context.Background())
	if err != nil {
		t.Fatalf("no-op apply: %v", err)
	}
	if result.Changed || !result.Plan.Unchanged {
		t.Fatalf("result = %+v, want an uncommitted no-op (symlink pointer is healthy)", result)
	}
	if result.Manifest.Generation != "g1" {
		t.Fatalf("no-op committed generation %q, want g1 untouched", result.Manifest.Generation)
	}
	// state.json must be byte-identical (no new generation).
	shaAfter := fileSHA256Hex(t, stateFile)
	if shaBefore != shaAfter {
		t.Fatal("state.json changed during a no-op transaction")
	}
}

// fileSHA256Hex returns the hex-encoded SHA-256 of a file's contents.
func fileSHA256Hex(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
