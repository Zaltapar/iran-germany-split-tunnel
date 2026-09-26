package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDisableUnitAndRemoveUnit(t *testing.T) {
	redirectPaths(t)
	s := splitterSpec(RoleGermany)
	live := unitLive(t, s)
	writeRaw(t, live, []byte("unit\n"))
	writeRaw(t, filepath.Join(wantsDir, "germany-splitter.service"), []byte("placeholder"))
	ex := &fakeExec{handler: func(args []string) (string, error) {
		if args[0] == "systemctl" && args[1] == "is-active" {
			return "active", nil
		}
		return "", nil
	}}
	m := newTestManager(ex)
	if err := DisableUnit(context.Background(), m, s); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, ex.calls, []string{"systemctl is-active germany-splitter.service", "systemctl stop germany-splitter.service", "systemctl disable germany-splitter.service"})
	if _, err := os.Stat(filepath.Join(wantsDir, "germany-splitter.service")); !os.IsNotExist(err) {
		t.Fatalf("wants entry remains: %v", err)
	}

	redirectPaths(t)
	s = splitterSpec(RoleGermany)
	live = unitLive(t, s)
	writeRaw(t, live, []byte("unit\n"))
	ex = &fakeExec{handler: func(args []string) (string, error) {
		if args[0] == "systemctl" && args[1] == "is-active" {
			return "inactive", errors.New("inactive")
		}
		return "", nil
	}}
	oldAllow := allowUnitRemoval
	allowUnitRemoval = func() bool { return true }
	if err := RemoveUnit(context.Background(), newTestManager(ex), s); err != nil {
		t.Fatal(err)
	}
	allowUnitRemoval = oldAllow
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatalf("live remains: %v", err)
	}
	if len(maybeUnitBackups(t, "germany-splitter.service")) != 1 {
		t.Fatalf("backup count mismatch")
	}
	assertCalls(t, ex.calls, []string{"systemctl is-active germany-splitter.service", "systemctl disable germany-splitter.service", "systemctl daemon-reload"})
}

func TestRemoveUnitIfAbsentSkipsSystemctlAndRemovesOnlyManagedWantsLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires Windows symlink privilege/dev mode")
	}
	redirectPaths(t)
	s := splitterSpec(RoleGermany)
	wants := filepath.Join(wantsDir, "germany-splitter.service")
	if err := os.Symlink("/etc/systemd/system/germany-splitter.service", wants); err != nil {
		t.Fatal(err)
	}
	ex := &fakeExec{}
	if err := RemoveUnitIfAbsent(context.Background(), newTestManager(ex), s); err != nil {
		t.Fatal(err)
	}
	if len(ex.calls) != 0 {
		t.Fatalf("systemctl calls = %#v, want none", ex.calls)
	}
	if _, err := os.Lstat(wants); !os.IsNotExist(err) {
		t.Fatalf("managed wants link remains: %v", err)
	}
}

func TestRemoveUnitIfAbsentRefusesUnsafeWantsTarget(t *testing.T) {
	redirectPaths(t)
	s := splitterSpec(RoleGermany)
	wants := filepath.Join(wantsDir, "germany-splitter.service")
	if err := os.WriteFile(wants, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	ex := &fakeExec{}
	if err := RemoveUnitIfAbsent(context.Background(), newTestManager(ex), s); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("error = %v, want ErrUnsafeTarget", err)
	}
	if len(ex.calls) != 0 {
		t.Fatalf("systemctl calls = %#v, want none", ex.calls)
	}
}

func TestRemoveUnitIfAbsentExistingUnitPreservesDisableErrors(t *testing.T) {
	redirectPaths(t)
	s := splitterSpec(RoleGermany)
	live := unitLive(t, s)
	writeRaw(t, live, []byte("unit\n"))
	// Enable the opt-in so the gate does not block the test from reaching
	// the DisableUnit step (the behavior under test is error propagation,
	// not the guard itself).
	oldAllow := allowUnitRemoval
	allowUnitRemoval = func() bool { return true }
	t.Cleanup(func() { allowUnitRemoval = oldAllow })
	wantErr := errors.New("disable failed")
	ex := &fakeExec{handler: func(args []string) (string, error) {
		if args[0] == "systemctl" && args[1] == "disable" {
			return "", wantErr
		}
		return "inactive", errors.New("inactive")
	}}
	if err := RemoveUnitIfAbsent(context.Background(), newTestManager(ex), s); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want disable error", err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("existing unit was removed after disable failure: %v", err)
	}
}

func maybeUnitBackups(t *testing.T, unit string) []string {
	t.Helper()
	got, err := managedUnitsBackups(unit)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestRemoveUnitRefusesByDefaultOnProductionUnit verifies the close-out T1
// safety guard: without SPLIT_ALLOW_UNIT_REMOVAL=1, RemoveUnit refuses on a
// production unit name and does NOT leave the unit removed or disabled.
func TestRemoveUnitRefusesByDefaultOnProductionUnit(t *testing.T) {
	redirectPaths(t)
	s := splitterSpec(RoleGermany) // germany-splitter.service — in the allowlist
	live := unitLive(t, s)
	writeRaw(t, live, []byte("unit\n"))
	writeRaw(t, filepath.Join(wantsDir, "germany-splitter.service"), []byte("placeholder"))
	ex := &fakeExec{handler: func(args []string) (string, error) {
		if args[0] == "systemctl" && args[1] == "is-active" {
			return "active", nil
		}
		return "", nil
	}}
	// No opt-in: allowUnitRemoval is still the default (reads the env var,
	// which is unset in the test environment).
	m := newTestManager(ex)
	err := RemoveUnit(context.Background(), m, s)
	if !errors.Is(err, ErrUnitRemovalRefused) {
		t.Fatalf("error = %v, want ErrUnitRemovalRefused", err)
	}
	// The unit file must still exist (not removed).
	if _, serr := os.Stat(live); serr != nil {
		t.Fatalf("live unit was removed despite refusal: %v", serr)
	}
	// No systemctl calls were made (no stop, no disable, no daemon-reload).
	if len(ex.calls) != 0 {
		t.Fatalf("systemctl calls = %#v, want none (pre-mutation refusal)", ex.calls)
	}
	// No backup was created (backup happens after the gate).
	if backups := maybeUnitBackups(t, "germany-splitter.service"); len(backups) != 0 {
		t.Fatalf("backups = %d, want 0 (refusal is pre-mutation)", len(backups))
	}
}

// TestRemoveUnitRefusesByDefaultOnNonListedUnit verifies that the guard also
// refuses a unit name that is NOT in the allowlist (defense in depth: ANY
// managed-unit removal requires the opt-in, not just the known five).
func TestRemoveUnitRefusesByDefaultOnNonListedUnit(t *testing.T) {
	redirectPaths(t)
	// Use a fake unit name not in protectedUnitNames.
	s := Spec{Role: RoleGermany, Component: ComponentSplitter,
		BinPath:  filepath.Join(binaryPrefix, "xray", "current", "xray"),
		UnitName: "my-test-fixture.service"}
	live := unitLive(t, s)
	writeRaw(t, live, []byte("unit\n"))
	ex := &fakeExec{}
	err := RemoveUnit(context.Background(), newTestManager(ex), s)
	if !errors.Is(err, ErrUnitRemovalRefused) {
		t.Fatalf("error = %v, want ErrUnitRemovalRefused", err)
	}
	if _, serr := os.Stat(live); serr != nil {
		t.Fatalf("live unit was removed despite refusal: %v", serr)
	}
}

// TestRemoveUnitWithOptInPerformsRemovalOnFakeUnit verifies that with the
// explicit opt-in enabled, RemoveUnit still performs the full removal
// sequence (disable + backup + remove + daemon-reload) on a fake unit name.
func TestRemoveUnitWithOptInPerformsRemovalOnFakeUnit(t *testing.T) {
	redirectPaths(t)
	s := Spec{Role: RoleGermany, Component: ComponentSplitter,
		BinPath:  filepath.Join(binaryPrefix, "xray", "current", "xray"),
		UnitName: "my-test-fixture.service"}
	live := unitLive(t, s)
	writeRaw(t, live, []byte("unit\n"))
	ex := &fakeExec{handler: func(args []string) (string, error) {
		if args[0] == "systemctl" && args[1] == "is-active" {
			return "inactive", errors.New("inactive")
		}
		return "", nil
	}}
	// Enable the opt-in.
	oldAllow := allowUnitRemoval
	allowUnitRemoval = func() bool { return true }
	t.Cleanup(func() { allowUnitRemoval = oldAllow })

	if err := RemoveUnit(context.Background(), newTestManager(ex), s); err != nil {
		t.Fatal(err)
	}
	// The unit file must be gone.
	if _, serr := os.Stat(live); !os.IsNotExist(serr) {
		t.Fatalf("live unit still exists after opt-in removal: %v", serr)
	}
	// A backup was created.
	if backups := maybeUnitBackups(t, "my-test-fixture.service"); len(backups) != 1 {
		t.Fatalf("backups = %d, want 1", len(backups))
	}
	// systemctl calls: is-active + disable + daemon-reload.
	assertCalls(t, ex.calls, []string{
		"systemctl is-active my-test-fixture.service",
		"systemctl disable my-test-fixture.service",
		"systemctl daemon-reload",
	})
}

func TestRollbackLast(t *testing.T) {
	redirectPaths(t)
	s := splitterSpec(RoleGermany)
	if err := RollbackLast(context.Background(), newTestManager(&fakeExec{}), s); !errors.Is(err, ErrPreflight) {
		t.Fatalf("error=%v", err)
	}
	live := unitLive(t, s)
	writeRaw(t, live, []byte("current\n"))
	backup := live + ".bak-1000001"
	writeRaw(t, backup, []byte("previous\n"))
	ex := &fakeExec{}
	if err := RollbackLast(context.Background(), newTestManager(ex), s); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(live)
	if string(got) != "previous\n" {
		t.Fatalf("restored=%q", got)
	}
	assertCalls(t, ex.calls, []string{"systemctl daemon-reload", "systemctl restart germany-splitter.service"})
}

// TestRollbackLastNoBackupIsClassified pins DEFECT-3's sentinel contract: with
// no managed backup, RollbackLast reports BOTH ErrPreflight (existing callers'
// classification) and ErrNoUnitBackup (deploy recovery's convergence signal).
func TestRollbackLastNoBackupIsClassified(t *testing.T) {
	redirectPaths(t)
	s := splitterSpec(RoleGermany)
	err := RollbackLast(context.Background(), newTestManager(&fakeExec{}), s)
	if !errors.Is(err, ErrPreflight) {
		t.Fatalf("error=%v, want ErrPreflight", err)
	}
	if !errors.Is(err, ErrNoUnitBackup) {
		t.Fatalf("error=%v, want ErrNoUnitBackup", err)
	}
}
