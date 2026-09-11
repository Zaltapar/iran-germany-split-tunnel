package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
	if err := RemoveUnit(context.Background(), newTestManager(ex), s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatalf("live remains: %v", err)
	}
	if len(maybeUnitBackups(t, "germany-splitter.service")) != 1 {
		t.Fatalf("backup count mismatch")
	}
	assertCalls(t, ex.calls, []string{"systemctl is-active germany-splitter.service", "systemctl disable germany-splitter.service", "systemctl daemon-reload"})
}

func maybeUnitBackups(t *testing.T, unit string) []string {
	t.Helper()
	got, err := managedUnitsBackups(unit)
	if err != nil {
		t.Fatal(err)
	}
	return got
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
