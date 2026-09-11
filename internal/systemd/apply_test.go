package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func splitterSpec(role Role) Spec {
	return Spec{Role: role, Component: ComponentSplitter,
		BinPath: filepath.Join(binaryPrefix, string(role)+"-splitter"),
		EnvFile: canonicalEnvFile(role)}
}

func xraySpec() Spec {
	return Spec{Role: RoleGermany, Component: ComponentXray, BinPath: filepath.Join(binaryPrefix, "xray", "current", "xray")}
}

func originSpec() Spec {
	return Spec{Role: RoleIran, Component: ComponentOrigin, BinPath: filepath.Join(binaryPrefix, "caddy", "v2.11.4", "caddy"), OriginVersion: "v2.11.4"}
}

func plantApplyPreconditions(t *testing.T, s Spec) {
	t.Helper()
	writeRaw(t, s.BinPath, []byte("fake binary\n"))
	if s.Component == ComponentSplitter {
		// 0600: production env files are 0600 root:root (D4), and the
		// Linux-gated preflight rejects env files more permissive than 0640.
		writeRaw0600(t, envPath(s.Role), []byte("SPLIT_SECRET="+secretMarker+"\n"))
	}
	for _, unit := range s.RequiresUnits {
		writeRaw(t, filepath.Join(unitDir, unit), []byte("[Unit]\n"))
	}
	switch s.Component {
	case ComponentXray:
		writeRaw(t, filepath.Join(stateDir, "xray-germany.json"), []byte("{}\n"))
	case ComponentOrigin:
		writeRaw(t, filepath.Join(stateDir, "Caddyfile"), []byte(":443\n"))
	}
}

func applySpec(t *testing.T, role Role, component Component) Spec {
	t.Helper()
	var s Spec
	switch component {
	case ComponentSplitter:
		s = splitterSpec(role)
	case ComponentXray:
		s = xraySpec()
	case ComponentOrigin:
		s = originSpec()
	}
	if component == ComponentSplitter && role == RoleGermany {
		s.RequiresUnits = []string{"xray-germany.service"}
	}
	plantApplyPreconditions(t, s)
	return s
}

func unitLive(t *testing.T, s Spec) string {
	t.Helper()
	n, err := s.unitName()
	if err != nil {
		t.Fatal(err)
	}
	p, err := unitPath(n)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func assertCalls(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("calls=%v, want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d=%q, want %q; calls=%v", i, got[i], want[i], got)
		}
	}
}
func unitBackups(t *testing.T, live string) []string {
	t.Helper()
	got, err := managedUnitBackups(live)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestApplyUnitFreshAndUpgrade(t *testing.T) {
	redirectPaths(t)
	s := applySpec(t, RoleGermany, ComponentSplitter)
	live := unitLive(t, s)
	ex := &fakeExec{handler: okHandler}
	m := newTestManager(ex)
	result, err := ApplyUnit(context.Background(), m, s)
	if err != nil {
		t.Fatal(err)
	}
	assertCalls(t, ex.calls, []string{
		"systemd-analyze verify " + live + ".tmp-" + strconv.Itoa(os.Getpid()),
		"systemctl daemon-reload", "systemctl enable germany-splitter.service",
		"systemctl start germany-splitter.service", "systemctl is-active germany-splitter.service"})
	want, _ := RenderUnit(s)
	got, _ := os.ReadFile(live)
	if string(got) != string(want) || result.Unchanged || !result.Restarted || !result.Health.Active {
		t.Fatalf("result=%+v live=%q", result, got)
	}
	if runtime.GOOS == "linux" {
		if st, _ := os.Stat(live); st.Mode().Perm() != 0o644 {
			t.Fatalf("mode=%o", st.Mode().Perm())
		}
	}
	if len(unitBackups(t, live)) != 0 {
		t.Fatal("fresh apply created backup")
	}

	oldCalls := len(ex.calls)
	oldBytes := append([]byte(nil), got...)
	result, err = ApplyUnit(context.Background(), m, s)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Unchanged || len(ex.calls) != oldCalls {
		t.Fatalf("no-op result=%+v calls=%v", result, ex.calls[oldCalls:])
	}
	if string(oldBytes) != string(got) {
		t.Fatal("no-op changed bytes")
	}

	s.Description = "changed only ignored description"
	result, err = ApplyUnit(context.Background(), m, s)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Unchanged {
		t.Fatal("description-only change should be no-op")
	}
}

func TestApplyUnitUpgradeAndRollback(t *testing.T) {
	redirectPaths(t)
	s := applySpec(t, RoleGermany, ComponentSplitter)
	live := unitLive(t, s)
	initial := []byte("old unit\n")
	writeRaw(t, live, initial)
	ex := &fakeExec{handler: okHandler}
	m := newTestManager(ex)
	result, err := ApplyUnit(context.Background(), m, s)
	if err != nil {
		t.Fatal(err)
	}
	if result.Unchanged || !result.Restarted {
		t.Fatalf("result=%+v", result)
	}
	if len(unitBackups(t, live)) != 1 {
		t.Fatalf("backups=%v", unitBackups(t, live))
	}
	assertCalls(t, ex.calls, []string{"systemctl is-active germany-splitter.service", "systemd-analyze verify " + live + ".tmp-" + strconv.Itoa(os.Getpid()), "systemctl daemon-reload", "systemctl enable germany-splitter.service", "systemctl restart germany-splitter.service", "systemctl is-active germany-splitter.service"})

	redirectPaths(t)
	s = applySpec(t, RoleGermany, ComponentSplitter)
	live = unitLive(t, s)
	writeRaw(t, live, initial)
	verifyErr := errors.New("verify rejected")
	ex = &fakeExec{handler: func(args []string) (string, error) {
		if args[0] == "systemd-analyze" {
			return "bad unit", verifyErr
		}
		return "", nil
	}}
	_, err = ApplyUnit(context.Background(), newTestManager(ex), s)
	if !errors.Is(err, ErrVerify) || errors.Is(err, verifyErr) {
		t.Fatalf("error=%v", err)
	}
	got, _ := os.ReadFile(live)
	if string(got) != string(initial) {
		t.Fatalf("live=%q calls=%v", got, ex.calls)
	}
	assertCalls(t, ex.calls, []string{
		"systemctl is-active germany-splitter.service",
		"systemd-analyze verify " + live + ".tmp-" + strconv.Itoa(os.Getpid()),
	})
}

func TestApplyUnitRollbackAfterReloadFailure(t *testing.T) {
	redirectPaths(t)
	s := applySpec(t, RoleGermany, ComponentSplitter)
	live := unitLive(t, s)
	old := []byte("known good\n")
	writeRaw(t, live, old)
	reloadErr := errors.New("reload failed")
	reloads := 0
	ex := &fakeExec{handler: func(args []string) (string, error) {
		if args[0] == "systemctl" && args[1] == "daemon-reload" {
			reloads++
			if reloads == 1 {
				return "", reloadErr
			}
		}
		return "active", nil
	}}
	_, err := ApplyUnit(context.Background(), newTestManager(ex), s)
	if !errors.Is(err, reloadErr) || !strings.Contains(err.Error(), StepReload) || !strings.Contains(err.Error(), "restored known good") {
		t.Fatalf("error=%v", err)
	}
	got, _ := os.ReadFile(live)
	if string(got) != string(old) {
		t.Fatalf("restored=%q", got)
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d", reloads)
	}
}

func TestApplyUnitWaitFailureAndCancellation(t *testing.T) {
	redirectPaths(t)
	s := applySpec(t, RoleGermany, ComponentSplitter)
	live := unitLive(t, s)
	old := []byte("old\n")
	writeRaw(t, live, old)
	ex := &fakeExec{handler: func(args []string) (string, error) {
		if args[0] == "systemctl" && args[1] == "is-active" {
			return "failed", errors.New("failed")
		}
		return "", nil
	}}
	_, err := ApplyUnit(context.Background(), newTestManager(ex), s)
	if !errors.Is(err, ErrUnitState) || !strings.Contains(err.Error(), StepHealth) {
		t.Fatalf("error=%v", err)
	}
	got, _ := os.ReadFile(live)
	if string(got) != string(old) {
		t.Fatalf("restored=%q", got)
	}

	redirectPaths(t)
	s = applySpec(t, RoleGermany, ComponentSplitter)
	live = unitLive(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	ex = &fakeExec{handler: func(args []string) (string, error) {
		if args[0] == "systemd-analyze" {
			cancel()
		}
		return "", nil
	}}
	_, err = ApplyUnit(ctx, newTestManager(ex), s)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "clean") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Stat(live); !os.IsNotExist(statErr) {
		t.Fatalf("live should be absent: %v", statErr)
	}
}

func TestApplyUnitCrashSweepAndPreflight(t *testing.T) {
	redirectPaths(t)
	s := applySpec(t, RoleGermany, ComponentSplitter)
	live := unitLive(t, s)
	dead := live + ".tmp-999999999"
	writeRaw(t, dead, []byte("crashed"))
	foreign := live + ".tmp-abc"
	writeRaw(t, foreign, []byte("foreign"))
	m := newTestManager(&fakeExec{handler: okHandler})
	m.PidAlive = func(pid int) bool { return false }
	if _, err := ApplyUnit(context.Background(), m, s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Fatalf("dead candidate remains: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign candidate removed: %v", err)
	}

	redirectPaths(t)
	s = applySpec(t, RoleGermany, ComponentSplitter)
	live = unitLive(t, s)
	livePid := live + ".tmp-123"
	writeRaw(t, livePid, []byte("candidate"))
	m = newTestManager(&fakeExec{})
	m.PidAlive = func(pid int) bool { return pid == 123 }
	if _, err := ApplyUnit(context.Background(), m, s); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(livePid); err != nil {
		t.Fatalf("live candidate removed: %v", err)
	}

	redirectPaths(t)
	s = applySpec(t, RoleGermany, ComponentSplitter)
	live = unitLive(t, s)
	m = newTestManager(&fakeExec{})
	if err := os.Remove(envPath(RoleGermany)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if _, err := ApplyUnit(context.Background(), m, s); !errors.Is(err, ErrPreflight) {
		t.Fatalf("missing env error=%v", err)
	}
	if m.Ex.(*fakeExec).count() != 0 {
		t.Fatal("executor called on preflight failure")
	}
}
