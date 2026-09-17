package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

// ---------------------------------------------------------------------------
// Shared fakes
// ---------------------------------------------------------------------------

// recordingSystemdExec is the L2 fake systemctl: every argv line is
// recorded, canned "active" answers keep health probes happy, and
// failRestarts turns `systemctl restart` into a failure (the DEFECT-1
// restart-failure policy test). It is the same injected-executor seam the
// systemd package's tests use, through ServiceManager's public constructor.
type recordingSystemdExec struct {
	lines        []string
	failRestarts bool
}

func (f *recordingSystemdExec) Run(_ context.Context, args ...string) (string, error) {
	line := strings.Join(args, " ")
	if f.failRestarts && strings.HasPrefix(line, "systemctl restart") {
		f.lines = append(f.lines, line)
		return "", errors.New("systemctl: restart job failed")
	}
	f.lines = append(f.lines, line)
	if strings.HasPrefix(line, "systemctl is-active") {
		return "active", nil
	}
	return "", nil
}

func (f *recordingSystemdExec) restarts() []string {
	var out []string
	for _, l := range f.lines {
		if strings.HasPrefix(l, "systemctl restart ") {
			out = append(out, strings.TrimPrefix(l, "systemctl restart "))
		}
	}
	return out
}

// unitApplyFake answers the adapter's ApplyUnit seam. The unit-file bytes
// are deliberately reported UNCHANGED for every unit (the staging condition:
// only the projected Xray config rotated), so the restart must be driven by
// the config-bytes delta, not by the unit delta.
type unitApplyFake struct {
	calls []string
	err   error
}

func (f *unitApplyFake) ApplyUnit(_ context.Context, _ *systemd.ServiceManager, s systemd.Spec) (systemd.Result, error) {
	f.calls = append(f.calls, unitName(s))
	if f.err != nil {
		return systemd.Result{}, f.err
	}
	return systemd.Result{Unit: unitName(s), Unchanged: true}, nil
}

// germanyActivateFixture wires a LinuxAdapter for the Germany activate phase
// with every host boundary faked: keypair generation, the T3 activation
// (result injectable), ApplyUnit, and systemctl through the executor seam.
type germanyActivateFixture struct {
	adapter   *LinuxAdapter
	exec      *recordingSystemdExec
	applied   *unitApplyFake
	activate  *xray.ActivationResult
	activateN int
}

func newGermanyActivateFixture(t *testing.T, activationChanged bool) *germanyActivateFixture {
	t.Helper()
	request := renderSafeRequest(validGermanyRequest())
	exec := &recordingSystemdExec{}
	res := &xray.ActivationResult{LivePath: "unused", Changed: activationChanged}
	fx := &germanyActivateFixture{exec: exec, applied: &unitApplyFake{}, activate: res}
	adapter := &LinuxAdapter{
		Request:          request,
		Services:         systemd.NewServiceManager(exec),
		Firewall:         &firewallFake{},
		xrayBinary:       renderSafePath("xray"),
		convergeStateDir: func(context.Context) error { return nil },
		keypairFn: func(xray.Executor, string) (*xray.Keypair, error) {
			return &xray.Keypair{PrivateRaw: strings.Repeat("Q", 43), PublicRaw: strings.Repeat("W", 43)}, nil
		},
		activateConfigFn: func(xray.ActivateParams) (xray.ActivationResult, error) {
			fx.activateN++
			return *fx.activate, nil
		},
		unitApply: fx.applied,
	}
	// The activate phase consumes the validated unit plan; build it through
	// the authoritative planner exactly as Validate would.
	plan, err := BuildSystemdPlan(request)
	if err != nil {
		t.Fatalf("BuildSystemdPlan: %v", err)
	}
	adapter.units = plan.Specs
	fx.adapter = adapter
	return fx
}

// ---------------------------------------------------------------------------
// DEFECT 1 — a rotated Germany Xray config must restart xray-germany
// ---------------------------------------------------------------------------

// TestActivateRotatedConfigRestartsXray is the staging regression
// (2026-09-14/15): every Germany activation regenerates the Reality keypair
// and rewrites xray-germany.json, but the UNIT bytes stay identical, so
// ApplyUnit is a byte no-op and — before the fix — nothing restarted the
// live inbound. `pair apply` then derived Blob B from the on-disk config
// while the process still held the old keypair, and Blob B could never
// authenticate (manual `systemctl restart xray-germany` was required).
// With the fix, the real restart flows through the adapter's ServiceManager
// into the injected fake systemctl, so the recorded argv IS the production
// argv: exactly one restart of xray-germany.service, and none of the
// splitter units (their handling is unchanged — env-driven restarts only).
func TestActivateRotatedConfigRestartsXray(t *testing.T) {
	fx := newGermanyActivateFixture(t, true)
	if err := fx.adapter.Activate(context.Background(), DesiredState{Role: RoleGermany}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	got := fx.exec.restarts()
	want := []string{"xray-germany.service"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("restarts = %v, want exactly %v", got, want)
	}
	if fx.applied.calls == nil || len(fx.applied.calls) != 2 {
		t.Fatalf("ApplyUnit calls = %v, want both plan units applied", fx.applied.calls)
	}
}

// TestActivateUnchangedConfigDoesNotRestart proves the other half: the
// restart fires ONLY on a real config-bytes delta. The activation seam
// reports Changed=false (identical rendered bytes — the Reality renderer is
// deterministic, so a re-activation of the same keypair is a true no-op),
// the unit bytes are unchanged, and the env configuration identity did not
// move: zero restarts, no needless service disruption on every re-apply.
func TestActivateUnchangedConfigDoesNotRestart(t *testing.T) {
	fx := newGermanyActivateFixture(t, false)
	if err := fx.adapter.Activate(context.Background(), DesiredState{Role: RoleGermany}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if got := fx.exec.restarts(); len(got) != 0 {
		t.Fatalf("restarts = %v, want none for a byte-identical config and unchanged units", got)
	}
	// Sanity: the units were still converged (the apply happened; only the
	// restart was skipped).
	if len(fx.applied.calls) != 2 {
		t.Fatalf("ApplyUnit calls = %v, want 2", fx.applied.calls)
	}
}

// TestActivateXrayRestartFailureFollowsApplyErrorPolicy pins the third leg:
// a failing restart is an Activate-phase failure, wrapped with the SAME
// message shape the env-change restart uses, and propagates unwrapped-else-
// where (the transaction's fail() recovers the previous state and RETAINS
// the in-flight journal). The transaction-level leg drives a real
// ApplyDesired through the adapter's seams.
func TestActivateXrayRestartFailureFollowsApplyErrorPolicy(t *testing.T) {
	t.Run("activate returns wrapped restart error", func(t *testing.T) {
		fx := newGermanyActivateFixture(t, true)
		fx.exec.failRestarts = true
		err := fx.adapter.Activate(context.Background(), DesiredState{Role: RoleGermany})
		if err == nil {
			t.Fatal("restart failure swallowed")
		}
		if !strings.Contains(err.Error(), "restart xray-germany.service after configuration change") {
			t.Fatalf("error = %v, want the existing restart-after-configuration-change wrapping", err)
		}
	})

	t.Run("apply failure propagates unchanged", func(t *testing.T) {
		fx := newGermanyActivateFixture(t, true)
		sentinel := errors.New("apply boom")
		fx.applied.err = sentinel
		err := fx.adapter.Activate(context.Background(), DesiredState{Role: RoleGermany})
		if !errors.Is(err, sentinel) {
			t.Fatalf("error = %v, want the raw ApplyUnit failure propagated (existing policy)", err)
		}
	})

	t.Run("transaction recovers and retains journal", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		request := requestIn(t, store, renderSafeRequest(validGermanyRequest()))
		previous := testManifest(store.Root, RoleGermany)
		// The committed manifest records a configuration identity, so the
		// journal legitimately expects an env byte-mutation this transaction
		// owns (the env file does not exist on disk yet) and the failed
		// transaction must roll it back through the recovery seam.
		previous.ConfigFingerprint = "previous-configuration-identity"
		if err := store.Save(previous); err != nil {
			t.Fatal(err)
		}
		desired, err := request.Desired()
		if err != nil {
			t.Fatal(err)
		}
		// Make the plan non-trivially different so the transaction runs
		// (a component version bump), while the configuration identity
		// stays equal (both fingerprints empty → configChanged=false):
		// the restart must be driven purely by the config rotation.
		desired.Components.Splitter.Version = "v9.9.9"

		fx := newGermanyActivateFixture(t, true)
		fx.exec.failRestarts = true
		fx.adapter.Store = store
		fx.adapter.Request = request
		ops := &recoveryOpsFake{}
		fx.adapter.recoveryOps = ops

		// Wrap so the pure phases are no-ops and only activate runs the
		// LinuxAdapter logic under test (the same embedding idiom as
		// restoreTrackingAdapter in recovery_test.go).
		wrapped := &activateOnlyAdapter{inner: fx.adapter}
		result, err := ApplyDesired(context.Background(), store, previous, desired, wrapped)
		if !errors.Is(err, ErrRecovered) {
			t.Fatalf("error = %v, want a recovered transaction failure", err)
		}
		if result.Changed {
			t.Fatal("failed transaction must not report a change")
		}
		if !strings.Contains(err.Error(), "restart xray-germany.service after configuration change") {
			t.Fatalf("error = %v, must carry the restart cause", err)
		}
		// Ownership-scoped recovery ran: the env file is rolled back (the
		// journal recorded it as a creation this transaction owned).
		if ops.envRoll != 1 {
			t.Fatalf("env rollback = %d, want 1", ops.envRoll)
		}
		// No unit is rolled back here BY DESIGN of the ownership record: the
		// failing restart is the EXTRA restart of a byte-unchanged unit, so
		// the unit file was never mutated by this transaction and never made
		// it into the in-flight unit set — reverting it would touch state the
		// transaction does not own.
		if len(ops.removed) != 0 || len(ops.rolled) != 0 {
			t.Fatalf("unit rollback = removed %v rolled %v, want none (byte-unchanged unit failed on the extra restart)", ops.removed, ops.rolled)
		}
		// The journal is retained for the operator (crash evidence) — only
		// a successful commit clears it.
		if _, jerr := store.ReadJournal(); jerr != nil {
			t.Fatalf("journal must survive a failed transaction: %v", jerr)
		}
	})
}

// TestActivateRotatedConfigSettlesAfterRestart is the staging-regression
// regression (2026-09-15/16): the EXTRA configuration-change restart in
// applyUnit is an asynchronous `systemctl restart` (it returns once the job
// is enqueued). A crash-looping binary can present a transient
// "active (running)" that a single is-active poll reads before it dies, so
// the transaction committed with xray-germany FAILED. applyUnit must now
// settle (confirm stable-active, or catch the failure) BEFORE the phase
// reports success.
func TestActivateRotatedConfigSettlesAfterRestart(t *testing.T) {
	t.Run("settle runs for the rotated xray unit and is recorded", func(t *testing.T) {
		fx := newGermanyActivateFixture(t, true)
		var settled []string
		fx.adapter.restartSettle = func(_ context.Context, unit string, _ time.Duration) error {
			settled = append(settled, unit)
			return nil
		}
		if err := fx.adapter.Activate(context.Background(), DesiredState{Role: RoleGermany}); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		if strings.Join(settled, ",") != "xray-germany.service" {
			t.Fatalf("settled units = %v, want exactly [xray-germany.service] (only the rotated xray unit takes the extra restart)", settled)
		}
	})

	t.Run("settle failure fails the phase with the restart wrapping", func(t *testing.T) {
		fx := newGermanyActivateFixture(t, true)
		fx.adapter.restartSettle = func(context.Context, string, time.Duration) error {
			return errors.New("settle: unit failed after restart")
		}
		err := fx.adapter.Activate(context.Background(), DesiredState{Role: RoleGermany})
		if err == nil {
			t.Fatal("settle failure swallowed")
		}
		if !strings.Contains(err.Error(), "restart xray-germany.service after configuration change") {
			t.Fatalf("error = %v, want the restart-after-configuration-change wrapping", err)
		}
		if !strings.Contains(err.Error(), "settle: unit failed after restart") {
			t.Fatalf("error = %v, must carry the settle cause", err)
		}
	})
}

// activateOnlyAdapter delegates the DEFECT-1 phase (Activate) to the real
// LinuxAdapter logic and no-ops the host-gated phases, so the activate →
// restart → recover policy runs cross-platform through fakes.
type activateOnlyAdapter struct {
	inner *LinuxAdapter
}

func (a *activateOnlyAdapter) Prepare(context.Context, DesiredState) error    { return nil }
func (a *activateOnlyAdapter) Validate(context.Context, DesiredState) error   { return nil }
func (a *activateOnlyAdapter) Backup(context.Context, *Manifest) error        { return nil }
func (a *activateOnlyAdapter) Transition(context.Context, DesiredState) error { return nil }
func (a *activateOnlyAdapter) Health(context.Context, DesiredState) error     { return nil }
func (a *activateOnlyAdapter) Activate(ctx context.Context, d DesiredState) error {
	return a.inner.Activate(ctx, d)
}
func (a *activateOnlyAdapter) Restore(ctx context.Context, m Manifest) error {
	return a.inner.Restore(ctx, m)
}
func (a *activateOnlyAdapter) CleanupFresh(context.Context, DesiredState) error { return nil }
func (a *activateOnlyAdapter) RecoverJournal(context.Context, ArtifactJournal, Manifest) error {
	return nil
}
func (a *activateOnlyAdapter) Uninstall(context.Context, Manifest) error { return nil }

// ---------------------------------------------------------------------------
// DEFECT 2 — the state dir must converge at the start of every non-read-only
// lifecycle command, even when the plan converges to a no-op
// ---------------------------------------------------------------------------

// convergeCounter is a StateDirConverger test adapter (plus the Adapter
// surface, embedded through adapterFake) recording convergence calls.
type convergeCounter struct {
	adapterFake
	calls int
	dir   string // optional real-FS emulation target
}

func (c *convergeCounter) ConvergeStateDir(context.Context) error {
	c.calls++
	if c.dir != "" {
		// Emulate EnsureStateDir's effect (mode 0750) on a real tree so the
		// regression also proves the drifted directory is healed by the
		// lifecycle entry. The real chown/chmod convergence against
		// /etc/split-tunnel is Linux+root territory and covered by
		// internal/systemd's perms_test.go (TestPermissionChainConvergence).
		return os.Chmod(c.dir, 0o750)
	}
	return nil
}

// TestNoOpConvergenceStillConvergesStateDir is the DEFECT-2 regression at
// the transaction level: a converged no-op install returns from
// Transaction.Apply BEFORE any adapter phase runs — but the state-dir
// convergence must still execute first, or a drifted 0700 /etc/split-tunnel
// (which T3's 0600 activation writes can leave behind) permanently locks
// the User=split-tunnel services out of their 0640 configs after a restart.
// Install AND upgrade are covered by running both against an identical
// desired state (true no-op plans).
func TestNoOpConvergenceStillConvergesStateDir(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fresh   bool
		role    string
		request func() InstallRequest
	}{
		{"no-op install (upgrade onto identical state)", false, RoleGermany, validGermanyRequest},
		{"no-op re-apply (identical committed state)", false, RoleIran, validIranRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewStore(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			request := requestIn(t, store, tc.request())
			desired, err := request.Desired()
			if err != nil {
				t.Fatal(err)
			}
			fake := &convergeCounter{}
			first, err := ApplyDesired(context.Background(), store, Manifest{}, desired, fake)
			if err != nil {
				t.Fatalf("first apply: %v", err)
			}
			if !first.Changed {
				t.Fatal("first apply must install")
			}
			fake.calls = 0
			fake.adapterFake = adapterFake{}
			second, err := ApplyDesired(context.Background(), store, first.Manifest, desired, fake)
			if err != nil {
				t.Fatalf("no-op apply: %v", err)
			}
			if second.Changed || !second.Plan.Unchanged {
				t.Fatalf("second apply not a no-op: %+v", second)
			}
			if fake.calls != 1 {
				t.Fatalf("state-dir convergence calls during a no-op = %d, want exactly 1", fake.calls)
			}
			// The no-op must still run NO other adapter phase (the early
			// return stays intact — only the entry convergence was added).
			if len(fake.adapterFake.calls) != 0 {
				t.Fatalf("no-op ran adapter phases: %v", fake.adapterFake.calls)
			}
		})
	}
}

// TestNoOpConvergenceHealsDriftedDirRealFS runs the same wiring against a
// REAL temporary tree whose directory starts drifted at 0700: the lifecycle
// entry converges it even though the plan is a no-op. (On non-Linux hosts
// the directory mode cannot be observed faithfully, so the strong
// before/after assertion is gated; the call-count regression above is the
// cross-platform core.)
func TestNoOpConvergenceHealsDriftedDirRealFS(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	request := requestIn(t, store, validIranRequest())
	desired, err := request.Desired()
	if err != nil {
		t.Fatal(err)
	}
	fake := &convergeCounter{dir: dir}
	if _, err := ApplyDesired(context.Background(), store, Manifest{}, desired, fake); err != nil {
		t.Fatalf("install: %v", err)
	}
	fake.calls = 0
	fake.adapterFake = adapterFake{}
	if _, err := ApplyDesired(context.Background(), store, testManifest(store.Root, RoleIran), desired, fake); err != nil {
		t.Fatalf("no-op: %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("converge calls = %d, want 1 on the no-op path", fake.calls)
	}
	if runtime.GOOS == "linux" {
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != 0o750 {
			t.Fatalf("drifted dir stayed %o after lifecycle entry, want 0750", got)
		}
	} else {
		t.Log("unix mode bits not observable on this host; call-count regression is asserted above")
	}
}

// TestLinuxAdapterLifecyclePathsConvergeStateDir pins the production
// adapter: install/upgrade go through ApplyDesired→Transaction.Converge;
// the recovery paths (Restore, RecoverJournal) — which do NOT run Prepare —
// converge at entry through the seam. Struct-literal adapters (every other
// test) keep a nil seam, so nothing here touches the real /etc.
func TestLinuxAdapterLifecyclePathsConvergeStateDir(t *testing.T) {
	t.Run("noop ApplyDesired through the real adapter logic", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		request := requestIn(t, store, validGermanyRequest())
		desired, err := request.Desired()
		if err != nil {
			t.Fatal(err)
		}
		// A committed manifest identical to the desired state → the plan
		// converges to a genuine no-op, so Transaction.Apply returns before
		// any adapter phase and only the lifecycle-entry convergence runs.
		previous := Manifest{
			Schema: SchemaVersion, Role: desired.Role, Generation: "g1",
			Components: desired.Components, Paths: desired.Paths,
			Pairing: desired.Pairing, Services: desired.Services,
			Firewall: desired.Firewall, ConfigFingerprint: desired.ConfigFingerprint,
		}
		calls := 0
		inner := &LinuxAdapter{Store: store, convergeStateDir: func(context.Context) error { calls++; return nil }}
		result, err := ApplyDesired(context.Background(), store, previous, desired, inner)
		if err != nil {
			t.Fatalf("no-op ApplyDesired: %v", err)
		}
		if !result.Plan.Unchanged {
			t.Fatalf("plan not a no-op: %+v", result.Plan)
		}
		if calls != 1 {
			t.Fatalf("converge calls = %d, want 1 on the real adapter's no-op path", calls)
		}
	})

	t.Run("RecoverJournal converges before touching units", func(t *testing.T) {
		journal := ArtifactJournal{Role: RoleGermany, Generation: "pending-9"}
		fx := newRecoveryFixture(t, RoleGermany, journal)
		fx.withValidRequest(t, RoleGermany)
		calls := 0
		fx.adapter.convergeStateDir = func(context.Context) error { calls++; return nil }
		previous := testManifest(fx.store.Root, RoleGermany)
		previous.Generation = "g1"
		if err := fx.adapter.RecoverJournal(context.Background(), journal, previous); err != nil {
			t.Fatalf("RecoverJournal: %v", err)
		}
		if calls != 1 {
			t.Fatalf("converge calls = %d, want 1 at recovery entry", calls)
		}
	})

	t.Run("Restore converges before reverting units", func(t *testing.T) {
		journal := ArtifactJournal{Role: RoleGermany, Generation: "pending-9"}
		fx := newRecoveryFixture(t, RoleGermany, journal)
		fx.withValidRequest(t, RoleGermany)
		calls := 0
		fx.adapter.convergeStateDir = func(context.Context) error { calls++; return nil }
		previous := testManifest(fx.store.Root, RoleGermany)
		previous.Generation = "g1"
		if err := fx.adapter.Restore(context.Background(), previous); err != nil {
			t.Fatalf("Restore: %v", err)
		}
		if calls != 1 {
			t.Fatalf("converge calls = %d, want 1 at restore entry", calls)
		}
	})

	t.Run("convergence failure aborts the lifecycle command", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		request := requestIn(t, store, validGermanyRequest())
		desired, err := request.Desired()
		if err != nil {
			t.Fatal(err)
		}
		wantErr := errors.New("chmod /etc/split-tunnel: boom")
		inner := &LinuxAdapter{Store: store, convergeStateDir: func(context.Context) error { return wantErr }}
		_, err = ApplyDesired(context.Background(), store, testManifest(store.Root, RoleGermany), desired, inner)
		if !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want the converge failure to fail the command closed", err)
		}
		if !strings.Contains(err.Error(), "converge state dir") {
			t.Fatalf("error = %v, want the converge wrap", err)
		}
	})
}

// ---------------------------------------------------------------------------
// DEFECT 2 (doctor) — a read-only check flags state-dir drift
// ---------------------------------------------------------------------------

func TestStateDirCheckPassesOnAbsentOrClean(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nothing")
	f := StateDirCheck(missing).Run(context.Background())
	if f.Severity != SeverityPass || f.ID != "state.dir" {
		t.Fatalf("absent dir finding = %+v, want pass", f)
	}
}

func TestBuildStateDirFindingSeverityPolicy(t *testing.T) {
	// The staging trap: drifted dir + a live service-readable config inside
	// → FAIL with the remediation action.
	trap := systemd.StateDirAudit{
		Path: "/etc/split-tunnel", Exists: true, Linux: true, Mode: 0o700, Uid: 0, GID: 0,
		GroupWant: 999, GroupKnown: true, WantDir: 0o750, WantFile: 0o640,
		Configs: []systemd.ConfigAudit{{Path: "/etc/split-tunnel/xray-germany.json", Mode: 0o640, Uid: 0, GID: 0}},
	}
	problems := trap.Problems()
	if len(problems) == 0 {
		t.Fatal("0700 dir with a live config must produce problems")
	}
	f := buildStateDirFinding(trap, nil)
	if f.Severity != SeverityFail {
		t.Fatalf("trap finding = %+v, want fail", f)
	}
	if !strings.Contains(f.Summary, "mode is 0700, want 0750") {
		t.Fatalf("summary = %q, must name the mode delta", f.Summary)
	}
	if !strings.Contains(f.Action, "re-converges the state dir") || !strings.Contains(f.Action, "read-only") {
		t.Fatalf("action = %q, must carry the suggested remediation and the read-only guarantee", f.Action)
	}

	// Drift with NO live config (fresh/copied tree) → WARN, same action.
	noConfig := systemd.StateDirAudit{
		Path: "/tmp/copied-state", Exists: true, Linux: true, Mode: 0o700, Uid: 1000, GID: 1000,
		GroupWant: 999, GroupKnown: true, WantDir: 0o750, WantFile: 0o640,
	}
	f = buildStateDirFinding(noConfig, nil)
	if f.Severity != SeverityWarn {
		t.Fatalf("configless drift = %+v, want warn", f)
	}
	if f.Action == "" {
		t.Fatal("warn finding must still carry the remediation action")
	}

	// Clean state → PASS.
	clean := systemd.StateDirAudit{
		Path: "/etc/split-tunnel", Exists: true, Linux: true, Mode: 0o750, Uid: 0, GID: 999,
		GroupWant: 999, GroupKnown: true, WantDir: 0o750, WantFile: 0o640,
		Configs: []systemd.ConfigAudit{{Path: "/etc/split-tunnel/xray-germany.json", Mode: 0o640, Uid: 0, GID: 999}},
	}
	f = buildStateDirFinding(clean, nil)
	if f.Severity != SeverityPass {
		t.Fatalf("clean finding = %+v, want pass", f)
	}

	// Audit error → FAIL closed.
	f = buildStateDirFinding(systemd.StateDirAudit{}, fmt.Errorf("stat: boom"))
	if f.Severity != SeverityFail || !strings.Contains(f.Summary, "audit failed") {
		t.Fatalf("error finding = %+v, want fail", f)
	}
}

// TestStateDirCheckIsReadOnly documents and proves the doctor READ-ONLY
// guarantee: the check inspects a drifted tree and reports, but the tree is
// byte-for-byte and mode-for-mode IDENTICAL afterwards — no chmod, no
// chown, no write, no create, no remove. Remediation happens only through a
// lifecycle command (ConvergeStateDir above). This is the "no
// state-changing call is made" assertion, taken against the real
// filesystem the check reads.
func TestStateDirCheckIsReadOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "xray-germany.json")
	payload := []byte("{}\n")
	if err := os.WriteFile(config, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	type entry struct {
		path string
		mode os.FileMode
		data string
	}
	snapshot := func() []entry {
		var out []entry
		st, err := os.Lstat(root)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, entry{root, st.Mode().Perm(), ""})
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, de := range entries {
			p := filepath.Join(root, de.Name())
			pst, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			data := ""
			if !pst.IsDir() {
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(b)
				data = hex.EncodeToString(sum[:])
			}
			out = append(out, entry{p, pst.Mode().Perm(), data})
		}
		return out
	}
	render := func(es []entry) string {
		var b strings.Builder
		for _, e := range es {
			fmt.Fprintf(&b, "%s|%o|%s\n", filepath.Base(e.path), e.mode, e.data)
		}
		return b.String()
	}

	before := render(snapshot())
	f := StateDirCheck(root).Run(context.Background())
	after := render(snapshot())

	if before != after {
		t.Fatalf("doctor check MUTATED the state dir:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// The check still REPORTS something (pass on non-Linux where the unix
	// bits are not observable; drift on Linux), with the documented action
	// whenever drift exists.
	if f.ID != "state.dir" {
		t.Fatalf("finding id = %q", f.ID)
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 && f.Severity == SeverityPass {
		t.Log("linux non-root: t.TempDir facts vary by umask; reporting a finding is informational")
	}
}

// ---------------------------------------------------------------------------
// DEFECT 2 (live drift) — install must heal a managed object that drifted
// since the last commit, while a clean host keeps the zero-PID-churn no-op
// ---------------------------------------------------------------------------

// liveAuditFake is an Adapter fake that implements the optional LiveAuditor
// capability: it reports a scripted drift verdict (or a scripted read error)
// and counts the audit calls, so the transaction-level policy (drift → full
// apply, clean → no-op, error → fail closed) is pinned without a host.
type liveAuditFake struct {
	adapterFake
	drift bool
	err   error
	calls int
}

func (f *liveAuditFake) AuditLiveDrift(context.Context) (bool, error) {
	f.calls++
	return f.drift, f.err
}

// manifestFromDesired builds a committed manifest that is field-identical to
// the desired state except for the generation, so PlanDesired plans a genuine
// no-op and the ONLY thing that can drive a mutation is the live audit.
func manifestFromDesired(d DesiredState, generation string) Manifest {
	return Manifest{
		Schema: SchemaVersion, Role: d.Role, Generation: generation,
		Components: d.Components, Paths: d.Paths,
		Pairing: d.Pairing, Services: d.Services,
		Firewall: d.Firewall, ConfigFingerprint: d.ConfigFingerprint,
	}
}

// TestNoOpInstallAuditsLiveDrift is the transaction-level DEFECT-2
// regression: a plan that converges to a no-op is NOT trusted until the
// adapter's live audit has said the managed objects match the commit. The
// staging defect was the opposite trust direction — the commit alone was
// trusted, so a live unit file edited out-of-band (or a removed binary)
// survived `install germany` as "already converged (no changes)" rc=0.
func TestNoOpInstallAuditsLiveDrift(t *testing.T) {
	newCase := func() (*Store, DesiredState, Manifest) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		request := requestIn(t, store, validGermanyRequest())
		desired, err := request.Desired()
		if err != nil {
			t.Fatal(err)
		}
		previous := manifestFromDesired(desired, "g1")
		if _, err := store.Commit(previous, "install"); err != nil {
			t.Fatal(err)
		}
		return store, desired, previous
	}

	t.Run("drifted live state forces the full apply", func(t *testing.T) {
		store, desired, previous := newCase()
		fake := &liveAuditFake{drift: true}
		result, err := ApplyDesired(context.Background(), store, previous, desired, fake)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if !result.Changed || !result.Plan.Unchanged {
			t.Fatalf("result = %+v, want a committed drift-heal on an unchanged plan", result)
		}
		if result.Manifest.Generation == "g1" {
			t.Fatal("drift-heal must commit a new generation (the healed state is recorded)")
		}
		if fake.calls != 1 {
			t.Fatalf("audit calls = %d, want exactly 1 (the audit runs only on the no-op plan)", fake.calls)
		}
		if strings.Join(fake.adapterFake.calls, ",") != "prepare,validate,backup,activate,transition,health" {
			t.Fatalf("drifted no-op ran phases %v, want the full apply sequence", fake.adapterFake.calls)
		}
		if _, err := store.ReadJournal(); !os.IsNotExist(err) {
			t.Fatalf("journal after successful heal = %v, want cleared", err)
		}
	})

	t.Run("clean live state keeps the zero-churn no-op", func(t *testing.T) {
		store, desired, previous := newCase()
		fake := &liveAuditFake{drift: false}
		result, err := ApplyDesired(context.Background(), store, previous, desired, fake)
		if err != nil {
			t.Fatalf("no-op apply: %v", err)
		}
		if result.Changed || !result.Plan.Unchanged {
			t.Fatalf("result = %+v, want an uncommitted no-op", result)
		}
		if result.Manifest.Generation != "g1" {
			t.Fatalf("no-op committed generation %q, want g1 untouched", result.Manifest.Generation)
		}
		if fake.calls != 1 {
			t.Fatalf("audit calls = %d, want exactly 1 (the no-op path must still audit)", fake.calls)
		}
		if len(fake.adapterFake.calls) != 0 {
			t.Fatalf("clean no-op ran adapter phases: %v, want zero (the af86f12 guarantee)", fake.adapterFake.calls)
		}
		if _, err := store.ReadJournal(); !os.IsNotExist(err) {
			t.Fatalf("journal after clean no-op = %v, want none written", err)
		}
	})

	t.Run("audit error fails closed before any mutation", func(t *testing.T) {
		store, desired, previous := newCase()
		fake := &liveAuditFake{err: errors.New("audit: stat failed")}
		_, err := ApplyDesired(context.Background(), store, previous, desired, fake)
		if err == nil || !strings.Contains(err.Error(), "audit live drift") {
			t.Fatalf("error = %v, want the fail-closed audit wrap", err)
		}
		if len(fake.adapterFake.calls) != 0 {
			t.Fatalf("audit failure ran adapter phases: %v, want zero", fake.adapterFake.calls)
		}
		if _, jerr := store.ReadJournal(); !os.IsNotExist(jerr) {
			t.Fatalf("journal after audit failure = %v, want none written (fail before the journal)", jerr)
		}
	})

	t.Run("adapter without the audit capability keeps the plain no-op", func(t *testing.T) {
		store, desired, previous := newCase()
		fake := &adapterFake{}
		result, err := ApplyDesired(context.Background(), store, previous, desired, fake)
		if err != nil {
			t.Fatalf("no-op apply: %v", err)
		}
		if result.Changed || len(fake.calls) != 0 {
			t.Fatalf("result = %+v calls = %v, want the unchallenged no-op (nil seam)", result, fake.calls)
		}
	})
}

// auditCoreFixture wires the real auditLiveDriftCore against a temp tree: a
// committed Germany manifest whose unit files, managed binary, and xray
// pointer all live under temp paths. The manifest's recorded paths are the
// test redirects — exactly the trust boundary the audit uses (it stats the
// paths the COMMIT recorded, not the canonical constants).
type auditCoreFixture struct {
	inner       *LinuxAdapter
	store       *Store
	unitDir     string
	binDir      string
	pointer     string
	liveXray    string
	liveSplit   string
	renderXray  []byte
	renderSplit []byte
}

func newAuditCoreFixture(t *testing.T) *auditCoreFixture {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	fx := &auditCoreFixture{store: store}
	fx.unitDir = t.TempDir()
	fx.binDir = t.TempDir()
	fx.pointer = filepath.Join(t.TempDir(), "xray", "current")
	withManagedPrefix(t, fx.binDir)

	request := requestIn(t, store, renderSafeRequest(validGermanyRequest()))
	desired, err := request.Desired()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildSystemdPlan(request)
	if err != nil {
		t.Fatal(err)
	}
	// plan.Specs is [xray, splitter] for Germany; the rendered bytes of the
	// apply-ready spec are exactly the bytes the committed hash covers.
	data, err := systemd.RenderUnit(applyReadySpec(plan.Specs[0]))
	if err != nil {
		t.Fatal(err)
	}
	fx.renderXray = data
	data, err = systemd.RenderUnit(applyReadySpec(plan.Specs[1]))
	if err != nil {
		t.Fatal(err)
	}
	fx.renderSplit = data
	fx.liveXray = filepath.Join(fx.unitDir, "xray-germany.service")
	fx.liveSplit = filepath.Join(fx.unitDir, "germany-splitter.service")

	previous := manifestFromDesired(desired, "g1")
	previous.Paths.UnitFiles = []string{fx.liveXray, fx.liveSplit}
	previous.Paths.BinaryPointer = fx.pointer
	if _, err := store.Commit(previous, "install"); err != nil {
		t.Fatal(err)
	}

	inner := &LinuxAdapter{Store: store}
	inner.liveAudit = inner.auditLiveDriftCore
	fx.inner = inner
	return fx
}

// writeClean makes every managed object match the commit: unit bytes equal
// the committed render, the managed binary is regular 0755, the xray pointer
// is a directory.
func (fx *auditCoreFixture) writeClean(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(fx.liveXray, fx.renderXray, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fx.liveSplit, fx.renderSplit, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.binDir, "germany-splitter"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fx.pointer, 0o755); err != nil {
		t.Fatal(err)
	}
}

func (fx *auditCoreFixture) audit(t *testing.T) (bool, error) {
	t.Helper()
	drifted, err := fx.inner.AuditLiveDrift(context.Background())
	if err != nil {
		t.Fatalf("AuditLiveDrift: %v", err)
	}
	return drifted, nil
}

// TestAuditLiveDriftCoreClassifiesManagedDrift pins the production audit's
// read-only classification of the MANAGED objects only: committed unit bytes
// vs the committed render, managed binary presence/mode, and (Germany) the
// xray pointer. Non-managed paths are never consulted.
func TestAuditLiveDriftCoreClassifiesManagedDrift(t *testing.T) {
	t.Run("no committed manifest reports no drift", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		inner := &LinuxAdapter{Store: store}
		inner.liveAudit = inner.auditLiveDriftCore
		drifted, err := inner.AuditLiveDrift(context.Background())
		if err != nil || drifted {
			t.Fatalf("fresh host audit = (%v, %v), want (false, nil)", drifted, err)
		}
	})

	t.Run("manifest without services reports no drift", func(t *testing.T) {
		store, err := NewStore(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		m := Manifest{Schema: SchemaVersion, Role: RoleGermany, Generation: "g1", Paths: Paths{StateRoot: store.Root}}
		if _, err := store.Commit(m, "install"); err != nil {
			t.Fatal(err)
		}
		inner := &LinuxAdapter{Store: store}
		inner.liveAudit = inner.auditLiveDriftCore
		drifted, err := inner.AuditLiveDrift(context.Background())
		if err != nil || drifted {
			t.Fatalf("serviceless manifest audit = (%v, %v), want (false, nil)", drifted, err)
		}
	})

	fx := newAuditCoreFixture(t)

	t.Run("clean managed objects report no drift", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("unix mode bits not observable on this host (the binary 0755 check)")
		}
		fx.writeClean(t)
		drifted, _ := fx.audit(t)
		if drifted {
			t.Fatal("clean tree classified as drifted")
		}
	})

	t.Run("drifted unit bytes are drift", func(t *testing.T) {
		fx.writeClean(t)
		tampered := append(append([]byte{}, fx.renderSplit...), []byte("# tampered out-of-band\n")...)
		if err := os.WriteFile(fx.liveSplit, tampered, 0o644); err != nil {
			t.Fatal(err)
		}
		// Read-only proof: the audit must not touch the tree it reads.
		snap := func() string {
			var b strings.Builder
			for _, dir := range []string{fx.unitDir, fx.binDir} {
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					p := filepath.Join(dir, e.Name())
					st, err := os.Lstat(p)
					if err != nil {
						t.Fatal(err)
					}
					h := ""
					if st.Mode().IsRegular() {
						data, err := os.ReadFile(p)
						if err != nil {
							t.Fatal(err)
						}
						sum := sha256.Sum256(data)
						h = hex.EncodeToString(sum[:])
					}
					fmt.Fprintf(&b, "%s|%v|%s\n", p, st.Mode(), h)
				}
			}
			return b.String()
		}
		before := snap()
		drifted, _ := fx.audit(t)
		if !drifted {
			t.Fatal("tampered unit bytes not classified as drift")
		}
		if after := snap(); after != before {
			t.Fatal("the audit MUTATED the managed tree it reads")
		}
	})

	t.Run("absent committed unit is drift", func(t *testing.T) {
		fx.writeClean(t)
		if err := os.Remove(fx.liveXray); err != nil {
			t.Fatal(err)
		}
		drifted, _ := fx.audit(t)
		if !drifted {
			t.Fatal("absent committed unit not classified as drift")
		}
	})

	t.Run("symlinked unit is drift", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires developer mode; Linux CI is authoritative")
		}
		fx.writeClean(t)
		if err := os.Remove(fx.liveSplit); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(fx.unitDir, "nowhere"), fx.liveSplit); err != nil {
			t.Fatal(err)
		}
		drifted, _ := fx.audit(t)
		if !drifted {
			t.Fatal("planted symlink where a committed unit must be not classified as drift")
		}
	})

	t.Run("absent managed binary is drift", func(t *testing.T) {
		fx.writeClean(t)
		if err := os.Remove(filepath.Join(fx.binDir, "germany-splitter")); err != nil {
			t.Fatal(err)
		}
		drifted, _ := fx.audit(t)
		if !drifted {
			t.Fatal("absent managed binary not classified as drift")
		}
	})

	t.Run("mode-drifted managed binary is drift", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("unix mode bits not observable on this host")
		}
		fx.writeClean(t)
		if err := os.Chmod(filepath.Join(fx.binDir, "germany-splitter"), 0o700); err != nil {
			t.Fatal(err)
		}
		drifted, _ := fx.audit(t)
		if !drifted {
			t.Fatal("0700 managed binary not classified as drift")
		}
	})

	t.Run("absent xray pointer is drift", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("unix mode bits not observable on this host (the binary 0755 check would mask the pointer case)")
		}
		fx.writeClean(t)
		if err := os.Remove(fx.pointer); err != nil {
			t.Fatal(err)
		}
		drifted, _ := fx.audit(t)
		if !drifted {
			t.Fatal("absent xray pointer not classified as drift")
		}
	})

	t.Run("non-directory xray pointer is drift", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("unix mode bits not observable on this host (the binary 0755 check would mask the pointer case)")
		}
		fx.writeClean(t)
		if err := os.Remove(fx.pointer); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fx.pointer, []byte("not a dir"), 0o644); err != nil {
			t.Fatal(err)
		}
		drifted, _ := fx.audit(t)
		if !drifted {
			t.Fatal("regular-file xray pointer not classified as drift")
		}
	})
}

// writingUnitApplyFake is the activate-phase ApplyUnit seam for the heal
// test: it records the applied unit and WRITES the rendered spec bytes to
// the fixture's live unit path, so the test can assert the heal actually
// landed on disk. It reports Unchanged (the adapter-level extra-restart
// channel stays off; a real T5 swap restarts inside ApplyUnit, which this
// fake stands in for).
type writingUnitApplyFake struct {
	calls []string
	live  map[string]string
}

func (f *writingUnitApplyFake) ApplyUnit(_ context.Context, _ *systemd.ServiceManager, s systemd.Spec) (systemd.Result, error) {
	name := unitName(s)
	f.calls = append(f.calls, name)
	data, err := systemd.RenderUnit(s)
	if err != nil {
		return systemd.Result{}, err
	}
	if path, ok := f.live[name]; ok {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return systemd.Result{}, err
		}
	}
	return systemd.Result{Unit: name, Unchanged: true}, nil
}

// healAuditAdapter is the activateOnlyAdapter plus the LiveAuditor
// capability, so the REAL audit seam (wired to auditLiveDriftCore on the
// inner adapter) is what the transaction consults — the production wiring,
// not a scripted verdict.
type healAuditAdapter struct {
	activateOnlyAdapter
}

func (a *healAuditAdapter) AuditLiveDrift(ctx context.Context) (bool, error) {
	return a.inner.AuditLiveDrift(ctx)
}

// TestInstallHealsDriftedLiveUnit is the end-to-end staging regression: the
// committed state is a no-op against the request, but the LIVE unit file
// diverges (the post-crash / out-of-band-edit shape). The transaction must
// detect the drift through the live audit, fall through to the full apply,
// re-write the drifted unit to the committed render, and commit a new
// generation — instead of reporting "already converged" rc=0.
func TestInstallHealsDriftedLiveUnit(t *testing.T) {
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
	pointer := filepath.Join(t.TempDir(), "xray", "current")

	// The committed state: identical to the request (a no-op plan) with its
	// recorded unit/pointer paths redirected at the temp tree, and the live
	// objects in place — with the SPLITTER unit drifted out-of-band. Both
	// desired and the commit are redirected so the plan stays a genuine
	// no-op while the audit core reaches the planted tree through the
	// committed (recorded) paths.
	desired.Paths.UnitFiles = []string{liveXray, liveSplit}
	desired.Paths.BinaryPointer = pointer
	previous := manifestFromDesired(desired, "g1")
	if _, err := store.Commit(previous, "install"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(liveXray, renderXray, 0o644); err != nil {
		t.Fatal(err)
	}
	tampered := append(append([]byte{}, renderSplit...), []byte("# tampered out-of-band\n")...)
	if err := os.WriteFile(liveSplit, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "germany-splitter"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pointer, 0o755); err != nil {
		t.Fatal(err)
	}

	exec := &recordingSystemdExec{}
	applyFake := &writingUnitApplyFake{live: map[string]string{
		"xray-germany.service":     liveXray,
		"germany-splitter.service": liveSplit,
	}}
	inner := &LinuxAdapter{
		Request:          request,
		Store:            store,
		Services:         systemd.NewServiceManager(exec),
		Firewall:         &firewallFake{},
		convergeStateDir: func(context.Context) error { return nil },
		keypairFn: func(xray.Executor, string) (*xray.Keypair, error) {
			return &xray.Keypair{PrivateRaw: strings.Repeat("Q", 43), PublicRaw: strings.Repeat("W", 43)}, nil
		},
		activateConfigFn: func(xray.ActivateParams) (xray.ActivationResult, error) {
			// No keypair rotation: the heal is driven by the unit drift alone.
			return xray.ActivationResult{LivePath: "unused", Changed: false}, nil
		},
		unitApply: applyFake,
	}
	inner.units = plan.Specs
	inner.liveAudit = inner.auditLiveDriftCore
	adapter := &healAuditAdapter{activateOnlyAdapter{inner: inner}}

	tx := Transaction{
		Store: store,
		Journal: ArtifactJournal{
			Role:       RoleGermany,
			Generation: "pending-heal",
			Units:      []string{"germany-splitter.service", "xray-germany.service"},
			PreUnits:   []string{"germany-splitter.service", "xray-germany.service"},
		},
		Previous:  previous,
		Desired:   desired,
		AuditLive: adapter.AuditLiveDrift,
		Recover:   func(ctx context.Context, old Manifest) error { return adapter.Restore(ctx, old) },
		Steps: []Step{
			{Phase: PhasePreflight, Name: "prepare", Run: func(context.Context) error { return nil }},
			{Phase: PhaseValidate, Name: "validate", Run: func(context.Context) error { return nil }},
			{Phase: PhaseBackup, Name: "backup", Run: func(context.Context) error { return nil }},
			{Phase: PhaseActivate, Name: "activate", Run: func(stepCtx context.Context) error {
				return adapter.Activate(stepCtx, desired)
			}},
			{Phase: PhaseTransition, Name: "transition", Run: func(context.Context) error { return nil }},
			{Phase: PhaseHealth, Name: "health", Run: func(context.Context) error { return nil }},
		},
	}

	result, err := tx.Apply(context.Background())
	if err != nil {
		t.Fatalf("drift-heal apply: %v", err)
	}
	if !result.Changed || !result.Plan.Unchanged {
		t.Fatalf("result = %+v, want a committed heal of an unchanged plan", result)
	}
	if result.Manifest.Generation == "g1" {
		t.Fatal("heal must commit a new generation")
	}
	if strings.Join(applyFake.calls, ",") != "xray-germany.service,germany-splitter.service" {
		t.Fatalf("applied units = %v, want both units through the normal apply semantics", applyFake.calls)
	}
	// The heal landed on disk: the drifted unit now equals the committed
	// render, and the already-clean unit is byte-identical.
	got, err := os.ReadFile(liveSplit)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(renderSplit) {
		t.Fatal("drifted unit was not re-written to the committed render")
	}
	got, err = os.ReadFile(liveXray)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(renderXray) {
		t.Fatal("clean unit bytes changed during the heal")
	}
	// The journal is cleared only by the commit.
	if _, err := store.ReadJournal(); !os.IsNotExist(err) {
		t.Fatalf("journal after successful heal = %v, want cleared", err)
	}
	// The adapter-level extra-restart channel stayed off (no config change,
	// no keypair rotation): zero systemctl calls reach the executor. The
	// swap-internal restart of a changed unit lives inside T5's ApplyUnit,
	// which this test fakes by design.
	if len(exec.lines) != 0 {
		t.Fatalf("heal issued systemctl calls %v, want none at the adapter level", exec.lines)
	}
}
