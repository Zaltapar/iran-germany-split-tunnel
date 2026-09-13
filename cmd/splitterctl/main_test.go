package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/deploy"
)

// recoverAdapterFake satisfies deploy.Adapter for the CLI tests. It records
// RecoverJournal calls and can block until the recovery context is done (to
// prove the CLI's timeout is applied) or fail.
type recoverAdapterFake struct {
	recoverCalls      int
	blockUntilCtxDone bool
	err               error
}

func (f *recoverAdapterFake) Prepare(context.Context, deploy.DesiredState) error  { return nil }
func (f *recoverAdapterFake) Validate(context.Context, deploy.DesiredState) error { return nil }
func (f *recoverAdapterFake) Backup(context.Context, *deploy.Manifest) error      { return nil }
func (f *recoverAdapterFake) Activate(context.Context, deploy.DesiredState) error { return nil }
func (f *recoverAdapterFake) Transition(context.Context, deploy.DesiredState) error {
	return nil
}
func (f *recoverAdapterFake) Health(context.Context, deploy.DesiredState) error { return nil }
func (f *recoverAdapterFake) Restore(context.Context, deploy.Manifest) error    { return nil }
func (f *recoverAdapterFake) CleanupFresh(context.Context, deploy.DesiredState) error {
	return nil
}
func (f *recoverAdapterFake) Uninstall(context.Context, deploy.Manifest) error { return nil }
func (f *recoverAdapterFake) RecoverJournal(ctx context.Context, _ deploy.ArtifactJournal, _ deploy.Manifest) error {
	f.recoverCalls++
	if f.blockUntilCtxDone {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.err
}

// stubRecoverController substitutes newRecoverController with a controller
// backed by the fake adapter, restoring the production constructor on
// cleanup.
func stubRecoverController(store *deploy.Store, fake *recoverAdapterFake) func() {
	old := newRecoverController
	newRecoverController = func(*deploy.Store, deploy.ArtifactJournal) (*deploy.Controller, error) {
		return &deploy.Controller{Store: store, Adapter: fake}, nil
	}
	return func() { newRecoverController = old }
}

func TestRunHelp(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"help"}, &out, &out); err != nil {
		t.Fatalf("run help: %v", err)
	}
	if !strings.Contains(out.String(), "usage: splitterctl") {
		t.Fatalf("help output = %q", out.String())
	}
}
func TestRunUnknownCommand(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	var out bytes.Buffer
	err := run(context.Background(), []string{"nope"}, &out, &out)
	if !errors.Is(err, errUsage) {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestRunMutationParsersRejectMalformedArguments(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	cases := [][]string{
		{"install"}, {"install", "france"},
		{"pair"}, {"pair", "exchange"},
		{"upgrade", "--unknown"}, {"upgrade", "--xray", "--origin"},
		{"rollback"}, {"rollback", "--to"}, {"rollback", "--to", "../escape"},
		{"uninstall", "--force"}, {"recover", "--bogus"},
		{"config"}, {"config", "delete"},
	}
	for _, args := range cases {
		var out bytes.Buffer
		err := run(context.Background(), args, &out, &out)
		if !errors.Is(err, errUsage) {
			t.Errorf("%v: error = %v, want usage error", args, err)
		}
	}
}

// withLinux forces the mutation commands' platform gate to pass on any
// host (restored after the test); the gate itself is covered by
// TestMutatingCommandsRequireLinux.
func withLinux(t *testing.T) {
	t.Helper()
	old := goos
	goos = "linux"
	t.Cleanup(func() { goos = old })
}

// withCanonicalRoot points the mutation commands' canonical state root at a
// temporary directory (restored after the test).
func withCanonicalRoot(t *testing.T, root string) {
	t.Helper()
	old := canonicalStateRoot
	canonicalStateRoot = root
	t.Cleanup(func() { canonicalStateRoot = old })
}

func TestMutatingCommandsRequireLinux(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	old := goos
	goos = "windows"
	t.Cleanup(func() { goos = old })
	for _, args := range [][]string{
		{"install", "iran"}, {"install", "germany"},
		{"rollback", "--to", "state-1"},
		{"uninstall"}, {"uninstall", "--purge"},
		{"recover"}, {"recover", "--ack"},
	} {
		var out bytes.Buffer
		err := run(context.Background(), args, &out, &out)
		if err == nil || !strings.Contains(err.Error(), "requires Linux") {
			t.Errorf("%v: error = %v, want Linux requirement error", args, err)
		}
	}
}

func TestRollbackUninstallAndRecoverWithoutState(t *testing.T) {
	withLinux(t)
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	withCanonicalRoot(t, t.TempDir())

	var out bytes.Buffer
	err := run(context.Background(), []string{"rollback", "--to", "state-1"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "rollback: nothing installed") {
		t.Fatalf("rollback: error = %v, want not-installed error", err)
	}
	out.Reset()
	err = run(context.Background(), []string{"uninstall"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "uninstall: nothing installed") {
		t.Fatalf("uninstall: error = %v, want not-installed error", err)
	}
	out.Reset()
	if err := run(context.Background(), []string{"recover"}, &out, &out); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !strings.Contains(out.String(), "no in-flight journal") {
		t.Fatalf("recover output = %q", out.String())
	}
}

// TestInstallFailsClosedOnMissingEnv pins the field-only error contract:
// with no host touched, install reports the first missing environment
// variable by name (never a value).
func TestInstallFailsClosedOnMissingEnv(t *testing.T) {
	withLinux(t)
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	// A valid role config so the first failure is the splitter artifact
	// variables, not the shared secret.
	t.Setenv("SPLIT_SECRET", strings.Repeat("a", 64))
	t.Setenv("SPLIT_UP_WS_URL", "wss://upload.example.com/upload")

	var out bytes.Buffer
	err := run(context.Background(), []string{"install", "germany"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "SPLITTERCTL_SPLITTER_BIN must be set to an absolute path") {
		t.Fatalf("error = %v, want missing splitter bin error", err)
	}

	t.Setenv("SPLITTERCTL_SPLITTER_BIN", filepath.Join(t.TempDir(), "splitter"))
	t.Setenv("SPLITTERCTL_SPLITTER_VERSION", "v1.0.0")
	out.Reset()
	err = run(context.Background(), []string{"install", "germany"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "Germany requires SPLITTERCTL_REALITY_SNI") {
		t.Fatalf("error = %v, want missing Reality parameters error", err)
	}
}

// TestRecoverExecutesRecovery covers the post-crash recovery loop: `recover`
// (no --ack) EXECUTES journal-driven recovery and clears the journal; a second
// recover reports nothing in flight; `--ack` with no journal is an error.
func TestRecoverExecutesRecovery(t *testing.T) {
	withLinux(t)
	root := t.TempDir()
	withCanonicalRoot(t, root)
	t.Setenv("SPLITTERCTL_STATE_ROOT", root)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	journal := deploy.ArtifactJournal{
		Role:       deploy.RoleGermany,
		Generation: "pending-1",
		Units:      []string{"germany-splitter.service"},
	}
	if err := store.WriteJournal(journal); err != nil {
		t.Fatal(err)
	}

	// Substitute a controller backed by the fake adapter (the recovery
	// EXECUTION is covered exhaustively in internal/deploy; here we pin the
	// CLI wiring: recover without --ack must build a controller and invoke
	// Recover, then clear the journal).
	fake := &recoverAdapterFake{}
	restore := stubRecoverController(store, fake)
	defer restore()

	var out bytes.Buffer
	if err := run(context.Background(), []string{"recover"}, &out, &out); err != nil {
		t.Fatalf("recover: %v", err)
	}
	got := out.String()
	for _, want := range []string{"in-flight journal:", "role: germany", "generation: pending-1", "germany-splitter.service", "recovered; journal cleared"} {
		if !strings.Contains(got, want) {
			t.Errorf("recover output %q does not contain %q", got, want)
		}
	}
	if fake.recoverCalls != 1 {
		t.Fatalf("RecoverJournal calls = %d, want 1", fake.recoverCalls)
	}
	if _, err := store.ReadJournal(); !os.IsNotExist(err) {
		t.Fatalf("journal not cleared after recovery: %v", err)
	}

	// A second recover finds nothing in flight and mutates nothing.
	out.Reset()
	if err := run(context.Background(), []string{"recover"}, &out, &out); err != nil {
		t.Fatalf("second recover: %v", err)
	}
	if !strings.Contains(out.String(), "no in-flight journal") {
		t.Fatalf("second recover output = %q", out.String())
	}

	// --ack with no journal is an explicit operator error.
	out.Reset()
	err = run(context.Background(), []string{"recover", "--ack"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "no in-flight journal to acknowledge") {
		t.Fatalf("error = %v, want no-journal ack error", err)
	}
}

// TestRecoverAckForceClearsWithoutRecovery pins the --ack escape hatch: it
// clears the journal WITHOUT building an adapter or touching the host.
func TestRecoverAckForceClearsWithoutRecovery(t *testing.T) {
	withLinux(t)
	root := t.TempDir()
	withCanonicalRoot(t, root)
	t.Setenv("SPLITTERCTL_STATE_ROOT", root)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteJournal(deploy.ArtifactJournal{Role: deploy.RoleGermany, Generation: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	fake := &recoverAdapterFake{}
	restore := stubRecoverController(store, fake)
	defer restore()

	var out bytes.Buffer
	if err := run(context.Background(), []string{"recover", "--ack"}, &out, &out); err != nil {
		t.Fatalf("recover --ack: %v", err)
	}
	if !strings.Contains(out.String(), "journal cleared without host changes") {
		t.Fatalf("ack output = %q", out.String())
	}
	if fake.recoverCalls != 0 {
		t.Fatalf("--ack must not execute recovery (calls = %d)", fake.recoverCalls)
	}
	if _, err := store.ReadJournal(); !os.IsNotExist(err) {
		t.Fatalf("journal not cleared: %v", err)
	}
}

// TestRecoverFailsClosedOnRecoveryError asserts a failing recovery surfaces a
// wrapped error and RETAINS the journal.
func TestRecoverFailsClosedOnRecoveryError(t *testing.T) {
	withLinux(t)
	root := t.TempDir()
	withCanonicalRoot(t, root)
	t.Setenv("SPLITTERCTL_STATE_ROOT", root)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteJournal(deploy.ArtifactJournal{Role: deploy.RoleIran, Generation: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	fake := &recoverAdapterFake{err: errors.New("injected")}
	restore := stubRecoverController(store, fake)
	defer restore()

	var out bytes.Buffer
	err = run(context.Background(), []string{"recover"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "recover:") {
		t.Fatalf("error = %v, want a wrapped recover error", err)
	}
	if _, jerr := store.ReadJournal(); jerr != nil {
		t.Fatalf("journal must be retained after a failed recovery: %v", jerr)
	}
}

// TestRecoverBoundedByTimeout asserts the CLI applies a context timeout to
// recovery (a blocked recovery must not hang the operator).
func TestRecoverBoundedByTimeout(t *testing.T) {
	withLinux(t)
	root := t.TempDir()
	withCanonicalRoot(t, root)
	t.Setenv("SPLITTERCTL_STATE_ROOT", root)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteJournal(deploy.ArtifactJournal{Role: deploy.RoleIran, Generation: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	// A recovery that blocks until its context is done must return promptly
	// with a context error — proving the CLI passed a bounded context.
	fake := &recoverAdapterFake{blockUntilCtxDone: true}
	restore := stubRecoverController(store, fake)
	defer restore()
	old := recoverTimeout
	recoverTimeout = 50 * time.Millisecond
	defer func() { recoverTimeout = old }()

	var out bytes.Buffer
	err = run(context.Background(), []string{"recover"}, &out, &out)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestRunPairRequiresPersistedState(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	for _, args := range [][]string{{"pair", "generate"}, {"pair", "apply"}, {"pair", "finalize"}} {
		var out bytes.Buffer
		err := run(context.Background(), args, &out, &out)
		if err == nil || !strings.Contains(err.Error(), "pair: load deployment state") {
			t.Errorf("%v: error = %v, want missing-state error", args, err)
		}
	}
}

func TestRunReadOnlyCommandsRejectArguments(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	for _, args := range [][]string{{"status", "extra"}, {"doctor", "--verbose"}} {
		var out bytes.Buffer
		err := run(context.Background(), args, &out, &out)
		if !errors.Is(err, errUsage) {
			t.Errorf("%v: error = %v, want usage error", args, err)
		}
	}
}

func TestStatusMissingState(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SPLITTERCTL_STATE_ROOT", filepath.Join(root, "state"))
	var out bytes.Buffer
	if err := run(context.Background(), []string{"status"}, &out, &out); err != nil {
		t.Fatalf("status: %v", err)
	}
	if got := out.String(); got != "status: not installed\n" {
		t.Fatalf("status output = %q", got)
	}
}

func TestStatusAndDoctorValidState(t *testing.T) {
	root := t.TempDir()
	store, err := deploy.NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(deploy.Manifest{
		Role:       deploy.RoleGermany,
		Generation: "g-test",
		Paths:      deploy.Paths{StateRoot: store.Root},
		Firewall:   deploy.FirewallState{Backend: "none"},
	}, "test")
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Setenv("SPLITTERCTL_STATE_ROOT", store.Root)

	var statusOut bytes.Buffer
	if err := run(context.Background(), []string{"status"}, &statusOut, &statusOut); err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{"role: germany", "generation: g-test", "firewall: none"} {
		if !strings.Contains(statusOut.String(), want) {
			t.Errorf("status output %q does not contain %q", statusOut.String(), want)
		}
	}

	var doctorOut bytes.Buffer
	if err := run(context.Background(), []string{"doctor"}, &doctorOut, &doctorOut); err != nil {
		t.Fatalf("doctor: %v; output=%q", err, doctorOut.String())
	}
	if !strings.Contains(doctorOut.String(), "state.integrity [pass]") {
		t.Fatalf("doctor output = %q", doctorOut.String())
	}
}

func TestConfigShowIsRedacted(t *testing.T) {
	root := t.TempDir()
	store, err := deploy.NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(deploy.Manifest{
		Role:       deploy.RoleIran,
		Generation: "i-config",
		Paths: deploy.Paths{
			StateRoot: store.Root,
			Env:       "/etc/split-tunnel/iran.env",
			Config:    "/etc/split-tunnel/secret-config.json",
		},
		Components: deploy.Components{
			Splitter: deploy.ComponentState{Version: "v1", Path: "/opt/split-tunnel/splitter", SHA256: "splitter-hash"},
			Origin:   deploy.OriginState{Mode: "caddy", Domain: "upload.example.com"},
		},
		Pairing:  deploy.PairingState{State: "finalized", Fingerprints: []string{"secret-fingerprint"}},
		Firewall: deploy.FirewallState{Backend: "ufw", RulesHash: "rules-hash"},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPLITTERCTL_STATE_ROOT", store.Root)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"config", "show"}, &out, &out); err != nil {
		t.Fatalf("config show: %v", err)
	}
	got := out.String()
	for _, want := range []string{"role: iran", "origin.mode: caddy", "origin.domain: upload.example.com", "pairing.state: finalized"} {
		if !strings.Contains(got, want) {
			t.Errorf("config output %q does not contain %q", got, want)
		}
	}
	for _, forbidden := range []string{"secret-fingerprint", "secret-config.json", "splitter-hash", "rules-hash", "stateRoot", "manifestHash"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("config output leaked %q: %q", forbidden, got)
		}
	}
}

func TestDoctorFailsClosedOnTamperedState(t *testing.T) {
	root := t.TempDir()
	store, err := deploy.NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(deploy.Manifest{
		Role:       deploy.RoleIran,
		Generation: "i-test",
		Paths:      deploy.Paths{StateRoot: store.Root},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(store.Root, "state.json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"role": "iran"`), []byte(`"role": "germany"`), 1)
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPLITTERCTL_STATE_ROOT", store.Root)

	var out bytes.Buffer
	err = run(context.Background(), []string{"doctor"}, &out, &out)
	if err == nil {
		t.Fatal("doctor unexpectedly succeeded")
	}
	if !strings.Contains(out.String(), "state.integrity [fail]") {
		t.Fatalf("doctor output = %q", out.String())
	}
}

func TestMutatingCommandsReportNotWired(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	for _, args := range [][]string{{"upgrade"}, {"upgrade", "--xray"}, {"config", "set"}} {
		var out bytes.Buffer
		err := run(context.Background(), args, &out, &out)
		if !errors.Is(err, errNotWired) {
			t.Errorf("%v: error = %v, want not wired", args, err)
		}
	}
}
