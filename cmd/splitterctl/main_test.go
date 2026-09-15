package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/deploy"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
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

// commitRole commits a minimal manifest for role so the ack role check has a
// committed role to compare against.
func commitRole(t *testing.T, store *deploy.Store, role string) {
	t.Helper()
	if _, err := store.Commit(deploy.Manifest{
		Role:       role,
		Generation: "g-committed",
		Paths:      deploy.Paths{StateRoot: store.Root},
		Firewall:   deploy.FirewallState{Backend: "none"},
	}, "test"); err != nil {
		t.Fatal(err)
	}
}

// TestRecoverAckRefusesRoleMismatch is the DEFECT-4 regression: when the
// committed manifest role CONTRADICTS the in-flight journal role, --ack must
// refuse and RETAIN the journal (fail closed) rather than silently unblock
// mutations on a possibly-inconsistent host.
func TestRecoverAckRefusesRoleMismatch(t *testing.T) {
	withLinux(t)
	root := t.TempDir()
	withCanonicalRoot(t, root)
	t.Setenv("SPLITTERCTL_STATE_ROOT", root)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	commitRole(t, store, deploy.RoleGermany)
	if err := store.WriteJournal(deploy.ArtifactJournal{Role: deploy.RoleIran, Generation: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = run(context.Background(), []string{"recover", "--ack"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "refusing --ack") {
		t.Fatalf("error = %v, want an ack refusal", err)
	}
	if _, jerr := store.ReadJournal(); jerr != nil {
		t.Fatalf("journal must be retained after a refused ack: %v", jerr)
	}
}

// TestRecoverAckAllowedWhenRolesAgree asserts --ack still clears the journal
// when the committed role matches the journal role.
func TestRecoverAckAllowedWhenRolesAgree(t *testing.T) {
	withLinux(t)
	root := t.TempDir()
	withCanonicalRoot(t, root)
	t.Setenv("SPLITTERCTL_STATE_ROOT", root)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	commitRole(t, store, deploy.RoleGermany)
	if err := store.WriteJournal(deploy.ArtifactJournal{Role: deploy.RoleGermany, Generation: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"recover", "--ack"}, &out, &out); err != nil {
		t.Fatalf("recover --ack: %v", err)
	}
	if _, jerr := store.ReadJournal(); !os.IsNotExist(jerr) {
		t.Fatalf("journal not cleared: %v", jerr)
	}
}

// TestRecoverAckRefusesUnreadableCommittedState asserts --ack fails closed when
// the committed manifest exists but cannot be trusted: a non-os.ErrNotExist
// Load error (here ErrTampered) means the committed state cannot prove the
// roles agree, so --ack must refuse and RETAIN the journal. The roles in this
// test AGREE, so only the fail-closed-on-unreadable rule can refuse the ack.
func TestRecoverAckRefusesUnreadableCommittedState(t *testing.T) {
	withLinux(t)
	root := t.TempDir()
	withCanonicalRoot(t, root)
	t.Setenv("SPLITTERCTL_STATE_ROOT", root)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	commitRole(t, store, deploy.RoleGermany)
	if err := store.WriteJournal(deploy.ArtifactJournal{Role: deploy.RoleGermany, Generation: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	// Tamper the committed manifest so Load returns ErrTampered (the stored
	// hash no longer matches) rather than os.ErrNotExist.
	statePath := filepath.Join(store.Root, "state.json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-2] ^= 1
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err = run(context.Background(), []string{"recover", "--ack"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "refusing --ack") {
		t.Fatalf("error = %v, want an ack refusal on unreadable committed state", err)
	}
	if _, jerr := store.ReadJournal(); jerr != nil {
		t.Fatalf("journal must be retained after a refused ack: %v", jerr)
	}
}

// TestRecoverAckAllowedWithNoManifest asserts --ack clears the journal when no
// committed manifest exists (a crashed fresh install has nothing to contradict).
func TestRecoverAckAllowedWithNoManifest(t *testing.T) {
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
	var out bytes.Buffer
	if err := run(context.Background(), []string{"recover", "--ack"}, &out, &out); err != nil {
		t.Fatalf("recover --ack: %v", err)
	}
	if _, jerr := store.ReadJournal(); !os.IsNotExist(jerr) {
		t.Fatalf("journal not cleared: %v", jerr)
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

// ---------------------------------------------------------------------------
// pair generate / apply / finalize (CLI wiring of the two-blob exchange)
// ---------------------------------------------------------------------------

// fixedPrivateRawTest is the documented fixed non-production X25519 test
// vector (internal/xray keygen_test.go); it is a TEST vector, not a deployed
// key, and the pairing tests below only ever prove that Blob B carries the
// public key DERIVED from it.
const fixedPrivateRawTest = "gAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHkA"

const cliInstalledSNI = "www.example.org"
const cliInstalledShortID = "0123456789abcdef"
const cliInstalledUUID = "550e8400-e29b-41d4-a716-446655440000"
const cliDownHost = "203.0.113.10"

// writeInstalledGermanyConfig renders a realistic Germany Xray config through
// the authoritative generator into its own temp dir and returns the path.
func writeInstalledGermanyConfig(t *testing.T) string {
	t.Helper()
	out, err := xray.RenderGermanyConfig(
		xray.RealityParams{SNI: cliInstalledSNI, ShortID: cliInstalledShortID, UUID: cliInstalledUUID},
		&xray.Keypair{PrivateRaw: fixedPrivateRawTest, PublicRaw: strings.Repeat("A", 43)},
	)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xray-germany.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// commitPairingManifest commits a minimal manifest for one role, optionally
// carrying a pre-set pairing state, and returns its store.
func commitPairingManifest(t *testing.T, role string, configPath string, pairingState deploy.PairingState) *deploy.Store {
	t.Helper()
	root := t.TempDir()
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(deploy.Manifest{
		Role:       role,
		Generation: "g-pair",
		Paths:      deploy.Paths{StateRoot: store.Root, Config: configPath},
		Pairing:    pairingState,
		Firewall:   deploy.FirewallState{Backend: "none"},
	}, "test"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPLITTERCTL_STATE_ROOT", store.Root)
	return store
}

// blobFileFor writes an encoded blob to an absolute temp path and sets the
// SPLITTERCTL_PAIR_BLOB_FILE contract variable.
func blobFileFor(t *testing.T, encoded string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blob.in")
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPLITTERCTL_PAIR_BLOB_FILE", path)
	return path
}

// generateBlobAForTest produces a valid Blob A through the deploy boundary.
func generateBlobAForTest(t *testing.T, secret string) string {
	t.Helper()
	encoded, _, err := (deploy.Pairing{}).GenerateA(secret, "upload.example.org")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestPairApplyGermanyEmitsReturnBlob is the CLI half of the fixed gap:
// generate→apply(emits B)→finalize, plus the idempotent re-apply that re-
// emits the SAME Blob B from the installed reality params.
func TestPairApplyGermanyEmitsReturnBlob(t *testing.T) {
	configPath := writeInstalledGermanyConfig(t)
	store := commitPairingManifest(t, deploy.RoleGermany, configPath, deploy.PairingState{State: deploy.PairingStateNone})
	secret := strings.Repeat("a", 64)
	blobA := generateBlobAForTest(t, secret)
	blobFileFor(t, blobA)
	t.Setenv("SPLITTERCTL_PAIR_DOWN_HOST", cliDownHost)

	outPath := filepath.Join(t.TempDir(), "blob-b.out")
	t.Setenv("SPLITTERCTL_PAIR_BLOB_OUT", outPath)

	var out bytes.Buffer
	if err := run(context.Background(), []string{"pair", "apply"}, &out, &out); err != nil {
		t.Fatalf("pair apply (germany): %v", err)
	}
	first := out.String()
	blobB := lastLine(t, first)
	parsed, err := pairing.ParseBlobB(blobB)
	if err != nil {
		t.Fatalf("emitted blob B must parse: %v", err)
	}
	if parsed.Germany.Host != cliDownHost || parsed.Germany.Port != 443 {
		t.Fatalf("down target = %+v", parsed.Germany)
	}
	if parsed.Public.SNI != cliInstalledSNI || parsed.Public.ShortID != cliInstalledShortID || parsed.Public.UUID != cliInstalledUUID {
		t.Fatalf("public params = %+v", parsed.Public)
	}
	installed, err := xray.ReadInstalledRealityParams(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Public.RealityPublicKey != installed.RealityPublicKey {
		t.Fatal("Blob B must carry the public key DERIVED from the installed private key")
	}

	// Non-display relay: the same blob, written 0600 to the absolute path.
	rawOut, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(rawOut)) != blobB {
		t.Fatal("SPLITTERCTL_PAIR_BLOB_OUT content differs from stdout blob")
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(outPath); err != nil {
			t.Fatal(err)
		} else if st.Mode().Perm() != 0o600 {
			t.Fatalf("blob-out mode = %v, want -rw-------", st.Mode().Perm())
		}
	}

	// A re-apply (Blob B was lost) re-emits the IDENTICAL blob.
	out.Reset()
	if err := run(context.Background(), []string{"pair", "apply"}, &out, &out); err != nil {
		t.Fatalf("pair apply re-run: %v", err)
	}
	if again := lastLine(t, out.String()); again != blobB {
		t.Fatal("re-apply must emit the same Blob B deterministically")
	}

	// Committed state: a-applied with exactly two fingerprints, never raw
	// blobs or the tunnel secret.
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Pairing.State != "a-applied" || loaded.Pairing.PeerRole != deploy.RoleIran || len(loaded.Pairing.Fingerprints) != 2 {
		t.Fatalf("pairing state = %+v", loaded.Pairing)
	}
	stateData, err := os.ReadFile(filepath.Join(store.Root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	// stdout contract: the Germany apply echoes Blob B exactly once and never
	// Blob A (which carries the tunnel secret) or any private material.
	if n := strings.Count(first, "splat-v1."); n != 1 {
		t.Fatalf("stdout contains %d blobs, want exactly 1 (the return blob)", n)
	}
	for _, forbidden := range []string{blobA, secret, fixedPrivateRawTest} {
		if strings.Contains(first, forbidden) {
			t.Fatalf("stdout leaked %q", forbidden)
		}
	}
	// Persisted state contract: fingerprints only — no raw blob or key/secret
	// material anywhere in state.json.
	for _, forbidden := range []string{blobA, blobB, secret, fixedPrivateRawTest} {
		if strings.Contains(string(stateData), forbidden) {
			t.Fatalf("committed state contains raw material %q", forbidden)
		}
	}
}

// TestPairHappyPathGenerateApplyFinalize runs the complete documented flow
// across two role state roots: Iran generate → Germany apply (emits B) →
// Iran finalize (consumes B).
func TestPairHappyPathGenerateApplyFinalize(t *testing.T) {
	secret := strings.Repeat("d", 64)

	// Iran: pair generate emits Blob A (last stdout line) and commits
	// a-generated with one fingerprint.
	iranStore := commitPairingManifest(t, deploy.RoleIran, "", deploy.PairingState{State: deploy.PairingStateNone})
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPLITTERCTL_SECRET_FILE", secretPath)
	t.Setenv("SPLITTERCTL_UPLOAD_DOMAIN", "upload.example.org")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"pair", "generate"}, &out, &out); err != nil {
		t.Fatalf("pair generate: %v", err)
	}
	blobA := lastLine(t, out.String())
	if _, err := pairing.ParseBlobA(blobA); err != nil {
		t.Fatalf("generated blob A must parse: %v", err)
	}
	iranState, err := iranStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if iranState.Pairing.State != "a-generated" || len(iranState.Pairing.Fingerprints) != 1 {
		t.Fatalf("iran state = %+v", iranState.Pairing)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatal("generate leaked the secret outside the blob")
	}

	// Germany: pair apply consumes Blob A and emits Blob B.
	configPath := writeInstalledGermanyConfig(t)
	commitPairingManifest(t, deploy.RoleGermany, configPath, deploy.PairingState{State: deploy.PairingStateNone})
	blobFileFor(t, blobA)
	t.Setenv("SPLITTERCTL_PAIR_DOWN_HOST", cliDownHost)
	out.Reset()
	if err := run(context.Background(), []string{"pair", "apply"}, &out, &out); err != nil {
		t.Fatalf("pair apply: %v", err)
	}
	blobB := lastLine(t, out.String())
	if _, err := pairing.ParseBlobB(blobB); err != nil {
		t.Fatalf("emitted blob B must parse: %v", err)
	}

	// Iran: pair finalize consumes Blob B and commits finalized. finalize
	// emits NO blob of its own (stdout carries only the summary).
	commitPairingManifest(t, deploy.RoleIran, "", iranState.Pairing)
	blobFileFor(t, blobB)
	out.Reset()
	if err := run(context.Background(), []string{"pair", "finalize"}, &out, &out); err != nil {
		t.Fatalf("pair finalize: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "pairing: finalized") {
		t.Fatalf("finalize output = %q", got)
	}
	if strings.Contains(got, "splat-v1.") {
		t.Fatalf("finalize must not emit a blob: %q", got)
	}
}

// TestPairApplyGermanyIdempotentAfterBlobLost covers the staging failure mode
// fixed here: Germany had already committed a-applied (old binary) but Blob B
// never reached Iran; re-running apply with the new binary must re-emit B.
func TestPairApplyGermanyIdempotentAfterBlobLost(t *testing.T) {
	configPath := writeInstalledGermanyConfig(t)
	secret := strings.Repeat("e", 64)
	blobA := generateBlobAForTest(t, secret)
	store := commitPairingManifest(t, deploy.RoleGermany, configPath, deploy.PairingState{
		PeerRole: deploy.RoleIran, State: "a-applied", Fingerprints: []string{"legacy-fingerprint"},
	})
	blobFileFor(t, blobA)
	t.Setenv("SPLITTERCTL_PAIR_DOWN_HOST", cliDownHost)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"pair", "apply"}, &out, &out); err != nil {
		t.Fatalf("re-apply from a-applied must succeed: %v", err)
	}
	blobB := lastLine(t, out.String())
	if _, err := pairing.ParseBlobB(blobB); err != nil {
		t.Fatalf("re-emitted blob B must parse: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Pairing.State != "a-applied" || len(loaded.Pairing.Fingerprints) != 2 {
		t.Fatalf("pairing state = %+v", loaded.Pairing)
	}
}

// TestPairRoleAndStateGates pins the preserved security semantics: wrong-role
// rejection on both hosts, terminal-state rejection, finalize with Blob A,
// and the config-path precondition.
func TestPairRoleAndStateGates(t *testing.T) {
	secret := strings.Repeat("f", 64)
	blobA := generateBlobAForTest(t, secret)

	cases := []struct {
		name    string
		role    string
		action  []string
		state   deploy.PairingState
		input   string
		wantMsg string
	}{
		{"iran rejects apply", deploy.RoleIran, []string{"pair", "apply"}, deploy.PairingState{State: deploy.PairingStateNone}, blobA, "Iran accepts only pair finalize"},
		{"germany rejects finalize", deploy.RoleGermany, []string{"pair", "finalize"}, deploy.PairingState{State: deploy.PairingStateNone}, blobA, "Germany accepts only pair apply"},
		{"germany rejects generate", deploy.RoleGermany, []string{"pair", "generate"}, deploy.PairingState{State: deploy.PairingStateNone}, "", "generate is currently supported on Iran"},
		{"apply after finalized rejected", deploy.RoleGermany, []string{"pair", "apply"}, deploy.PairingState{PeerRole: deploy.RoleIran, State: "finalized"}, blobA, "only valid before or after a-applied"},
		{"apply without config path", deploy.RoleGermany, []string{"pair", "apply"}, deploy.PairingState{State: deploy.PairingStateNone}, blobA, "records no Xray config path"},
	}
	for _, tc := range cases {
		if tc.wantMsg == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			configPath := ""
			if tc.role == deploy.RoleGermany && tc.name != "apply without config path" {
				configPath = writeInstalledGermanyConfig(t)
			}
			commitPairingManifest(t, tc.role, configPath, tc.state)
			if tc.input != "" {
				blobFileFor(t, tc.input)
			}
			t.Setenv("SPLITTERCTL_PAIR_DOWN_HOST", cliDownHost)
			var out bytes.Buffer
			err := run(context.Background(), tc.action, &out, &out)
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %v, want %q", err, tc.wantMsg)
			}
			if strings.Contains(err.Error(), blobA) {
				t.Fatalf("error echoed blob content: %v", err)
			}
		})
	}

	// Iran generate without a role-2 manifest is exercised above; confirm the
	// positive counterpart works so the gate is role-based, not global.
	store := commitPairingManifest(t, deploy.RoleIran, "", deploy.PairingState{State: deploy.PairingStateNone})
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPLITTERCTL_SECRET_FILE", secretPath)
	t.Setenv("SPLITTERCTL_UPLOAD_DOMAIN", "upload.example.org")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"pair", "generate"}, &out, &out); err != nil {
		t.Fatalf("iran generate: %v", err)
	}
	if _, err := pairing.ParseBlobA(lastLine(t, out.String())); err != nil {
		t.Fatal(err)
	}
	if s, _ := store.Load(); s.Pairing.State != "a-generated" {
		t.Fatalf("state = %+v", s.Pairing)
	}
}

// TestPairFinalizeRejectsBlobA pins the wrong-blob boundary on Iran: Blob A
// fails the pairing role check with a sentinel, echoing no content.
func TestPairFinalizeRejectsBlobA(t *testing.T) {
	commitPairingManifest(t, deploy.RoleIran, "", deploy.PairingState{State: "a-generated"})
	blobA := generateBlobAForTest(t, strings.Repeat("7", 64))
	blobFileFor(t, blobA)
	var out bytes.Buffer
	err := run(context.Background(), []string{"pair", "finalize"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "role mismatch") {
		t.Fatalf("error = %v, want pairing role mismatch", err)
	}
	if strings.Contains(err.Error(), blobA) {
		t.Fatalf("error echoed blob content: %v", err)
	}
}

// TestPairBlobOutMustBeAbsolute pins the relay-path contract: a relative
// SPLITTERCTL_PAIR_BLOB_OUT is refused BEFORE the state commit happens.
func TestPairBlobOutMustBeAbsolute(t *testing.T) {
	configPath := writeInstalledGermanyConfig(t)
	store := commitPairingManifest(t, deploy.RoleGermany, configPath, deploy.PairingState{State: deploy.PairingStateNone})
	blobFileFor(t, generateBlobAForTest(t, strings.Repeat("8", 64)))
	t.Setenv("SPLITTERCTL_PAIR_DOWN_HOST", cliDownHost)
	t.Setenv("SPLITTERCTL_PAIR_BLOB_OUT", "relative/blob.out")
	var out bytes.Buffer
	err := run(context.Background(), []string{"pair", "apply"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "must be an absolute path") {
		t.Fatalf("error = %v, want absolute-path refusal", err)
	}
	loaded, lerr := store.Load()
	if lerr != nil {
		t.Fatal(lerr)
	}
	if loaded.Pairing.State != deploy.PairingStateNone {
		t.Fatalf("refused apply mutated pairing state: %+v", loaded.Pairing)
	}
}

// TestPairDownHostFailureNamesFieldOnly pins the error hygiene for the Blob B
// target: a bad host is rejected by the pairing validator naming the FIELD,
// and nothing about the value (or the blob) reaches the error.
func TestPairDownHostFailureNamesFieldOnly(t *testing.T) {
	configPath := writeInstalledGermanyConfig(t)
	store := commitPairingManifest(t, deploy.RoleGermany, configPath, deploy.PairingState{State: deploy.PairingStateNone})
	blobFileFor(t, generateBlobAForTest(t, strings.Repeat("9", 64)))
	t.Setenv("SPLITTERCTL_PAIR_DOWN_HOST", "bad host!")
	var out bytes.Buffer
	err := run(context.Background(), []string{"pair", "apply"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "germany.host") {
		t.Fatalf("error = %v, want the germany.host field named", err)
	}
	if strings.Contains(err.Error(), "bad host") {
		t.Fatalf("error echoed the invalid value: %v", err)
	}
	loaded, lerr := store.Load()
	if lerr != nil {
		t.Fatal(lerr)
	}
	if loaded.Pairing.State != deploy.PairingStateNone {
		t.Fatalf("failed apply must not commit: %+v", loaded.Pairing)
	}
}

// lastLine returns the final non-empty line of a command's output (the
// emitted blob, by the documented output contract).
func lastLine(t *testing.T, output string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
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

// ---------------------------------------------------------------------------
// config set / upgrade (T8 M5)
// ---------------------------------------------------------------------------

// mutationFake is the adapter fake the config/upgrade tests substitute for the
// production adapter. It records the desired state it was handed, so the tests
// can assert the COMMAND's request (the overridden configuration) reached the
// adapter through the controller's transaction — not just that some code ran.
type mutationFake struct {
	calls   []string
	desired []deploy.DesiredState
}

func (f *mutationFake) record(name string, d deploy.DesiredState) error {
	f.calls = append(f.calls, name)
	f.desired = append(f.desired, d)
	return nil
}
func (f *mutationFake) Prepare(_ context.Context, d deploy.DesiredState) error {
	return f.record("prepare", d)
}
func (f *mutationFake) Validate(_ context.Context, d deploy.DesiredState) error {
	return f.record("validate", d)
}
func (f *mutationFake) Backup(context.Context, *deploy.Manifest) error { return nil }
func (f *mutationFake) Activate(_ context.Context, d deploy.DesiredState) error {
	return f.record("activate", d)
}
func (f *mutationFake) Transition(_ context.Context, d deploy.DesiredState) error {
	return f.record("transition", d)
}
func (f *mutationFake) Health(_ context.Context, d deploy.DesiredState) error {
	return f.record("health", d)
}
func (f *mutationFake) Restore(context.Context, deploy.Manifest) error { return nil }
func (f *mutationFake) CleanupFresh(context.Context, deploy.DesiredState) error {
	return nil
}
func (f *mutationFake) RecoverJournal(context.Context, deploy.ArtifactJournal, deploy.Manifest) error {
	return nil
}
func (f *mutationFake) Uninstall(context.Context, deploy.Manifest) error { return nil }

// stubMutationController substitutes the mutation-controller constructor with
// one backed by the fake adapter (restored on cleanup). Production wiring is
// unchanged: it composes the same controller from the same request.
func stubMutationController(store *deploy.Store, fake *mutationFake) func() {
	old := newMutationController
	newMutationController = func(*deploy.Store, deploy.InstallRequest) (*deploy.Controller, error) {
		return &deploy.Controller{Store: store, Adapter: fake}, nil
	}
	return func() { newMutationController = old }
}

// withMutationEnv provides the complete mutation environment contract for a
// role, pointed at temporary directories so the request builder can be
// exercised off a Linux host (canonicalStateRoot/canonicalBinaryPrefix are
// redirected to the same temporary tree, so the request paths are absolute and
// consistent — exactly as they are on Linux).
func withMutationEnv(t *testing.T, role string) string {
	t.Helper()
	root := t.TempDir()
	prefix := filepath.Join(root, "opt")
	withCanonicalRoot(t, root)
	oldPrefix := canonicalBinaryPrefix
	canonicalBinaryPrefix = prefix
	t.Cleanup(func() { canonicalBinaryPrefix = oldPrefix })
	// The read-only commands resolve their store from SPLITTERCTL_STATE_ROOT;
	// point it at the same temporary root the mutation commands use (in
	// production both are the canonical /etc/split-tunnel).
	t.Setenv("SPLITTERCTL_STATE_ROOT", root)

	t.Setenv("SPLITTERCTL_SPLITTER_BIN", filepath.Join(prefix, "splitter"))
	t.Setenv("SPLITTERCTL_SPLITTER_VERSION", "v1.0.0")
	t.Setenv("SPLIT_SECRET", strings.Repeat("a", 64))
	switch role {
	case deploy.RoleIran:
		t.Setenv("SPLIT_SOCKS_LISTEN", "127.0.0.1:10900")
		t.Setenv("SPLIT_WS_LISTEN", "127.0.0.1:9001")
		t.Setenv("SPLIT_DOWN_CARRIER_ADDR", "127.0.0.1:10802")
		t.Setenv("SPLITTERCTL_ORIGIN_MODE", "caddy")
		t.Setenv("SPLITTERCTL_UPLOAD_DOMAIN", "upload.example.com")
	default:
		t.Setenv("SPLIT_UP_WS_URL", "wss://upload.example.com/upload")
		t.Setenv("SPLIT_DOWN_LISTEN", ":9002")
		t.Setenv("SPLITTERCTL_REALITY_SNI", "www.example.com")
		t.Setenv("SPLITTERCTL_REALITY_SHORT_ID", "0123456789abcdef")
		t.Setenv("SPLITTERCTL_REALITY_UUID", "550e8400-e29b-41d4-a716-446655440000")
	}
	return root
}

// installForTest commits an initial deployment through the controller, so the
// command under test starts from a real committed state (the documented
// requirement: config set/upgrade refuse when nothing is installed).
func installForTest(t *testing.T, store *deploy.Store, request deploy.InstallRequest) deploy.Manifest {
	t.Helper()
	result, err := (&deploy.Controller{Store: store, Adapter: &mutationFake{}}).ApplyRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("initial install: %v", err)
	}
	return result.Manifest
}

// TestConfigSetRequiresLinuxAndInstalledState pins both gates: the platform
// gate and the "nothing installed" refusal.
func TestConfigSetRequiresLinuxAndInstalledState(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	old := goos
	goos = "windows"
	t.Cleanup(func() { goos = old })
	var out bytes.Buffer
	err := run(context.Background(), []string{"config", "set", "relay.buf=65536"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("error = %v, want Linux requirement", err)
	}

	withLinux(t)
	withCanonicalRoot(t, t.TempDir())
	out.Reset()
	err = run(context.Background(), []string{"config", "set", "relay.buf=65536"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "config: not installed") {
		t.Fatalf("error = %v, want not-installed refusal", err)
	}
}

// TestConfigSetRejectsMalformedKeys is the strict-parsing contract: an
// unknown key, a missing '=', an empty key, and a non-projectable field are
// each refused — the last one with its documented reason, never silently
// ignored.
func TestConfigSetRejectsMalformedKeys(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, store, request)
	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	cases := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{"no assignment", []string{"config", "set"}, "at least one KEY=VALUE"},
		{"missing equals", []string{"config", "set", "relay.buf"}, "expects KEY=VALUE"},
		{"empty key", []string{"config", "set", "=1"}, "non-empty key"},
		{"unknown key", []string{"config", "set", "nope=1"}, "unknown key"},
		{"non-projectable key", []string{"config", "set", "keepalive.interval=60"}, "cannot be set"},
		{"wrong role key", []string{"config", "set", "up.ws.url=wss://x.example.com/upload"}, "applies to germany"},
		{"duplicate key", []string{"config", "set", "relay.buf=65536", "relay.buf=32768"}, "more than once"},
		{"non-integer", []string{"config", "set", "relay.buf=abc"}, "expects an integer"},
		{"non-boolean", []string{"config", "set", "allow.weak.secret=maybe"}, "expects a boolean"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(context.Background(), tc.args, &out, &out)
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %v, want %q", err, tc.wantMsg)
			}
			if !errors.Is(err, errUsage) && tc.name != "non-projectable key" {
				t.Fatalf("error = %v, want a usage error", err)
			}
		})
	}
	// Nothing above may have reached the host.
	if len(fake.calls) != 0 {
		t.Fatalf("rejected input mutated the host: %#v", fake.calls)
	}
}

// TestConfigSetRejectsInvalidValuesThroughAuthoritativeValidation proves the
// CLI does not re-implement validation: an out-of-range value is judged by
// internal/config inside the transaction, and the host is not touched.
func TestConfigSetRejectsInvalidValuesThroughAuthoritativeValidation(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, store, request)
	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	var out bytes.Buffer
	err = run(context.Background(), []string{"config", "set", "metrics.port=70000"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "SPLIT_METRICS_PORT") {
		t.Fatalf("error = %v, want authoritative validation error naming the field", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("invalid value mutated the host: %#v", fake.calls)
	}
}

// TestConfigSetAppliesTransactionallyAndNeverEchoesValues is the happy path:
// a configuration change runs the full transaction through the controller and
// reaches the adapter (which owns the env-file write), while the output and
// errors stay value-free — including for the secret itself.
func TestConfigSetAppliesTransactionallyAndNeverEchoesValues(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	before := installForTest(t, store, request)
	if before.ConfigFingerprint == "" {
		t.Fatal("committed manifest records no configuration identity")
	}

	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	var out bytes.Buffer
	if err := run(context.Background(), []string{"config", "set", "relay.buf=65536", "metrics.port=9100"}, &out, &out); err != nil {
		t.Fatalf("config set: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "config: committed") || !strings.Contains(got, "relay.buf") {
		t.Fatalf("output = %q", got)
	}
	for _, forbidden := range []string{"65536", "9100", strings.Repeat("a", 64)} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("output leaked %q: %q", forbidden, got)
		}
	}
	// The transaction ran and drove the adapter with the OVERRIDDEN
	// configuration, which is what makes the env-file rewrite happen.
	if len(fake.desired) == 0 {
		t.Fatal("config set did not reach the adapter through the transaction")
	}
	last := fake.desired[len(fake.desired)-1]
	if last.ConfigFingerprint == "" || last.ConfigFingerprint == before.ConfigFingerprint {
		t.Fatal("adapter did not receive the changed configuration identity")
	}

	committed, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if committed.ConfigFingerprint == before.ConfigFingerprint {
		t.Fatal("committed configuration identity did not change")
	}
	if committed.Generation == before.Generation {
		t.Fatal("no new generation was committed")
	}

	// Re-running the same change is a true no-op: no transaction, no journal,
	// no adapter call.
	second := &mutationFake{}
	defer stubMutationController(store, second)()
	out.Reset()
	if err := run(context.Background(), []string{"config", "set", "relay.buf=65536", "metrics.port=9100"}, &out, &out); err != nil {
		t.Fatalf("repeat config set: %v", err)
	}
	if !strings.Contains(out.String(), "already converged") {
		t.Fatalf("repeat output = %q", out.String())
	}
	if len(second.calls) != 0 {
		t.Fatalf("repeat config set mutated the host: %#v", second.calls)
	}
	if _, err := store.ReadJournal(); !os.IsNotExist(err) {
		t.Fatalf("no-op config set wrote a journal: %v", err)
	}
}

// TestConfigSetSecretIsNeverEchoed pins secret hygiene for the one key whose
// value is sensitive: the change is accepted and applied, and the value
// appears nowhere in the output or in the committed state.
func TestConfigSetSecretIsNeverEchoed(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, store, request)
	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	secret := strings.Repeat("b", 64)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"config", "set", "secret=" + secret}, &out, &out); err != nil {
		t.Fatalf("config set secret: %v", err)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatalf("output leaked the secret: %q", out.String())
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", loaded), secret) {
		t.Fatal("committed state contains the secret")
	}

	// A weak secret is refused by the authoritative policy, and the error
	// names the field without echoing the value. The probe value is chosen so
	// it cannot appear as an incidental substring of the policy message.
	out.Reset()
	weak := strings.Repeat("z", 8)
	err = run(context.Background(), []string{"config", "set", "secret=" + weak}, &out, &out)
	if err == nil || strings.Contains(err.Error(), weak) {
		t.Fatalf("error = %v, want a field-only secret policy error", err)
	}
	if !strings.Contains(err.Error(), "SPLIT_SECRET") {
		t.Fatalf("error = %v, want the secret field named", err)
	}
}

// TestConfigSetRefusesStaleJournal pins the stale-journal gate: a crashed
// mutation must be recovered before a configuration change is accepted.
func TestConfigSetRefusesStaleJournal(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, store, request)
	if err := store.WriteJournal(deploy.ArtifactJournal{Role: deploy.RoleIran, Generation: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	var out bytes.Buffer
	err = run(context.Background(), []string{"config", "set", "relay.buf=65536"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "in-flight journal") {
		t.Fatalf("error = %v, want stale-journal refusal", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("stale journal did not block the mutation: %#v", fake.calls)
	}
}

// TestUpgradeRequiresLinuxAndInstalledState pins both gates for upgrade.
func TestUpgradeRequiresLinuxAndInstalledState(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	old := goos
	goos = "windows"
	t.Cleanup(func() { goos = old })
	var out bytes.Buffer
	err := run(context.Background(), []string{"upgrade"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("error = %v, want Linux requirement", err)
	}

	withLinux(t)
	withCanonicalRoot(t, t.TempDir())
	out.Reset()
	err = run(context.Background(), []string{"upgrade"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "upgrade: nothing installed") {
		t.Fatalf("error = %v, want not-installed refusal", err)
	}
}

// TestUpgradeRefusesUnsupportedTargets covers the documented component
// restrictions: Iran has no managed Xray, --origin requires a configured
// origin, and --splitter must be driven by a real environment change.
func TestUpgradeRefusesUnsupportedTargets(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, store, request)
	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	cases := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{"xray on Iran", []string{"upgrade", "--xray"}, "uses an external Xray"},
		{"splitter with no environment change", []string{"upgrade", "--splitter"}, "no splitter change"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(context.Background(), tc.args, &out, &out)
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %v, want %q", err, tc.wantMsg)
			}
		})
	}
	if len(fake.calls) != 0 {
		t.Fatalf("refused upgrade mutated the host: %#v", fake.calls)
	}

	// --origin on a role with no configured origin is refused too. Germany's
	// origin plan is none, so the same state exercises the other branch.
	germanyRoot := withMutationEnv(t, deploy.RoleGermany)
	germanyStore, err := deploy.NewStore(germanyRoot)
	if err != nil {
		t.Fatal(err)
	}
	germanyRequest, err := installRequestFromEnv(deploy.RoleGermany)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, germanyStore, germanyRequest)
	germanyFake := &mutationFake{}
	defer stubMutationController(germanyStore, germanyFake)()
	var out bytes.Buffer
	err = run(context.Background(), []string{"upgrade", "--origin"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "requires a configured origin") {
		t.Fatalf("error = %v, want origin refusal", err)
	}
	if len(germanyFake.calls) != 0 {
		t.Fatalf("refused --origin mutated the host: %#v", germanyFake.calls)
	}
}

// TestUpgradeSplitterUsesTheControllerAndEnvironment is the --splitter happy
// path: a changed environment version is applied through the controller, which
// drives the adapter with the upgraded request.
func TestUpgradeSplitterUsesTheControllerAndEnvironment(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	before := installForTest(t, store, request)

	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	// The environment now supplies a new splitter version.
	t.Setenv("SPLITTERCTL_SPLITTER_VERSION", "v2.0.0")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"upgrade", "--splitter"}, &out, &out); err != nil {
		t.Fatalf("upgrade --splitter: %v", err)
	}
	if !strings.Contains(out.String(), "upgrade: committed") || !strings.Contains(out.String(), "splitter v2.0.0") {
		t.Fatalf("output = %q", out.String())
	}
	if len(fake.calls) == 0 {
		t.Fatal("upgrade did not run a transaction")
	}
	committed, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if committed.Components.Splitter.Version != "v2.0.0" {
		t.Fatalf("committed splitter version = %q", committed.Components.Splitter.Version)
	}
	if committed.Generation == before.Generation {
		t.Fatal("no new generation was committed")
	}
	if committed.ConfigFingerprint != before.ConfigFingerprint {
		t.Fatal("a splitter upgrade changed the configuration identity")
	}
}

// TestUpgradeXrayPinsTheManagedVersion is the --xray path on Germany: the
// pinned Xray version is applied, and a conflicting environment pin is
// refused rather than silently overridden.
func TestUpgradeXrayPinsTheManagedVersion(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleGermany)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleGermany)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, store, request)
	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	// A conflicting environment pin is refused.
	t.Setenv("SPLITTERCTL_XRAY_VERSION", "v26.3.26")
	var out bytes.Buffer
	err = run(context.Background(), []string{"upgrade", "--xray"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "pinned Xray") {
		t.Fatalf("error = %v, want pinned-version refusal", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("refused --xray mutated the host: %#v", fake.calls)
	}

	// With the environment agreeing with the pin, the upgrade runs.
	t.Setenv("SPLITTERCTL_XRAY_VERSION", "v26.3.27")
	out.Reset()
	if err := run(context.Background(), []string{"upgrade", "--xray"}, &out, &out); err != nil {
		t.Fatalf("upgrade --xray: %v", err)
	}
	if !strings.Contains(out.String(), "xray v26.3.27") {
		t.Fatalf("output = %q", out.String())
	}
	committed, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if committed.Components.Xray.Version != "v26.3.27" {
		t.Fatalf("committed xray version = %q", committed.Components.Xray.Version)
	}
}

// TestUpgradeOriginAppliesThePinnedOrigin is the --origin path: a role with a
// configured origin applies the pinned origin through the controller.
func TestUpgradeOriginAppliesThePinnedOrigin(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, store, request)
	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	// The environment agrees with the pin, so the upgrade is accepted and
	// converges the origin artifacts.
	var out bytes.Buffer
	if err := run(context.Background(), []string{"upgrade", "--origin"}, &out, &out); err != nil {
		t.Fatalf("upgrade --origin: %v", err)
	}
	if !strings.Contains(out.String(), "origin v2.11.4") {
		t.Fatalf("output = %q", out.String())
	}
	committed, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if committed.Components.Origin.Version != "v2.11.4" {
		t.Fatalf("committed origin version = %q", committed.Components.Origin.Version)
	}
}

// TestUpgradeRefusesStaleJournal pins the stale-journal gate for upgrade.
func TestUpgradeRefusesStaleJournal(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, store, request)
	if err := store.WriteJournal(deploy.ArtifactJournal{Role: deploy.RoleIran, Generation: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	// A real environment change so the request is genuinely actionable: the
	// stale-journal gate must still win, because the host may be inconsistent.
	t.Setenv("SPLITTERCTL_SPLITTER_VERSION", "v2.0.0")
	var out bytes.Buffer
	err = run(context.Background(), []string{"upgrade", "--splitter"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "in-flight journal") {
		t.Fatalf("error = %v, want stale-journal refusal", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("stale journal did not block the upgrade: %#v", fake.calls)
	}
}

// TestUpgradeNoFlagReappliesWithoutChanges pins the documented no-flag
// behavior: the environment is unchanged, so the plan is Unchanged and no
// transaction runs.
func TestUpgradeNoFlagReappliesWithoutChanges(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, store, request)
	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	var out bytes.Buffer
	if err := run(context.Background(), []string{"upgrade"}, &out, &out); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !strings.Contains(out.String(), "already converged") {
		t.Fatalf("output = %q", out.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("no-op upgrade mutated the host: %#v", fake.calls)
	}
	if _, err := store.ReadJournal(); !os.IsNotExist(err) {
		t.Fatalf("no-op upgrade wrote a journal: %v", err)
	}
}

// TestUpgradeRejectsMalformedArguments pins strict parsing for the new
// command wiring: unknown flags, extra arguments, and missing targets are
// usage errors, never silently ignored.
func TestUpgradeRejectsMalformedArguments(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	cases := [][]string{
		{"upgrade", "--unknown"},
		{"upgrade", "--xray", "--origin"},
		{"upgrade", "--splitter", "extra"},
		{"upgrade", "splitter"},
	}
	for _, args := range cases {
		var out bytes.Buffer
		err := run(context.Background(), args, &out, &out)
		if !errors.Is(err, errUsage) {
			t.Errorf("%v: error = %v, want usage error", args, err)
		}
	}
}

// TestConfigSetKeepsConfigShowUnchanged pins that the new command does not
// change the existing read-only config surface.
func TestConfigSetKeepsConfigShowUnchanged(t *testing.T) {
	withLinux(t)
	root := withMutationEnv(t, deploy.RoleIran)
	store, err := deploy.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatal(err)
	}
	installForTest(t, store, request)
	fake := &mutationFake{}
	defer stubMutationController(store, fake)()

	t.Setenv("SPLITTERCTL_STATE_ROOT", root)
	var before bytes.Buffer
	if err := run(context.Background(), []string{"config", "show"}, &before, &before); err != nil {
		t.Fatalf("config show: %v", err)
	}
	if err := run(context.Background(), []string{"config", "set", "metrics.port=9100"}, &before, &before); err != nil {
		t.Fatalf("config set: %v", err)
	}
	var after bytes.Buffer
	if err := run(context.Background(), []string{"config", "show"}, &after, &after); err != nil {
		t.Fatalf("config show after set: %v", err)
	}
	for _, want := range []string{"role: iran", "origin.mode: caddy", "origin.domain: upload.example.com"} {
		if !strings.Contains(after.String(), want) {
			t.Fatalf("config show output %q does not contain %q", after.String(), want)
		}
	}
	// The command's output surface is unchanged: no configuration values and
	// no fingerprints are added by the new capability.
	for _, forbidden := range []string{"9100", "configFingerprint", "manifestHash"} {
		if strings.Contains(after.String(), forbidden) {
			t.Fatalf("config show leaked %q: %q", forbidden, after.String())
		}
	}
}
