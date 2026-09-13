package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/firewall"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

// recoveryOpsFake records the T5 operations journal-driven recovery performs
// and (optionally) materializes unit removals against a temp unit dir so a
// test can assert real removal. It is the seam that lets the adapter's
// ownership logic run without a root Linux host.
type recoveryOpsFake struct {
	removed   []string
	rolled    []string
	reapplied []string
	// reappliedSpecs records the FULL spec passed to ReapplyUnit so a test
	// can assert the DEFECT-3 fallback renders the committed unit faithfully
	// (dependency ordering and canonical env path included).
	reappliedSpecs []systemd.Spec
	envRoll        int
	unitDir        string
	failWith       error
	// noBackup makes RollbackLast report systemd.ErrNoUnitBackup — the
	// no-managed-backup condition DEFECT-3 recovery must converge through.
	noBackup bool
}

func (o *recoveryOpsFake) RemoveUnit(_ context.Context, _ *systemd.ServiceManager, s systemd.Spec) error {
	o.removed = append(o.removed, s.UnitName)
	if o.unitDir != "" {
		_ = os.Remove(filepath.Join(o.unitDir, s.UnitName))
	}
	return o.failWith
}

func (o *recoveryOpsFake) RollbackLast(_ context.Context, _ *systemd.ServiceManager, s systemd.Spec) error {
	if o.noBackup {
		return fmt.Errorf("%w: %w for %s (nothing to roll back to)", systemd.ErrPreflight, systemd.ErrNoUnitBackup, s.UnitName)
	}
	o.rolled = append(o.rolled, s.UnitName)
	return o.failWith
}

func (o *recoveryOpsFake) ReapplyUnit(_ context.Context, _ *systemd.ServiceManager, s systemd.Spec) error {
	o.reapplied = append(o.reapplied, s.UnitName)
	o.reappliedSpecs = append(o.reappliedSpecs, s)
	return o.failWith
}

func (o *recoveryOpsFake) RollbackEnvFile(context.Context, systemd.Role) error {
	o.envRoll++
	return o.failWith
}

// firewallFake records owned-rule removals.
type firewallFake struct {
	removed int
}

func (f *firewallFake) Detect(context.Context) (firewall.Backend, error) {
	return firewall.BackendUFW, nil
}
func (f *firewallFake) Inspect(context.Context, firewall.Plan) (firewall.Snapshot, error) {
	return firewall.Snapshot{Backend: firewall.BackendUFW, Rules: []firewall.Rule{{Port: 443, Protocol: "tcp", Action: "allow", Comment: firewall.Marker}}}, nil
}
func (f *firewallFake) Apply(context.Context, firewall.Plan) (firewall.Result, error) {
	return firewall.Result{}, nil
}
func (f *firewallFake) Remove(context.Context, firewall.Snapshot) error {
	f.removed++
	return nil
}

// withManagedPrefix redirects the managed binary prefix at a temp dir so the
// prefix-bounded version-dir removal is exercisable on any host.
func withManagedPrefix(t *testing.T, prefix string) {
	t.Helper()
	old := managedBinaryPrefix
	managedBinaryPrefix = prefix
	t.Cleanup(func() { managedBinaryPrefix = old })
}

// recoveryFixture builds a post-crash state: a state root with a persisted
// journal, an owned config + env file, an owned unit dir, a redirected binary
// prefix with an owned xray dir, and unrelated sentinels that recovery must
// NOT touch. The adapter is a NEW LinuxAdapter with EMPTY runtime sets — the
// exact post-crash condition RF-2 is about.
type recoveryFixture struct {
	store     *Store
	adapter   *LinuxAdapter
	ops       *recoveryOpsFake
	fw        *firewallFake
	unitDir   string
	config    string
	env       string
	xrayDir   string
	sentinel  string
	preFile   string
	preUnit   string
	unrelated string
}

func newRecoveryFixture(t *testing.T, role string, journal ArtifactJournal) *recoveryFixture {
	t.Helper()
	stateRoot := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	binPrefix := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binPrefix, 0o755); err != nil {
		t.Fatal(err)
	}
	withManagedPrefix(t, binPrefix)

	unitDir := filepath.Join(t.TempDir(), "units")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(stateRoot, role+".json")
	env := filepath.Join(stateRoot, role+".env")
	for _, f := range []string{config, env} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	xrayDir := filepath.Join(binPrefix, "xray", "v26.3.27")
	if err := os.MkdirAll(xrayDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(xrayDir, "xray"), []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Unrelated sentinels: a directory + file outside the ownership scope.
	sentinel := filepath.Join(t.TempDir(), "unrelated")
	if err := os.MkdirAll(filepath.Join(sentinel, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(stateRoot, "unrelated.json")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	ops := &recoveryOpsFake{unitDir: unitDir}
	fw := &firewallFake{}
	adapter := &LinuxAdapter{
		Request: InstallRequest{
			Role:         role,
			StateRoot:    stateRoot,
			EnvPath:      env,
			ConfigPath:   config,
			SplitterPath: "/opt/split-tunnel/splitter",
		},
		Store:       store,
		Firewall:    fw,
		recoveryOps: ops,
	}
	// RF-2 precondition: a NEW process has empty runtime ownership sets.
	if len(adapter.units) != 0 || len(adapter.inFlightUnits) != 0 || len(adapter.inFlightFiles) != 0 {
		t.Fatal("fixture adapter must start with empty runtime sets")
	}
	if err := store.WriteJournal(journal); err != nil {
		t.Fatal(err)
	}
	return &recoveryFixture{
		store: store, adapter: adapter, ops: ops, fw: fw,
		unitDir: unitDir, config: config, env: env, xrayDir: xrayDir,
		sentinel: sentinel, unrelated: unrelated,
	}
}

// withValidRequest gives the fixture adapter a COMPLETE, validated request
// rooted at the fixture's temp state. Production adapters always carry such a
// request (NewLinuxAdapter validates it), and recovery's faithful spec
// derivation (recoverySpecFor → BuildSystemdPlan) requires it; the fixture's
// minimal request lacks the role-specific artifact metadata. The request is
// returned so a test can build the authoritative plan for comparison.
func (fx *recoveryFixture) withValidRequest(t *testing.T, role string) InstallRequest {
	t.Helper()
	var req InstallRequest
	if role == RoleGermany {
		req = validGermanyRequest()
	} else {
		req = validIranRequest()
	}
	req.StateRoot = fx.store.Root
	req.EnvPath = fx.env
	req.ConfigPath = fx.config
	fx.adapter.Request = req
	return req
}

// renderSafeSplitterPath returns an absolute, whitespace-free path that
// InstallRequest.Validate accepts on both Windows and Unix and that
// systemd.RenderUnit (which rejects whitespace) can render. The request
// helpers root artifacts under the checkout, whose path may contain spaces.
func renderSafeSplitterPath() string {
	if vol := filepath.VolumeName(absoluteTestPath("x")); vol != "" {
		return vol + string(filepath.Separator) + "split-tunnel-test-splitter"
	}
	return "/split-tunnel-test-splitter"
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be removed, stat err = %v", path, err)
	}
}

// TestRecoverFreshIsJournalDriven is the RF-2 proof: a NEW LinuxAdapter (empty
// runtime sets — the post-crash process) recovers a fresh install purely from
// the persisted journal. Owned units/files/xray dir are removed, unrelated
// resources survive, and the journal is cleared.
func TestRecoverFreshIsJournalDriven(t *testing.T) {
	for _, role := range []string{RoleGermany, RoleIran} {
		t.Run(role, func(t *testing.T) {
			unit := role + "-splitter.service"
			journal := ArtifactJournal{
				Role:       role,
				Generation: "pending-1",
				Files:      nil, // filled below once paths are known
				Units:      []string{unit},
				Firewall:   false,
			}
			fx := newRecoveryFixture(t, role, journal)
			// Re-persist with the real owned paths now that they are known.
			// The env file is created by a fresh install → owned (j.Files).
			journal.Files = []string{fx.config, fx.env}
			if role == RoleGermany {
				journal.Units = []string{"germany-splitter.service", "xray-germany.service"}
				journal.XrayDir = fx.xrayDir
			} else {
				journal.Units = []string{"iran-splitter.service"}
			}
			if err := fx.store.WriteJournal(journal); err != nil {
				t.Fatal(err)
			}
			// Materialize the owned unit files so removal is observable.
			for _, u := range journal.Units {
				if err := os.WriteFile(filepath.Join(fx.unitDir, u), []byte("unit"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			controller := &Controller{Store: fx.store, Adapter: fx.adapter}
			result, err := controller.Recover(context.Background())
			if err != nil {
				t.Fatalf("Recover: %v", err)
			}
			if !result.Changed || result.Phase != PhaseRecover {
				t.Fatalf("result = %+v, want a changed recover phase", result)
			}
			// Owned artifacts removed.
			mustNotExist(t, fx.config)
			mustNotExist(t, fx.env)
			for _, u := range journal.Units {
				mustNotExist(t, filepath.Join(fx.unitDir, u))
			}
			if role == RoleGermany {
				mustNotExist(t, fx.xrayDir)
			}
			// Unrelated resources survive (ownership isolation).
			mustExist(t, filepath.Join(fx.sentinel, "child"))
			mustExist(t, fx.unrelated)
			// Journal cleared (deadlock resolved).
			if _, err := fx.store.ReadJournal(); !os.IsNotExist(err) {
				t.Fatalf("journal not cleared: %v", err)
			}
		})
	}
}

// TestRecoverFreshDoesNotCallRestore asserts a fresh install recovery cleans
// up owned artifacts and never invokes restore semantics.
func TestRecoverFreshDoesNotCallRestore(t *testing.T) {
	journal := ArtifactJournal{Role: RoleIran, Generation: "pending-1"}
	fx := newRecoveryFixture(t, RoleIran, journal)
	adapter := &restoreTrackingAdapter{LinuxAdapter: fx.adapter}
	controller := &Controller{Store: fx.store, Adapter: adapter}
	if _, err := controller.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if adapter.restored {
		t.Fatal("fresh recovery must not call Restore")
	}
}

// restoreTrackingAdapter wraps the LinuxAdapter to detect a Restore call.
type restoreTrackingAdapter struct {
	*LinuxAdapter
	restored bool
}

func (a *restoreTrackingAdapter) Restore(ctx context.Context, m Manifest) error {
	a.restored = true
	return a.LinuxAdapter.Restore(ctx, m)
}

// TestRecoverUpgradeConvergesToPrevious covers the upgrade crash: a committed
// previous manifest plus an in-flight journal. Pre-existing units are rolled
// back, newly-created units are removed, the env file is restored, and the
// journal is cleared.
func TestRecoverUpgradeConvergesToPrevious(t *testing.T) {
	journal := ArtifactJournal{Role: RoleGermany, Generation: "pending-2"}
	fx := newRecoveryFixture(t, RoleGermany, journal)
	previous := testManifest(fx.store.Root, RoleGermany)
	previous.Generation = "g1"
	previous.Services = []ServiceState{{Unit: "germany-splitter.service", Component: "splitter"}}
	committed, err := fx.store.Commit(previous, "install")
	if err != nil {
		t.Fatal(err)
	}
	// In-flight journal for an upgrade that ADDED xray and REPLACED splitter.
	journal.Units = []string{"germany-splitter.service", "xray-germany.service"}
	journal.PreUnits = []string{"germany-splitter.service"}
	journal.Files = []string{fx.config}
	journal.PreFiles = []string{fx.config} // config pre-existed → not removed
	if err := fx.store.WriteJournal(journal); err != nil {
		t.Fatal(err)
	}

	controller := &Controller{Store: fx.store, Adapter: fx.adapter}
	if _, err := controller.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !reflect.DeepEqual(fx.ops.rolled, []string{"germany-splitter.service"}) {
		t.Fatalf("rolled back = %#v, want the pre-existing splitter unit", fx.ops.rolled)
	}
	if !reflect.DeepEqual(fx.ops.removed, []string{"xray-germany.service"}) {
		t.Fatalf("removed = %#v, want the newly-created xray unit", fx.ops.removed)
	}
	if fx.ops.envRoll != 1 {
		t.Fatalf("env rollbacks = %d, want 1", fx.ops.envRoll)
	}
	mustExist(t, fx.config) // pre-existing → left to its owner's rollback path
	if _, err := fx.store.ReadJournal(); !os.IsNotExist(err) {
		t.Fatalf("journal not cleared: %v", err)
	}
	if _, err := fx.store.Load(); err != nil {
		t.Fatalf("committed manifest must survive recovery: %v", err)
	}
	_ = committed
}

// TestRecoverTamperedJournalFailsClosed asserts a tampered/malformed journal
// deletes nothing, retains the journal, and returns a diagnosable error.
func TestRecoverTamperedJournalFailsClosed(t *testing.T) {
	journal := ArtifactJournal{Role: RoleIran, Generation: "pending-1"}
	fx := newRecoveryFixture(t, RoleIran, journal)
	// Overwrite with an out-of-root file entry → ReadJournal fails closed.
	tampered := `{"role":"iran","generation":"g1","files":["/etc/passwd"]}`
	if err := os.WriteFile(filepath.Join(fx.store.Root, "journal.json"), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	controller := &Controller{Store: fx.store, Adapter: fx.adapter}
	_, err := controller.Recover(context.Background())
	if !errors.Is(err, ErrTransaction) {
		t.Fatalf("error = %v, want ErrTransaction", err)
	}
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("error = %v, want a diagnosable ErrTampered cause", err)
	}
	if len(fx.ops.removed) != 0 || len(fx.ops.rolled) != 0 {
		t.Fatalf("adapter mutated the host on a tampered journal: %#v %#v", fx.ops.removed, fx.ops.rolled)
	}
	mustExist(t, fx.config)
	mustExist(t, fx.env)
	if _, err := fx.store.ReadJournal(); err == nil {
		t.Fatal("tampered journal must be retained for the operator")
	}
}

// TestRecoverNoJournalIsNoOp asserts there is a clear "nothing to recover"
// outcome with no error and no mutation.
func TestRecoverNoJournalIsNoOp(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	ops := &recoveryOpsFake{}
	adapter := &LinuxAdapter{Request: InstallRequest{Role: RoleIran, StateRoot: stateRoot}, Store: store, recoveryOps: ops}
	result, err := (&Controller{Store: store, Adapter: adapter}).Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover with no journal = %v, want nil", err)
	}
	if result.Changed || result.Phase != PhaseRecover {
		t.Fatalf("result = %+v, want unchanged recover phase", result)
	}
	if len(ops.removed) != 0 || len(ops.rolled) != 0 || ops.envRoll != 0 {
		t.Fatalf("adapter was invoked with no journal: %#v", ops)
	}
}

// TestRecoverIsIdempotent asserts calling Recover twice is safe.
func TestRecoverIsIdempotent(t *testing.T) {
	journal := ArtifactJournal{Role: RoleIran, Generation: "pending-1"}
	fx := newRecoveryFixture(t, RoleIran, journal)
	controller := &Controller{Store: fx.store, Adapter: fx.adapter}
	if _, err := controller.Recover(context.Background()); err != nil {
		t.Fatalf("first Recover: %v", err)
	}
	result, err := controller.Recover(context.Background())
	if err != nil {
		t.Fatalf("second Recover: %v", err)
	}
	if result.Changed {
		t.Fatalf("second Recover = %+v, want a no-op", result)
	}
}

// TestRecoverResolvesInstallDeadlock asserts a successful Recover unblocks a
// subsequent install (the stale-journal gate no longer refuses).
func TestRecoverResolvesInstallDeadlock(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteJournal(ArtifactJournal{Role: RoleIran, Generation: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	request := requestIn(t, store, validIranRequest())
	fake := &controllerFake{}
	controller := &Controller{Store: store, Adapter: fake}

	if _, err := controller.ApplyRequest(context.Background(), request); !errors.Is(err, ErrTransaction) {
		t.Fatalf("install with a stale journal = %v, want refusal", err)
	}
	if _, err := controller.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if _, err := controller.ApplyRequest(context.Background(), request); err != nil {
		t.Fatalf("install after recovery = %v, want success", err)
	}
}

// TestRecoverOwnershipIsolation asserts pre-existing (PreFiles/PreUnits)
// artifacts are NOT deleted by a fresh recovery.
func TestRecoverOwnershipIsolation(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	preFile := filepath.Join(stateRoot, "pre-existing.json")
	newFile := filepath.Join(stateRoot, "created.json")
	env := filepath.Join(stateRoot, "iran.env")
	for _, f := range []string{preFile, newFile, env} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unitDir := t.TempDir()
	preUnit := "iran-origin.service"
	newUnit := "iran-splitter.service"
	for _, u := range []string{preUnit, newUnit} {
		if err := os.WriteFile(filepath.Join(unitDir, u), []byte("u"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	journal := ArtifactJournal{
		Role:       RoleIran,
		Generation: "pending-1",
		Files:      []string{newFile},
		PreFiles:   []string{preFile},
		Units:      []string{newUnit, preUnit},
		PreUnits:   []string{preUnit},
	}
	if err := store.WriteJournal(journal); err != nil {
		t.Fatal(err)
	}
	ops := &recoveryOpsFake{unitDir: unitDir}
	adapter := &LinuxAdapter{
		Request:     InstallRequest{Role: RoleIran, StateRoot: stateRoot, EnvPath: env, SplitterPath: "/opt/splitter"},
		Store:       store,
		recoveryOps: ops,
	}
	if _, err := (&Controller{Store: store, Adapter: adapter}).Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	mustNotExist(t, newFile)
	mustExist(t, preFile) // pre-existing → untouched
	mustNotExist(t, filepath.Join(unitDir, newUnit))
	mustExist(t, filepath.Join(unitDir, preUnit)) // pre-existing → untouched
	if !reflect.DeepEqual(ops.removed, []string{newUnit}) {
		t.Fatalf("removed units = %#v, want only %q", ops.removed, newUnit)
	}
}

// TestRecoverRemovesOwnedFirewall asserts a fresh recovery removes the owned
// firewall snapshot when the journal records one.
func TestRecoverRemovesOwnedFirewall(t *testing.T) {
	journal := ArtifactJournal{Role: RoleIran, Generation: "pending-1", Firewall: true}
	fx := newRecoveryFixture(t, RoleIran, journal)
	if _, err := (&Controller{Store: fx.store, Adapter: fx.adapter}).Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if fx.fw.removed != 1 {
		t.Fatalf("firewall removals = %d, want 1", fx.fw.removed)
	}
}

// TestRecoverRetainsJournalOnAdapterFailure asserts a failing adapter leaves
// the journal in place and returns a wrapped, diagnosable error.
func TestRecoverRetainsJournalOnAdapterFailure(t *testing.T) {
	// The journal must own at least one unit so the adapter's T5 operation is
	// actually exercised and can fail.
	journal := ArtifactJournal{
		Role:       RoleIran,
		Generation: "pending-1",
		Units:      []string{"iran-splitter.service"},
	}
	fx := newRecoveryFixture(t, RoleIran, journal)
	wantErr := errors.New("injected adapter failure")
	fx.ops.failWith = wantErr
	_, err := (&Controller{Store: fx.store, Adapter: fx.adapter}).Recover(context.Background())
	if !errors.Is(err, ErrTransaction) || !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want a wrapped ErrTransaction carrying the cause", err)
	}
	if _, err := fx.store.ReadJournal(); err != nil {
		t.Fatalf("journal must be retained after a failed recovery: %v", err)
	}
}

// TestRecoverBoundedByContext asserts recovery honors a canceled context and
// mutates nothing.
func TestRecoverBoundedByContext(t *testing.T) {
	journal := ArtifactJournal{Role: RoleIran, Generation: "pending-1"}
	fx := newRecoveryFixture(t, RoleIran, journal)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&Controller{Store: fx.store, Adapter: fx.adapter}).Recover(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(fx.ops.removed) != 0 || len(fx.ops.rolled) != 0 {
		t.Fatalf("recovery mutated the host under a canceled context: %#v", fx.ops)
	}
	mustExist(t, fx.config)
	if _, err := fx.store.ReadJournal(); err != nil {
		t.Fatalf("journal must be retained when recovery is canceled: %v", err)
	}
}

// TestRecoverJournalRejectsRoleMismatch asserts the adapter refuses a journal
// whose role does not match its request (defense in depth).
func TestRecoverJournalRejectsRoleMismatch(t *testing.T) {
	adapter := &LinuxAdapter{Request: InstallRequest{Role: RoleIran}}
	err := adapter.RecoverJournal(context.Background(), ArtifactJournal{Role: RoleGermany}, Manifest{})
	if err == nil {
		t.Fatal("role-mismatched journal accepted")
	}
}

// TestRecoverFreshPreservesPreexistingEnv is the DEFECT-2 regression: a fresh
// recovery must remove the env file ONLY when the journal records it as
// created by the transaction (present in Files). Here the journal owns the
// config but NOT the env (the env is neither in Files nor PreFiles — it
// pre-existed the transaction), so the env file must SURVIVE.
func TestRecoverFreshPreservesPreexistingEnv(t *testing.T) {
	journal := ArtifactJournal{Role: RoleIran, Generation: "pending-1"}
	fx := newRecoveryFixture(t, RoleIran, journal)
	// Own the config only; the env is NOT owned by this transaction.
	journal.Files = []string{fx.config}
	if err := fx.store.WriteJournal(journal); err != nil {
		t.Fatal(err)
	}
	mustExist(t, fx.env)
	if _, err := (&Controller{Store: fx.store, Adapter: fx.adapter}).Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	mustNotExist(t, fx.config) // owned config removed
	mustExist(t, fx.env)       // pre-existing env must SURVIVE
}

// TestRecoverFreshPreservesEnvRecordedAsPreFile asserts PreFiles wins even if
// the env also appears in Files: a resource recorded as pre-existing is never
// deleted (it is left to its owner's rollback path).
func TestRecoverFreshPreservesEnvRecordedAsPreFile(t *testing.T) {
	journal := ArtifactJournal{Role: RoleIran, Generation: "pending-1"}
	fx := newRecoveryFixture(t, RoleIran, journal)
	journal.Files = []string{fx.config, fx.env}
	journal.PreFiles = []string{fx.env}
	if err := fx.store.WriteJournal(journal); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Controller{Store: fx.store, Adapter: fx.adapter}).Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	mustExist(t, fx.env) // pre-existing → never removed
}

// TestRecoverFreshRemovesOwnedEnv pins the normal fresh case unchanged: when
// the journal records the env as created (j.Files, not j.PreFiles), fresh
// recovery removes it.
func TestRecoverFreshRemovesOwnedEnv(t *testing.T) {
	journal := ArtifactJournal{Role: RoleIran, Generation: "pending-1"}
	fx := newRecoveryFixture(t, RoleIran, journal)
	journal.Files = []string{fx.config, fx.env}
	if err := fx.store.WriteJournal(journal); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Controller{Store: fx.store, Adapter: fx.adapter}).Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	mustNotExist(t, fx.env) // owned env removed
}

// TestRecoverUpgradeConvergesWhenNoUnitBackup is the DEFECT-3 regression: a
// crashed upgrade whose pre-existing unit has NO managed backup (created by a
// fresh install and never backed up) must CONVERGE by re-applying the
// committed unit from the manifest, not error and retain the journal.
func TestRecoverUpgradeConvergesWhenNoUnitBackup(t *testing.T) {
	journal := ArtifactJournal{Role: RoleGermany, Generation: "pending-2"}
	fx := newRecoveryFixture(t, RoleGermany, journal)
	// Production adapters always carry a complete, validated request, and the
	// faithful re-apply (recoverySpecFor → BuildSystemdPlan) requires one; the
	// fixture's minimal request lacks the Germany artifact metadata.
	fx.withValidRequest(t, RoleGermany)
	previous := testManifest(fx.store.Root, RoleGermany)
	previous.Generation = "g1"
	previous.Services = []ServiceState{{Unit: "germany-splitter.service", Component: "splitter"}}
	if _, err := fx.store.Commit(previous, "install"); err != nil {
		t.Fatal(err)
	}
	// The crashed upgrade owned the pre-existing splitter unit; it has no
	// managed backup to restore.
	journal.Units = []string{"germany-splitter.service"}
	journal.PreUnits = []string{"germany-splitter.service"}
	if err := fx.store.WriteJournal(journal); err != nil {
		t.Fatal(err)
	}
	fx.ops.noBackup = true

	result, err := (&Controller{Store: fx.store, Adapter: fx.adapter}).Recover(context.Background())
	if err != nil {
		t.Fatalf("recovery did not converge (no-backup upgrade): %v", err)
	}
	if !result.Changed {
		t.Fatal("recovery reported no change")
	}
	if !reflect.DeepEqual(fx.ops.reapplied, []string{"germany-splitter.service"}) {
		t.Fatalf("reapplied = %#v, want the pre-existing unit re-applied", fx.ops.reapplied)
	}
	if len(fx.ops.rolled) != 0 {
		t.Fatalf("rolled = %#v, want no successful rollback", fx.ops.rolled)
	}
	if _, err := fx.store.ReadJournal(); !os.IsNotExist(err) {
		t.Fatalf("journal not cleared after convergence: %v", err)
	}
	if _, err := fx.store.Load(); err != nil {
		t.Fatalf("committed manifest must survive recovery: %v", err)
	}
}

// TestRecoveryReapplyMatchesNormalApply is the DEFECT-3 spec-fidelity
// regression: the recovery re-apply fallback must reproduce the EXACT unit
// the normal apply path installs — same spec and same rendered bytes — for
// both roles. Before the fix, unitSpecFor omitted RequiresUnits/OriginEnabled,
// so the fallback wrote a unit missing the After=/Wants= dependency ordering
// (a silent divergence from the committed content).
func TestRecoveryReapplyMatchesNormalApply(t *testing.T) {
	cases := []struct {
		name string
		role string
		unit string
	}{
		{"germany splitter requires xray", RoleGermany, "germany-splitter.service"},
		{"iran splitter origin-enabled", RoleIran, "iran-splitter.service"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var request InstallRequest
			if tc.role == RoleGermany {
				request = validGermanyRequest()
			} else {
				request = validIranRequest()
			}
			// Render-safe splitter path. RenderUnit rejects whitespace, and
			// the request helpers root artifacts under the checkout (which may
			// contain spaces); the path does not affect the fidelity property
			// under test, only that the request validates and renders.
			request.SplitterPath = renderSafeSplitterPath()

			adapter := &LinuxAdapter{Request: request}
			got, err := adapter.recoverySpecFor(tc.unit)
			if err != nil {
				t.Fatalf("recoverySpecFor(%s): %v", tc.unit, err)
			}

			// The authoritative normal-apply spec: BuildSystemdPlan is the
			// single source of truth, normalised exactly as the production
			// Activate path normalises the xray unit. The normalisation is
			// written out here (rather than reusing the helper) so the test
			// pins the intended contract independently of the helper.
			plan, err := BuildSystemdPlan(request)
			if err != nil {
				t.Fatalf("BuildSystemdPlan: %v", err)
			}
			var want systemd.Spec
			found := false
			for _, spec := range plan.Specs {
				if unitName(spec) == tc.unit {
					if spec.Component == systemd.ComponentXray {
						spec.BinPath = systemd.XrayBinaryPath
					}
					spec.UnitName = tc.unit
					want = spec
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("unit %s absent from the normal plan %#v", tc.unit, plan.Specs)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("recovery spec = %#v, want the normal-apply spec %#v", got, want)
			}

			// The substantive property: the rendered BYTES match.
			gotBytes, err := systemd.RenderUnit(got)
			if err != nil {
				t.Fatalf("RenderUnit(recovery): %v", err)
			}
			wantBytes, err := systemd.RenderUnit(want)
			if err != nil {
				t.Fatalf("RenderUnit(normal): %v", err)
			}
			if string(gotBytes) != string(wantBytes) {
				t.Fatalf("recovery unit bytes differ from the normal apply path:\n--- recovery ---\n%s\n--- normal ---\n%s", gotBytes, wantBytes)
			}

			// Pin the specific fidelity properties the defect was about.
			switch tc.unit {
			case "germany-splitter.service":
				if len(got.RequiresUnits) != 1 || got.RequiresUnits[0] != "xray-germany.service" {
					t.Fatalf("germany splitter RequiresUnits = %#v, want [xray-germany.service]", got.RequiresUnits)
				}
			case "iran-splitter.service":
				if !got.OriginEnabled {
					t.Fatal("iran splitter lost its OriginEnabled flag on recovery re-apply")
				}
			}
			if got.EnvFile != systemd.EnvFile(systemd.Role(request.Role)) {
				t.Fatalf("env file = %q, want the canonical %q", got.EnvFile, systemd.EnvFile(systemd.Role(request.Role)))
			}
		})
	}
}

// TestRecoverySpecForUnknownUnitFailsClosed asserts an unknown unit name (one
// not in the request's plan) is refused rather than re-applied with a guessed
// spec.
func TestRecoverySpecForUnknownUnitFailsClosed(t *testing.T) {
	adapter := &LinuxAdapter{Request: validGermanyRequest()}
	if _, err := adapter.recoverySpecFor("iran-origin.service"); err == nil {
		t.Fatal("recoverySpecFor accepted a unit absent from the request's plan")
	}
}

// TestRecoverUpgradeReapplyIsSpecFaithful drives the DEFECT-3 fallback through
// the real recovery path and asserts the spec handed to ReapplyUnit equals the
// normal-apply spec (not the minimal name-scoped one).
func TestRecoverUpgradeReapplyIsSpecFaithful(t *testing.T) {
	journal := ArtifactJournal{Role: RoleGermany, Generation: "pending-2"}
	fx := newRecoveryFixture(t, RoleGermany, journal)
	req := fx.withValidRequest(t, RoleGermany)

	previous := testManifest(fx.store.Root, RoleGermany)
	previous.Generation = "g1"
	previous.Services = []ServiceState{{Unit: "germany-splitter.service", Component: "splitter"}}
	if _, err := fx.store.Commit(previous, "install"); err != nil {
		t.Fatal(err)
	}
	journal.Units = []string{"germany-splitter.service"}
	journal.PreUnits = []string{"germany-splitter.service"}
	if err := fx.store.WriteJournal(journal); err != nil {
		t.Fatal(err)
	}
	fx.ops.noBackup = true

	if _, err := (&Controller{Store: fx.store, Adapter: fx.adapter}).Recover(context.Background()); err != nil {
		t.Fatalf("recovery did not converge: %v", err)
	}
	if len(fx.ops.reappliedSpecs) != 1 {
		t.Fatalf("reapplied specs = %#v, want exactly one", fx.ops.reappliedSpecs)
	}
	got := fx.ops.reappliedSpecs[0]
	if len(got.RequiresUnits) != 1 || got.RequiresUnits[0] != "xray-germany.service" {
		t.Fatalf("recovery re-apply lost the xray dependency: %#v", got.RequiresUnits)
	}
	plan, err := BuildSystemdPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	var want systemd.Spec
	for _, spec := range plan.Specs {
		if unitName(spec) == "germany-splitter.service" {
			spec.UnitName = "germany-splitter.service"
			want = spec
			break
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recovery re-apply spec = %#v, want the normal-apply spec %#v", got, want)
	}
}
