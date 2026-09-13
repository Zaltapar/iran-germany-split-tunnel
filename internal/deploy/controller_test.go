package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type controllerFake struct {
	adapterFake
	restored    Manifest
	uninstalled Manifest
}

func (f *controllerFake) Restore(ctx context.Context, m Manifest) error {
	f.restored = m
	return f.call("restore")
}
func (f *controllerFake) Uninstall(ctx context.Context, m Manifest) error {
	f.uninstalled = m
	return f.call("uninstall")
}

// requestIn points the canonical test request at the test store root so the
// journal's file validation (paths below the state root) holds.
func requestIn(t *testing.T, store *Store, request InstallRequest) InstallRequest {
	t.Helper()
	request.StateRoot = store.Root
	request.EnvPath = filepath.Join(store.Root, request.Role+".env")
	request.ConfigPath = filepath.Join(store.Root, request.Role+".json")
	return request
}

func TestControllerApplyRequestKeepsSecretOutOfManifest(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	request := requestIn(t, store, validIranRequest())
	fake := &controllerFake{}
	result, err := (&Controller{Store: store, Adapter: fake}).ApplyRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("ApplyRequest: %v", err)
	}
	if strings.Contains(result.Manifest.ManifestHash, request.Config.Secret) {
		t.Fatal("manifest hash contains the tunnel secret")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", loaded), request.Config.Secret) {
		t.Fatal("persisted manifest contains the tunnel secret")
	}
}

func TestControllerApplyRequestTreatsMissingStateAsFreshInstall(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	request := requestIn(t, store, validIranRequest())
	fake := &controllerFake{}
	result, err := (&Controller{Store: store, Adapter: fake}).ApplyRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("ApplyRequest: %v", err)
	}
	if !result.Changed || result.Manifest.Role != RoleIran {
		t.Fatalf("result = %+v", result)
	}
	if !reflect.DeepEqual(fake.calls, []string{"prepare", "validate", "backup", "activate", "transition", "health"}) {
		t.Fatalf("calls = %#v", fake.calls)
	}
}

func TestControllerApplyRequestBlocksTamperedState(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(testManifest(store.Root, RoleGermany), "install"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Root, "state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"role": "germany"`, `"role": "iran"`, 1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	request := requestIn(t, store, validIranRequest())
	fake := &controllerFake{}
	_, err = (&Controller{Store: store, Adapter: fake}).ApplyRequest(context.Background(), request)
	if !errors.Is(err, ErrTransaction) {
		t.Fatalf("error = %v, want ErrTransaction", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("adapter called for tampered state: %#v", fake.calls)
	}
}

// commitFinalizedPairing installs once through the controller, then simulates
// `pair finalize` (the pair commands own and commit pairing state) and returns
// the committed pairing state.
func commitFinalizedPairing(t *testing.T, store *Store, request InstallRequest) PairingState {
	t.Helper()
	if _, err := (&Controller{Store: store, Adapter: &controllerFake{}}).ApplyRequest(context.Background(), request); err != nil {
		t.Fatalf("initial ApplyRequest: %v", err)
	}
	committed, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	committed.Pairing = PairingState{PeerRole: RoleGermany, State: "finalized", Fingerprints: []string{"pairing-fingerprint"}}
	if _, err := store.Commit(committed, "pair-finalize"); err != nil {
		t.Fatal(err)
	}
	return committed.Pairing
}

// TestControllerReapplyAfterPairingIsNoOp is the RF-4 regression: install is
// not authoritative over pairing, so re-running the same install after the
// pair commands committed a real pairing state must be a true no-op and must
// not reset the committed pairing state to "none".
func TestControllerReapplyAfterPairingIsNoOp(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	request := requestIn(t, store, validIranRequest())
	wantPairing := commitFinalizedPairing(t, store, request)
	paired, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}

	fake := &controllerFake{}
	result, err := (&Controller{Store: store, Adapter: fake}).ApplyRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("re-apply ApplyRequest: %v", err)
	}
	if !result.Plan.Unchanged || result.Changed {
		t.Fatalf("re-apply plan = %+v, want unchanged no-op", result.Plan)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("re-apply mutated the host: %#v", fake.calls)
	}
	if result.Manifest.Generation != paired.Generation {
		t.Fatalf("generation = %q, want untouched %q", result.Manifest.Generation, paired.Generation)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.Pairing, wantPairing) {
		t.Fatalf("pairing = %+v, want preserved %+v", loaded.Pairing, wantPairing)
	}
	if loaded.Pairing.State == PairingStateNone {
		t.Fatal("install reset pairing state to none")
	}
}

// TestControllerInstallPreservesPairingAcrossRealChange asserts a genuine
// install change (which runs a full transaction and rebuilds the committed
// manifest from desired state) still carries the committed pairing state
// forward instead of resetting it to "none".
func TestControllerInstallPreservesPairingAcrossRealChange(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	request := requestIn(t, store, validIranRequest())
	wantPairing := commitFinalizedPairing(t, store, request)

	changed := request
	changed.SplitterVersion = "v1.0.1"
	result, err := (&Controller{Store: store, Adapter: &controllerFake{}}).ApplyRequest(context.Background(), changed)
	if err != nil {
		t.Fatalf("ApplyRequest: %v", err)
	}
	if result.Plan.Unchanged {
		t.Fatal("expected a real change to run a transaction")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.Pairing, wantPairing) {
		t.Fatalf("pairing = %+v, want preserved %+v", loaded.Pairing, wantPairing)
	}
}

func TestControllerRollbackAndUninstallDelegate(t *testing.T) {
	store, first, current := commitRollbackFixture(t)
	fake := &controllerFake{}
	controller := &Controller{Store: store, Adapter: fake}
	if _, err := controller.Rollback(context.Background(), first.Revisions[0].ID); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if fake.restored.Generation != first.Generation {
		t.Fatalf("restored = %q, want %q", fake.restored.Generation, first.Generation)
	}
	if err := controller.Uninstall(context.Background(), false); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if fake.uninstalled.Generation != first.Generation {
		t.Fatalf("uninstalled = %q, want rolled-back %q", fake.uninstalled.Generation, first.Generation)
	}
	_ = current
}

// TestUninstallPurgeRefusesSymlinkedRevisionsDir is the DEFECT-1 regression:
// a symlink planted at the store-owned revisions directory must NOT be
// followed by `uninstall --purge`; the link is unlinked and its target (a
// directory of unrelated data) survives.
func TestUninstallPurgeRefusesSymlinkedRevisionsDir(t *testing.T) {
	store, _, _ := commitRollbackFixture(t)
	// Replace the real revisions dir with a symlink to an unrelated target.
	if err := os.RemoveAll(store.revisionsDir()); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(filepath.Join(target, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, store.revisionsDir()); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
	if err := (&Controller{Store: store, Adapter: &controllerFake{}}).Uninstall(context.Background(), true); err != nil {
		t.Fatalf("Uninstall --purge: %v", err)
	}
	if _, err := os.Lstat(store.revisionsDir()); !os.IsNotExist(err) {
		t.Fatalf("revisions symlink survived purge: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "keep")); err != nil {
		t.Fatalf("purge followed the symlink and deleted its target: %v", err)
	}
}

// TestUninstallPurgeRemovesRealRevisionsDir pins the normal purge path: a real
// revisions directory (with contents) is removed recursively.
func TestUninstallPurgeRemovesRealRevisionsDir(t *testing.T) {
	store, _, _ := commitRollbackFixture(t)
	if err := os.MkdirAll(store.revisionsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.revisionsDir(), "r.json"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&Controller{Store: store, Adapter: &controllerFake{}}).Uninstall(context.Background(), true); err != nil {
		t.Fatalf("Uninstall --purge: %v", err)
	}
	if _, err := os.Stat(store.revisionsDir()); !os.IsNotExist(err) {
		t.Fatalf("revisions dir survived purge: %v", err)
	}
}

// TestUninstallPurgeRefusesNonDirectoryRevisions exercises the non-directory
// refusal branch of the symlink-safe removal on every host (the symlink case
// skips where symlinks are unprivileged): a regular file planted at the
// store-owned revisions path is refused, not deleted.
func TestUninstallPurgeRefusesNonDirectoryRevisions(t *testing.T) {
	store, _, _ := commitRollbackFixture(t)
	if err := os.RemoveAll(store.revisionsDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.revisionsDir(), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := (&Controller{Store: store, Adapter: &controllerFake{}}).Uninstall(context.Background(), true)
	if err == nil {
		t.Fatal("purge accepted a non-directory revisions path")
	}
	if _, serr := os.Stat(store.revisionsDir()); serr != nil {
		t.Fatalf("non-directory revisions path was removed: %v", serr)
	}
}
