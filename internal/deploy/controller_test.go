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
