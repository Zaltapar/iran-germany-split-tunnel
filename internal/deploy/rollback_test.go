package deploy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func commitRollbackFixture(t *testing.T) (*Store, Manifest, Manifest) {
	t.Helper()
	root := t.TempDir()
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Commit(testManifest(store.Root, RoleIran), "install")
	if err != nil {
		t.Fatal(err)
	}
	secondState := testManifest(store.Root, RoleIran)
	secondState.Revisions = append([]Revision(nil), first.Revisions...)
	secondState.Generation = "g2"
	secondState.Components.Splitter.Version = "v2.0.0"
	second, err := store.Commit(secondState, "upgrade")
	if err != nil {
		t.Fatal(err)
	}
	return store, first, second
}

func TestRollbackRestoresTargetAndCommitsNewRevision(t *testing.T) {
	store, first, current := commitRollbackFixture(t)
	var restored Manifest
	got, err := store.Rollback(context.Background(), first.Revisions[0].ID, func(_ context.Context, target Manifest) error {
		restored = target
		return nil
	})
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if restored.Generation != first.Generation {
		t.Fatalf("restored generation = %q, want %q", restored.Generation, first.Generation)
	}
	if got.Generation != first.Generation || got.Components.Splitter.Version != "v1.0.0" {
		t.Fatalf("rolled back manifest = %+v", got)
	}
	if len(got.Revisions) <= len(current.Revisions) {
		t.Fatalf("rollback history was not retained: got %d, before %d", len(got.Revisions), len(current.Revisions))
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Generation != got.Generation {
		t.Fatalf("loaded generation = %q, want %q", loaded.Generation, got.Generation)
	}
}

func TestRollbackFailureLeavesCurrentStateUntouched(t *testing.T) {
	store, first, current := commitRollbackFixture(t)
	before, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("health failed")
	_, err = store.Rollback(context.Background(), first.Revisions[0].ID, func(context.Context, Manifest) error {
		return wantErr
	})
	if !errors.Is(err, ErrTransaction) || !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want transaction wrapping health error", err)
	}
	after, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != current.Generation || after.ManifestHash != before.ManifestHash {
		t.Fatalf("state changed after failed rollback: before=%+v after=%+v", before, after)
	}
}

func TestRollbackRejectsRoleMismatchAndActiveTarget(t *testing.T) {
	store, first, current := commitRollbackFixture(t)
	other := testManifest(store.Root, RoleGermany)
	other.Generation = "foreign"
	otherCommitted, err := store.Commit(other, "foreign")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rollback(context.Background(), otherCommitted.Revisions[len(otherCommitted.Revisions)-1].ID, func(context.Context, Manifest) error { return nil }); !errors.Is(err, ErrTransaction) {
		t.Fatalf("role mismatch error = %v", err)
	}
	if _, err := store.Rollback(context.Background(), current.Revisions[len(current.Revisions)-1].ID, func(context.Context, Manifest) error { return nil }); !errors.Is(err, ErrTransaction) {
		t.Fatalf("active target error = %v", err)
	}
	_ = first
}
