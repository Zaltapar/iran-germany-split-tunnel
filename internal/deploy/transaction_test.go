package deploy

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestTransactionRunsPhasesInOrderAndCommits(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	tx := Transaction{
		Store: store,
		Desired: DesiredState{
			Role:  RoleIran,
			Paths: Paths{StateRoot: root},
		},
		Steps: []Step{
			{Phase: PhasePreflight, Name: "preflight", Run: func(context.Context) error { got = append(got, "preflight"); return nil }},
			{Phase: PhasePrepare, Name: "prepare", Run: func(context.Context) error { got = append(got, "prepare"); return nil }},
			{Phase: PhaseValidate, Name: "validate", Run: func(context.Context) error { got = append(got, "validate"); return nil }},
		},
	}
	result, err := tx.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"preflight", "prepare", "validate"}) {
		t.Fatalf("steps = %#v", got)
	}
	if !result.Changed || result.Manifest.Role != RoleIran {
		t.Fatalf("result = %+v", result)
	}
}

func TestTransactionUnchangedIsNoOp(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(root)
	previous := testManifest(root, RoleGermany)
	if err := store.Save(previous); err != nil {
		t.Fatal(err)
	}
	called := false
	tx := Transaction{Store: store, Previous: previous, Desired: desiredFor(previous), Steps: []Step{{Phase: PhasePrepare, Run: func(context.Context) error { called = true; return nil }}}}
	result, err := tx.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || called {
		t.Fatalf("result=%+v called=%v, want no-op", result, called)
	}
}

func TestTransactionFailureRecoversPrevious(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(root)
	previous := testManifest(root, RoleIran)
	recovered := false
	tx := Transaction{
		Store: store, Previous: previous,
		Desired: DesiredState{Role: RoleIran, Paths: Paths{StateRoot: root}},
		Steps:   []Step{{Phase: PhaseActivate, Name: "activate", Run: func(context.Context) error { return errors.New("injected") }}},
		Recover: func(_ context.Context, got Manifest) error {
			recovered = true
			if got.Generation != previous.Generation {
				return errors.New("wrong previous state")
			}
			return nil
		},
	}
	_, err := tx.Apply(context.Background())
	if !errors.Is(err, ErrRecovered) || !recovered {
		t.Fatalf("error=%v recovered=%v", err, recovered)
	}
}

func TestTransactionCancellationRunsRecovery(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recovered := false
	tx := Transaction{
		Store: store, Previous: testManifest(root, RoleGermany),
		Desired: DesiredState{Role: RoleGermany, Paths: Paths{StateRoot: root}},
		Steps:   []Step{{Phase: PhasePrepare, Run: func(context.Context) error { t.Fatal("step ran"); return nil }}},
		Recover: func(context.Context, Manifest) error { recovered = true; return nil },
	}
	_, err := tx.Apply(ctx)
	if !errors.Is(err, ErrRecovered) || !recovered {
		t.Fatalf("error=%v recovered=%v", err, recovered)
	}
}
