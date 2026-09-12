package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

func TestTransactionWritesJournalBeforeMutationAndClearsAfterCommit(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(root)
	var observedInStep ArtifactJournal
	sawJournalInStep := false
	tx := Transaction{
		Store: store,
		Journal: ArtifactJournal{
			Role:  RoleIran,
			Units: []string{"iran-splitter.service"},
		},
		Desired: DesiredState{Role: RoleIran, Paths: Paths{StateRoot: root}},
		Steps: []Step{
			{Phase: PhasePrepare, Name: "prepare", Run: func(context.Context) error {
				j, err := store.ReadJournal()
				if err != nil {
					return err
				}
				observedInStep = j
				sawJournalInStep = true
				return nil
			}},
		},
	}
	_, err := tx.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !sawJournalInStep {
		t.Fatal("journal was not visible inside a step (must be written before mutation)")
	}
	if observedInStep.Role != RoleIran || observedInStep.Generation == "" {
		t.Fatalf("in-step journal = %+v, want role+generation set", observedInStep)
	}
	if _, err := os.Stat(filepath.Join(root, "journal.json")); !os.IsNotExist(err) {
		t.Fatalf("journal still present after commit: %v", err)
	}
}

func TestTransactionRetainsJournalOnFailureAndOnUnrecoveredRecovery(t *testing.T) {
	for name, fatal := range map[string]bool{
		"recovered":   false,
		"unrecovered": true,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			store, _ := NewStore(root)
			tx := Transaction{
				Store: store,
				Journal: ArtifactJournal{
					Role:  RoleIran,
					Units: []string{"iran-splitter.service"},
				},
				Desired: DesiredState{Role: RoleIran, Paths: Paths{StateRoot: root}},
				Steps:   []Step{{Phase: PhaseActivate, Name: "activate", Run: func(context.Context) error { return errors.New("injected") }}},
				Recover: func(context.Context, Manifest) error {
					if fatal {
						return errors.New("recovery also failed")
					}
					return nil
				},
			}
			_, err := tx.Apply(context.Background())
			if !errors.Is(err, ErrTransaction) {
				t.Fatalf("error=%v, want ErrTransaction", err)
			}
			if !fatal && !errors.Is(err, ErrRecovered) {
				t.Fatalf("error=%v, want ErrRecovered", err)
			}
			j, err := store.ReadJournal()
			if err != nil {
				t.Fatalf("journal must remain after failure: %v", err)
			}
			if j.Role != RoleIran || len(j.Units) != 1 {
				t.Fatalf("retained journal = %+v", j)
			}
		})
	}
}

func TestTransactionRejectsInvalidJournalBeforeAnyMutation(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(root)
	ran := false
	tx := Transaction{
		Store: store,
		Journal: ArtifactJournal{
			Role:  RoleIran,
			Units: []string{"../evil.service"},
		},
		Desired: DesiredState{Role: RoleIran, Paths: Paths{StateRoot: root}},
		Steps:   []Step{{Phase: PhasePrepare, Run: func(context.Context) error { ran = true; return nil }}},
	}
	_, err := tx.Apply(context.Background())
	if err == nil {
		t.Fatal("invalid journal accepted")
	}
	if ran {
		t.Fatal("steps ran despite invalid journal (must fail before mutation)")
	}
	if _, err := os.Stat(filepath.Join(root, "journal.json")); !os.IsNotExist(err) {
		t.Fatal("invalid journal was persisted")
	}
}

func TestApplyDesiredPersistsAndClearsJournal(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	fake := &adapterFake{}
	root := store.Root
	_, err := ApplyDesired(context.Background(), store, Manifest{}, DesiredState{
		Role:     RoleIran,
		Paths:    Paths{StateRoot: root},
		Services: []ServiceState{{Unit: "iran-splitter.service", Component: "splitter"}},
	}, fake)
	if err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "journal.json")); !os.IsNotExist(err) {
		t.Fatal("journal must be cleared after a committed install")
	}
}

func TestApplyDesiredRetainsJournalOnAdapterFailure(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	fake := &adapterFake{errAt: "health"}
	root := store.Root
	_, err := ApplyDesired(context.Background(), store, Manifest{}, DesiredState{
		Role:     RoleIran,
		Paths:    Paths{StateRoot: root},
		Services: []ServiceState{{Unit: "iran-splitter.service", Component: "splitter"}},
	}, fake)
	if !errors.Is(err, ErrRecovered) {
		t.Fatalf("error=%v, want ErrRecovered", err)
	}
	j, err := store.ReadJournal()
	if err != nil {
		t.Fatalf("journal must remain for operator recovery: %v", err)
	}
	if len(j.Units) != 1 || j.Units[0] != "iran-splitter.service" {
		t.Fatalf("retained journal units = %#v", j.Units)
	}
}
