package deploy

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type adapterFake struct {
	calls      []string
	errAt      string
	cleanupErr bool
}

func (f *adapterFake) call(name string) error {
	f.calls = append(f.calls, name)
	if f.errAt == name {
		return errors.New(name + " failed")
	}
	return nil
}
func (f *adapterFake) Prepare(context.Context, DesiredState) error  { return f.call("prepare") }
func (f *adapterFake) Validate(context.Context, DesiredState) error { return f.call("validate") }
func (f *adapterFake) Backup(context.Context, *Manifest) error      { return f.call("backup") }
func (f *adapterFake) Activate(context.Context, DesiredState) error { return f.call("activate") }
func (f *adapterFake) Transition(context.Context, DesiredState) error {
	return f.call("transition")
}
func (f *adapterFake) Health(context.Context, DesiredState) error { return f.call("health") }
func (f *adapterFake) Restore(context.Context, Manifest) error    { return f.call("restore") }
func (f *adapterFake) CleanupFresh(context.Context, DesiredState) error {
	f.calls = append(f.calls, "cleanup-fresh")
	if f.cleanupErr {
		return errors.New("cleanup-fresh failed")
	}
	return nil
}
func (f *adapterFake) Uninstall(context.Context, Manifest) error { return f.call("uninstall") }

func TestApplyDesiredMapsAdapterPhases(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fake := &adapterFake{}
	result, err := ApplyDesired(context.Background(), store, Manifest{}, DesiredState{
		Role:  RoleIran,
		Paths: Paths{StateRoot: store.Root},
	}, fake)
	if err != nil {
		t.Fatalf("ApplyDesired: %v", err)
	}
	if !reflect.DeepEqual(fake.calls, []string{"prepare", "validate", "backup", "activate", "transition", "health"}) {
		t.Fatalf("calls = %#v", fake.calls)
	}
	if !result.Changed || result.Manifest.Role != RoleIran {
		t.Fatalf("result = %+v", result)
	}
}

func TestApplyDesiredRecoversOnAdapterFailure(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	previous := testManifest(store.Root, RoleGermany)
	fake := &adapterFake{errAt: "activate"}
	_, err = ApplyDesired(context.Background(), store, previous, DesiredState{
		Role:  RoleGermany,
		Paths: Paths{StateRoot: store.Root},
	}, fake)
	if !errors.Is(err, ErrRecovered) {
		t.Fatalf("error = %v, want ErrRecovered", err)
	}
	if !reflect.DeepEqual(fake.calls, []string{"prepare", "validate", "backup", "activate", "restore"}) {
		t.Fatalf("calls = %#v", fake.calls)
	}
}

func TestApplyDesiredFreshFailureUsesExplicitCleanup(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fake := &adapterFake{errAt: "activate"}
	_, err = ApplyDesired(context.Background(), store, Manifest{}, DesiredState{
		Role:  RoleIran,
		Paths: Paths{StateRoot: store.Root},
	}, fake)
	if !errors.Is(err, ErrRecovered) {
		t.Fatalf("error = %v, want ErrRecovered", err)
	}
	if !reflect.DeepEqual(fake.calls, []string{"prepare", "validate", "backup", "activate", "cleanup-fresh"}) {
		t.Fatalf("fresh failure calls = %#v", fake.calls)
	}
}

func TestApplyDesiredFreshCleanupFailureIsFatal(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fake := &adapterFake{errAt: "activate", cleanupErr: true}
	_, err = ApplyDesired(context.Background(), store, Manifest{}, DesiredState{
		Role:  RoleIran,
		Paths: Paths{StateRoot: store.Root},
	}, fake)
	if !errors.Is(err, ErrTransaction) || errors.Is(err, ErrRecovered) {
		t.Fatalf("error = %v, want fatal unrecovered transaction error", err)
	}
}

func TestApplyDesiredRequiresAdapter(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyDesired(context.Background(), store, Manifest{}, DesiredState{Role: RoleIran}, nil)
	if !errors.Is(err, ErrTransaction) {
		t.Fatalf("error = %v, want ErrTransaction", err)
	}
}
