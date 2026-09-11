package firewall

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeExecutor struct {
	calls     [][]string
	out       string
	err       error
	failAt    int
	failError error
}

func (f *fakeExecutor) Run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(f.calls) == 1 {
		return f.out, f.err
	}
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return "", f.failError
	}
	return "", f.err
}

func testPlan() Plan {
	return Plan{
		Backend: BackendUFW,
		Role:    "germany",
		Allow:   []Rule{{Port: 443, Protocol: "tcp", Action: "allow", Comment: Marker}},
		Deny:    []Rule{{Port: 9002, Protocol: "tcp", Action: "deny", Comment: Marker}},
	}
}

func TestApplyIsIdempotentForOwnedRules(t *testing.T) {
	f := &fakeExecutor{out: "443/tcp ALLOW Anywhere # split-tunnel\n9002/tcp DENY Anywhere # split-tunnel"}
	m := New(f)
	got, err := m.Apply(context.Background(), testPlan())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !got.Unchanged || len(got.Added) != 0 {
		t.Fatalf("result = %+v, want unchanged with no additions", got)
	}
	wantCalls := [][]string{{"ufw", "status", "number"}}
	if !reflect.DeepEqual(f.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", f.calls, wantCalls)
	}
}

func TestApplyUsesSeparatedArgvAndAddsMissingRule(t *testing.T) {
	f := &fakeExecutor{out: ""}
	m := New(f)
	got, err := m.Apply(context.Background(), Plan{
		Backend: BackendUFW,
		Role:    "iran",
		Allow:   []Rule{{Port: 443, Protocol: "tcp", Action: "allow", Comment: Marker}},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(got.Added) != 1 || got.Added[0].Port != 443 {
		t.Fatalf("added = %+v, want port 443", got.Added)
	}
	want := [][]string{
		{"ufw", "status", "number"},
		{"ufw", "allow", "443/tcp", "comment", Marker},
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %#v, want %#v", f.calls, want)
	}
}

func TestRemoveNeverRemovesUnownedRules(t *testing.T) {
	f := &fakeExecutor{}
	m := New(f)
	err := m.Remove(context.Background(), Snapshot{
		Backend: BackendUFW,
		Rules: []Rule{
			{Port: 443, Protocol: "tcp", Action: "allow", Comment: Marker},
			{Port: 22, Protocol: "tcp", Action: "allow", Comment: "openssh"},
		},
	})
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	want := [][]string{{"ufw", "delete", "allow", "443/tcp"}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %#v, want %#v", f.calls, want)
	}
}

func TestInvalidPlanFailsBeforeExecutor(t *testing.T) {
	f := &fakeExecutor{}
	m := New(f)
	_, err := m.Apply(context.Background(), Plan{
		Backend: BackendUFW,
		Role:    "germany",
		Allow:   []Rule{{Port: 443, Protocol: "udp", Action: "allow", Comment: Marker}},
	})
	if !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("error = %v, want ErrInvalidPlan", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("executor calls = %#v, want none", f.calls)
	}
}

func TestApplyRollsBackPartialFailure(t *testing.T) {
	f := &fakeExecutor{failAt: 3, failError: errors.New("injected")}
	m := New(f)
	_, err := m.Apply(context.Background(), Plan{
		Backend: BackendUFW,
		Role:    "iran",
		Allow: []Rule{
			{Port: 443, Protocol: "tcp", Action: "allow", Comment: Marker},
			{Port: 80, Protocol: "tcp", Action: "allow", Comment: Marker},
		},
	})
	if err == nil {
		t.Fatal("Apply succeeded after injected command failure")
	}
	want := [][]string{
		{"ufw", "status", "number"},
		{"ufw", "allow", "443/tcp", "comment", Marker},
		{"ufw", "allow", "80/tcp", "comment", Marker},
		{"ufw", "delete", "allow", "443/tcp"},
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %#v, want %#v", f.calls, want)
	}
}

func TestApplyReportsPartialFailure(t *testing.T) {
	f := &fakeExecutor{err: errors.New("injected")}
	m := New(f)
	_, err := m.Apply(context.Background(), Plan{
		Backend: BackendUFW,
		Role:    "iran",
		Allow: []Rule{
			{Port: 443, Protocol: "tcp", Action: "allow", Comment: Marker},
			{Port: 80, Protocol: "tcp", Action: "allow", Comment: Marker},
		},
	})
	if err == nil {
		t.Fatal("Apply succeeded after injected command failure")
	}
	if len(f.calls) != 1 {
		t.Fatalf("calls = %#v, want inspect only before first failed add", f.calls)
	}
}

func TestNoneBackendIsNoOp(t *testing.T) {
	f := &fakeExecutor{}
	m := New(f)
	got, err := m.Apply(context.Background(), Plan{Backend: BackendNone, Role: "iran"})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !got.Unchanged || len(f.calls) != 0 {
		t.Fatalf("result=%+v calls=%#v, want unchanged/no calls", got, f.calls)
	}
}
