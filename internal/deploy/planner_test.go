package deploy

import "testing"

func desiredFor(m Manifest) DesiredState {
	return DesiredState{
		Role:       m.Role,
		Components: m.Components,
		Paths:      m.Paths,
		Pairing:    m.Pairing,
		Services:   m.Services,
		Firewall:   m.Firewall,
	}
}

func TestPlanFreshInstall(t *testing.T) {
	p, err := PlanDesired(nil, DesiredState{Role: RoleIran})
	if err != nil {
		t.Fatal(err)
	}
	if p.Unchanged || len(p.Changes) != 1 || p.Changes[0].Field != "install" {
		t.Fatalf("plan = %+v, want one install change", p)
	}
}

func TestPlanUnchangedIsNoOp(t *testing.T) {
	m := testManifest("/tmp/state", RoleGermany)
	p, err := PlanDesired(&m, desiredFor(m))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Unchanged || len(p.Changes) != 0 {
		t.Fatalf("plan = %+v, want unchanged", p)
	}
}

func TestPlanMarksOriginChangeDestructive(t *testing.T) {
	m := testManifest("/tmp/state", RoleIran)
	d := desiredFor(m)
	d.Components.Origin.Domain = "upload.example.org"
	p, err := PlanDesired(&m, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes) != 1 || !p.Changes[0].Destructive {
		t.Fatalf("plan = %+v, want one destructive change", p)
	}
}

func TestPlanRejectsRoleChange(t *testing.T) {
	m := testManifest("/tmp/state", RoleIran)
	_, err := PlanDesired(&m, DesiredState{Role: RoleGermany})
	if err == nil {
		t.Fatal("role change unexpectedly accepted")
	}
}

// TestPlanReportsGenuinePairingDrift guards the comparison the controller's
// carry-forward relies on: when desired really differs from the committed
// pairing state the planner must still report it, so the fix cannot merely
// delete the comparison.
func TestPlanReportsGenuinePairingDrift(t *testing.T) {
	current := testManifest("/tmp/state", RoleIran)
	current.Pairing = PairingState{State: "a-generated", Fingerprints: []string{"fp"}}
	desired := desiredFor(current)
	desired.Pairing = PairingState{State: "finalized", Fingerprints: []string{"fp"}}
	plan, err := PlanDesired(&current, desired)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Unchanged || len(plan.Changes) != 1 || plan.Changes[0].Field != "pairing.state" {
		t.Fatalf("plan = %+v, want one pairing.state change", plan)
	}
}
