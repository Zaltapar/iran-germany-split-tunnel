package deploy

import "testing"

func TestPlanDesiredDetectsCompleteStateDrift(t *testing.T) {
	current := testManifest("/tmp/state", RoleGermany)
	current.Services = []ServiceState{{Unit: "germany-splitter.service", Component: "splitter"}}
	current.Firewall = FirewallState{Backend: "none", Ownership: "split-tunnel", RulesHash: "old"}
	base := desiredFor(current)
	base.Services = append([]ServiceState(nil), current.Services...)
	base.Firewall = current.Firewall
	base.Pairing = PairingState{State: "a-applied"}

	cases := []struct {
		name   string
		mutate func(*DesiredState)
		field  string
	}{
		{"service", func(d *DesiredState) {
			d.Services = append(d.Services, ServiceState{Unit: "xray-germany.service", Component: "xray"})
		}, "services"},
		{"firewall", func(d *DesiredState) { d.Firewall.RulesHash = "new" }, "firewall.rulesHash"},
		{"pairing", func(d *DesiredState) { d.Pairing.State = "finalized" }, "pairing.state"},
		{"component", func(d *DesiredState) { d.Components.Xray.Version = "v26.3.28" }, "components.xray.version"},
		{"path", func(d *DesiredState) { d.Paths.Config = "/tmp/state/other.json" }, "paths.config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			tc.mutate(&d)
			plan, err := PlanDesired(&current, d)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, change := range plan.Changes {
				if change.Field == tc.field {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("changes = %#v, missing %q", plan.Changes, tc.field)
			}
		})
	}
}
