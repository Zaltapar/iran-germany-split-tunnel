package deploy

import (
	"testing"
)

// TestSplitterArtifactContentIdentityH3 pins the H-3 remediation at the
// deployment boundary:
//   - the manifest records the splitter content digest;
//   - changed bytes at the same path/version are planned as convergence;
//   - a re-apply with the identical digest stays a no-op;
//   - a legacy manifest that never asserted a splitter digest does NOT plan
//     spurious drift (the empty/unknown rule), and the next commit upgrades
//     it in place.
func TestSplitterArtifactContentIdentityH3(t *testing.T) {
	const splitter = "/opt/split-tunnel/bin/splitter"
	const version = "v1.0.0"

	t.Run("changed bytes at same path and version plan convergence", func(t *testing.T) {
		m := testManifest("/tmp/state", RoleIran)
		m.Components.Splitter = ComponentState{Version: version, Path: splitter, SHA256: "digest-a"}
		d := desiredFor(m)
		d.Components.Splitter = ComponentState{Version: version, Path: splitter, SHA256: "digest-b"}
		plan, err := PlanDesired(&m, d)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Unchanged {
			t.Fatalf("plan = %+v, want a splitter content-identity convergence", plan.Changes)
		}
		if !hasChange(plan, "components.splitter.sha256") {
			t.Fatalf("plan = %+v, want drift on components.splitter.sha256", plan.Changes)
		}
	})

	t.Run("identical digest at same path and version is a no-op", func(t *testing.T) {
		m := testManifest("/tmp/state", RoleIran)
		m.Components.Splitter = ComponentState{Version: version, Path: splitter, SHA256: "digest-a"}
		d := desiredFor(m)
		plan, err := PlanDesired(&m, d)
		if err != nil {
			t.Fatal(err)
		}
		if !plan.Unchanged {
			t.Fatalf("plan = %+v, want unchanged (correct reuse)", plan.Changes)
		}
	})

	t.Run("legacy manifest without asserted digest plans no spurious drift", func(t *testing.T) {
		m := testManifest("/tmp/state", RoleIran)
		// Simulate a schema-1 legacy manifest: it recorded the version/path but
		// never asserted a content digest (the field is empty).
		m.Components.Splitter = ComponentState{Version: version, Path: splitter}
		d := desiredFor(m)
		// A re-apply that likewise asserts nothing must not plan drift.
		d.Components.Splitter = ComponentState{Version: version, Path: splitter}
		plan, err := PlanDesired(&m, d)
		if err != nil {
			t.Fatal(err)
		}
		if !plan.Unchanged {
			t.Fatalf("legacy unasserted digest planned spurious drift: %+v", plan.Changes)
		}
	})

	t.Run("legacy manifest gains asserted digest and plans convergence once", func(t *testing.T) {
		m := testManifest("/tmp/state", RoleIran)
		// Legacy manifest: no recorded digest.
		m.Components.Splitter = ComponentState{Version: version, Path: splitter}
		// New request asserts a real digest (the CLI now computes it locally).
		d := desiredFor(m)
		d.Components.Splitter = ComponentState{Version: version, Path: splitter, SHA256: "digest-live"}
		plan, err := PlanDesired(&m, d)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Unchanged || !hasChange(plan, "components.splitter.sha256") {
			t.Fatalf("plan = %+v, want a one-time convergence that records the digest", plan.Changes)
		}
	})
}
