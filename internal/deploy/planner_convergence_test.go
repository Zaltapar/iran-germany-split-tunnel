package deploy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/origin"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

// hasChange reports whether the plan contains the named field.
func hasChange(p Plan, field string) bool {
	for _, c := range p.Changes {
		if c.Field == field {
			return true
		}
	}
	return false
}

// renderSafePath returns an absolute, whitespace-free binary path. The request
// helpers root artifacts under the checkout, whose path may contain spaces;
// systemd.RenderUnit rejects whitespace in BinPath, so a test that wants a
// rendered unit hash must use a render-safe path. This affects only the test
// fixture, not the property under test.
func renderSafePath(name string) string {
	if vol := filepath.VolumeName(absoluteTestPath("x")); vol != "" {
		return vol + string(filepath.Separator) + "split-tunnel-test-" + name
	}
	return "/opt/split-tunnel/" + name
}

// renderSafeRequest returns a request whose binary paths render cleanly.
func renderSafeRequest(r InstallRequest) InstallRequest {
	r.SplitterPath = renderSafePath("splitter")
	if r.Role == RoleGermany {
		r.XrayPath = renderSafePath("xray")
	}
	if r.Role == RoleIran {
		r.OriginPath = renderSafePath("caddy")
	}
	return r
}

// TestPlanDetectsBinaryHashDrift covers the ISSUE B gap-1 fix: an in-place
// binary replacement that keeps the same path and version is invisible to a
// path/version comparison but MUST be detected through the true binary hash.
func TestPlanDetectsBinaryHashDrift(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest, *DesiredState)
		field  string
	}{
		{
			"splitter binary",
			func(m *Manifest, d *DesiredState) {
				m.Components.Splitter = ComponentState{Version: "v1.0.0", Path: "/opt/split-tunnel/splitter", SHA256: "hash-a"}
				d.Components.Splitter = ComponentState{Version: "v1.0.0", Path: "/opt/split-tunnel/splitter", SHA256: "hash-b"}
			},
			"components.splitter.sha256",
		},
		{
			"xray binary",
			func(m *Manifest, d *DesiredState) {
				m.Components.Xray = ComponentState{Version: "v26.3.27", Path: "/opt/split-tunnel/xray/v26.3.27/xray", SHA256: "hash-a"}
				d.Components.Xray = ComponentState{Version: "v26.3.27", Path: "/opt/split-tunnel/xray/v26.3.27/xray", SHA256: "hash-b"}
			},
			"components.xray.sha256",
		},
		{
			"reality public fingerprint",
			func(m *Manifest, d *DesiredState) {
				m.Components.Xray = ComponentState{Version: "v26.3.27", RealityFingerprint: "fp-a"}
				d.Components.Xray = ComponentState{Version: "v26.3.27", RealityFingerprint: "fp-b"}
			},
			"components.xray.realityFingerprint",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := testManifest("/tmp/state", RoleGermany)
			d := desiredFor(m)
			tc.mutate(&m, &d)
			plan, err := PlanDesired(&m, d)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Unchanged || !hasChange(plan, tc.field) {
				t.Fatalf("plan = %#v, want drift on %q", plan.Changes, tc.field)
			}
		})
	}
}

// TestPlanDoesNotFabricateUnassertedBinaryHash pins the empty/unknown rule: a
// request that carries no artifact hash must NOT plan drift against a manifest
// that recorded one.
func TestPlanDoesNotFabricateUnassertedBinaryHash(t *testing.T) {
	m := testManifest("/tmp/state", RoleIran)
	m.Components.Splitter.SHA256 = "recorded-hash"
	d := desiredFor(m)
	d.Components.Splitter.SHA256 = "" // request asserts nothing
	plan, err := PlanDesired(&m, d)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Unchanged {
		t.Fatalf("unasserted hash planned drift: %#v", plan.Changes)
	}
}

// TestPlanDetectsOriginDrift covers the ISSUE B gap-3 fix: every origin field
// that participates in the render/plan is compared, so a changed Caddyfile,
// ACME setting, CDN setting, or upstream is planned.
func TestPlanDetectsOriginDrift(t *testing.T) {
	request := renderSafeRequest(validIranRequest())
	base, err := request.Desired()
	if err != nil {
		t.Fatal(err)
	}
	// Build the current manifest from the desired state so the unmutated
	// baseline is a genuine no-op first.
	current := Manifest{
		Schema:     SchemaVersion,
		Role:       RoleIran,
		Generation: "g1",
		Components: base.Components,
		Paths:      base.Paths,
		Pairing:    base.Pairing,
		Services:   base.Services,
		Firewall:   base.Firewall,
	}

	cases := []struct {
		name   string
		mutate func(*DesiredState)
		field  string
	}{
		{"domain", func(d *DesiredState) { d.Components.Origin.Domain = "other.example.com" }, "components.origin.domain"},
		{"caddyfile hash", func(d *DesiredState) { d.Components.Origin.CaddyfileHash = "different" }, "components.origin.caddyfileHash"},
		{"acme challenge", func(d *DesiredState) { d.Components.Origin.ACMEChallenge = string(origin.ACMETLSALPN01) }, "components.origin.acmeChallenge"},
		{"acme email", func(d *DesiredState) { d.Components.Origin.ACMEEmail = "ops@example.com" }, "components.origin.acmeEmail"},
		{"upstream", func(d *DesiredState) { d.Components.Origin.UpstreamAddr = "127.0.0.1:9100" }, "components.origin.upstreamAddr"},
		{"cdn security", func(d *DesiredState) { d.Components.Origin.CDNSecurity = string(origin.CDNTLSOrigin) }, "components.origin.cdnSecurity"},
		{"cdn origin trust", func(d *DesiredState) { d.Components.Origin.CDNOriginTrust = string(origin.CDNOriginTrustPullCA) }, "components.origin.cdnOriginTrust"},
		{"origin port", func(d *DesiredState) { d.Components.Origin.OriginPort = 8443 }, "components.origin.originPort"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			tc.mutate(&d)
			plan, err := PlanDesired(&current, d)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Unchanged || !hasChange(plan, tc.field) {
				t.Fatalf("plan = %#v, want drift on %q", plan.Changes, tc.field)
			}
		})
	}

	// Baseline sanity: the unmutated desired state against a manifest built
	// from it is a true no-op.
	plan, err := PlanDesired(&current, base)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Unchanged {
		t.Fatalf("baseline planned spurious drift: %#v", plan.Changes)
	}
}

// TestPlanDetectsUnitDrift covers the ISSUE B gap-5 fix: a changed rendered unit
// (same unit name, different bytes) is detected through ServiceState.Hash.
func TestPlanDetectsUnitDrift(t *testing.T) {
	m := testManifest("/tmp/state", RoleIran)
	m.Services = []ServiceState{{Unit: "iran-splitter.service", Component: "splitter", Hash: "old-hash"}}
	d := desiredFor(m)
	d.Services = []ServiceState{{Unit: "iran-splitter.service", Component: "splitter", Hash: "new-hash"}}
	plan, err := PlanDesired(&m, d)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Unchanged || !hasChange(plan, "services") {
		t.Fatalf("plan = %#v, want services drift", plan.Changes)
	}

	// An unasserted (empty) desired hash must not plan drift.
	d.Services = []ServiceState{{Unit: "iran-splitter.service", Component: "splitter", Hash: ""}}
	plan, err = PlanDesired(&m, d)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Unchanged {
		t.Fatalf("unasserted unit hash planned drift: %#v", plan.Changes)
	}
}

// TestPlanDetectsPairingFingerprintDrift covers the ISSUE B gap-6 fix: pairing
// fingerprints are compared, not only the pairing state.
func TestPlanDetectsPairingFingerprintDrift(t *testing.T) {
	m := testManifest("/tmp/state", RoleIran)
	m.Pairing = PairingState{State: "finalized", Fingerprints: []string{"fp-a"}}
	d := desiredFor(m)
	d.Pairing = PairingState{State: "finalized", Fingerprints: []string{"fp-b"}}
	plan, err := PlanDesired(&m, d)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Unchanged || !hasChange(plan, "pairing.fingerprints") {
		t.Fatalf("plan = %#v, want pairing fingerprint drift", plan.Changes)
	}
}

// TestPlanDetectsManagedPathDrift covers the ISSUE B gap-4 fix: the managed
// paths derived from internal/systemd are recorded and compared.
func TestPlanDetectsManagedPathDrift(t *testing.T) {
	m := testManifest("/tmp/state", RoleIran)
	m.Paths.UnitDir = systemd.UnitDir
	m.Paths.BinaryPrefix = systemd.BinaryPrefix
	d := desiredFor(m)
	d.Paths.UnitDir = "/etc/systemd/system-relocated"
	plan, err := PlanDesired(&m, d)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Unchanged || !hasChange(plan, "paths.unitDir") {
		t.Fatalf("plan = %#v, want paths.unitDir drift", plan.Changes)
	}
}

// TestDesiredRecordsUnitHashesAndPaths proves the desired state actually
// populates the new fields (from the authoritative systemd renderer and
// constants) rather than leaving them empty.
func TestDesiredRecordsUnitHashesAndPaths(t *testing.T) {
	requests := []InstallRequest{renderSafeRequest(validIranRequest()), renderSafeRequest(validGermanyRequest())}
	for _, request := range requests {
		d, err := request.Desired()
		if err != nil {
			t.Fatalf("Desired(%s): %v", request.Role, err)
		}
		if d.Paths.UnitDir != systemd.UnitDir || d.Paths.BinaryPrefix != systemd.BinaryPrefix {
			t.Fatalf("managed paths not derived from systemd constants: %+v", d.Paths)
		}
		if len(d.Paths.UnitFiles) != len(d.Services) {
			t.Fatalf("unit files %d != services %d", len(d.Paths.UnitFiles), len(d.Services))
		}
		for _, s := range d.Services {
			if s.Hash == "" {
				t.Fatalf("service %q has no rendered-unit hash", s.Unit)
			}
		}
		if request.Role == RoleGermany {
			if d.Components.Xray.RealityFingerprint == "" {
				t.Fatal("Germany xray reality fingerprint not recorded")
			}
			if d.Paths.BinaryPointer == "" {
				t.Fatal("Germany binary pointer not recorded")
			}
		}
		if request.Role == RoleIran {
			if d.Components.Origin.CaddyfileHash == "" {
				t.Fatal("Iran caddy origin caddyfile hash not recorded")
			}
		}
	}
}

// TestConvergenceStableAcrossRepeatedApply is the idempotence guarantee: a
// fresh install followed by re-planning the identical desired state is a TRUE
// no-op (Unchanged, no transaction, no journal, no adapter calls).
func TestConvergenceStableAcrossRepeatedApply(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := requestIn(t, store, renderSafeRequest(validIranRequest()))

	first, err := (&Controller{Store: store, Adapter: &controllerFake{}}).ApplyRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("first ApplyRequest: %v", err)
	}
	if !first.Changed {
		t.Fatal("fresh install did not change the host")
	}
	// The committed manifest must record real unit hashes (not empty), proving
	// the stability below is meaningful rather than vacuous.
	for _, s := range first.Manifest.Services {
		if s.Hash == "" {
			t.Fatalf("committed service %q has no unit hash", s.Unit)
		}
	}

	// A direct plan against the committed manifest must be unchanged.
	desired, err := request.Desired()
	if err != nil {
		t.Fatal(err)
	}
	previous, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanDesired(&previous, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Unchanged {
		t.Fatalf("re-plan after apply = %#v, want unchanged", plan.Changes)
	}

	// A second apply is a no-op: no adapter calls, no journal.
	second := &controllerFake{}
	result, err := (&Controller{Store: store, Adapter: second}).ApplyRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("second ApplyRequest: %v", err)
	}
	if !result.Plan.Unchanged || result.Changed {
		t.Fatalf("second apply = %+v, want unchanged no-op", result.Plan)
	}
	if len(second.calls) != 0 {
		t.Fatalf("second apply mutated the host: %#v", second.calls)
	}
	if _, err := store.ReadJournal(); !os.IsNotExist(err) {
		t.Fatalf("no-op apply wrote a journal: %v", err)
	}
}
