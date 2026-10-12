package systemd

// key_isolation_test.go — C5 D3 key-isolation guard (design §12 C5, F-3).
//
// The only live config that embeds a Reality PRIVATE key is
// /etc/split-tunnel/xray-germany.json. C5 isolates it from the dashboard's
// group: the config converges to 0640 root:split-tunnel-xray (XrayKeyGroup),
// and the ONLY unit that joins that group is xray-germany.service (via its
// SupplementaryGroups= line). The dashboard unit (tunneldash.service) runs
// User=split-tunnel Group=split-tunnel and is NEVER in the key group, so a
// compromised tunneldash process cannot read the key from disk.
//
// These assertions are pure (renderer bytes + the key-file sets) and run on
// every host. The real file-mode/owner + dashboard-uid exclusion is
// exercised on Linux+root in key_isolation_linux_test.go.

import (
	"strings"
	"testing"
)

// TestC5KeyFileSetsAreDisjoint pins the partition: the key-bearing config
// (xray-germany.json) is in keyStateFiles, the service-readable-but-key-free
// configs are in liveStateFiles, and the two sets are disjoint. A future edit
// that moves xray-germany.json back into liveStateFiles (so it converges to
// root:split-tunnel, re-exposing the key to the dashboard group) fails here.
func TestC5KeyFileSetsAreDisjoint(t *testing.T) {
	keySet := map[string]bool{}
	for _, f := range keyStateFiles {
		keySet[f] = true
	}
	for _, f := range liveStateFiles {
		if keySet[f] {
			t.Fatalf("config %q is in BOTH liveStateFiles and keyStateFiles; the key isolation contract requires a disjoint split", f)
		}
	}
	if !keySet["xray-germany.json"] {
		t.Fatal("xray-germany.json must be classified as a key file (it embeds the Reality privateKey)")
	}
	// The Iran consumer config carries only PUBLIC Reality parameters, so it
	// must NOT be in the key set.
	if keySet["xray-consumer.json"] {
		t.Fatal("xray-consumer.json holds no private key and must stay service-group readable")
	}
}

// TestC5RendererGroupSeparation asserts the rendered units encode the
// separation: the xray unit joins the key group (and only the xray unit),
// the dashboard unit does not, and the dashboard's primary group is NOT the
// key group. This is the in-repo expression of "the tunneldash unit cannot
// read the key file."
func TestC5RendererGroupSeparation(t *testing.T) {
	// xray-germany.service must join the key group.
	xrayUnit, err := RenderUnit(Spec{
		Role:      RoleGermany,
		Component: ComponentXray,
		BinPath:   "/opt/split-tunnel/xray/current/xray",
	})
	if err != nil {
		t.Fatalf("RenderUnit xray: %v", err)
	}
	if !strings.Contains(string(xrayUnit), "SupplementaryGroups="+XrayKeyGroup+"\n") {
		t.Fatalf("xray-germany unit must declare SupplementaryGroups=%s so it can read the key config:\n%s", XrayKeyGroup, xrayUnit)
	}
	// ... but its primary group stays the service group.
	if !strings.Contains(string(xrayUnit), "Group="+ServiceGroup+"\n") {
		t.Fatalf("xray-germany unit primary group must remain %s:\n%s", ServiceGroup, xrayUnit)
	}

	// The dashboard unit must NOT join the key group at all.
	dashUnit, err := RenderExtraUnit(ExtraUnitSpec{
		Unit:       "tunneldash.service",
		BinPath:    "/opt/split-tunnel/tunneldash",
		BasePath:   "00112233445566778899aabbccddeeff",
		EnvFile:    "/etc/split-tunnel/dashboard.env",
		ConfigPath: "/etc/split-tunnel/dashboard/config.json",
	})
	if err != nil {
		t.Fatalf("RenderExtraUnit tunneldash: %v", err)
	}
	if strings.Contains(string(dashUnit), XrayKeyGroup) {
		t.Fatalf("tunneldash unit must NOT reference the key group %s (the dashboard must not be able to read the key):\n%s", XrayKeyGroup, dashUnit)
	}
	// The dashboard runs as the service user/group, which is a DIFFERENT
	// group than the key group — that is the whole isolation.
	if !strings.Contains(string(dashUnit), "User="+ServiceUser+"\n") || !strings.Contains(string(dashUnit), "Group="+ServiceGroup+"\n") {
		t.Fatalf("tunneldash unit must run User=%s Group=%s:\n%s", ServiceUser, ServiceGroup, dashUnit)
	}
	if XrayKeyGroup == ServiceGroup {
		t.Fatalf("the key group must be distinct from the service group (got both %q); otherwise the dashboard could read the key", ServiceGroup)
	}

	// The Iran consumer + splitter + origin units must not join the key group
	// either (only xray-germany reads the private key).
	for _, spec := range []Spec{
		{Role: RoleGermany, Component: ComponentSplitter, BinPath: "/opt/split-tunnel/germany-splitter", EnvFile: EnvFile(RoleGermany)},
		{Role: RoleIran, Component: ComponentSplitter, BinPath: "/opt/split-tunnel/iran-splitter", EnvFile: EnvFile(RoleIran)},
	} {
		u, err := RenderUnit(spec)
		if err != nil {
			t.Fatalf("RenderUnit %s: %v", spec.Component, err)
		}
		if strings.Contains(string(u), XrayKeyGroup) {
			t.Fatalf("%s unit must not join the key group %s:\n%s", spec.Component, XrayKeyGroup, u)
		}
	}
	consUnit, err := RenderExtraUnit(ExtraUnitSpec{Unit: "xray-consumer.service", BinPath: "/opt/split-tunnel/xray/current/xray"})
	if err != nil {
		t.Fatalf("RenderExtraUnit consumer: %v", err)
	}
	if strings.Contains(string(consUnit), XrayKeyGroup) {
		t.Fatalf("xray-consumer unit must not join the key group (the consumer config holds no private key):\n%s", consUnit)
	}
}
