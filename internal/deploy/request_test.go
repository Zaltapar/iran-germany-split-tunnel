package deploy

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/firewall"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/origin"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

func absoluteTestPath(name string) string {
	path, err := filepath.Abs(filepath.Join("split-tunnel-test", name))
	if err != nil {
		panic(err)
	}
	return path
}

func validIranRequest() InstallRequest {
	c := *config.Defaults()
	c.SocksListen = "127.0.0.1:10900"
	c.WsListen = "127.0.0.1:9001"
	c.DownCarrierAddr = "127.0.0.1:10802"
	c.Secret = strings.Repeat("a", 64)
	// RFC 1929 SOCKS credentials (plans/socks5-auth-design.md §7.3):
	// extend the fixture so every projection/planner/golden test
	// exercises the new keys for free. The password is a
	// policy-satisfying 40-char value.
	c.SocksUser = "alice"
	c.SocksPass = strings.Repeat("z", 40)
	return InstallRequest{
		Role:            RoleIran,
		Config:          c,
		Origin:          origin.Plan{Mode: origin.ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001"},
		StateRoot:       absoluteTestPath("state"),
		EnvPath:         absoluteTestPath(filepath.Join("state", "iran.env")),
		ConfigPath:      absoluteTestPath(filepath.Join("state", "iran.json")),
		SplitterVersion: "v1.0.0",
		SplitterPath:    absoluteTestPath("iran-splitter"),
		OriginVersion:   "v2.11.4",
		OriginPath:      absoluteTestPath("caddy"),
		Firewall:        firewall.Plan{Backend: firewall.BackendNone, Role: RoleIran},
	}
}

func validGermanyRequest() InstallRequest {
	c := *config.Defaults()
	c.UpWsUrl = "wss://upload.example.com/upload"
	c.DownListen = ":9002"
	c.Secret = strings.Repeat("b", 64)
	return InstallRequest{
		Role:            RoleGermany,
		Config:          c,
		Origin:          origin.Plan{Mode: origin.ModeNone, UpstreamAddr: "127.0.0.1:9001"},
		StateRoot:       absoluteTestPath("state"),
		EnvPath:         absoluteTestPath(filepath.Join("state", "germany.env")),
		ConfigPath:      absoluteTestPath(filepath.Join("state", "xray-germany.json")),
		SplitterVersion: "v1.0.0",
		SplitterPath:    absoluteTestPath("germany-splitter"),
		XrayVersion:     "v26.3.27",
		XrayPath:        absoluteTestPath("xray"),
		Reality:         xray.RealityParams{SNI: "www.example.com", ShortID: "0123456789abcdef", UUID: "550e8400-e29b-41d4-a716-446655440000"},
		Firewall:        firewall.Plan{Backend: firewall.BackendNone, Role: RoleGermany},
	}
}

func TestInstallRequestDesiredValidRoles(t *testing.T) {
	for _, request := range []InstallRequest{validIranRequest(), validGermanyRequest()} {
		desired, err := request.Desired()
		if err != nil {
			t.Fatalf("Desired(%s): %v", request.Role, err)
		}
		if desired.Role != request.Role || desired.Paths.StateRoot != request.StateRoot {
			t.Fatalf("desired = %+v", desired)
		}
		if desired.Pairing.State != "none" {
			t.Fatalf("pairing state = %q", desired.Pairing.State)
		}
		if desired.Firewall.Backend != string(firewall.BackendNone) || desired.Firewall.Ownership != firewall.Marker || desired.Firewall.RulesHash == "" {
			t.Fatalf("firewall projection = %+v", desired.Firewall)
		}
		if request.Role == RoleGermany && len(desired.Services) != 2 {
			t.Fatalf("Germany services = %+v", desired.Services)
		}
		if request.Role == RoleIran && len(desired.Services) != 2 {
			t.Fatalf("Iran services = %+v", desired.Services)
		}
	}
}

func TestInstallRequestEnvProjectionKeepsSecretOutOfDesiredState(t *testing.T) {
	r := validIranRequest()
	env, err := r.Env()
	if err != nil {
		t.Fatal(err)
	}
	if env[config.EnvSecret] != r.Config.Secret {
		t.Fatal("env projection omitted the secret")
	}
	// RFC 1929: both credentials are projected into the env map (the
	// fixture now carries them), so the env projection must include them
	// but the desired state must not.
	if env[config.EnvSocksUser] != r.Config.SocksUser || env[config.EnvSocksPass] != r.Config.SocksPass {
		t.Fatalf("env projection omitted the RFC 1929 credentials: user=%q pass=%q", env[config.EnvSocksUser], env[config.EnvSocksPass])
	}
	desired, err := r.Desired()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join([]string{desired.Components.Splitter.Path, desired.Paths.Env, desired.Paths.Config}, "\n")
	if strings.Contains(joined, r.Config.Secret) {
		t.Fatal("desired state contains the tunnel secret")
	}
	// The SOCKS password must not appear in any desired-state field either
	// (same non-invertible-fingerprint guarantee as SPLIT_SECRET).
	if strings.Contains(desired.ConfigFingerprint, r.Config.SocksPass) {
		t.Fatal("config fingerprint contains the SOCKS password")
	}
}

// TestConfigFingerprintTracksEveryProjectedValue pins the configuration
// identity that makes `config set` planner-visible: any change to a projected
// value — the shared secret included — changes the digest, while an identical
// configuration yields an identical one.
func TestConfigFingerprintTracksEveryProjectedValue(t *testing.T) {
	base := validIranRequest()
	basePrint, err := base.ConfigFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if basePrint == "" {
		t.Fatal("empty config fingerprint")
	}
	if strings.Contains(basePrint, base.Config.Secret) {
		t.Fatal("config fingerprint contains the tunnel secret")
	}
	again, err := base.ConfigFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if again != basePrint {
		t.Fatalf("fingerprint is not deterministic: %q != %q", again, basePrint)
	}
	// The Desired projection must record the SAME identity the helper
	// returns, so the CLI's change detection and the planner agree.
	desired, err := base.Desired()
	if err != nil {
		t.Fatal(err)
	}
	if desired.ConfigFingerprint != basePrint {
		t.Fatalf("desired fingerprint = %q, want %q", desired.ConfigFingerprint, basePrint)
	}

	// A changed secret (or any other projected value) is a different
	// configuration; each case must be detected.
	cases := []struct {
		name   string
		mutate func(*InstallRequest)
	}{
		{"secret", func(r *InstallRequest) { r.Config.Secret = strings.Repeat("c", 64) }},
		{"socks listener", func(r *InstallRequest) { r.Config.SocksListen = "127.0.0.1:10901" }},
		{"ws listener", func(r *InstallRequest) { r.Config.WsListen = "127.0.0.1:9002" }},
		{"down carrier", func(r *InstallRequest) { r.Config.DownCarrierAddr = "127.0.0.1:10803" }},
		{"metrics port", func(r *InstallRequest) { r.Config.MetricsPort = 9100 }},
		{"relay buffer", func(r *InstallRequest) { r.Config.RelayBufSize = 65536 }},
		{"queue bytes", func(r *InstallRequest) { r.Config.QueueBytesPerStream = 1 << 20 }},
		{"queue frames", func(r *InstallRequest) { r.Config.QueueFramesPerStream = 8 }},
		{"queue total", func(r *InstallRequest) { r.Config.QueueBytesTotal = 4 << 20 }},
		{"overflow wait", func(r *InstallRequest) { r.Config.OverflowWaitMs = 250 }},
		{"carrier grace", func(r *InstallRequest) { r.Config.CarrierGraceMs = 7000 }},
		{"bootstrap wait", func(r *InstallRequest) { r.Config.BootstrapWaitMs = 1000 }},
		{"session buffer", func(r *InstallRequest) { r.Config.SessionBufBytes = 512 << 10 }},
		{"session buffer total", func(r *InstallRequest) { r.Config.SessionBufTotal = 8 << 20 }},
		{"liveness rounds", func(r *InstallRequest) { r.Config.LivenessRounds = 5 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.mutate(&changed)
			got, err := changed.ConfigFingerprint()
			if err != nil {
				t.Fatal(err)
			}
			if got == basePrint {
				t.Fatalf("%s change did not alter the config fingerprint", tc.name)
			}
		})
	}
}

// TestPlanDetectsConfigOnlyChange is the core of the config-set wiring: a
// change that touches ONLY the projected configuration must be planned, so
// the transaction reaches the adapter (which rewrites the env file) instead
// of short-circuiting as unchanged.
func TestPlanDetectsConfigOnlyChange(t *testing.T) {
	request := validIranRequest()
	desired, err := request.Desired()
	if err != nil {
		t.Fatal(err)
	}
	current := Manifest{
		Schema:            SchemaVersion,
		Role:              desired.Role,
		Generation:        "g1",
		Components:        desired.Components,
		Paths:             desired.Paths,
		Pairing:           desired.Pairing,
		Services:          desired.Services,
		Firewall:          desired.Firewall,
		ConfigFingerprint: desired.ConfigFingerprint,
	}
	// Baseline: an identical configuration is a true no-op.
	plan, err := PlanDesired(&current, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Unchanged {
		t.Fatalf("identical configuration planned drift: %#v", plan.Changes)
	}

	// A configuration-only change (nothing else differs) must be planned.
	changed := request
	changed.Config.RelayBufSize = 65536
	changedDesired, err := changed.Desired()
	if err != nil {
		t.Fatal(err)
	}
	if changedDesired.Components != desired.Components || !reflect.DeepEqual(changedDesired.Paths, desired.Paths) {
		t.Fatal("fixture changed more than the configuration")
	}
	plan, err = PlanDesired(&current, changedDesired)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Unchanged || !hasChange(plan, "config.fingerprint") {
		t.Fatalf("plan = %#v, want config.fingerprint drift", plan.Changes)
	}
	if plan.Changes[0].Destructive {
		t.Fatalf("config change marked destructive: %#v", plan.Changes)
	}
}

// TestPlanDoesNotFabricateConfigIdentity pins the empty/unknown rule for the
// configuration identity: a legacy manifest that never recorded it must not
// plan spurious drift against a request that asserts one.
func TestPlanDoesNotFabricateConfigIdentity(t *testing.T) {
	m := testManifest("/tmp/state", RoleIran)
	d := desiredFor(m)
	d.ConfigFingerprint = ""
	plan, err := PlanDesired(&m, d)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Unchanged {
		t.Fatalf("unasserted config identity planned drift: %#v", plan.Changes)
	}
}

// TestConfigKeyTableIsCompleteAndConsistent pins the projection table the CLI
// resolves `config set` keys through: every settable key names a real
// config.Env* variable, is unique, and applies to at least one role.
func TestConfigKeyTableIsCompleteAndConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, key := range ConfigKeys {
		if key.Name == "" || key.EnvVar == "" {
			t.Fatalf("incomplete key entry: %+v", key)
		}
		if len(key.Roles) == 0 {
			t.Fatalf("key %q applies to no role", key.Name)
		}
		normalized := NormalizeConfigKey(key.Name)
		if seen[normalized] {
			t.Fatalf("duplicate key %q", key.Name)
		}
		seen[normalized] = true
		for _, role := range key.Roles {
			if role != RoleIran && role != RoleGermany {
				t.Fatalf("key %q has invalid role %q", key.Name, role)
			}
		}
	}
	// Lookup accepts the canonical spelling and a normalized variant.
	if _, ok := LookupConfigKey("relay.buf"); !ok {
		t.Fatal("canonical key not found")
	}
	if _, ok := LookupConfigKey("RELAY_BUF"); !ok {
		t.Fatal("normalized key not found")
	}
	if _, ok := LookupConfigKey("nope"); ok {
		t.Fatal("unknown key unexpectedly resolved")
	}
	// The one deliberately non-settable field is refused with a reason and is
	// NOT settable.
	if reason := ConfigKeyRefusal(ConfigKeyKeepAlive); reason == "" {
		t.Fatalf("%s has no documented refusal reason", ConfigKeyKeepAlive)
	}
	if _, ok := LookupConfigKey(ConfigKeyKeepAlive); ok {
		t.Fatalf("%s must not be settable", ConfigKeyKeepAlive)
	}
}

// TestRestartAfterConfigChange pins the adapter's restart decision: a
// configuration-only change restarts an unchanged unit (the env file it reads
// was rewritten), while a unit whose bytes changed is left to T5's own
// transition and an unchanged configuration never restarts anything.
func TestRestartAfterConfigChange(t *testing.T) {
	cases := []struct {
		name          string
		unchanged     bool
		configChanged bool
		want          bool
	}{
		{"config change with unchanged unit bytes", true, true, true},
		{"config change with rewritten unit", false, true, false},
		{"no config change with unchanged unit bytes", true, false, false},
		{"no config change with rewritten unit", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := restartAfterConfigChange(systemd.Result{Unchanged: tc.unchanged}, tc.configChanged)
			if got != tc.want {
				t.Fatalf("restartAfterConfigChange = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInstallRequestRejectsPathEscape(t *testing.T) {
	r := validIranRequest()
	r.EnvPath = filepath.Join(filepath.Dir(r.StateRoot), "escape.env")
	if err := r.Validate(); err == nil {
		t.Fatal("path escape unexpectedly accepted")
	}
}

func TestInstallRequestRejectsUnsafeOrIncompleteInput(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*InstallRequest)
	}{
		{"bad role", func(r *InstallRequest) { r.Role = "other" }},
		{"missing splitter artifact", func(r *InstallRequest) { r.SplitterPath = "" }},
		{"Germany missing xray", func(r *InstallRequest) { r.XrayPath = "" }},
		{"invalid xray version", func(r *InstallRequest) { r.XrayVersion = "latest" }},
		{"invalid origin version", func(r *InstallRequest) { r.OriginVersion = "latest" }},
		{"invalid origin plan", func(r *InstallRequest) {
			r.Origin = origin.Plan{Mode: origin.ModeCaddy, Domain: "bad domain", UpstreamAddr: "127.0.0.1:9001"}
		}},
		{"relative state root", func(r *InstallRequest) { r.StateRoot = "relative" }},
		{"Iran none origin", func(r *InstallRequest) { r.Origin = origin.Plan{Mode: origin.ModeNone, UpstreamAddr: "127.0.0.1:9001"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validIranRequest()
			if tc.name == "Germany missing xray" {
				r = validGermanyRequest()
			}
			tc.mutate(&r)
			if _, err := r.Desired(); err == nil {
				t.Fatal("Desired unexpectedly succeeded")
			}
		})
	}
}

// TestConfigFingerprintChangesWhenSocksPassChanges mirrors
// TestConfigFingerprintTracksEveryProjectedValue for the RFC 1929 keys
// (plans/socks5-auth-design.md §7.3): changing the password changes the
// fingerprint, an identical request yields an equal fingerprint, and the
// digest never contains either credential.
func TestConfigFingerprintChangesWhenSocksPassChanges(t *testing.T) {
	base := validIranRequest()
	baseFp, err := base.ConfigFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(baseFp, base.Config.SocksPass) || strings.Contains(baseFp, base.Config.SocksUser) {
		t.Fatal("config fingerprint contains an RFC 1929 credential")
	}
	// Deterministic: identical request → identical digest.
	again, err := base.ConfigFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if again != baseFp {
		t.Fatalf("fingerprint not deterministic: %q != %q", again, baseFp)
	}
	// A changed password is a different configuration.
	mut := base
	mut.Config.SocksPass = strings.Repeat("y", 40)
	mutFp, err := mut.ConfigFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if mutFp == baseFp {
		t.Fatal("fingerprint did not change when the SOCKS password changed")
	}
}

// TestLookupConfigKeySocksUserPass proves the CLI key table resolves the
// new keys in every accepted spelling and refuses the rejected combined
// form (plans/socks5-auth-design.md §7.3).
func TestLookupConfigKeySocksUserPass(t *testing.T) {
	cases := []struct {
		key  string
		want string
	}{
		{"socks.user", config.EnvSocksUser},
		{"SOCKS_USER", config.EnvSocksUser},
		{"socks-user", config.EnvSocksUser},
		{"socks.pass", config.EnvSocksPass},
		{"SOCKS_PASS", config.EnvSocksPass},
		{"socks-pass", config.EnvSocksPass},
	}
	for _, tc := range cases {
		k, ok := LookupConfigKey(tc.key)
		if !ok {
			t.Fatalf("LookupConfigKey(%q) not found", tc.key)
		}
		if k.EnvVar != tc.want {
			t.Fatalf("LookupConfigKey(%q).EnvVar = %q, want %q", tc.key, k.EnvVar, tc.want)
		}
	}
	// The rejected combined form must NOT be settable.
	if k, ok := LookupConfigKey("socks.auth"); ok {
		t.Fatalf("LookupConfigKey(socks.auth) = %+v, want not settable", k)
	}
}
