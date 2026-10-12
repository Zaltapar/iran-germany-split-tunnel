// c4_test.go — the C4 routing + multi-carrier validators (pure functions,
// plans/dashboard-control-design.md C4 requirements 1 and 2). Each table
// drives ValidateRoutingChange / ValidateMCChange over role/key/value
// combinations and asserts the closed error set; BuildC4Diff's redaction
// (fingerprinted SOCKS values, full SNI / policy values) is asserted too.
package controlagent

import (
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// ---------------------------------------------------------------------------
// routing plane validator
// ---------------------------------------------------------------------------

func TestValidateRoutingChange(t *testing.T) {
	t.Run("valid policy change", func(t *testing.T) {
		if errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{config.EnvTargetAddrPolicy: "prefer-ipv4"}, map[string]string{}); len(errs) != 0 {
			t.Fatalf("expected valid, got %v", errs)
		}
	})

	t.Run("valid allowlist (ip + cidr)", func(t *testing.T) {
		if errs := ValidateRoutingChange(config.RoleIran,
			map[string]string{config.EnvSocksAllowedSources: "10.0.0.1,192.168.0.0/24"}, map[string]string{}); len(errs) != 0 {
			t.Fatalf("expected valid, got %v", errs)
		}
	})

	t.Run("empty allowlist is the allow-all sentinel", func(t *testing.T) {
		if errs := ValidateRoutingChange(config.RoleIran,
			map[string]string{config.EnvSocksAllowedSources: ""}, map[string]string{}); len(errs) != 0 {
			t.Fatalf("expected empty (allow-all) to be valid, got %v", errs)
		}
	})

	t.Run("bad policy enum is refused", func(t *testing.T) {
		errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{config.EnvTargetAddrPolicy: "ipv5-only"}, map[string]string{})
		if len(errs) == 0 || !strings.Contains(errs[0], "default|prefer-ipv4|ipv4-only") {
			t.Fatalf("want policy-enum error, got %v", errs)
		}
	})

	t.Run("malformed allowlist entry is refused", func(t *testing.T) {
		errs := ValidateRoutingChange(config.RoleIran,
			map[string]string{config.EnvSocksAllowedSources: "not-an-ip"}, map[string]string{})
		if len(errs) == 0 {
			t.Fatalf("want allowlist parse error, got none: %v", errs)
		}
	})

	t.Run("allowlist key is Iran-role only", func(t *testing.T) {
		errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{config.EnvSocksAllowedSources: "10.0.0.1"}, map[string]string{})
		if len(errs) == 0 || !strings.Contains(errs[0], "not accepted for role") {
			t.Fatalf("want role restriction error, got %v", errs)
		}
	})

	t.Run("a secret-named key is refused", func(t *testing.T) {
		errs := ValidateRoutingChange(config.RoleIran,
			map[string]string{config.EnvSecret: "hunter2"}, map[string]string{})
		if len(errs) == 0 || !strings.Contains(errs[0], "secret-named") {
			t.Fatalf("want secret-named error, got %v", errs)
		}
	})

	t.Run("a key outside the routing concept is refused", func(t *testing.T) {
		errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{config.EnvPolicyMode: "adaptive"}, map[string]string{})
		if len(errs) == 0 || !strings.Contains(errs[0], "not in the C4 routing concept") {
			t.Fatalf("want not-in-concept error, got %v", errs)
		}
	})

	t.Run("unknown role is refused", func(t *testing.T) {
		errs := ValidateRoutingChange("mars", map[string]string{config.EnvTargetAddrPolicy: "default"}, nil)
		if len(errs) == 0 || !strings.Contains(errs[0], "role:") {
			t.Fatalf("want role error, got %v", errs)
		}
	})

	t.Run("empty set is refused", func(t *testing.T) {
		errs := ValidateRoutingChange(config.RoleGermany, map[string]string{}, map[string]string{})
		if len(errs) == 0 || !strings.Contains(errs[0], "at least one key") {
			t.Fatalf("want empty-set error, got %v", errs)
		}
	})

	t.Run("TARGET_ONLY_IPV4=true + prefer-ipv4 contradiction is refused", func(t *testing.T) {
		base := map[string]string{config.EnvTargetOnlyIPv4: "true"}
		errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{config.EnvTargetAddrPolicy: "prefer-ipv4"}, base)
		found := false
		for _, e := range errs {
			if strings.Contains(e, "contradicts") {
				found = true
			}
		}
		if !found {
			t.Fatalf("want the prefer-ipv4 / only-ipv4 contradiction error, got %v", errs)
		}
	})

	t.Run("TARGET_ONLY_IPV4=false + prefer-ipv4 is fine", func(t *testing.T) {
		base := map[string]string{config.EnvTargetOnlyIPv4: "false"}
		if errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{config.EnvTargetAddrPolicy: "prefer-ipv4"}, base); len(errs) != 0 {
			t.Fatalf("expected valid, got %v", errs)
		}
	})
}

// ---------------------------------------------------------------------------
// multi-carrier validator
// ---------------------------------------------------------------------------

func TestValidateMCChange(t *testing.T) {
	t.Run("valid Germany enablement (listener + SNI)", func(t *testing.T) {
		base := map[string]string{config.EnvDownListen: "127.0.0.1:9002"}
		set := map[string]string{
			config.EnvMultiCarrierEnabled: "true",
			config.EnvDownListen2:         "127.0.0.1:9003",
			config.EnvDownSNI2:            "second.example.com",
		}
		if errs := ValidateMCChange(config.RoleGermany, set, base); len(errs) != 0 {
			t.Fatalf("expected valid, got %v", errs)
		}
	})

	t.Run("valid Iran enablement (dial target)", func(t *testing.T) {
		base := map[string]string{config.EnvDownCarrier: "127.0.0.1:8080"}
		set := map[string]string{
			config.EnvMultiCarrierEnabled: "true",
			config.EnvDownCarrierAddr2:    "127.0.0.1:8081",
		}
		if errs := ValidateMCChange(config.RoleIran, set, base); len(errs) != 0 {
			t.Fatalf("expected valid, got %v", errs)
		}
	})

	t.Run("enabling with no second listener is refused", func(t *testing.T) {
		set := map[string]string{config.EnvMultiCarrierEnabled: "true"}
		errs := ValidateMCChange(config.RoleGermany, set, map[string]string{})
		if len(errs) == 0 || !strings.Contains(strings.Join(errs, " "), config.EnvDownListen2) {
			t.Fatalf("want a required-listener error, got %v", errs)
		}
	})

	t.Run("enabling with a missing SNI is refused", func(t *testing.T) {
		set := map[string]string{
			config.EnvMultiCarrierEnabled: "true",
			config.EnvDownListen2:         "127.0.0.1:9003",
		}
		errs := ValidateMCChange(config.RoleGermany, set, map[string]string{})
		if len(errs) == 0 || !strings.Contains(strings.Join(errs, " "), config.EnvDownSNI2) {
			t.Fatalf("want a required-SNI error, got %v", errs)
		}
	})

	t.Run("an invalid SNI is refused", func(t *testing.T) {
		set := map[string]string{
			config.EnvMultiCarrierEnabled: "true",
			config.EnvDownListen2:         "127.0.0.1:9003",
			config.EnvDownSNI2:            "9.9.9.9", // an IP literal is not a valid SNI
		}
		errs := ValidateMCChange(config.RoleGermany, set, map[string]string{})
		if len(errs) == 0 {
			t.Fatalf("want an SNI error, got %v", errs)
		}
	})

	t.Run("duplicate second-listener endpoint is refused", func(t *testing.T) {
		base := map[string]string{config.EnvDownListen: "127.0.0.1:9002"}
		set := map[string]string{
			config.EnvMultiCarrierEnabled: "true",
			config.EnvDownListen2:         "127.0.0.1:9002", // same bind as the primary
			config.EnvDownSNI2:            "second.example.com",
		}
		errs := ValidateMCChange(config.RoleGermany, set, base)
		if len(errs) == 0 || !strings.Contains(strings.Join(errs, " "), "conflicts with") {
			t.Fatalf("want a duplicate-endpoint error, got %v", errs)
		}
	})

	t.Run("the reserved dashboard port is refused", func(t *testing.T) {
		set := map[string]string{
			config.EnvMultiCarrierEnabled: "true",
			config.EnvDownListen2:         "127.0.0.1:8443", // config.ReservedPort
			config.EnvDownSNI2:            "second.example.com",
		}
		errs := ValidateMCChange(config.RoleGermany, set, map[string]string{})
		if len(errs) == 0 || !strings.Contains(strings.Join(errs, " "), "reserved") {
			t.Fatalf("want a reserved-port error, got %v", errs)
		}
	})

	t.Run("second carrier dial target must differ from primary", func(t *testing.T) {
		base := map[string]string{config.EnvDownCarrier: "127.0.0.1:8080"}
		set := map[string]string{
			config.EnvMultiCarrierEnabled: "true",
			config.EnvDownCarrierAddr2:    "127.0.0.1:8080", // equals the primary
		}
		errs := ValidateMCChange(config.RoleIran, set, base)
		if len(errs) == 0 || !strings.Contains(strings.Join(errs, " "), "must dial a different") {
			t.Fatalf("want a distinct-dial-target error, got %v", errs)
		}
	})

	t.Run("probing enabled without a URL is refused", func(t *testing.T) {
		set := map[string]string{
			config.EnvMultiCarrierEnabled: "true",
			config.EnvDownListen2:         "127.0.0.1:9003",
			config.EnvDownSNI2:            "second.example.com",
			config.EnvProbingEnabled:      "true",
			// EnvProbeURL absent
		}
		errs := ValidateMCChange(config.RoleGermany, set, map[string]string{})
		if len(errs) == 0 || !strings.Contains(strings.Join(errs, " "), config.EnvProbeURL) {
			t.Fatalf("want a required-probe-URL error, got %v", errs)
		}
	})

	t.Run("a policy knob outside its range is refused", func(t *testing.T) {
		errs := ValidateMCChange(config.RoleGermany,
			map[string]string{config.EnvPolicyTopK: "9"}, map[string]string{})
		if len(errs) == 0 {
			t.Fatalf("want a topk-range error, got %v", errs)
		}
	})

	t.Run("the second-listener key is Germany-role only", func(t *testing.T) {
		errs := ValidateMCChange(config.RoleIran,
			map[string]string{config.EnvDownListen2: "127.0.0.1:9003"}, map[string]string{})
		if len(errs) == 0 || !strings.Contains(errs[0], "Germany-side") {
			t.Fatalf("want role restriction error, got %v", errs)
		}
	})

	t.Run("the second-dial-target key is Iran-role only", func(t *testing.T) {
		errs := ValidateMCChange(config.RoleGermany,
			map[string]string{config.EnvDownCarrierAddr2: "127.0.0.1:8081"}, map[string]string{})
		if len(errs) == 0 || !strings.Contains(errs[0], "Iran-side") {
			t.Fatalf("want role restriction error, got %v", errs)
		}
	})

	t.Run("disabling multi-carrier is always allowed", func(t *testing.T) {
		base := map[string]string{
			config.EnvMultiCarrierEnabled: "true",
			config.EnvDownListen2:         "127.0.0.1:9003",
			config.EnvDownSNI2:            "second.example.com",
		}
		// A disable does not require the listener/SNI again.
		if errs := ValidateMCChange(config.RoleGermany,
			map[string]string{config.EnvMultiCarrierEnabled: "false"}, base); len(errs) != 0 {
			t.Fatalf("expected disable to be valid, got %v", errs)
		}
	})

	t.Run("a secret-named key is refused", func(t *testing.T) {
		errs := ValidateMCChange(config.RoleGermany,
			map[string]string{config.EnvSocksPass: "pw"}, map[string]string{})
		if len(errs) == 0 || !strings.Contains(errs[0], "secret-named") {
			t.Fatalf("want secret-named error, got %v", errs)
		}
	})
}

// ---------------------------------------------------------------------------
// diff redaction (requirement 7: SNI / policy in full, SOCKS values never)
// ---------------------------------------------------------------------------

func TestBuildC4DiffRedactsSocksOnly(t *testing.T) {
	base := map[string]string{
		config.EnvSocksAllowedSources: "10.1.2.3,192.168.0.0/24",
		config.EnvTargetAddrPolicy:    "prefer-ipv4",
	}
	override := map[string]string{
		config.EnvSocksAllowedSources: "10.9.9.9",
		config.EnvTargetAddrPolicy:    "ipv4-only",
	}
	diff := BuildC4Diff(base, override, c4RoutingFields)

	var socks, policy *DiffEntry
	for i := range diff {
		switch diff[i].Key {
		case config.EnvSocksAllowedSources:
			socks = &diff[i]
		case config.EnvTargetAddrPolicy:
			policy = &diff[i]
		}
	}
	if socks == nil || policy == nil {
		t.Fatalf("diff missing entries: %+v", diff)
	}
	// SOCKS values are redacted (fingerprinted), never the raw value.
	if !socks.Redacted {
		t.Fatalf("socks diff entry not marked redacted: %+v", socks)
	}
	if strings.Contains(socks.Before, "10.1.2.3") || strings.Contains(socks.After, "10.9.9.9") {
		t.Fatalf("raw SOCKS allowlist value leaked into the diff: %+v", socks)
	}
	// The target-address policy is operator config (not secret): full.
	if policy.Redacted {
		t.Fatalf("policy diff entry should not be redacted: %+v", policy)
	}
	if policy.Before != "prefer-ipv4" || policy.After != "ipv4-only" {
		t.Fatalf("policy diff values not full: %+v", policy)
	}
}

func TestBuildC4DiffMultiCarrierSNIIsFull(t *testing.T) {
	base := map[string]string{config.EnvDownListen2: "127.0.0.1:9003"}
	override := map[string]string{config.EnvDownSNI2: "second.example.com"}
	diff := BuildC4Diff(base, override, c4MCFields)
	var sni *DiffEntry
	for i := range diff {
		if diff[i].Key == config.EnvDownSNI2 {
			sni = &diff[i]
		}
	}
	if sni == nil {
		t.Fatalf("diff missing the SNI entry: %+v", diff)
	}
	// SNI is explicitly allowed to be logged in full (requirement 7).
	if sni.Redacted || sni.After != "second.example.com" {
		t.Fatalf("SNI diff not in full: %+v", sni)
	}
}

// fingerprint is the stable digest helper the diff uses for redacted values.
func TestFingerprintIsStableAndOpaque(t *testing.T) {
	a := fingerprint("10.1.2.3,192.168.0.0/24")
	b := fingerprint("10.1.2.3,192.168.0.0/24")
	c := fingerprint("a-totally-different-value")
	if a != b {
		t.Fatalf("fingerprint is not deterministic: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("fingerprint collided across distinct values: %q", a)
	}
	if strings.Contains(a, "10.1.2.3") || strings.Contains(a, "192.168.0.0") {
		t.Fatalf("fingerprint exposed the raw value: %q", a)
	}
}
