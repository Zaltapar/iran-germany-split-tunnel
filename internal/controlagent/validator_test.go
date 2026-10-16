// validator_test.go — the authoritative candidate validation (design
// §5.2 F6, §4.4): allowlist, secret denylist, per-value bounds,
// full-config fold, restart classification, and redacted diff.
package controlagent

import (
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

func TestValidateCandidateValid(t *testing.T) {
	set := map[string]string{
		config.EnvPolicyMode:          config.PolicyAdaptiveMode,
		config.EnvPolicyTopK:          "3",
		config.EnvTTFBBaselineMs:      "250",
		config.EnvProbeDailyBudget:    "10485760",
		config.EnvMultiCarrierEnabled: "true",
	}
	errs, restart := ValidateCandidate(config.RoleIran, set, defaultConfigBuilder)
	if len(errs) != 0 {
		t.Fatalf("expected valid, got %v", errs)
	}
	if !restart {
		t.Fatal("all C2 keys require a restart; restartRequired must be true")
	}
}

func TestValidateCandidateBadRole(t *testing.T) {
	errs, _ := ValidateCandidate("xray", map[string]string{config.EnvPolicyMode: "static"}, defaultConfigBuilder)
	if len(errs) == 0 || !strings.Contains(errs[0], "role") {
		t.Fatalf("expected role error, got %v", errs)
	}
}

func TestValidateCandidateEmptySet(t *testing.T) {
	errs, _ := ValidateCandidate(config.RoleGermany, map[string]string{}, defaultConfigBuilder)
	if len(errs) == 0 {
		t.Fatal("empty set must be rejected")
	}
}

func TestValidateCandidateUnknownKey(t *testing.T) {
	set := map[string]string{"SPLIT_ROUTING_MODE": "direct"}
	errs, _ := ValidateCandidate(config.RoleIran, set, defaultConfigBuilder)
	if len(errs) == 0 || !strings.Contains(errs[0], "not in the C2 editable concept") {
		t.Fatalf("expected allowlist rejection, got %v", errs)
	}
}

func TestValidateCandidateSecretKeyRejected(t *testing.T) {
	for _, k := range []string{"SPLIT_SECRET", "SPLIT_SOCKS_PASSWORD", "XRAY_API_KEY"} {
		errs, _ := ValidateCandidate(config.RoleIran, map[string]string{k: "value"}, defaultConfigBuilder)
		if len(errs) == 0 || !strings.Contains(errs[0], "secret-named") {
			t.Fatalf("key %s: expected secret rejection, got %v", k, errs)
		}
	}
}

func TestValidateCandidateBounds(t *testing.T) {
	errs, _ := ValidateCandidate(config.RoleIran, map[string]string{config.EnvPolicyMode: "turbo"}, defaultConfigBuilder)
	if len(errs) == 0 || !strings.Contains(errs[0], config.EnvPolicyMode) {
		t.Fatalf("expected mode bounds error, got %v", errs)
	}
	errs, _ = ValidateCandidate(config.RoleIran, map[string]string{config.EnvPolicyTopK: "9"}, defaultConfigBuilder)
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, " "), "1..8") {
		t.Fatalf("expected topk bounds error, got %v", errs)
	}
	errs, _ = ValidateCandidate(config.RoleIran, map[string]string{config.EnvPolicyTopK: "0"}, defaultConfigBuilder)
	if len(errs) == 0 {
		t.Fatalf("topk=0 must fail, got %v", errs)
	}
	errs, _ = ValidateCandidate(config.RoleIran, map[string]string{config.EnvTTFBBaselineMs: "40000"}, defaultConfigBuilder)
	if len(errs) == 0 {
		t.Fatalf("ttfb=40000 must fail, got %v", errs)
	}
	errs, _ = ValidateCandidate(config.RoleIran, map[string]string{config.EnvMultiCarrierEnabled: "notabool"}, defaultConfigBuilder)
	if len(errs) == 0 {
		t.Fatalf("bad bool must fail, got %v", errs)
	}
	errs, _ = ValidateCandidate(config.RoleIran, map[string]string{config.EnvProbeDailyBudget: "-1"}, defaultConfigBuilder)
	if len(errs) == 0 {
		t.Fatalf("negative budget must fail, got %v", errs)
	}
}

func TestBuildDiffRedactsSecretNames(t *testing.T) {
	// Secret-named keys are NOT in the editable set, so BuildDiff skips
	// them; this asserts the skip behaviour directly.
	base := map[string]string{"SPLIT_POLICY_MODE": "static"}
	override := map[string]string{config.EnvPolicyMode: "adaptive"}
	d := BuildDiff(base, override)
	if len(d) != 1 {
		t.Fatalf("expected 1 diff entry, got %d", len(d))
	}
	e := d[0]
	if e.Before != "static" || e.After != "adaptive" || e.Redacted {
		t.Fatalf("diff entry wrong: %+v", e)
	}

	// Non-editable keys never appear.
	d = BuildDiff(base, map[string]string{"SPLIT_SECRET": "x"})
	if len(d) != 0 {
		t.Fatalf("non-editable key leaked into diff: %+v", d)
	}
}

func TestFingerprintStableAndDistinct(t *testing.T) {
	a1 := fingerprint("hunter2")
	a2 := fingerprint("hunter2")
	if a1 != a2 {
		t.Fatal("fingerprint not stable")
	}
	if len(a1) != 12 {
		t.Fatalf("fingerprint length = %d, want 12", len(a1))
	}
	if fingerprint("hunter2") == fingerprint("hunter3") {
		t.Fatal("distinct values collide")
	}
}

func TestC2KeyRequiresRestartCoversWholeSet(t *testing.T) {
	for k := range c2EditableFields {
		if !c2KeyRequiresRestart(k) {
			t.Fatalf("key %s must require restart", k)
		}
	}
}
