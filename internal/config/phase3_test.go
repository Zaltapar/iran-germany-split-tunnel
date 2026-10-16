// Phase 3 (gate G3) config validation tests for the carrier-intelligence
// policy knobs added in plans/multi-carrier-intelligence-design.md Phase 3:
// the SPLIT_POLICY_* / SPLIT_PROBING_* / SPLIT_PROBE_* / SPLIT_TTFB_BASELINE_MS
// fields. These rules are scoped to MultiCarrierEnabled (single-carrier
// configs with zero Phase 3 fields must stay valid and byte-identical).
package config

import (
	"testing"
)

// p3Valid returns a fully-valid multi-carrier config that also carries valid
// Phase 3 policy defaults (static mode, topk 2, probing off, no URL), so it
// can serve as the base for individual field overrides.
func p3Valid(role string) *Config {
	c := mcValid(role) // MultiCarrierEnabled = true, valid Phase 3 defaults
	// Ensure the Phase 3 fields are explicitly at their valid defaults.
	c.PolicyMode = PolicyStaticMode
	c.PolicyTopK = DefaultPolicyTopK
	c.ProbingEnabled = false
	c.ProbeURL = ""
	c.ProbeDailyBudget = DefaultProbeDailyBudget
	c.TTFBBaselineMs = 0
	return c
}

// The Phase 3 policy knobs are valid at their defaults when multi-carrier is
// enabled (this is what TestMultiCarrierValid now also exercises, stated
// explicitly).
func TestPhase3PolicyDefaultValid(t *testing.T) {
	if err := p3Valid(RoleGermany).Validate(RoleGermany); err != nil {
		t.Fatalf("default Phase 3 policy config failed validation: %v", err)
	}
	if err := p3Valid(RoleIran).Validate(RoleIran); err != nil {
		t.Fatalf("default Phase 3 policy config (Iran) failed validation: %v", err)
	}
}

// An unknown SPLIT_POLICY_MODE is rejected (only "static" or "adaptive").
func TestPhase3PolicyModeEnum(t *testing.T) {
	c := p3Valid(RoleGermany)
	c.PolicyMode = "chill"
	ps := problemsOfMC(t, c.Validate(RoleGermany))
	if !hasSub(ps, EnvPolicyMode) {
		t.Errorf("bad %s not reported: %v", EnvPolicyMode, ps)
	}
	for _, ok := range []string{PolicyStaticMode, PolicyAdaptiveMode} {
		c := p3Valid(RoleGermany)
		c.PolicyMode = ok
		if err := c.Validate(RoleGermany); err != nil {
			t.Errorf("mode %q should be valid: %v", ok, err)
		}
	}
}

// SPLIT_POLICY_TOPK is bounded to 1..8.
func TestPhase3TopKBounded(t *testing.T) {
	for _, bad := range []int{0, -1, 9, 100} {
		c := p3Valid(RoleGermany)
		c.PolicyTopK = bad
		ps := problemsOfMC(t, c.Validate(RoleGermany))
		if !hasSub(ps, EnvPolicyTopK) {
			t.Errorf("%s=%d not reported: %v", EnvPolicyTopK, bad, ps)
		}
	}
	for _, good := range []int{1, 2, 8} {
		c := p3Valid(RoleGermany)
		c.PolicyTopK = good
		if err := c.Validate(RoleGermany); err != nil {
			t.Errorf("%s=%d should be valid: %v", EnvPolicyTopK, good, err)
		}
	}
}

// SPLIT_PROBE_DAILY_BUDGET must be non-negative.
func TestPhase3ProbeBudgetNonNegative(t *testing.T) {
	c := p3Valid(RoleGermany)
	c.ProbeDailyBudget = -1
	ps := problemsOfMC(t, c.Validate(RoleGermany))
	if !hasSub(ps, EnvProbeDailyBudget) {
		t.Errorf("negative %s not reported: %v", EnvProbeDailyBudget, ps)
	}
	// 0 is the "disable the budget gate" sentinel: valid.
	c2 := p3Valid(RoleGermany)
	c2.ProbeDailyBudget = 0
	if err := c2.Validate(RoleGermany); err != nil {
		t.Errorf("zero probe budget should be valid: %v", err)
	}
}

// SPLIT_TTFB_BASELINE_MS is bounded to 0..30000 (0 = library default).
func TestPhase3TTFBBaselineBounded(t *testing.T) {
	for _, bad := range []int{-1, 30001} {
		c := p3Valid(RoleGermany)
		c.TTFBBaselineMs = bad
		ps := problemsOfMC(t, c.Validate(RoleGermany))
		if !hasSub(ps, EnvTTFBBaselineMs) {
			t.Errorf("%s=%d not reported: %v", EnvTTFBBaselineMs, bad, ps)
		}
	}
	for _, good := range []int{0, 500, 30000} {
		c := p3Valid(RoleGermany)
		c.TTFBBaselineMs = good
		if err := c.Validate(RoleGermany); err != nil {
			t.Errorf("%s=%d should be valid: %v", EnvTTFBBaselineMs, good, err)
		}
	}
}

// Enabling probing WITHOUT a URL is rejected (fail-closed, no third-party
// default — design §6.4 / requirement 2).
func TestPhase3ProbingRequiresURL(t *testing.T) {
	c := p3Valid(RoleGermany)
	c.ProbingEnabled = true
	c.ProbeURL = ""
	ps := problemsOfMC(t, c.Validate(RoleGermany))
	if !hasSub(ps, EnvProbeURL) {
		t.Errorf("probing enabled without %s not reported: %v", EnvProbeURL, ps)
	}
}

// Enabling probing WITH a URL that is not a valid http(s) URL (no scheme,
// no host, or a non-http scheme) is rejected.
func TestPhase3ProbeURLMustBeHTTP(t *testing.T) {
	for _, bad := range []string{"ftp://probe.internal", "no-scheme", "https://", "probe.internal"} {
		c := p3Valid(RoleGermany)
		c.ProbingEnabled = true
		c.ProbeURL = bad
		ps := problemsOfMC(t, c.Validate(RoleGermany))
		if !hasSub(ps, EnvProbeURL) {
			t.Errorf("bad %s=%q not rejected: %v", EnvProbeURL, bad, ps)
		}
	}
	// A well-formed operator URL is valid.
	c := p3Valid(RoleGermany)
	c.ProbingEnabled = true
	c.ProbeURL = "https://probe.internal/ok"
	if err := c.Validate(RoleGermany); err != nil {
		t.Errorf("valid probe URL rejected: %v", err)
	}
}

// Single-carrier configs (MultiCarrierEnabled=false) ignore all Phase 3
// validation: zero-value Phase 3 fields are fine and the config still passes.
func TestPhase3InertWhenSingleCarrier(t *testing.T) {
	c := validIran() // a fully valid single-carrier config (MultiCarrierEnabled=false)
	if c.MultiCarrierEnabled {
		t.Fatalf("precondition: single-carrier config must have MultiCarrierEnabled=false")
	}
	// Deliberately set every Phase 3 field to a value that WOULD fail
	// validation if it were checked (unknown mode, out-of-range topk, negative
	// budget, probing on with no URL, out-of-range TTFB): still no error,
	// proving the Phase 3 rules are gated on MultiCarrierEnabled.
	c.PolicyMode = "chill"
	c.PolicyTopK = 99
	c.ProbingEnabled = true
	c.ProbeURL = ""
	c.ProbeDailyBudget = -1
	c.TTFBBaselineMs = 999999
	if err := c.Validate(RoleIran); err != nil {
		t.Fatalf("single-carrier config with zero/invalid Phase 3 fields must validate: %v", err)
	}
}
