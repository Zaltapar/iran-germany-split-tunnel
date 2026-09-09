package origin

// cdn_trust_test.go — review HIGH-4 / decision D9: CDN mode A must fail
// closed on an undeclared origin-certificate trust capability, and the
// operator-facing instructions must never imply a Caddy-internal
// certificate is automatically trusted by a generic CDN. The two
// declared contracts (pullCA / unauthenticatedTLS) are pinned here.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A cdn mode A plan with NO declared trust capability is rejected
// fail-closed (ErrInvalidPlan naming cdnOriginTrust) — before any
// install, render, or activation.
func TestCDNModeAFailsClosedWithoutTrustDeclaration(t *testing.T) {
	plan := Plan{
		Mode:         ModeCDN,
		Domain:       "upload.example.com",
		CDNSecurity:  CDNTLSOrigin,
		UpstreamAddr: "127.0.0.1:9001",
		OriginPort:   8443,
		// CDNOriginTrust deliberately unset.
	}
	if err := plan.validate(); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("want ErrInvalidPlan, got %v", err)
	} else if !strings.Contains(err.Error(), "cdnOriginTrust") {
		t.Errorf("error must name cdnOriginTrust: %v", err)
	}
	if _, err := RenderCaddyfile(plan); !errors.Is(err, ErrInvalidPlan) {
		t.Errorf("RenderCaddyfile: want ErrInvalidPlan, got %v", err)
	}
	core, _, _ := wireCore(t)
	p := &CDNProvider{core: core}
	if err := p.Configure(context.Background(), plan); !errors.Is(err, ErrInvalidPlan) {
		t.Errorf("Configure: want ErrInvalidPlan, got %v", err)
	}
	if _, err := p.CDNOriginInstructions(plan); !errors.Is(err, ErrInvalidPlan) {
		t.Errorf("CDNOriginInstructions: want ErrInvalidPlan, got %v", err)
	}
}

// An unknown trust capability value is rejected (fail closed on unknown
// capability, exactly as D9 requires).
func TestCDNModeARejectsUnknownTrustValue(t *testing.T) {
	plan := Plan{
		Mode:           ModeCDN,
		Domain:         "upload.example.com",
		CDNSecurity:    CDNTLSOrigin,
		CDNOriginTrust: CDNOriginTrust("providerWillFigureItOut"), // unknown
		UpstreamAddr:   "127.0.0.1:9001",
		OriginPort:     8443,
	}
	if err := plan.validate(); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("unknown trust value accepted: %v", err)
	}
}

// Both declared contracts render mode A and produce instructions that
// name the chosen trust model honestly.
func TestCDNModeATrustContractsPinned(t *testing.T) {
	core, _, _ := wireCore(t)
	p := &CDNProvider{core: core}
	for _, tc := range []struct {
		trust    CDNOriginTrust
		mustHave []string
		mustNot  []string
	}{
		{
			trust: CDNOriginTrustPullCA,
			mustHave: []string{
				"AUTHENTICATED private-CA origin TLS",
				"pullCA",
				"ROOT CA CERTIFICATE",
				"never leaves the host",
			},
			mustNot: nil,
		},
		{
			trust: CDNOriginTrustUnauthenticated,
			mustHave: []string{
				"NON-AUTHENTICATED origin TLS",
				"unauthenticatedTLS",
				"ACTIVE MITM",
			},
			mustNot: nil,
		},
	} {
		plan := Plan{
			Mode:           ModeCDN,
			Domain:         "upload.example.com",
			CDNSecurity:    CDNTLSOrigin,
			CDNOriginTrust: tc.trust,
			UpstreamAddr:   "127.0.0.1:9001",
			OriginPort:     8443,
		}
		if err := plan.validate(); err != nil {
			t.Fatalf("%s: declared trust rejected: %v", tc.trust, err)
		}
		if _, err := RenderCaddyfile(plan); err != nil {
			t.Fatalf("%s: render: %v", tc.trust, err)
		}
		s1, err := p.CDNOriginInstructions(plan)
		if err != nil {
			t.Fatalf("%s: instructions: %v", tc.trust, err)
		}
		s2, _ := p.CDNOriginInstructions(plan)
		if s1 != s2 {
			t.Errorf("%s: instructions not deterministic", tc.trust)
		}
		for _, want := range tc.mustHave {
			if !strings.Contains(s1, want) {
				t.Errorf("%s: instructions missing %q:\n%s", tc.trust, want, s1)
			}
		}
		for _, not := range tc.mustNot {
			if strings.Contains(s1, not) {
				t.Errorf("%s: instructions must not contain %q:\n%s", tc.trust, not, s1)
			}
		}
	}
}

// No mode A text may imply a Caddy-internal certificate is
// automatically provider-trusted (the HIGH-4 acceptance statement).
func TestCDNModeANeverImpliesAutomaticProviderTrust(t *testing.T) {
	core, _, _ := wireCore(t)
	p := &CDNProvider{core: core}
	for _, trust := range []CDNOriginTrust{CDNOriginTrustPullCA, CDNOriginTrustUnauthenticated} {
		plan := Plan{
			Mode:           ModeCDN,
			Domain:         "upload.example.com",
			CDNSecurity:    CDNTLSOrigin,
			CDNOriginTrust: trust,
			UpstreamAddr:   "127.0.0.1:9001",
			OriginPort:     8443,
		}
		s, err := p.CDNOriginInstructions(plan)
		if err != nil {
			t.Fatal(err)
		}
		// The text must STATE the trust requirement, not assume it.
		if !strings.Contains(s, "PRIVATE (local) CA") {
			t.Errorf("%s: text must state the cert is a private CA cert:\n%s", trust, s)
		}
		if !strings.Contains(s, "does NOT trust it automatically") {
			t.Errorf("%s: text must state the CDN does not auto-trust it:\n%s", trust, s)
		}
		// Guard against the exact false implication flagged in Round 1.
		for _, banned := range []string{
			"the public certificate is supplied by the CDN\"",
		} {
			if strings.Contains(s, banned) {
				t.Errorf("%s: text contains the banned implication %q:\n%s", trust, banned, s)
			}
		}
	}
}

// Mode B carries no trust field (the origin leg is plain HTTP); a trust
// value on mode B is rejected.
func TestCDNModeBRejectsTrustField(t *testing.T) {
	plan := Plan{
		Mode:           ModeCDN,
		Domain:         "upload.example.com",
		CDNSecurity:    CDNPlainOrigin,
		CDNOriginTrust: CDNOriginTrustPullCA, // not for mode B
		OriginPort:     8443,
	}
	if err := plan.validate(); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("mode B with a trust value accepted: %v", err)
	}
}
