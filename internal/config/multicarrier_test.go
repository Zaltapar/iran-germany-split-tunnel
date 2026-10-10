// Multi-carrier (Phase 2) config validation matrix.
//
// Covers the structured down-carrier list added in
// plans/multi-carrier-intelligence-design.md Phase 2: duplicate / bad
// addresses, conflicting listeners, the dashboard-reserved port 8443, and the
// "enabled with no usable carrier / missing SNI" rules. Multi-carrier is OFF
// by default, so the single-value form stays valid and byte-identical.
package config

import (
	"errors"
	"strings"
	"testing"
)

// mcValid returns a fully-valid multi-carrier config for the given role.
// Germany: a second down listener on a distinct loopback port + a real SNI.
// Iran: a second down dial target distinct from the primary.
func mcValid(role string) *Config {
	c := validIran()
	switch role {
	case RoleGermany:
		c.UpWsUrl = "wss://cdn.example.org/upload"
		c.DownListen2 = "127.0.0.1:9003"
		c.DownSNI2 = "b.lovelive123.com"
	case RoleIran:
		c.DownCarrierAddr2 = "127.0.0.1:10803"
	}
	c.MultiCarrierEnabled = true
	c.DownListen = DefaultDownListen
	c.DownCarrierAddr = DefaultDownCarrier
	return c
}

// problemsOfMC isolates a ConfigError's problems (or fails if err is nil /
// not a ConfigError), for assertion convenience.
func problemsOfMC(t *testing.T, err error) []string {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a validation error, got nil")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConfigError, got %T (%v)", err, err)
	}
	return ce.Problems
}

// hasSub reports whether any problem in ps contains sub.
func hasSub(ps []string, sub string) bool {
	for _, p := range ps {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

// Default is OFF: multi-carrier is off and the single-value form validates
// with no multi-carrier-specific problems even when the _2 fields are empty.
func TestMultiCarrierDefaultOff(t *testing.T) {
	for _, role := range []string{RoleGermany, RoleIran} {
		c := Defaults()
		c.Secret = strongSecret
		if role == RoleGermany {
			c.UpWsUrl = "wss://cdn.example.org/upload"
		}
		if c.MultiCarrierEnabled {
			t.Fatalf("%s: default MultiCarrierEnabled must be false", role)
		}
		if err := c.Validate(role); err != nil {
			t.Fatalf("%s: default config failed validation: %v", role, err)
		}
	}
}

// Enabled with no usable carrier / missing SNI is rejected, per role.
func TestMultiCarrierEnabledRequiresUsableCarrier(t *testing.T) {
	// Germany: enabled but the second listener and SNI are unset.
	c := mcValid(RoleGermany)
	c.DownListen2 = ""
	c.DownSNI2 = ""
	ps := problemsOfMC(t, c.Validate(RoleGermany))
	if !hasSub(ps, EnvDownListen2) {
		t.Errorf("missing %s not reported: %v", EnvDownListen2, ps)
	}
	if !hasSub(ps, EnvDownSNI2) {
		t.Errorf("missing %s not reported: %v", EnvDownSNI2, ps)
	}

	// Iran: enabled but the second dial target is unset.
	ci := mcValid(RoleIran)
	ci.DownCarrierAddr2 = ""
	psi := problemsOfMC(t, ci.Validate(RoleIran))
	if !hasSub(psi, EnvDownCarrierAddr2) {
		t.Errorf("missing %s not reported: %v", EnvDownCarrierAddr2, psi)
	}
}

// A bad address (not host:port) on the second instance is rejected.
func TestMultiCarrierBadAddress(t *testing.T) {
	c := mcValid(RoleGermany)
	c.DownListen2 = "not-an-address"
	ps := problemsOfMC(t, c.Validate(RoleGermany))
	if !hasSub(ps, EnvDownListen2) {
		t.Errorf("bad %s not reported: %v", EnvDownListen2, ps)
	}

	ci := mcValid(RoleIran)
	ci.DownCarrierAddr2 = ":10803" // dial target requires an explicit host
	psi := problemsOfMC(t, ci.Validate(RoleIran))
	if !hasSub(psi, EnvDownCarrierAddr2) {
		t.Errorf("hostless %s not reported: %v", EnvDownCarrierAddr2, psi)
	}
}

// The second down dial target may not equal the primary (a no-op second
// carrier adds nothing).
func TestMultiCarrierDuplicateDownTarget(t *testing.T) {
	c := mcValid(RoleIran)
	c.DownCarrierAddr2 = c.DownCarrierAddr
	ps := problemsOfMC(t, c.Validate(RoleIran))
	if !hasSub(ps, "must dial a different") {
		t.Errorf("duplicate down target not reported: %v", ps)
	}
}

// Conflicting listeners (same bind address as the primary down listener) are
// rejected on the Germany role.
func TestMultiCarrierConflictingListeners(t *testing.T) {
	c := mcValid(RoleGermany)
	c.DownListen2 = c.DownListen // same endpoint as the primary down listener
	ps := problemsOfMC(t, c.Validate(RoleGermany))
	if !hasSub(ps, "use the same endpoint") {
		t.Errorf("conflicting listener not reported: %v", ps)
	}
}

// Port 8443 (dashboard-reserved) is rejected for a carrier listener.
func TestMultiCarrierReservedPort(t *testing.T) {
	// Primary down listener on the reserved port.
	c := validGermany()
	c.DownListen = "0.0.0.0:8443"
	ps := problemsOfMC(t, c.Validate(RoleGermany))
	if !hasSub(ps, "reserved for the dashboard") {
		t.Errorf("reserved primary port not reported: %v", ps)
	}

	// Second down listener on the reserved port.
	cm := mcValid(RoleGermany)
	cm.DownListen2 = "127.0.0.1:8443"
	psm := problemsOfMC(t, cm.Validate(RoleGermany))
	if !hasSub(psm, "reserved for the dashboard") {
		t.Errorf("reserved second port not reported: %v", psm)
	}
}

// An invalid SNI (uppercase / IP literal) on the second instance is rejected.
func TestMultiCarrierInvalidSNI(t *testing.T) {
	for _, bad := range []string{"UPPER.COM", "9.9.9.9", "bad-sni"} {
		c := mcValid(RoleGermany)
		c.DownSNI2 = bad
		ps := problemsOfMC(t, c.Validate(RoleGermany))
		if !hasSub(ps, EnvDownSNI2) {
			t.Errorf("SNI %q not rejected: %v", bad, ps)
		}
	}
}

// A fully-valid multi-carrier config passes on both roles.
func TestMultiCarrierValid(t *testing.T) {
	if err := mcValid(RoleGermany).Validate(RoleGermany); err != nil {
		t.Errorf("Germany multi-carrier valid config failed: %v", err)
	}
	if err := mcValid(RoleIran).Validate(RoleIran); err != nil {
		t.Errorf("Iran multi-carrier valid config failed: %v", err)
	}
}
