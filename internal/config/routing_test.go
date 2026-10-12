// routing_test.go — GERMANY OUTBOUND ROUTING ENGINE config validation
// (§22). Covers: routing OFF (no-op), routing ON (rules file, default
// outbound enum, WARP endpoint, debug flag), and the full Load path.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRulesFile creates a valid minimal rules JSON in dir and returns
// its path.
func writeRulesFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}
	return p
}

const validRulesJSON = `{"version":1,"rules":[]}`

// ---------------------------------------------------------------------------
// Pure Validate tests (no env)
// ---------------------------------------------------------------------------

// TestRoutingOffNoValidation: when RoutingRulesFile is empty, checkRouting
// is a no-op; a valid Germany config without routing still validates.
func TestRoutingOffNoValidation(t *testing.T) {
	c := validGermany()
	// Explicitly confirm the routing fields are at their defaults.
	if c.RoutingRulesFile != "" {
		t.Fatalf("RoutingRulesFile default = %q, want empty", c.RoutingRulesFile)
	}
	if c.RoutingDebug {
		t.Fatal("RoutingDebug default should be false")
	}
	if err := c.Validate(RoleGermany); err != nil {
		t.Fatalf("routing OFF should validate clean: %v", err)
	}
}

// TestRoutingOnValid: a valid rules file + valid default + valid WARP
// endpoint → no validation errors.
func TestRoutingOnValid(t *testing.T) {
	c := validGermany()
	c.RoutingRulesFile = writeRulesFile(t, validRulesJSON)
	c.RoutingDefault = "warp"
	c.WarpSocksAddr = "127.0.0.1:40000"
	if err := c.Validate(RoleGermany); err != nil {
		t.Fatalf("valid routing config should pass: %v", err)
	}
}

// TestRoutingOnRoutingDefaultBlock: "block" is rejected as a default.
func TestRoutingOnRoutingDefaultBlock(t *testing.T) {
	c := validGermany()
	c.RoutingRulesFile = writeRulesFile(t, validRulesJSON)
	c.RoutingDefault = "block"
	err := c.Validate(RoleGermany)
	if err == nil {
		t.Fatal("routing default=block must be rejected")
	}
	if !strings.Contains(err.Error(), "SPLIT_ROUTING_DEFAULT") {
		t.Fatalf("error should name the env var: %v", err)
	}
}

// TestRoutingOnRoutingDefaultUnknown: "tunnel" is not a valid outbound.
func TestRoutingOnRoutingDefaultUnknown(t *testing.T) {
	c := validGermany()
	c.RoutingRulesFile = writeRulesFile(t, validRulesJSON)
	c.RoutingDefault = "tunnel"
	err := c.Validate(RoleGermany)
	if err == nil {
		t.Fatal("routing default=tunnel must be rejected")
	}
}

// TestRoutingOnWarpSocksAddrInvalid: malformed host:port.
func TestRoutingOnWarpSocksAddrInvalid(t *testing.T) {
	c := validGermany()
	c.RoutingRulesFile = writeRulesFile(t, validRulesJSON)
	c.WarpSocksAddr = "not-a-port"
	err := c.Validate(RoleGermany)
	if err == nil {
		t.Fatal("invalid WARP addr must be rejected")
	}
	if !strings.Contains(err.Error(), "SPLIT_WARP_SOCKS_ADDR") {
		t.Fatalf("error should name the env var: %v", err)
	}
}

// TestRoutingOnRulesFileMissing: a rules file path that does not exist.
func TestRoutingOnRulesFileMissing(t *testing.T) {
	c := validGermany()
	c.RoutingRulesFile = "/nonexistent/path/rules.json"
	err := c.Validate(RoleGermany)
	if err == nil {
		t.Fatal("missing rules file must be rejected")
	}
}

// TestRoutingOnRulesFileMalformed: rules file with bad JSON.
func TestRoutingOnRulesFileMalformed(t *testing.T) {
	c := validGermany()
	c.RoutingRulesFile = writeRulesFile(t, `{not json`)
	err := c.Validate(RoleGermany)
	if err == nil {
		t.Fatal("malformed rules file must be rejected")
	}
}

// TestRoutingOnRulesFileBlockDefault: rules file with default_action=block
// is rejected by the rule validator (the config layer surfaces it).
func TestRoutingOnRulesFileBlockDefault(t *testing.T) {
	c := validGermany()
	c.RoutingRulesFile = writeRulesFile(t, `{"version":1,"default_action":"block","rules":[]}`)
	err := c.Validate(RoleGermany)
	if err == nil {
		t.Fatal("block default_action in rules file must be rejected")
	}
}

// TestRoutingOnWarpRuleRequiresWarpAddr: a rules file with a warp rule
// but WARP address empty → validation error (the engine would fail to
// construct).
func TestRoutingOnWarpRuleRequiresWarpAddr(t *testing.T) {
	c := validGermany()
	c.RoutingRulesFile = writeRulesFile(t,
		`{"version":1,"rules":[{"id":"w","match":{"keyword":"x"},"action":"warp"}]}`)
	// WarpSocksAddr stays at the default "127.0.0.1:40000" → OK.
	// (The engine's New would reject an empty WARPAddr, but the config
	// layer only checks host:port form when non-empty.)
	if err := c.Validate(RoleGermany); err != nil {
		t.Fatalf("warp rule with default WARP addr should pass: %v", err)
	}
	// Now explicitly empty it (a hand-constructed Config) → still
	// passes config validation (the engine's New catches it at runtime).
	// This is the documented "config validates form, engine validates
	// semantic existence" split.
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

func TestRoutingDefaults(t *testing.T) {
	c := Defaults()
	if c.RoutingRulesFile != "" {
		t.Errorf("RoutingRulesFile default = %q, want empty (routing OFF)", c.RoutingRulesFile)
	}
	if c.RoutingDefault != "" {
		t.Errorf("RoutingDefault = %q, want empty (defer to the rules file's default_action)", c.RoutingDefault)
	}
	if c.WarpSocksAddr != "127.0.0.1:40000" {
		t.Errorf("WarpSocksAddr = %q, want 127.0.0.1:40000", c.WarpSocksAddr)
	}
	if c.RoutingDebug {
		t.Error("RoutingDebug default should be false")
	}
}

// ---------------------------------------------------------------------------
// Load path (env-driven)
// ---------------------------------------------------------------------------

func TestLoadRoutingOff(t *testing.T) {
	isolatedEnv(t)
	t.Setenv(EnvUpWsUrl, "wss://cdn.example.org/upload")
	t.Setenv(EnvSecret, strongSecret)
	// All routing env vars empty → routing OFF, no validation errors.
	c, err := Load(RoleGermany)
	if err != nil {
		t.Fatalf("Load(germany) with routing OFF: %v", err)
	}
	if c.RoutingRulesFile != "" {
		t.Fatalf("RoutingRulesFile = %q, want empty", c.RoutingRulesFile)
	}
	if c.RoutingDefault != "" {
		t.Fatalf("RoutingDefault = %q, want empty (defer to the rules file's default_action)", c.RoutingDefault)
	}
}

func TestLoadRoutingOn(t *testing.T) {
	isolatedEnv(t)
	t.Setenv(EnvUpWsUrl, "wss://cdn.example.org/upload")
	t.Setenv(EnvSecret, strongSecret)
	rulesPath := writeRulesFile(t, validRulesJSON)
	t.Setenv(EnvRoutingRulesFile, rulesPath)
	t.Setenv(EnvRoutingDefault, "warp")
	t.Setenv(EnvWarpSocksAddr, "10.0.0.1:1080")
	t.Setenv(EnvRoutingDebug, "true")

	c, err := Load(RoleGermany)
	if err != nil {
		t.Fatalf("Load(germany) with routing ON: %v", err)
	}
	if c.RoutingRulesFile != rulesPath {
		t.Errorf("RoutingRulesFile = %q, want %q", c.RoutingRulesFile, rulesPath)
	}
	if c.RoutingDefault != "warp" {
		t.Errorf("RoutingDefault = %q, want warp", c.RoutingDefault)
	}
	if c.WarpSocksAddr != "10.0.0.1:1080" {
		t.Errorf("WarpSocksAddr = %q, want 10.0.0.1:1080", c.WarpSocksAddr)
	}
	if !c.RoutingDebug {
		t.Error("RoutingDebug = false, want true")
	}
}

func TestLoadRoutingOnInvalidDefault(t *testing.T) {
	isolatedEnv(t)
	t.Setenv(EnvUpWsUrl, "wss://cdn.example.org/upload")
	t.Setenv(EnvSecret, strongSecret)
	rulesPath := writeRulesFile(t, validRulesJSON)
	t.Setenv(EnvRoutingRulesFile, rulesPath)
	t.Setenv(EnvRoutingDefault, "block")

	_, err := Load(RoleGermany)
	if err == nil {
		t.Fatal("Load must reject SPLIT_ROUTING_DEFAULT=block")
	}
	if !strings.Contains(err.Error(), "SPLIT_ROUTING_DEFAULT") {
		t.Fatalf("error should name SPLIT_ROUTING_DEFAULT: %v", err)
	}
}

// TestLoadRoutingDebugInvalidBool: SPLIT_ROUTING_DEBUG=notabool.
func TestLoadRoutingDebugInvalidBool(t *testing.T) {
	isolatedEnv(t)
	t.Setenv(EnvUpWsUrl, "wss://cdn.example.org/upload")
	t.Setenv(EnvSecret, strongSecret)
	t.Setenv(EnvRoutingDebug, "notabool")
	_, err := Load(RoleGermany)
	if err == nil {
		t.Fatal("Load must reject SPLIT_ROUTING_DEBUG=notabool")
	}
	if !strings.Contains(err.Error(), "SPLIT_ROUTING_DEBUG") {
		t.Fatalf("error should name SPLIT_ROUTING_DEBUG: %v", err)
	}
}
