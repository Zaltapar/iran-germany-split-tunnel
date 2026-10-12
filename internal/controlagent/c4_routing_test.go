// c4_routing_test.go — the GERMANY OUTBOUND ROUTING ENGINE data hook:
// the C4 routing concept's acceptance of the rules-file contents as a
// validated public-fields-only object (requirement 7). All four new
// keys are Germany-role-only; the rules-file value is loaded and
// validated by routing.LoadRulesFile at C4 validate time.
package controlagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// writeRulesFileForTest creates a temporary rules file and returns its
// path (cleaned up via t.TempDir).
func writeRulesFileForTest(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}
	return p
}

const c4ValidRules = `{"version":1,"rules":[
	{"id":"w","match":{"domain":".example.com"},"action":"warp","fallback":"direct"},
	{"id":"blk","match":{"keyword":"evil"},"action":"block"}
]}`

// ---------------------------------------------------------------------------
// routingKeyRole: Germany-only restriction
// ---------------------------------------------------------------------------

func TestRoutingKeyRoleGermanyOnly(t *testing.T) {
	for _, key := range []string{
		config.EnvRoutingRulesFile,
		config.EnvRoutingDefault,
		config.EnvWarpSocksAddr,
		config.EnvRoutingDebug,
	} {
		// Accepted for Germany.
		if errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{key: ""}, map[string]string{}); len(errs) != 0 {
			t.Errorf("%s for Germany: unexpected error %v", key, errs)
		}
		// Refused for Iran (the routing engine is Germany-only).
		errs := ValidateRoutingChange(config.RoleIran,
			map[string]string{key: ""}, map[string]string{})
		if len(errs) == 0 || !strings.Contains(errs[0], "not accepted for role") {
			t.Errorf("%s for Iran: want role-restriction error, got %v", key, errs)
		}
	}
}

// ---------------------------------------------------------------------------
// SPLIT_ROUTING_RULES_FILE data hook
// ---------------------------------------------------------------------------

func TestRoutingRulesFileValid(t *testing.T) {
	p := writeRulesFileForTest(t, c4ValidRules)
	if errs := ValidateRoutingChange(config.RoleGermany,
		map[string]string{config.EnvRoutingRulesFile: p}, map[string]string{}); len(errs) != 0 {
		t.Fatalf("valid rules file: %v", errs)
	}
}

func TestRoutingRulesFileEmpty(t *testing.T) {
	// Empty = routing OFF: valid, no I/O.
	if errs := ValidateRoutingChange(config.RoleGermany,
		map[string]string{config.EnvRoutingRulesFile: ""}, map[string]string{}); len(errs) != 0 {
		t.Fatalf("empty (OFF) rules file: %v", errs)
	}
}

func TestRoutingRulesFileMissing(t *testing.T) {
	errs := ValidateRoutingChange(config.RoleGermany,
		map[string]string{config.EnvRoutingRulesFile: "/nonexistent/rules.json"},
		map[string]string{})
	if len(errs) == 0 {
		t.Fatal("missing rules file must be rejected")
	}
	if !strings.Contains(errs[0], config.EnvRoutingRulesFile) {
		t.Fatalf("error should name the env var: %v", errs)
	}
}

func TestRoutingRulesFileBlockDefault(t *testing.T) {
	p := writeRulesFileForTest(t, `{"version":1,"default_action":"block","rules":[]}`)
	errs := ValidateRoutingChange(config.RoleGermany,
		map[string]string{config.EnvRoutingRulesFile: p}, map[string]string{})
	if len(errs) == 0 {
		t.Fatal("block default_action in rules file must be rejected")
	}
}

func TestRoutingRulesFileSecretField(t *testing.T) {
	// The strict JSON decode (DisallowUnknownFields) rejects any field
	// not in the public schema, including credential-named fields —
	// the structural guarantee that rules never carry secrets.
	p := writeRulesFileForTest(t,
		`{"version":1,"rules":[{"id":"r","match":{"keyword":"x"},"action":"direct","password":"secret"}]}`)
	errs := ValidateRoutingChange(config.RoleGermany,
		map[string]string{config.EnvRoutingRulesFile: p}, map[string]string{})
	if len(errs) == 0 {
		t.Fatal("unknown field 'password' in rules file must be rejected")
	}
}

func TestRoutingRulesFileCatchAll(t *testing.T) {
	// A catch-all rule (no match criteria) is rejected for every action.
	p := writeRulesFileForTest(t,
		`{"version":1,"rules":[{"id":"all","action":"direct"}]}`)
	errs := ValidateRoutingChange(config.RoleGermany,
		map[string]string{config.EnvRoutingRulesFile: p}, map[string]string{})
	if len(errs) == 0 {
		t.Fatal("catch-all rule (no match criteria) must be rejected")
	}
}

// ---------------------------------------------------------------------------
// SPLIT_ROUTING_DEFAULT enum
// ---------------------------------------------------------------------------

func TestRoutingDefaultValid(t *testing.T) {
	for _, v := range []string{"", "direct", "warp"} {
		if errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{config.EnvRoutingDefault: v}, map[string]string{}); len(errs) != 0 {
			t.Errorf("RoutingDefault=%q: unexpected error %v", v, errs)
		}
	}
}

func TestRoutingDefaultBlockRejected(t *testing.T) {
	errs := ValidateRoutingChange(config.RoleGermany,
		map[string]string{config.EnvRoutingDefault: "block"}, map[string]string{})
	if len(errs) == 0 || !strings.Contains(errs[0], "block is not a valid default") {
		t.Fatalf("want block-default rejection, got %v", errs)
	}
}

func TestRoutingDefaultUnknown(t *testing.T) {
	errs := ValidateRoutingChange(config.RoleGermany,
		map[string]string{config.EnvRoutingDefault: "tunnel"}, map[string]string{})
	if len(errs) == 0 {
		t.Fatal("unknown default outbound must be rejected")
	}
}

// ---------------------------------------------------------------------------
// SPLIT_WARP_SOCKS_ADDR
// ---------------------------------------------------------------------------

func TestWarpSocksAddrValid(t *testing.T) {
	for _, v := range []string{"", "127.0.0.1:40000", "10.0.0.1:1080"} {
		if errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{config.EnvWarpSocksAddr: v}, map[string]string{}); len(errs) != 0 {
			t.Errorf("WarpSocksAddr=%q: unexpected error %v", v, errs)
		}
	}
}

func TestWarpSocksAddrInvalid(t *testing.T) {
	for _, v := range []string{"not-a-port", ":40000", "127.0.0.1:99999"} {
		errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{config.EnvWarpSocksAddr: v}, map[string]string{})
		if len(errs) == 0 {
			t.Errorf("WarpSocksAddr=%q: want rejection, got none", v)
		}
	}
}

// ---------------------------------------------------------------------------
// SPLIT_ROUTING_DEBUG
// ---------------------------------------------------------------------------

func TestRoutingDebugValid(t *testing.T) {
	for _, v := range []string{"", "true", "false", "1", "0"} {
		if errs := ValidateRoutingChange(config.RoleGermany,
			map[string]string{config.EnvRoutingDebug: v}, map[string]string{}); len(errs) != 0 {
			t.Errorf("RoutingDebug=%q: unexpected error %v", v, errs)
		}
	}
}

func TestRoutingDebugInvalid(t *testing.T) {
	errs := ValidateRoutingChange(config.RoleGermany,
		map[string]string{config.EnvRoutingDebug: "notabool"}, map[string]string{})
	if len(errs) == 0 {
		t.Fatal("SPLIT_ROUTING_DEBUG=notabool must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Combined (multiple routing keys in one set)
// ---------------------------------------------------------------------------

func TestRoutingCombinedValid(t *testing.T) {
	p := writeRulesFileForTest(t, c4ValidRules)
	set := map[string]string{
		config.EnvRoutingRulesFile: p,
		config.EnvRoutingDefault:   "warp",
		config.EnvWarpSocksAddr:    "10.0.0.1:1080",
		config.EnvRoutingDebug:     "true",
	}
	if errs := ValidateRoutingChange(config.RoleGermany, set, map[string]string{}); len(errs) != 0 {
		t.Fatalf("combined valid routing set: %v", errs)
	}
}
