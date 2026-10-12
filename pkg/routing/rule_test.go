// rule_test.go — parser/validator matrix for the routing rule model.
package routing

import (
	"errors"
	"strings"
	"testing"
)

func mustRules(t *testing.T, js string) *RuleSet {
	t.Helper()
	rs, err := ParseRules([]byte(js))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	return rs
}

func wantErr(t *testing.T, js string, sub string) {
	t.Helper()
	_, err := ParseRules([]byte(js))
	if err == nil {
		t.Fatalf("want error containing %q, got nil", sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("want error containing %q, got %v", sub, err)
	}
}

func TestParseRulesValid(t *testing.T) {
	js := `{
		"version": 1,
		"default_action": "direct",
		"rules": [
			{"id":"r1","match":{"domain":".example.com"},"action":"warp","fallback":"direct"},
			{"id":"r2","match":{"ip_cidr":"10.0.0.0/8"},"action":"block"},
			{"id":"r3","match":{"keyword":"internal"},"action":"direct"}
		]
	}`
	rs := mustRules(t, js)
	if rs.DefaultAction != "direct" {
		t.Fatalf("DefaultAction = %q", rs.DefaultAction)
	}
	if len(rs.Rules) != 3 {
		t.Fatalf("len(Rules) = %d", len(rs.Rules))
	}
	if !rs.Rules[0].Enabled {
		t.Error("rule with no enabled field should default to enabled")
	}
	if !rs.Rules[1].Enabled {
		t.Error("rule with no enabled field should default to enabled (block rule)")
	}
}

func TestParseRulesDisabledRule(t *testing.T) {
	js := `{"version":1,"default_action":"direct","rules":[{"id":"off","match":{"keyword":"x"},"action":"block","enabled":false}]}`
	rs := mustRules(t, js)
	if rs.Rules[0].Enabled {
		t.Error("explicit enabled:false should be disabled")
	}
}

func TestParseRulesDuplicateID(t *testing.T) {
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"keyword":"x"},"action":"direct"},{"id":"a","match":{"keyword":"y"},"action":"direct"}]}`,
		"duplicate rule id",
	)
}

func TestParseRulesUnknownAction(t *testing.T) {
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"keyword":"x"},"action":"tunnel"}]}`,
		"unknown action",
	)
}

func TestParseRulesEmptyMatch(t *testing.T) {
	// catch-all block is refused
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","action":"block"}]}`,
		"lock out the tunnel",
	)
	// catch-all direct is refused (shadow)
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","action":"direct"}]}`,
		"shadow every rule",
	)
}

func TestParseRulesBlockDefault(t *testing.T) {
	wantErr(t,
		`{"version":1,"default_action":"block","rules":[]}`,
		"block default",
	)
}

func TestParseRulesUnknownField(t *testing.T) {
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"keyword":"x"},"action":"direct","password":"hunter2"}]}`,
		"JSON decode",
	)
}

func TestParseRulesBadDomain(t *testing.T) {
	// uppercase
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"domain":".Example.COM"},"action":"direct"}]}`,
		"invalid character",
	)
	// wildcard
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"domain":"*.example.com"},"action":"direct"}]}`,
		"wildcards",
	)
	// leading hyphen label
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"domain":".-example.com"},"action":"direct"}]}`,
		"leading or trailing hyphen",
	)
	// trailing hyphen label
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"domain":"example-.com"},"action":"direct"}]}`,
		"leading or trailing hyphen",
	)
	// empty label (double dot)
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"domain":"example..com"},"action":"direct"}]}`,
		"empty label",
	)
}

func TestParseRulesGoodDomain(t *testing.T) {
	// exact
	mustRules(t, `{"version":1,"rules":[{"id":"a","match":{"domain":"example.com"},"action":"direct"}]}`)
	// suffix
	mustRules(t, `{"version":1,"rules":[{"id":"a","match":{"domain":".example.com"},"action":"direct"}]}`)
	// subdomain suffix
	mustRules(t, `{"version":1,"rules":[{"id":"a","match":{"domain":".a.b.example.com"},"action":"direct"}]}`)
	// single-label domain
	mustRules(t, `{"version":1,"rules":[{"id":"a","match":{"domain":"host"},"action":"direct"}]}`)
}

func TestParseRulesBadCIDR(t *testing.T) {
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"ip_cidr":"10.0.0.0/33"},"action":"direct"}]}`,
		"ip_cidr",
	)
}

func TestParseRulesGoodCIDR(t *testing.T) {
	mustRules(t, `{"version":1,"rules":[{"id":"a","match":{"ip_cidr":"10.0.0.0/8"},"action":"direct"}]}`)
	mustRules(t, `{"version":1,"rules":[{"id":"a","match":{"ip_cidr":"fe80::/10"},"action":"direct"}]}`)
}

func TestParseRulesPortRange(t *testing.T) {
	// valid
	mustRules(t, `{"version":1,"rules":[{"id":"a","match":{"keyword":"x","port_min":80,"port_max":443},"action":"direct"}]}`)
	// min > max
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"keyword":"x","port_min":443,"port_max":80},"action":"direct"}]}`,
		"port_min 443 exceeds port_max 80",
	)
	// out of range
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"keyword":"x","port_min":70000},"action":"direct"}]}`,
		"port_min 70000 out of range",
	)
}

func TestParseRulesFallbackValidation(t *testing.T) {
	// fallback on non-warp rule
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"keyword":"x"},"action":"direct","fallback":"direct"}]}`,
		"fallback is only meaningful for action=warp",
	)
	// invalid fallback value
	wantErr(t,
		`{"version":1,"rules":[{"id":"a","match":{"keyword":"x"},"action":"warp","fallback":"block"}]}`,
		"fallback must be \"direct\" or empty",
	)
	// valid fallback on warp
	mustRules(t, `{"version":1,"rules":[{"id":"a","match":{"keyword":"x"},"action":"warp","fallback":"direct"}]}`)
}

func TestParseRulesMaxRules(t *testing.T) {
	// Build 501 rules to exceed the cap.
	var sb strings.Builder
	sb.WriteString(`{"version":1,"rules":[`)
	for i := 0; i < MaxRules+1; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":"r` + itoa(i) + `","match":{"keyword":"k` + itoa(i) + `"},"action":"direct"}`)
	}
	sb.WriteString("]}")
	_, err := ParseRules([]byte(sb.String()))
	if err == nil {
		t.Fatal("want max-rules error, got nil")
	}
	if !strings.Contains(err.Error(), "too many rules") {
		t.Fatalf("want too-many-rules error, got %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := ""
	for i > 0 {
		digits = string(rune('0'+i%10)) + digits
		i /= 10
	}
	return digits
}

func TestParseRulesMaxBytes(t *testing.T) {
	// A document over MaxConfigBytes is refused.
	big := strings.Repeat("a", MaxConfigBytes+1)
	_, err := ParseRules([]byte("{" + `"junk":"` + big + `"}`))
	if err == nil {
		t.Fatal("want max-bytes error")
	}
}

func TestSanitizeVersion(t *testing.T) {
	wantErr(t, `{"version":2}`, "unsupported rules file version")
}

func TestLoadRulesFile(t *testing.T) {
	// Non-existent file.
	_, err := LoadRulesFile("/nonexistent/path/rules.json")
	if err == nil {
		t.Fatal("want error for missing file")
	}
	// This test only checks the error path; the happy path is
	// covered by ParseRules.
	_ = errors.Is(err, errors.New("")) // silence unused
}
