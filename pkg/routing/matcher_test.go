// matcher_test.go — matching semantics matrix for the routing engine.
package routing

import (
	"testing"
)

func eval(t *testing.T, js string, host string, port int) (OutboundKind, string) {
	t.Helper()
	rs := mustRules(t, js)
	kind, ruleID := rs.Evaluate(&Destination{Host: host, Port: port})
	return kind, ruleID
}

func TestMatchFirstMatchWins(t *testing.T) {
	js := `{
		"version":1,"default_action":"direct",
		"rules":[
			{"id":"first","match":{"keyword":"a"},"action":"warp"},
			{"id":"second","match":{"keyword":"a"},"action":"block"}
		]
	}`
	kind, id := eval(t, js, "host-a", 443)
	if kind != OutboundWarp || id != "first" {
		t.Fatalf("first match should win: got (%v, %q)", kind, id)
	}
}

func TestMatchDisabledRulesSkipped(t *testing.T) {
	js := `{
		"version":1,"default_action":"warp",
		"rules":[
			{"id":"off","match":{"keyword":"skip"},"action":"block","enabled":false}
		]
	}`
	// "skip" matches the disabled rule → falls through to the default.
	kind, id := eval(t, js, "skip-me", 80)
	if kind != OutboundWarp || id != "" {
		t.Fatalf("disabled rule should be skipped (default warp), got (%v, %q)", kind, id)
	}
}

func TestMatchDomainSuffix(t *testing.T) {
	js := `{"version":1,"default_action":"direct","rules":[
		{"id":"suf","match":{"domain":".example.com"},"action":"warp"},
		{"id":"ex","match":{"domain":"internal.example.com"},"action":"block"}
	]}`

	cases := []struct {
		host string
		want OutboundKind
		id   string
	}{
		{"example.com", OutboundWarp, "suf"},          // suffix matches the bare domain
		{"sub.example.com", OutboundWarp, "suf"},      // subdomain
		{"a.b.example.com", OutboundWarp, "suf"},      // deep subdomain
		{"internal.example.com", OutboundBlock, "ex"}, // exact wins (first rule? no — "suf" also matches ".example.com"; first-match-wins → "suf")
		{"notexample.com", OutboundDirect, ""},        // suffix form does not match a superstring without the dot
		{"comexample.com", OutboundDirect, ""},        // no rule matches → default (direct)
	}
	// Re-evaluate "internal.example.com": the ".example.com" suffix
	// matches it too, and the "suf" rule comes first → warp, not block.
	cases[3] = struct {
		host string
		want OutboundKind
		id   string
	}{"internal.example.com", OutboundWarp, "suf"}

	for _, c := range cases {
		kind, id := eval(t, js, c.host, 443)
		if kind != c.want || id != c.id {
			t.Errorf("host %q: got (%v, %q), want (%v, %q)", c.host, kind, id, c.want, c.id)
		}
	}
}

func TestMatchDomainExact(t *testing.T) {
	js := `{"version":1,"default_action":"direct","rules":[
		{"id":"ex","match":{"domain":"example.com"},"action":"warp"}
	]}`
	cases := []struct {
		host string
		want OutboundKind
	}{
		{"example.com", OutboundWarp},
		{"EXAMPLE.com", OutboundWarp},       // case-insensitive
		{"sub.example.com", OutboundDirect}, // exact form does NOT match subdomains
	}
	for _, c := range cases {
		kind, _ := eval(t, js, c.host, 443)
		if kind != c.want {
			t.Errorf("host %q: got %v, want %v", c.host, kind, c.want)
		}
	}
}

func TestMatchDomainDoesNotMatchIPLiteral(t *testing.T) {
	js := `{"version":1,"default_action":"direct","rules":[
		{"id":"d","match":{"domain":"10.0.0.1"},"action":"warp"}
	]}`
	// A domain-pattern host string that looks like an IP literal is not
	// a parseable IP name match path: domain rules only apply to names.
	kind, _ := eval(t, js, "10.0.0.1", 80)
	if kind != OutboundDirect {
		t.Fatalf("domain rule should not match a literal IP host; got %v", kind)
	}
}

func TestMatchKeyword(t *testing.T) {
	js := `{"version":1,"default_action":"direct","rules":[
		{"id":"k","match":{"keyword":"Internal"},"action":"block"}
	]}`
	cases := []struct {
		host string
		want OutboundKind
	}{
		{"MY.internal.host", OutboundBlock}, // case-insensitive
		{"10.10.internal.net", OutboundBlock},
		{"unrelated", OutboundDirect},
	}
	for _, c := range cases {
		kind, _ := eval(t, js, c.host, 80)
		if kind != c.want {
			t.Errorf("host %q: got %v, want %v", c.host, kind, c.want)
		}
	}
}

func TestMatchCIDR(t *testing.T) {
	js := `{"version":1,"default_action":"direct","rules":[
		{"id":"c4","match":{"ip_cidr":"10.0.0.0/8"},"action":"block"},
		{"id":"c6","match":{"ip_cidr":"fe80::/10"},"action":"warp"}
	]}`
	cases := []struct {
		host string
		want OutboundKind
		id   string
	}{
		{"10.255.1.2", OutboundBlock, "c4"},
		{"11.0.0.1", OutboundDirect, ""},
		{"fe80::1", OutboundWarp, "c6"},
		{"2001:db8::1", OutboundDirect, ""},
		{"example.com", OutboundDirect, ""}, // domains never CIDR-match
	}
	for _, c := range cases {
		kind, id := eval(t, js, c.host, 443)
		if kind != c.want || id != c.id {
			t.Errorf("host %q: got (%v,%q), want (%v,%q)", c.host, kind, id, c.want, c.id)
		}
	}
}

func TestMatchPortRange(t *testing.T) {
	js := `{"version":1,"default_action":"direct","rules":[
		{"id":"p","match":{"keyword":"a","port_min":80,"port_max":443},"action":"block"},
		{"id":"p2","match":{"keyword":"a","port_min":8080},"action":"warp"},
		{"id":"p3","match":{"keyword":"a","port_max":1000},"action":"direct"}
	]}`
	cases := []struct {
		host string
		port int
		want OutboundKind
		id   string
	}{
		{"a", 443, OutboundBlock, "p"},
		{"a", 80, OutboundBlock, "p"},
		{"a", 8080, OutboundWarp, "p2"}, // 8080 > 443 → p2's [8080,65535]
		{"a", 1000, OutboundWarp, "p2"}, // 1000 is in p2's range too, but p2 first? no: p2's range is [8080,65535]; 1000 not in it
		{"a", 8081, OutboundWarp, "p2"},
		{"a", 999, OutboundDirect, "p3"}, // [1,1000]
		{"a", 1001, OutboundDirect, ""},  // default
		{"a", 0, OutboundDirect, ""},     // port 0 is out of every range
	}
	// Fix the 1000 case expectation: p covers [80,443]; p2 covers
	// [8080,65535]; 1000 is in neither → p3 [1,1000] matches.
	cases[3] = struct {
		host string
		port int
		want OutboundKind
		id   string
	}{"a", 1000, OutboundDirect, "p3"}

	for _, c := range cases {
		kind, id := eval(t, js, c.host, c.port)
		if kind != c.want || id != c.id {
			t.Errorf("host %q port %d: got (%v,%q), want (%v,%q)", c.host, c.port, kind, id, c.want, c.id)
		}
	}
}

func TestMatchCriteriaOR(t *testing.T) {
	js := `{"version":1,"default_action":"direct","rules":[
		{"id":"o","match":{"domain":".x.com","keyword":"y","ip_cidr":"192.168.0.0/16"},"action":"block"}
	]}`
	for _, host := range []string{"x.com", "sub.x.com", "a.y.b", "192.168.1.1"} {
		kind, id := eval(t, js, host, 80)
		if kind != OutboundBlock || id != "o" {
			t.Errorf("OR-criteria host %q: got (%v,%q), want block/o", host, kind, id)
		}
	}
	kind, _ := eval(t, js, "nomatch.example.org", 80)
	if kind != OutboundDirect {
		t.Errorf("unmatched host should hit default, got %v", kind)
	}
}

func TestDefaultOutbound(t *testing.T) {
	js := `{"version":1,"default_action":"warp","rules":[]}`
	kind, id := eval(t, js, "whatever.example.org", 443)
	if kind != OutboundWarp || id != "" {
		t.Fatalf("default warp: got (%v,%q)", kind, id)
	}

	jsDirect := `{"version":1,"rules":[]}` // empty default_action → "direct"
	kind, id = eval(t, jsDirect, "whatever.example.org", 443)
	if kind != OutboundDirect || id != "" {
		t.Fatalf("empty default_action → direct: got (%v,%q)", kind, id)
	}
}

func TestEvaluateIPv6Literal(t *testing.T) {
	js := `{"version":1,"default_action":"direct","rules":[
		{"id":"v6","match":{"ip_cidr":"::1/128"},"action":"warp"}
	]}`
	kind, id := eval(t, js, "::1", 65535)
	if kind != OutboundWarp || id != "v6" {
		t.Fatalf("loopback v6: got (%v,%q), want (warp, v6)", kind, id)
	}
	kind, _ = eval(t, js, "fe80::1", 80)
	if kind != OutboundDirect {
		t.Fatalf("non-loopback v6 should hit default, got %v", kind)
	}
}
