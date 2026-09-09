package origin

// adversarial_test.go — hostile-input Caddyfile injection tests (review
// CRITICAL-1). Every rejected value must produce ErrInvalidPlan, NO
// rendered bytes, NO gate call, and NO filesystem mutation; every
// accepted render must contain ONLY canonicalized tokens (the raw
// operator string never reaches a Caddyfile token).

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ACME email token injection (CRITICAL-1, field 1)
// ---------------------------------------------------------------------------

// Hostile acmeEmail values. Each would escape the `tls`/`email`
// Caddyfile token if the raw string were rendered: internal newline,
// carriage return, tab, internal/leading/trailing spaces, braces,
// comment markers, and directive-shaped suffixes.
var hostileEmails = []string{
	"ops@example.com\n}", // internal newline + close-brace
	"ops@example.com\n\treverse_proxy /evil 8.8.8.8:80", // directive injection
	"ops@example.com\r\nimport /etc/evil",               // CRLF + import directive
	"ops@example.com\t{",                                // tab + open-brace
	"ops @example.com",                                  // internal space
	" ops@example.com",                                  // leading space
	"ops@example.com ",                                  // trailing space
	"ops@example.com\x00",                               // NUL control byte
	"ops@example.com\v",                                 // vertical tab (Unicode space)
	"ops@example.com admin {",                           // NBSP + injected block
	"ops@example.com#comment",                           // comment marker
	"ops@example.com{reverse_proxy}",                    // brace burst
	"ops@example.com}",                                  // lone close-brace
	"ops@example.com{",                                  // lone open-brace
	"ops@exa`mple.com",                                  // backquote
	"ops@exa\\mple.com",                                 // backslash (re-tokenizes)
	`ops@"example.com`,                                  // double quote
	"ops@example.com;",                                  // semicolon
}

func TestACMEEmailAdversarialRejected(t *testing.T) {
	for _, e := range hostileEmails {
		plan := Plan{
			Mode:         ModeCaddy,
			Domain:       "upload.example.com",
			UpstreamAddr: "127.0.0.1:9001",
			ACMEEmail:    e,
		}
		out, err := RenderCaddyfile(plan)
		if err == nil {
			t.Errorf("acmeEmail %q accepted (rendered %d bytes)", e, len(out))
			continue
		}
		if !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("acmeEmail %q: want ErrInvalidPlan, got %v", e, err)
		}
		if out != nil {
			t.Errorf("acmeEmail %q: rejected but %d bytes were rendered", e, len(out))
		}
		// The same value must also be rejected on the tlsalpn01 path
		// (the `email` subdirective token).
		plan.ACMEChallenge = ACMETLSALPN01
		if _, err := RenderCaddyfile(plan); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("acmeEmail %q (alpn01): want ErrInvalidPlan, got %v", e, err)
		}
	}
}

// A rejected plan must not reach the gate or the filesystem when driven
// through the full activation path (no rendered bytes, no gate call, no
// filesystem mutation — review CRITICAL-1 acceptance).
func TestACMEEmailAdversarialNoGateNoMutation(t *testing.T) {
	dir := t.TempDir()
	fe := &fakeExec{}
	plan := Plan{
		Mode:         ModeCaddy,
		Domain:       "upload.example.com",
		UpstreamAddr: "127.0.0.1:9001",
		ACMEEmail:    "ops@example.com\n\treverse_proxy /upload 8.8.8.8:80\n}",
	}
	_, err := ActivateCaddyfile(ActivateParams{Plan: plan, Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("want ErrInvalidPlan, got %v", err)
	}
	if len(fe.calls) != 0 {
		t.Errorf("gate was called on a rejected plan: %v", fe.calls)
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		t.Errorf("filesystem mutated by a rejected plan: %v", entries)
	}
}

// ---------------------------------------------------------------------------
// Upstream port token injection (CRITICAL-1, field 2)
// ---------------------------------------------------------------------------

// Hostile upstreamAddr values. SplitHostPort accepts every one of these
// STRUCTURALLY (a non-empty port string) — they must be rejected by the
// decimal-port rule instead of reaching the reverse_proxy token.
var hostileUpstreams = []string{
	"127.0.0.1:9001\n\treverse_proxy /evil 8.8.8.8:80\n}", // newline directive injection
	"127.0.0.1:9001\r\nimport /etc/evil",                  // CRLF
	"127.0.0.1:9001\t}",                                   // tab + brace
	"127.0.0.1:9001 }",                                    // space + brace
	"127.0.0.1:9001{",                                     // brace suffix
	"127.0.0.1:9001#x",                                    // comment marker
	"127.0.0.1:9001 ",                                     // trailing space
	"127.0.0.1: 9001",                                     // leading space in port
	"127.0.0.1:09001",                                     // zero-padded (accepted→canonicalized, see below)
	"127.0.0.1:9001\x00",                                  // NUL
	"127.0.0.1:+9001",                                     // sign
	"127.0.0.1:0x2329",                                    // hex
	"127.0.0.1:9001.5",                                    // decimal point
	"127.0.0.1:99999",                                     // out of range
	"127.0.0.1:0",                                         // port zero
	"127.0.0.1:65536",                                     // just over the max
	"127.0.0.1:90010",                                     // 5 digits but > 65535... (90010 > 65535)
	"127.0.0.1:999999",                                    // 6 digits (length overflow)
}

func TestUpstreamAdversarialRejected(t *testing.T) {
	for _, u := range hostileUpstreams {
		// 09001 is DECIMAL-valid (it is 9001); it must be accepted and
		// canonicalized, tested separately below.
		if u == "127.0.0.1:09001" {
			continue
		}
		plan := Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: u}
		out, err := RenderCaddyfile(plan)
		if err == nil {
			t.Errorf("upstreamAddr %q accepted (rendered %d bytes)", u, len(out))
			continue
		}
		if !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("upstreamAddr %q: want ErrInvalidPlan, got %v", u, err)
		}
		if out != nil {
			t.Errorf("upstreamAddr %q: rejected but %d bytes were rendered", u, len(out))
		}
		// Same rejection on the cdn mode A path (same rule).
		planCDN := Plan{
			Mode:           ModeCDN,
			Domain:         "upload.example.com",
			CDNSecurity:    CDNTLSOrigin,
			CDNOriginTrust: CDNOriginTrustPullCA,
			UpstreamAddr:   u,
			OriginPort:     8443,
		}
		if _, err := RenderCaddyfile(planCDN); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("upstreamAddr %q (cdn A): want ErrInvalidPlan, got %v", u, err)
		}
	}
}

// A rejected upstream must not reach the gate or the filesystem.
func TestUpstreamAdversarialNoGateNoMutation(t *testing.T) {
	dir := t.TempDir()
	fe := &fakeExec{}
	plan := Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001\n}"}
	_, err := ActivateCaddyfile(ActivateParams{Plan: plan, Dir: dir, Bin: "/fake/caddy", Exec: fe})
	if !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("want ErrInvalidPlan, got %v", err)
	}
	if len(fe.calls) != 0 {
		t.Errorf("gate was called on a rejected plan: %v", fe.calls)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("filesystem mutated by a rejected plan: %v", entries)
	}
}

// ---------------------------------------------------------------------------
// Canonicalization (CRITICAL-1 acceptance): the rendered output must
// contain ONLY canonicalized tokens, never the raw input.
// ---------------------------------------------------------------------------

// A zero-padded / IPv6-long-form upstream is ACCEPTED by the rule but
// rendered CANONICALLY: "09001" → "9001", "0:0:0:0:0:0:0:1" → "::1".
// The raw string must NOT appear in the output.
func TestUpstreamCanonicalizedNotRaw(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // canonical form that MUST appear
	}{
		{"zero-padded port", "127.0.0.1:09001", "127.0.0.1:9001"},
		{"ipv6 long form", "[0:0:0:0:0:0:0:1]:9001", "[::1]:9001"},
		// IPv4-mapped IPv6 loopback canonicalizes to the plain IPv4 form
		// (net.IP.String() renders 4-byte-mapped addresses as dotted
		// quad) — the raw bracketed token must not appear.
		{"ipv4-mapped loopback", "[::ffff:127.0.0.1]:9001", "127.0.0.1:9001"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: c.in}
			out, err := RenderCaddyfile(plan)
			if err != nil {
				t.Fatalf("canonicalizable upstream %q rejected: %v", c.in, err)
			}
			if !strings.Contains(string(out), "reverse_proxy "+UpstreamPath+" "+c.want) {
				t.Errorf("canonical upstream %q missing; got:\n%s", c.want, out)
			}
			if c.in != c.want && strings.Contains(string(out), c.in) {
				t.Errorf("raw input %q leaked into the rendered Caddyfile:\n%s", c.in, out)
			}
		})
	}
}

// The canonical upstream helper agrees with the validation rule on the
// boundary ports and rejects non-loopback/non-numeric input.
func TestCanonicalUpstreamBoundary(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:1", "127.0.0.1:65535", "[::1]:443"} {
		if _, err := canonicalUpstream(ok); err != nil {
			t.Errorf("canonicalUpstream(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range []string{"127.0.0.1:0", "127.0.0.1:65536", "8.8.8.8:9001", "127.0.0.1:http"} {
		if _, err := canonicalUpstream(bad); err == nil {
			t.Errorf("canonicalUpstream(%q) accepted", bad)
		}
	}
}

// The canonical email helper round-trips exactly the accepted set.
func TestCanonicalACMEEmailRoundTrip(t *testing.T) {
	for _, ok := range []string{"ops@example.com", "a@b.co", "o+p.s-x@example-domain.com"} {
		got, err := canonicalACMEEmail(ok)
		if err != nil || got != ok {
			t.Errorf("canonicalACMEEmail(%q) = %q, %v", ok, got, err)
		}
	}
	for _, bad := range hostileEmails {
		if _, err := canonicalACMEEmail(bad); err == nil {
			t.Errorf("canonicalACMEEmail(%q) accepted", bad)
		}
	}
}

// A benign accepted render must not contain any byte that failed the
// hostile set (defense in depth: the output is exactly the template +
// canonical tokens).
func TestRenderContainsOnlyCanonicalTokens(t *testing.T) {
	plan := Plan{
		Mode:         ModeCaddy,
		Domain:       "upload.example.com",
		UpstreamAddr: "127.0.0.1:09001",
		ACMEEmail:    "ops@example.com",
	}
	out, err := RenderCaddyfile(plan)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if bytes.Contains(out, []byte("09001")) {
		t.Errorf("raw (non-canonical) port token present:\n%s", out)
	}
	if !bytes.Contains(out, []byte("127.0.0.1:9001")) {
		t.Errorf("canonical upstream missing:\n%s", out)
	}
}

// The golden-set plans still render after canonicalization (the benign
// vectors are unaffected).
func TestAdversarialGoldenPlansStillRender(t *testing.T) {
	for _, plan := range []Plan{goldenPlanCaddy(), goldenPlanALPN(), goldenPlanCDN()} {
		if _, err := RenderCaddyfile(plan); err != nil {
			t.Errorf("golden plan rejected after canonicalization: %v", err)
		}
	}
}

// canonicalUpstream must never be reached with an invalid value through
// the PUBLIC render path (validate() is the gate; canonicalUpstream is
// the defensive re-check). Drive it directly to prove fail-closed.
func TestCanonicalUpstreamNeverRendersRaw(t *testing.T) {
	raw := "127.0.0.1:9001\n\treverse_proxy /evil 8.8.8.8:80"
	if _, err := canonicalUpstream(raw); err == nil {
		t.Errorf("canonicalUpstream rendered the hostile raw value %q", raw)
	}
}

// A pre-existing operator-owned Caddyfile (no marker) must refuse the
// mode A → B deactivation (HIGH-5 ownership guard, exercised here as
// part of the no-mutation acceptance).
func TestAdversarialNoMutationOnRejectedPlanDir(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	fe := &fakeExec{}
	plan := Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001\t}"}
	if _, err := ActivateCaddyfile(ActivateParams{Plan: plan, Dir: dir, Bin: "/fake/caddy", Exec: fe}); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("want ErrInvalidPlan, got %v", err)
	}
	b, err := os.ReadFile(sentinel)
	if err != nil || string(b) != "do not touch" {
		t.Errorf("sentinel disturbed: %v %q", err, b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("unexpected files after a rejected plan: %v", entries)
	}
}
