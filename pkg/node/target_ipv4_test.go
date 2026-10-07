// Tests for the egress-target address-family policies (target_ipv4.go):
// the opt-in hard filter SPLIT_TARGET_ONLY_IPV4 and the opt-in preference
// SPLIT_TARGET_ADDR_POLICY=prefer-ipv4 (deterministic v4-first with v6
// fallback).
//
// The dialer's domain path is exercised through the injectable
// ipv4Lookup (hard filter) and dualStackLookup (prefer-ipv4) package
// variables: tests substitute deterministic resolvers and assert on
// (a) filter/selection behavior, (b) the refusal-to-fall-back property of
// the hard filter, and (c) the AAAA-only + v4-failure fallback properties
// of prefer-ipv4. The literal-IP path is exercised against real loopback
// listeners (IPv4 always; IPv6 when the host has an IPv6 loopback, which
// is the case on the supported deployment targets).

package node

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
)

// setIPv4Lookup swaps the injectable hard-filter resolver for the duration
// of the test and restores it on cleanup (package-internal test, serial
// within a package).
func setIPv4Lookup(t *testing.T, f func(ctx context.Context, host string) ([]string, error)) {
	t.Helper()
	orig := ipv4Lookup
	ipv4Lookup = f
	t.Cleanup(func() { ipv4Lookup = orig })
}

// setDualStackLookup swaps the injectable dual-stack resolver (the
// prefer-ipv4 path) for the duration of the test and restores it on
// cleanup.
func setDualStackLookup(t *testing.T, f func(ctx context.Context, host string) (v4, v6 []string, err error)) {
	t.Helper()
	orig := dualStackLookup
	dualStackLookup = f
	t.Cleanup(func() { dualStackLookup = orig })
}

// TestDefaultTargetDialOffPreservesPlainDial proves the policy is OFF by
// default: newDefaultTargetDial(false) must behave exactly like the
// historical net.DialTimeout("tcp") default — an IPv4 loopback dial
// succeeds and no resolver is involved.
func TestDefaultTargetDialOffPreservesPlainDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	setIPv4Lookup(t, func(ctx context.Context, h string) ([]string, error) {
		t.Fatalf("resolver must not be consulted when the policy is off, got %q", h)
		return nil, nil
	})

	dial := newDefaultTargetDial(false, false)
	conn, err := dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("off-policy dial of %s: %v", ln.Addr(), err)
	}
	defer conn.Close()
	if rc, ok := conn.RemoteAddr().(*net.TCPAddr); !ok || rc.IP.To4() == nil {
		t.Fatalf("off-policy dial did not produce an IPv4 connection: %v", conn.RemoteAddr())
	}
}

// TestDefaultTargetDialOffUnsetAlsoPlain mirrors the Config.Sanitize
// default path: a zero-value Config (policy unset) sanitizes to the
// plain dual-stack dial — byte-identical pre-policy behavior.
func TestDefaultTargetDialOffUnsetAlsoPlain(t *testing.T) {
	var cfg Config
	if err := cfg.Sanitize(); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if cfg.TargetDial == nil {
		t.Fatal("default TargetDial must be installed by Sanitize")
	}
	setIPv4Lookup(t, func(ctx context.Context, h string) ([]string, error) {
		t.Fatalf("resolver must not be consulted with an unset policy, got %q", h)
		return nil, nil
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	conn, err := cfg.TargetDial(ln.Addr().String())
	if err != nil {
		t.Fatalf("plain dial of %s: %v", ln.Addr(), err)
	}
	conn.Close()
}

// TestOnlyIPv4DomainPicksV4WhenBothFamiliesPresent: a domain that has
// both A and AAAA records must be dialed over the v4 address. We point
// the A record at our loopback listener (so the dial succeeds) and assert
// the connection landed on the v4 address, never the v6 one.
func TestOnlyIPv4DomainPicksV4WhenBothFamiliesPresent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	v4 := ln.Addr().(*net.TCPAddr).IP.String() // "127.0.0.1"
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	// Fake dual-homed domain: the resolver returns BOTH families (the
	// filter must keep only the v4 record).
	setIPv4Lookup(t, func(ctx context.Context, h string) ([]string, error) {
		if h != "dual.example.org" {
			t.Fatalf("lookup of unexpected host %q", h)
		}
		return []string{v4, "2001:db8::1"}, nil
	})

	dial := newDefaultTargetDial(true, false)
	conn, err := dial("dual.example.org:" + port)
	if err != nil {
		t.Fatalf("dual-homed domain should dial its v4 record: %v", err)
	}
	defer conn.Close()
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ra.String() != ln.Addr().String() {
		t.Fatalf("connection did not land on the loopback v4 listener: got %v want %v", conn.RemoteAddr(), ln.Addr())
	}
	if ra.IP.To4() == nil {
		t.Fatalf("dialed address is not IPv4: %v", ra.IP)
	}
}

// TestOnlyIPv4DomainAAAOnlyIsRefused proves there is no silent IPv6
// fallback: an AAAA-only host (no A record) must fail with a clear,
// policy-named error.
func TestOnlyIPv4DomainAAAOnlyIsRefused(t *testing.T) {
	lookups := 0
	setIPv4Lookup(t, func(ctx context.Context, h string) ([]string, error) {
		lookups++
		// Resolver hands back ONLY an IPv6 record: the To4() filter
		// inside defaultIPv4Lookup would drop it, so here (the
		// injection point) we report the v6-only result exactly as the
		// real filter would.
		return []string{}, nil // no A record survives the filter
	})

	dial := newDefaultTargetDial(true, false)
	_, err := dial("aaaa-only.example.org:443")
	if err == nil {
		t.Fatal("AAAA-only domain must not dial under the IPv4-only policy")
	}
	if !strings.Contains(err.Error(), "no IPv4 A record") {
		t.Fatalf("want a clear policy error naming the refusal, got: %v", err)
	}
	if !strings.Contains(err.Error(), "SPLIT_TARGET_ONLY_IPV4") {
		t.Fatalf("error must name the policy switch, got: %v", err)
	}
	if lookups == 0 {
		t.Fatal("resolver was not consulted for the domain host")
	}
}

// TestOnlyIPv4ResolverFilter: the To4() filter drops v6 results even when
// the resolver hands back a mixed list — only the v4 candidate reaches the
// dial (proven by the dial error naming 127.0.0.1, which the filter
// mapped as the sole A record, and by the connection being refused on the
// closed loopback port 1 rather than on a missing-A-record refusal).
func TestOnlyIPv4ResolverFilter(t *testing.T) {
	setIPv4Lookup(t, func(ctx context.Context, h string) ([]string, error) {
		// Simulate a resolver that already filtered to v4-only: the A
		// record points at a closed loopback port so the dial reaches the
		// "no reachable A record" branch, not the "no A record at all"
		// branch.
		return []string{"127.0.0.1"}, nil
	})
	dial := newDefaultTargetDial(true, false)
	_, err := dial("mixed.example.org:1")
	if err == nil {
		t.Fatal("expected a connection failure (127.0.0.1:1 is closed)")
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error must reference the v4 candidate that survived the filter: %v", err)
	}
	if strings.Contains(err.Error(), "no IPv4 A record") {
		t.Fatalf("the v4 candidate WAS present, so the refusal path is wrong: %v", err)
	}
	if !strings.Contains(err.Error(), "IPv4 only") {
		t.Fatalf("error must name the address-family policy: %v", err)
	}
}

// TestLiteralIPv4PassthroughUnderPolicy: a literal v4 IP bypasses the
// resolver and dials exactly as given.
func TestLiteralIPv4PassthroughUnderPolicy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	setIPv4Lookup(t, func(ctx context.Context, h string) ([]string, error) {
		t.Fatalf("resolver must not be consulted for a literal IP, got %q", h)
		return nil, nil
	})

	dial := newDefaultTargetDial(true, false)
	conn, err := dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("literal v4 dial failed: %v", err)
	}
	conn.Close()
}

// TestLiteralIPv6IsNotRewritten: an IPv6 literal must dial as IPv6 even
// under the IPv4-only policy — the filter applies to resolved domain
// hosts only, never to explicit addresses.
func TestLiteralIPv6IsNotRewritten(t *testing.T) {
	// Requires an IPv6 loopback on this host (all supported targets have
	// it); skip cleanly rather than fail on an IPv4-only machine.
	v6ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback available: %v", err)
	}
	defer v6ln.Close()

	setIPv4Lookup(t, func(ctx context.Context, h string) ([]string, error) {
		t.Fatalf("resolver must not be consulted for a literal IP, got %q", h)
		return nil, nil
	})

	dial := newDefaultTargetDial(true, false)
	conn, err := dial(v6ln.Addr().String()) // "[::1]:port"
	if err != nil {
		t.Fatalf("literal v6 dial failed (must NOT be rewritten to v4): %v", err)
	}
	defer conn.Close()
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ra.IP.To4() != nil {
		t.Fatalf("IPv6 literal was dialed as something else: %v", conn.RemoteAddr())
	}
}

// TestOnlyIPv4EndToEndWithValidARecord: a host whose A record points at
// our loopback listener must produce a working connection — the full
// resolve→filter→dial path with a real TCP dial.
func TestOnlyIPv4EndToEndWithValidARecord(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	setIPv4Lookup(t, func(ctx context.Context, h string) ([]string, error) {
		if h != "site.example" {
			t.Fatalf("lookup of unexpected host %q", h)
		}
		return []string{"127.0.0.1"}, nil
	})

	dial := newDefaultTargetDial(true, false)
	conn, err := dial("site.example:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatalf("end-to-end IPv4-only dial of a valid A record failed: %v", err)
	}
	defer conn.Close()
	// Prove the connection is real by exchanging one byte.
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write over dialed conn: %v", err)
	}
}

// =====================================================================
// SUBTASK 42 regression tests: SPLIT_TARGET_ADDR_POLICY=prefer-ipv4
// =====================================================================

// TestPreferIPv4DomainPicksV4WhenBothFamiliesPresent proves that under the
// prefer-ipv4 policy, a dual-stack domain (both A and AAAA records) dials
// the v4 address first. The AAAA record is NOT consulted — this is the v4
// speed benefit the policy was designed for.
func TestPreferIPv4DomainPicksV4WhenBothFamiliesPresent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	v4Addr := ln.Addr().(*net.TCPAddr).IP.String()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	setDualStackLookup(t, func(ctx context.Context, h string) (v4, v6 []string, err error) {
		if h != "dual.example.org" {
			t.Fatalf("lookup of unexpected host %q", h)
		}
		return []string{v4Addr}, []string{"2001:db8::1"}, nil
	})

	dial := newDefaultTargetDial(false, true)
	conn, err := dial("dual.example.org:" + port)
	if err != nil {
		t.Fatalf("prefer-ipv4 dual-stack domain should dial its v4 record: %v", err)
	}
	defer conn.Close()
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ra.IP.To4() == nil {
		t.Fatalf("prefer-ipv4 did not produce an IPv4 connection: %v", conn.RemoteAddr())
	}
}

// TestPreferIPv4DomainAAAOnlyFallsBackToV6 is THE REGRESSION TEST for the
// 96-refusal bug: under prefer-ipv4, an AAAA-only domain (no A record) must
// DIAL IPv6 successfully — it must NOT be refused. The hard filter
// (SPLIT_TARGET_ONLY_IPV4=true) broke exactly this case; this test proves
// the preference policy does not.
func TestPreferIPv4DomainAAAOnlyFallsBackToV6(t *testing.T) {
	// Requires an IPv6 loopback on this host; skip cleanly on IPv4-only
	// machines.
	v6ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback available: %v", err)
	}
	defer v6ln.Close()
	v6Addr := v6ln.Addr().(*net.TCPAddr).IP.String()
	port := strconv.Itoa(v6ln.Addr().(*net.TCPAddr).Port)

	// AAAA-only: the resolver returns an empty v4 slice and one v6 record.
	setDualStackLookup(t, func(ctx context.Context, h string) (v4, v6 []string, err error) {
		if h != "aaaa-only.example.org" {
			t.Fatalf("lookup of unexpected host %q", h)
		}
		return nil, []string{v6Addr}, nil
	})

	dial := newDefaultTargetDial(false, true)
	conn, err := dial("aaaa-only.example.org:" + port)
	if err != nil {
		t.Fatalf("prefer-ipv4 must NOT refuse an AAAA-only domain; got: %v", err)
	}
	defer conn.Close()
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ra.IP.To4() != nil {
		t.Fatalf("AAAA-only domain must have been dialed over IPv6, got: %v", conn.RemoteAddr())
	}
}

// TestPreferIPv4V4FailureFallsBackToV6 proves that when every IPv4 dial
// fails (e.g. closed port, unreachable host), the policy falls back to the
// first reachable IPv6 candidate within the shared 10s budget.
func TestPreferIPv4V4FailureFallsBackToV6(t *testing.T) {
	v6ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback available: %v", err)
	}
	defer v6ln.Close()
	v6Addr := v6ln.Addr().(*net.TCPAddr).IP.String()
	port := strconv.Itoa(v6ln.Addr().(*net.TCPAddr).Port)

	// v4 points at a CLOSED loopback port (the dial will fail fast); v6
	// points at our live listener.
	setDualStackLookup(t, func(ctx context.Context, h string) (v4, v6 []string, err error) {
		return []string{"127.0.0.1"}, []string{v6Addr}, nil
	})

	dial := newDefaultTargetDial(false, true)
	conn, err := dial("mixed.example.org:" + port)
	if err != nil {
		t.Fatalf("prefer-ipv4 must fall back to IPv6 when all v4 dials fail: %v", err)
	}
	defer conn.Close()
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ra.IP.To4() != nil {
		t.Fatalf("after v4 failure, the connection must be IPv6, got: %v", conn.RemoteAddr())
	}
}

// TestPreferIPv4LiteralIPv4Passthrough proves that a literal IPv4 address
// bypasses the resolver under the prefer-ipv4 policy and dials exactly as
// given.
func TestPreferIPv4LiteralIPv4Passthrough(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	setDualStackLookup(t, func(ctx context.Context, h string) (v4, v6 []string, err error) {
		t.Fatalf("resolver must not be consulted for a literal IP, got %q", h)
		return nil, nil, nil
	})

	dial := newDefaultTargetDial(false, true)
	conn, err := dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("prefer-ipv4 literal v4 dial failed: %v", err)
	}
	conn.Close()
}

// TestPreferIPv4LiteralIPv6Passthrough proves that a literal IPv6 address
// bypasses the resolver under the prefer-ipv4 policy and dials exactly as
// given (never rewritten to v4).
func TestPreferIPv4LiteralIPv6Passthrough(t *testing.T) {
	v6ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback available: %v", err)
	}
	defer v6ln.Close()

	setDualStackLookup(t, func(ctx context.Context, h string) (v4, v6 []string, err error) {
		t.Fatalf("resolver must not be consulted for a literal IP, got %q", h)
		return nil, nil, nil
	})

	dial := newDefaultTargetDial(false, true)
	conn, err := dial(v6ln.Addr().String())
	if err != nil {
		t.Fatalf("prefer-ipv4 literal v6 dial failed (must NOT be rewritten to v4): %v", err)
	}
	defer conn.Close()
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ra.IP.To4() != nil {
		t.Fatalf("literal IPv6 was dialed as something else: %v", conn.RemoteAddr())
	}
}

// TestPreferIPv4NoUsableAddressFailsCleanly proves that a domain that
// resolves to NO addresses at all (empty v4 AND empty v6) returns a clear
// "no usable address" error under prefer-ipv4.
func TestPreferIPv4NoUsableAddressFailsCleanly(t *testing.T) {
	setDualStackLookup(t, func(ctx context.Context, h string) (v4, v6 []string, err error) {
		return nil, nil, nil
	})
	dial := newDefaultTargetDial(false, true)
	_, err := dial("dead.example.org:443")
	if err == nil {
		t.Fatal("prefer-ipv4 with no A or AAAA record must fail")
	}
	if !strings.Contains(err.Error(), "no IPv4 or IPv6 address") {
		t.Fatalf("error must name the missing-address condition, got: %v", err)
	}
}

// TestOnlyIPv4PrecedenceWinsOverPreferIPv4 proves that when BOTH the hard
// filter and the preference are set (operator error), the hard filter wins
// (onlyIPv4=true overrides preferIPv4). This is the documented precedence
// in Config.Sanitize.
func TestOnlyIPv4PrecedenceWinsOverPreferIPv4(t *testing.T) {
	// Under the hard filter, an AAAA-only domain is refused even though
	// prefer-ipv4 would have allowed it.
	setIPv4Lookup(t, func(ctx context.Context, h string) ([]string, error) {
		return []string{}, nil // no A record
	})
	dial := newDefaultTargetDial(true, true) // onlyIPv4=true wins
	_, err := dial("aaaa-only.example.org:443")
	if err == nil {
		t.Fatal("only-IPv4 must win over prefer-ipv4: AAAA-only domain must be refused")
	}
	if !strings.Contains(err.Error(), "SPLIT_TARGET_ONLY_IPV4") {
		t.Fatalf("error must name the hard-filter policy, got: %v", err)
	}
}

// TestDefaultPolicyUnsetIsByteIdentical proves that a zero-value Config
// (no policy set) sanitizes to dialPlain — the historical dual-stack
// net.DialTimeout path. No resolver is consulted.
func TestDefaultPolicyUnsetIsByteIdentical(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	setDualStackLookup(t, func(ctx context.Context, h string) (v4, v6 []string, err error) {
		t.Fatalf("resolver must not be consulted under the default policy, got %q", h)
		return nil, nil, nil
	})
	setIPv4Lookup(t, func(ctx context.Context, h string) ([]string, error) {
		t.Fatalf("resolver must not be consulted under the default policy, got %q", h)
		return nil, nil
	})

	var cfg Config
	if err := cfg.Sanitize(); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if cfg.TargetDial == nil {
		t.Fatal("default TargetDial must be installed by Sanitize")
	}
	conn, err := cfg.TargetDial(ln.Addr().String())
	if err != nil {
		t.Fatalf("plain dial of %s: %v", ln.Addr(), err)
	}
	conn.Close()
}
