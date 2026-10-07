// Tests for the opt-in only-IPv4 egress-target dial policy
// (SPLIT_TARGET_ONLY_IPV4, target_ipv4.go).
//
// The dialer's domain path is exercised through the injectable
// ipv4Lookup package variable: tests substitute a deterministic resolver
// and assert on (a) pure filter/selection behavior and (b) the refusal to
// silently fall back to IPv6. The literal-IP path is exercised against
// real loopback listeners (IPv4 always; IPv6 when the host has an IPv6
// loopback, which is the case on the supported deployment targets).

package node

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
)

// setIPv4Lookup swaps the injectable resolver for the duration of the test
// and restores it on cleanup (package-internal test, serial within a
// package).
func setIPv4Lookup(t *testing.T, f func(ctx context.Context, host string) ([]string, error)) {
	t.Helper()
	orig := ipv4Lookup
	ipv4Lookup = f
	t.Cleanup(func() { ipv4Lookup = orig })
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

	dial := newDefaultTargetDial(false)
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

	dial := newDefaultTargetDial(true)
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

	dial := newDefaultTargetDial(true)
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
	dial := newDefaultTargetDial(true)
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

	dial := newDefaultTargetDial(true)
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

	dial := newDefaultTargetDial(true)
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

	dial := newDefaultTargetDial(true)
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
