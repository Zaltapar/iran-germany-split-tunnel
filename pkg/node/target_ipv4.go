// target_ipv4.go holds the egress-target dial policy (the default
// TargetDial) and the opt-in only-IPv4 address-family filter.
//
// The node's default TargetDial (Config.Sanitize, node.go) is the single
// place the Germany-side engine actually dials an egress target. The
// historical default was net.DialTimeout("tcp", addr, 10s), which lets
// the OS resolver pick the address family — on a dual-homed Germany box
// that is typically IPv6-first (empty /etc/gai.conf + RFC 6724), so a
// domain that answers AAAA gets an IPv6 socket even when the IPv6 egress
// leg is the fragile one.
//
// SPLIT_TARGET_ONLY_IPV4 (opt-in, default false) makes the dialer resolve
// domain hosts to IPv4 (A) records only, dial the first reachable one,
// and — crucially — REFUSE to silently fall back to IPv6 when a domain has
// no A record. Literal IP addresses (v4 or v6) always bypass resolution and
// dial exactly as given: an IPv6 literal is never rewritten to IPv4.

package node

import (
	"context"
	"fmt"
	"net"
	"time"
)

// targetDialTimeout is the fixed 10s budget for a single default TargetDial,
// preserved byte-for-byte from the pre-policy net.DialTimeout default.
const targetDialTimeout = 10 * time.Second

// dialPlain is the historical dual-stack default: a single 10s TCP dial with
// no address-family steering. It is also the exact behavior when the only-
// IPv4 policy is OFF, so "off" remains byte-identical to the pre-change code.
func dialPlain(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, targetDialTimeout)
}

// ipv4Lookup resolves a domain to its IPv4 (A) addresses. It is a package-
// level variable so tests can substitute a deterministic resolver;
// production uses the system resolver via the default value. The "ip4"
// network argument makes the resolver report only A records
// deterministically, and the To4() filter below is a second,
// belt-and-suspenders guard so a misconfigured resolver can never leak an
// AAAA result into the dial set. The context bounds the lookup so a hung
// resolver cannot stall a bootstrap stream for unbounded time (the pre-
// policy net.DialTimeout resolved within the same 10s dial budget).
var ipv4Lookup = defaultIPv4Lookup

// defaultIPv4Lookup is the production ipv4Lookup: system resolver, A records
// only. An empty result (host resolves but has no A record, e.g. an
// AAAA-only domain) is an empty slice, not an error — the caller must
// surface the policy error, never silently use IPv6.
func defaultIPv4Lookup(ctx context.Context, host string) ([]string, error) {
	// LookupHost returns the host's A and AAAA results; we filter the
	// results to IPv4 only (ip.To4() != nil) so that a mixed-family or
	// misconfigured resolver can never leak an AAAA result into the dial
	// set. A host that has only AAAA records resolves here to an EMPTY
	// slice (not an error) — the caller turns that into the policy error.
	addrs, err := (&net.Resolver{}).LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			out = append(out, ip.String())
		}
	}
	return out, nil
}

// newDefaultTargetDial builds the node's default egress TargetDial.
//
//   - onlyIPv4=false: returns dialPlain (the historical dual-stack
//     net.DialTimeout, byte-identical to pre-policy behavior).
//   - onlyIPv4=true: resolves domain hosts to IPv4 (A) records only and
//     dials the first reachable one within a shared 10s budget. A domain
//     with no A record returns a clear error naming the policy; it does
//     NOT silently dial IPv6. Literal IP addresses (v4 or v6) bypass
//     resolution entirely and dial exactly as given (an IPv6 literal is
//     never rewritten to IPv4).
func newDefaultTargetDial(onlyIPv4 bool) func(addr string) (net.Conn, error) {
	if !onlyIPv4 {
		return dialPlain
	}
	return func(addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// Literal IP (v4 or v6) or a host that does not need resolution:
		// dial exactly as given. No family filter, no rewrite — an IPv6
		// literal stays IPv6.
		if net.ParseIP(host) != nil {
			return dialPlain(addr)
		}
		// Bound the resolution within the same 10s budget so a hung
		// resolver cannot stall the stream.
		ctx, cancel := context.WithTimeout(context.Background(), targetDialTimeout)
		defer cancel()
		ips, err := ipv4Lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q for target dial: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf(
				"target %q has no IPv4 A record; the SPLIT_TARGET_ONLY_IPV4 policy refuses to dial AAAA/IPv6 (set SPLIT_TARGET_ONLY_IPV4=false to allow dual-stack)", host)
		}
		// Shared 10s budget across the candidate A records so a slow first
		// record cannot multiply the wait. "tcp4" keeps the kernel on IPv4.
		deadline := time.Now().Add(targetDialTimeout)
		var lastErr error
		for _, ip := range ips {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort(ip, port), remaining)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, fmt.Errorf("dial %q (IPv4 only, %d candidate A record(s)): %w", host, len(ips), lastErr)
		}
		return nil, fmt.Errorf("dial %q (IPv4 only): no reachable A record", host)
	}
}
