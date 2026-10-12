// target_ipv4.go holds the egress-target dial policy (the default
// TargetDial) and the opt-in address-family steering:
//
//   - SPLIT_TARGET_ONLY_IPV4 (bool, opt-in, default false): HARD FILTER —
//     domain hosts resolve to IPv4 (A) records only and dial the first
//     reachable one; a domain with no A record is REFUSED with a clear
//     error. Do NOT use for general traffic — it actively breaks AAAA-only
//     endpoints (see docs/target-ipv4-policy.md and the 2026-10-07 WARP
//     episode: 96 stream refusals in ~13 minutes on Meta's AAAA-only
//     endpoints after deployment).
//   - SPLIT_TARGET_ADDR_POLICY=prefer-ipv4 (opt-in, default "default"):
//     PREFERENCE — for domain hosts, resolve BOTH families, dial IPv4
//     first, and fall back to IPv6 only if no IPv4 candidate succeeds (or
//     if no IPv4 candidate exists at all). This is the RECOMMENDED setting
//     for dual-homed Germany deployments: it takes the v4 speed benefit
//     without breaking AAAA-only hosts.
//
// Both policies are ADDITIVE and OFF by default: Config.Sanitize with
// neither flag set returns dialPlain (the historical
// net.DialTimeout("tcp", addr, 10s) — byte-identical to pre-policy code).
//
// Literal IP addresses (v4 or v6) ALWAYS bypass resolution under every
// policy and dial exactly as given: an IPv6 literal is never rewritten to
// IPv4.
//
// Semantics of prefer-ipv4 (the important one):
//
//   - domain + dual-stack (A and AAAA)  → dial the first reachable A record;
//     fall back to the first reachable AAAA record only if every A record
//     dial failed (shared 10s budget preserved across all candidates).
//   - domain + AAAA-only                → dial the AAAA record. No refusal.
//     This is the regression the hard IPv4 filter caused (96 stream
//     refusals on Meta's AAAA-only endpoints during the 2026-10-07 WARP
//     episode).
//   - domain + A-only                   → dial the A record (v6 fallback
//     never runs because there is no AAAA record to fall back to).
//   - literal IPv4 / literal IPv6       → dial exactly as given (no
//     resolver, no rewrite).
//
// Deterministic v4-first with v6 fallback — NOT happy-eyeballs:
//
//   - We do NOT race both families concurrently. The kernel's RFC 8305
//     happy-eyeballs (net.Dialer with a bare "tcp" network and no
//     ForceIPv4/ForceIPv6) would start both families in parallel and let
//     the FIRST one that connects win; on a fragile v6 egress leg this
//     produces a v6 connection even when v4 is faster, which is the
//     exact behavior the original diagnosis was trying to avoid.
//
//   - We do NOT use net.Dialer's HappyEyeballs field either: that API
//     would connect BOTH races concurrently and the first winner wins —
//     again racing the v6 fragile leg.
//
//   - Our ordering is STRICT: try every IPv4 candidate first (sequentially,
//     within the shared 10s budget). Only when there is no IPv4 candidate
//     or every IPv4 dial failed do we try the first reachable IPv6
//     candidate. This is what "deterministic v4-first" means.
//
//   - Timeout: the shared targetDialTimeout (10s) covers BOTH the
//     resolution step (via context.WithTimeout on the resolver) and all
//     the dial attempts (a single deadline, one net.Dialer reused across
//     every candidate). A hung resolver or a slow first record cannot
//     stall a bootstrap stream for unbounded time.
//
//   - Context: the resolver context is created with
//     context.WithTimeout(context.Background(), targetDialTimeout) and
//     cancelled via defer cancel() in the same scope, mirroring the
//     pre-policy net.DialTimeout budget.
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
// no address-family steering. It is also the exact behavior when BOTH
// policy flags are OFF (SPLIT_TARGET_ADDR_POLICY=default and
// SPLIT_TARGET_ONLY_IPV4=false), so "off" remains byte-identical to the
// pre-change code.
func dialPlain(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, targetDialTimeout)
}

// Target address-family policy values (Config.TargetAddrPolicy,
// SPLIT_TARGET_ADDR_POLICY). The default is "default": today's
// byte-identical dual-stack net.DialTimeout, so nothing changes unless an
// operator opts in.
const (
	// TargetAddrPolicyDefault is "default": the historical dual-stack
	// net.DialTimeout("tcp", 10s) — OS address-family preference (RFC
	// 6724; on Germany that is typically IPv6-first). This is the only
	// value the node used before SUBTASK 42.
	TargetAddrPolicyDefault = "default"
	// TargetAddrPolicyPreferIPv4 is "prefer-ipv4": deterministic
	// IPv4-first with IPv6 fallback. For a domain, resolve both families,
	// dial every IPv4 candidate first, and fall back to the IPv6
	// candidates ONLY when no IPv4 candidate succeeded. AAAA-only
	// domains still succeed over IPv6 (the regression the hard
	// SPLIT_TARGET_ONLY_IPV4 filter caused — 96 stream refusals on Meta's
	// AAAA-only endpoints during the 2026-10-07 WARP episode). This is
	// the RECOMMENDED opt-in for dual-homed Germany deployments.
	TargetAddrPolicyPreferIPv4 = "prefer-ipv4"
	// TargetAddrPolicyIPv4Only is "ipv4-only": the hard A-record filter
	// (equivalent to SPLIT_TARGET_ONLY_IPV4=true). Use with care — it
	// breaks AAAA-only endpoints.
	TargetAddrPolicyIPv4Only = "ipv4-only"
)

// validTargetAddrPolicy reports whether p is one of the allowed
// Config.TargetAddrPolicy values (the empty string is accepted as the
// "unset" sentinel and is treated as TargetAddrPolicyDefault by
// Config.Sanitize).
func validTargetAddrPolicy(p string) bool {
	switch p {
	case "", TargetAddrPolicyDefault, TargetAddrPolicyPreferIPv4, TargetAddrPolicyIPv4Only:
		return true
	}
	return false
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

// dualStackLookup resolves a domain to its IPv4 AND IPv6 addresses,
// partitioned so each address appears in exactly one slice. It is a
// package-level variable so tests can substitute a deterministic resolver;
// production uses the system resolver (dual-stack LookupHost, then split
// on ip.To4()). An empty overall result (host resolves but yields no
// usable address in EITHER family) is an empty pair, NOT an error — the
// caller surfaces a "no usable address" error and the stream is dropped
// at bootstrapUpStream.
//
// This is the resolver the prefer-ipv4 policy consults: it returns BOTH
// families so the dialer can enforce v4-first with v6 fallback, and it is
// NEVER the resolver the ipv4-only policy consults (that one uses the
// To4()-filtered ipv4Lookup above so a misconfigured resolver cannot leak
// an AAAA record into the hard-filter dial set).
var dualStackLookup = defaultDualStackLookup

// defaultDualStackLookup is the production dualStackLookup: system resolver,
// both families. A host that yields no addresses at all (NXDOMAIN, or a
// resolver that returned nothing parseable) yields an empty pair and no
// error — the caller turns that into the "no usable address" policy error.
func defaultDualStackLookup(ctx context.Context, host string) (v4, v6 []string, err error) {
	addrs, err := (&net.Resolver{}).LookupHost(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue // unparseable — skip, never fail the whole lookup
		}
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	return v4, v6, nil
}

// dialWithBudget dials addr with a remaining-time budget bounded by
// deadline. It uses net.Dialer (not net.DialTimeout) so the SAME deadline
// can be enforced across multiple candidates sequentially without
// multiplying the wait: each candidate gets time.Until(deadline), and a
// candidate that hits the ceiling (remaining <= 0) is skipped. This is
// the exact pattern the pre-policy net.DialTimeout gave for a single
// candidate, extended to N candidates under ONE shared 10s budget.
func dialWithBudget(deadline time.Time, addr string) (net.Conn, error) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, fmt.Errorf("no time remaining within the shared %s budget", targetDialTimeout)
	}
	d := net.Dialer{Timeout: remaining}
	return d.Dial("tcp", addr)
}

// newDefaultTargetDial builds the node's default egress TargetDial.
//
//   - onlyIPv4=true  (SPLIT_TARGET_ONLY_IPV4=1): HARD FILTER. Resolves
//     domain hosts to IPv4 (A) records only (via the To4()-filtered
//     ipv4Lookup), dials the first reachable one within a shared 10s
//     budget. A domain with no A record returns a clear error naming
//     SPLIT_TARGET_ONLY_IPV4; it does NOT silently dial IPv6. This is
//     the pre-existing behavior, preserved byte-for-byte so operators
//     who want the hard filter keep it working. preferIPv4 is ignored
//     when onlyIPv4=true (only-IPv4 wins — it is the stricter of the
//     two, and honoring both would be contradictory).
//   - preferIPv4=true (SPLIT_TARGET_ADDR_POLICY=prefer-ipv4, onlyIPv4
//     must be false): PREFERENCE. Resolves domain hosts to BOTH families
//     (via dualStackLookup), dials every IPv4 candidate first within a
//     shared 10s budget, and falls back to every IPv6 candidate ONLY IF
//     no IPv4 candidate succeeded (or there was no IPv4 candidate at
//     all). An AAAA-only domain succeeds over IPv6 — it is never refused.
//     Literal IP addresses (v4 or v6) bypass resolution entirely and
//     dial exactly as given.
//   - onlyIPv4=false, preferIPv4=false: dialPlain — the historical
//     dual-stack net.DialTimeout, byte-identical to pre-policy behavior.
//
// The two flags are mutually reinforcing but only "prefer" is
// meaningful when "only" is off; the caller (Config.Sanitize, node.go)
// enforces the merge precedence.
// DefaultTargetDial is the exported form of newDefaultTargetDial: it
// builds the node's policy-aware egress TargetDial for the given
// address-family flags. The GERMANY outbound routing engine (§22) uses
// it as its "direct" outbound, so a routing-enabled build's direct path
// is byte-identical to the dial the node would install when routing is
// OFF (Config.Sanitize's nil-TargetDial default). Callers pass the SAME
// merged flags Sanitize derives from Config.TargetOnlyIPv4 /
// Config.TargetAddrPolicy (onlyIPv4 = TargetOnlyIPv4 || policy==ipv4-only,
// preferIPv4 = policy==prefer-ipv4).
func DefaultTargetDial(onlyIPv4, preferIPv4 bool) func(addr string) (net.Conn, error) {
	return newDefaultTargetDial(onlyIPv4, preferIPv4)
}

// newDefaultTargetDial builds the node's default egress TargetDial.
func newDefaultTargetDial(onlyIPv4, preferIPv4 bool) func(addr string) (net.Conn, error) {
	if onlyIPv4 {
		// Hard filter: A records only, no v6 fallback. Unchanged from
		// the pre-SUBTASK-42 behavior.
		return func(addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// Literal IP (v4 or v6) or a host that does not need
			// resolution: dial exactly as given. No family filter, no
			// rewrite — an IPv6 literal stays IPv6.
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
			// Shared 10s budget across the candidate A records so a slow
			// first record cannot multiply the wait. "tcp4" keeps the
			// kernel on IPv4 (net.DialTimeout picks the family from the
			// address; we use the same primitive as the pre-policy code
			// for byte-identical behavior).
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

	if !preferIPv4 {
		// default policy: the historical dual-stack net.DialTimeout,
		// byte-identical to the pre-policy code path.
		return dialPlain
	}

	// prefer-ipv4: deterministic v4-first with v6 fallback (NOT a race).
	//
	//   - For a domain, resolve BOTH families via dualStackLookup.
	//   - For a literal IP, dial exactly as given (no resolver, no
	//     rewrite) — an IPv6 literal is never rewritten to IPv4, and an
	//     IPv4 literal is never rewritten to IPv6.
	//   - Within the shared 10s budget, try every IPv4 candidate
	//     SEQUENTIALLY first (deterministic ordering). Only when every
	//     IPv4 dial failed (or there was no IPv4 candidate) do we try
	//     the IPv6 candidates in the resolver's order. This is a strict
	//     ordering, NOT the kernel's RFC 8305 happy-eyeballs race: we
	//     never start a v6 dial while a v4 candidate is still in
	//     flight, so a fragile v6 leg can never "win" the race by
	//     being faster to connect.
	//   - The budget is ONE 10s deadline covering resolution AND every
	//     dial attempt; a hung resolver or a slow first record cannot
	//     multiply the wait.
	return func(addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// Literal IP (v4 or v6): dial exactly as given. No resolver, no
		// rewrite — an IPv6 literal stays IPv6 under prefer-ipv4 too.
		if net.ParseIP(host) != nil {
			return dialPlain(addr)
		}
		// Bound the resolution within the same 10s budget so a hung
		// resolver cannot stall the stream.
		ctx, cancel := context.WithTimeout(context.Background(), targetDialTimeout)
		deadline := time.Now().Add(targetDialTimeout)
		v4s, v6s, err := dualStackLookup(ctx, host)
		cancel() // resolver is done; the budget for dials is the same deadline
		if err != nil {
			return nil, fmt.Errorf("resolve %q for target dial: %w", host, err)
		}
		if len(v4s) == 0 && len(v6s) == 0 {
			return nil, fmt.Errorf(
				"dial %q: no IPv4 or IPv6 address available (resolver returned no usable records)", host)
		}
		// Phase 1: every IPv4 candidate, sequentially, within the shared
		// deadline. "tcp4" keeps the kernel on IPv4 even on a v6-first
		// host.
		var lastV4Err error
		for _, ip := range v4s {
			conn, err := dialWithBudget(deadline, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			lastV4Err = err
			if time.Now().After(deadline) {
				break
			}
		}
		// Phase 2: fall back to IPv6 ONLY when no IPv4 candidate
		// succeeded. This is the AAAA-only path (len(v4s)==0) AND the
		// v4-failed path (every A record dial failed). Deterministic:
		// we never start a v6 dial while any v4 candidate is still
		// pending.
		var lastV6Err error
		for _, ip := range v6s {
			conn, err := dialWithBudget(deadline, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			lastV6Err = err
			if time.Now().After(deadline) {
				break
			}
		}
		// Every candidate in both families failed (or the budget was
		// exhausted). Report the LAST v4 error (the phase that had
		// priority) if any v4 candidate was tried, otherwise the last
		// v6 error. This mirrors the pre-policy net.DialTimeout error
		// shape (single last error) and keeps the log line useful for
		// operators.
		switch {
		case len(v4s) > 0 && lastV4Err != nil:
			return nil, fmt.Errorf(
				"dial %q (prefer-IPv4: %d A record(s), then %d AAAA record(s) as fallback): %w",
				host, len(v4s), len(v6s), lastV4Err)
		case lastV6Err != nil:
			return nil, fmt.Errorf(
				"dial %q (prefer-IPv4: no reachable A record; %d AAAA record(s) tried as fallback): %w",
				host, len(v6s), lastV6Err)
		default:
			return nil, fmt.Errorf("dial %q (prefer-IPv4): no reachable address", host)
		}
	}
}
