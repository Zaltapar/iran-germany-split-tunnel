// matcher.go — pure destination matching for the routing engine
// (§22 matching semantics). All functions are side-effect free and
// safe to call from the per-stream dial path.
//
// Matching semantics (documented in rule.go):
//
//   - FIRST match wins: rules are evaluated in order; the first
//     enabled rule whose criteria are satisfied selects the outbound.
//   - Within a rule, domain / keyword / ip_cidr are OR-ed; the port
//     range is an AND pre-condition.
//   - Domain suffix/exact matching applies to destination HOST NAMES
//     (available in the SOCKS CONNECT target when it is a name;
//     otherwise IP matching applies). Domain rules never match a
//     literal-IP host.
//   - IP CIDR matching applies to literal-IP hosts only.
//   - Keyword matching applies to the raw host string (names and IPs).
package routing

import (
	"net"
	"strconv"
	"strings"
)

// Destination is one evaluable target: the host exactly as it appears
// in the SOCKS CONNECT request (a domain name, an IPv4/IPv6 literal,
// or bracketed IPv6) and the port.
type Destination struct {
	// Host is the destination host string (domain name or IP literal,
	// exactly as dialed). Never resolved at match time.
	Host string
	// Port is the destination port (1..65535).
	Port int
}

// PortInRange reports whether the destination port satisfies the rule's
// optional port-range pre-condition. Both PortMin/PortMax zero means
// "no filter" (always true). PortMin only → [PortMin, 65535];
// PortMax only → [1, PortMax]; both → [PortMin, PortMax].
func (m Match) PortInRange(port int) bool {
	lo, hi := m.PortMin, m.PortMax
	if lo == 0 {
		lo = 1
	}
	if hi == 0 {
		hi = 65535
	}
	return port >= lo && port <= hi
}

// matchRule reports whether one enabled rule's match criteria are
// satisfied by the destination (port pre-condition AND any-criterion
// match).
func matchRule(r *Rule, dst *Destination) bool {
	if !r.Enabled {
		return false
	}
	if !r.Match.PortInRange(dst.Port) {
		return false
	}
	// OR of the individual criteria.
	if r.Match.Domain != "" && matchDomain(r, dst.Host) {
		return true
	}
	if r.mKW != "" && matchKeyword(r, dst.Host) {
		return true
	}
	if r.mCIDR != nil && matchCIDR(r, dst.Host) {
		return true
	}
	return false
}

// matchDomain applies the domain criterion. Domain rules do NOT match
// literal-IP hosts (there is no host name to compare; the dial path
// performs resolution, matching does not). Comparison is on the
// lowercased host name.
func matchDomain(r *Rule, host string) bool {
	h := strings.ToLower(host)
	if net.ParseIP(h) != nil {
		return false // IP literal: domain criteria do not apply
	}
	if r.mDomSuffix {
		// ".example.com" → "example.com" and "sub.example.com" ...
		// h == core OR h ends with "."+core
		return h == r.mDom || strings.HasSuffix(h, "."+r.mDom)
	}
	return h == r.mDom // exact
}

// matchKeyword applies the keyword criterion: case-insensitive
// substring on the raw host string (names AND IP literals).
func matchKeyword(r *Rule, host string) bool {
	return strings.Contains(strings.ToLower(host), r.mKW)
}

// matchCIDR applies the IP-CIDR criterion, literal-IP hosts only.
// IPv4 and IPv6 CIDRs both work; an IPv4 literal is checked against
// IPv4 CIDRs (and vice versa) via net.IPNet.Contains.
func matchCIDR(r *Rule, host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return r.mCIDR.Contains(ip)
}

// Evaluate runs the rule set against one destination and returns the
// selected outbound plus the id of the rule that decided it ("" when
// the default outbound applied).
//
// Decision order:
//  1. first ENABLED rule whose criteria match → that rule's Action
//     (block → OutboundBlock; warp → OutboundWarp; direct →
//     OutboundDirect).
//  2. no rule matched → the default outbound (never block; "direct"
//     when unset).
//
// The WARP health gate (reachability + fallback) is NOT applied here:
// it is applied at DIAL time by the engine, because WARP state can
// change between rule evaluation and the actual connect.
func (rs *RuleSet) Evaluate(dst *Destination) (OutboundKind, string) {
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if matchRule(r, dst) {
			kind, _ := ParseOutboundKind(r.Action) // validated in Sanitize
			return kind, r.ID
		}
	}
	kind, _ := ParseOutboundKind(rs.DefaultAction)
	return kind, ""
}

// HasRules reports whether the set carries at least one rule.
func (rs *RuleSet) HasRules() bool { return len(rs.Rules) > 0 }

// RuleCount reports the total rule count (enabled or not).
func (rs *RuleSet) RuleCount() int { return len(rs.Rules) }

// ---------------------------------------------------------------------------
// Address helpers (shared with the outbound dials)
// ---------------------------------------------------------------------------

// SplitHostPort splits the addr string ("host:port" as produced by
// net.JoinHostPort at the dial call site) into (host, port, ok). It
// accepts IPv6 literals in bracket syntax.
func SplitHostPort(addr string) (host string, port int, ok bool) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, false
	}
	port, err = strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return h, port, true
}
