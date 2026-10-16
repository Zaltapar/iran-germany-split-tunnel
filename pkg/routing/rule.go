// Package routing implements the Germany outbound routing engine
// (plans/dashboard-control-design.md §22 "Routing engine").
//
// The engine evaluates a destination (host + port, as dialed by the
// Germany splitter's TargetDial path) against an ordered rule set and
// selects an outbound: direct (the node's policy-aware default dial),
// warp (a SOCKS5h CONNECT through the local WARP proxy), or block
// (a clean stream refusal).
//
// It is a pure package: no internal/* dependencies (enforced by
// internal/archtest), no I/O beyond the operator's rules file, no
// wire-protocol changes. When routing is OFF (SPLIT_ROUTING_RULES_FILE
// unset — the default), the engine is never constructed and the dial
// path is byte-identical to the pre-routing build.
//
// Rule model (3x-ui / Sanaei-style):
//
//   - An ordered list of rules; the FIRST enabled rule whose match
//     criteria are satisfied wins.
//   - Each rule has: id (unique, required), an enabled flag (default
//     true when the JSON key is absent), a match block (domain
//     exact/suffix, keyword, IP CIDR, optional port range; regex-free
//     by design), an action (direct | warp | block), an optional
//     fallback ("direct", warp rules only), and an optional comment.
//   - When no rule matches, the default outbound is used: "direct" or
//     "warp" (never "block" — a block default would lock out the
//     tunnel for every unmatched destination and is refused at
//     validation time).
//   - A catch-all block rule (action=block with NO match criteria) is
//     likewise refused: it would block every logical stream.
//
// Matching semantics (see matcher.go):
//
//   - Domain: ".example.com" (suffix form) matches "example.com" and
//     every subdomain; "example.com" (exact form) matches only that
//     host. Case-insensitive. Not consulted for literal-IP hosts.
//   - Keyword: case-insensitive substring on the destination host
//     string (domain names AND IP literals).
//   - IP CIDR: matched against literal-IP hosts only. Domain hosts are
//     NOT resolved at match time (the dial performs resolution), so a
//     rule with only ip_cidr never matches a domain destination.
//   - Port range: optional inclusive [port_min, port_max] pre-
//     condition; a rule whose range excludes the destination port
//     never matches, regardless of its other criteria.
//   - Criteria within one rule are OR-ed; the port range ANDs with
//     them.
//
// WARP health gate (see engine.go):
//
//   - action=warp + fallback="direct": when the WARP SOCKS endpoint is
//     UNREACHABLE (connect/handshake failure), the stream falls back
//     to the direct dial. When WARP is reachable but refuses the
//     CONNECT (SOCKS REP 4-7), there is NO fallback — the target
//     failed inside WARP and silently leaking it onto the direct path
//     is exactly what the gate prevents.
//   - action=warp + no fallback (the default): fail-closed — the
//     stream is refused with a clear reason when WARP is unreachable.
//   - The default outbound, when "warp", is fail-closed (no fallback
//     is ever carried by the default).
//
// Logging: destinations and rule decisions are logged ONLY when the
// debug flag (SPLIT_ROUTING_DEBUG) is on; at the default level the
// engine logs nothing. The engine holds no credentials and never logs
// any.
package routing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// ---------------------------------------------------------------------------
// Constants and outbound kinds
// ---------------------------------------------------------------------------

// MaxRules is the maximum number of rules in a single rule set.
const MaxRules = 500

// MaxConfigBytes is the maximum size (bytes) of the rules file/document.
const MaxConfigBytes = 64 << 10 // 64 KiB

// OutboundKind identifies which outbound a destination is routed to.
type OutboundKind int

const (
	// OutboundDirect uses the node's existing target dial path
	// (the policy-aware default dial, i.e. the pre-routing behavior).
	OutboundDirect OutboundKind = iota
	// OutboundWarp routes through the WARP SOCKS5 proxy (SOCKS5h).
	OutboundWarp
	// OutboundBlock refuses the stream cleanly.
	OutboundBlock
)

// String returns the operator-facing name for the outbound kind.
func (k OutboundKind) String() string {
	switch k {
	case OutboundDirect:
		return "direct"
	case OutboundWarp:
		return "warp"
	case OutboundBlock:
		return "block"
	default:
		return fmt.Sprintf("unknown(%d)", int(k))
	}
}

// ParseOutboundKind converts a JSON action string to OutboundKind.
// It returns an error for unknown values (no silent fallback).
func ParseOutboundKind(s string) (OutboundKind, error) {
	switch s {
	case "direct":
		return OutboundDirect, nil
	case "warp":
		return OutboundWarp, nil
	case "block":
		return OutboundBlock, nil
	}
	return 0, fmt.Errorf("unknown action %q (allowed: direct|warp|block)", s)
}

// ErrBlocked is the sentinel error returned when a rule blocks a
// stream. The stream is refused cleanly (the client sees a
// connection-not-allowed style SOCKS refusal).
var ErrBlocked = fmt.Errorf("routing: destination blocked by rule")

// ErrWarpUnreachable is returned when the WARP SOCKS5 endpoint cannot
// be reached (TCP connect failure, handshake failure, or protocol
// exchange failure — the endpoint is effectively down or
// misconfigured). The caller decides the fail-closed vs
// fallback-direct behavior from the rule's Fallback field.
//
// A SOCKS CONNECT that the endpoint ACCEPTS but then fails on the
// target (REP 4-7) is NOT wrapped with this sentinel: the endpoint is
// reachable, the target failed inside WARP, and no fallback applies.
var ErrWarpUnreachable = fmt.Errorf("warp socks endpoint unreachable")

// ---------------------------------------------------------------------------
// Match — one rule's match criteria
// ---------------------------------------------------------------------------

// Match holds the match criteria for one routing rule. The domain,
// keyword and IP-CIDR fields are OR-ed together: a rule matches when
// ANY of its set fields matches the destination. The port range is a
// pre-condition (AND): when set, the destination port must fall
// within it for any other field to be consulted.
//
// All criteria are regex-free (by design, §22): domain patterns are
// exact or suffix forms, the keyword is a plain case-insensitive
// substring, and the CIDR is a standard net.ParseCIDR block.
type Match struct {
	// Domain is a domain pattern for domain destinations.
	//   - Suffix form (leading "."): ".example.com" matches
	//     "example.com" and all subdomains ("sub.example.com", ...).
	//   - Exact form: "example.com" matches only "example.com".
	// Not consulted when the destination is a literal IP address.
	// Must be lowercase RFC 1123 (no wildcards); validated in
	// Sanitize.
	Domain string `json:"domain,omitempty"`

	// Keyword is a case-insensitive substring matched against the
	// destination host string (both domain names and IP literals).
	Keyword string `json:"keyword,omitempty"`

	// IPCIDR is a CIDR block ("10.0.0.0/8", "203.0.113.5/32",
	// "fe80::/10") matched against the destination when it is a
	// literal IP address. Not consulted for domain destinations
	// (no resolved IP is available at match time; the dial itself
	// performs resolution).
	IPCIDR string `json:"ip_cidr,omitempty"`

	// PortMin / PortMax define an optional inclusive port-range
	// filter. Both 0 means "no port filter". When either is set, the
	// range is [lo, hi] where lo = PortMin (0 means 1) and hi =
	// PortMax (0 means 65535).
	PortMin int `json:"port_min,omitempty"`
	PortMax int `json:"port_max,omitempty"`
}

// ---------------------------------------------------------------------------
// Rule — one routing rule
// ---------------------------------------------------------------------------

// Rule is one entry in the ordered routing rule set.
type Rule struct {
	// ID is the rule's unique identifier (required, non-empty,
	// unique within the set).
	ID string `json:"id"`

	// Enabled controls whether the rule participates in matching.
	// When the JSON key is absent the rule is ENABLED (default true);
	// only an explicit "enabled": false disables it.
	Enabled bool `json:"enabled"`

	// Match holds the match criteria. At least one of Domain,
	// Keyword or IPCIDR must be set: a rule with no criteria is a
	// catch-all, and a catch-all block would lock out the tunnel
	// (the non-block catch-all would shadow every rule after it,
	// which is almost never intended).
	Match Match `json:"match"`

	// Action is the outbound for matched traffic: "direct", "warp",
	// or "block". Required.
	Action string `json:"action"`

	// Fallback is only meaningful when Action is "warp":
	//   - "direct": when the WARP SOCKS5 endpoint is UNREACHABLE,
	//     fall back to the direct dial path.
	//   - "" (the default): fail-closed — the stream is refused when
	//     WARP is unreachable. Traffic does NOT silently leak
	//     outside WARP.
	// Ignored for actions other than "warp" (a non-empty Fallback on
	// a non-warp rule is a validation error).
	Fallback string `json:"fallback,omitempty"`

	// Comment is an optional operator note. It is never matched, and
	// is never logged (at any level).
	Comment string `json:"comment,omitempty"`

	// Precomputed match state, filled by Sanitize (not serialized):
	// the parsed CIDR, the lowercased keyword, and the lowercased
	// domain core + suffix flag.
	mCIDR      *net.IPNet
	mKW        string
	mDom       string
	mDomSuffix bool
}

// UnmarshalJSON decodes one rule strictly (unknown fields — including
// any secret-bearing field a rules document must never carry — are
// rejected) and applies the enabled-default-true convention: a
// missing "enabled" key means the rule is enabled.
func (r *Rule) UnmarshalJSON(data []byte) error {
	aux := struct {
		ID       string `json:"id"`
		Enabled  *bool  `json:"enabled"`
		Match    Match  `json:"match"`
		Action   string `json:"action"`
		Fallback string `json:"fallback,omitempty"`
		Comment  string `json:"comment,omitempty"`
	}{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&aux); err != nil {
		return err
	}
	r.ID = aux.ID
	// Absent "enabled" → enabled (the operator default); explicit
	// false → disabled.
	r.Enabled = aux.Enabled == nil || *aux.Enabled
	r.Match = aux.Match
	r.Action = aux.Action
	r.Fallback = aux.Fallback
	r.Comment = aux.Comment
	return nil
}

// ---------------------------------------------------------------------------
// RuleSet — the full routing configuration
// ---------------------------------------------------------------------------

// RuleSet is the complete routing configuration: an ordered list of
// rules and a default outbound for when no rule matches.
type RuleSet struct {
	// Version is the schema version (1 = current).
	Version int `json:"version"`

	// DefaultAction is the outbound used when no rule matches.
	// Must be "direct" or "warp" (never "block"). Empty after decode
	// is lifted to "direct" by Sanitize.
	DefaultAction string `json:"default_action"`

	// Rules is the ordered rule list. First match wins.
	Rules []Rule `json:"rules"`
}

// Sanitize fills defaults on a freshly-parsed RuleSet and validates
// the whole set. It is called after JSON decoding, before the rule
// set is used.
func (rs *RuleSet) Sanitize() error {
	if rs.Version != 1 {
		return fmt.Errorf("routing: unsupported rules file version %d (want 1)", rs.Version)
	}
	if rs.DefaultAction == "" {
		rs.DefaultAction = "direct"
	}
	if _, err := ParseOutboundKind(rs.DefaultAction); err != nil {
		return fmt.Errorf("routing: default_action: %v", err)
	}
	// A block default would lock out the tunnel for every unmatched
	// destination: refuse it.
	if rs.DefaultAction == "block" {
		return fmt.Errorf("routing: default_action %q is not allowed (a block default would lock out the tunnel for all unmatched destinations; use specific block rules instead)", rs.DefaultAction)
	}
	if len(rs.Rules) > MaxRules {
		return fmt.Errorf("routing: too many rules: %d (max %d)", len(rs.Rules), MaxRules)
	}

	seen := make(map[string]bool, len(rs.Rules))
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("routing: rules[%d]: id is required", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("routing: rules[%d]: duplicate rule id %q", i, r.ID)
		}
		seen[r.ID] = true
		if err := rs.validateRule(r, i); err != nil {
			return err
		}
	}
	return nil
}

// validateRule checks one rule's fields and fills its precomputed
// match state.
func (rs *RuleSet) validateRule(r *Rule, idx int) error {
	prefix := fmt.Sprintf("routing: rules[%d] (%q)", idx, r.ID)

	// Action must be set and valid (unknown actions are rejected, no
	// silent fallback).
	if r.Action == "" {
		return fmt.Errorf("%s: action is required (direct|warp|block)", prefix)
	}
	if _, err := ParseOutboundKind(r.Action); err != nil {
		return fmt.Errorf("%s: %v", prefix, err)
	}

	// Fallback is only valid for warp rules and must be "direct" or "".
	if r.Fallback != "" && r.Fallback != "direct" {
		return fmt.Errorf("%s: fallback must be \"direct\" or empty (got %q)", prefix, r.Fallback)
	}
	if r.Fallback != "" && r.Action != "warp" {
		return fmt.Errorf("%s: fallback is only meaningful for action=warp (action=%q)", prefix, r.Action)
	}

	// At least one match criterion is required for EVERY rule: a
	// catch-all (empty match) would either shadow every later rule
	// (direct/warp) or lock out the tunnel entirely (block). Both are
	// refused — operators enumerate specific destinations.
	hasMatch := r.Match.Domain != "" || r.Match.Keyword != "" || r.Match.IPCIDR != ""
	if !hasMatch {
		return fmt.Errorf("%s: at least one match criterion (domain, keyword, or ip_cidr) is required; a catch-all rule would %s",
			prefix, blockOrShadow(r.Action))
	}

	// Domain validation (lowercase RFC 1123 labels, no wildcards; the
	// only allowed prefix form is the suffix dot).
	if r.Match.Domain != "" {
		if err := validateDomain(r.Match.Domain); err != nil {
			return fmt.Errorf("%s: domain: %v", prefix, err)
		}
		dom := strings.ToLower(r.Match.Domain)
		if strings.HasPrefix(dom, ".") {
			r.mDom = dom[1:]
			r.mDomSuffix = true
		} else {
			r.mDom = dom
		}
	}
	r.mKW = strings.ToLower(r.Match.Keyword)

	// CIDR validation (both families; stored pre-parsed).
	if r.Match.IPCIDR != "" {
		_, cidr, err := net.ParseCIDR(r.Match.IPCIDR)
		if err != nil {
			return fmt.Errorf("%s: ip_cidr %q: %v", prefix, r.Match.IPCIDR, err)
		}
		r.mCIDR = cidr
	}

	// Port range validation.
	if r.Match.PortMin < 0 || r.Match.PortMin > 65535 {
		return fmt.Errorf("%s: port_min %d out of range 0..65535", prefix, r.Match.PortMin)
	}
	if r.Match.PortMax < 0 || r.Match.PortMax > 65535 {
		return fmt.Errorf("%s: port_max %d out of range 0..65535", prefix, r.Match.PortMax)
	}
	if r.Match.PortMin > 0 && r.Match.PortMax > 0 && r.Match.PortMin > r.Match.PortMax {
		return fmt.Errorf("%s: port_min %d exceeds port_max %d", prefix, r.Match.PortMin, r.Match.PortMax)
	}

	return nil
}

// blockOrShadow renders the tail of the catch-all error per action.
func blockOrShadow(action string) string {
	if action == "block" {
		return "lock out the tunnel for every destination (refused)"
	}
	return "shadow every rule that follows it (refused; enumerate specific destinations)"
}

// validateDomain checks that a domain pattern is a valid lowercase RFC
// 1123 hostname: labels of 1-63 alphanumeric/hyphen characters with no
// leading/trailing hyphen, total length <= 253, no wildcards, and the
// only special form is a leading "." (the suffix-matching form, whose
// core is validated the same way).
func validateDomain(d string) error {
	core := d
	if strings.HasPrefix(core, ".") {
		core = core[1:]
	}
	if core == "" {
		return fmt.Errorf("empty domain")
	}
	if len(core) > 253 {
		return fmt.Errorf("domain too long (%d chars, max 253)", len(core))
	}
	for _, label := range strings.Split(core, ".") {
		if label == "" {
			return fmt.Errorf("empty label in %q", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("label too long (>63 chars) in %q", d)
		}
		if strings.Contains(label, "*") {
			return fmt.Errorf("wildcards are not allowed in domain patterns")
		}
		for i, c := range label {
			switch {
			case c == '-':
				if i == 0 || i == len(label)-1 {
					return fmt.Errorf("label %q has a leading or trailing hyphen", label)
				}
			case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
				// valid
			default:
				return fmt.Errorf("label %q contains invalid character %q (lowercase alphanumerics and hyphens only; use lowercase)", label, c)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// JSON loading
// ---------------------------------------------------------------------------

// LoadRulesFile reads and validates a rules JSON file from disk. The
// file must be at most MaxConfigBytes and conform to the v1 schema;
// unknown fields at any level (including secret-bearing fields a
// rules document must never carry) are rejected.
func LoadRulesFile(path string) (*RuleSet, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("routing: cannot read rules file %q: %w", path, err)
	}
	if info.Size() > MaxConfigBytes {
		return nil, fmt.Errorf("routing: rules file %q is %d bytes (max %d)", path, info.Size(), MaxConfigBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("routing: reading %q: %w", path, err)
	}
	return ParseRules(data)
}

// ParseRules decodes and validates a rules JSON document. The decode
// is strict at the top level AND inside every rule (Rule's custom
// unmarshaler and the Match struct are both strict), so public fields
// only: anything unknown — including any credential-named field — is
// a hard error.
func ParseRules(data []byte) (*RuleSet, error) {
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("routing: rules document is %d bytes (max %d)", len(data), MaxConfigBytes)
	}
	var rs RuleSet
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("routing: JSON decode: %w", err)
	}
	if err := rs.Sanitize(); err != nil {
		return nil, err
	}
	return &rs, nil
}
