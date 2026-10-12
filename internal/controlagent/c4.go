// c4.go — Phase C4: the routing plane and the multi-carrier control
// concept (plans/dashboard-control-design.md §4.4, §4.6, §12 C4).
//
// C4 routing plane — what genuinely exists and is safe to edit at runtime:
//
//   - SPLIT_TARGET_ADDR_POLICY (both roles): the egress-target address-
//     family policy enum default|prefer-ipv4|ipv4-only, validated in
//     internal/config (config.Validate) and consumed by pkg/node on every
//     dial. A typo'd value is a config error, never a silent fallback.
//   - SPLIT_SOCKS_ALLOWED_SOURCES (Iran role): the opt-in SOCKS5
//     source-IP allowlist. Empty = allow all (backward-compatible
//     default); when non-empty every entry must parse as an IPv4/IPv6
//     address or CIDR (config.ParseAllowedSources), so a typo'd
//     allowlist fails fast instead of silently allowing everyone.
//
// Deliberately NOT exposed by the C4 routing concept (documented in the
// C4 completion note): xray routing-rule / RoutingPolicy editing (the
// dashboard's routing concepts are display-only; no live routing engine
// consumes them — design F-8/D9; the xray configs carry the
// renderer-owned single inbound→outbound rule), the legacy
// SPLIT_TARGET_ONLY_IPV4 flag (superseded by the policy enum; its
// contradiction with prefer-ipv4 is still cross-checked against the
// base env), and every secret-named key (F-6: SPLIT_SECRET, the SOCKS
// RFC 1929 credential pair).
//
// The C4 apply engine reuses the C2 transaction discipline exactly
// (lock → journal → pre-snapshot → render → validate → [xray gate] →
// backup → atomic swap → restart → verify → commit → auto-rollback),
// with fault-injectable steps so the state machine is drivable to
// failure at every point and asserted to land where design §5.6 says.
package controlagent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
)

// ---------------------------------------------------------------------------
// Error codes (C4-specific; extend the closed C2/C3 set)
// ---------------------------------------------------------------------------

// ErrCodeXrayGateNotConfigured is returned when a change alters the
// rendered xray config (the C4 xray gate applies) but no XrayGate is
// wired on the agent: the gate is fail-closed, never skipped, so an
// xray-affecting change cannot be applied half-way (the xray binary
// would run the old config while the splitter env expects the new one).
const ErrCodeXrayGateNotConfigured = "xray_gate_not_configured"

// ---------------------------------------------------------------------------
// C4 editable concepts (env-key closed sets, the agent's own allowlists)
// ---------------------------------------------------------------------------

// c4RoutingFields is the C4 routing-plane editable concept. Two keys,
// both env-driven and validated in internal/config; both are read by
// the splitter process at start, so every routing change restarts the
// affected splitter service (the conservative, honest classification).
var c4RoutingFields = map[string]bool{
	config.EnvTargetAddrPolicy:    true, // SPLIT_TARGET_ADDR_POLICY (both roles)
	config.EnvSocksAllowedSources: true, // SPLIT_SOCKS_ALLOWED_SOURCES (Iran role)
}

// c4SecretBlocklist is the closed set of secret-named env keys that NO C4
// concept may ever edit or echo (F-6: SPLIT_SECRET, the SOCKS RFC 1929
// credential pair). The name-fragment denylist below deliberately DROPS
// the C2 "socks" fragment: SPLIT_SOCKS_ALLOWED_SOURCES is operator
// configuration (a source-IP allowlist — internal/config documents "the
// allowlist entries are operator configuration, not secret material"),
// not a credential; the credential pair is blocked by exact name here.
var c4SecretBlocklist = map[string]bool{
	config.EnvSecret:    true, // SPLIT_SECRET
	config.EnvSocksUser: true, // SPLIT_SOCKS_USER
	config.EnvSocksPass: true, // SPLIT_SOCKS_PASS
}

// c4SecretDenylist is the name-fragment denylist for C4 keys. It is the
// C2 set minus "socks" (see c4SecretBlocklist). No C4 editable key may
// contain any fragment; the editable allowlists are the second gate.
var c4SecretDenylist = []string{
	"secret", "key", "token", "password", "basepath", "credential", "private",
}

// c4KeyIsSecret reports whether an env key name is secret-named under the
// C4 rules (exact-name blocklist OR name-fragment denylist).
func c4KeyIsSecret(name string) bool {
	if c4SecretBlocklist[name] {
		return true
	}
	ln := strings.ToLower(name)
	for _, sub := range c4SecretDenylist {
		if strings.Contains(ln, sub) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The C4 xray gate seam
// ---------------------------------------------------------------------------

// XrayGate is the host-facing executor for the C4 xray -test gate (the
// "xray only when the SNI/listener changes" half of requirement 4: a C4
// change that alters the rendered xray config additionally renders the
// candidate xray config, runs the `xray run -test` equivalent on it, and
// restarts/verifies the affected xray unit — the C3 inbound surface's
// discipline, re-used, not re-implemented). Nil (the default) keeps C4
// apply fail-closed for any xray-affecting change; pure env changes
// (routing, policy knobs) never consult the gate.
//
// No method may return, log, or print key material.
type XrayGate interface {
	// RenderXrayForMC renders (or resolves) the role's candidate xray
	// config for the multi-carrier form and returns a sandbox path to
	// test. The gate may re-test the live-rendered config when the
	// candidate is the live form (the second inbound is peer-staged via
	// Blob B until the Iran agent lands).
	RenderXrayForMC(role string, env map[string]string) (string, error)
	// ConfigTest runs the `xray run -test` equivalent on the candidate.
	// A failure here means NO xray-affecting swap/restart may proceed.
	ConfigTest(role, candidatePath string) error
	// RestartXray restarts ONLY the affected xray unit.
	RestartXray(role string) error
	// VerifyXray confirms the xray unit is active and its listeners up.
	VerifyXray(role string) error
}

// ---------------------------------------------------------------------------
// C4 op payloads + concepts
// ---------------------------------------------------------------------------

// C4ApplyOp is one C4 apply request as decoded from the frame (the
// CandidateChange shape: role + candidate env set + optimistic base).
type C4ApplyOp struct {
	Change         CandidateChange
	IdempotencyKey string
	Actor          string
}

// c4Concept is one C4 editable concept: its closed key allowlist, its
// authoritative validator, and its xray-affected classifier (nil = the
// concept never alters the rendered xray config).
type c4Concept struct {
	name     string
	allowed  map[string]bool
	validate func(role string, set, base map[string]string) []string
	// xrayAffected reports whether the candidate env would change the
	// rendered xray config (SNI / second listener / multi-carrier flip).
	// nil = never xray-affecting (the routing plane).
	xrayAffected func(base, set map[string]string) bool
}

// ---------------------------------------------------------------------------
// Routing plane validators (the C4 routing concept)
// ---------------------------------------------------------------------------

// routingKeyRole restricts one key to a role: SPLIT_SOCKS_ALLOWED_SOURCES
// configures the Iran SOCKS5 listener only; the target-address policy is
// wired on BOTH roles (config-layer symmetry, the planner's Roles
// list). Setting the wrong role's key is a validation error, not a
// silent no-op.
func routingKeyRole(key, role string) error {
	switch key {
	case config.EnvSocksAllowedSources:
		if role != config.RoleIran {
			return fmt.Errorf("set.%s: this key configures the Iran SOCKS5 listener and is not accepted for role %q", key, role)
		}
	}
	return nil
}

// routingValueError checks one routing field value against the
// config-layer rules (the same ranges/enum the splitter validates at
// process start; the agent re-derives them so it is authoritative).
func routingValueError(key, value string) error {
	switch key {
	case config.EnvTargetAddrPolicy:
		switch value {
		case "default", "prefer-ipv4", "ipv4-only":
			return nil
		}
		return fmt.Errorf("set.%s: must be one of default|prefer-ipv4|ipv4-only (got %q)", key, value)
	case config.EnvSocksAllowedSources:
		// Empty = the documented "allow all" sentinel; a non-empty value
		// must parse entry-by-entry (config.ParseAllowedSources is the
		// single source of truth the splitter itself uses).
		if strings.TrimSpace(value) == "" {
			return nil
		}
		if _, err := config.ParseAllowedSources(value); err != nil {
			return fmt.Errorf("set.%s: %v", key, err)
		}
		return nil
	}
	return nil
}

// ValidateRoutingChange runs the authoritative C4 routing-plane gates
// over one candidate: (1) role known, (2) non-empty set, (3) every key
// in the closed allowlist, role-restricted where applicable, (4) no
// secret-named key, (5) per-value bounds/enum/parse, (6) the documented
// SPLIT_TARGET_ONLY_IPV4=true + SPLIT_TARGET_ADDR_POLICY=prefer-ipv4
// contradiction against the candidate (base folded in). Empty result =
// valid. No I/O.
func ValidateRoutingChange(role string, set, base map[string]string) []string {
	var errs []string

	if role != config.RoleIran && role != config.RoleGermany {
		errs = append(errs, fmt.Sprintf("role: must be %q or %q", config.RoleIran, config.RoleGermany))
		return errs
	}
	if len(set) == 0 {
		errs = append(errs, "set: at least one key is required")
		return errs
	}
	for k, v := range set {
		if c4KeyIsSecret(k) {
			errs = append(errs, fmt.Sprintf("set.%s: secret-named key, never editable via the dashboard", k))
			continue
		}
		if !c4RoutingFields[k] {
			errs = append(errs, fmt.Sprintf("set.%s: not in the C4 routing concept", k))
			continue
		}
		if err := routingKeyRole(k, role); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if err := routingValueError(k, v); err != nil {
			errs = append(errs, err.Error())
		}
	}
	// Cross-field: the hard filter (SPLIT_TARGET_ONLY_IPV4, read from the
	// base env — it is NOT C4-editable, superseded by the policy enum)
	// contradicts the soft preference; the same rule config.Validate
	// enforces, mirrored here so the gate is authoritative without a
	// full-config fold.
	onlyV4 := base[config.EnvTargetOnlyIPv4]
	if _, ok := set[config.EnvTargetOnlyIPv4]; ok {
		onlyV4 = set[config.EnvTargetOnlyIPv4]
	}
	policy := base[config.EnvTargetAddrPolicy]
	if v, ok := set[config.EnvTargetAddrPolicy]; ok {
		policy = v
	}
	if onlyV4 == "true" && policy == "prefer-ipv4" {
		errs = append(errs, fmt.Sprintf(
			"set.%s=%q contradicts %s=true (base): the hard IPv4-only filter refuses AAAA-only domains while prefer-ipv4 falls back to IPv6; use %s=ipv4-only or %s=false",
			config.EnvTargetAddrPolicy, "prefer-ipv4", config.EnvTargetOnlyIPv4, config.EnvTargetAddrPolicy, config.EnvTargetOnlyIPv4))
	}
	return errs
}

// c4RoutingConcept is the routing-plane concept value (the shared apply
// engine's routing instance).
func c4RoutingConcept() *c4Concept {
	return &c4Concept{
		name:    "routing",
		allowed: c4RoutingFields,
		validate: func(role string, set, base map[string]string) []string {
			return ValidateRoutingChange(role, set, base)
		},
		// Routing knobs are pure splitter env: the rendered xray config
		// is byte-identical, so the xray gate never applies.
		xrayAffected: nil,
	}
}

// ---------------------------------------------------------------------------
// C4 diff (redacted where the audit sink would refuse: the C2 audit sink
// treats "socks" as a secret-name fragment, so SPLIT_SOCKS_ALLOWED_SOURCES
// values are fingerprinted in diffs. SNI / target-addr-policy values are
// operator config, not secret, and are logged in full (requirement 7).)
// ---------------------------------------------------------------------------

// BuildC4Diff produces the before/after diff for one C4 candidate set
// against the current base env, restricted to the concept's allowed
// keys. Secret-named keys never reach the diff (the allowlists exclude
// them); socks-* values are fingerprinted so the C2 audit sink (which
// treats "socks" as secret-named) accepts the record; absent base
// values render as "(not set)".
func BuildC4Diff(base, override map[string]string, allowed map[string]bool) []DiffEntry {
	var out []DiffEntry
	keys := make([]string, 0, len(override))
	for k := range override {
		if allowed[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		after := override[k]
		before := base[k]
		if before == "" {
			before = "(not set)"
		}
		if after == "" {
			after = "(not set)"
		}
		redact := strings.Contains(strings.ToLower(k), "socks")
		if redact {
			if v := base[k]; v != "" {
				before = fingerprint(v)
			}
			if v := override[k]; v != "" {
				after = fingerprint(v)
			}
		}
		out = append(out, DiffEntry{Key: k, Before: before, After: after, Redacted: redact})
	}
	return out
}

// ---------------------------------------------------------------------------
// Multi-carrier concept + validators
// ---------------------------------------------------------------------------

// c4MCFields is the C4 multi-carrier control concept's closed key set:
// the master toggle, the second carrier's listen/dial addresses and SNI,
// and the Phase 3 policy knobs (mode, topk, probing enable/url/budget,
// TTFB baseline). All are validated by internal/config; the admission
// floor / hysteresis margin / dwell / cooldown are code constants in
// pkg/node (design F-11) and are deliberately NOT exposed (they are C5
// code changes, not env keys).
var c4MCFields = map[string]bool{
	config.EnvMultiCarrierEnabled: true,
	config.EnvDownListen2:         true, // Germany
	config.EnvDownCarrierAddr2:    true, // Iran
	config.EnvDownSNI2:            true, // Germany
	config.EnvPolicyMode:          true,
	config.EnvPolicyTopK:          true,
	config.EnvProbingEnabled:      true,
	config.EnvProbeURL:            true,
	config.EnvProbeDailyBudget:    true,
	config.EnvTTFBBaselineMs:      true,
}

// mcKeyRole restricts the second-carrier addresses to their role: the
// second down LISTENER + its SNI belong to Germany; the second down
// DIAL target belongs to Iran. The master toggle and policy/probing
// knobs are wired on both roles.
func mcKeyRole(key, role string) error {
	switch key {
	case config.EnvDownListen2, config.EnvDownSNI2:
		if role != config.RoleGermany {
			return fmt.Errorf("set.%s: the second down LISTENER + SNI are Germany-side; not accepted for role %q", key, role)
		}
	case config.EnvDownCarrierAddr2:
		if role != config.RoleIran {
			return fmt.Errorf("set.%s: the second down DIAL target is Iran-side; not accepted for role %q", key, role)
		}
	}
	return nil
}

// mcValueError checks one multi-carrier field value against the
// config-layer bounds (the same ranges internal/config enforces).
func mcValueError(key, value string) error {
	switch key {
	case config.EnvMultiCarrierEnabled:
		if _, err := strconv.ParseBool(value); err != nil {
			return fmt.Errorf("set.%s: must be a boolean (true/false, 1/0)", key)
		}
	case config.EnvDownListen2:
		if value != "" {
			if err := mcHostPortError(key, value, true, config.ReservedPort); err != nil {
				return err
			}
		}
	case config.EnvDownCarrierAddr2:
		if value != "" {
			if err := mcHostPortError(key, value, true, 0); err != nil {
				return err
			}
		}
	case config.EnvDownSNI2:
		if value != "" && !pairing.ValidSNI(value) {
			return fmt.Errorf("set.%s: must be a lowercase RFC 1123 hostname (no IP literal, no port)", key)
		}
	case config.EnvPolicyMode:
		if value != config.PolicyStaticMode && value != config.PolicyAdaptiveMode {
			return fmt.Errorf("set.%s: must be %q or %q", key, config.PolicyStaticMode, config.PolicyAdaptiveMode)
		}
	case config.EnvPolicyTopK:
		n, err := strconv.Atoi(value)
		if err != nil || n < config.MinPolicyTopK || n > config.MaxPolicyTopK {
			return fmt.Errorf("set.%s: must be an integer %d..%d", key, config.MinPolicyTopK, config.MaxPolicyTopK)
		}
	case config.EnvProbingEnabled:
		if _, err := strconv.ParseBool(value); err != nil {
			return fmt.Errorf("set.%s: must be a boolean (true/false, 1/0)", key)
		}
	case config.EnvProbeURL:
		if value != "" {
			if err := mcProbeURL(value); err != nil {
				return err
			}
		}
	case config.EnvProbeDailyBudget:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("set.%s: must be a non-negative byte count", key)
		}
	case config.EnvTTFBBaselineMs:
		n, err := strconv.Atoi(value)
		if err != nil || n < config.MinTTFBBaselineMs || n > config.MaxTTFBBaselineMs {
			return fmt.Errorf("set.%s: must be in range %d..%d", key, config.MinTTFBBaselineMs, config.MaxTTFBBaselineMs)
		}
	}
	return nil
}

// mcHostPortError validates one host:port value (host required when
// requireHost; reservedPort, when non-zero, is refused — 8443 is the
// dashboard's).
func mcHostPortError(key, value string, requireHost bool, reservedPort int) error {
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("set.%s: must be a host:port address (e.g. 127.0.0.1:9003)", key)
	}
	if requireHost && host == "" {
		return fmt.Errorf("set.%s: requires an explicit host (e.g. 127.0.0.1:9003)", key)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < config.MinPort || p > config.MaxPort {
		return fmt.Errorf("set.%s: expected a port between %d and %d", key, config.MinPort, config.MaxPort)
	}
	if reservedPort != 0 && p == reservedPort {
		return fmt.Errorf("set.%s: port %d is reserved for the dashboard TLS listener", key, reservedPort)
	}
	return nil
}

// mcProbeURL validates the operator-owned probe target (http/https with
// a host; no third-party default — the config layer's rule).
func mcProbeURL(value string) error {
	if value == "" {
		return nil
	}
	scheme, host, ok := parseProbeURL(value)
	if !ok || (scheme != "http" && scheme != "https") || host == "" {
		return fmt.Errorf("set.%s: expected an operator-configured http(s) URL with a host", config.EnvProbeURL)
	}
	return nil
}

// parseProbeURL splits a probe URL into (scheme, host, ok) without the
// full url import (the config layer is the authority; this is a gate
// pre-check that keeps the error stable).
func parseProbeURL(raw string) (scheme, host string, ok bool) {
	rest := raw
	for i, c := range raw {
		if c == ':' {
			scheme = strings.ToLower(raw[:i])
			rest = raw[i+1:]
			break
		}
	}
	if !strings.HasPrefix(rest, "//") {
		return scheme, "", false
	}
	rest = rest[2:]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return scheme, rest, true
}

// mcMerge folds the candidate set over the base into a complete
// candidate env (the config layer's view of the post-change state).
func mcMerge(base, set map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(set))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range set {
		merged[k] = v
	}
	return merged
}

// ValidateMCChange runs the authoritative C4 multi-carrier gates over
// one candidate: (1) role known, (2) non-empty set, (3) every key in the
// closed allowlist, role-restricted, (4) no secret-named key, (5)
// per-value bounds/enum/parse, (6) cross-field: when multi-carrier is
// enabled the second carrier's address + SNI (Germany) or dial target
// (Iran) are REQUIRED (enabling with no usable carrier or a missing SNI
// is refused), conflicting/repeated addresses are refused, and probing
// enabled without a probe URL is refused. Disabling multi-carrier is
// always allowed (returns to the single-carrier form, byte-identical).
// Empty result = valid. No I/O.
func ValidateMCChange(role string, set, base map[string]string) []string {
	var errs []string

	if role != config.RoleIran && role != config.RoleGermany {
		errs = append(errs, fmt.Sprintf("role: must be %q or %q", config.RoleIran, config.RoleGermany))
		return errs
	}
	if len(set) == 0 {
		errs = append(errs, "set: at least one key is required")
		return errs
	}
	for k, v := range set {
		if c4KeyIsSecret(k) {
			errs = append(errs, fmt.Sprintf("set.%s: secret-named key, never editable via the dashboard", k))
			continue
		}
		if !c4MCFields[k] {
			errs = append(errs, fmt.Sprintf("set.%s: not in the C4 multi-carrier concept", k))
			continue
		}
		if err := mcKeyRole(k, role); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if err := mcValueError(k, v); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Cross-field over the merged candidate.
	m := mcMerge(base, set)
	enabled := m[config.EnvMultiCarrierEnabled] == "true"

	// (6a) Enabling multi-carrier requires a usable second carrier + SNI.
	if enabled {
		switch role {
		case config.RoleGermany:
			if mcHostPortError(config.EnvDownListen2, m[config.EnvDownListen2], true, config.ReservedPort) != nil {
				errs = append(errs, fmt.Sprintf("%s: required when %s=true (the second down LISTENER; a host:port, not %d)",
					config.EnvDownListen2, config.EnvMultiCarrierEnabled, config.ReservedPort))
			}
			if m[config.EnvDownSNI2] == "" {
				errs = append(errs, fmt.Sprintf("%s: required when %s=true (the second down carrier's TLS 1.3 SNI)",
					config.EnvDownSNI2, config.EnvMultiCarrierEnabled))
			} else if !pairing.ValidSNI(m[config.EnvDownSNI2]) {
				errs = append(errs, fmt.Sprintf("%s: must be a lowercase RFC 1123 hostname when %s=true",
					config.EnvDownSNI2, config.EnvMultiCarrierEnabled))
			}
		case config.RoleIran:
			if mcHostPortError(config.EnvDownCarrierAddr2, m[config.EnvDownCarrierAddr2], true, 0) != nil {
				errs = append(errs, fmt.Sprintf("%s: required when %s=true (the second down DIAL target; a host:port)",
					config.EnvDownCarrierAddr2, config.EnvMultiCarrierEnabled))
			}
		}
		// Conflicting second-carrier addresses (duplicate endpoints).
		if role == config.RoleGermany {
			if m[config.EnvDownListen2] != "" && endpointConflict(m[config.EnvDownListen], m[config.EnvDownListen2]) {
				errs = append(errs, fmt.Sprintf("%s=%q conflicts with %s=%q (same bind endpoint)",
					config.EnvDownListen2, m[config.EnvDownListen2], config.EnvDownListen, m[config.EnvDownListen]))
			}
		} else if m[config.EnvDownCarrierAddr2] != "" && m[config.EnvDownCarrierAddr2] == m[config.EnvDownCarrier] {
			errs = append(errs, fmt.Sprintf("%s=%q equals %s=%q (the second down carrier must dial a different consumer inbound)",
				config.EnvDownCarrierAddr2, m[config.EnvDownCarrierAddr2], config.EnvDownCarrier, m[config.EnvDownCarrier]))
		}
		// Probing enabled without a URL is a config error (fail-closed).
		if m[config.EnvProbingEnabled] == "true" && strings.TrimSpace(m[config.EnvProbeURL]) == "" {
			errs = append(errs, fmt.Sprintf("%s: required when %s=true (an operator-owned probe target; no third-party default)",
				config.EnvProbeURL, config.EnvProbingEnabled))
		}
	}
	return errs
}

// endpointConflict reports whether two app-owned endpoints fight over
// the same bind address: equal ports AND identical hosts, or one binding
// all interfaces (the config layer's conflict() rule, mirrored here).
func endpointConflict(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ah, ap, aok := portOfEndpoint(a)
	bh, bp, bok := portOfEndpoint(b)
	if !aok || !bok || ap != bp {
		return false
	}
	if ah == bh {
		return true
	}
	return bindsAllInterfaces(ah) || bindsAllInterfaces(bh)
}

func portOfEndpoint(addr string) (string, int, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, false
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, false
	}
	return host, p, true
}

func bindsAllInterfaces(host string) bool {
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}
	return false
}

// c4MCConcept is the multi-carrier concept value (the shared apply
// engine's MC instance). xrayAffected: the second listener/SNI/master
// flip alters the rendered xray config (a C3-shaped inbound change), so
// those keys route through the xray gate; pure policy/probing knobs do
// not.
func c4MCConcept() *c4Concept {
	xrayKeys := map[string]bool{
		config.EnvMultiCarrierEnabled: true,
		config.EnvDownListen2:         true,
		config.EnvDownCarrierAddr2:    true,
		config.EnvDownSNI2:            true,
	}
	return &c4Concept{
		name:    "multi-carrier",
		allowed: c4MCFields,
		validate: func(role string, set, base map[string]string) []string {
			return ValidateMCChange(role, set, base)
		},
		xrayAffected: func(base, set map[string]string) bool {
			for k := range set {
				if xrayKeys[k] {
					return true
				}
			}
			return false
		},
	}
}

// ---------------------------------------------------------------------------
// The shared C4 transaction engine (C2 discipline, C4 validators/gates).
//
// The engine is two-phase so the coordinated two-host flow (coordinated.go)
// can reuse it verbatim:
//
//	PrepareC4  F1-F10 + xray gate. NO live-file writes, no service
//	                   restarts. Owns the agent's apply lock until the
//	                   matching CommitC4 / AbortC4 / RollbackCommittedC4.
//	CommitC4   F11-F15 (backup → swap → restart → verify → commit), with
//	                   the auto-rollback guarantee on any post-swap step.
//	AbortC4    discards a prepared transaction: clear the journal, drop
//	                   the sandbox; the live file is untouched (prepare
//	                   never wrote it).
//	RollbackCommittedC4 restores the pre copy of a COMMITTED revision
//	                   (the coordinated flow's "one side committed, the
//	                   other failed" repair: the committed side reverts).
//
// Fault points: "render", "validate", "xrayrender", "configtest",
// "backup", "swap", "restart", "restartXray", "verify", "verifyXray",
// "restore", "commit".
// ---------------------------------------------------------------------------

// c4Prepared is one prepared (not yet committed) C4 transaction. The
// apply lock is held by the owning agent from PrepareC4 until the
// transaction is committed, aborted, or rolled back.
type c4Prepared struct {
	agent        *Agent
	op           C4ApplyOp
	c            *c4Concept
	revID        string
	parent       string
	cand         string // sandbox env candidate path
	xrayCand     string // sandbox xray candidate path ("" when not xray-affected)
	xrayAffected bool
}

// recordC4Audit writes one redacted C4 audit entry (the sink re-checks).
func (a *Agent) recordC4Audit(op C4ApplyOp, c *c4Concept, res *TxResult, outcome string) {
	if a.Audit == nil {
		return
	}
	if outcome == "" {
		outcome = res.Outcome
	}
	_ = a.Audit.Record(AuditEntry{
		Actor:    op.Actor,
		Concept:  c.name,
		ChangeID: op.Change.ChangeID,
		RevTo:    res.RevisionID,
		Diff:     BuildC4Diff(a.baseEnv(op.Change.Role), op.Change.Set, c.allowed),
		Outcome:  outcome,
	})
}

// PrepareC4 runs the no-live-write phase (F1-F10 + xray gate) and
// returns the prepared handle. On any failure the journal is cleared,
// the lock released, and nothing outside the agent's own store exists.
// A prepare failure NEVER leaves a live file or a service touched.
func (a *Agent) PrepareC4(op C4ApplyOp, c *c4Concept, faults Faults) (*c4Prepared, TxResult, string, string) {
	var res TxResult
	role := op.Change.Role
	set := op.Change.Set

	// F1: concurrency lock — held until commit/abort (C2 invariant).
	if !a.acquireApplyLock() {
		res.Outcome = "refused"
		return nil, res, ErrCodeApplyInProgress, "another apply is in progress"
	}

	fail := func(outcome, code, msg string) (*c4Prepared, TxResult, string, string) {
		res.Outcome = outcome
		a.clearJournal()
		a.releaseApplyLock()
		a.recordC4Audit(op, c, &res, outcome)
		return nil, res, code, msg
	}

	// F2: in-flight journal → refuse (fail closed on corrupt).
	if a.Journal != nil {
		if _, inFlight, rerr := a.Journal.Read(); rerr != nil || inFlight {
			return fail("recovery-required", ErrCodeRecoveryRequired, "an in-flight journal is present; run recovery first")
		}
	}

	// F3: kill switch.
	if a.Store.IsFrozen() || (a.Frozen != nil && a.Frozen()) {
		return fail("frozen", ErrCodeFrozen, "kill switch engaged; unfreeze via the CLI before applying")
	}

	// F4: rate limits (the C2 windows apply to C4 too).
	now := a.Now()
	if ok, wait := a.rlShort.AllowApply(now); !ok {
		return fail("rate-limited", ErrCodeRateLimited, "rate limited (10-minute window); retry after "+wait.String())
	}
	if ok, wait := a.rlLong.AllowApply(now); !ok {
		return fail("rate-limited", ErrCodeRateLimited, "rate limited (24-hour window); retry after "+wait.String())
	}

	// F5: validate (authoritative; the web's validate is re-checked).
	base := a.baseEnv(role)
	if errs := c.validate(role, set, base); len(errs) > 0 {
		res.Err = fmt.Errorf("%s", joinErrs(errs))
		return fail("validation-failed", ErrCodeValidation, joinErrs(errs))
	}

	// F6: optimistic concurrency — base must equal the current head.
	head, _ := a.Store.Head()
	if op.Change.BaseRevision != "" && op.Change.BaseRevision != head {
		return fail("stale-base", ErrCodeStaleBase, "baseRevision does not match the current head")
	}
	if op.Change.ChangeID == "" {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		op.Change.ChangeID = "c4-" + hex.EncodeToString(b)
	}

	revID, err := a.Store.NewRevisionID()
	if err != nil {
		res.Err = err
		res.Outcome = "internal"
		a.releaseApplyLock()
		a.recordC4Audit(op, c, &res, "internal")
		return nil, res, ErrCodeInternal, err.Error()
	}

	// F7: pre-snapshot the live env file (the rollback source).
	livePath := a.Seam.LiveFile(role)
	pre := map[string]string{}
	if livePath != "" {
		pre[baseName(livePath)] = livePath
	}
	if err := a.Store.PreSnapshot(revID, pre); err != nil {
		res.Err = err
		res.Outcome = "internal"
		a.releaseApplyLock()
		a.recordC4Audit(op, c, &res, "internal")
		return nil, res, ErrCodeInternal, "pre-snapshot: " + err.Error()
	}

	// F8: journal prepared (before the first mutation).
	preHash := ""
	if livePath != "" {
		if h, herr := a.Store.HashFile(livePath); herr == nil {
			preHash = h
		}
	}
	xrayAffected := c.xrayAffected != nil && c.xrayAffected(base, set)

	// F9: render the candidate env into the sandbox.
	cand, err := faultInject(faults, "render", func() (string, error) {
		return a.Seam.WriteCandidate(role, base, set)
	})
	if err != nil {
		res.Err = err
		return fail("render-failed", ErrCodeValidation, "render: "+err.Error())
	}

	// F10: validate the candidate (splitter --validate-config equivalent).
	if err := faultInjectErr(faults, "validate", func() error {
		return a.Seam.ValidateCandidate(role, cand)
	}); err != nil {
		res.Err = err
		return fail("validate-failed", ErrCodeValidation, "candidate validation: "+err.Error())
	}

	// C4 xray gate (requirement 4: the xray unit is touched ONLY when
	// the SNI/listener changes). Fail-closed when no gate is wired.
	xrayCand := ""
	if xrayAffected {
		if a.XrayGate == nil {
			res.Outcome = "xray-gate-unavailable"
			a.clearJournal()
			a.releaseApplyLock()
			a.recordC4Audit(op, c, &res, "xray-gate-unavailable")
			return nil, res, ErrCodeXrayGateNotConfigured,
				"this change alters the rendered xray config and no xray gate (xray run -test) is configured on this agent; wire the gate before applying xray-affecting changes"
		}
		merged := mcMerge(base, set)
		var gerr error
		xrayCand, gerr = faultInject(faults, "xrayrender", func() (string, error) {
			return a.XrayGate.RenderXrayForMC(role, merged)
		})
		if gerr != nil {
			res.Err = gerr
			return fail("xray-gate-failed", ErrCodeValidation, "xray render gate: "+gerr.Error())
		}
		if err := faultInjectErr(faults, "configtest", func() error {
			return a.XrayGate.ConfigTest(role, xrayCand)
		}); err != nil {
			// The C3 gate: xray -test rejection means NO swap occurs.
			res.Err = err
			return fail("config-test-failed", ErrCodeConfigTestFailed, "candidate rejected by the xray test gate: "+err.Error())
		}
	}

	// F8 (journal write): now that the candidates are rendered, persist
	// the prepared state (incl. the xray fields, so crash recovery can
	// classify the live file — design §5.6).
	if a.Journal != nil {
		newHash := ""
		if h, herr := a.Store.HashFile(cand); herr == nil {
			newHash = h
		}
		if err := a.Journal.Write(ControlJournalEntry{
			ChangeID:     op.Change.ChangeID,
			Role:         role,
			State:        JournalPrepared,
			Revision:     revID,
			Parent:       head,
			PreHash:      preHash,
			NewHash:      newHash,
			XrayCand:     xrayCand,
			XrayAffected: xrayAffected,
		}); err != nil {
			res.Err = err
			return fail("internal", ErrCodeInternal, "write journal: "+err.Error())
		}
	}

	// Prepared: the lock stays held; the live file is untouched.
	res.Outcome = "prepared"
	res.RevisionID = revID
	res.PrevRevisionID = head
	p := &c4Prepared{
		agent:        a,
		op:           op,
		c:            c,
		revID:        revID,
		parent:       head,
		cand:         cand,
		xrayCand:     xrayCand,
		xrayAffected: xrayAffected,
	}
	return p, res, "", ""
}

// CommitC4 runs the write phase (F11-F15) of a prepared transaction.
// The live file is swapped, the splitter (and xray, when affected) is
// restarted and verified, and the revision is committed last. Any
// post-swap failure auto-rolls-back (restore the pre copy, restart,
// point head back at the parent). The apply lock is released on every
// exit path.
func (a *Agent) CommitC4(p *c4Prepared, faults Faults) (res TxResult, code string, errMsg string) {
	role := p.op.Change.Role

	failPostSwap := func(step string, cause error) (TxResult, string, string) {
		a.rollbackC4(role, &res, p.revID, p.parent, p.xrayAffected, faults)
		a.releaseApplyLock()
		a.recordC4Audit(p.op, p.c, &res, res.Outcome)
		res.Err = cause
		return res, "", "auto-rollback after " + step + ": " + cause.Error()
	}

	// F11: back up the live file.
	livePath := a.Seam.LiveFile(role)
	if _, err := faultInject(faults, "backup", func() (string, error) {
		if livePath == "" {
			return "", nil
		}
		return a.Seam.BackupFile(role, livePath)
	}); err != nil {
		a.clearJournal()
		res.Err = err
		res.Outcome = "internal"
		a.releaseApplyLock()
		a.recordC4Audit(p.op, p.c, &res, "internal")
		return res, ErrCodeInternal, "backup: " + err.Error()
	}

	// F12: atomic swap of the live env file.
	if err := faultInjectErr(faults, "swap", func() error {
		if livePath == "" {
			return nil
		}
		return a.Seam.SwapFile(p.cand, livePath)
	}); err != nil {
		return failPostSwap("swap", err)
	}
	a.journalState("swapped")

	// F13: restart the affected splitter service.
	if err := faultInjectErr(faults, "restart", func() error {
		return a.Seam.RestartService(role)
	}); err != nil {
		return failPostSwap("restart", err)
	}
	a.journalState("restarted")

	// F13b: restart the xray unit ONLY when the xray config changed.
	if p.xrayAffected {
		if err := faultInjectErr(faults, "restartXray", func() error {
			return a.XrayGate.RestartXray(role)
		}); err != nil {
			return failPostSwap("restartXray", err)
		}
	}

	// F14: verify the splitter; verify xray when it restarted.
	if err := faultInjectErr(faults, "verify", func() error {
		return a.Seam.Verify(role)
	}); err != nil {
		return failPostSwap("verify", err)
	}
	if p.xrayAffected {
		if err := faultInjectErr(faults, "verifyXray", func() error {
			return a.XrayGate.VerifyXray(role)
		}); err != nil {
			return failPostSwap("verifyXray", err)
		}
	}
	a.journalState("verified")

	// F15: commit (authoritative and last).
	post := map[string]string{}
	if livePath != "" {
		post[baseName(livePath)] = p.cand
	} else {
		post["env"] = p.cand
	}
	meta := RevisionMeta{
		ID:       p.revID,
		Parent:   p.parent,
		ChangeID: p.op.Change.ChangeID,
		Actor:    p.op.Actor,
		Role:     role,
		Kind:     p.c.name,
		Outcome:  "committed",
	}
	if err := faultInjectErr(faults, "commit", func() error {
		return a.Store.CommitRevision(meta, post, p.parent)
	}); err != nil {
		return failPostSwap("commit", err)
	}
	a.clearJournal()
	if p.parent != "" {
		_ = a.Store.PromoteLKG(p.parent)
	}
	a.rlShort.RecordApply(a.Now())
	a.rlLong.RecordApply(a.Now())
	a.releaseApplyLock()
	a.recordC4Audit(p.op, p.c, &res, "committed")
	res.Outcome = "committed"
	res.RevisionID = p.revID
	res.PrevRevisionID = p.parent
	return res, "", ""
}

// AbortC4 discards a prepared transaction without touching the live
// file: the journal is cleared and the sandbox candidates dropped. The
// apply lock is released. This is the coordinated flow's "one side's
// prepare failed → both sides untouched" primitive.
func (a *Agent) AbortC4(p *c4Prepared) TxResult {
	var res TxResult
	res.Outcome = "aborted"
	res.RevisionID = p.revID
	res.PrevRevisionID = p.parent
	a.clearJournal()
	if p.cand != "" {
		_ = os.Remove(p.cand)
	}
	if p.xrayCand != "" {
		_ = os.Remove(p.xrayCand)
	}
	a.releaseApplyLock()
	a.recordC4Audit(p.op, p.c, &res, "aborted")
	return res
}

// RollbackCommittedC4 restores the pre copy of a COMMITTED revision and
// points head back at its parent (the coordinated flow's repair when
// one side committed and the peer failed: the committed side reverts,
// keeping both hosts coupled in the same state).
func (a *Agent) RollbackCommittedC4(p *c4Prepared, faults Faults) TxResult {
	var res TxResult
	a.journalState("rolling-back")
	a.rollbackC4(p.op.Change.Role, &res, p.revID, p.parent, p.xrayAffected, faults)
	// rollbackC4 already cleared the journal; the lock releases here.
	a.releaseApplyLock()
	res.Outcome = "rolled-back"
	res.RevisionID = p.revID
	res.PrevRevisionID = p.parent
	a.recordC4Audit(p.op, p.c, &res, "rolled-back")
	return res
}

// runC4Apply is the single-host convenience path (the op handlers):
// prepare, and when the prepare succeeded, commit. Both phases share
// one apply-lock hold (prepare keeps the lock; commit releases it).
func (a *Agent) runC4Apply(op C4ApplyOp, c *c4Concept, faults Faults) (res TxResult, code string, errMsg string) {
	p, pres, pcode, pmsg := a.PrepareC4(op, c, faults)
	if pcode != "" {
		return pres, pcode, pmsg
	}
	res, code, errMsg = a.CommitC4(p, faults)
	return res, code, errMsg
}

// rollbackC4 restores the revision's pre/ copy onto the live env file,
// restarts the splitter (and the xray unit when the change was
// xray-affected), and points head back at the parent. A failed restore
// is recovery-required: the journal is retained and every mutating op is
// refused (the C2 fail-closed stance).
func (a *Agent) rollbackC4(role string, res *TxResult, revID, parent string, xrayAffected bool, faults Faults) {
	a.journalState("rolling-back")
	res.Outcome = "rolled-back"
	pre, err := a.Store.LoadPreCopies(revID)
	if err != nil {
		res.Err = fmt.Errorf("rollback: cannot load pre copies: %v", err)
		res.Outcome = "recovery-required"
		return
	}
	livePath := a.Seam.LiveFile(role)
	if livePath != "" {
		if len(pre) == 0 {
			res.Err = fmt.Errorf("rollback: no pre copy for the live file (inconsistent state)")
			res.Outcome = "recovery-required"
			return
		}
		if err := faultInjectErr(faults, "restore", func() error {
			return a.Seam.RestoreFile(role, livePath, firstVal(pre))
		}); err != nil {
			res.Err = fmt.Errorf("rollback: restore failed: %v", err)
			res.Outcome = "recovery-required"
			return
		}
	}
	if err := a.Seam.RestartService(role); err != nil {
		res.Err = fmt.Errorf("rollback: restart after restore failed: %v", err)
		res.Outcome = "recovery-required"
		return
	}
	if xrayAffected && a.XrayGate != nil {
		if err := a.XrayGate.RestartXray(role); err != nil {
			res.Err = fmt.Errorf("rollback: xray restart after restore failed: %v", err)
			res.Outcome = "recovery-required"
			return
		}
	}
	_ = a.Store.writePointer("head", parent)
	a.journalState("rolled-back")
	a.clearJournal()
}

// ---------------------------------------------------------------------------
// C4 op handlers (the socket surface; the dashboard forwards these)
// ---------------------------------------------------------------------------

// opRoutingValidate runs the pure C4 routing-plane validation and returns
// the redacted diff + restart classification. No host mutation.
func (a *Agent) opRoutingValidate(conn net.Conn, frame *Frame) error {
	var cc CandidateChange
	if err := framePayload(frame, &cc); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	c := c4RoutingConcept()
	base := a.baseEnv(cc.Role)
	errs := c.validate(cc.Role, cc.Set, base)
	data := map[string]any{
		"valid":           len(errs) == 0,
		"errors":          errs,
		"restartRequired": true,  // C4 routing keys are read at process start
		"xrayAffected":    false, // the routing plane never alters xray
		"diff":            BuildC4Diff(base, cc.Set, c.allowed),
	}
	return a.reply(conn, frame, true, data, "", "")
}

// opRoutingApply runs the full C4 routing apply transaction (the C2
// state machine with the routing validator; the xray gate is inert for
// this concept). Fault injection lives in runC4Apply.
func (a *Agent) opRoutingApply(conn net.Conn, frame *Frame) error {
	op := C4ApplyOp{IdempotencyKey: frame.IdempotencyKey, Actor: frame.ReqID}
	if err := framePayload(frame, &op.Change); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	if frame.ChangeID != "" {
		op.Change.ChangeID = frame.ChangeID
	}
	if entry, conflict := a.c4IdempotencyLookup(op); conflict {
		return a.reply(conn, frame, false, nil, ErrCodeIdempotency, "idempotency key was used with a different request")
	} else if entry != nil {
		return a.reply(conn, frame, true, entry.result, "", "")
	}
	res, code, errMsg := a.runC4Apply(op, c4RoutingConcept(), nil)
	a.c4IdempotencyStore(op, &res)
	if code != "" {
		return a.reply(conn, frame, false, nil, code, errMsg)
	}
	out := res.ToResponse()
	out["restartRequired"] = true
	out["restartWarning"] = "the splitter service restarted; the tunnel was briefly unavailable (estimated 10 s)"
	return a.reply(conn, frame, true, out, "", "")
}

// opMCValidate runs the pure C4 multi-carrier validation and returns the
// redacted diff + the xray-affected classification + restart flag.
func (a *Agent) opMCValidate(conn net.Conn, frame *Frame) error {
	var cc CandidateChange
	if err := framePayload(frame, &cc); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	c := c4MCConcept()
	base := a.baseEnv(cc.Role)
	errs := c.validate(cc.Role, cc.Set, base)
	xrayAff := c.xrayAffected(base, cc.Set)
	data := map[string]any{
		"valid":           len(errs) == 0,
		"errors":          errs,
		"restartRequired": true,
		"xrayAffected":    xrayAff,
		"diff":            BuildC4Diff(base, cc.Set, c.allowed),
	}
	return a.reply(conn, frame, true, data, "", "")
}

// opMCApply runs the full C4 multi-carrier apply transaction. An
// xray-affected change (SNI/listener/master flip) additionally routes
// through the xray gate and restarts the xray unit.
func (a *Agent) opMCApply(conn net.Conn, frame *Frame) error {
	op := C4ApplyOp{IdempotencyKey: frame.IdempotencyKey, Actor: frame.ReqID}
	if err := framePayload(frame, &op.Change); err != nil {
		return a.reply(conn, frame, false, nil, ErrCodeInvalidJSON, err.Error())
	}
	if frame.ChangeID != "" {
		op.Change.ChangeID = frame.ChangeID
	}
	if entry, conflict := a.c4IdempotencyLookup(op); conflict {
		return a.reply(conn, frame, false, nil, ErrCodeIdempotency, "idempotency key was used with a different request")
	} else if entry != nil {
		return a.reply(conn, frame, true, entry.result, "", "")
	}
	c := c4MCConcept()
	res, code, errMsg := a.runC4Apply(op, c, nil)
	a.c4IdempotencyStore(op, &res)
	if code != "" {
		return a.reply(conn, frame, false, nil, code, errMsg)
	}
	out := res.ToResponse()
	out["restartRequired"] = true
	out["restartWarning"] = "the splitter service restarted; the tunnel was briefly unavailable (estimated 10 s)"
	if c.xrayAffected(a.baseEnv(op.Change.Role), op.Change.Set) {
		out["xrayRestarted"] = true
		out["peerChangeRequired"] = peerChangeForRole(op.Change.Role)
	}
	return a.reply(conn, frame, true, out, "", "")
}

// ---------------------------------------------------------------------------
// C4 idempotency (a third key space; the request-hash shape is the C4 one
// so a C2 or C3 key can never collide into this space)
// ---------------------------------------------------------------------------

func c4IdempotencyHash(op C4ApplyOp) string {
	h := sha256.Sum256([]byte("c4|" + op.Change.Role + "|" + stableSet(op.Change.Set) + "|" + op.Change.BaseRevision + "|" + op.Change.ChangeID))
	return hex.EncodeToString(h[:])
}

func (a *Agent) c4IdempotencyLookup(op C4ApplyOp) (*idemEntry, bool) {
	if op.IdempotencyKey == "" {
		return nil, false
	}
	a.idemMu.Lock()
	defer a.idemMu.Unlock()
	if a.idemC4 == nil {
		return nil, false
	}
	e, ok := a.idemC4[op.IdempotencyKey]
	if !ok {
		return nil, false
	}
	if e.requestHash != c4IdempotencyHash(op) {
		return nil, true
	}
	return e, false
}

func (a *Agent) c4IdempotencyStore(op C4ApplyOp, res *TxResult) {
	if op.IdempotencyKey == "" {
		return
	}
	a.idemMu.Lock()
	defer a.idemMu.Unlock()
	if a.idemC4 == nil {
		a.idemC4 = map[string]*idemEntry{}
	}
	a.idemC4[op.IdempotencyKey] = &idemEntry{requestHash: c4IdempotencyHash(op), result: res.ToResponse()}
}
