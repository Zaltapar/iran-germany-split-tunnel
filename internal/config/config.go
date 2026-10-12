// Package config is the centralized configuration-loading and validation
// layer for both splitter binaries (Phase 7).
//
// The lifecycle is strictly ordered:
//
//	load (env → defaults)  →  parse  →  validate  →  construct runtime
//
// A binary must not open a listener, dial a carrier or start worker
// goroutines until config.Load has returned successfully; Load reports
// ALL validation problems at once (error aggregation) so operators do
// not have to fix-one-error-restart repeatedly.
//
// Environment-variable syntax:
//   - a variable that is unset OR set to the empty string means "use
//     the default";
//   - integers are parsed with strconv (no silent zeroing — the legacy
//     fmt.Sscanf parseInt is gone);
//   - SPLIT_ALLOW_WEAK_SECRET is parsed with strconv.ParseBool
//     (1/0/t/f/true/false/TRUE/False); any other value is a config error;
//   - addresses are host:port (empty host allowed for listeners, i.e.
//     ":9002"); IPv6 must use bracket syntax ("[::1]:9002").
//
// The shared-secret policy is Phase 6's mux.ValidateSecretMaterial,
// called here, not re-implemented; validation errors never include the
// secret value itself.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/routing"
)

const (
	RoleIran    = "iran"
	RoleGermany = "germany"
)

// Phase 3 carrier-intelligence policy modes (the values accepted by
// SPLIT_POLICY_MODE). These mirror the pkg/node PolicyStatic / PolicyAdaptive
// constants so the config layer can validate the operator's choice without
// importing pkg/node (the config package stays transport-free).
const (
	PolicyStaticMode   = "static"
	PolicyAdaptiveMode = "adaptive"
)

// Environment variable names (single source of truth).
const (
	EnvSocksListen         = "SPLIT_SOCKS_LISTEN"               // Iran
	EnvSocksUser           = "SPLIT_SOCKS_USER"                 // Iran — SOCKS5 RFC 1929 username
	EnvSocksPass           = "SPLIT_SOCKS_PASS"                 // Iran — SOCKS5 RFC 1929 password (never logged)
	EnvSocksAllowedSources = "SPLIT_SOCKS_ALLOWED_SOURCES"      // Iran — SOCKS5 source-IP allowlist (unset/empty = allow all)
	EnvWsListen            = "SPLIT_WS_LISTEN"                  // Iran
	EnvDownCarrier         = "SPLIT_DOWN_CARRIER_ADDR"          // Iran
	EnvUpWsUrl             = "SPLIT_UP_WS_URL"                  // Germany
	EnvDownListen          = "SPLIT_DOWN_LISTEN"                // Germany
	EnvSecret              = "SPLIT_SECRET"                     // both
	EnvAllowWeak           = "SPLIT_ALLOW_WEAK_SECRET"          // both (bool)
	EnvMetricsPort         = "SPLIT_METRICS_PORT"               // both
	EnvRelayBuf            = "SPLIT_RELAY_BUF"                  // both
	EnvQueueBytes          = "SPLIT_STREAM_QUEUE_BYTES"         // both
	EnvQueueFrames         = "SPLIT_STREAM_QUEUE_FRAMES"        // both
	EnvQueueTotal          = "SPLIT_STREAM_QUEUE_TOTAL_BYTES"   // both
	EnvOverflowMs          = "SPLIT_STREAM_OVERFLOW_MS"         // both
	EnvCarrierGrace        = "SPLIT_CARRIER_GRACE"              // both (ms) — Phase 5
	EnvBootstrapWait       = "SPLIT_BOOTSTRAP_WAIT_MS"          // both (ms) — Issue #7
	EnvSessionBuf          = "SPLIT_SESSION_BUFFER_BYTES"       // both — Phase 5
	EnvSessionBufTotal     = "SPLIT_SESSION_BUFFER_TOTAL_BYTES" // both — Issue #6
	EnvLivenessRounds      = "SPLIT_LIVENESS_ROUNDS"            // both — blackhole detection
	// Phase B credit flow-control (Slices 4-8):
	//
	// SPLIT_CREDITS_ENABLED is the master on/off for the whole credit plane.
	// The three sub-knobs that were here (SPLIT_CREDIT_WINDOW_MAX,
	// SPLIT_CREDIT_SAFE_TIMEOUT_MS, SPLIT_CREDIT_BATCH_BYTES) have been
	// removed: their values are fixed by the design §5/§14 invariants
	// (creditWindowMax = 512 KiB, CreditSafeTimeout = 2 s,
	// creditBatchBytes = MaxPayload) and are NOT per-operator tunable —
	// changing creditWindowMax would break the B2 memory-bound guarantee
	// (creditPreLatchBound < MaxBytesPerStream) that the whole credit plane
	// relies on. The pkg/node constants are the single source of truth.
	EnvCreditsEnabled = "SPLIT_CREDITS_ENABLED" // both (bool, default false) — credit plane master on/off
	// Opt-in only-IPv4 egress-target policy: when true, the node's
	// default TargetDial resolves domain hosts to IPv4 (A records only)
	// and refuses to silently fall back to IPv6; literal IP addresses
	// bypass resolution entirely. Wired on BOTH roles even though only
	// the Germany role currently dials egress targets, so the config
	// stays symmetric.
	EnvTargetOnlyIPv4 = "SPLIT_TARGET_ONLY_IPV4" // both (bool, default false)
	// Opt-in egress-target address-family POLICY (SUBTASK 42): a single
	// additive knob with three values that expresses every dial family
	// behavior in one place — "default" (today's byte-identical dual-
	// stack dial), "prefer-ipv4" (deterministic v4-first with v6
	// fallback, the RECOMMENDED opt-in), and "ipv4-only" (the hard A-
	// record filter, equivalent to SPLIT_TARGET_ONLY_IPV4=true). Wired
	// on BOTH roles for symmetry.
	EnvTargetAddrPolicy = "SPLIT_TARGET_ADDR_POLICY" // both (enum, default "default")
	// Multi-carrier down-plane (Phase 2, plans/multi-carrier-intelligence-design.md):
	//
	// SPLIT_MULTI_CARRIER_ENABLED is the master on/off for a SECOND down
	// carrier. OFF by default; when off the single-value down form
	// (SPLIT_DOWN_LISTEN / SPLIT_DOWN_CARRIER_ADDR) is used and behavior is
	// byte-identical to the pre-Phase-2 build. When on, the second down
	// instance (a second VLESS+Reality listener on Germany, a second
	// consumer inbound on Iran) is added and the three SPLIT_DOWN_*_2 /
	EnvMultiCarrierEnabled = "SPLIT_MULTI_CARRIER_ENABLED" // both (bool, default false)
	// Second down instance (only consulted when MultiCarrierEnabled).
	EnvDownListen2      = "SPLIT_DOWN_LISTEN_2"       // Germany: second down-carrier loopback listener (host:port, host required)
	EnvDownCarrierAddr2 = "SPLIT_DOWN_CARRIER_ADDR_2" // Iran: second down-carrier dial target (host:port, host required)
	EnvDownSNI2         = "SPLIT_DOWN_CARRIER2_SNI"   // Germany: second instance's TLS 1.3 SNI (operator-set, required when enabled; never a hardcoded third-party default)

	// Phase 3 carrier-intelligence policy (plans/multi-carrier-intelligence-
	// design.md §6-§7). These knobs are only consulted when
	// MultiCarrierEnabled is true (the policy engine is constructed only for a
	// multi-carrier down plane); in a single-carrier node they are ignored and
	// the Phase 3 path is fully inert.
	//
	// SPLIT_POLICY_MODE selects the new-stream selection policy: "static"
	// (the Phase 2 static-priority rollback, the default; adaptive switching
	// is OFF) or "adaptive" (hard gates + weighted score + hysteresis +
	// cooldown + smooth WRR). The static mode is the design rollback.
	EnvPolicyMode = "SPLIT_POLICY_MODE" // both (enum static|adaptive, default "static")
	// SPLIT_POLICY_TOPK is the number of top-scored Active carriers used for
	// new-stream round-robin in adaptive mode (design §7.1, D13 default 2).
	EnvPolicyTopK = "SPLIT_POLICY_TOPK" // both (int, default 2, 1..8)
	// SPLIT_PROBING_ENABLED turns on the bounded in-tunnel active probes.
	// OFF by default; when ON the probe URL (SPLIT_PROBE_URL) is required —
	// there is deliberately no third-party default, so probing enabled without
	// a URL is a config error (fail-closed, design §6.4).
	EnvProbingEnabled = "SPLIT_PROBING_ENABLED" // both (bool, default false)
	// SPLIT_PROBE_URL is the operator-configured probe target. No default.
	EnvProbeURL = "SPLIT_PROBE_URL" // both (string, required when probing enabled)
	// SPLIT_PROBE_DAILY_BUDGET is the hard daily byte budget per carrier for
	// active probes (design §6.4, D7 default 96 MiB). 0 = no cap (test
	// sentinel); NEGATIVE is a config error. Expressed in bytes.
	EnvProbeDailyBudget = "SPLIT_PROBE_DAILY_BUDGET" // both (int bytes, default 96 MiB, >= 0)
	// SPLIT_TTFB_BASELINE_MS is the Phase 0 baseline p50 TTFB used to
	// normalize the T score term (design §6.3). 0 = library default (500 ms).
	EnvTTFBBaselineMs = "SPLIT_TTFB_BASELINE_MS" // both (int ms, default 500, 0..30000)

	// GERMANY OUTBOUND ROUTING ENGINE (§22, plans/dashboard-control-
	// design.md). The rule file is the 3x-ui-style ordered rule set
	// (domains, CIDRs, port ranges, first-match-wins) that decides the
	// egress outbound for every NEW stream on the Germany node's
	// target dial path. OFF by default: an empty (unset) SPLIT_ROUTING_
	// RULES_FILE means the pre-routing policy dial is used, byte-
	// identical to the no-routing build. The routing concept is
	// Germany-only (only the Germany node dials egress targets).
	EnvRoutingRulesFile = "SPLIT_ROUTING_RULES_FILE" // Germany: JSON rules file path (empty = routing OFF)
	// SPLIT_ROUTING_DEFAULT is the outbound used when NO rule matches:
	// "direct" (the default) or "warp". "block" is NOT a valid default
	// (it would lock out the tunnel for every unmatched destination —
	// the same reason the rule validator rejects a catch-all block
	// rule). Overridden from the rules file's default_action when the
	// env is set; when unset the rules file's default_action stands.
	EnvRoutingDefault = "SPLIT_ROUTING_DEFAULT" // Germany: enum "direct"|"warp" (default "direct" when routing ON and the rules file has no default_action)
	// SPLIT_WARP_SOCKS_ADDR is the WARP SOCKS5 endpoint the routing
	// engine dials for the "warp" outbound (SOCKS5h: DNS resolution
	// happens inside WARP, not on this host). Required when any rule
	// or the default routes to warp; empty (unset) is only valid when
	// no warp routing is configured. Default 127.0.0.1:40000 (the
	// WARP local forwarder on a typical host) applies when routing is
	// ON and the env is unset.
	EnvWarpSocksAddr = "SPLIT_WARP_SOCKS_ADDR" // Germany: host:port of the WARP SOCKS5 endpoint
	// SPLIT_ROUTING_DEBUG turns on the per-dial debug log line
	// ("routing: <host>:<port> → <outbound> (rule <id>)"). OFF by
	// default: at the default level the destination is NEVER logged.
	EnvRoutingDebug = "SPLIT_ROUTING_DEBUG" // Germany (bool, default false)
)

// Defaults (mirror the pre-Phase-7 hardcoded values; every one is safe
// and bounded — the queue zeros fall back to mux.DefaultStreamLimits
// via mux.SanitizeLimits at runtime).
const (
	DefaultSocksListen = "127.0.0.1:10900"
	DefaultWsListen    = "127.0.0.1:9001"
	DefaultDownCarrier = "127.0.0.1:10802"
	// Placeholder URL: rejected by Validate so a fresh install fails
	// fast instead of dialing a dead domain forever.
	DefaultUpWsUrl    = "wss://cdn.example.com/upload"
	DefaultDownListen = ":9002"
	// Placeholder secret: rejected by the Phase 6 policy.
	DefaultSecret = "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING"
	// RFC 1929 SOCKS5 credentials (Iran): empty means auth disabled,
	// preserving the pre-RFC-1929 behavior (plans/socks5-auth-design.md §1.2).
	DefaultSocksUser    = ""
	DefaultSocksPass    = ""
	DefaultRelayBuf     = 32768
	DefaultKeepAlive    = 30 * time.Second
	ExpectedCarrierPath = "/upload" // the only path Iran's WS server serves

	// Relay buffer bounds: it is the socket read chunk size. 1 KiB
	// minimum keeps frame overhead sane; 8 MiB maximum stops a
	// misconfiguration from allocating absurd per-connection buffers.
	MinRelayBuf = 1024
	MaxRelayBuf = 8 << 20 // 8 MiB

	// Stream-queue bounds. Zero means "library default"; the maxima keep
	// a misconfigured deployment from reserving gigabytes.
	MaxQueueBytesPerStream = 64 << 20  // 64 MiB
	MaxQueueBytesTotal     = 256 << 20 // 256 MiB
	MaxOverflowWaitMs      = 30000     // 30 s

	// Phase 5 carrier-loss recovery bounds.
	MinCarrierGraceMs = 500    // 0.5 s
	MaxCarrierGraceMs = 600000 // 10 min

	// Issue #7 bootstrap wait bounds (ms). 0 = library default
	// (node.defaultBootstrapWait, 30 s). The maximum keeps a
	// misconfiguration from holding a new session hostage for hours;
	// the minimum keeps a genuinely broken carrier from being retried
	// pointlessly.
	DefaultBootstrapWaitMs = 0
	MinBootstrapWaitMs     = 500    // 0.5 s
	MaxBootstrapWaitMs     = 120000 // 2 min
	DefaultSessionBuf      = 256 << 10
	MinSessionBuf          = 4 << 10  // 4 KiB
	MaxSessionBuf          = 16 << 20 // 16 MiB

	// Issue #6: node-level aggregate session-buffer budget bounds.
	// 0 = library default (node.DefaultSessionBufferTotal, 32 MiB) —
	// the same 0-means-default convention as the queue fields. The
	// maximum keeps a misconfiguration from reserving gigabytes up
	// front; the per-buffer SPLIT_SESSION_BUFFER_BYTES bound is
	// unchanged and still applies on top of the aggregate.
	DefaultSessionBufTotal = 0
	MaxSessionBufTotal     = 512 << 20 // 512 MiB

	// Carrier liveness (blackhole detection): consecutive unanswered
	// keepalive pings after which the carrier is declared dead. Zero is
	// the "library default" sentinel (mux.DefaultLivenessRounds = 3,
	// ~45 s at the 30 s default ping period) — the same 0-means-default
	// convention as the queue fields. The maximum keeps a
	// misconfiguration from making detection effectively unbounded
	// (20 rounds ≈ 10 min at the default ping period).
	DefaultLivenessRounds = 0
	MinLivenessRounds     = 0
	MaxLivenessRounds     = 20

	// Phase B credit flow-control (Slices 6-7). Credits are OFF by default;
	// the whole plane is inert until SPLIT_CREDITS_ENABLED is set true. The
	// credit-plane sub-constants (window, timeout, batch) are fixed by the
	// design §5/§14 invariants in pkg/node/credit.go and are NOT exposed as
	// the operator env vars (setting one would break the B2 memory-bound
	// guarantee creditPreLatchBound < MaxBytesPerStream).
	DefaultCreditsEnabled = false
	// Multi-carrier down-plane default (Phase 2): OFF. When false the
	// single-value down form is used and behavior is byte-identical to the
	// pre-Phase-2 build.
	DefaultMultiCarrierEnabled = false

	// Phase 3 carrier-intelligence defaults (plans/multi-carrier-intelligence-
	// design.md §6-§7). The policy engine sanitizes zero values to the
	// documented starting values; these defaults mirror the ON/OFF and the
	// bounded ranges enforced at config validation.
	// DefaultPolicyMode is the Phase 2 rollback: "static" (adaptive switching
	// OFF by default).
	DefaultPolicyMode = PolicyStaticMode
	// DefaultProbingEnabled: OFF (probes are opt-in; the byte budget and the
	// probe URL are only consulted when ON).
	DefaultProbingEnabled = false
	// DefaultProbeURL: no third-party default (empty). Required when
	// ProbingEnabled is true.
	DefaultProbeURL = ""
	// DefaultProbeDailyBudget: the hard daily byte cap for active probes
	// (design §6.4, D7): 96 MiB.
	DefaultProbeDailyBudget = 96 << 20 // 96 MiB
	// MinTTFBBaselineMs / MaxTTFBBaselineMs bound the TTFB baseline (ms).
	// 0 means "library default" (500 ms).
	MinTTFBBaselineMs = 0
	MaxTTFBBaselineMs = 30000
	// MinPolicyTopK / MaxPolicyTopK bound the top-K carrier count.
	MinPolicyTopK = 1
	MaxPolicyTopK = 8
	// DefaultPolicyTopK (design §7.1, D13).
	DefaultPolicyTopK = 2

	// GERMANY OUTBOUND ROUTING ENGINE (§22):
	// DefaultRoutingRulesFile: empty — routing is OFF unless the operator
	// (or the C4 control plane) sets SPLIT_ROUTING_RULES_FILE.
	DefaultRoutingRulesFile = ""
	// DefaultRoutingDefault: empty — SPLIT_ROUTING_DEFAULT defers to the
	// rules file's default_action (which the rules validator lifts to
	// "direct" when the file omits it). An explicit env value OVERRIDES
	// the rules file's default_action; the empty value never overrides.
	DefaultRoutingDefault = ""
	// RoutingDefaultAllowed is the valid value set for SPLIT_ROUTING_DEFAULT.
	// "block" is deliberately NOT allowed: a block default would refuse
	// every unmatched destination and lock out the tunnel (the same
	// reason a catch-all block rule is rejected by the validator).
	RoutingDefaultAllowed = "direct|warp"
	// DefaultWarpSocksAddr: the WARP local SOCKS5 forwarder. The routing
	// engine only reaches it when a rule or the default routes to warp.
	DefaultWarpSocksAddr = "127.0.0.1:40000"
	// DefaultRoutingDebug: OFF — at the default log level the engine
	// logs no destination at all.
	DefaultRoutingDebug = false
	// Opt-in only-IPv4 target-dial policy: false by default preserves the
	// current net.DialTimeout("tcp") behavior for every host (dual-stack
	// resolution, OS address-family preference). When true, domain hosts
	// are resolved to IPv4 A records only and a clear error is returned
	// when no A record exists (no silent IPv6 fallback).
	DefaultTargetOnlyIPv4 = false

	// Opt-in egress-target address-family policy (SPLIT_TARGET_ADDR_POLICY,
	// SUBTASK 42). The default "default" preserves today's byte-identical
	// dual-stack net.DialTimeout. The three allowed values (and their
	// semantics) are documented in docs/target-ipv4-policy.md:
	//   - "default"     — OS dual-stack preference (today's behavior);
	//   - "prefer-ipv4" — deterministic IPv4-first with IPv6 fallback
	//     (RECOMMENDED for dual-homed Germany; never refuses AAAA-only);
	//   - "ipv4-only"   — hard A-record filter (use with care — breaks
	//     AAAA-only endpoints; 96-refusal evidence).
	DefaultTargetAddrPolicy    = "default"
	TargetAddrPolicyPreferIPv4 = "prefer-ipv4"
	TargetAddrPolicyIPv4Only   = "ipv4-only"
	// targetAddrPolicyAllowed is the valid value set, named in validation
	// errors.
	targetAddrPolicyAllowed = "default|prefer-ipv4|ipv4-only"

	MinPort = 1
	MaxPort = 65535

	// ReservedPort is the dashboard TLS port (plans/oneclick-installer-design.md
	// §305). It must never be used for a carrier listener: a carrier bound to
	// it would fail at bind time once the dashboard is installed, so the
	// config layer refuses it up front.
	ReservedPort = 8443

	// SOCKS5 RFC 1929 username bounds: RFC 1929 encodes the username
	// length in one byte, so 1..255 is the representable range. The
	// password has no separate length rule (its strength policy is
	// §5 of plans/socks5-auth-design.md); Min/MaxSocksPassLen are
	// NOT a config bound, only the protocol's 255-byte field cap.
	MinSocksUserLen = 1
	MaxSocksUserLen = 255
)

// Config is the full configuration for one splitter role. Role-irrelevant
// fields always carry their defaults; Validate(role) enforces only the
// role-relevant ones. Tests may construct Config directly and call
// Validate without touching the environment.
type Config struct {
	// Role-specific
	SocksListen     string // Iran: SOCKS5 listener (host:port)
	WsListen        string // Iran: up-carrier WS server (host:port)
	DownCarrierAddr string // Iran: down-carrier dial target (host:port)
	UpWsUrl         string // Germany: up-carrier WS URL (ws:// or wss://host/upload)
	DownListen      string // Germany: down-carrier TCP listener (host:port, host may be empty)
	// Iran RFC 1929 SOCKS5 credentials (plans/socks5-auth-design.md §1.2):
	// empty = auth not configured (pre-RFC-1929 behavior); both non-empty =
	// auth enforced. Exactly one set is a config error (fail closed). The
	// password is never logged or echoed in errors.
	SocksUser string
	SocksPass string

	// Iran SOCKS5 source-IP allowlist (opt-in; comma-separated CIDRs and/or
	// bare IPv4/IPv6 addresses). Empty = unset = allow all sources
	// (backward-compatible default). When set, a non-empty entry list is
	// validated at config load: every entry must be a well-formed CIDR or
	// single address, or the config fails (a typo'd allowlist must NOT
	// silently allow everyone). Independent of the RFC 1929 credential pair.
	SocksAllowedSources string
	// Shared
	Secret               string        // never logged, never echoed in errors
	AllowWeakSecret      bool          // SPLIT_ALLOW_WEAK_SECRET (Phase 6 bypass)
	MetricsPort          int           // 0 = metrics disabled; else 1..65535, binds 127.0.0.1
	RelayBufSize         int           // socket read chunk size
	KeepAliveInterval    time.Duration // fixed default; no env variable
	QueueBytesPerStream  int           // 0 = library default
	QueueFramesPerStream int           // 0 = library default (max mux.MaxFrames)
	QueueBytesTotal      int           // 0 = library default
	OverflowWaitMs       int           // 0 = library default

	// Phase 5 carrier-loss recovery (pkg/node engine).
	CarrierGraceMs int // SPLIT_CARRIER_GRACE: grace window per direction (ms)
	// Issue #7 bootstrap wait (pkg/node engine).
	BootstrapWaitMs int // SPLIT_BOOTSTRAP_WAIT_MS: bounded bootstrap wait for a down carrier (ms; 0 = library default)
	SessionBufBytes int // SPLIT_SESSION_BUFFER_BYTES: bounded per-direction reconnect buffer
	SessionBufTotal int // SPLIT_SESSION_BUFFER_TOTAL_BYTES: node-level aggregate (0 = library default)
	// Carrier liveness (blackhole detection): consecutive unanswered
	// keepalive pings before the carrier is torn down through the normal
	// loss/rebind machinery. 0 = library default (mux.DefaultLivenessRounds).
	LivenessRounds int // SPLIT_LIVENESS_ROUNDS

	// Phase B credit flow-control (Slices 6-7). CreditsEnabled is the
	// master on/off (default false → the whole credit plane is inert).
	// The credit-plane sub-constants (window, timeout, batch) are fixed
	// by design §5/§14 invariants in pkg/node/credit.go and are NOT
	// per-operator env vars.
	CreditsEnabled bool // SPLIT_CREDITS_ENABLED

	// Opt-in only-IPv4 egress-target policy (SPLIT_TARGET_ONLY_IPV4).
	// Default false preserves the existing dual-stack net.DialTimeout
	// behavior. When true the node's default TargetDial resolves domain
	// hosts to IPv4 only; literal IPs dial exactly as given.
	TargetOnlyIPv4 bool // SPLIT_TARGET_ONLY_IPV4 (hard filter; SUBTASK-42 legacy)

	// Opt-in egress-target address-family policy (SPLIT_TARGET_ADDR_POLICY,
	// SUBTASK 42). One of "default" | "prefer-ipv4" | "ipv4-only".
	// Default "default" preserves today's byte-identical dual-stack dial.
	// "prefer-ipv4" is the recommended opt-in (v4-first, v6 fallback,
	// AAAA-only still succeeds); "ipv4-only" is the hard A-record filter
	// (equivalent to TargetOnlyIPv4=true). Unknown values are a validation
	// error naming the allowed set. Precedence when both are set:
	// TargetOnlyIPv4=true / "ipv4-only" is the stricter policy and wins;
	// the explicit contradiction TargetOnlyIPv4=true + "prefer-ipv4" is a
	// validation error.
	TargetAddrPolicy string // SPLIT_TARGET_ADDR_POLICY

	// Multi-carrier down-plane (Phase 2). MultiCarrierEnabled is the master
	// on/off (default false → single-value down form, byte-identical behavior).
	// When true, the SECOND down instance is described by the three _2 fields
	// (all required and validated): Germany adds a second loopback Reality
	// listener (DownListen2), Iran dials a second local consumer inbound
	// (DownCarrierAddr2), and Germany renders the second instance's SNI
	// (DownSNI2). Port 8443 is reserved for the dashboard and rejected for
	// any carrier listener.
	MultiCarrierEnabled bool   // SPLIT_MULTI_CARRIER_ENABLED
	DownListen2         string // Germany: second down-carrier loopback listener (host:port)
	DownCarrierAddr2    string // Iran: second down-carrier dial target (host:port)
	DownSNI2            string // Germany: second instance SNI (TLS 1.3, operator-set)

	// Phase 3 carrier-intelligence policy (only consulted when
	// MultiCarrierEnabled; inert in single-carrier nodes).
	PolicyMode       string // SPLIT_POLICY_MODE (static|adaptive, default static)
	PolicyTopK       int    // SPLIT_POLICY_TOPK (1..8, default 2)
	ProbingEnabled   bool   // SPLIT_PROBING_ENABLED (default false)
	ProbeURL         string // SPLIT_PROBE_URL (required when ProbingEnabled; no default)
	ProbeDailyBudget int64  // SPLIT_PROBE_DAILY_BUDGET (bytes, default 96 MiB, >= 0)
	TTFBBaselineMs   int    // SPLIT_TTFB_BASELINE_MS (ms, default 0 = library 500 ms)

	// GERMANY OUTBOUND ROUTING ENGINE (§22). Germany role only (the
	// Germany node is the only side that dials egress targets). When
	// RoutingRulesFile is empty the routing engine is NOT constructed:
	// the node's default policy dial (post-Sanitize) is used, which is
	// byte-identical to the no-routing build.
	RoutingRulesFile string // SPLIT_ROUTING_RULES_FILE (empty = routing OFF)
	// RoutingDefault is the outbound kind ("direct"|"warp") used when no
	// rule matches; it OVERRIDES the rules file's default_action when
	// non-empty. "block" is not a valid value.
	RoutingDefault string // SPLIT_ROUTING_DEFAULT ("" = use the rules file's default_action; "direct"|"warp")
	// WarpSocksAddr is the WARP SOCKS5 endpoint for the "warp" outbound.
	// Required when any rule or the default routes to warp; default
	// DefaultWarpSocksAddr when routing is ON and the env is unset.
	WarpSocksAddr string // SPLIT_WARP_SOCKS_ADDR (default 127.0.0.1:40000 when routing ON)
	// RoutingDebug turns on the per-dial debug log line (destination is
	// logged ONLY when this is true).
	RoutingDebug bool // SPLIT_ROUTING_DEBUG (default false)
}

// Defaults returns a Config with all built-in defaults (no env read).
func Defaults() *Config {
	return &Config{
		SocksListen:     DefaultSocksListen,
		WsListen:        DefaultWsListen,
		DownCarrierAddr: DefaultDownCarrier,
		UpWsUrl:         DefaultUpWsUrl,
		DownListen:      DefaultDownListen,
		Secret:          DefaultSecret,
		// Empty credentials: auth disabled, byte-for-byte pre-RFC-1929
		// behavior (plans/socks5-auth-design.md §1.2, §8.2).
		SocksUser:         DefaultSocksUser,
		SocksPass:         DefaultSocksPass,
		MetricsPort:       0,
		RelayBufSize:      DefaultRelayBuf,
		KeepAliveInterval: DefaultKeepAlive,
		CarrierGraceMs:    5000,
		SessionBufBytes:   DefaultSessionBuf,
		// Phase B credit flow-control default (Slices 6-7): credits off.
		CreditsEnabled: DefaultCreditsEnabled,
		// Opt-in only-IPv4 target policy default (off: preserves the
		// existing dual-stack dial behavior).
		TargetOnlyIPv4: DefaultTargetOnlyIPv4,
		// Opt-in egress-target address-family policy default ("default"
		// preserves today's byte-identical dual-stack dial; SUBTASK 42).
		TargetAddrPolicy: DefaultTargetAddrPolicy,
		// Multi-carrier down-plane default (Phase 2): OFF.
		MultiCarrierEnabled: DefaultMultiCarrierEnabled,
		// Phase 3 carrier-intelligence defaults (inert unless
		// MultiCarrierEnabled): static policy (the Phase 2 rollback),
		// probing OFF, no third-party probe URL, the 96 MiB daily budget,
		// and the 0-means-library-default TTFB baseline.
		PolicyMode:       DefaultPolicyMode,
		PolicyTopK:       DefaultPolicyTopK,
		ProbingEnabled:   DefaultProbingEnabled,
		ProbeURL:         DefaultProbeURL,
		ProbeDailyBudget: DefaultProbeDailyBudget,
		TTFBBaselineMs:   0,
		// GERMANY OUTBOUND ROUTING ENGINE (§22): routing OFF by default.
		// Empty rules file = the pre-routing policy dial (byte-identical).
		RoutingRulesFile: DefaultRoutingRulesFile,
		RoutingDefault:   DefaultRoutingDefault,
		WarpSocksAddr:    DefaultWarpSocksAddr,
		RoutingDebug:     DefaultRoutingDebug,
	}
}

// SocksAuthEnabled reports whether RFC 1929 authentication is configured
// (both SocksUser and SocksPass non-empty). Iran role only; Germany's
// fields are not Iran's and the predicate reads no role argument — callers
// gate on the role themselves (plans/socks5-auth-design.md §5).
func (c *Config) SocksAuthEnabled() bool { return c.SocksUser != "" && c.SocksPass != "" }

// ConfigError aggregates every validation problem found, formatted as a
// bulleted list.
type ConfigError struct {
	Problems []string
}

func (e *ConfigError) Error() string {
	var b strings.Builder
	b.WriteString("configuration validation failed:")
	for _, p := range e.Problems {
		b.WriteString("\n  - " + p)
	}
	return b.String()
}

// Load reads the environment, applies defaults, parses and validates
// everything, and returns the complete configuration — or ALL problems
// at once. role must be RoleIran or RoleGermany.
func Load(role string) (*Config, error) {
	if role != RoleIran && role != RoleGermany {
		return nil, fmt.Errorf("config: unknown role %q (want %q or %q)", role, RoleIran, RoleGermany)
	}
	c := Defaults()
	var problems []string

	c.SocksListen = envString(EnvSocksListen, c.SocksListen)
	c.WsListen = envString(EnvWsListen, c.WsListen)
	c.DownCarrierAddr = envString(EnvDownCarrier, c.DownCarrierAddr)
	c.UpWsUrl = envString(EnvUpWsUrl, c.UpWsUrl)
	c.DownListen = envString(EnvDownListen, c.DownListen)
	c.Secret = envString(EnvSecret, c.Secret)
	// RFC 1929 SOCKS5 credentials (plans/socks5-auth-design.md §1.2–§1.3):
	// unset or empty means "not set" (the documented env convention), so a
	// half-set state is deterministic and fails closed in Validate.
	c.SocksUser = envString(EnvSocksUser, c.SocksUser)
	c.SocksPass = envString(EnvSocksPass, c.SocksPass)
	// SOCKS5 source-IP allowlist (opt-in): unset or empty means "allow all"
	// (the backward-compatible default; a restrictive default would break a
	// user who runs the SOCKS5 proxy from an unknown IP).
	c.SocksAllowedSources = envString(EnvSocksAllowedSources, "")
	c.MetricsPort = envInt(&problems, EnvMetricsPort, 0, 0, MaxPort)
	c.RelayBufSize = envInt(&problems, EnvRelayBuf, DefaultRelayBuf, MinRelayBuf, MaxRelayBuf)
	c.QueueBytesPerStream = envInt(&problems, EnvQueueBytes, 0, 0, MaxQueueBytesPerStream)
	c.QueueFramesPerStream = envInt(&problems, EnvQueueFrames, 0, 0, mux.MaxFrames)
	c.QueueBytesTotal = envInt(&problems, EnvQueueTotal, 0, 0, MaxQueueBytesTotal)
	c.OverflowWaitMs = envInt(&problems, EnvOverflowMs, 0, 0, MaxOverflowWaitMs)
	c.CarrierGraceMs = envInt(&problems, EnvCarrierGrace, 5000, MinCarrierGraceMs, MaxCarrierGraceMs)
	c.BootstrapWaitMs = envInt(&problems, EnvBootstrapWait, DefaultBootstrapWaitMs, 0, MaxBootstrapWaitMs) // 0 = library default
	c.SessionBufBytes = envInt(&problems, EnvSessionBuf, DefaultSessionBuf, MinSessionBuf, MaxSessionBuf)
	c.SessionBufTotal = envInt(&problems, EnvSessionBufTotal, DefaultSessionBufTotal, 0, MaxSessionBufTotal)             // 0 = library default
	c.LivenessRounds = envInt(&problems, EnvLivenessRounds, DefaultLivenessRounds, MinLivenessRounds, MaxLivenessRounds) // 0 = library default
	// Phase B credit flow-control (Slices 6-7): master flag. The three
	// sub-knobs (window/timeout/batch) are fixed by pkg/node/credit.go
	// constants and are NOT operator env vars (removing them prevents
	// SPLIT_CREDIT_* from silently doing nothing).
	c.CreditsEnabled = envBool(&problems, EnvCreditsEnabled, DefaultCreditsEnabled)
	// Opt-in only-IPv4 target policy: an invalid value (anything other
	// than 1/0/t/f/true/false) is a config error, matching the
	// EnvAllowWeak boolean convention; unset/empty keeps the default
	// (false — current dual-stack behavior preserved).
	c.TargetOnlyIPv4 = envBool(&problems, EnvTargetOnlyIPv4, DefaultTargetOnlyIPv4)
	// Opt-in egress-target address-family policy (SUBTASK 42): a string
	// enum, default "default" (today's behavior). Unset/empty keeps the
	// default. An unknown value is rejected in Validate (naming the
	// allowed set) rather than silently falling back to the default —
	// a typo'd policy must not silently change dial behavior.
	c.TargetAddrPolicy = envString(EnvTargetAddrPolicy, DefaultTargetAddrPolicy)
	// Multi-carrier down-plane (Phase 2): master on/off (default false →
	// single-value form, byte-identical behavior). The three _2 values are
	// read only when enabled; when disabled they stay at their defaults
	// (empty) and are NOT validated, so an operator can set them early
	// without flipping the master switch.
	c.MultiCarrierEnabled = envBool(&problems, EnvMultiCarrierEnabled, DefaultMultiCarrierEnabled)
	c.DownListen2 = envString(EnvDownListen2, c.DownListen2)
	c.DownCarrierAddr2 = envString(EnvDownCarrierAddr2, c.DownCarrierAddr2)
	c.DownSNI2 = envString(EnvDownSNI2, c.DownSNI2)
	// Phase 3 carrier-intelligence policy (only validated when
	// MultiCarrierEnabled; inert otherwise).
	c.PolicyMode = envString(EnvPolicyMode, DefaultPolicyMode)
	c.PolicyTopK = envInt(&problems, EnvPolicyTopK, DefaultPolicyTopK, MinPolicyTopK, MaxPolicyTopK)
	c.ProbingEnabled = envBool(&problems, EnvProbingEnabled, DefaultProbingEnabled)
	c.ProbeURL = envString(EnvProbeURL, c.ProbeURL)
	c.ProbeDailyBudget = envInt64(&problems, EnvProbeDailyBudget, DefaultProbeDailyBudget)
	c.TTFBBaselineMs = envInt(&problems, EnvTTFBBaselineMs, 0, MinTTFBBaselineMs, MaxTTFBBaselineMs) // 0 = library default
	// GERMANY OUTBOUND ROUTING ENGINE (§22). OFF by default: an empty
	// rules-file value leaves routing disabled and the node's pre-
	// routing policy dial in place (byte-identical to no-routing).
	// SPLIT_ROUTING_DEFAULT, when set, OVERRIDES the rules file's
	// default_action; when empty the rules file's default_action (or
	// "direct" if the file omits it) stands.
	c.RoutingRulesFile = envString(EnvRoutingRulesFile, c.RoutingRulesFile) // "" = routing OFF
	c.RoutingDefault = envString(EnvRoutingDefault, c.RoutingDefault)       // empty env → keep the default ("direct")
	// SPLIT_WARP_SOCKS_ADDR: the DefaultWarpSocksAddr (127.0.0.1:40000)
	// is applied only when routing is ON; when routing is OFF the value
	// stays at the default (unused, so it is never dialed).
	c.WarpSocksAddr = envString(EnvWarpSocksAddr, DefaultWarpSocksAddr)
	// SPLIT_ROUTING_DEBUG: OFF by default — at the default level the
	// engine logs no destination at all.
	c.RoutingDebug = envBool(&problems, EnvRoutingDebug, DefaultRoutingDebug)

	if v, ok := os.LookupEnv(EnvAllowWeak); ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			problems = append(problems, fmt.Sprintf(
				"%s=%q: expected a boolean (true/false, 1/0)", EnvAllowWeak, v))
		} else {
			c.AllowWeakSecret = b
		}
	}

	if err := c.Validate(role); err != nil {
		var ce *ConfigError
		if errors.As(err, &ce) {
			problems = append(problems, ce.Problems...)
		} else {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return nil, &ConfigError{Problems: problems}
	}
	return c, nil
}

// Validate runs the pure validation rules for the given role and returns
// every problem at once (aggregated). It is exported so tests (and
// future non-env callers) can validate a directly-constructed Config
// without environment access. Zero-valued queue fields are the
// documented "library default" sentinel (mux.SanitizeLimits) and are
// therefore NOT errors; negative values are.
func (c *Config) Validate(role string) error {
	var problems []string

	switch role {
	case RoleIran:
		checkHostPort(&problems, EnvSocksListen, c.SocksListen, true)
		checkHostPort(&problems, EnvWsListen, c.WsListen, false)
		checkHostPort(&problems, EnvDownCarrier, c.DownCarrierAddr, true)
		if conflict(c.SocksListen, c.WsListen) {
			problems = append(problems, fmt.Sprintf(
				"%s and %s use the same endpoint %q; the app owns both listeners",
				EnvSocksListen, EnvWsListen, c.SocksListen))
		}
		// RFC 1929 SOCKS5 credentials (plans/socks5-auth-design.md §1.4).
		// These rules are Iran-only; a Germany config leaving the pair empty
		// (or half-set, which Validate does not see because Load rejects it
		// first) is unaffected.
		if c.SocksUser != "" || c.SocksPass != "" {
			if c.SocksUser == "" || c.SocksPass == "" {
				// Exactly one set: fail closed. Field names only, never values.
				problems = append(problems, fmt.Sprintf(
					"%s and %s must be set together (a username without a password cannot authenticate anything); set both or neither",
					EnvSocksUser, EnvSocksPass))
			} else {
				// Both set: enforce the representable-range rule on the
				// username (RFC 1929's 1-byte ULEN field) and the password
				// strength policy (reusing the SPLIT_SECRET bypass, §5).
				if len(c.SocksUser) < MinSocksUserLen || len(c.SocksUser) > MaxSocksUserLen {
					problems = append(problems, fmt.Sprintf(
						"%s: expected 1..255 bytes (RFC 1929 encodes the username length in one byte)",
						EnvSocksUser))
				}
				if err := mux.ValidateSecretMaterial(c.SocksPass, c.AllowWeakSecret); err != nil {
					problems = append(problems, fmt.Sprintf(
						"%s: does not satisfy the minimum security requirements (%v); generate one with: openssl rand -hex 24",
						EnvSocksPass, err))
				}
			}
		}
		// SOCKS5 source-IP allowlist (opt-in; independent of the credential pair):
		// empty = allow all (backward-compatible default). When non-empty, every
		// comma-separated entry must be a well-formed CIDR or single IPv4/IPv6
		// address; an invalid entry fails config load so a typo'd allowlist
		// cannot silently allow everyone.
		checkSocksAllowedSources(&problems, c.SocksAllowedSources)
		// Multi-carrier (Phase 2, Iran role): a SECOND down-carrier dial
		// target (loopback port of the second Xray consumer inbound). Valid
		// only when multi-carrier is enabled; it must be a well-formed host:port
		// that differs from the primary down target, otherwise the two carriers
		// would dial the same endpoint and the second carrier adds nothing.
		if c.MultiCarrierEnabled {
			checkHostPort(&problems, EnvDownCarrierAddr2, c.DownCarrierAddr2, true)
			if c.DownCarrierAddr2 != "" && c.DownCarrierAddr2 == c.DownCarrierAddr {
				problems = append(problems, fmt.Sprintf(
					"%s=%q equals %s=%q; the second down carrier must dial a different local consumer inbound",
					EnvDownCarrierAddr2, c.DownCarrierAddr2, EnvDownCarrier, c.DownCarrierAddr))
			}
		}
	case RoleGermany:
		checkWsUrl(&problems, c.UpWsUrl)
		checkHostPort(&problems, EnvDownListen, c.DownListen, false)
		// Port 8443 is reserved for the dashboard TLS listener
		// (plans/oneclick-installer-design.md §305); a carrier bound to it
		// would fail at bind time once the dashboard is installed, so reject
		// it at config time. The primary down listener and, when enabled, the
		// second down listener are both carrier listeners.
		checkNotReservedCarrierPort(&problems, EnvDownListen, c.DownListen)
		// Multi-carrier (Phase 2, Germany role): a SECOND down-carrier
		// listener (loopback port of the second splitter down instance) plus
		// the second instance's TLS 1.3 SNI for Reality config rendering.
		// All are required and validated only when multi-carrier is enabled.
		if c.MultiCarrierEnabled {
			checkHostPort(&problems, EnvDownListen2, c.DownListen2, true)
			checkNotReservedCarrierPort(&problems, EnvDownListen2, c.DownListen2)
			// Conflicting listeners: the second down listener must not fight
			// the first over the same bind address.
			if c.DownListen2 != "" && conflict(c.DownListen, c.DownListen2) {
				problems = append(problems, fmt.Sprintf(
					"%s and %s use the same endpoint %q; the app owns both listeners",
					EnvDownListen, EnvDownListen2, c.DownListen2))
			}
			// SNI: required when multi-carrier is enabled. The default is the
			// operator-placeholder sentinel; a real TLS 1.3-compliant domain
			// must be set (decision D3). It is validated with the same SNI
			// rule the Reality renderer uses (internal/pairing.ValidSNI).
			if c.DownSNI2 == "" {
				problems = append(problems, fmt.Sprintf(
					"%s is required when %s=true (the second down carrier's TLS 1.3 SNI; set a real, TLS 1.3-compliant domain)",
					EnvDownSNI2, EnvMultiCarrierEnabled))
			} else if !pairing.ValidSNI(c.DownSNI2) {
				problems = append(problems, fmt.Sprintf(
					"%s=%q: must be a lowercase RFC 1123 hostname (no IP literal, no port, no scheme)",
					EnvDownSNI2, c.DownSNI2))
			}
		}
		// GERMANY OUTBOUND ROUTING ENGINE (§22): routing is OFF unless the
		// operator (or the C4 control plane) sets SPLIT_ROUTING_RULES_FILE.
		// When OFF, the node's pre-routing policy dial is used, byte-
		// identical to the no-routing build, so no routing fields are
		// validated here.
		checkRouting(&problems, c)
	case "":
		return fmt.Errorf("config: no role given")
	default:
		return fmt.Errorf("config: unknown role %q (want %q or %q)", role, RoleIran, RoleGermany)
	}
	// App-owned listener endpoints vs the metrics port (metrics always
	// binds 127.0.0.1:<port>): a collision would fail at bind time, so
	// report it at config time.
	if c.MetricsPort > 0 {
		metricsAddr := "127.0.0.1:" + strconv.Itoa(c.MetricsPort)
		for _, ep := range roleOwnedEndpoints(role, c) {
			if conflict(metricsAddr, ep[1]) {
				problems = append(problems, fmt.Sprintf(
					"%s=%d collides with %s=%q; both would bind the same endpoint",
					EnvMetricsPort, c.MetricsPort, ep[0], ep[1]))
			}
		}
	}

	// Shared numeric bounds (0 = library default where documented).
	if c.MetricsPort < 0 || c.MetricsPort > MaxPort {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected a port between 0 (disabled) and %d",
			EnvMetricsPort, c.MetricsPort, MaxPort))
	}
	if c.RelayBufSize < 0 || (c.RelayBufSize > 0 && c.RelayBufSize > MaxRelayBuf) {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected %d..%d bytes (0 = library default %d)",
			EnvRelayBuf, c.RelayBufSize, MinRelayBuf, MaxRelayBuf, DefaultRelayBuf))
	}
	if c.QueueBytesPerStream < 0 || c.QueueBytesPerStream > MaxQueueBytesPerStream {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d",
			EnvQueueBytes, c.QueueBytesPerStream, MaxQueueBytesPerStream))
	}
	if c.QueueFramesPerStream < 0 || c.QueueFramesPerStream > mux.MaxFrames {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d",
			EnvQueueFrames, c.QueueFramesPerStream, mux.MaxFrames))
	}
	if c.QueueBytesTotal < 0 || c.QueueBytesTotal > MaxQueueBytesTotal {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d",
			EnvQueueTotal, c.QueueBytesTotal, MaxQueueBytesTotal))
	}
	if c.OverflowWaitMs < 0 || c.OverflowWaitMs > MaxOverflowWaitMs {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d milliseconds",
			EnvOverflowMs, c.OverflowWaitMs, MaxOverflowWaitMs))
	}
	if c.CarrierGraceMs < MinCarrierGraceMs || c.CarrierGraceMs > MaxCarrierGraceMs {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected %d..%d milliseconds (Phase 5 carrier-loss grace window)",
			EnvCarrierGrace, c.CarrierGraceMs, MinCarrierGraceMs, MaxCarrierGraceMs))
	}
	// 0 is the library-default sentinel; any explicit value must be
	// within MinBootstrapWaitMs..MaxBootstrapWaitMs (Issue #7).
	if (c.BootstrapWaitMs != 0 && c.BootstrapWaitMs < MinBootstrapWaitMs) ||
		c.BootstrapWaitMs > MaxBootstrapWaitMs {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d milliseconds, or %d..%d (Issue #7 bootstrap wait for a temporarily down carrier)",
			EnvBootstrapWait, c.BootstrapWaitMs, MaxBootstrapWaitMs, MinBootstrapWaitMs, MaxBootstrapWaitMs))
	}
	if c.LivenessRounds < MinLivenessRounds || c.LivenessRounds > MaxLivenessRounds {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d (blackhole detection: consecutive unanswered keepalive pings)",
			EnvLivenessRounds, c.LivenessRounds, MaxLivenessRounds))
	}
	if c.SessionBufBytes < MinSessionBuf || c.SessionBufBytes > MaxSessionBuf {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected %d..%d bytes (Phase 5 per-direction reconnect buffer)",
			EnvSessionBuf, c.SessionBufBytes, MinSessionBuf, MaxSessionBuf))
	}
	if c.SessionBufTotal < 0 || c.SessionBufTotal > MaxSessionBufTotal {
		problems = append(problems, fmt.Sprintf(
			"%s=%d: expected 0 (library default) .. %d bytes (Issue #6 node-level aggregate session-buffer budget)",
			EnvSessionBufTotal, c.SessionBufTotal, MaxSessionBufTotal))
	}
	// Opt-in egress-target address-family policy (SUBTASK 42): the value
	// must be one of the allowed set (default|prefer-ipv4|ipv4-only); an
	// unknown value is rejected naming the allowed set so a typo'd policy
	// cannot silently change dial behavior.
	// The empty string is the "unset" sentinel (a hand-constructed Config
	// that never reads the env) and is valid — Load fills it with the
	// default before Validate, so by the time Load's Validate runs the
	// field is always one of the three allowed values; a directly
	// constructed Config (tests, future non-env callers) may leave it
	// empty and that means "default".
	switch c.TargetAddrPolicy {
	case "", "default", "prefer-ipv4", "ipv4-only":
	default:
		problems = append(problems, fmt.Sprintf(
			"%s=%q: expected one of %s",
			EnvTargetAddrPolicy, c.TargetAddrPolicy, targetAddrPolicyAllowed))
	}
	// Cross-field: the hard filter (SPLIT_TARGET_ONLY_IPV4=true) is the
	// STRICTER policy; it is equivalent to "ipv4-only" and compatible with
	// "default"/"ipv4-only". The explicit contradiction TargetOnlyIPv4=true
	// + "prefer-ipv4" (hard refuse + soft fallback) is a config error, not
	// a silent precedence, so an operator cannot unknowingly get one or
	// the other.
	if c.TargetOnlyIPv4 && c.TargetAddrPolicy == "prefer-ipv4" {
		problems = append(problems, fmt.Sprintf(
			"%s=true contradicts %s=%q: the hard IPv4-only filter refuses AAAA-only domains, while %q falls back to IPv6. Use either %s=false + %s=prefer-ipv4, or %s=true + %s=ipv4-only, not both",
			EnvTargetOnlyIPv4, EnvTargetAddrPolicy, c.TargetAddrPolicy,
			c.TargetAddrPolicy, EnvTargetOnlyIPv4, EnvTargetAddrPolicy,
			EnvTargetOnlyIPv4, EnvTargetAddrPolicy))
	}

	// Cross-field: the carrier-wide budget must cover one stream's share.
	if c.QueueBytesPerStream > 0 && c.QueueBytesTotal > 0 &&
		c.QueueBytesTotal < c.QueueBytesPerStream {
		problems = append(problems, fmt.Sprintf(
			"%s=%d is smaller than %s=%d; the aggregate budget must cover at least one stream",
			EnvQueueTotal, c.QueueBytesTotal, EnvQueueBytes, c.QueueBytesPerStream))
	}

	// Phase 3 policy config: all validations are gated on MultiCarrierEnabled
	// so that single-carrier deployments (the default) are unaffected by the
	// Phase 3 fields (they stay at their zero defaults and are never
	// validated). This preserves the "hand-built config must validate without
	// env" invariant.
	if c.MultiCarrierEnabled {
		if c.PolicyMode != PolicyStaticMode && c.PolicyMode != PolicyAdaptiveMode {
			problems = append(problems, fmt.Sprintf(
				"%s=%q: expected %q or %q", EnvPolicyMode, c.PolicyMode, PolicyStaticMode, PolicyAdaptiveMode))
		}
		if c.PolicyTopK < MinPolicyTopK || c.PolicyTopK > MaxPolicyTopK {
			problems = append(problems, fmt.Sprintf(
				"%s=%d: expected %d..%d", EnvPolicyTopK, c.PolicyTopK, MinPolicyTopK, MaxPolicyTopK))
		}
		if c.ProbeDailyBudget < 0 {
			problems = append(problems, fmt.Sprintf(
				"%s=%d: expected a non-negative byte count", EnvProbeDailyBudget, c.ProbeDailyBudget))
		}
		if c.TTFBBaselineMs < MinTTFBBaselineMs || c.TTFBBaselineMs > MaxTTFBBaselineMs {
			problems = append(problems, fmt.Sprintf(
				"%s=%d: expected %d..%d milliseconds (0 = library default)", EnvTTFBBaselineMs, c.TTFBBaselineMs, MinTTFBBaselineMs, MaxTTFBBaselineMs))
		}
		if c.ProbingEnabled && strings.TrimSpace(c.ProbeURL) == "" {
			problems = append(problems, fmt.Sprintf(
				"%s is required when %s=true; configure an operator-owned probe target (no third-party default)", EnvProbeURL, EnvProbingEnabled))
		}
		if c.ProbingEnabled && c.ProbeURL != "" {
			u, err := url.ParseRequestURI(c.ProbeURL)
			if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				problems = append(problems, fmt.Sprintf(
					"%s: expected an operator-configured http(s) URL with a host", EnvProbeURL))
			}
		}
	}

	// Secret policy: Phase 6's validator, not duplicated here. The
	// message never includes the secret value.
	if err := mux.ValidateSecretMaterial(c.Secret, c.AllowWeakSecret); err != nil {
		problems = append(problems, fmt.Sprintf(
			"%s: does not satisfy the minimum security requirements (%v); generate one with: openssl rand -hex 32",
			EnvSecret, err))
	}

	if len(problems) > 0 {
		return &ConfigError{Problems: problems}
	}
	return nil
}

// roleOwnedEndpoints lists this role's app-owned listener endpoints
// (the dial target is not a local listener, so it is excluded).
func roleOwnedEndpoints(role string, c *Config) [][2]string {
	if role == RoleIran {
		return [][2]string{
			{EnvSocksListen, c.SocksListen},
			{EnvWsListen, c.WsListen},
		}
	}
	return [][2]string{{EnvDownListen, c.DownListen}}
}

// checkSocksAllowedSources validates the optional SOCKS5 source-IP allowlist
// (SPLIT_SOCKS_ALLOWED_SOURCES). The empty string means "allow all sources"
// (the backward-compatible default) and is accepted without further checks.
// When non-empty, the value must be a comma-separated list where every entry
// is either a single IPv4/IPv6 address or a CIDR block ("10.0.0.0/8",
// "fe80::/64"); any entry that parses to neither is a config problem, so a
// typo'd allowlist fails fast at config load instead of silently allowing
// everyone.
func checkSocksAllowedSources(problems *[]string, raw string) {
	if _, err := ParseAllowedSources(raw); err != nil {
		*problems = append(*problems, fmt.Sprintf(
			"%s: %v; each entry must be a single IPv4/IPv6 address or a CIDR block",
			EnvSocksAllowedSources, err))
	}
}

// ParseAllowedSources parses a comma-separated allowlist of single IPs or
// CIDR blocks into a slice of *net.IPNet. A bare address is wrapped in its
// host network (a /32 for IPv4, /128 for IPv6) so membership is a single
// uniform Contains() check. The empty or all-whitespace string is the
// "allow all sources" sentinel and returns a NIL slice (a nil result means
// no restriction). Any empty entry inside a non-empty list (a stray comma)
// or any entry that is neither an address nor a CIDR is a parse error, so a
// typo'd allowlist cannot be silently dropped.
func ParseAllowedSources(raw string) ([]*net.IPNet, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil // allow-all sentinel
	}
	parts := strings.Split(trimmed, ",")
	out := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		entry := strings.TrimSpace(p)
		if entry == "" {
			// A stray comma ("10.0.0.0/8,,1.2.3.4") is not representable as
			// "allow all"; dropping it would widen the allowlist, so fail.
			return nil, fmt.Errorf("entry list contains an empty entry (stray comma)")
		}
		var n *net.IPNet
		if ip := net.ParseIP(entry); ip != nil {
			// A bare address: a single /32 (v4) or /128 (v6) host network.
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			n = &net.IPNet{IP: ip, Mask: mask}
		} else if _, cidr, err := net.ParseCIDR(entry); err == nil {
			n = cidr
		} else {
			return nil, fmt.Errorf("entry %q is not a valid IPv4/IPv6 address or CIDR block", entry)
		}
		out = append(out, n)
	}
	return out, nil
}

// AllowedSourcesMatch reports whether the client source IP (the host part of
// the client's RemoteAddr, which the caller must strip the port from) is
// permitted by a raw allowlist string (the form stored on
// Config.SocksAllowedSources). The empty string permits every source
// (allow-all default). A clientIP that cannot be parsed as an IP address is
// rejected when an allowlist is set; under the allow-all default the parse
// is never consulted. The source IP is a non-secret value, safe to log
// (matching the existing "from <RemoteAddr>" lines); the allowlist entries
// are operator configuration, not secret material.
func AllowedSourcesMatch(raw, clientIP string) bool {
	nets, err := ParseAllowedSources(raw)
	if err != nil {
		// Unreachable in production (Load validates before storing).
		// Fail closed rather than open if it ever happens.
		return false
	}
	if len(nets) == 0 {
		return true // allow-all sentinel
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// checkRouting validates the GERMANY OUTBOUND ROUTING ENGINE fields (§22).
// It is a no-op when routing is OFF (empty RoutingRulesFile). When ON, it
// validates:
//   - SPLIT_ROUTING_DEFAULT is "" (use the rules file's default_action) or
//     one of "direct"|"warp" ("block" is rejected — a block default would
//     lock out the tunnel for every unmatched destination);
//   - SPLIT_WARP_SOCKS_ADDR is a well-formed host:port when any rule or the
//     default could route to warp (the same condition the engine's New
//     checks, surfaced earlier at config-load time);
//   - the rules file exists and parses (routing.LoadRulesFile); the error
//     message names the file path, not its contents (no destination or
//     rule data is echoed — the file is a public artifact, not secret,
//     but its contents may include operator-chosen domain strings and
//     should not be echoed into a config error).
func checkRouting(problems *[]string, c *Config) {
	if c.RoutingRulesFile == "" {
		return // routing OFF: byte-identical, nothing to validate.
	}
	// Default outbound enum: only "direct"|"warp" (empty = deferral to
	// the rules file). "block" is deliberately rejected: a block default
	// would refuse every unmatched destination and lock out the tunnel.
	if c.RoutingDefault != "" && c.RoutingDefault != "direct" && c.RoutingDefault != "warp" {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected one of %s (a block default would lock out the tunnel)",
			EnvRoutingDefault, c.RoutingDefault, RoutingDefaultAllowed))
	}
	// WARP endpoint must be a valid host:port when routing is ON (it will
	// be dialed whenever any rule or the default routes to warp).
	if c.WarpSocksAddr != "" {
		checkHostPort(problems, EnvWarpSocksAddr, c.WarpSocksAddr, true)
	}
	// Rules file must exist and parse (public-field validation happens in
	// routing.ParseRules; the error text names only the file path and the
	// first parse problem, never rule contents).
	if _, err := routing.LoadRulesFile(c.RoutingRulesFile); err != nil {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: %v", EnvRoutingRulesFile, c.RoutingRulesFile, err))
	}
}

// checkHostPort validates a host:port endpoint. requireHost applies to
// dial targets (a listen address may omit the host: ":9002"). IPv6
// requires bracket syntax ("[::1]:9002") — that is standard
// net.SplitHostPort behavior.
func checkHostPort(problems *[]string, name, addr string, requireHost bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected host:port (e.g. 127.0.0.1:9001, :9002 or [::1]:9002)", name, addr))
		return
	}
	if requireHost && host == "" {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: dial target requires an explicit host (e.g. 127.0.0.1:10802)", name, addr))
		return
	}
	if strings.ContainsAny(host, " \t\n") {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: host must not contain whitespace", name, addr))
		return
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < MinPort || p > MaxPort {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected a port between %d and %d", name, addr, MinPort, MaxPort))
	}
}

// checkNotReservedCarrierPort reports a config problem when the
// host:port endpoint's port is the dashboard-reserved port 8443
// (plans/oneclick-installer-design.md §305). A carrier listener on that
// port would fail to bind once the dashboard is installed, so the config
// layer refuses it up front. The endpoint's port is parsed with the same
// host:port rules as checkHostPort (IPv6 bracket syntax supported); when
// the endpoint is unparseable checkHostPort has already reported the
// problem, so this helper is a no-op in that case.
func checkNotReservedCarrierPort(problems *[]string, name, addr string) {
	_, p, ok := portOf(addr)
	if !ok {
		return // checkHostPort already reported the parse problem.
	}
	if p == ReservedPort {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: port %d is reserved for the dashboard TLS listener; use a different carrier port",
			name, addr, ReservedPort))
	}
}

// checkWsUrl validates the up-carrier WebSocket URL: ws:// or wss://
// scheme, non-empty host, and the carrier path the Iran side serves.
// Query strings are allowed (CDN dial patterns). The value is echoed in
// errors because a URL is not secret material.
func checkWsUrl(problems *[]string, raw string) {
	if raw == DefaultUpWsUrl {
		*problems = append(*problems, fmt.Sprintf(
			"%s is still the placeholder %q; set the real CDN up-carrier URL", EnvUpWsUrl, raw))
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: malformed URL: %v", EnvUpWsUrl, raw, err))
		return
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: scheme must be ws or wss (got %q)", EnvUpWsUrl, raw, u.Scheme))
		return
	}
	if u.Host == "" {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: missing host", EnvUpWsUrl, raw))
		return
	}
	if u.Path != ExpectedCarrierPath {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: path must be %q (the only path the Iran side serves)", EnvUpWsUrl, raw, ExpectedCarrierPath))
	}
}

// conflict reports whether two app-owned listen endpoints would fight
// over the same bind address: equal ports AND either identical hosts or
// one of them binding all interfaces.
func conflict(a, b string) bool {
	ah, ap, aok := portOf(a)
	bh, bp, bok := portOf(b)
	if !aok || !bok || ap != bp {
		return false
	}
	if ah == bh {
		return true
	}
	return bindsEverything(ah) || bindsEverything(bh)
}

func bindsEverything(host string) bool {
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}
	return false
}

// portOf splits a host:port endpoint into (host, port, ok).
func portOf(addr string) (string, int, bool) {
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

// envString returns the env value, or def when the variable is unset or
// the empty string (documented: empty = use the default).
func envString(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

// envInt parses an integer env variable with explicit min/max bounds and
// aggregates a precise error (never a silent zero). Unset/empty returns
// def.
func envInt(problems *[]string, name string, def, min, max int) int {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected an integer between %d and %d", name, v, min, max))
		return def
	}
	if n < min || n > max {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected an integer between %d and %d", name, v, min, max))
		return def
	}
	return n
}

// envBool parses a boolean env variable (1/0/t/f/true/false, case-insensitive
// via strconv.ParseBool). Unset/empty returns def. An invalid value is
// aggregated as a precise problem (mirroring the EnvAllowWeak convention in
// Load) and def is returned.
func envBool(problems *[]string, name string, def bool) bool {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected a boolean (true/false, 1/0)", name, v))
		return def
	}
	return b
}

// envInt64 parses an integer64 env variable (the probe byte budget is the one
// int64-typed knob). Unset/empty returns def. A non-integer value is a config
// error (no silent zeroing). Negative values are validated by the caller
// (Validate) since the minimum is knob-specific; this helper only parses.
func envInt64(problems *[]string, name string, def int64) int64 {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf(
			"%s=%q: expected an integer (bytes)", name, v))
		return def
	}
	return n
}
