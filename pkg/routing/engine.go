// engine.go — the routing engine: outbound construction (direct,
// warp, block) and the per-stream Dial hook the Germany splitter
// wires into its TargetDial path when routing is enabled (§22).
//
// The engine is the ONLY place that knows how to reach WARP; the rule
// set stays pure (no dials, no I/O) and is fully unit-testable.
//
// Design invariants:
//
//   - When routing is OFF the engine is never constructed; the node's
//     TargetDial is the pre-routing policy dial, byte-identical.
//   - When routing is ON, each NEW stream's destination is evaluated
//     at DIAL time (bootstrapUpStream) against the pinned rule set,
//     and the resulting outbound is what dials it. Existing sessions
//     are unaffected by a later rule-set change (rules are pinned at
//     dial time — a rules reload RESTARTS the splitter service,
//     which is the C4 apply path's documented behavior).
//   - Block is a CLEAN refusal: the stream bootstrap is dropped with
//     the "blocked by rule" reason (FrameClose + deregister, exactly
//     like a target dial failure), never a silent blackhole.
//   - WARP health gate: a rule with fallback="direct" falls back to
//     the DIRECT dial when the WARP endpoint is UNREACHABLE. The
//     default (no fallback) and the default outbound fail CLOSED
//     (stream refused, clear reason) so traffic never silently leaks
//     outside WARP.
//   - Logging: no destination (host/port) is ever logged at the
//     default level. The debug flag (SPLIT_ROUTING_DEBUG) enables a
//     per-dial line "routing: <host>:<port> → <outbound> (rule
//     <id>)". No credential ever appears in code or logs.
package routing

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// DialFunc dials a destination address ("host:port", the form the
// node's TargetDial receives). The default implementation is the
// node's policy-aware dial (Config.TargetDial after Sanitize — which
// for a routing-enabled build is the SAME dial routing OFF would use,
// i.e. "direct").
type DialFunc func(addr string) (net.Conn, error)

// Engine evaluates one RuleSet and produces outbounds. It is
// immutable after New (the RuleSet pointer is captured once) and
// safe for concurrent use.
type Engine struct {
	rs     *RuleSet
	direct DialFunc // the node's policy-aware dial (the "direct" outbound)

	// WARP SOCKS5 outbound configuration.
	warpAddr  string
	warpDial  DialFunc
	warpProto bool // when false the SOCKS5 protocol exchange is skipped
	warpTO    time.Duration

	// Debug logging (SPLIT_ROUTING_DEBUG). Nil = off (the default):
	// no destination is ever logged.
	debugLog func(format string, args ...any)
}

// Config parameterizes an Engine.
type Config struct {
	// Rules is the validated rule set (required, non-nil).
	Rules *RuleSet

	// Direct is the policy-aware dial used for the direct outbound and
	// for the fallback path (required, non-nil).
	Direct DialFunc

	// WARPAddr is the WARP SOCKS5 endpoint (e.g. "127.0.0.1:40000").
	// Required when any rule or the default routes to warp; a
	// validation error otherwise.
	WARPAddr string

	// WARPTimeout bounds a single WARP endpoint connect (default
	// warpDefaultTimeout, 5s — inside the node's shared 10s target
	// dial budget so the routing hook never multiplies it).
	WARPTimeout time.Duration

	// DebugLogging, when non-nil, receives one line per dialed stream:
	// "routing: <host>:<port> → <outbound> (rule <id>)". It is the
	// SPLIT_ROUTING_DEBUG sink; at the default level it is nil.
	DebugLogging func(format string, args ...any)

	// WARPTransport, when non-nil, replaces the default TCP transport
	// for reaching the WARP SOCKS endpoint (tests inject a fake).
	WARPTransport DialFunc

	// SkipWARPProtocol: when true, the SOCKS5 handshake/CONNECT
	// exchange is omitted and the raw connection is returned as the
	// "warp outbound" tunnel to the target. Production is false.
	// (The endpoint is then expected to behave as a plain TCP
	// forwarder, e.g. a local test fake.)
	SkipWARPProtocol bool
}

const warpDefaultTimeout = 5 * time.Second

// ErrWARPAddrNotConfigured is returned when a warp outbound is needed
// but the endpoint address is empty.
var ErrWARPAddrNotConfigured = errors.New("routing: WARP SOCKS endpoint address is not configured (SPLIT_WARP_SOCKS_ADDR)")

// New builds an Engine. Rules and Direct are required. WARPAddr is
// required when the rule set (any rule or the default) can produce a
// warp outbound; when it is empty and any warp routing is configured,
// a validation error is returned.
func New(cfg Config) (*Engine, error) {
	if cfg.Rules == nil {
		return nil, errors.New("routing: Rules is required")
	}
	if cfg.Direct == nil {
		return nil, errors.New("routing: Direct dial is required")
	}
	if cfg.WARPTimeout <= 0 {
		cfg.WARPTimeout = warpDefaultTimeout
	}

	needsWARP := cfg.Rules.DefaultAction == "warp"
	for i := range cfg.Rules.Rules {
		if cfg.Rules.Rules[i].Action == "warp" {
			needsWARP = true
			break
		}
	}
	if needsWARP && cfg.WARPAddr == "" {
		return nil, ErrWARPAddrNotConfigured
	}

	var transport DialFunc
	if cfg.WARPTransport != nil {
		transport = cfg.WARPTransport
	} else {
		transport = func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, cfg.WARPTimeout)
		}
	}

	return &Engine{
		rs:        cfg.Rules,
		direct:    cfg.Direct,
		warpAddr:  cfg.WARPAddr,
		warpDial:  transport,
		warpProto: !cfg.SkipWARPProtocol,
		warpTO:    cfg.WARPTimeout,
		debugLog:  cfg.DebugLogging,
	}, nil
}

// Rules returns the engine's rule set (read-only use).
func (e *Engine) Rules() *RuleSet { return e.rs }

// DefaultOutbound returns the default outbound kind (the one used when
// no rule matches).
func (e *Engine) DefaultOutbound() OutboundKind {
	k, _ := ParseOutboundKind(e.rs.DefaultAction)
	return k
}

// ---------------------------------------------------------------------------
// Dial — the per-stream entry point the Germany node's TargetDial wraps
// ---------------------------------------------------------------------------

// Dial evaluates the destination and dials it through the selected
// outbound. addr is "host:port" (the form node.TargetDial receives
// from bootstrapUpStream: net.JoinHostPort(dest.Addr, port)).
//
// Outbound behavior:
//   - direct → the engine's Direct dial (byte-identical to the
//     pre-routing policy dial).
//   - block  → ErrBlocked (the stream bootstrap drops it cleanly).
//   - warp   → SOCKS5h CONNECT through the WARP endpoint. On a
//     UNREACHABLE endpoint: fallback="direct" rules fall back to the
//     direct dial; everything else (fail-closed default) returns
//     ErrWarpUnreachable so the stream is refused with a clear reason.
//     On a reachable endpoint whose SOCKS CONNECT fails on the
//     TARGET (REP 4-7) or whose connection dies: the error is
//     returned AS-IS (no fallback — the target failed inside WARP;
//     silently leaking it onto the direct path is what the gate
//     prevents).
//
// The destination is logged ONLY when debug logging is enabled.
func (e *Engine) Dial(addr string) (net.Conn, error) {
	host, port, ok := SplitHostPort(addr)
	if !ok {
		return nil, fmt.Errorf("routing: malformed target address %q", addr)
	}
	dst := &Destination{Host: host, Port: port}
	kind, ruleID := e.rs.Evaluate(dst)
	rule := e.ruleByID(ruleID)

	switch kind {
	case OutboundBlock:
		e.logDecision(addr, kind, ruleID)
		return nil, ErrBlocked

	case OutboundDirect:
		e.logDecision(addr, kind, ruleID)
		return e.direct(addr)

	case OutboundWarp:
		conn, err := e.dialWarp(addr)
		if err == nil {
			e.logDecision(addr, kind, ruleID)
			return conn, nil
		}
		// Health gate: fall back to direct ONLY when the endpoint is
		// UNREACHABLE AND this rule (explicitly) says fallback=direct.
		if errors.Is(err, ErrWarpUnreachable) && rule != nil && rule.Fallback == "direct" {
			e.logDecision(addr, OutboundDirect, ruleID+" (fallback from warp)")
			return e.direct(addr)
		}
		e.logDecision(addr, kind, ruleID+" (failed: "+shortErr(err)+")")
		return nil, err
	}

	// Unreachable (kind is validated in Sanitize).
	return nil, fmt.Errorf("routing: unknown outbound %v", kind)
}

// ruleByID resolves the rule that produced a decision (nil for the
// default outbound).
func (e *Engine) ruleByID(id string) *Rule {
	if id == "" {
		return nil
	}
	for i := range e.rs.Rules {
		if e.rs.Rules[i].ID == id {
			return &e.rs.Rules[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// WARP SOCKS5h outbound
// ---------------------------------------------------------------------------

// dialWarp reaches the WARP SOCKS5 endpoint and issues a SOCKS5
// CONNECT (SOCKS5h semantics: the destination is passed as a DOMAIN
// name so DNS resolution happens INSIDE WARP — not on this host —
// keeping egress attribution on the WARP side). The CONNECT target is
// the original (host, port); a literal-IP host is passed as an IP
// address-form SOCKS target, and a domain host is passed as a
// domain-form target.
//
// Error classification (drives the health gate in Dial):
//   - the TCP connect to the endpoint, or any failure of the protocol
//     exchange BEFORE the server's CONNECT reply, is wrapped with
//     ErrWarpUnreachable (the endpoint is down / misconfigured).
//   - the server's CONNECT reply with REP != 0 (target refused, host
//     unreachable, ...), or a read/write error AFTER the endpoint
//     accepted the protocol, is returned unwrapped: the endpoint
//     reached the target (or its policy) and the result is a
//     target-level failure, not an endpoint-level one. No fallback
//     applies to these.
func (e *Engine) dialWarp(addr string) (net.Conn, error) {
	host, port, _ := SplitHostPort(addr) // always ok (checked in Dial)

	// 1) Reach the SOCKS endpoint.
	proxy, err := e.warpDial(e.warpAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWarpUnreachable, err)
	}

	if e.warpProto {
		// 2) SOCKS5 handshake: no-auth.
		if _, err := proxy.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			proxy.Close()
			return nil, fmt.Errorf("%w: handshake: %v", ErrWarpUnreachable, err)
		}
		if _, err := io.CopyN(io.Discard, proxy, 2); err != nil {
			proxy.Close()
			return nil, fmt.Errorf("%w: handshake read: %v", ErrWarpUnreachable, err)
		}

		// 3) CONNECT command: domain form when the host is a name
		//    (SOCKS5h: DNS inside WARP), IP form for literals.
		req := buildConnectReq(host, port)
		if _, err := proxy.Write(req); err != nil {
			proxy.Close()
			return nil, fmt.Errorf("%w: connect write: %v", ErrWarpUnreachable, err)
		}

		// 4) Read the CONNECT reply header: ver(1) rep(1) rsv(1)
		//    atype(1), then the address block, then port(2).
		head := make([]byte, 4)
		if _, err := io.ReadFull(proxy, head); err != nil {
			proxy.Close()
			return nil, fmt.Errorf("%w: connect reply: %v", ErrWarpUnreachable, err)
		}
		if head[1] != 0 {
			// REP != 0: the endpoint reached a policy/target outcome.
			// This is a TARGET-LEVEL result, not an endpoint-unreachable
			// one: no fallback. (Error text carries the REP byte, never
			// the destination.)
			proxy.Close()
			return nil, fmt.Errorf("warp socks CONNECT refused by endpoint (rep=%d)", head[1])
		}
		if err := readAddrBlock(proxy, head[3]); err != nil {
			proxy.Close()
			return nil, fmt.Errorf("warp socks CONNECT reply malformed: %v", err)
		}
	}

	// The connection is now the tunnel to the target (through WARP).
	return proxy, nil
}

// buildConnectReq renders the SOCKS5 CONNECT request byte string.
func buildConnectReq(host string, port int) []byte {
	var buf []byte
	buf = append(buf, 0x05, 0x01, 0x00) // ver, cmd CONNECT, rsv
	if ip := net.ParseIP(host); ip != nil {
		// IP-form target.
		var addr []byte
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x01)
			addr = v4
		} else {
			buf = append(buf, 0x04)
			addr = ip.To16()
		}
		buf = append(buf, addr...)
	} else {
		// Domain-form target (SOCKS5h semantics: DNS in WARP).
		hb := []byte(host)
		if len(hb) > 255 {
			hb = hb[:255]
		}
		buf = append(buf, 0x03, byte(len(hb)))
		buf = append(buf, hb...)
	}
	var p [2]byte
	p[0] = byte(port >> 8)
	p[1] = byte(port & 0xFF)
	buf = append(buf, p[:]...)
	return buf
}

// readAddrBlock consumes the address block of a SOCKS5 reply based on
// its address type byte (0x01 IPv4, 0x04 IPv6, 0x03 domain).
func readAddrBlock(r io.Reader, atype byte) error {
	switch atype {
	case 0x01:
		return readN(r, 4+2) // 4 ip + 2 port
	case 0x04:
		return readN(r, 16+2)
	case 0x03:
		return readDomainAddrBlock(r)
	default:
		return fmt.Errorf("unknown address type 0x%02x", atype)
	}
}

func readDomainAddrBlock(r io.Reader) error {
	lb := make([]byte, 1)
	if _, err := io.ReadFull(r, lb); err != nil {
		return err
	}
	return readN(r, int(lb[0])+2) // len bytes + 2 port bytes
}

func readN(r io.Reader, n int) error {
	if n <= 0 {
		return nil
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return err
}

// shortErr returns a compact, credential-free form of an error for the
// debug log line (never the destination).
func shortErr(err error) string {
	s := err.Error()
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

// logDecision emits the per-dial debug line when enabled. At the
// default (debug off, e.debugLog nil) NOTHING is logged: no
// destination, no rule id, no outbound.
func (e *Engine) logDecision(addr string, kind OutboundKind, ruleID string) {
	if e.debugLog == nil {
		return
	}
	e.debugLog("routing: %s → %s%s", addr, kind, ruleRef(ruleID))
}

func ruleRef(id string) string {
	if id == "" {
		return " (default)"
	}
	return " (rule " + id + ")"
}
