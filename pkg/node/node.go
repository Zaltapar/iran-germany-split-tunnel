// Package node is one side of the split tunnel: the engine that owns
// the carrier transports, their replacement (Phase 5), and the sessions
// riding on them. Both binaries (Iran / Germany) are thin transport
// wrappers around a Node.
//
// Phase 5 model:
//
//   - a SESSION owns the logical stream (stable StreamID, sockets,
//     lifecycle — see pkg/session);
//   - a CARRIER is a replaceable transport. Each installed carrier has a
//     monotonically increasing generation per node+direction;
//   - a session's binding to a carrier per direction is an Attachment
//     (session.Attachment): Attached(gen) / Unavailable(grace) /
//     Rebinding / Closed.
//
// Carrier loss (either direction):
//  1. the carrier's watcher detaches every session bound to that
//     generation — each attachment enters Unavailable and a bounded
//     grace window (Config.Grace) starts;
//  2. upload-side data already read from the socket sits in a bounded
//     pending buffer (Config.BufferBytes) and is flushed in order when a
//     replacement carrier attaches — no unbounded memory, backpressure
//     all the way to the socket when full;
//  3. the Iran node (stream originator) initiates the rebind on every
//     (re)established carrier: Register(streamID) + FrameRebind as the
//     FIRST frame of the stream + Attach(newGen);
//  4. the Germany node re-attaches the EXISTING session when the
//     FrameRebind arrives (it never creates a session on rebind);
//  5. a session that has not re-attached by the end of the grace window
//     is closed through the Phase 4 lifecycle with reason
//     "upload/download carrier timeout".
//
// Stale-carrier protection is by generation: a carrier-death event only
// detaches the sessions bound to ITS generation, a superseded consumer
// relay drops its late frames (it never writes a superseded epoch's data
// to the socket), and a FrameRebind is rejected unless its sender
// generation is strictly greater than the last accepted one.
//
// Independent directions: an up-carrier loss only detaches up
// attachments (and vice versa); a half-closed direction closes its
// attachment and is never re-bound, so a client FIN stays a half-close
// across carrier failures.
package node

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// Role identifies which side of the tunnel a Node operates.
type Role int

const (
	// RoleIran is the client-facing side: it owns the SOCKS client
	// sessions, originates every logical stream (up FrameHeader, down
	// stream registration) and INITIATES FrameRebind on both carriers.
	RoleIran Role = iota
	// RoleGermany is the target-facing side: it bootstraps sessions from
	// up-carrier FrameHeaders and RESPONDS to FrameRebind by re-attaching
	// an existing session.
	RoleGermany
)

// Config parameterizes a Node. Sanitize fills defaults for zero values.
type Config struct {
	Role Role
	// Grace bounds the carrier-loss recovery window per direction
	// (SPLIT_CARRIER_GRACE; default 5s). A session not re-attached within
	// the window is closed with an explicit carrier-timeout reason.
	Grace time.Duration
	// BufferBytes bounds each session direction's pending reconnect
	// buffer (SPLIT_SESSION_BUFFER_BYTES; default 256 KiB). When full the
	// relay applies backpressure (stops reading the socket) instead of
	// growing memory.
	BufferBytes int
	// SessionBufferTotalBytes bounds the SUM of ALL shape-A pending
	// reconnect buffers on this node (Issue #6; SPLIT_SESSION_BUFFER_
	// TOTAL_BYTES; default 32 MiB, see defaultSessionBufferTotal). When
	// exhausted, additional buffer fills are refused and the relays stop
	// reading their sockets — backpressure to the client/target, exactly
	// as the per-buffer-full case — so the aggregate can never silently
	// exceed the budget. 0 is lifted to the default by Sanitize. See
	// budget.go for the exact accounting invariant and the fair-refusal
	// policy.
	SessionBufferTotalBytes int
	// RelayBufSize is the socket read-buffer size (default 32 KiB).
	RelayBufSize int
	// KeepAliveInterval is the carrier ping period (default 30s).
	KeepAliveInterval time.Duration
	// LivenessRounds is the number of consecutive unanswered keepalive
	// pings after which the carrier is declared blackholed and torn down
	// through the normal carrier-loss/rebind machinery (default 3, i.e.
	// ~45s at the default ping period). <=0 falls back to the library
	// default (mux.DefaultLivenessRounds).
	LivenessRounds int
	// BootstrapWait bounds the bootstrap wait for a carrier that is
	// temporarily down (SPLIT_BOOTSTRAP_WAIT_MS; default 30s). Iran: how
	// long StartSession waits for BOTH carriers to be ready before
	// failing the SOCKS connection. Germany: how long an up bootstrap
	// waits for the down carrier to become ready before dropping the
	// session (Issue #7). 0 → defaultBootstrapWait.
	BootstrapWait time.Duration
	// StreamLimits is the carrier backpressure policy (Phase 3).
	StreamLimits mux.StreamLimits
	// CreditsEnabled is the Phase B master on/off for credit flow-control
	// (design §15, SPLIT_CREDITS_ENABLED; default OFF). When false the whole
	// credit plane is inert: the sender gate is bypassed, the receiver
	// emitter is a no-op, and recordPeerGen is a no-op — behaviour is
	// byte-identical to the pre-credit build (the pending >= 256 KiB gate
	// plus the mailbox caps remain the sole enforcement). The ctrlCh control
	// plane stays in the binary but idle (carrying only Ping/Pong/Close).
	// This slice ships the flag as a package-level default-off Config field;
	// env-var plumbing lives in Slice 7.
	CreditsEnabled bool
	// TargetOnlyIPv4 is the opt-in HARD only-IPv4 egress-target filter
	// (SPLIT_TARGET_ONLY_IPV4; default false). It only takes effect for
	// the DEFAULT TargetDial (i.e. when TargetDial is nil at Sanitize
	// time): domain hosts resolve to IPv4 A records only and a domain
	// with no A record is refused — never silently dialed over IPv6.
	// Use with care: it breaks AAAA-only endpoints (the 2026-10-07
	// WARP episode: 96 stream refusals in ~13 minutes). Prefer
	// TargetAddrPolicy "prefer-ipv4" for general traffic. Literal IP
	// addresses always dial as given. When a custom TargetDial is
	// supplied it is used as-is and both policy fields are ignored
	// (the caller owns that dialer).
	TargetOnlyIPv4 bool
	// TargetAddrPolicy is the egress-target address-family policy
	// (SPLIT_TARGET_ADDR_POLICY; default "default"). Values:
	//   - "default"     — today's byte-identical dual-stack dial
	//     (net.DialTimeout("tcp", 10s), OS address-family preference);
	//   - "prefer-ipv4" — dial IPv4 candidates first, fall back to
	//     IPv6 only when no IPv4 candidate succeeds (or no IPv4 record
	//     exists). AAAA-only domains still succeed. RECOMMENDED for
	//     dual-homed deployments where the v6 egress leg is the
	//     fragile one;
	//   - "ipv4-only"   — the hard A-record filter, equivalent to
	//     TargetOnlyIPv4=true.
	// Unknown values are a Sanitize error naming the allowed set.
	// Precedence: TargetOnlyIPv4=true (or "ipv4-only") is the stricter
	// policy and wins over "prefer-ipv4"; config.Load rejects the
	// explicit contradiction (TargetOnlyIPv4=true + "prefer-ipv4").
	TargetAddrPolicy string
	// TargetDial dials a logical destination (RoleGermany only).
	// Default (nil): 10s TCP dial, address-family policy per
	// TargetOnlyIPv4 (see target_ipv4.go).
	TargetDial func(addr string) (net.Conn, error)

	// DownCarrierIDs is the STATIC priority order of down-carrier instances
	// (multi-carrier Phase 2, D1). Empty or a single entry = the
	// single-carrier shape (byte-identical to the pre-Phase-2 build,
	// DefaultDownCarrierID). Two entries = a primary plus a standby:
	// new streams pin to the first ready carrier, and a lost carrier's
	// pinned streams may rebind to the other ready down carrier. When len
	// > 1 the rebind wire is v2 (rebindVersionV2) with per-carrier identity.
	DownCarrierIDs []CarrierID
}

// Sanitize replaces zero/negative values with defaults. It returns a loud
// error when the stream limits are inconsistent (MaxBytesTotal <
// MaxBytesPerStream; Phase B B5 amendment) — a misconfiguration that would
// otherwise mask a per-stream admission defect.
func (c *Config) Sanitize() error {
	if c.Grace <= 0 {
		c.Grace = 5 * time.Second
	}
	if c.BufferBytes <= 0 {
		c.BufferBytes = 256 << 10
	}
	if c.SessionBufferTotalBytes <= 0 {
		c.SessionBufferTotalBytes = defaultSessionBufferTotal
	}
	if c.RelayBufSize <= 0 {
		c.RelayBufSize = 32 << 10
	}
	if c.KeepAliveInterval <= 0 {
		c.KeepAliveInterval = 15 * time.Second
	}
	if c.BootstrapWait <= 0 {
		c.BootstrapWait = defaultBootstrapWait
	}
	sl, err := mux.SanitizeLimits(c.StreamLimits)
	if err != nil {
		return err
	}
	c.StreamLimits = sl
	if c.TargetAddrPolicy != "" && !validTargetAddrPolicy(c.TargetAddrPolicy) {
		return fmt.Errorf("unknown target address policy %q (allowed: %q, %q, %q; see SPLIT_TARGET_ADDR_POLICY)",
			c.TargetAddrPolicy, TargetAddrPolicyDefault, TargetAddrPolicyPreferIPv4, TargetAddrPolicyIPv4Only)
	}
	// Merge the legacy hard-filter boolean with the enum policy: the
	// hard filter (ipv4-only) is the stricter of the two and wins.
	onlyIPv4 := c.TargetOnlyIPv4 || c.TargetAddrPolicy == TargetAddrPolicyIPv4Only
	preferIPv4 := c.TargetAddrPolicy == TargetAddrPolicyPreferIPv4
	if c.TargetDial == nil {
		c.TargetDial = newDefaultTargetDial(onlyIPv4, preferIPv4)
	}
	return nil
}

// carrierHandle is one installed carrier transport. Its generation is
// monotonically increasing per node+direction and is the ownership token
// used for stale-carrier protection. id is the carrier instance this handle
// belongs to (Phase 2: a down direction may hold several, one per CarrierID;
// the up direction always holds DefaultUpCarrierID).
type carrierHandle struct {
	carrier *mux.CarrierConn
	gen     uint64
	id      CarrierID
	// done is closed once the carrier's dispatcher has fully exited
	// (read loop dead, all frames consumed).
	done chan struct{}
	// lost is closed once the loss sweep (detach + grace start) for this
	// carrier has finished running.
	lost chan struct{}
}

// Done is closed after the dispatcher has fully exited.
func (h *carrierHandle) Done() <-chan struct{} { return h.done }

// Carrier exposes the underlying mux carrier.
func (h *carrierHandle) Carrier() *mux.CarrierConn { return h.carrier }

// Gen is the carrier's generation.
func (h *carrierHandle) Gen() uint64 { return h.gen }

// defaultSessionBufferTotal is the node-level aggregate session-buffer
// budget default (Issue #6): 32 MiB. At the default per-buffer bound
// (256 KiB) that covers ~128 fully-stalled session-directions before the
// aggregate engages — ample for a healthy node (each buffer fills only
// while its carrier is down AND the peer keeps sending), yet far below
// the OOM territory the unbounded sum reached (hundreds of sessions at
// the 16 MiB per-buffer max setting). Operators raise it for very large
// concurrent-session deployments.
const defaultSessionBufferTotal = 32 << 20 // 32 MiB

// defaultBootstrapWait is the default bootstrap wait for a temporarily
// down carrier (Issue #7): 30s, the historical fixed waitCarriers
// deadline, now explicit and configurable. It is sized to cover the
// carrier reconnect backoff's typical early attempts (2s → 60s cap):
// a carrier that is merely flapping reconnects within a few seconds,
// well inside this window; a carrier that is genuinely down for the
// whole window is treated as down and the bootstrap fails cleanly
// (bounded, cancelable — never an infinite wait).
const defaultBootstrapWait = 30 * time.Second

// Node is the per-side engine.
type Node struct {
	cfg          Config
	store        *session.SessionStore
	metrics      *Metrics
	logger       *log.Logger
	muxUpStats   *mux.QueueStats
	muxDownStats *mux.QueueStats
	secret       []byte

	// buf is the node-level aggregate budget for shape-A reconnect
	// buffers (Issue #6). It is immutable after NewNode (created with
	// the sanitized limit) — explicit ownership, no mutable global.
	buf *sessionBufferBudget

	ctx    context.Context
	cancel context.CancelFunc

	mu sync.RWMutex
	// upReg / downReg are the per-direction carrier registries
	// (multi-carrier-intelligence-design §4.2). The up registry holds
	// exactly ONE entry (D5: single up carrier); the down registry holds
	// one entry PER CarrierID (Phase 2 multi-carrier: a static-priority
	// list of down instances). The registry is the authoritative handle
	// storage. Reconnect accounting is tracked PER CarrierID (a lost
	// carrier is owed exactly one reconnect metric when it comes back up),
	// which generalizes the Phase 1 direction-wide lost flags to the
	// multi-carrier shape (single-carrier reduces to one entry).
	upReg     *carrierRegistry
	downReg   *carrierRegistry
	lostMap   map[CarrierID]bool // per-CarrierID "died since previous install"
	genSeq    uint64
	streamSeq uint32 // atomic counter for logical stream IDs

	// Carrier-readiness signals (Issue #7), the node-level mirror of
	// session.Attachment.ReadySignal: per direction, a channel that is
	// CLOSED while a ready carrier is installed and re-created (open)
	// on loss. Waiters (the bootstrap paths) select on it and MUST
	// re-check ready(dir) after a wake — a wake only means "state
	// changed", not "ready now". They are maintained inside n.mu
	// alongside up/down/lost*, so the signal and the carrier state can
	// never disagree. A closed signal is re-created (open) by
	// onCarrierLost under n.mu the moment the direction becomes not
	// ready, and closed again by install — so a waiter that observes
	// a closed channel always re-checks currentIfReady, and a waiter
	// that observes an open channel knows the direction is down (or
	// was down since its last wake).
	upReady   chan struct{}
	downReady chan struct{}
	// readyClosed mirrors the state of the ready channels (Issue #7):
	// true once the channel is closed, reset when the channel is
	// re-created. Maintained under n.mu, exactly like
	// session.Attachment.readyClosed.
	upReadyClosed   bool
	downReadyClosed bool

	// creditGate is the sender-side credit ledger registry (Phase B).
	// creditEmitter is the receiver-side per-(carrier, streamID) credit
	// emitter (Phase B). Both are nil when CreditsEnabled is false, so
	// every call site guards on nil and the credit plane is fully inert.
	creditGate    *creditGateManager
	creditEmitter *creditEmitter
}

// NewNode creates a Node with the given role, config (sanitized),
// logger and shared secret (used by the transport layer for CarrierAuth
// before InstallUp/InstallDown; the Node itself does not authenticate).
// It returns an error when the config's stream limits are inconsistent
// (Phase B B5 amendment: SanitizeLimits fails loud on
// MaxBytesTotal < MaxBytesPerStream).
func NewNode(cfg Config, logger *log.Logger, secret []byte) (*Node, error) {
	if err := cfg.Sanitize(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	metrics := NewMetrics()
	buf := newSessionBufferBudget(cfg.SessionBufferTotalBytes)
	buf.setMetrics(metrics)
	var creditGate *creditGateManager
	var creditEmitter *creditEmitter
	if cfg.CreditsEnabled {
		creditGate = newCreditGateManager()
		creditEmitter = newCreditEmitter(uint32(cfg.StreamLimits.MaxBytesPerStream))
	}
	downReg := newDownRegistry(cfg.DownCarrierIDs)
	// Phase 2 multi-carrier (D1): when the down direction holds more than one
	// instance, enable the per-carrier /metrics names (loss + reconnect). In
	// single-carrier deployments this is never enabled, so /metrics stays
	// byte-identical to the pre-Phase-2 build.
	if !downReg.SingleEntry() {
		metrics.SetMultiCarrier(downReg.KnownIDs())
	}
	return &Node{
		cfg:           cfg,
		store:         session.NewSessionStore(),
		metrics:       metrics,
		buf:           buf,
		logger:        logger,
		muxUpStats:    &mux.QueueStats{},
		muxDownStats:  &mux.QueueStats{},
		secret:        secret,
		ctx:           ctx,
		cancel:        cancel,
		creditGate:    creditGate,
		creditEmitter: creditEmitter,
		lostMap:       make(map[CarrierID]bool),
		// No carrier installed yet: both directions start NOT ready
		// (open ready channels) — the bootstrap waits must block until
		// a carrier is actually installed (Issue #7).
		upReady:   make(chan struct{}),
		downReady: make(chan struct{}),
		// Phase 2 registries: the up direction is ALWAYS single-carrier
		// (D5). The down direction is single-carrier unless cfg.DownCarrierIDs
		// names two or more instances (multi-carrier ON), in which case it
		// accepts the static-priority list and carries a second standby.
		upReg: newCarrierRegistry(CarrierDescriptor{
			ID:     DefaultUpCarrierID,
			Dir:    session.DirUp,
			Family: FamilyCDNWS,
		}),
		downReg: downReg,
	}, nil
}

// newDownRegistry builds the down-direction registry from the operator's
// static-priority list. An empty or single-element list is the
// single-carrier shape (byte-identical to the pre-Phase-2 build); two
// elements enable the second down instance (multi-carrier ON).
func newDownRegistry(ids []CarrierID) *carrierRegistry {
	if len(ids) > 1 {
		return newMultiCarrierRegistry(session.DirDown, ids)
	}
	// Single-carrier (default): exactly one known down carrier.
	id := DefaultDownCarrierID
	if len(ids) == 1 {
		id = ids[0]
	}
	return newCarrierRegistry(CarrierDescriptor{
		ID:     id,
		Dir:    session.DirDown,
		Family: FamilyReality,
	})
}

// multiDown reports whether the down direction is multi-carrier (two or more
// instances). When true, the rebind wire is v2 (per-carrier identity) and
// the second-instance registry slot is live.
func (n *Node) multiDown() bool { return !n.downReg.SingleEntry() }

// Store is the session store.
func (n *Node) Store() *session.SessionStore { return n.store }

// Secret returns the derived shared secret. The Node does not perform
// the carrier authentication itself; the transport layer (cmd/*) runs
// mux.CarrierAuth with this secret BEFORE handing the authenticated
// connection to InstallUp/InstallDown.
func (n *Node) Secret() []byte { return n.secret }

// Metrics is the metrics set (used by the /metrics handler).
func (n *Node) Metrics() *Metrics { return n.metrics }

// QueueStats returns the fixed queue telemetry surface for one direction.
func (n *Node) QueueStats(dir session.Direction) *mux.QueueStats {
	if dir == session.DirUp {
		return n.muxUpStats
	}
	return n.muxDownStats
}

// Context is cancelled by Close — every wait/park in the node selects on
// it so shutdown unblocks immediately.
func (n *Node) Context() context.Context { return n.ctx }

// Shutdown reports whether Close has been called.
func (n *Node) Shutdown() bool { return n.ctx.Err() != nil }

// Close shuts the node down: cancel the context, close every session
// (Phase 4 authoritative path), close the current carriers, and force-
// reclaim every outstanding session-buffer reservation. Idempotent.
//
// The budget reclamation is authoritative (budget.go): even a relay
// that is parked in a socket read with a partially-reserved chunk at
// this instant has its bytes reclaimed here, so after Close the
// aggregate reports zero accounted bytes and zero active relays and
// main's wg.Wait() completes with no buffer bytes outstanding.
func (n *Node) Close() {
	n.cancel()
	n.store.CloseAll()
	n.mu.Lock()
	n.upReg.CloseAll()
	n.downReg.CloseAll()
	n.mu.Unlock()
	if reclaimed := n.buf.Close(); reclaimed > 0 {
		n.metrics.AddSessionBufferReclaimed(reclaimed)
	}
}

// SessionBufferAccounted is the current node-level aggregate usage of
// the shape-A reconnect buffers in bytes (the session_buffered_bytes
// /metrics gauge, Issue #6).
func (n *Node) SessionBufferAccounted() int64 { return n.buf.AccountedBytes() }

// SessionBufferActiveRelays is the number of shape-A relays currently
// registered with the aggregate budget (white-box leak check; must be
// 0 after Close).
func (n *Node) SessionBufferActiveRelays() int { return n.buf.ActiveRelays() }

// UpReady reports whether a live up carrier is currently installed.
// Phase 1: routes through the up registry's sole entry under the
// Node mutex, so the check-and-capture is atomic (the registry's
// Ready() is read under n.mu.RLock, exactly like the legacy
// n.up field was).
func (n *Node) UpReady() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.upReg.Ready()
}

// DownReady reports whether a live down carrier is currently installed.
// Phase 1: routes through the down registry's sole entry.
func (n *Node) DownReady() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.downReg.Ready()
}

// DownCarrierReady reports whether the down-carrier instance named id is
// currently installed and its read loop is alive. For a single-carrier node
// (id = the registry's sole entry) this is identical to DownReady; for a
// multi-carrier node it lets the transport layer gate each named instance
// independently. Unknown ids (an id not in the down registry's allowed set)
// are reported not-ready (fail-closed) rather than panicking.
func (n *Node) DownCarrierReady(id CarrierID) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.downReg.IsKnown(id) {
		return false
	}
	return n.downReg.Handle(id) != nil
}

// MultiDown exposes whether the node's down direction is multi-carrier. The
// transport layer uses it to decide whether to bring up a second down
// instance (or to emit the v2 rebind wire). Mirrors multiDown() but is part
// of the public surface so cmd/* and tests can branch on it.
func (n *Node) MultiDown() bool { return n.multiDown() }

// DownCarrierIDs returns the node's static down-carrier priority order
// (index 0 = primary). The transport layer maps its own listener/dialer
// endpoints onto these ids when multi-carrier is enabled.
func (n *Node) DownCarrierIDs() []CarrierID {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.downReg.KnownIDs()
}

// SecondaryDownCarrierID returns the down registry's secondary carrier id
// (index 1), used by the transport layer to install/instance the second
// down carrier. When the node is single-carrier (index 1 absent), it returns
// the configured secondary id so a transport that always names it still
// resolves to a known, fail-closed value.
func (n *Node) SecondaryDownCarrierID() CarrierID {
	ids := n.downReg.KnownIDs()
	if len(ids) > 1 {
		return ids[1]
	}
	return SecondDownCarrierID
}

func (n *Node) current(dir session.Direction) *carrierHandle {
	n.mu.RLock()
	defer n.mu.RUnlock()
	// The registry mirror is authoritative. For the (single) up direction
	// this is the sole entry; for the down direction it is the static-
	// priority primary (the first ready carrier in config order).
	if dir == session.DirUp {
		return n.upReg.Primary()
	}
	return n.downReg.Primary()
}

// handleForGen resolves the handle whose generation is gen. Node-global
// generations (n.genSeq) are unique across BOTH directions and BOTH down
// carriers, so at most one handle matches. Used by the relays, which pin to
// a specific attachment generation: the attachment's gen names the exact
// carrier it is bound to, even when several down carriers are installed.
func (n *Node) handleForGen(gen uint64) *carrierHandle {
	if gen == 0 {
		return nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, h := range n.upReg.Handles() {
		if h != nil && h.gen == gen {
			return h
		}
	}
	for _, h := range n.downReg.Handles() {
		if h != nil && h.gen == gen {
			return h
		}
	}
	return nil
}

// currentIfReady returns the current carrier handle for dir if it is
// installed and READY (read loop alive), atomically under the node
// lock. "Installed" alone is not enough: a handle can still be current
// while its read loop has just stopped (loss sweep in flight), and
// Ready() covers that window. The atomic check-and-capture is what
// makes the bootstrap paths (Issue #7) attach to a genuinely live
// generation, never a stale one.
func (n *Node) currentIfReady(dir session.Direction) *carrierHandle {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if dir == session.DirUp {
		return n.upReg.Primary()
	}
	return n.downReg.Primary()
}

// currentIfReadyBoth is the two-direction snapshot: both handles are
// captured under ONE lock, so the waiters that need both (Iran
// StartSession) never pair a ready up carrier with an already-dead
// down carrier (Issue #7).
func (n *Node) currentIfReadyBoth() (upH, downH *carrierHandle) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	upH = n.upReg.Primary()
	downH = n.downReg.Primary()
	return upH, downH
}

// dropIfCurrent clears the registry entry for dir that still points at h
// (loss-sweep backstop: a dying carrier only clears its own slot when it is
// still current for that CarrierID).
func (n *Node) dropIfCurrent(dir session.Direction, h *carrierHandle) {
	n.mu.Lock()
	if dir == session.DirUp {
		n.upReg.ClearIf(h.id, h)
	} else {
		n.downReg.ClearIf(h.id, h)
	}
	n.mu.Unlock()
}

// nextStreamID allocates the next logical stream ID. It never repeats
// within the process (wrap-around would take 2^32 sessions); the rebind
// protocol cross-checks StreamID against SessionID regardless. On the
// 32-bit wrap the counter passes through 0 — the stream ID reserved for
// protocol/control frames — so that value is skipped: a session can never
// be allocated stream 0 (Register(0) is refused, and a session with ID 0
// would collide with FrameAuth/Ping/Pong/Close on the control stream).
func (n *Node) nextStreamID() uint32 {
	for {
		id := atomic.AddUint32(&n.streamSeq, 1)
		if id != 0 {
			return id
		}
	}
}

// onGraceTimeout is the attachment timer callback: the carrier-loss
// recovery window expired without a rebind. The session is closed
// through the Phase 4 lifecycle with an explicit reason.
func (n *Node) onGraceTimeout(sess *session.Session, dir session.Direction) {
	if sess.DirClosed(dir) {
		// The direction finished logically during the loss window —
		// there is nothing to recover; the session may still live on
		// the other direction.
		return
	}
	n.metrics.SessionLostAfterFailure()
	n.logger.Printf("session %s: %s not reattached within grace, closing",
		shortID(sess.ID), dirName(dir))
	sess.Close(carrierTimeoutReason(dir))
}

// InstallUp installs an authenticated upload-carrier transport as the
// current up carrier (closing a still-live previous one, if any) and
// starts its watcher. The transport layer must have completed
// CarrierAuth on the connection first. It then runs the Phase 5 rebind
// sweep (Iran only) so sessions in their grace window re-attach.
func (n *Node) InstallUp(conn io.ReadWriteCloser, br *bufio.Reader) *carrierHandle {
	h, err := n.installFor(n.upReg.ID(), session.DirUp, conn, br)
	if err != nil {
		// An unknown up id is a misconfiguration; the up registry only
		// ever knows DefaultUpCarrierID, so this cannot fire in practice.
		conn.Close()
		n.logger.Printf("install up carrier: %v", err)
	}
	return h
}

// InstallDown installs an authenticated download-carrier transport on the
// down direction's PRIMARY carrier (the single-carrier / default path). For
// a multi-carrier down plane, the transport layer instead names the specific
// instance it just authenticated via InstallDownOn.
func (n *Node) InstallDown(conn io.ReadWriteCloser, br *bufio.Reader) *carrierHandle {
	h, err := n.installFor(n.downReg.ID(), session.DirDown, conn, br)
	if err != nil {
		conn.Close()
		n.logger.Printf("install down carrier: %v", err)
	}
	return h
}

// InstallDownOn installs an authenticated download-carrier transport as the
// carrier instance named by id (multi-carrier, Phase 2). id must be one of
// the down registry's known IDs; an unknown id is rejected (fail-closed,
// ErrUnknownCarrierID) and the transport is closed. The rebind sweep runs
// only when this is the direction's currently-losing carrier being replaced
// (the existing loss-driven logic, now keyed per CarrierID).
func (n *Node) InstallDownOn(id CarrierID, conn io.ReadWriteCloser, br *bufio.Reader) (*carrierHandle, error) {
	h, err := n.installFor(id, session.DirDown, conn, br)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return h, nil
}

func (n *Node) installFor(id CarrierID, dir session.Direction, conn io.ReadWriteCloser, br *bufio.Reader) (*carrierHandle, error) {
	// Bind the auth bufio.Reader inside the constructor: the carrier's
	// read loop starts immediately and latches its read buffer on the
	// first read, so any bytes the auth reader already pulled from the
	// transport (e.g. a FrameRebind written right after the handshake)
	// must be bound BEFORE the loop starts. Installing the reader
	// afterwards (NewCarrierConn + SetReadBuffer) races the first read
	// and can orphan those bytes.
	var c *mux.CarrierConn
	if br != nil {
		c = mux.NewCarrierConnWithReader(conn, n.cfg.KeepAliveInterval, br)
	} else {
		c = mux.NewCarrierConn(conn, n.cfg.KeepAliveInterval)
	}
	// The config's stream limits were sanitized (and consistency-checked) in
	// NewNode, so SetStreamLimits cannot fail here in practice; discard the
	// error explicitly (availability over integrity: a carrier install must
	// never be torn down on an impossible misconfiguration case).
	_ = c.SetStreamLimits(n.cfg.StreamLimits)
	c.SetQueueStats(n.QueueStats(dir))
	if n.cfg.LivenessRounds > 0 {
		c.SetLivenessRounds(n.cfg.LivenessRounds)
	}
	c.OnStreamTerminated = func(streamID uint32) {
		if sess, ok := n.store.ByStream(streamID); ok {
			sess.Stats.MarkTerminated()
		}
	}
	c.OnStreamDataUndeliverable = func(streamID uint32) {
		if sess, ok := n.store.ByStream(streamID); ok {
			sess.Stats.MarkDataUndeliverable()
		}
	}

	n.mu.Lock()
	// Validate the carrier id against the direction's registry up front
	// (fail-closed on an unknown id — design §4.4). The registry returns the
	// previous handle for that ID (nil on first install or a disconnect).
	reg := n.downReg
	if dir == session.DirUp {
		reg = n.upReg
	}
	if !reg.IsKnown(id) {
		n.mu.Unlock()
		return nil, fmt.Errorf("%w: direction %s, got %q", ErrUnknownCarrierID, dirName(dir), id)
	}
	n.genSeq++
	h := &carrierHandle{carrier: c, gen: n.genSeq, id: id, done: make(chan struct{}), lost: make(chan struct{})}
	old, _ := reg.Add(id, h) // replace-on-install per CarrierID
	wasLost := n.lostMap[id]
	delete(n.lostMap, id)
	// Carrier installed and (by construction) ready: mark the direction's
	// ready signal so the bootstrap waits can wake (Issue #7). Flag-
	// guarded so a still-closed channel is not double-closed.
	if dir == session.DirUp {
		if !n.upReadyClosed {
			close(n.upReady)
			n.upReadyClosed = true
		}
	} else {
		if !n.downReadyClosed {
			close(n.downReady)
			n.downReadyClosed = true
		}
	}
	n.mu.Unlock()
	if wasLost {
		n.metrics.CarrierReconnect()
		n.metrics.CarrierReconnectOn(h.id)
	}
	reconnectCounted := wasLost
	if old != nil {
		// A replacement arrived while the old carrier was still current
		// (it is either already dying or just being terminated). Wait
		// (bounded) for its loss sweep to finish BEFORE running the
		// rebind sweep, so the loss metrics and the detachment are
		// settled; the sweep also force-detaches as a backstop.
		old.carrier.Close()
		lossSettled := false
		select {
		case <-old.lost:
			lossSettled = true
		case <-time.After(5 * time.Second):
			n.logger.Printf("carrier %s: previous carrier loss sweep did not finish within 5s", dirName(dir))
		}
		if lossSettled {
			// Reconnect accounting is loss-driven, not install-snapshot-
			// driven: the old carrier's loss sweep (onCarrierLost) may
			// have run AFTER this install took the flag, in which case
			// wasLost was false although the old carrier did die. Now
			// that old.lost is closed, the sweep fully completed (lost
			// flag set + CarrierLossEvent counted), so the reconnect is
			// owed exactly once, whether or not wasLost was true.
			if !reconnectCounted {
				n.metrics.CarrierReconnect()
				n.metrics.CarrierReconnectOn(h.id)
				reconnectCounted = true
			}
			// Settle a stale lost flag: the sweep may have set it after
			// the clear above (install-before-sweep ordering); the loss
			// is now fully accounted for and the flag must not leak into
			// the next replacement. Keyed per CarrierID (the id being
			// reinstalled, `h.id`), not direction-wide.
			n.mu.Lock()
			delete(n.lostMap, h.id)
			n.mu.Unlock()
			_ = old
		}
	}

	// OnNewStream is set BEFORE Dispatch starts, so there is no window
	// in which a first frame could be seen without the callback.
	if n.cfg.Role == RoleGermany {
		if dir == session.DirUp {
			c.OnNewStream = func(id uint32, firstType uint8, ch chan []byte) {
				n.onUpNewStream(h, id, firstType, ch)
			}
		} else {
			c.OnNewStream = func(id uint32, firstType uint8, ch chan []byte) {
				n.onDownNewStream(h, id, firstType, ch)
			}
		}
	}

	// Phase B (Slice 5): on the Germany DOWN carrier — the carrier the
	// DATA sender writes to — accept the receiver's credits into the
	// ledger (design §5). The callback fires in the dispatcher goroutine
	// OUTSIDE c.mu and must not block: the onCredit work is O(1). The
	// incoming gen is validated (StaleCreditGeneration) and clamped to
	// the CARRIER's live MaxBytesPerStream (Limits(), SF-4) — never the
	// node config. Inert when credits are disabled (n.creditGate is nil).
	if n.creditGate != nil && n.cfg.Role == RoleGermany && dir == session.DirDown {
		c.OnStreamCredit = func(id uint32, p mux.CreditPayload) {
			capBytes := uint64(c.Limits().MaxBytesPerStream) // SF-4
			if n.creditGate.ledger(h.gen, id).onCredit(p, h.gen, capBytes) {
				// A live credit was accepted: un-arm the per-stream
				// CreditSafeTimeout fallback timer so it cannot degrade
				// a healthy ledger (Slice 6). O(1), outside c.mu.
				n.creditGate.cancelTimer(id)
			}
		}
	}

	go func() {
		c.Dispatch()
		close(h.done)
		// Phase 5: mark the carrier lost — detach the sessions bound to
		// THIS generation and start their grace windows. Then close the
		// carrier (stream channels close; per-epoch consumers drain and
		// exit) and drop the handle if it is still current.
		n.onCarrierLost(dir, h)
		close(h.lost)
		c.Close()
		n.dropIfCurrent(dir, h)
	}()

	n.logger.Printf("carrier %s (id %s) ready (gen %d)", dirName(dir), h.id, h.gen)
	n.onCarrierReady(dir, h)
	return h, nil
}

// onCarrierLost runs when a carrier's dispatcher has exited. The detach is
// scoped to the sessions pinned to THIS carrier instance (h.id, h.gen): a
// stream pinned to a DIFFERENT healthy down carrier is never touched — only
// the lost carrier's pinned streams enter the grace window and may rebind to
// another healthy carrier (design §7.2/§7.3).
func (n *Node) onCarrierLost(dir session.Direction, h *carrierHandle) {
	n.mu.Lock()
	n.lostMap[h.id] = true
	// Only re-create (open) the direction's ready signal if NO other carrier
	// in the direction is still ready. In the single-carrier case this is
	// always true. In multi-carrier, if a standby down carrier is still up
	// the direction stays Ready (closed signal) and bootstrap waiters keep
	// their ready snapshot; the lost carrier's pinned streams rebind to the
	// surviving carrier (see the detach sweep below + rebindDirection).
	reg := n.downReg
	if dir == session.DirUp {
		reg = n.upReg
	}
	reg.ClearIf(h.id, h) // this carrier is dying; drop its slot if still current
	if dir == session.DirUp {
		if !n.upReg.Ready() {
			n.upReady = make(chan struct{})
			n.upReadyClosed = false
		}
	} else {
		if !n.downReg.Ready() {
			n.downReady = make(chan struct{})
			n.downReadyClosed = false
		}
	}
	n.mu.Unlock()
	n.metrics.CarrierLossEvent()
	n.metrics.CarrierLossEventOn(h.id)
	n.logger.Printf("carrier %s lost (gen %d); grace window %s for affected sessions",
		dirName(dir), h.gen, n.cfg.Grace)

	for _, sess := range n.store.Snapshot() {
		att := sess.Att(dir)
		if att == nil {
			continue
		}
		// Generation-guarded: only sessions bound to this exact carrier
		// are detached. A session that already moved to a newer carrier
		// is untouched (stale-carrier protection).
		if att.Detach(h.gen) {
			n.logger.Printf("session %s: %s transport lost, grace %s",
				shortID(sess.ID), dirName(dir), n.cfg.Grace)
		}
	}

	// Phase 2 (D1) hot-standby failover: when OTHER carriers in this
	// direction are still Active (ready) after this loss — the F1 "re-attach
	// within grace" case — the detached sessions immediately re-attach onto
	// the surviving carrier rather than waiting for a fresh install. The
	// standby never went down, so no install runs onCarrierReady; the loss
	// itself must trigger the rebind sweep. Only the stream originator
	// (RoleIran) runs the sweep; the peer (Germany) re-attaches in response
	// to the resulting FrameRebind (v2, naming the surviving carrier). We
	// re-attach to the HIGHEST-PRIORITY survivor only (D1: K=2, static
	// priority): a session already moved onto it is not swept again.
	if n.cfg.Role == RoleIran {
		reg := n.downReg
		if dir == session.DirUp {
			reg = n.upReg
		}
		for _, survivor := range reg.ReadyExcept(h.id) {
			n.logger.Printf("carrier %s lost; failing over pinned streams to surviving carrier %s",
				h.id, survivor.id)
			n.rebindDirection(dir, survivor)
			break
		}
	}
}

// onCarrierReady runs after a carrier is installed. Iran (the stream
// originator) rebinds eligible sessions onto it; Germany only
// re-attaches in response to FrameRebind frames (the peer controls the
// ordering between re-register and resumed data).
func (n *Node) onCarrierReady(dir session.Direction, h *carrierHandle) {
	if n.cfg.Role != RoleIran {
		return
	}
	n.rebindDirection(dir, h)
}

// encodeRebind builds the FrameRebind payload for carrier h. When the node
// is multi-carrier it emits the v2 payload (version + carrier ID + generation)
// so the peer can re-attach to the specific carrier this stream rebinds onto;
// otherwise it emits the byte-identical v1 payload so single-carrier peers
// (and the golden byte stream) are unaffected. This is the "capability
// negotiation" half of D9: the wire version is chosen from local state, and
// receivers accept both versions (see ParseRebindAny).
func (n *Node) encodeRebind(sessID session.SessionID, h *carrierHandle) []byte {
	if n.multiDown() {
		return session.EncodeRebindV2(sessID, string(h.id), h.gen)
	}
	return session.EncodeRebind(sessID, h.gen)
}

// rebindDirection re-attaches every eligible session's dir attachment
// to the carrier h. Eligible = Active session, direction not
// half-closed, attachment Unavailable (inside its grace window). The
// logical stream ID is preserved — no new session, no duplicate active
// session for one logical stream.
func (n *Node) rebindDirection(dir session.Direction, h *carrierHandle) {
	for _, sess := range n.store.Snapshot() {
		if n.ctx.Err() != nil {
			return
		}
		if sess.State() != session.StateActive {
			continue
		}
		att := sess.Att(dir)
		if att == nil {
			continue
		}
		if sess.DirClosed(dir) {
			continue // direction logically done — never re-bind it
		}
		st, g := att.State()
		switch st {
		case session.AttAttached:
			// Bound to a superseded carrier whose loss sweep may not
			// have run yet (fast replacement): detach it explicitly so
			// the rebind can proceed. Already on this exact carrier:
			// skip (no double rebind).
			if g == h.gen {
				continue
			}
			if !att.Detach(g) {
				// Lost the race to the loss sweep — re-check: proceed
				// only if we are now Unavailable.
				st2, _ := att.State()
				if st2 != session.AttUnavailable {
					continue
				}
			}
			fallthrough
		case session.AttUnavailable:
			// proceed to rebind
		default:
			continue
		}
		if !att.BeginRebind() {
			continue // lost the claim race
		}

		id := streamIDOf(sess, dir)
		ch := h.carrier.Register(id)
		if ch == nil {
			n.failRebind(sess, dir, att, "stream registration failed")
			continue
		}
		// FrameRebind MUST be the first frame of this stream on the new
		// carrier: the peer's OnNewStream branches on its type, and any
		// user data arriving first would be dropped as malformed.
		if err := h.carrier.WriteFrame(id, mux.FrameRebind, n.encodeRebind(sess.ID, h)); err != nil {
			h.carrier.Deregister(id)
			n.failRebind(sess, dir, att, "rebind frame write failed: "+err.Error())
			continue
		}
		// Attach BEFORE starting the consumer: the consumer's strict
		// generation guard only acts while the attachment is bound to
		// h.gen, so attaching first removes any window in which a
		// fresh frame could be seen by a not-yet-current consumer.
		if !att.Attach(h.gen) {
			// The session closed or its direction half-closed while
			// the rebind was in flight.
			h.carrier.Deregister(id)
			att.FailRebind()
			n.metrics.RebindRefusal("other")
			continue
		}
		// Phase B (Slice 6): rebind-attach resets the credit plane for the
		// down (data) direction. The sender-side ledger re-pins to the new
		// carrier gen (re-entering the bounded UNLATCHED state) and the
		// receiver-side emitter record is cleared; the attach-time anchor is
		// then emitted GO-SPAWNED (B3: never inline in this Dispatch/attach
		// context — the spawned goroutine may outlive the carrier, and
		// TryWriteControlFrame then returns (false, ErrCarrierClosed) and
		// the goroutine drops silently without leaking). Inert when credits
		// are disabled (both pointers nil).
		if dir == session.DirDown {
			if n.creditGate != nil {
				n.creditGate.resetStream(h.gen, id)
			}
			if n.creditEmitter != nil {
				// Reset the record, then stamp peerGen: recordPeerGen
				// creates/updates the record and resetStream deletes it, so
				// the stamp must come AFTER the reset or subsequent data
				// credits would carry a zero (rejected) peer gen. h.gen is
				// this node's down generation; down generations are lockstep
				// across both nodes, so it is the peer gen the peer's gate
				// ledger is pinned to.
				//
				// SUBTASK 25 fix: do NOT emit the attach-time anchor here.
				// A down rebind is a CARRIER RECONNECT: the peer's new
				// generation has an EMPTY stream map until it processes this
				// stream's FrameRebind. A go-spawned anchor would race ahead
				// of that rebind and arrive as a FrameCredit on an
				// UNREGISTERED stream, which the mux read loop treats as a
				// connection-level fatal (ErrCreditUnknownStream,
				// carrier.go:300-314) and tears the peer's down carrier down
				// — the production reconnect STORM (carrier_loss_events 115,
				// gen 36->130). The sender is already bounded by the 640 KiB
				// creditPreLatchBound (UNLATCHED) plus the per-stream
				// CreditSafeTimeout timer armed in resetStream above, and the
				// first real data credit (relays.go recordConsumed->emit)
				// latches the gate — so omitting the anchor preserves the
				// plan's "bound the sender" intent without killing the
				// carrier. Symmetric with the fresh StartSession path
				// (node.go:1066-1082), which deliberately omits the down
				// anchor for the same reason.
				key := carrierKey{carrier: h.carrier, streamID: id}
				n.creditEmitter.resetStream(key)
				n.creditEmitter.recordPeerGen(key, h.gen)
			}
		}
		if n.hasChannelConsumer(dir) {
			// Wait (bounded) for the previous carrier's consumer to
			// fully exit so two consumers never write the same
			// socket. Now that the attachment is bound to h.gen, the
			// old consumer's strict generation guard drops its
			// remaining frames and it exits promptly.
			if !att.JoinEpoch(n.cfg.Grace) {
				n.logger.Printf("session %s: previous %s consumer did not exit within %s; continuing under the generation guard",
					shortID(sess.ID), dirName(dir), n.cfg.Grace)
			}
			n.startChannelConsumer(sess, dir, h, ch)
		}
		n.metrics.Rebind()
		n.metrics.SessionRecovered()
		n.logger.Printf("session %s: %s reattached to carrier gen %d",
			shortID(sess.ID), dirName(dir), h.gen)
	}
}

// failRebind abandons one rebind attempt (grace window keeps running).
func (n *Node) failRebind(sess *session.Session, dir session.Direction, att *session.Attachment, why string) {
	att.FailRebind()
	n.metrics.RebindRefusal("other")
	n.logger.Printf("session %s: %s rebind failed: %s", shortID(sess.ID), dirName(dir), why)
}

// hasChannelConsumer reports whether this node runs a per-carrier-epoch
// consumer for the direction (up watcher on Iran; data relay on
// Germany-up and Iran-down). Germany-down is write-only (shape A).
func (n *Node) hasChannelConsumer(dir session.Direction) bool {
	if n.cfg.Role == RoleIran {
		return true
	}
	return dir == session.DirUp
}

// onUpNewStream handles a new up-carrier stream (RoleGermany only).
// FrameHeader bootstraps a new session; FrameRebind re-attaches an
// existing one; anything else is malformed and dropped.
func (n *Node) onUpNewStream(h *carrierHandle, id uint32, firstType uint8, ch chan []byte) {
	switch firstType {
	case mux.FrameHeader:
		go n.bootstrapUpStream(h, id, ch)
	case mux.FrameRebind:
		go n.handleRebind(session.DirUp, h, id, ch)
	default:
		n.logger.Printf("up carrier: dropping stream %d opened with frame type 0x%02x", id, firstType)
		h.carrier.Deregister(id)
	}
}

// onDownNewStream handles a new down-carrier stream (RoleGermany only).
// Down streams are only ever opened by the peer's FrameRebind — there is
// no bootstrap on the down direction.
func (n *Node) onDownNewStream(h *carrierHandle, id uint32, firstType uint8, ch chan []byte) {
	switch firstType {
	case mux.FrameRebind:
		go n.handleRebind(session.DirDown, h, id, ch)
	default:
		n.logger.Printf("down carrier: dropping stream %d opened with frame type 0x%02x", id, firstType)
		h.carrier.Deregister(id)
	}
}

// handleRebind re-attaches an EXISTING session's dir attachment to the
// carrier h (Phase 5). It never creates a session: a rebind is valid
// only for a session that already exists and awaits re-attachment.
// Resolution is by the frame's StreamID — the identity shared by both
// nodes (each node keeps its OWN local SessionID for the same logical
// session, so the payload's SessionID is the sender's local ID, used
// for validation/diagnostics, never for lookup). Validation, in order:
// payload version, session exists+active for this stream, direction not
// half-closed, sender generation strictly greater than the last
// accepted (stale/replay protection), attachment state re-bindable.
// A refused rebind is dropped — no FrameClose is sent, because a
// refused rebind must not be mistaken for a peer half-close.
func (n *Node) handleRebind(dir session.Direction, h *carrierHandle, id uint32, ch chan []byte) {
	drop := func(why string) {
		reason := "other"
		if why == "no active session for stream" {
			reason = "unknown_peer"
		} else if why == "stale sender carrier generation" {
			reason = "stale_generation"
		}
		n.metrics.RebindRefusal(reason)
		n.logger.Printf("rebind refused: stream %d (%s): %s", id, dirName(dir), why)
		h.carrier.Deregister(id)
	}

	p, ok := <-ch
	if !ok {
		return // carrier died before the rebind frame was delivered
	}
	if p == nil {
		return // FrameClose as first frame — not a rebind
	}
	// D9: accept both v1 and v2 rebind payloads. The arriving carrier h is
	// the exact carrier this stream re-attaches to, so a v2 payload MUST name
	// h's carrier ID; any mismatch (or an unknown ID) fails closed. v1
	// payloads carry no ID (the single-carrier default) and always match h.
	rb, ok := session.ParseRebindAny(p)
	if !ok {
		drop("malformed rebind payload")
		return
	}
	if rb.Version == session.RebindVersionV2 && rb.CarrierID != string(h.id) {
		drop("rebind carrier id mismatch (unknown for this carrier)")
		return
	}
	gen := rb.Gen
	sess, ok := n.store.GetByStream(id)
	if !ok || sess.State() != session.StateActive {
		drop("no active session for stream")
		return
	}
	if sess.DirClosed(dir) {
		drop("direction already half-closed")
		return
	}
	att := sess.Att(dir)
	if att == nil {
		drop("session has no attachment for direction")
		return
	}
	if gen <= att.LastRebindGen() {
		drop("stale sender carrier generation")
		return
	}
	// Hot-standby failover (Phase 2, D1): the surviving down carrier never
	// went down, so the stream originator's LOSS-triggered rebind sweep
	// (Iran) writes the FrameRebind naming that surviving carrier IMMEDIATELY
	// — before THIS node's own loss sweep has detached the attachment from
	// the just-died carrier. The attachment may still be bound to the dying
	// generation g (g != gen; gen is strictly newer, it passed the stale
	// check above). Force-detach it so the stream re-attaches on the
	// surviving carrier, mirroring rebindDirection's AttAttached backstop.
	st, g := att.State()
	switch st {
	case session.AttAttached:
		if g == gen {
			// Already bound to this exact (new) carrier; re-attach is a
			// no-op — nothing to do.
			drop("already attached to this carrier")
			return
		}
		if !att.Detach(g) {
			st2, _ := att.State()
			if st2 != session.AttUnavailable {
				drop("attachment not awaiting rebind (state " + st2.String() + ")")
				return
			}
		}
	case session.AttUnavailable, session.AttRebinding:
		// proceed to rebind
	default:
		drop("attachment not awaiting rebind (state " + st.String() + ")")
		return
	}

	att.SetLastRebindGen(gen)
	// Phase B (Slice 4): learn the SENDER's carrier generation from the
	// rebind payload and stamp it on the (carrier, streamID) credit record
	// (recordPeerGen, S6). Emitted credits carry this peerGen so the
	// sender can validate creditGen against the generation of the carrier
	// the credit ARRIVED on. h is the arriving receiver-side carrier and
	// id the logical stream, so the key is unambiguous (up/down are
	// separate carriers). Inert when credits are disabled.
	if n.creditEmitter != nil {
		n.creditEmitter.recordPeerGen(carrierKey{carrier: h.carrier, streamID: id}, gen)
	}
	// Phase B (Slice 6): rebind-attach resets the credit plane for the down
	// (data) direction — handleRebind is the receiver-side rebind path, and
	// down rebinds are the data-receiver rebinds. The sender-side ledger
	// re-pins to the new gen (bounded UNLATCHED state) and the receiver-side
	// emitter record is cleared, then the attach-time anchor is emitted
	// GO-SPAWNED (B3: never inline in this Dispatch/attach context — the
	// spawned goroutine may outlive the carrier, and TryWriteControlFrame
	// then returns (false, ErrCarrierClosed) and the goroutine drops
	// silently without leaking). Inert when credits are disabled.
	if dir == session.DirDown {
		if n.creditGate != nil {
			n.creditGate.resetStream(h.gen, id)
		}
		if n.creditEmitter != nil {
			// Reset the record, then stamp the peer gen: recordPeerGen
			// creates/updates the record and resetStream deletes it, so the
			// peer generation must be re-stamped AFTER the reset, otherwise
			// subsequent data credits carry a zero (rejected) peer gen.
			//
			// SUBTASK 25 fix: do NOT emit the attach-time anchor here.
			// handleRebind is the Germany-side responder to Iran's
			// down FrameRebind; at this moment the down stream is only
			// registered on this node's NEW carrier, and Iran's peer-side
			// down stream for this generation is still unregistered until
			// it processes the rebind. A go-spawned anchor from this node
			// would arrive as a FrameCredit on Iran's UNREGISTERED stream,
			// which the mux read loop treats as a connection-level fatal
			// (ErrCreditUnknownStream, carrier.go:300-314) and tears Iran's
			// down carrier down — the production reconnect STORM
			// (carrier_loss_events 115, gen 36->130). The sender is
			// already bounded by the 640 KiB creditPreLatchBound (UNLATCHED)
			// plus the per-stream CreditSafeTimeout timer armed in
			// resetStream above, and the first real data credit latches the
			// gate — so omitting the anchor preserves the plan's "bound the
			// sender" intent without killing the carrier. Symmetric with
			// the fresh StartSession path (node.go:1066-1082).
			key := carrierKey{carrier: h.carrier, streamID: id}
			n.creditEmitter.resetStream(key)
			n.creditEmitter.recordPeerGen(key, gen)
		}
	}
	// Attach BEFORE starting the consumer: the consumer's strict
	// generation guard only acts while the attachment is bound to
	// h.gen, so attaching first removes any window in which a fresh
	// frame could be seen by a not-yet-current consumer.
	if !att.Attach(h.gen) {
		st, _ := att.State()
		drop("attach failed (state " + st.String() + ")")
		return
	}
	if n.hasChannelConsumer(dir) {
		// Wait (bounded) for the previous carrier's consumer to fully
		// exit so two consumers never write the same socket. Now that
		// the attachment is bound to h.gen, the old consumer's strict
		// generation guard drops its remaining frames and it exits
		// promptly.
		if !att.JoinEpoch(n.cfg.Grace) {
			n.logger.Printf("session %s: previous %s consumer did not exit within %s; continuing under the generation guard",
				shortID(sess.ID), dirName(dir), n.cfg.Grace)
		}
		n.startChannelConsumer(sess, dir, h, ch)
	}
	n.metrics.Rebind()
	n.metrics.SessionRecovered()
	n.logger.Printf("session %s: %s reattached to carrier gen %d", shortID(sess.ID), dirName(dir), h.gen)
}

// StartSession (RoleIran) starts a new logical session for clientConn
// toward dest. It blocks while either carrier is down (up to 30s or
// node shutdown).
//
// Ownership of clientConn: the CALLER owns it until setup succeeds.
// On success the connection is adopted by the session (through
// sess.AdoptConn, which refuses the transfer if teardown is already in
// flight) and the caller sends the SOCKS success reply. On failure the
// connection is returned to the caller still OPEN, so the caller can
// deliver the SOCKS error reply before closing it — a session-bound
// conn closed during setup would swallow that reply.
func (n *Node) StartSession(clientConn net.Conn, dest *session.Destination) (*session.Session, error) {
	upH, downH, err := n.waitCarriers()
	if err != nil {
		return nil, err // clientConn is still the caller's to close
	}

	id := n.nextStreamID()
	raw, _ := session.GenerateSessionID()
	var sid session.SessionID
	copy(sid[:], raw)

	// The session does NOT own clientConn yet: setup can still fail
	// (registration, activation, destination encoding, header write)
	// and the caller must be able to send the SOCKS error reply after
	// such a failure. Ownership is transferred below, once every
	// failure point has passed.
	sess := session.NewSession(sid, dest, nil, nil, n.ctx)
	sess.StreamIDUp = id
	sess.StreamIDDown = id
	sess.UpAtt = session.NewAttachment(n.cfg.Grace, func() { n.onGraceTimeout(sess, session.DirUp) })
	sess.DownAtt = session.NewAttachment(n.cfg.Grace, func() { n.onGraceTimeout(sess, session.DirDown) })
	sess.OnClose(func() { n.onSessionClosed(sess) })

	n.store.Add(sid, sess)
	n.store.AddStream(sess)
	n.metrics.SessionStarted()

	upCh := upH.carrier.Register(id)
	downCh := downH.carrier.Register(id)
	if upCh == nil || downCh == nil {
		sess.Close("carrier stream registration failed")
		return nil, errors.New("carrier stream registration failed")
	}

	if !sess.Activate() {
		sess.Close("activation failed")
		return nil, errors.New("activation failed")
	}

	// FrameHeader MUST be the first frame of the up stream — the peer
	// bootstraps the target from it.
	hdr := make([]byte, session.MaxHeaderSize)
	nw := session.WriteDestinationBuffer(hdr, dest)
	if nw == 0 {
		sess.Close("destination encoding failed")
		return nil, errors.New("destination encoding failed")
	}
	if err := upH.carrier.WriteFrame(id, mux.FrameHeader, hdr[:nw]); err != nil {
		sess.Close("up-carrier header write failed")
		return nil, fmt.Errorf("up-carrier header write: %w", err)
	}

	// All setup failure points are behind us: hand the client conn over
	// to the session so its authoritative Close is the only closer.
	// This happens BEFORE the Attach calls on purpose: once attached, a
	// carrier loss could start the grace window and close the session,
	// and a conn not yet adopted by the session would leak (nobody
	// else closes it). If a teardown raced in, the adopt is refused and
	// the conn is returned to the caller still open (the caller closes
	// it with the other failure paths, after its SOCKS error reply) —
	// the session's ClientConn is nil, so its teardown will not touch
	// it.
	if !sess.AdoptConn(clientConn) {
		return nil, errors.New("client conn adopt refused (session closing)")
	}

	sess.UpAtt.Attach(upH.gen)
	sess.DownAtt.Attach(downH.gen)

	// Phase B (Slice 6, B2): stamp the record's peerGen with the CURRENT
	// down carrier generation so every subsequent data credit carries the
	// gen the peer's gate ledger is pinned to (the arriving carrier's
	// h.gen) and is accepted instead of rejected as stale/pinned-mismatch.
	//
	// The anchor is NOT emitted here on the fresh StartSession path: the
	// mux read loop (carrier.go:310-314) treats a FrameCredit for a
	// stream the carrier has not yet registered as a CONNECTION-level
	// fatal error (ErrCreditUnknownStream). At this point the peer has
	// not registered the down stream (it registers it in bootstrapUp-
	// Stream, triggered by the up FrameHeader written above, and the up
	// and down carriers have no ordering guarantee). Emitting the anchor
	// now would tear down the peer's down carrier. The 640 KiB UNLATCHED
	// pre-latch bound prevents any stall: the first real data credit
	// (emitted when the receiver writes to its socket) latches the gate.
	// The anchor is NOT emitted on the rebind path either (SUBTASK 25 fix).
	// A down rebind installs a FRESH carrier generation on both sides, on
	// which NO stream is registered yet; the registering FrameRebind and the
	// go-spawned anchor would both be in flight, and because the control
	// plane (ctrlCh) is peeked ahead of the data plane (writeCh) by
	// writeLoop, the anchor OVERTAKES the FrameRebind that registers the
	// stream. The peer's down readLoop then sees a FrameCredit on an
	// UNREGISTERED stream and fails it as ErrCreditUnknownStream
	// (carrier.go:310-314), tearing the peer's down carrier down and
	// retriggering the loss/rebind cycle — the production reconnect storm
	// (carrier_loss_events 115, carrier gen 36->130, 09:29-09:39 UTC on
	// 2026-10-04). The sender is already bounded by the 640 KiB UNLATCHED
	// creditPreLatchBound plus the per-stream CreditSafeTimeout timer armed
	// in creditGate.resetStream on every rebind, and the first real data
	// credit (relays.go recordConsumed->emit) latches the gate, so omitting
	// the rebind anchor preserves the plan's "bound the sender" intent
	// without killing the carrier. Same reasoning as the fresh path above.
	// Inert when credits are disabled (n.creditEmitter is nil).
	if n.creditEmitter != nil {
		n.creditEmitter.recordPeerGen(
			carrierKey{carrier: downH.carrier, streamID: id}, downH.gen)
	}

	// client → up: buffered upload relay (shape A, session-lifetime)
	go n.relayShapeA(sess, session.DirUp, clientConn)
	// down → client: per-carrier data relay (shape B)
	n.startChannelConsumer(sess, session.DirDown, downH, downCh)
	// up stream toward us: peer FrameClose watcher (e.g. target dial
	// failure) — also per-carrier epoch
	n.startChannelConsumer(sess, session.DirUp, upH, upCh)

	return sess, nil
}

// onSessionClosed is the OnClose hook: deregister the streams from the
// CURRENT carriers (the session may have re-bound; the old carriers
// clear their own stream tables during their Close), unindex and count.
func (n *Node) onSessionClosed(sess *session.Session) {
	// Deregister the session's streams from every installed carrier in the
	// direction. In multi-carrier a down stream may be pinned to the
	// standby carrier, not the primary, so deregistering via a single
	// "current" carrier would leak the stream on the other instance.
	// Deregister is idempotent/quiet when the stream is absent (a lost
	// carrier already removed its stream table on Close), so sweeping the
	// whole direction is safe and leaves no slot behind.
	if sess.StreamIDUp != 0 {
		for _, h := range n.upReg.Handles() {
			if h != nil {
				h.carrier.Deregister(sess.StreamIDUp)
			}
		}
	}
	if sess.StreamIDDown != 0 {
		for _, h := range n.downReg.Handles() {
			if h != nil {
				h.carrier.Deregister(sess.StreamIDDown)
			}
		}
	}
	// Phase B (Slice 6): the captured down carrier cleans up the credit
	// plane's per-(carrier, streamID) records (timer + ledger on the
	// gate, emitter record) — prevents a map leak of one entry per
	// finished session. Inert when credits are disabled.
	// Remove the credit gate's per-stream ledger + CreditSafeTimeout timer
	// (Sender side, Germany) and the receiver-side emitter records. The gate
	// is keyed by streamID (direction-wide); the emitter records are keyed
	// by (carrier, streamID), so in multi-carrier they may exist on ANY
	// down carrier the stream was ever pinned to — sweep the whole set to
	// leave no per-session map leak. Inert when credits are disabled.
	if n.creditGate != nil && sess.StreamIDDown != 0 {
		n.creditGate.removeStream(sess.StreamIDDown)
	}
	if n.creditEmitter != nil && sess.StreamIDDown != 0 {
		for _, h := range n.downReg.Handles() {
			if h != nil {
				n.creditEmitter.removeStream(carrierKey{carrier: h.carrier, streamID: sess.StreamIDDown})
			}
		}
	}
	n.store.Remove(sess.ID)
	reason := closeReasonClass(sess)
	if sess.Stats.DataUndeliverable.Load() {
		sess.SetDataUndeliverableReason()
	} else if sess.Stats.Terminated.Load() {
		sess.SetOverflowReason()
	}
	n.metrics.SessionClosed(reason)
	clean := (reason == ReasonClientEOF || reason == ReasonTargetEOF) &&
		sess.Stats.CleanHalfClose.Load() && !sess.Stats.Terminated.Load() &&
		sess.DirClosed(session.DirUp) && sess.DirClosed(session.DirDown)
	if clean {
		n.metrics.SessionCleanComplete()
	} else if sess.Stats.FirstByte.Load() {
		n.metrics.SessionMidTransfer()
	} else {
		n.metrics.SessionClosedBeforeFirstByte()
	}
	n.metrics.SessionEnded()
	n.logger.Printf("session %s closed: %s", shortID(sess.ID), sess.Reason())
}

// waitCarriers blocks until BOTH carriers are ready (Iran bootstrap):
// bounded by Config.BootstrapWait (SPLIT_BOOTSTRAP_WAIT_MS, Issue #7),
// and cancelable immediately on node shutdown. It is signal-driven,
// not polled: each wake comes from a carrier install or a carrier loss
// (the ready channels), so a carrier that reconnects mid-wait is
// observed without any polling interval. On wake the wait re-checks a
// single atomic snapshot (currentIfReadyBoth) — the returned handles
// are captured under the node lock, so they are attached to a
// generation that was ready at the moment of capture (no stale-gen
// attachment, no pairing a live up carrier with a dead down one).
//
// The wait never extends beyond the deadline, even while the carrier
// reconnect loop is mid-attempt: the backoff is bounded (2s..60s) and
// the bootstrap window is explicitly configured to cover it.
func (n *Node) waitCarriers() (upH, downH *carrierHandle, err error) {
	deadline := time.NewTimer(n.cfg.BootstrapWait)
	defer deadline.Stop()
	for {
		upH, downH = n.currentIfReadyBoth()
		if upH != nil && downH != nil {
			return upH, downH, nil
		}
		// Wait ONLY on the directions that are not ready: a nil
		// channel disables its select case, so an already-ready
		// direction (whose ready channel is therefore CLOSED) can
		// never be selected — selecting a closed channel every
		// iteration would spin the loop at full CPU until the
		// deadline (regression: TestWaitCarriersNoBusySpin). A ready
		// direction that is later lost and reinstalled is
		// re-captured on the next wake (handles are re-fetched from
		// currentIfReadyBoth on every loop), so no stale handle is
		// ever returned.
		var sigU, sigD <-chan struct{}
		if upH == nil {
			sigU = n.readySig(session.DirUp)
		}
		if downH == nil {
			sigD = n.readySig(session.DirDown)
		}
		select {
		case <-sigU:
		case <-sigD:
		case <-n.ctx.Done():
			return nil, nil, n.ctx.Err()
		case <-deadline.C:
			return nil, nil, fmt.Errorf("carriers not ready after %s", n.cfg.BootstrapWait)
		}
	}
}

// waitCarrierReady blocks until the single direction's carrier is
// ready (Germany up-bootstrap, Issue #7): bounded by
// Config.BootstrapWait, cancelable on node shutdown, signal-driven.
// Returns the carrier handle captured atomically at the ready moment.
func (n *Node) waitCarrierReady(dir session.Direction) (*carrierHandle, error) {
	deadline := time.NewTimer(n.cfg.BootstrapWait)
	defer deadline.Stop()
	for {
		if h := n.currentIfReady(dir); h != nil {
			return h, nil
		}
		sig := n.readySig(dir)
		select {
		case <-sig:
		case <-n.ctx.Done():
			return nil, n.ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("%s carrier not ready after %s", dirName(dir), n.cfg.BootstrapWait)
		}
	}
}

// readySig returns the carrier-ready signal for one direction: closed
// while a ready carrier is installed, re-created (open) on loss.
// Waiters must re-check ready state after a wake (a wake means "state
// changed", not "ready now"). The returned channel must be used in a
// select that also has a non-channel exit (deadline/ctx), and a
// direction whose carrier is ready must not be selected on (its
// channel is closed — see waitCarriers).
func (n *Node) readySig(dir session.Direction) <-chan struct{} {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if dir == session.DirUp {
		return n.upReady
	}
	return n.downReady
}

// bootstrapUpStream (RoleGermany) handles a NEW up stream: decode the
// destination from the FrameHeader, dial the target, and wire the
// session. (A resumed stream arrives as FrameRebind and goes to
// handleRebind instead.)
func (n *Node) bootstrapUpStream(h *carrierHandle, id uint32, ch chan []byte) {
	drop := func(err error) {
		h.carrier.WriteFrame(id, mux.FrameClose, nil)
		h.carrier.Deregister(id)
		n.metrics.Error()
		n.logger.Printf("up carrier stream %d: dropped: %v", id, err)
	}

	p, ok := <-ch
	if !ok {
		return // carrier died before the header was delivered
	}
	if p == nil {
		return // FrameClose before any header — nothing to bootstrap
	}
	dest := session.ParseDestinationFromBuf(p)
	if dest == nil {
		drop(errors.New("invalid destination header"))
		return
	}

	targetConn, err := n.cfg.TargetDial(net.JoinHostPort(dest.Addr, strconv.Itoa(int(dest.Port))))
	if err != nil {
		n.metrics.TargetDialFailure()
		drop(fmt.Errorf("target %s dial failed: %w", dest.Addr, err))
		return
	}
	n.metrics.TargetDialSuccess()

	// Bounded bootstrap wait for the down carrier (Issue #7): if it is
	// down at FrameHeader arrival but reconnects within BootstrapWait
	// (SPLIT_BOOTSTRAP_WAIT_MS), the session bootstraps successfully
	// instead of being dropped. Signal-driven (carrier-ready channel),
	// bounded, and cancelable on Node.Close. On success the handle is
	// captured atomically at the ready moment, so the session attaches
	// to the CURRENT generation (acceptance #5) — a carrier that
	// reconnects mid-wait is seen as a fresh install, never a stale gen.
	downH, err := n.waitCarrierReady(session.DirDown)
	if err != nil {
		targetConn.Close()
		drop(fmt.Errorf("down carrier not ready: %w", err))
		return
	}

	raw, _ := session.GenerateSessionID()
	var sid session.SessionID
	copy(sid[:], raw)

	sess := session.NewSession(sid, dest, nil, targetConn, n.ctx)
	sess.StreamIDUp = id
	sess.StreamIDDown = id
	sess.UpAtt = session.NewAttachment(n.cfg.Grace, func() { n.onGraceTimeout(sess, session.DirUp) })
	sess.DownAtt = session.NewAttachment(n.cfg.Grace, func() { n.onGraceTimeout(sess, session.DirDown) })
	sess.OnClose(func() { n.onSessionClosed(sess) })

	downCh := downH.carrier.Register(id)
	if downCh == nil {
		targetConn.Close()
		drop(errors.New("down stream registration failed"))
		return
	}

	n.store.Add(sid, sess)
	n.store.AddStream(sess)
	n.metrics.SessionStarted()

	if !sess.Activate() {
		sess.Close("activation failed")
		return
	}

	sess.UpAtt.Attach(h.gen)
	sess.DownAtt.Attach(downH.gen)

	// Phase B (Slice 6, B2): emit the attach-time anchor on the down carrier
	// so the sender's gate latches from the first carrier. This is the
	// initial-attach (fresh session) path for Germany — complementing
	// StartSession (Iran) and rebindDirection/handleRebind (rebinds). The
	// record's peerGen is stamped with the down carrier generation (down
	// generations are lockstep across both nodes) so the anchor carries a
	// valid, non-stale gen. GO-SPAWNED (B3). Inert when credits are
	// disabled.
	if n.creditEmitter != nil {
		key := carrierKey{carrier: downH.carrier, streamID: id}
		n.creditEmitter.recordPeerGen(key, downH.gen)
		go n.creditEmitter.emitAnchor(key)
	}

	// up → target: per-carrier data relay (shape B)
	n.startChannelConsumer(sess, session.DirUp, h, ch)
	// target → down: buffered download relay (shape A, session-lifetime)
	go n.relayShapeA(sess, session.DirDown, targetConn)

	n.logger.Printf("up carrier stream %d: bootstrapped session %s → %s:%d",
		id, shortID(sid), dest.Addr, dest.Port)
}

// finalizeDrain arms the post-up-close drain timer (RoleGermany): if the
// target has not finished within 10s of the client half-close, the
// session is closed. (Preserves the pre-Phase-5 drain behavior.)
func (n *Node) finalizeDrain(sess *session.Session) {
	time.AfterFunc(10*time.Second, func() {
		if sess.IsClosed() || sess.DirClosed(session.DirDown) {
			return
		}
		sess.Close("target did not finish after client EOF")
	})
}

// ============================================================
// small helpers
// ============================================================

func shortID(id session.SessionID) string {
	return fmt.Sprintf("%x", id[:4])
}

func dirName(dir session.Direction) string {
	if dir == session.DirUp {
		return "up"
	}
	return "down"
}

func streamIDOf(sess *session.Session, dir session.Direction) uint32 {
	if dir == session.DirUp {
		return sess.StreamIDUp
	}
	return sess.StreamIDDown
}

// carrierTimeoutReason is the explicit close reason for a grace timeout.
func carrierTimeoutReason(dir session.Direction) string {
	if dir == session.DirUp {
		return "upload carrier timeout"
	}
	return "download carrier timeout"
}

// closeWrite half-closes a TCP connection when possible (in-memory test
// connections do not support it; the logical half-close still applies).
func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}
