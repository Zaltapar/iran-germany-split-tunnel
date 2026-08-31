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
	// RelayBufSize is the socket read-buffer size (default 32 KiB).
	RelayBufSize int
	// KeepAliveInterval is the carrier ping period (default 15s).
	KeepAliveInterval time.Duration
	// StreamLimits is the carrier backpressure policy (Phase 3).
	StreamLimits mux.StreamLimits
	// TargetDial dials a logical destination (RoleGermany only).
	// Default: 10s TCP dial.
	TargetDial func(addr string) (net.Conn, error)
}

// Sanitize replaces zero/negative values with defaults.
func (c *Config) Sanitize() {
	if c.Grace <= 0 {
		c.Grace = 5 * time.Second
	}
	if c.BufferBytes <= 0 {
		c.BufferBytes = 256 << 10
	}
	if c.RelayBufSize <= 0 {
		c.RelayBufSize = 32 << 10
	}
	if c.KeepAliveInterval <= 0 {
		c.KeepAliveInterval = 15 * time.Second
	}
	c.StreamLimits = mux.SanitizeLimits(c.StreamLimits)
	if c.TargetDial == nil {
		c.TargetDial = func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 10*time.Second)
		}
	}
}

// carrierHandle is one installed carrier transport. Its generation is
// monotonically increasing per node+direction and is the ownership token
// used for stale-carrier protection.
type carrierHandle struct {
	carrier *mux.CarrierConn
	gen     uint64
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

// Node is the per-side engine.
type Node struct {
	cfg     Config
	store   *session.SessionStore
	metrics *Metrics
	logger  *log.Logger
	secret  []byte

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.RWMutex
	up        *carrierHandle
	down      *carrierHandle
	lostUp    bool // up carrier died since the previous install
	lostDown  bool
	genSeq    uint64
	streamSeq uint32 // atomic counter for logical stream IDs
}

// NewNode creates a Node with the given role, config (sanitized),
// logger and shared secret (used by the transport layer for CarrierAuth
// before InstallUp/InstallDown; the Node itself does not authenticate).
func NewNode(cfg Config, logger *log.Logger, secret []byte) *Node {
	cfg.Sanitize()
	ctx, cancel := context.WithCancel(context.Background())
	return &Node{
		cfg:     cfg,
		store:   session.NewSessionStore(),
		metrics: NewMetrics(),
		logger:  logger,
		secret:  secret,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Store is the session store.
func (n *Node) Store() *session.SessionStore { return n.store }

// Secret returns the derived shared secret. The Node does not perform
// the carrier authentication itself; the transport layer (cmd/*) runs
// mux.CarrierAuth with this secret BEFORE handing the authenticated
// connection to InstallUp/InstallDown.
func (n *Node) Secret() []byte { return n.secret }

// Metrics is the metrics set (used by the /metrics handler).
func (n *Node) Metrics() *Metrics { return n.metrics }

// Context is cancelled by Close — every wait/park in the node selects on
// it so shutdown unblocks immediately.
func (n *Node) Context() context.Context { return n.ctx }

// Shutdown reports whether Close has been called.
func (n *Node) Shutdown() bool { return n.ctx.Err() != nil }

// Close shuts the node down: cancel the context, close every session
// (Phase 4 authoritative path), close the current carriers. Idempotent.
func (n *Node) Close() {
	n.cancel()
	n.store.CloseAll()
	n.mu.Lock()
	if n.up != nil {
		n.up.carrier.Close()
	}
	if n.down != nil {
		n.down.carrier.Close()
	}
	n.mu.Unlock()
}

// UpReady reports whether a live up carrier is currently installed.
func (n *Node) UpReady() bool {
	h := n.current(session.DirUp)
	return h != nil && h.carrier.Ready()
}

// DownReady reports whether a live down carrier is currently installed.
func (n *Node) DownReady() bool {
	h := n.current(session.DirDown)
	return h != nil && h.carrier.Ready()
}

func (n *Node) current(dir session.Direction) *carrierHandle {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if dir == session.DirUp {
		return n.up
	}
	return n.down
}

// dropIfCurrent clears the handle slot if it still points at h.
func (n *Node) dropIfCurrent(dir session.Direction, h *carrierHandle) {
	n.mu.Lock()
	if dir == session.DirUp && n.up == h {
		n.up = nil
	}
	if dir == session.DirDown && n.down == h {
		n.down = nil
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
	return n.install(session.DirUp, conn, br)
}

// InstallDown installs an authenticated download-carrier transport.
func (n *Node) InstallDown(conn io.ReadWriteCloser, br *bufio.Reader) *carrierHandle {
	return n.install(session.DirDown, conn, br)
}

func (n *Node) install(dir session.Direction, conn io.ReadWriteCloser, br *bufio.Reader) *carrierHandle {
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
	c.SetStreamLimits(n.cfg.StreamLimits)

	n.mu.Lock()
	n.genSeq++
	h := &carrierHandle{carrier: c, gen: n.genSeq, done: make(chan struct{}), lost: make(chan struct{})}
	var old *carrierHandle
	var wasLost bool
	if dir == session.DirUp {
		old = n.up
		n.up = h
		wasLost = n.lostUp
		n.lostUp = false
	} else {
		old = n.down
		n.down = h
		wasLost = n.lostDown
		n.lostDown = false
	}
	n.mu.Unlock()

	if wasLost {
		n.metrics.CarrierReconnect()
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
				reconnectCounted = true
			}
			// Settle a stale lost flag: the sweep may have set it after
			// the clear above (install-before-sweep ordering); the loss
			// is now fully accounted for and the flag must not leak into
			// the next replacement.
			n.mu.Lock()
			if dir == session.DirUp {
				n.lostUp = false
			} else {
				n.lostDown = false
			}
			n.mu.Unlock()
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

	n.logger.Printf("carrier %s ready (gen %d)", dirName(dir), h.gen)
	n.onCarrierReady(dir, h)
	return h
}

// onCarrierLost runs when a carrier's dispatcher has exited.
func (n *Node) onCarrierLost(dir session.Direction, h *carrierHandle) {
	n.mu.Lock()
	if dir == session.DirUp {
		n.lostUp = true
	} else {
		n.lostDown = true
	}
	n.mu.Unlock()

	n.metrics.CarrierLossEvent()
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
		if err := h.carrier.WriteFrame(id, mux.FrameRebind, session.EncodeRebind(sess.ID, h.gen)); err != nil {
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
			n.metrics.RebindFailure()
			continue
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
	n.metrics.RebindFailure()
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
		n.metrics.RebindFailure()
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
	_, gen, ok := session.ParseRebind(p)
	if !ok {
		drop("malformed rebind payload")
		return
	}
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
	st, _ := att.State()
	if st != session.AttUnavailable && st != session.AttRebinding {
		drop("attachment not awaiting rebind (state " + st.String() + ")")
		return
	}

	att.SetLastRebindGen(gen)
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
	n.mu.RLock()
	if h := n.up; h != nil && sess.StreamIDUp != 0 {
		h.carrier.Deregister(sess.StreamIDUp)
	}
	if h := n.down; h != nil && sess.StreamIDDown != 0 {
		h.carrier.Deregister(sess.StreamIDDown)
	}
	n.mu.RUnlock()
	n.store.Remove(sess.ID)
	n.metrics.SessionEnded()
	n.logger.Printf("session %s closed: %s", shortID(sess.ID), sess.Reason())
}

// waitCarriers blocks until both carriers are ready: up to 30s, or
// immediately on node shutdown.
func (n *Node) waitCarriers() (upH, downH *carrierHandle, err error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		upH, downH = n.current(session.DirUp), n.current(session.DirDown)
		if upH != nil && upH.carrier.Ready() && downH != nil && downH.carrier.Ready() {
			return upH, downH, nil
		}
		if time.Now().After(deadline) {
			return nil, nil, errors.New("carriers not ready after 30s")
		}
		t := time.NewTimer(50 * time.Millisecond)
		select {
		case <-t.C:
		case <-n.ctx.Done():
			t.Stop()
			return nil, nil, n.ctx.Err()
		}
	}
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
		drop(fmt.Errorf("target %s dial failed: %w", dest.Addr, err))
		return
	}

	downH := n.current(session.DirDown)
	if downH == nil || !downH.carrier.Ready() {
		h.carrier.WriteFrame(id, mux.FrameClose, nil)
		h.carrier.Deregister(id)
		targetConn.Close()
		n.metrics.Error()
		n.logger.Printf("up carrier stream %d: down carrier not ready, dropping", id)
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
		h.carrier.WriteFrame(id, mux.FrameClose, nil)
		h.carrier.Deregister(id)
		targetConn.Close()
		n.logger.Printf("up carrier stream %d: down stream registration failed", id)
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
