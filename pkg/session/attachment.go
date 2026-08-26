package session

import (
	"encoding/binary"
	"sync"
	"time"
)

// ============================================================
// Attachment — carrier binding for one session direction (Phase 5)
// ============================================================
//
// A session's LIFECYCLE (Pending/Active/Closing/Closed, half-closed
// directions) lives in Session. Its TRANSPORT BINDING — which carrier
// generation currently carries this direction, and whether that carrier
// is alive — lives here, one Attachment per direction.
//
// The session owns the logical stream (stable StreamID, sockets,
// lifecycle); the carrier is a replaceable transport. When the bound
// carrier dies, the binary calls Detach(gen): the attachment becomes
// Unavailable and a bounded grace window starts. A replacement carrier
// is attached via BeginRebind/Attach with the NEW generation. A frame
// or channel event may only act on the attachment while it is still
// bound to the generation that produced it (the binary compares
// Attachments.State() against its own carrier generation) — this is the
// stale-carrier guard: a late event from a superseded carrier is a
// no-op, never data on the wrong transport.
//
// Attachment is deliberately carrier-agnostic: it knows no mux types.
// The binary decides what "attach" means (register the stream on the
// new carrier, send FrameRebind, (re)start the consumer relay) and what
// "lost" means (mark the carrier unavailable, keep draining the old
// channel).

// AttachmentState is one stage of the transport-binding lifecycle.
type AttachmentState int

const (
	// AttUnavailable: not bound to a carrier. Initial state before the
	// first Attach (no grace timer yet) and state after carrier loss
	// (grace timer running until rebind or timeout).
	AttUnavailable AttachmentState = iota
	// AttRebinding: a replacement carrier is being attached; claimed so
	// concurrent rebind attempts cannot double-fire. The grace timer
	// from Detach keeps running — a rebind that does not complete within
	// the grace window still times out.
	AttRebinding
	// AttAttached: bound to the live carrier whose generation is Gen.
	AttAttached
	// AttClosed: permanently closed — the direction was half-closed or
	// the session was torn down. A closed attachment is never re-bound.
	AttClosed
)

func (s AttachmentState) String() string {
	switch s {
	case AttUnavailable:
		return "Unavailable"
	case AttRebinding:
		return "Rebinding"
	case AttAttached:
		return "Attached"
	case AttClosed:
		return "Closed"
	}
	return "Unknown"
}

// Attachment tracks the carrier binding of one session direction.
// All operations are safe for concurrent use.
type Attachment struct {
	mu        sync.Mutex
	state     AttachmentState
	gen       uint64 // generation of the bound carrier (valid when AttAttached)
	grace     time.Duration
	onTimeout func() // binary-provided: close the session, called by the grace timer
	timer     *time.Timer
	// ready is closed while the attachment is Attached; Detach/Close
	// install a fresh (open) channel. A waiter that captured the signal
	// while Unattached is woken when Attach closes it; spurious wakes
	// are safe (the waiter re-checks State).
	ready       chan struct{}
	readyClosed bool
	// lastRebindGen is the highest SENDER carrier generation accepted in
	// a FrameRebind for this direction (the token is the remote node's
	// generation, embedded in the rebind payload). Rebinds with
	// gen <= lastRebindGen are stale/replayed and must be rejected.
	lastRebindGen uint64
	// epochDone, when set, is the done channel of the current consumer
	// relay for this direction (set by the binary). JoinEpoch waits for
	// it before a replacement relay may start, so two consumers never
	// write the same socket.
	epochDone chan struct{}
}

// NewAttachment creates an attachment in AttUnavailable with no grace
// timer. grace bounds the carrier-loss recovery window; onTimeout is
// invoked (from the timer goroutine) if the window expires while the
// attachment is still Unavailable or Rebinding. onTimeout must not
// block.
func NewAttachment(grace time.Duration, onTimeout func()) *Attachment {
	return &Attachment{
		state:     AttUnavailable,
		grace:     grace,
		onTimeout: onTimeout,
		ready:     make(chan struct{}),
	}
}

// State returns the current state and, when AttAttached, the bound
// carrier generation.
func (a *Attachment) State() (AttachmentState, uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state, a.gen
}

// Attach binds the attachment to the carrier with the given generation.
// Legal from AttUnavailable and AttRebinding only; it stops the grace
// timer. It returns false (no state change) from AttAttached (already
// bound) and AttClosed (direction done / session torn down).
func (a *Attachment) Attach(gen uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != AttUnavailable && a.state != AttRebinding {
		return false
	}
	a.state = AttAttached
	a.gen = gen
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	if !a.readyClosed {
		close(a.ready)
		a.readyClosed = true
	}
	return true
}

// Detach marks the bound carrier (gen) as lost and starts the grace
// window. Legal from AttAttached AND only for the bound generation —
// a stale carrier death (gen mismatch, e.g. the session already moved
// to a newer carrier) is a no-op, which is the stale-carrier guard.
// Returns true if the state changed to AttUnavailable.
func (a *Attachment) Detach(gen uint64) bool {
	a.mu.Lock()
	if a.state != AttAttached || a.gen != gen {
		a.mu.Unlock()
		return false
	}
	a.state = AttUnavailable
	a.gen = 0
	a.ready = make(chan struct{})
	a.readyClosed = false
	a.startTimerLocked()
	a.mu.Unlock()
	return true
}

// BeginRebind claims the rebind for this direction: AttUnavailable →
// AttRebinding. It returns false from any other state (already
// re-binding/attached, closed, or the grace timer already ran and the
// binary closed the session).
func (a *Attachment) BeginRebind() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != AttUnavailable {
		return false
	}
	a.state = AttRebinding
	return true
}

// FailRebind gives up a failed rebind attempt: AttRebinding →
// AttUnavailable. The grace timer from Detach keeps running, so the
// session still times out if no carrier recovers in time.
func (a *Attachment) FailRebind() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != AttRebinding {
		return false
	}
	a.state = AttUnavailable
	return true
}

// Close permanently closes the attachment (direction half-closed or
// session teardown). It cancels the grace timer. Idempotent.
func (a *Attachment) Close() {
	a.mu.Lock()
	if a.state == AttClosed {
		a.mu.Unlock()
		return
	}
	a.state = AttClosed
	a.gen = 0
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	a.ready = make(chan struct{})
	a.readyClosed = false
	a.mu.Unlock()
}

// ReadySignal returns a channel that is closed while the attachment is
// Attached and re-created (open) on every transition away from it.
// Waiters must re-check State() after a wake.
func (a *Attachment) ReadySignal() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ready
}

// LastRebindGen returns the highest sender generation accepted in a
// FrameRebind (0 = none yet).
func (a *Attachment) LastRebindGen() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastRebindGen
}

// SetLastRebindGen records the sender generation of an accepted rebind.
func (a *Attachment) SetLastRebindGen(gen uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastRebindGen = gen
}

// SetEpochDone records the done channel of the consumer relay currently
// serving this direction.
func (a *Attachment) SetEpochDone(d chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.epochDone = d
}

// JoinEpoch blocks until the current consumer relay's done channel
// closes or the timeout elapses. It returns false on timeout (the
// caller may proceed — the generation guard then protects socket
// ordering — but should log).
func (a *Attachment) JoinEpoch(timeout time.Duration) bool {
	a.mu.Lock()
	d := a.epochDone
	a.mu.Unlock()
	if d == nil {
		return true
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-d:
		return true
	case <-t.C:
		return false
	}
}

// startTimerLocked arms the grace timer. Caller holds a.mu. The
// callback re-validates the state before acting, so a timer that
// outlives a rebind is harmless.
func (a *Attachment) startTimerLocked() {
	if a.timer != nil {
		return
	}
	a.timer = time.AfterFunc(a.grace, func() {
		a.mu.Lock()
		if a.state == AttClosed {
			a.mu.Unlock()
			return
		}
		a.timer = nil
		a.mu.Unlock()
		if a.onTimeout != nil {
			a.onTimeout()
		}
	})
}

// ============================================================
// FrameRebind payload codec (versioned)
// ============================================================
//
//	[0]     RebindVersion (1)
//	[1:17]  SessionID (16 bytes)
//	[17:25] sender carrier generation (uint64, big-endian)

// RebindVersion is the current FrameRebind payload version.
const RebindVersion = 1

// RebindPayloadSize is the exact FrameRebind payload length.
const RebindPayloadSize = 1 + SessionIDLen + 8

// EncodeRebind builds a FrameRebind payload for the session with the
// given sender carrier generation.
func EncodeRebind(sid SessionID, gen uint64) []byte {
	b := make([]byte, RebindPayloadSize)
	b[0] = RebindVersion
	copy(b[1:], sid[:])
	binary.BigEndian.PutUint64(b[1+SessionIDLen:], gen)
	return b
}

// ParseRebind validates and decodes a FrameRebind payload. It returns
// ok=false for wrong size or unknown version — receivers must drop the
// rebind (and log) when ok is false.
func ParseRebind(payload []byte) (sid SessionID, gen uint64, ok bool) {
	if len(payload) != RebindPayloadSize || payload[0] != RebindVersion {
		return SessionID{}, 0, false
	}
	copy(sid[:], payload[1:1+SessionIDLen])
	gen = binary.BigEndian.Uint64(payload[1+SessionIDLen:])
	return sid, gen, true
}
