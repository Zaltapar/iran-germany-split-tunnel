package node

import (
	"sync"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// This file is Increment 2 (the sender half) of the D4 hybrid per-stream
// credit design, plus the receiver's credit emission. It is authoritative
// from plans/architecture-checkpoint-backpressure.md §E.1–§E.6, §F.2, §H,
// §I, §U and the rev-2/rev-3 amendment maps. The integrity invariant is
// preserved: credit only ever PARKS the sender (or, when un-latched, leaves
// it unlimited); it never drops or terminates DATA. The refused-DATA
// safety net (pkg/mux failUndeliverableData) stays armed on every path.

// ledgerSnap is a lock-free copy of one credit entry's decision fields,
// taken under the ledger lock so the relay gate never holds it across the
// socket read (R2-1: no carrier write / no q.mu ever in the pop or gate
// path; the gate only reads this node-side mirror).
type ledgerSnap struct {
	gen            uint64 // the down-carrier generation this entry is anchored to
	latched        bool   // true after the first valid credit frame for this gen (A4)
	window         uint64 // derived creditWindow = popped - cumulativeSent, clamped at 0
	cumulativeSent uint64 // bytes this sender has written as FrameData since the (re)anchor
}

// creditLedger holds the SENDER-side (RoleGermany) per-stream D4 credit
// state, keyed by logical stream ID. It lives on the Node (NOT in
// pkg/mux) so relayShapeA's gate can consult it without touching the
// mailbox lock. The receiver (Iran) owns the absolute popped counter
// (§E.1); this ledger is its sender-side mirror.
//
// State machine (B / §E.2, §E.4.1, §I; INCREMENT 3 amendment to A4):
//   - A stream is UN-LATCHED (= unlimited) until its first valid FrameCredit
//     (version 1, 18-byte payload, current generation).
//   - LATCH on ANY valid credit frame for the generation. On the on-attach
//     ANCHOR credit (popped = 0) the stream seeds a safe initialWindow (the
//     per-stream mailbox capacity) so the sender is BOUNDED from the very
//     first credit instead of running unlimited; on a drained credit
//     (popped > 0) the window is the derived popped - cumulativeSent,
//     clamped at 0 (PARK, never wrap to a huge positive — R2-3).
//   - REBIND: both sides reset to 0 at attach; the first post-rebind frame
//     anchors both sides. A stale-generation frame is structurally
//     undeliverable (R2-2), so onCredit only ever runs on a genuine
//     rebind-attach generation.
type creditLedger struct {
	mu      sync.Mutex
	entries map[uint32]*creditEntry
	// onTimeout, when set, is invoked on the timer goroutine once when a
	// stream's un-latched establishment window expires with no valid credit:
	// revert to unlimited + count relay_credit_establish_timeout (A3). It
	// never blocks.
	onTimeout func(streamID uint32)
	// onLatch, when set, is invoked once when a stream first latches to
	// credit-gated mode on a given generation (clearing its establishment
	// timer). It never blocks.
	onLatch func(streamID uint32)
	// initialWindow is the safe initial credit window a stream receives when
	// it latches on the on-attach ANCHOR credit (popped = 0, A4 relaxed at
	// INCREMENT 3): the sender is bounded to the per-stream mailbox capacity
	// from the very first credit, instead of running unlimited. It equals
	// the carrier's MaxBytesPerStream (the mailbox byte bound), so the
	// sender can never commit more than the mailbox can hold; it falls back
	// to mux.DefaultStreamLimits.MaxBytesPerStream when the limit is
	// unavailable. Set via setInitialWindow before the ledger is used.
	initialWindow uint64
}

func newCreditLedger(onTimeout, onLatch func(uint32)) *creditLedger {
	return &creditLedger{entries: make(map[uint32]*creditEntry), onTimeout: onTimeout, onLatch: onLatch}
}

// setInitialWindow sets the safe initial credit window used when a stream
// latches on the on-attach anchor credit (popped = 0) (INCREMENT 3). It is
// called ONCE from NewNode, before the ledger is used, with the carrier's
// per-stream mailbox byte bound (MaxBytesPerStream); when that limit is
// unavailable (<=0) it falls back to the mux default so the sender is never
// unbounded. It is not safe for concurrent use with the ledger's data
// methods — it must only run at construction.
func (l *creditLedger) setInitialWindow(w uint64) {
	if w == 0 {
		w = uint64(mux.DefaultStreamLimits.MaxBytesPerStream)
	}
	l.mu.Lock()
	l.initialWindow = w
	l.mu.Unlock()
}

// creditEntry is one logical stream's sender credit state. It is anchored
// to a down-carrier generation; a rebind (new generation) resets
// cumulativeSent and re-arms the establishment window.
type creditEntry struct {
	mu      sync.Mutex
	gen     uint64
	cumSent uint64
	latched bool
	window  uint64
	// est is the armed establishment timer; estSeq is a monotonically
	// increasing marker so only the NEWEST armed timer counts a fallback
	// (a rebind re-arm or a latch makes older timers stale — no double
	// count, no count after the stream established).
	est    *time.Timer
	estSeq uint64
}

// snapshot copies the decision fields for streamID under the ledger lock.
// A missing or stale-generation entry reports the un-latched, zero-window
// state so the gate treats it as unlimited.
func (l *creditLedger) snapshot(streamID uint32) ledgerSnap {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[streamID]
	if !ok {
		return ledgerSnap{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return ledgerSnap{gen: e.gen, latched: e.latched, window: e.window, cumulativeSent: e.cumSent}
}

// currentGen returns the generation the entry for streamID is anchored to
// (0 when absent). The relay gate uses it to apply the REAL current-
// generation check: a credit frame only latches a stream for the down-
// carrier generation it was observed on, so a late/stale-generation credit
// can never gate (or over-credit) the current stream (R2-2; it is NOT the
// FrameRebind-only node.go:821 guard).
func (l *creditLedger) currentGen(streamID uint32) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.entries[streamID]; ok {
		e.mu.Lock()
		g := e.gen
		e.mu.Unlock()
		return g
	}
	return 0
}

// addSent advances the sender's cumulative-sent counter by bytes for
// streamID, anchored to gen. It is called from the down relay's flush path
// after each successful FrameData write. It is idempotent under rebind:
// a rebind re-anchors the entry (zeroing cumSent) BEFORE the first
// post-rebind data write, so the two counters stay anchored together (§E.4.1).
//
// INCREMENT 3: on a latched entry, addSent also DRAINS the live window
// budget (window = max(0, window - bytes)) so a credit-latched sender is
// bounded from its first credit onward — it can never commit more bytes than
// the window (initially the mailbox capacity, then the receiver's drained
// credit) allows. A recompute in onCredit from the absolute counters still
// takes precedence on the next credit. The clamp never wraps (R2-3).
func (l *creditLedger) addSent(streamID uint32, bytes, gen uint64) {
	if bytes == 0 {
		return
	}
	l.mu.Lock()
	e, ok := l.entries[streamID]
	if !ok {
		e = &creditEntry{gen: gen}
		l.entries[streamID] = e
	}
	l.mu.Unlock()
	e.mu.Lock()
	if e.gen != gen {
		// A data write landed on a generation the entry does not know about
		// (e.g. the anchor credit had not been observed yet). Re-anchor:
		// both counters to 0, un-latched (A4). This keeps cumSent anchored
		// to the generation the credit will observe.
		e.gen = gen
		e.cumSent = 0
		e.latched = false
		e.window = 0
	}
	e.cumSent += bytes
	// INCREMENT 3: spend from the live window budget (PARK, never wrap).
	if e.window >= bytes {
		e.window -= bytes
	} else {
		e.window = 0
	}
	e.mu.Unlock()
}

// onCredit is called by the down carrier's dispatcher (OnStreamCredit) for
// every VALID FrameCredit (version 1, exact 18-byte payload — validated in
// pkg/mux before the callback fires). It re-anchors on a generation change,
// latches on the first valid frame for the generation, and recomputes the
// window with the mandatory clamp (PARK, never wrap).
func (l *creditLedger) onCredit(streamID uint32, popped, gen uint64) {
	l.mu.Lock()
	e, ok := l.entries[streamID]
	if !ok {
		e = &creditEntry{gen: gen}
		l.entries[streamID] = e
	}
	l.mu.Unlock()

	e.mu.Lock()
	if e.gen != gen {
		// Rebind reset (deterministic, §E.4.1 / §I Step 2): both sides
		// anchor to 0 on a new generation; the stream is UN-LATCHED again
		// and the establishment window is re-armed by the attach path.
		// Invalidate any timer armed for the OLD generation so it cannot
		// count a fallback for the fresh one.
		e.gen = gen
		e.cumSent = 0
		e.latched = false
		e.window = 0
		e.estSeq++
	}
	// MANDATORY clamp (R2-3, load-bearing): if popped < cumSent the window
	// is 0 (PARK), never a wrapped uint64. This is reachable during the
	// un-latched / revert-to-unlimited windows where the sender ran free
	// and can outpace the next credit frame.
	if popped >= e.cumSent {
		e.window = popped - e.cumSent
	} else {
		e.window = 0
	}
	// INCREMENT 3 (A4 relaxed at this call site): latch on ANY valid credit
	// frame for the current generation — including the on-attach ANCHOR
	// (popped == 0) — not only a drained credit. Live diagnosis showed the
	// anchor does NOT latch, so while un-latched the sender runs unlimited,
	// outruns the per-stream mailbox (MaxBytesPerStream), and the first data
	// frame is refused → data_undeliverable before any latch could take
	// effect. Latching on the anchor fixes that root cause at this site.
	//
	// Drained credit (popped > 0): keep the derived window (popped -
	// cumulativeSent, clamped above). Anchor (popped == 0) on a FRESH latch:
	// seed a safe initial window so the sender is BOUNDED from the very first
	// credit instead of unlimited. The seed is capped to the remaining
	// mailbox capacity so it can never over-credit (R2-4, CRITICAL SAFETY):
	// a genuine on-attach anchor has both sides re-anchored to 0 (cumSent==0),
	// so seeding the full initialWindow is exactly the mailbox capacity; when
	// the un-latched sender had already flushed cumSent>0 bytes before the
	// anchor arrived (the live symptom), seed only the REMAINING capacity,
	// clamped at 0 (PARK) — never a wrapped or over-credited window.
	wasLatched := e.latched
	e.latched = true
	if !wasLatched && popped == 0 {
		if l.initialWindow >= e.cumSent {
			e.window = l.initialWindow - e.cumSent // fresh anchor ⇒ full capacity; else remaining
		} else {
			e.window = 0 // cumSent already ≥ capacity ⇒ PARK, never over-credit
		}
	}
	// A drained credit (popped > 0) keeps the derived window computed above;
	// an already-latched entry keeps its derived window as well.
	// A latch settles the establishment window: bump estSeq so any
	// still-scheduled timer becomes stale (it must not count a fallback
	// for an already-established stream).
	if e.latched {
		e.estSeq++
		e.est = nil
	}
	firstLatch := e.latched && !wasLatched
	e.mu.Unlock()

	if firstLatch && l.onLatch != nil {
		l.onLatch(streamID)
	}
}

// armEstablish records the un-latched establishment start for streamID on
// gen and (re-)arms the CreditEstablishTimeout timer (A3). When it fires
// with the stream still un-latched, the revert-to-unlimited fallback runs
// (bounded; the stream simply stays in pre-fix behaviour — never a
// terminate, never a forever-park). It is a no-op when the stream is
// already latched (established), so repeated attach frames are safe.
func (l *creditLedger) armEstablish(streamID uint32, gen uint64, timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	// l.mu guards the entries MAP only; every field of an entry is guarded
	// by e.mu (the same lock onCredit / addSent / snapshot use), so all
	// entry-field reads/writes below run under e.mu. l.mu is released
	// before e.mu is taken — the two locks are never held together.
	l.mu.Lock()
	e, ok := l.entries[streamID]
	if !ok {
		e = &creditEntry{gen: gen}
		l.entries[streamID] = e
	}
	l.mu.Unlock()

	e.mu.Lock()
	if e.gen != gen {
		// Rebind reset (deterministic, §E.4.1 / §I Step 2): both sides
		// anchor to 0 on a new generation; the stream is UN-LATCHED again.
		// Invalidate any timer armed for the OLD generation.
		e.gen = gen
		e.cumSent = 0
		e.latched = false
		e.window = 0
		e.estSeq++
	}
	// Re-arm only while the stream is still un-latched on this generation;
	// once latched (a usable credit arrived) the establishment window is
	// settled and the timer is dead. Rebind-attach re-anchors the entry to
	// un-latched, so this call re-arms it for the new generation (§I 1/2).
	if e.latched {
		e.mu.Unlock()
		return
	}
	e.estSeq++
	seq := e.estSeq
	if e.est != nil {
		e.est.Stop()
	}
	e.est = time.AfterFunc(timeout, func() {
		e.mu.Lock()
		// Only the NEWEST armed timer counts a fallback: a latch, a rebind
		// re-arm, or clearStream bumps estSeq (or sets latched), making
		// this timer (seq) stale. Reverting to unlimited is exactly the
		// un-latched pre-fix behaviour — never a terminate, never a park.
		fellBack := !e.latched && e.estSeq == seq
		if fellBack {
			e.est = nil
		}
		e.mu.Unlock()
		if fellBack {
			if l.onTimeout != nil {
				l.onTimeout(streamID)
			}
		}
	})
	e.mu.Unlock()
}

// clearStream drops the stream's entry and any armed timer (session end or
// the stream leaving the store). Idempotent. Bumping estSeq makes any
// still-scheduled timer stale (it must not count a fallback for a cleared
// stream), and stopping the timer frees the entry.
func (l *creditLedger) clearStream(streamID uint32) {
	l.mu.Lock()
	e := l.entries[streamID]
	if e != nil {
		delete(l.entries, streamID)
	}
	l.mu.Unlock()
	if e != nil {
		e.mu.Lock()
		e.estSeq++ // invalidate any armed timer for this stream
		if e.est != nil {
			e.est.Stop()
			e.est = nil
		}
		e.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Node-side credit wiring (emitter on Iran; gate + callbacks on Germany).
// ---------------------------------------------------------------------------

// creditRebindAttach is the (re)bind-attach anchor for the DOWN direction
// (§I Step 2). It runs on BOTH roles after a down attach (bootstrap or
// rebind): Iran re-emits the initial down-credit (popped=0 on the fresh
// carrier's stream record) and baselines its emission hysteresis, and the
// Germany sender re-arms the establishment timer on the new generation.
// The two halves are idempotent and role-guarded, so calling it on either
// side of a rebind-attach is safe.
func (n *Node) creditRebindAttach(streamID uint32, gen uint64) {
	n.emitCreditAnchor(streamID)
	n.armCreditEstablish(streamID, gen)
}

// emitCreditAnchor is the (re)bind-bootstrap initial credit (§I Step 2): it
// anchors BOTH sides to 0 for a freshly-attached (or re-attached) down
// stream, including one that has not yet popped. On Iran it is written as a
// FrameCredit with poppedBytesTotal=0 through the Ready()-checked down-
// carrier accessor, generation-pinned and inert on failure.
func (n *Node) emitCreditAnchor(streamID uint32) {
	if n.cfg.Role != RoleIran || streamID == 0 {
		return
	}
	n.setLastEmitted(streamID, 0)
	n.writeCredit(streamID, 0)
}

// emitCreditPopped is the OnStreamPopped handler (Iran): it runs in the
// streamWorker goroutine STRICTLY after the pop path released q.mu, and
// applies the emission hysteresis (CreditThreshold, §E.1) before writing a
// FrameCredit on the down carrier.
func (n *Node) emitCreditPopped(streamID uint32, poppedTotal uint64) {
	if n.cfg.Role != RoleIran {
		return
	}
	if !n.shouldEmit(streamID, poppedTotal) {
		return
	}
	n.writeCredit(streamID, poppedTotal)
}

// writeCredit performs the actual FrameCredit emission. It resolves the down
// carrier through the Ready()-checked accessor (currentIfReady, never a
// plain un-checked current()) and pins the generation it writes against (a
// concurrent rebind cannot place this frame on a superseded/dying carrier).
// The write is a BLOCKING handoff on the carrier's serialized write path
// (§E.5, rev-3 Note C — NOT a non-blocking control-frame shortcut) and must
// never run while q.mu is held. Any failure / not-ready outcome makes the
// frame INERT: it is dropped, never retried, and it can never terminate a
// stream or alter DATA ordering (a lost credit is absorbed by the sender's
// CreditEstablishTimeout / revert-to-unlimited).
func (n *Node) writeCredit(streamID uint32, poppedTotal uint64) {
	h := n.currentIfReady(session.DirDown)
	if h == nil {
		return // carrier absent or NOT ready ⇒ inert (drop), A3/§E.5
	}
	// PIN the generation we emit against: we write on the handle we just
	// resolved (its gen is fixed), never re-resolving, so a rebind that
	// supersedes n.down in flight cannot move this frame onto a dying
	// carrier — a write racing that carrier's Close simply fails inert.
	info := mux.CreditFrameInfo{
		CreditVersion:         mux.CreditVersion1,
		CumulativeBytesPopped: poppedTotal,
		// CreditWindow is the informational D1-Q6 value; the sender
		// re-derives the authoritative window (popped - cumulativeSent),
		// so a 0 here is correct and ignored by the sender.
	}
	_ = h.carrier.WriteFrame(streamID, mux.FrameCredit, mux.CreditPayload(info)) // INERT on error
}

// shouldEmit applies the emission hysteresis (§E.1): emit a FrameCredit only
// when the stream's cumulative popped total has advanced by at least
// CreditThreshold since the last emitted credit (or on the first emit). The
// counter is absolute, so a dropped emit self-heals on the next one.
func (n *Node) shouldEmit(streamID uint32, poppedTotal uint64) bool {
	n.creditEmitMu.Lock()
	defer n.creditEmitMu.Unlock()
	last, ok := n.creditEmitLast[streamID]
	if !ok {
		n.creditEmitLast[streamID] = poppedTotal
		return true
	}
	if poppedTotal <= last || poppedTotal-last < uint64(n.cfg.CreditThreshold) {
		return false
	}
	n.creditEmitLast[streamID] = poppedTotal
	return true
}

func (n *Node) setLastEmitted(streamID uint32, poppedTotal uint64) {
	n.creditEmitMu.Lock()
	n.creditEmitLast[streamID] = poppedTotal
	n.creditEmitMu.Unlock()
}

// onCredit (Germany): the down carrier's OnStreamCredit callback. It is
// dispatched for every VALID credit frame on THIS carrier (a superseded
// carrier's dispatcher has exited, so its frames never arrive — R2-2), so
// the pinned gen (this handle's generation) is always the current one.
func (n *Node) onCredit(streamID uint32, info mux.CreditFrameInfo, gen uint64) {
	if n.cfg.Role != RoleGermany {
		return
	}
	n.creditLedger.onCredit(streamID, info.CumulativeBytesPopped, gen)
}

// addSent (Germany, DirDown only): record the bytes just flushed to the
// down carrier for the stream, anchored to the attachment's generation
// (§E.4.1). The up direction has no credit gate, so its bytes are not
// tracked.
func (n *Node) addSent(dir session.Direction, streamID uint32, bytes int, gen uint64) {
	if dir != session.DirDown || n.cfg.Role != RoleGermany || bytes <= 0 || streamID == 0 {
		return
	}
	n.creditLedger.addSent(streamID, uint64(bytes), gen)
}

// creditPark parks a credit-blocked down relay until the stream's credit
// window refills (a new valid credit frame arrives) or the
// attachment/session state changes. It mirrors the EXISTING park
// mechanism used by the pending-full park (waitAttach, relays.go:234):
// the moment the attachment is no longer Attached, it hands off to
// waitAttach and the carrier-loss grace path takes over; while attached
// it re-checks the window on a bounded 50ms cadence — the same re-check
// style as waitAttach's unattached re-check — so a credit-dead stream
// cannot busy-spin the relay goroutine while the carrier is healthy. It
// never holds a lock across the park and never inverts c.mu → q.mu
// (R2-1).
func (n *Node) creditPark(sess *session.Session, dir session.Direction, att *session.Attachment) {
	id := streamIDOf(sess, dir)
	for {
		select {
		case <-sess.Ctx.Done():
			return
		default:
		}
		if n.creditLedger.snapshot(id).window > 0 {
			return // window refilled: unpark
		}
		st, _ := att.State()
		if st != session.AttAttached {
			// Detached (carrier lost) or closed: hand off to the existing
			// grace path; it bounds the park and re-attaches or closes
			// the session.
			n.waitAttach(sess, att)
			return
		}
		sig := att.ReadySignal()
		select {
		case <-sess.Ctx.Done():
			return
		case <-sig:
		case <-time.After(50 * time.Millisecond): // bounded re-check cadence
		}
	}
}

// creditGate is the DirDown gate predicate (C / §E.2, §E.3). It is ONLY
// consulted in the !socketEOF fall-through of relayShapeA, immediately
// before the socket read; the socketEOF branch is never credit-gated
// (half-close safety, A6). It acquires no mailbox lock and never inverts
// c.mu → q.mu (R2-1) — it reads only this node-side ledger.
//
// Returns:
//   - gated: the stream is credit-gated (latched), its window is exhausted,
//     and it has already sent at least one chunk (cumulativeSent>0) — so the
//     anchor (both counters 0) always permits the initial chunk and a fresh
//     stream can never self-deadlock.
//   - floor: the A2 credit-floor guard — a parked down-relay still drains the
//     target into `pending` up to `floor` bytes so the two-way target-
//     exhaustion cycle cannot hold (§F.2); the caller parks only once the
//     pending reaches the floor.
//   - unlatched: the stream is credit-eligible but not yet latched (running
//     unlimited, pre-fix behaviour, A4) — a metric observation, not a gate.
func (n *Node) creditGate(streamID uint32, attGen uint64) (gated bool, floor int, unlatched bool) {
	floor = n.cfg.CreditFloorDrain
	if streamID == 0 {
		return false, floor, false
	}
	s := n.creditLedger.snapshot(streamID)
	// Generation validation (real, not the FrameRebind-only guard): the
	// credit only gates for the CURRENT down generation the attachment is
	// bound to. A stale/absent entry means the stream is un-anchored on
	// this generation → unlimited (not gated).
	if s.gen != attGen || !s.latched {
		return false, floor, true
	}
	if s.window > 0 || s.cumulativeSent == 0 {
		return false, floor, false // headroom, or the always-permitted anchor chunk
	}
	return true, floor, false // latched + window==0 + already sending → gated
}

// armCreditEstablish re-arms the un-latched establishment window for
// streamID on gen (§I Step 1, A3). It runs on the SENDER (Germany) at
// (re)bind-attach and bootstrap: a stream that has not yet latched must
// establish credit within CreditEstablishTimeout, then reverts to
// unlimited. It is a no-op for the receiver (Iran) — only the Germany
// node owns the ledger. A stream already latched on this generation is
// left alone (the timer is dead once latched).
func (n *Node) armCreditEstablish(streamID uint32, gen uint64) {
	if n.cfg.Role != RoleGermany {
		return
	}
	n.creditLedger.armEstablish(streamID, gen, n.cfg.CreditEstablishTimeout)
}

// clearCreditState drops every node-side D4 credit structure for one
// logical stream on session end, so the ledger, its armed timers and the
// emission-hysteresis map have fixed, bounded cardinality and never leak
// across streams. Callers: onSessionClosed (both roles) and
// OnStreamTerminated (Germany ledger).
func (n *Node) clearCreditState(streamID uint32) {
	if streamID == 0 {
		return
	}
	n.creditLedger.clearStream(streamID)
	n.creditEmitMu.Lock()
	delete(n.creditEmitLast, streamID)
	n.creditEmitMu.Unlock()
}
