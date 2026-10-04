// Package node — Phase B credit flow-control, Slices 1-8.
//
// This file ships the CREDIT PLANE primitives and their production wiring:
//
//   - creditLedger: the per-stream SENDER-side ledger that gates how much
//     target data may be issued against a receiver's granted window, with
//     the B4 wake channel (ready / nWaiters / wakeLocked) mirroring
//     mux.StreamQueue.wake / wakeLocked (queue.go:162-168) so an accepted
//     credit un-parks a waiting relay in ~µs rather than waiting for the
//     2 s CreditSafeTimeout fallback.
//   - creditGateManager: the per-node registry of ledgers, plus the
//     per-stream CreditSafeTimeout fallback timer (arm on attach/reset,
//     fire latchSafelyCapped on silence, cancel on an accepted credit,
//     cleaned up on session close).
//   - creditEmitter / streamCredit: the per-(carrier, streamID) RECEIVER-side
//     cumulative-absolute accounting that batches credit emission at
//     creditBatchBytes and hands each credit to the mux control plane via
//     TryWriteControlFrame (fire-and-forget; a drop is pure delay, never
//     loss, because bytesConsumed is cumulative-absolute).
//
// Wiring status (Slices 4-6, now in the binary): Slices 4-5 are wired —
// relays.go charges the ledger per chunk (recordSent, flushPending) and the
// down receiver emits credits (recordConsumed/emit/finalize, the B1/SF-1
// shape); node.go accepts incoming credits into the ledger
// (OnStreamCredit → ledger.onCredit), learns the peer generation on rebind
// (recordPeerGen), and resets both the ledger and the emitter record at
// rebind/attach. Slice 6 adds the attach-time anchor credit (emitted
// go-spawned, B3) and the per-stream CreditSafeTimeout fallback timer. The
// whole plane is INERT (nil gate/emitter) unless Config.CreditsEnabled is
// set (SPLIT_CREDITS_ENABLED, default false), so the default build is
// byte-identical to the pre-credit behaviour.
package node

import (
	"context"
	"sync"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
)

// ============================================================
// Constants (design §5 table, §14; values fixed by the task)
// ============================================================

// creditWindowMax is the receiver's granted window ceiling:
// MaxBytesPerStream − creditUnackedAllowance − MaxPayload = 512 KiB
// (design §5 table). The latched, non-capped gate allows
// window + allowance; this constant is the "adaptive-down" starting window.
const creditWindowMax = 512 * 1024 // 512 KiB

// creditUnackedAllowance is the un-acked allowance added to the window on
// the latched path: 2 × mux.MaxPayload ≈ 128 KiB. Together with
// creditWindowMax it yields the UNLATCHED pre-latch bound below.
const creditUnackedAllowance = 128 * 1024 // 128 KiB

// creditPreLatchBound (B2, REV 1) is the bound on an UNLATCHED ledger from
// the instant a carrier attaches: creditWindowMax + creditUnackedAllowance =
// 640 KiB — NOT MaxBytesPerStream. This is the state that would otherwise
// re-trip fullLocked/rejectAggregate on a fresh-carrier attach and
// reproduce the D4 defect Phase B exists to fix.
const creditPreLatchBound = creditWindowMax + creditUnackedAllowance // 640 KiB

// CreditSafeWindow (S2) is the degraded SAFELY_CAPPED window: one
// mux.MaxPayload (≈ 64 KiB). It is a BOUNDED, never-unlimited state.
const CreditSafeWindow = mux.MaxPayload // ≈ 64 KiB

// CreditSafeTimeout is the fallback park bound (design §4.1): if a live
// credit does not arrive within this window while parked, the ledger
// degrades to SAFELY_CAPPED rather than parking unboundedly. With the B4
// wake channel this is a fallback, not the only exit.
const CreditSafeTimeout = 2 * time.Second

// creditBatchBytes (design §3) is the byte threshold for credit emission:
// one credit per ≥ creditBatchBytes of socket-written bytes (one per 64 KiB,
// not per 32 KiB — the D4 throttle's mechanism was the finer granularity).
const creditBatchBytes = mux.MaxPayload // ≈ 64 KiB

// creditBatchMaxAge (design §3) is the time threshold OR-ed with the byte
// threshold so a trickle-then-burst consumer is not starved of a credit.
const creditBatchMaxAge = 100 * time.Millisecond

// creditInitialWindow is the adaptive-down starting window: creditWindowMax.
const creditInitialWindow = creditWindowMax // 512 KiB

// ============================================================
// creditLedger — the per-stream sender-side gate ledger
// ============================================================

// creditLedger is the per-stream ledger that bounds how much target data
// the sender may issue against a receiver's granted window. All state is
// guarded by mu; mu is a LEAF lock (never held while calling a ledger
// method, never nested under a mux lock — design §9 proof 2).
//
// ready / nWaiters / wakeLocked mirror mux.StreamQueue.wake / wakeLocked
// (queue.go:162-168): ready is closed-and-replaced on each accepted credit
// that LOWERS outstanding; creditPark selects on it, so a live credit
// un-parks a waiting relay within ~µs instead of waiting the full
// CreditSafeTimeout.
type creditLedger struct {
	mu           sync.Mutex
	outstanding  uint64        // issued − credited, clamped >= 0
	lastSeen     uint64        // last accepted bytesConsumed (monotonic guard)
	window       uint32        // accepted windowGranted (clamped to MaxBytesPerStream)
	latched      bool          // after first valid credit
	safelyCapped bool          // degraded by CreditSafeTimeout
	gen          uint64        // pinned to the arriving-carrier gen at latch
	ready        chan struct{} // nil/open: parked waiters present; closed: woken
	nWaiters     int           // parked creditPark callers
}

// wakeLocked signals a parked creditPark (if any) that the ledger state
// changed. Mirrors StreamQueue.wakeLocked exactly (queue.go:162-168): the
// caller must hold l.mu.
func (l *creditLedger) wakeLocked() {
	if l.nWaiters > 0 {
		close(l.ready)
		l.ready = nil
		l.nWaiters = 0
	}
}

// canSendLocked reports whether chunk bytes may be issued now. It assumes
// l.mu is held. The UNLATCHED bound is creditPreLatchBound (B2); the
// latched bound is window+allowance, or CreditSafeWindow when degraded.
// capBytes is the CARRIER's live MaxBytesPerStream (S1) so the clamp can
// never silently exceed the real mailbox cap.
func (l *creditLedger) canSendLocked(chunk, capBytes uint64) bool {
	limit := uint64(creditPreLatchBound) // B2: UNLATCHED bound = 640 KiB
	if l.latched {
		if l.safelyCapped {
			limit = CreditSafeWindow
		} else {
			limit = uint64(l.window) + creditUnackedAllowance
		}
	}
	if limit > capBytes {
		limit = capBytes // S1: carrier cap, not cfg
	}
	return l.outstanding+chunk <= limit
}

// canSend reports whether chunk bytes may be issued now (locks l.mu).
func (l *creditLedger) canSend(chunk, capBytes uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.canSendLocked(chunk, capBytes)
}

// recordSent charges n successfully-issued bytes against the ledger's
// in-flight (outstanding) total. Per-chunk (S3): the flush loop charges
// len(chunk) after each successful write, so a large pending flush cannot
// overshoot the gate by more than one chunk.
func (l *creditLedger) recordSent(n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.outstanding += n
}

// onCredit is called from the OnStreamCredit callback for a valid,
// connection- and stream-level-validated credit. It returns false for any
// reject (stale generation, pinned-gen mismatch, out-of-order
// bytesConsumed) without touching outstanding. On an accepted credit that
// LOWERS outstanding it calls wakeLocked (B4) so a parked creditPark is
// un-parked within ~µs; an anchor (bytesConsumed == 0, no lowering) latches
// WITHOUT waking (SF-2).
func (l *creditLedger) onCredit(p mux.CreditPayload, arrivingGen, capBytes uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if mux.StaleCreditGeneration(p.Gen, arrivingGen) {
		return false // §9: gen desync (creditGen != arriving carrier gen)
	}
	if p.Gen != l.gen {
		return false // pinned-at-latch
	}
	if p.BytesConsumed < l.lastSeen {
		return false // out-of-order (monotonic lastSeen guard)
	}
	consumed := p.BytesConsumed - l.lastSeen
	if consumed > l.outstanding {
		consumed = l.outstanding // R2-3 clamp: no underflow
	}
	lowered := consumed > 0
	l.outstanding -= consumed
	l.lastSeen = p.BytesConsumed
	if l.latched {
		l.window = mux.ClampCreditWindow(p.WindowGranted, uint32(capBytes)) // S1 clamp
		l.safelyCapped = false                                              // a live credit heals the degraded state
	}
	l.latched = true
	if lowered {
		l.wakeLocked() // B4: wake parked creditPark within ~µs, not 2 s
	}
	return true
}

// reset re-enters the UNLATCHED state on a rebind-attach (Section 7): it
// zeroes the in-flight accounting and re-pins to the new carrier's gen.
// ready / nWaiters are cleared so no stale wake channel survives the
// generation change. It is re-bounded by creditPreLatchBound (640 KiB),
// never unlimited.
func (l *creditLedger) reset(gen uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.outstanding = 0
	l.lastSeen = 0
	l.latched = false
	l.safelyCapped = false
	l.gen = gen
	l.window = creditInitialWindow
	l.ready = nil
	l.nWaiters = 0
}

// latchSafelyCapped performs the CreditSafeTimeout-driven transition to the
// SAFELY_CAPPED state: bounded (CreditSafeWindow), never unlimited. The
// manager's per-stream timer (Slice 6) invokes this; it is idempotent.
func (l *creditLedger) latchSafelyCapped() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.latched = true
	l.safelyCapped = true
	l.window = CreditSafeWindow
}

// creditPark blocks until a credit lowers outstanding enough to admit
// chunk, the context is cancelled, or CreditSafeTimeout elapses (the
// fallback). It mirrors waitAttach (relays.go:321) plus the B4 wake-channel
// select (queue.go:235-241). A live accepted credit closes l.ready and
// un-parks within ~µs, so the 2 s timeout is no longer the only exit.
func (l *creditLedger) creditPark(ctx context.Context, chunk, capBytes uint64) {
	l.mu.Lock()
	if l.canSendLocked(chunk, capBytes) {
		l.mu.Unlock()
		return // not actually gated; nothing to wait for
	}
	if l.ready == nil {
		l.ready = make(chan struct{})
	}
	l.nWaiters++
	r := l.ready
	l.mu.Unlock()
	select {
	case <-r: // woken by an accepted credit (B4)
	case <-ctx.Done():
	case <-time.After(CreditSafeTimeout): // fallback: the safe cap is applied by the manager
	}
}

// ============================================================
// creditGateManager — the per-node ledger registry
// ============================================================

// creditGateManager owns the node's credit ledgers, keyed by streamID. Its
// mutex guards the registry (and the fallback-timer map) ONLY and is always
// released before any ledger method is called (design §9: leaf, never nested
// under a mux lock). It is wired into relayShapeA (the DirDown DATA-sender
// gate, Germany) and rebind/attach bookkeeping.
type creditGateManager struct {
	mu      sync.Mutex
	ledgers map[uint32]*creditLedger
	// timers is the per-stream CreditSafeTimeout fallback timer (Slice 6).
	// Armed on attach/reset, it fires latchSafelyCapped on the stream's
	// ledger when no credit has arrived within CreditSafeTimeout, degrading
	// the sender to the BOUNDED SAFELY_CAPPED window instead of parking
	// unboundedly. Cancelled when a live credit is accepted and removed on
	// session close (removeStream) to prevent a map leak. Guarded by g.mu.
	timers map[uint32]*time.Timer
}

// newCreditGateManager returns an empty manager.
func newCreditGateManager() *creditGateManager {
	return &creditGateManager{
		ledgers: make(map[uint32]*creditLedger),
		timers:  make(map[uint32]*time.Timer),
	}
}

// arriving carrier's gen. The registry lock is released before the caller
// uses the ledger (no nesting under a mux lock). It also ARMS the
// per-stream CreditSafeTimeout fallback timer on first attach (Slice 6):
// if no credit arrives within CreditSafeTimeout the timer degrades the
// ledger to SAFELY_CAPPED rather than parking unboundedly.
func (g *creditGateManager) ledger(gen uint64, streamID uint32) *creditLedger {
	g.mu.Lock()
	l, ok := g.ledgers[streamID]
	if !ok {
		l = &creditLedger{gen: gen, window: creditInitialWindow}
		g.ledgers[streamID] = l
		g.armTimerLocked(streamID, l) // Slice 6: arm the fallback timer on attach
	}
	g.mu.Unlock()
	return l
}

// resetStream re-pins a stream's ledger to a new carrier generation on
// rebind-attach and RE-ARMS the CreditSafeTimeout fallback timer (Slice 6):
// the fresh carrier's gen must arrive a live credit within the window, or
// the ledger degrades to SAFELY_CAPPED rather than parking unboundedly.
func (g *creditGateManager) resetStream(gen uint64, streamID uint32) {
	g.mu.Lock()
	l, ok := g.ledgers[streamID]
	if !ok {
		l = &creditLedger{gen: gen, window: creditInitialWindow}
		g.ledgers[streamID] = l
	}
	g.armTimerLocked(streamID, l)
	g.mu.Unlock()
	l.reset(gen)
}

// armTimerLocked arms (or re-arms) the stream's CreditSafeTimeout fallback
// timer. Caller must hold g.mu. The timer callback releases the ledger
// reference OUTSIDE g.mu before invoking latchSafelyCapped (the timer is
// created with the ledger captured at arm time; a concurrent
// resetStream/removeStream cannot leak a stale timer because the map
// entry is replaced or deleted under g.mu before the callback could fire —
// the callback checks the current map entry and no-ops if the stream was
// already reset to a newer gen or removed).
func (g *creditGateManager) armTimerLocked(streamID uint32, l *creditLedger) {
	if old, ok := g.timers[streamID]; ok {
		old.Stop()
	}
	// Declare t separately so the closure can reference it (Go forbids
	// a variable in its own := initializer; var-then-assign is safe
	// because the closure captures the variable, not a value — by the
	// time the timer fires, t has been assigned).
	var t *time.Timer
	t = time.AfterFunc(CreditSafeTimeout, func() {
		g.mu.Lock()
		// Fire only if THIS timer is still the current one for the stream.
		// A re-arm (resetStream/ledger re-attach) or a cancel (live credit)
		// replaces/deletes the map entry, so a stale timer's callback no-ops.
		// If the ledger was removed on session close, cur is nil.
		isCurrent := g.timers[streamID] == t
		cur, ok := g.ledgers[streamID]
		g.mu.Unlock()
		if !isCurrent || !ok {
			return
		}
		if cur == l {
			l.latchSafelyCapped()
		}
	})
	g.timers[streamID] = t
}

// cancelTimerLocked stops and removes the stream's fallback timer. Called
// when a live credit is accepted (the timer no longer needs to fire).
// Caller must hold g.mu.
func (g *creditGateManager) cancelTimerLocked(streamID uint32) {
	if t, ok := g.timers[streamID]; ok {
		t.Stop()
		delete(g.timers, streamID)
	}
}

// cancelTimer stops and removes the stream's CreditSafeTimeout fallback timer
// (Slice 6): called from the credit-accept path (OnStreamCredit) so a live
// credit un-arms the degrade timer. It acquires g.mu (unlike
// cancelTimerLocked) and is O(1) — safe to call from the dispatcher
// goroutine outside c.mu. Inert when there is no armed timer.
func (g *creditGateManager) cancelTimer(streamID uint32) {
	g.mu.Lock()
	g.cancelTimerLocked(streamID)
	g.mu.Unlock()
}

// removeStream removes the stream's ledger and fallback timer on session
// close (Slice 6 timer-cleanup requirement: prevent a map leak).
func (g *creditGateManager) removeStream(streamID uint32) {
	g.mu.Lock()
	if t, ok := g.timers[streamID]; ok {
		t.Stop()
		delete(g.timers, streamID)
	}
	delete(g.ledgers, streamID)
	g.mu.Unlock()
}

// ============================================================
// creditEmitter — the per-(carrier, streamID) receiver-side emitter
// ============================================================

// carrierKey is the (S6) record key: which carrier a credit is emitted on
// and for which stream.
type carrierKey struct {
	carrier  *mux.CarrierConn
	streamID uint32
}

// streamCredit is one (carrier, streamID) credit-emission record.
// consumed is CUMULATIVE-ABSOLUTE (the running total of bytes written to
// the socket); pending is the delta since lastEmit that has not yet been
// carried in an emitted credit. Because consumed is cumulative, a dropped
// credit loses nothing durable: the next credit carries the running total.
type streamCredit struct {
	consumed uint64 // cumulative bytes written to the client socket
	pending  uint64 // bytes since lastEmit not yet in an emitted credit
	peerGen  uint64 // generation stamped on emitted credits (recordPeerGen)
	lastEmit uint64 // consumed value last carried in an emitted credit
	// lastEmitTime is when the record last emitted (or was created); the
	// time threshold creditBatchMaxAge ORs with the byte threshold so a
	// trickle-then-burst consumer is not starved of a credit (design §3).
	lastEmitTime time.Time
}

// creditEmitter tracks per-(carrier, streamID) cumulative-absolute credit
// accounting and emits FrameCredit on the carrier's control plane. mu is a
// leaf lock (design §9). maxBytes is the carrier's MaxBytesPerStream cap
// used to clamp emitted windows via ClampCreditWindow.
type creditEmitter struct {
	mu       sync.Mutex
	recs     map[carrierKey]*streamCredit
	maxBytes uint32
}

// newCreditEmitter returns an emitter that clamps emitted windows to
// maxBytes (the carrier's MaxBytesPerStream).
func newCreditEmitter(maxBytes uint32) *creditEmitter {
	return &creditEmitter{recs: make(map[carrierKey]*streamCredit), maxBytes: maxBytes}
}

// recordLocked returns (creating lazily) the record for key. Caller holds
// e.mu.
func (e *creditEmitter) recordLocked(key carrierKey) *streamCredit {
	rc, ok := e.recs[key]
	if !ok {
		rc = &streamCredit{lastEmitTime: time.Now()}
		e.recs[key] = rc
	}
	return rc
}

// timeDueLocked reports whether the record's pending bytes are old enough
// (≥ creditBatchMaxAge since the last emit) to trigger a time-threshold
// credit emission. OR-ed with the byte threshold in recordConsumed (design
// §3): a trickle-then-burst consumer is not starved of a credit. Caller
// holds e.mu.
func (e *creditEmitter) timeDueLocked(rc *streamCredit) bool {
	return time.Since(rc.lastEmitTime) >= creditBatchMaxAge
}

// recordPeerGen records the peer's carrier generation for a (carrier,
// streamID) record: the gen that emitted credits will stamp (design
// recordPeerGen, S6). It is stored on the record (emitter-side), not the
// ledger, because the gen stamped on an outgoing credit is the PEER's gen
// learned from a rebind — distinct from the ledger's pinned arriving-gen.
func (e *creditEmitter) recordPeerGen(key carrierKey, gen uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.recordLocked(key).peerGen = gen
}

// recordConsumed charges n socket-written bytes into the record and reports
// whether a credit batch is due: pending ≥ creditBatchBytes OR the record is
// ≥ creditBatchMaxAge old (timeSinceLastEmit). Both thresholds OR into
// emission (design §3); the relay calls this on every socket Write. A drop
// at emit time is safe (cumulative-absolute).
func (e *creditEmitter) recordConsumed(key carrierKey, n uint64) bool {
	e.mu.Lock()
	rc := e.recordLocked(key)
	rc.consumed += n
	rc.pending += n
	due := rc.pending >= creditBatchBytes || e.timeDueLocked(rc)
	e.mu.Unlock()
	return due
}

// buildPayload assembles the cumulative-absolute credit payload from the
// record (caller holds e.mu for the reads). window is clamped against
// maxBytes via ClampCreditWindow; final sets CreditFlagsFinal.
func (e *creditEmitter) buildPayload(rc *streamCredit, final bool) mux.CreditPayload {
	flags := byte(0)
	if final {
		flags |= mux.CreditFlagsFinal
	}
	return mux.CreditPayload{
		Version:       mux.CreditVersion,
		Gen:           rc.peerGen,
		BytesConsumed: rc.consumed, // cumulative-absolute running total
		WindowGranted: mux.ClampCreditWindow(uint32(creditWindowMax), e.maxBytes),
		Flags:         flags,
		Reserved:      make([]byte, 10),
	}
}

// emit force-flushes the record's pending bytes as one FrameCredit on the
// carrier's control plane, fire-and-forget via TryWriteControlFrame. The
// credit is built from the CUMULATIVE consumed total, so a dropped credit
// (full ctrlCh) is pure delay, never loss: the next credit (next batch,
// flush, or finalize) already carries every byte the dropped one would have
// reported. This is exactly the property design §3/O4 relies on.
//
// It reports whether a credit was actually enqueued. A drop on a full
// ctrlCh (or a nil carrier) returns false so the caller can count it as
// relay_credit_dropped_total (design §13); the drop itself is safe.
func (e *creditEmitter) emit(key carrierKey, final bool) bool {
	if key.carrier == nil {
		return false
	}
	e.mu.Lock()
	rc := e.recordLocked(key)
	if rc.pending == 0 && !final {
		e.mu.Unlock()
		return false // nothing to report and not a terminal flush
	}
	p := e.buildPayload(rc, final)
	rc.lastEmit = rc.consumed
	rc.pending = 0
	rc.lastEmitTime = time.Now()
	e.mu.Unlock()

	// Fire-and-forget: a drop on a full ctrlCh is safe (cumulative-absolute).
	ok, _ := key.carrier.TryWriteControlFrame(key.streamID, mux.FrameCredit, mux.EncodeCreditPayload(&p))
	return ok
}

// emitAnchor emits the attach-time anchor credit (bytesConsumed = 0, gen =
// peerGen, window = creditWindowMax, flags = 0) that latches the sender from
// the instant the carrier attaches (design §5 B2). It is always emitted by a
// go-spawned context (Slice 6), never inline in Dispatch/OnNewStream, and
// drop-on-full beyond 64 concurrent sessions is safe (O4).
func (e *creditEmitter) emitAnchor(key carrierKey) {
	if key.carrier == nil {
		return
	}
	e.mu.Lock()
	rc := e.recordLocked(key)
	p := mux.CreditPayload{
		Version:       mux.CreditVersion,
		Gen:           rc.peerGen,
		BytesConsumed: 0,
		WindowGranted: mux.ClampCreditWindow(uint32(creditWindowMax), e.maxBytes),
		Flags:         0,
		Reserved:      make([]byte, 10),
	}
	e.mu.Unlock()
	_, _ = key.carrier.TryWriteControlFrame(key.streamID, mux.FrameCredit, mux.EncodeCreditPayload(&p))
}

// finalize force-flushes the record on half-close, emitting the partial
// pending bytes with CreditFlagsFinal regardless of size (a terminal,
// cumulative-absolute credit: "no further credits are expected for this
// stream").
func (e *creditEmitter) finalize(key carrierKey) {
	e.emit(key, true)
}

// resetStream clears a record's accounting on rebind-attach (Slice 6
// territory; provided now for a complete wiring surface).
func (e *creditEmitter) resetStream(key carrierKey) {
	e.mu.Lock()
	delete(e.recs, key)
	e.mu.Unlock()
}

// removeStream drops the (carrier, streamID) record entirely on session
// close (Slice 6 timer-cleanup analogue on the receiver side: prevent the
// emitter's recs map from leaking one entry per finished session).
func (e *creditEmitter) removeStream(key carrierKey) {
	e.mu.Lock()
	delete(e.recs, key)
	e.mu.Unlock()
}
