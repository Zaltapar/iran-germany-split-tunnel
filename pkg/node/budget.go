// Aggregate session-buffer budget (Issue #6).
//
// sessionBufferBudget is the node-level aggregate byte budget for the
// shape-A per-direction reconnect buffers (the "pending" buffers in
// relayShapeA). It mirrors the Phase 3 carrier-wide aggregate budget
// (pkg/mux: StreamLimits.MaxBytesTotal / StreamQueue.budget) for the
// session side: the per-buffer bound stays per-buffer
// (Config.BufferBytes, SPLIT_SESSION_BUFFER_BYTES); this budget bounds
// the SUM over all sessions and directions on this node.
//
// # GAUGE SEMANTICS
//
// The gauge (AccountedBytes, exposed as /metrics session_buffered_bytes)
// is EXACTLY the sum of the pending-slice lengths over all live shape-A
// relays: a byte is counted at the instant it is appended to a pending
// slice and uncounted at the instant it is flushed to a carrier or
// discarded. Each relay additionally owns one fixed read buffer
// (RelayBufSize, allocated at relay start, independent of traffic) —
// that fixed per-connection memory exists before this change and is
// deliberately not part of the budget (budgeting it would be a per-
// connection, not per-byte, policy).
//
// WHY THE CHECK-AND-CHARGE IS ATOMIC (and why it is NOT a bare atomic
// counter)
//
// The Phase 3 accounting-race fix (see the StreamQueue.budget docs in
// pkg/mux/queue.go) established the pattern this reuses: a
// check-then-add is unsafe with an atomic counter alone, because a
// concurrent decrement can slip between the check and the add (the
// check over-estimates headroom) and a reclaim can race the add
// (driving the total negative). The fix there was to perform the budget
// check and the accounting update under the same lock as the state the
// bytes belong to.
//
// Here the bytes belong to a shape-A relay's pending slice, which has
// an explicit single owner: the relayShapeA goroutine is the ONLY
// goroutine that appends to, flushes, or discards its pending buffer
// (the session Close only cancels the relay's context; nothing else
// touches the slice). The budget's own mutex serializes all relays'
// charges/refunds/reclaims with each other, so at every instant:
//
//   - 0 <= accounted <= limit (when limit > 0) — NEVER silently
//     exceeded: the only way for accounted to grow is an admitted
//     charge, and an admission happens only when
//     accounted+n <= limit under b.mu;
//   - accounted == Σ pending-slice lengths (exact, no drift, no double
//     count);
//   - reclaims are clamped to the outstanding amount, so a bug can
//     never drive the total negative.
//
// REFUSAL / BACKPRESSURE POLICY (deterministic and fair — documented,
// not accidental)
//
// A relay only charges bytes after it has read them from the socket.
// If charging would take the aggregate over the limit, chargeWait PARKS
// the relay (its bytes sit in the relay's fixed read buffer, NOT in a
// pending slice, NOT in the gauge) until either (a) a refund frees
// space — the budget wakes every parker on any space-free — or (b) the
// relay's session context is done (grace timeout / Node.Close), in
// which case the relay exits and its pending bytes are reclaimed.
//
// Consequences:
//  1. A relay blocked in sock.Read holds ZERO budget (it has not
//     charged yet), so stalled/idle peers can never starve the budget:
//     the gauge reflects only bytes actually buffered.
//  2. When the aggregate is saturated, no pending buffer grows further
//     (the node-level "no more growth" latch the issue asks for), while
//     existing buffers keep flushing — flushes refund, which frees
//     space and wakes parkers. One session's sustained stall fills at
//     most its own per-buffer cap (the per-buffer bound still applies)
//     and, across a full aggregate, blocks only until its (or any)
//     buffer drains — there is no path in which a session monopolizes
//     the budget while equally-stalled sessions starve permanently.
//  3. No deadlock: a saturated aggregate with no live carrier parks
//     every reader in chargeWait; the carrier-loss grace window
//     (Config.Grace) closes the stalled sessions, their relays exit,
//     and their bytes are refunded — the system always resolves
//     (acceptance #4). Node.Close force-reclaims everything, so
//     shutdown leaves zero accounted bytes and zero active relays
//     regardless of relay timing.
//
// LIMIT == 0 is the "no aggregate budget" sentinel (the same
// 0-means-default convention as the stream-queue fields): every charge
// is admitted immediately and nothing is accounted. Production wiring
// always passes the validated SPLIT_SESSION_BUFFER_TOTAL_BYTES.
package node

import (
	"context"
	"sync"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// bufKey identifies one shape-A relay: one (session, direction).
type bufKey struct {
	sess *session.Session
	dir  session.Direction
}

// sessionBufferBudget is the node-level aggregate byte budget for
// shape-A reconnect buffers. See the package doc comment above for the
// gauge semantics, the accounting invariants, and the refusal policy.
type sessionBufferBudget struct {
	mu sync.Mutex
	// limit <= 0: disabled (no aggregate budget).
	limit int64
	// accounted: sum of the charged (pending) bytes over all live
	// relays. Invariant when limit > 0: 0 <= accounted <= limit.
	accounted int64
	// active: live relays -> their charged byte count. Enables
	// Close()'s force-reclaim, the clamped refunds, and the
	// active-relay leak check.
	active map[bufKey]int64
	// wake: closed (and replaced) whenever space is freed, so every
	// parked chargeWait re-checks. Plain channel lifecycle (no waiter
	// count): close+replace is safe for any number of parkers — a
	// parker always observes the close of the channel it parked on and
	// re-loops.
	wake   chan struct{}
	closed bool
}

func newSessionBufferBudget(limit int) *sessionBufferBudget {
	return &sessionBufferBudget{limit: int64(limit), active: make(map[bufKey]int64)}
}

// begin registers a relay. Called once, from the relay's own goroutine,
// before its first charge. A begin after Close is a no-op (the relay
// will exit at its next ctx check / refused charge).
func (b *sessionBufferBudget) begin(k bufKey) {
	b.mu.Lock()
	if !b.closed {
		b.active[k] = 0
	}
	b.mu.Unlock()
}

// chargeWait admits n charged bytes for relay k, parking (without
// holding any budget) until they fit, the budget is closed, or ctx is
// done. It returns false in the latter two cases — the relay must then
// exit (the session is dead or the node is shutting down) and its
// still-buffered bytes are reclaimed by end.
//
// It NEVER returns true having taken the aggregate over the limit: the
// check and the add happen under b.mu, exactly as StreamQueue.TryPush
// does under q.mu.
func (b *sessionBufferBudget) chargeWait(k bufKey, n int, ctx context.Context) bool {
	if n <= 0 {
		return true
	}
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return false
		}
		if b.limit <= 0 { // disabled
			b.mu.Unlock()
			return true
		}
		if _, ok := b.active[k]; !ok {
			// Unknown relay (begun after Close, or a bug): refuse
			// loudly instead of corrupting the accounting.
			b.mu.Unlock()
			return false
		}
		if b.accounted+int64(n) <= b.limit {
			b.accounted += int64(n)
			b.active[k] += int64(n)
			b.mu.Unlock()
			return true
		}
		// No room: park until space is freed (or ctx done).
		if b.wake == nil {
			b.wake = make(chan struct{})
		}
		w := b.wake
		b.mu.Unlock()
		select {
		case <-w:
			// Space was freed somewhere: re-check.
		case <-ctx.Done():
			return false
		}
	}
}

// refund uncharges n bytes (they were flushed to a carrier or
// discarded). It returns the number of bytes actually refunded (clamped
// to the relay's outstanding charge, so a bug can never drive the total
// negative). Any positive refund wakes the parkers.
func (b *sessionBufferBudget) refund(k bufKey, n int) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n <= 0 || b.limit <= 0 || b.closed {
		return 0
	}
	cur := b.active[k]
	if int64(n) > cur {
		n = int(cur)
	}
	if n == 0 {
		return 0
	}
	b.accounted -= int64(n)
	b.active[k] = cur - int64(n)
	b.wakeLocked()
	return int64(n)
}

// end deregisters the relay, reclaiming any charged bytes it still
// holds (session ended with buffered data: discard + refund). It returns
// the reclaimed byte count (0 in the common case, where the relay has
// already flushed its whole pending slice).
func (b *sessionBufferBudget) end(k bufKey) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, ok := b.active[k]
	if !ok {
		return 0
	}
	if b.limit > 0 && !b.closed && cur > 0 {
		b.accounted -= cur
	}
	delete(b.active, k)
	if cur > 0 {
		b.wakeLocked()
	}
	return cur
}

// wakeLocked signals every parked chargeWait that the budget state
// changed (space freed). Caller must hold b.mu.
func (b *sessionBufferBudget) wakeLocked() {
	if b.wake != nil {
		close(b.wake)
		b.wake = make(chan struct{})
	}
}

// AccountedBytes is the current aggregate usage — EXACTLY the sum of
// the live relays' pending-slice lengths (the /metrics gauge).
func (b *sessionBufferBudget) AccountedBytes() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.accounted
}

// ActiveRelays is the number of registered relays (white-box leak check:
// must be 0 after Node.Close).
func (b *sessionBufferBudget) ActiveRelays() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.active)
}

// Close force-reclaims every outstanding charge and closes the budget;
// idempotent. Returns the reclaimed byte count. Node.Close calls it;
// after it, AccountedBytes() is 0, ActiveRelays() is 0, and every
// parked chargeWait is woken and returns false.
func (b *sessionBufferBudget) Close() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0
	}
	b.closed = true
	var reclaimed int64
	for k, cur := range b.active {
		if b.limit > 0 {
			reclaimed += cur
			b.accounted -= cur
		}
		delete(b.active, k)
	}
	b.wakeLocked()
	return reclaimed
}
