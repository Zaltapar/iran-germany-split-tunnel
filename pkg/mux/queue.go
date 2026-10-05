package mux

import (
	"sync"
	"sync/atomic"
)

// queueItem is one entry in a stream's bounded mailbox.
//
//   - data/header frames: payload non-nil, isClose false;
//   - FrameClose:         payload nil, isClose true (0 bytes, 1 frame).
type queueItem struct {
	payload []byte
	isClose bool
}

// StreamQueue is the bounded per-stream mailbox between the dispatcher
// and a stream's consumer.
//
// Why it exists: before Phase 3 the dispatcher did a blocking send into a
// 64-slot stream channel. One consumer that stopped reading filled that
// channel and blocked the dispatcher, stalling EVERY other stream on the
// carrier (head-of-line blocking, Issue B). Now the dispatcher only does
// a non-blocking TryPush; if the mailbox is full the dispatcher moves on
// to other streams and applies the overflow policy to just this stream
// (see CarrierConn.deliver/applyPressure/terminateStream).
//
// Memory bound is dual: at most MaxFrames items AND at most MaxBytes
// bytes (a mailbox of 64 full-size frames is very different from 64 tiny
// ones, so the frame count alone is not a real bound). The carrier adds
// an aggregate byte budget on top of the per-stream limits.
//
// Concurrency contract: many producers (in practice only the dispatcher)
// may call TryPush/TryCarry; exactly ONE consumer goroutine (the stream
// worker) calls Pop.
type StreamQueue struct {
	maxFrames int
	maxBytes  int

	mu sync.Mutex
	// items is the PRIMARY mailbox: an append-only slice, removal from the
	// front is O(n) with n bounded by maxFrames — fine, and far simpler
	// than a ring.
	items  []queueItem
	nBytes int
	// overflow is the RETRY-GRACE carry region (SUBTASK 26): when the
	// primary is full (a transient consumer stall — the ~1 MB
	// download-truncation signature), the dispatcher CARRIES a refused
	// item here instead of terminating the stream. It is NOT a parallel
	// mailbox: Pop serves the primary first and falls through to the carry
	// region only when the primary is empty, so per-stream FIFO holds — a
	// carried FrameClose is reached only after every older carried data
	// frame, and a carried tail can never be stranded at end-of-data.
	//
	// Carried bytes ARE charged to the aggregate carrier budget (so
	// MaxBytesTotal remains a true memory bound) and bounded per-stream by
	// overflowCap (= MaxBytesPerStream); when the cap is exhausted the
	// consumer is far behind and the dispatcher escalates to a clean abort
	// (deliver-or-fail). Escalation is also time-bounded: a carry episode
	// that has made no drain progress for the full OverflowWait escalates
	// (see ovSince / CarrySince).
	overflow         []queueItem
	overflowBytes    int
	overflowCap      int // payload-byte cap; aggregate budget is also enforced
	overflowFrameCap int // hard item cap, including zero-length frames
	closed           bool
	wake             chan struct{} // open: a Pop is parked waiting; closed: never
	nWaiters         int           // Pop calls currently parked on wake

	// budget, when non-nil, is the carrier-wide aggregate byte budget
	// (see CarrierConn.queuedBytes). Byte accounting is done HERE, under
	// q.mu, so the dispatcher's check+add (TryPush/TryCarry) and the
	// worker's pop+subtract (Pop) are serialized per stream: an item is
	// counted in the aggregate exactly while it is in the mailbox, never
	// before (an unpushed item) and never twice (a popped item reclaimed by
	// Close). A race-free check-then-add is impossible with an atomic
	// counter outside this lock, and the old unguarded Load→TryPush→Add
	// sequence in deliver() let a pop slip between the check and the add,
	// over-counting the budget (and Close then re-claiming the
	// already-decremented bytes, driving the total negative).
	budget *int64
	// budgetLimitLocked is the carrier-wide aggregate limit
	// (StreamLimits.MaxBytesTotal) for TryPush's check. It is a plain
	// field updated by SetBudgetLimit under q.mu (SetStreamLimits keeps
	// it in sync for existing mailboxes). Keeping it a value — not a
	// callback that would take another lock while q.mu is held — is what
	// keeps the lock ordering q.mu-only on the hot path.
	budgetLimitLocked int64

	// stats is optional instrumentation. It is assigned before a queue is
	// exposed to a dispatcher/worker and is always read while q.mu is held.
	stats *QueueStats
	// queuedItems points at the carrier-wide queued item counter. It is
	// separate from budget because tests may use a queue without an aggregate
	// byte budget.
	queuedItems *int64
}

// NewStreamQueue creates an empty mailbox with the given bounds. budget
// is the carrier-wide aggregate byte counter the mailbox must keep in
// sync (may be nil for tests that do not model the aggregate budget);
// budgetLimit is the current aggregate limit for pushes.
func NewStreamQueue(maxFrames, maxBytes int, budget *int64, budgetLimit int64) *StreamQueue {
	frameCap := maxFrames * 16
	if frameCap < maxFrames {
		frameCap = maxFrames
	}
	return &StreamQueue{
		maxFrames:         maxFrames,
		maxBytes:          maxBytes,
		overflowCap:       maxBytes,
		overflowFrameCap:  frameCap,
		budget:            budget,
		budgetLimitLocked: budgetLimit,
	}
}

// SetStats installs the optional queue telemetry surface. The queue mutex
// keeps assignment ordered with TryPush, TryCarry, Pop, and Close.
func (q *StreamQueue) SetStats(s *QueueStats) {
	q.mu.Lock()
	q.stats = s
	q.mu.Unlock()
}

// setQueuedItems installs the carrier-wide queued-item counter. Caller may
// invoke it before the queue is exposed to any producer or consumer.
func (q *StreamQueue) setQueuedItems(items *int64) {
	q.mu.Lock()
	q.queuedItems = items
	q.mu.Unlock()
}

// adjustAggregateLocked applies one mailbox occupancy delta to the existing
// aggregate byte/item accounting and returns both post-update totals. Caller
// must hold q.mu. The carrier-owned counters remain authoritative; when a
// queue is used standalone, the stats gauges provide the aggregate mirror.
func (q *StreamQueue) adjustAggregateLocked(bytesDelta, itemsDelta int64) (int64, int64) {
	var totalBytes, totalItems int64
	if q.budget != nil {
		totalBytes = atomic.AddInt64(q.budget, bytesDelta)
	}
	if q.queuedItems != nil {
		totalItems = atomic.AddInt64(q.queuedItems, itemsDelta)
	}
	if q.stats != nil {
		if q.budget == nil {
			totalBytes = atomic.AddInt64(&q.stats.QueuedBytesNow, bytesDelta)
		} else {
			atomic.AddInt64(&q.stats.QueuedBytesNow, bytesDelta)
		}
		if q.queuedItems == nil {
			totalItems = atomic.AddInt64(&q.stats.QueuedFramesNow, itemsDelta)
		} else {
			atomic.AddInt64(&q.stats.QueuedFramesNow, itemsDelta)
		}
	}
	return totalBytes, totalItems
}

// SetBudgetLimit updates the aggregate limit for TryPush's check.
// Takes q.mu; the carrier calls it (for every existing mailbox) when
// SetStreamLimits changes MaxBytesTotal.
func (q *StreamQueue) SetBudgetLimit(n int64) {
	q.mu.Lock()
	q.budgetLimitLocked = n
	q.mu.Unlock()
}

// SetOverflowCap re-sizes the retry-grace carry region: when the primary is
// full, a refused item may be carried here (up to n payload bytes) instead
// of terminating the stream. The carrier keeps it in sync with
// StreamLimits.MaxBytesPerStream (SetStreamLimits). n <= 0 disables the
// region, restoring the pre-retry-grace behaviour (a refused frame
// escalates immediately). Caller may invoke it before the queue is exposed
// to a dispatcher/worker; q.mu keeps the assignment ordered.
func (q *StreamQueue) SetOverflowCap(n int) {
	q.mu.Lock()
	q.overflowCap = n
	q.mu.Unlock()
}

// fullLocked reports whether adding it to the primary would exceed either
// bound. Caller must hold q.mu.
func (q *StreamQueue) fullLocked(it queueItem) bool {
	// A non-empty carry region is an ordering barrier: every later frame
	// must join its tail, never jump back into the primary ahead of it.
	return len(q.overflow) > 0 || len(q.items) >= q.maxFrames ||
		q.nBytes+len(it.payload) > q.maxBytes
}

// rejectReasonLocked classifies the mutually-exclusive TryPush rejection
// predicates. Caller must hold q.mu.
func (q *StreamQueue) rejectReasonLocked(it queueItem) rejectReason {
	switch {
	case q.closed:
		return rejectClosed
	case len(q.overflow) > 0:
		return rejectStreamFrames
	case len(q.items) >= q.maxFrames:
		return rejectStreamFrames
	case q.nBytes+len(it.payload) > q.maxBytes:
		return rejectStreamBytes
	default:
		return rejectAggregate
	}
}

// wakeLocked signals a parked Pop (if any) that the queue state changed.
// Caller must hold q.mu.
func (q *StreamQueue) wakeLocked() {
	if q.nWaiters > 0 {
		close(q.wake)
		q.wake = nil
		q.nWaiters = 0
	}
}

// TryPush appends it without blocking. It returns false — without
// modifying the queue — when the queue is closed or full. The dispatcher
// must never block in here.
//
// When an aggregate budget is attached, a push is ALSO refused when it
// would take the carrier-wide total over the budget. The budget check
// and the accounting update happen under q.mu, so the total is exactly
// the sum of the payload bytes in all attached mailboxes at all times.
func (q *StreamQueue) TryPush(it queueItem) bool {
	ok, _ := q.TryPushReason(it)
	return ok
}

// TryPushReason is TryPush but also reports, on refusal, WHY the push was
// refused (the mutually-exclusive rejectReason). It lets the dispatcher's
// overflow policy (the retry-grace, SUBTASK 26) distinguish a PER-STREAM
// bound refusal (frame count or stream byte cap — a transient consumer
// stall that the dispatcher may CARRY across the pressure window) from a
// carrier-wide AGGREGATE refusal or a CLOSED mailbox (which are not
// transient stalls and escalate immediately). On acceptance it returns
// (true, 0).
func (q *StreamQueue) TryPushReason(it queueItem) (bool, rejectReason) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.fullLocked(it) {
		r := q.rejectReasonLocked(it)
		if q.stats != nil {
			q.stats.reject(r)
		}
		return false, r
	}
	if q.budget != nil &&
		atomic.LoadInt64(q.budget)+int64(len(it.payload)) > q.budgetLimitLocked {
		if q.stats != nil {
			q.stats.reject(rejectAggregate)
		}
		return false, rejectAggregate
	}
	q.items = append(q.items, it)
	q.nBytes += len(it.payload)
	totalBytes, totalItems := q.adjustAggregateLocked(int64(len(it.payload)), 1)
	if q.stats != nil {
		q.stats.push(len(it.payload))
		q.stats.observeHighStream(int64(q.nBytes), int64(len(q.items)))
		q.stats.observeHighQueued(totalBytes, totalItems)
	}
	q.wakeLocked()
	return true, 0
}

// TryCarry appends it to the carry region without blocking. It succeeds when
// the queue is not closed, the carry region is enabled, and the item fits
// BOTH the per-stream carry cap (overflowCap) and the carrier-wide aggregate
// budget (carried bytes are counted there, so MaxBytesTotal stays a true
// memory bound). On refusal it reports rejectAggregate for the cap/budget
// (the consumer is far behind, or the carrier is saturated — the dispatcher
// escalates) and rejectClosed for a closed mailbox. On success it wakes a
// parked Pop (a worker waiting on an empty primary can now take the tail).
func (q *StreamQueue) TryCarry(it queueItem) (bool, rejectReason) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		if q.stats != nil {
			q.stats.reject(rejectClosed)
		}
		return false, rejectClosed
	}
	if q.overflowCap <= 0 || len(q.overflow) >= q.overflowFrameCap || q.overflowBytes+len(it.payload) > q.overflowCap {
		if q.stats != nil {
			q.stats.reject(rejectAggregate)
		}
		return false, rejectAggregate
	}
	if q.budget != nil &&
		atomic.LoadInt64(q.budget)+int64(len(it.payload)) > q.budgetLimitLocked {
		if q.stats != nil {
			q.stats.reject(rejectAggregate)
		}
		return false, rejectAggregate
	}
	q.overflow = append(q.overflow, it)
	q.overflowBytes += len(it.payload)
	totalBytes, totalItems := q.adjustAggregateLocked(int64(len(it.payload)), 1)
	if q.stats != nil {
		q.stats.observeHighQueued(totalBytes, totalItems)
	}
	q.wakeLocked()
	return true, 0
}

// OverflowLen reports how many items are currently held in the carry region.
// The dispatcher uses it to know a carry episode is in flight (and therefore
// that a refused close must be carried behind its data rather than dropped
// through the legacy pressure path).
func (q *StreamQueue) OverflowLen() int {
	q.mu.Lock()
	n := len(q.overflow)
	q.mu.Unlock()
	return n
}

// OverflowDataLen reports how many of the carried items are DATA frames
// (isClose false). The dispatcher credits them to dropped_data_frames when
// it escalates to a clean abort.
func (q *StreamQueue) OverflowDataLen() int {
	q.mu.Lock()
	n := 0
	for _, ov := range q.overflow {
		if !ov.isClose {
			n++
		}
	}
	q.mu.Unlock()
	return n
}

// QueueDataLen reports the total number of DATA items (isClose false)
// sitting in BOTH the primary mailbox and the carry region. The dispatcher
// uses it in failUndeliverableData to credit every undelivered DATA frame
// to dropped_data_frames when a stream is cleanly aborted.
func (q *StreamQueue) QueueDataLen() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, it := range q.items {
		if !it.isClose {
			n++
		}
	}
	for _, it := range q.overflow {
		if !it.isClose {
			n++
		}
	}
	return n
}

// overflowLocked pops one item from the carry region. Caller must hold q.mu;
// it returns ok=false when the region is empty. Carried bytes were charged
// to the aggregate budget, so they are returned to it here.
func (q *StreamQueue) overflowLocked() (it queueItem, ok bool) {
	if len(q.overflow) == 0 {
		return queueItem{}, false
	}
	it = q.overflow[0]
	q.overflow = q.overflow[1:]
	q.overflowBytes -= len(it.payload)
	totalBytes, totalItems := q.adjustAggregateLocked(-int64(len(it.payload)), -1)
	if q.stats != nil {
		q.stats.observeHighQueued(totalBytes, totalItems)
	}
	return it, true
}

// Pop blocks until an item is available or the queue is closed.
// ok is false once the queue is closed AND both regions are empty
// (still-queued items are discarded by Close and accounted for via its
// return value). Exactly one goroutine may call Pop on a queue.
//
// It serves the PRIMARY mailbox first and falls through to the carry region
// only when the primary is empty — that ordering is what keeps per-stream
// FIFO under the retry-grace (a carried FrameClose can never overtake an
// older carried data frame) and what prevents a carried tail from being
// stranded at end-of-data.
//
// Popping returns the item's payload bytes to the aggregate budget
// (under q.mu, serialized with TryPush's add), so the item is counted
// in the aggregate only while it sits in the mailbox.
func (q *StreamQueue) Pop() (it queueItem, ok bool) {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			it = q.items[0]
			highBytes, highFrames := int64(q.nBytes), int64(len(q.items))
			q.items = q.items[1:]
			q.nBytes -= len(it.payload)
			totalBytes, totalItems := q.adjustAggregateLocked(-int64(len(it.payload)), -1)
			if q.stats != nil {
				q.stats.observeHighStream(highBytes, highFrames)
				q.stats.observeHighQueued(totalBytes, totalItems)
			}
			q.mu.Unlock()
			return it, true
		}
		if len(q.overflow) > 0 {
			it, _ = q.overflowLocked()
			q.mu.Unlock()
			return it, true
		}
		if q.closed {
			q.mu.Unlock()
			return queueItem{}, false
		}
		// Park until a producer adds an item (primary or carry) or Close
		// wakes us.
		if q.wake == nil {
			q.wake = make(chan struct{})
		}
		q.nWaiters++
		w := q.wake
		q.mu.Unlock()
		<-w
	}
}

// Close terminates the queue: Pop unblocks and returns ok=false, and
// TryPush/TryCarry keep failing. Idempotent — both the carrier's Close and
// stream termination call it.
//
// Close discards whatever is still queued — in BOTH the primary and the
// carry region — and RETURNS the payload bytes it discarded (the caller uses
// the value only for the stats fold; the aggregate budget is corrected here).
// When an aggregate budget is attached, those bytes are returned to it here
// (under q.mu, so a concurrently parked Pop can never decrement the same
// bytes again). A second Close returns 0.
func (q *StreamQueue) Close() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0
	}
	q.closed = true
	discarded := q.nBytes
	discardedItems := len(q.items)
	if q.stats != nil {
		q.stats.discard(int64(discarded), int64(discardedItems))
	}
	q.items = nil
	q.nBytes = 0
	// Carried bytes were charged to the aggregate budget too (TryCarry), so
	// they are reclaimed here alongside the primary's: this is the clean
	// abort, where the carried tail is deliberately lost.
	discarded += q.overflowBytes
	discardedItems += len(q.overflow)
	q.overflow = nil
	q.overflowBytes = 0
	totalBytes, totalItems := q.adjustAggregateLocked(-int64(discarded), -int64(discardedItems))
	if q.stats != nil {
		q.stats.observeHighQueued(totalBytes, totalItems)
	}
	q.wakeLocked()
	return discarded
}
