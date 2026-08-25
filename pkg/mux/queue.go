package mux

import "sync"

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
// may call TryPush; exactly ONE consumer goroutine (the stream worker)
// calls Pop.
type StreamQueue struct {
	maxFrames int
	maxBytes  int

	mu sync.Mutex
	// items is an append-only slice; removal from the front is O(n)
	// with n bounded by maxFrames — fine, and far simpler than a ring.
	items    []queueItem
	nBytes   int
	closed   bool
	wake     chan struct{} // open: a Pop is parked waiting; closed: never
	nWaiters int           // Pop calls currently parked on wake
}

// NewStreamQueue creates an empty mailbox with the given bounds.
func NewStreamQueue(maxFrames, maxBytes int) *StreamQueue {
	return &StreamQueue{maxFrames: maxFrames, maxBytes: maxBytes}
}

// fullLocked reports whether adding it would exceed either bound.
// Caller must hold q.mu.
func (q *StreamQueue) fullLocked(it queueItem) bool {
	return len(q.items) >= q.maxFrames ||
		q.nBytes+len(it.payload) > q.maxBytes
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
func (q *StreamQueue) TryPush(it queueItem) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.fullLocked(it) {
		return false
	}
	q.items = append(q.items, it)
	q.nBytes += len(it.payload)
	q.wakeLocked()
	return true
}

// Pop blocks until an item is available or the queue is closed.
// ok is false once the queue is closed (still-queued items are discarded
// by Close and accounted for via its return value). Exactly one
// goroutine may call Pop on a queue.
func (q *StreamQueue) Pop() (it queueItem, ok bool) {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			it = q.items[0]
			q.items = q.items[1:]
			q.nBytes -= len(it.payload)
			q.mu.Unlock()
			return it, true
		}
		if q.closed {
			q.mu.Unlock()
			return queueItem{}, false
		}
		// Park until a producer adds an item or Close wakes us.
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
// TryPush keeps failing. Idempotent — both the carrier's Close and stream
// termination call it.
//
// Close discards anything still queued and RETURNS the payload bytes it
// discarded, so the caller (carrier) can return them to its aggregate
// byte budget. A second Close returns 0.
func (q *StreamQueue) Close() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0
	}
	q.closed = true
	discarded := q.nBytes
	q.items = nil
	q.nBytes = 0
	q.wakeLocked()
	return discarded
}
