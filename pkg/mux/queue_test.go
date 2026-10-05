package mux

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestStreamQueueFrameBound verifies the mailbox enforces MaxFrames even
// for tiny payloads (the frame bound is a hard ceiling on item count).
func TestStreamQueueFrameBound(t *testing.T) {
	q := NewStreamQueue(3, 1<<20, nil, 0)
	for i := 0; i < 3; i++ {
		if !q.TryPush(queueItem{payload: []byte("x")}) {
			t.Fatalf("push %d refused before the frame bound was reached", i)
		}
	}
	if q.TryPush(queueItem{payload: []byte("x")}) {
		t.Fatal("push beyond MaxFrames accepted")
	}
	// A FrameClose item still counts as one frame.
	if q.TryPush(queueItem{isClose: true}) {
		t.Fatal("FrameClose accepted beyond MaxFrames")
	}
}

// TestStreamQueueByteBound verifies the mailbox enforces MaxBytes even for
// short payloads (the byte bound is what actually caps memory).
func TestStreamQueueByteBound(t *testing.T) {
	q := NewStreamQueue(1<<20, 4, nil, 0)
	if !q.TryPush(queueItem{payload: []byte("ab")}) {
		t.Fatal("first 2-byte push refused")
	}
	if !q.TryPush(queueItem{payload: []byte("cd")}) {
		t.Fatal("push up to exactly MaxBytes refused")
	}
	if q.TryPush(queueItem{payload: []byte("e")}) {
		t.Fatal("push beyond MaxBytes accepted")
	}
	// FrameClose costs 0 bytes, so it still fits at the byte bound.
	if !q.TryPush(queueItem{isClose: true}) {
		t.Fatal("zero-byte FrameClose refused at the byte bound")
	}
}

// TestStreamQueueFIFOAndWake verifies Pop returns items in push order and
// that a parked Pop is woken by a later TryPush.
func TestStreamQueueFIFOAndWake(t *testing.T) {
	q := NewStreamQueue(8, 1<<20, nil, 0)
	want := []string{"a", "b", "c"}
	for _, s := range want {
		if !q.TryPush(queueItem{payload: []byte(s)}) {
			t.Fatalf("push %q refused", s)
		}
	}
	for _, s := range want {
		it, ok := q.Pop()
		if !ok || string(it.payload) != s {
			t.Fatalf("Pop = (%q, %v), want (%q, true)", it.payload, ok, s)
		}
	}

	itCh := make(chan queueItem, 1)
	okCh := make(chan bool, 1)
	go func() { it, ok := q.Pop(); itCh <- it; okCh <- ok }()
	select {
	case <-itCh:
		t.Fatal("Pop returned from an empty open queue")
	case <-time.After(50 * time.Millisecond):
	}
	if !q.TryPush(queueItem{payload: []byte("wake")}) {
		t.Fatal("push to wake a parked Pop failed")
	}
	select {
	case it := <-itCh:
		if ok := <-okCh; !ok {
			t.Fatal("Pop ok=false after TryPush")
		}
		if string(it.payload) != "wake" {
			t.Fatalf("Pop = %q, want %q", it.payload, "wake")
		}
	case <-time.After(time.Second):
		t.Fatal("parked Pop not woken by TryPush")
	}
}

// TestStreamQueueCloseAccountsBytes verifies Close discards queued items,
// returns their payload bytes exactly once, and leaves the queue unusable.
func TestStreamQueueCloseAccountsBytes(t *testing.T) {
	q := NewStreamQueue(8, 1<<20, nil, 0)
	q.TryPush(queueItem{payload: make([]byte, 3)})
	q.TryPush(queueItem{payload: make([]byte, 4)})
	if n := q.Close(); n != 7 {
		t.Fatalf("Close discarded = %d, want 7", n)
	}
	if n := q.Close(); n != 0 {
		t.Fatalf("second Close = %d, want 0", n)
	}
	if _, ok := q.Pop(); ok {
		t.Fatal("Pop after Close returned ok=true")
	}
	if q.TryPush(queueItem{payload: []byte("x")}) {
		t.Fatal("TryPush after Close succeeded")
	}
}

// TestStreamQueueCloseWakesParkedPop verifies a Pop parked on an empty
// queue is released by Close with ok=false.
func TestStreamQueueCloseWakesParkedPop(t *testing.T) {
	q := NewStreamQueue(8, 1<<20, nil, 0)
	okCh := make(chan bool, 1)
	go func() { _, ok := q.Pop(); okCh <- ok }()
	time.Sleep(20 * time.Millisecond) // let Pop park
	q.Close()
	select {
	case ok := <-okCh:
		if ok {
			t.Fatal("parked Pop got ok=true after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("parked Pop not woken by Close")
	}
}

// TestSanitizeLimits pins the normalization contract: zero fields fall
// back to defaults, the frame bound is clamped to MaxFrames, and an
// aggregate below the per-stream bound is REJECTED LOUDLY (a non-nil
// error, Phase B B5 amendment) — the old silent-reset-to-default is gone.
func TestSanitizeLimits(t *testing.T) {
	d := DefaultStreamLimits
	l, err := SanitizeLimits(StreamLimits{})
	if err != nil {
		t.Fatalf("SanitizeLimits(zero) errored: %v", err)
	}
	if l != d {
		t.Fatalf("SanitizeLimits(zero) = %+v, want defaults %+v", l, d)
	}

	l, err = SanitizeLimits(StreamLimits{
		MaxFramesPerStream: MaxFrames + 1,
		MaxBytesPerStream:  100,
		MaxBytesTotal:      1000,
		OverflowWait:       time.Millisecond,
	})
	if err != nil {
		t.Fatalf("SanitizeLimits clamped-frames case errored: %v", err)
	}
	if l.MaxFramesPerStream != MaxFrames {
		t.Fatalf("MaxFramesPerStream = %d, want clamp to %d", l.MaxFramesPerStream, MaxFrames)
	}

	// B5 amendment: an aggregate below the per-stream bound is a LOUD error,
	// not a silent reset to the default.
	if _, err = SanitizeLimits(StreamLimits{
		MaxFramesPerStream: 4,
		MaxBytesPerStream:  100,
		MaxBytesTotal:      50, // below the per-stream bound
		OverflowWait:       time.Millisecond,
	}); err == nil {
		t.Fatal("SanitizeLimits(MaxBytesTotal < MaxBytesPerStream) returned nil error; want the loud failure")
	}

	l, err = SanitizeLimits(StreamLimits{
		MaxFramesPerStream: 4,
		MaxBytesPerStream:  100,
		MaxBytesTotal:      1000,
		OverflowWait:       5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("SanitizeLimits(valid) errored: %v", err)
	}
	want := StreamLimits{
		MaxFramesPerStream: 4,
		MaxBytesPerStream:  100,
		MaxBytesTotal:      1000,
		OverflowWait:       5 * time.Millisecond,
	}
	if l != want {
		t.Fatalf("SanitizeLimits(valid) = %+v, want unchanged %+v", l, want)
	}
}

// TestMaxBytesPerStreamReduced pins the Phase B B5 sizing: the default
// per-stream mailbox bound dropped from 1 MiB to 704 KiB.
func TestMaxBytesPerStreamReduced(t *testing.T) {
	if got := DefaultStreamLimits.MaxBytesPerStream; got != 704<<10 {
		t.Fatalf("DefaultStreamLimits.MaxBytesPerStream = %d, want %d (704 KiB)", got, 704<<10)
	}
}

// TestMaxBytesTotalSetTo16MiB pins the Phase B B5 sizing: the default
// aggregate carrier budget is 16 MiB (NOT the v2 doc's 8 MiB, and NOT the
// pre-B5 32 MiB).
func TestMaxBytesTotalSetTo16MiB(t *testing.T) {
	if got := DefaultStreamLimits.MaxBytesTotal; got != 16<<20 {
		t.Fatalf("DefaultStreamLimits.MaxBytesTotal = %d, want %d (16 MiB)", got, 16<<20)
	}
}

// TestSanitizeLimitsFailsLoud proves the B5 loud-error contract: a
// positive MaxBytesTotal that is smaller than a positive MaxBytesPerStream
// yields a non-nil error with the documented message shape.
func TestSanitizeLimitsFailsLoud(t *testing.T) {
	_, err := SanitizeLimits(StreamLimits{
		MaxFramesPerStream: 4,
		MaxBytesPerStream:  1000,
		MaxBytesTotal:      500, // < per-stream bound
		OverflowWait:       time.Millisecond,
	})
	if err == nil {
		t.Fatal("SanitizeLimits(MaxBytesTotal < MaxBytesPerStream) returned nil; want a loud error")
	}
	want := "mux: MaxBytesTotal (500) < MaxBytesPerStream (1000); raise MaxBytesTotal to >= N_max*MaxBytesPerStream"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

// TestCarryRegionAccountingBalance is the PERMANENT form of the carry-accounting
// check that lived only in the scratch tree during the subtask-27 -race run and
// was wiped on cleanup. It proves, through the queue's normal public API, that
// the carry region's aggregate byte accounting returns to exactly zero after
// churn, is reclaimed by Close, and never drifts negative.
//
// Why it is NOT tautological: every sub-case drives the real API
// (TryPush / TryPushReason / TryCarry / Pop / Close) on a queue attached to a
// real aggregate budget, and the carry region is genuinely REACHED and
// asserted non-empty at the exact moments carried bytes are expected. The
// driving trick is fullLocked's ordering barrier (a non-empty carry region
// refuses every TryPush), so the primary is filled to its bound first and the
// refused frame must then go through TryCarry — the only way forward. If a
// regression silently stopped carrying, or let TryCarry succeed without
// charging the budget, this test fails loudly instead of passing vacuously.
// It was additionally validated by MUTATION: breaking overflowLocked's return
// of carried bytes to the aggregate makes it FAIL (see final-suite/
// carry-accounting-mutation-proof.txt).
//
// Semantics respected (learned the hard way):
//   - Pop BLOCKS on an empty open queue, so every drain is bounded by an
//     exact item count the test computed itself — never a "pop until empty"
//     loop.
//   - fullLocked refuses TryPush while the carry region is non-empty, so the
//     carry region is ALWAYS fully drained before the primary is refilled.
//   - Close reclaims carried bytes alongside the primary's, so the aggregate
//     is 0 after Close and a second Close must not re-reclaim (that
//     double-reclaim is what drove the total negative in the original bug).
//
// Bounds are deliberately tiny (maxFrames 2, per-stream cap 16 bytes) so each
// cycle provably exercises the refusal/carry path rather than riding a buffer.
func TestCarryRegionAccountingBalance(t *testing.T) {
	const (
		maxFrames = 2
		payloadSz = 8
		maxBytes  = payloadSz * 2 // per-stream cap == carry cap (overflowCap)
		cycles    = 64
		churn     = 200
	)
	const budgetLimit = int64(1 << 20)

	// budget/items mirror the carrier-wide counters StreamQueue maintains
	// (CarrierConn.queuedBytes / queuedItems); queuedItems is installed so the
	// item accounting is exercised alongside the byte accounting.
	var budget int64
	var items int64

	// Each helper takes the SUBTEST's *testing.T: a t.Fatalf raised on the
	// parent t from inside a subtest goroutine trips "FailNow on a parent
	// test", so the subtest t must be threaded through explicitly.
	assertBalanced := func(t *testing.T, stage string) {
		t.Helper()
		if got := atomic.LoadInt64(&budget); got != 0 {
			t.Fatalf("%s: aggregate queued bytes = %d, want 0 (leaked %d bytes)", stage, got, got)
		}
	}

	newQueue := func() *StreamQueue {
		q := NewStreamQueue(maxFrames, maxBytes, &budget, budgetLimit)
		q.setQueuedItems(&items)
		return q
	}

	dataFrame := func(tag byte, n int) queueItem {
		p := make([]byte, n)
		p[0] = tag
		return queueItem{payload: p}
	}

	// fillPrimary pushes exactly maxFrames data frames, exhausting the primary
	// so the NEXT frame is refused by fullLocked and must be carried.
	fillPrimary := func(t *testing.T, q *StreamQueue, tag byte) {
		t.Helper()
		for i := 0; i < maxFrames; i++ {
			if !q.TryPush(dataFrame(tag, payloadSz)) {
				t.Fatalf("TryPush(primary %d/%d) refused before the primary was full", i+1, maxFrames)
			}
		}
	}

	// drainExact pops exactly n items, n always derived from counts the test
	// itself established, so Pop can never park on an empty queue.
	drainExact := func(t *testing.T, q *StreamQueue, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			it, ok := q.Pop()
			if !ok {
				t.Fatalf("drain %d/%d: Pop returned ok=false on an open queue", i+1, n)
			}
			if it.isClose && len(it.payload) != 0 {
				t.Fatalf("drain %d/%d: FrameClose carried %d payload bytes, want 0", i+1, n, len(it.payload))
			}
		}
	}

	// Phase 1 — N add-to-carry / remove cycles must net to zero.
	t.Run("CarryThenRemoveCycles", func(t *testing.T) {
		q := newQueue()
		for c := 0; c < cycles; c++ {
			tag := byte(c%251 + 1)
			fillPrimary(t, q, tag)

			// Primary full => TryPush refused with the per-stream reason the
			// dispatcher's retry-grace turns into a carry. Pin the reason.
			if ok, reason := q.TryPushReason(dataFrame(tag, payloadSz)); ok {
				t.Fatalf("cycle %d: TryPush accepted past the primary bound", c)
			} else if reason != rejectStreamFrames {
				t.Fatalf("cycle %d: refusal reason = %v, want rejectStreamFrames", c, reason)
			}

			// Carry the refused frame — the only way it can be delivered now.
			if ok, reason := q.TryCarry(dataFrame(tag, payloadSz)); !ok {
				t.Fatalf("cycle %d: TryCarry refused (reason %v)", c, reason)
			}

			// PROVE the carry path was exercised and charged.
			if n := q.OverflowLen(); n != 1 {
				t.Fatalf("cycle %d: OverflowLen = %d, want 1 (carry region not exercised)", c, n)
			}
			if n := q.OverflowDataLen(); n != 1 {
				t.Fatalf("cycle %d: OverflowDataLen = %d, want 1", c, n)
			}
			wantBytes := int64((maxFrames + 1) * payloadSz)
			if got := atomic.LoadInt64(&budget); got != wantBytes {
				t.Fatalf("cycle %d: aggregate = %d while carried, want %d (carry bytes not charged)", c, got, wantBytes)
			}

			// Pop serves the primary first, then falls through to the carry
			// region: 2 primary + 1 carried = 3 exact pops (never blocking).
			drainExact(t, q, maxFrames+1)
			if n := q.OverflowLen(); n != 0 {
				t.Fatalf("cycle %d: OverflowLen = %d after full drain, want 0", c, n)
			}
			assertBalanced(t, "after carry/remove cycle")
		}
		q.Close()
		assertBalanced(t, "after Close of a fully drained queue")
	})

	// Phase 2 — Close() must RECLAIM residual carry bytes exactly once.
	t.Run("CloseReclaimsResidualCarry", func(t *testing.T) {
		q := newQueue()
		fillPrimary(t, q, 0xA1)
		if ok, reason := q.TryCarry(dataFrame(0xA1, payloadSz)); !ok {
			t.Fatalf("TryCarry refused (reason %v); cannot exercise Close reclaim", reason)
		}
		if n := q.OverflowLen(); n != 1 {
			t.Fatalf("OverflowLen = %d before Close, want 1", n)
		}
		wantResidual := int64((maxFrames + 1) * payloadSz)
		if got := atomic.LoadInt64(&budget); got != wantResidual {
			t.Fatalf("aggregate = %d before Close, want %d", got, wantResidual)
		}

		// Close discards BOTH regions and returns their bytes once.
		if discarded := q.Close(); discarded != int(wantResidual) {
			t.Fatalf("Close discarded = %d bytes, want %d", discarded, wantResidual)
		}
		assertBalanced(t, "after Close reclaimed the carry region")
		if n := q.OverflowLen(); n != 0 {
			t.Fatalf("OverflowLen = %d after Close, want 0", n)
		}
		// A second Close must not re-reclaim (the double-reclaim that drove
		// the total negative in the original bug): it returns 0, total stays 0.
		if second := q.Close(); second != 0 {
			t.Fatalf("second Close = %d, want 0", second)
		}
		assertBalanced(t, "after second Close")
	})

	// Phase 3 — ~200 mixed push / carry / pop / close cycles: no drift, never
	// negative, back to 0. The mix varies per cycle: the carried DATA size
	// rotates 1..payloadSz (so a 1-byte accounting error cannot hide), every
	// third cycle also carries a ZERO-BYTE FrameClose (item +1, bytes +0), and
	// every fifth cycle probes an OVER-CAP carry that MUST be refused without
	// disturbing the aggregate. This is the standing regression guard for the
	// fix that moved all byte accounting under q.mu.
	t.Run("MixedChurn200Cycles", func(t *testing.T) {
		q := newQueue()
		var pushed, popped, carried, carriedClose, refusedCarries, carriedBytes int
		for c := 0; c < churn; c++ {
			tag := byte(c%251 + 1)
			withClose := c%3 == 0
			probeRefusal := c%5 == 0

			fillPrimary(t, q, tag)
			pushed += maxFrames

			// Carried DATA size rotates 1..payloadSz so the accounting must be
			// byte-exact, not merely "roughly right".
			carrySz := c%payloadSz + 1
			if ok, reason := q.TryCarry(dataFrame(tag, carrySz)); !ok {
				t.Fatalf("cycle %d: TryCarry(%d bytes) refused (reason %v)", c, carrySz, reason)
			}
			carried++
			carriedBytes += carrySz

			// A carried FrameClose rides behind the carried data frame and
			// costs 0 bytes but still occupies an item slot.
			heldItems := 1
			if withClose {
				if ok, reason := q.TryCarry(queueItem{isClose: true}); !ok {
					t.Fatalf("cycle %d: TryCarry(FrameClose) refused (reason %v)", c, reason)
				}
				carriedClose++
				heldItems++
			}

			heldBytes := maxFrames*payloadSz + carrySz
			if got := atomic.LoadInt64(&budget); got != int64(heldBytes) {
				t.Fatalf("cycle %d: aggregate = %d while held, want %d", c, got, heldBytes)
			}
			if n := q.OverflowLen(); n != heldItems {
				t.Fatalf("cycle %d: OverflowLen = %d, want %d", c, n, heldItems)
			}

			// A carry beyond the per-stream carry cap MUST be refused and MUST
			// NOT change the aggregate.
			if probeRefusal {
				if ok, reason := q.TryCarry(dataFrame(tag, maxBytes+1)); ok {
					t.Fatalf("cycle %d: TryCarry accepted %d bytes past the carry cap", c, maxBytes+1)
				} else if reason != rejectAggregate {
					t.Fatalf("cycle %d: over-cap refusal reason = %v, want rejectAggregate", c, reason)
				}
				if got := atomic.LoadInt64(&budget); got != int64(heldBytes) {
					t.Fatalf("cycle %d: refused carry moved the aggregate to %d, want %d", c, got, heldBytes)
				}
				refusedCarries++
			}

			// Drain the carry region fully BEFORE the next fillPrimary — the
			// ordering barrier makes this mandatory, and the count is exact so
			// Pop never parks.
			drainExact(t, q, maxFrames+heldItems)
			popped += maxFrames + heldItems
			if n := q.OverflowLen(); n != 0 {
				t.Fatalf("cycle %d: OverflowLen = %d after drain, want 0", c, n)
			}

			// Never negative, and exactly zero — a negative excursion is caught
			// at the moment it happens, not merely at the end.
			if got := atomic.LoadInt64(&budget); got < 0 {
				t.Fatalf("cycle %d: aggregate = %d — accounting went NEGATIVE", c, got)
			}
			assertBalanced(t, "after mixed churn cycle")
		}

		// Not tautological: the churn must have driven real traffic through the
		// carry region, including both refusals and zero-byte frames. These are
		// closed-form expectations for 200 cycles, independent of the loop.
		if pushed != churn*maxFrames || popped != churn*(maxFrames+1)+carriedClose {
			t.Fatalf("churn traffic: pushed=%d popped=%d carriedClose=%d", pushed, popped, carriedClose)
		}
		if carried != churn || carriedBytes <= 0 {
			t.Fatalf("churn carries: carried=%d carriedBytes=%d, want %d and > 0", carried, carriedBytes, churn)
		}
		if carriedClose != (churn+2)/3 {
			t.Fatalf("carried FrameClose count = %d, want %d", carriedClose, (churn+2)/3)
		}
		if refusedCarries != churn/5 {
			t.Fatalf("refused over-cap carries = %d, want %d", refusedCarries, churn/5)
		}
		if items != 0 {
			t.Fatalf("aggregate queued items = %d after churn, want 0", items)
		}

		q.Close()
		assertBalanced(t, "after Close of the churned queue")
		if got := atomic.LoadInt64(&budget); got < 0 {
			t.Fatalf("aggregate = %d after Close, must never be negative", got)
		}
	})
}
