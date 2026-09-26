package mux

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// This file is the Increment 2 (sender half) pkg/mux test surface,
// authoritative from plans/architecture-checkpoint-backpressure.md §E.4,
// §G.1 M9 and the integrity-invariant recap (§U). These tests confirm that
// credit PARKING of N streams cannot turn the aggregate TryPush refusal into
// a carrier-wide termination: the refusal stays per-stream and no other
// stream is terminated, and that a refused in-order DATA frame still
// terminates cleanly when credit is latched.

// TestAggregateMailboxBudgetUnderCreditParking (M9): with N streams PARKED
// on credit (each holding resident bytes in its mailbox — the sender parked
// at the credit floor) plus one active stream, the TryPush aggregate refusal
// stays PER-STREAM: it is attributed to the one pushed stream, the parked
// streams keep their bytes, and NO stream is terminated. The real
// c.queuedBytes aggregate budget is wired (not a nil budget), so the
// refusal is the MaxBytesTotal check, not a per-stream bound.
func TestAggregateMailboxBudgetUnderCreditParking(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)

	const perStream = 1 << 20 // per-stream byte bound is large: never the refuser
	const total = 8           // aggregate bound is TIGHT: it is the refuser
	const N = 8               // N parked streams x 1 byte == total
	c.SetStreamLimits(StreamLimits{
		MaxFramesPerStream: MaxFrames,
		MaxBytesPerStream:  perStream,
		MaxBytesTotal:      total,
		OverflowWait:       time.Second,
	})

	// N credit-parked streams: each holds exactly 1 byte resident. The
	// aggregate budget (c.queuedBytes) climbs to `total` (=8) as they do;
	// every parked stream's own mailbox is far from its per-stream bound,
	// so only the AGGREGATE can refuse.
	parked := make([]*streamRec, 0, N)
	for i := 1; i <= N; i++ {
		s := buildWorkerlessStream(t, c, stats, uint32(i), MaxFrames, perStream, total)
		if !s.q.TryPush(queueItem{payload: []byte{'p'}}) {
			t.Fatalf("parked stream %d push refused; aggregate should admit the first %d bytes", i, total)
		}
		parked = append(parked, s)
	}
	if got := atomic.LoadInt64(&c.queuedBytes); got != total {
		t.Fatalf("aggregate queuedBytes = %d, want %d (N parked x 1 byte)", got, total)
	}

	// One ACTIVE stream now pushes: the aggregate is saturated, so this is
	// refused — and it must be refused on the AGGREGATE bound, per-stream.
	active := buildWorkerlessStream(t, c, stats, uint32(N+1), MaxFrames, perStream, total)
	if active.q.TryPush(queueItem{payload: []byte{'A'}}) {
		t.Fatal("active stream push was accepted past the saturated aggregate (budget not enforced)")
	}
	if got := atomic.LoadInt64(&c.queuedBytes); got != total {
		t.Fatalf("refused push changed the aggregate to %d, want %d (a refused push must not account)", got, total)
	}

	// The refusal stayed PER-STREAM: it is attributed to the pushed stream
	// (PushRejectedTotal counts aggregate refusals), and no parked stream
	// lost its bytes or terminated.
	if got := atomic.LoadInt64(&stats.PushRejectedTotal); got != 1 {
		t.Fatalf("PushRejectedTotal = %d, want 1 (the one aggregate refusal)", got)
	}
	for i, s := range parked {
		s.q.mu.Lock()
		by, n := s.q.nBytes, len(s.q.items)
		s.q.mu.Unlock()
		if by != 1 || n != 1 {
			t.Fatalf("parked stream %d lost bytes after the aggregate refusal (bytes=%d items=%d)", i+1, by, n)
		}
		if s.terminated.Load() {
			t.Fatalf("parked stream %d was terminated by an aggregate refusal of ANOTHER stream", i+1)
		}
	}
	if active.terminated.Load() {
		t.Fatal("the refused (active) stream must not be terminated by TryPush — TryPush never terminates (the dispatcher's deliver-or-fail path does, separately)")
	}
}

// TestRefusedDataFrameWithCreditLatchedStillTerminates (integrity under
// latch, §U): when credit is LATCHED (a valid FrameCredit was observed) and
// an in-order DATA frame is then refused by a full mailbox, the stream is
// still terminated cleanly with a contiguous in-order prefix — no byte
// hole. This asserts the INVARIANT, not the provenance: exactly one
// termination (stopOnce observed via OnStreamTerminated), a contiguous
// in-order prefix, a clean nil end, OnStreamDataUndeliverable at most
// once, and the source-crediting bounds (dropped+worker >= 1, each <= 1)
// — the same treatment as
// TestRefusedDataFrameStillTerminatesWithCreditPlumbing, whose comment
// explains why the stopOnce winner (dispatcher failUndeliverableData vs
// worker OverflowWait handoff) cannot be pinned by the counters.
// Credit is an OPTIMIZATION; the refused-DATA safety net stays armed.
func TestRefusedDataFrameWithCreditLatchedStillTerminates(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	// A 2-frame mailbox with a fast OverflowWait: 4 data frames cannot all
	// fit, so at least one is refused and must fail the stream (same shape
	// as TestRefusedDataFrameStillTerminatesWithCreditPlumbing, M1).
	c.SetStreamLimits(bpLimits(2, 4096, 4096, 50*time.Millisecond))
	ch := c.Register(1)
	go c.Dispatch()

	// Credit latching is ACTIVE: observe a valid credit frame first (the
	// node-side ledger would latch the stream on this event). The valid
	// credit must be ROUTED to OnStreamCredit, not dropped.
	var latched atomic.Bool
	c.OnStreamCredit = func(uint32, CreditFrameInfo) { latched.Store(true) }
	var terms atomic.Int32
	c.OnStreamTerminated = func(uint32) { terms.Add(1) }
	if err := WriteCreditFrame(b, 1, CreditFrameInfo{
		CreditVersion:         CreditVersion1,
		CumulativeBytesPopped: 0,
	}); err != nil {
		t.Fatalf("WriteCreditFrame: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !latched.Load() {
		if time.Now().After(deadline) {
			t.Fatal("a valid FrameCredit was not latched (OnStreamCredit never fired)")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Refuse in-order DATA: 4 frames against a 2-frame mailbox guarantees
	// at least one refusal while the stream is still live; the refusal must
	// fail the stream cleanly (deliver-or-fail, §U).
	for i := 0; i < 4; i++ {
		if err := WriteFrame(b, 1, FrameData, []byte{byte('a' + i)}); err != nil {
			t.Fatalf("WriteFrame data %d: %v", i, err)
		}
	}
	s := waitTerminated(t, c, 1, 3*time.Second)

	// The consumer sees a contiguous in-order PREFIX of what was sent, then
	// nil — never a hole. This is the integrity invariant under ACTIVE
	// credit latching: the refused-DATA safety net is not weakened.
	var got []byte
loop:
	for {
		select {
		case f, ok := <-ch:
			if !ok {
				t.Fatal("consumer channel closed without the clean nil end signal")
			}
			if f == nil {
				break loop
			}
			got = append(got, f...)
		case <-time.After(3 * time.Second):
			t.Fatal("consumer never received the clean nil end signal")
		}
	}
	sent := "abcd"
	if len(got) > len(sent) {
		t.Fatalf("consumer received %d bytes, %d sent", len(got), len(sent))
	}
	for i, byteInGot := range got {
		if byteInGot != sent[i] {
			t.Fatalf("consumer byte %d = %q, want %q (in-order prefix violated — byte hole)", i, byteInGot, sent[i])
		}
	}
	if !s.terminated.Load() {
		t.Fatal("refused in-order DATA with credit latched left the stream alive (silent byte hole)")
	}
	// (2) EXACTLY ONE termination: OnStreamTerminated fires once inside
	// terminateStream's stopOnce body (or the worker's isClose arm, which
	// cannot run here — no FrameClose is on the wire), so exactly one
	// stream-wide termination is observable. Its fire is sequenced
	// AFTER the terminated store, so poll for it before asserting; a
	// double-termination would fire it twice (sync.Once makes that
	// structurally impossible — a canary against a new non-stopOnce
	// termination path).
	termsDeadline := time.Now().Add(3 * time.Second)
	for terms.Load() == 0 && time.Now().Before(termsDeadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if n := terms.Load(); n != 1 {
		t.Fatalf("OnStreamTerminated fired %d times, want exactly 1 (one termination; stopOnce semantics)", n)
	}
	// (4) SOURCE CREDITING (the observable), not PROVENANCE (not
	// pinnable): the dispatcher's failUndeliverableData and the worker's
	// OverflowWait handoff are both stopOnce-arbitrated sources; each
	// credits its counter OUTSIDE the arbitration, so "exactly one
	// source" cannot be expressed by DroppedDataFrames /
	// OverflowTerminationsWorker (a losing path that already passed its
	// checks still credits). Assert the product of what IS observable:
	//   - at least one source is credited (the winner's credit
	//     happens-before its terminated store, settled by waitTerminated);
	//   - no source is double-credited (each counter is <= 1).
	dropped := atomic.LoadInt64(&stats.DroppedDataFrames)
	worker := atomic.LoadInt64(&stats.OverflowTerminationsWorker)
	if dropped > 1 {
		t.Fatalf("dropped_data_frames = %d, want at most 1 (failUndeliverableData runs at most once per stream)", dropped)
	}
	if worker > 1 {
		t.Fatalf("overflow_terminations_worker = %d, want at most 1 (the worker's OverflowWait times out at most once)", worker)
	}
	if dropped+worker < 1 {
		t.Fatalf("no termination source credited (dropped=%d worker=%d); the stopOnce winner's credit happens-before its terminated store", dropped, worker)
	}
	// (5) OnStreamDataUndeliverable is not installed here, so it fires 0
	// times — trivially at most once; the sibling M1 test pins the
	// dispatcher-source bound.
	// The credit that latched the stream was routed (not dropped): latching
	// was genuinely active when the DATA path failed.
	if !latched.Load() {
		t.Fatal("credit was not latched before the DATA refusal (test precondition failed)")
	}
}
