package mux

import (
	"bufio"
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// D4 hybrid per-stream credit — Increment 1 (receiver half). These tests pin
// the frame codec, the receiver-side routing/validation, and the R2-1 lock
// rule (no callback or counter write while q.mu is held).

// TestFrameCreditRoundTripBigEndian pins the exact 18-byte FrameCredit wire
// layout (every multi-byte field binary.BigEndian) and that
// WriteCreditFrame/parseCreditFrame round-trip losslessly.
func TestFrameCreditRoundTripBigEndian(t *testing.T) {
	info := CreditFrameInfo{
		CreditVersion:         creditVersion1,
		CumulativeBytesPopped: 0x0102030405060708,
		CreditWindow:          0x0000ABCD,
	}
	var buf bytes.Buffer
	if err := WriteCreditFrame(&buf, 0x00010203, info); err != nil {
		t.Fatalf("WriteCreditFrame: %v", err)
	}
	// Known vector: 7-byte header + 18-byte payload (1+8+4+1+4), big-endian.
	want := []byte{
		0x00, 0x01, 0x02, 0x03, FrameCredit, 0x00, 0x12,
		0x01,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00, 0x00, 0xAB, 0xCD,
		0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("wire bytes = %v, want %v", buf.Bytes(), want)
	}

	f, err := ReadFrame(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.StreamID != 0x00010203 || f.Type != FrameCredit || f.Length != creditPayloadSize {
		t.Fatalf("frame = {ID:%d Type:%#x Len:%d}, want credit header {ID:0x10203 Type:%#x Len:%d}",
			f.StreamID, f.Type, f.Length, uint8(FrameCredit), creditPayloadSize)
	}
	got, ok := parseCreditFrame(f.Payload)
	if !ok {
		t.Fatal("parseCreditFrame rejected a valid credit frame")
	}
	if got != info {
		t.Fatalf("round-trip = %+v, want %+v", got, info)
	}
}

// TestFrameCreditVersionMismatchIgnored (M6): a credit payload whose
// version byte is not 1 must be IGNORED — no state change, no panic — and
// DATA handling is unaffected.
func TestFrameCreditVersionMismatchIgnored(t *testing.T) {
	// Codec level: every version other than 1 is rejected.
	for _, v := range []byte{0, 2, 0xFF} {
		payload := make([]byte, creditPayloadSize)
		payload[0] = v
		if _, ok := parseCreditFrame(payload); ok {
			t.Fatalf("version %d accepted, want ignored", v)
		}
	}

	// Dispatcher level: an invalid-version credit is dropped and a
	// following DATA frame is still delivered.
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	ch := c.Register(1)
	go c.Dispatch()
	var credits atomic.Int32
	c.OnStreamCredit = func(uint32, CreditFrameInfo) { credits.Add(1) }

	bad := make([]byte, creditPayloadSize)
	bad[0] = 2
	if err := WriteFrame(b, 1, FrameCredit, bad); err != nil {
		t.Fatalf("WriteFrame credit: %v", err)
	}
	if err := WriteFrame(b, 1, FrameData, []byte("d1")); err != nil {
		t.Fatalf("WriteFrame data: %v", err)
	}
	select {
	case f := <-ch:
		if string(f) != "d1" {
			t.Fatalf("data = %q, want %q", f, "d1")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DATA delivery stalled after a version-mismatch credit")
	}
	if n := credits.Load(); n != 0 {
		t.Fatalf("OnStreamCredit fired %d times for an invalid version, want 0", n)
	}
}

// TestFrameCreditMalformedLengthDropped: a credit payload of any length
// other than 18 is dropped without crashing, and DATA handling is
// unaffected.
func TestFrameCreditMalformedLengthDropped(t *testing.T) {
	// Codec level: every length other than 18 is rejected (no panic).
	for _, n := range []int{0, 1, 17, 19, creditPayloadSize + 1} {
		payload := make([]byte, n)
		if n > 0 {
			payload[0] = creditVersion1
		}
		if _, ok := parseCreditFrame(payload); ok {
			t.Fatalf("length %d accepted, want dropped", n)
		}
	}

	// Dispatcher level: a 17-byte "credit" is dropped as malformed, and a
	// following DATA frame is still delivered.
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	ch := c.Register(1)
	go c.Dispatch()
	var credits atomic.Int32
	c.OnStreamCredit = func(uint32, CreditFrameInfo) { credits.Add(1) }

	short := make([]byte, creditPayloadSize-1)
	short[0] = creditVersion1
	if err := WriteFrame(b, 1, FrameCredit, short); err != nil {
		t.Fatalf("WriteFrame credit: %v", err)
	}
	if err := WriteFrame(b, 1, FrameData, []byte("ok")); err != nil {
		t.Fatalf("WriteFrame data: %v", err)
	}
	select {
	case f := <-ch:
		if string(f) != "ok" {
			t.Fatalf("data = %q, want %q", f, "ok")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DATA delivery stalled after a malformed credit")
	}
	if n := credits.Load(); n != 0 {
		t.Fatalf("OnStreamCredit fired %d times for a malformed payload, want 0", n)
	}
}

// TestOldPeerDropsUnknownFrame (M5): a peer that does not understand
// FrameCredit decodes it as an ordinary frame — the 7-byte header is
// unchanged and the payload occupies exactly 18 bytes, so the old peer's
// ReadFrame stays byte-aligned and its `default:` arm drops it exactly as
// it drops any unknown type today. No existing type was renumbered. A new
// peer accepts-and-ignores a valid credit (no state change), so the wire
// format stays behaviour-neutral for DATA.
func TestOldPeerDropsUnknownFrame(t *testing.T) {
	// Pin that no existing type moved and 0x07 is the new one.
	switch {
	case FrameData != 0x00, FrameAuth != 0x01, FramePing != 0x02,
		FramePong != 0x03, FrameClose != 0x04, FrameHeader != 0x05,
		FrameRebind != 0x06:
		t.Fatal("existing frame type constants were renumbered")
	}
	if FrameCredit != 0x07 {
		t.Fatalf("FrameCredit = %#x, want 0x07", FrameCredit)
	}

	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	ch := c.Register(1)
	go c.Dispatch()

	// One credit frame is exactly 25 wire bytes (header + payload); the
	// following DATA frame stays aligned for an old peer's ReadFrame.
	var raw bytes.Buffer
	if err := WriteCreditFrame(&raw, 1, CreditFrameInfo{CreditVersion: creditVersion1}); err != nil {
		t.Fatalf("WriteCreditFrame: %v", err)
	}
	if n := raw.Len(); n != HeaderSize+creditPayloadSize {
		t.Fatalf("credit wire size = %d, want %d (old peer must stay byte-aligned)",
			n, HeaderSize+creditPayloadSize)
	}
	if _, err := raw.WriteTo(b); err != nil {
		t.Fatalf("write credit frame: %v", err)
	}
	if err := WriteFrame(b, 1, FrameData, []byte("post-credit")); err != nil {
		t.Fatalf("WriteFrame data: %v", err)
	}
	select {
	case f := <-ch:
		if string(f) != "post-credit" {
			t.Fatalf("data = %q, want %q", f, "post-credit")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DATA delivery stalled after the credit frame")
	}
	// Accept-and-ignore: the credit must not create a phantom stream,
	// terminate anything, or disturb the carrier.
	if n := c.StreamCount(); n != 1 {
		t.Fatalf("StreamCount = %d, want 1 (a credit must not create or kill streams)", n)
	}
	if !c.Ready() {
		t.Fatal("carrier ended after a credit frame was processed")
	}
}

// TestPoppedCounterCountOnlyUnderLock: poppedBytesTotal increases
// monotonically as items are popped, and the callback observes the running
// total only AFTER the pop path released q.mu (the callback fires before
// the channel handoff, so after reading the last item every pop's callback
// has already run — no polling).
func TestPoppedCounterCountOnlyUnderLock(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	ch := c.Register(1)
	go c.Dispatch()

	var mu sync.Mutex
	var totals []uint64
	c.OnStreamPopped = func(id uint32, total uint64) {
		_ = id
		mu.Lock()
		totals = append(totals, total)
		mu.Unlock()
	}

	const n = 5
	for i := 0; i < n; i++ {
		if err := WriteFrame(b, 1, FrameData, []byte{byte('a' + i)}); err != nil {
			t.Fatalf("WriteFrame %d: %v", i, err)
		}
	}
	for i := 0; i < n; i++ {
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatalf("item %d not delivered", i)
		}
	}
	mu.Lock()
	calls := append([]uint64(nil), totals...)
	mu.Unlock()
	if len(calls) != n {
		t.Fatalf("OnStreamPopped fired %d times, want %d", len(calls), n)
	}
	for i, total := range calls {
		if total != uint64(i+1) {
			t.Fatalf("call %d total = %d, want %d (monotone, count-only)", i, total, i+1)
		}
	}
	// The plain counter is readable under q.mu and matches the last total.
	c.mu.Lock()
	s := c.streams[1]
	c.mu.Unlock()
	s.q.mu.Lock()
	got := s.poppedBytesTotal
	s.q.mu.Unlock()
	if got != uint64(n) {
		t.Fatalf("poppedBytesTotal = %d, want %d", got, n)
	}
}

// TestOnStreamPoppedFiresOutsideQueueLock: the lock-inversion guard. From
// inside the callback, re-acquire q.mu (reading the counter the way the
// pop path writes it). If the callback ever fired while q.mu was still
// held by the pop path, this Lock would deadlock — the assert completes
// only when the callback provably runs outside the queue lock.
func TestOnStreamPoppedFiresOutsideQueueLock(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	ch := c.Register(1)
	go c.Dispatch()

	var mu sync.Mutex
	var failed int
	c.OnStreamPopped = func(id uint32, total uint64) {
		done := make(chan struct{})
		go func() {
			c.mu.Lock()
			s := c.streams[id]
			c.mu.Unlock()
			s.q.mu.Lock()
			_ = s.poppedBytesTotal
			s.q.mu.Unlock()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			mu.Lock()
			failed++
			mu.Unlock()
		}
	}
	for i := 0; i < 3; i++ {
		if err := WriteFrame(b, 1, FrameData, []byte{0}); err != nil {
			t.Fatalf("WriteFrame %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatalf("item %d not delivered", i)
		}
	}
	mu.Lock()
	nFailed := failed
	mu.Unlock()
	if nFailed != 0 {
		t.Fatalf("q.mu re-acquisition inside the callback failed %d/3 times: OnStreamPopped fired with the queue lock held", nFailed)
	}
}

// TestRefusedDataFrameStillTerminatesWithCreditPlumbing (M1, receiver
// half): with the credit plumbing (OnStreamCredit / OnStreamPopped)
// installed, a refused in-order DATA frame still terminates the stream
// cleanly. This asserts the INVARIANT, not the provenance: the consumer
// sees a contiguous in-order prefix and then a clean nil end (no hole,
// no reorder, no ragged frame), the stream terminates exactly ONCE
// (stopOnce semantics observed: OnStreamTerminated fires exactly once),
// and OnStreamDataUndeliverable fires at most once. WHICH termination
// source won the stopOnce arbitration (the dispatcher's
// failUndeliverableData vs the worker's OverflowWait handoff) is
// deliberately not pinned — see the source-crediting comment below for
// why. The integrity invariant is unchanged: in this increment the
// credit plumbing is a pure observer of the DATA path.
func TestRefusedDataFrameStillTerminatesWithCreditPlumbing(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	stats := &QueueStats{}
	c.SetQueueStats(stats)
	c.SetStreamLimits(bpLimits(2, 4096, 4096, 50*time.Millisecond))
	ch := c.Register(1)
	go c.Dispatch()

	var credits atomic.Int32
	c.OnStreamCredit = func(id uint32, info CreditFrameInfo) {
		_ = id
		credits.Add(1)
		if info.CumulativeBytesPopped != 0xC0FFEE {
			t.Errorf("credit info = %+v, want cumulative 0xC0FFEE", info)
		}
	}
	var popped atomic.Int32
	c.OnStreamPopped = func(id uint32, total uint64) {
		_, _ = id, total
		popped.Add(1)
	}
	var undel atomic.Int32
	c.OnStreamDataUndeliverable = func(uint32) { undel.Add(1) }
	var terms atomic.Int32
	c.OnStreamTerminated = func(uint32) { terms.Add(1) }

	// A valid credit first (accepted and routed), then 4 data frames
	// against a 2-frame mailbox: one is refused and must fail the stream.
	if err := WriteCreditFrame(b, 1, CreditFrameInfo{
		CreditVersion:         creditVersion1,
		CumulativeBytesPopped: 0xC0FFEE,
		CreditWindow:          4096,
	}); err != nil {
		t.Fatalf("WriteCreditFrame: %v", err)
	}
	for i := 0; i < 4; i++ {
		if err := WriteFrame(b, 1, FrameData, []byte{byte('a' + i)}); err != nil {
			t.Fatalf("WriteFrame data %d: %v", i, err)
		}
	}
	s := waitTerminated(t, c, 1, 3*time.Second)

	// Consumer: a contiguous in-order PREFIX of what was sent, then nil.
	// The refused frame ('d', the 4th) never reaches the consumer.
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
	if len(got) > len(sent) || string(got) != sent[:len(got)] {
		t.Fatalf("consumer bytes = %q, want a contiguous in-order prefix of %q", got, sent)
	}
	if !s.terminated.Load() {
		t.Fatal("refused DATA frame left the stream alive (silent byte hole)")
	}
	// (2) EXACTLY ONE termination: OnStreamTerminated is the stopOnce-
	// observed signal — every live termination source in this scenario
	// fires it exactly once (inside terminateStream's stopOnce body, OR
	// in the worker's isClose arm which cannot run here — no FrameClose
	// is on the wire, only credit + data frames). Its fire is sequenced
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
	// pinnable): deliver's failUndeliverableData and the worker's
	// OverflowWait handoff are BOTH legitimate, stopOnce-arbitrated
	// sources of this termination. Each path credits its own counter
	// BEFORE its terminated store (dispatcher: droppedDataFrame() then
	// terminateStream; worker: overflowTerminatedWorker() then
	// terminateStream / the isClose arm's store), and the arbitration
	// only picks WHICH path delivers the nil — it does NOT un-credit a
	// path that already ran. So under -race scheduling the worker can
	// win (dropped stays 0) and/or both paths can credit (both == 1);
	// "exactly one source" therefore cannot be expressed by these
	// counters. Assert the product of what IS observable instead:
	//   - at least one source is credited: the terminating path's
	//     credit happens-before its terminated store, and both
	//     waitTerminated (step s.terminated.Load()==true) and the
	//     consumer's clean nil end synchronized on that store, so the
	//     winning path's counter is settled here;
	//   - no source is double-credited: failUndeliverableData runs at
	//     most once per stream (the sequential dispatcher early-returns
	//     on terminated for every later frame) and the worker's
	//     OverflowWait times out at most once before it exits — each
	//     counter is <= 1.
	dropped := atomic.LoadInt64(&stats.DroppedDataFrames)
	worker := atomic.LoadInt64(&stats.OverflowTerminationsWorker)
	if dropped > 1 {
		t.Fatalf("dropped_data_frames = %d, want at most 1 (failUndeliverableData runs at most once per stream)", dropped)
	}
	if worker > 1 {
		t.Fatalf("overflow_terminations_worker = %d, want at most 1 (the worker's OverflowWait times out at most once)", worker)
	}
	if dropped+worker < 1 {
		t.Fatalf("no termination source credited (dropped=%d worker=%d); the terminating path's credit happens-before its terminated store, which waitTerminated observed", dropped, worker)
	}
	// (5) OnStreamDataUndeliverable fires AT MOST once: 0 under a
	// worker win, 1 under a dispatcher win (it is fired only by
	// failUndeliverableData, which runs at most once per stream).
	if n := undel.Load(); n > 1 {
		t.Fatalf("OnStreamDataUndeliverable fired %d times, want at most 1", n)
	}
	// The valid credit was routed to OnStreamCredit exactly once, not
	// dropped (arbitration-independent: the credit frame precedes the
	// data frames in FIFO dispatch order).
	if n := credits.Load(); n != 1 {
		t.Fatalf("OnStreamCredit fired %d times, want 1 (the valid credit must be routed, not dropped)", n)
	}
	_ = popped.Load() // worker pops ran concurrently; only the prefix/no-hole property is load-bearing
}
