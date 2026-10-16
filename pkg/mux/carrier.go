package mux

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// writeReq is one serialized write request.
type writeReq struct {
	data []byte
	done chan error
}

// ErrCarrierClosed is returned by WriteFrame (and the internal write
// primitive) once Close has started. No WriteFrame caller is ever left
// waiting: still-queued requests are failed with this error by Close, and
// new requests are rejected immediately.
var ErrCarrierClosed = errors.New("mux: carrier closed")

// CarrierConn is the frame engine for one carrier (up-carrier WS or
// down-carrier TCP). It wraps any io.ReadWriteCloser — a raw net.Conn or a
// *websocket.Conn behind a ReadWriteCloser adapter.
//
// Concurrency model:
//   - one read-loop goroutine decodes frames and pushes them on frames;
//   - one dispatcher goroutine (Dispatch) routes frames into bounded
//     per-stream mailboxes — it NEVER blocks on a slow consumer (Phase 3);
//   - one worker goroutine per stream drains its mailbox into the stream's
//     consumer channel (cap 1);
//   - ALL writes (auth, keepalive, data, close) are serialized through
//     writeCh by a single writer goroutine, so frames can never interleave.
//
// Backpressure (Phase 3): if a stream's consumer stalls, its mailbox
// fills, the dispatcher stops accepting that stream's data (non-blocking
// TryPush) and, after StreamLimits.OverflowWait, terminates THAT stream
// only — its consumer receives nil (same signal as FrameClose) — while
// every other stream keeps flowing. See queue.go for the mailbox and
// deliver/applyPressure/terminateStream for the policy.
//
// Lifecycle: the closed channel is the carrier's cancellation signal (the
// context equivalent — every loop and blocking write selects on it), so
// Close deterministically terminates the read loop, the writer, the
// keepalive and a running Dispatch without goroutine leaks. See Close for
// the exact shutdown sequence; ShutdownDone reports when all carrier-owned
// goroutines have actually exited.
type CarrierConn struct {
	rwc io.ReadWriteCloser

	bufMu sync.Mutex
	buf   *bufio.Reader

	frames  chan Frame
	writeCh chan writeReq
	// ctrlCh carries the ordering-INSENSITIVE control frames (Credit, Close,
	// Ping, Pong) so a control frame is never queued behind up to 256 DATA
	// frames on writeCh. Consumed by the same single writeLoop as writeCh
	// (Phase B, control plane). Cap 64 — the per-stream fairness analysis in
	// the design (Section 4 O1) bounds any one stream's stall, and credits
	// are cumulative-absolute so a drop is pure delay, never loss.
	ctrlCh    chan writeReq
	readErr   error
	readDone  chan struct{}
	closed    chan struct{}
	closeOnce sync.Once

	// writeWG counts write() calls that are still allowed to enqueue a
	// request. Done runs as soon as the request is enqueued (or the call
	// is aborted by close), NOT when the write completes — so Close's
	// Wait cannot deadlock on a write whose resolution it is still
	// responsible for (see drainWrites).
	writeWG sync.WaitGroup
	// ctrlWG counts control-frame writers still allowed to enqueue on
	// ctrlCh. Exact mirror of writeWG for the control plane (Phase B):
	// Done runs as soon as the request is enqueued or the call is aborted,
	// so Close's Wait cannot deadlock on a control write whose resolution it
	// is still responsible for (see drainCtrl).
	ctrlWG sync.WaitGroup
	// shutdownDone is closed when every carrier-owned goroutine
	// (readLoop, writeLoop, keepalive) has exited.
	shutdownDone chan struct{}
	shutdownOnce sync.Once

	mu      sync.Mutex
	streams map[uint32]*streamRec
	closing bool
	// stats is optional fixed-cardinality queue telemetry for this carrier.
	stats *QueueStats
	// queuedItems mirrors the number of items currently held by all
	// mailboxes. StreamQueue updates it under its existing mailbox lock.
	queuedItems int64
	// live counts the carrier-owned goroutines still running.
	live int
	// limits bounds the per-stream mailboxes (see StreamLimits). Set via
	// SetStreamLimits before starting Dispatch or calling Register.
	limits StreamLimits
	// queuedBytes is the total payload bytes currently sitting in this
	// carrier's stream mailboxes. The MAILBOXES own the accounting (each
	// StreamQueue is attached to this counter and updates it under its
	// own lock on push/pop/close — see StreamQueue), so the value always
	// equals the sum over mailboxes; the per-mailbox budget check in
	// TryPush enforces limits.MaxBytesTotal (aggregate memory budget).
	queuedBytes int64
	// dispatched is latched true at Dispatch entry; false if this carrier
	// never started Dispatch.
	dispatched atomic.Bool
	// dispatchDone is closed by Dispatch on return (after draining c.frames);
	// Close waits on it.
	dispatchDone chan struct{}
	// workerWait counts stream workers that have started but not yet
	// exited. Close's step 5 (a) closes EVERY mailbox (allStreams, which
	// Deregister does not shrink), which is the only thing that can
	// release a worker parked in Pop; step 5 (b) then waits for all
	// workers to exit — OUTSIDE c.mu, because the last worker's final
	// goroutineStopped() takes c.mu; and only then does step 5 (c)
	// close any s.ch. That ordering is what makes "send on a closed
	// channel" impossible: by the time Close closes s.ch, every worker
	// has exited or is provably unable to send (its mailbox is closed,
	// so no further Pop, and the closed channel has been open since
	// step 2, which aborts every in-flight handoff select).
	//
	// Add/Wait ordering under concurrent Register/createStream/Close:
	// the Add happens under c.mu, and createStreamLocked is only
	// reachable while closing==false (Register and Dispatch both check
	// closing under c.mu before calling it) — the same c.mu Close uses
	// to latch closing=true before it can reach Wait. So every Add is
	// mutex-ordered either before the latch (hence before the Wait) or
	// never happens; no Add can follow the Wait, and no worker can
	// start without having been counted (the Add precedes the go).
	workerWait sync.WaitGroup
	// termWG counts public Terminate calls that are still running their
	// terminateStream handoff (the s.ch <- nil send). It is the third,
	// UNTRACKED-elsewhere sender on s.ch: Terminate is a public API that the
	// node calls from spawned goroutines (e.g. bootstrapUpStream's dial-drop
	// path), which neither workerWait (stream workers) nor dispatchDone (the
	// dispatcher) covers. Close's step (b3) waits on termWG before step (c)
	// closes s.ch, so no Terminate-originated send can race the close — this
	// is exactly the "send on closed channel" panic / -race the bootstrap
	// dial-refused teardown hit.
	//
	// Add/Wait ordering: Terminate Add's under c.mu only when the carrier is
	// NOT yet closing (a closing carrier lets Close close s.ch as the wake,
	// so it Adds nothing). Close latches closing=true under the SAME c.mu in
	// step 1, and reaches termWG.Wait in step (b3). So any Add that observed
	// closing==false is mutex-ordered before the latch, hence before the
	// Wait — the Wait always sees it and blocks until its Done. The handoff
	// is bounded (its select unblocks on c.closed, closed at step 2), so the
	// Wait can never hang.
	termWG sync.WaitGroup
	// allStreams tracks every stream record this carrier has EVER
	// created. It is an append-only slice (not a map) and is never
	// shrunk: neither Deregister nor re-Register of the same ID may
	// remove an entry, because an old record's worker may still be
	// parked in Pop (its mailbox is the only object that can wake it).
	// Losing it would hang Close's worker wait (and the
	// live/shutdownDone accounting) — e.g. a deregistered stream, or
	// the previous generation of a re-bound stream ID (Phase 5 rebind
	// reuses IDs: Deregister + Register on the same ID creates a NEW
	// record while the old one's worker is still alive).
	// Dispatcher-owned; appended under c.mu; iterated under c.mu.
	allStreams []*streamRec

	// Liveness state (see liveness). livenessRounds is the configured
	// number of consecutive unanswered pings before the carrier is
	// declared blackholed (set via SetLivenessRounds before the loop
	// starts; the liveness loop reads it under c.mu). sawPong latches
	// that a FramePong was seen since the previous ping round; the
	// liveness loop (the only writer of the decision) clears it under
	// c.mu after each round.
	livenessRounds int
	sawPong        bool
	// OnStreamTerminated, if non-nil, is called once when a stream is
	// terminated by overflow pressure. The callback is keyed only by the
	// stream ID and must not block.
	OnStreamTerminated func(streamID uint32)

	// OnStreamReset, if non-nil, is called (synchronously, in the
	// dispatcher goroutine, OUTSIDE c.mu — mirroring OnStreamCredit) when a
	// well-formed FrameReset (Issue #20) arrives on a registered stream.
	// The node callback terminates the stranded logical session locally
	// (closeSession) instead of retrying the rebind forever. It must not
	// block. Unknown-stream / stale resets are still routed here; the
	// node callback re-validates session existence + generation echo and
	// makes them idempotent no-ops.
	OnStreamReset func(streamID uint32, reason byte, gen uint64)

	// OnStreamBootstrapAck, if non-nil, is called (in the dispatcher
	// goroutine, outside c.mu) for every well-formed FrameBootstrapAck
	// (Issue #21) on a registered stream. The node callback resolves the
	// pending StartSession bootstrap wait with the status byte. Unknown-
	// stream acks are dropped silently in Dispatch (no callback), which
	// is correct: a stale ack for a dead stream has no waiter.
	OnStreamBootstrapAck func(streamID uint32, status byte)

	// OnStreamDataUndeliverable, if non-nil, is called once when a stream
	// is terminated because an in-order DATA frame could not be delivered
	// (the deliver-or-fail policy; see failUndeliverableData). It is
	// distinct from OnStreamTerminated (a sustained-overflow / worker-stall
	// termination) so the node can classify the close as data_undeliverable
	// rather than overflow. Keyed by stream ID; must not block.
	OnStreamDataUndeliverable func(streamID uint32)

	// OnNewStream, if non-nil, is called (synchronously, in the dispatch
	// goroutine) when the first frame for a previously unknown stream
	// arrives. The dispatcher creates and registers the stream channel and
	// passes it to the callback together with the TYPE of the triggering
	// frame (Phase 5: a stream may be opened by FrameHeader — bootstrap a
	// new session — or by FrameRebind — re-attach an existing one; the
	// callback must branch on it). The triggering frame's payload is the
	// first item delivered on ch. The callback must return quickly (spawn
	// a goroutine for slow work such as a target dial).
	OnNewStream func(streamID uint32, firstType uint8, ch chan []byte)

	// OnStreamCredit, if non-nil, is invoked (in the dispatcher goroutine,
	// OUTSIDE c.mu — mirroring OnNewStream/OnStreamTerminated) for every
	// VALID, accepted FrameCredit on a registered stream. Phase A left this
	// a no-op ("valid credit: no-op"); Phase B wires it to the node credit
	// ledger (Section 4 of the design). The payload is already
	// connection-level-validated by readLoop (length) and stream-level by
	// ValidateCreditPayload; a stream-level reject terminates the stream
	// before this callback runs, so the callback only ever sees a credit
	// that passed validation. It must not block (the ledger accounting it
	// performs is O(1); a credit's emission is never enqueued from here —
	// see Section 4's no-block invariant B3).
	OnStreamCredit func(streamID uint32, p CreditPayload)
}

// newCarrierConn constructs a CarrierConn and starts its loops. If br is
// non-nil it is bound as the read buffer BEFORE any loop is started, so
// bytes already pulled out of rwc by a preceding handshake (e.g.
// CarrierAuth's bufio over-read) are consumed by the read loop, never
// orphaned in a second reader.
func newCarrierConn(rwc io.ReadWriteCloser, pingInterval time.Duration, br *bufio.Reader) *CarrierConn {
	c := &CarrierConn{
		rwc:          rwc,
		frames:       make(chan Frame, 256),
		writeCh:      make(chan writeReq, 256),
		ctrlCh:       make(chan writeReq, 64),
		readDone:     make(chan struct{}),
		closed:       make(chan struct{}),
		shutdownDone: make(chan struct{}),
		dispatchDone: make(chan struct{}),
		streams:      make(map[uint32]*streamRec),
		limits:       DefaultStreamLimits,
		buf:          br, // bound before readLoop starts (see NewCarrierConnWithReader)
	}
	c.mu.Lock()
	c.live = 2 // readLoop + writeLoop
	c.livenessRounds = DefaultLivenessRounds
	c.mu.Unlock()
	go c.writeLoop()
	go c.readLoop()
	if pingInterval > 0 {
		c.mu.Lock()
		c.live++
		c.mu.Unlock()
		go c.liveness(pingInterval)
	}
	return c
}

// NewCarrierConn starts the read loop, writer and keepalive ping loop
// over rwc. The read loop consumes the stream exclusively from this
// point on. For an authenticated transport, run CarrierAuth FIRST and
// construct the carrier with NewCarrierConnWithReader (passing the
// auth's bufio.Reader) so already-buffered bytes are not lost.
func NewCarrierConn(rwc io.ReadWriteCloser, pingInterval time.Duration) *CarrierConn {
	return newCarrierConn(rwc, pingInterval, nil)
}

// NewCarrierConnWithReader starts the read loop, writer and keepalive
// ping loop over rwc, consuming from the provided pre-auth
// bufio.Reader from the very first read. Run CarrierAuth FIRST (it
// returns the bufio.Reader it used) and pass that reader here so bytes
// it already pulled from rwc — e.g. a FrameRebind the peer wrote
// immediately after the handshake — are delivered instead of orphaned.
//
// This is the only safe way to hand the auth reader to a carrier: the
// read loop starts inside the constructor and latches its read buffer
// on its first read, so installing the reader afterwards (SetReadBuffer
// after NewCarrierConn) races that first read and can orphan the
// pre-buffered bytes.
func NewCarrierConnWithReader(rwc io.ReadWriteCloser, pingInterval time.Duration, br *bufio.Reader) *CarrierConn {
	return newCarrierConn(rwc, pingInterval, br)
}

func (c *CarrierConn) readLoop() {
	defer close(c.readDone)
	defer close(c.frames)
	defer c.goroutineStopped()
	br := c.readBuffer()
	for {
		f, err := ReadFrame(br)
		if err != nil {
			c.mu.Lock()
			c.readErr = err
			c.stats.readFailure(errors.Is(err, io.EOF))
			c.mu.Unlock()
			return
		}
		// Post-auth frame-context rules (Phase 6):
		//  1. FrameAuth is ONLY valid during the handshake (which ran
		//     before this carrier existed) — any FrameAuth seen now is a
		//     protocol violation (v0 peer or attacker).
		//  2. Stream 0 is reserved for control frames (Ping/Pong).
		//     Application frames on stream 0 would otherwise create a
		//     phantom stream via OnNewStream or hit Deregister(0);
		//     they are rejected.
		// Both are connection-level failures: the carrier is terminated.
		if f.Type == FrameAuth ||
			(f.StreamID == 0 && f.Type != FramePing && f.Type != FramePong) {
			c.mu.Lock()
			c.readErr = ErrProtocolViolation
			c.mu.Unlock()
			return
		}

		// Post-auth FrameCredit context rules (Phase A, design doc §5.3).
		// A credit frame must (a) carry the fixed 32-byte payload and
		// (b) reference a stream this carrier actually has. A peer that
		// violates either is mixed-version or actively attacking, so both
		// are CONNECTION-level failures (the carrier is terminated, the
		// frame is never silently dropped):
		//   - malformed length  -> ErrCreditMalformedLength
		//   - unregistered stream -> ErrCreditUnknownStream
		// (Stream-0 credits are already fatal via the rule above, as
		// ErrProtocolViolation.) Semantic content — creditVersion, creditGen,
		// reserved fields, flags — is validated per-stream in Dispatch (the
		// FrameCredit case), where a bad value is a STREAM-level reject.
		if f.Type == FrameCredit {
			c.mu.Lock()
			_, known := c.streams[f.StreamID]
			c.mu.Unlock()
			if len(f.Payload) != CreditPayloadSize {
				c.mu.Lock()
				c.readErr = ErrCreditMalformedLength
				c.mu.Unlock()
				return
			}
			if !known {
				c.mu.Lock()
				c.readErr = ErrCreditUnknownStream
				c.mu.Unlock()
				return
			}
		}
		select {
		case c.frames <- f:
		case <-c.closed:
			return
		}
	}
}

// writeLoop serializes every write through a single goroutine that drains
// BOTH the user-data queue (writeCh) and the control-plane queue (ctrlCh).
// It exits as soon as the carrier is closed — it never blocks on an
// uncancelled channel receive. Failing the requests still queued at that
// moment is Close's job (drainWrites / drainCtrl), so no write caller is
// ever left waiting on a dead writer.
//
// Scheduling (Phase B, Section 4, REV 2 "E"): the loop FIRST peeks ctrlCh
// under a non-blocking default. When a control frame is READY it is written
// ahead of the next DATA frame. When no control frame is ready, the loop
// enters a blocking select over closed/ctrlCh/writeCh — and Go RESOLVES a
// blocking select with multiple ready channels by UNIFORM RANDOM CHOICE,
// not by priority. So the accurate statement is: priority peek for the
// ready-control case, arbitrary (fair) hand-off when both channels are
// simultaneously ready. We do NOT claim strict priority: a DATA burst with
// no credit in flight is not starved behind a perpetually-queued control
// frame, because the blocking arm alternates fairly between the two
// producers.
func (c *CarrierConn) writeLoop() {
	defer c.goroutineStopped()
	for {
		// 1. Priority PEEK: a READY control frame preempts the next DATA.
		select {
		case req := <-c.ctrlCh:
			c.writeOne(req)
			continue
		default:
		}
		// 2. No control ready: service ctrl or DATA, or exit on close.
		// Both channels ready here => Go picks uniformly at random:
		// DATA cannot be starved by a full ctrl queue.
		select {
		case <-c.closed:
			return // Close's drainCtrl()/drainWrites() resolve anything in flight
		case req := <-c.ctrlCh:
			c.writeOne(req)
		case req := <-c.writeCh:
			c.writeOne(req)
		}
	}
}

// writeOne performs one serialized rwc.Write for a request and resolves
// req.done. It is the single write path shared by both queues (writeCh and
// ctrlCh), so DATA and control frames can never interleave mid-frame.
// On a write error it records the failure on the (optional) stats and, if
// Close has started, reports the deterministic ErrCarrierClosed instead of
// whatever the underlying connection error was — so a write that lands
// around the close reports a stable result.
func (c *CarrierConn) writeOne(req writeReq) {
	_, err := c.rwc.Write(req.data)
	if err != nil {
		c.mu.Lock()
		stats := c.stats
		c.mu.Unlock()
		stats.writeFailure()
	}
	select {
	case <-c.closed:
		err = ErrCarrierClosed
	default:
	}
	req.done <- err
}

// write is the serialized write primitive: it enqueues the raw encoded
// frame and waits for the writer goroutine to complete it.
//
// Once Close has started, write fails immediately with ErrCarrierClosed.
// A write that enqueued before the shutdown is guaranteed to be resolved:
// either the writer processes it (possibly into a now-closed connection)
// or Close's drain fails it with ErrCarrierClosed.
func (c *CarrierConn) write(data []byte) error {
	req := writeReq{data: data, done: make(chan error, 1)}
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return ErrCarrierClosed
	}
	// The Add must happen under the same lock Close uses to set closing:
	// every Add is ordered before Close's Wait (WaitGroup contract), and
	// no Add can happen after closing is set. Done runs below as soon as
	// the request is enqueued or the call is aborted — never after
	// waiting on req.done, which Close is responsible for resolving.
	c.writeWG.Add(1)
	c.mu.Unlock()
	select {
	case c.writeCh <- req:
		c.writeWG.Done()
	case <-c.closed:
		c.writeWG.Done()
		return ErrCarrierClosed
	}
	return <-req.done
}

// drainWrites fails every write request still in the queue. It runs in
// Close after writeWG.Wait(), so no further request can be enqueued; it
// is safe to run while the writer is exiting because each request is
// received exactly once (by the writer or by this drain) and done is
// buffered.
func (c *CarrierConn) drainWrites() {
	for {
		select {
		case req := <-c.writeCh:
			req.done <- ErrCarrierClosed
		default:
			return
		}
	}
}

// writeControl is the blocking control-plane enqueue primitive: the exact
// mirror of write (carrier.go:364) for the ordering-insensitive control
// queue (ctrlCh). Once Close has started it fails immediately with
// ErrCarrierClosed; a request that enqueued before the shutdown is
// guaranteed to be resolved either by the writer or by Close's drainCtrl.
// Used internally for keepalive Ping/Pong and terminal FrameClose.
func (c *CarrierConn) writeControl(data []byte) error {
	req := writeReq{data: data, done: make(chan error, 1)}
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return ErrCarrierClosed
	}
	// The Add happens under the same lock Close uses to set closing —
	// identical to the writeWG discipline (see write): every Add is ordered
	// before Close's ctrlWG.Wait, and no Add can follow closing=true.
	c.ctrlWG.Add(1)
	c.mu.Unlock()
	select {
	case c.ctrlCh <- req:
		c.ctrlWG.Done()
	case <-c.closed:
		c.ctrlWG.Done()
		return ErrCarrierClosed
	}
	return <-req.done
}

// drainCtrl fails every control-frame request still queued on ctrlCh. It
// runs in Close immediately after ctrlWG.Wait() (and, per the Section 4
// ordering, BEFORE writeWG.Wait()/drainWrites), so no further control
// request can be enqueued; it is safe to run while the writer is exiting
// because each request is received exactly once (by the writer or by this
// drain) and done is buffered. A FrameClose stranded on ctrlCh is thus
// never held up behind a still-draining DATA queue.
func (c *CarrierConn) drainCtrl() {
	for {
		select {
		case req := <-c.ctrlCh:
			req.done <- ErrCarrierClosed
		default:
			return
		}
	}
}

// WriteControlFrame encodes and enqueues one ordering-insensitive control
// frame (Credit, Close, Ping, Pong) on the control plane. It is the
// BLOCKING variant (mirror of write), reserved for terminal signals that
// must not be dropped (FrameClose) and for keepalive Ping/Pong. It returns
// once the write is complete (or the carrier has closed).
func (c *CarrierConn) WriteControlFrame(streamID uint32, typ uint8, payload []byte) error {
	return c.writeControl(encodeControlFrame(streamID, typ, payload))
}

// TryWriteControlFrame encodes and enqueues one control frame on ctrlCh
// WITHOUT blocking. On a full ctrlCh it DROPS and returns (false, nil);
// once Close has started it returns (false, ErrCarrierClosed). This is the
// entry point used by the credit emitter (Section 3), whose no-deadlock
// proof rests on this being non-blocking (drop-on-full). Done is called in
// BOTH arms so ctrlWG.Wait() in Close can never stall on a dropped or
// aborted request.
func (c *CarrierConn) TryWriteControlFrame(streamID uint32, typ uint8, payload []byte) (bool, error) {
	req := writeReq{data: encodeControlFrame(streamID, typ, payload), done: make(chan error, 1)}
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return false, ErrCarrierClosed
	}
	c.ctrlWG.Add(1)
	c.mu.Unlock()
	select {
	case c.ctrlCh <- req:
		c.ctrlWG.Done()
		return true, nil
	default:
		c.ctrlWG.Done()
		return false, nil
	}
}

// encodeControlFrame builds the 7-byte-header frame buffer for one control
// frame (the same layout WriteFrame uses). Small helper so the blocking
// and non-blocking control-frame enqueues share one encoding path.
func encodeControlFrame(streamID uint32, typ uint8, payload []byte) []byte {
	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], streamID)
	buf[4] = typ
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(payload)))
	copy(buf[HeaderSize:], payload)
	return buf
}

// goroutineStopped records that one carrier-owned goroutine has exited;
// the last one to exit closes shutdownDone.
func (c *CarrierConn) goroutineStopped() {
	c.mu.Lock()
	c.live--
	last := c.live == 0
	c.mu.Unlock()
	if last {
		c.shutdownOnce.Do(func() { close(c.shutdownDone) })
	}
}

// ShutdownDone returns a channel that is closed once every carrier-owned
// goroutine (readLoop, writeLoop, keepalive, and all stream workers) has
// exited. Useful for tests and deferred resource accounting; not required
// for correct shutdown.
func (c *CarrierConn) ShutdownDone() <-chan struct{} {
	return c.shutdownDone
}

// StreamLimits bounds the per-stream mailboxes and the carrier's total
// queued memory (Phase 3, backpressure).
//
// Per stream, the mailbox holds at most MaxFramesPerStream items AND at
// most MaxBytesPerStream payload bytes — whichever bound is hit first.
// (With MaxFramesPerStream = MaxFrames = 16 the frame bound alone can
// never exceed 16 × MaxPayload = 1 MiB, so the two bounds align by
// default; raising MaxFramesPerStream without MaxBytesPerStream makes
// the frame bound the larger ceiling.)
//
// MaxBytesTotal is the carrier-wide aggregate budget across ALL streams'
// mailboxes, so hundreds of slow streams cannot multiply per-stream
// memory into unbounded RAM.
//
// OverflowWait is how long a stream may be unable to accept data (full
// mailbox or a consumer that stopped reading) before the carrier
// terminates that stream — not the carrier.
//
// ConsumerStall (SUBTASK 30) is the CONSUMER-side backpressure bound: how
// long the per-stream worker may hold a popped item on its cap-1 handoff
// channel waiting for the consumer (the node relay that writes the socket)
// to drain it, before terminating THAT stream. It is deliberately DECOUPLED
// from OverflowWait (the sender/dispatcher mailbox bound) because the two
// measure different things: OverflowWait paces the SENDER against a full
// mailbox, while ConsumerStall absorbs a SLOW but ALIVE consumer (a remote
// client whose socket write takes far longer than 100 ms over the internet).
// A dead consumer (relay exited, session closed) is still reclaimed, but
// only after ConsumerStall — bounded, and never a hang (the carrier's Close
// also releases the handoff via c.closed).
type StreamLimits struct {
	MaxFramesPerStream int
	MaxBytesPerStream  int
	MaxBytesTotal      int
	OverflowWait       time.Duration
	ConsumerStall      time.Duration
}

// DefaultStreamLimits: 16 frames / 704 KiB per stream, 16 MiB per carrier,
// 100 ms overflow wait, 30 s consumer stall.
//
// The 704 KiB per-stream bound (NOT 1 MiB) and the 16 MiB aggregate are the
// Phase B credit-plane sizing (design §5 / B5 amendment): the memory bound
// Σ_streams min(MaxBytesPerStream, creditWindow) <= MaxBytesTotal holds at
// 23 full mailboxes (704 KiB × 23 ≈ 16 MiB), so the credit gate (which caps
// a live stream at creditWindowMax ≈ 512 KiB in flight) can never drive the
// mailbox past the aggregate budget under the pre-latch bound.
//
// ConsumerStall defaults to 30 s: a remote client's socket write over the
// internet (TCP window + RTT) is far slower than the 100 ms OverflowWait,
// so a slow-but-alive consumer must not trigger a per-item stream
// termination mid-transfer. 30 s is generous enough to absorb a real
// internet stall, and a dead consumer is still reclaimed (bounded, no
// hang — Close also releases the handoff).
var DefaultStreamLimits = StreamLimits{
	MaxFramesPerStream: MaxFrames,
	MaxBytesPerStream:  704 << 10, // 704 KiB
	MaxBytesTotal:      16 << 20,  // 16 MiB
	OverflowWait:       100 * time.Millisecond,
	ConsumerStall:      30 * time.Second,
}

// MaxFrames is the maximum number of frames a stream mailbox can hold.
const MaxFrames = 16

// SanitizeLimits normalizes a limit set: zero or negative fields fall back
// to the defaults (a "0 limit" must never mean unbounded or instant-kill),
// and the frame bound is clamped to MaxFrames.
//
// It returns a LOUD error when MaxBytesTotal < MaxBytesPerStream (both
// positive): the aggregate carrier-wide budget must cover at least one
// stream's share, and silently resetting it to the default would mask a
// misconfiguration that would just push the defect back into the runtime
// (a per-stream mailbox that can never be admitted). The caller (the two
// cmd/*/main.go streamLimits() helpers do NOT call this — only the
// Config.Sanitize path) must surface the error; this is the Phase B B5
// amendment that replaces the old silent-reset behaviour.
func SanitizeLimits(l StreamLimits) (StreamLimits, error) {
	d := DefaultStreamLimits
	if l.MaxFramesPerStream <= 0 || l.MaxFramesPerStream > MaxFrames {
		l.MaxFramesPerStream = d.MaxFramesPerStream
	}
	if l.MaxBytesPerStream <= 0 {
		l.MaxBytesPerStream = d.MaxBytesPerStream
	}
	if l.MaxBytesTotal <= 0 {
		l.MaxBytesTotal = d.MaxBytesTotal
	}
	if l.OverflowWait <= 0 {
		l.OverflowWait = d.OverflowWait
	}
	if l.ConsumerStall <= 0 {
		l.ConsumerStall = d.ConsumerStall
	}
	if l.MaxBytesTotal < l.MaxBytesPerStream {
		return l, fmt.Errorf(
			"mux: MaxBytesTotal (%d) < MaxBytesPerStream (%d); raise MaxBytesTotal to >= N_max*MaxBytesPerStream",
			l.MaxBytesTotal, l.MaxBytesPerStream)
	}
	return l, nil
}

// SetStreamLimits configures the per-stream mailbox bounds. Values are
// sanitized (see SanitizeLimits). Call it before starting Dispatch or
// calling Register, like SetReadBuffer. Changing MaxBytesTotal also
// re-syncs the aggregate limit of every already-created mailbox.
// SetQueueStats installs the optional queue telemetry surface. It is
// intended to be called before Dispatch starts. Existing mailboxes are
// updated without changing their bounds or queue state.
func (c *CarrierConn) SetQueueStats(s *QueueStats) {
	c.mu.Lock()
	c.stats = s
	qs := make([]*StreamQueue, 0, len(c.allStreams))
	for _, rec := range c.allStreams {
		qs = append(qs, rec.q)
	}
	c.mu.Unlock()
	for _, q := range qs {
		q.SetStats(s)
		q.setQueuedItems(&c.queuedItems)
	}
}

// QueueStats returns this carrier's optional queue telemetry surface.
func (c *CarrierConn) QueueStats() *QueueStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// SetStreamLimits configures the per-stream mailbox bounds. Values are
// sanitized (see SanitizeLimits, which returns a loud error when
// MaxBytesTotal < MaxBytesPerStream). Call it before starting Dispatch or
// calling Register, like SetReadBuffer. Changing MaxBytesTotal also
// re-syncs the aggregate limit of every already-created mailbox. It
// returns the SanitizeLimits error so a misconfigured aggregate is
// surfaced at the call site (Phase B B5 amendment) instead of being
// silently reset to the default.
func (c *CarrierConn) SetStreamLimits(l StreamLimits) error {
	s, err := SanitizeLimits(l)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.limits = s
	limit := int64(c.limits.MaxBytesTotal)
	overflowCap := c.limits.MaxBytesPerStream
	qs := make([]*StreamQueue, 0, len(c.allStreams))
	for _, s := range c.allStreams {
		qs = append(qs, s.q)
	}
	c.mu.Unlock()
	// Budget and overflow cap updates take each mailbox's own lock — never
	// c.mu — so calling them outside c.mu keeps lock ordering acyclic.
	for _, q := range qs {
		q.SetBudgetLimit(limit)
		q.SetOverflowCap(overflowCap)
	}
	return nil
}

// streamRec is one multiplexed stream: its bounded mailbox, its consumer
// channel (cap 1 — the mailbox is the queue, the channel is only the
// handoff) and the worker that drains mailbox → channel.
type streamRec struct {
	id         uint32
	q          *StreamQueue
	ch         chan []byte // consumer channel; nil = FrameClose / stream end
	terminated atomic.Bool
	// callback, when true, makes the dispatcher fire OnNewStream once for
	// this stream (on its first frame, outside c.mu). Dispatcher-owned.
	callback bool
	// pressureStart is owned by the dispatcher goroutine alone: it marks
	// when a refused FrameClose first started pressuring this stream (the
	// legacy close pressure path; see applyPressure). DATA retry-grace is
	// held by StreamQueue and does not add dispatcher-owned state here.
	pressureStart time.Time
	stopOnce      sync.Once
}

// createStreamLocked creates and registers a stream. Caller holds c.mu.
// callback marks whether OnNewStream must fire for this stream (only for
// streams the dispatcher discovers; pre-registered streams never fire it).
func (c *CarrierConn) createStreamLocked(id uint32, callback bool) *streamRec {
	if id == 0 {
		return nil // stream 0 is reserved for control frames
	}
	if s, ok := c.streams[id]; ok {
		return s
	}
	s := &streamRec{
		id: id,
		// The mailbox owns its slice of the aggregate byte budget
		// (queuedBytes); see StreamQueue. The limit is a plain value
		// (c.mu is held by the caller); SetStreamLimits re-syncs it on
		// existing mailboxes.
		q: NewStreamQueue(c.limits.MaxFramesPerStream, c.limits.MaxBytesPerStream,
			&c.queuedBytes, int64(c.limits.MaxBytesTotal)),
		ch:       make(chan []byte, 1),
		callback: callback,
	}
	s.q.SetOverflowCap(c.limits.MaxBytesPerStream)
	s.q.SetStats(c.stats)
	s.q.setQueuedItems(&c.queuedItems)
	c.streams[id] = s
	c.allStreams = append(c.allStreams, s)
	c.live++
	c.workerWait.Add(1) // under c.mu, before the go — see the field's doc
	go c.streamWorker(s)
	return s
}

// Register reserves streamID and returns its consumer channel. The first
// frame for the ID (e.g. FrameHeader) arrives on ch; FrameClose arrives
// as a nil payload; the channel is closed when the carrier closes.
// Returns nil on a closed carrier.
func (c *CarrierConn) Register(id uint32) chan []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || id == 0 {
		return nil // stream 0 is reserved for control frames
	}
	s, ok := c.streams[id]
	if !ok {
		s = c.createStreamLocked(id, false)
	}
	return s.ch
}

// Deregister unregisters a stream. It is intentionally QUIET: the
// mailbox, its worker and the consumer channel are left as they are (the
// channel is only closed by Close), so a consumer that is done reading
// but not yet unwound keeps its existing semantics. The worker exits
// when the carrier closes (Close also closes the mailbox of a
// deregistered stream — see allStreams — which is what actually wakes a
// worker parked in Pop) or when the stream is terminated by the overflow
// policy. Further frames for the ID start a NEW stream, same as before
// Phase 3.
func (c *CarrierConn) Deregister(id uint32) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

// Terminate ends the stream id with TERMINATING semantics (the up-carrier
// drop-storm fix, Part 1). It is the safe replacement for Deregister at any
// "this destination is dead, do not re-open it" drop path.
//
// Unlike Deregister (which is quiet and lets a later peer retransmit on the
// SAME id re-open it as a brand-new stream and re-fire OnNewStream — the
// 0x00/0x04 re-drop storm), Terminate keeps the stream record registered and
// marks it terminated. Every subsequent frame the peer retransmits on that id
// (FrameData 0x00, FrameClose 0x04, ...) is therefore dropped SILENTLY by the
// dispatcher (the terminated record is still in c.streams, so the dispatcher
// never re-creates it and OnNewStream does not re-fire), and the peer is
// signalled a best-effort FrameClose over the control plane so it tears its
// end down too. This matches the documented invariant pinned by
// TestTerminatedStreamStaysRegistered: a dead stream stays registered so it
// does NOT re-open and re-dial a dead destination.
//
// A brand-NEW stream with a NEW id for the same destination is UNaffected:
// that is the recovery path, and it is the ONLY way the peer re-establishes a
// session after a termination.
//
// Safe to call from the dispatcher goroutine (mirrors the overflow
// applyPressure path that already calls terminateStream) or from a spawned
// consumer goroutine. If the id is already unknown (deregistered, or the
// carrier is closing) it installs a terminated tombstone so any in-flight
// retransmit on the id is dropped silently; on a closing carrier it is a
// quiet no-op.
func (c *CarrierConn) Terminate(id uint32) {
	// tracked latches (under c.mu) whether this call is counted on termWG.
	// It is set in the SAME critical section as the Add so Done is called
	// if and only if Add was — never on a closing carrier, where Close
	// closes s.ch as the consumer wake instead.
	tracked := false
	c.mu.Lock()
	s, ok := c.streams[id]
	if !ok && !c.closing {
		// Not yet registered: install a terminated tombstone. callback=false
		// so OnNewStream can NEVER fire for this id (a retransmit that does
		// arrive is dropped silently by the dispatcher, not re-opened).
		s = c.createStreamLocked(id, false)
	}
	if s != nil && !c.closing {
		tracked = true
		c.termWG.Add(1)
	}
	c.mu.Unlock()
	if s == nil {
		return // closing carrier, or stream 0
	}
	// signalPeer=true: best-effort FrameClose over the control plane so the
	// remote side tears down its end of the stream too. The handoff's
	// consumer send is bounded by c.closed (Closed at step 2), so a racing
	// Close cannot hang on this Done.
	c.terminateStream(s, true)
	if tracked {
		c.termWG.Done()
	}
}

// WriteFrame encodes and sends one frame. Serialized via writeCh.
func (c *CarrierConn) WriteFrame(streamID uint32, typ uint8, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrPayloadTooLarge
	}
	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], streamID)
	buf[4] = typ
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(payload)))
	copy(buf[HeaderSize:], payload)
	return c.write(buf)
}

// Liveness: the keepalive loop is a round-trip detector. It sends one
// FramePing every `interval`; a live peer answers each ping with a
// FramePong (Dispatch does this). If NO pong arrives for
// DefaultLivenessRounds consecutive pings, the carrier is declared
// blackholed — reachable writes but no traffic comes back (a dropped
// path the OS will never time out on its own) — and the carrier is
// torn down through the STANDARD Close path. Close interrupts the
// stuck read (rwc.Close), which ends the read loop, ends Dispatch,
// and drives the normal carrier-loss/rebind machinery — there is no
// second teardown path.
//
// The decision is deterministic (a round counter, not a wall-clock
// timer): a healthy long-lived connection is never declared dead
// because a pong resets the counter each round, and detection is
// bounded to LivenessRounds * interval (45 s at the defaults) —
// independent of OS TCP timeouts, which may never fire.
const DefaultLivenessRounds = 3

// LivenessRounds is the configured number of consecutive unanswered
// pings after which the carrier is declared blackholed. The value is
// read under c.mu by the liveness loop at every ping round, so a call
// takes effect from the next round onward (mutex-ordered with the
// loop's read; the loop's first decision is at least one interval
// after the constructor returns). rounds <= 0 are ignored (the
// default stays in force).
func (c *CarrierConn) SetLivenessRounds(rounds int) {
	c.mu.Lock()
	if rounds > 0 {
		c.livenessRounds = rounds
	}
	c.mu.Unlock()
}

// liveness runs the keepalive ping loop AND the blackhole detection.
// The carrier closes and always stops its ticker, so no ticker leaks.
// Termination signal: c.closed (Close). Write failures are IGNORED for
// the liveness decision: a failed write means the path is broken and
// the READ side will observe the error (readErr) — the read loop is
// the authoritative "carrier is gone" signal, and Close() is
// idempotent, so declaring it on write failure too would at worst
// close the carrier a moment earlier. Counting write failures as
// "missed rounds" instead would risk a false positive: a single
// transient write error on a healthy path must not start the death
// clock.
func (c *CarrierConn) liveness(interval time.Duration) {
	defer c.goroutineStopped()
	t := time.NewTicker(interval)
	defer t.Stop()
	ping := make([]byte, HeaderSize) // StreamID 0, FramePing, Length 0
	ping[4] = FramePing
	missed := 0
	for {
		select {
		case <-t.C:
			c.mu.Lock()
			rounds := c.livenessRounds
			c.mu.Unlock()
			// Keepalive Ping rides the control plane (ctrlCh): a Ping is
			// ordering-insensitive and must not queue behind DATA frames.
			_ = c.writeControl(ping) // best effort; see the method doc
			c.mu.Lock()
			if c.sawPong {
				c.sawPong = false
				missed = 0
			} else {
				missed++
			}
			dead := missed >= rounds
			c.mu.Unlock()
			if dead {
				// Blackhole detected: standard teardown. Close is
				// idempotent and safe from any goroutine.
				c.mu.Lock()
				stats := c.stats
				c.mu.Unlock()
				stats.blackholeDeath()
				c.Close()
			}
		case <-c.closed:
			return
		}
	}
}

// Conn returns the underlying io.ReadWriteCloser.
func (c *CarrierConn) Conn() io.ReadWriteCloser { return c.rwc }

// SetReadBuffer installs the bufio.Reader the read loop should
// consume. For the pre-auth handshake reader, prefer
// NewCarrierConnWithReader instead: the read loop starts inside the
// constructor and latches its buffer on the first read, so installing
// the reader after construction races that first read and can orphan
// pre-buffered bytes. SetReadBuffer remains for tests that replace
// the buffer on an idle carrier before any frame has been read.
func (c *CarrierConn) SetReadBuffer(br *bufio.Reader) {
	c.bufMu.Lock()
	c.buf = br
	c.bufMu.Unlock()
}

// readBuffer returns the active read buffer, creating one if needed.
func (c *CarrierConn) readBuffer() *bufio.Reader {
	c.bufMu.Lock()
	if c.buf == nil {
		c.buf = bufio.NewReaderSize(c.rwc, 65536)
	}
	br := c.buf
	c.bufMu.Unlock()
	return br
}

// ReadErr returns the error that terminated the read loop (nil while the
// read loop is still running).
func (c *CarrierConn) ReadErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readErr
}

// Closing reports whether the carrier's Close has started (the closing flag
// is latched at step 1 of Close, before closed is closed). Callers use it
// to distinguish a PARKED PUSH that was released by a clean carrier teardown
// (which must NOT be classified as a data-integrity failure) from one
// released by a worker's consumer-stall reclaim (a genuine stream failure).
// SUBTASK 30.
func (c *CarrierConn) Closing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closing
}

// Ready reports whether the carrier read loop is still alive.
func (c *CarrierConn) Ready() bool {
	select {
	case <-c.readDone:
		return false
	default:
	}
	c.mu.Lock()
	dead := c.closing
	c.mu.Unlock()
	return !dead
}

// WaitCarrier polls Ready() at 50ms intervals until the context expires.
func WaitCarrier(ctx context.Context, c *CarrierConn) (*CarrierConn, error) {
	if c == nil {
		return nil, errors.New("mux: no carrier")
	}
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		if c.Ready() {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// StreamCount returns the number of registered streams.
func (c *CarrierConn) StreamCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.streams)
}

// Dispatch is the single consumer of the frames channel. It routes
// FrameHeader/FrameData/FrameRebind/FrameClose into the stream's bounded
// mailbox and replies FramePong[0] to FramePing. Frames for unknown or
// already removed streams are dropped — unless OnNewStream is set, in
// which case the first frame of a new stream creates it and triggers the
// callback (with the triggering frame's type).
//
// Dispatch NEVER blocks on a slow consumer (Phase 3, Issue B): every
// delivery is a non-blocking TryPush into the stream mailbox. When a
// stream's mailbox is full — because its consumer stopped reading — the
// dispatcher keeps serving every other stream and, once that stream has
// been unable to accept data for limits.OverflowWait, terminates just
// THAT stream (its consumer then receives nil, the same signal as
// FrameClose, and a best-effort FrameClose goes back to the peer).
// Dispatch returns when the read loop terminates.
func (c *CarrierConn) Dispatch() {
	c.dispatched.Store(true)
	defer close(c.dispatchDone)
	for f := range c.frames {
		switch f.Type {
		case FrameData, FrameHeader, FrameRebind, FrameClose:
			c.mu.Lock()
			s, ok := c.streams[f.StreamID]
			if !ok && c.OnNewStream != nil && !c.closing {
				s = c.createStreamLocked(f.StreamID, true)
				ok = true
			}
			c.mu.Unlock()
			if !ok {
				continue // unknown stream (deregistered or never registered)
			}
			if s.callback {
				s.callback = false
				c.OnNewStream(f.StreamID, f.Type, s.ch)
			}
			var it queueItem
			if f.Type == FrameClose {
				it = queueItem{isClose: true}
			} else {
				it = queueItem{payload: f.Payload}
			}
			c.deliver(s, it)
		case FrameReset:
			// Issue #20: stream-level negative acknowledgement. The node
			// callback terminates the stranded local session; its OnClose
			// hook deregisters the stream from every carrier, so a repeat
			// or reordered reset for the same stream is an idempotent no-op
			// here (the stream is already gone, or a new session owns the
			// ID and its own generation check rejects the stale frame).
			//
			// These are CONTROL frames: they are NEVER delivered to the
			// stream mailbox, so no OnNewStream fire is suppressed and no
			// stream record is created (a reset for a stream unknown to this
			// carrier is expected mid-loss-window and must not spawn a
			// phantom stream or trigger a connection-level failure). The
			// payload is parse-validated here (structural only) and the
			// semantic validation (session existence, generation echo)
			// happens in the node callback.
			if c.OnStreamReset != nil {
				if reason, gen, perr := ParseResetPayload(f.Payload); perr == nil {
					c.OnStreamReset(f.StreamID, reason, gen)
				}
			}
		case FrameBootstrapAck:
			// Issue #21: bootstrap result from Germany. The originator
			// pre-registers its up stream at StartSession, so a live wait
			// implies the stream exists on this carrier; an unknown-stream
			// ack (its session already closed, or a stale frame for a
			// superseded stream) has no waiter and is dropped SILENTLY —
			// never a protocol violation (duplicate/stale control frames
			// are expected and must stay idempotent). No stream mailbox
			// delivery: control-only, parsed structurally here and resolved
			// semantically in the node callback.
			if c.OnStreamBootstrapAck != nil {
				if status, perr := ParseBootstrapAckPayload(f.Payload); perr == nil {
					c.OnStreamBootstrapAck(f.StreamID, status)
				}
			}
		case FramePing:
			pong := make([]byte, HeaderSize+1)
			pong[4] = FramePong
			binary.BigEndian.PutUint16(pong[5:7], 1)
			pong[7] = 0
			// Keepalive Pong replies ride the control plane (ctrlCh); the
			// pong is ordering-insensitive vs DATA (Section 4 routing table).
			_ = c.writeControl(pong)
		case FramePong:
			// keepalive ack: latch for the liveness loop, which reads
			// and clears it under c.mu after each ping round.
			c.mu.Lock()
			c.sawPong = true
			c.mu.Unlock()
		case FrameCredit:
			// Phase A (design doc §5.3): parse and validate the credit.
			// Connection-level rejects (malformed payload length, stream
			// 0, unregistered stream) are enforced in readLoop before
			// the frame reaches the dispatcher; the stream here is
			// always registered and the payload is always 32 bytes.
			//
			// STREAM-level reject: a credit whose semantic content
			// (version, generation, reserved fields) violates §5.3
			// terminates the target stream (the credit itself is the
			// signal; a FrameClose would be semantically wrong).
			p, _ := DecodeCreditPayload(f.Payload) // length guaranteed by readLoop
			if vErr := ValidateCreditPayload(&p); vErr != nil {
				c.mu.Lock()
				s, known := c.streams[f.StreamID]
				c.mu.Unlock()
				if known {
					c.terminateStream(s, false)
				}
				continue
			}
			// Valid credit (Phase B, Section 4): hand it to OnStreamCredit
			// — OUTSIDE c.mu (mirroring OnNewStream/OnStreamTerminated), so
			// the ledger leaf lock taken inside the callback is never nested
			// under c.mu (the Section 9 lock-ordering proof, point 3). The
			// callback only records state; it never enqueues a credit
			// (the no-block invariant B3). A nil callback is a no-op, which
			// keeps the control plane inert until a later slice wires it.
			if c.OnStreamCredit != nil {
				c.OnStreamCredit(f.StreamID, p)
			}
		default:
			// unknown frame type: drop
		}
	}
}

// limitsLocked returns a copy of the current stream limits (takes c.mu;
// call sites must not already hold it).
func (c *CarrierConn) limitsLocked() StreamLimits {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.limits
}

// Limits returns a copy of the carrier's current stream limits, suitable
// for lock-free use by the caller (SF-4). It acquires c.mu, copies the
// StreamLimits struct, and releases before returning; no c.mu is held
// across the return. This is the accessor Phase B Slices 4-5 use for
// the sender credit gate clamp (the hot path must read the CARRIER's
// live MaxBytesPerStream, not the node config, so SetStreamLimits
// (carrier.go:633, under c.mu) cannot race the reader).
func (c *CarrierConn) Limits() StreamLimits {
	c.mu.Lock()
	l := c.limits
	c.mu.Unlock()
	return l
}

// deliver routes one item into a stream's mailbox. Called by the dispatcher
// goroutine only (it owns s.pressureStart; the queue owns and synchronizes
// its primary and carry regions).
//
// Overflow policy (Phase 3 + retry-grace + SUBTASK 30 backpressure): a
// stream whose primary mailbox cannot accept data may carry the refused
// frame in the queue's bounded FIFO overflow region. The worker drains the
// primary first and then the carry region, so a transient consumer stall
// no longer loses an in-order byte or strands a tail at end-of-data.
//
// SUBTASK 30 — real backpressure: when BOTH the primary and the carry are
// full (or the aggregate budget is exhausted), the dispatcher BLOCKS in
// PushPark until the consumer drains the mailbox (a Pop frees space and
// wakes the parked pusher) or the queue is closed (carrier teardown /
// stream termination). This propagates backpressure through the entire
// chain: dispatcher → c.frames → readLoop → TCP read → peer's WriteFrame
// → peer's relay → target/client socket. A slow consumer paces the sender
// instead of triggering a stream termination.
//
// The dispatcher never reorders anything: the mailbox is FIFO, the carry
// region is FIFO, and the single worker serves the primary and only then
// the carry region, so per-stream order holds end-to-end.
//
// Deadlock analysis: PushPark holds no locks while parked (it waits on
// the free channel after releasing q.mu). The consumer (worker) holds no
// locks while blocked on s.ch (a channel send). The sender (readLoop)
// holds no locks while blocked on c.frames (a channel send). No lock is
// held across any blocking wait, so no lock-ordering cycle can form.
// The only external dependency is the consumer's socket write (a kernel
// call that will complete or error), and the carrier's c.closed channel
// (closed by Close, which also closes q, waking any parked pusher).
func (c *CarrierConn) deliver(s *streamRec, it queueItem) {
	if s.terminated.Load() {
		return // stream already over: drop
	}
	if it.isClose {
		c.deliverClose(s, it)
		return
	}
	// DATA / HEADER / REBIND — the survivable retry-grace path. A refused
	// frame is CARRIED (in the queue's bounded carry region), not killed on
	// the first refusal.
	ok, reason := s.q.TryPushReason(it)
	if ok {
		return
	}
	if s.terminated.Load() {
		// A concurrent termination raced us: the mailbox closed and the
		// nil is on its way; this frame dies with the clean abort.
		return
	}
	if reason == rejectStreamFrames || reason == rejectStreamBytes {
		// A per-stream bound (frame count or stream byte cap): a genuine
		// consumer STALL — the exact slow-client path (SUBTASK 30). First
		// carry the frame in the bounded carry region (headroom), and when
		// the carry is also full, BLOCK the dispatcher in PushPark until
		// the consumer drains the mailbox (a Pop frees space and wakes the
		// parked pusher). This paces the upstream sender — never a silent
		// truncation, never a per-item termination of a live stream.
		if ok, _ := s.q.TryCarry(it); ok {
			return
		}
		if s.terminated.Load() {
			return // a concurrent termination raced us
		}
		if s.q.PushPark(it) {
			return // accepted after the consumer drained space
		}
		// PushPark returned false: the queue was closed while we parked.
		// Two distinct causes, both of which lose the in-order byte:
		//   - a concurrent worker CONSUMER-STALL reclaim (terminateStream):
		//     a genuine data-integrity failure -> classify it;
		//   - a clean CARRIER teardown (Close, rebind/loss): the frame dies
		//     with the carrier's clean abort -> do NOT classify it as
		//     data_undeliverable (that would mislabel a normal rebind as a
		//     data loss).
		// terminated=true is already set on both reclaim paths, so a
		// terminated stream never double-classifies.
		if !s.terminated.Load() && !c.Closing() {
			c.failUndeliverableData(s, true)
		}
		return
	}
	// An aggregate carrier-wide byte budget (or a closed mailbox) is NOT a
	// per-stream consumer stall: it means the CARRIER is saturated across
	// all its streams. Blocking the single dispatcher on it would stall
	// every other stream on this carrier (head-of-line) with no single
	// consumer that can drain it, so we preserve deliver-or-fail by ending
	// only THIS stream, never silently dropping an in-order byte.
	c.failUndeliverableData(s, true)
}

// deliverClose handles a FrameClose. A close must follow every preceding
// DATA frame in FIFO order, so when the primary (or the carry) is full the
// dispatcher CARRIES it behind the data (Pop drains the primary first and
// only then the carry region).
//
// SUBTASK 30: if both the carry cap and the aggregate budget are exhausted,
// BLOCK in PushPark until the consumer drains the mailbox, so the ordered
// half-close is delivered rather than the stream being terminated. A close
// carries no payload bytes, so it fits the carry cap by byte-count (0 B);
// PushPark's park waits for the carry frame cap or the aggregate budget to
// free up.
func (c *CarrierConn) deliverClose(s *streamRec, it queueItem) {
	if s.q.TryPush(it) {
		s.pressureStart = time.Time{}
		return
	}
	if s.terminated.Load() {
		return
	}
	if ok, _ := s.q.TryCarry(it); ok {
		return
	}
	if s.terminated.Load() {
		return
	}
	// Both the primary and the carry are full: block until the consumer
	// drains the mailbox so the close can be delivered in order.
	if s.q.PushPark(it) {
		return
	}
	// Queue was closed while we parked. A clean CARRIER teardown (Close)
	// loses the close with the abort and must NOT be classified as
	// data_undeliverable; a worker CONSUMER-STALL reclaim (terminated
	// already set) is. terminated=true covers the reclaim, so only a
	// live, non-closing stream can be mislabelled — suppress it there.
	if !s.terminated.Load() && !c.Closing() {
		c.failUndeliverableData(s, false)
	}
}

// failUndeliverableData records that an in-order DATA frame is undeliverable
// to this live stream and terminates the stream cleanly. It is the
// dispatcher-side terminal of the retry-grace: a DATA byte that could not be
// queued or carried is either DELIVERED (mailbox/carry) or the STREAM IS
// CLEANLY FAILED — never silently dropped while the stream stays healthy.
// Dispatcher goroutine only; takes c.mu solely to read the stats pointer.
// triggerLostData reports whether the triggering frame itself is a lost DATA
// frame (true) or a FrameClose (false — a close carries no bytes).
func (c *CarrierConn) failUndeliverableData(s *streamRec, triggerLostData bool) {
	// Count every DATA frame the consumer will never get: frames still in
	// the primary mailbox, frames in the carry region, and the triggering
	// frame if it is DATA. Close reclaims the bytes; we credit the drops.
	if s.terminated.Load() {
		return
	}
	lost := int64(s.q.QueueDataLen())
	if triggerLostData {
		lost++
	}
	if lost == 0 {
		// No DATA bytes were actually lost (e.g. a close-only escalation on
		// an empty queue): still terminate, but skip the drop loop.
	}
	c.mu.Lock()
	stats := c.stats
	c.mu.Unlock()
	for i := int64(0); i < lost; i++ {
		stats.droppedDataFrame()
	}
	// terminateStream(s, true) delivers nil to the consumer and signals the
	// peer with a best-effort FrameClose, so both ends tear the stream down
	// deterministically (no half-alive stream, no byte hole).
	c.terminateStream(s, true)
	if c.OnStreamDataUndeliverable != nil {
		c.OnStreamDataUndeliverable(s.id)
	}
}

// applyPressure records that a stream could not accept data right now and
// terminates it once that state has persisted for OverflowWait. It never
// blocks and never touches other streams. Dispatcher goroutine only.
func (c *CarrierConn) applyPressure(s *streamRec) {
	if s.pressureStart.IsZero() {
		s.pressureStart = time.Now()
		return
	}
	if time.Since(s.pressureStart) >= c.limitsLocked().OverflowWait {
		wait := time.Since(s.pressureStart)
		c.mu.Lock()
		stats := c.stats
		c.mu.Unlock()
		stats.overflowTerminated(wait)
		c.terminateStream(s, true)
	}
}

// terminateStream ends one stream (never the carrier) and notifies its
// consumer exactly once. Idempotent — the dispatcher (overflow pressure)
// and the stream worker (consumer that stopped reading) can both call it.
//
// Notification contract (mirrors FrameClose semantics): the consumer
// channel receives one nil payload — unless the carrier is already
// closing (Close then closes the channel) or the channel cannot accept
// it within OverflowWait (the consumer is stuck; Close closes the
// channel later).
//
// signalPeer sends a best-effort FrameClose back to the peer so the
// remote side tears its end of the stream down too; used when the LOCAL
// consumer caused the termination (not when the peer sent FrameClose).
//
// The stream stays registered (terminated flag set) so later frames for
// its ID are dropped instead of being treated as a brand-new stream —
// which would re-fire OnNewStream and re-dial a dead destination.
func (c *CarrierConn) terminateStream(s *streamRec, signalPeer bool) {
	s.stopOnce.Do(func() {
		s.terminated.Store(true)
		if c.OnStreamTerminated != nil {
			c.OnStreamTerminated(s.id)
		}
		// Closing the mailbox discards what is still queued; the bytes
		// come back to the aggregate budget inside q.Close (under
		// q.mu, so a concurrent Pop cannot reclaim them again).
		s.q.Close()
		if signalPeer {
			// FrameClose is a terminal signal that must not be dropped, so it
			// rides the control plane (ctrlCh) via the BLOCKING variant
			// (Section 4 routing table). Best effort: ErrCarrierClosed if the
			// carrier is already closing.
			_ = c.WriteControlFrame(s.id, FrameClose, nil)
		}
		select {
		case s.ch <- nil:
		case <-c.closed:
		case <-time.After(c.limitsLocked().OverflowWait):
			// consumer stuck: nothing to deliver; Close closes ch.
		}
	})
}

// streamWorker drains one stream's mailbox into its consumer channel.
// One worker per stream; it is a carrier-owned goroutine (counted in
// live and in workerWait; it exits via the Phase 2 lifecycle: queue
// Close — which Close performs for every stream, deregistered or not —
// or carrier close aborting one of its handoff selects).
//
// Send/closure contract: this worker is the ONLY sender on s.ch besides
// terminateStream (dispatcher-side), and Close is the ONLY closer of
// s.ch. Close waits for every worker to exit (workerWait) before it
// closes any s.ch, so a send on a closed channel is structurally
// impossible — no select arm here can ever mask one.
// Per-stream ordering is preserved: single mailbox (FIFO) → single worker
// → single consumer channel. A worker blocked on a full consumer channel
// for longer than ConsumerStall terminates its own stream — the slow
// consumer's deadline (SUBTASK 30).
//
// SUBTASK 30: the handoff deadline is now ConsumerStall, NOT OverflowWait.
// The old code used OverflowWait (100 ms) for the CONSUMER-side handoff,
// which is the exact bug: a remote client whose socket write takes longer
// than 100 ms (TCP window + RTT over the internet) caused the worker to
// terminate the stream mid-download — the ~2–3.5 MB truncation signature.
// ConsumerStall (default 30 s) absorbs a slow-but-alive consumer; a dead
// consumer (relay exited / session closed) is still reclaimed after
// ConsumerStall, so the worker never blocks forever (Close's c.closed also
// releases the handoff, and Close closes s.ch after workerWait).
func (c *CarrierConn) streamWorker(s *streamRec) {
	defer c.goroutineStopped()
	defer c.workerWait.Done()
	for {
		it, ok := s.q.Pop()
		if !ok {
			return // queue closed: stream terminated or carrier closing
		}
		if it.isClose {
			// FrameClose: hand the nil (half-close) to the consumer and
			// exit. Bounded by ConsumerStall: a consumer that stopped
			// reading ends the stream silently (Close closes the channel
			// later; c.closed also aborts this handoff on teardown).
			select {
			case s.ch <- nil:
			case <-c.closed:
			case <-time.After(c.limitsLocked().ConsumerStall):
				c.mu.Lock()
				stats := c.stats
				c.mu.Unlock()
				stats.overflowTerminatedWorker()
				s.terminated.Store(true)
				if c.OnStreamTerminated != nil {
					c.OnStreamTerminated(s.id)
				}
			}
			return
		}
		// The popped item's payload bytes were already returned to the
		// aggregate budget by Pop itself (under the mailbox lock) — do
		// NOT touch queuedBytes here again.
		select {
		case s.ch <- it.payload:
			// Delivered: this is the real backpressure release point. The
			// consumer (the node relay) has taken the frame and will write
			// it to the socket, which paces the upstream sender via the
			// dispatcher's PushPark (deliver). Nothing to do on success.
		case <-c.closed:
			return
		case <-time.After(c.limitsLocked().ConsumerStall):
			// consumer stopped reading for ConsumerStall: end this stream,
			// not the carrier. Bounded — a dead consumer is reclaimed.
			c.mu.Lock()
			stats := c.stats
			c.mu.Unlock()
			stats.overflowTerminatedWorker()
			c.terminateStream(s, false)
			return
		}
	}
}

// Close shuts the carrier down. It is idempotent and safe to call from
// multiple goroutines at once.
//
// Shutdown sequence (every remaining block is cancellable via the closed
// channel or the connection close, so no goroutine stays blocked):
//  1. closing=true — new Register/WriteFrame calls fail immediately;
//  2. close(closed) — unblocks the keepalive, a running dispatcher, and
//     in-flight writes;
//  3. rwc.Close() — unblocks a read (or write) stuck in the network
//     layer;
//  4. wait for in-flight write callers, then fail every still-queued
//     write with ErrCarrierClosed — after Close returns, no WriteFrame
//     caller is still waiting;
//  5. shut down the streams, in four sub-steps:
//     (a) close EVERY stream mailbox — allStreams, which also includes
//     streams removed by Deregister — reclaiming discarded bytes
//     from the aggregate budget; closing the mailbox is the only
//     thing that releases a worker parked in Pop;
//     (b) wait for every stream worker to exit — OUTSIDE c.mu, because
//     the last worker's exit path takes c.mu. By the time the wait
//     returns, no worker can send on any s.ch: a worker is either
//     gone, or (it cannot exist) it would have to hold a mailbox
//     item, which requires a Pop from a still-open mailbox, and all
//     mailboxes are now closed;
//     (b2) wait for the dispatcher's own terminate handoffs (covered by
//     dispatchDone);
//     (b3) wait for every in-flight PUBLIC Terminate (termWG) — the
//     third sender on s.ch, running in node-spawned goroutines that
//     neither workerWait nor dispatchDone covers;
//     (c) close every stream channel, waking stream consumers. No send
//     on s.ch can ever race this close, so "send on closed channel"
//     is impossible.
//
// As a consequence the read loop (read error on the closed connection or
// the closed channel), the writer, the keepalive and every stream worker
// all terminate, and a running Dispatch returns once the read loop closes
// the frames channel.
// ShutdownDone is closed when all carrier-owned goroutines have exited.
//
// Step 4 may briefly block until in-flight writes settle; that is bounded
// because step 3 interrupts their blocking IO (true for net.Conn and
// *websocket.Conn, the rwc implementations this project uses).
func (c *CarrierConn) Close() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		c.mu.Unlock()

		close(c.closed)
		// Best effort: the peer may already be gone; the close also
		// interrupts any read/write blocked in the network layer.
		_ = c.rwc.Close()

		// Phase B control-plane drain, sequenced FIRST (Section 4): resolve
		// in-flight + queued control frames before the DATA frames, so a
		// FrameClose stranded on ctrlCh is never held up behind a still-
		// draining writeCh. ctrlWG.Add happens under c.mu exactly like
		// writeWG.Add, so every Add is mutex-ordered before closing=true.
		c.ctrlWG.Wait()
		c.drainCtrl()

		c.writeWG.Wait()
		c.drainWrites()

		// (a) Close every mailbox — all streams, including ones Deregister
		// removed from c.streams. Workers parked in Pop return via the
		// closed queue; the bytes discarded by each mailbox are returned
		// to the aggregate budget inside q.Close (under q.mu, so no
		// concurrent Pop can reclaim the same bytes). The channels are
		// NOT closed yet. The snapshot is taken under c.mu, but the
		// q.Close calls run OUTSIDE it: a mailbox close only takes q.mu,
		// and q.mu is never taken while c.mu is held anywhere else, so
		// the lock ordering stays acyclic.
		c.mu.Lock()
		qs := make([]*StreamQueue, 0, len(c.allStreams))
		for _, s := range c.allStreams {
			qs = append(qs, s.q)
		}
		c.mu.Unlock()
		for _, q := range qs {
			q.Close()
		}

		// (b) Wait for every stream worker to exit, WITHOUT c.mu held
		// (the last worker's goroutineStopped takes it). Safe and
		// bounded: every worker is either gone or will exit because its
		// mailbox is closed and c.closed has been open since step 2.
		c.workerWait.Wait()

		// (b2) Wait for the dispatcher to finish any terminate handoff
		// (s.ch send) before closing s.ch: the dispatcher is also a
		// sender on s.ch (the terminateStream handoff in
		// applyPressure/failUndeliverableData), and the worker wait in (b)
		// does NOT cover it. The channel close/receive gives the
		// happens-before; it is bounded because step 2/3 aborts the read
		// loop and closReceeder lets readLoop close c.frames, so the
		// dispatcher drains <=256 frames and returns; without this wait,
		// step (c) could close an s.ch the dispatcher is about to send on
		// — "send on closed channel".
		if c.dispatched.Load() { // skip carriers that never ran Dispatch (shutdown/unit-test paths)
			<-c.dispatchDone
		}

		// (b3) Wait for any in-flight PUBLIC Terminate to finish its
		// terminateStream handoff (the s.ch <- nil send) before closing
		// s.ch: Terminate is called from node-spawned goroutines
		// (bootstrapUpStream's dial-drop, handleRebind's drop, the
		// onUpNewStream/onDownNewStream default branches) that neither
		// workerWait (stream workers) nor dispatchDone (the dispatcher
		// itself) covers — the dispatcher spawns them and returns without
		// waiting. This is the untracked third sender on s.ch that the
		// original close-safety proof did not account for. Bounded: every
		// tracked handoff's consumer send is released by c.closed (step 2),
		// so the Wait can never hang; and termWG.Add is mutex-ordered under
		// c.mu before the closing latch, so this Wait sees every in-flight
		// call (and no call started AFTER the latch can Add — see the
		// field doc). Without this wait, step (c) could close an s.ch that
		// a racing Terminate is about to send on — "send on closed
		// channel" / the -race between close(s.ch) and s.ch <- nil.
		c.termWG.Wait()

		// (c) Now — and only now — close every stream channel, waking
		// the consumers. No worker can be sending when this runs.
		// allStreams may contain several records for one ID (re-bind
		// generations); each channel is closed exactly once, and the
		// streams map is emptied.
		c.mu.Lock()
		for _, s := range c.allStreams {
			close(s.ch) // wakes the consumer (Phase 2 contract)
			delete(c.streams, s.id)
		}
		c.mu.Unlock()
	})
}

// CarrierAuth lives in auth.go (v1 challenge/response protocol, Phase 6).
