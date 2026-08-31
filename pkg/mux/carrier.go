package mux

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
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

	frames    chan Frame
	writeCh   chan writeReq
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
	// shutdownDone is closed when every carrier-owned goroutine
	// (readLoop, writeLoop, keepalive) has exited.
	shutdownDone chan struct{}
	shutdownOnce sync.Once

	mu      sync.Mutex
	streams map[uint32]*streamRec
	closing bool
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
		readDone:     make(chan struct{}),
		closed:       make(chan struct{}),
		shutdownDone: make(chan struct{}),
		streams:      make(map[uint32]*streamRec),
		limits:       DefaultStreamLimits,
		buf:          br, // bound before readLoop starts (see NewCarrierConnWithReader)
	}
	c.mu.Lock()
	c.live = 2 // readLoop + writeLoop
	c.mu.Unlock()
	go c.writeLoop()
	go c.readLoop()
	if pingInterval > 0 {
		c.mu.Lock()
		c.live++
		c.mu.Unlock()
		go c.keepalive(pingInterval)
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
			c.mu.Unlock()
			return
		}
		// Post-auth frame-context rules (Phase 6):
		//  1. FrameAuth is ONLY valid during the handshake (which ran
		//     before this carrier existed) — any FrameAuth seen now is a
		//     protocol violation (v0 peer or attacker).
		//  2. Stream 0 is reserved for control frames (Ping/Pong).
		//     Application frames on stream 0 would otherwise create a
		//     phantom stream via OnNewStream or hit Deregister(0); they
		//     are rejected.
		// Both are connection-level failures: the carrier is terminated.
		if f.Type == FrameAuth ||
			(f.StreamID == 0 && f.Type != FramePing && f.Type != FramePong) {
			c.mu.Lock()
			c.readErr = ErrProtocolViolation
			c.mu.Unlock()
			return
		}
		select {
		case c.frames <- f:
		case <-c.closed:
			return
		}
	}
}

// writeLoop serializes every write through a single goroutine. It exits
// as soon as the carrier is closed — it never blocks on an uncancelled
// channel receive. Failing the requests still queued at that moment is
// Close's job (drainWrites), so no write caller is ever left waiting on a
// dead writer.
func (c *CarrierConn) writeLoop() {
	defer c.goroutineStopped()
	for {
		select {
		case <-c.closed:
			return
		case req := <-c.writeCh:
			_, err := c.rwc.Write(req.data)
			select {
			case <-c.closed:
				// Close has started: report the shutdown error so a
				// write that lands around the close reports a
				// deterministic result, whatever the underlying
				// connection error was.
				err = ErrCarrierClosed
			default:
			}
			req.done <- err
		}
	}
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
// default; raising MaxFramesPerStream without MaxBytesPerStream makes the
// frame bound the larger ceiling.)
//
// MaxBytesTotal is the carrier-wide aggregate budget across ALL streams'
// mailboxes, so hundreds of slow streams cannot multiply per-stream
// memory into unbounded RAM.
//
// OverflowWait is how long a stream may be unable to accept data (full
// mailbox or a consumer that stopped reading) before the carrier
// terminates that stream — not the carrier.
type StreamLimits struct {
	MaxFramesPerStream int
	MaxBytesPerStream  int
	MaxBytesTotal      int
	OverflowWait       time.Duration
}

// DefaultStreamLimits: 16 frames / 1 MiB per stream, 32 MiB per carrier,
// 100 ms overflow wait.
var DefaultStreamLimits = StreamLimits{
	MaxFramesPerStream: MaxFrames,
	MaxBytesPerStream:  1 << 20,  // 1 MiB
	MaxBytesTotal:      32 << 20, // 32 MiB
	OverflowWait:       100 * time.Millisecond,
}

// MaxFrames is the maximum number of frames a stream mailbox can hold.
const MaxFrames = 16

// SanitizeLimits normalizes a limit set: zero or negative fields fall
// back to the defaults (a "0 limit" must never mean unbounded or
// instant-kill), and the frame bound is clamped to MaxFrames.
func SanitizeLimits(l StreamLimits) StreamLimits {
	d := DefaultStreamLimits
	if l.MaxFramesPerStream <= 0 || l.MaxFramesPerStream > MaxFrames {
		l.MaxFramesPerStream = d.MaxFramesPerStream
	}
	if l.MaxBytesPerStream <= 0 {
		l.MaxBytesPerStream = d.MaxBytesPerStream
	}
	if l.MaxBytesTotal <= 0 || l.MaxBytesTotal < l.MaxBytesPerStream {
		l.MaxBytesTotal = d.MaxBytesTotal
	}
	if l.OverflowWait <= 0 {
		l.OverflowWait = d.OverflowWait
	}
	return l
}

// SetStreamLimits configures the per-stream mailbox bounds. Values are
// sanitized (see SanitizeLimits). Call it before starting Dispatch or
// calling Register, like SetReadBuffer. Changing MaxBytesTotal also
// re-syncs the aggregate limit of every already-created mailbox.
func (c *CarrierConn) SetStreamLimits(l StreamLimits) {
	c.mu.Lock()
	c.limits = SanitizeLimits(l)
	limit := int64(c.limits.MaxBytesTotal)
	qs := make([]*StreamQueue, 0, len(c.allStreams))
	for _, s := range c.allStreams {
		qs = append(qs, s.q)
	}
	c.mu.Unlock()
	// SetBudgetLimit takes each mailbox's own lock — never c.mu — so
	// calling it outside c.mu keeps the lock ordering acyclic.
	for _, q := range qs {
		q.SetBudgetLimit(limit)
	}
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
	// when this stream first started rejecting data.
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

// keepalive sends FramePing periodically. It exits promptly when the
// carrier closes and always stops its ticker, so no ticker leaks.
func (c *CarrierConn) keepalive(interval time.Duration) {
	defer c.goroutineStopped()
	t := time.NewTicker(interval)
	defer t.Stop()
	ping := make([]byte, HeaderSize) // StreamID 0, FramePing, Length 0
	ping[4] = FramePing
	for {
		select {
		case <-t.C:
			_ = c.write(ping)
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
		case FramePing:
			pong := make([]byte, HeaderSize+1)
			pong[4] = FramePong
			binary.BigEndian.PutUint16(pong[5:7], 1)
			pong[7] = 0
			_ = c.write(pong)
		case FramePong:
			// keepalive ack, nothing to do
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

// deliver routes one item into a stream's mailbox without ever blocking.
// Called by the dispatcher goroutine only (it owns s.pressureStart).
//
// Overflow policy (Phase 3): a stream whose mailbox cannot accept data is
// under pressure; the dispatcher drops its frames but keeps going — other
// streams are never affected. If the pressure lasts longer than
// OverflowWait, the stream is terminated (not the carrier).
func (c *CarrierConn) deliver(s *streamRec, it queueItem) {
	if s.terminated.Load() {
		return // stream already over: drop
	}
	if it.isClose {
		// FrameClose (0 bytes). If the mailbox is full the stream will
		// be terminated by the pressure rule anyway, and termination
		// notifies the consumer of stream end the same way.
		if s.q.TryPush(it) {
			s.pressureStart = time.Time{}
		} else {
			c.applyPressure(s)
		}
		return
	}
	// TryPush atomically checks the per-stream bounds AND the carrier-wide
	// aggregate byte budget (all under the mailbox lock — see
	// StreamQueue), adds the accepted bytes to the aggregate, and reports
	// false if the push was refused for any reason. Pressure applies to
	// THIS stream only; other streams are never affected.
	if s.q.TryPush(it) {
		s.pressureStart = time.Time{}
		return
	}
	c.applyPressure(s)
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
		// Closing the mailbox discards what is still queued; the bytes
		// come back to the aggregate budget inside q.Close (under
		// q.mu, so a concurrent Pop cannot reclaim them again).
		s.q.Close()
		if signalPeer {
			_ = c.WriteFrame(s.id, FrameClose, nil) // best effort; ErrCarrierClosed if closing
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
//
// Per-stream ordering is preserved: single mailbox (FIFO) → single worker
// → single consumer channel. A worker blocked on a full consumer channel
// for longer than OverflowWait terminates its own stream — the slow
// consumer's deadline.
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
			// exit. Bounded: a consumer that stopped reading ends the
			// stream silently (Close closes the channel later).
			select {
			case s.ch <- nil:
			case <-c.closed:
			case <-time.After(c.limitsLocked().OverflowWait):
				s.terminated.Store(true)
			}
			return
		}
		// The popped item's payload bytes were already returned to the
		// aggregate budget by Pop itself (under the mailbox lock) — do
		// NOT touch queuedBytes here again.
		select {
		case s.ch <- it.payload:
		case <-c.closed:
			return
		case <-time.After(c.limitsLocked().OverflowWait):
			// consumer stopped reading: end this stream, not the carrier.
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
//  5. shut down the streams, in three sub-steps:
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
