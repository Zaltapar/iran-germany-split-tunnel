package mux

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
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
//   - one dispatcher goroutine (Dispatch) owns the stream-channel map and
//     routes per-stream payloads to handler goroutines;
//   - ALL writes (auth, keepalive, data, close) are serialized through
//     writeCh by a single writer goroutine, so frames can never interleave.
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
	streams map[uint32]chan []byte
	closing bool
	// live counts the carrier-owned goroutines still running.
	live int

	// OnNewStream, if non-nil, is called (synchronously, in the dispatch
	// goroutine) when the first frame for a previously unknown stream
	// arrives. The dispatcher creates and registers the stream channel and
	// passes it to the callback; the callback must return quickly (spawn a
	// goroutine for slow work such as a target dial).
	OnNewStream func(streamID uint32, ch chan []byte)
}

// NewCarrierConn starts the read loop, writer and keepalive ping loop.
// The read loop consumes the stream exclusively from this point on; use
// CarrierAuth BEFORE calling NewCarrierConn to run the auth handshake,
// then install the auth bufio.Reader with SetReadBuffer so already
// buffered bytes are not lost.
func NewCarrierConn(rwc io.ReadWriteCloser, pingInterval time.Duration) *CarrierConn {
	c := &CarrierConn{
		rwc:          rwc,
		frames:       make(chan Frame, 256),
		writeCh:      make(chan writeReq, 256),
		readDone:     make(chan struct{}),
		closed:       make(chan struct{}),
		shutdownDone: make(chan struct{}),
		streams:      make(map[uint32]chan []byte),
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
// goroutine (readLoop, writeLoop, keepalive) has exited. Useful for tests
// and deferred resource accounting; not required for correct shutdown.
func (c *CarrierConn) ShutdownDone() <-chan struct{} {
	return c.shutdownDone
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

// SetReadBuffer installs the bufio.Reader the read loop should consume
// (e.g. the one used during the pre-protocol auth handshake). Call it
// before starting Dispatch.
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

// Register adds a stream channel and returns it. Mutex-protected and safe
// to call from any goroutine (typically the session handler). Returns nil
// if the carrier is already closing.
func (c *CarrierConn) Register(streamID uint32) chan []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return nil
	}
	ch := make(chan []byte, 64)
	c.streams[streamID] = ch
	return ch
}

// Deregister removes a stream channel. Safe to call from any goroutine.
func (c *CarrierConn) Deregister(streamID uint32) {
	c.mu.Lock()
	delete(c.streams, streamID)
	c.mu.Unlock()
}

// StreamCount returns the number of registered streams.
func (c *CarrierConn) StreamCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.streams)
}

// Dispatch is the single consumer of the frames channel. Stream channels
// are pre-registered by session handlers via Register (safe from any
// goroutine); Dispatch only routes: FrameHeader/FrameData payloads go to
// the stream's channel, FrameClose is delivered as a nil payload, and
// frames for unknown or already-removed streams are dropped — unless
// OnNewStream is set, in which case the first frame of a new stream
// creates the channel and triggers the callback. FramePing gets a
// FramePong[0] reply. Dispatch returns when the read loop terminates.
func (c *CarrierConn) Dispatch() {
	for f := range c.frames {
		switch f.Type {
		case FrameData, FrameHeader, FrameClose:
			c.mu.Lock()
			ch := c.streams[f.StreamID]
			newStream := false
			if ch == nil && c.OnNewStream != nil {
				ch = make(chan []byte, 64)
				c.streams[f.StreamID] = ch
				newStream = true
			}
			c.mu.Unlock()
			if ch == nil {
				continue
			}
			if newStream {
				c.OnNewStream(f.StreamID, ch)
			}
			var payload []byte
			if f.Type == FrameData || f.Type == FrameHeader {
				payload = f.Payload
			}
			select {
			case ch <- payload:
			case <-c.closed:
				return
			}
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
//  5. close all stream channels — wakes stream consumers.
//
// As a consequence the read loop (read error on the closed connection or
// the closed channel), the writer and the keepalive all terminate, and a
// running Dispatch returns once the read loop closes the frames channel.
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

		c.mu.Lock()
		for id, ch := range c.streams {
			close(ch)
			delete(c.streams, id)
		}
		c.mu.Unlock()
	})
}

// CarrierAuth performs the symmetric FrameAuth handshake on rwc:
// the initiator (carrier client) sends FrameAuth(SHA-256 secret) and waits
// for FramePong [0]; the responder (carrier server) validates the secret in
// constant time and replies FrameAuth (echo) + FramePong [0].
// The returned bufio.Reader holds any bytes already buffered from rwc —
// pass it to the new CarrierConn via SetReadBuffer.
func CarrierAuth(ctx context.Context, rwc io.ReadWriteCloser, isClient bool, secret []byte) (*bufio.Reader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ds, hasDeadline := rwc.(interface {
		SetDeadline(time.Time) error
	})
	resetDeadline := func() {
		if hasDeadline {
			_ = ds.SetDeadline(time.Time{})
		}
	}
	if isClient {
		if err := WriteFrame(rwc, 0, FrameAuth, secret); err != nil {
			return nil, err
		}
	}
	if hasDeadline {
		if d, ok := ctx.Deadline(); ok {
			_ = ds.SetDeadline(d)
		}
	}
	br := bufio.NewReader(rwc)
	for {
		f, err := ReadFrame(br)
		if err != nil {
			resetDeadline()
			return nil, err
		}
		switch f.Type {
		case FrameAuth:
			if !isClient {
				if len(f.Payload) != 32 || !ValidateSecret(f.Payload, secret) {
					resetDeadline()
					return nil, errors.New("mux: auth secret mismatch")
				}
				if err := WriteFrame(rwc, 0, FrameAuth, secret); err != nil {
					resetDeadline()
					return nil, err
				}
				if err := WriteFrame(rwc, 0, FramePong, []byte{0}); err != nil {
					resetDeadline()
					return nil, err
				}
				resetDeadline()
				return br, nil
			}
			// client: server echo, keep waiting for FramePong
		case FramePong:
			if len(f.Payload) == 1 && f.Payload[0] == 0 {
				resetDeadline()
				return br, nil
			}
			resetDeadline()
			return nil, errors.New("mux: bad auth pong")
		default:
			resetDeadline()
			return nil, errors.New("mux: unexpected frame during auth")
		}
	}
}
