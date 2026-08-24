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

	mu      sync.Mutex
	streams map[uint32]chan []byte
	closing bool

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
		rwc:      rwc,
		frames:   make(chan Frame, 256),
		writeCh:  make(chan writeReq, 256),
		readDone: make(chan struct{}),
		closed:   make(chan struct{}),
		streams:  make(map[uint32]chan []byte),
	}
	go c.writeLoop()
	go c.readLoop()
	if pingInterval > 0 {
		go c.keepalive(pingInterval)
	}
	return c
}

func (c *CarrierConn) readLoop() {
	defer close(c.readDone)
	defer close(c.frames)
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

// writeLoop serializes every write through a single goroutine.
func (c *CarrierConn) writeLoop() {
	for req := range c.writeCh {
		_, err := c.rwc.Write(req.data)
		req.done <- err
	}
}

// write is the serialized write primitive: it enqueues the raw encoded
// frame and waits for the writer goroutine to complete it.
func (c *CarrierConn) write(data []byte) error {
	req := writeReq{data: data, done: make(chan error, 1)}
	select {
	case c.writeCh <- req:
	case <-c.closed:
		return errors.New("mux: carrier closed")
	}
	return <-req.done
}

// WriteFrame encodes and sends one frame. Serialized via writeCh.
func (c *CarrierConn) WriteFrame(streamID uint32, typ uint8, payload []byte) error {
	if len(payload) > MaxPayload {
		return errors.New("mux: frame payload too large")
	}
	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], streamID)
	buf[4] = typ
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(payload)))
	copy(buf[HeaderSize:], payload)
	return c.write(buf)
}

func (c *CarrierConn) keepalive(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	ping := make([]byte, HeaderSize) // StreamID 0, FramePing, Length 0
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

// Close shuts the carrier down: it closes the underlying connection and
// every registered stream channel so blocked handlers unblock and clean up.
// Idempotent. Call it AFTER the dispatcher goroutine has returned, so the
// read loop has already stopped consuming the connection.
func (c *CarrierConn) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.mu.Lock()
		c.closing = true
		for id, ch := range c.streams {
			close(ch)
			delete(c.streams, id)
		}
		c.mu.Unlock()
		_ = c.rwc.Close()
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
