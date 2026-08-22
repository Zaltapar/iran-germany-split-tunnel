package mux

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"crypto/sha256"
	"crypto/subtle"
)

// Frame types
const (
	FrameData  = 0x00
	FrameAuth  = 0x01
	FramePing  = 0x02
	FramePong  = 0x03
	FrameClose = 0x04
)

const MaxPayloadSize = 65535

// FrameHeader is the 7-byte multiplexed frame header:
// StreamID (4 bytes BE) + Type (1 byte) + Length (2 bytes BE)
type FrameHeader struct {
	StreamID uint32
	Type     byte
	Length   uint16
}

// Frame is a complete multiplexed frame
type Frame struct {
	Header   *FrameHeader
	Payload  []byte
	Type     byte   // alias for convenience
	StreamID uint32 // alias for convenience
}

// Stream represents a multiplexed virtual connection
type Stream struct {
	ID      uint32
	mu      sync.Mutex
	writeCh chan []byte
	closed  bool
}

// Transport is the abstract transport layer for carriers.
// It wraps any io.ReadWriteCloser (websocket.Conn, net.Conn, etc.)
// and provides a serialized frame writer.
type Transport struct {
	reader  io.Reader
	writer  io.Writer
	closer  io.Closer
	writeCh chan *Frame
	done    chan struct{}
	closeMu sync.Mutex
	closed  bool
}

// NewTransport wraps an io.ReadWriteCloser and starts the serialized writer goroutine.
func NewTransport(rw io.ReadWriteCloser) *Transport {
	t := &Transport{
		reader:  rw,
		writer:  rw,
		closer:  rw,
		writeCh: make(chan *Frame, 512),
		done:    make(chan struct{}),
	}
	go t.writerLoop()
	return t
}

// NewTransportFromReaderWriterCloser creates a transport from separate io interfaces
func NewTransportFromReaderWriterCloser(r io.Reader, w io.Writer, c io.Closer) *Transport {
	t := &Transport{
		reader:  r,
		writer:  w,
		closer:  c,
		writeCh: make(chan *Frame, 512),
		done:    make(chan struct{}),
	}
	go t.writerLoop()
	return t
}

// writerLoop reads from writeCh and serializes all writes to the underlying writer.
func (t *Transport) writerLoop() {
	defer close(t.done)
	for f := range t.writeCh {
		if t.closed {
			break
		}
		WriteFrame(t.writer, f)
	}
}

// SendQueue pushes a frame onto the write queue (non-blocking).
func (t *Transport) SendQueue(f *Frame) error {
	t.closeMu.Lock()
	if t.closed {
		t.closeMu.Unlock()
		return errors.New("transport closed")
	}
	t.closeMu.Unlock()
	select {
	case t.writeCh <- f:
		return nil
	default:
		return errors.New("write queue full")
	}
}

// Send sends a frame synchronously (blocks until written).
func (t *Transport) Send(f *Frame) error {
	t.closeMu.Lock()
	if t.closed {
		t.closeMu.Unlock()
		return errors.New("transport closed")
	}
	t.closeMu.Unlock()
	return WriteFrame(t.writer, f)
}

// Read delegates to the underlying reader.
func (t *Transport) Read(b []byte) (n int, err error) {
	return t.reader.Read(b)
}

// Close shuts down the transport and stops the writer goroutine.
func (t *Transport) Close() error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.closer != nil {
		return t.closer.Close()
	}
	return nil
}

// IsClosed returns whether the transport is closed.
func (t *Transport) IsClosed() bool {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	return t.closed
}

// Writer returns the io.Writer for direct writes.
func (t *Transport) Writer() io.Writer {
	return t.writer
}

// Carrier manages the persistent multiplexed connection
type Carrier struct {
	mu           sync.RWMutex
	streams      map[uint32]*Stream
	nextStreamID uint32
	secret       []byte
	connected    atomic.Bool
}

// NewCarrier creates a new multiplexed carrier
func NewCarrier(secret []byte) *Carrier {
	c := &Carrier{
		streams: make(map[uint32]*Stream),
		secret:  secret,
	}
	c.connected.Store(false)
	return c
}

// OpenStream creates a new stream and registers it, returns a unique stream ID.
// Uses a prefix from carrierRole (0=up, 1=down) to prevent collisions.
func (c *Carrier) OpenStream(role byte) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextStreamID
	c.nextStreamID++
	// Encode role in upper 8 bits to prevent collisions
	encodedID := (uint32(role) << 24) | (id & 0x00FFFFFF)
	s := &Stream{
		ID:      encodedID,
		writeCh: make(chan []byte, 1024),
	}
	c.streams[encodedID] = s
	return s
}

// GetStream retrieves a stream by ID
func (c *Carrier) GetStream(id uint32) (*Stream, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.streams[id]
	return s, ok
}

// RemoveStream removes a stream
func (c *Carrier) RemoveStream(id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.streams, id)
}

// StreamCount returns active stream count
func (c *Carrier) StreamCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.streams)
}

// IsConnected returns connection state
func (c *Carrier) IsConnected() bool {
	return c.connected.Load()
}

// SetConnected sets connection state
func (c *Carrier) SetConnected(v bool) {
	c.connected.Store(v)
}

// Secret returns the carrier secret
func (c *Carrier) Secret() []byte {
	return c.secret
}

// DeriveSecret derives a 32-byte binary secret from a string using SHA256
func DeriveSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// SecretFromHex derives a 32-byte binary secret from a hex-encoded string
func SecretFromHex(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

// Frame constructors
func NewAuthFrame(secret []byte) *Frame {
	return &Frame{
		Header:  &FrameHeader{StreamID: 0, Type: FrameAuth, Length: uint16(len(secret))},
		Payload: secret,
		Type:    FrameAuth,
	}
}

func NewPingFrame() *Frame {
	return &Frame{Header: &FrameHeader{StreamID: 0, Type: FramePing, Length: 0}, Type: FramePing}
}

func NewPongFrame() *Frame {
	return &Frame{Header: &FrameHeader{StreamID: 0, Type: FramePong, Length: 0}, Type: FramePong}
}

func NewDataFrame(streamID uint32, data []byte) *Frame {
	return &Frame{
		Header:  &FrameHeader{StreamID: streamID, Type: FrameData, Length: uint16(len(data))},
		Payload: data,
		Type:    FrameData,
	}
}

func NewCloseFrame(streamID uint32) *Frame {
	return &Frame{Header: &FrameHeader{StreamID: streamID, Type: FrameClose, Length: 0}, Type: FrameClose}
}

// ReadFrame reads a complete frame from reader
func ReadFrame(r io.Reader) (*Frame, error) {
	buf4 := make([]byte, 4)
	if _, err := io.ReadFull(r, buf4); err != nil {
		return nil, err
	}
	streamID := binary.BigEndian.Uint32(buf4)

	buf1 := make([]byte, 1)
	if _, err := io.ReadFull(r, buf1); err != nil {
		return nil, err
	}
	frameType := buf1[0]

	buf2 := make([]byte, 2)
	if _, err := io.ReadFull(r, buf2); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(buf2)

	if length > MaxPayloadSize {
		return nil, errors.New("payload too large")
	}

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}

	return &Frame{
		Header:   &FrameHeader{StreamID: streamID, Type: frameType, Length: length},
		Payload:  payload,
		Type:     frameType,
		StreamID: streamID,
	}, nil
}

// WriteFrame writes a complete frame to writer (serialized by caller)
func WriteFrame(w io.Writer, f *Frame) error {
	sidBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sidBuf, f.StreamID)
	if _, err := w.Write(sidBuf); err != nil {
		return err
	}
	if _, err := w.Write([]byte{f.Type}); err != nil {
		return err
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, f.Header.Length)
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	if f.Payload != nil {
		_, err := w.Write(f.Payload)
		return err
	}
	return nil
}

// ValidateSecret verifies shared secret using constant-time comparison
func ValidateSecret(provided []byte, expected []byte) bool {
	return subtle.ConstantTimeCompare(provided, expected) == 1
}

// KeepAliveInterval is the default keepalive period
const KeepAliveInterval = 30 * time.Second

// Write sends data to a stream (enqueues payload for writer goroutine)
func (s *Stream) Write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("stream closed")
	}
	select {
	case s.writeCh <- data:
		return nil
	default:
		return errors.New("write queue full")
	}
}

// Close closes a stream
func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
