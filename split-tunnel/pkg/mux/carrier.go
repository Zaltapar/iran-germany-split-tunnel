package mux

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
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
	Type     byte
	StreamID uint32
}

// Stream represents a multiplexed virtual connection
type Stream struct {
	ID      uint32
	mu      sync.Mutex
	writeCh chan []byte
	closed  bool
}

// Carrier manages the persistent multiplexed connection
type Carrier struct {
	mu           sync.RWMutex
	streams      map[uint32]*Stream
	nextStreamID uint32
	secret       []byte
	connected    atomic.Bool
	writeMu      sync.Mutex
}

// NewCarrier creates a new carrier
func NewCarrier(secret []byte) *Carrier {
	c := &Carrier{
		streams: make(map[uint32]*Stream),
		secret:  secret,
	}
	c.connected.Store(false)
	return c
}

// OpenStream creates a new virtual stream
func (c *Carrier) OpenStream() *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextStreamID
	c.nextStreamID++
	s := &Stream{ID: id, writeCh: make(chan []byte, 1024)}
	c.streams[id] = s
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

// Frame constructors
func NewAuthFrame(secret []byte) *Frame {
	return &Frame{
		Header:   &FrameHeader{StreamID: 0, Type: FrameAuth, Length: uint16(len(secret))},
		Payload:  secret,
		Type:     FrameAuth,
		StreamID: 0,
	}
}

func NewPingFrame() *Frame {
	return &Frame{
		Header:   &FrameHeader{StreamID: 0, Type: FramePing, Length: 0},
		Type:     FramePing,
		StreamID: 0,
	}
}

func NewPongFrame() *Frame {
	return &Frame{
		Header:   &FrameHeader{StreamID: 0, Type: FramePong, Length: 0},
		Type:     FramePong,
		StreamID: 0,
	}
}

func NewDataFrame(streamID uint32, data []byte) *Frame {
	return &Frame{
		Header:   &FrameHeader{StreamID: streamID, Type: FrameData, Length: uint16(len(data))},
		Payload:  data,
		Type:     FrameData,
		StreamID: streamID,
	}
}

func NewCloseFrame(streamID uint32) *Frame {
	return &Frame{
		Header:   &FrameHeader{StreamID: streamID, Type: FrameClose, Length: 0},
		Type:     FrameClose,
		StreamID: streamID,
	}
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

// WriteFrame writes a complete frame to writer
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

// ValidateSecret verifies shared secret
func ValidateSecret(provided, expected []byte) bool {
	if len(provided) != len(expected) {
		return false
	}
	for i := range expected {
		if provided[i] != expected[i] {
			return false
		}
	}
	return true
}

// KeepAliveInterval is the default keepalive period
const KeepAliveInterval = 30 * time.Second

// Write sends data to a stream
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
