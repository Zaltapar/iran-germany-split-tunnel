package mux

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"crypto/sha256"
	"crypto/subtle"
)

const (
	FrameData  = 0x00
	FrameAuth  = 0x01
	FramePing  = 0x02
	FramePong  = 0x03
	FrameClose = 0x04
)

const MaxPayloadSize = 65535

type FrameHeader struct {
	StreamID uint32
	Type     byte
	Length   uint16
}

type Frame struct {
	Header   *FrameHeader
	Payload  []byte
	Type     byte
	StreamID uint32
}

type Stream struct {
	ID      uint32
	mu      sync.Mutex
	writeCh chan []byte
	closed  bool
}

type Carrier struct {
	mu           sync.RWMutex
	streams      map[uint32]*Stream
	nextStreamID uint32
	secret       []byte
	connected    atomic.Bool
}

func NewCarrier(secret []byte) *Carrier {
	c := &Carrier{streams: make(map[uint32]*Stream), secret: secret}
	c.connected.Store(false)
	return c
}

func (c *Carrier) OpenStream() *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextStreamID
	c.nextStreamID++
	s := &Stream{ID: id, writeCh: make(chan []byte, 1024)}
	c.streams[id] = s
	return s
}

func (c *Carrier) GetStream(id uint32) (*Stream, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.streams[id], true
}

func (c *Carrier) RemoveStream(id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.streams, id)
}

func (c *Carrier) StreamCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.streams)
}

func (c *Carrier) IsConnected() bool {
	return c.connected.Load()
}

func (c *Carrier) SetConnected(v bool) {
	c.connected.Store(v)
}

func (c *Carrier) Secret() []byte {
	return c.secret
}

func DeriveSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func SecretFromHex(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

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

func ValidateSecret(provided []byte, expected []byte) bool {
	return subtle.ConstantTimeCompare(provided, expected) == 1
}

const KeepAliveInterval = 30 * time.Second

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

func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

type CarrierConn struct {
	conn    net.Conn
	carrier *Carrier
	writeCh chan *Frame
	done    chan struct{}
	closeMu sync.Mutex
	closed  bool
}

func NewCarrierConn(conn net.Conn, carrier *Carrier) *CarrierConn {
	cc := &CarrierConn{conn: conn, carrier: carrier, writeCh: make(chan *Frame, 512), done: make(chan struct{})}
	go cc.writerLoop()
	return cc
}

func (cc *CarrierConn) writerLoop() {
	defer close(cc.done)
	for f := range cc.writeCh {
		if cc.closed {
			break
		}
		WriteFrame(cc.conn, f)
	}
}

func (cc *CarrierConn) SendQueue(f *Frame) error {
	cc.closeMu.Lock()
	if cc.closed {
		cc.closeMu.Unlock()
		return errors.New("carrier closed")
	}
	cc.closeMu.Unlock()
	select {
	case cc.writeCh <- f:
		return nil
	default:
		return errors.New("write queue full")
	}
}

func (cc *CarrierConn) Send(f *Frame) error {
	cc.closeMu.Lock()
	if cc.closed {
		cc.closeMu.Unlock()
		return errors.New("carrier closed")
	}
	cc.closeMu.Unlock()
	return WriteFrame(cc.conn, f)
}

func (cc *CarrierConn) Read(b []byte) (n int, err error) {
	return cc.conn.Read(b)
}

func (cc *CarrierConn) Close() error {
	cc.closeMu.Lock()
	defer cc.closeMu.Unlock()
	if cc.closed {
		return nil
	}
	cc.closed = true
	cc.conn.Close()
	<-cc.done
	return nil
}

func (cc *CarrierConn) Conn() net.Conn {
	return cc.conn
}

func (cc *CarrierConn) IsClosed() bool {
	cc.closeMu.Lock()
	defer cc.closeMu.Unlock()
	return cc.closed
}

func (cc *CarrierConn) Write(b []byte) (n int, err error) {
	return cc.conn.Write(b)
}

func (cc *CarrierConn) OpenStream() *Stream {
	return cc.carrier.OpenStream()
}
