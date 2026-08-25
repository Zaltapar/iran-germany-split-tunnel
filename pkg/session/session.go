package session

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Address types (SOCKS5 / Trojan compatible)
const (
	AddrTypeIPv4   = 1
	AddrTypeDomain = 3
	AddrTypeIPv6   = 4
)

// Constants
const (
	SessionIDLen = 16
	// MaxHeaderSize is the largest possible destination header:
	// [1 atype][1 domain length][255 domain][2 port] = 259 bytes.
	// (IPv4 headers are 7 bytes, IPv6 headers are 19 bytes.)
	MaxHeaderSize = 1 + 1 + 255 + 2
)

// SessionID is a unique 16-byte identifier
type SessionID [SessionIDLen]byte

func (s SessionID) String() string {
	h := make([]byte, SessionIDLen*2)
	hex.Encode(h, s[:])
	return string(h)
}

// Destination represents the parsed destination
type Destination struct {
	AddrType byte
	Addr     string
	Port     uint16
}

func ReadDestination(r io.Reader) (*Destination, error) {
	at := make([]byte, 1)
	if _, err := io.ReadFull(r, at); err != nil {
		return nil, err
	}
	return readDestFromReader(r, at[0])
}

func ReadDestinationEx(r io.Reader, atype byte) (*Destination, error) {
	return readDestFromReader(r, atype)
}

func readDestFromReader(r io.Reader, atype byte) (*Destination, error) {
	dest := &Destination{AddrType: atype}
	switch atype {
	case AddrTypeIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return nil, err
		}
		dest.Addr = net.IP(ip).String()
	case AddrTypeDomain:
		dl := make([]byte, 1)
		if _, err := io.ReadFull(r, dl); err != nil {
			return nil, err
		}
		n := int(dl[0])
		if n > 255 {
			return nil, errors.New("domain too long")
		}
		d := make([]byte, n)
		if _, err := io.ReadFull(r, d); err != nil {
			return nil, err
		}
		dest.Addr = string(d)
	case AddrTypeIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return nil, err
		}
		dest.Addr = net.IP(ip).String()
	default:
		return nil, errors.New("unknown address type")
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	dest.Port = binary.BigEndian.Uint16(p)
	return dest, nil
}

func WriteDestination(w io.Writer, dest *Destination) error {
	if _, err := w.Write([]byte{dest.AddrType}); err != nil {
		return err
	}
	switch dest.AddrType {
	case AddrTypeIPv4:
		ip := net.ParseIP(dest.Addr)
		if ip == nil || ip.To4() == nil {
			return errors.New("invalid IPv4")
		}
		if _, err := w.Write(ip.To4()); err != nil {
			return err
		}
	case AddrTypeDomain:
		if len(dest.Addr) > 255 {
			return errors.New("domain too long")
		}
		if _, err := w.Write([]byte{byte(len(dest.Addr))}); err != nil {
			return err
		}
		if _, err := w.Write([]byte(dest.Addr)); err != nil {
			return err
		}
	case AddrTypeIPv6:
		ip := net.ParseIP(dest.Addr)
		if ip == nil || ip.To4() != nil {
			return errors.New("invalid IPv6")
		}
		if _, err := w.Write(ip.To16()); err != nil {
			return err
		}
	default:
		return errors.New("unknown address type")
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, dest.Port)
	_, err := w.Write(pb)
	return err
}

func WriteDestinationBuffer(buf []byte, dest *Destination) int {
	if len(buf) < MaxHeaderSize {
		return 0
	}
	pos := 0
	buf[pos] = dest.AddrType
	pos++
	switch dest.AddrType {
	case AddrTypeIPv4:
		ip := net.ParseIP(dest.Addr)
		if ip == nil || ip.To4() == nil {
			return 0
		}
		copy(buf[pos:pos+4], ip.To4())
		pos += 4
	case AddrTypeDomain:
		l := len(dest.Addr)
		if l > 255 {
			l = 255
		}
		buf[pos] = byte(l)
		pos++
		copy(buf[pos:pos+l], []byte(dest.Addr)[:l])
		pos += l
	case AddrTypeIPv6:
		ip := net.ParseIP(dest.Addr)
		if ip == nil || ip.To4() != nil {
			return 0
		}
		copy(buf[pos:pos+16], ip.To16())
		pos += 16
	default:
		return 0
	}
	buf[pos] = byte(dest.Port >> 8)
	buf[pos+1] = byte(dest.Port)
	pos += 2
	return pos
}

func ParseDestinationFromBuf(buf []byte) *Destination {
	if len(buf) < 4 {
		return nil
	}
	dest := &Destination{AddrType: buf[0]}
	pos := 1
	switch dest.AddrType {
	case AddrTypeIPv4:
		if len(buf) < pos+4+2 {
			return nil
		}
		dest.Addr = net.IP(buf[pos : pos+4]).String()
		pos += 4
	case AddrTypeDomain:
		if len(buf) < pos+1+2 {
			return nil
		}
		n := int(buf[pos])
		pos++
		if len(buf) < pos+n+2 {
			return nil
		}
		dest.Addr = string(buf[pos : pos+n])
		pos += n
	case AddrTypeIPv6:
		if len(buf) < pos+16+2 {
			return nil
		}
		dest.Addr = net.IP(buf[pos : pos+16]).String()
		pos += 16
	default:
		return nil
	}
	if len(buf) < pos+2 {
		return nil
	}
	dest.Port = uint16(buf[pos])<<8 | uint16(buf[pos+1])
	return dest
}

// ============================================================
// Session holds yamux stream references
// ============================================================

type Session struct {
	ID         SessionID
	Dest       *Destination
	ClientConn net.Conn
	// StreamIDUp is the frame StreamID of this session on the up-carrier
	// (client upload bytes Iran→Germany); StreamIDDown is its StreamID on
	// the down-carrier (download bytes Germany→Iran).
	StreamIDUp   uint32
	StreamIDDown uint32
	Ctx          context.Context
	Cancel       context.CancelFunc
}

func (s *Session) cancelCtx() {
	if s.Cancel != nil {
		s.Cancel()
	}
}

// ============================================================
// SessionStore — keyed by SessionID
// ============================================================

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[SessionID]*Session
	streams  map[uint32]*Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[SessionID]*Session),
		streams:  make(map[uint32]*Session),
	}
}

func (ss *SessionStore) Add(id SessionID, s *Session) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[id] = s
}

func (ss *SessionStore) Get(id SessionID) (*Session, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	s, ok := ss.sessions[id]
	return s, ok
}

func (ss *SessionStore) GetSession(id SessionID) (*Session, bool) {
	return ss.Get(id)
}

func (ss *SessionStore) Remove(id SessionID) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[id]
	if ok {
		if s.ClientConn != nil {
			s.ClientConn.Close()
		}
		if s.Cancel != nil {
			s.Cancel()
		}
		ss.removeStreamsLocked(s)
		delete(ss.sessions, id)
	}
}

// AddStream indexes a session under its up- and/or down-carrier StreamIDs
// so the carrier demuxers can resolve StreamID → *Session.
func (ss *SessionStore) AddStream(s *Session) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if s.StreamIDUp != 0 {
		ss.streams[s.StreamIDUp] = s
	}
	if s.StreamIDDown != 0 {
		ss.streams[s.StreamIDDown] = s
	}
}

// GetByStream resolves a session by its carrier StreamID.
func (ss *SessionStore) GetByStream(streamID uint32) (*Session, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	s, ok := ss.streams[streamID]
	return s, ok
}

// RemoveStream unindexes a session's StreamIDs (without closing anything).
func (ss *SessionStore) RemoveStream(s *Session) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.removeStreamsLocked(s)
}

func (ss *SessionStore) removeStreamsLocked(s *Session) {
	if s.StreamIDUp != 0 {
		delete(ss.streams, s.StreamIDUp)
	}
	if s.StreamIDDown != 0 {
		delete(ss.streams, s.StreamIDDown)
	}
}

func (ss *SessionStore) CloseAll() {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	for _, s := range ss.sessions {
		if s.ClientConn != nil {
			s.ClientConn.Close()
		}
	}
}

func (ss *SessionStore) Count() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return len(ss.sessions)
}

func (ss *SessionStore) Wait(id SessionID, timeoutMs int) (*Session, bool) {
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	for time.Now().Before(deadline) {
		ss.mu.RLock()
		s, ok := ss.sessions[id]
		ss.mu.RUnlock()
		if ok {
			return s, true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, false
}

// GenerateSessionID creates a random 16-byte session ID
func GenerateSessionID() ([]byte, error) {
	buf := make([]byte, SessionIDLen)
	_, err := io.ReadFull(rand.Reader, buf)
	return buf, err
}
