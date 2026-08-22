package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/split-tunnel/pkg/mux"
)

// Transport is an alias to mux.Transport for session references
type Transport = mux.Transport

// Address types (compatible with SOCKS5 and Trojan headers)
const (
	AddrTypeIPv4   = 1
	AddrTypeDomain = 3
	AddrTypeIPv6   = 4
)

// Constants
const (
	SessionIDLen  = 16
	MaxHeaderSize = 1 + 255 + 2
)

// SessionID is a unique 16-byte identifier for each split-tunnel session
type SessionID [SessionIDLen]byte

// String returns the session ID as a hex string
func (s SessionID) String() string {
	h := make([]byte, SessionIDLen*2)
	hex.Encode(h, s[:])
	return string(h)
}

// Destination represents the destination address parsed from the header
type Destination struct {
	AddrType byte
	Addr     string
	Port     uint16
}

// ReadDestination reads a destination address from the reader
func ReadDestination(r io.Reader) (*Destination, error) {
	addrType := make([]byte, 1)
	if _, err := io.ReadFull(r, addrType); err != nil {
		return nil, err
	}
	return readDestFromReader(r, addrType[0])
}

// ReadDestinationEx reads a destination from a raw SOCKS5 address type byte
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
		domainLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, domainLenBuf); err != nil {
			return nil, err
		}
		domainLen := int(domainLenBuf[0])
		if domainLen > 255 {
			return nil, errors.New("domain too long")
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, err
		}
		dest.Addr = string(domain)
	case AddrTypeIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return nil, err
		}
		dest.Addr = net.IP(ip).String()
	default:
		return nil, errors.New("unknown address type")
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, err
	}
	dest.Port = binary.BigEndian.Uint16(port)
	return dest, nil
}

// WriteDestination writes a destination address to the writer
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
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, dest.Port)
	_, err := w.Write(portBuf)
	return err
}

// WriteDestinationBuffer writes a destination address into a pre-allocated buffer
// and returns the number of bytes written. Returns 0 on error.
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
		if len(dest.Addr) > 255 {
			return 0
		}
		buf[pos] = byte(len(dest.Addr))
		pos++
		copy(buf[pos:pos+len(dest.Addr)], []byte(dest.Addr))
		pos += len(dest.Addr)
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

// ParseDestinationFromBuf manually parses a destination from a byte buffer
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
		domainLen := int(buf[pos])
		pos++
		if len(buf) < pos+domainLen+2 {
			return nil
		}
		dest.Addr = string(buf[pos : pos+domainLen])
		pos += domainLen
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

// Session represents an active split-tunnel session.
// The 16-byte SessionID is the primary router key - both splitters
// match sessions by this ID, not by stream IDs.
type Session struct {
	// Identity
	ID   SessionID
	Dest *Destination

	// Transport
	ClientConn net.Conn // Xray → iran-splitter connection

	// Per-carrier transport references (for relay goroutines)
	UpTransport   *Transport // pointer to up-carrier transport
	DownTransport *Transport // pointer to down-carrier transport

	// Context
	Ctx    context.Context
	cancel context.CancelFunc
}

// Cancel cancels the session
func (s *Session) Cancel() {
	if s.cancel != nil {
		s.cancel()
	}
}

// SessionStore is a thread-safe map of active sessions keyed by 16-byte SessionID
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[SessionID]*Session
}

// NewSessionStore creates a new session store
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[SessionID]*Session),
	}
}

// Add adds a session to the store
func (ss *SessionStore) Add(id SessionID, s *Session) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[id] = s
}

// Get retrieves a session by ID
func (ss *SessionStore) Get(id SessionID) (*Session, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	s, ok := ss.sessions[id]
	return s, ok
}

// Remove removes a session from the store
func (ss *SessionStore) Remove(id SessionID) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[id]
	if ok {
		if s.ClientConn != nil {
			s.ClientConn.Close()
		}
		if s.cancel != nil {
			s.cancel()
		}
		delete(ss.sessions, id)
	}
}

// CloseAll closes all client connections
func (ss *SessionStore) CloseAll() {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	for _, s := range ss.sessions {
		if s.ClientConn != nil {
			s.ClientConn.Close()
		}
	}
}

// Count returns the number of active sessions
func (ss *SessionStore) Count() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return len(ss.sessions)
}

// ForEachSession calls fn for each session. Safe for concurrent use.
func (ss *SessionStore) ForEachSession(fn func(id SessionID, s *Session)) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	for id, s := range ss.sessions {
		fn(id, s)
	}
}

// GetSession retrieves a session by ID (thread-safe).
func (ss *SessionStore) GetSession(id SessionID) (*Session, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	s, ok := ss.sessions[id]
	return s, ok
}

// SetTransport stores up/down transport references for a session.
func (ss *SessionStore) SetTransport(id SessionID, up *Transport, down *Transport) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if s, ok := ss.sessions[id]; ok {
		s.UpTransport = up
		s.DownTransport = down
	}
}

// Wait waits for a session to become available with timeout
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

// GenerateSessionID creates a new random 16-byte session ID
func GenerateSessionID() ([]byte, error) {
	buf := make([]byte, SessionIDLen)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Ensure bytes package is imported
var _ = bytes.NewReader
