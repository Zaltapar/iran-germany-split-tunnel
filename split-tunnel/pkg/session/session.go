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

// Address types (compatible with SOCKS5 and Trojan headers)
const (
	AddrTypeIPv4   = 1
	AddrTypeDomain = 3
	AddrTypeIPv6   = 4
)

// MaxSessionIDLen is the size of session ID in bytes
const SessionIDLen = 16

// MaxHeaderSize is the maximum size of a destination header
const MaxHeaderSize = 1 + 255 + 2 // type + max domain + port

// SessionID is a unique identifier for each split session
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
// Format: addr_type (1) + addr + port (2)
func ReadDestination(r io.Reader) (*Destination, error) {
	addrType := make([]byte, 1)
	if _, err := io.ReadFull(r, addrType); err != nil {
		return nil, err
	}

	dest := &Destination{AddrType: addrType[0]}

	switch addrType[0] {
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
			return nil, errors.New("domain name too long")
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
		return nil, errors.New("unknown address type: " + string(addrType[0]))
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
		if ip == nil {
			return errors.New("invalid IPv4 address")
		}
		if ip.To4() == nil {
			return errors.New("not an IPv4 address")
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
		if ip == nil {
			return errors.New("invalid IPv6 address")
		}
		if ip.To4() != nil {
			return errors.New("not an IPv6 address")
		}
		if _, err := w.Write(ip.To16()); err != nil {
			return err
		}

	default:
		return errors.New("unknown address type")
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, dest.Port)
	if _, err := w.Write(portBuf); err != nil {
		return err
	}

	return nil
}

// Session represents a split-tunnel session
type Session struct {
	ID        SessionID
	Dest      *Destination
	UpConn    net.Conn // connection from up-leg (Germany)
	DownConn  net.Conn // connection from down-leg (Germany)
	DeadConn  net.Conn // actual destination connection
	Ctx       context.Context
	cancel    context.CancelFunc
	CreatedAt time.Time
}

// NewSession creates a new session with context
func NewSession(id SessionID, dest *Destination) (*Session, context.Context) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		ID:        id,
		Dest:      dest,
		CreatedAt: time.Now(),
		Ctx:       ctx,
		cancel:    cancel,
	}, ctx
}

// Cancel cancels the session context
func (s *Session) Cancel() {
	s.cancel()
}

// SessionStore thread-safe map of active sessions
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
func (ss *SessionStore) Add(id SessionID, session *Session) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[id] = session
}

// Get retrieves a session by ID
func (ss *SessionStore) Get(id SessionID) (*Session, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	session, ok := ss.sessions[id]
	return session, ok
}

// Remove removes a session from the store
func (ss *SessionStore) Remove(id SessionID) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.sessions, id)
}

// CloseAll closes all active sessions' destination connections
func (ss *SessionStore) CloseAll() {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	for _, session := range ss.sessions {
		if session.DeadConn != nil {
			session.DeadConn.Close()
		}
	}
}

// Count returns the number of active sessions
func (ss *SessionStore) Count() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return len(ss.sessions)
}

// Wait waits for a session to become available with timeout
func (ss *SessionStore) Wait(id SessionID, timeoutMs int) (*Session, bool) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ss.mu.RLock()
		session, ok := ss.sessions[id]
		ss.mu.RUnlock()
		if ok {
			return session, true
		}
		// Brief sleep before retrying
		time.Sleep(10 * time.Millisecond)
	}
	return nil, false
}

// ReadyFlag tracks ready status per session
type ReadyFlag struct {
	mu    sync.Mutex
	ready bool
	cond  *sync.Cond
}

// NewReadyFlag creates a new ready flag
func NewReadyFlag() *ReadyFlag {
	rf := &ReadyFlag{}
	rf.cond = sync.NewCond(&rf.mu)
	return rf
}

// SignalReady marks the session as ready
func (rf *ReadyFlag) SignalReady() {
	rf.cond.L.Lock()
	defer rf.cond.L.Unlock()
	rf.ready = true
	rf.cond.Broadcast()
}

// WaitForReady waits until ready or timeout
func (rf *ReadyFlag) WaitForReady(timeoutMs int) bool {
	done := make(chan struct{})
	go func() {
		time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
		close(done)
	}()

	rf.cond.L.Lock()
	defer rf.cond.L.Unlock()
	for !rf.ready {
		select {
		case <-done:
			return false
		default:
			rf.cond.Wait()
		}
	}
	return true
}

// GenerateSessionID creates a new random session ID
func GenerateSessionID() (SessionID, error) {
	var sid SessionID
	if _, err := io.ReadFull(rand.Reader, sid[:]); err != nil {
		return sid, err
	}
	return sid, nil
}
