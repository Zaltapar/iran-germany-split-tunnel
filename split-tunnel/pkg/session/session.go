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

const (
	AddrTypeIPv4   = 1
	AddrTypeDomain = 3
	AddrTypeIPv6   = 4
)

const SessionIDLen = 16
const MaxHeaderSize = 1 + 255 + 2

type SessionID [SessionIDLen]byte

func (s SessionID) String() string {
	h := make([]byte, SessionIDLen*2)
	hex.Encode(h, s[:])
	return string(h)
}

type Destination struct {
	AddrType byte
	Addr     string
	Port     uint16
}

func ReadDestination(r io.Reader) (*Destination, error) {
	addrType := make([]byte, 1)
	if _, err := io.ReadFull(r, addrType); err != nil {
		return nil, err
	}
	return readDestFromReader(r, addrType[0])
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

type Session struct {
	ID           SessionID
	Dest         *Destination
	UpStreamID   uint32
	DownStreamID uint32
	ClientConn   net.Conn
	Ctx          context.Context
	cancel       context.CancelFunc
}

func (s *Session) Cancel() {
	if s.cancel != nil {
		s.cancel()
	}
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[SessionID]*Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[SessionID]*Session)}
}

func (ss *SessionStore) Add(id SessionID, s *Session) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[id] = s
}

func (ss *SessionStore) Get(id SessionID) (*Session, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.sessions[id], true
}

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

func (ss *SessionStore) ForEachSession(fn func(id SessionID, s *Session)) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	for id, s := range ss.sessions {
		fn(id, s)
	}
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

func GenerateSessionID() ([]byte, error) {
	buf := make([]byte, SessionIDLen)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
