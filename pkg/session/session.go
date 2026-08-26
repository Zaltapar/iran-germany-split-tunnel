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
// Session — explicit lifecycle (Phase 4)
// ============================================================
//
// Every session moves through one state machine:
//
//	Pending → Active → Closing → Closed
//	            └── per-direction half-closed flags (DirUp / DirDown)
//
//   - NewSession creates a session in Pending.
//   - Activate marks it Active (the relays may now run).
//   - MarkDirClosed half-closes ONE direction (client EOF / FrameClose);
//     the other direction keeps flowing. When both directions are closed
//     the session transitions itself into Closing.
//   - Close is the single authoritative teardown path: any goroutine may
//     call it, any number of times, in any order. Teardown (context
//     cancel, owned-conn closes, OnClose hooks) runs exactly once, and a
//     session that reached Closed can never become active again.
//
// Ownership:
//   - the Session EXCLUSIVELY owns ClientConn / TargetConn (whichever are
//     non-nil) — nothing else in the system may close them;
//   - the Session owns its context (the cancel func is internal);
//   - carrier deregistration, store unindexing and metric decrements are
//     owned by the binary, installed via OnClose, and therefore also run
//     exactly once.

// State is one stage of the session lifecycle.
type State int

const (
	// StatePending: created, relays not started yet.
	StatePending State = iota
	// StateActive: relays running; directions may be half-closed.
	StateActive
	// StateClosing: teardown started, resources being released.
	StateClosing
	// StateClosed: teardown complete; the session is dead and cannot be
	// revived.
	StateClosed
)

func (st State) String() string {
	switch st {
	case StatePending:
		return "Pending"
	case StateActive:
		return "Active"
	case StateClosing:
		return "Closing"
	case StateClosed:
		return "Closed"
	}
	return "Unknown"
}

// Direction names the two relay directions of a session.
type Direction int

const (
	// DirUp is the upload direction (client → carrier, or carrier →
	// target on the Germany side).
	DirUp Direction = iota
	// DirDown is the download direction (carrier → client, or target →
	// carrier on the Germany side).
	DirDown
)

func (d Direction) String() string {
	if d == DirUp {
		return "up"
	}
	return "down"
}

type Session struct {
	ID   SessionID
	Dest *Destination
	// ClientConn is the local client socket (SOCKS5 client on the Iran
	// side); nil on the Germany side. Owned by this session: Close is
	// the only closer.
	ClientConn net.Conn
	// TargetConn is the real destination socket (dialled on the Germany
	// side); nil on the Iran side. Owned by this session: Close is the
	// only closer.
	TargetConn net.Conn
	// StreamIDUp / StreamIDDown are the frame StreamIDs of this session
	// on the up-/down-carrier. Informational here — deregistration from
	// the carriers happens in the binary's OnClose hooks.
	StreamIDUp   uint32
	StreamIDDown uint32
	// UpAtt / DownAtt (Phase 5) track the carrier binding per direction:
	// which carrier generation currently carries this direction and the
	// bounded grace window after a carrier loss. Owned and driven by the
	// binary (see pkg/node); the session only guarantees they are closed
	// during teardown and when a direction is half-closed. Nil for
	// sessions/tests without carrier management.
	UpAtt   *Attachment
	DownAtt *Attachment
	// Ctx is cancelled by Close; relays select on it to unblock.
	Ctx context.Context

	cancel     context.CancelFunc
	mu         sync.Mutex
	state      State
	upClosed   bool
	downClosed bool
	reason     string
	once       sync.Once
	done       chan struct{}
	onClose    []func()
}

// NewSession creates a session in StatePending. The session owns its
// connections: Close (and only Close) closes them.
func NewSession(id SessionID, dest *Destination, clientConn, targetConn net.Conn, parent context.Context) *Session {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &Session{
		ID:         id,
		Dest:       dest,
		ClientConn: clientConn,
		TargetConn: targetConn,
		Ctx:        ctx,
		cancel:     cancel,
		state:      StatePending,
		done:       make(chan struct{}),
	}
}

// Activate moves Pending → Active. It returns false for any other state
// (invalid transition) — a session that started closing can never
// become active again.
func (s *Session) Activate() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StatePending {
		return false
	}
	s.state = StateActive
	return true
}

// State returns the current lifecycle state.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// IsClosed reports whether teardown has completed.
func (s *Session) IsClosed() bool { return s.State() == StateClosed }

// Reason returns the first close reason recorded ("" while open).
func (s *Session) Reason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

// Done is closed once teardown has fully completed (context cancelled,
// connections closed, all OnClose hooks run).
func (s *Session) Done() <-chan struct{} { return s.done }

// DirClosed reports whether one direction has been half-closed.
func (s *Session) DirClosed(dir Direction) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir == DirUp {
		return s.upClosed
	}
	return s.downClosed
}

// Att returns the carrier attachment for one direction (nil if the
// session has no attachment for it — tests and legacy wiring).
func (s *Session) Att(dir Direction) *Attachment {
	if dir == DirUp {
		return s.UpAtt
	}
	return s.DownAtt
}

// OnClose registers a teardown hook (carrier deregistration, store
// unindex, metric decrement, ...). Hooks run exactly once, in
// registration order, after the owned connections are closed. A hook
// registered after teardown has already started runs immediately.
// Hooks must not block.
func (s *Session) OnClose(fn func()) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	switch s.state {
	case StatePending, StateActive:
		s.onClose = append(s.onClose, fn)
	default:
		s.mu.Unlock()
		fn()
		return
	}
	s.mu.Unlock()
}

// MarkDirClosed half-closes one direction (client EOF / FrameClose).
// The OTHER direction keeps flowing. When this call completes BOTH
// directions the session transitions to Closing and teardown runs
// synchronously in the caller. It returns true only if this call
// completed the session. From Pending/Closing/Closed the call is an
// invalid transition: a no-op returning false. Marking the same
// direction twice is a no-op returning false.
func (s *Session) MarkDirClosed(dir Direction, reason string) bool {
	s.mu.Lock()
	switch s.state {
	case StateClosed, StateClosing:
		s.mu.Unlock()
		return false
	case StatePending:
		// half-closing before the relays ever started is invalid.
		s.mu.Unlock()
		return false
	}
	if dir == DirUp {
		if s.upClosed {
			s.mu.Unlock()
			return false
		}
		s.upClosed = true
	} else {
		if s.downClosed {
			s.mu.Unlock()
			return false
		}
		s.downClosed = true
	}
	if s.reason == "" {
		s.reason = reason
	}
	complete := s.upClosed && s.downClosed
	if complete {
		s.state = StateClosing
	}
	s.mu.Unlock()
	// Phase 5: a half-closed direction is permanently done — close its
	// attachment so a carrier reconnect can never re-bind it (this is
	// what keeps a client FIN a half-close, not a full close, across a
	// carrier loss).
	if att := s.Att(dir); att != nil {
		att.Close()
	}
	if complete {
		s.teardown()
	}
	return complete
}

// Close is the single authoritative teardown path for the session. It
// may be called concurrently from any goroutine, repeatedly, with
// different reasons: teardown runs exactly once (the first reason
// wins) and a Closed session can never be revived.
func (s *Session) Close(reason string) {
	s.mu.Lock()
	switch s.state {
	case StateClosed, StateClosing:
		s.mu.Unlock()
		return
	}
	s.state = StateClosing
	if s.reason == "" {
		s.reason = reason
	}
	s.mu.Unlock()
	s.teardown()
}

// teardown releases the resources exactly once. It is only reached
// after state became StateClosing (published via the mutex), so no
// concurrent Close/MarkDirClosed/OnClose caller can still append hooks
// or change state while it runs.
func (s *Session) teardown() {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.ClientConn != nil {
			s.ClientConn.Close()
		}
		if s.TargetConn != nil {
			s.TargetConn.Close()
		}
		// Phase 5: cancel any running carrier-loss grace timers BEFORE the
		// hooks run, so a pending timer cannot race the deregistration.
		if s.UpAtt != nil {
			s.UpAtt.Close()
		}
		if s.DownAtt != nil {
			s.DownAtt.Close()
		}
		for _, fn := range s.onClose {
			fn()
		}
		s.mu.Lock()
		s.state = StateClosed
		s.mu.Unlock()
		if s.done != nil {
			close(s.done)
		}
	})
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

// Add registers a session by ID. If the session has already started
// closing (checked under the store lock so the check and the insert
// are atomic with respect to Remove), it is NOT indexed — its teardown
// already unindexed it and a late insert would leak.
func (ss *SessionStore) Add(id SessionID, s *Session) {
	ss.mu.Lock()
	if s.State() == StateClosing || s.State() == StateClosed {
		ss.mu.Unlock()
		return
	}
	ss.sessions[id] = s
	ss.mu.Unlock()
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

// Remove unindexes a session (by ID and by stream IDs). It has NO
// side effects on the session itself: closing the connections and
// cancelling the context belong to Session.Close (Phase 4 ownership).
// Idempotent.
func (ss *SessionStore) Remove(id SessionID) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[id]
	if ok {
		ss.removeStreamsLocked(s)
		delete(ss.sessions, id)
	}
}

// AddStream indexes a session under its up- and/or down-carrier
// StreamIDs so the carrier demuxers can resolve StreamID → *Session.
// Like Add, a session that already started closing is NOT indexed
// (checked under the store lock, atomic with RemoveStream/Remove).
func (ss *SessionStore) AddStream(s *Session) {
	ss.mu.Lock()
	if s.State() == StateClosing || s.State() == StateClosed {
		ss.mu.Unlock()
		return
	}
	if s.StreamIDUp != 0 {
		ss.streams[s.StreamIDUp] = s
	}
	if s.StreamIDDown != 0 {
		ss.streams[s.StreamIDDown] = s
	}
	ss.mu.Unlock()
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

// CloseAll closes every registered session through its authoritative
// Close path (Phase 4): each session cancels its context, closes its
// owned connections and runs its OnClose hooks (deregister, unindex,
// metric decrement), which empties the store. Sessions are closed
// outside the store lock so hooks may freely call back into it.
func (ss *SessionStore) CloseAll() {
	ss.mu.RLock()
	sessions := make([]*Session, 0, len(ss.sessions))
	for _, s := range ss.sessions {
		sessions = append(sessions, s)
	}
	ss.mu.RUnlock()
	for _, s := range sessions {
		s.Close("store: close all")
	}
}

// Snapshot returns a point-in-time list of all sessions in the store.
// Used by the carrier-loss/rebind sweep (Phase 5): iterating a snapshot
// keeps the store lock out of the (potentially slow) rebind path, and
// entries may close between snapshot and use — every consumer re-validates
// session state before acting.
func (ss *SessionStore) Snapshot() []*Session {
	ss.mu.RLock()
	sessions := make([]*Session, 0, len(ss.sessions))
	for _, s := range ss.sessions {
		sessions = append(sessions, s)
	}
	ss.mu.RUnlock()
	return sessions
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
