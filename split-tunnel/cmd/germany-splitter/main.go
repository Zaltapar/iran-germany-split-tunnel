package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/split-tunnel/pkg/session"
)

// Config holds the germany-splitter configuration
type Config struct {
	UpListen     string // Up-listen address (127.0.0.1:10901)
	DownListen   string // Down-listen address (127.0.0.1:10902)
	MetricsPort  int    // Port for metrics endpoint (0 = disabled)
	RelayBufSize int    // Relay buffer size in bytes
	WaitTimeout  int    // Wait timeout for session in ms
}

// GermanySession holds the state for a split session on Germany side
type GermanySession struct {
	SID      session.SessionID
	Dest     *session.Destination
	Relay    net.Conn // Connection to real destination
	UpConn   net.Conn // Connection from iran-splitter up-leg
	DownConn net.Conn // Connection from iran-splitter down-leg
}

// SessionStoreForGermany is a thread-safe map of active sessions on Germany side
type SessionStoreForGermany struct {
	mu         sync.RWMutex
	sessions   map[session.SessionID]*GermanySession
	readyFlags map[session.SessionID]*session.ReadyFlag
}

// NewSessionStoreForGermany creates a new session store
func NewSessionStoreForGermany() *SessionStoreForGermany {
	return &SessionStoreForGermany{
		sessions:   make(map[session.SessionID]*GermanySession),
		readyFlags: make(map[session.SessionID]*session.ReadyFlag),
	}
}

// Add adds a session to the store
func (ss *SessionStoreForGermany) Add(id session.SessionID, s *GermanySession) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[id] = s
	ss.readyFlags[id] = session.NewReadyFlag()
}

// Get retrieves a session by ID
func (ss *SessionStoreForGermany) Get(id session.SessionID) (*GermanySession, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	s, ok := ss.sessions[id]
	return s, ok
}

// Remove removes a session from the store
func (ss *SessionStoreForGermany) Remove(id session.SessionID) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.sessions, id)
	delete(ss.readyFlags, id)
}

// GetReadyFlag gets or creates a ready flag for the session
func (ss *SessionStoreForGermany) GetReadyFlag(id session.SessionID) *session.ReadyFlag {
	ss.mu.RLock()
	flag, ok := ss.readyFlags[id]
	ss.mu.RUnlock()
	if ok {
		return flag
	}
	ss.mu.Lock()
	flag = session.NewReadyFlag()
	ss.readyFlags[id] = flag
	ss.mu.Unlock()
	return flag
}

// Count returns the number of active sessions
func (ss *SessionStoreForGermany) Count() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return len(ss.sessions)
}

// CloseAll closes all active sessions' connections
func (ss *SessionStoreForGermany) CloseAll() {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	for _, s := range ss.sessions {
		if s.Relay != nil {
			s.Relay.Close()
		}
		if s.UpConn != nil {
			s.UpConn.Close()
		}
		if s.DownConn != nil {
			s.DownConn.Close()
		}
	}
}

// Metrics tracks statistics
type Metrics struct {
	mu             sync.Mutex
	activeSessions int64
	totalSessions  int64
	totalBytesUp   int64
	totalBytesDown int64
	errors         int64
}

func (m *Metrics) incSession() {
	m.mu.Lock()
	m.activeSessions++
	m.totalSessions++
	m.mu.Unlock()
}

func (m *Metrics) decSession() {
	m.mu.Lock()
	m.activeSessions--
	m.mu.Unlock()
}

func (m *Metrics) incUp(n int) {
	m.mu.Lock()
	m.totalBytesUp += int64(n)
	m.mu.Unlock()
}

func (m *Metrics) incDown(n int) {
	m.mu.Lock()
	m.totalBytesDown += int64(n)
	m.mu.Unlock()
}

func (m *Metrics) incErr() {
	m.mu.Lock()
	m.errors++
	m.mu.Unlock()
}

// Splitter is the germany-splitter daemon
type Splitter struct {
	config  *Config
	store   *SessionStoreForGermany
	metrics *Metrics
	logger  *log.Logger
}

func main() {
	cfg := &Config{
		UpListen:     "127.0.0.1:10901",
		DownListen:   "127.0.0.1:10902",
		RelayBufSize: 32768,
		WaitTimeout:  3000,
	}

	// Environment variable overrides
	if v := os.Getenv("SPLIT_UP_LISTEN"); v != "" {
		cfg.UpListen = v
	}
	if v := os.Getenv("SPLIT_DOWN_LISTEN"); v != "" {
		cfg.DownListen = v
	}
	if v := os.Getenv("SPLIT_METRICS_PORT"); v != "" {
		cfg.MetricsPort = parseInt(v)
	}
	if v := os.Getenv("SPLIT_RELAY_BUF"); v != "" {
		cfg.RelayBufSize = parseInt(v)
	}
	if v := os.Getenv("SPLIT_WAIT_TIMEOUT"); v != "" {
		cfg.WaitTimeout = parseInt(v)
	}

	s := &Splitter{
		config:  cfg,
		store:   NewSessionStoreForGermany(),
		metrics: &Metrics{},
		logger:  log.New(os.Stderr, "[germany-splitter] ", log.LstdFlags),
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Metrics server
	if cfg.MetricsPort > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runMetrics(fmt.Sprintf("127.0.0.1:%d", cfg.MetricsPort))
		}()
	}

	// Up-listener: receives session_id + destination from iran-splitter up-leg
	upLn, err := net.Listen("tcp", cfg.UpListen)
	if err != nil {
		s.logger.Fatalf("Failed to listen on up %s: %v", cfg.UpListen, err)
	}
	defer upLn.Close()

	// Down-listener: receives session_id from iran-splitter down-leg
	downLn, err := net.Listen("tcp", cfg.DownListen)
	if err != nil {
		s.logger.Fatalf("Failed to listen on down %s: %v", cfg.DownListen, err)
	}
	defer downLn.Close()

	s.logger.Printf("Up-listen on %s", cfg.UpListen)
	s.logger.Printf("Down-listen on %s", cfg.DownListen)

	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			conn, err := upLn.Accept()
			if err != nil {
				s.logger.Printf("Up accept error: %v", err)
				continue
			}
			go s.handleUpConnection(conn)
		}
	}()

	go func() {
		defer wg.Done()
		for {
			conn, err := downLn.Accept()
			if err != nil {
				s.logger.Printf("Down accept error: %v", err)
				continue
			}
			go s.handleDownConnection(conn)
		}
	}()

	s.logger.Println("germany-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")

	s.store.CloseAll()
	wg.Wait()
	s.logger.Println("germany-splitter stopped")
}

// handleUpConnection processes a connection from iran-splitter on the up-listener
// The first bytes are: session_id (16) + destination header
func (s *Splitter) handleUpConnection(legConn net.Conn) {
	defer legConn.Close()

	s.logger.Printf("Up-leg connection from %s", legConn.RemoteAddr())

	// Read session ID
	rawSid := make([]byte, session.SessionIDLen)
	if _, err := io.ReadFull(legConn, rawSid); err != nil {
		s.logger.Printf("Read session ID: %v", err)
		s.metrics.incErr()
		return
	}

	var sid session.SessionID
	copy(sid[:], rawSid)

	// Read destination
	dest, err := session.ReadDestination(legConn)
	if err != nil {
		s.logger.Printf("Read destination: %v", err)
		s.metrics.incErr()
		legConn.Close()
		return
	}

	addr := net.JoinHostPort(dest.Addr, fmt.Sprintf("%d", dest.Port))
	s.logger.Printf("Up-leg session %s -> %s", sid.String(), addr)

	// Dial the real destination
	relConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		s.logger.Printf("Dial destination %s: %v", addr, err)
		s.metrics.incErr()
		legConn.Close()
		return
	}

	// Create session entry
	sess := &GermanySession{
		SID:    sid,
		Dest:   dest,
		Relay:  relConn,
		UpConn: legConn,
	}
	s.store.Add(sid, sess)
	s.metrics.incSession()
	defer func() {
		s.metrics.decSession()
		s.store.Remove(sid)
	}()

	// Start relay: up-leg -> destination (upload direction)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.copyLoop(relConn, legConn, true, sid)
	}()

	// Signal that destination connection is ready
	flag := s.store.GetReadyFlag(sid)
	flag.SignalReady()

	// Wait for down-leg to connect or timeout
	if !flag.WaitForReady(s.config.WaitTimeout) {
		s.logger.Printf("Timeout: no down-leg for session %s", sid.String())
		relConn.Close()
		return
	}

	// Get down-leg connection
	s.store.mu.RLock()
	downConn := sess.DownConn
	s.store.mu.RUnlock()

	if downConn == nil {
		s.logger.Printf("No down-leg for session %s", sid.String())
		relConn.Close()
		return
	}

	// Start relay: destination -> down-leg (download direction)
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.copyLoop(downConn, relConn, false, sid)
	}()

	wg.Wait()
	s.logger.Printf("Session %s ended", sid.String())
}

// handleDownConnection processes a connection from iran-splitter on the down-listener
// The first bytes are: session_id (16)
func (s *Splitter) handleDownConnection(legConn net.Conn) {
	defer legConn.Close()

	s.logger.Printf("Down-leg connection from %s", legConn.RemoteAddr())

	// Read session ID
	rawSid := make([]byte, session.SessionIDLen)
	if _, err := io.ReadFull(legConn, rawSid); err != nil {
		s.logger.Printf("Read session ID: %v", err)
		s.metrics.incErr()
		return
	}

	var sid session.SessionID
	copy(sid[:], rawSid)

	s.logger.Printf("Down-leg session %s", sid.String())

	// Wait for the session to be created by up-leg
	sess, ok := s.store.Wait(sid, 5000) // 5 second max wait
	if !ok {
		s.logger.Printf("Session %s not found (up-leg hasn't connected yet)", sid.String())
		legConn.Close()
		s.metrics.incErr()
		return
	}

	// Send ACK
	legConn.Write([]byte{0})
	s.logger.Printf("Down-leg connected to session %s", sid.String())

	s.store.mu.Lock()
	sess.DownConn = legConn
	s.store.mu.Unlock()
}

// Wait waits for a session to become available with timeout
func (ss *SessionStoreForGermany) Wait(id session.SessionID, timeoutMs int) (*GermanySession, bool) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	deadline := time.Now().Add(timeout)
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

// copyLoop copies data from src to dst and tracks bytes
func (s *Splitter) copyLoop(dst, src net.Conn, isUp bool, sid session.SessionID) {
	defer src.Close()
	defer dst.Close()

	buf := make([]byte, s.config.RelayBufSize)
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("Copy error session %s: %v", sid.String(), err)
			}
			return
		}
		if n > 0 {
			if isUp {
				s.metrics.incUp(n)
			} else {
				s.metrics.incDown(n)
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				s.logger.Printf("Copy write error session %s: %v", sid.String(), werr)
				return
			}
		}
	}
}

// runMetrics serves basic metrics on HTTP
func (s *Splitter) runMetrics(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s.metrics.mu.Lock()
		fmt.Fprintf(w, `active_sessions %d
total_sessions %d
total_bytes_up %d
total_bytes_down %d
errors %d
`,
			s.metrics.activeSessions,
			s.metrics.totalSessions,
			s.metrics.totalBytesUp,
			s.metrics.totalBytesDown,
			s.metrics.errors,
		)
		fmt.Fprintf(w, "session_count %d\n", s.store.Count())
		s.metrics.mu.Unlock()
	})

	s.logger.Printf("Metrics on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		s.logger.Printf("Metrics server error: %v", err)
	}
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
