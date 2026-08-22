package main

import (
	"crypto/sha256"
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

	"github.com/Zaltapar/iran-germany-split-tunnel/split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/split-tunnel/pkg/session"
)

type Config struct {
	ListenAddr   string
	MetricsPort  int
	RelayBufSize int
	Secret       string
}

type Metrics struct {
	mu             sync.Mutex
	activeSessions int64
	totalSessions  int64
	totalBytesUp   int64
	totalBytesDown int64
	errors         int64
}

type SessionState struct {
	DestConn net.Conn
	UpConn   net.Conn
	Dest     *session.Destination
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[uint32]*SessionState
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[uint32]*SessionState)}
}

func (ss *SessionStore) Add(streamID uint32, s *SessionState) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[streamID] = s
}

func (ss *SessionStore) Remove(streamID uint32) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[streamID]
	if ok {
		if s.DestConn != nil {
			s.DestConn.Close()
		}
		if s.UpConn != nil {
			s.UpConn.Close()
		}
		delete(ss.sessions, streamID)
	}
}

func (ss *SessionStore) Count() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return len(ss.sessions)
}

func main() {
	cfg := &Config{
		ListenAddr:   ":9000",
		Secret:       "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING",
		RelayBufSize: 32768,
	}

	if v := os.Getenv("SPLIT_LISTEN"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("SPLIT_SECRET"); v != "" {
		cfg.Secret = v
	}
	if v := os.Getenv("SPLIT_METRICS_PORT"); v != "" {
		cfg.MetricsPort = parseInt(v)
	}

	secret := sha256.Sum256([]byte(cfg.Secret))
	s := &Splitter{
		config:  cfg,
		store:   NewSessionStore(),
		metrics: &Metrics{},
		logger:  log.New(os.Stderr, "[germany-splitter] ", log.LstdFlags),
		secret:  secret[:],
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup

	if cfg.MetricsPort > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runMetrics(fmt.Sprintf("127.0.0.1:%d", cfg.MetricsPort))
		}()
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		s.logger.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	defer ln.Close()

	s.logger.Printf("Germany-splitter listening on %s", cfg.ListenAddr)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				s.logger.Printf("Accept error: %v", err)
				continue
			}
			go s.handleCarrier(conn)
		}
	}()

	s.logger.Println("germany-splitter started (mux mode)")
	<-sigCh
	s.logger.Println("Shutting down...")
	wg.Wait()
	s.logger.Println("germany-splitter stopped")
}

type Splitter struct {
	config  *Config
	store   *SessionStore
	metrics *Metrics
	logger  *log.Logger
	secret  []byte
}

func (s *Splitter) handleCarrier(conn net.Conn) {
	defer conn.Close()

	frame, err := mux.ReadFrame(conn)
	if err != nil {
		s.logger.Printf("Failed to read auth: %v", err)
		return
	}
	if frame.Type != mux.FrameAuth {
		s.logger.Printf("Expected auth frame, got type %d", frame.Type)
		conn.Write([]byte{1})
		conn.Close()
		return
	}
	if !mux.ValidateSecret(frame.Payload, s.secret) {
		s.logger.Printf("Auth rejected for %s", conn.RemoteAddr())
		conn.Write([]byte{1})
		conn.Close()
		return
	}
	conn.Write([]byte{0})
	s.logger.Printf("Carrier authenticated: %s", conn.RemoteAddr())

	var readerDone chan struct{}
	var readerWg sync.WaitGroup
	readerDone = make(chan struct{})
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		s.readFrames(conn, readerDone)
	}()

	var keepaliveDone chan struct{}
	keepaliveDone = make(chan struct{})
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		s.keepaliveWriter(conn, keepaliveDone)
	}()

	<-readerDone
	close(keepaliveDone)
	readerWg.Wait()
}

func (s *Splitter) readFrames(conn net.Conn, done chan struct{}) {
	defer close(done)
	for {
		frame, err := mux.ReadFrame(conn)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("Read frame error: %v", err)
			}
			return
		}
		switch frame.Type {
		case mux.FrameData:
			s.handleDataFrame(frame)
		case mux.FramePing:
			pong := mux.NewPongFrame()
			mux.WriteFrame(conn, pong)
		}
	}
}

func (s *Splitter) handleDataFrame(frame *mux.Frame) {
	if s.metrics != nil {
		s.metrics.incDown(len(frame.Payload))
	}
}

func (s *Splitter) keepaliveWriter(conn net.Conn, done chan struct{}) {
	ticker := time.NewTicker(mux.KeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			mux.WriteFrame(conn, mux.NewPingFrame())
		}
	}
}

func (s *Splitter) runMetrics(addr string) {
	mhttp := http.NewServeMux()
	mhttp.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
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
	if err := http.ListenAndServe(addr, mhttp); err != nil {
		s.logger.Printf("Metrics error: %v", err)
	}
}

func (m *Metrics) incSession()       { m.mu.Lock(); m.activeSessions++; m.totalSessions++; m.mu.Unlock() }
func (m *Metrics) decSession()       { m.mu.Lock(); m.activeSessions--; m.mu.Unlock() }
func (m *Metrics) incUp(n int)       { m.mu.Lock(); m.totalBytesUp += int64(n); m.mu.Unlock() }
func (m *Metrics) incDown(n int)     { m.mu.Lock(); m.totalBytesDown += int64(n); m.mu.Unlock() }
func (m *Metrics) incErr()           { m.mu.Lock(); m.errors++; m.mu.Unlock() }
func parseInt(s string) int          { var n int; fmt.Sscanf(s, "%d", &n); return n }
