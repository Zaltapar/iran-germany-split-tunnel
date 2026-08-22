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

// Config holds the iran-splitter configuration
type Config struct {
	ListenAddr   string // Address Xray connects to (127.0.0.1:10900)
	UpSockAddr   string // helper-up SOCKS address (127.0.0.1:10801)
	DownSockAddr string // helper-down SOCKS address (127.0.0.1:10802)
	MetricsPort  int    // Port for metrics endpoint (0 = disabled)
	RelayBufSize int    // Relay buffer size in bytes
	LogFile      string // Log file path (empty = stderr)
}

// Metrics tracks statistics for the splitter
type Metrics struct {
	mu             sync.Mutex
	activeSessions int64
	totalSessions  int64
	totalBytesUp   int64
	totalBytesDown int64
	errors         int64
}

// Splitter is the iran-splitter daemon
type Splitter struct {
	config  *Config
	store   *session.SessionStore
	metrics *Metrics
	logger  *log.Logger
}

func main() {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:10900",
		UpSockAddr:   "127.0.0.1:10801",
		DownSockAddr: "127.0.0.1:10802",
		RelayBufSize: 32768,
	}

	// Environment variable overrides
	if v := os.Getenv("SPLIT_LISTEN"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("SPLIT_UP_SOCKS"); v != "" {
		cfg.UpSockAddr = v
	}
	if v := os.Getenv("SPLIT_DOWN_SOCKS"); v != "" {
		cfg.DownSockAddr = v
	}
	if v := os.Getenv("SPLIT_METRICS_PORT"); v != "" {
		cfg.MetricsPort = parseInt(v)
	}
	if v := os.Getenv("SPLIT_RELAY_BUF"); v != "" {
		cfg.RelayBufSize = parseInt(v)
	}

	s := &Splitter{
		config:  cfg,
		store:   session.NewSessionStore(),
		metrics: &Metrics{},
		logger:  log.New(os.Stderr, "[iran-splitter] ", log.LstdFlags),
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

	// Main listener
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		s.logger.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	defer ln.Close()

	s.logger.Printf("Listening on %s", cfg.ListenAddr)
	s.logger.Printf("Up SOCKS: %s", cfg.UpSockAddr)
	s.logger.Printf("Down SOCKS: %s", cfg.DownSockAddr)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				s.logger.Printf("Accept error: %v", err)
				continue
			}
			go s.handleConnection(conn)
		}
	}()

	s.logger.Println("iran-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")

	s.store.CloseAll()
	wg.Wait()
	s.logger.Println("iran-splitter stopped")
}

// handleConnection processes a connection from Xray
func (s *Splitter) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	s.logger.Printf("Connection from %s", clientConn.RemoteAddr())

	// Read header: session_id (16 bytes)
	rawSid := make([]byte, session.SessionIDLen)
	if _, err := io.ReadFull(clientConn, rawSid); err != nil {
		s.logger.Printf("Read session ID from %s: %v", clientConn.RemoteAddr(), err)
		s.metrics.incErr()
		return
	}

	var sid session.SessionID
	copy(sid[:], rawSid)

	// Connect to helper-up SOCKS
	upLeg, err := s.connectWithSID(s.config.UpSockAddr, sid)
	if err != nil {
		s.logger.Printf("Up-leg connect: %v", err)
		s.metrics.incErr()
		return
	}

	// Connect to helper-down SOCKS
	downLeg, err := s.connectWithSID(s.config.DownSockAddr, sid)
	if err != nil {
		s.logger.Printf("Down-leg connect: %v", err)
		s.metrics.incErr()
		upLeg.Close()
		return
	}

	// Register session
	s.store.Add(sid, &session.Session{ID: sid})
	s.metrics.incSession()
	defer func() {
		s.metrics.decSession()
		s.store.Remove(sid)
	}()

	// Relay: client <-> upLeg (upload direction)
	// Relay: client <-> downLeg (download direction)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		s.copyLoop(clientConn, upLeg, true)
	}()

	go func() {
		defer wg.Done()
		s.copyLoop(downLeg, clientConn, false)
	}()

	wg.Wait()
	s.logger.Printf("Session %s ended", sid.String())
}

// connectWithSID connects to a SOCKS server and sends the session ID
func (s *Splitter) connectWithSID(addr string, sid session.SessionID) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// Send session ID
	if _, err := conn.Write(sid[:]); err != nil {
		conn.Close()
		return nil, err
	}

	// Wait for ACK
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})

	if buf[0] != 0 {
		conn.Close()
		return nil, fmt.Errorf("NACK received: code %d", buf[0])
	}

	return conn, nil
}

// copyLoop copies data from src to dst, tracking bytes
func (s *Splitter) copyLoop(dst, src net.Conn, isUp bool) {
	defer src.Close()
	defer dst.Close()

	buf := make([]byte, s.config.RelayBufSize)
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("Copy error: %v", err)
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
				s.logger.Printf("Copy write error: %v", werr)
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

// Metrics methods
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

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
