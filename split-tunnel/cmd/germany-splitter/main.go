package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/split-tunnel/pkg/session"
	"github.com/hashicorp/yamux"
)

// ============================================================
// Config & Metrics
// ============================================================

type Config struct {
	WsListen          string
	Secret            string
	MetricsPort       int
	KeepAliveInterval time.Duration
	RelayBufSize      int
}

type Metrics struct {
	mu             sync.Mutex
	activeSessions int64
	totalSessions  int64
	totalBytesUp   int64
	totalBytesDown int64
	errors         int64
}

func (m *Metrics) incSession()     { m.mu.Lock(); m.activeSessions++; m.totalSessions++; m.mu.Unlock() }
func (m *Metrics) decSession()     { m.mu.Lock(); m.activeSessions--; m.mu.Unlock() }
func (m *Metrics) incUp(n int64)   { m.mu.Lock(); m.totalBytesUp += n; m.mu.Unlock() }
func (m *Metrics) incDown(n int64) { m.mu.Lock(); m.totalBytesDown += n; m.mu.Unlock() }
func (m *Metrics) incErr()         { m.mu.Lock(); m.errors++; m.mu.Unlock() }

// ============================================================
// Splitter
// ============================================================

type Splitter struct {
	config      *Config
	store       map[session.SessionID]*SessionEntry
	mu          sync.RWMutex
	metrics     *Metrics
	logger      *log.Logger
	secret      []byte
	upSession   *yamux.Session // WS up-carrier (from CDN)
	downSession *yamux.Session // TCP down-carrier (to Iran)
}

type SessionEntry struct {
	DestConn net.Conn
	Dest     *session.Destination
	Done     chan struct{}
}

func main() {
	cfg := &Config{
		WsListen:          ":9001",
		KeepAliveInterval: 30 * time.Second,
		RelayBufSize:      32768,
	}

	if v := os.Getenv("SPLIT_UP_WS_LISTEN"); v != "" {
		cfg.WsListen = v
	}
	if v := os.Getenv("SPLIT_SECRET"); v != "" {
		cfg.Secret = v
	} else {
		cfg.Secret = "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING"
	}
	if v := os.Getenv("SPLIT_METRICS_PORT"); v != "" {
		cfg.MetricsPort = parseInt(v)
	}
	if v := os.Getenv("SPLIT_RELAY_BUF"); v != "" {
		cfg.RelayBufSize = parseInt(v)
	}

	derived := mux.DeriveSecret(cfg.Secret)

	s := &Splitter{
		config:  cfg,
		store:   make(map[session.SessionID]*SessionEntry),
		metrics: &Metrics{},
		logger:  log.New(os.Stderr, "[germany-splitter] ", log.LstdFlags),
		secret:  derived,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup

	// --- Up-carrier: WS server (CDN connects to us) ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runUpWsServer()
	}()

	// --- Down-carrier: TCP listener (receives yamux from Iran) ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runDownCarrierListener()
	}()

	s.logger.Printf("Up-carrier (WS) listening on %s", cfg.WsListen)
	s.logger.Println("germany-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")
	s.cleanupAll()
	if s.upSession != nil {
		s.upSession.Close()
	}
	if s.downSession != nil {
		s.downSession.Close()
	}
	wg.Wait()
	s.logger.Println("germany-splitter stopped")
}

// ---- Up-carrier: WS server (CDN/Nginx connects) ----

func (s *Splitter) runUpWsServer() {
	ln, err := net.Listen("tcp", s.config.WsListen)
	if err != nil {
		s.logger.Fatalf("WS listener: %v", err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleUpWsConnection(conn)
	}
}

func (s *Splitter) handleUpWsConnection(rawConn net.Conn) {
	// Auth: read secret header
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(rawConn, hdr); err != nil {
		return
	}
	sl := int(hdr[2])<<8 | int(hdr[3])
	secretPayload := make([]byte, sl)
	if _, err := io.ReadFull(rawConn, secretPayload); err != nil {
		return
	}
	if !mux.ValidateSecret(secretPayload, s.secret) {
		s.logger.Printf("Up-carrier auth rejected for %s", rawConn.RemoteAddr())
		rawConn.Close()
		return
	}
	// Auth ACK
	rawConn.Write([]byte{0x00, 0x00, 0x00, 1, 0x00})
	s.logger.Printf("Up-carrier authenticated: %s", rawConn.RemoteAddr())

	// Create yamux client (we are client; CDN is server)
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = true
	yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
	yamuxSession, err := yamux.Client(rawConn, yamuxCfg)
	if err != nil {
		s.logger.Printf("Up-carrier yamux client: %v", err)
		rawConn.Close()
		return
	}

	s.logger.Printf("Up-carrier yamux session established")

	s.mu.Lock()
	s.upSession = yamuxSession
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(s.config.KeepAliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				yamuxSession.Ping()
			}
		}
	}()

	<-yamuxSession.CloseChan()
	s.logger.Printf("Up-carrier yamux session closed")
	s.mu.Lock()
	if s.upSession == yamuxSession {
		s.upSession = nil
	}
	s.mu.Unlock()
}

// ---- Down-carrier: TCP listener (receives yamux from Iran) ----

func (s *Splitter) runDownCarrierListener() {
	ln, err := net.Listen("tcp", ":9002")
	if err != nil {
		s.logger.Fatalf("Down-carrier listener: %v", err)
	}
	defer ln.Close()

	s.logger.Printf("Down-carrier listening on :9002")

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleDownCarrier(conn)
	}
}

func (s *Splitter) handleDownCarrier(rawConn net.Conn) {
	// Auth
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(rawConn, hdr); err != nil {
		return
	}
	sl := int(hdr[2])<<8 | int(hdr[3])
	secretPayload := make([]byte, sl)
	if _, err := io.ReadFull(rawConn, secretPayload); err != nil {
		return
	}
	if !mux.ValidateSecret(secretPayload, s.secret) {
		s.logger.Printf("Down-carrier auth rejected: %s", rawConn.RemoteAddr())
		rawConn.Close()
		return
	}
	rawConn.Write([]byte{0x00, 0x00, 0x00, 1, 0x00})
	s.logger.Printf("Down-carrier authenticated: %s", rawConn.RemoteAddr())

	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = true
	yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
	yamuxSession, err := yamux.Server(rawConn, yamuxCfg)
	if err != nil {
		s.logger.Printf("Down-carrier yamux server: %v", err)
		rawConn.Close()
		return
	}

	s.logger.Printf("Down-carrier yamux session established")

	s.mu.Lock()
	s.downSession = yamuxSession
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(s.config.KeepAliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				yamuxSession.Ping()
			}
		}
	}()

	<-yamuxSession.CloseChan()
	s.logger.Printf("Down-carrier yamux session closed")
	s.mu.Lock()
	if s.downSession == yamuxSession {
		s.downSession = nil
	}
	s.mu.Unlock()
}

// ---- Stream handler: up-carrier streams from CDN ----

func (s *Splitter) handleUpStream(stream *yamux.Stream) {
	defer stream.Close()

	// Read sessionID (16 bytes)
	sidBuf := make([]byte, session.SessionIDLen)
	if _, err := io.ReadFull(stream, sidBuf); err != nil {
		return
	}
	var sid session.SessionID
	copy(sid[:], sidBuf)

	// Read dest header (addr_type + addr + port)
	hdr := make([]byte, session.MaxHeaderSize)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		return
	}
	dest := session.ParseDestinationFromBuf(hdr)
	if dest == nil {
		s.metrics.incErr()
		return
	}

	addr := fmt.Sprintf("%s:%d", dest.Addr, dest.Port)
	s.logger.Printf("New session %s → %s (from CDN up-carrier)", sid.String(), addr)

	// Dial destination
	destConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		s.logger.Printf("Dial %s: %v", addr, err)
		s.metrics.incErr()
		return
	}
	s.logger.Printf("Session %s destination connected → %s", sid.String(), addr)

	done := make(chan struct{})
	entry := &SessionEntry{DestConn: destConn, Dest: dest, Done: done}

	s.mu.Lock()
	s.store[sid] = entry
	s.mu.Unlock()

	s.metrics.incSession()
	go func() {
		<-done
		s.metrics.decSession()
		s.mu.Lock()
		delete(s.store, sid)
		s.mu.Unlock()
	}()

	// Relay: stream (upload data from Iran via CDN) → destConn
	go func() {
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.logger.Printf("UpStream read: %v", err)
				}
				destConn.Close()
				return
			}
			if n > 0 {
				s.metrics.incUp(int64(n))
				destConn.Write(buf[:n])
			}
		}
	}()

	// Relay: destConn (download from internet) → down-carrier yamux stream
	go func() {
		buf := make([]byte, s.config.RelayBufSize)
		// Wait for down-carrier session to be ready
		for s.downSession == nil {
			time.Sleep(100 * time.Millisecond)
		}
		downStream, err := s.downSession.OpenStream()
		if err != nil {
			s.logger.Printf("Open down-stream: %v", err)
			return
		}
		defer downStream.Close()

		// Write sessionID first
		downStream.Write(sid[:])

		for {
			n, err := destConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.logger.Printf("DestConn read: %v", err)
				}
				return
			}
			if n > 0 {
				s.metrics.incDown(int64(n))
				downStream.Write(buf[:n])
			}
		}
	}()
}

// ---- Cleanup ----

func (s *Splitter) cleanupAll() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.store {
		if entry.DestConn != nil {
			entry.DestConn.Close()
		}
	}
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
