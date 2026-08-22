package main

import (
	"bytes"
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
	"github.com/gorilla/websocket"
)

// wsReader wraps a websocket.Conn to implement io.Reader
type wsReader struct {
	conn *websocket.Conn
}

func (r *wsReader) Read(p []byte) (n int, err error) {
	_, msg, err := r.conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	copy(p, msg)
	return len(msg), nil
}

// wsWriter wraps a websocket.Conn to implement io.Writer
type wsWriter struct {
	conn *websocket.Conn
}

func (w *wsWriter) Write(p []byte) (n int, err error) {
	err = w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// wsReadWriteCloser implements io.ReadWriteCloser for websocket.Conn
type wsReadWriteCloser struct {
	*wsReader
	*wsWriter
	conn *websocket.Conn
}

func newWsReadWriteCloser(conn *websocket.Conn) *wsReadWriteCloser {
	return &wsReadWriteCloser{
		wsReader: &wsReader{conn: conn},
		wsWriter: &wsWriter{conn: conn},
		conn:     conn,
	}
}

func (w *wsReadWriteCloser) Close() error {
	return w.conn.Close()
}

// Config holds configuration
type Config struct {
	// Down-carrier: TCP listener (receives from Iran via Xray tunnel)
	DownListen string // e.g. :9002

	// Up-carrier: WebSocket dialer (sends to CDN)
	UpWsUrl string // e.g. wss://cdn.example.com/upload

	Secret       string
	MetricsPort  int
	RelayBufSize int
}

// Metrics
type Metrics struct {
	mu             sync.Mutex
	activeSessions int64
	totalSessions  int64
	totalBytesUp   int64
	totalBytesDown int64
	errors         int64
}

// SessionEntry represents a session on Germany side
type SessionEntry struct {
	DestConn net.Conn
	Dest     *session.Destination
	Role     string
	Done     chan struct{}
}

// Splitter is the main daemon
type Splitter struct {
	config      *Config
	store       map[session.SessionID]*SessionEntry // sessionID → entry
	mu          sync.RWMutex
	metrics     *Metrics
	logger      *log.Logger
	secret      []byte
	metricsAddr string
	upWsDialer  *websocket.Upgrader
}

func main() {
	cfg := &Config{
		DownListen:   ":9002",
		UpWsUrl:      "wss://cdn.example.com/upload",
		Secret:       "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING",
		RelayBufSize: 32768,
	}

	if v := os.Getenv("SPLIT_DOWN_LISTEN"); v != "" {
		cfg.DownListen = v
	}
	if v := os.Getenv("SPLIT_UP_WS_URL"); v != "" {
		cfg.UpWsUrl = v
	}
	if v := os.Getenv("SPLIT_SECRET"); v != "" {
		cfg.Secret = v
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

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup

	// Metrics server
	if cfg.MetricsPort > 0 {
		s.metricsAddr = fmt.Sprintf("127.0.0.1:%d", cfg.MetricsPort)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.runMetrics(s.metricsAddr); err != nil {
				s.logger.Printf("Metrics: %v", err)
			}
		}()
	}

	// === Down-carrier: TCP listener (receives from Iran via Xray tunnel) ===
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runDownListener()
	}()

	// === Up-carrier: WebSocket dialer (connects to CDN for upload) ===
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runUpDialer(&wg)
	}()

	s.logger.Printf("Down-carrier (TCP) listener on %s", cfg.DownListen)
	s.logger.Printf("Up-carrier (WS) dials %s", cfg.UpWsUrl)
	s.logger.Println("germany-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")
	s.cleanupAll()
	wg.Wait()
	s.logger.Println("germany-splitter stopped")
}

// runDownListener accepts TCP connections from Iran's down-carrier
func (s *Splitter) runDownListener() {
	ln, err := net.Listen("tcp", s.config.DownListen)
	if err != nil {
		s.logger.Fatalf("Down-carrier listener failed: %v", err)
	}
	defer ln.Close()

	s.logger.Printf("Down-carrier listener on %s", s.config.DownListen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.logger.Printf("Down-carrier accept error: %v", err)
			continue
		}
		go s.handleDownConnection(conn)
	}
}

// handleDownConnection handles a down-carrier TCP connection from Iran
func (s *Splitter) handleDownConnection(conn net.Conn) {
	defer conn.Close()

	s.logger.Printf("Down-carrier connection from %s", conn.RemoteAddr())

	// Read auth frame
	frame, err := mux.ReadFrame(conn)
	if err != nil {
		s.logger.Printf("Auth read: %v", err)
		return
	}
	if frame.Type != mux.FrameAuth {
		s.logger.Printf("Expected auth frame, got type %d", frame.Type)
		return
	}
	if !mux.ValidateSecret(frame.Payload, s.secret) {
		s.logger.Printf("Auth rejected for %s", conn.RemoteAddr())
		return
	}

	// Send auth ACK (FrameAuth with payload [0] = success)
	mux.WriteFrame(conn, mux.NewAuthFrame([]byte{0}))
	s.logger.Printf("Down-carrier authenticated: %s", conn.RemoteAddr())

	// Start frame reader
	s.runDownFrameReader(conn)
	s.logger.Printf("Down-carrier disconnected: %s", conn.RemoteAddr())
}

// runDownFrameReader reads frames from down-carrier (download data from Iran via Xray)
// These frames contain sessionID + download bytes from destination
func (s *Splitter) runDownFrameReader(conn net.Conn) {
	for {
		frame, err := mux.ReadFrame(conn)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("Down-carrier read: %v", err)
			}
			return
		}
		switch frame.Type {
		case mux.FrameData:
			s.handleDownData(frame)
		case mux.FramePing:
			mux.WriteFrame(conn, mux.NewPongFrame())
		}
	}
}

// handleDownData routes download data from down-carrier to matching session
func (s *Splitter) handleDownData(frame *mux.Frame) {
	if len(frame.Payload) < session.SessionIDLen {
		s.metrics.incErr()
		return
	}

	var sid session.SessionID
	copy(sid[:], frame.Payload[:session.SessionIDLen])

	s.mu.RLock()
	entry, ok := s.store[sid]
	s.mu.RUnlock()

	if !ok {
		s.metrics.incErr()
		s.logger.Printf("Unknown session %s", sid.String())
		return
	}

	// Relay: data → destination connection (download from Iran to Germany→destination)
	// This is actually data coming from the user, being sent to the destination
	s.metrics.mu.Lock()
	s.metrics.totalBytesUp += int64(len(frame.Payload) - session.SessionIDLen)
	s.metrics.mu.Unlock()

	entry.DestConn.Write(frame.Payload[session.SessionIDLen:])
}

// runUpDialer connects to the CDN WebSocket (up-carrier for upload)
func (s *Splitter) runUpDialer(wg *sync.WaitGroup) {
	for {
		s.logger.Printf("Up-carrier dialing %s...", s.config.UpWsUrl)
		conn, _, err := websocket.DefaultDialer.Dial(s.config.UpWsUrl, nil)
		if err != nil {
			s.logger.Printf("Up-carrier dial failed: %v (retrying in 5s)", err)
			time.Sleep(5 * time.Second)
			continue
		}
		s.logger.Printf("Up-carrier connected to CDN")

		// Wrap websocket.Conn to implement io interfaces
		wsc := newWsReadWriteCloser(conn)

		// Auth phase: send auth frame
		auth := mux.NewAuthFrame(s.secret)
		if err := mux.WriteFrame(wsc, auth); err != nil {
			s.logger.Printf("Up-carrier auth send failed: %v (retrying in 2s)", err)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		// Read auth response
		resp, err := mux.ReadFrame(wsc)
		if err != nil {
			s.logger.Printf("Up-carrier auth read failed: %v (retrying in 2s)", err)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.Type != mux.FrameAuth || len(resp.Payload) < 1 {
			s.logger.Printf("Up-carrier bad auth response type %d", resp.Type)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.Payload[0] != 0 {
			s.logger.Printf("Up-carrier auth rejected")
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		s.logger.Printf("Up-carrier authenticated with CDN")

		// Start frame reader for this connection
		done := make(chan struct{})
		var readerWg sync.WaitGroup
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			s.runUpFrameReader(wsc, done)
		}()

		// Wait for disconnect or shutdown
		<-done
		close(done)
		readerWg.Wait()
		conn.Close()
		s.logger.Printf("Up-carrier disconnected from CDN")

		time.Sleep(2 * time.Second)
	}
}

// runUpFrameReader reads frames from up-carrier (download data from Germany CDN to destination)
// The up-carrier receives download bytes from Iran that need to go to the destination
func (s *Splitter) runUpFrameReader(conn *wsReadWriteCloser, done chan struct{}) {
	defer close(done)
	for {
		frame, err := mux.ReadFrame(conn)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("Up-carrier read: %v", err)
			}
			return
		}
		switch frame.Type {
		case mux.FrameData:
			s.handleUpData(frame, conn)
		case mux.FramePing:
			// Convert ping to pong for keepalive
			mux.WriteFrame(conn, mux.NewPongFrame())
		}
	}
}

// handleUpData routes download data from up-carrier to matching destination connection
// These frames are download responses that came back through the CDN
func (s *Splitter) handleUpData(frame *mux.Frame, conn *wsReadWriteCloser) {
	if len(frame.Payload) < session.SessionIDLen {
		s.metrics.incErr()
		return
	}

	var sid session.SessionID
	copy(sid[:], frame.Payload[:session.SessionIDLen])

	s.mu.RLock()
	entry, ok := s.store[sid]
	s.mu.RUnlock()

	if !ok {
		s.metrics.incErr()
		s.logger.Printf("Unknown session %s on up-carrier", sid.String())
		return
	}

	// Relay: data → destination connection (this is download data)
	s.metrics.mu.Lock()
	s.metrics.totalBytesDown += int64(len(frame.Payload) - session.SessionIDLen)
	s.metrics.mu.Unlock()

	entry.DestConn.Write(frame.Payload[session.SessionIDLen:])
}

// handleNewStreamSession creates a new session and dials the destination
func (s *Splitter) handleNewStreamSession(sid session.SessionID, dest *session.Destination, cc *wsReadWriteCloser) {
	addr := fmt.Sprintf("%s:%d", dest.Addr, dest.Port)
	s.logger.Printf("New session %s → %s", sid.String(), addr)

	// Dial destination
	destConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		s.logger.Printf("Dial %s: %v", addr, err)
		s.metrics.incErr()
		return
	}
	s.logger.Printf("Session %s destination connected → %s", sid.String(), addr)

	// Store entry
	done := make(chan struct{})
	entry := &SessionEntry{
		DestConn: destConn,
		Dest:     dest,
		Role:     "active",
		Done:     done,
	}

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

	// Relay: destination → up-carrier WebSocket (upload bytes from destination to Iran)
	// This is data going FROM the real internet TO the user (through the CDN)
	go func() {
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := destConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.logger.Printf("Dest read: %v", err)
				}
				return
			}
			if n > 0 {
				// Build frame with session ID prefix
				frame := make([]byte, session.SessionIDLen+n)
				copy(frame[:session.SessionIDLen], sid[:])
				copy(frame[session.SessionIDLen:], buf[:n])
				mux.WriteFrame(cc.wsWriter, mux.NewDataFrame(0, frame))
				s.metrics.incDown(n)
			}
		}
	}()

	// Note: down-carrier frames from Iran to destination are handled by handleDownData
}

// parseDestFromBuf manually parses a destination from a byte buffer
func (s *Splitter) parseDestFromBuf(buf []byte) *session.Destination {
	if len(buf) < 4 {
		return nil
	}
	dest := &session.Destination{AddrType: buf[0]}
	pos := 1
	switch dest.AddrType {
	case session.AddrTypeIPv4:
		if len(buf) < pos+4+2 {
			return nil
		}
		dest.Addr = net.IP(buf[pos : pos+4]).String()
		pos += 4
	case session.AddrTypeDomain:
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
	case session.AddrTypeIPv6:
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

// cleanupAll closes all active session connections
func (s *Splitter) cleanupAll() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.store {
		if entry.DestConn != nil {
			entry.DestConn.Close()
		}
	}
}

// runMetrics serves /metrics on HTTP
func (s *Splitter) runMetrics(addr string) error {
	mhttp := http.NewServeMux()
	mhttp.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s.metrics.mu.Lock()
		fmt.Fprintf(w, "active_sessions %d\ntotal_sessions %d\ntotal_bytes_up %d\ntotal_bytes_down %d\nerrors %d\n",
			s.metrics.activeSessions,
			s.metrics.totalSessions,
			s.metrics.totalBytesUp,
			s.metrics.totalBytesDown,
			s.metrics.errors,
		)
		s.metrics.mu.Unlock()
		s.mu.RLock()
		fmt.Fprintf(w, "session_count %d\n", len(s.store))
		s.mu.RUnlock()
	})
	s.logger.Printf("Metrics on %s", addr)
	return http.ListenAndServe(addr, mhttp)
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

// Ensure bytes is imported
var _ = bytes.NewReader
