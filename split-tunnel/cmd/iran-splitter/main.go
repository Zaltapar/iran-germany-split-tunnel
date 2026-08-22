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
	// SOCKS5 listener for Xray (receives user connections)
	SocksListen string // e.g. 127.0.0.1:10900

	// Up-carrier: WebSocket server (receives from CDN/Nginx on this port)
	WsListen string // e.g. 127.0.0.1:9001

	// Down-carrier: dial local Xray outbound (which routes to Germany)
	DownCarrierAddr string // e.g. 127.0.0.1:10802

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

// Splitter is the main daemon
type Splitter struct {
	config      *Config
	store       *session.SessionStore
	metrics     *Metrics
	logger      *log.Logger
	secret      []byte
	mu          sync.RWMutex
	upTransport *mux.Transport // WS transport (up-carrier: CDN → iran → upload)
	downConn    net.Conn       // raw TCP to Xray (down-carrier)
	metricsAddr string
}

func main() {
	cfg := &Config{
		SocksListen:     "127.0.0.1:10900",
		WsListen:        "127.0.0.1:9001",
		DownCarrierAddr: "127.0.0.1:10802",
		Secret:          "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING",
		RelayBufSize:    32768,
	}

	if v := os.Getenv("SPLIT_SOCKS_LISTEN"); v != "" {
		cfg.SocksListen = v
	}
	if v := os.Getenv("SPLIT_WS_LISTEN"); v != "" {
		cfg.WsListen = v
	}
	if v := os.Getenv("SPLIT_DOWN_CARRIER_ADDR"); v != "" {
		cfg.DownCarrierAddr = v
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
		store:   session.NewSessionStore(),
		metrics: &Metrics{},
		logger:  log.New(os.Stderr, "[iran-splitter] ", log.LstdFlags),
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

	// === Up-carrier: WebSocket server (CDN/Nginx sends upload data to us) ===
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runWsServer()
	}()

	// === Down-carrier: dial local Xray outbound (routes to Germany via VLESS+Reality) ===
	downConn, err := net.DialTimeout("tcp", cfg.DownCarrierAddr, 10*time.Second)
	if err != nil {
		s.logger.Fatalf("Down-carrier dial failed: %v", err)
	}
	s.logger.Printf("Down-carrier connected to %s", cfg.DownCarrierAddr)

	s.mu.Lock()
	s.downConn = downConn
	s.mu.Unlock()

	// Start down-carrier frame reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runDownCarrier(downConn)
	}()

	s.logger.Printf("SOCKS5 listener on %s", cfg.SocksListen)
	s.logger.Printf("Up-carrier (WS) listener on %s", cfg.WsListen)
	s.logger.Printf("Down-carrier → %s", cfg.DownCarrierAddr)
	s.logger.Println("iran-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")
	s.store.CloseAll()
	s.mu.RLock()
	if s.upTransport != nil {
		s.upTransport.Close()
	}
	if s.downConn != nil {
		s.downConn.Close()
	}
	s.mu.RUnlock()
	wg.Wait()
	s.logger.Println("iran-splitter stopped")
}

// runWsServer hosts an HTTP server that accepts WebSocket connections from CDN/Nginx
func (s *Splitter) runWsServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		s.handleWsConnection(w, r)
	})

	ln, err := net.Listen("tcp", s.config.WsListen)
	if err != nil {
		s.logger.Fatalf("WS listener failed: %v", err)
	}
	defer ln.Close()

	s.logger.Printf("WS server listening on %s", s.config.WsListen)
	if err := http.Serve(ln, mux); err != nil {
		s.logger.Printf("WS server error: %v", err)
	}
}

// handleWsConnection handles a new WebSocket connection from the up-carrier
func (s *Splitter) handleWsConnection(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
	upConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Printf("WS upgrade failed: %v", err)
		return
	}
	defer upConn.Close()

	s.logger.Printf("Up-carrier WS connected from %s", r.RemoteAddr)

	// Wrap websocket.Conn to implement io interfaces
	wsc := newWsReadWriteCloser(upConn)

	// Auth phase: read auth frame
	frame, err := mux.ReadFrame(wsc)
	if err != nil {
		s.logger.Printf("Auth read: %v", err)
		return
	}
	if frame.Type != mux.FrameAuth {
		s.logger.Printf("Expected auth frame, got type %d", frame.Type)
		return
	}
	if !mux.ValidateSecret(frame.Payload, s.secret) {
		s.logger.Printf("Auth rejected for %s", r.RemoteAddr)
		return
	}

	// Send auth ACK (FrameAuth with payload [0] = success)
	mux.WriteFrame(wsc, mux.NewAuthFrame([]byte{0}))
	s.logger.Printf("Up-carrier authenticated: %s", r.RemoteAddr)

	// Create transport for this WS connection
	transport := mux.NewTransport(wsc)
	defer transport.Close()

	// Store reference
	s.mu.Lock()
	s.upTransport = transport
	s.mu.Unlock()

	// Read frames from up-carrier
	s.runUpCarrier(transport)
	s.logger.Printf("Up-carrier disconnected: %s", r.RemoteAddr)
}

// runUpCarrier reads frames from the up-carrier (upload direction)
// Data flow: up-carrier frames → session → client connection
func (s *Splitter) runUpCarrier(t *mux.Transport) {
	for {
		frame, err := mux.ReadFrame(t)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("Up-carrier read: %v", err)
			}
			return
		}
		switch frame.Type {
		case mux.FrameData:
			s.handleUpFrame(frame)
		case mux.FramePing:
			t.Send(mux.NewPongFrame())
		}
	}
}

// handleUpFrame routes upload data from carrier to matching session's client
// The frame payload contains: sessionID (16 bytes) + upload bytes
func (s *Splitter) handleUpFrame(frame *mux.Frame) {
	if len(frame.Payload) < session.SessionIDLen {
		s.metrics.incErr()
		return
	}

	var sid session.SessionID
	copy(sid[:], frame.Payload[:session.SessionIDLen])

	sess, ok := s.store.GetSession(sid)
	if !ok {
		s.metrics.incErr()
		s.logger.Printf("Unknown session %s", sid.String())
		return
	}

	// Relay: data → client connection (this is upload data from the user)
	s.metrics.mu.Lock()
	s.metrics.totalBytesUp += int64(len(frame.Payload) - session.SessionIDLen)
	s.metrics.mu.Unlock()

	sess.ClientConn.Write(frame.Payload[session.SessionIDLen:])
}

// runDownCarrier reads frames from the down-carrier (download direction)
// Data flow: destination response → down-carrier → session → client connection
func (s *Splitter) runDownCarrier(conn net.Conn) {
	defer conn.Close()
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
			s.handleDownFrame(frame)
		case mux.FramePing:
			mux.WriteFrame(conn, mux.NewPongFrame())
		}
	}
}

// handleDownFrame routes download data from down-carrier to matching session's client
func (s *Splitter) handleDownFrame(frame *mux.Frame) {
	if len(frame.Payload) < session.SessionIDLen {
		s.metrics.incErr()
		return
	}

	var sid session.SessionID
	copy(sid[:], frame.Payload[:session.SessionIDLen])

	sess, ok := s.store.GetSession(sid)
	if !ok {
		s.metrics.incErr()
		s.logger.Printf("Unknown session %s on down-carrier", sid.String())
		return
	}

	// Relay: data → client connection (this is download data from the internet)
	s.metrics.mu.Lock()
	s.metrics.totalBytesDown += int64(len(frame.Payload) - session.SessionIDLen)
	s.metrics.mu.Unlock()

	sess.ClientConn.Write(frame.Payload[session.SessionIDLen:])
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
		fmt.Fprintf(w, "session_count %d\n", s.store.Count())
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
