package main

import (
	"context"
	"encoding/binary"
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
	"github.com/hashicorp/yamux"
)

// ============================================================
// WebSocket io.ReadWriteCloser wrapper
// ============================================================

type wsConn struct {
	conn *websocket.Conn
}

func (w *wsConn) Read(p []byte) (int, error) {
	for {
		_, msg, err := w.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		n := copy(p, msg)
		if n < len(msg) {
			return n, nil // truncated
		}
		if n > 0 {
			return n, nil
		}
		// empty message, skip
	}
}

func (w *wsConn) Write(p []byte) (int, error) {
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) Close() error { return w.conn.Close() }

// ============================================================
// Config & Metrics
// ============================================================

type Config struct {
	SocksListen       string
	WsListen          string
	DownCarrierAddr   string
	Secret            string
	MetricsPort       int
	RelayBufSize      int
	KeepAliveInterval time.Duration
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
	store       *session.SessionStore
	metrics     *Metrics
	logger      *log.Logger
	secret      []byte
	mu          sync.RWMutex
	upSession   *yamux.Session // WS server (CDN → upload streams)
	downSession *yamux.Session // TCP server (Germany → download streams)
}

func main() {
	cfg := &Config{
		SocksListen:       "127.0.0.1:10900",
		WsListen:          "127.0.0.1:9001",
		DownCarrierAddr:   "127.0.0.1:10802",
		Secret:            "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING",
		RelayBufSize:      32768,
		KeepAliveInterval: 30 * time.Second,
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup

	// --- Metrics ---
	if cfg.MetricsPort > 0 {
		wg.Add(1)
		go func() { defer wg.Done(); s.runMetrics(fmt.Sprintf("127.0.0.1:%d", cfg.MetricsPort)) }()
	}

	// --- Up-Carrier: WS server (behind CDN /upload) ---
	wg.Add(1)
	go func() { defer wg.Done(); s.runUpCarrier(&wg) }()

	// --- SOCKS5 server (user connections from Xray) ---
	wg.Add(1)
	go func() { defer wg.Done(); s.runSocksServer() }()

	// --- Down-Carrier: TCP client → Germany ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runDownCarrier(&wg)
	}()

	s.logger.Printf("SOCKS5: %s | WS: %s | Down → %s", cfg.SocksListen, cfg.WsListen, cfg.DownCarrierAddr)
	s.logger.Println("iran-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")
	s.store.CloseAll()
	s.mu.RLock()
	if s.upSession != nil {
		s.upSession.Close()
	}
	if s.downSession != nil {
		s.downSession.Close()
	}
	s.mu.RUnlock()
	wg.Wait()
	s.logger.Println("iran-splitter stopped")
}

// ============================================================
// Up-Carrier: WebSocket server (CDN connects to us on SPLIT_WS_LISTEN)
// ============================================================

func (s *Splitter) runUpCarrier(wg *sync.WaitGroup) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}

	muxHTTP := http.NewServeMux()
	muxHTTP.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			s.logger.Printf("WS upgrade failed from %s: %v", r.RemoteAddr, err)
			return
		}
		s.logger.Printf("Up-carrier WS connected from %s", r.RemoteAddr)
		s.handleUpWsConn(wsConn)
		s.logger.Printf("Up-carrier WS disconnected from %s", r.RemoteAddr)
	})

	ln, err := net.Listen("tcp", s.config.WsListen)
	if err != nil {
		s.logger.Fatalf("WS listener: %v", err)
	}
	defer ln.Close()
	s.logger.Printf("WS server listening on %s", s.config.WsListen)

	if err := http.Serve(ln, muxHTTP); err != nil && err != http.ErrServerClosed {
		s.logger.Printf("WS server error: %v", err)
	}
}

func (s *Splitter) handleUpWsConn(ws *websocket.Conn) {
	wsc := &wsConn{conn: ws}

	// Auth: read 32-byte secret with 4-byte big-endian length prefix
	var lenBuf [4]byte
	if _, err := io.ReadFull(wsc, lenBuf[:]); err != nil {
		s.logger.Printf("Up-carrier auth read length: %v", err)
		wsc.Close()
		return
	}
	secretLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if secretLen != 32 {
		s.logger.Printf("Up-carrier auth bad length %d", secretLen)
		wsc.Close()
		return
	}
	secretPayload := make([]byte, 32)
	if _, err := io.ReadFull(wsc, secretPayload); err != nil {
		s.logger.Printf("Up-carrier auth read secret: %v", err)
		wsc.Close()
		return
	}
	if !mux.ValidateSecret(secretPayload, s.secret) {
		s.logger.Printf("Up-carrier auth rejected from %s", ws.RemoteAddr())
		wsc.Close()
		return
	}
	// Auth ACK
	wsc.Write([]byte{0x00})
	s.logger.Printf("Up-carrier authenticated from %s", ws.RemoteAddr())

	// Wrap in yamux.Server (we are server, CDN is client)
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = true
	yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
	yamuxSession, err := yamux.Server(wsc, yamuxCfg)
	if err != nil {
		s.logger.Printf("Up-carrier yamux server: %v", err)
		wsc.Close()
		return
	}

	s.mu.Lock()
	s.upSession = yamuxSession
	s.mu.Unlock()
	s.logger.Printf("Up-carrier yamux session established")

	// Accept upload streams from CDN (each stream = one user session)
	go func() {
		for {
			stream, err := yamuxSession.AcceptStream()
			if err != nil {
				s.logger.Printf("Up-carrier accept stream: %v", err)
				yamuxSession.Close()
				return
			}
			go s.handleUpStream(stream)
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

// handleUpStream: passthrough — download data comes via down-carrier instead
func (s *Splitter) handleUpStream(stream *yamux.Stream) {
	defer stream.Close()
	buf := make([]byte, 1460)
	for {
		_, err := stream.Read(buf)
		if err != nil {
			return
		}
	}
}

// ============================================================
// Down-Carrier: TCP client → Germany (persistent tunnel)
// ============================================================

func (s *Splitter) runDownCarrier(wg *sync.WaitGroup) {
	for {
		conn, err := net.DialTimeout("tcp", s.config.DownCarrierAddr, 10*time.Second)
		if err != nil {
			s.logger.Printf("Down-carrier dial to %s: %v (retrying in 5s)", s.config.DownCarrierAddr, err)
			time.Sleep(5 * time.Second)
			continue
		}
		s.logger.Printf("Down-carrier connected to %s", s.config.DownCarrierAddr)

		// Auth: send 32-byte secret with 4-byte length prefix
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, 32)
		if _, err := conn.Write(append(prefix, s.secret...)); err != nil {
			s.logger.Printf("Down-carrier auth send: %v", err)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		ack := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, ack); err != nil || ack[0] != 0x00 {
			s.logger.Printf("Down-carrier auth ACK failed: byte=%v err=%v", ack, err)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		s.logger.Printf("Down-carrier authenticated")

		// Wrap in yamux.Server (we are server, Germany is client)
		yamuxCfg := yamux.DefaultConfig()
		yamuxCfg.EnableKeepAlive = true
		yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
		yamuxSession, err := yamux.Server(conn, yamuxCfg)
		if err != nil {
			s.logger.Printf("Down-carrier yamux server: %v", err)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		s.mu.Lock()
		if s.downSession != nil {
			s.downSession.Close()
		}
		s.downSession = yamuxSession
		s.mu.Unlock()
		s.logger.Printf("Down-carrier yamux session established")

		// Accept download streams from Germany
		go func() {
			for {
				stream, err := yamuxSession.AcceptStream()
				if err != nil {
					s.logger.Printf("Down-carrier accept stream: %v", err)
					yamuxSession.Close()
					return
				}
				go s.handleDownStream(stream)
			}
		}()

		<-yamuxSession.CloseChan()
		s.logger.Printf("Down-carrier yamux session closed")
		s.mu.Lock()
		if s.downSession == yamuxSession {
			s.downSession = nil
		}
		s.mu.Unlock()

		// Reconnect delay
		time.Sleep(3 * time.Second)
	}
}

// handleDownStream: download stream from Germany — contains sessionID + download data
func (s *Splitter) handleDownStream(stream *yamux.Stream) {
	defer stream.Close()

	// Read sessionID (16 bytes)
	sidBuf := make([]byte, session.SessionIDLen)
	if _, err := io.ReadFull(stream, sidBuf); err != nil {
		s.logger.Printf("DownStream read sessionID: %v", err)
		return
	}
	var sid session.SessionID
	copy(sid[:], sidBuf)

	// Look up session
	sess, ok := s.store.GetSession(sid)
	if !ok {
		s.logger.Printf("DownStream session %s not found", sid.String())
		return
	}

	s.logger.Printf("DownStream session %s: relaying to client", sid.String())

	// Relay: downStream → client
	buf := make([]byte, s.config.RelayBufSize)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("DownStream read: %v", err)
			}
			return
		}
		if n > 0 {
			s.metrics.incDown(int64(n))
			sess.ClientConn.Write(buf[:n])
		}
	}
}

// ============================================================
// SOCKS5 Server (user connections from Xray)
// ============================================================

func (s *Splitter) runSocksServer() {
	ln, err := net.Listen("tcp", s.config.SocksListen)
	if err != nil {
		s.logger.Fatalf("SOCKS5: %v", err)
	}
	defer ln.Close()
	s.logger.Printf("SOCKS5 listening on %s", s.config.SocksListen)

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleSocksConn(c)
	}
}

func (s *Splitter) handleSocksConn(clientConn net.Conn) {
	defer clientConn.Close()

	// --- SOCKS5 negotiation ---
	// Read [0x05, NMETHODS]
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, hdr); err != nil {
		return
	}
	nMethods := int(hdr[1])
	if nMethods > 0 {
		methods := make([]byte, nMethods)
		io.ReadFull(clientConn, methods)
	}
	// Write [0x05, 0x00] (no auth required)
	clientConn.Write([]byte{0x05, 0x00})

	// --- SOCKS5 CONNECT request ---
	// Read [0x05, 0x01, 0x00, ATYP]
	req := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, req); err != nil {
		return
	}
	atyp := req[3]

	// Read destination
	dest, err := session.ReadDestinationEx(clientConn, atyp)
	if err != nil {
		s.logger.Printf("SOCKS5 dest: %v", err)
		return
	}
	s.logger.Printf("User SOCKS5 CONNECT → %s:%d", dest.Addr, dest.Port)

	// --- Create session ---
	rawSid, err := session.GenerateSessionID()
	if err != nil {
		return
	}
	var sid session.SessionID
	copy(sid[:], rawSid)

	ctx, cancel := context.WithCancel(context.Background())
	sess := &session.Session{
		ID:     sid,
		Dest:   dest,
		Ctx:    ctx,
		Cancel: cancel,
	}
	s.store.Add(sid, sess)
	s.metrics.incSession()

	// Wait for up-carrier session
	s.mu.RLock()
	upS := s.upSession
	downS := s.downSession
	s.mu.RUnlock()

	if upS == nil || downS == nil {
		s.logger.Printf("No carrier sessions available")
		cancel()
		s.store.Remove(sid)
		s.metrics.decSession()
		return
	}

	// Open yamux stream on up-carrier (to Germany via CDN)
	upStream, err := upS.OpenStream()
	if err != nil {
		s.logger.Printf("Open up-stream: %v", err)
		cancel()
		s.store.Remove(sid)
		s.metrics.decSession()
		return
	}

	// Write sessionID (16 bytes) + destination header
	headerBuf := make([]byte, session.SessionIDLen+session.MaxHeaderSize)
	copy(headerBuf[:session.SessionIDLen], sid[:])
	n := session.WriteDestinationBuffer(headerBuf[session.SessionIDLen:], dest)
	if n <= 0 {
		s.logger.Printf("Failed to encode destination")
		upStream.Close()
		cancel()
		s.store.Remove(sid)
		s.metrics.decSession()
		return
	}
	upStream.Write(headerBuf[:session.SessionIDLen+n])

	// Relay: client → up-stream (upload direction)
	go func() {
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := clientConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.logger.Printf("Client read: %v", err)
				}
				cancel()
				return
			}
			if n > 0 {
				s.metrics.incUp(int64(n))
				upStream.Write(buf[:n])
			}
		}
	}()

	// Wait for session to end
	<-ctx.Done()
	s.logger.Printf("Session %s ended", sid.String())
	upStream.Close()
	s.store.Remove(sid)
	s.metrics.decSession()
}

// ============================================================
// Metrics
// ============================================================

func (s *Splitter) runMetrics(addr string) error {
	mhttp := http.NewServeMux()
	mhttp.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s.metrics.mu.Lock()
		fmt.Fprintf(w, "active_sessions %d\ntotal_sessions %d\ntotal_bytes_up %d\ntotal_bytes_down %d\nerrors %d\n",
			s.metrics.activeSessions, s.metrics.totalSessions,
			s.metrics.totalBytesUp, s.metrics.totalBytesDown, s.metrics.errors)
		s.metrics.mu.Unlock()
		fmt.Fprintf(w, "session_count %d\n", s.store.Count())
	})
	return http.ListenAndServe(addr, mhttp)
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
