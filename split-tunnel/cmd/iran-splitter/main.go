package main

import (
	"context"
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
// websocket.io wrappers
// ============================================================

type wsReadWriteCloser struct {
	conn *websocket.Conn
}

func (w *wsReadWriteCloser) Read(p []byte) (int, error) {
	_, msg, err := w.conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	n := len(msg)
	if n > len(p) {
		n = len(p)
	}
	copy(p, msg[:n])
	return n, nil
}

func (w *wsReadWriteCloser) Write(p []byte) (int, error) {
	err := w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsReadWriteCloser) Close() error { return w.conn.Close() }

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
	metricsAddr string
	upSession   *yamux.Session // WS up-carrier (to Germany)
	downSession *yamux.Session // TCP down-carrier (to Germany)
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

	// --- Up-carrier: WS server from CDN ---
	wg.Add(1)
	go func() { defer wg.Done(); s.runWsServer(&wg) }()

	// --- SOCKS5 server for user connections ---
	wg.Add(1)
	go func() { defer wg.Done(); s.runSocksServer() }()

	// --- Down-carrier: dial local Xray (VLESS tunnel to Germany) ---
	dcConn, err := net.DialTimeout("tcp", cfg.DownCarrierAddr, 10*time.Second)
	if err != nil {
		s.logger.Fatalf("Down-carrier dial failed: %v", err)
	}
	s.logger.Printf("Down-carrier connected to %s", cfg.DownCarrierAddr)

	// Auth: send secret, read ACK
	_, err = dcConn.Write(append([]byte{0x00, 0x00, 0x00, 32}, derived...))
	if err != nil {
		s.logger.Printf("Down-carrier auth send: %v", err)
	} else {
		buf := make([]byte, 1)
		dcConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(dcConn, buf); err != nil || buf[0] != 0 {
			s.logger.Printf("Down-carrier auth ACK: got type byte %v", buf)
		} else {
			s.logger.Printf("Down-carrier authenticated")
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runDownCarrierSession(dcConn)
	}()

	s.logger.Printf("SOCKS5: %s | WS: %s | Down → %s", cfg.SocksListen, cfg.WsListen, cfg.DownCarrierAddr)
	s.logger.Println("iran-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")
	s.store.CloseAll()
	if s.upSession != nil {
		s.upSession.Close()
	}
	if s.downSession != nil {
		s.downSession.Close()
	}
	wg.Wait()
	s.logger.Println("iran-splitter stopped")
}

// ---- Up-carrier: WS server (CDN/Nginx sends upload data) ----

func (s *Splitter) runWsServer(wg *sync.WaitGroup) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			s.logger.Printf("WS upgrade: %v", err)
			return
		}
		s.logger.Printf("Up-carrier WS connected from %s", r.RemoteAddr)
		s.handleUpCarrierConn(conn)
		s.logger.Printf("Up-carrier WS disconnected from %s", r.RemoteAddr)
	})

	ln, err := net.Listen("tcp", s.config.WsListen)
	if err != nil {
		s.logger.Fatalf("WS listener: %v", err)
	}
	defer ln.Close()

	s.logger.Printf("WS server listening on %s", s.config.WsListen)
	if err := http.Serve(ln, nil); err != nil && err != http.ErrServerClosed {
		s.logger.Printf("WS server: %v", err)
	}
}

func (s *Splitter) handleUpCarrierConn(wsConn *websocket.Conn) {
	wsc := &wsReadWriteCloser{conn: wsConn}

	// Auth: read secret, validate
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(wsc, hdr); err != nil {
		return
	}
	sl := int(hdr[2])<<8 | int(hdr[3])
	secretPayload := make([]byte, sl)
	if _, err := io.ReadFull(wsc, secretPayload); err != nil {
		return
	}
	if !mux.ValidateSecret(secretPayload, s.secret) {
		s.logger.Printf("Up-carrier auth rejected for %s", wsConn.RemoteAddr())
		wsc.Close()
		return
	}
	// Auth ACK
	wsc.Write([]byte{0x00, 0x00, 0x00, 1, 0x00})

	// Create yamux session (we are server; CDN is client)
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = true
	yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
	yamuxSession, err := yamux.Server(wsc, yamuxCfg)
	if err != nil {
		s.logger.Printf("Up-carrier yamux server: %v", err)
		return
	}

	s.logger.Printf("Up-carrier yamux session established")

	s.mu.Lock()
	s.upSession = yamuxSession
	s.mu.Unlock()

	// Accept streams
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

	// Keepalive
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

func (s *Splitter) handleUpStream(stream *yamux.Stream) {
	defer stream.Close()

	// Read sessionID (16 bytes) first
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

	s.logger.Printf("Up-stream: session %s → %s:%d", sid.String(), dest.Addr, dest.Port)

	ctx, cancel := context.WithCancel(context.Background())
	sess := &session.Session{ID: sid, Dest: dest, Ctx: ctx, Cancel: cancel}
	s.store.Add(sid, sess)
	s.metrics.incSession()

	// Relay: upStream → client (upload data from user → internet)
	go func() {
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.logger.Printf("UpStream read: %v", err)
				}
				cancel()
				return
			}
			if n > 0 {
				s.metrics.incUp(int64(n))
				sess.ClientConn.Write(buf[:n])
			}
		}
	}()

	<-ctx.Done()
	s.logger.Printf("Session %s ended", sid.String())
	s.store.Remove(sid)
	s.metrics.decSession()
}

// ---- Down-carrier: TCP (Xray tunnel to Germany) ----

func (s *Splitter) runDownCarrierSession(dcConn net.Conn) {
	defer dcConn.Close()

	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = true
	yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
	yamuxSession, err := yamux.Client(dcConn, yamuxCfg)
	if err != nil {
		s.logger.Printf("Down-carrier yamux client: %v", err)
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

// ---- SOCKS5 Server (user connections from Xray) ----

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
		go s.handleSocksConnection(c)
	}
}

func (s *Splitter) handleSocksConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// SOCKS5 negotiation
	hdr := make([]byte, 3)
	if _, err := io.ReadFull(clientConn, hdr); err != nil {
		return
	}
	nm := int(hdr[1])
	if nm > 0 {
		methods := make([]byte, nm)
		io.ReadFull(clientConn, methods)
	}
	// SOCKS5 success: 10-byte response (version 5, no auth, IPv4 0.0.0.0:0)
	successReply := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	clientConn.Write(successReply)

	// SOCKS5 CONNECT request
	req := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, req); err != nil {
		return
	}
	atype := req[3]

	dest, err := session.ReadDestinationEx(clientConn, atype)
	if err != nil {
		s.logger.Printf("SOCKS5 dest: %v", err)
		return
	}
	s.logger.Printf("User CONNECT → %s:%d", dest.Addr, dest.Port)

	rawSid, err := session.GenerateSessionID()
	if err != nil {
		return
	}
	var sid session.SessionID
	copy(sid[:], rawSid)

	ctx, cancel := context.WithCancel(context.Background())
	sess := &session.Session{ID: sid, Dest: dest, ClientConn: clientConn, Ctx: ctx, Cancel: cancel}
	s.store.Add(sid, sess)
	s.metrics.incSession()

	s.mu.RLock()
	upS := s.upSession
	downS := s.downSession
	s.mu.RUnlock()

	if upS == nil || downS == nil {
		cancel()
		s.store.Remove(sid)
		s.metrics.decSession()
		return
	}

	// Open up-stream (upload to Germany via CDN)
	upStream, err := upS.OpenStream()
	if err != nil {
		s.logger.Printf("Open up-stream: %v", err)
		cancel()
		s.store.Remove(sid)
		s.metrics.decSession()
		return
	}

	// Open down-stream (download from Germany via direct tunnel)
	downStream, err := downS.OpenStream()
	if err != nil {
		s.logger.Printf("Open down-stream: %v", err)
		cancel()
		s.store.Remove(sid)
		s.metrics.decSession()
		return
	}

	sess.UpStream = upStream
	sess.DownStream = downStream

	// Write session header: sessionID (16) + dest header (variable)
	headerBuf := make([]byte, session.SessionIDLen+session.MaxHeaderSize)
	copy(headerBuf[:session.SessionIDLen], sid[:])
	n := session.WriteDestinationBuffer(headerBuf[session.SessionIDLen:], dest)
	if n > 0 {
		upStream.Write(headerBuf[:session.SessionIDLen+n])
	}

	// Relay: client → up-stream (upload)
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

	// Relay: down-stream → client (download)
	go func() {
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := downStream.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.logger.Printf("DownStream read: %v", err)
				}
				cancel()
				return
			}
			if n > 0 {
				s.metrics.incDown(int64(n))
				clientConn.Write(buf[:n])
			}
		}
	}()

	<-ctx.Done()
	s.logger.Printf("Session %s ended", sid.String())
	upStream.Close()
	downStream.Close()
	s.store.Remove(sid)
	s.metrics.decSession()
}

// ---- Metrics ----

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
