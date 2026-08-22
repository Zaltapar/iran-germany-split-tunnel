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

type wsConn struct {
	conn   *websocket.Conn
	reader io.Reader
}

func (w *wsConn) Read(p []byte) (int, error) {
	for {
		if w.reader == nil {
			_, r, err := w.conn.NextReader()
			if err != nil {
				return 0, err
			}
			w.reader = r
		}
		n, err := w.reader.Read(p)
		if err == io.EOF {
			w.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (w *wsConn) Write(p []byte) (int, error) {
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) Close() error { return w.conn.Close() }

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

type Splitter struct {
	config      *Config
	store       *session.SessionStore
	metrics     *Metrics
	logger      *log.Logger
	secret      []byte
	mu          sync.RWMutex
	upSession   *yamux.Session
	downSession *yamux.Session
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
	if v := os.Getenv("SPLIT_SOCKS_LISTEN"); v != "" { cfg.SocksListen = v }
	if v := os.Getenv("SPLIT_WS_LISTEN"); v != "" { cfg.WsListen = v }
	if v := os.Getenv("SPLIT_DOWN_CARRIER_ADDR"); v != "" { cfg.DownCarrierAddr = v }
	if v := os.Getenv("SPLIT_SECRET"); v != "" { cfg.Secret = v }
	if v := os.Getenv("SPLIT_METRICS_PORT"); v != "" { cfg.MetricsPort = parseInt(v) }
	if v := os.Getenv("SPLIT_RELAY_BUF"); v != "" { cfg.RelayBufSize = parseInt(v) }

	derived := mux.DeriveSecret(cfg.Secret)
	s := &Splitter{
		config: cfg, store: session.NewSessionStore(), metrics: &Metrics{},
		logger: log.New(os.Stderr, "[iran-splitter] ", log.LstdFlags), secret: derived,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup

	if cfg.MetricsPort > 0 {
		wg.Add(1)
		go func() { defer wg.Done(); s.runMetrics(fmt.Sprintf("127.0.0.1:%d", cfg.MetricsPort)) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); s.runUpCarrier(&wg) }()
	wg.Add(1)
	go func() { defer wg.Done(); s.runSocksServer() }()
	wg.Add(1)
	go func() { defer wg.Done(); s.runDownCarrier(&wg) }()

	s.logger.Printf("SOCKS5: %s | WS: %s | Down → %s", cfg.SocksListen, cfg.WsListen, cfg.DownCarrierAddr)
	s.logger.Println("iran-splitter started")
	<-sigCh
	s.logger.Println("Shutting down...")
	s.store.CloseAll()
	s.mu.RLock()
	if s.upSession != nil { s.upSession.Close() }
	if s.downSession != nil { s.downSession.Close() }
	s.mu.RUnlock()
	wg.Wait()
	s.logger.Println("iran-splitter stopped")
}

func (s *Splitter) runUpCarrier(wg *sync.WaitGroup) {
	upgrader := websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096, CheckOrigin: func(r *http.Request) bool { return true }}
	muxHTTP := http.NewServeMux()
	muxHTTP.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil { s.logger.Printf("WS upgrade failed from %s: %v", r.RemoteAddr, err); return }
		s.logger.Printf("Up-carrier WS connected from %s", r.RemoteAddr)
		s.handleUpWsConn(wsConn)
		s.logger.Printf("Up-carrier WS disconnected from %s", r.RemoteAddr)
	})
	ln, err := net.Listen("tcp", s.config.WsListen)
	if err != nil { s.logger.Fatalf("WS listener: %v", err) }
	defer ln.Close()
	s.logger.Printf("WS server listening on %s", s.config.WsListen)
	if err := http.Serve(ln, muxHTTP); err != nil && err != http.ErrServerClosed { s.logger.Printf("WS server error: %v", err) }
}

func (s *Splitter) handleUpWsConn(ws *websocket.Conn) {
	wsc := &wsConn{conn: ws}
	var lenBuf [4]byte
	if _, err := io.ReadFull(wsc, lenBuf[:]); err != nil { wsc.Close(); return }
	secretLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if secretLen != 32 { wsc.Close(); return }
	secretPayload := make([]byte, 32)
	if _, err := io.ReadFull(wsc, secretPayload); err != nil { wsc.Close(); return }
	if !mux.ValidateSecret(secretPayload, s.secret) { wsc.Close(); return }
	wsc.Write([]byte{0x00})
	s.logger.Printf("Up-carrier authenticated from %s", ws.RemoteAddr())

	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = true
	yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
	yamuxSession, err := yamux.Server(wsc, yamuxCfg)
	if err != nil { wsc.Close(); return }
	s.mu.Lock()
	s.upSession = yamuxSession
	s.mu.Unlock()
	s.logger.Printf("Up-carrier yamux session established")

	go func() {
		for {
			stream, err := yamuxSession.AcceptStream()
			if err != nil { yamuxSession.Close(); return }
			go s.handleUpStream(stream)
		}
	}()
	<-yamuxSession.CloseChan()
	s.logger.Printf("Up-carrier yamux session closed")
	s.mu.Lock()
	if s.upSession == yamuxSession { s.upSession = nil }
	s.mu.Unlock()
}

func (s *Splitter) handleUpStream(stream *yamux.Stream) {
	defer stream.Close()
	buf := make([]byte, 1460)
	for { _, err := stream.Read(buf); err != nil { return } }
}

func (s *Splitter) runDownCarrier(wg *sync.WaitGroup) {
	for {
		conn, err := net.DialTimeout("tcp", s.config.DownCarrierAddr, 10*time.Second)
		if err != nil { time.Sleep(5 * time.Second); continue }
		s.logger.Printf("Down-carrier connected to %s", s.config.DownCarrierAddr)
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, 32)
		if _, err := conn.Write(append(prefix, s.secret...)); err != nil { conn.Close(); time.Sleep(2 * time.Second); continue }
		ack := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, ack); err != nil || ack[0] != 0x00 { conn.Close(); time.Sleep(2 * time.Second); continue }
		s.logger.Printf("Down-carrier authenticated")

		yamuxCfg := yamux.DefaultConfig()
		yamuxCfg.EnableKeepAlive = true
		yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
		yamuxSession, err := yamux.Server(conn, yamuxCfg)
		if err != nil { conn.Close(); time.Sleep(2 * time.Second); continue }
		s.mu.Lock()
		if s.downSession != nil { s.downSession.Close() }
		s.downSession = yamuxSession
		s.mu.Unlock()
		s.logger.Printf("Down-carrier yamux session established")

		go func() {
			for {
				stream, err := yamuxSession.AcceptStream()
				if err != nil { yamuxSession.Close(); return }
				go s.handleDownStream(stream)
			}
		}()
		<-yamuxSession.CloseChan()
		s.logger.Printf("Down-carrier yamux session closed")
		s.mu.Lock()
		if s.downSession == yamuxSession { s.downSession = nil }
		s.mu.Unlock()
		time.Sleep(3 * time.Second)
	}
}

func (s *Splitter) handleDownStream(stream *yamux.Stream) {
	defer stream.Close()
	sidBuf := make([]byte, session.SessionIDLen)
	if _, err := io.ReadFull(stream, sidBuf); err != nil { return }
	var sid session.SessionID
	copy(sid[:], sidBuf)
	sess, ok := s.store.GetSession(sid)
	if !ok { return }
	buf := make([]byte, s.config.RelayBufSize)
	for {
		n, err := stream.Read(buf)
		if err != nil { return }
		if n > 0 { s.metrics.incDown(int64(n)); sess.ClientConn.Write(buf[:n]) }
	}
}

func (s *Splitter) runSocksServer() {
	ln, err := net.Listen("tcp", s.config.SocksListen)
	if err != nil { s.logger.Fatalf("SOCKS5: %v", err) }
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil { continue }
		go s.handleSocksConn(c)
	}
}

func (s *Splitter) handleSocksConn(clientConn net.Conn) {
	defer clientConn.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, hdr); err != nil { return }
	nMethods := int(hdr[1])
	if nMethods > 0 { methods := make([]byte, nMethods); io.ReadFull(clientConn, methods) }
	clientConn.Write([]byte{0x05, 0x00})
	req := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, req); err != nil { return }
	atyp := req[3]
	dest, err := session.ReadDestinationEx(clientConn, atyp)
	if err != nil { return }
	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil { return }
	s.logger.Printf("User SOCKS5 CONNECT → %s:%d", dest.Addr, dest.Port)
	rawSid, err := session.GenerateSessionID()
	if err != nil { return }
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
	if upS == nil || downS == nil { cancel(); s.store.Remove(sid); s.metrics.decSession(); return }
	upStream, err := upS.OpenStream()
	if err != nil { cancel(); s.store.Remove(sid); s.metrics.decSession(); return }
	headerBuf := make([]byte, session.SessionIDLen+session.MaxHeaderSize)
	copy(headerBuf[:session.SessionIDLen], sid[:])
	n := session.WriteDestinationBuffer(headerBuf[session.SessionIDLen:], dest)
	if n <= 0 { upStream.Close(); cancel(); s.store.Remove(sid); s.metrics.decSession(); return }
	upStream.Write(headerBuf[:session.SessionIDLen+n])
	go func() {
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := clientConn.Read(buf)
			if err != nil { cancel(); return }
			if n > 0 { s.metrics.incUp(int64(n)); upStream.Write(buf[:n]) }
		}
	}()
	<-ctx.Done()
	upStream.Close()
	s.store.Remove(sid)
	s.metrics.decSession()
}

func (s *Splitter) runMetrics(addr string) error {
	mhttp := http.NewServeMux()
	mhttp.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s.metrics.mu.Lock()
		fmt.Fprintf(w, "active_sessions %d\ntotal_sessions %d\ntotal_bytes_up %d\ntotal_bytes_down %d\nerrors %d\n",
			s.metrics.activeSessions, s.metrics.totalSessions, s.metrics.totalBytesUp, s.metrics.totalBytesDown, s.metrics.errors)
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
