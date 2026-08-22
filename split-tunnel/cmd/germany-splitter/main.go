package main

import (
	"encoding/binary"
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
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

type Config struct {
	UpWsUrl           string
	DownListen        string
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
	store       map[session.SessionID]*SessionEntry
	mu          sync.RWMutex
	metrics     *Metrics
	logger      *log.Logger
	secret      []byte
	upSession   *yamux.Session
	downSession *yamux.Session
}

type SessionEntry struct {
	DestConn net.Conn
	Dest     *session.Destination
	Done     chan struct{}
}

func main() {
	cfg := &Config{
		UpWsUrl: "wss://cdn.example.com/upload", DownListen: ":9002",
		KeepAliveInterval: 30 * time.Second, RelayBufSize: 32768,
	}
	if v := os.Getenv("SPLIT_UP_WS_URL"); v != "" { cfg.UpWsUrl = v }
	if v := os.Getenv("SPLIT_DOWN_LISTEN"); v != "" { cfg.DownListen = v }
	if v := os.Getenv("SPLIT_SECRET"); v != "" { cfg.Secret = v } else { cfg.Secret = "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING" }
	if v := os.Getenv("SPLIT_METRICS_PORT"); v != "" { cfg.MetricsPort = parseInt(v) }
	if v := os.Getenv("SPLIT_RELAY_BUF"); v != "" { cfg.RelayBufSize = parseInt(v) }

	derived := mux.DeriveSecret(cfg.Secret)
	s := &Splitter{
		config: cfg, store: make(map[session.SessionID]*SessionEntry),
		metrics: &Metrics{}, logger: log.New(os.Stderr, "[germany-splitter] ", log.LstdFlags), secret: derived,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.runUpCarrier(&wg) }()
	wg.Add(1)
	go func() { defer wg.Done(); s.runDownCarrier() }()

	s.logger.Printf("Up-carrier (WS) dial: %s", cfg.UpWsUrl)
	s.logger.Printf("Down-carrier (TCP) listen: %s", cfg.DownListen)
	s.logger.Println("germany-splitter started")
	<-sigCh
	s.logger.Println("Shutting down...")
	s.cleanupAll()
	s.mu.RLock()
	if s.upSession != nil { s.upSession.Close() }
	if s.downSession != nil { s.downSession.Close() }
	s.mu.RUnlock()
	wg.Wait()
	s.logger.Println("germany-splitter stopped")
}

func (s *Splitter) runUpCarrier(wg *sync.WaitGroup) {
	for {
		conn, _, err := websocket.DefaultDialer.Dial(s.config.UpWsUrl, nil)
		if err != nil { s.logger.Printf("Up-carrier dial %s: %v (retrying in 5s)", s.config.UpWsUrl, err); time.Sleep(5 * time.Second); continue }
		s.logger.Printf("Up-carrier WS connected to CDN")
		wsc := &wsReadWriteCloser{conn: conn}
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, 32)
		if _, err := wsc.Write(append(prefix, s.secret...)); err != nil { conn.Close(); time.Sleep(2 * time.Second); continue }
		ack := make([]byte, 1)
		if _, err := io.ReadFull(wsc, ack); err != nil || ack[0] != 0x00 { conn.Close(); time.Sleep(2 * time.Second); continue }
		s.logger.Printf("Up-carrier authenticated")
		yamuxCfg := yamux.DefaultConfig()
		yamuxCfg.EnableKeepAlive = true
		yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
		yamuxSession, err := yamux.Client(wsc, yamuxCfg)
		if err != nil { conn.Close(); time.Sleep(2 * time.Second); continue }
		s.mu.Lock()
		if s.upSession != nil { s.upSession.Close() }
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
		conn.Close()
		time.Sleep(3 * time.Second)
	}
}

func (s *Splitter) handleUpStream(stream *yamux.Stream) {
	sidBuf := make([]byte, session.SessionIDLen)
	if _, err := io.ReadFull(stream, sidBuf); err != nil { stream.Close(); return }
	var sid session.SessionID
	copy(sid[:], sidBuf)
	hdr := make([]byte, session.MaxHeaderSize)
	if _, err := io.ReadFull(stream, hdr); err != nil { stream.Close(); return }
	dest := session.ParseDestinationFromBuf(hdr)
	if dest == nil { stream.Close(); return }
	addr := fmt.Sprintf("%s:%d", dest.Addr, dest.Port)
	s.logger.Printf("New session %s -> %s", sid.String(), addr)
	destConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil { stream.Close(); s.logger.Printf("Dial %s: %v", addr, err); s.metrics.incErr(); return }
	s.logger.Printf("Session %s destination connected", sid.String())
	entry := &SessionEntry{DestConn: destConn, Dest: dest}
	s.mu.Lock()
	s.store[sid] = entry
	s.mu.Unlock()
	s.metrics.incSession()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := stream.Read(buf)
			if err != nil { if err != io.EOF { s.logger.Printf("UpStream read: %v", err) }; destConn.Close(); return }
			if n > 0 { s.metrics.incUp(int64(n)); destConn.Write(buf[:n]) }
		}
	}()
	var downStream *yamux.Stream
	for s.downSession == nil { time.Sleep(100 * time.Millisecond) }
	downStream, err = s.downSession.OpenStream()
	if err != nil { destConn.Close(); stream.Close(); wg.Wait(); s.mu.Lock(); delete(s.store, sid); s.mu.Unlock(); s.metrics.decSession(); return }
	downStream.Write(sid[:])
	go func() {
		defer wg.Done()
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := destConn.Read(buf)
			if err != nil { if err != io.EOF { s.logger.Printf("DestConn read: %v", err) }; downStream.Close(); return }
			if n > 0 { s.metrics.incDown(int64(n)); downStream.Write(buf[:n]) }
		}
	}()
	wg.Wait()
	stream.Close()
	downStream.Close()
	destConn.Close()
	s.mu.Lock()
	delete(s.store, sid)
	s.mu.Unlock()
	s.metrics.decSession()
	s.logger.Printf("Session %s cleaned up", sid.String())
}

func (s *Splitter) runDownCarrier() {
	ln, err := net.Listen("tcp", s.config.DownListen)
	if err != nil { s.logger.Fatalf("Down-carrier listener: %v", err) }
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil { continue }
		go s.handleDownCarrierConn(conn)
	}
}

func (s *Splitter) handleDownCarrierConn(rawConn net.Conn) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(rawConn, lenBuf[:]); err != nil { rawConn.Close(); return }
	secretLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if secretLen != 32 { rawConn.Close(); return }
	secretPayload := make([]byte, 32)
	if _, err := io.ReadFull(rawConn, secretPayload); err != nil { rawConn.Close(); return }
	if !mux.ValidateSecret(secretPayload, s.secret) { rawConn.Close(); return }
	rawConn.Write([]byte{0x00})
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = true
	yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
	yamuxSession, err := yamux.Client(rawConn, yamuxCfg)
	if err != nil { rawConn.Close(); return }
	s.mu.Lock()
	s.downSession = yamuxSession
	s.mu.Unlock()
	<-yamuxSession.CloseChan()
	s.mu.Lock()
	if s.downSession == yamuxSession { s.downSession = nil }
	s.mu.Unlock()
}

func (s *Splitter) cleanupAll() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.store {
		if entry.DestConn != nil { entry.DestConn.Close() }
	}
}

type wsReadWriteCloser struct {
	conn   *websocket.Conn
	reader io.Reader
}

func (w *wsReadWriteCloser) Read(p []byte) (int, error) {
	for {
		if w.reader == nil {
			_, r, err := w.conn.NextReader()
			if err != nil { return 0, err }
			w.reader = r
		}
		n, err := w.reader.Read(p)
		if err == io.EOF { w.reader = nil; if n > 0 { return n, nil }; continue }
		return n, err
	}
}

func (w *wsReadWriteCloser) Write(p []byte) (int, error) {
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil { return 0, err }
	return len(p), nil
}

func (w *wsReadWriteCloser) Close() error { return w.conn.Close() }

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
