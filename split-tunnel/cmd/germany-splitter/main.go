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

// ============================================================
// Config & Metrics
// ============================================================

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
	upSession   *yamux.Session // WS client (to CDN)
	downSession *yamux.Session // TCP client (to Iran on :9002)
}

type SessionEntry struct {
	DestConn net.Conn
	Dest     *session.Destination
	Done     chan struct{}
}

func main() {
	cfg := &Config{
		UpWsUrl:           "wss://cdn.example.com/upload",
		DownListen:        ":9002",
		KeepAliveInterval: 30 * time.Second,
		RelayBufSize:      32768,
	}

	if v := os.Getenv("SPLIT_UP_WS_URL"); v != "" {
		cfg.UpWsUrl = v
	}
	if v := os.Getenv("SPLIT_DOWN_LISTEN"); v != "" {
		cfg.DownListen = v
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

	// --- Up-Carrier: WebSocket client → CDN ---
	wg.Add(1)
	go func() { defer wg.Done(); s.runUpCarrier(&wg) }()

	// --- Down-Carrier: TCP server (accept from Iran) ---
	wg.Add(1)
	go func() { defer wg.Done(); s.runDownCarrier() }()

	s.logger.Printf("Up-carrier (WS) dial: %s", cfg.UpWsUrl)
	s.logger.Printf("Down-carrier (TCP) listen: %s", cfg.DownListen)
	s.logger.Println("germany-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")
	s.cleanupAll()
	s.mu.RLock()
	if s.upSession != nil {
		s.upSession.Close()
	}
	if s.downSession != nil {
		s.downSession.Close()
	}
	s.mu.RUnlock()
	wg.Wait()
	s.logger.Println("germany-splitter stopped")
}

// ============================================================
// Up-Carrier: WebSocket client dialing CDN (SPLIT_UP_WS_URL)
// ============================================================

func (s *Splitter) runUpCarrier(wg *sync.WaitGroup) {
	for {
		conn, _, err := websocket.DefaultDialer.Dial(s.config.UpWsUrl, nil)
		if err != nil {
			s.logger.Printf("Up-carrier dial %s: %v (retrying in 5s)", s.config.UpWsUrl, err)
			time.Sleep(5 * time.Second)
			continue
		}
		s.logger.Printf("Up-carrier WS connected to CDN")

		wsc := &wsReadWriteCloser{conn: conn}

		// Auth: send 32-byte secret with 4-byte length prefix
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, 32)
		if _, err := wsc.Write(append(prefix, s.secret...)); err != nil {
			s.logger.Printf("Up-carrier auth send: %v (retrying in 2s)", err)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		ack := make([]byte, 1)
		if _, err := io.ReadFull(wsc, ack); err != nil || ack[0] != 0x00 {
			s.logger.Printf("Up-carrier auth ACK failed")
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		s.logger.Printf("Up-carrier authenticated")

		// Wrap in yamux.Client (we are client)
		yamuxCfg := yamux.DefaultConfig()
		yamuxCfg.EnableKeepAlive = true
		yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
		yamuxSession, err := yamux.Client(wsc, yamuxCfg)
		if err != nil {
			s.logger.Printf("Up-carrier yamux client: %v", err)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		s.mu.Lock()
		if s.upSession != nil {
			s.upSession.Close()
		}
		s.upSession = yamuxSession
		s.mu.Unlock()
		s.logger.Printf("Up-carrier yamux session established")

		// Accept upload streams from Iran via CDN
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
		conn.Close()
		time.Sleep(3 * time.Second)
	}
}

// handleUpStream: received from Iran via CDN - contains sessionID + dest header
func (s *Splitter) handleUpStream(stream *yamux.Stream) {
	defer stream.Close()

	// Read 16-byte SessionID
	sidBuf := make([]byte, session.SessionIDLen)
	if _, err := io.ReadFull(stream, sidBuf); err != nil {
		s.logger.Printf("UpStream read sessionID: %v", err)
		return
	}
	var sid session.SessionID
	copy(sid[:], sidBuf)

	// Read destination header
	hdr := make([]byte, session.MaxHeaderSize)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		s.logger.Printf("UpStream read dest: %v", err)
		return
	}
	dest := session.ParseDestinationFromBuf(hdr)
	if dest == nil {
		s.logger.Printf("UpStream invalid dest")
		return
	}

	addr := fmt.Sprintf("%s:%d", dest.Addr, dest.Port)
	s.logger.Printf("New session %s -> %s", sid.String(), addr)

	// Dial target destination
	destConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		s.logger.Printf("Dial %s: %v", addr, err)
		s.metrics.incErr()
		return
	}
	s.logger.Printf("Session %s destination connected", sid.String())

	// Create entry with defer cleanup
	entry := &SessionEntry{DestConn: destConn, Dest: dest}
	s.mu.Lock()
	s.store[sid] = entry
	s.mu.Unlock()
	s.metrics.incSession()

	// Relay: stream (upload from Iran) -> destConn
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

	// Relay: destConn (download from internet) -> down-carrier yamux stream
	// Wait for down-carrier session to be ready
	var downStream *yamux.Stream
	for s.downSession == nil {
		time.Sleep(100 * time.Millisecond)
	}
	downStream, err = s.downSession.OpenStream()
	if err != nil {
		s.logger.Printf("Open down-stream: %v", err)
		destConn.Close()
		return
	}
	defer downStream.Close()

	// Write sessionID (16 bytes) first
	downStream.Write(sid[:])

	// Relay: destConn -> down-stream
	go func() {
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := destConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.logger.Printf("DestConn read: %v", err)
				}
				downStream.Close()
				return
			}
			if n > 0 {
				s.metrics.incDown(int64(n))
				downStream.Write(buf[:n])
			}
		}
	}()

	// Defer cleanup: remove session and close destination when stream ends
	defer func() {
		s.mu.Lock()
		delete(s.store, sid)
		s.mu.Unlock()
		s.metrics.decSession()
		destConn.Close()
	}()
}

// ============================================================
// Down-Carrier: TCP server (accepts connections from Iran on :9002)
// ============================================================

func (s *Splitter) runDownCarrier() {
	ln, err := net.Listen("tcp", s.config.DownListen)
	if err != nil {
		s.logger.Fatalf("Down-carrier listener: %v", err)
	}
	defer ln.Close()
	s.logger.Printf("Down-carrier listening on %s", s.config.DownListen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleDownCarrierConn(conn)
	}
}

func (s *Splitter) handleDownCarrierConn(rawConn net.Conn) {
	// Auth: read 4-byte length prefix + 32-byte secret
	var lenBuf [4]byte
	if _, err := io.ReadFull(rawConn, lenBuf[:]); err != nil {
		s.logger.Printf("Down-carrier auth read: %v", err)
		rawConn.Close()
		return
	}
	secretLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if secretLen != 32 {
		s.logger.Printf("Down-carrier auth bad length %d", secretLen)
		rawConn.Close()
		return
	}
	secretPayload := make([]byte, 32)
	if _, err := io.ReadFull(rawConn, secretPayload); err != nil {
		s.logger.Printf("Down-carrier auth read secret: %v", err)
		rawConn.Close()
		return
	}
	if !mux.ValidateSecret(secretPayload, s.secret) {
		s.logger.Printf("Down-carrier auth rejected from %s", rawConn.RemoteAddr())
		rawConn.Close()
		return
	}
	// Auth ACK
	rawConn.Write([]byte{0x00})
	s.logger.Printf("Down-carrier authenticated from %s", rawConn.RemoteAddr())

	// Wrap in yamux.Client (we are client)
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.EnableKeepAlive = true
	yamuxCfg.KeepAliveInterval = s.config.KeepAliveInterval
	yamuxSession, err := yamux.Client(rawConn, yamuxCfg)
	if err != nil {
		s.logger.Printf("Down-carrier yamux client: %v", err)
		rawConn.Close()
		return
	}

	s.mu.Lock()
	s.downSession = yamuxSession
	s.mu.Unlock()
	s.logger.Printf("Down-carrier yamux session established")

	<-yamuxSession.CloseChan()
	s.logger.Printf("Down-carrier yamux session closed")
	s.mu.Lock()
	if s.downSession == yamuxSession {
		s.downSession = nil
	}
	s.mu.Unlock()
}

// ============================================================
// Cleanup
// ============================================================

func (s *Splitter) cleanupAll() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.store {
		if entry.DestConn != nil {
			entry.DestConn.Close()
		}
	}
}

// ============================================================
// WebSocket io.ReadWriteCloser wrapper (streaming NextReader)
// ============================================================

type wsReadWriteCloser struct {
	conn   *websocket.Conn
	reader io.Reader
}

func (w *wsReadWriteCloser) Read(p []byte) (int, error) {
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

func (w *wsReadWriteCloser) Write(p []byte) (int, error) {
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsReadWriteCloser) Close() error { return w.conn.Close() }

// ============================================================
// Metrics
// ============================================================

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
