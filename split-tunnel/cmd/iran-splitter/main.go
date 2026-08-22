package main

import (
	"context"
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
	CarrierAddr  string
	MetricsPort  int
	RelayBufSize int
	Secret       string
	WaitTimeout  int
}

type Metrics struct {
	mu             sync.Mutex
	activeSessions int64
	totalSessions  int64
	totalBytesUp   int64
	totalBytesDown int64
	errors         int64
	activeStreams  int64
}

type Splitter struct {
	config  *Config
	store   *SessionStore
	metrics *Metrics
	logger  *log.Logger
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[session.SessionID]*UserSession
}

type UserSession struct {
	Stream   *mux.Stream
	StreamID uint32
	Dest     *session.Destination
	Ctx      context.Context
	Cancel   context.CancelFunc
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[session.SessionID]*UserSession)}
}

func (ss *SessionStore) Add(id session.SessionID, s *UserSession) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[id] = s
}

func (ss *SessionStore) Remove(id session.SessionID) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[id]
	if ok {
		if s.Stream != nil {
			s.Stream.Close()
		}
		if s.Cancel != nil {
			s.Cancel()
		}
		delete(ss.sessions, id)
	}
}

func (ss *SessionStore) CloseAll() {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	for _, s := range ss.sessions {
		if s.Stream != nil {
			s.Stream.Close()
		}
		if s.Cancel != nil {
			s.Cancel()
		}
	}
}

func (ss *SessionStore) Count() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return len(ss.sessions)
}

func main() {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:10900",
		CarrierAddr:  "germany-server:9000",
		Secret:       "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING",
		RelayBufSize: 32768,
		WaitTimeout:  5000,
	}

	if v := os.Getenv("SPLIT_LISTEN"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("SPLIT_CARRIER"); v != "" {
		cfg.CarrierAddr = v
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

	secret := sha256.Sum256([]byte(cfg.Secret))
	s := &Splitter{
		config:  cfg,
		store:   NewSessionStore(),
		metrics: &Metrics{},
		logger:  log.New(os.Stderr, "[iran-splitter] ", log.LstdFlags),
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

	carrier := mux.NewCarrier(secret[:])

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			s.logger.Printf("Connecting to carrier %s...", cfg.CarrierAddr)
			conn, err := net.DialTimeout("tcp", cfg.CarrierAddr, 10*time.Second)
			if err != nil {
				s.logger.Printf("Carrier connect failed: %v (retrying in 5s)", err)
				time.Sleep(5 * time.Second)
				continue
			}
			s.logger.Printf("Connected to carrier %s", cfg.CarrierAddr)
			carrier.SetConnected(true)
			s.handleCarrier(conn, carrier)
			carrier.SetConnected(false)
			s.logger.Printf("Carrier disconnected, reconnecting in 2s...")
			time.Sleep(2 * time.Second)
		}
	}()

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		s.logger.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	defer ln.Close()

	s.logger.Printf("Listening on %s", cfg.ListenAddr)
	s.logger.Printf("Carrier target: %s", cfg.CarrierAddr)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				s.logger.Printf("Accept error: %v", err)
				continue
			}
			go s.handleConnection(conn, carrier)
		}
	}()

	s.logger.Println("iran-splitter started (mux mode)")
	<-sigCh
	s.logger.Println("Shutting down...")
	s.store.CloseAll()
	wg.Wait()
	s.logger.Println("iran-splitter stopped")
}

func (s *Splitter) handleCarrier(conn net.Conn, carrier *mux.Carrier) {
	authFrame := mux.NewAuthFrame(carrier.Secret())
	if err := mux.WriteFrame(conn, authFrame); err != nil {
		s.logger.Printf("Failed to send auth: %v", err)
		conn.Close()
		return
	}

	respFrame, err := mux.ReadFrame(conn)
	if err != nil {
		s.logger.Printf("Failed to read auth response: %v", err)
		conn.Close()
		return
	}
	if respFrame.Type != mux.FrameAuth || len(respFrame.Payload) < 1 {
		s.logger.Printf("Invalid auth response type: %d", respFrame.Type)
		conn.Close()
		return
	}
	if respFrame.Payload[0] != 0 {
		s.logger.Printf("Auth rejected")
		conn.Close()
		return
	}
	s.logger.Printf("Carrier authenticated")

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
	s.store.mu.RLock()
	for _, sess := range s.store.sessions {
		if sess.StreamID == frame.StreamID {
			s.metrics.incDown(len(frame.Payload))
			if sess.Stream != nil {
				sess.Stream.Write(frame.Payload)
			}
			s.store.mu.RUnlock()
			return
		}
	}
	s.store.mu.RUnlock()
	s.metrics.incErr()
}

func (s *Splitter) keepaliveWriter(conn net.Conn, done chan struct{}) {
	ticker := time.NewTicker(mux.KeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			ping := mux.NewPingFrame()
			mux.WriteFrame(conn, ping)
		}
	}
}

func (s *Splitter) handleConnection(clientConn net.Conn, carrier *mux.Carrier) {
	defer clientConn.Close()

	if !carrier.IsConnected() {
		s.logger.Printf("Carrier not connected, rejecting")
		s.metrics.incErr()
		return
	}

	rawSid := make([]byte, session.SessionIDLen)
	if _, err := io.ReadFull(clientConn, rawSid); err != nil {
		s.logger.Printf("Read session ID: %v", err)
		s.metrics.incErr()
		return
	}

	var sid session.SessionID
	copy(sid[:], rawSid)

	dest, err := session.ReadDestination(clientConn)
	if err != nil {
		s.logger.Printf("Read destination: %v", err)
		s.metrics.incErr()
		return
	}

	s.logger.Printf("Session %s -> %s:%d", sid.String(), dest.Addr, dest.Port)

	ctx, cancel := context.WithCancel(context.Background())
	sess := &UserSession{Dest: dest, Ctx: ctx, Cancel: cancel}
	s.store.Add(sid, sess)
	s.metrics.incSession()
	defer func() {
		s.metrics.decSession()
		s.store.Remove(sid)
		cancel()
	}()

	stream := carrier.OpenStream()
	sess.Stream = stream
	sess.StreamID = stream.ID
	s.metrics.incStream()
	defer func() {
		s.metrics.decStream()
	}()

	destBuf := make([]byte, session.MaxHeaderSize)
	n := session.WriteDestinationBuffer(destBuf, dest)
	if n > 0 {
		stream.Write(destBuf[:n])
	}

	go func() {
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := clientConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.logger.Printf("Client read error: %v", err)
				}
				return
			}
			if n > 0 {
				s.metrics.incUp(n)
				stream.Write(buf[:n])
			}
		}
	}()

	<-ctx.Done()
	s.logger.Printf("Session %s ended", sid.String())
}

func (s *Splitter) runMetrics(addr string) {
	mhttp := http.NewServeMux()
	mhttp.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s.metrics.mu.Lock()
		fmt.Fprintf(w, `active_sessions %d
total_sessions %d
total_bytes_up %d
total_bytes_down %d
active_streams %d
errors %d
`,
			s.metrics.activeSessions,
			s.metrics.totalSessions,
			s.metrics.totalBytesUp,
			s.metrics.totalBytesDown,
			s.metrics.activeStreams,
			s.metrics.errors,
		)
		fmt.Fprintf(w, "session_count %d\n", s.store.Count())
		s.metrics.mu.Unlock()
	})
	s.logger.Printf("Metrics on %s", addr)
	if err := http.ListenAndServe(addr, mhttp); err != nil {
		s.logger.Printf("Metrics server error: %v", err)
	}
}

func (m *Metrics) incSession()       { m.mu.Lock(); m.activeSessions++; m.totalSessions++; m.mu.Unlock() }
func (m *Metrics) decSession()       { m.mu.Lock(); m.activeSessions--; m.mu.Unlock() }
func (m *Metrics) incUp(n int)       { m.mu.Lock(); m.totalBytesUp += int64(n); m.mu.Unlock() }
func (m *Metrics) incDown(n int)     { m.mu.Lock(); m.totalBytesDown += int64(n); m.mu.Unlock() }
func (m *Metrics) incErr()           { m.mu.Lock(); m.errors++; m.mu.Unlock() }
func (m *Metrics) incStream()        { m.mu.Lock(); m.activeStreams++; m.mu.Unlock() }
func (m *Metrics) decStream()        { m.mu.Lock(); m.activeStreams--; m.mu.Unlock() }
func parseInt(s string) int          { var n int; fmt.Sscanf(s, "%d", &n); return n }
