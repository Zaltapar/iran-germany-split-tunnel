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
)

type Config struct {
	ListenAddr   string
	ListenDown   string
	Secret       string
	MetricsPort  int
	RelayBufSize int
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

type StreamEntry struct {
	StreamID uint32
	DestConn net.Conn
	Dest     *session.Destination
	Role     string
	Done     chan struct{}
}

type Splitter struct {
	config         *Config
	store          map[uint32]*StreamEntry
	mu             sync.RWMutex
	metrics        *Metrics
	logger         *log.Logger
	secret         []byte
	upCarrierObj   *mux.Carrier
	downCarrierObj *mux.Carrier
}

func main() {
	cfg := &Config{
		ListenAddr:   ":9001",
		ListenDown:   ":9002",
		Secret:       "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING",
		RelayBufSize: 32768,
		WaitTimeout:  5000,
	}

	if v := os.Getenv("SPLIT_LISTEN"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("SPLIT_LISTEN_DOWN"); v != "" {
		cfg.ListenDown = v
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
	if v := os.Getenv("SPLIT_WAIT_TIMEOUT"); v != "" {
		cfg.WaitTimeout = parseInt(v)
	}

	derived := mux.DeriveSecret(cfg.Secret)
	s := &Splitter{
		config:         cfg,
		store:          make(map[uint32]*StreamEntry),
		metrics:        &Metrics{},
		logger:         log.New(os.Stderr, "[germany-splitter] ", log.LstdFlags),
		secret:         derived,
		upCarrierObj:   mux.NewCarrier(derived),
		downCarrierObj: mux.NewCarrier(derived),
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup

	if cfg.MetricsPort > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.runMetrics(fmt.Sprintf("127.0.0.1:%d", cfg.MetricsPort)); err != nil {
				s.logger.Printf("Metrics: %v", err)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runListener("up", cfg.ListenAddr, s.upCarrierObj)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runListener("down", cfg.ListenDown, s.downCarrierObj)
	}()

	s.logger.Printf("Germany-splitter listening on %s (up) and %s (down)", cfg.ListenAddr, cfg.ListenDown)
	s.logger.Println("germany-splitter started (dual-carrier mux mode)")

	<-sigCh
	s.logger.Println("Shutting down...")
	s.cleanupAll()
	wg.Wait()
	s.logger.Println("germany-splitter stopped")
}

func (s *Splitter) runListener(role, addr string, carrier *mux.Carrier) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Fatalf("[%s] Failed to listen on %s: %v", role, addr, err)
	}
	defer ln.Close()
	s.logger.Printf("[%s] Listening on %s", role, addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.logger.Printf("[%s] Accept error: %v", role, err)
			continue
		}
		go s.handleCarrierConn(role, conn, carrier)
	}
}

func (s *Splitter) handleCarrierConn(role string, rawConn net.Conn, carrier *mux.Carrier) {
	defer rawConn.Close()
	s.logger.Printf("[%s] Connection from %s", role, rawConn.RemoteAddr())

	frame, err := mux.ReadFrame(rawConn)
	if err != nil {
		s.logger.Printf("[%s] Read auth: %v", role, err)
		return
	}
	if frame.Type != mux.FrameAuth {
		s.logger.Printf("[%s] Expected auth, got type %d", role, frame.Type)
		return
	}
	if !mux.ValidateSecret(frame.Payload, s.secret) {
		s.logger.Printf("[%s] Auth rejected for %s", role, rawConn.RemoteAddr())
		return
	}
	mux.WriteFrame(rawConn, mux.NewPongFrame())
	s.logger.Printf("[%s] Authenticated: %s", role, rawConn.RemoteAddr())

	cc := mux.NewCarrierConn(rawConn, carrier)
	var done chan struct{}
	var wg sync.WaitGroup
	done = make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.readFrames(role, cc)
	}()
	<-done
	close(done)
	wg.Wait()
	s.logger.Printf("[%s] Disconnected: %s", role, rawConn.RemoteAddr())
}

func (s *Splitter) readFrames(role string, cc *mux.CarrierConn) {
	for {
		frame, err := mux.ReadFrame(cc)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("[%s] Read frame error: %v", role, err)
			}
			return
		}
		switch frame.Type {
		case mux.FrameData:
			s.handleDataFrame(role, frame, cc)
		case mux.FramePing:
			cc.Send(mux.NewPongFrame())
		}
	}
}

func (s *Splitter) handleDataFrame(role string, frame *mux.Frame, cc *mux.CarrierConn) {
	streamID := frame.StreamID
	s.mu.RLock()
	entry, ok := s.store[streamID]
	s.mu.RUnlock()

	if !ok {
		if role == "up" {
			s.handleNewStream(streamID, frame, cc)
		} else {
			s.metrics.incErr()
			s.logger.Printf("Unknown stream %d in %s data frame", streamID, role)
		}
		return
	}

	switch role {
	case "up":
		if entry.DestConn != nil {
			s.metrics.incUp(len(frame.Payload))
			entry.DestConn.Write(frame.Payload)
		}
	case "down":
		s.metrics.incDown(len(frame.Payload))
		_ = cc
	}
}

func (s *Splitter) handleNewStream(streamID uint32, frame *mux.Frame, cc *mux.CarrierConn) {
	payload := frame.Payload
	if len(payload) < 4 {
		s.logger.Printf("Short session header in stream %d", streamID)
		s.metrics.incErr()
		return
	}
	dest := s.parseDestFromBuf(payload[4:])
	if dest == nil {
		s.logger.Printf("Cannot parse destination for stream %d", streamID)
		s.metrics.incErr()
		return
	}
	addr := fmt.Sprintf("%s:%d", dest.Addr, dest.Port)
	s.logger.Printf("New stream %d → %s", streamID, addr)

	destConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		s.logger.Printf("Dial %s: %v", addr, err)
		s.metrics.incErr()
		return
	}
	s.logger.Printf("Stream %d session created → %s", streamID, addr)

	done := make(chan struct{})
	entry := &StreamEntry{StreamID: streamID, DestConn: destConn, Dest: dest, Role: "up", Done: done}
	s.mu.Lock()
	s.store[streamID] = entry
	s.mu.Unlock()
	s.metrics.incSession()
	go func() {
		<-done
		s.metrics.decSession()
		s.mu.Lock()
		delete(s.store, streamID)
		s.mu.Unlock()
	}()

	go func() {
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, err := cc.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.logger.Printf("Up-carrier read: %v", err)
				}
				destConn.Close()
				return
			}
			if n > 0 {
				s.metrics.incUp(n)
				destConn.Write(buf[:n])
			}
		}
	}()

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
				s.metrics.incDown(n)
				cc.Send(mux.NewDataFrame(streamID, buf[:n]))
			}
		}
	}()
}

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

func (s *Splitter) cleanupAll() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.store {
		if entry.DestConn != nil {
			entry.DestConn.Close()
		}
	}
}

func (s *Splitter) runMetrics(addr string) error {
	mhttp := http.NewServeMux()
	mhttp.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s.metrics.mu.Lock()
		fmt.Fprintf(w, "active_sessions %d\ntotal_sessions %d\ntotal_bytes_up %d\ntotal_bytes_down %d\nactive_streams %d\nerrors %d\n",
			s.metrics.activeSessions, s.metrics.totalSessions, s.metrics.totalBytesUp,
			s.metrics.totalBytesDown, s.metrics.activeStreams, s.metrics.errors)
		s.metrics.mu.Unlock()
		s.mu.RLock()
		fmt.Fprintf(w, "session_count %d\n", len(s.store))
		s.mu.RUnlock()
	})
	s.logger.Printf("Metrics on %s", addr)
	return http.ListenAndServe(addr, mhttp)
}

func (m *Metrics) incSession() { m.mu.Lock(); m.activeSessions++; m.totalSessions++; m.mu.Unlock() }
func (m *Metrics) decSession() { m.mu.Lock(); m.activeSessions--; m.mu.Unlock() }
func (m *Metrics) incUp(n int) { m.mu.Lock(); m.totalBytesUp += int64(n); m.mu.Unlock() }
func (m *Metrics) incDown(n int) { m.mu.Lock(); m.totalBytesDown += int64(n); m.mu.Unlock() }
func (m *Metrics) incErr() { m.mu.Lock(); m.errors++; m.mu.Unlock() }
func (m *Metrics) incStream() { m.mu.Lock(); m.activeStreams++; m.mu.Unlock() }
func (m *Metrics) decStream() { m.mu.Lock(); m.activeStreams--; m.mu.Unlock() }
func parseInt(s string) int { var n int; fmt.Sscanf(s, "%d", &n); return n }
