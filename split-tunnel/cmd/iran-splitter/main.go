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
)

type Config struct {
	SplitListen     string
	CarrierUpAddr   string
	CarrierDownAddr string
	Secret          string
	MetricsPort     int
	RelayBufSize    int
}

type Metrics struct {
	mu             sync.Mutex
	activeSessions int64
	totalSessions  int64
	totalBytesUp   int64
	totalBytesDown int64
	errors         int64
}

type Splitter struct {
	config         *Config
	store          *session.SessionStore
	metrics        *Metrics
	logger         *log.Logger
	secret         []byte
	mu             sync.RWMutex
	upCarrier      *mux.CarrierConn
	downCarrier    *mux.CarrierConn
	upCarrierObj   *mux.Carrier
	downCarrierObj *mux.Carrier
}

func main() {
	cfg := &Config{
		SplitListen:     "127.0.0.1:10900",
		CarrierUpAddr:   "germany-server:9001",
		CarrierDownAddr: "germany-server:9002",
		Secret:          "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING",
		RelayBufSize:    32768,
	}

	if v := os.Getenv("SPLIT_LISTEN"); v != "" {
		cfg.SplitListen = v
	}
	if v := os.Getenv("SPLIT_CARRIER_UP"); v != "" {
		cfg.CarrierUpAddr = v
	}
	if v := os.Getenv("SPLIT_CARRIER_DOWN"); v != "" {
		cfg.CarrierDownAddr = v
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
	s.upCarrierObj = mux.NewCarrier(derived)
	s.downCarrierObj = mux.NewCarrier(derived)

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

	upCC := s.dialCarrierSync("up", cfg.CarrierUpAddr, s.upCarrierObj)
	if upCC != nil {
		s.mu.Lock()
		s.upCarrier = upCC
		s.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runCarrierReader("up", upCC)
		}()
	}

	downCC := s.dialCarrierSync("down", cfg.CarrierDownAddr, s.downCarrierObj)
	if downCC != nil {
		s.mu.Lock()
		s.downCarrier = downCC
		s.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runCarrierReader("down", downCC)
		}()
	}

	ln, err := net.Listen("tcp", cfg.SplitListen)
	if err != nil {
		s.logger.Fatalf("Failed to listen on %s: %v", cfg.SplitListen, err)
	}
	defer ln.Close()

	s.logger.Printf("SOCKS5 listener on %s", cfg.SplitListen)
	s.logger.Printf("Up-carrier  → %s", cfg.CarrierUpAddr)
	s.logger.Printf("Down-carrier→ %s", cfg.CarrierDownAddr)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				s.logger.Printf("Accept error: %v", err)
				continue
			}
			go s.handleSOCKS5(c)
		}
	}()

	s.logger.Println("iran-splitter started (dual-carrier mux mode)")
	<-sigCh
	s.logger.Println("Shutting down...")
	s.store.CloseAll()
	s.mu.RLock()
	if s.upCarrier != nil {
		s.upCarrier.Close()
	}
	if s.downCarrier != nil {
		s.downCarrier.Close()
	}
	s.mu.RUnlock()
	wg.Wait()
	s.logger.Println("iran-splitter stopped")
}

func (s *Splitter) dialCarrierSync(role, addr string, carrier *mux.Carrier) *mux.CarrierConn {
	for {
		s.logger.Printf("[%s] Connecting to %s...", role, addr)
		rawConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			s.logger.Printf("[%s] Connect failed: %v (retrying in 5s)", role, err)
			time.Sleep(5 * time.Second)
			continue
		}
		s.logger.Printf("[%s] Connected to %s", role, addr)
		cc := mux.NewCarrierConn(rawConn, carrier)
		auth := mux.NewAuthFrame(s.secret)
		if err := mux.WriteFrame(cc, auth); err != nil {
			s.logger.Printf("[%s] Auth send failed: %v", role, err)
			cc.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		resp, err := mux.ReadFrame(cc)
		if err != nil {
			s.logger.Printf("[%s] Auth read failed: %v", role, err)
			cc.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.Type != mux.FrameAuth || len(resp.Payload) < 1 {
			s.logger.Printf("[%s] Bad auth response type %d", role, resp.Type)
			cc.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.Payload[0] != 0 {
			s.logger.Printf("[%s] Auth rejected", role)
			cc.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		s.logger.Printf("[%s] Authenticated OK", role)
		return cc
	}
}

func (s *Splitter) runCarrierReader(role string, cc *mux.CarrierConn) {
	defer cc.Close()
	for {
		frame, err := mux.ReadFrame(cc)
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("[%s] Carrier read error: %v", role, err)
			}
			return
		}
		switch frame.Type {
		case mux.FrameData:
			s.handleCarrierDataFrame(frame, role)
		case mux.FramePing:
			cc.Send(mux.NewPongFrame())
		}
	}
}

func (s *Splitter) handleCarrierDataFrame(frame *mux.Frame, role string) {
	s.store.ForEachSession(func(id session.SessionID, sess *session.Session) {
		if role == "down" && sess.DownStreamID == frame.StreamID {
			s.metrics.incDown(len(frame.Payload))
			sess.ClientConn.Write(frame.Payload)
		}
	})
}

func (s *Splitter) handleSOCKS5(clientConn net.Conn) {
	defer clientConn.Close()
	header := make([]byte, 3)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		s.logger.Printf("SOCKS5 hello: %v", err)
		return
	}
	nmethods := int(header[1])
	if nmethods > 0 {
		methods := make([]byte, nmethods)
		io.ReadFull(clientConn, methods)
	}
	clientConn.Write([]byte{0x05, 0x00})
	req := make([]byte, 3)
	if _, err := io.ReadFull(clientConn, req); err != nil {
		s.logger.Printf("SOCKS5 request: %v", err)
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		s.logger.Printf("SOCKS5: expected CONNECT, got ver=%d cmd=%d", req[0], req[1])
		return
	}
	atype := req[2]
	dest, err := session.ReadDestinationEx(clientConn, atype)
	if err != nil {
		s.logger.Printf("SOCKS5 dest: %v", err)
		return
	}
	s.logger.Printf("CONNECT %s:%d", dest.Addr, dest.Port)

	s.mu.RLock()
	upCC := s.upCarrier
	downCC := s.downCarrier
	s.mu.RUnlock()

	if upCC == nil || upCC.IsClosed() || downCC == nil || downCC.IsClosed() {
		s.logger.Printf("Carriers not connected, rejecting")
		return
	}

	rawSid, err := session.GenerateSessionID()
	if err != nil {
		s.logger.Printf("Generate session ID: %v", err)
		return
	}
	var sid session.SessionID
	copy(sid[:], rawSid)

	ctx, cancel := context.WithCancel(context.Background())
	sess := &session.Session{
		ID:         sid,
		Dest:       dest,
		ClientConn: clientConn,
		Ctx:        ctx,
	}
	s.store.Add(sid, sess)
	s.metrics.incSession()
	defer func() {
		s.metrics.decSession()
		s.store.Remove(sid)
		cancel()
	}()

	upStream := upCC.OpenStream()
	downStream := downCC.OpenStream()
	sess.UpStreamID = upStream.ID
	sess.DownStreamID = downStream.ID
	s.logger.Printf("Session %s upStream=%d downStream=%d", sid.String(), upStream.ID, downStream.ID)

	buf := make([]byte, 4+session.MaxHeaderSize)
	copy(buf[:4], sid[:4])
	n := session.WriteDestinationBuffer(buf[4:], dest)
	if n > 0 {
		upCC.SendQueue(mux.NewDataFrame(upStream.ID, buf[4:4+n]))
	}

	go func() {
		data := make([]byte, s.config.RelayBufSize)
		for {
			n, err := clientConn.Read(data)
			if err != nil {
				if err != io.EOF {
					s.logger.Printf("Client read: %v", err)
				}
				return
			}
			if n > 0 {
				s.metrics.incUp(n)
				upCC.SendQueue(mux.NewDataFrame(upStream.ID, data[:n]))
			}
		}
	}()

	<-ctx.Done()
	s.logger.Printf("Session %s ended", sid.String())
}

func (s *Splitter) runMetrics(addr string) error {
	mhttp := http.NewServeMux()
	mhttp.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s.metrics.mu.Lock()
		fmt.Fprintf(w, "active_sessions %d\ntotal_sessions %d\ntotal_bytes_up %d\ntotal_bytes_down %d\nerrors %d\n",
			s.metrics.activeSessions, s.metrics.totalSessions, s.metrics.totalBytesUp,
			s.metrics.totalBytesDown, s.metrics.errors)
		s.metrics.mu.Unlock()
		fmt.Fprintf(w, "session_count %d\n", s.store.Count())
	})
	s.logger.Printf("Metrics on %s", addr)
	return http.ListenAndServe(addr, mhttp)
}

func (m *Metrics) incSession() { m.mu.Lock(); m.activeSessions++; m.totalSessions++; m.mu.Unlock() }
func (m *Metrics) decSession() { m.mu.Lock(); m.activeSessions--; m.mu.Unlock() }
func (m *Metrics) incUp(n int) { m.mu.Lock(); m.totalBytesUp += int64(n); m.mu.Unlock() }
func (m *Metrics) incDown(n int) { m.mu.Lock(); m.totalBytesDown += int64(n); m.mu.Unlock() }
func (m *Metrics) incErr() { m.mu.Lock(); m.errors++; m.mu.Unlock() }
func parseInt(s string) int { var n int; fmt.Sscanf(s, "%d", &n); return n }
