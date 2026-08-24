package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/split-tunnel/pkg/session"
	"github.com/gorilla/websocket"
)

// ============================================================
// WebSocket io.ReadWriteCloser adapter
// (lets *websocket.Conn plug into the CarrierConn abstraction)
// ============================================================

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

// carrierHandle pairs a live carrier with its dispatcher completion.
type carrierHandle struct {
	carrier *mux.CarrierConn
	done    chan struct{}
}

// close waits for the dispatcher to drain, then tears the carrier down.
func (h *carrierHandle) close() {
	<-h.done
	h.carrier.Close()
}

type Splitter struct {
	config  *Config
	store   *session.SessionStore
	metrics *Metrics
	logger  *log.Logger
	secret  []byte

	mu   sync.RWMutex
	up   *carrierHandle // up carrier: WS server, Germany dials /upload
	down *carrierHandle // down carrier: TCP client → local Xray :10802

	streamID uint32 // per-session stream ID, shared by both carriers

	lnMu    sync.Mutex
	socksLn net.Listener
	upLn    net.Listener
	mLn     net.Listener
}

func (s *Splitter) getUp() *mux.CarrierConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.up != nil {
		return s.up.carrier
	}
	return nil
}

func (s *Splitter) getDown() *mux.CarrierConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.down != nil {
		return s.down.carrier
	}
	return nil
}

// closeListeners unblocks all accept loops for a clean shutdown.
func (s *Splitter) closeListeners() {
	s.lnMu.Lock()
	defer s.lnMu.Unlock()
	for _, ln := range []net.Listener{s.socksLn, s.upLn, s.mLn} {
		if ln != nil {
			ln.Close()
		}
	}
}

// waitCarriers blocks until both carriers are live (30s timeout).
func (s *Splitter) waitCarriers() (*mux.CarrierConn, *mux.CarrierConn, error) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		up := s.getUp()
		down := s.getDown()
		if up != nil && up.Ready() && down != nil && down.Ready() {
			return up, down, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, nil, errors.New("carriers not ready")
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

	if cfg.MetricsPort > 0 {
		wg.Add(1)
		go func() { defer wg.Done(); s.runMetrics(fmt.Sprintf("127.0.0.1:%d", cfg.MetricsPort)) }()
	}

	// Up-Carrier: WS server (behind CDN / nginx on :9001)
	wg.Add(1)
	go func() { defer wg.Done(); s.runUpCarrier() }()

	// SOCKS5 server (user connections from local Xray)
	wg.Add(1)
	go func() { defer wg.Done(); s.runSocksServer() }()

	// Down-Carrier: TCP client → 127.0.0.1:10802 (local Xray inbound)
	wg.Add(1)
	go func() { defer wg.Done(); s.runDownCarrier() }()

	s.logger.Printf("SOCKS5: %s | Up-carrier WS: %s | Down-carrier → %s", cfg.SocksListen, cfg.WsListen, cfg.DownCarrierAddr)
	s.logger.Println("iran-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")
	s.store.CloseAll()
	s.mu.Lock()
	if s.up != nil {
		s.up.carrier.Close()
	}
	if s.down != nil {
		s.down.carrier.Close()
	}
	s.mu.Unlock()
	s.closeListeners()
	wg.Wait()
	s.logger.Println("iran-splitter stopped")
}

// ============================================================
// Up-Carrier: WebSocket server on SPLIT_WS_LISTEN (/upload)
// Germany dials wss://<cdn-domain>/upload → CDN → nginx → here
// ============================================================

func (s *Splitter) runUpCarrier() {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}

	muxHTTP := http.NewServeMux()
	muxHTTP.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if s.getUp() != nil {
			s.logger.Printf("Up-carrier: rejected %s (carrier already connected)", r.RemoteAddr)
			http.Error(w, "up-carrier already connected", http.StatusConflict)
			return
		}
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			s.logger.Printf("Up-carrier WS upgrade failed from %s: %v", r.RemoteAddr, err)
			return
		}
		s.logger.Printf("Up-carrier WS connected from %s", r.RemoteAddr)
		s.handleUpWsConn(wsConn)
		s.logger.Printf("Up-carrier WS disconnected from %s", r.RemoteAddr)
	})

	ln, err := net.Listen("tcp", s.config.WsListen)
	if err != nil {
		s.logger.Fatalf("Up-carrier WS listener: %v", err)
	}
	s.lnMu.Lock()
	s.upLn = ln
	s.lnMu.Unlock()
	defer ln.Close()
	s.logger.Printf("Up-carrier WS server listening on %s (path /upload)", s.config.WsListen)

	if err := http.Serve(ln, muxHTTP); err != nil && err != http.ErrServerClosed {
		s.logger.Printf("Up-carrier WS server error: %v", err)
	}
}

func (s *Splitter) handleUpWsConn(ws *websocket.Conn) {
	wsc := &wsConn{conn: ws}

	// The WS adapter cannot enforce deadlines, so watchdog any
	// connection that does not complete the auth handshake in time.
	watchdog := time.AfterFunc(15*time.Second, func() { ws.Close() })
	defer watchdog.Stop()

	br, err := mux.CarrierAuth(context.Background(), wsc, false, s.secret)
	if err != nil {
		s.logger.Printf("Up-carrier auth failed from %s: %v", ws.RemoteAddr(), err)
		ws.Close()
		return
	}
	s.logger.Printf("Up-carrier authenticated from %s", ws.RemoteAddr())

	carrier := mux.NewCarrierConn(wsc, s.config.KeepAliveInterval)
	carrier.SetReadBuffer(br)
	h := &carrierHandle{carrier: carrier, done: make(chan struct{})}
	go func() {
		defer close(h.done)
		carrier.Dispatch()
	}()

	s.mu.Lock()
	s.up = h
	s.mu.Unlock()
	s.logger.Printf("Up-carrier established")

	<-h.done
	h.close()
	s.mu.Lock()
	if s.up == h {
		s.up = nil
	}
	s.mu.Unlock()
	s.logger.Printf("Up-carrier torn down")
}

// ============================================================
// Down-Carrier: TCP client → 127.0.0.1:10802 (local Xray inbound
// that tunnels over VLESS+Reality to Germany's :9002)
// ============================================================

func (s *Splitter) runDownCarrier() {
	for {
		conn, err := net.DialTimeout("tcp", s.config.DownCarrierAddr, 10*time.Second)
		if err != nil {
			s.logger.Printf("Down-carrier dial %s: %v (retrying in 5s)", s.config.DownCarrierAddr, err)
			time.Sleep(5 * time.Second)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		br, err := mux.CarrierAuth(ctx, conn, true, s.secret)
		cancel()
		if err != nil {
			s.logger.Printf("Down-carrier auth to %s: %v (retrying in 2s)", s.config.DownCarrierAddr, err)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		s.logger.Printf("Down-carrier authenticated to %s", s.config.DownCarrierAddr)

		carrier := mux.NewCarrierConn(conn, s.config.KeepAliveInterval)
		carrier.SetReadBuffer(br)
		h := &carrierHandle{carrier: carrier, done: make(chan struct{})}
		go func() {
			defer close(h.done)
			carrier.Dispatch()
		}()

		s.mu.Lock()
		old := s.down
		s.down = h
		s.mu.Unlock()
		s.logger.Printf("Down-carrier established")

		<-h.done
		h.close()
		if old != nil {
			old.close()
		}
		s.mu.Lock()
		if s.down == h {
			s.down = nil
		}
		s.mu.Unlock()
		s.logger.Printf("Down-carrier torn down (reconnecting)")
		time.Sleep(3 * time.Second)
	}
}

// ============================================================
// SOCKS5 server (user connections from local Xray)
// ============================================================

func (s *Splitter) runSocksServer() {
	ln, err := net.Listen("tcp", s.config.SocksListen)
	if err != nil {
		s.logger.Fatalf("SOCKS5 listener: %v", err)
	}
	s.lnMu.Lock()
	s.socksLn = ln
	s.lnMu.Unlock()
	defer ln.Close()
	s.logger.Printf("SOCKS5 listening on %s", s.config.SocksListen)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleSOCKS5Conn(c)
	}
}

// socksReply sends a SOCKS5 reply (bind addr 0.0.0.0:0, atyp IPv4).
func socksReply(clientConn net.Conn, status byte) {
	_, _ = clientConn.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func (s *Splitter) handleSOCKS5Conn(clientConn net.Conn) {
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))

	// --- SOCKS5 greeting: [0x05, NMETHODS, methods...] ---
	greet := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, greet); err != nil || greet[0] != 0x05 {
		return
	}
	methods := make([]byte, int(greet[1]))
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}
	methodOK := false
	for _, m := range methods {
		if m == 0x00 {
			methodOK = true
			break
		}
	}
	if !methodOK {
		_, _ = clientConn.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// --- SOCKS5 request: [0x05, CMD, 0x00, ATYP, ...] ---
	req := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		socksReply(clientConn, 0x07) // command not supported
		return
	}
	dest, err := session.ReadDestinationEx(clientConn, req[3])
	if err != nil {
		s.logger.Printf("SOCKS5 destination parse: %v", err)
		return
	}
	_ = clientConn.SetDeadline(time.Time{})
	s.logger.Printf("SOCKS5 CONNECT → %s:%d from %s", dest.Addr, dest.Port, clientConn.RemoteAddr())

	// Wait until both carriers are live
	upC, downC, err := s.waitCarriers()
	if err != nil {
		s.logger.Printf("SOCKS5 %s:%d: %v", dest.Addr, dest.Port, err)
		socksReply(clientConn, 0x06) // general SOCKS server failure
		return
	}

	// --- Create session ---
	rawSid, _ := session.GenerateSessionID()
	var sid session.SessionID
	copy(sid[:], rawSid)

	streamID := atomic.AddUint32(&s.streamID, 1)

	ctx, cancel := context.WithCancel(context.Background())
	sess := &session.Session{
		ID:           sid,
		Dest:         dest,
		ClientConn:   clientConn,
		StreamIDUp:   streamID,
		StreamIDDown: streamID,
		Ctx:          ctx,
		Cancel:       cancel,
	}
	s.store.Add(sid, sess)
	s.store.AddStream(sess)
	s.metrics.incSession()
	s.logger.Printf("Session %s → %s:%d (stream %d)", sid.String(), dest.Addr, dest.Port, streamID)

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cancel()
			s.store.RemoveStream(sess)
			s.store.Remove(sid)
			s.metrics.decSession()
			s.logger.Printf("Session %s cleaned up", sid.String())
		})
	}

	// Register this session's streams in both carrier demuxers
	upCh := upC.Register(streamID)
	downCh := downC.Register(streamID)
	if upCh == nil || downCh == nil {
		cleanup()
		return
	}

	// SOCKS5 success reply
	socksReply(clientConn, 0x00)

	// Send the initial Header frame (encoded destination) over the up-carrier
	hdrBuf := make([]byte, session.MaxHeaderSize)
	n := session.WriteDestinationBuffer(hdrBuf, dest)
	if n <= 0 {
		cleanup()
		return
	}
	if err := upC.WriteFrame(streamID, mux.FrameHeader, hdrBuf[:n]); err != nil {
		s.logger.Printf("Session %s up-carrier header: %v", sid.String(), err)
		cleanup()
		return
	}

	// Up-carrier stream watcher: a FrameClose from Germany tears the
	// session down (unexpected data frames are ignored).
	go func() {
		defer upC.Deregister(streamID)
		for frame := range upCh {
			if frame == nil {
				s.logger.Printf("Session %s: up-carrier closed by Germany", sid.String())
				cleanup()
				return
			}
		}
		cleanup()
	}()

	// Down-carrier relay: Germany → client (download direction)
	go func() {
		defer downC.Deregister(streamID)
		for frame := range downCh {
			if frame == nil {
				// target finished: half-close the client side
				if tc, ok := clientConn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				cleanup()
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.metrics.incDown(int64(len(frame)))
			if _, werr := clientConn.Write(frame); werr != nil {
				cleanup()
				return
			}
		}
		cleanup()
	}()

	// Relay: client → up-carrier (upload direction)
	buf := make([]byte, s.config.RelayBufSize)
	for {
		n, rerr := clientConn.Read(buf)
		if n > 0 {
			s.metrics.incUp(int64(n))
			if werr := upC.WriteFrame(streamID, mux.FrameData, buf[:n]); werr != nil {
				s.logger.Printf("Session %s up-carrier write: %v", sid.String(), werr)
				break
			}
			// carrier replaced underneath us → tear down
			if s.getUp() != upC {
				break
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				s.logger.Printf("Session %s client read: %v", sid.String(), rerr)
			}
			break
		}
	}
	// Half-close: tell Germany the client side is finished
	_ = upC.WriteFrame(streamID, mux.FrameClose, nil)
	cleanup()
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
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.lnMu.Lock()
	s.mLn = ln
	s.lnMu.Unlock()
	defer ln.Close()
	return http.Serve(ln, mhttp)
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
