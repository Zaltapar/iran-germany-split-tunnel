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

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
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

	// Stream queue (backpressure) settings, SPLIT_STREAM_QUEUE_* /
	// SPLIT_STREAM_OVERFLOW_MS. Zero falls back to the library defaults
	// (mux.SanitizeLimits); a slow stream is terminated, never the carrier.
	QueueBytesPerStream  int
	QueueFramesPerStream int
	QueueBytesTotal      int
	OverflowWaitMs       int
}

// streamLimits builds the per-stream mailbox limits from config. Zero
// values fall back to mux.DefaultStreamLimits via SanitizeLimits.
func (s *Splitter) streamLimits() mux.StreamLimits {
	return mux.StreamLimits{
		MaxBytesPerStream:  s.config.QueueBytesPerStream,
		MaxFramesPerStream: s.config.QueueFramesPerStream,
		MaxBytesTotal:      s.config.QueueBytesTotal,
		OverflowWait:       time.Duration(s.config.OverflowWaitMs) * time.Millisecond,
	}
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

	// Up-carrier auth-failure backoff state (Phase 6).
	authFailMu sync.Mutex
	authFails  int
	authFailAt time.Time
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
	if v := os.Getenv("SPLIT_STREAM_QUEUE_BYTES"); v != "" {
		cfg.QueueBytesPerStream = parseInt(v)
	}
	if v := os.Getenv("SPLIT_STREAM_QUEUE_FRAMES"); v != "" {
		cfg.QueueFramesPerStream = parseInt(v)
	}
	if v := os.Getenv("SPLIT_STREAM_QUEUE_TOTAL_BYTES"); v != "" {
		cfg.QueueBytesTotal = parseInt(v)
	}
	if v := os.Getenv("SPLIT_STREAM_OVERFLOW_MS"); v != "" {
		cfg.OverflowWaitMs = parseInt(v)
	}

	// Fail fast on insecure secret material (Phase 6). The blocklist is
	// always enforced; the length policy has a dev/test bypass.
	if err := mux.ValidateSecretMaterial(cfg.Secret, os.Getenv("SPLIT_ALLOW_WEAK_SECRET") == "1"); err != nil {
		log.Fatalf("invalid SPLIT_SECRET: %v (generate one with: openssl rand -hex 32)", err)
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

// Up-carrier handshake resource limits (Phase 6): bound concurrent
// in-flight handshakes, and back off new handshakes after a burst of
// repeated authentication failures (a per-process counter, no
// distributed state).
const (
	maxConcurrentHandshakes = 16
	authFailBackoffLimit    = 10
	authFailBackoffWindow   = 60 * time.Second
)

func (s *Splitter) runUpCarrier() {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		// Machine-to-machine carrier: the Origin header is NOT a security
		// boundary here (carrier dialers send no Origin; browsers are not
		// legitimate clients of this endpoint). The real security boundary
		// is the v1 challenge/response carrier authentication (plus
		// TLS/Reality in the transport), so the permissive origin policy is
		// deliberate and documented — do not "tighten" it without
		// breaking CDN dial patterns.
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	muxHTTP := http.NewServeMux()
	muxHTTP.HandleFunc("/upload", s.uploadHandler(upgrader))
	// Every other path gets the mux's default 404; the carrier is only
	// ever established on /upload.

	ln, err := net.Listen("tcp", s.config.WsListen)
	if err != nil {
		s.logger.Fatalf("Up-carrier WS listener: %v", err)
	}
	s.lnMu.Lock()
	s.upLn = ln
	s.lnMu.Unlock()
	defer ln.Close()
	s.logger.Printf("Up-carrier WS server listening on %s (path /upload)", s.config.WsListen)

	// ReadHeaderTimeout bounds the UNAUTHENTICATED request phase;
	// IdleTimeout reclaims idle keep-alive sockets. Read/Write timeouts
	// must stay ZERO: after the upgrade the connection is a long-lived
	// authenticated carrier and must never be killed by a write timeout.
	srv := &http.Server{
		Handler:           muxHTTP,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		s.logger.Printf("Up-carrier WS server error: %v", err)
	}
}

// uploadHandler is the /upload HTTP handler: method check, auth-failure
// backoff, bounded handshake concurrency, single-carrier enforcement,
// then the WebSocket upgrade.
func (s *Splitter) uploadHandler(upgrader websocket.Upgrader) http.HandlerFunc {
	sem := make(chan struct{}, maxConcurrentHandshakes)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.authInBackoff() {
			s.logger.Printf("Up-carrier: rejected handshake from %s (auth-failure backoff active)", r.RemoteAddr)
			http.Error(w, "too many failed authentications; retry later", http.StatusTooManyRequests)
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			http.Error(w, "too many concurrent handshakes", http.StatusServiceUnavailable)
			return
		}
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
	}
}

// recordAuthFail / clearAuthFails / authInBackoff implement a lightweight
// per-process backoff: after authFailBackoffLimit failures within
// authFailBackoffWindow, new handshakes are rejected (HTTP 429) until the
// window lapses. A successful authentication resets the counter.
func (s *Splitter) recordAuthFail() {
	s.authFailMu.Lock()
	defer s.authFailMu.Unlock()
	if s.authFails > 0 && time.Since(s.authFailAt) > authFailBackoffWindow {
		s.authFails = 0 // burst window lapsed
	}
	s.authFails++
	if s.authFails == 1 {
		s.authFailAt = time.Now()
	}
}

func (s *Splitter) clearAuthFails() {
	s.authFailMu.Lock()
	s.authFails = 0
	s.authFailMu.Unlock()
}

func (s *Splitter) authInBackoff() bool {
	s.authFailMu.Lock()
	defer s.authFailMu.Unlock()
	return s.authFails >= authFailBackoffLimit && time.Since(s.authFailAt) <= authFailBackoffWindow
}

func (s *Splitter) handleUpWsConn(ws *websocket.Conn) {
	wsc := &wsConn{conn: ws}

	// The WS adapter cannot enforce deadlines, so watchdog any
	// connection that does not complete the auth handshake in time.
	watchdog := time.AfterFunc(15*time.Second, func() { ws.Close() })
	defer watchdog.Stop()

	br, err := mux.CarrierAuth(context.Background(), wsc, false, mux.RoleUpload, s.secret)
	if err != nil {
		// The error is for LOCAL logging only; nothing about WHICH check
		// failed is transmitted to the peer (the connection is simply
		// closed by the auth implementation).
		s.logger.Printf("Up-carrier auth failed from %s: %v", ws.RemoteAddr(), err)
		s.recordAuthFail()
		ws.Close()
		return
	}
	s.clearAuthFails()
	s.logger.Printf("Up-carrier authenticated from %s", ws.RemoteAddr())

	carrier := mux.NewCarrierConn(wsc, s.config.KeepAliveInterval)
	carrier.SetReadBuffer(br)
	carrier.SetStreamLimits(s.streamLimits())
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
		br, err := mux.CarrierAuth(ctx, conn, true, mux.RoleDownload, s.secret)
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
		carrier.SetStreamLimits(s.streamLimits())
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
func socksReply(w io.Writer, status byte) {
	_, _ = w.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func (s *Splitter) handleSOCKS5Conn(clientConn net.Conn) {
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))

	dest, err := socksNegotiate(clientConn)
	if err != nil {
		s.logger.Printf("SOCKS5 negotiation: %v (from %s)", err, clientConn.RemoteAddr())
		clientConn.Close()
		return
	}
	_ = clientConn.SetDeadline(time.Time{})
	s.logger.Printf("SOCKS5 CONNECT → %s:%d from %s", dest.Addr, dest.Port, clientConn.RemoteAddr())

	// Wait until both carriers are live
	upC, downC, err := s.waitCarriers()
	if err != nil {
		s.logger.Printf("SOCKS5 %s:%d: %v", dest.Addr, dest.Port, err)
		socksReply(clientConn, 0x06) // general SOCKS server failure
		clientConn.Close()
		return
	}

	// --- Create the session (Phase 4: the session owns the client conn) ---
	rawSid, _ := session.GenerateSessionID()
	var sid session.SessionID
	copy(sid[:], rawSid)

	streamID := atomic.AddUint32(&s.streamID, 1)
	sess := session.NewSession(sid, dest, clientConn, nil, context.Background())
	sess.StreamIDUp = streamID
	sess.StreamIDDown = streamID
	// Binary-owned teardown, run exactly once by Session.Close: carrier
	// deregistration, store unindex, metric decrement.
	sess.OnClose(func() {
		upC.Deregister(streamID)
		downC.Deregister(streamID)
		s.store.Remove(sid)
		s.metrics.decSession()
		s.logger.Printf("Session %s cleaned up (%s)", sid.String(), sess.Reason())
	})
	s.store.Add(sid, sess)
	s.store.AddStream(sess)
	s.metrics.incSession()
	s.logger.Printf("Session %s → %s:%d (stream %d)", sid.String(), dest.Addr, dest.Port, streamID)

	// Register this session's streams in both carrier demuxers
	upCh := upC.Register(streamID)
	downCh := downC.Register(streamID)
	if upCh == nil || downCh == nil {
		sess.Close("carrier stream registration failed")
		return
	}
	if !sess.Activate() {
		sess.Close("session activate failed")
		return
	}

	// SOCKS5 success reply
	socksReply(clientConn, 0x00)

	// Send the initial Header frame (encoded destination) over the up-carrier
	hdrBuf := make([]byte, session.MaxHeaderSize)
	n := session.WriteDestinationBuffer(hdrBuf, dest)
	if n <= 0 {
		sess.Close("destination encode failed")
		return
	}
	if err := upC.WriteFrame(streamID, mux.FrameHeader, hdrBuf[:n]); err != nil {
		s.logger.Printf("Session %s up-carrier header: %v", sid.String(), err)
		sess.Close("up-carrier header write failed")
		return
	}

	upWatchDone := make(chan struct{})
	downDone := make(chan struct{})
	upRelayDone := make(chan struct{})

	// Up-carrier stream watcher: a FrameClose from Germany (dial failure,
	// down-carrier not ready) tears the session down. Unexpected data
	// frames in this direction are ignored.
	go func() {
		defer close(upWatchDone)
		for {
			select {
			case <-sess.Ctx.Done():
				return
			case frame, ok := <-upCh:
				if !ok {
					sess.Close("up carrier closed")
					return
				}
				if frame == nil {
					s.logger.Printf("Session %s: up-carrier closed by Germany", sid.String())
					sess.Close("up stream closed by peer")
					return
				}
			}
		}
	}()

	// Down relay: down-carrier → client (download direction)
	go func() {
		defer close(downDone)
		for {
			select {
			case <-sess.Ctx.Done():
				return
			case frame, ok := <-downCh:
				if !ok {
					sess.Close("down carrier closed")
					return
				}
				if frame == nil {
					// Target finished (FrameClose from Germany):
					// half-close the client write side. Every frame has
					// already been written, so the data the client has
					// not read yet stays deliverable.
					if tc, ok := clientConn.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					sess.MarkDirClosed(session.DirDown, "target EOF")
					return
				}
				s.metrics.incDown(int64(len(frame)))
				if _, werr := clientConn.Write(frame); werr != nil {
					s.logger.Printf("Session %s client write: %v", sid.String(), werr)
					sess.Close("client write failed")
					return
				}
			}
		}
	}()

	// Up relay: client → up-carrier (upload direction)
	go func() {
		defer close(upRelayDone)
		buf := make([]byte, s.config.RelayBufSize)
		for {
			select {
			case <-sess.Ctx.Done():
				return
			default:
			}
			n, rerr := clientConn.Read(buf)
			if n > 0 {
				s.metrics.incUp(int64(n))
				if werr := upC.WriteFrame(streamID, mux.FrameData, buf[:n]); werr != nil {
					s.logger.Printf("Session %s up-carrier write: %v", sid.String(), werr)
					sess.Close("up-carrier write failed")
					return
				}
				// Carrier replaced underneath us → tear down (the old
				// carrier is torn down by its own run loop).
				if s.getUp() != upC {
					sess.Close("up carrier replaced")
					return
				}
			}
			if rerr != nil {
				// Tell Germany the client side is finished (best effort).
				_ = upC.WriteFrame(streamID, mux.FrameClose, nil)
				if errors.Is(rerr, io.EOF) {
					// Client FIN: half-close ONLY. Germany closes its
					// target write side; the target may still send
					// response data, which the down relay keeps
					// delivering until the target EOF.
					sess.MarkDirClosed(session.DirUp, "client EOF")
				} else {
					s.logger.Printf("Session %s client read: %v", sid.String(), rerr)
					sess.Close("client read error")
				}
				return
			}
		}
	}()

	// Wait for both directions (and the watcher) to finish, then
	// finalize. If a direction already closed the session, this is an
	// idempotent no-op.
	<-upRelayDone
	<-downDone
	<-upWatchDone
	sess.Close("session ended")
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
