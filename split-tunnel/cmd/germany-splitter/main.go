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
	"strconv"
	"sync"
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
	up   *carrierHandle // up carrier: WS client → wss://<cdn-domain>/upload
	down *carrierHandle // down carrier: TCP server ← Iran (via VLESS+Reality)

	lnMu   sync.Mutex
	downLn net.Listener
	mLn    net.Listener
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
	for _, ln := range []net.Listener{s.downLn, s.mLn} {
		if ln != nil {
			ln.Close()
		}
	}
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
		store:   session.NewSessionStore(),
		metrics: &Metrics{},
		logger:  log.New(os.Stderr, "[germany-splitter] ", log.LstdFlags),
		secret:  derived,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup

	if cfg.MetricsPort > 0 {
		wg.Add(1)
		go func() { defer wg.Done(); s.runMetrics(fmt.Sprintf("127.0.0.1:%d", cfg.MetricsPort)) }()
	}

	// Up-Carrier: WS client → CDN (exponential backoff reconnect)
	wg.Add(1)
	go func() { defer wg.Done(); s.runUpCarrier() }()

	// Down-Carrier: TCP server ← Iran
	wg.Add(1)
	go func() { defer wg.Done(); s.runDownCarrier() }()

	s.logger.Printf("Up-carrier (WS) dial: %s | Down-carrier (TCP) listen: %s", cfg.UpWsUrl, cfg.DownListen)
	s.logger.Println("germany-splitter started")

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
	s.logger.Println("germany-splitter stopped")
}

// ============================================================
// Up-Carrier: WebSocket client → wss://<cdn-domain>/upload
// Exponential backoff reconnect (2s → 60s cap), reset on a
// successfully authenticated session.
// ============================================================

func (s *Splitter) runUpCarrier() {
	backoff := 2 * time.Second
	for {
		conn, resp, err := websocket.DefaultDialer.Dial(s.config.UpWsUrl, nil)
		if err != nil {
			s.logger.Printf("Up-carrier dial %s: %v (retrying in %s)", s.config.UpWsUrl, err, backoff)
			time.Sleep(backoff)
			backoff = nextBackoff(backoff)
			continue
		}
		s.logger.Printf("Up-carrier WS connected (HTTP %s)", resp.Status)

		wsc := &wsConn{conn: conn}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		br, err := mux.CarrierAuth(ctx, wsc, true, s.secret)
		cancel()
		if err != nil {
			s.logger.Printf("Up-carrier auth failed: %v (retrying in %s)", err, backoff)
			conn.Close()
			time.Sleep(backoff)
			backoff = nextBackoff(backoff)
			continue
		}
		s.logger.Printf("Up-carrier authenticated")
		backoff = 2 * time.Second // successful session — reset backoff

		carrier := mux.NewCarrierConn(wsc, s.config.KeepAliveInterval)
		carrier.SetReadBuffer(br)
		c := carrier // closure must capture this carrier, not the loop var
		carrier.OnNewStream = func(streamID uint32, ch chan []byte) {
			go s.bootstrapUpStream(c, streamID, ch)
		}
		h := &carrierHandle{carrier: carrier, done: make(chan struct{})}
		go func() {
			defer close(h.done)
			carrier.Dispatch()
		}()

		s.mu.Lock()
		old := s.up
		s.up = h
		s.mu.Unlock()
		s.logger.Printf("Up-carrier established")

		<-h.done
		h.close()
		if old != nil {
			old.close()
		}
		s.mu.Lock()
		if s.up == h {
			s.up = nil
		}
		s.mu.Unlock()
		s.logger.Printf("Up-carrier torn down (reconnecting in %s)", backoff)
		time.Sleep(backoff)
		backoff = nextBackoff(backoff)
	}
}

func nextBackoff(b time.Duration) time.Duration {
	if b >= 60*time.Second {
		return 60 * time.Second
	}
	return b * 2
}

// ============================================================
// Stream bootstrap & internet relaying
// ============================================================

// bootstrapUpStream handles a new up-carrier stream. The first frame the
// dispatcher delivers on the stream channel is the FrameHeader payload
// (encoded destination). It dials the real target on the open internet,
// registers the session and runs the two strictly-directional relays:
//
//	up-carrier stream → target socket        (upload)
//	target socket → down-carrier             (download, strictly)
func (s *Splitter) bootstrapUpStream(upC *mux.CarrierConn, streamID uint32, ch chan []byte) {
	defer upC.Deregister(streamID)

	// First frame: the Header payload (encoded destination)
	hdr := <-ch
	if hdr == nil {
		// Late FrameClose for an already-torn-down stream — nothing to do
		return
	}
	dest := session.ParseDestinationFromBuf(hdr)
	if dest == nil {
		s.logger.Printf("Up-carrier stream %d: invalid destination header", streamID)
		return
	}
	addr := net.JoinHostPort(dest.Addr, strconv.Itoa(int(dest.Port)))
	s.logger.Printf("New stream %d → %s", streamID, addr)

	// Dial the real destination on the open internet
	destConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		s.logger.Printf("Stream %d: dial %s: %v", streamID, addr, err)
		s.metrics.incErr()
		_ = upC.WriteFrame(streamID, mux.FrameClose, nil) // session dead
		return
	}
	s.logger.Printf("Stream %d: target connected", streamID)

	downC := s.getDown()
	if downC == nil || !downC.Ready() {
		s.logger.Printf("Stream %d: down-carrier not ready, dropping", streamID)
		destConn.Close()
		_ = upC.WriteFrame(streamID, mux.FrameClose, nil)
		return
	}

	// Register the active session
	sidBytes, _ := session.GenerateSessionID()
	var sid session.SessionID
	copy(sid[:], sidBytes)
	ctx, cancel := context.WithCancel(context.Background())
	sess := &session.Session{
		ID:           sid,
		Dest:         dest,
		StreamIDUp:   streamID,
		StreamIDDown: streamID,
		Ctx:          ctx,
		Cancel:       cancel,
	}
	s.store.Add(sid, sess)
	s.store.AddStream(sess)
	s.metrics.incSession()
	s.logger.Printf("Stream %d: session %s registered", streamID, sid.String())

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cancel()
			destConn.Close()
			s.store.RemoveStream(sess)
			s.store.Remove(sid)
			s.metrics.decSession()
			s.logger.Printf("Stream %d cleaned up", streamID)
		})
	}

	// Both relays report completion; cleanup runs after they are done.
	upDone := make(chan struct{})
	downDone := make(chan struct{})

	// Up-relay: up-carrier stream → target
	go func() {
		defer close(upDone)
		for {
			select {
			case <-ctx.Done():
				return
			case frame, ok := <-ch:
				if !ok {
					return // carrier died
				}
				if frame == nil {
					// FrameClose from Iran: client finished → half-close target
					if tc, ok := destConn.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					return
				}
				s.metrics.incUp(int64(len(frame)))
				if _, werr := destConn.Write(frame); werr != nil {
					s.logger.Printf("Stream %d target write: %v", streamID, werr)
					return
				}
			}
		}
	}()

	// Down-relay: target → down-carrier (strictly)
	go func() {
		defer close(downDone)
		buf := make([]byte, s.config.RelayBufSize)
		for {
			n, rerr := destConn.Read(buf)
			if n > 0 {
				s.metrics.incDown(int64(n))
				if werr := downC.WriteFrame(streamID, mux.FrameData, buf[:n]); werr != nil {
					s.logger.Printf("Stream %d down-carrier write: %v", streamID, werr)
					break
				}
			}
			if rerr != nil {
				if rerr != io.EOF {
					s.logger.Printf("Stream %d target read: %v", streamID, rerr)
				}
				break
			}
		}
		// target finished: propagate FrameClose over the down-carrier
		_ = downC.WriteFrame(streamID, mux.FrameClose, nil)
	}()

	// Wait for the up direction to end, then give the down relay a grace
	// period to drain (the target normally closes right after responding),
	// so a misbehaving server cannot pin the session forever.
	<-upDone
	select {
	case <-downDone:
	case <-time.After(10 * time.Second):
	}
	cleanup()
}

// ============================================================
// Down-Carrier: TCP server on SPLIT_DOWN_LISTEN (0.0.0.0:9002)
// Iran's local Xray tunnels to us over VLESS+Reality; the raw TCP
// connection lands here.
// ============================================================

func (s *Splitter) runDownCarrier() {
	ln, err := net.Listen("tcp", s.config.DownListen)
	if err != nil {
		s.logger.Fatalf("Down-carrier listener: %v", err)
	}
	s.lnMu.Lock()
	s.downLn = ln
	s.lnMu.Unlock()
	defer ln.Close()
	s.logger.Printf("Down-carrier listening on %s", s.config.DownListen)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleDownConn(conn)
	}
}

func (s *Splitter) handleDownConn(conn net.Conn) {
	// Only one down-carrier at a time — reject secondaries cleanly
	if s.getDown() != nil {
		s.logger.Printf("Down-carrier: rejected %s (already connected)", conn.RemoteAddr())
		conn.Close()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	br, err := mux.CarrierAuth(ctx, conn, false, s.secret)
	cancel()
	if err != nil {
		s.logger.Printf("Down-carrier auth failed from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	s.logger.Printf("Down-carrier authenticated from %s", conn.RemoteAddr())

	carrier := mux.NewCarrierConn(conn, s.config.KeepAliveInterval)
	carrier.SetReadBuffer(br)
	h := &carrierHandle{carrier: carrier, done: make(chan struct{})}
	go func() {
		defer close(h.done)
		carrier.Dispatch()
	}()

	s.mu.Lock()
	s.down = h
	s.mu.Unlock()
	s.logger.Printf("Down-carrier established")

	<-h.done
	h.close()
	s.mu.Lock()
	if s.down == h {
		s.down = nil
	}
	s.mu.Unlock()
	s.logger.Printf("Down-carrier torn down (waiting for reconnect)")
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
