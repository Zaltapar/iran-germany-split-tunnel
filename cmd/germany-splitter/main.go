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
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
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
//
// The Config type lives in internal/config (Phase 7): one shared
// load→parse→validate→construct path for both binaries. This file only
// builds runtime limits from the validated config.

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
	config  *config.Config
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
	// Phase 7: load → parse → validate the ENTIRE configuration before
	// any listener opens or goroutine starts. Load reports every problem
	// at once (aggregated) and enforces the Phase 6 secret policy.
	cfg, err := config.Load(config.RoleGermany)
	if err != nil {
		log.Fatalf("germany-splitter: %v", err)
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
		br, err := mux.CarrierAuth(ctx, wsc, true, mux.RoleUpload, s.secret)
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
		carrier.SetStreamLimits(s.streamLimits())
		c := carrier // closure must capture this carrier, not the loop var
		carrier.OnNewStream = func(streamID uint32, firstType uint8, ch chan []byte) {
			// Frame-type-aware dispatch (Phase 5): a stream opens on
			// FrameHeader (bootstrap a new session) or FrameRebind (an
			// existing session re-attaching after a carrier loss). This
			// standalone binary predates rebind support and keeps no
			// cross-carrier session state, so it can only bootstrap; any
			// other opener is dropped, never misread as a destination.
			if firstType != mux.FrameHeader {
				go s.dropUnsupportedStream(c, streamID, firstType, ch)
				return
			}
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

// dropUnsupportedStream ends a stream that was not opened by a
// FrameHeader (e.g. a Phase 5 FrameRebind from a newer Iran node). The
// dispatcher still delivers the triggering frame's payload, so drain it
// first, then deregister. No target is dialed and NO FrameClose is sent:
// a refused open must not be mistaken for a peer half-close.
func (s *Splitter) dropUnsupportedStream(upC *mux.CarrierConn, streamID uint32, firstType uint8, ch chan []byte) {
	_, _ = <-ch // drain the triggering frame's payload
	s.logger.Printf("Stream %d: unsupported opening frame type 0x%02x (this build only bootstraps FrameHeader streams); dropping", streamID, firstType)
	upC.Deregister(streamID)
}

// bootstrapUpStream handles a new up-carrier stream. The first frame the
// dispatcher delivers on the stream channel is the FrameHeader payload
// (encoded destination). It dials the real target on the open internet,
// registers the session and runs the two strictly-directional relays:
//
//	up-carrier stream → target socket        (upload)
//	target socket → down-carrier             (download, strictly)
func (s *Splitter) bootstrapUpStream(upC *mux.CarrierConn, streamID uint32, ch chan []byte) {
	// First frame: the Header payload (encoded destination)
	hdr, ok := <-ch
	if !ok {
		// carrier died before the header arrived: nothing to bootstrap
		upC.Deregister(streamID)
		return
	}
	if hdr == nil {
		// Late FrameClose for an already-torn-down stream: nothing to do
		upC.Deregister(streamID)
		return
	}
	dest := session.ParseDestinationFromBuf(hdr)
	if dest == nil {
		s.logger.Printf("Up-carrier stream %d: invalid destination header", streamID)
		upC.Deregister(streamID)
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
		upC.Deregister(streamID)
		return
	}
	s.logger.Printf("Stream %d: target connected", streamID)

	downC := s.getDown()
	if downC == nil || !downC.Ready() {
		s.logger.Printf("Stream %d: down-carrier not ready, dropping", streamID)
		destConn.Close() // no session yet: the bootstrap owns the conn
		_ = upC.WriteFrame(streamID, mux.FrameClose, nil)
		upC.Deregister(streamID)
		return
	}

	// Register the active session (Phase 4: the session owns destConn)
	sidBytes, _ := session.GenerateSessionID()
	var sid session.SessionID
	copy(sid[:], sidBytes)
	sess := session.NewSession(sid, dest, nil, destConn, context.Background())
	sess.StreamIDUp = streamID
	sess.StreamIDDown = streamID
	// Binary-owned teardown, run exactly once by Session.Close: carrier
	// deregistration, store unindex, metric decrement.
	sess.OnClose(func() {
		upC.Deregister(streamID)
		downC.Deregister(streamID)
		s.store.Remove(sid)
		s.metrics.decSession()
		s.logger.Printf("Stream %d cleaned up (%s)", streamID, sess.Reason())
	})
	s.store.Add(sid, sess)
	s.store.AddStream(sess)
	s.metrics.incSession()
	s.logger.Printf("Stream %d: session %s registered", streamID, sid.String())
	if !sess.Activate() {
		sess.Close("session activate failed")
		return
	}

	// Both relays report completion; the session is finalized after they
	// are done.
	upDone := make(chan struct{})
	downDone := make(chan struct{})

	// Up relay: up-carrier stream → target (upload direction)
	go func() {
		defer close(upDone)
		for {
			select {
			case <-sess.Ctx.Done():
				return
			case frame, ok := <-ch:
				if !ok {
					sess.Close("up carrier closed")
					return
				}
				if frame == nil {
					// FrameClose from Iran: client finished. Half-close
					// the target write side; the target may still send
					// response data (the download keeps flowing).
					if tc, ok := destConn.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					sess.MarkDirClosed(session.DirUp, "client EOF (FrameClose)")
					return
				}
				s.metrics.incUp(int64(len(frame)))
				if _, werr := destConn.Write(frame); werr != nil {
					s.logger.Printf("Stream %d target write: %v", streamID, werr)
					sess.Close("target write failed")
					return
				}
			}
		}
	}()

	// Down relay: target → down-carrier (download direction, strictly)
	go func() {
		defer close(downDone)
		buf := make([]byte, s.config.RelayBufSize)
		for {
			select {
			case <-sess.Ctx.Done():
				return
			default:
			}
			n, rerr := destConn.Read(buf)
			if n > 0 {
				s.metrics.incDown(int64(n))
				if werr := downC.WriteFrame(streamID, mux.FrameData, buf[:n]); werr != nil {
					s.logger.Printf("Stream %d down-carrier write: %v", streamID, werr)
					sess.Close("down carrier write failed")
					return
				}
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					// Target finished: propagate FrameClose over the
					// down-carrier, then half-close this direction.
					_ = downC.WriteFrame(streamID, mux.FrameClose, nil)
					sess.MarkDirClosed(session.DirDown, "target EOF")
				} else {
					s.logger.Printf("Stream %d target read: %v", streamID, rerr)
					sess.Close("target read error")
				}
				return
			}
		}
	}()

	// Wait for the up direction to end, then give the down relay a grace
	// period to drain (the target normally closes right after responding),
	// so a misbehaving server cannot pin the session forever.
	<-upDone
	select {
	case <-downDone:
	case <-time.After(10 * time.Second):
		sess.Close("target did not finish after client EOF")
	}
	<-downDone                  // if the timeout closed the session, wait for the relay
	sess.Close("session ended") // idempotent finalizer
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
	br, err := mux.CarrierAuth(ctx, conn, false, mux.RoleDownload, s.secret)
	cancel()
	if err != nil {
		s.logger.Printf("Down-carrier auth failed from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	s.logger.Printf("Down-carrier authenticated from %s", conn.RemoteAddr())

	carrier := mux.NewCarrierConn(conn, s.config.KeepAliveInterval)
	carrier.SetReadBuffer(br)
	carrier.SetStreamLimits(s.streamLimits())
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
