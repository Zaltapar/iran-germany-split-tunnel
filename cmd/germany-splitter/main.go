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

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/backoff"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
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
// Splitter — thin transport wrapper around pkg/node
// ============================================================
//
// Phase 5 production wiring: ALL carrier ownership, carrier
// generations, session/carrier attachments, the rebind protocol
// (handling Iran's FrameRebind on both directions) and the grace-
// window logic live in pkg/node (the Phase 5 engine). This binary
// only provides the TRANSPORTS:
//
//   - the up-carrier WebSocket dial (us → wss://<cdn-domain>/upload),
//   - the down-carrier TCP listener (Iran lands here via VLESS+Reality),
//   - the metrics listener.
//
// Authenticated transport connections are handed to the node via
// InstallUp/InstallDown; the node owns every carrier from that point
// (dispatch, loss sweep, re-attach on rebind, replacement). Target
// dialing uses the node's default TargetDial (10 s TCP), identical
// to the pre-wiring behavior. There is no second carrier- or
// session-management implementation in this file.

type Splitter struct {
	config *config.Config
	node   *node.Node
	logger *log.Logger

	lnMu   sync.Mutex
	downLn net.Listener
	mLn    net.Listener
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
	// Phase 8 (installer): `--validate-config` runs the Phase 7
	// load→parse→validate→construct path and exits BEFORE any listener
	// is opened or goroutine started. install.sh uses this as a
	// pre-install gate so a misconfigured deployment is reported before
	// the systemd unit is written. No other argument is interpreted;
	// normal startup is unchanged.
	if len(os.Args) > 1 && os.Args[1] == "--validate-config" {
		if _, err := config.Load(config.RoleGermany); err != nil {
			log.Fatalf("germany-splitter: %v", err)
		}
		log.Printf("germany-splitter: configuration OK (role: %s)", config.RoleGermany)
		return
	}

	// Phase 7: load → parse → validate the ENTIRE configuration before
	// any listener opens or goroutine starts. Load reports every problem
	// at once (aggregated) and enforces the Phase 6 secret policy.
	cfg, err := config.Load(config.RoleGermany)
	if err != nil {
		log.Fatalf("germany-splitter: %v", err)
	}

	logger := log.New(os.Stderr, "[germany-splitter] ", log.LstdFlags)
	n := node.NewNode(node.Config{
		Role:              node.RoleGermany,
		Grace:             time.Duration(cfg.CarrierGraceMs) * time.Millisecond,
		BufferBytes:       cfg.SessionBufBytes,
		RelayBufSize:      cfg.RelayBufSize,
		KeepAliveInterval: cfg.KeepAliveInterval,
		StreamLimits:      streamLimits(cfg),
	}, logger, mux.DeriveSecret(cfg.Secret))

	s := &Splitter{
		config: cfg,
		node:   n,
		logger: logger,
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
	s.node.Close() // Phase 4 authoritative session teardown + carrier close
	s.closeListeners()
	wg.Wait()
	s.logger.Println("germany-splitter stopped")
}

// streamLimits builds the per-stream mailbox limits from config (Phase 3
// backpressure policy, applied by the node to every installed carrier).
// Zero values fall back to mux.DefaultStreamLimits via SanitizeLimits.
func streamLimits(cfg *config.Config) mux.StreamLimits {
	return mux.StreamLimits{
		MaxBytesPerStream:  cfg.QueueBytesPerStream,
		MaxFramesPerStream: cfg.QueueFramesPerStream,
		MaxBytesTotal:      cfg.QueueBytesTotal,
		OverflowWait:       time.Duration(cfg.OverflowWaitMs) * time.Millisecond,
	}
}

// ============================================================
// Up-Carrier: WebSocket client → wss://<cdn-domain>/upload
// Reconnect loop with internal/backoff (2s → 60s, jittered, reset on
// a successfully authenticated carrier; shutdown-cancellable via the
// node context).
// ============================================================

func (s *Splitter) runUpCarrier() {
	b := backoff.New(2*time.Second, 60*time.Second)
	for {
		if s.node.Shutdown() {
			return
		}
		conn, resp, err := websocket.DefaultDialer.Dial(s.config.UpWsUrl, nil)
		if err != nil {
			s.logger.Printf("Up-carrier dial %s: %v", s.config.UpWsUrl, err)
			if s.backoffSleep(b) {
				return
			}
			continue
		}
		s.logger.Printf("Up-carrier WS connected (HTTP %s)", resp.Status)

		wsc := &wsConn{conn: conn}
		ctx, cancel := context.WithTimeout(s.node.Context(), 15*time.Second)
		br, err := mux.CarrierAuth(ctx, wsc, true, mux.RoleUpload, s.node.Secret())
		cancel()
		if err != nil {
			s.logger.Printf("Up-carrier auth failed: %v", err)
			conn.Close()
			if s.backoffSleep(b) {
				return
			}
			continue
		}
		s.logger.Printf("Up-carrier authenticated")

		h := s.node.InstallUp(wsc, br)
		<-h.Done()
		b.Reset() // a full authenticated carrier session ran
		s.logger.Printf("Up-carrier torn down (reconnecting)")
		if s.backoffSleep(b) {
			return
		}
	}
}

// backoffSleep waits for the next jittered delay; returns true when the
// node is shutting down and the loop must stop.
func (s *Splitter) backoffSleep(b *backoff.Backoff) bool {
	if err := b.Sleep(s.node.Context()); err != nil {
		return true // node context cancelled — shutting down
	}
	return s.node.Shutdown()
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
	// (the node's DownReady() reports whether one is installed).
	if s.node.DownReady() {
		s.logger.Printf("Down-carrier: rejected %s (already connected)", conn.RemoteAddr())
		conn.Close()
		return
	}

	ctx, cancel := context.WithTimeout(s.node.Context(), 15*time.Second)
	br, err := mux.CarrierAuth(ctx, conn, false, mux.RoleDownload, s.node.Secret())
	cancel()
	if err != nil {
		s.logger.Printf("Down-carrier auth failed from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	s.logger.Printf("Down-carrier authenticated from %s", conn.RemoteAddr())

	h := s.node.InstallDown(conn, br)
	<-h.Done()
	s.logger.Printf("Down-carrier torn down (waiting for reconnect)")
}

// ============================================================
// Metrics
// ============================================================

func (s *Splitter) runMetrics(addr string) error {
	mhttp := http.NewServeMux()
	mhttp.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, s.node.Metrics().Render())
		fmt.Fprintf(w, "session_count %d\n", s.node.Store().Count())
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
