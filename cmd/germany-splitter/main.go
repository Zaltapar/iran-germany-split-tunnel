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

	// Down-carrier unauthenticated-handshake gate (Issue #5): a buffered
	// semaphore bounding how many v1 handshakes may run concurrently on
	// the Internet-exposed :9002 listener. Slots are held ONLY while the
	// connection is unauthenticated (released as soon as it authenticates
	// or auth fails), so an installed carrier never consumes a slot and a
	// legitimate reconnect is never blocked. It is created by the goroutine
	// that spawns runDownCarrier (main in production; the test helpers in
	// tests) so the field write happens before the accept loop or any
	// handler reads it (no data race). Its CAPACITY is the unauthenticated-
	// handshake bound: main sizes it to maxDownHandshakes; tests size it to
	// a smaller value to make saturation deterministic. The accept loop
	// reads the bound as cap(downAuthGate) (immutable instance state), never
	// a mutable global.
	downAuthGate chan struct{}
	// downH waits for in-flight down-carrier handlers (one per accepted
	// conn) so shutdown and tests can confirm every handler exits — no
	// goroutine leak.
	downH sync.WaitGroup
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
		LivenessRounds:    cfg.LivenessRounds,
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

	// Down-Carrier: TCP server ← Iran. The unauthenticated-handshake gate
	// is created here (the spawning goroutine) so its write happens-before
	// the accept loop and every handler read it; runDownCarrier treats a
	// pre-created gate as authoritative and only creates one if absent.
	s.downAuthGate = make(chan struct{}, maxDownHandshakes)
	wg.Add(1)
	go func() { defer wg.Done(); s.runDownCarrier() }()

	s.logger.Printf("Up-carrier (WS) dial: %s | Down-carrier (TCP) listen: %s", cfg.UpWsUrl, cfg.DownListen)
	s.logger.Println("germany-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")
	s.node.Close() // Phase 4 authoritative session teardown + carrier close
	s.closeListeners()
	wg.Wait()
	// Issue #5: every in-flight down-carrier handler must exit before we
	// stop. Each is bounded (auth by AuthTimeout, install by the node
	// context / carrier close), so this completes; it guarantees no
	// goroutine is leaked past shutdown.
	s.downH.Wait()
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

// runUpCarrier is the reconnect loop (exponential backoff, reset on a
// successfully authenticated carrier, shutdown-cancellable). Each
// iteration runs one full connection attempt via runUpCarrierOnce.
func (s *Splitter) runUpCarrier() {
	b := backoff.New(2*time.Second, 60*time.Second)
	for {
		if s.node.Shutdown() {
			return
		}
		err := s.runUpCarrierOnce(s.config.UpWsUrl)
		if err != nil {
			if s.backoffSleep(b) {
				return
			}
			continue
		}
		// A full authenticated carrier session ran (or was torn down
		// after installing): reset the backoff and reconnect.
		b.Reset()
		if s.backoffSleep(b) {
			return
		}
	}
}

// runUpCarrierOnce performs a single up-carrier connection attempt:
// dial, WebSocket upgrade, v1 carrier authentication, and install. It
// returns an error when the attempt fails BEFORE a full authenticated
// carrier session ran (dial or auth failure — the connection is closed),
// and nil once the installed carrier has completed its session (normal
// teardown, the caller reconnects).
//
// The authentication handshake is bounded: the context deadline (15 s,
// derived from the node context) plus CarrierAuth's hard AuthTimeout cap
// apply to the wsConn adapter even though it cannot enforce socket
// deadlines — a peer that upgrades but never sends the challenge cannot
// hold this goroutine (or the connection) forever.
func (s *Splitter) runUpCarrierOnce(url string) error {
	conn, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		s.logger.Printf("Up-carrier dial %s: %v", url, err)
		return err
	}
	s.logger.Printf("Up-carrier WS connected (HTTP %s)", resp.Status)

	wsc := &wsConn{conn: conn}
	ctx, cancel := context.WithTimeout(s.node.Context(), 15*time.Second)
	br, err := mux.CarrierAuth(ctx, wsc, true, mux.RoleUpload, s.node.Secret())
	cancel()
	if err != nil {
		s.logger.Printf("Up-carrier auth failed: %v", err)
		conn.Close()
		return err
	}
	s.logger.Printf("Up-carrier authenticated")

	h := s.node.InstallUp(wsc, br)
	<-h.Done()
	s.logger.Printf("Up-carrier torn down (reconnecting)")
	return nil
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

// Down-carrier unauthenticated-handshake concurrency bound (Issue #5):
// the maximum number of v1 authentication handshakes that may run
// concurrently on the Internet-exposed down-carrier listener. Connections
// beyond the bound are closed promptly in the accept loop — no auth
// goroutine is spawned for them. This mirrors the Iran /upload WebSocket
// endpoint's maxConcurrentHandshakes, adapted to raw TCP where there are no
// status codes: the equivalent is an immediate close plus a rate-limited log
// line (downAuthLogInterval). It is a CONST (immutable), NOT mutable global
// state: each Splitter's gate channel is sized to a capacity at construction
// (main uses maxDownHandshakes; tests pass a smaller one), and the accept
// loop reads the bound as cap(s.downAuthGate). 16 matches the Iran WS limit
// and is ample for the 1–2 concurrent handshakes seen in legitimate
// operation.
const maxDownHandshakes = 16

// downAuthLogInterval rate-limits the saturation log: while the gate is
// saturated the accept loop closes a connection on every iteration, so an
// unthrottled log would itself become a resource-exhaustion vector.
const downAuthLogInterval = time.Second

// runDownCarrier is the down-carrier accept loop. It gates each accepted
// connection through a non-blocking handshake semaphore (maxDownHandshakes)
// BEFORE spawning a handler: the gate is acquired in the accept loop and is
// never blocked on, so saturation closes the connection immediately without
// consuming an auth goroutine and the accept loop itself stays responsive.
func (s *Splitter) runDownCarrier() {
	ln := s.downLn // may be pre-configured (tests); production leaves it nil
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", s.config.DownListen)
		if err != nil {
			s.logger.Fatalf("Down-carrier listener: %v", err)
		}
		s.lnMu.Lock()
		s.downLn = ln
		s.lnMu.Unlock()
	}
	defer ln.Close()
	// The gate is normally created by the spawning goroutine (see main),
	// so its field write happens-before the accept loop reads it. Only
	// create it here if the caller (a test) did not pre-create one.
	if s.downAuthGate == nil {
		s.downAuthGate = make(chan struct{}, maxDownHandshakes)
	}
	s.logger.Printf("Down-carrier listening on %s (max %d concurrent handshakes)", ln.Addr(), cap(s.downAuthGate))
	var lastSatLog time.Time
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Gate the UNAUTHENTICATED handshake. The slot is held only while
		// the connection is unauthenticated (handleDownConn releases it as
		// soon as auth completes or fails), so a long-lived installed
		// carrier never occupies a slot and a legitimate reconnect can
		// never be starved by the gate: a legit carrier can only begin
		// authenticating when DownReady() is false, i.e. when no carrier
		// is installed holding a slot.
		select {
		case s.downAuthGate <- struct{}{}:
			s.downH.Add(1)
			go s.handleDownConn(conn, func() { <-s.downAuthGate })
		default:
			// Saturated: close promptly. Rate-limited log (the TCP
			// analogue of the WS endpoint's 429/503 backoff).
			now := time.Now()
			if now.Sub(lastSatLog) >= downAuthLogInterval {
				lastSatLog = now
				s.logger.Printf("Down-carrier: rejected %s (max %d concurrent handshakes)", conn.RemoteAddr(), cap(s.downAuthGate))
			}
			conn.Close()
		}
	}
}

// handleDownConn processes one accepted down-carrier connection: the
// single-carrier DownReady() check, the bounded v1 authentication
// handshake, and installation of the authenticated carrier on the node.
// releaseSlot frees the accept-loop handshake slot; it is invoked exactly
// once per connection, as soon as the connection is no longer
// unauthenticated (auth success or failure) so the installed carrier holds
// no slot.
func (s *Splitter) handleDownConn(conn net.Conn, releaseSlot func()) {
	defer s.downH.Done()

	// Only one down-carrier at a time — reject secondaries cleanly
	// (the node's DownReady() reports whether one is installed).
	if s.node.DownReady() {
		releaseSlot()
		s.logger.Printf("Down-carrier: rejected %s (already connected)", conn.RemoteAddr())
		conn.Close()
		return
	}

	ctx, cancel := context.WithTimeout(s.node.Context(), 15*time.Second)
	br, err := mux.CarrierAuth(ctx, conn, false, mux.RoleDownload, s.node.Secret())
	cancel()
	// Authentication has concluded (succeeded or failed): release the
	// handshake slot. The carrier must not keep it for its lifetime.
	releaseSlot()
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
