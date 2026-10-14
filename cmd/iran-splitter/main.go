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

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/backoff"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
	"github.com/gorilla/websocket"
)

// buildInfo is stamped at build time by the reproducible build script
// (scripts/build-linux.sh) via -ldflags "-X main.buildInfo=<git-commit>". It is
// empty in local/dev builds. It carries only a non-secret build identity.
var buildInfo = ""

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
// generations, session/carrier attachments, the rebind protocol and
// the grace-window logic live in pkg/node (the Phase 5 engine). This
// binary only provides the TRANSPORTS:
//
//   - the SOCKS5 listener (local Xray → us),
//   - the up-carrier WebSocket server (Germany dials /upload),
//   - the down-carrier TCP dial (us → local Xray),
//   - the metrics listener.
//
// Authenticated transport connections are handed to the node via
// InstallUp/InstallDown; the node owns every carrier from that point
// (dispatch, loss sweep, rebind sweep, replacement). There is no
// second carrier- or session-management implementation in this file.

type Splitter struct {
	config *config.Config
	node   *node.Node
	logger *log.Logger

	// socksCreds is the immutable RFC 1929 credential view for the SOCKS
	// server (plans/socks5-auth-design.md §6.3): built once in main()
	// before any goroutine starts, then read-only, so no new
	// synchronization is introduced (race-safe by construction, §7.7).
	socksCreds socksCredentials

	// socksSources is the immutable source-IP allowlist view for the SOCKS
	// server (opt-in; zero value = allow all sources). Built once in main()
	// before any goroutine starts, read-only after (race-safe by
	// construction, same property as socksCreds).
	socksSources socksAllowedSources

	lnMu    sync.Mutex
	socksLn net.Listener
	upLn    net.Listener
	mLn     net.Listener

	// Up-carrier auth-failure backoff state (Phase 6): the node's
	// UpReady() feeds the single-carrier rule; these counters feed the
	// 429 backoff on repeated authentication failures.
	authFailMu sync.Mutex
	authFails  int
	authFailAt time.Time
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

// activeTargetAddrPolicy computes the ACTIVE egress-target address-family
// policy for operator logging (kept symmetric with germany-splitter;
// inert on the Iran role). The strictest of the legacy hard filter and the
// enum wins: "ipv4-only" beats "prefer-ipv4", which beats "default".
func activeTargetAddrPolicy(onlyIPv4 bool, policy string) string {
	if onlyIPv4 || policy == "ipv4-only" {
		return "ipv4-only"
	}
	if policy == "prefer-ipv4" {
		return "prefer-ipv4"
	}
	return "default"
}

// downCarrierIDs returns the node's static down-carrier priority order for the
// split node's constructor. Multi-carrier is always OFF in single-carrier
// deployments (the default), so this returns the single-instance set; when
// enabled it returns the two-instance set (primary first).
func downCarrierIDs(cfg *config.Config) []node.CarrierID {
	if cfg.MultiCarrierEnabled {
		return []node.CarrierID{node.DefaultDownCarrierID, node.SecondDownCarrierID}
	}
	return []node.CarrierID{node.DefaultDownCarrierID}
}

// nodePolicyConfig maps the operator-configurable Phase 3 fields onto a copy of
// the documented starting values (node.PolicyConfigDefaults). Only the knobs
// exposed as environment variables are overridden; every other field keeps the
// library default. The result is inert in single-carrier nodes: the policy
// engine is only constructed when DownCarrierIDs has two or more entries.
func nodePolicyConfig(cfg *config.Config) node.PolicyConfig {
	pc := node.PolicyConfigDefaults()
	pc.Mode = cfg.PolicyMode
	pc.TopK = cfg.PolicyTopK
	pc.ProbingEnabled = cfg.ProbingEnabled
	pc.ProbeURL = cfg.ProbeURL
	// 0 is the "disable the daily budget gate" sentinel; a non-negative value
	// (bytes) is a hard cap. Negative values are rejected by config validation.
	pc.ProbeDailyBudgetBytes = cfg.ProbeDailyBudget
	if cfg.TTFBBaselineMs > 0 {
		pc.TTFBBaseline = time.Duration(cfg.TTFBBaselineMs) * time.Millisecond
	}
	return pc
}

// secondDialSuffix renders the optional second down-carrier dial-target
// suffix for the startup log line (empty when multi-carrier is disabled).
func secondDialSuffix(cfg *config.Config) string {
	if cfg.MultiCarrierEnabled {
		return fmt.Sprintf(" | Down-carrier #2 (multi-carrier) → %s", cfg.DownCarrierAddr2)
	}
	return ""
}

func main() {
	// --version / -version: print the reproducible-build commit stamp
	// (scripts/build-linux.sh embeds it via -X main.buildInfo). No other
	// behavior changes; it exits before any listener or unit work.
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		commit := buildInfo
		if commit == "" {
			commit = "dev"
		}
		fmt.Println("iran-splitter buildInfo:", commit)
		return
	}
	// Phase 8 (installer): `--validate-config` runs the Phase 7
	// load→parse→validate→construct path and exits BEFORE any listener
	// is opened or goroutine started. install.sh uses this as a
	// pre-install gate so a misconfigured deployment is reported before
	// the systemd unit is written. No other argument is interpreted;
	// normal startup is unchanged.
	if len(os.Args) > 1 && os.Args[1] == "--validate-config" {
		vcfg, err := config.Load(config.RoleIran)
		if err != nil {
			log.Fatalf("iran-splitter: %v", err)
		}
		log.Printf("iran-splitter: configuration OK (role: %s)", config.RoleIran)
		// Operator visibility for the opt-in egress-target address-family
		// policy (kept symmetric with germany-splitter even though the
		// Iran role currently never dials egress targets).
		// Operator visibility for the egress-target address-family policy
		// (kept symmetric with germany-splitter even though the Iran role
		// currently never dials egress targets — the line is informational
		// and marks the field as inert here).
		activePolicy := activeTargetAddrPolicy(vcfg.TargetOnlyIPv4, vcfg.TargetAddrPolicy)
		log.Printf("iran-splitter: target dial policy = %s (inert on this role: no egress target dial)", activePolicy)
		return
	}

	// Phase 7: load → parse → validate the ENTIRE configuration before
	// any listener opens or goroutine starts. Load reports every problem
	// at once (aggregated) and enforces the Phase 6 secret policy.
	cfg, err := config.Load(config.RoleIran)
	if err != nil {
		log.Fatalf("iran-splitter: %v", err)
	}
	logger := log.New(os.Stderr, "[iran-splitter] ", log.LstdFlags)
	n, err := node.NewNode(node.Config{
		Role:  node.RoleIran,
		Grace: time.Duration(cfg.CarrierGraceMs) * time.Millisecond,
		// Issue #7: bounded bootstrap wait for a temporarily down carrier
		// (0 = node's library default, 30 s).
		BootstrapWait: time.Duration(cfg.BootstrapWaitMs) * time.Millisecond,
		BufferBytes:   cfg.SessionBufBytes,
		// Issue #6: node-level aggregate session-buffer budget (0 =
		// node's library default, 32 MiB).
		SessionBufferTotalBytes: cfg.SessionBufTotal,
		RelayBufSize:            cfg.RelayBufSize,
		KeepAliveInterval:       cfg.KeepAliveInterval,
		LivenessRounds:          cfg.LivenessRounds,
		StreamLimits:            streamLimits(cfg),
		// Phase B: credit flow-control master flag (SPLIT_CREDITS_ENABLED).
		CreditsEnabled: cfg.CreditsEnabled,
		// Opt-in only-IPv4 egress-target policy (SPLIT_TARGET_ONLY_IPV4).
		// Set for both roles (keeps config symmetric; only the Germany
		// role currently dials egress targets, so this is inert on Iran).
		TargetOnlyIPv4: cfg.TargetOnlyIPv4,
		// Opt-in egress-target address-family policy (SPLIT_TARGET_ADDR_POLICY,
		// SUBTASK 42); inert on the Iran role (no egress target dial) but
		// kept for config symmetry.
		TargetAddrPolicy: cfg.TargetAddrPolicy,
		// up-carrier drop-storm fix (Parts 2 & 3): bounded target-dial ceiling
		// + per-target dial-failure circuit breaker + jittered retry backoff.
		// Set on BOTH roles for config symmetry (inert on Iran, which never
		// dials egress targets). All default OFF → byte-identical healthy path.
		TargetDialBoundedMs:     cfg.TargetDialBoundMs,
		TargetBreakerEnabled:    cfg.TargetBreakerEnabled,
		TargetBreakerWindowMs:   cfg.TargetBreakerWindowMs,
		TargetBreakerThreshold:  cfg.TargetBreakerThreshold,
		TargetBreakerCooldownMs: cfg.TargetBreakerCooldownMs,
		TargetBreakerMaxTargets: cfg.TargetBreakerMaxTargets,
		TargetBackoffEnabled:    cfg.TargetBackoffEnabled,
		TargetBackoffBaseMs:     cfg.TargetBackoffBaseMs,
		TargetBackoffMaxMs:      cfg.TargetBackoffMaxMs,
		// Phase 2 multi-carrier down plane: when enabled, the node's down
		// registry holds the static-priority two-instance set (primary first),
		// enabling per-carrier pinning and the v2 rebind wire.
		DownCarrierIDs: downCarrierIDs(cfg),
		// Phase 3 carrier-intelligence policy (inert when single-carrier;
		// the policy engine is constructed only when DownCarrierIDs has two
		// or more entries). Operator-configurable fields are overridden on
		// top of the documented starting values (PolicyConfigDefaults).
		PolicyCfg: nodePolicyConfig(cfg),
	}, logger, mux.DeriveSecret(cfg.Secret))
	if err != nil {
		log.Fatalf("iran-splitter: node construction: %v", err)
	}
	// Phase 3: start the 10 s policy evaluation ticker. No-op when the
	// node is single-carrier (n.policy is nil). The ticker drives Evaluate
	// and the probe scheduler on the wall clock.
	n.StartPolicyTicker()

	s := &Splitter{
		config:       cfg,
		node:         n,
		logger:       logger,
		socksCreds:   newSocksCredentials(cfg),
		socksSources: newSocksAllowedSources(cfg),
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup

	if cfg.MetricsPort > 0 {
		wg.Add(1)
		go func() { defer wg.Done(); s.runMetrics(metricsListenAddr(cfg.MetricsPort)) }()
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

	// Phase 2 multi-carrier: when enabled, a SECOND down-carrier dialer
	// targets DownCarrierAddr2 (the local second Xray consumer inbound) and
	// is installed under the secondary CarrierID.
	if cfg.MultiCarrierEnabled {
		s.logger.Printf("Down-carrier #2 (multi-carrier) dial: %s", cfg.DownCarrierAddr2)
		wg.Add(1)
		go func() { defer wg.Done(); s.runDownCarrier2() }()
	}

	s.logger.Printf("SOCKS5: %s | Up-carrier WS: %s | Down-carrier → %s%s",
		cfg.SocksListen, cfg.WsListen, cfg.DownCarrierAddr, secondDialSuffix(cfg))
	s.logger.Println("iran-splitter started")

	<-sigCh
	s.logger.Println("Shutting down...")
	s.node.Close() // Phase 4 authoritative session teardown + carrier close
	s.closeListeners()
	wg.Wait()
	s.logger.Println("iran-splitter stopped")
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
		// Single-carrier rule (Phase 6): the node's UpReady() reports
		// whether a live up carrier is currently installed.
		if s.node.UpReady() {
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

// handleUpWsConn authenticates one accepted WebSocket connection (v1
// challenge/response, Phase 6) and hands the transport to the node.
// The handler returns only when the carrier's dispatcher has exited —
// the node's InstallUp runs the loss sweep + rebind sweep for the
// replacement lifecycle asynchronously, so a fast Germany reconnect
// can be served from the ACCEPT loop while the previous carrier is
// still settling.
func (s *Splitter) handleUpWsConn(ws *websocket.Conn) {
	wsc := &wsConn{conn: ws}

	// The WS adapter cannot enforce deadlines, so CarrierAuth itself
	// bounds this handshake: it races each read against AuthTimeout
	// (and the context, where one is given) and closes the connection
	// on expiry, which interrupts the blocked read.
	br, err := mux.CarrierAuth(context.Background(), wsc, false, mux.RoleUpload, s.secret())
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

	h := s.node.InstallUp(wsc, br)
	<-h.Done()
}

func (s *Splitter) secret() []byte { return s.node.Secret() }

// ============================================================
// Down-Carrier: TCP client → 127.0.0.1:10802 (local Xray inbound
// that tunnels over VLESS+Reality to Germany's :9002)
// ============================================================
//
// Reconnect loop with a configurable, bounded internal/backoff schedule
// (exponential base → cap, plus a cumulative reconnect window so a brief
// underlay blip cannot amplify into a multi-minute outage; jittered, reset
// on a successfully authenticated carrier; shutdown-cancellable via the node
// context). See docs/carrier-reconnect-backoff.md. Each authenticated
// transport is installed on the node, which owns it from there.

const downDialTimeout = 10 * time.Second

// runDownCarrier is the PRIMARY down-carrier dial loop (D1 instance A).
// Phase 2 multi-carrier keeps this loop for the single-carrier case; a
// second instance dials DownCarrierAddr2 on runDownCarrier2 when enabled.
func (s *Splitter) runDownCarrier() { s.runDownInstance(false) }

// runDownCarrier2 is the SECOND down-carrier dial loop (D1 instance B,
// D4: dials the second local Xray consumer inbound).
func (s *Splitter) runDownCarrier2() { s.runDownInstance(true) }

// runDownInstance is the down-carrier reconnect loop for one named instance:
// dial → v1 handshake → install under the instance's CarrierID. Each instance
// owns its own backoff and reconnects independently, so losing one down
// carrier never disturbs the other.
func (s *Splitter) runDownInstance(secondary bool) {
	var id node.CarrierID
	var addr string
	if secondary {
		id = s.node.SecondaryDownCarrierID()
		addr = s.config.DownCarrierAddr2
	} else {
		id = s.node.DownCarrierIDs()[0]
		addr = s.config.DownCarrierAddr
	}
	b := s.reconnectBackoff()
	windowExhaustedLogged := false
	for {
		if s.node.Shutdown() {
			return
		}
		// An already-live instance does not need a reconnect: skip the dial
		// while its CarrierID is installed and ready. In single-carrier mode
		// this collapses to the original DownReady() behavior; in
		// multi-carrier mode each instance is gated on its own slot so the
		// two carriers reconnect independently.
		if s.node.DownCarrierReady(id) {
			if s.backoffSleep(b) {
				return
			}
			continue
		}
		conn, err := net.DialTimeout("tcp", addr, downDialTimeout)
		if err != nil {
			s.logger.Printf("Down-carrier %s dial %s: %v", id, addr, err)
			if b.WindowExhausted() && !windowExhaustedLogged {
				s.logger.Printf("Down-carrier %s: reconnect window exhausted; probing every %v",
					id, time.Duration(s.config.ReconnectClampMs)*time.Millisecond)
				windowExhaustedLogged = true
			}
			if s.backoffSleep(b) {
				return
			}
			continue
		}

		ctx, cancel := context.WithTimeout(s.node.Context(), 15*time.Second)
		br, err := mux.CarrierAuth(ctx, conn, true, mux.RoleDownload, s.secret())
		cancel()
		if err != nil {
			s.logger.Printf("Down-carrier %s auth to %s: %v", id, addr, err)
			conn.Close()
			if b.WindowExhausted() && !windowExhaustedLogged {
				s.logger.Printf("Down-carrier %s: reconnect window exhausted; probing every %v",
					id, time.Duration(s.config.ReconnectClampMs)*time.Millisecond)
				windowExhaustedLogged = true
			}
			if s.backoffSleep(b) {
				return
			}
			continue
		}
		s.logger.Printf("Down-carrier %s authenticated to %s", id, addr)

		h, err := s.node.InstallDownOn(id, conn, br)
		if err != nil {
			s.logger.Printf("Down-carrier %s install failed: %v", id, err)
			if s.backoffSleep(b) {
				return
			}
			continue
		}
		<-h.Done()
		b.Reset() // a full authenticated carrier session ran
		windowExhaustedLogged = false
		s.logger.Printf("Down-carrier %s torn down (reconnecting)", id)
		if s.backoffSleep(b) {
			return
		}
	}
}

// reconnectBackoff builds the carrier reconnect schedule from config:
// exponential base → max, with the cumulative reconnect window bounded so a
// transient underlay failure cannot amplify into a multi-minute outage.
// The old hardcoded 2s→60s schedule summed to 122s across six attempts.
// See docs/carrier-reconnect-backoff.md.
func (s *Splitter) reconnectBackoff() *backoff.Backoff {
	return backoff.NewBounded(
		time.Duration(s.config.ReconnectBaseMs)*time.Millisecond,
		time.Duration(s.config.ReconnectMaxMs)*time.Millisecond,
		time.Duration(s.config.ReconnectWindowMs)*time.Millisecond,
		time.Duration(s.config.ReconnectClampMs)*time.Millisecond,
	)
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
	switch {
	case s.socksCreds.enabled && s.socksSources.enabled:
		s.logger.Printf("SOCKS5 listening on %s (auth: enabled, source allowlist: enabled)", s.config.SocksListen)
	case s.socksCreds.enabled:
		s.logger.Printf("SOCKS5 listening on %s (auth: enabled)", s.config.SocksListen)
	case s.socksSources.enabled:
		s.logger.Printf("SOCKS5 listening on %s (auth: disabled, source allowlist: enabled)", s.config.SocksListen)
	default:
		s.logger.Printf("SOCKS5 listening on %s (auth: disabled)", s.config.SocksListen)
	}
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

	dest, err := socksNegotiate(clientConn, &s.socksCreds)
	if err != nil {
		if errors.Is(err, errSocksAuthFailed) {
			// Uniform credential-free log line (plans/socks5-auth-design.md §4.1):
			// the remote address only — no username, no password, no
			// "wrong user vs wrong password" distinction. This is exactly
			// what fail2ban anchors on (§10.2).
			s.logger.Printf("SOCKS5 auth failed from %s", clientConn.RemoteAddr())
		} else {
			s.logger.Printf("SOCKS5 negotiation: %v (from %s)", err, clientConn.RemoteAddr())
		}
		clientConn.Close()
		return
	}
	_ = clientConn.SetDeadline(time.Time{})

	// Source-IP allowlist gate (opt-in, SPLIT_SOCKS_ALLOWED_SOURCES): runs
	// AFTER method/credential negotiation so the client has identified
	// itself, and BEFORE any CONNECT is issued or session allocated. An
	// unset/empty allowlist (the default) makes this a no-op, preserving
	// byte-for-byte backward compatibility. The log line matches the
	// existing "from <RemoteAddr>" convention (the remote address only —
	// never the requested destination, never credentials).
	if err := socksSourceGate(s.socksSources, clientConn.RemoteAddr()); err != nil {
		s.logger.Printf("SOCKS5 source rejected from %s", clientConn.RemoteAddr())
		clientConn.Close()
		return
	}

	s.logger.Printf("SOCKS5 CONNECT → %s:%d from %s", dest.Addr, dest.Port, clientConn.RemoteAddr())

	// Hand the session to the Phase 5 engine (pkg/node): it waits for
	// both carriers (30 s), allocates the stream ID, runs the relays
	// (with the bounded reconnect buffer) and rebinds the session
	// across carrier losses. On success it ADOPTS the client conn (the
	// session's Close becomes the only closer) and returns the session;
	// on failure it tears the session down but returns the client conn
	// to us still open, so the SOCKS error reply below is actually
	// delivered.
	sess, err := s.node.StartSession(clientConn, dest)
	if err != nil {
		s.logger.Printf("SOCKS5 %s:%d: %v", dest.Addr, dest.Port, err)
		socksReply(clientConn, 0x06) // general SOCKS server failure
		clientConn.Close()
		return
	}

	// SOCKS5 success reply. The conn may be read at any time now: from
	// this point on the client is connected to the tunnel.
	socksReply(clientConn, 0x00)
	s.logger.Printf("Session %s → %s:%d", sess.ID.String(), dest.Addr, dest.Port)
}

// ============================================================
// Metrics
// ============================================================

const metricsListenHost = "127.0.0.1"

func metricsListenAddr(port int) string {
	return net.JoinHostPort(metricsListenHost, strconv.Itoa(port))
}

func (s *Splitter) runMetrics(addr string) error {
	mhttp := http.NewServeMux()
	mhttp.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, s.node.Metrics().Render())
		fmt.Fprintf(w, "session_count %d\n", s.node.Store().Count())
		// Issue #6: current node-level aggregate usage of the shape-A
		// reconnect buffers (gauge).
		fmt.Fprintf(w, "session_buffered_bytes %d\n", s.node.SessionBufferAccounted())
		fmt.Fprint(w, s.node.QueueStats(session.DirUp).Render("mux_up_"))
		fmt.Fprint(w, s.node.QueueStats(session.DirDown).Render("mux_down_"))
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); !ok || !tcpAddr.IP.IsLoopback() {
		_ = ln.Close()
		return errors.New("metrics listener is not loopback")
	}
	s.lnMu.Lock()
	s.mLn = ln
	s.lnMu.Unlock()
	defer ln.Close()
	return http.Serve(ln, mhttp)
}
