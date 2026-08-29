package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
	"github.com/gorilla/websocket"
)

// newTestUpSplitter builds a Germany-role Splitter with inert
// dependencies (no listeners, no carriers installed): just enough for the
// up-carrier connection path to run the production dial+auth code.
func newTestUpSplitter(t *testing.T) *Splitter {
	t.Helper()
	cfg := config.Defaults()
	logger := log.New(io.Discard, "", 0)
	n := node.NewNode(node.Config{
		Role:              node.RoleGermany,
		Grace:             time.Duration(cfg.CarrierGraceMs) * time.Millisecond,
		BufferBytes:       cfg.SessionBufBytes,
		RelayBufSize:      cfg.RelayBufSize,
		KeepAliveInterval: cfg.KeepAliveInterval,
		StreamLimits:      streamLimits(cfg),
	}, logger, mux.DeriveSecret("germany-test-secret-01234567890123456789"))
	t.Cleanup(n.Close)
	return &Splitter{config: cfg, node: n, logger: logger}
}

// wsURL rewrites an httptest http:// URL to the ws:// scheme and appends
// the carrier path.
func wsURL(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	return "ws" + ts.URL[len("http"):] + "/upload"
}

// TestUpCarrierSilentPeer is the production-path regression: a WebSocket
// server that completes the HTTP upgrade but NEVER sends the
// authentication challenge (silent peer). The Germany dial + CarrierAuth
// must not block forever: the handshake bound fires, the goroutine
// returns, and the connection is closed. Uses a short test-specific bound
// via the documented mux.AuthTimeout test hook (no real 15 s wait).
func TestUpCarrierSilentPeer(t *testing.T) {
	orig := mux.AuthTimeout
	mux.AuthTimeout = 300 * time.Millisecond // short test-specific bound
	defer func() { mux.AuthTimeout = orig }()

	var upgraded atomic.Bool
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		upgraded.Store(true)
		// Silent peer: never send the challenge. Hold the socket until
		// the client gives up and closes it.
		buf := make([]byte, 1024)
		_, _ = (&wsConn{conn: conn}).Read(buf)
	}))
	t.Cleanup(ts.Close)

	s := newTestUpSplitter(t)
	url := wsURL(t, ts)

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- s.runUpCarrierOnce(url) }()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("up-carrier run completed against a silent peer")
		}
		if elapsed > 3*time.Second {
			t.Fatalf("up-carrier auth blocked for %v; the handshake bound was not enforced on wsConn", elapsed)
		}
		if !upgraded.Load() {
			t.Fatal("WebSocket upgrade never completed before the auth bound")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("up-carrier auth blocked forever: the silent peer held the handshake")
	}
}

// TestUpCarrierAuthSuccess verifies the normal authenticated path is
// unaffected by the bound: a peer that completes the v1 challenge/response
// handshake yields a successful auth over the production wsConn adapter,
// with the returned bufio.Reader ready to feed the carrier.
func TestUpCarrierAuthSuccess(t *testing.T) {
	s := newTestUpSplitter(t)
	secret := s.node.Secret()

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		ws := &wsConn{conn: conn}
		if _, err := mux.CarrierAuth(context.Background(), ws, false, mux.RoleUpload, secret); err != nil {
			return
		}
		// Stay up: consume frames until the client closes.
		buf := make([]byte, 4096)
		for {
			if _, err := ws.Read(buf); err != nil {
				return
			}
		}
	}))
	t.Cleanup(ts.Close)

	url := wsURL(t, ts)
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	wsc := &wsConn{conn: conn}
	br, err := mux.CarrierAuth(context.Background(), wsc, true, mux.RoleUpload, secret)
	if err != nil {
		t.Fatalf("client auth failed against a live peer: %v", err)
	}
	if br == nil {
		t.Fatal("auth returned a nil bufio.Reader")
	}
}
