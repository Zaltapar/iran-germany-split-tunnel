package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
	"github.com/gorilla/websocket"
)

// newTestSplitter builds a Splitter with inert dependencies for HTTP
// handler tests (no listeners, no carriers).
func newTestSplitter() *Splitter {
	return &Splitter{
		config:  &Config{},
		store:   session.NewSessionStore(),
		metrics: &Metrics{},
		logger:  log.New(io.Discard, "", 0),
		secret:  mux.DeriveSecret("test-secret-must-be-long-enough-0123456789"),
	}
}

func newUploadServer(t *testing.T, s *Splitter) *httptest.Server {
	t.Helper()
	m := http.NewServeMux()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	m.HandleFunc("/upload", s.uploadHandler(upgrader))
	ts := httptest.NewServer(m)
	t.Cleanup(ts.Close)
	return ts
}

// TestUploadHandlerPathAndMethod verifies the HTTP surface of /upload:
// unknown paths are 404, non-GET methods are 405, and a plain (non
// WebSocket) request is rejected with 400 before any carrier is created.
func TestUploadHandlerPathAndMethod(t *testing.T) {
	s := newTestSplitter()
	ts := newUploadServer(t, s)

	resp, err := http.Get(ts.URL + "/definitely-not-the-carrier")
	if err != nil {
		t.Fatalf("GET /other: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path status = %d, want 404", resp.StatusCode)
	}

	resp, err = http.Post(ts.URL+"/upload", "application/octet-stream", nil)
	if err != nil {
		t.Fatalf("POST /upload: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", resp.StatusCode)
	}

	// A normal GET (no Upgrade header) cannot become a carrier.
	resp, err = http.Get(ts.URL + "/upload")
	if err != nil {
		t.Fatalf("GET /upload: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("non-WS GET status = %d, want 400", resp.StatusCode)
	}
}

// TestUploadHandlerAuthBackoff verifies that after a burst of failed
// authentications the handler rejects new handshakes with 429, and that a
// successful authentication resets the backoff.
func TestUploadHandlerAuthBackoff(t *testing.T) {
	s := newTestSplitter()
	ts := newUploadServer(t, s)

	for i := 0; i < authFailBackoffLimit; i++ {
		s.recordAuthFail()
	}
	if !s.authInBackoff() {
		t.Fatal("authInBackoff = false after the failure limit")
	}
	resp, err := http.Get(ts.URL + "/upload")
	if err != nil {
		t.Fatalf("GET /upload: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status during backoff = %d, want 429", resp.StatusCode)
	}

	// Success resets: backoff clears and the handler proceeds to the
	// upgrade attempt (which fails with 400 — it is not a WS request).
	s.clearAuthFails()
	if s.authInBackoff() {
		t.Fatal("authInBackoff still true after clearAuthFails")
	}
	resp, err = http.Get(ts.URL + "/upload")
	if err != nil {
		t.Fatalf("GET /upload after reset: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Fatal("still in backoff after clearAuthFails")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status after reset = %d, want 400 (non-WS upgrade failure)", resp.StatusCode)
	}
}

// TestAuthFailBackoffWindowReset verifies the counter logic directly:
// the burst window lapses, stale failures do not count toward the limit,
// and the limit triggers the backoff.
func TestAuthFailBackoffWindowReset(t *testing.T) {
	s := newTestSplitter()

	// Stale burst (older than the window): must not be in backoff.
	s.authFailMu.Lock()
	s.authFails = 100
	s.authFailAt = time.Now().Add(-2 * authFailBackoffWindow)
	s.authFailMu.Unlock()
	if s.authInBackoff() {
		t.Fatal("stale failures still trigger backoff")
	}

	// recordAuthFail after the window lapsed restarts the burst at 1.
	s.recordAuthFail()
	s.authFailMu.Lock()
	n := s.authFails
	s.authFailMu.Unlock()
	if n != 1 {
		t.Fatalf("authFails = %d after window-lapse record, want 1", n)
	}

	// Fresh burst reaches the limit.
	for i := 0; i < authFailBackoffLimit-1; i++ {
		s.recordAuthFail()
	}
	if !s.authInBackoff() {
		t.Fatal("backoff not active at the failure limit")
	}
}
