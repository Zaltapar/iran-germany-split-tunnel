package dashboard

// tls.go — the server-hosted TLS listener (one-click dashboard design §3).
//
// The dashboard is a local-only tool by default (loopback bind, plain HTTP,
// no basePath). The one-click installer's Germany build enables TLS so the
// operator can open it from a browser on a separate high port. The public
// surface is deliberately narrow and fail-closed:
//
//   - A non-loopback listen address is accepted ONLY when TLS is enabled,
//     complete (cert + key), and carries a valid 32-hex random BasePath.
//     Every other non-loopback bind is refused exactly as before.
//   - When a BasePath is set, ALL routes (UI + /api/v1/...) are mounted under
//     /<basePath>/; anything outside that prefix returns 404. The random
//     path is the first secret of access (defense-in-depth with TLS + an
//     optional admin Bearer token).
//   - In TLS mode, every response carries security headers (HSTS, CSP,
//     X-Content-Type-Options, X-Frame-Options, Referrer-Policy).
//   - The admin Bearer token is read from the SPLIT_TUNNELDASH_TOKEN env var
//     or a token file path named by SPLIT_TUNNELDASH_TOKEN_FILE. It is never
//     logged or echoed. Mutations remain 403 (readOnly default) regardless.
//
// The token is loaded at server construction via LoadAdminToken, which the
// installer wires from the 0600 dashboard.env. Until mutations are ever
// enabled, the token gates the (future) mutation endpoints; read endpoints
// are reachable under TLS + basePath.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// EnvAdminToken and EnvAdminTokenFile are the two admin-token sources. The
// token itself is secret material: it never appears in logs, config files,
// or error strings.
const (
	EnvAdminToken     = "SPLIT_TUNNELDASH_TOKEN"
	EnvAdminTokenFile = "SPLIT_TUNNELDASH_TOKEN_FILE"
)

// LoadAdminToken resolves the dashboard admin Bearer token from the
// environment. Precedence: an explicit non-empty SPLIT_TUNNELDASH_TOKEN wins;
// otherwise SPLIT_TUNNELDASH_TOKEN_FILE names a 0600 file whose contents
// (trimmed) are the token. Neither value is echoed on error.
func LoadAdminToken() string {
	if tok := strings.TrimSpace(os.Getenv(EnvAdminToken)); tok != "" {
		return tok
	}
	path := strings.TrimSpace(os.Getenv(EnvAdminTokenFile))
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// GenerateBasePath returns a fresh 32-hex (128-bit) random base path — the
// installer's "random-ish" access secret. It is the equivalent of
// `openssl rand -hex 16`.
func GenerateBasePath() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("dashboard: generate base path: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// NewTLSServer builds a Server whose Router() mounts every route under the
// configured BasePath and whose ListenAndServeTLS serves TLS. It is the
// server-hosted path the one-click installer uses on Germany.
func NewTLSServer(cfg *DashboardConfig, cache *Cache, audit *AuditLog, mutator Mutator, auth Authenticator) *Server {
	s := NewServer(cfg, cache, audit, mutator, auth)
	s.tlsEnabled = cfg.TLS != nil && cfg.TLS.Enabled
	if !s.tlsEnabled {
		return s
	}
	s.securityHeaders = true
	return s
}

// isLoopback reports whether addr is a loopback bind.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch host {
	case "127.0.0.1", "::1", "localhost", "":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateListenAddrSecure is the relaxed bind gate: a non-loopback address
// is permitted only when TLS is enabled, complete, and a 32-hex BasePath is
// set (TLSConfig.IsSecure). Otherwise it falls back to the strict loopback
// gate. It never echoes the key material.
func (s *Server) validateListenAddrSecure(addr string) error {
	if isLoopback(addr) {
		return nil
	}
	if s.cfg.TLS != nil && s.cfg.TLS.IsSecure() {
		return nil
	}
	return fmt.Errorf(
		"dashboard: listen address %q is not loopback; a public bind requires a complete TLS config (cert, key, and a 32-hex basePath)",
		addr)
}

// ListenAndServeTLS binds the configured address and serves over TLS until
// ctx is cancelled. It requires a complete TLS config; the loopback
// relaxation (validateListenAddrSecure) is what authorizes a non-loopback
// bind.
func (s *Server) ListenAndServeTLS(ctx context.Context) error {
	if s.cfg.TLS == nil || !s.cfg.TLS.Enabled {
		return fmt.Errorf("dashboard: TLS is not enabled; refusing to serve over TLS")
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("dashboard: load TLS key pair: %w", err)
	}

	addr := s.cfg.ListenAddr
	if err := s.validateListenAddrSecure(addr); err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("dashboard: listen %s: %w", addr, err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	go s.pollLoop(ctx)

	return srv.ServeTLS(ln, "", "")
}
