package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is the dashboard's HTTP API and embedded UI. It binds to a
// loopback-only address by default and refuses to start on a public
// interface in the safe default configuration.
//
// Safety invariants enforced by this server:
//   - No command execution from HTTP request parameters.
//   - No arbitrary shell or remote-execution endpoint.
//   - All request bodies are size-bounded (64 KiB default).
//   - Path IDs are validated against a strict character set.
//   - Log and config values are redacted before display.
//   - The apply endpoint is gated behind config flags and an injectable
//     Mutator; the default nil mutator refuses every apply.
//   - In server-hosted TLS mode (NewTLSServer), every response carries
//     security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options,
//     Referrer-Policy), all routes are mounted under a random 32-hex
//     BasePath, and non-loopback binds are authorized only with a complete
//     TLS config.
type Server struct {
	cfg       *DashboardConfig
	cache     *Cache
	audit     *AuditLog
	mutator   Mutator
	auth      Authenticator
	origin    *OriginChecker
	startTime time.Time

	// tlsEnabled marks a server-hosted TLS build (NewTLSServer). It drives
	// the security-headers middleware and the basePath route prefix.
	tlsEnabled bool
	// securityHeaders is a derived convenience flag (true when tlsEnabled).
	securityHeaders bool

	// planMu guards plans and planTimes for concurrent HTTP handlers.
	planMu sync.RWMutex
	// plans holds dry-run plan results by planID for the apply endpoint.
	// Bounded: when the cap is reached the oldest entry is evicted; entries
	// older than planTTL are dropped lazily on access.
	plans     map[string]*PlanResult
	planTimes map[string]time.Time

	// requestBodyLimit caps POST request bodies.
	requestBodyLimit int64
}

// planTTL bounds how long a stored dry-run plan remains usable by the apply
// endpoint. Plans are re-creatable, so expiry only frees memory.
const planTTL = 1 * time.Hour

// NewServer wires the HTTP server. mutator and auth may be nil; they fall
// back to the safe defaults (nil mutator, loopback authenticator).
func NewServer(cfg *DashboardConfig, cache *Cache, audit *AuditLog, mutator Mutator, auth Authenticator) *Server {
	if mutator == nil {
		mutator = NewNilMutator()
	}
	if auth == nil {
		auth = NewLoopbackAuthenticator()
	}
	return &Server{
		cfg:              cfg,
		cache:            cache,
		audit:            audit,
		mutator:          mutator,
		auth:             auth,
		origin:           NewOriginChecker(""),
		startTime:        time.Now(),
		plans:            map[string]*PlanResult{},
		planTimes:        map[string]time.Time{},
		requestBodyLimit: 64 << 10, // 64 KiB
	}
}

// Router returns the complete HTTP handler: API + embedded UI + middleware.
// In the server-hosted TLS build (s.tlsEnabled) the entire surface is
// additionally mounted under the random 32-hex BasePath; requests outside
// that prefix are 404'd (the path is the first secret of access).
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()

	// API v1.
	mux.HandleFunc("/api/v1/overview", s.apiHandler(s.handleOverview))
	mux.HandleFunc("/api/v1/servers", s.apiHandler(s.handleServers))
	mux.HandleFunc("/api/v1/servers/", s.apiHandler(s.handleServerSub))
	mux.HandleFunc("/api/v1/audit", s.apiHandler(s.handleAudit))
	mux.HandleFunc("/api/v1/health", s.apiHandler(s.handleHealth))
	mux.HandleFunc("/api/v1/config-keys", s.apiHandler(s.handleConfigKeys))

	// API v2 (Dashboard v2): read-only GET/HEAD JSON under the same basePath
	// and middleware chain. Any other method is answered 405 by handleV2.
	mux.HandleFunc("/api/v2/", s.handleV2)

	// Embedded UI: index at "/", assets under "/static/".
	mux.HandleFunc("/", s.serveUI)

	inner := s.middleware(mux)

	// In server-hosted TLS mode, mount the whole surface under the random
	// 32-hex BasePath; everything outside the prefix is a 404.
	if s.tlsEnabled {
		return s.basePathHandler(inner)
	}
	return inner
}

// basePathHandler restricts the served surface to a single random 32-hex
// prefix ("<cfg>.BasePath()"). Requests outside the prefix return 404; the
// bare prefix (no trailing slash) canonicalizes to the trailing-slash form.
// The request path is rewritten (prefix stripped) before reaching the inner
// router, so every handler sees the same "/", "/static/...", "/api/v1/..."
// shape it always did.
func (s *Server) basePathHandler(inner http.Handler) http.Handler {
	prefix := s.cfg.BasePath()              // "/<hex>/" or ""
	bare := strings.TrimSuffix(prefix, "/") // "/<hex>"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == bare:
			http.Redirect(w, r, prefix, http.StatusMovedPermanently)
			return
		case strings.HasPrefix(p, prefix):
			rest := "/" + strings.TrimPrefix(p, prefix)
			r.URL.Path = rest
			r.URL.RawPath = ""
			inner.ServeHTTP(w, r)
		default:
			// Outside the random access prefix: 404, no content.
			setSecurityHeaders(w, s.securityHeaders)
			http.NotFound(w, r)
		}
	})
}

// setSecurityHeaders applies the response hardening headers for the
// server-hosted TLS build. It is a no-op when disabled (local loopback mode).
func setSecurityHeaders(w http.ResponseWriter, enabled bool) {
	if !enabled {
		return
	}
	h := w.Header()
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
}

// ListenAndServe binds the configured listen address and serves until ctx
// is cancelled. Non-loopback addresses are refused (fail closed): the local
// dashboard must never expose itself to a public interface without an
// explicit future configuration change plus a real auth mechanism.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := s.cfg.ListenAddr
	if err := validateListenAddr(addr); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
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

	// Initial collection + background poller.
	go s.pollLoop(ctx)

	return srv.Serve(ln)
}

// validateListenAddr refuses non-loopback binds (fail closed).
func validateListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("dashboard: invalid listen address %q: %w", addr, err)
	}
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return nil
	}
	return fmt.Errorf(
		"dashboard: listen address %q is not loopback; the local dashboard must bind 127.0.0.1 or ::1",
		addr)
}

// pollLoop refreshes the cache on the configured interval.
func (s *Server) pollLoop(ctx context.Context) {
	interval := time.Duration(s.cfg.RefreshSec) * time.Second
	if interval < time.Second {
		interval = time.Second
	}
	s.cache.Refresh(ctx)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.cache.Refresh(ctx)
		}
	}
}

// --- Middleware ---

// middleware wraps h with panic recovery, method whitelisting, request
// body limits, and consistent error responses.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers for the server-hosted TLS build (HSTS, CSP,
		// nosniff, DENY, no-referrer). No-op in local loopback mode.
		setSecurityHeaders(w, s.securityHeaders)

		// Panic recovery: log stack, return 500. Never leak internals.
		defer func() {
			if p := recover(); p != nil {
				debug.PrintStack()
				writeJSONError(w, http.StatusInternalServerError, "internal error")
			}
		}()

		// Method whitelist: only the standard verbs are allowed anywhere.
		switch r.Method {
		case http.MethodGet, http.MethodPost, http.MethodHead, http.MethodOptions:
		default:
			w.Header().Set("Allow", "GET, POST, HEAD, OPTIONS")
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Body size limit for POST.
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, s.requestBodyLimit)
		}

		// CSRF / origin check for mutating endpoints (POST). Read-only
		// GET requests are never origin-checked.
		if r.Method == http.MethodPost {
			if err := s.origin.Check(r); err != nil {
				var hErr *httpError
				if ok := asHTTPError(err, &hErr); ok {
					writeJSONError(w, hErr.Code, hErr.Msg)
				} else {
					writeJSONError(w, http.StatusForbidden, "request origin not allowed")
				}
				return
			}
		}

		// Auth.
		if _, err := s.auth.Authenticate(r); err != nil {
			var hErr *httpError
			if ok := asHTTPError(err, &hErr); ok {
				if hErr.Code == http.StatusUnauthorized && hErr.Www != "" {
					// HTTP Basic challenge: makes the browser prompt once,
					// then cache + auto-send credentials for the origin.
					w.Header().Set("WWW-Authenticate", hErr.Www)
				}
				writeJSONError(w, hErr.Code, hErr.Msg)
			} else {
				writeJSONError(w, http.StatusUnauthorized, "authentication failed")
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

func asHTTPError(err error, target **httpError) bool {
	if err == nil {
		return false
	}
	if he, ok := err.(*httpError); ok {
		*target = he
		return true
	}
	return false
}

// apiHandler wraps an API endpoint with JSON response handling. Path
// elements are computed from the cleaned, decoded request path, so
// traversal attempts ("..", "%2e%2e") are neutralised by ServeMux's
// path cleaning and by validServerID's strict character check.
func (s *Server) apiHandler(fn func(w http.ResponseWriter, r *http.Request, pathElements []string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		elements := splitPath(r.URL.Path)
		fn(w, r, elements)
	}
}

// --- Handlers ---

// handleOverview: GET /api/v1/overview
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, _ []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	s.cache.Refresh(r.Context())
	snaps := s.cache.AllSnapshots()

	resp := OverviewResponse{
		Healthy:  true,
		ReadOnly: s.cfg.ReadOnly,
	}
	var last time.Time
	for i := range snaps {
		snap := &snaps[i]
		if snap.CollectedAt.After(last) {
			last = snap.CollectedAt
		}
		summary := s.buildSummary(snap)
		resp.Servers = append(resp.Servers, summary)
		if snap.Status == Unreachable || snap.Status == Unsupported {
			resp.Warnings = append(resp.Warnings, fmt.Sprintf("server %s: %s", snap.ServerID, snap.Status))
		}
	}
	resp.LastCollection = last
	if resp.Servers == nil {
		resp.Servers = []ServerSummary{}
	}
	writeJSON(w, http.StatusOK, resp)
}

// buildSummary extracts the headline numbers for one server snapshot.
func (s *Server) buildSummary(snap *ServerSnapshot) ServerSummary {
	// Role starts empty and is only set from the verified config entry.
	// Falling back to ServerID here was an audit bug: it silently labelled
	// the server's role with its own ID when the config lookup missed.
	summary := ServerSummary{
		ID:          snap.ServerID,
		Status:      snap.Status,
		CollectedAt: snap.CollectedAt,
		Errors:      snap.Errors,
	}
	if srv, ok := s.cache.ServerConfig(snap.ServerID); ok {
		summary.Name = srv.Name
		summary.Role = srv.Role
	}
	if snap.Metrics != nil {
		rates := s.cache.RatesFor(snap.ServerID)
		for _, sample := range snap.Metrics.Samples {
			switch sample.Name {
			case "active_sessions":
				summary.ActiveSess = int64(sample.Value)
			case "carrier_loss_events":
				summary.CarrierLosses = int64(sample.Value)
			}
			if r, ok := rates[sampleKey(sample)]; ok {
				switch sample.Name {
				case "total_bytes_up":
					summary.BytesUpRate = r.PerSec
				case "total_bytes_down":
					summary.BytesDownRate = r.PerSec
				}
			}
		}
	}
	return summary
}

// handleServers: GET /api/v1/servers
func (s *Server) handleServers(w http.ResponseWriter, r *http.Request, _ []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	type serverView struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Role    string `json:"role"`
		Address string `json:"address"`
		Source  string `json:"sourceType"`
	}
	out := make([]serverView, 0, len(s.cfg.Servers))
	for _, srv := range s.cfg.Servers {
		out = append(out, serverView{
			ID:      srv.ID,
			Name:    srv.Name,
			Role:    srv.Role,
			Address: srv.Address,
			Source:  srv.SourceType,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleServerSub dispatches /api/v1/servers/{id} and
// /api/v1/servers/{id}/{metrics|logs|config|config/plan|config/apply}.
func (s *Server) handleServerSub(w http.ResponseWriter, r *http.Request, elements []string) {
	// elements: [api, v1, servers, id, ...]
	if len(elements) < 4 {
		writeJSONError(w, http.StatusNotFound, "unknown endpoint")
		return
	}
	id := elements[3]
	if !validServerID(id) {
		writeJSONError(w, http.StatusBadRequest, "invalid server id")
		return
	}
	// Verify the server exists in the config.
	srv, ok := s.cache.ServerConfig(id)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown server: "+id)
		return
	}

	if len(elements) == 4 {
		// GET /api/v1/servers/{id}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		_ = s.cache.RefreshServer(r.Context(), id)
		snap, _ := s.cache.Snapshot(id)
		if snap == nil {
			writeJSONError(w, http.StatusNotFound, "no snapshot yet for server "+id)
			return
		}
		type snapshotView struct {
			ServerSnapshot
			Rates map[string]Rate `json:"rates,omitempty"`
		}
		view := snapshotView{
			ServerSnapshot: *snap,
			Rates:          s.cache.RatesFor(id),
		}
		writeJSON(w, http.StatusOK, view)
		return
	}

	sub := elements[4]
	switch sub {
	case "metrics":
		s.handleServerMetrics(w, r, id, srv)
	case "logs":
		s.handleServerLogs(w, r, id, srv)
	case "config":
		if len(elements) == 5 {
			s.handleServerConfig(w, r, id, srv)
			return
		}
		if len(elements) < 6 {
			writeJSONError(w, http.StatusNotFound, "unknown endpoint")
			return
		}
		switch elements[5] {
		case "plan":
			s.handleConfigPlan(w, r, id, srv)
		case "apply":
			s.handleConfigApply(w, r, id, srv)
		default:
			writeJSONError(w, http.StatusNotFound, "unknown config sub-resource: "+elements[5])
		}
	default:
		writeJSONError(w, http.StatusNotFound, "unknown endpoint /api/v1/servers/"+id+"/"+sub)
	}
}

func (s *Server) handleServerMetrics(w http.ResponseWriter, r *http.Request, id string, srv *ServerConfig) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	_ = s.cache.RefreshServer(r.Context(), id)
	snap, _ := s.cache.Snapshot(id)
	if snap == nil || snap.Metrics == nil {
		writeJSONError(w, http.StatusNotFound, "no metrics available for server "+id)
		return
	}
	type metricsView struct {
		ServerID string          `json:"serverId"`
		Source   string          `json:"source"`
		Status   SnapshotStatus  `json:"status"`
		Metrics  *ParsedMetrics  `json:"metrics"`
		Rates    map[string]Rate `json:"rates,omitempty"`
	}
	writeJSON(w, http.StatusOK, metricsView{
		ServerID: id,
		Source:   srv.SourceType,
		Status:   snap.Status,
		Metrics:  snap.Metrics,
		Rates:    s.cache.RatesFor(id),
	})
}

// handleServerLogs: GET /api/v1/servers/{id}/logs?limit=N
// N is clamped to 1..cfg.MaxLogEntries. The limit only bounds how many
// entries are returned; it is never a file path or other input.
func (s *Server) handleServerLogs(w http.ResponseWriter, r *http.Request, id string, srv *ServerConfig) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	limit := s.cfg.MaxLogEntries
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > s.cfg.MaxLogEntries {
		limit = s.cfg.MaxLogEntries
	}

	_ = s.cache.RefreshServer(r.Context(), id)
	snap, _ := s.cache.Snapshot(id)
	if snap == nil {
		writeJSONError(w, http.StatusNotFound, "no snapshot yet for server "+id)
		return
	}

	type logsResponse struct {
		ServerID  string     `json:"serverId"`
		Source    string     `json:"source"`
		Entries   []LogEntry `json:"entries"`
		Truncated bool       `json:"truncated"`
		Warning   string     `json:"warning,omitempty"`
	}
	out := logsResponse{
		ServerID: id,
		Source:   srv.SourceType,
		Entries:  []LogEntry{},
	}
	if len(snap.Logs) > limit {
		out.Entries = snap.Logs[len(snap.Logs)-limit:]
		out.Truncated = true
	} else {
		out.Entries = snap.Logs
	}
	if len(out.Entries) == 0 && srv.SourceType != "fixture" {
		out.Warning = "log collection via this source is not yet implemented; no remote logs were fetched"
	}
	// Redact every log message before it leaves the server.
	redacted := make([]LogEntry, len(out.Entries))
	for i, e := range out.Entries {
		e2 := e
		e2.Message = RedactString(e.Message)
		redacted[i] = e2
	}
	out.Entries = redacted
	writeJSON(w, http.StatusOK, out)
}

// handleServerConfig: GET /api/v1/servers/{id}/config
// Only allowlisted, safe, redacted values are returned. Raw env files,
// secrets, or unit text are never included.
func (s *Server) handleServerConfig(w http.ResponseWriter, r *http.Request, id string, _ *ServerConfig) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	_ = s.cache.RefreshServer(r.Context(), id)
	snap, _ := s.cache.Snapshot(id)
	type configResponse struct {
		ServerID string        `json:"serverId"`
		ReadOnly bool          `json:"readOnly"`
		Values   []ConfigValue `json:"values"`
		Warnings []string      `json:"warnings,omitempty"`
	}
	resp := configResponse{
		ServerID: id,
		ReadOnly: s.cfg.ReadOnly,
		Values:   []ConfigValue{},
	}
	if snap != nil && len(snap.Config) > 0 {
		resp.Values = snap.Config
	} else {
		// Seed with the safe-key defaults so the UI always has structure.
		for _, spec := range SafeConfigKeys {
			resp.Values = append(resp.Values, ConfigValue{
				Key:             spec.EnvVar,
				Value:           "(unknown)",
				Mutable:         !s.cfg.ReadOnly,
				RequiresRestart: spec.RequiresRestart,
			})
		}
	}
	resp.Warnings = []string{"only allowlisted, non-secret values are shown; secrets are never returned"}
	writeJSON(w, http.StatusOK, resp)
}

// handleConfigPlan: POST /api/v1/servers/{id}/config/plan
// Accepts only typed, allowlisted key/value changes; validates enums and
// ranges; returns a redacted before/after diff with restart metadata and a
// plan ID. It MUST NOT apply anything.
func (s *Server) handleConfigPlan(w http.ResponseWriter, r *http.Request, id string, srv *ServerConfig) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req struct {
		PlanID  string          `json:"planId"`
		Changes []ChangeRequest `json:"changes"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, s.requestBodyLimit)).Decode(&req); err != nil {
		if err == io.EOF {
			writeJSONError(w, http.StatusBadRequest, "empty request body")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if len(req.Changes) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no changes supplied")
		return
	}
	plan, err := PlanChanges(id, srv.Role, req.PlanID, req.Changes)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.storePlan(plan)

	// Record a local audit event (dry-run plan creation only).
	s.audit.Add(AuditEvent{
		EventType: "plan_created",
		ServerID:  id,
		PlanID:    plan.PlanID,
		Detail:    fmt.Sprintf("dry-run plan with %d change(s); restartRequired=%v", len(plan.Changes), plan.RestartRequired),
	})

	type planResponse struct {
		ChangePlan
		Applied bool `json:"applied"` // always false in this release
	}
	resp := planResponse{
		ChangePlan: ChangePlan{
			PlanID:          plan.PlanID,
			ServerID:        plan.ServerID,
			Changes:         plan.Changes,
			AffectedUnits:   plan.AffectedUnits,
			RestartRequired: plan.RestartRequired,
			Warnings:        plan.Warnings,
			CreatedAt:       time.Now(),
		},
		Applied: false,
	}
	writeJSON(w, http.StatusCreated, resp)
}

// handleConfigApply: POST /api/v1/servers/{id}/config/apply
// In the default local build this endpoint ALWAYS returns 403
// ("mutations disabled") or 409 (unknown/mismatched plan). It never writes
// files, executes commands, or contacts a host. A real mutator may only be
// injected later behind explicit config (readOnly=false AND
// server.AllowMutations=true).
func (s *Server) handleConfigApply(w http.ResponseWriter, r *http.Request, id string, srv *ServerConfig) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req struct {
		PlanID string `json:"planId"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, s.requestBodyLimit)).Decode(&req); err != nil {
		if err == io.EOF {
			writeJSONError(w, http.StatusBadRequest, "empty request body")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if req.PlanID == "" {
		writeJSONError(w, http.StatusBadRequest, "planId is required")
		return
	}
	plan, ok := s.getPlan(req.PlanID)
	if !ok || plan.ServerID != id {
		s.audit.Add(AuditEvent{
			EventType: "apply_rejected",
			ServerID:  id,
			PlanID:    req.PlanID,
			Detail:    "unknown plan or plan belongs to a different server",
		})
		writeJSONError(w, http.StatusConflict, "plan not found or belongs to a different server")
		return
	}

	// Mutation gate: BOTH the global read-only flag must be off AND the
	// per-server allowMutations flag must be on. The safe default has
	// readOnly=true, so this path is taken and the mutator is provably
	// never called.
	if s.cfg.ReadOnly || !srv.AllowMutations {
		s.audit.Add(AuditEvent{
			EventType: "apply_blocked",
			ServerID:  id,
			PlanID:    req.PlanID,
			Detail:    fmt.Sprintf("mutations disabled (readOnly=%v, allowMutations=%v)", s.cfg.ReadOnly, srv.AllowMutations),
		})
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":   "mutations disabled",
			"details": "this dashboard build is read-only; no host was contacted and no files were written. To enable mutations later, inject a real mutator and set readOnly=false plus per-server allowMutations=true.",
		})
		return
	}

	// Future path: delegate to the injected mutator. With the default nil
	// mutator this still fails closed.
	err := s.mutator.ApplyPlan(r.Context(), id, req.PlanID)
	if err != nil {
		s.audit.Add(AuditEvent{
			EventType: "apply_failed",
			ServerID:  id,
			PlanID:    req.PlanID,
			Detail:    err.Error(),
		})
		if strings.Contains(err.Error(), "mutations disabled") {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":   "mutations disabled",
				"details": err.Error(),
			})
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "apply failed")
		return
	}

	s.audit.Add(AuditEvent{
		EventType: "apply_succeeded",
		ServerID:  id,
		PlanID:    req.PlanID,
		Detail:    "plan applied via injected mutator",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "applied"})
}

// handleAudit: GET /api/v1/audit?limit=N
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	limit := s.cfg.MaxAudit
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > s.cfg.MaxAudit {
		limit = s.cfg.MaxAudit
	}
	events := s.audit.LastN(limit)
	if events == nil {
		events = []AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

// handleHealth: GET /api/v1/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, _ []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	resp := HealthResponse{
		Status:    "ok",
		ReadOnly:  s.cfg.ReadOnly,
		UptimeSec: time.Since(s.startTime).Seconds(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleConfigKeys: GET /api/v1/config-keys
// Returns the safe allowlist so the UI can render the plan form.
func (s *Server) handleConfigKeys(w http.ResponseWriter, r *http.Request, _ []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	writeJSON(w, http.StatusOK, SafeConfigKeys)
}

// --- plan store (bounded, in-memory, concurrency-safe) ---

const maxStoredPlans = 100

// storePlan records a plan under the server's write lock. It lazily drops
// expired entries, then enforces the hard cap by evicting the oldest stored
// plan.
func (s *Server) storePlan(p *PlanResult) {
	now := time.Now()
	s.planMu.Lock()
	defer s.planMu.Unlock()
	s.expirePlansLocked(now)
	if len(s.plans) >= maxStoredPlans {
		// Evict the oldest entry by insertion time.
		var oldest string
		var oldestTime time.Time
		for k, t := range s.planTimes {
			if oldest == "" || t.Before(oldestTime) {
				oldest = k
				oldestTime = t
			}
		}
		if oldest != "" {
			delete(s.plans, oldest)
			delete(s.planTimes, oldest)
		}
	}
	s.plans[p.PlanID] = p
	s.planTimes[p.PlanID] = now
}

// getPlan retrieves a plan under a read lock, treating an expired plan as
// absent (it is dropped lazily by the next store or here).
func (s *Server) getPlan(id string) (*PlanResult, bool) {
	s.planMu.RLock()
	p, ok := s.plans[id]
	if !ok {
		s.planMu.RUnlock()
		return nil, false
	}
	created, hasTime := s.planTimes[id]
	s.planMu.RUnlock()
	if hasTime && time.Since(created) > planTTL {
		return nil, false
	}
	return p, true
}

// expirePlansLocked drops plans older than planTTL. Caller must hold planMu.
func (s *Server) expirePlansLocked(now time.Time) {
	for k, t := range s.planTimes {
		if now.Sub(t) > planTTL {
			delete(s.plans, k)
			delete(s.planTimes, k)
		}
	}
}

// NewPlanID generates a random plan identifier.
func NewPlanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "plan-" + hex.EncodeToString(b)
}

// --- helpers ---

// validServerID enforces a strict ID character set so path traversal and
// encoded-slash tricks can never reach a handler as a valid ID.
func validServerID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIError{Error: msg})
}
