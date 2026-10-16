// control_wiring_test.go — Tests for the control-agent wiring seam
// (SetControlAgent / NewControlClient) and the config fail-closed
// invariants (applyEnabled=true requires socketPath; all capability
// flags default false).
package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- (d) all capability flags default false -------------------------------

func TestControlConfigFlagsDefaultFalse(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Control != nil {
		t.Fatal("default config must have nil Control section (no control plane)")
	}
	// A zero-value ControlConfig has all flags false.
	var cc ControlConfig
	if cc.ApplyEnabled {
		t.Error("ApplyEnabled must default to false")
	}
	if cc.SocketPath != "" {
		t.Error("SocketPath must default to empty")
	}
	if cc.C3Flags.GermanyInboundsApply || cc.C3Flags.IranInboundsApply ||
		cc.C3Flags.KeyRotation || cc.C3Flags.BlobExport {
		t.Error("all C3 capability flags must default to false")
	}
	if cc.C4Flags.RoutingApply || cc.C4Flags.MultiCarrierApply ||
		cc.C4Flags.CoordinatedApply {
		t.Error("all C4 capability flags must default to false")
	}
}

// --- (c) applyEnabled=true with empty socketPath fails closed ---------------

func TestValidateControlApplyEnabledRequiresSocketPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{ApplyEnabled: true} // no socketPath
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() must refuse applyEnabled=true with empty socketPath (fail closed)")
	}
}

func TestValidateControlApplyEnabledWithSocketPathOK(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{ApplyEnabled: true, SocketPath: "/run/split-tunnel-ctl/control.sock"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with applyEnabled+socketPath: %v", err)
	}
}

func TestValidateControlNoApplyEnabledNoSocketPathOK(t *testing.T) {
	// applyEnabled=false with no socketPath is fine (read-only forwarding
	// will 503 agent_unavailable, but that is the documented safe default).
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{ApplyEnabled: false}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with applyEnabled=false and no socketPath: %v", err)
	}
}

// --- (a) with a control section + socketPath, the server has an agent ------
// (asserted via the endpoint no longer returning agent_unavailable when a
// fake agent is attached; the real ControlClient would 503 if the socket
// is absent, but the fake proves the wiring seam works).

func TestControlWiringWithFakeAgentEndpointsWork(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{
		ApplyEnabled: true,
		SocketPath:   "/run/split-tunnel-ctl/control.sock",
	}
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	fake := &fakeC2Agent{}
	s.SetControlAgent(fake)

	// GET /api/v2/revisions with the fake agent attached: should NOT be
	// 503 agent_unavailable.
	fake.result = c2AgentResult{OK: true, Data: map[string]any{"revisions": []any{}}}
	req := httptest.NewRequest(http.MethodGet, "/api/v2/revisions", nil)
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v2/revisions with fake agent = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 1 {
		t.Fatalf("fake agent calls = %v, want [revisions]", fake.calls)
	}
}

// --- (b) with no control section, endpoints still return 503 ---------------

func TestControlNoSectionEndpointsReturn503(t *testing.T) {
	cfg := DefaultConfig()
	// cfg.Control is nil (no control section).
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	// Deliberately do NOT call SetControlAgent.

	req := httptest.NewRequest(http.MethodGet, "/api/v2/revisions", nil)
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /api/v2/revisions with no control section = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "agent_unavailable") {
		t.Fatalf("503 body must name agent_unavailable: %s", rr.Body.String())
	}
}

// --- (e) read-only paths unchanged when no control section -----------------

func TestControlNoSectionReadOnlyPathsUnchanged(t *testing.T) {
	cfg := DefaultConfig()
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)

	// /api/v1/health must still work.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/api/v1/health = %d, want 200", rr.Code)
	}

	// /api/v1/overview must still work.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	rr = httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/api/v1/overview = %d, want 200", rr.Code)
	}
}

// --- ControlClient with an absent socket returns a clear error (no crash) ---

func TestControlClientAbsentSocketReturns503Reason(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{ApplyEnabled: true, SocketPath: "/nonexistent/test-socket.sock"}
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	// Attach the REAL ControlClient (not a fake); the socket does not exist.
	s.SetControlAgent(NewControlClient(cfg.Control.SocketPath))

	req := httptest.NewRequest(http.MethodGet, "/api/v2/revisions", nil)
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)

	// The real ControlClient will fail to dial the absent socket → 503.
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /api/v2/revisions with absent socket = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "agent_unavailable") {
		t.Fatalf("503 body must name agent_unavailable: %s", rr.Body.String())
	}
}
