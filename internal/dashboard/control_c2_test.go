// control_c2_test.go — the dashboard's C2 forwarding plane (design §3.2,
// §6, §8, §12 C2): the apply flag off-by-default guarantee, the 4xx/5xx
// mapping, never-fail-open on an unavailable agent, read-only forwarding
// that works even with the apply flag off, and the invariant that the
// web process stays read-only toward the host (mutator nil, no
// filesystem writes).
package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// fakeC2Agent is the in-memory C2Agent: it records the forwarded op and
// returns a scripted result or error, standing in for the real Unix
// socket so the whole mapping layer is testable without a host.
type fakeC2Agent struct {
	calls []string
	// result / err script the next Call.
	result c2AgentResult
	err    error
}

func (f *fakeC2Agent) Call(ctx context.Context, op, reqID, changeID, idemKey string, payload any) (c2AgentResult, error) {
	f.calls = append(f.calls, op)
	if f.err != nil {
		return c2AgentResult{}, f.err
	}
	return f.result, nil
}

// c2TestServer builds a C2-ready server: flag on, a fake agent wired,
// the CSRF header expectations pre-set on requests.
func c2TestServer(t *testing.T, flagOn bool) (*Server, *fakeC2Agent) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{ApplyEnabled: flagOn, SocketPath: "/run/split-tunnel-ctl/control.sock"}
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	fake := &fakeC2Agent{}
	s.SetControlAgent(fake)
	return s, fake
}

// c2PostApply posts to /api/v2/changes/{id}/apply with the C2 CSRF
// header; returns the recorder.
func c2PostApply(t *testing.T, s *Server, changeID, body string, withCSRF bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v2/changes/"+changeID+"/apply", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	if withCSRF {
		req.Header.Set(c2ControlHeader, "1")
	}
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	return rr
}

// c2Get performs a GET on the C2 read-only endpoints.
func c2Get(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	return rr
}

// --- apply flag off → 503 control_apply_disabled (the default state) ---
func TestC2ApplyFlagOff(t *testing.T) {
	s, fake := c2TestServer(t, false)
	rr := c2PostApply(t, s, "iran", `{"role":"iran","set":{"`+config.EnvPolicyMode+`":"adaptive"},"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("flag off status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "control_apply_disabled") {
		t.Fatalf("503 body must name the disabled flag: %s", rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite the flag being off: %v", fake.calls)
	}
}

// --- the C1 read-only validate endpoint keeps working when C2 is off ---
func TestC2OffLeavesC1ValidationWorking(t *testing.T) {
	s, _ := c2TestServer(t, false)
	rr := c1Post(t, s, `{"role":"germany","set":{"`+config.EnvPolicyTopK+`":"5"}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("C1 validate should still be 200 with C2 off; got %d (%s)", rr.Code, rr.Body.String())
	}
}

// --- the web process never touches the host filesystem / mutator ---
func TestC2ApplyKeepsMutatorNilAndNoFSWrites(t *testing.T) {
	s, fake := c2TestServer(t, true)
	if _, ok := s.mutator.(*nilMutator); !ok {
		t.Fatal("NewServer must fall back to the nil mutator")
	}
	// Run the request with the CWD pointed at a clean scratch dir: a
	// regression that makes the web process write host files shows up
	// here. The package binary runs serially, so the chdir is scoped
	// safely (restored before the test returns).
	oldWd, err := os.Getwd()
	if err != nil {
		t.Skipf("cannot resolve cwd: %v", err)
	}
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Skipf("cannot chdir to scratch: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	fake.result = c2AgentResult{OK: true, Data: map[string]any{"outcome": "committed", "revision": "r-1", "prevRevision": "r-0"}}
	rr := c2PostApply(t, s, "iran", `{"role":"iran","set":{"`+config.EnvPolicyMode+`":"adaptive"},"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	// Nothing may have been created in the working directory: the web
	// process is read-only toward the host (design sec 3.2).
	if entries, _ := os.ReadDir("."); len(entries) != 0 {
		for _, e := range entries {
			t.Errorf("web process wrote a host file: %s", e.Name())
		}
	}
}

// --- 403: missing the control CSRF header ---
func TestC2ApplyMissingControlHeader(t *testing.T) {
	s, fake := c2TestServer(t, true)
	rr := c2PostApply(t, s, "iran", `{"role":"iran","set":{"`+config.EnvPolicyMode+`":"adaptive"},"confirm":"RESTART"}`, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite a 403: %v", fake.calls)
	}
}

// --- 400: bad confirm token ---
func TestC2ApplyBadConfirm(t *testing.T) {
	s, fake := c2TestServer(t, true)
	rr := c2PostApply(t, s, "iran", `{"role":"iran","set":{"`+config.EnvPolicyMode+`":"adaptive"},"confirm":"WRONG"}`, true)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called despite a 400: %v", fake.calls)
	}
}

// --- 503: no agent wired ---
func TestC2ApplyNoAgentWired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{ApplyEnabled: true}
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil)
	// Deliberately do NOT call SetControlAgent.
	rr := c2PostApply(t, s, "iran", `{"role":"iran","set":{"`+config.EnvPolicyMode+`":"adaptive"},"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (no agent); body=%s", rr.Code, rr.Body.String())
	}
}

// --- agent error code → HTTP mapping ---
func TestC2AgentErrorCodeMapping(t *testing.T) {
	cases := []struct {
		agentCode string
		want      int
	}{
		{"validation_failed", http.StatusUnprocessableEntity},
		{"frozen", http.StatusLocked},
		{"recovery_required", http.StatusLocked},
		{"apply_in_progress", http.StatusConflict},
		{"idempotency_conflict", http.StatusConflict},
		{"stale_base", http.StatusConflict},
		{"rate_limited", http.StatusTooManyRequests},
		{"unknown_op", http.StatusBadRequest},
		{"internal", http.StatusBadGateway},
	}
	for _, c := range cases {
		t.Run(c.agentCode, func(t *testing.T) {
			s, fake := c2TestServer(t, true)
			fake.result = c2AgentResult{OK: false, Error: &c2AgentError{Code: c.agentCode, Message: "x"}}
			rr := c2PostApply(t, s, "iran", `{"role":"iran","set":{"`+config.EnvPolicyMode+`":"adaptive"},"confirm":"RESTART"}`, true)
			if rr.Code != c.want {
				t.Fatalf("agent code %q → %d, want %d", c.agentCode, rr.Code, c.want)
			}
		})
	}
}

// --- never fail open: a dial/read failure is a 503, never 200 ---
func TestC2ApplyNeverFailsOpen(t *testing.T) {
	s, fake := c2TestServer(t, true)
	fake.err = errors.New("dial unix /run/split-tunnel-ctl/control.sock: connection refused")
	rr := c2PostApply(t, s, "iran", `{"role":"iran","set":{"`+config.EnvPolicyMode+`":"adaptive"},"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (agent unreachable); body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "agent_unavailable") {
		t.Fatalf("503 must name agent_unavailable: %s", rr.Body.String())
	}
}

// --- successful apply round-trips the agent's data ---
func TestC2ApplySuccess(t *testing.T) {
	s, fake := c2TestServer(t, true)
	fake.result = c2AgentResult{OK: true, Data: map[string]any{"outcome": "committed", "revision": "r-9", "prevRevision": "r-8"}}
	rr := c2PostApply(t, s, "iran", `{"role":"iran","set":{"`+config.EnvPolicyMode+`":"adaptive"},"confirm":"RESTART"}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	var resp c2ApplyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Outcome != "committed" || resp.Revision != "r-9" || resp.PrevRevision != "r-8" || resp.ChangeID != "iran" {
		t.Fatalf("response mismatch: %+v", resp)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "apply" {
		t.Fatalf("agent ops = %v, want [apply]", fake.calls)
	}
}

// --- the read-only forwarding endpoints work even with the flag off ---
func TestC2ReadForwardingFlagOff(t *testing.T) {
	s, fake := c2TestServer(t, false)
	fake.result = c2AgentResult{OK: true, Data: map[string]any{"revisions": []any{}}}
	rr := c2Get(t, s, "/api/v2/revisions")
	if rr.Code != http.StatusOK {
		t.Fatalf("revisions with flag off = %d, want 200 (read-only forwarding is independent); body=%s", rr.Code, rr.Body.String())
	}
	fake.result = c2AgentResult{OK: true, Data: map[string]any{"entries": []any{}}}
	rr = c2Get(t, s, "/api/v2/audit")
	if rr.Code != http.StatusOK {
		t.Fatalf("audit with flag off = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.calls) != 2 {
		t.Fatalf("agent calls = %v, want 2 read ops", fake.calls)
	}
}

// --- read forwarding: no agent → 503 agent_unavailable ---
func TestC2ReadForwardingNoAgent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Control = &ControlConfig{ApplyEnabled: true}
	s := NewServer(cfg, NewCache(cfg), NewAuditLog(cfg.MaxAudit), nil, nil) // no agent
	rr := c2Get(t, s, "/api/v2/revisions")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("revisions no-agent = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "agent_unavailable") {
		t.Fatalf("must name agent_unavailable: %s", rr.Body.String())
	}
}

// --- read forwarding: agent transport error → 503 ---
func TestC2ReadForwardingAgentDown(t *testing.T) {
	s, fake := c2TestServer(t, true)
	fake.err = errors.New("socket closed")
	rr := c2Get(t, s, "/api/v2/audit")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit agent-down = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
}

// --- 404: an unknown v2 segment under changes is not a C2 route ---
func TestC2UnknownChangeSegment404s(t *testing.T) {
	s, fake := c2TestServer(t, true)
	// POST /api/v2/changes/validate is C1; POST /api/v2/changes/{x}/apply
	// is C2. A 3-segment POST that is NOT ".../apply" must fall through
	// to 405 (method not allowed) and never touch the agent.
	req := httptest.NewRequest(http.MethodPost, "/api/v2/changes/iran/rollback", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFRequestHeader, CSRFRequestValue)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 (rollback is not a web route; the agent/CLI own it)", rr.Code)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("agent was called for a non-C2 route: %v", fake.calls)
	}
}
