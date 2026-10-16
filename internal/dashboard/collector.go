package dashboard

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Collector gathers a ServerSnapshot from an injected source.
// Implementations must be safe for concurrent use.
type Collector interface {
	Collect(ctx context.Context, cfg ServerConfig) (*ServerSnapshot, error)
}

// --- Fixture Collector ---

// FixtureCollector returns deterministic sample data. It never contacts
// any external host.
type FixtureCollector struct {
	// Now allows tests to control timestamps.
	Now func() time.Time
}

// NewFixtureCollector returns a FixtureCollector with the real clock.
func NewFixtureCollector() *FixtureCollector {
	return &FixtureCollector{Now: time.Now}
}

// Collect implements Collector.
func (f *FixtureCollector) Collect(ctx context.Context, cfg ServerConfig) (*ServerSnapshot, error) {
	now := f.Now()
	snap := &ServerSnapshot{
		ServerID:    cfg.ID,
		Status:      Fresh,
		CollectedAt: now,
	}

	// Deterministic fixture metrics based on the server role.
	seed := int64(now.Unix()/int64(fixInterval)) % 100
	roleScale := 1.0
	if cfg.Role == "germany" {
		roleScale = 0.7
	}
	activeSessions := int64(5 + seed%20)
	totalSessions := int64(120 + seed)
	bytesUp := int64(500_000_000*roleScale) + seed*1_000_000
	bytesDown := int64(800_000_000*roleScale) + seed*2_000_000

	fixtureSamples := []MetricSample{
		{Name: "active_sessions", Value: float64(activeSessions)},
		{Name: "total_sessions", Value: float64(totalSessions)},
		{Name: "total_bytes_up", Value: float64(bytesUp)},
		{Name: "total_bytes_down", Value: float64(bytesDown)},
		{Name: "errors", Value: float64(seed % 10)},
		{Name: "carrier_loss_events", Value: float64(2 + seed%5)},
		{Name: "carrier_reconnects", Value: float64(3 + seed%7)},
		{Name: "target_dial_success", Value: float64(900 + seed)},
		{Name: "target_dial_failure", Value: float64(5 + seed%3)},
		{Name: "relay_bytes_read", Value: float64(bytesUp)},
		{Name: "relay_bytes_written", Value: float64(bytesDown)},
		{Name: "relay_buffer_full", Value: float64(seed % 2)},
		{Name: "relay_write_failures", Value: float64(seed % 3)},
		{Name: "close_reason", Labels: map[string]string{"reason": "client_eof"}, Value: 100},
		{Name: "close_reason", Labels: map[string]string{"reason": "carrier"}, Value: 15},
		{Name: "close_reason", Labels: map[string]string{"reason": "data_undeliverable"}, Value: 2},
		{Name: "close_reason", Labels: map[string]string{"reason": "overflow"}, Value: 3},
		{Name: "relay_credit_emitted_total", Value: 50000},
		{Name: "relay_credit_dropped_total", Value: 12},
		{Name: "relay_credit_gate_park_total", Value: 4},
	}

	snap.Metrics = &ParsedMetrics{
		CollectedAt: now,
		Samples:     fixtureSamples,
	}

	// Fixture logs.
	logs := []LogEntry{
		{Timestamp: now.Add(-5 * time.Minute), Level: "INFO", Message: "carrier re-established after loss event"},
		{Timestamp: now.Add(-3 * time.Minute), Level: "INFO", Message: fmt.Sprintf("active sessions: %d", activeSessions)},
		{Timestamp: now.Add(-1 * time.Minute), Level: "WARN", Message: "relay buffer high watermark observed"},
		{Timestamp: now.Add(-30 * time.Second), Level: "ERROR", Message: "target dial failed: connection refused"},
		{Timestamp: now, Level: "INFO", Message: "metrics snapshot collected"},
	}
	snap.Logs = logs

	// Fixture services.
	unitName := "iran-splitter"
	if cfg.Role == "germany" {
		unitName = "germany-splitter"
	}
	snap.Services = []ServiceState{
		{Unit: unitName + ".service", State: "active", Active: true, SubState: "running"},
	}
	snap.Listeners = []ListenerState{
		{Protocol: "tcp", Address: "127.0.0.1:9001", PID: 1234},
		{Protocol: "tcp", Address: "127.0.0.1:10900", PID: 1234},
	}

	// Fixture safe config values (no secrets).
	snap.Config = []ConfigValue{
		{Key: "SPLIT_METRICS_PORT", Value: "9101", Mutable: true, RequiresRestart: true},
		{Key: "SPLIT_RELAY_BUF", Value: "32768", Mutable: true, RequiresRestart: true},
		{Key: "SPLIT_TARGET_ADDR_POLICY", Value: "default", Mutable: true, RequiresRestart: false},
		{Key: "SPLIT_TARGET_ONLY_IPV4", Value: "false", Mutable: true, RequiresRestart: false},
		RedactConfigValue("SPLIT_SECRET", "some-secret-here", false, true),
		RedactConfigValue("SPLIT_SOCKS_PASS", "user-password", false, true),
	}

	snap.UptimeSec = 3600.0
	return snap, nil
}

const fixInterval = 60 // fixture data changes every 60s

// --- HTTP Metrics Collector ---

// HTTPCollector fetches metrics from a configured URL.
type HTTPCollector struct {
	HTTPClient *http.Client
	Now        func() time.Time
}

// NewHTTPCollector returns an HTTPCollector with sensible defaults.
func NewHTTPCollector() *HTTPCollector {
	return &HTTPCollector{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Now:        time.Now,
	}
}

// Collect implements Collector.
func (h *HTTPCollector) Collect(ctx context.Context, cfg ServerConfig) (*ServerSnapshot, error) {
	now := h.Now()
	snap := &ServerSnapshot{
		ServerID:    cfg.ID,
		CollectedAt: now,
	}
	if cfg.MetricsURL == "" {
		snap.Status = Unsupported
		snap.Errors = append(snap.Errors, "no metrics URL configured for server "+cfg.ID)
		return snap, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.MetricsURL, nil)
	if err != nil {
		snap.Status = Unreachable
		snap.Errors = append(snap.Errors, fmt.Sprintf("build request: %v", err))
		return snap, nil
	}
	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		snap.Status = Unreachable
		snap.Errors = append(snap.Errors, fmt.Sprintf("http error: %v", err))
		return snap, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snap.Status = Unreachable
		snap.Errors = append(snap.Errors, fmt.Sprintf("unexpected status %d", resp.StatusCode))
		return snap, nil
	}
	// Cap response at 1 MiB.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		snap.Status = Unreachable
		snap.Errors = append(snap.Errors, fmt.Sprintf("read body: %v", err))
		return snap, nil
	}
	samples, parseErrs := ParseMetricsText(string(body))
	snap.Metrics = &ParsedMetrics{CollectedAt: now, Samples: samples, Errors: parseErrs}
	snap.Status = Fresh

	// Placeholder services for http mode.
	unitName := cfg.Role + "-splitter"
	snap.Services = []ServiceState{
		{Unit: unitName + ".service", State: "unknown", Active: false},
	}
	return snap, nil
}

// --- Collector Factory ---

// NewCollector returns the appropriate Collector for the given source type.
func NewCollector(sourceType string) Collector {
	switch sourceType {
	case "http":
		return NewHTTPCollector()
	case "ssh":
		return NewSSHCollector()
	default: // "fixture" or unknown
		return NewFixtureCollector()
	}
}
