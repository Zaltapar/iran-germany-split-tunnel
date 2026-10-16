// Package dashboard provides the local-only monitoring dashboard for the
// Iran–Germany split-tunnel deployment. It exposes a JSON HTTP API and an
// embedded read-only web UI.
//
// Safe defaults:
//   - Binds to 127.0.0.1 only
//   - Mutations (config apply) are disabled by default
//   - No external host access unless explicitly configured
//   - No command execution from HTTP request parameters
//   - No arbitrary shell endpoint
//   - All secrets are redacted before display
package dashboard

import (
	"time"
)

// SnapshotStatus is the collection freshness of a server snapshot.
type SnapshotStatus string

const (
	// Fresh: data was collected successfully within the last poll interval.
	Fresh SnapshotStatus = "fresh"
	// Stale: data was collected but is older than the poll interval.
	Stale SnapshotStatus = "stale"
	// Unreachable: the collector could not reach the source.
	Unreachable SnapshotStatus = "unreachable"
	// Unsupported: the source type does not yet support collection.
	Unsupported SnapshotStatus = "unsupported"
)

// MetricSample is one parsed metric line from a collector source.
type MetricSample struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Value  float64           `json:"value"`
}

// Rate is a computed per-second rate for a monotonic counter.
type Rate struct {
	PerSec float64 `json:"perSec"`
	Window string  `json:"window,omitempty"`
	Reset  bool    `json:"reset,omitempty"` // true when counter reset was detected
}

// ParsedMetrics holds a full snapshot of parsed metric samples plus computed rates.
type ParsedMetrics struct {
	CollectedAt time.Time       `json:"collectedAt"`
	Samples     []MetricSample  `json:"samples"`
	Rates       map[string]Rate `json:"rates,omitempty"`
	Errors      []string        `json:"errors,omitempty"`
}

// LogEntry is one log line from a collector source.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

// ServiceState describes one systemd service observed on a server.
type ServiceState struct {
	Unit     string `json:"unit"`
	State    string `json:"state"`
	Active   bool   `json:"active"`
	SubState string `json:"subState,omitempty"`
	// Enabled reports the unit-file enablement state ("enabled", "disabled",
	// "static", etc.) from UnitFileState in `systemctl show`.
	Enabled string `json:"enabled,omitempty"`
	// MainPID is the main process ID from `systemctl show`. 0 when the
	// service is not running or the field was unavailable (unprivileged).
	MainPID int `json:"mainPid,omitempty"`
}

// ListenerState describes one port listener observed on a server.
type ListenerState struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	PID      int    `json:"pid,omitempty"`
}

// ConfigValue is a safe, redacted configuration value for display.
type ConfigValue struct {
	Key             string `json:"key"`
	Value           string `json:"value"`
	Redacted        bool   `json:"redacted,omitempty"`
	Mutable         bool   `json:"mutable"`
	RequiresRestart bool   `json:"requiresRestart,omitempty"`
}

// ChangePlan is the result of a dry-run configuration change proposal.
type ChangePlan struct {
	PlanID          string         `json:"planId"`
	ServerID        string         `json:"serverId"`
	Changes         []ConfigChange `json:"changes"`
	AffectedUnits   []string       `json:"affectedUnits,omitempty"`
	RestartRequired bool           `json:"restartRequired"`
	Warnings        []string       `json:"warnings,omitempty"`
	CreatedAt       time.Time      `json:"createdAt"`
}

// ConfigChange is one individual key/value change in a plan.
type ConfigChange struct {
	Key             string `json:"key"`
	Before          string `json:"before"`
	After           string `json:"after"`
	Redacted        bool   `json:"redacted,omitempty"`
	RequiresRestart bool   `json:"requiresRestart"`
}

// AuditEvent is one local audit log entry.
type AuditEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"eventType"`
	ServerID  string    `json:"serverId,omitempty"`
	PlanID    string    `json:"planId,omitempty"`
	Detail    string    `json:"detail"`
}

// ServerConfig describes one monitored server in the dashboard config.
type ServerConfig struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Role       string `json:"role"` // "iran" or "germany"
	Address    string `json:"address"`
	MetricsURL string `json:"metricsUrl,omitempty"`
	// SourceType is "fixture", "http", or "ssh".
	SourceType string `json:"sourceType"`
	// AllowMutations controls whether the apply endpoint can mutate this server.
	AllowMutations bool `json:"allowMutations,omitempty"`
	// SSH is the strict, per-server remote host collector configuration.
	// It is only used when SourceType == "ssh". If it is nil for an ssh
	// server, the collector fails closed without contacting any host.
	//
	// Security: this config NEVER carries secrets. The identity file and
	// pinned known-hosts file are referenced by absolute path only; their
	// contents are never read into the dashboard or displayed. See
	// ValidateSSHConfig for the enforced invariants (pinned host keys,
	// BatchMode, no password auth, fixed remote command allowlist).
	SSH *SSHConfig `json:"ssh,omitempty"`
	// MaxLogEntries is a per-server cap on the log tail returned for this
	// source. 0 means "use the dashboard-level MaxLogEntries".
	MaxLogEntries int `json:"maxLogEntries,omitempty"`
}

// TLSConfig controls the optional server-hosted TLS listener for tunneldash
// (one-click dashboard design §3). It is disabled by default; when enabled,
// the dashboard must also carry a 32-hex random BasePath and an admin Bearer
// token before it may bind a non-loopback address. The key/cert material is
// read from the filesystem at startup and is never displayed.
//
// The JSON wire shape is the conventional nested form under the parent
// "tls" object (DashboardConfig.TLS, tag "tls,omitempty"):
//
//	"tls": { "enabled": true, "certFile": "...", "keyFile": "...", "basePath": "<32-hex>" }
//
// NOTE (schema-bug fix): the original tags were flat dotted keys
// ("tls.enabled" inside the "tls" object), which encoding/json silently
// ignores for conventional nested input — a conventional config left
// Enabled=false, and the non-loopback bind gate then refused the public
// listen address at startup (fail-closed, but a crash-loop). The tags are
// now conventional; a round-trip test pins the wire shape.
type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
	BasePath string `json:"basePath"`
}

// IsSecure reports whether the TLS config is complete enough to serve over a
// public (non-loopback) interface: enabled + cert + key + valid 32-hex path.
func (c TLSConfig) IsSecure() bool {
	if !c.Enabled || c.CertFile == "" || c.KeyFile == "" {
		return false
	}
	return validBasePath(c.BasePath)
}

// DashboardConfig is the top-level dashboard configuration.
//
// CORS is unconditionally disabled in this build; no config field exists to
// enable it. A future authenticated build may add an explicit allow-list.
type DashboardConfig struct {
	ListenAddr    string         `json:"listenAddr"`
	ReadOnly      bool           `json:"readOnly"`
	RefreshSec    int            `json:"refreshSec"`
	MaxLogEntries int            `json:"maxLogEntries"`
	MaxAudit      int            `json:"maxAudit"`
	Servers       []ServerConfig `json:"servers"`
	TLS           *TLSConfig     `json:"tls,omitempty"`
	// HistoryPoints bounds the in-memory chart history per series (Dashboard
	// v2). 0 means DefaultHistoryPoints; values are clamped to
	// MaxHistoryPoints. Nothing is written to disk.
	HistoryPoints int `json:"historyPoints,omitempty"`
	// Outbounds is the read-only view of configured Reality/Xray outbounds
	// (Dashboard v2). Public identity fields only; no keys or UUIDs.
	Outbounds []OutboundConfig `json:"outbounds,omitempty"`
	// Routing is the read-only view of the routing policy (Dashboard v2).
	// nil means "not declared"; the UI then shows an explicit empty state.
	Routing *RoutingPolicy `json:"routing,omitempty"`
	// Control configures the C2 control APPLY plane (design §12 C2). nil
	// (the default) means the apply plane is OFF: POST apply answers 503
	// and the read-only forwarding endpoints report the agent as
	// unavailable. It never affects the C1 read-only validation endpoint.
	Control *ControlConfig `json:"control,omitempty"`
}

// validBasePath reports whether p is a 32-character lowercase hex string.
func validBasePath(p string) bool {
	if len(p) != 32 {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// BasePath returns the normalized route prefix ("/<32-hex>/"), or "" when the
// TLS base path is unset/invalid.
func (c *DashboardConfig) BasePath() string {
	if c.TLS != nil && validBasePath(c.TLS.BasePath) {
		return "/" + c.TLS.BasePath + "/"
	}
	return ""
}

// ServerSnapshot is the full state of one server as seen by the dashboard.
type ServerSnapshot struct {
	ServerID    string          `json:"serverId"`
	Status      SnapshotStatus  `json:"status"`
	CollectedAt time.Time       `json:"collectedAt"`
	Errors      []string        `json:"errors,omitempty"`
	Metrics     *ParsedMetrics  `json:"metrics,omitempty"`
	Logs        []LogEntry      `json:"logs,omitempty"`
	Services    []ServiceState  `json:"services,omitempty"`
	Listeners   []ListenerState `json:"listeners,omitempty"`
	Config      []ConfigValue   `json:"config,omitempty"`
	// UptimeSec is the observed process uptime, if available.
	UptimeSec float64 `json:"uptimeSec,omitempty"`
	// MemoryMB is the used RAM in MiB reported by `free -b` (SSH source).
	// 0 when unavailable.
	MemoryMB int64 `json:"memoryMB,omitempty"`
	// DiskBytes is the used bytes on the root filesystem reported by
	// `df -B1 /` (SSH source). 0 when unavailable.
	DiskBytes int64 `json:"diskBytes,omitempty"`
}

// OverviewResponse is the /api/v1/overview payload.
type OverviewResponse struct {
	Healthy        bool            `json:"healthy"`
	ReadOnly       bool            `json:"readOnly"`
	LastCollection time.Time       `json:"lastCollection"`
	Servers        []ServerSummary `json:"servers"`
	Warnings       []string        `json:"warnings,omitempty"`
}

// ServerSummary is one server entry in the overview response.
type ServerSummary struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Role          string         `json:"role"`
	Status        SnapshotStatus `json:"status"`
	ActiveSess    int64          `json:"activeSessions"`
	BytesUpRate   float64        `json:"bytesUpPerSec"`
	BytesDownRate float64        `json:"bytesDownPerSec"`
	CarrierLosses int64          `json:"carrierLossEvents"`
	CollectedAt   time.Time      `json:"collectedAt"`
	Errors        []string       `json:"errors,omitempty"`
}

// HealthResponse is the /api/v1/health payload.
type HealthResponse struct {
	Status    string  `json:"status"`
	ReadOnly  bool    `json:"readOnly"`
	UptimeSec float64 `json:"uptimeSec"`
}

// APIError is the consistent error response schema.
type APIError struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}
