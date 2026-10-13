package dashboard

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadConfig reads and validates a dashboard configuration file.
func LoadConfig(path string) (*DashboardConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dashboard: cannot read config: %w", err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// ParseConfig parses a dashboard config from raw JSON bytes.
func ParseConfig(data []byte) (*DashboardConfig, error) {
	var cfg DashboardConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("dashboard: invalid config JSON: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks config invariants: unique server IDs, valid roles, non-empty
// listen address, and known source types.
func (c *DashboardConfig) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:8080"
	}
	if c.ReadOnly == false {
		// Default is read-only; explicit true is fine.
	}
	if c.RefreshSec <= 0 {
		c.RefreshSec = 10
	}
	if c.MaxLogEntries <= 0 {
		c.MaxLogEntries = 200
	}
	if c.MaxAudit <= 0 {
		c.MaxAudit = 500
	}
	if c.HistoryPoints <= 0 {
		c.HistoryPoints = DefaultHistoryPoints
	}
	if c.HistoryPoints > MaxHistoryPoints {
		c.HistoryPoints = MaxHistoryPoints
	}
	if len(c.Servers) == 0 {
		return fmt.Errorf("dashboard: config must define at least one server")
	}
	seen := map[string]bool{}
	for i, s := range c.Servers {
		if s.ID == "" {
			return fmt.Errorf("dashboard: server[%d] missing id", i)
		}
		if seen[s.ID] {
			return fmt.Errorf("dashboard: duplicate server id %q", s.ID)
		}
		seen[s.ID] = true
		if s.Role != "iran" && s.Role != "germany" {
			return fmt.Errorf("dashboard: server %q has invalid role %q (want iran or germany)", s.ID, s.Role)
		}
		switch s.SourceType {
		case "fixture", "http", "ssh":
		case "":
			s.SourceType = "fixture"
			c.Servers[i].SourceType = s.SourceType
		default:
			return fmt.Errorf("dashboard: server %q has unknown sourceType %q", s.ID, s.SourceType)
		}
		// For ssh source, validate the strict SSH sub-config.
		if s.SourceType == "ssh" {
			if s.SSH == nil {
				return fmt.Errorf("dashboard: server %q uses sourceType=ssh but has no ssh sub-config; "+
					"host is NOT contacted — provide a complete pinned SSH config or use sourceType=fixture", s.ID)
			}
			if err := ValidateSSHConfig(s.SSH, s.Role); err != nil {
				return fmt.Errorf("dashboard: server %q ssh config: %w", s.ID, err)
			}
		}
	}
	// Outbound and routing views (Dashboard v2). Names must be unique and
	// every object must pass the same validators the future editor will use.
	outboundNames := map[string]bool{}
	for i, o := range c.Outbounds {
		if errs := ValidateOutbound(o); len(errs) > 0 {
			return fmt.Errorf("dashboard: outbounds[%d] invalid: %s", i, errs[0])
		}
		if outboundNames[o.Name] {
			return fmt.Errorf("dashboard: duplicate outbound name %q", o.Name)
		}
		outboundNames[o.Name] = true
	}
	if c.Routing != nil {
		if errs := ValidateRoutingPolicy(*c.Routing, c.Outbounds); len(errs) > 0 {
			return fmt.Errorf("dashboard: routing invalid: %s", errs[0])
		}
	}
	// TLS config invariants: when enabled, the config must be complete (cert,
	// key, and a 32-hex random base path). A partial TLS config is an operator
	// mistake, not a silent loopback fallback.
	if c.TLS != nil && c.TLS.Enabled {
		if c.TLS.CertFile == "" {
			return fmt.Errorf("dashboard: tls.enabled=true requires tls.certFile")
		}
		if c.TLS.KeyFile == "" {
			return fmt.Errorf("dashboard: tls.enabled=true requires tls.keyFile")
		}
		if !validBasePath(c.TLS.BasePath) {
			return fmt.Errorf("dashboard: tls.enabled=true requires tls.basePath to be exactly 32 lowercase hex chars")
		}
	}
	// Control config invariants: when the C2 apply plane is explicitly
	// enabled, the socket path MUST be set (fail closed, matching the TLS
	// "complete or refuse" pattern). Without a socketPath the operator
	// cannot have intended a working agent; starting would give a
	// misleading 503 on every apply while claiming the plane is "on".
	if c.Control != nil && c.Control.ApplyEnabled && c.Control.SocketPath == "" {
		return fmt.Errorf("dashboard: control.applyEnabled=true requires control.socketPath to be set (the agent socket must be named explicitly)")
	}
	return nil
}

// DefaultConfig returns a safe fixture-only config for local demonstration.
func DefaultConfig() *DashboardConfig {
	return &DashboardConfig{
		ListenAddr:    "127.0.0.1:8080",
		ReadOnly:      true,
		RefreshSec:    10,
		MaxLogEntries: 200,
		MaxAudit:      500,
		Servers: []ServerConfig{
			{ID: "iran", Name: "Iran Splitter", Role: "iran", Address: "188.121.111.122", SourceType: "fixture"},
			{ID: "germany", Name: "Germany Splitter", Role: "germany", Address: "91.107.152.1", SourceType: "fixture"},
		},
	}
}
