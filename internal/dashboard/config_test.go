package dashboard

import (
	"encoding/json"
	"os"
	"testing"
)

func TestParseConfigDefaults(t *testing.T) {
	data := []byte(`{"listenAddr":"127.0.0.1:8080","readOnly":true,"servers":[{"id":"iran","role":"iran","address":"188.121.111.122","sourceType":"fixture"}]}`)
	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if !cfg.ReadOnly {
		t.Error("ReadOnly default not applied")
	}
	if cfg.RefreshSec != 10 {
		t.Errorf("RefreshSec default = %d, want 10", cfg.RefreshSec)
	}
	if cfg.MaxLogEntries != 200 {
		t.Errorf("MaxLogEntries default = %d, want 200", cfg.MaxLogEntries)
	}
	if cfg.Servers[0].SourceType != "fixture" {
		t.Errorf("server sourceType = %q, want fixture", cfg.Servers[0].SourceType)
	}
}

func TestParseConfigInvalidRole(t *testing.T) {
	data := []byte(`{"servers":[{"id":"x","role":"france","sourceType":"fixture"}]}`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestParseConfigDuplicateIDs(t *testing.T) {
	data := []byte(`{"servers":[
		{"id":"a","role":"iran","sourceType":"fixture"},
		{"id":"a","role":"germany","sourceType":"fixture"}
	]}`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Fatal("expected error for duplicate server id")
	}
}

func TestParseConfigNoServers(t *testing.T) {
	data := []byte(`{"servers":[]}`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Fatal("expected error for empty server list")
	}
}

func TestParseConfigUnknownSourceType(t *testing.T) {
	data := []byte(`{"servers":[{"id":"a","role":"iran","sourceType":"carrier-pigeon"}]}`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Fatal("expected error for unknown sourceType")
	}
}

func TestDefaultConfigIsSafe(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config failed validation: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("default listen = %q, want 127.0.0.1:8080", cfg.ListenAddr)
	}
	if !cfg.ReadOnly {
		t.Error("default config must be read-only")
	}
	if len(cfg.Servers) != 2 {
		t.Errorf("default config has %d servers, want 2", len(cfg.Servers))
	}
}

func TestLoadConfigBadJSON(t *testing.T) {
	data := []byte(`{invalid json`)
	_, err := ParseConfig(data)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

// TestSSHExampleConfigValidates loads the shipped SSH example config through
// the real ParseConfig path and confirms every server's strict SSH sub-config
// passes validation (pinned host keys, fixed bounds, known units). This locks
// the example schema so it can never silently drift from ValidateSSHConfig.
// It does NOT open an SSH connection; ValidateSSHConfig only checks that the
// referenced paths are absolute and well-formed.
func TestSSHExampleConfigValidates(t *testing.T) {
	data, err := os.ReadFile("../../config/tunneldash-ssh-example.json")
	if err != nil {
		t.Skipf("ssh example config not present: %v", err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("ParseConfig(ssh example): %v", err)
	}
	for _, s := range cfg.Servers {
		if s.SourceType != "ssh" {
			t.Fatalf("server %q: expected sourceType ssh, got %q", s.ID, s.SourceType)
		}
		if s.SSH == nil {
			t.Fatalf("server %q: ssh sub-config missing", s.ID)
		}
		// Re-validate explicitly; ParseConfig already called ValidateSSHConfig,
		// but this documents the invariant.
		if err := ValidateSSHConfig(s.SSH, s.Role); err != nil {
			t.Errorf("server %q ssh config: %v", s.ID, err)
		}
		// Host-key pinning must be present and strict.
		if s.SSH.KnownHosts == "" {
			t.Errorf("server %q: knownHosts pin missing", s.ID)
		}
	}
}

// TestConfigJSONRoundTrip ensures the config schema is stable for operator use.
func TestConfigJSONRoundTrip(t *testing.T) {
	original := DefaultConfig()
	original.Servers[0].MetricsURL = "http://127.0.0.1:9101/metrics"
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var restored DashboardConfig
	if err := json.Unmarshal(b, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.Servers[0].MetricsURL != "http://127.0.0.1:9101/metrics" {
		t.Errorf("round-trip lost MetricsURL: %q", restored.Servers[0].MetricsURL)
	}
}

// TestParseConfigTLSNestedShape pins the dashboard TLS wire schema to the
// conventional NESTED form ({"tls":{"enabled":..., "certFile":..., ...}}) that
// install-oneclick.sh generate_dashboard writes. Regression guard for the
// flat-dotted-key bug (tags "tls.enabled" inside the "tls" object) which
// made encoding/json silently drop conventional input, leave Enabled=false,
// and trip the non-loopback bind gate into a crash-loop on public listen.
func TestParseConfigTLSNestedShape(t *testing.T) {
	data := []byte(`{
		"listenAddr":"0.0.0.0:8443","readOnly":true,
		"tls":{"enabled":true,"certFile":"/etc/x/cert.pem","keyFile":"/etc/x/key.pem","basePath":"0123456789abcdef0123456789abcdef"},
		"servers":[{"id":"germany","role":"germany","address":"127.0.0.1","sourceType":"http","metricsUrl":"http://127.0.0.1:9101/metrics"}]
	}`)
	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("ParseConfig(nested tls): %v", err)
	}
	if cfg.TLS == nil {
		t.Fatal("cfg.TLS is nil; nested tls object was not unmarshalled")
	}
	if !cfg.TLS.Enabled {
		t.Errorf("TLS.Enabled = false, want true (nested shape must populate it)")
	}
	if cfg.TLS.CertFile != "/etc/x/cert.pem" {
		t.Errorf("TLS.CertFile = %q", cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "/etc/x/key.pem" {
		t.Errorf("TLS.KeyFile = %q", cfg.TLS.KeyFile)
	}
	if cfg.TLS.BasePath != "0123456789abcdef0123456789abcdef" {
		t.Errorf("TLS.BasePath = %q", cfg.TLS.BasePath)
	}
	if !cfg.TLS.IsSecure() {
		t.Error("TLS.IsSecure() = false, want true for a complete config")
	}
}
