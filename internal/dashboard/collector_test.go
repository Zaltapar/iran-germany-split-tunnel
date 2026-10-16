package dashboard

import (
	"context"
	"testing"
	"time"
)

func TestFixtureCollectorDeterministic(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	coll := &FixtureCollector{Now: func() time.Time { return fixedTime }}

	cfg := ServerConfig{ID: "iran", Role: "iran", SourceType: "fixture"}
	snap, err := coll.Collect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if snap.Status != Fresh {
		t.Errorf("status = %q, want fresh", snap.Status)
	}
	if snap.ServerID != "iran" {
		t.Errorf("serverID = %q, want iran", snap.ServerID)
	}
	if snap.Metrics == nil {
		t.Fatal("fixture collector returned nil metrics")
	}
	if len(snap.Metrics.Samples) == 0 {
		t.Error("fixture metrics has no samples")
	}
	if len(snap.Logs) == 0 {
		t.Error("fixture logs empty")
	}
	if len(snap.Services) == 0 {
		t.Error("fixture services empty")
	}
}

func TestFixtureCollectorHasConfigWithRedactedSecrets(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	coll := &FixtureCollector{Now: func() time.Time { return fixedTime }}
	cfg := ServerConfig{ID: "germany", Role: "germany", SourceType: "fixture"}
	snap, _ := coll.Collect(context.Background(), cfg)

	// The fixture must include a redacted SPLIT_SECRET value.
	found := false
	for _, cv := range snap.Config {
		if cv.Key == "SPLIT_SECRET" {
			found = true
			if cv.Value != "[REDACTED]" {
				t.Errorf("SPLIT_SECRET value = %q, want [REDACTED]", cv.Value)
			}
			if !cv.Redacted {
				t.Error("SPLIT_SECRET not flagged as redacted")
			}
		}
		if cv.Key == "SPLIT_SOCKS_PASS" {
			if cv.Value != "[REDACTED]" {
				t.Errorf("SPLIT_SOCKS_PASS value = %q, want [REDACTED]", cv.Value)
			}
		}
	}
	if !found {
		t.Error("fixture config does not contain a SPLIT_SECRET entry")
	}
}

func TestHTTPCollectorUnsupportedWithoutURL(t *testing.T) {
	coll := NewHTTPCollector()
	cfg := ServerConfig{ID: "x", Role: "iran", SourceType: "http", MetricsURL: ""}
	snap, err := coll.Collect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if snap.Status != Unsupported {
		t.Errorf("status = %q, want unsupported", snap.Status)
	}
}

// TestSSHCollectorFailsClosedWithoutSubConfig verifies that an ssh-typed
// server with no SSH sub-config fails closed and contacts no host.
func TestSSHCollectorFailsClosedWithoutSubConfig(t *testing.T) {
	// The fake runner records every call; it must record ZERO calls here.
	r := newFakeRunner()
	coll := NewSSHCollectorWithRunner(r)
	cfg := ServerConfig{ID: "iran", Role: "iran", SourceType: "ssh"}
	snap, err := coll.Collect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if snap.Status != Unsupported {
		t.Errorf("ssh collector status = %q, want unsupported", snap.Status)
	}
	if len(r.calls) != 0 {
		t.Errorf("fake runner was invoked %d times; expected 0 (no host contacted)", len(r.calls))
	}
}

func TestNewCollectorFactory(t *testing.T) {
	if c := NewCollector("http"); c == nil {
		t.Error("NewCollector(http) returned nil")
	}
	if c := NewCollector("ssh"); c == nil {
		t.Error("NewCollector(ssh) returned nil")
	}
	if c := NewCollector("fixture"); c == nil {
		t.Error("NewCollector(fixture) returned nil")
	}
	// Unknown type falls back to fixture (safe default).
	if c := NewCollector("unknown"); c == nil {
		t.Error("NewCollector(unknown) returned nil")
	}
}
