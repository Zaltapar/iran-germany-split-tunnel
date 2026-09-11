package deploy

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/firewall"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

func TestNewLinuxAdapterRejectsNonCanonicalPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production adapter is Linux-only")
	}
	r := validGermanyRequest()
	r.StateRoot = "/tmp/not-managed"
	if _, err := NewLinuxAdapter(r, nil, nil); err == nil {
		t.Fatal("non-canonical state root unexpectedly accepted")
	}
}

func TestNewLinuxAdapterRejectsInvalidFirewallPlan(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production adapter is Linux-only")
	}
	r := validGermanyRequest()
	r.StateRoot = systemd.StateDir
	r.EnvPath = systemd.EnvFile(systemd.RoleGermany)
	r.ConfigPath = systemd.StateDir + "/xray-germany.json"
	r.Firewall = firewall.Plan{Role: "unknown"}
	if _, err := NewLinuxAdapter(r, nil, nil); err == nil {
		t.Fatal("invalid firewall plan unexpectedly accepted")
	}
}

func TestLinuxAdapterFreshCleanupIsBoundedByOwnedState(t *testing.T) {
	// This test documents the production contract without invoking root-gated
	// T5 operations: an adapter with no applied firewall snapshot and no unit
	// journal has no cleanup work and must not report success as a restore.
	adapter := &LinuxAdapter{}
	if err := adapter.CleanupFresh(context.Background(), DesiredState{}); err != nil {
		t.Fatalf("empty cleanup: %v", err)
	}
	if err := adapter.Restore(context.Background(), Manifest{}); err == nil || errors.Is(err, ErrRecovered) {
		t.Fatalf("empty restore = %v, want explicit unsupported restore", err)
	}
}
