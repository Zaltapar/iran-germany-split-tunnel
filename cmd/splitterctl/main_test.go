package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/deploy"
)

func TestRunHelp(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"help"}, &out, &out); err != nil {
		t.Fatalf("run help: %v", err)
	}
	if !strings.Contains(out.String(), "usage: splitterctl") {
		t.Fatalf("help output = %q", out.String())
	}
}
func TestRunUnknownCommand(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	var out bytes.Buffer
	err := run(context.Background(), []string{"nope"}, &out, &out)
	if !errors.Is(err, errUsage) {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestRunReadOnlyCommandsRejectArguments(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	for _, args := range [][]string{{"status", "extra"}, {"doctor", "--verbose"}} {
		var out bytes.Buffer
		err := run(context.Background(), args, &out, &out)
		if !errors.Is(err, errUsage) {
			t.Errorf("%v: error = %v, want usage error", args, err)
		}
	}
}

func TestStatusMissingState(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SPLITTERCTL_STATE_ROOT", filepath.Join(root, "state"))
	var out bytes.Buffer
	if err := run(context.Background(), []string{"status"}, &out, &out); err != nil {
		t.Fatalf("status: %v", err)
	}
	if got := out.String(); got != "status: not installed\n" {
		t.Fatalf("status output = %q", got)
	}
}

func TestStatusAndDoctorValidState(t *testing.T) {
	root := t.TempDir()
	store, err := deploy.NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(deploy.Manifest{
		Role:       deploy.RoleGermany,
		Generation: "g-test",
		Paths:      deploy.Paths{StateRoot: store.Root},
		Firewall:   deploy.FirewallState{Backend: "none"},
	}, "test")
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Setenv("SPLITTERCTL_STATE_ROOT", store.Root)

	var statusOut bytes.Buffer
	if err := run(context.Background(), []string{"status"}, &statusOut, &statusOut); err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{"role: germany", "generation: g-test", "firewall: none"} {
		if !strings.Contains(statusOut.String(), want) {
			t.Errorf("status output %q does not contain %q", statusOut.String(), want)
		}
	}

	var doctorOut bytes.Buffer
	if err := run(context.Background(), []string{"doctor"}, &doctorOut, &doctorOut); err != nil {
		t.Fatalf("doctor: %v; output=%q", err, doctorOut.String())
	}
	if !strings.Contains(doctorOut.String(), "state.integrity [pass]") {
		t.Fatalf("doctor output = %q", doctorOut.String())
	}
}

func TestConfigShowIsRedacted(t *testing.T) {
	root := t.TempDir()
	store, err := deploy.NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(deploy.Manifest{
		Role:       deploy.RoleIran,
		Generation: "i-config",
		Paths: deploy.Paths{
			StateRoot: store.Root,
			Env:       "/etc/split-tunnel/iran.env",
			Config:    "/etc/split-tunnel/secret-config.json",
		},
		Components: deploy.Components{
			Splitter: deploy.ComponentState{Version: "v1", Path: "/opt/split-tunnel/splitter", SHA256: "splitter-hash"},
			Origin:   deploy.OriginState{Mode: "caddy", Domain: "upload.example.com"},
		},
		Pairing:  deploy.PairingState{State: "finalized", Fingerprints: []string{"secret-fingerprint"}},
		Firewall: deploy.FirewallState{Backend: "ufw", RulesHash: "rules-hash"},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPLITTERCTL_STATE_ROOT", store.Root)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"config", "show"}, &out, &out); err != nil {
		t.Fatalf("config show: %v", err)
	}
	got := out.String()
	for _, want := range []string{"role: iran", "origin.mode: caddy", "origin.domain: upload.example.com", "pairing.state: finalized"} {
		if !strings.Contains(got, want) {
			t.Errorf("config output %q does not contain %q", got, want)
		}
	}
	for _, forbidden := range []string{"secret-fingerprint", "secret-config.json", "splitter-hash", "rules-hash", "stateRoot", "manifestHash"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("config output leaked %q: %q", forbidden, got)
		}
	}
}

func TestDoctorFailsClosedOnTamperedState(t *testing.T) {
	root := t.TempDir()
	store, err := deploy.NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(deploy.Manifest{
		Role:       deploy.RoleIran,
		Generation: "i-test",
		Paths:      deploy.Paths{StateRoot: store.Root},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(store.Root, "state.json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"role": "iran"`), []byte(`"role": "germany"`), 1)
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPLITTERCTL_STATE_ROOT", store.Root)

	var out bytes.Buffer
	err = run(context.Background(), []string{"doctor"}, &out, &out)
	if err == nil {
		t.Fatal("doctor unexpectedly succeeded")
	}
	if !strings.Contains(out.String(), "state.integrity [fail]") {
		t.Fatalf("doctor output = %q", out.String())
	}
}

func TestMutatingCommandsReportNotWired(t *testing.T) {
	t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())
	for _, args := range [][]string{{"install", "iran"}, {"pair", "generate"}, {"upgrade"}, {"rollback"}, {"uninstall"}, {"config", "set"}} {
		var out bytes.Buffer
		err := run(context.Background(), args, &out, &out)
		if !errors.Is(err, errNotWired) {
			t.Errorf("%v: error = %v, want not wired", args, err)
		}
	}
}
