package deploy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLegacyManifest writes a schema-1 state.json exactly as the previous
// schema would have: only the legacy fields, no convergence-identity fields,
// and a ManifestHash computed the same way Store.Load recomputes it. This is a
// faithful on-disk legacy file, not a hand-edited approximation.
func writeLegacyManifest(t *testing.T, root string, m Manifest) {
	t.Helper()
	m.Schema = 1
	hash, err := manifestHash(m)
	if err != nil {
		t.Fatal(err)
	}
	m.ManifestHash = hash
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestLoadLegacyManifestWithoutNewFields is the backward-compatibility
// guarantee: a state.json written before the convergence-identity fields
// existed (schema 1, no binary hashes, no unit hashes, no origin params, no
// managed paths) loads successfully with no error and no spurious destructive
// drift against a matching desired state.
func TestLoadLegacyManifestWithoutNewFields(t *testing.T) {
	root := t.TempDir()
	legacy := Manifest{
		Role:       RoleIran,
		Generation: "g-legacy",
		Paths:      Paths{StateRoot: root, Env: filepath.Join(root, "iran.env")},
		Components: Components{
			Splitter: ComponentState{Version: "v1.0.0", Path: "/opt/split-tunnel/splitter", SHA256: "legacy-splitter-hash"},
			Origin:   OriginState{Mode: "caddy", Version: "v2.11.4", Domain: "upload.example.com"},
		},
		Pairing:  PairingState{State: "none"},
		Firewall: FirewallState{Backend: "none", Ownership: "split-tunnel", RulesHash: "legacy-rules"},
	}
	writeLegacyManifest(t, root, legacy)

	// The raw file must not contain any of the new fields.
	raw, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"realityFingerprint", "caddyfileHash", "unitDir", "binaryPrefix", "unitFiles"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("legacy fixture unexpectedly contains new field %q", forbidden)
		}
	}

	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("legacy manifest failed to load: %v", err)
	}
	if loaded.Generation != "g-legacy" || loaded.Role != RoleIran {
		t.Fatalf("loaded legacy manifest = %+v", loaded)
	}

	// A desired state that carries no new assertions must not plan drift
	// against the legacy manifest (the empty/unknown rule).
	desired := desiredFor(loaded)
	plan, err := PlanDesired(&loaded, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Unchanged {
		t.Fatalf("legacy manifest planned spurious drift: %#v", plan.Changes)
	}
}

// TestCommitUpgradesLegacySchema pins the documented migration expectation: a
// legacy manifest is upgraded to the current schema on the next commit, and the
// committed file then carries the new fields.
func TestCommitUpgradesLegacySchema(t *testing.T) {
	root := t.TempDir()
	legacy := Manifest{
		Role:       RoleIran,
		Generation: "g-legacy",
		Paths:      Paths{StateRoot: root},
		Firewall:   FirewallState{Backend: "none"},
	}
	writeLegacyManifest(t, root, legacy)

	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Schema != 1 {
		t.Fatalf("loaded schema = %d, want legacy 1", loaded.Schema)
	}
	committed, err := store.Commit(loaded, "upgrade")
	if err != nil {
		t.Fatalf("Commit of legacy manifest: %v", err)
	}
	if committed.Schema != SchemaVersion {
		t.Fatalf("committed schema = %d, want %d", committed.Schema, SchemaVersion)
	}
	reloaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Schema != SchemaVersion {
		t.Fatalf("reloaded schema = %d, want %d", reloaded.Schema, SchemaVersion)
	}
}

// TestValidateManifestRejectsUnknownSchema ensures the legacy acceptance does
// not become a hole: an unknown schema (not current, not legacy) fails closed.
func TestValidateManifestRejectsUnknownSchema(t *testing.T) {
	m := Manifest{Schema: 99, Role: RoleIran, Paths: Paths{StateRoot: "/tmp/state"}}
	if err := validateManifest(m); err == nil {
		t.Fatal("unknown schema unexpectedly accepted")
	}
}
