package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

func TestDiagnosticsIncludesStateAndChecks(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(root)
	if err := store.Save(testManifest(root, RoleIran)); err != nil {
		t.Fatal(err)
	}
	d := Diagnostics{
		Store: store,
		Checks: []Check{
			{ID: "service.splitter", Run: func(context.Context) Finding { return Finding{Severity: SeverityPass, Summary: "active"} }},
			{ID: "firewall.rules", Run: func(context.Context) Finding {
				return Finding{Severity: SeverityWarn, Summary: "rules differ", Action: "reconcile"}
			}},
		},
	}
	findings := d.Run(context.Background())
	if len(findings) != 3 || HasFailures(findings) {
		t.Fatalf("findings = %+v", findings)
	}
	for _, f := range findings {
		if !f.Redacted {
			t.Fatalf("finding not marked redacted: %+v", f)
		}
	}
}

func TestDiagnosticsTamperedStateFailsClosed(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(root)
	if err := store.Save(testManifest(root, RoleIran)); err != nil {
		t.Fatal(err)
	}
	path := store.manifestPath()
	data, _ := os.ReadFile(path)
	data[len(data)-2] = '!'
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	findings := (Diagnostics{Store: store}).Run(context.Background())
	if !HasFailures(findings) || findings[0].ID != "state.integrity" {
		t.Fatalf("findings = %+v", findings)
	}
	if strings.Contains(findings[0].Summary, "!") {
		t.Fatal("diagnostic leaked state contents")
	}
}

func TestDiagnosticsNilCheckAndStateFinding(t *testing.T) {
	findings := (Diagnostics{Checks: []Check{{ID: "missing"}}}).Run(context.Background())
	if !HasFailures(findings) {
		t.Fatalf("findings = %+v", findings)
	}
	f := StateFinding(errors.New("secret-value"))
	if !f.Redacted || strings.Contains(f.Summary, "secret-value") {
		t.Fatalf("state finding leaked error: %+v", f)
	}
}

type diagnosticSystemdFake struct {
	state string
	calls []string
}

func (f *diagnosticSystemdFake) Run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if len(args) >= 2 && args[0] == "systemctl" && args[1] == "is-active" {
		return f.state, nil
	}
	return "", nil
}

func TestServiceStateCheckPositiveAndNegativeAreReadOnly(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(Manifest{
		Schema:     SchemaVersion,
		Role:       RoleGermany,
		Generation: "g-service",
		Paths:      Paths{StateRoot: root},
		Services:   []ServiceState{{Unit: "germany-splitter.service"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		state string
		want  Severity
	}{
		{"active", "active", SeverityPass},
		{"failed", "failed", SeverityFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &diagnosticSystemdFake{state: tc.state}
			before, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			finding := ServiceStateCheck(store, systemd.NewServiceManager(fake)).Run(context.Background())
			if finding.Severity != tc.want {
				t.Fatalf("finding = %+v, want %s", finding, tc.want)
			}
			if len(fake.calls) != 1 || fake.calls[0] != "systemctl is-active germany-splitter.service" {
				t.Fatalf("calls = %#v, want one read-only is-active call", fake.calls)
			}
			after, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("service diagnostic mutated state")
			}
		})
	}
}

func TestArtifactIntegrityCheckPositiveAndNegative(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "splitter")
	content := []byte("managed-test-artifact")
	if err := os.WriteFile(artifact, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	goodHash := hex.EncodeToString(sum[:])
	for _, tc := range []struct {
		name string
		hash string
		want Severity
	}{
		{"matching hash", goodHash, SeverityPass},
		{"mismatching hash", strings.Repeat("0", 64), SeverityFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := NewStore(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Save(Manifest{
				Schema:     SchemaVersion,
				Role:       RoleIran,
				Generation: "g-artifact",
				Paths:      Paths{StateRoot: store.Root},
				Components: Components{Splitter: ComponentState{Path: artifact, SHA256: tc.hash}},
			}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(artifact)
			if err != nil {
				t.Fatal(err)
			}
			finding := ArtifactIntegrityCheck(store).Run(context.Background())
			if finding.Severity != tc.want {
				t.Fatalf("finding = %+v, want %s", finding, tc.want)
			}
			after, err := os.ReadFile(artifact)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("artifact diagnostic mutated artifact")
			}
		})
	}
}
