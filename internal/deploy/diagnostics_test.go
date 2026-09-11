package deploy

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
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
