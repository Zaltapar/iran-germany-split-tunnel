package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

func TestBuildSystemdPlanGermany(t *testing.T) {
	plan, err := BuildSystemdPlan(validGermanyRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Specs) != 2 {
		t.Fatalf("spec count = %d, want 2", len(plan.Specs))
	}
	if plan.Specs[0].Component != systemd.ComponentXray || plan.Specs[1].Component != systemd.ComponentSplitter {
		t.Fatalf("components = %#v", plan.Specs)
	}
	if len(plan.Specs[1].RequiresUnits) != 1 || plan.Specs[1].RequiresUnits[0] != "xray-germany.service" {
		t.Fatalf("splitter requirements = %#v", plan.Specs[1].RequiresUnits)
	}
	if plan.Env[config.EnvSecret] == "" {
		t.Fatal("env projection omitted secret")
	}
}

func TestIranStagingSplitterNeverReachesExecStartOrManifest(t *testing.T) {
	r := validIranRequest()
	r.SplitterPath = filepath.Join(t.TempDir(), "staging", "iran-splitter")
	plan, err := BuildSystemdPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	unit, err := systemd.RenderUnit(plan.Specs[1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unit), "staging") || !strings.Contains(string(unit), "ExecStart=/opt/split-tunnel/iran-splitter\n") {
		t.Fatalf("Iran unit has non-canonical ExecStart:\n%s", unit)
	}
	desired, err := r.Desired()
	if err != nil {
		t.Fatal(err)
	}
	if got := desired.Components.Splitter.Path; got != "/opt/split-tunnel/iran-splitter" {
		t.Fatalf("manifest splitter path = %q, want canonical path", got)
	}
}

func TestInstallCanonicalSplitterCopiesStagingArtifact(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "staging", "iran-splitter")
	managed := filepath.Join(root, "managed", "iran-splitter")
	if err := os.MkdirAll(filepath.Dir(staging), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(managed), 0o755); err != nil {
		t.Fatal(err)
	}
	want := []byte("canonical artifact")
	if err := os.WriteFile(staging, want, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := installCanonicalSplitter(staging, managed); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(managed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("managed artifact = %q, want %q", got, want)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Fatalf("staging source was removed: %v", err)
	}
}

func TestBuildSystemdPlanIranOriginDependency(t *testing.T) {
	plan, err := BuildSystemdPlan(validIranRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Specs) != 2 {
		t.Fatalf("spec count = %d, want 2", len(plan.Specs))
	}
	if plan.Specs[0].Component != systemd.ComponentOrigin || plan.Specs[1].Component != systemd.ComponentSplitter {
		t.Fatalf("components = %#v", plan.Specs)
	}
	if !plan.Specs[1].OriginEnabled {
		t.Fatal("Iran splitter did not enable origin dependency")
	}
	if strings.Contains(strings.Join([]string{plan.Specs[0].BinPath, plan.Specs[1].BinPath}, "\n"), validIranRequest().Config.Secret) {
		t.Fatal("systemd plan leaked tunnel secret")
	}
}
