package deploy

import (
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
