package systemd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// extraGoldenSpecs maps golden file base names to the ExtraUnitSpec that renders them.
func extraGoldenSpecs() map[string]ExtraUnitSpec {
	return map[string]ExtraUnitSpec{
		"xray-consumer": {
			Unit:    "xray-consumer.service",
			BinPath: "/opt/split-tunnel/xray/current/xray",
		},
		"tunneldash": {
			Unit:       "tunneldash.service",
			BinPath:    "/opt/split-tunnel/tunneldash",
			BasePath:   "00112233445566778899aabbccddeeff",
			EnvFile:    "/etc/split-tunnel/dashboard.env",
			ConfigPath: "/etc/split-tunnel/dashboard/config.json",
		},
		"control-agent": {
			Unit:                  "control-agent.service",
			BinPath:               "/opt/split-tunnel/splitterctl",
			ControlAgentStoreRoot: "/var/lib/split-tunnel-ctl",
		},
		"control-agent.socket": {
			Unit:                   "control-agent.socket",
			BinPath:               "/opt/split-tunnel/splitterctl",
			ControlAgentSocketPath: "/run/split-tunnel-ctl/control.sock",
		},
	}
}

func TestRenderExtraUnitGolden(t *testing.T) {
	for name, s := range extraGoldenSpecs() {
		t.Run(name, func(t *testing.T) {
			got, err := RenderExtraUnit(s)
			if err != nil {
				t.Fatalf("RenderExtraUnit: %v", err)
			}
			if strings.Contains(string(got), "\r") {
				t.Fatalf("renderer emitted CR bytes")
			}
			if !strings.HasSuffix(string(got), "\n") || strings.HasSuffix(string(got), "\n\n") {
				t.Fatalf("renderer output must end with exactly one newline")
			}
			goldenPath := filepath.Join("testdata", "golden", name+".golden.service")
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %s: %v", goldenPath, err)
			}
			want = normalizeLineEndings(want)
			if string(got) != string(want) {
				t.Fatalf("unit bytes differ from golden:\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

func TestRenderExtraUnitDeterministic(t *testing.T) {
	for name, s := range extraGoldenSpecs() {
		t.Run(name, func(t *testing.T) {
			first, err := RenderExtraUnit(s)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			for i := 0; i < 50; i++ {
				got, err := RenderExtraUnit(s)
				if err != nil {
					t.Fatalf("render %d: %v", i, err)
				}
				if string(got) != string(first) {
					t.Fatalf("render %d diverged", i)
				}
			}
		})
	}
}

func TestRenderExtraUnitRejection(t *testing.T) {
	cases := map[string]ExtraUnitSpec{
		"unknown unit":           {Unit: "bogus.service", BinPath: "/opt/x"},
		"empty binpath":          {Unit: "xray-consumer.service"},
		"relative binpath":       {Unit: "xray-consumer.service", BinPath: "relative/bin"},
		"whitespace binpath":     {Unit: "xray-consumer.service", BinPath: "/opt/has space"},
		"consumer with basepath": {Unit: "xray-consumer.service", BinPath: "/opt/x", BasePath: "00112233445566778899aabbccddeeff"},
		"dash bad basepath":      {Unit: "tunneldash.service", BinPath: "/opt/t", BasePath: "tooshort", EnvFile: "/etc/x.env", ConfigPath: "/etc/x.json"},
		"dash empty envfile":     {Unit: "tunneldash.service", BinPath: "/opt/t", BasePath: "00112233445566778899aabbccddeeff", ConfigPath: "/etc/x.json"},
		"ctl empty storeroot":    {Unit: "control-agent.service", BinPath: "/opt/splitterctl"},
		"ctl relative storeroot": {Unit: "control-agent.service", BinPath: "/opt/splitterctl", ControlAgentStoreRoot: "relative/root"},
		"ctl with basepath":      {Unit: "control-agent.service", BinPath: "/opt/splitterctl", ControlAgentStoreRoot: "/var/lib/ctl", BasePath: "00112233445566778899aabbccddeeff"},
		"sock empty path":        {Unit: "control-agent.socket", BinPath: "/opt/splitterctl"},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := RenderExtraUnit(s); !errors.Is(err, ErrSpec) {
				t.Fatalf("want ErrSpec, got %v", err)
			}
		})
	}
}

// Ensure no secret material appears in the extra unit bytes.
func TestExtraUnitsContainNoSecretMaterial(t *testing.T) {
	for name, s := range extraGoldenSpecs() {
		t.Run(name, func(t *testing.T) {
			got, err := RenderExtraUnit(s)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if strings.Contains(string(got), "SECRET") || strings.Contains(string(got), "KEY") {
				t.Errorf("unit bytes contain secret marker: %q", string(got))
			}
		})
	}
}
