// render_test.go — design §7 items 1 (golden), 2 (rejection matrix),
// plus the D4 property: no unit byte string may carry secret material.
package systemd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenSpecs maps golden file base names to the Spec that renders them.
// The golden files live in testdata/golden/ as <name>.golden.service.
func goldenSpecs() map[string]Spec {
	return map[string]Spec{
		"germany-splitter": {
			Role:      RoleGermany,
			Component: ComponentSplitter,
			BinPath:   "/opt/split-tunnel/germany-splitter",
			EnvFile:   canonicalEnvFile(RoleGermany),
		},
		"xray-germany": {
			Role:      RoleGermany,
			Component: ComponentXray,
			BinPath:   XrayBinaryPath,
		},
		"iran-splitter": {
			Role:          RoleIran,
			Component:     ComponentSplitter,
			BinPath:       "/opt/split-tunnel/iran-splitter",
			EnvFile:       canonicalEnvFile(RoleIran),
			OriginEnabled: true,
		},
		"iran-origin": {
			Role:          RoleIran,
			Component:     ComponentOrigin,
			BinPath:       "/opt/split-tunnel/caddy/v2.11.4/caddy",
			OriginVersion: "v2.11.4",
		},
		// The 5th golden (no origin): same spec, OriginEnabled=false.
		"iran-splitter.no-origin": {
			Role:      RoleIran,
			Component: ComponentSplitter,
			BinPath:   "/opt/split-tunnel/iran-splitter",
			EnvFile:   canonicalEnvFile(RoleIran),
		},
	}
}

// normalizeLineEndings maps CRLF→LF (CRITICAL-2: the goldens are
// CRLF-normalized before comparison so a Windows checkout of the repo
// cannot fail the byte comparison).
func normalizeLineEndings(b []byte) []byte {
	return []byte(strings.ReplaceAll(string(b), "\r\n", "\n"))
}

func TestRenderGolden(t *testing.T) {
	specified := goldenSpecs()
	seen := map[string]bool{}
	for name, s := range specified {
		t.Run(name, func(t *testing.T) {
			got, err := RenderUnit(s)
			if err != nil {
				t.Fatalf("RenderUnit: %v", err)
			}
			// Renderer contract: LF only, a single trailing newline.
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
			seen[name] = true
		})
	}
	// Every committed golden must be produced by a spec (no orphans).
	entries, err := os.ReadDir(filepath.Join("testdata", "golden"))
	if err != nil {
		t.Fatalf("read golden dir: %v", err)
	}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".golden.service")
		if _, ok := specified[name]; !ok {
			t.Errorf("golden %s has no spec (orphan golden)", e.Name())
		}
	}
}

// TestRenderDeterministic: 100 renders of every spec → 1 byte string.
func TestRenderDeterministic(t *testing.T) {
	for name, s := range goldenSpecs() {
		t.Run(name, func(t *testing.T) {
			first, err := RenderUnit(s)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			for i := 0; i < 100; i++ {
				got, err := RenderUnit(s)
				if err != nil {
					t.Fatalf("render %d: %v", i, err)
				}
				if string(got) != string(first) {
					t.Fatalf("render %d diverged from the first render", i)
				}
			}
		})
	}
}

// TestRenderRejection is the §7-2 matrix: every invalid spec must fail
// with ErrSpec BEFORE any I/O (RenderUnit is pure).
func TestRenderRejection(t *testing.T) {
	cases := map[string]Spec{
		"unit-name traversal":    {Role: RoleGermany, Component: ComponentSplitter, BinPath: "/opt/x", EnvFile: canonicalEnvFile(RoleGermany), UnitName: "../x.service"},
		"unit-name .d override":  {Role: RoleGermany, Component: ComponentSplitter, BinPath: "/opt/x", EnvFile: canonicalEnvFile(RoleGermany), UnitName: "x.d/y.service"},
		"unit-name uppercase":    {Role: RoleGermany, Component: ComponentSplitter, BinPath: "/opt/x", EnvFile: canonicalEnvFile(RoleGermany), UnitName: "X.service"},
		"unit-name no suffix":    {Role: RoleGermany, Component: ComponentSplitter, BinPath: "/opt/x", EnvFile: canonicalEnvFile(RoleGermany), UnitName: "service"},
		"unit-name empty suffix": {Role: RoleGermany, Component: ComponentSplitter, BinPath: "/opt/x", EnvFile: canonicalEnvFile(RoleGermany), UnitName: ".service"},
		"binpath relative":       {Role: RoleGermany, Component: ComponentSplitter, BinPath: "relative/bin", EnvFile: canonicalEnvFile(RoleGermany)},
		"binpath whitespace":     {Role: RoleGermany, Component: ComponentSplitter, BinPath: "/opt/has space", EnvFile: canonicalEnvFile(RoleGermany)},
		"binpath empty":          {Role: RoleGermany, Component: ComponentSplitter, BinPath: "", EnvFile: canonicalEnvFile(RoleGermany)},
		"binpath too long":       {Role: RoleGermany, Component: ComponentSplitter, BinPath: "/opt/" + strings.Repeat("a", 5000), EnvFile: canonicalEnvFile(RoleGermany)},
		"xray on iran":           {Role: RoleIran, Component: ComponentXray, BinPath: XrayBinaryPath},
		"origin on germany":      {Role: RoleGermany, Component: ComponentOrigin, BinPath: "/opt/caddy", OriginVersion: "v2.11.4"},
		"splitter wrong envfile": {Role: RoleGermany, Component: ComponentSplitter, BinPath: "/opt/x", EnvFile: "/etc/other.env"},
		"xray with envfile":      {Role: RoleGermany, Component: ComponentXray, BinPath: XrayBinaryPath, EnvFile: canonicalEnvFile(RoleGermany)},
		"origin bad version":     {Role: RoleIran, Component: ComponentOrigin, BinPath: "/opt/caddy", OriginVersion: "v1.2"},
		"origin missing version": {Role: RoleIran, Component: ComponentOrigin, BinPath: "/opt/caddy"},
		"origin version slash":   {Role: RoleIran, Component: ComponentOrigin, BinPath: "/opt/caddy", OriginVersion: "v2.11.4/../../etc"},
		"requires traversal":     {Role: RoleGermany, Component: ComponentSplitter, BinPath: "/opt/x", EnvFile: canonicalEnvFile(RoleGermany), RequiresUnits: []string{"../etc.service"}},
		"unknown role":           {Role: "mars", Component: ComponentSplitter, BinPath: "/opt/x", EnvFile: "/x"},
		"unknown component":      {Role: RoleGermany, Component: "bogus", BinPath: "/opt/x"},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := RenderUnit(s); !errors.Is(err, ErrSpec) {
				t.Fatalf("want ErrSpec, got %v", err)
			}
		})
	}
}

// TestDescriptionIgnored: the documented trap — Spec.Description has no
// effect on the rendered bytes.
func TestDescriptionIgnored(t *testing.T) {
	s := goldenSpecs()["germany-splitter"]
	with, err := RenderUnit(s)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s.Description = "ATTACKER-CONTROLLED-DESCRIPTION\nEnvironment=EVIL=1\n"
	without, err := RenderUnit(s)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if string(with) != string(without) {
		t.Fatalf("Spec.Description leaked into the rendered bytes")
	}
	if !strings.Contains(string(without), "EnvironmentFile=") || strings.Contains(string(without), "EVIL") {
		t.Fatalf("unexpected environment line in rendered unit")
	}
}

// TestRenderedUnitsContainNoSecretMaterial: a 32-hex run (the shape of
// the tunnel secret) and the test secret marker must not appear in ANY
// rendered unit — the D4 property, asserted on the actual byte strings.
func TestRenderedUnitsContainNoSecretMaterial(t *testing.T) {
	for name, s := range goldenSpecs() {
		t.Run(name, func(t *testing.T) {
			got, err := RenderUnit(s)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			for i := 0; i+len(secretMarker[:32]) <= len(got); i++ {
				if isHexRun(string(got), i, 32) {
					t.Fatalf("unit bytes contain a 32-hex run at %d: %q", i, got[i:i+32])
				}
			}
			if strings.Contains(string(got), secretMarker) {
				t.Fatalf("unit bytes contain the secret marker")
			}
		})
	}
}

// isHexRun reports whether s[i:i+n] is all lowercase hex digits.
func isHexRun(s string, i, n int) bool {
	for j := i; j < i+n; j++ {
		c := s[j]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
