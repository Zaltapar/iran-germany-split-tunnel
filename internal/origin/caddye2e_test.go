//go:build caddye2e

// caddye2e_test.go — real-binary gate helper for the "Pinned Caddy
// gate" CI step (design doc plans/t4-design.md §6). It renders the
// Caddyfile for every fixed non-production vector into STABLE paths
// and prints a marker line per variant that the shell step parses.
//
// Why a stable path: t.TempDir() is wiped when `go test` exits, but
// the CI step must run `caddy validate --config` on each file AFTER
// the test process is gone. The output dir is gitignored
// (internal/origin/testdata/e2e/).
//
// Excluded from the hermetic unit suite by this build tag; compiled
// only by the CI gate step:
//
//	go test -v -tags caddye2e -run TestE2ERenderGoldens ./internal/origin/
package origin

import (
	"os"
	"path/filepath"
	"testing"
)

// TestE2ERenderGoldens renders all three committed-golden variants
// into testdata/e2e/<name>.Caddyfile and prints:
//
//	E2E_CADDYFILE_PATH=<name>=<absolute path>
//
// The CI step downloads the pinned Caddy, verifies its SHA-512, and
// runs `caddy validate --config <path>` on every variant — the real
// binary is the authority on whether the generated Caddyfiles are
// valid (the T4 gate). The vectors are the same fixed, documented,
// non-production ones as the committed goldens.
func TestE2ERenderGoldens(t *testing.T) {
	cases := []struct {
		name string
		plan Plan
	}{
		{"caddy-default", goldenPlanCaddy()},
		{"caddy-alpn01", goldenPlanALPN()},
		{"cdn-tls-internal", goldenPlanCDN()},
	}
	dir := filepath.Join("testdata", "e2e")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir e2e dir: %v", err)
	}
	for _, c := range cases {
		b, err := RenderCaddyfile(c.plan)
		if err != nil {
			t.Fatalf("render %s: %v", c.name, err)
		}
		abs, err := filepath.Abs(filepath.Join(dir, c.name+".Caddyfile"))
		if err != nil {
			t.Fatalf("abs e2e path: %v", err)
		}
		if err := os.WriteFile(abs, b, 0o600); err != nil {
			t.Fatalf("write e2e Caddyfile: %v", err)
		}
		t.Logf("E2E_CADDYFILE_PATH=%s=%s", c.name, abs)
	}
}
