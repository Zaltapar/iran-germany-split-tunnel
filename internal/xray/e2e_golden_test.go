//go:build xraye2e

// e2e_golden_test.go — real-binary gate helper for the "Pinned Xray gate"
// CI step (design doc plans/t3-design.md §7). It renders the Germany
// config for the fixed non-production vector into a STABLE path and
// prints a marker line the shell step parses.
//
// Why a stable path: t.TempDir() is wiped when `go test` exits, but the
// CI step must read the rendered file AFTER the test process is gone.
// The output dir is gitignored (internal/xray/testdata/e2e/).
//
// Excluded from the hermetic unit suite by this build tag; compiled only
// by the CI gate step:
//
//	go test -v -tags xraye2e -run TestE2ERenderGolden ./internal/xray/
package xray

import (
	"os"
	"path/filepath"
	"testing"
)

// TestE2ERenderGolden renders the golden-vector Germany config into
// testdata/e2e/germany-e2e.json and prints:
//
//	E2E_CONFIG_PATH=<absolute path>
//
// The CI step downloads the pinned Xray and runs
// `xray run -test -config <path>` against it — the real binary is the
// authority on whether the generated config is valid (T3 spec item 8).
// The vector is the same fixed, documented, non-production one as the
// committed golden (no production secret is ever rendered here).
func TestE2ERenderGolden(t *testing.T) {
	b, err := RenderGermanyConfig(goldenParams(), goldenKeypair())
	if err != nil {
		t.Fatalf("render e2e config: %v", err)
	}
	dir := filepath.Join("testdata", "e2e")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir e2e dir: %v", err)
	}
	abs, err := filepath.Abs(filepath.Join(dir, "germany-e2e.json"))
	if err != nil {
		t.Fatalf("abs e2e path: %v", err)
	}
	if err := os.WriteFile(abs, b, 0o600); err != nil {
		t.Fatalf("write e2e config: %v", err)
	}
	t.Logf("E2E_CONFIG_PATH=%s", abs)
}
