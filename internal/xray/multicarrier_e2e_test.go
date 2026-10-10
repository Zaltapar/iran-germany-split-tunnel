//go:build xraye2e

// multicarrier_e2e_test.go — real-binary gate helper for the Phase 2
// two-carrier configs (plans/multi-carrier-intelligence-design.md §8, D1/D3/D4).
// It renders BOTH two-carrier configs (Germany second Reality inbound on
// 2053 + Iran second consumer inbound) into STABLE paths and prints marker
// lines the CI step parses, so the pinned Xray binary is the authority on
// whether the generated multi-carrier config is valid:
//
//	MULTI_E2E_GERMANY_CONFIG_PATH=<absolute path>
//	MULTI_E2E_CONSUMER_CONFIG_PATH=<absolute path>
//
// The CI step then runs `xray run -test` against each rendered file. Excluded
// from the hermetic unit suite by this build tag (see e2e_golden_test.go);
// the two-instance golden inputs live in multicarrier_test.go (no build tag)
// so they are always available when this file is compiled in.
package xray

import (
	"os"
	"path/filepath"
	"testing"
)

// TestE2EMultiCarrierRender writes the two Phase 2 two-carrier configs into
// testdata/e2e/ and prints the marker lines for the `xray run -test` gate.
func TestE2EMultiCarrierRender(t *testing.T) {
	dir := filepath.Join("testdata", "e2e")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir e2e dir: %v", err)
	}

	germany := multiGoldenGermanyParams()
	gb, err := RenderGermanyMultiConfig(germany)
	if err != nil {
		t.Fatalf("render germany multi: %v", err)
	}
	gabs, err := filepath.Abs(filepath.Join(dir, "germany-multicarrier-e2e.json"))
	if err != nil {
		t.Fatalf("abs path (germany): %v", err)
	}
	if err := os.WriteFile(gabs, gb, 0o600); err != nil {
		t.Fatalf("write germany multi config: %v", err)
	}
	t.Logf("MULTI_E2E_GERMANY_CONFIG_PATH=%s", gabs)

	consumer := multiGoldenConsumerParams()
	cb, err := RenderConsumerMultiConfig(consumer)
	if err != nil {
		t.Fatalf("render consumer multi: %v", err)
	}
	cabs, err := filepath.Abs(filepath.Join(dir, "consumer-multicarrier-e2e.json"))
	if err != nil {
		t.Fatalf("abs path (consumer): %v", err)
	}
	if err := os.WriteFile(cabs, cb, 0o600); err != nil {
		t.Fatalf("write consumer multi config: %v", err)
	}
	t.Logf("MULTI_E2E_CONSUMER_CONFIG_PATH=%s", cabs)
}
