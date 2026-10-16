//go:build goldenwrite

package xray

// multicarrier_goldenwrite_test.go — one-shot golden regeneration for the
// Phase 2 two-carrier configs, EXCLUDED from normal builds (build tag).
// Regenerate on purpose with:
//
//	go test -tags goldenwrite -run 'TestWriteMultiCarrierGoldens' ./internal/xray/

import (
	"os"
	"path/filepath"
	"testing"
)

// The two-instance golden inputs live in multicarrier_test.go (no build
// tag) so the normal test build can pin the committed goldens; this
// one-shot writer reuses them when built with -tags goldenwrite.
func TestWriteMultiCarrierGoldens(t *testing.T) {
	germany := multiGoldenGermanyParams()
	out, err := RenderGermanyMultiConfig(germany)
	if err != nil {
		t.Fatalf("render germany multi: %v", err)
	}
	dst := filepath.Join("testdata", "golden", "germany-config-multicarrier.golden.json")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		t.Fatalf("write golden: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", dst, len(out))

	consumer := multiGoldenConsumerParams()
	cout, err := RenderConsumerMultiConfig(consumer)
	if err != nil {
		t.Fatalf("render consumer multi: %v", err)
	}
	cdst := filepath.Join("testdata", "golden", "consumer-config-multicarrier.golden.json")
	if err := os.WriteFile(cdst, cout, 0o644); err != nil {
		t.Fatalf("write golden: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", cdst, len(cout))
}
