//go:build goldenwrite

package systemd

// extra_goldenwrite_test.go — one-shot golden regeneration for the extra
// units, EXCLUDED from normal builds (build tag). Regenerate on purpose with:
//
//	go test -tags goldenwrite -run TestWriteExtraUnitGoldens ./internal/systemd/

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteExtraUnitGoldens(t *testing.T) {
	for name, s := range extraGoldenSpecs() {
		out, err := RenderExtraUnit(s)
		if err != nil {
			t.Fatalf("render %s: %v", name, err)
		}
		dst := filepath.Join("testdata", "golden", name+".golden.service")
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(dst), err)
		}
		if err := os.WriteFile(dst, out, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", dst, err)
		}
		t.Logf("wrote %s (%d bytes)", dst, len(out))
	}
}
