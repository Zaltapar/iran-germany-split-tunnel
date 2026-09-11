//go:build goldenwrite

package systemd

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteGolden regenerates the committed unit goldens intentionally.
// Run only when the renderer contract changes:
// go test -tags goldenwrite -run TestWriteGolden ./internal/systemd/
func TestWriteGolden(t *testing.T) {
	for name, spec := range goldenSpecs() {
		data, err := RenderUnit(spec)
		if err != nil {
			t.Fatalf("%s: render: %v", name, err)
		}
		path := filepath.Join("testdata", "golden", name+".golden.service")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
	}
}
