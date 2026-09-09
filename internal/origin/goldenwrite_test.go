//go:build goldenwrite

package origin

// goldenwrite_test.go — one-shot golden regeneration, EXCLUDED from
// normal builds (build tag). Regenerate the committed goldens on
// purpose (e.g. after a reviewed shape change) with:
//
//	go test -tags goldenwrite -run TestWriteGoldens ./internal/origin/
//
// The committed goldens pin the exact bytes; the pinned-binary gate
// (caddy validate --config) is the authority that those bytes load.
//
// IMPORTANT: the golden bytes were cross-verified against the pinned
// caddy v2.11.4 binary (validate + adapt, design §2.3 / T4-C1).
// Regenerating after a version pin change requires re-verifying.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteGoldens(t *testing.T) {
	cases := []struct {
		name string
		plan Plan
	}{
		{"caddy-default.golden.Caddyfile", goldenPlanCaddy()},
		{"caddy-alpn01.golden.Caddyfile", goldenPlanALPN()},
		{"cdn-tls-internal.golden.Caddyfile", goldenPlanCDN()},
	}
	for _, c := range cases {
		out, err := RenderCaddyfile(c.plan)
		if err != nil {
			t.Fatalf("render %s: %v", c.name, err)
		}
		dst := filepath.Join("testdata", "golden", c.name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(dst, out, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d bytes)", dst, len(out))
	}
}
