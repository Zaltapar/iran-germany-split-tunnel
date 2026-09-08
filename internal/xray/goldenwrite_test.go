//go:build goldenwrite

package xray

// goldenwrite_test.go — one-shot golden regeneration, EXCLUDED from normal
// builds (build tag). Regenerate the golden file on purpose (e.g. after a
// reviewed shape change) with:
//
//	go test -tags goldenwrite -run TestWriteGolden ./internal/xray/
//
// The committed golden pins the exact bytes; CI's pinned-binary gate
// (xray run -test) is the authority that those bytes load.

import (
	"os"
	"path/filepath"
	"testing"
)

// goldenParams and the fixed key vectors (keygen_test.go) are the single
// documented test-only input for the golden file.
func TestWriteGolden(t *testing.T) {
	params := RealityParams{
		SNI:     "www.lovelive123.com",
		ShortID: "0123456789abcdef",
		UUID:    "123e4567-e89b-42d3-a456-426614174000",
	}
	kp := &Keypair{
		PrivateRaw: rawURL(fixedPriv),
		PublicRaw:  rawURL(fixedPub),
		Hash32Raw:  rawURL(fixedH32),
	}
	out, err := RenderGermanyConfig(params, kp)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	dst := filepath.Join("testdata", "golden", "germany-config.golden.json")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		t.Fatalf("write golden: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", dst, len(out))
}
