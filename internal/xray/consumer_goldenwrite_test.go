//go:build goldenwrite

package xray

// consumer_goldenwrite_test.go — one-shot golden regeneration for the
// consumer config, EXCLUDED from normal builds (build tag). Regenerate on
// purpose with:
//
//	go test -tags goldenwrite -run TestWriteConsumerGolden ./internal/xray/

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteConsumerGolden(t *testing.T) {
	out, err := RenderConsumerConfig(consumerGoldenParams())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	dst := filepath.Join("testdata", "golden", "consumer-config.golden.json")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		t.Fatalf("write golden: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", dst, len(out))
}
