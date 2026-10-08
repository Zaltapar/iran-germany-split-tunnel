package xray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// consumerGoldenParams is the fixed test-only input for the consumer golden.
func consumerGoldenParams() ConsumerParams {
	return ConsumerParams{
		PublicKey:  rawURL(fixedPub),
		SNI:        "www.lovelive123.com",
		ShortID:    "0123456789abcdef",
		UUID:       "123e4567-e89b-42d3-a456-426614174000",
		DownHost:   "91.107.152.1",
		DownPort:   443,
		ListenAddr: "127.0.0.1",
		ListenPort: 10802,
	}
}

func TestRenderConsumerGolden(t *testing.T) {
	got, err := RenderConsumerConfig(consumerGoldenParams())
	if err != nil {
		t.Fatalf("RenderConsumerConfig: %v", err)
	}
	// Renderer contract: LF only, single trailing newline.
	if strings.Contains(string(got), "\r") {
		t.Fatalf("renderer emitted CR bytes")
	}
	if !strings.HasSuffix(string(got), "\n") || strings.HasSuffix(string(got), "\n\n") {
		t.Fatalf("renderer output must end with exactly one newline")
	}

	goldenPath := filepath.Join("testdata", "golden", "consumer-config.golden.json")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v", goldenPath, err)
	}
	want = []byte(strings.ReplaceAll(string(want), "\r\n", "\n"))
	if string(got) != string(want) {
		t.Fatalf("consumer config bytes differ from golden:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderConsumerDeterministic(t *testing.T) {
	params := consumerGoldenParams()
	first, err := RenderConsumerConfig(params)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for i := 0; i < 50; i++ {
		got, err := RenderConsumerConfig(params)
		if err != nil {
			t.Fatalf("render %d: %v", i, err)
		}
		if string(got) != string(first) {
			t.Fatalf("render %d diverged", i)
		}
	}
}

func TestRenderConsumerValidation(t *testing.T) {
	cases := map[string]ConsumerParams{
		"bad sni":      {PublicKey: rawURL(fixedPub), SNI: "UPPER.COM", ShortID: "0123456789abcdef", UUID: "123e4567-e89b-42d3-a456-426614174000", DownHost: "9.9.9.9", DownPort: 443, ListenAddr: "127.0.0.1", ListenPort: 10802},
		"bad shortId":  {PublicKey: rawURL(fixedPub), SNI: "www.example.com", ShortID: "XYZ", UUID: "123e4567-e89b-42d3-a456-426614174000", DownHost: "9.9.9.9", DownPort: 443, ListenAddr: "127.0.0.1", ListenPort: 10802},
		"bad uuid":     {PublicKey: rawURL(fixedPub), SNI: "www.example.com", ShortID: "0123456789abcdef", UUID: "not-a-uuid", DownHost: "9.9.9.9", DownPort: 443, ListenAddr: "127.0.0.1", ListenPort: 10802},
		"empty pub":    {PublicKey: "", SNI: "www.example.com", ShortID: "0123456789abcdef", UUID: "123e4567-e89b-42d3-a456-426614174000", DownHost: "9.9.9.9", DownPort: 443, ListenAddr: "127.0.0.1", ListenPort: 10802},
		"bad port":     {PublicKey: rawURL(fixedPub), SNI: "www.example.com", ShortID: "0123456789abcdef", UUID: "123e4567-e89b-42d3-a456-426614174000", DownHost: "9.9.9.9", DownPort: 99999, ListenAddr: "127.0.0.1", ListenPort: 10802},
		"empty listen": {PublicKey: rawURL(fixedPub), SNI: "www.example.com", ShortID: "0123456789abcdef", UUID: "123e4567-e89b-42d3-a456-426614174000", DownHost: "9.9.9.9", DownPort: 443, ListenAddr: "", ListenPort: 10802},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := RenderConsumerConfig(p); err == nil {
				t.Fatalf("expected error for %q", name)
			}
		})
	}
}

// Ensure no secret material (32-hex runs) appears in the consumer config.
func TestConsumerConfigContainsNoSecret(t *testing.T) {
	got, err := RenderConsumerConfig(consumerGoldenParams())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// A 32-hex run would indicate secret leakage.
	s := string(got)
	for i := 0; i+32 <= len(s); i++ {
		if hexRun32(s, i) {
			t.Fatalf("consumer config contains a 32-hex run at %d (secret leakage?)", i)
		}
	}
}

// hexRun32 reports whether s[i:i+32] is all hex digits.
func hexRun32(s string, i int) bool {
	for j := i; j < i+32; j++ {
		c := s[j]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
