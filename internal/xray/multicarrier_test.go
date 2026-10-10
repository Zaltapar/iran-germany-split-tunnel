package xray

// multicarrier_test.go — Phase 2 (D1/D3/D4) golden + validation matrix for the
// two-carrier Germany and consumer config renderers. Hermetic: no network, no
// real binary, fixed non-production test vectors.
//
// It also asserts the single-carrier goldens remain byte-identical to the
// committed files: the multi-carrier work adds NEW functions and goldens and
// must not disturb the single-carrier byte stream (gate G2 "single-carrier
// goldens byte-identical").

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// multiGoldenGermanyParams is the fixed test-only two-instance input that pins
// the committed Germany multi-carrier golden.
func multiGoldenGermanyParams() MultiInstanceParams {
	return MultiInstanceParams{
		A: RealityInstance{
			RealityParams: RealityParams{
				SNI:     "www.lovelive123.com",
				ShortID: "0123456789abcdef",
				UUID:    "123e4567-e89b-42d3-a456-426614174000",
			},
			Keypair: goldenKeypair(),
		},
		B: RealityInstance{
			RealityParams: RealityParams{
				SNI:     "www.example-sni-b.com",
				ShortID: "abcdef0123456789",
				UUID:    "9f8e7d6c-5b4a-4321-9876-543210fedcba",
			},
			PubPort:     secondDownPublicPort,
			SplitPort:   secondSplitterPort,
			InboundTag:  tagSplitDownB,
			OutboundTag: tagToSplitterB,
			Keypair:     goldenKeypair(),
		},
	}
}

// multiGoldenConsumerParams is the fixed test-only two-instance input that pins
// the committed consumer multi-carrier golden.
func multiGoldenConsumerParams() ConsumerMultiParams {
	return ConsumerMultiParams{
		A: ConsumerInstance{
			PublicKey:  rawURL(fixedPub),
			SNI:        "www.lovelive123.com",
			ShortID:    "0123456789abcdef",
			UUID:       "123e4567-e89b-42d3-a456-426614174000",
			DownHost:   "91.107.152.1",
			DownPort:   443,
			ListenAddr: "127.0.0.1",
			ListenPort: 10802,
		},
		B: ConsumerInstance{
			PublicKey:   rawURL(fixedPub),
			SNI:         "www.example-sni-b.com",
			ShortID:     "abcdef0123456789",
			UUID:        "9f8e7d6c-5b4a-4321-9876-543210fedcba",
			DownHost:    "91.107.152.1",
			DownPort:    secondDownPublicPort,
			ListenAddr:  "127.0.0.1",
			ListenPort:  10803,
			InboundTag:  "to-germany-b",
			OutboundTag: "reality-germany-b",
		},
	}
}

// TestRenderGermanyMultiGolden pins the two-instance Germany config against
// the committed golden file (byte-identical).
func TestRenderGermanyMultiGolden(t *testing.T) {
	got, err := RenderGermanyMultiConfig(multiGoldenGermanyParams())
	if err != nil {
		t.Fatalf("RenderGermanyMultiConfig: %v", err)
	}
	if strings.Contains(string(got), "\r") {
		t.Fatalf("renderer emitted CR bytes")
	}
	if !strings.HasSuffix(string(got), "\n") || strings.HasSuffix(string(got), "\n\n") {
		t.Fatalf("renderer output must end with exactly one newline")
	}
	want, err := os.ReadFile(filepath.Join("testdata", "golden", "germany-config-multicarrier.golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("rendered multi-carrier config differs from golden:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRenderConsumerMultiGolden pins the two-instance consumer config against
// the committed golden file (byte-identical).
func TestRenderConsumerMultiGolden(t *testing.T) {
	got, err := RenderConsumerMultiConfig(multiGoldenConsumerParams())
	if err != nil {
		t.Fatalf("RenderConsumerMultiConfig: %v", err)
	}
	if strings.Contains(string(got), "\r") {
		t.Fatalf("renderer emitted CR bytes")
	}
	if !strings.HasSuffix(string(got), "\n") || strings.HasSuffix(string(got), "\n\n") {
		t.Fatalf("renderer output must end with exactly one newline")
	}
	want, err := os.ReadFile(filepath.Join("testdata", "golden", "consumer-config-multicarrier.golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("rendered multi-carrier consumer config differs from golden:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestMultiRenderDeterministic: 50 renders of each multi-carrier config are
// byte-identical.
func TestMultiRenderDeterministic(t *testing.T) {
	var gsum [sha256.Size]byte
	var csum [sha256.Size]byte
	for i := 0; i < 50; i++ {
		g, err := RenderGermanyMultiConfig(multiGoldenGermanyParams())
		if err != nil {
			t.Fatalf("render germany multi: %v", err)
		}
		c, err := RenderConsumerMultiConfig(multiGoldenConsumerParams())
		if err != nil {
			t.Fatalf("render consumer multi: %v", err)
		}
		gx, cx := sha256.Sum256(g), sha256.Sum256(c)
		if i == 0 {
			gsum, csum = gx, cx
		} else if gx != gsum || cx != csum {
			t.Fatalf("render %d produced different multi-carrier bytes (determinism broken)", i)
		}
	}
}

// TestMultiConfigShape asserts the two-instance topology the design requires:
// Germany carries two inbounds (443 + 2053) and two freedom redirects
// (9002 + 9003); the consumer carries two dokodemo inbounds (10802 + 10803).
func TestMultiConfigShape(t *testing.T) {
	gb, err := RenderGermanyMultiConfig(multiGoldenGermanyParams())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		`"port": 443`,
		`"port": 2053`,
		`"redirect": "127.0.0.1:9002"`,
		`"redirect": "127.0.0.1:9003"`,
		`"tag": "split-down-b"`,
	} {
		if !strings.Contains(string(gb), want) {
			t.Errorf("Germany multi config missing %s", want)
		}
	}
	cb, err := RenderConsumerMultiConfig(multiGoldenConsumerParams())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		`"port": 10802`,
		`"port": 10803`,
		`"tag": "to-germany-b"`,
		`"tag": "reality-germany-b"`,
	} {
		if !strings.Contains(string(cb), want) {
			t.Errorf("consumer multi config missing %s", want)
		}
	}
}

// TestSingleCarrierGoldenByteIdentical re-renders the single-carrier configs
// and asserts they are byte-identical to the committed single-carrier goldens
// — the Phase 2 multi-carrier change must not alter the single-carrier bytes.
func TestSingleCarrierGoldenByteIdentical(t *testing.T) {
	cases := []struct {
		name   string
		got    []byte
		golden string
		err    error
	}{
		{
			name:   "germany",
			golden: filepath.Join("testdata", "golden", "germany-config.golden.json"),
		},
		{
			name:   "consumer",
			golden: filepath.Join("testdata", "golden", "consumer-config.golden.json"),
		},
	}
	for _, c := range cases {
		if c.name == "germany" {
			out, err := RenderGermanyConfig(goldenParams(), goldenKeypair())
			if err != nil {
				t.Fatalf("%s render: %v", c.name, err)
			}
			c.got = out
		} else {
			out, err := RenderConsumerConfig(consumerGoldenParams())
			if err != nil {
				t.Fatalf("%s render: %v", c.name, err)
			}
			c.got = out
		}
		want, err := os.ReadFile(c.golden)
		if err != nil {
			t.Fatalf("%s read golden: %v", c.name, err)
		}
		want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
		got := bytes.ReplaceAll(c.got, []byte("\r\n"), []byte("\n"))
		if !bytes.Equal(got, want) {
			t.Fatalf("%s single-carrier golden bytes CHANGED (regression):\n--- got ---\n%s\n--- want ---\n%s", c.name, got, want)
		}
	}
}

// TestMultiInstanceValidationMatrix: instance b must differ from instance a
// (SNI + public port), must not use 8443, and both must carry valid keypairs.
func TestMultiInstanceValidationMatrix(t *testing.T) {
	base := multiGoldenGermanyParams()

	// distinct-SNI / distinct-port base is valid.
	if err := ValidateMultiInstanceParams(base); err != nil {
		t.Fatalf("valid base rejected: %v", err)
	}

	// Same SNI as instance a → rejected.
	same := base
	same.B.SNI = base.A.SNI
	if err := ValidateMultiInstanceParams(same); err == nil {
		t.Error("same SNI for instance b: want error, got nil")
	}

	// Public port 8443 (dashboard-reserved) → rejected.
	dash := base
	dash.B.PubPort = 8443
	if err := ValidateMultiInstanceParams(dash); err == nil {
		t.Error("instance b on port 8443: want error, got nil")
	}

	// Same public port as instance a → rejected.
	samePort := base
	// instance a's public port is the topology default (443) because it is
	// omitted; force b onto it.
	samePort.A.PubPort = germanyPort
	samePort.B.PubPort = germanyPort
	if err := ValidateMultiInstanceParams(samePort); err == nil {
		t.Error("instance b sharing instance a's public port: want error, got nil")
	}

	// Missing instance b keypair → rejected.
	noKP := base
	noKP.B.Keypair = nil
	if err := ValidateMultiInstanceParams(noKP); err == nil {
		t.Error("instance b without keypair: want error, got nil")
	}
}

// TestConsumerMultiValidationMatrix: instance b listen port must differ from
// instance a's, and SNI must differ.
func TestConsumerMultiValidationMatrix(t *testing.T) {
	base := multiGoldenConsumerParams()
	if err := ValidateConsumerMultiParams(base); err != nil {
		t.Fatalf("valid base rejected: %v", err)
	}
	samePort := base
	samePort.B.ListenPort = base.A.ListenPort
	if err := ValidateConsumerMultiParams(samePort); err == nil {
		t.Error("consumer instance b sharing instance a's listen port: want error, got nil")
	}
	sameSNI := base
	sameSNI.B.SNI = base.A.SNI
	if err := ValidateConsumerMultiParams(sameSNI); err == nil {
		t.Error("consumer instance b sharing instance a's SNI: want error, got nil")
	}
}
