package xray

// realityconfig_test.go — golden + validation matrix for the Germany Xray
// config generator (design doc plans/t3-design.md §5). Hermetic: no
// network, no real binary, fixed non-production test vectors.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenParams is the single documented test-only input that pins the
// committed golden file.
func goldenParams() RealityParams {
	return RealityParams{
		SNI:     "www.lovelive123.com",
		ShortID: "0123456789abcdef",
		UUID:    "123e4567-e89b-42d3-a456-426614174000",
	}
}

// goldenKeypair is the matching fixed (non-production) key vector — the
// SAME bytes keygen_test.go uses, clamped as the pinned binary produces.
func goldenKeypair() *Keypair {
	return &Keypair{
		PrivateRaw: rawURL(fixedPriv),
		PublicRaw:  rawURL(fixedPub),
		Hash32Raw:  rawURL(fixedH32),
		PrivateStd: base64.StdEncoding.EncodeToString(fixedPriv),
		PublicStd:  base64.StdEncoding.EncodeToString(fixedPub),
	}
}

func renderGolden(t *testing.T) []byte {
	t.Helper()
	out, err := RenderGermanyConfig(goldenParams(), goldenKeypair())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

// 1. valid input → bytes == golden file; render-twice identical.
func TestGoldenMatchesCommittedFile(t *testing.T) {
	got := renderGolden(t)
	want, err := os.ReadFile(filepath.Join("testdata", "golden", "germany-config.golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("rendered config differs from golden\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	// trailing newline, 2-space indent (shape invariants).
	if len(got) == 0 || got[len(got)-1] != '\n' {
		t.Error("golden does not end with a trailing newline")
	}
	if !strings.Contains(string(got), "\n  \"log\"") {
		t.Error("golden does not use 2-space indentation")
	}
}

// 12. determinism: 100 renders → 1 distinct byte string.
func TestRenderIsDeterministic(t *testing.T) {
	var first [sha256.Size]byte
	for i := 0; i < 100; i++ {
		out := renderGolden(t)
		sum := sha256.Sum256(out)
		if i == 0 {
			first = sum
		} else if sum != first {
			t.Fatalf("render %d produced different bytes (determinism broken)", i)
		}
	}
}

// 2–5. every invalid input is rejected, names its field, and never
// panics. The table also asserts (11) that no error string carries the
// private key material.
func TestInvalidInputsRejected(t *testing.T) {
	valid := goldenParams()
	kp := goldenKeypair()
	privBytes := rawURL(fixedPriv)

	cases := []struct {
		name    string
		params  RealityParams
		kp      *Keypair
		wantSub string // fragment that MUST appear in the error (field name)
	}{
		// --- SNI ---
		{"sni empty", RealityParams{SNI: "", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni uppercase", RealityParams{SNI: "WWW.Lovelive123.com", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni trailing dot", RealityParams{SNI: "www.lovelive123.com.", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni ip literal", RealityParams{SNI: "203.0.113.10", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni label leading hyphen", RealityParams{SNI: "www.-lovelive123.com", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni label trailing hyphen", RealityParams{SNI: "www.lovelive123-.com", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni with port", RealityParams{SNI: "www.lovelive123.com:443", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni scheme", RealityParams{SNI: "https://www.lovelive123.com", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni single label", RealityParams{SNI: "lovelive123", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni underscore", RealityParams{SNI: "www_lovelive123.com", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni whitespace", RealityParams{SNI: "www.lo velive123.com", ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni quote (json escape hazard)", RealityParams{SNI: `www."evil.com`, ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		{"sni too long", RealityParams{SNI: strings.Repeat("a", 100) + "." + strings.Repeat("b", 154), ShortID: valid.ShortID, UUID: valid.UUID}, kp, "sni"},
		// --- shortId ---
		{"shortid empty", RealityParams{SNI: valid.SNI, ShortID: "", UUID: valid.UUID}, kp, "shortId"},
		{"shortid 15 hex", RealityParams{SNI: valid.SNI, ShortID: "0123456789abcde", UUID: valid.UUID}, kp, "shortId"},
		{"shortid 17 hex", RealityParams{SNI: valid.SNI, ShortID: "0123456789abcdef0", UUID: valid.UUID}, kp, "shortId"},
		{"shortid uppercase", RealityParams{SNI: valid.SNI, ShortID: "0123456789ABCDEF", UUID: valid.UUID}, kp, "shortId"},
		{"shortid bad char", RealityParams{SNI: valid.SNI, ShortID: "0123456789abcdeg", UUID: valid.UUID}, kp, "shortId"},
		// --- uuid ---
		{"uuid empty", RealityParams{SNI: valid.SNI, ShortID: valid.ShortID, UUID: ""}, kp, "uuid"},
		{"uuid version 1", RealityParams{SNI: valid.SNI, ShortID: valid.ShortID, UUID: "123e4567-e89b-12d3-a456-426614174000"}, kp, "uuid"},
		{"uuid uppercase", RealityParams{SNI: valid.SNI, ShortID: valid.ShortID, UUID: "123E4567-E89B-42D3-A456-426614174000"}, kp, "uuid"},
		{"uuid 35 chars", RealityParams{SNI: valid.SNI, ShortID: valid.ShortID, UUID: "123e4567-e89b-42d3-a456-4266141740001"}, kp, "uuid"},
		{"uuid non-hex", RealityParams{SNI: valid.SNI, ShortID: valid.ShortID, UUID: "123e4567-e89b-42d3-a456-42661417400g"}, kp, "uuid"},
		// --- key material ---
		{"keypair nil", valid, nil, ErrMissingKeypair.Error()},
		{"keypair zero value", valid, &Keypair{}, ErrMissingKeypair.Error()},
		{"private key non-b64", valid, &Keypair{PrivateRaw: "!!!not-base64!!!", PublicRaw: kp.PublicRaw}, "privateKey"},
		{"private key 31 bytes", valid, &Keypair{PrivateRaw: rawURL(make([]byte, 31)), PublicRaw: kp.PublicRaw}, "privateKey"},
		{"private key 33 bytes", valid, &Keypair{PrivateRaw: rawURL(make([]byte, 33)), PublicRaw: kp.PublicRaw}, "privateKey"},
		{"public key std-encoded (padded)", valid, &Keypair{PrivateRaw: kp.PrivateRaw, PublicRaw: base64.StdEncoding.EncodeToString(fixedPub)}, "publicKey"},
		{"public key 31 bytes", valid, &Keypair{PrivateRaw: kp.PrivateRaw, PublicRaw: rawURL(make([]byte, 31))}, "publicKey"},
	}
	for _, c := range cases {
		_, err := RenderGermanyConfig(c.params, c.kp)
		if err == nil {
			t.Errorf("%s: expected rejection, got success", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantSub) {
			t.Errorf("%s: error does not name the offending field: %v", c.name, err)
		}
		if strings.Contains(err.Error(), privBytes) {
			t.Errorf("%s: error leaks private key material: %v", c.name, err)
		}
	}

	// Missing-input rejection must be the field-named sentinel.
	if _, err := RenderGermanyConfig(RealityParams{SNI: "", ShortID: valid.ShortID, UUID: valid.UUID}, kp); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("missing SNI: want ErrInvalidParams, got %v", err)
	}
	if _, err := RenderGermanyConfig(valid, nil); !errors.Is(err, ErrMissingKeypair) {
		t.Errorf("nil keypair: want ErrMissingKeypair, got %v", err)
	}
}

// 6. valid params + valid keypair accept a hand-built keypair even when the
// parser was not involved (the renderer only re-checks the encoding
// contract; crypto shape was keygen's job).
func TestHandBuiltKeypairAccepted(t *testing.T) {
	_, err := RenderGermanyConfig(goldenParams(), goldenKeypair())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// 10. structural exposure audit of the rendered config:
//   - the only public listener is the Reality inbound 0.0.0.0:443;
//   - 9002 and 127.0.0.1 appear ONLY inside the freedom outbound's
//     settings.redirect ("127.0.0.1:9002") — nowhere else in the document;
//   - there is exactly one inbound and one outbound, no extra listeners.
func TestStructuralExposureAudit(t *testing.T) {
	out := renderGolden(t)

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}

	// Collect every port, listen/address, and redirect value in the whole
	// document (the exposure surface), regardless of nesting.
	var walk func(any)
	ports := map[int]int{}        // port value -> occurrences
	listens := map[string]int{}   // listen/address value -> occurrences
	redirects := map[string]int{} // redirect value -> occurrences
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				switch k {
				case "port":
					if n, ok := val.(float64); ok {
						ports[int(n)]++
					}
				case "listen", "address":
					if s, ok := val.(string); ok {
						listens[s]++
					}
				case "redirect":
					if s, ok := val.(string); ok {
						redirects[s]++
					}
				}
				walk(val)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(doc)

	// The only numeric port in the document is 443 (the inbound listener).
	// 9002 must NOT appear as a port field — it exists only inside the
	// redirect string.
	if len(ports) != 1 {
		t.Errorf("expected exactly 1 distinct port field (443), got %v", ports)
	}
	if ports[443] != 1 {
		t.Errorf("port 443 must appear exactly once, got %d", ports[443])
	}

	// The only listen address is 0.0.0.0 (the one public inbound). The
	// loopback address 127.0.0.1 must NOT appear as a listen/address field.
	if len(listens) != 1 {
		t.Errorf("expected exactly 1 listen/address value (0.0.0.0), got %v", listens)
	}
	if listens["0.0.0.0"] != 1 {
		t.Errorf("listen 0.0.0.0 must appear exactly once, got %v", listens)
	}

	// 9002 and 127.0.0.1 live ONLY in the freedom outbound redirect,
	// exactly once each, bound to the fixed splitter endpoint.
	if len(redirects) != 1 {
		t.Fatalf("expected exactly 1 redirect value, got %v", redirects)
	}
	if redirects["127.0.0.1:9002"] != 1 {
		t.Errorf("redirect must be exactly 127.0.0.1:9002, got %v", redirects)
	}

	// Exactly one inbound (split-down) and one outbound (to-splitter).
	ibs, _ := doc["inbounds"].([]any)
	obs, _ := doc["outbounds"].([]any)
	if len(ibs) != 1 {
		t.Fatalf("expected exactly 1 inbound, got %d", len(ibs))
	}
	if len(obs) != 1 {
		t.Fatalf("expected exactly 1 outbound, got %d", len(obs))
	}
	ib, _ := ibs[0].(map[string]any)
	ob, _ := obs[0].(map[string]any)
	if ib["tag"] != "split-down" {
		t.Errorf("inbound tag = %v, want split-down", ib["tag"])
	}
	if ob["tag"] != "to-splitter" {
		t.Errorf("outbound tag = %v, want to-splitter", ob["tag"])
	}
	if ob["protocol"] != "freedom" {
		t.Errorf("outbound protocol = %v, want freedom", ob["protocol"])
	}

	// The routing rule must bind split-down -> to-splitter.
	rt, ok := doc["routing"].(map[string]any)
	if !ok {
		t.Fatal("routing section missing")
	}
	rules, _ := rt["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("expected exactly 1 routing rule, got %d", len(rules))
	}
	r, _ := rules[0].(map[string]any)
	inboundTag, _ := r["inboundTag"].([]any)
	if len(inboundTag) != 1 || inboundTag[0] != "split-down" {
		t.Errorf("routing rule inboundTag = %v, want [split-down]", r["inboundTag"])
	}
	if r["outboundTag"] != "to-splitter" {
		t.Errorf("routing rule outboundTag = %v, want to-splitter", r["outboundTag"])
	}
}

// 12b. the private key bytes DO appear in the rendered config (by design —
// doc §4.4 embeds it in the 0600 config) — this pins that the renderer
// actually wrote the REALITY-PRIVATE placeholder, not something else.
func TestConfigEmbedsPrivateKey(t *testing.T) {
	out := renderGolden(t)
	if !strings.Contains(string(out), rawURL(fixedPriv)) {
		t.Error("rendered config does not contain the Reality private key")
	}
	// and the public key must NOT appear in the config (only the private
	// key is server-side material).
	if strings.Contains(string(out), rawURL(fixedPub)) {
		t.Error("rendered config must not contain the public key")
	}
}
