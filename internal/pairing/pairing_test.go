package pairing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// makeSecret returns a policy-valid 64-hex secret (deterministic for
// fixtures; the policy requires length + non-weak).
func makeSecret() string {
	return "9f2c1ab34d5e6f708192a3b4c5d6e7f80123456789abcdef0123456789abcdef"
}

// fixtureBlobA builds a valid, encoded blob A.
func fixtureBlobA(t *testing.T) (*BlobA, string) {
	t.Helper()
	a, err := NewBlobA(makeSecret(), "upload.example.com")
	if err != nil {
		t.Fatalf("NewBlobA: %v", err)
	}
	s, err := a.Encode()
	if err != nil {
		t.Fatalf("BlobA.Encode: %v", err)
	}
	return a, s
}

// fixtureBlobB builds a valid, encoded blob B with a well-formed
// base64 32-byte "public key" (validated by shape, not crypto — no Xray
// dependency in this package).
func fixtureBlobB(t *testing.T) (*BlobB, string) {
	t.Helper()
	pub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	b, err := NewBlobB(PublicParams{RealityPublicKey: pub, ShortID: "0123456789abcdef", UUID: "123e4567-e89b-42d3-a456-426614174000", SNI: "www.lovelive123.com"}, DownTarget{Host: "203.0.113.10", Port: 443})
	if err != nil {
		t.Fatalf("NewBlobB: %v", err)
	}
	s, err := b.Encode()
	if err != nil {
		t.Fatalf("BlobB.Encode: %v", err)
	}
	return b, s
}

// withPayload rebuilds the wire form around an arbitrary payload.
func withPayload(t *testing.T, payload []byte) string {
	t.Helper()
	sum := sha256.Sum256(payload)
	return BlobFormat + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Valid pairing (round trips)
// ---------------------------------------------------------------------------

func TestBlobARoundTrip(t *testing.T) {
	_, wire := fixtureBlobA(t)
	got, err := ParseBlobA(wire)
	if err != nil {
		t.Fatalf("ParseBlobA: %v", err)
	}
	if got.Secret != makeSecret() {
		t.Error("secret mismatch after round trip")
	}
	if got.UploadDomain != "upload.example.com" {
		t.Errorf("uploadDomain = %q", got.UploadDomain)
	}
	if got.V != Version {
		t.Errorf("version = %d", got.V)
	}
}

func TestBlobBRoundTrip(t *testing.T) {
	_, wire := fixtureBlobB(t)
	got, err := ParseBlobB(wire)
	if err != nil {
		t.Fatalf("ParseBlobB: %v", err)
	}
	if got.Public.UUID != "123e4567-e89b-42d3-a456-426614174000" ||
		got.Public.ShortID != "0123456789abcdef" ||
		got.Public.SNI != "www.lovelive123.com" ||
		got.Germany.Host != "203.0.113.10" || got.Germany.Port != 443 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	_, w1 := fixtureBlobA(t)
	_, w2 := fixtureBlobA(t)
	if w1 != w2 {
		t.Error("encoding is not deterministic")
	}
}

// ---------------------------------------------------------------------------
// Invalid pairing
// ---------------------------------------------------------------------------

func TestParseEmpty(t *testing.T) {
	if _, err := ParseBlobA(""); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty: got %v, want ErrEmpty", err)
	}
	if _, err := ParseBlobB(""); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty: got %v, want ErrEmpty", err)
	}
}

func TestParseGarbage(t *testing.T) {
	for _, s := range []string{
		"garbage",
		"splat-v1",
		"splat-v1.onlyonepart",
		"splat-v1.a.b.c",
		"splat-v2.abc.def",    // wrong format prefix
		"splat-v1.!!!bad.@@@", // not base64url
		"splat-v1.aa.aa",      // short "checksum"
		"  splat-v1.aa.aa",    // surrounding whitespace
		"splat-v1.aa.aa  ",
	} {
		if _, err := ParseBlobA(s); err == nil {
			t.Errorf("ParseBlobA(%q): expected error, got nil", s)
		}
	}
}

func TestChecksumMismatch(t *testing.T) {
	// A valid wire form whose digest is replaced: must fail checksum.
	_, wire := fixtureBlobA(t)
	parts := strings.Split(wire, ".")
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := ParseBlobA(tampered); !errors.Is(err, ErrChecksum) {
		t.Errorf("tampered: got %v, want ErrChecksum", err)
	}
}

func TestTruncatedBlob(t *testing.T) {
	_, wire := fixtureBlobA(t)
	step := len(wire) / 7
	if step < 1 {
		step = 1
	}
	for i := 1; i < len(wire); i += step {
		if _, err := ParseBlobA(wire[:i]); err == nil {
			t.Errorf("truncated at %d: expected error", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Wrong version
// ---------------------------------------------------------------------------

func TestWrongVersion(t *testing.T) {
	v2 := struct {
		V    int    `json:"v"`
		Role string `json:"role"`
	}{V: 2, Role: roleA}
	b, err := json.Marshal(v2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBlobA(withPayload(t, b)); !errors.Is(err, ErrVersion) {
		t.Errorf("wrong version: got %v, want ErrVersion", err)
	}
}

// ---------------------------------------------------------------------------
// Role mismatch
// ---------------------------------------------------------------------------

func TestRoleMismatch(t *testing.T) {
	_, aWire := fixtureBlobA(t)
	if _, err := ParseBlobB(aWire); !errors.Is(err, ErrWrongRole) {
		t.Errorf("A as B: got %v, want ErrWrongRole", err)
	}
	_, bWire := fixtureBlobB(t)
	if _, err := ParseBlobA(bWire); !errors.Is(err, ErrWrongRole) {
		t.Errorf("B as A: got %v, want ErrWrongRole", err)
	}
}

// ---------------------------------------------------------------------------
// Malformed / invalid fields (validated, fail closed)
// ---------------------------------------------------------------------------

func TestBlobAInvalidFields(t *testing.T) {
	cases := map[string]struct{ secret, domain string }{
		"weak secret":       {"password", "upload.example.com"},
		"short secret":      {"tooshort", "upload.example.com"},
		"empty secret":      {"", "upload.example.com"},
		"placeholder":       {"CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING", "upload.example.com"},
		"domain bare label": {makeSecret(), "upload"},
		"domain with port":  {makeSecret(), "upload.example.com:443"},
		"domain whitespace": {makeSecret(), "up load.example.com"},
		"domain scheme":     {makeSecret(), "http://upload.example.com"},
		"domain underscore": {makeSecret(), "upload_ex.example.com"},
		"empty domain":      {makeSecret(), ""},
	}
	for name, c := range cases {
		if _, err := NewBlobA(c.secret, c.domain); err == nil {
			t.Errorf("NewBlobA(%s): expected validation error", name)
		}
	}
}

func TestBlobBInvalidFields(t *testing.T) {
	valid := func() PublicParams {
		return PublicParams{RealityPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), ShortID: "0123456789abcdef", UUID: "123e4567-e89b-42d3-a456-426614174000", SNI: "www.lovelive123.com"}
	}
	cases := map[string]func(*PublicParams){
		"pubkey 31 bytes":     func(p *PublicParams) { p.RealityPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 31)) },
		"pubkey 33 bytes":     func(p *PublicParams) { p.RealityPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 33)) },
		"pubkey not b64":      func(p *PublicParams) { p.RealityPublicKey = "not-base64!!!" },
		"pubkey empty":        func(p *PublicParams) { p.RealityPublicKey = "" },
		"shortid 15 hex":      func(p *PublicParams) { p.ShortID = "0123456789abcde" },
		"shortid upper":       func(p *PublicParams) { p.ShortID = "0123456789ABCDEF" },
		"shortid bad char":    func(p *PublicParams) { p.ShortID = "0123456789abcdeg" },
		"uuid wrong ver":      func(p *PublicParams) { p.UUID = "123e4567-e89b-12d3-a456-426614174000" },
		"uuid upper":          func(p *PublicParams) { p.UUID = "123E4567-E89B-42D3-A456-426614174000" },
		"uuid short":          func(p *PublicParams) { p.UUID = "123e4567-e89b-42d3" },
		"sni empty":           func(p *PublicParams) { p.SNI = "" },
		"sni uppercase":       func(p *PublicParams) { p.SNI = "WWW.Lovelive123.com" },
		"sni ip literal":      func(p *PublicParams) { p.SNI = "203.0.113.10" },
		"sni with port":       func(p *PublicParams) { p.SNI = "www.lovelive123.com:443" },
		"sni single label":    func(p *PublicParams) { p.SNI = "lovelive123" },
		"sni scheme":          func(p *PublicParams) { p.SNI = "https://www.lovelive123.com" },
		"sni underscore":      func(p *PublicParams) { p.SNI = "www_lovelive123.com" },
		"sni whitespace":      func(p *PublicParams) { p.SNI = "www.lo velive123.com" },
		"sni leading hyphen":  func(p *PublicParams) { p.SNI = "www.-lovelive123.com" },
		"sni trailing hyphen": func(p *PublicParams) { p.SNI = "www.lovelive123-.com" },
		"sni too long":        func(p *PublicParams) { p.SNI = strings.Repeat("a", 100) + "." + strings.Repeat("b", 154) },
	}
	for name, mutate := range cases {
		p := valid()
		mutate(&p)
		if _, err := NewBlobB(p, DownTarget{Host: "203.0.113.10", Port: 443}); err == nil {
			t.Errorf("NewBlobB(%s): expected validation error", name)
		}
	}
	badTargets := []struct {
		name string
		g    DownTarget
	}{
		{"port in host", DownTarget{Host: "203.0.113.10:443", Port: 443}},
		{"port 0", DownTarget{Host: "203.0.113.10", Port: 0}},
		{"port 70000", DownTarget{Host: "203.0.113.10", Port: 70000}},
		{"whitespace host", DownTarget{Host: "ger many", Port: 443}},
		{"single label", DownTarget{Host: "germany", Port: 443}},
	}
	for _, c := range badTargets {
		if _, err := NewBlobB(valid(), c.g); err == nil {
			t.Errorf("NewBlobB target %s (%+v): expected validation error", c.name, c.g)
		}
	}
}

// Unknown fields are rejected (fail closed; a privateKey smuggled into
// blob B must be impossible).
func TestUnknownFieldRejected(t *testing.T) {
	payloadA := `{"v":1,"role":"a","secret":"` + makeSecret() + `","uploadDomain":"upload.example.com","evil":"x"}`
	if _, err := ParseBlobA(withPayload(t, []byte(payloadA))); err == nil {
		t.Error("unknown field accepted in blob A")
	}
	payloadB := `{"v":1,"role":"b","public":{"realityPublicKey":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `","shortId":"0123456789abcdef","uuid":"123e4567-e89b-42d3-a456-426614174000","sni":"www.lovelive123.com"},"germany":{"host":"203.0.113.10","port":443},"privateKey":"MUST-REJECT"}`
	if _, err := ParseBlobB(withPayload(t, []byte(payloadB))); err == nil {
		t.Error("unknown field (privateKey) accepted in blob B — key material boundary broken")
	}
}

// A type-mismatched payload (e.g. a number where a string is expected)
// must be rejected AND the error must not echo the offending VALUE — Go's
// json errors embed value fragments.
func TestTypeMismatchDoesNotLeakValue(t *testing.T) {
	leaky := "SUPERSECRETMARKER9f2c"
	payloadA := `{"v":1,"role":"a","secret":{"k":"` + leaky + `"},"uploadDomain":"upload.example.com"}`
	_, err := ParseBlobA(withPayload(t, []byte(payloadA)))
	if err == nil {
		t.Fatal("expected error for type-mismatched payload")
	}
	if strings.Contains(err.Error(), leaky) {
		t.Errorf("error leaks payload value: %v", err)
	}
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("want ErrMalformed, got %v", err)
	}

	// Numeric overflow into an int field is the path where Go's json error
	// text embeds the offending value verbatim; it must be sanitized too.
	big := "123456789012345678901234567890"
	payloadB2 := `{"v":1,"role":"b","public":{"realityPublicKey":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `","shortId":"0123456789abcdef","uuid":"123e4567-e89b-42d3-a456-426614174000","sni":"www.lovelive123.com"},"germany":{"host":"203.0.113.10","port":` + big + `}}`
	_, err2 := ParseBlobB(withPayload(t, []byte(payloadB2)))
	if err2 == nil {
		t.Fatal("expected error for overflowing port")
	}
	if strings.Contains(err2.Error(), big) {
		t.Errorf("error leaks overflowing number: %v", err2)
	}
}

// ---------------------------------------------------------------------------
// Repeated pairing (idempotence of the pure exchange)
// ---------------------------------------------------------------------------

func TestRepeatedPairingIsStable(t *testing.T) {
	a, wireA := fixtureBlobA(t)
	for i := 0; i < 3; i++ {
		got, err := ParseBlobA(wireA)
		if err != nil {
			t.Fatalf("repeat %d: %v", i, err)
		}
		if got.Secret != a.Secret || got.UploadDomain != a.UploadDomain {
			t.Errorf("repeat %d: content drifted", i)
		}
		// Re-encoding the parsed value reproduces the same wire form
		// (convergent, no hidden state).
		again, err := got.Encode()
		if err != nil {
			t.Fatalf("repeat %d re-encode: %v", i, err)
		}
		if again != wireA {
			t.Errorf("repeat %d: re-encode differs from original", i)
		}
	}
	// Fresh secret generation is stateless.
	s1, err1 := GenerateTunnelSecret()
	s2, err2 := GenerateTunnelSecret()
	if err1 != nil || err2 != nil {
		t.Fatalf("GenerateTunnelSecret: %v / %v", err1, err2)
	}
	if s1 == s2 {
		t.Error("two generated secrets are identical")
	}
}

// ---------------------------------------------------------------------------
// Secret never appears in output/logging
// ---------------------------------------------------------------------------

func TestSecretNeverInOutputOrLogging(t *testing.T) {
	secret := makeSecret()
	a, _ := fixtureBlobA(t)

	if strings.Contains(a.Summary(), secret) {
		t.Error("BlobA.Summary() leaks the secret")
	}
	if strings.Contains(a.String(), secret) {
		t.Error("BlobA.String() leaks the secret")
	}

	// Error messages must not echo values.
	if _, err := NewBlobA(secret, "up load.example.com"); err != nil && strings.Contains(err.Error(), secret) {
		t.Error("NewBlobA error leaks the secret")
	}
	if _, err := NewBlobA("password", "upload.example.com"); err != nil && strings.Contains(err.Error(), "password") {
		t.Error("NewBlobA error echoes the raw secret value")
	}
	if _, err := ParseBlobA("splat-v1.tampered.aaa"); err != nil && strings.Contains(err.Error(), "tampered") {
		t.Errorf("ParseBlobA error leaks blob content: %v", err)
	}
	_, bWire := fixtureBlobB(t)
	if _, err := ParseBlobA(bWire); err != nil && strings.Contains(err.Error(), bWire) {
		t.Error("ParseBlobA wrong-role error leaks blob content")
	}
}

func TestRedactMasksSecretMaterial(t *testing.T) {
	secret := makeSecret()
	line := "pairing: from 203.0.113.10 secret=" + secret + " done"
	out := Redact(line)
	if strings.Contains(out, secret) {
		t.Errorf("Redact left the secret: %q", out)
	}
	if !strings.Contains(out, "<redacted>") {
		t.Errorf("Redact did not mark: %q", out)
	}
	// Short hex (shortId) is public material — NOT masked.
	shortLine := "shortId=0123456789abcdef"
	if Redact(shortLine) != shortLine {
		t.Error("Redact over-masks public shortIds")
	}
}

// ---------------------------------------------------------------------------
// Generators (key material boundaries)
// ---------------------------------------------------------------------------

func TestGenerateTunnelSecret(t *testing.T) {
	s, err := GenerateTunnelSecret()
	if err != nil {
		t.Fatalf("GenerateTunnelSecret: %v", err)
	}
	if len(s) != 64 {
		t.Errorf("length = %d, want 64 hex chars", len(s))
	}
	if !isHex(s) {
		t.Error("not lowercase hex")
	}
}

func TestGenerateShortID(t *testing.T) {
	s, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	if !shortIDRe.MatchString(s) {
		t.Errorf("shortId %q does not match 16 lowercase hex", s)
	}
}

func TestGenerateUUID(t *testing.T) {
	u, err := GenerateUUID()
	if err != nil {
		t.Fatalf("GenerateUUID: %v", err)
	}
	if !uuidV4Re.MatchString(u) {
		t.Errorf("uuid %q is not a lowercase v4 UUID", u)
	}
	u2, _ := GenerateUUID()
	if u == u2 {
		t.Error("two UUIDs identical")
	}
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
