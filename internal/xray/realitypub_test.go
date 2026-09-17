package xray

// realitypub_test.go — hermetic L1 tests for the Germany installed-config
// read-back used by `splitterctl pair apply` to emit the return blob (Blob B).
// Everything runs on files written into t.TempDir(); no binary, no network,
// and every key below is the documented fixed NON-PRODUCTION test vector.

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testUUID = "123e4567-e89b-42d3-a456-426614174000"

const fixedPrivRawURL = "gAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHkA" // = base64.RawURLEncoding(fixedPriv)

// realityInboundJSON builds a config with exactly `count` Reality vless
// inbounds sharing the same (first) parameters, with the private key field
// verbatim so malformed-key cases are expressible.
func realityInboundJSON(count int, port int, uuid, sni, shortID, priv string) string {
	one := fmt.Sprintf(`{"tag":"split-down","listen":"0.0.0.0","port":%d,"protocol":"vless",`+
		`"settings":{"clients":[{"id":%q}],"decryption":"none"},`+
		`"streamSettings":{"network":"tcp","security":"reality",`+
		`"realitySettings":{"dest":%q,"serverNames":[%q],"privateKey":%q,"shortIds":[%q]}}}`,
		port, uuid, sni+":443", sni, priv, shortID)
	inbounds := one
	for i := 1; i < count; i++ {
		inbounds += "," + one
	}
	return `{"log":{"loglevel":"warning","error":"/dev/null"},"inbounds":[` + inbounds + `],"outbounds":[],"routing":{"rules":[]}}`
}

func writeConfigFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadInstalledRealityParamsGolden(t *testing.T) {
	got, err := ReadInstalledRealityParams(filepath.Join("testdata", "golden", "germany-config.golden.json"))
	if err != nil {
		t.Fatalf("golden config must parse: %v", err)
	}
	if got.SNI != "www.lovelive123.com" || got.ShortID != "0123456789abcdef" || got.UUID != testUUID || got.Port != 443 {
		t.Fatalf("params mismatch: %+v", got)
	}
	// The returned public key must equal the X25519 derivation of the
	// config's private key, re-encoded base64.RawURLEncoding (the Xray and
	// pairing Blob B format) — independently re-derived here via crypto/ecdh.
	priv, err := base64.RawURLEncoding.DecodeString(fixedPrivRawURL)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	if got.RealityPublicKey != want {
		t.Fatal("derived public key mismatch")
	}
	// Hygiene: the private material (either alphabet) must not appear inside
	// the public key string the reader hands to the blob.
	stdPriv := base64.StdEncoding.EncodeToString(priv)
	if len(got.RealityPublicKey) != 43 || strings.ContainsAny(got.RealityPublicKey, "=+/") {
		t.Fatal("derived public key is not canonical RawURL")
	}
	if strings.Contains(got.RealityPublicKey, fixedPrivRawURL[:16]) ||
		strings.Contains(got.RealityPublicKey, stdPriv[:16]) {
		t.Fatal("private material leaked into derived public key")
	}
}

func TestReadInstalledRealityParamsRoundTripAndDeterminism(t *testing.T) {
	// Render a real Germany config through the real generator, then read it
	// back; repeated reads must be byte-identical (Blob B re-emission
	// determinism depends on it).
	params := RealityParams{SNI: "www.lovelive123.com", ShortID: "0123456789abcdef", UUID: testUUID}
	kp := &Keypair{PrivateRaw: fixedPrivRawURL, PublicRaw: rawURL(fixedPub), Hash32Raw: rawURL(fixedH32)}
	out, err := RenderGermanyConfig(params, kp)
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, "xray-germany.json", string(out))
	first, err := ReadInstalledRealityParams(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReadInstalledRealityParams(path)
	if err != nil || *second != *first {
		t.Fatalf("re-read mismatch: %+v vs %+v (%v)", *second, *first, err)
	}
	if b, err := base64.RawURLEncoding.DecodeString(first.RealityPublicKey); err != nil || len(b) != 32 {
		t.Fatalf("public key shape: %v, len=%d", err, len(b))
	}
}

func TestReadInstalledRealityParamsErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
		want error
	}{
		{"not json", `not-json{`, ErrInstalledConfig},
		{"empty file", ``, ErrInstalledConfig},
		{"no inbounds", `{}`, ErrInstalledConfig},
		{"no reality inbound", `{"inbounds":[{"protocol":"vless","port":443,"settings":{"clients":[{"id":"` + testUUID + `"}]},"streamSettings":{"network":"tcp","security":"tls"}}]}`, ErrInstalledConfig},
		{"two reality inbounds", realityInboundJSON(2, 443, testUUID, "a.com", "0123456789abcdef", fixedPrivRawURL), ErrInstalledConfig},
		{"bad port", realityInboundJSON(1, 70000, testUUID, "a.com", "0123456789abcdef", fixedPrivRawURL), ErrInstalledConfig},
		{"uuid not v4", realityInboundJSON(1, 443, strings.Replace(testUUID, "-4", "-5", 1), "a.com", "0123456789abcdef", fixedPrivRawURL), ErrInstalledConfig},
		{"uppercase sni", realityInboundJSON(1, 443, testUUID, "A.com", "0123456789abcdef", fixedPrivRawURL), ErrInstalledConfig},
		{"bad shortid", realityInboundJSON(1, 443, testUUID, "a.com", "XYZ3456789abcdef", fixedPrivRawURL), ErrInstalledConfig},
		{"missing private key", realityInboundJSON(1, 443, testUUID, "a.com", "0123456789abcdef", ""), ErrInstalledKey},
		{"private key not base64url", realityInboundJSON(1, 443, testUUID, "a.com", "0123456789abcdef", "!-not-base64-!"), ErrInstalledKey},
		{"private key std-encoded", realityInboundJSON(1, 443, testUUID, "a.com", "0123456789abcdef", base64.StdEncoding.EncodeToString(mustPriv())), ErrInstalledKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfigFile(t, strings.ReplaceAll(tc.name, " ", "-")+".json", tc.json)
			_, err := ReadInstalledRealityParams(path)
			if err == nil || !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			// Error hygiene: no key material or config bytes may be echoed.
			for _, forbidden := range []string{fixedPrivRawURL, "gAECAwQ", tc.json} {
				if forbidden != "" && strings.Contains(err.Error(), forbidden) {
					t.Fatalf("error echoed material %q: %v", forbidden, err)
				}
			}
		})
	}
	// Empty path and missing file are read failures (path may be echoed —
	// it is manifest data, never secret material — but not contents).
	if _, err := ReadInstalledRealityParams(""); !errors.Is(err, ErrInstalledConfigRead) {
		t.Fatalf("empty path error = %v, want read failure", err)
	}
	missing := filepath.Join(t.TempDir(), "gone.json")
	if _, err := ReadInstalledRealityParams(missing); !errors.Is(err, ErrInstalledConfigRead) {
		t.Fatalf("missing file error = %v, want read failure", err)
	}
}

func TestReadInstalledRealityParamsRejectsSymlink(t *testing.T) {
	params := RealityParams{SNI: "www.lovelive123.com", ShortID: "0123456789abcdef", UUID: testUUID}
	kp := &Keypair{PrivateRaw: fixedPrivRawURL, PublicRaw: rawURL(fixedPub), Hash32Raw: rawURL(fixedH32)}
	out, err := RenderGermanyConfig(params, kp)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	live := filepath.Join(dir, "xray-germany.json")
	if err := os.WriteFile(live, out, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "evil-link")
	if err := os.Symlink(live, link); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
	if _, err := ReadInstalledRealityParams(link); !errors.Is(err, ErrInstalledConfigRead) {
		t.Fatalf("symlinked config path must be refused, got %v", err)
	}
}

func mustPriv() []byte {
	b, err := base64.RawURLEncoding.DecodeString(fixedPrivRawURL)
	if err != nil {
		panic(err)
	}
	return b
}
