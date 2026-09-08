package xray

// keygen_test.go — hermetic tests for the Reality keypair parser.
// No network, no real binary: the fake Executor returns canned
// "xray x25519" output. The fixture keys below are FIXED, documented,
// NON-PRODUCTION test vectors (never used in a deployment).

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fixedTestKeypair is a deterministic, non-production X25519 vector.
// The private key is clamped as the binary would produce it:
// b[0] & 0x07 == 0, b[31] & 0xc0 == 0x40 (X25519 scalar clamp).
var (
	fixedPriv = func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(i) // 0x00..0x1f
		}
		b[0] = 0x80  // clamped: low 3 bits zero
		b[31] = 0x40 // clamped: bit 7 clear, bit 6 set
		return b
	}()
	fixedPub = func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(0xa0 + i)
		}
		return b
	}()
	fixedH32 = func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(0x30 + i)
		}
		return b
	}()
)

func rawURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func x25519Out(priv, pub, h32 string) string {
	return "PrivateKey: " + priv + "\n" +
		"Password (PublicKey): " + pub + "\n" +
		"Hash32: " + h32 + "\n"
}

// keygenFake is an Executor whose Keypair returns canned output.
type keygenFake struct {
	out string
	err error
}

func (keygenFake) VersionOutput(string) (string, error) {
	return "Xray 26.3.27", nil
}
func (keygenFake) RunTest(string, string) (string, error) { return "", nil }
func (f keygenFake) Keypair(string) (string, error)       { return f.out, f.err }

func TestParseX25519OutputValid(t *testing.T) {
	got, err := ParseX25519Output(x25519Out(rawURL(fixedPriv), rawURL(fixedPub), rawURL(fixedH32)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.PrivateRaw != rawURL(fixedPriv) {
		t.Errorf("PrivateRaw mismatch")
	}
	if got.PublicRaw != rawURL(fixedPub) {
		t.Errorf("PublicRaw mismatch")
	}
	if got.Hash32Raw != rawURL(fixedH32) {
		t.Errorf("Hash32Raw mismatch")
	}
	// Std forms are the SAME bytes, StdEncoding (padded) — the format
	// pairing.PublicParams.RealityPublicKey requires.
	if got.PrivateStd != base64.StdEncoding.EncodeToString(fixedPriv) {
		t.Errorf("PrivateStd mismatch")
	}
	if got.PublicStd != base64.StdEncoding.EncodeToString(fixedPub) {
		t.Errorf("PublicStd mismatch")
	}
}

func TestParseX25519OutputCRLF(t *testing.T) {
	out := strings.ReplaceAll(
		x25519Out(rawURL(fixedPriv), rawURL(fixedPub), rawURL(fixedH32)),
		"\n", "\r\n")
	got, err := ParseX25519Output(out)
	if err != nil {
		t.Fatalf("CRLF output must be accepted: %v", err)
	}
	if got.PublicRaw != rawURL(fixedPub) {
		t.Errorf("PublicRaw mismatch under CRLF")
	}
}

func TestParseX25519OutputMalformed(t *testing.T) {
	marker := rawURL(fixedPub) // must never appear in any error

	cases := []struct {
		name string
		out  string
		want error
	}{
		{"empty", "", ErrKeygenFormat},
		{"two lines", "PrivateKey: " + rawURL(fixedPriv) + "\nPassword (PublicKey): " + marker + "\n", ErrKeygenFormat},
		{"four lines", x25519Out(rawURL(fixedPriv), marker, rawURL(fixedH32)) + "extra line\n", ErrKeygenFormat},
		{"wrong prefix", "Private key: " + rawURL(fixedPriv) + "\nPassword (PublicKey): " + marker + "\nHash32: " + rawURL(fixedH32) + "\n", ErrKeygenFormat},
		{"missing colon space", "PrivateKey:" + rawURL(fixedPriv) + "\nPassword (PublicKey): " + marker + "\nHash32: " + rawURL(fixedH32) + "\n", ErrKeygenFormat},
		{"empty value", "PrivateKey: \nPassword (PublicKey): " + marker + "\nHash32: " + rawURL(fixedH32) + "\n", ErrKeygenFormat},
		{"space in value", "PrivateKey: " + rawURL(fixedPriv)[:8] + " " + rawURL(fixedPriv)[8:] + "\nPassword (PublicKey): " + marker + "\nHash32: " + rawURL(fixedH32) + "\n", ErrKeygenFormat},
		{"non base64 alphabet", "PrivateKey: !notbase64!\nPassword (PublicKey): " + marker + "\nHash32: " + rawURL(fixedH32) + "\n", ErrKeygenBadKey},
		{"std encoding padded rejected", "PrivateKey: " + base64.StdEncoding.EncodeToString(fixedPriv) + "\nPassword (PublicKey): " + marker + "\nHash32: " + rawURL(fixedH32) + "\n", ErrKeygenBadKey},
		{"wrong length 31", "PrivateKey: " + rawURL(fixedPriv[:31]) + "\nPassword (PublicKey): " + marker + "\nHash32: " + rawURL(fixedH32) + "\n", ErrKeygenBadKey},
		{"wrong length 33", "PrivateKey: " + rawURL(append(append([]byte{}, fixedPriv...), 0)) + "\nPassword (PublicKey): " + marker + "\nHash32: " + rawURL(fixedH32) + "\n", ErrKeygenBadKey},
		{"public wrong length", "PrivateKey: " + rawURL(fixedPriv) + "\nPassword (PublicKey): " + rawURL(fixedPub[:16]) + "\nHash32: " + rawURL(fixedH32) + "\n", ErrKeygenBadKey},
		{"unclamped private low bits", func() string {
			b := append([]byte{}, fixedPriv...)
			b[0] = 0x8f // 0x8f & 0x07 == 0x07 != 0
			return x25519Out(rawURL(b), marker, rawURL(fixedH32))
		}(), ErrKeygenBadKey},
		{"unclamped private high bits", func() string {
			b := append([]byte{}, fixedPriv...)
			b[31] = 0xe0 // bit 7 set: violates the clamp (must be clear)
			return x25519Out(rawURL(b), marker, rawURL(fixedH32))
		}(), ErrKeygenBadKey},
		{"unclamped private bit6 missing", func() string {
			b := append([]byte{}, fixedPriv...)
			b[31] = 0x20 // bit 6 clear, bit 5 set: violates the clamp (bit 6 must be set)
			return x25519Out(rawURL(b), marker, rawURL(fixedH32))
		}(), ErrKeygenBadKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseX25519Output(tc.out)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error leaks key material: %v", err)
			}
		})
	}
}

// TestParseX25519OutputClampRegression pins the EXACT clamp boundary the
// pinned binary produces (v26.3.27: byte 0 &= 0xf8, byte 31 &= 0x7f,
// byte 31 |= 0x40). Bit 3 of byte 0 and bits 0-5 of byte 31 are RANDOM in
// a real key, so a key with bit 3 of byte 0 SET and bit 5 of byte 31 CLEAR
// is perfectly valid. The pre-fix check (priv[0]&0x0f != 0 || priv[31]&0xa0
// != 0x20) rejected exactly this shape — and therefore ~75% of all real
// keys. This test fails if the check ever regresses to that over-strict form.
func TestParseX25519OutputClampRegression(t *testing.T) {
	b := append([]byte{}, fixedPriv...)
	b[0] = 0x88  // low 3 bits 000, bit 3 SET (random in a real key)
	b[31] = 0x44 // bit 7 clear, bit 6 SET, bit 5 clear (random in a real key)
	if _, err := ParseX25519Output(x25519Out(rawURL(b), rawURL(fixedPub), rawURL(fixedH32))); err != nil {
		t.Fatalf("valid clamped key (bit3 of byte0 set, bit5 of byte31 clear) must be accepted: %v", err)
	}
}

func TestGenerateRealityKeypairHappyPath(t *testing.T) {
	f := keygenFake{out: x25519Out(rawURL(fixedPriv), rawURL(fixedPub), rawURL(fixedH32))}
	kp, err := GenerateRealityKeypair(f, "/opt/split-tunnel/xray/v26.3.27/xray")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kp.PublicStd != base64.StdEncoding.EncodeToString(fixedPub) {
		t.Errorf("PublicStd mismatch")
	}
}

func TestGenerateRealityKeypairExecErrorLeaksNothing(t *testing.T) {
	// The execution error must not carry the (possibly key-bearing)
	// output. The canned output deliberately embeds a marker.
	const secretLine = "PRIVATEKEY-MARKER-VALUE"
	f := keygenFake{
		out: "PrivateKey: " + secretLine + "\nPassword (PublicKey): " + rawURL(fixedPub) + "\n",
		err: errors.New("exit status 1"),
	}
	_, err := GenerateRealityKeypair(f, "/bin/xray")
	if !errors.Is(err, ErrKeygenExec) {
		t.Fatalf("want ErrKeygenExec, got %v", err)
	}
	if strings.Contains(err.Error(), secretLine) {
		t.Fatalf("exec error leaks key material: %v", err)
	}
}

func TestKeypairHasNoStringer(t *testing.T) {
	// Keypair must never implement fmt.Stringer or fmt.Formatter, so an
	// accidental print cannot dump the private key. The type assertion
	// below fails at RUNTIME if the type ever gains a String() method.
	var kp *Keypair
	if _, isStr := any(kp).(interface{ String() string }); isStr {
		t.Fatal("Keypair must not implement String()")
	}
	if _, isFmt := any(kp).(interface {
		Format(f fmt.Formatter, verb rune)
	}); isFmt {
		t.Fatal("Keypair must not implement Format()")
	}
}
