package xray

// keygen.go implements the Germany-side Reality keypair generation
// (architecture doc §4.4). The keypair is produced by the pinned,
// SHA-256-verified Xray binary itself (`xray x25519`), so the
// project never re-implements curve25519 key derivation and the
// generated keys are guaranteed compatible with the same binary that
// will serve the Reality inbound.
//
// Security invariants (doc §4.4, §8):
//   - the private key is generated on Germany and NEVER transmitted:
//     it enters no pairing blob, no log line, no error string, and no
//     test output (except the fixed, documented, non-production
//     vector in testdata);
//   - every error returned here is a sentinel plus a structural
//     reason; none echoes key material;
//   - the Keypair type has no String/Format method on purpose, so an
//     accidental fmt.Print of the struct cannot dump the keys.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Keygen failures. None of them include the key material.
var (
	ErrKeygenExec   = errors.New("xray: keygen: 'xray x25519' execution failed")
	ErrKeygenFormat = errors.New("xray: keygen: unexpected 'xray x25519' output format")
	ErrKeygenBadKey = errors.New("xray: keygen: key material failed validation")
)

// keyLine prefixes, exactly as printed by the pinned Xray
// (main/commands/all/curve25519.go @ v26.3.27).
const (
	keyLinePrivate = "PrivateKey: "
	keyLinePublic  = "Password (PublicKey): "
	keyLineHash32  = "Hash32: "
	keyLen         = 32 // X25519 scalar / point length
)

// Keypair is one Reality X25519 keypair in both base64 alphabets.
//
// The *Raw fields are base64.RawURLEncoding (unpadded) — the exact
// strings the binary printed and the exact format the pinned Xray
// config loader expects for realitySettings.privateKey
// (infra/conf REALITYConfig.Build decodes RawURLEncoding, 32 bytes).
//
// The *Std fields are the same 32 bytes re-encoded as
// base64.StdEncoding — the format the pairing blob requires for
// PublicParams.RealityPublicKey. One keypair, two encodings; the
// bytes are identical.
//
// Do not add a String()/Format() method: the private key must never
// be printable.
type Keypair struct {
	PrivateRaw string
	PublicRaw  string
	Hash32Raw  string // blake3-256(public key), as printed; cross-check only
	PrivateStd string
	PublicStd  string
}

// GenerateRealityKeypair runs "<bin> x25519" through the Executor
// boundary (so tests inject a fake) and parses/validates the output.
// ex may be nil (OSExecutor is used).
func GenerateRealityKeypair(ex Executor, bin string) (*Keypair, error) {
	if ex == nil {
		ex = OSExecutor{}
	}
	out, err := ex.Keypair(bin)
	if err != nil {
		// runCombined's error is "xray: <exit>" — it never carries
		// the output, which could contain a key line.
		return nil, fmt.Errorf("%w: %v", ErrKeygenExec, err)
	}
	return ParseX25519Output(out)
}

// ParseX25519Output strictly parses the three-line output of
// "xray x25519" (default RawURL encoding, no flags). It is the single
// trusted entry point for key material: anything that is not exactly
// three labeled lines of 32-byte RawURL base64 is rejected.
func ParseX25519Output(out string) (*Keypair, error) {
	lines := strings.Split(out, "\n")
	// Tolerate one (or more) trailing newline(s) — the binary ends
	// with \n; nothing else may be blank.
	for len(lines) > 0 && strings.TrimRight(lines[len(lines)-1], "\r") == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) != 3 {
		return nil, fmt.Errorf("%w: expected exactly 3 output lines, got %d", ErrKeygenFormat, len(lines))
	}

	prefixes := []string{keyLinePrivate, keyLinePublic, keyLineHash32}
	vals := make([]string, 3)
	for i, p := range prefixes {
		v, ok := strings.CutPrefix(strings.TrimSuffix(lines[i], "\r"), p)
		if !ok {
			return nil, fmt.Errorf("%w: line %d has an unexpected prefix", ErrKeygenFormat, i+1)
		}
		if v == "" || strings.ContainsAny(v, " \t") {
			return nil, fmt.Errorf("%w: line %d value is empty or malformed", ErrKeygenFormat, i+1)
		}
		vals[i] = v
	}

	privRaw, pubRaw, h32Raw := vals[0], vals[1], vals[2]

	priv, err := decodeKey32(privRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: private key", err)
	}
	pub, err := decodeKey32(pubRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: public key", err)
	}
	if _, err := decodeKey32(h32Raw); err != nil {
		return nil, fmt.Errorf("%w: hash32", err)
	}

	// The binary applies the standard X25519 scalar clamp before printing
	// (privateKey[0] &= 0xf8; privateKey[31] &= 0x7f; privateKey[31] |= 0x40):
	// the low 3 bits of byte 0 are zero, bit 7 of byte 31 is clear and bit 6
	// of byte 31 is set. (Bit 3 of byte 0 and bits 0-5 of byte 31 remain
	// random — do NOT check them; doing so would reject ~75% of real keys.)
	// Re-checking the clamped bits catches a broken or tampered binary.
	if priv[0]&0x07 != 0 || priv[31]&0xc0 != 0x40 {
		return nil, fmt.Errorf("%w: private key is not a clamped X25519 secret", ErrKeygenBadKey)
	}

	return &Keypair{
		PrivateRaw: privRaw,
		PublicRaw:  pubRaw,
		Hash32Raw:  h32Raw,
		PrivateStd: base64.StdEncoding.EncodeToString(priv),
		PublicStd:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// decodeKey32 decodes a base64.RawURLEncoding string and requires
// exactly keyLen bytes. RawURL decoding is strict about the alphabet
// (StdEncoding input with '+'/'/' or padding '=' is rejected), which
// is deliberate: the generator must feed ONLY the binary's default
// output into the Xray config.
func decodeKey32(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: not strict base64.RawURLEncoding", ErrKeygenBadKey)
	}
	if len(b) != keyLen {
		return nil, fmt.Errorf("%w: must decode to %d bytes, got %d", ErrKeygenBadKey, keyLen, len(b))
	}
	return b, nil
}
