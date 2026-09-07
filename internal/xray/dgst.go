package xray

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Digest errors. None of them include file contents.
var (
	ErrDgstFormat   = errors.New("xray: digest file malformed (expected 'SHA2-256= <hex>' line)")
	ErrDgstMismatch = errors.New("xray: SHA-256 mismatch (file corrupted or tampered — refusing)")
	ErrDgstMissing  = errors.New("xray: no SHA2-256 entry in digest file (release rejected — §4.2 pin floor)")
	ErrDgstEmpty    = errors.New("xray: digest file empty")
	ErrDgstTooLarge = errors.New("xray: digest file too large (refusing)")
)

// maxDgstBytes bounds the .dgst sidecar (the real one is a few hundred
// bytes); a hostile or corrupt sidecar must not exhaust memory.
const maxDgstBytes = 1 << 20

// digestLineRe matches an upstream .dgst line, e.g.
// "SHA2-256= 23cd9af9...". The '=' form is what XTLS publishes;
// a ':' variant is tolerated for robustness.
var digestLineRe = regexp.MustCompile(`(?i)^\s*SHA2-?256\s*[=:]\s*([0-9a-fA-F]{64})\s*$`)

// ParseDigest extracts the SHA-256 hex from an upstream .dgst sidecar.
// Fail closed: empty file, or no SHA2-256 line → error. The MD5/SHA1/
// SHA2-512 lines are ignored (SHA-256 is the binding verification).
func ParseDigest(data []byte) (string, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return "", ErrDgstEmpty
	}
	for _, line := range strings.Split(string(data), "\n") {
		if m := digestLineRe.FindStringSubmatch(line); m != nil {
			return strings.ToLower(m[1]), nil
		}
	}
	return "", ErrDgstMissing
}

// VerifyDigest computes SHA-256 over r and compares it to expectedHex
// (64 lowercase/uppercase hex) in CONSTANT TIME — a mismatch must not be
// distinguishable by timing. It reads exactly what is given; callers
// should pass the downloaded zip body.
func VerifyDigest(r io.Reader, expectedHex string) error {
	exp := strings.ToLower(strings.TrimSpace(expectedHex))
	if len(exp) != 64 {
		return fmt.Errorf("%w: expected 64 hex chars", ErrDgstFormat)
	}
	expBytes, err := hexToBytes(exp)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDgstFormat, err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return fmt.Errorf("xray: hashing download: %w", err)
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), expBytes) != 1 {
		return ErrDgstMismatch
	}
	return nil
}

// VerifyFile is the same check bound to a concrete digest string; the
// pair (data, digestHex) is what a manifest records.
func VerifyFile(data []byte, digestHex string) error {
	return VerifyDigest(bytes.NewReader(data), digestHex)
}

func hexToBytes(s string) ([]byte, error) {
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi, ok1 := hexVal(s[2*i])
		lo, ok2 := hexVal(s[2*i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("invalid hex at position %d", 2*i)
		}
		b[i] = hi<<4 | lo
	}
	return b, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
