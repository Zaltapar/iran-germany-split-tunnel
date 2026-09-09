package origin

import (
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Checksum errors. None of them include file contents.
var (
	ErrChecksumFormat   = errors.New("origin: checksums file malformed (expected '<sha512-hex>  <name>' lines)")
	ErrChecksumMismatch = errors.New("origin: SHA-512 mismatch (tar corrupted or tampered — refusing)")
	ErrChecksumMissing  = errors.New("origin: no SHA-512 entry for the tar in the checksums file (release rejected)")
	ErrChecksumEmpty    = errors.New("origin: checksums file empty")
	ErrChecksumTooLarge = errors.New("origin: checksums file too large (refusing)")
)

// maxChecksumBytes bounds the upstream checksums file (the real one is
// ~3 KiB for the 8 linux assets + the checksums file itself); a hostile
// or corrupt file must not exhaust memory.
const maxChecksumBytes = 1 << 20

// ParseChecksumFile extracts the SHA-512 hex for the named asset from
// the upstream caddy_<v>_checksums.txt. The file is in the standard
// "gpg --print-md SHA512" format: "<128-hex><two spaces><name>" (a
// leading ' *' marker is tolerated, as GPG output sometimes carries).
// Fail closed: empty file, or no line naming the asset → error.
func ParseChecksumFile(data []byte, asset string) (string, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return "", ErrChecksumEmpty
	}
	if int64(len(data)) > maxChecksumBytes {
		return "", fmt.Errorf("%w: %d bytes", ErrChecksumTooLarge, len(data))
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip a GPG marker (" *name" / "*name" / "  name").
		line = strings.TrimPrefix(line, "*")
		parts := strings.SplitN(line, "  ", 2) // exactly two spaces
		if len(parts) != 2 {
			continue
		}
		hexPart := strings.TrimSpace(parts[0])
		namePart := strings.TrimSpace(parts[1])
		if len(hexPart) != sha512.Size*2 { // 128 hex chars
			continue
		}
		if !isHex(hexPart) {
			continue
		}
		if namePart == asset {
			return strings.ToLower(hexPart), nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrChecksumMissing, asset)
}

// VerifyFile computes SHA-512 over data and compares it to expectedHex
// (128 hex chars) in CONSTANT TIME — a mismatch must not be
// distinguishable by timing.
func VerifyFile(data []byte, expectedHex string) error {
	exp := strings.ToLower(strings.TrimSpace(expectedHex))
	if len(exp) != sha512.Size*2 {
		return fmt.Errorf("%w: expected %d hex chars", ErrChecksumFormat, sha512.Size*2)
	}
	expBytes, err := hex.DecodeString(exp)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrChecksumFormat, err)
	}
	sum := sha512.Sum512(data)
	if subtle.ConstantTimeCompare(sum[:], expBytes) != 1 {
		return ErrChecksumMismatch
	}
	return nil
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
