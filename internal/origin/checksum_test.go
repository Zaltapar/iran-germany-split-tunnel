package origin

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func sha512For(t *testing.T, data []byte) string {
	t.Helper()
	sum := sha512.Sum512(data)
	return hex.EncodeToString(sum[:])
}

// checksumsFile renders the upstream caddy_checksums.txt format
// ("<sha512-hex><two spaces><name>").
func checksumsFile(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

func TestParseChecksumFile(t *testing.T) {
	good := sha512For(t, []byte("fake tar"))
	name := "caddy_" + PinnedVersion + "_linux_amd64.tar.gz"
	other := "caddy_" + PinnedVersion + "_linux_arm64.tar.gz"

	got, err := ParseChecksumFile(checksumsFile(
		fmt.Sprintf("%s  %s", sha512For(t, []byte("other")), other),
		fmt.Sprintf("%s  %s", good, name),
	), name)
	if err != nil || got != good {
		t.Errorf("ParseChecksumFile = %q, %v; want %q", got, err, good)
	}

	// Uppercase hex normalized to lowercase.
	upper := checksumsFile(fmt.Sprintf("%s  %s", strings.ToUpper(good), name))
	got, err = ParseChecksumFile(upper, name)
	if err != nil || got != good {
		t.Errorf("uppercase = %q, %v", got, err)
	}

	// No entry for the asset → fail closed.
	if _, err := ParseChecksumFile(checksumsFile(fmt.Sprintf("%s  %s", good, other)), name); err == nil {
		t.Error("missing entry accepted")
	}
	// Empty → fail closed.
	if _, err := ParseChecksumFile(nil, name); err == nil {
		t.Error("empty file accepted")
	}
	// Malformed hex length (not 128) is skipped → no entry.
	if _, err := ParseChecksumFile(checksumsFile(fmt.Sprintf("%s  %s", strings.Repeat("0", 64), name)), name); err == nil {
		t.Error("short hash accepted")
	}
	// Oversized file → fail closed.
	if _, err := ParseChecksumFile([]byte(strings.Repeat("x", maxChecksumBytes+1)), name); err == nil {
		t.Error("oversized file accepted")
	}
}

func TestVerifyFile(t *testing.T) {
	data := []byte("the tar bytes")
	good := sha512For(t, data)
	if err := VerifyFile(data, good); err != nil {
		t.Errorf("match: %v", err)
	}
	if err := VerifyFile(data, strings.Repeat("0", sha512.Size*2)); err == nil {
		t.Error("mismatch accepted")
	}
	if err := VerifyFile(data, "abc"); err == nil {
		t.Error("short digest accepted")
	}
}
