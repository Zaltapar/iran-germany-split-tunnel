package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/deploy"
)

// TestHashFileSha256Hex pins the H-3 content-identity primitive:
//   - an absent or non-regular or relative path is UNASSERTED (""),
//   - a present regular file yields its exact content digest,
//   - changed bytes at the same path yield a different digest.
func TestHashFileSha256Hex(t *testing.T) {
	dir := t.TempDir()
	if got := hashFileSha256Hex(filepath.Join(dir, "absent")); got != "" {
		t.Fatalf("absent file hash = %q, want empty (unasserted)", got)
	}
	if got := hashFileSha256Hex("relative.bin"); got != "" {
		t.Fatalf("relative path hash = %q, want empty (unasserted)", got)
	}
	if got := hashFileSha256Hex(dir); got != "" {
		t.Fatalf("directory hash = %q, want empty (not a regular file)", got)
	}

	p := filepath.Join(dir, "splitter")
	content := []byte("installed-splitter-bytes")
	if err := os.WriteFile(p, content, 0o755); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(content)
	wantHex := hex.EncodeToString(want[:])
	if got := hashFileSha256Hex(p); got != wantHex {
		t.Fatalf("hash = %q, want %q", got, wantHex)
	}

	changed := append([]byte{}, content...)
	changed[0] ^= 0x01
	if err := os.WriteFile(p, changed, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := hashFileSha256Hex(p); got == wantHex {
		t.Fatal("changed bytes at the same path produced the same digest")
	}
}

// TestInstallRequestFromEnvRecordsSplitterSHA256 proves the H-3 deployment
// boundary: installRequestFromEnv computes the splitter artifact digest from
// the operator-supplied absolute binary and records it on the request, so the
// manifest persists the content identity.
func TestInstallRequestFromEnvRecordsSplitterSHA256(t *testing.T) {
	// withMutationEnv returns the state root; the CLI env var
	// SPLITTERCTL_SPLITTER_BIN is <root>/opt/splitter.
	root := withMutationEnv(t, deploy.RoleIran)
	bin := filepath.Join(root, "opt", "splitter")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("germany-or-iran-splitter-bytes")
	if err := os.WriteFile(bin, content, 0o755); err != nil {
		t.Fatal(err)
	}
	req, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatalf("installRequestFromEnv: %v", err)
	}
	want := sha256.Sum256(content)
	if got := req.SplitterSHA256; got != hex.EncodeToString(want[:]) {
		t.Fatalf("SplitterSHA256 = %q, want the supplied binary's content digest", got)
	}
}

// TestInstallRequestFromEnvSplitterSHA256UnassertedWhenAbsent proves the
// legacy-compatibility side of H-3: when the artifact file is not present the
// field is left unasserted ("") rather than fabricated, so legacy hosts and
// read-only contexts keep the planner's empty/unknown no-drift rule.
func TestInstallRequestFromEnvSplitterSHA256UnassertedWhenAbsent(t *testing.T) {
	withMutationEnv(t, deploy.RoleIran)
	req, err := installRequestFromEnv(deploy.RoleIran)
	if err != nil {
		t.Fatalf("installRequestFromEnv: %v", err)
	}
	if req.SplitterSHA256 != "" {
		t.Fatalf("SplitterSHA256 = %q, want empty when the artifact is absent", req.SplitterSHA256)
	}
}
