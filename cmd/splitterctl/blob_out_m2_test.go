package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestWriteEmittedBlobNoFollow pins the M-2 remediation:
//   - a healthy write creates a regular 0600 file;
//   - a SYMLINK planted at the final path is refused (never followed);
//   - a DIRECTORY at the final path is refused;
//   - a relative path is refused;
//   - errors never leak the blob's content.
func TestWriteEmittedBlobNoFollow(t *testing.T) {
	blob := "SECRET-BLOB-CONTENT-MUST-NEVER-LEAK"

	t.Run("healthy write creates a 0600 regular file", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "blob.out")
		if err := writeEmittedBlob(out, blob); err != nil {
			t.Fatalf("writeEmittedBlob: %v", err)
		}
		st, err := os.Lstat(out)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Mode().IsRegular() {
			t.Fatalf("target mode = %v, want a regular file", st.Mode())
		}
		if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
			t.Fatalf("target mode = %o, want 0600", st.Mode().Perm())
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != blob+"\n" {
			t.Fatalf("content = %q, want the blob plus newline", data)
		}
	})

	t.Run("symlink target is refused and not followed", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks unavailable without developer mode; Linux CI is authoritative")
		}
		dir := t.TempDir()
		victim := filepath.Join(dir, "victim")
		if err := os.WriteFile(victim, []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "blob.out")
		if err := os.Symlink(victim, out); err != nil {
			t.Fatal(err)
		}
		err := writeEmittedBlob(out, blob)
		if err == nil {
			t.Fatal("symlinked target was written through (refusal missing)")
		}
		// The victim must be untouched: no-follow semantics mean the write was
		// never redirected to the symlink target.
		data, rerr := os.ReadFile(victim)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if string(data) != "existing" {
			t.Fatalf("symlink target was mutated: %q", data)
		}
		// The error must not echo the blob's content.
		if strings.Contains(err.Error(), blob) {
			t.Fatalf("error leaked the blob content: %q", err.Error())
		}
	})

	t.Run("directory target is refused", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "sub")
		if err := os.Mkdir(out, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeEmittedBlob(out, blob); err == nil {
			t.Fatal("directory target was accepted (refusal missing)")
		}
	})

	t.Run("relative path is refused", func(t *testing.T) {
		if err := writeEmittedBlob("relative/blob.out", blob); err == nil {
			t.Fatal("relative path was accepted (must be absolute)")
		}
	})
}
