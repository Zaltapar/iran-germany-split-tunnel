package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnsureBinaryPointer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows requires symlink privilege/dev mode")
	}
	redirectPaths(t)
	base := filepath.Join(binaryPrefix, "xray")
	if err := os.MkdirAll(filepath.Join(base, "v26.3.27"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "v26.3.28"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := EnsureBinaryPointer(context.Background(), PointerXray, "v26.3.27"); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(base, "current")
	got, err := os.Readlink(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(base, "v26.3.27") {
		t.Fatalf("target=%q", got)
	}
	if err := EnsureBinaryPointer(context.Background(), PointerXray, "v26.3.27"); err != nil {
		t.Fatal(err)
	}
	if err := EnsureBinaryPointer(context.Background(), PointerXray, "v26.3.28"); err != nil {
		t.Fatal(err)
	}
	got, err = os.Readlink(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(base, "v26.3.28") {
		t.Fatalf("swapped target=%q", got)
	}
}

func TestEnsureBinaryPointerRejectsUnsafeTargets(t *testing.T) {
	redirectPaths(t)
	base := filepath.Join(binaryPrefix, "xray")
	if err := os.MkdirAll(filepath.Join(base, "v26.3.27"), 0o755); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(base, "current")
	if err := os.WriteFile(pointer, []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnsureBinaryPointer(context.Background(), PointerXray, "v26.3.27"); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("error=%v", err)
	}

	if err := os.Remove(pointer); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(base, "v26.3.27"), filepath.Join(base, "v26.3.28")); err != nil {
			t.Fatal(err)
		}
		if err := EnsureBinaryPointer(context.Background(), PointerXray, "v26.3.28"); !errors.Is(err, ErrPreflight) {
			t.Fatalf("symlink version error=%v", err)
		}
	}
}

func TestEnsureBinaryPointerValidation(t *testing.T) {
	redirectPaths(t)
	bad := []string{"v1.2", "../x", "v1.2.3/..", "v1.2.3 ", ""}
	for _, version := range bad {
		t.Run(version, func(t *testing.T) {
			if err := EnsureBinaryPointer(context.Background(), PointerXray, version); !errors.Is(err, ErrSpec) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if err := EnsureBinaryPointer(context.Background(), PointerKind("caddy"), "v1.2.3"); !errors.Is(err, ErrSpec) {
		t.Fatalf("unknown kind error=%v", err)
	}
	if err := EnsureBinaryPointer(context.Background(), PointerXray, "v26.3.27"); !errors.Is(err, ErrPreflight) {
		t.Fatalf("missing dir error=%v", err)
	}
}
