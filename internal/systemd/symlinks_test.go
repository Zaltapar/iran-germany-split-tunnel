package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestManagedPathSymlinkRefusals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests require Windows symlink privilege/dev mode")
	}
	redirectPaths(t)
	ctx := context.Background()

	t.Run("unit path", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target")
		writeRaw(t, target, []byte("not a unit"))
		live := filepath.Join(unitDir, "germany-splitter.service")
		if err := os.Symlink(target, live); err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(binaryPrefix, "germany-splitter")
		writeRaw(t, bin, []byte("fake binary"))
		writeRaw(t, envPath(RoleGermany), []byte("SPLIT_SECRET=x\n"))
		s := splitterSpec(RoleGermany)
		m := newTestManager(&fakeExec{})
		if _, err := ApplyUnit(ctx, m, s); !errors.Is(err, ErrUnsafeTarget) {
			t.Fatalf("error=%v", err)
		}
		if _, err := os.Lstat(live); err != nil {
			t.Fatalf("symlink removed: %v", err)
		}
	})

	t.Run("env path", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target")
		writeRaw(t, target, []byte("SPLIT_SECRET=x\n"))
		if err := os.Symlink(target, envPath(RoleGermany)); err != nil {
			t.Fatal(err)
		}
		_, _, err := WriteEnvFile(ctx, RoleGermany, validEnvKV(t, RoleGermany))
		if !errors.Is(err, ErrUnsafeTarget) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("backup target", func(t *testing.T) {
		path := envPath(RoleGermany)
		writeRaw(t, path, []byte("old\n"))
		backup := path + ".bak-999"
		target := filepath.Join(t.TempDir(), "target")
		writeRaw(t, target, []byte("secret backup\n"))
		if err := os.Symlink(target, backup); err != nil {
			t.Fatal(err)
		}
		if err := RollbackEnvFile(ctx, RoleGermany); !errors.Is(err, ErrPreflight) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestStateDirectorySymlinkRefusal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("directory provisioning is Linux-only")
	}
	redirectPaths(t)
	actual := stateDir
	linkTarget := filepath.Join(t.TempDir(), "real-state")
	if err := os.Mkdir(linkTarget, 0o750); err != nil {
		t.Fatal(err)
	}
	os.Remove(actual)
	if err := os.Symlink(linkTarget, actual); err != nil {
		t.Fatal(err)
	}
	if err := EnsureStateDir(context.Background()); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("error=%v", err)
	}
}
