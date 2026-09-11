package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestManagedPathSymlinkRefusals: a managed path planted as a symlink is
// refused (ErrUnsafeTarget / ErrPreflight), never followed. Each subtest
// runs on its OWN temp tree (redirectPaths): the live paths (unit file,
// env file, backup, state dir) are fixed names inside the redirected
// dirs, so a subtest that plants a symlink at one of them must not share
// a tree with a subtest that plants at a different one (os.Symlink fails
// with EEXIST when the link already exists).
func TestManagedPathSymlinkRefusals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests require Windows symlink privilege/dev mode")
	}
	ctx := context.Background()

	t.Run("unit path", func(t *testing.T) {
		redirectPaths(t)
		target := filepath.Join(t.TempDir(), "target")
		writeRaw(t, target, []byte("not a unit"))
		live := filepath.Join(unitDir, "germany-splitter.service")
		if err := os.Symlink(target, live); err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(binaryPrefix, "germany-splitter")
		writeRaw(t, bin, []byte("fake binary"))
		// 0600: the env preflight (Linux-gated mode ≤ 0640) would reject
		// a 0644 plant before the live-symlink check runs.
		writeRaw0600(t, envPath(RoleGermany), []byte("SPLIT_SECRET=x\n"))
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
		redirectPaths(t)
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
		redirectPaths(t)
		path := envPath(RoleGermany)
		writeRaw0600(t, path, []byte("old\n"))
		backup := path + ".bak-999"
		target := filepath.Join(t.TempDir(), "target")
		writeRaw(t, target, []byte("secret backup\n"))
		if err := os.Symlink(target, backup); err != nil {
			t.Fatal(err)
		}
		// The symlinked backup must be skipped (not a managed regular
		// file), leaving no rollback source: ErrPreflight.
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
	// stateDir is not empty (units-backup/ lives inside it); a directory
	// must be renamed away, not removed, before planting the symlink.
	if err := os.Rename(actual, actual+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linkTarget, actual); err != nil {
		t.Fatal(err)
	}
	if err := EnsureStateDir(context.Background()); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("error=%v", err)
	}
}
