package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/firewall"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

func TestNewLinuxAdapterRejectsNonCanonicalPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production adapter is Linux-only")
	}
	r := validGermanyRequest()
	r.StateRoot = "/tmp/not-managed"
	if _, err := NewLinuxAdapter(r, nil, nil); err == nil {
		t.Fatal("non-canonical state root unexpectedly accepted")
	}
}

func TestNewLinuxAdapterRejectsInvalidFirewallPlan(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production adapter is Linux-only")
	}
	r := validGermanyRequest()
	r.StateRoot = systemd.StateDir
	r.EnvPath = systemd.EnvFile(systemd.RoleGermany)
	r.ConfigPath = systemd.StateDir + "/xray-germany.json"
	r.Firewall = firewall.Plan{Role: "unknown"}
	if _, err := NewLinuxAdapter(r, nil, nil); err == nil {
		t.Fatal("invalid firewall plan unexpectedly accepted")
	}
}

func TestLinuxAdapterFreshCleanupIsBoundedByOwnedState(t *testing.T) {
	// This test documents the production contract without invoking root-gated
	// T5 operations: an adapter with no applied firewall snapshot and no unit
	// journal has no cleanup work and must not report success as a restore.
	adapter := &LinuxAdapter{}
	if err := adapter.CleanupFresh(context.Background(), DesiredState{}); err != nil {
		t.Fatalf("empty cleanup: %v", err)
	}
	if err := adapter.Restore(context.Background(), Manifest{}); err == nil || errors.Is(err, ErrRecovered) {
		t.Fatalf("empty restore = %v, want explicit unsupported restore", err)
	}
}

// TestCleanupFreshRefusesJournalDirOutsideBinaryPrefix is the RF-3
// end-to-end regression: a journal whose XrayDir/OriginDir names a directory
// outside the managed binary prefix must never direct a recursive deletion
// there. The journal is pointed AT the sentinel, so a regression (the raw
// os.RemoveAll of the persisted field) deletes it and fails this test.
// ReadJournal rejects the tampered journal (fail closed), and CleanupFresh
// leaves the referenced directory untouched. The sentinel stands in for a
// sensitive directory a tampered journal might target (e.g. /etc).
func TestCleanupFreshRefusesJournalDirOutsideBinaryPrefix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		role    string
		journal func(sentinel string) string
	}{
		{"germany xrayDir", RoleGermany, func(s string) string {
			return `{"role":"germany","generation":"g1","xrayDir":"` + filepath.ToSlash(s) + `"}`
		}},
		{"iran originDir", RoleIran, func(s string) string {
			return `{"role":"iran","generation":"g1","originDir":"` + filepath.ToSlash(s) + `"}`
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateRoot := t.TempDir()
			store, err := NewStore(stateRoot)
			if err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(t.TempDir(), "sentinel")
			if err := os.MkdirAll(filepath.Join(sentinel, "child"), 0o755); err != nil {
				t.Fatal(err)
			}
			journal := tc.journal(sentinel)
			if err := os.WriteFile(filepath.Join(stateRoot, "journal.json"), []byte(journal), 0o600); err != nil {
				t.Fatal(err)
			}
			// The out-of-prefix directory must be rejected at read time
			// (fail closed) — the primary containment.
			if _, err := store.ReadJournal(); err == nil {
				t.Fatal("tampered journal accepted by ReadJournal")
			}
			adapter := &LinuxAdapter{
				Request: InstallRequest{Role: tc.role, EnvPath: filepath.Join(stateRoot, tc.role+".env")},
				Store:   store,
			}
			// CleanupFresh must not remove the referenced directory even if
			// validation were bypassed (the removal path is prefix-bounded).
			_ = adapter.CleanupFresh(context.Background(), DesiredState{})
			if _, statErr := os.Stat(filepath.Join(sentinel, "child")); statErr != nil {
				t.Fatalf("CleanupFresh deleted a directory outside the prefix: %v", statErr)
			}
		})
	}
}

// TestRemovePrefixDirRefusesOutsidePrefix asserts the defense-in-depth prefix
// check in removePrefixDir: even if validation were bypassed, the destructive
// helper refuses (and does not delete) any path outside the binary prefix.
func TestRemovePrefixDirRefusesOutsidePrefix(t *testing.T) {
	sentinel := filepath.Join(t.TempDir(), "sentinel")
	if err := os.MkdirAll(sentinel, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := removePrefixDir(sentinel, systemd.BinaryPrefix); err == nil {
		t.Fatal("removePrefixDir accepted an out-of-prefix directory")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("out-of-prefix directory was removed: %v", err)
	}
}

// TestRemoveWithinPrefixSymlinkAndNonDir covers the symlink-safe removal
// branch directly (the branch is unreachable through removePrefixDir in tests
// because the real binary prefix is not writable). A symlink is unlinked
// WITHOUT following it into its target; a non-directory is refused.
func TestRemoveWithinPrefixSymlinkAndNonDir(t *testing.T) {
	root := t.TempDir()

	dir := filepath.Join(root, "version")
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := removeWithinPrefix(dir); err != nil {
		t.Fatalf("remove real directory: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory survived removal: %v", err)
	}

	file := filepath.Join(root, "plain-file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeWithinPrefix(file); err == nil {
		t.Fatal("removeWithinPrefix accepted a non-directory")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("non-directory was removed: %v", err)
	}

	if runtime.GOOS == "windows" {
		t.Log("skipping symlink assertion: Windows requires symlink privilege/dev mode")
		return
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := removeWithinPrefix(link); err != nil {
		t.Fatalf("remove symlink: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("symlink survived removal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "keep")); err != nil {
		t.Fatalf("symlink target was deleted (must not be followed): %v", err)
	}
}
