package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

func testManifest(root, role string) Manifest {
	now := time.Unix(1700000000, 0).UTC()
	return Manifest{
		Schema:     SchemaVersion,
		Role:       role,
		Generation: "g1",
		CreatedAt:  now,
		UpdatedAt:  now,
		Paths:      Paths{StateRoot: root, Env: filepath.Join(root, role+".env")},
		Components: Components{Splitter: ComponentState{Version: "v1.0.0", Path: "/opt/split-tunnel/bin/splitter", SHA256: "abc"}},
		Pairing:    PairingState{State: "none"},
		Firewall:   FirewallState{Backend: "none"},
	}
}

func TestStoreRoundTripAndTamperDetection(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	m := testManifest(root, RoleIran)
	if err := s.Save(m); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ManifestHash == "" || got.Role != RoleIran {
		t.Fatalf("loaded manifest = %+v", got)
	}
	path := filepath.Join(root, "state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-2] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Load after tamper = %v, want ErrTampered", err)
	}
}

func TestStoreRejectsUnsafeRootAndRevisionID(t *testing.T) {
	if _, err := NewStore("relative"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("NewStore relative = %v", err)
	}
	root := t.TempDir()
	s, _ := NewStore(root)
	if _, err := s.ReadRevision("../escape"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("ReadRevision traversal = %v", err)
	}
}

func TestStoreCommitRetainsTenRevisions(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	m := testManifest(root, RoleGermany)
	for i := 0; i < 12; i++ {
		m.Generation = "g" + string(rune('a'+i))
		got, err := s.Commit(m, "install")
		if err != nil {
			t.Fatalf("Commit %d: %v", i, err)
		}
		m = got
	}
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Revisions) != maxRevisions {
		t.Fatalf("revisions = %d, want %d", len(loaded.Revisions), maxRevisions)
	}
	entries, err := os.ReadDir(filepath.Join(root, "revisions"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != maxRevisions {
		t.Fatalf("snapshot files = %d, want %d", len(entries), maxRevisions)
	}
}

func TestAtomicWriteRefusesSymlink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.json")
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := atomicWrite(path, []byte("replace"), 0o600); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("atomicWrite symlink = %v, want ErrUnsafePath", err)
	}
}

// TestStoreCommitConvergesServiceStateRootMode is the staging-defect
// regression: the production service state root (/etc/split-tunnel) must
// converge to 0750 on commit, not 0700. A 0700 root locks the non-root
// service group out of its own 0640 live configs, so any committed
// transaction that restarted xray-germany left the unit failed while the
// transaction reported success. The safe default for a private root stays
// 0700; only the explicit service root opts into 0750.
func TestStoreCommitConvergesServiceStateRootMode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("unix mode bits not observable on this host")
	}
	t.Run("service root converges to 0750 (not 0700)", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		s, err := NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		s.RootMode = systemd.StateDirMode
		if _, err := s.Commit(testManifest(root, RoleGermany), "install"); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		st, err := os.Stat(root)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != 0o750 {
			t.Fatalf("root mode = %o, want %o (service state root)", got, 0o750)
		}
	})
	t.Run("private root keeps the 0700 default", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o750); err != nil {
			t.Fatal(err)
		}
		s, err := NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(testManifest(root, RoleGermany), "install"); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		st, err := os.Stat(root)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != 0o700 {
			t.Fatalf("root mode = %o, want %o (private default)", got, 0o700)
		}
	})
}
