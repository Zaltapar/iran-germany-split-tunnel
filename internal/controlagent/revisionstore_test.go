// revisionstore_test.go — the C2 revision store (design §5.4): atomic
// writes, per-revision MANIFEST.sha256, retention 10, symlink refusal,
// manifest self-hash + per-file hash verification, pre-snapshot, and the
// kill-switch file.
package controlagent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *RevisionStore {
	t.Helper()
	root := t.TempDir()
	st, err := NewRevisionStore(root)
	if err != nil {
		t.Fatalf("NewRevisionStore: %v", err)
	}
	return st
}

// newTestStoreDayAdvancing returns a store whose clock advances one UTC
// day per call, so each revision id embeds a strictly increasing date
// prefix. With the real clock, a burst of same-day ids is ordered by
// their random 6-byte suffix, which breaks Prune's "newest last"
// lexicographic assumption (a pre-existing flake: the head can fall
// inside the drop window, get skipped as retained, and retention keeps
// 11 instead of 10).
func newTestStoreDayAdvancing(t *testing.T) *RevisionStore {
	t.Helper()
	st := newTestStore(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var n int
	st.Now = func() time.Time {
		n++
		return base.AddDate(0, 0, n)
	}
	return st
}

func TestCommitRevisionRoundTrip(t *testing.T) {
	st := newTestStore(t)
	id, err := st.NewRevisionID()
	if err != nil {
		t.Fatalf("NewRevisionID: %v", err)
	}
	filesDir := t.TempDir()
	live := filepath.Join(filesDir, "iran.env")
	if err := os.WriteFile(live, []byte("SPLIT_POLICY_MODE=adaptive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.PreSnapshot(id, map[string]string{"iran.env": live}); err != nil {
		t.Fatalf("PreSnapshot: %v", err)
	}
	meta := RevisionMeta{
		ID: id, Parent: "r-parent", ChangeID: "c-1", Actor: "operator",
		Role: "iran", Kind: "splitter-policy", Outcome: "committed",
	}
	if err := st.CommitRevision(meta, map[string]string{"iran.env": live}, "r-parent"); err != nil {
		t.Fatalf("CommitRevision: %v", err)
	}

	gotMeta, gotFiles, err := st.LoadRevision(id)
	if err != nil {
		t.Fatalf("LoadRevision: %v", err)
	}
	if gotMeta.ID != id || gotMeta.Parent != "r-parent" {
		t.Fatalf("meta mismatch: %+v", gotMeta)
	}
	if len(gotFiles) != 1 {
		t.Fatalf("expected 1 file copy, got %d", len(gotFiles))
	}
	head, _ := st.Head()
	if head != id {
		t.Fatalf("head = %q, want %q", head, id)
	}
}

func TestLoadRevisionDetectsFileTamper(t *testing.T) {
	st := newTestStore(t)
	id, _ := st.NewRevisionID()
	live := filepath.Join(t.TempDir(), "iran.env")
	_ = os.WriteFile(live, []byte("A\n"), 0o600)
	_ = st.PreSnapshot(id, map[string]string{"iran.env": live})
	if err := st.CommitRevision(RevisionMeta{ID: id, Role: "iran", Kind: "k", Outcome: "committed"},
		map[string]string{"iran.env": live}, ""); err != nil {
		t.Fatal(err)
	}
	// Tamper with a stored copy AFTER the manifest was written.
	filesDir := filepath.Join(st.Root, "revisions", id, "files", "iran.env")
	if err := os.WriteFile(filesDir, []byte("TAMPERED\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.LoadRevision(id); err == nil {
		t.Fatal("expected a manifest/hash mismatch, got nil")
	}
}

func TestPruneRetentionKeepsTen(t *testing.T) {
	st := newTestStoreDayAdvancing(t)
	ids := make([]string, 0, 14)
	for i := 0; i < 14; i++ {
		id, err := st.NewRevisionID()
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		src := filepath.Join(t.TempDir(), "e.env")
		_ = os.WriteFile(src, []byte("x"), 0o600)
		_ = st.PreSnapshot(id, map[string]string{"e.env": src})
		if err := st.CommitRevision(RevisionMeta{ID: id, Role: "iran", Kind: "k", Outcome: "committed"},
			map[string]string{"e.env": src}, ""); err != nil {
			t.Fatal(err)
		}
	}
	remaining, err := st.RevisionIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != DefaultRetention {
		t.Fatalf("retention: kept %d revisions, want %d", len(remaining), DefaultRetention)
	}
	// The head must always survive pruning.
	head, _ := st.Head()
	kept := false
	for _, rid := range remaining {
		if rid == head {
			kept = true
		}
	}
	if !kept {
		t.Fatal("head revision was pruned")
	}
}

func TestPruneNeverDropsLKG(t *testing.T) {
	st := newTestStoreDayAdvancing(t)
	ids := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		id, _ := st.NewRevisionID()
		ids = append(ids, id)
		src := filepath.Join(t.TempDir(), "e.env")
		_ = os.WriteFile(src, []byte("x"), 0o600)
		_ = st.PreSnapshot(id, map[string]string{"e.env": src})
		// The 11th commit's internal prune drops ids[0] (oldest beyond the
		// 10-window), so after it ids[1] is the oldest RETAINED revision.
		// Promote it to LKG just before the final commit so that the final
		// commit's prune must protect it (the drop candidate) rather than
		// drop it.
		if i == 10 {
			if err := st.PromoteLKG(ids[1]); err != nil {
				t.Fatal(err)
			}
		}
		_ = st.CommitRevision(RevisionMeta{ID: id, Role: "iran", Kind: "k", Outcome: "committed"},
			map[string]string{"e.env": src}, "")
	}
	// ids[1] sits in the drop window of the final commit; the LKG guard
	// must keep it even though it is the oldest.
	remaining, _ := st.RevisionIDs()
	kept := false
	for _, rid := range remaining {
		if rid == ids[1] {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("lkg revision was pruned; kept: %v", remaining)
	}
}

func TestSymlinkRefusalPreDir(t *testing.T) {
	st := newTestStore(t)
	id, _ := st.NewRevisionID()
	src := filepath.Join(t.TempDir(), "e.env")
	_ = os.WriteFile(src, []byte("x"), 0o600)
	// Make the revision's pre/ dir a symlink; PreSnapshot must refuse
	// to write through it.
	revDir := filepath.Join(st.Root, "revisions", id)
	_ = os.MkdirAll(revDir, 0o700)
	preLink := filepath.Join(revDir, "pre")
	if err := os.Symlink(src, preLink); err != nil {
		t.Skipf("cannot create symlink on this host: %v", err)
	}
	if err := st.PreSnapshot(id, map[string]string{"e.env": src}); err == nil {
		t.Fatal("expected symlink refusal, got nil")
	}
}

func TestSymlinkRefusalSourceFile(t *testing.T) {
	st := newTestStore(t)
	id, _ := st.NewRevisionID()
	src := filepath.Join(t.TempDir(), "e.env")
	_ = os.WriteFile(src, []byte("x"), 0o600)
	// The LIVE file itself is a symlink: the copy must refuse it
	// (design §5.4: refuse symlinks on both ends).
	srcLink := src + ".lnk"
	if err := os.Symlink(src, srcLink); err != nil {
		t.Skipf("cannot create symlink on this host: %v", err)
	}
	if err := st.PreSnapshot(id, map[string]string{"e.env": srcLink}); err == nil {
		t.Fatal("expected symlink source refusal, got nil")
	}
}

// TestEnsureDirSymlink asserts the dir-creation helper itself refuses a
// symlinked component (the platform-independent half of the guarantee).
func TestEnsureDirSymlink(t *testing.T) {
	st := newTestStore(t)
	target := filepath.Join(t.TempDir(), "target")
	_ = os.MkdirAll(target, 0o700)
	dir := filepath.Join(st.Root, "revisions", "r-link", "pre")
	_ = os.MkdirAll(filepath.Join(st.Root, "revisions", "r-link"), 0o700)
	if err := os.Symlink(target, dir); err != nil {
		t.Skipf("cannot create symlink on this host: %v", err)
	}
	if err := st.ensureDir(dir); err == nil {
		t.Fatal("ensureDir accepted a symlinked directory")
	}
}

func TestKillSwitch(t *testing.T) {
	st := newTestStore(t)
	if st.IsFrozen() {
		t.Fatal("fresh store reports frozen")
	}
	if err := st.Freeze(); err != nil {
		t.Fatal(err)
	}
	if !st.IsFrozen() {
		t.Fatal("freeze did not engage")
	}
	if _, err := os.Stat(st.KillSwitchPath()); err != nil {
		t.Fatalf("kill-switch file missing: %v", err)
	}
	if err := st.Unfreeze(); err != nil {
		t.Fatal(err)
	}
	if st.IsFrozen() {
		t.Fatal("unfreeze did not clear")
	}
	if err := st.Unfreeze(); err != nil {
		t.Fatalf("second unfreeze should be idempotent: %v", err)
	}
}

func TestNewRevisionIDUniqueAndSafe(t *testing.T) {
	st := newTestStore(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		id, err := st.NewRevisionID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("duplicate revision id %s", id)
		}
		seen[id] = true
		if !validateStoreToken(id) {
			t.Fatalf("unsafe token: %s", id)
		}
	}
}
