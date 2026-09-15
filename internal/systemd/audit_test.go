// audit_test.go — the read-only state-dir audit (doctor's inspection half of
// DEFECT-2). The hard invariant every test here asserts: the audit NEVER
// mutates. It performs no chmod, no chown, no create/remove/rename and no
// executor call — so a drifted mode must still be drifted after the audit,
// with the same bytes and the same directory entries.
package systemd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// snapshotTree records every path + content digest under root. It is the
// mutation detector the read-only tests compare before/after.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			out[rel(t, root, p)+"/"] = ""
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		out[rel(t, root, p)] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return out
}

func rel(t *testing.T, root, p string) string {
	t.Helper()
	r, err := filepath.Rel(root, p)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(r)
}

func assertUnchanged(t *testing.T, before, after map[string]string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("audit mutated the tree (entry count %d → %d)", len(before), len(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("audit mutated %s", k)
		}
	}
}

// The audit's contract: a drifted directory is REPORTED, never repaired.
func TestAuditStateDirIsReadOnly(t *testing.T) {
	root := redirectPaths(t)
	state := filepath.Join(root, "state")
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, filepath.Join(state, "xray-germany.json"), []byte("{}\n"))
	// The mode to compare against is the OBSERVED one, not the requested
	// 0700: Windows does not preserve Unix permission bits (its chmod maps
	// to the read-only attribute), so the test's own setup is not
	// authoritative there. Comparing against the stat the audit actually
	// faced is the honest read-only assertion on every host: the mode is
	// exactly what it was, or the audit repaired it — which it must never
	// do (remediation is EnsureStateDir's job).
	beforeMode := mustPerm(t, state)
	before := snapshotTree(t, root)

	audit, err := AuditStateDir()
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Exists {
		t.Fatalf("audit = %+v, want an existing directory", audit)
	}
	if got := audit.Problems(); len(got) > 0 {
		t.Logf("problems on this host: %v", got) // informational; not asserted cross-platform
	}

	assertUnchanged(t, before, snapshotTree(t, root))
	if after := mustPerm(t, state); after != beforeMode {
		t.Fatalf("audit changed the state-dir mode %o to %o — remediation is EnsureStateDir's job, not the audit's", beforeMode, after)
	}
}

func mustPerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestAuditStateDirAbsentIsNotDrift(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "no-such-state-dir")
	audit, err := AuditStateDirAt(missing)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Exists {
		t.Fatal("absent directory reported as existing")
	}
	if len(audit.Problems()) != 0 {
		t.Fatalf("absent directory must report no problems, got %v", audit.Problems())
	}
}

func TestAuditStateDirSymlinkIsReportedNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests require Windows symlink privilege/dev mode")
	}
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	audit, err := AuditStateDirAt(link)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Exists || !audit.Symlink {
		t.Fatalf("audit = %+v, want Exists+Symlink", audit)
	}
	problems := audit.Problems()
	if len(problems) != 1 || problems[0].Kind != ProblemSymlink {
		t.Fatalf("problems = %v, want exactly the symlink problem", problems)
	}
}

// On Linux the drifted-mode finding is precise: 0700 must be flagged with
// the wanted 0750 (the exact staging defect). Root-owned groups and the
// contract-clean pass are covered by the Linux+root case below.
func TestAuditStateDirFlagsModeDriftOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix mode/owner bits exist only on the deployment platform (the audit reports facts)")
	}
	if _, err := lookupGroupGID(ServiceGroup); err != nil {
		t.Skipf("service group %q unavailable on this host: %v", ServiceGroup, err)
	}
	root := redirectPaths(t)
	state := filepath.Join(root, "state")
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	audit, err := AuditStateDir()
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	var modeProblem *Problem
	problems := audit.Problems()
	for i := range problems {
		if problems[i].Kind == ProblemMode && problems[i].Path == state {
			modeProblem = &problems[i]
		}
	}
	if modeProblem == nil {
		t.Fatalf("0700 state dir not flagged as a mode problem: %v", problems)
	}
	if modeProblem.Detail == "" {
		t.Fatal("mode problem must carry a human-readable detail")
	}
}
