// audit.go — the READ-ONLY view of the state-directory permission chain
// (doctor semantics, design §4.8 / T7).
//
// AuditStateDir is the inspection counterpart of EnsureStateDir: it reports
// the SAME converged contract (state dir 0750 root:split-tunnel, live
// service-readable configs 0640 root:split-tunnel) without changing anything.
//
// Hard read-only invariant (asserted by tests): this file performs no chmod,
// no chown, no create/remove/rename, no symlink, and no executor call — only
// Lstat and NSS group lookups. Remediation belongs to EnsureStateDir, which
// the mutating lifecycle commands run through the deploy adapter
// (LinuxAdapter.ConvergeStateDir); doctor only observes and reports.
package systemd

import (
	"fmt"
	"os"
	"runtime"
)

// StateDirAudit is the read-only snapshot of one state directory's permission
// chain, taken against the converged contract EnsureStateDir enforces:
//
//	dir                      0750 root:split-tunnel
//	  <live config files>    0640 root:split-tunnel
//
// Linux reports whether the Unix stat facts (permission bits, uid, gid) are
// measurable and contract-applicable on this host. The deployment target is
// Linux; on any other host (a developer's Windows box) the facts do not
// exist, every ownership check reports not-applicable, and Problems() is
// empty — an unmeasurable expectation never becomes a finding. This mirrors
// how apply.go gates its preflight permission checks on runtime.GOOS.
type StateDirAudit struct {
	Path       string      // the audited directory
	Exists     bool        // false → nothing to audit (not installed yet)
	Symlink    bool        // true → the path is not a real directory (unsafe)
	NotDir     bool        // true → the path exists but is not a directory
	Linux      bool        // Unix stat facts are measurable here
	Mode       os.FileMode // permission bits when Exists
	Uid        int         // owner uid (-1 when not measurable)
	GID        int         // group gid (-1 when not measurable)
	GroupWant  int         // numeric id of ServiceGroup (-1 when unresolvable)
	GroupKnown bool        // GroupWant resolved through NSS
	Configs    []ConfigAudit
	WantDir    os.FileMode // the converged contract: 0750
	WantFile   os.FileMode // the converged contract: 0640
}

// ConfigAudit is the read-only snapshot of one live service-readable config
// file inside the state dir. Only files that EXIST are reported.
type ConfigAudit struct {
	Path string
	Mode os.FileMode
	Uid  int
	GID  int
}

// ProblemKind classifies one audit finding so consumers can pick a severity
// without parsing strings. ProblemMode/ProblemGroup/ProblemSymlink/
// ProblemNotDir describe conditions that make a User=<service> unit unable
// to read the file it must start with; ProblemOwner is a deviation from the
// documented security contract (root ownership) that does not by itself
// break service reads.
type ProblemKind string

const (
	ProblemMode    ProblemKind = "mode"
	ProblemGroup   ProblemKind = "group"
	ProblemOwner   ProblemKind = "owner"
	ProblemSymlink ProblemKind = "symlink"
	ProblemNotDir  ProblemKind = "notdir"
)

// Problem is one violated element of the converged permission chain.
type Problem struct {
	Kind ProblemKind
	Path string
	// Detail is a human-readable, secret-free description of the delta.
	Detail string
}

// String renders "kind: detail".
func (p Problem) String() string { return string(p.Kind) + ": " + p.Detail }

// AuditStateDir inspects the canonical state directory (/etc/split-tunnel).
// It never mutates anything.
func AuditStateDir() (StateDirAudit, error) { return AuditStateDirAt(stateDir) }

// AuditStateDirAt inspects an explicit state directory. Production uses
// AuditStateDir (the canonical path); the parameterized form exists so the
// read-only checks can be exercised against a temporary tree and so a
// doctor run with SPLITTERCTL_STATE_ROOT audits the root it was pointed at.
// It never mutates anything.
func AuditStateDirAt(dir string) (StateDirAudit, error) {
	a := StateDirAudit{
		Path:      dir,
		Linux:     runtime.GOOS == "linux",
		Uid:       -1,
		GID:       -1,
		GroupWant: -1,
		WantDir:   0o750,
		WantFile:  0o640,
	}
	st, err := os.Lstat(dir)
	switch {
	case os.IsNotExist(err):
		return a, nil // absent: not drift, just nothing installed
	case err != nil:
		return a, fmt.Errorf("systemd: audit: stat %s: %w", dir, err)
	}
	a.Exists = true
	if st.Mode()&os.ModeSymlink != 0 {
		a.Symlink = true
		return a, nil
	}
	if !st.IsDir() {
		a.NotDir = true // the mode facts are meaningless on a non-directory
		return a, nil
	}
	a.Mode = st.Mode().Perm()
	// One NSS lookup for the wanted group (read-only). An unresolvable group
	// means this host has never run the deployment, so the group element of
	// the contract is not applicable rather than a false finding.
	if gid, gerr := lookupGroupGID(ServiceGroup); gerr == nil {
		a.GroupWant, a.GroupKnown = gid, true
	}
	if a.Linux {
		a.Uid, a.GID = uidOf(st.Sys()), gidOf(st.Sys())
	}
	for _, name := range liveStateFiles {
		p := dir + "/" + name
		fst, ferr := os.Lstat(p)
		if ferr != nil {
			if os.IsNotExist(ferr) {
				continue // not installed yet
			}
			return a, fmt.Errorf("systemd: audit: stat %s: %w", p, ferr)
		}
		f := ConfigAudit{Path: p, Mode: fst.Mode().Perm(), Uid: -1, GID: -1}
		if a.Linux {
			f.Uid, f.GID = uidOf(fst.Sys()), gidOf(fst.Sys())
		}
		a.Configs = append(a.Configs, f)
	}
	return a, nil
}

// Problems returns every element of the converged contract that the audited
// state violates, in a stable order (empty when clean, absent, or when the
// Unix facts are not measurable on this host).
func (a StateDirAudit) Problems() []Problem {
	if !a.Exists {
		return nil
	}
	if a.Symlink {
		return []Problem{{Kind: ProblemSymlink, Path: a.Path,
			Detail: fmt.Sprintf("%s is a symlink (the state dir must be a real directory)", a.Path)}}
	}
	if a.NotDir {
		return []Problem{{Kind: ProblemNotDir, Path: a.Path,
			Detail: fmt.Sprintf("%s exists but is not a directory", a.Path)}}
	}
	if !a.Linux {
		return nil // Windows/dev host: the owner+mode bits do not exist here
	}
	var out []Problem
	if a.Mode != a.WantDir {
		out = append(out, Problem{Kind: ProblemMode, Path: a.Path,
			Detail: fmt.Sprintf("%s mode is %04o, want %04o", a.Path, a.Mode, a.WantDir)})
	}
	if a.Uid != 0 {
		out = append(out, Problem{Kind: ProblemOwner, Path: a.Path,
			Detail: fmt.Sprintf("%s is owned by uid %d, want root (uid 0)", a.Path, a.Uid)})
	}
	if a.GroupKnown && a.GID != a.GroupWant {
		out = append(out, Problem{Kind: ProblemGroup, Path: a.Path,
			Detail: fmt.Sprintf("%s group is gid %d, want %s (gid %d)", a.Path, a.GID, ServiceGroup, a.GroupWant)})
	}
	for _, f := range a.Configs {
		if f.Mode != a.WantFile {
			out = append(out, Problem{Kind: ProblemMode, Path: f.Path,
				Detail: fmt.Sprintf("%s mode is %04o, want %04o", f.Path, f.Mode, a.WantFile)})
		}
		if f.Uid != 0 {
			out = append(out, Problem{Kind: ProblemOwner, Path: f.Path,
				Detail: fmt.Sprintf("%s is owned by uid %d, want root (uid 0)", f.Path, f.Uid)})
		}
		if a.GroupKnown && f.GID != a.GroupWant {
			out = append(out, Problem{Kind: ProblemGroup, Path: f.Path,
				Detail: fmt.Sprintf("%s group is gid %d, want %s (gid %d)", f.Path, f.GID, ServiceGroup, a.GroupWant)})
		}
	}
	return out
}
