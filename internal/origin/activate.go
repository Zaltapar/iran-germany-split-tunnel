package origin

// activate.go — transactional activation of the generated Caddyfile
// (design §3.1). Mirrors internal/xray/activate.go but closes the
// rollback-artifact hole found in review HIGH-3.
//
// The sequence is strictly ordered and fail-closed:
//
//  1. ctx check — a canceled Ctx aborts BEFORE any filesystem mutation
//     (review HIGH-2: cancellation must not begin a new mutation);
//  2. render — validated Plan → deterministic bytes (RenderCaddyfile;
//     any validation failure changes nothing);
//  3. write tmp — <dir>/<file>.tmp created with 0600 (O_EXCL), fsync'd;
//  4. gate — the pinned binary's own `caddy validate --config`
//     validates the candidate BEFORE it becomes live; on failure the
//     tmp is removed and the directory is left byte-identical, NOTHING
//     is (re)started;
//  5. backup — the previous live Caddyfile (if any) is preserved as
//     <dir>/<file>.prev with 0600 (rollback artifact). An EXISTING .prev
//     is first snapshotted in memory and re-mapped aside as
//     .prev.old (same-directory rename) so a later failure can restore
//     it byte-identically — the live/candidate/rollback set is ONE
//     transaction (review HIGH-3);
//  6. swap — os.Rename(tmp, live) is atomic on the same filesystem. If
//     the swap fails, the ENTIRE pre-activation file set (live, prev,
//     prev.tmp, tmp) is restored byte-identically.
//
// Secret hygiene: the Caddyfile carries only public facts (domain,
// upstream, timeouts) — NO secret ever reaches the file or the gate.
//
// Filesystem safety: the target dir must exist and be a directory;
// EVERY managed transaction path (live, tmp, prev, prev.tmp) is Lstat
// checked and a symlink / special object is refused — a pre-planted
// link cannot redirect a 0600 write (review HIGH-3). The tmp name is
// fixed and created O_EXCL, so two concurrent activations cannot
// clobber each other (the second fails on the existing tmp).
//
// No service restart (T5's job, design D6).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrActivateDir: the target directory or file name is not
	// acceptable (missing, not a directory, traversal attempt, path
	// separators).
	ErrActivateDir = errors.New("origin: activate: invalid target directory or file name")
	// ErrActivateTarget: an existing managed object (live, tmp, prev,
	// prev.tmp) at the target path is a symlink or not a regular file.
	ErrActivateTarget = errors.New("origin: activate: refusing unsafe existing target (symlink or non-regular file)")
	// ErrActivateWrite: the candidate Caddyfile could not be written
	// (permissions, disk). No live file was touched.
	ErrActivateWrite = errors.New("origin: activate: failed to write candidate Caddyfile (live file untouched)")
	// ErrActivateRename: the atomic swap failed. The previous file set —
	// live Caddyfile AND any pre-existing rollback artifact — is restored
	// byte-identical and the candidate is removed.
	ErrActivateRename = errors.New("origin: activate: failed to swap Caddyfile into place (previous file set restored)")
)

// ActivateParams is the full input to ActivateCaddyfile. Dir is the
// project config directory (T5: /etc/split-tunnel, 0700); FileName is
// the live Caddyfile name inside it (default below).
type ActivateParams struct {
	Plan     Plan
	Dir      string
	FileName string // default "Caddyfile"
	Bin      string // path to the pinned caddy binary
	// Exec is the managed boundary (default OSExecutor); tests
	// substitute a fake to exercise gate ordering hermetically.
	Exec Executor
	// Rename is the atomic-swap + aside-mapping seam (default
	// os.Rename). It is a field so a deterministic final-swap failure is
	// injectable in tests (review HIGH-3): the transaction must restore
	// the FULL pre-state — live, candidate, rollback AND rollback-temp —
	// on such a failure.
	Rename func(oldpath, newpath string) error
	// Ctx bounds the transaction. A canceled Ctx aborts before any
	// filesystem mutation and returns context.Canceled /
	// context.DeadlineExceeded (review HIGH-2); it is also threaded into
	// the validate gate. Nil means context.Background().
	Ctx context.Context
}

const defaultCaddyFileName = "Caddyfile"

// ActivateCaddyfile renders the Caddyfile for the Plan and atomically
// activates it behind the pinned binary's own `caddy validate --config`
// gate. On success it returns the live path; on any failure the
// previous file set (live + .prev rollback artifact, if any) is
// byte-identical and no candidate file remains.
func ActivateCaddyfile(a ActivateParams) (string, error) {
	if err := a.Plan.validate(); err != nil {
		return "", err
	}
	out, err := RenderCaddyfile(a.Plan)
	if err != nil {
		return "", err
	}
	return activateRendered(a, out)
}

// activateRendered is the transaction engine behind ActivateCaddyfile,
// parameterized by the already-rendered candidate bytes. It exists so a
// test can activate EXACTLY a golden byte string (a changed plan that
// renders byte-identical must still exercise the changed-plan path).
// Callers outside tests use ActivateCaddyfile.
func activateRendered(a ActivateParams, out []byte) (string, error) {
	ctx := a.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// Cancellation must abort BEFORE any filesystem mutation (HIGH-2).
	if err := ctx.Err(); err != nil {
		return "", err
	}
	rename := a.Rename
	if rename == nil {
		rename = os.Rename
	}

	// Traversal is rejected on the RAW input (filepath.Clean would
	// resolve ".." away before the guard could see it). Both separator
	// styles are checked (Windows accepts / as well as \).
	if a.Dir == "" || a.Dir == "." {
		return "", fmt.Errorf("%w: directory is empty", ErrActivateDir)
	}
	for _, sep := range []string{string(os.PathSeparator), "/"} {
		for _, comp := range strings.Split(a.Dir, sep) {
			if comp == ".." {
				return "", fmt.Errorf("%w: directory contains a .. component", ErrActivateDir)
			}
		}
	}
	dir := filepath.Clean(a.Dir)
	file := a.FileName
	if file == "" {
		file = defaultCaddyFileName
	}
	if file == "." || file == ".." || file != filepath.Base(file) {
		return "", fmt.Errorf("%w: file name must be a plain name (no path)", ErrActivateDir)
	}
	// The directory must already exist and be a real directory (T5
	// creates it 0700); we never create the project prefix ourselves.
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%w: %s must exist and be a directory", ErrActivateDir, dir)
	}

	live := filepath.Join(dir, file)
	tmp := live + ".tmp"
	prev := live + ".prev"
	prevOld := prev + ".old"
	prevTmp := prev + ".tmp"

	// --- existing live file: must be a regular file, not a symlink ---
	oldExists := false
	var oldBytes []byte
	if st, err := os.Lstat(live); err == nil {
		if !st.Mode().IsRegular() {
			return "", fmt.Errorf("%w: %s is a symlink or special file", ErrActivateTarget, live)
		}
		oldBytes, err = os.ReadFile(live)
		if err != nil {
			return "", fmt.Errorf("%w: cannot read previous Caddyfile: %v", ErrActivateWrite, err)
		}
		oldExists = true
	}

	// --- existing rollback artifact: regular file is preserved (its
	// bytes are snapshotted so the whole transaction can roll BACK to
	// it); anything else is a planted object (refuse) ---
	prevExists := false
	var prevBytes []byte
	if st, err := os.Lstat(prev); err == nil {
		if !st.Mode().IsRegular() {
			return "", fmt.Errorf("%w: %s is a symlink or special file", ErrActivateTarget, prev)
		}
		prevBytes, err = os.ReadFile(prev)
		if err != nil {
			return "", fmt.Errorf("%w: cannot read existing rollback artifact: %v", ErrActivateWrite, err)
		}
		prevExists = true
	}

	// --- leftover tmp from a crashed run: regular file is ours
	// (delete); anything else is a planted object (refuse) ---
	if st, err := os.Lstat(tmp); err == nil {
		if !st.Mode().IsRegular() {
			return "", fmt.Errorf("%w: %s is a symlink or special file", ErrActivateTarget, tmp)
		}
		if err := os.Remove(tmp); err != nil {
			return "", fmt.Errorf("%w: cannot remove stale tmp: %v", ErrActivateWrite, err)
		}
	}

	// --- leftover rollback-temp / aside-mapping from a crashed run:
	// refuse a planted object; a regular leftover is removed before we
	// claim the name (writeFile0600 creates .prev.tmp O_EXCL, and a
	// stale .prev.old would confuse the failure-path restore) ---
	for _, stale := range []string{prevTmp, prevOld} {
		if st, err := os.Lstat(stale); err == nil {
			if !st.Mode().IsRegular() {
				return "", fmt.Errorf("%w: %s is a symlink or special file", ErrActivateTarget, stale)
			}
			if err := os.Remove(stale); err != nil {
				return "", fmt.Errorf("%w: cannot remove stale transaction residue: %v", ErrActivateWrite, err)
			}
		}
	}

	// Cancellation after the pre-flight reads, before the first write.
	if err := ctx.Err(); err != nil {
		return "", err
	}

	// --- write the candidate: 0600 from creation, fsync before the
	// gate. O_EXCL makes create fail if the tmp exists (a planted
	// object was already Lstat-refused above). ---
	candidate, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrActivateWrite, err)
	}
	_, werr := candidate.Write(out)
	serr := candidate.Sync()
	cerr := candidate.Close()
	if werr != nil || serr != nil || cerr != nil {
		candidate.Close()
		os.Remove(tmp)
		return "", fmt.Errorf("%w: %v", ErrActivateWrite, firstErr(werr, serr, cerr))
	}

	// --- gate: the pinned binary validates the candidate itself ---
	exec := a.Exec
	if exec == nil {
		exec = OSExecutor{}
	}
	if out2, gerr := exec.Validate(ctx, a.Bin, tmp); gerr != nil {
		os.Remove(tmp)
		// caddy validate/adapt error lines reference the config path
		// + directive (public facts) and never a secret — a bounded
		// excerpt is safe (design §3.4).
		return "", fmt.Errorf("%w: %v; caddy output: %s", ErrConfigGate, gerr, excerpt(out2))
	}

	// Cancellation must abort before the irreversible phase (the
	// backup/aside rewrites); the candidate is removed and the previous
	// file set stays byte-identical.
	if err := ctx.Err(); err != nil {
		os.Remove(tmp)
		return "", err
	}

	// --- backup the previous live Caddyfile (rollback artifact, 0600).
	// An EXISTING .prev is part of the transaction: map it aside to
	// .prev.old first (in-memory snapshot already taken above) so a
	// later failure restores it byte-identically. ---
	mappedAside := false
	wrotePrev := false
	if prevExists {
		if err := rename(prev, prevOld); err != nil {
			os.Remove(tmp)
			return "", fmt.Errorf("%w: cannot preserve existing rollback artifact: %v", ErrActivateWrite, err)
		}
		mappedAside = true
	}
	if oldExists {
		if err := writeFile0600(prev, oldBytes); err != nil {
			os.Remove(tmp)
			if mappedAside {
				_ = rename(prevOld, prev)
			}
			return "", fmt.Errorf("%w: cannot write rollback backup: %v", ErrActivateWrite, err)
		}
		wrotePrev = true
	}

	// --- atomic swap (same filesystem) ---
	if err := rename(tmp, live); err != nil {
		// Restore the FULL pre-activation file set (HIGH-3): the swap
		// failed, so live still holds oldBytes (if any); remove the
		// candidate, undo the new .prev write, and re-map a pre-existing
		// .prev back from .prev.old.
		os.Remove(tmp)
		if wrotePrev {
			os.Remove(prev)
		}
		if mappedAside {
			if rerr := rename(prevOld, prev); rerr != nil {
				// The restore failed (already reported fs trouble); fall
				// back to the in-memory snapshot so the artifact is not
				// silently lost.
				_ = writeFile0600(prev, prevBytes)
			}
		}
		return "", fmt.Errorf("%w: %v", ErrActivateRename, err)
	}
	// Success: drop the aside mapping (the pre-activation rollback
	// artifact is superseded by the new one, which now holds the
	// previous live bytes).
	if mappedAside {
		_ = os.Remove(prevOld)
	}
	return live, nil
}

// writeFile0600 writes data to path with 0600 from creation (tmp +
// rename in the same directory), fsyncing before the swap. Used for
// the .prev rollback artifact.
func writeFile0600(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		f.Close()
		os.Remove(tmp)
		return firstErr(werr, serr, cerr)
	}
	return os.Rename(tmp, path)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
