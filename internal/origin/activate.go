package origin

// activate.go — transactional activation of the generated Caddyfile
// (design §3.1). Mirrors internal/xray/activate.go.
//
// The sequence is strictly ordered and fail-closed:
//
//  1. render — validated Plan → deterministic bytes (RenderCaddyfile;
//     any validation failure changes nothing);
//  2. write tmp — <dir>/<file>.tmp created with 0600 (O_EXCL), fsync'd;
//  3. gate — the pinned binary's own `caddy validate --config`
//     validates the candidate BEFORE it becomes live; on failure the
//     tmp is removed and the directory is left byte-identical, NOTHING
//     is (re)started;
//  4. backup — the previous live Caddyfile (if any) is preserved as
//     <dir>/<file>.prev with 0600 (rollback artifact);
//  5. swap — os.Rename(tmp, live) is atomic on the same filesystem.
//
// Secret hygiene: the Caddyfile carries only public facts (domain,
// upstream, timeouts) — NO secret ever reaches the file or the gate.
//
// Filesystem safety: the target dir must exist and be a directory; an
// existing live file or leftover tmp that is a SYMLINK (or not a
// regular file) is refused — a pre-planted link cannot redirect the
// 0600 write. The tmp name is fixed and created O_EXCL, so two
// concurrent activations cannot clobber each other (the second fails
// on the existing tmp).
//
// No service restart (T5's job, design D6).

import (
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
	// ErrActivateTarget: an existing live file or leftover tmp at the
	// target path is a symlink or not a regular file.
	ErrActivateTarget = errors.New("origin: activate: refusing unsafe existing target (symlink or non-regular file)")
	// ErrActivateWrite: the candidate Caddyfile could not be written
	// (permissions, disk). No live file was touched.
	ErrActivateWrite = errors.New("origin: activate: failed to write candidate Caddyfile (live file untouched)")
	// ErrActivateRename: the atomic swap failed. The previous live
	// Caddyfile (if any) is untouched and the candidate is removed.
	ErrActivateRename = errors.New("origin: activate: failed to swap Caddyfile into place (previous file untouched)")
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
}

const defaultCaddyFileName = "Caddyfile"

// ActivateCaddyfile renders the Caddyfile for the Plan and atomically
// activates it behind the pinned binary's own `caddy validate --config`
// gate. On success it returns the live path; on any failure the
// previous live Caddyfile (if any) is byte-identical and no candidate
// file remains.
func ActivateCaddyfile(a ActivateParams) (string, error) {
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

	out, err := RenderCaddyfile(a.Plan)
	if err != nil {
		return "", err
	}

	live := filepath.Join(dir, file)
	tmp := live + ".tmp"
	prev := live + ".prev"

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
	if out2, gerr := exec.Validate(a.Bin, tmp); gerr != nil {
		os.Remove(tmp)
		// caddy validate/adapt error lines reference the config path
		// + directive (public facts) and never a secret — a bounded
		// excerpt is safe (design §3.4).
		return "", fmt.Errorf("%w: %v; caddy output: %s", ErrConfigGate, gerr, excerpt(out2))
	}

	// --- backup the previous live Caddyfile (rollback artifact, 0600) ---
	if oldExists {
		if err := writeFile0600(prev, oldBytes); err != nil {
			os.Remove(tmp)
			return "", fmt.Errorf("%w: cannot write rollback backup: %v", ErrActivateWrite, err)
		}
	}

	// --- atomic swap (same filesystem) ---
	if err := os.Rename(tmp, live); err != nil {
		os.Remove(tmp)
		if oldExists {
			os.Remove(prev) // restore the exact pre-activation file set
		}
		return "", fmt.Errorf("%w: %v", ErrActivateRename, err)
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
