package xray

// activate.go — transactional activation of the generated Germany Xray
// config (design doc plans/t3-design.md §3.1/§3.5/§3.6; spec items 7–11).
//
// The sequence is strictly ordered and fail-closed:
//
//  1. render      — validated params + keypair → deterministic bytes
//     (RenderGermanyConfig; any validation failure changes nothing);
//  2. write tmp   — <dir>/<file>.tmp created with 0600 (O_EXCL), fsync'd;
//  3. gate        — the pinned binary's own `xray run -test` validates the
//     candidate BEFORE it becomes live; on failure the tmp is removed and
//     the directory is left byte-identical, NOTHING is (re)started;
//  4. backup      — the previous live config (if any) is preserved as
//     <dir>/<file>.prev with 0600 (rollback artifact; it contains the
//     previous private key, hence the explicit permission);
//  5. swap        — os.Rename(tmp, live) is atomic on the same filesystem.
//
// Secret hygiene: xray's own decode-error path ECHOES the privateKey value
// (verified at the pinned tag: infra/conf REALITYConfig.Build builds the
// error with the key string). Therefore the gate-failure error excerpt is
// masked with maskSecrets before it is returned — no rendered-config bytes
// or key material ever reach an error string, a log line, or the journal.
//
// Filesystem safety: the target dir must exist and be a directory; an
// existing live file or leftover tmp that is a SYMLINK (or not a regular
// file) is refused — a pre-planted link cannot redirect the 0600 write.
// The tmp name is fixed and created O_EXCL, so two concurrent activations
// cannot clobber each other (the second fails on the existing tmp).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrActivateDir: the target directory or file name is not acceptable
	// (missing, not a directory, traversal attempt, path separators).
	ErrActivateDir = errors.New("xray: activate: invalid target directory or file name")
	// ErrActivateTarget: an existing live file or leftover tmp at the
	// target path is a symlink or not a regular file (refusing to write
	// through or over unsafe filesystem objects).
	ErrActivateTarget = errors.New("xray: activate: refusing unsafe existing target (symlink or non-regular file)")
	// ErrActivateWrite: the candidate config could not be written
	// (permissions, disk). No live file was touched.
	ErrActivateWrite = errors.New("xray: activate: failed to write candidate config (live config untouched)")
	// ErrActivateRename: the atomic swap failed. The previous live config
	// (if any) is untouched and the candidate is removed.
	ErrActivateRename = errors.New("xray: activate: failed to swap config into place (previous config untouched)")
)

// ActivateParams is the full input to ActivateGermanyConfig. Dir is the
// project config directory (T5: /etc/split-tunnel, 0700); FileName is the
// live config file name inside it (default below).
type ActivateParams struct {
	Params   RealityParams
	Keypair  *Keypair
	Dir      string
	FileName string // default "xray-germany.json"
	Bin      string // path to the pinned xray binary
	// Exec is the managed-transport boundary (default OSExecutor);
	// tests substitute a fake to exercise gate ordering hermetically.
	Exec Executor
}

const defaultConfigFileName = "xray-germany.json"

// ActivateGermanyConfig renders the Germany Xray config and atomically
// activates it behind the pinned binary's own `xray run -test` gate. On
// success it returns the live path; on any failure the previous live
// config (if any) is byte-identical and no candidate file remains.
func ActivateGermanyConfig(a ActivateParams) (string, error) {
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
		file = defaultConfigFileName
	}
	if file == "." || file == ".." || file != filepath.Base(file) {
		return "", fmt.Errorf("%w: file name must be a plain name (no path)", ErrActivateDir)
	}
	// The directory must already exist and be a real directory (T5
	// creates it 0700); we never create the project prefix ourselves.
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%w: %s must exist and be a directory", ErrActivateDir, dir)
	}

	out, err := RenderGermanyConfig(a.Params, a.Keypair)
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
			return "", fmt.Errorf("%w: cannot read previous config: %v", ErrActivateWrite, err)
		}
		oldExists = true
	}

	// --- leftover tmp from a crashed run: regular file is ours (delete);
	// anything else is a planted object (refuse) ---
	if st, err := os.Lstat(tmp); err == nil {
		if !st.Mode().IsRegular() {
			return "", fmt.Errorf("%w: %s is a symlink or special file", ErrActivateTarget, tmp)
		}
		if err := os.Remove(tmp); err != nil {
			return "", fmt.Errorf("%w: cannot remove stale tmp: %v", ErrActivateWrite, err)
		}
	}

	// --- write the candidate: 0600 from creation, fsync before the gate.
	// O_EXCL makes create fail if the tmp exists (a planted object was
	// already Lstat-refused above); the bounded Lstat→create TOCTOU is
	// accepted per design §6 (same prefix, 0700 dir, single deploy user). ---
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
	if out2, gerr := exec.RunTest(a.Bin, tmp); gerr != nil {
		os.Remove(tmp)
		// xray's decode error can echo the privateKey value — mask the
		// exact key strings before any excerpt leaves this function.
		// Both base64 alphabets are masked (the rendered config embeds
		// the Raw form; the Std form is masked as defense-in-depth in
		// case a future error path surfaces it).
		kp := a.Keypair
		masked := maskSecrets(out2, kp.PrivateRaw, kp.PublicRaw, kp.PrivateStd, kp.PublicStd)
		return "", fmt.Errorf("%w: %v; xray output: %s", ErrConfigGate, gerr, excerpt(masked))
	}

	// --- backup the previous live config (rollback artifact, 0600) ---
	if oldExists {
		if err := writeSecretFile(prev, oldBytes); err != nil {
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

// writeSecretFile writes data to path with 0600 from creation (tmp +
// rename in the same directory), fsyncing before the swap. Used for the
// .prev rollback artifact, which contains the previous private key.
func writeSecretFile(path string, data []byte) error {
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

// maskSecrets replaces each non-empty secret string with a fixed marker,
// then bounds the result. It is the single choke point through which any
// xray output that may embed key material passes on its way to an error
// string.
func maskSecrets(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "<redacted>")
		}
	}
	return s
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
