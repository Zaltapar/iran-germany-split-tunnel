package origin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Install/supply-chain errors. None of them include file contents or
// downloaded bytes.
var (
	ErrDownload       = errors.New("origin: download failed")
	ErrExtract        = errors.New("origin: extraction failed")
	ErrTarEntry       = errors.New("origin: unsafe or oversized tar entry (refusing)")
	ErrSmokeCheck     = errors.New("origin: 'caddy version' smoke check failed (binary not runnable)")
	ErrConfigGate     = errors.New("origin: 'caddy validate --config' rejected the generated Caddyfile (install aborted before any service change)")
	ErrInstallAborted = errors.New("origin: install aborted; no service was started and the previous version (if any) is untouched")
)

// Downloader fetches a release asset. It is a type so tests substitute
// local bytes — the install logic itself is network-independent. The
// ctx is authoritative (review HIGH-2): a canceled ctx aborts the fetch.
type Downloader interface {
	Fetch(ctx context.Context, url string) (io.ReadCloser, error)
}

// HTTPDownloader is the production Downloader (stdlib HTTP client;
// redirect-following, TLS by default — github.com release URLs).
type HTTPDownloader struct{}

// Fetch implements Downloader.
func (HTTPDownloader) Fetch(ctx context.Context, url string) (io.ReadCloser, error) {
	resp, err := httpGet(ctx, url)
	if err != nil {
		// Preserve the cancellation/deadline class: httpGet already
		// returns context.Canceled/DeadlineExceeded unwrapped for a
		// canceled ctx — propagate it as-is (HIGH-2), do not wrap it in
		// ErrDownload.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrDownload, err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("%w: upstream returned status %d", ErrDownload, resp.StatusCode)
	}
	return resp.Body, nil
}

// Executor is the managed boundary to the caddy binary. The installer
// and activator shell out through this interface so every L1/L2 test
// runs against a fake. Every call carries a ctx (review HIGH-2): the
// production implementation uses exec.CommandContext, so a canceled ctx
// kills the child process.
type Executor interface {
	// VersionOutput runs "<bin> version" and returns its combined
	// output. The installer checks that its FIRST field equals the
	// pinned version (output is "v2.11.4 h1:<build-hash>").
	VersionOutput(ctx context.Context, bin string) (string, error)
	// Validate runs "<bin> validate --config <cfg>" and returns the
	// combined output. Non-nil error or non-zero exit = the gate
	// failed and NOTHING may be (re)started.
	Validate(ctx context.Context, bin, config string) (string, error)
}

// OSExecutor runs the real binary. exec.CommandContext is used for
// every invocation (HIGH-2), so a canceled/deadline-exceeded ctx kills
// the child and returns promptly; the child is additionally bounded by
// commandTimeout so a wedged binary cannot block a deploy forever.
type OSExecutor struct{}

// commandTimeout bounds a single caddy subcommand (version / validate).
// Both are local, sub-second operations on a healthy host; the cap is
// deliberately generous so it only trips on a genuinely wedged process.
const commandTimeout = 2 * time.Minute

// VersionOutput implements Executor.
func (OSExecutor) VersionOutput(ctx context.Context, bin string) (string, error) {
	return runCombined(ctx, bin, "version")
}

// Validate implements Executor.
func (OSExecutor) Validate(ctx context.Context, bin, config string) (string, error) {
	return runCombined(ctx, bin, "validate", "--config", config)
}

func runCombined(ctx context.Context, name string, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Bound the child by the caller's ctx AND the executor cap
	// (whichever ends first): a caller with no deadline still cannot
	// hang forever on a wedged binary.
	cctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	out, err := cmd.CombinedOutput()
	// Cancellation is reported as the ctx error itself (HIGH-2:
	// callers must see context.Canceled / context.DeadlineExceeded, not
	// a bare "signal: killed").
	if ctxErr := ctx.Err(); ctxErr != nil {
		return string(out), ctxErr
	}
	if ctxErr := cctx.Err(); ctxErr != nil && err != nil {
		return string(out), ctxErr
	}
	if err != nil {
		// Return the output alongside the error: the gates embed a
		// bounded excerpt (see excerpt) so a rejected Caddyfile is
		// diagnosable. The generated Caddyfile carries only public
		// facts and caddy error lines do not echo secrets, so a
		// bounded echo is safe (design §3.4).
		return string(out), fmt.Errorf("origin: %v", err)
	}
	return string(out), nil
}

// Installer installs a pinned Caddy release into the project prefix
// (versioned layout) and records the manifest. It is pure filesystem +
// Downloader + Executor: no systemd, no user management (T5). A
// re-install into an existing version dir fails fast unless Force.
//
// Force is TRANSACTIONAL (review HIGH-1): the candidate is downloaded,
// verified, extracted, smoke-checked and (optionally) config-gated in a
// STAGING directory BEFORE the existing version is touched, and the
// existing version dir is then exchanged through a same-filesystem
// backup name — a failure at ANY step leaves the pre-existing working
// version byte-identical.
type Installer struct {
	Prefix string
	DL     Downloader
	Exec   Executor
	Force  bool // overwrite an existing version dir

	// Chmod sets the executable bit on the installed binary. It is a
	// field (default: os.Chmod) so a failure is injectable in tests.
	Chmod func(path string, mode os.FileMode) error
	// Rename is the same-filesystem exchange seam (default os.Rename).
	// It is a field so the two renames of the Force exchange (live→
	// backup, candidate→live) are failure-injectable in tests (HIGH-1).
	Rename func(oldpath, newpath string) error
}

// Installed records what Install placed on disk (the manifest row).
type Installed struct {
	Version     string    `json:"version"`
	Arch        string    `json:"arch"`
	TarURL      string    `json:"tarUrl"`
	TarSHA512   string    `json:"tarSha512"` // the checksums.txt value, verified
	Path        string    `json:"path"`      // absolute path of the caddy binary
	InstalledAt time.Time `json:"installedAt"`
}

// Install runs the full pipeline (design §3.5):
//
//  1. resolve version+arch → tar.gz URL + checksums.txt URL
//  2. download tar.gz + checksums.txt
//  3. parse checksums.txt (fail closed if no SHA-512 line for the tar)
//  4. verify tar.gz SHA-512 (constant time; fail closed on mismatch)
//  5. extract into a STAGING dir (tar-slip + size caps)
//  6. stage → CANDIDATE dir inside the prefix (same filesystem)
//  7. chmod + `caddy version` smoke check on the CANDIDATE (first field
//     == version) + `caddy validate --config <cfg>` gate (if cfg given)
//  8. exchange: rename existing version dir → <version>.old, rename
//     candidate → version dir, remove the backup on success; ANY
//     failure restores the existing dir (HIGH-1: the known-good pinned
//     version survives every injected failure)
//
// On ANY failure the staged/candidate/backup residue is removed and the
// pre-existing version dir (if any) is left byte-identical. The ctx
// bounds every download and binary invocation; a canceled ctx aborts
// before the candidate is built and before the existing version is
// touched (HIGH-2).
func (in *Installer) Install(ctx context.Context, version string, arch CaddyArch, testConfig string) (*Installed, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if in.Prefix == "" {
		return nil, fmt.Errorf("origin: empty prefix")
	}
	if !ValidVersion(version) {
		return nil, fmt.Errorf("origin: invalid version %q", version)
	}
	if in.DL == nil {
		in.DL = HTTPDownloader{}
	}
	if in.Exec == nil {
		in.Exec = OSExecutor{}
	}
	if in.Chmod == nil {
		in.Chmod = os.Chmod
	}
	if in.Rename == nil {
		in.Rename = os.Rename
	}
	tarURL, err := TarURL(version, arch)
	if err != nil {
		return nil, err
	}
	ckURL, err := ChecksumURL(version)
	if err != nil {
		return nil, err
	}
	tarName, err := TarName(version, arch)
	if err != nil {
		return nil, err
	}

	// The existing version dir is resolved and safety-checked BEFORE any
	// network or staging work: refuse symlinks/non-directories before any
	// recursive removal or rename can ever reach them (HIGH-1).
	versionDir, err := VersionDir(in.Prefix, version)
	if err != nil {
		return nil, err
	}
	// Step 0 (review HIGH-R2-1): reconcile residue from a CRASHED force
	// exchange BEFORE detecting the existing version. A lone
	// <version>.old with no live peer is the only copy of a previously
	// working version (the crash landed between the two exchange
	// renames) and is restored first, so the detection below sees the
	// true state and the next install can never sweep it away.
	// Ambiguous or unsafe residue fails closed here, before any network
	// work.
	if err := in.reconcileInstallResidue(); err != nil {
		return nil, err
	}
	existing := false
	if st, serr := os.Lstat(versionDir); serr == nil {
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("origin: refusing to touch %s (symlink or non-directory); remove it manually first", versionDir)
		}
		if !in.Force {
			return nil, fmt.Errorf("origin: %s already exists (use Force to overwrite); existing versions are preserved for rollback", versionDir)
		}
		existing = true
	}

	// Cancellation must abort before any download or mutation (HIGH-2).
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Step 2-3: fetch the checksums file and parse the SHA-512 line.
	ckData, err := fetchChecksums(ctx, in.DL, ckURL)
	if err != nil {
		return nil, err
	}
	sha512Hex, err := ParseChecksumFile(ckData, tarName)
	if err != nil {
		return nil, err
	}

	// Step 4: buffer the tar.gz (bounded) and verify in constant time.
	// Buffering keeps the verify→extract order clean and re-reads the
	// same bytes.
	tarBody, err := in.DL.Fetch(ctx, tarURL)
	if err != nil {
		return nil, err
	}
	defer tarBody.Close()
	tarBytes, err := readBounded(tarBody, maxExtractedBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: tar", ErrDownload)
	}
	if err := VerifyFile(tarBytes, sha512Hex); err != nil {
		return nil, err
	}

	// Step 5: stage INSIDE the prefix so the candidate build and the
	// final exchange are atomic same-filesystem renames on Linux. Stale
	// stage/candidate/backup dirs from a crashed install are swept first
	// (prefix-scoped only, regular directories only).
	stage, err := prepareStageDir(in.Prefix)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	if err := extractTar(tarBytes, stage); err != nil {
		return nil, err
	}

	// Cancellation before the candidate appears in the layout.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Step 6: materialize the CANDIDATE at a distinct fixed name inside
	// the prefix (NOT the live version dir). The existing version stays
	// untouched through every validation step (HIGH-1).
	candidateDir := versionDir + ".new"
	cleanupRefuse := refuseUnsafeDir(candidateDir)
	if cleanupRefuse != nil {
		return nil, cleanupRefuse
	}
	if err := in.Rename(stage, candidateDir); err != nil {
		// Cross-device fallback: move the single expected tree.
		if err := moveTree(stage, candidateDir); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInstallAborted, err)
		}
	}
	candidateOK := false
	defer func() {
		if !candidateOK {
			cleanupVersionDir(candidateDir)
		}
	}()
	bin := filepath.Join(candidateDir, "caddy")
	if err := in.Chmod(bin, 0o755); err != nil {
		return nil, fmt.Errorf("origin: chmod: %w", err)
	}

	// Step 7: smoke check — the FIRST field of `caddy version` must
	// equal the pinned version ("v2.11.4 h1:<hash>").
	out, err := in.Exec.VersionOutput(ctx, bin)
	if err != nil || firstField(out) != version {
		reason := "first field of 'caddy version' != " + version
		if err != nil {
			reason = err.Error()
		}
		return nil, fmt.Errorf("%w: %s; caddy output: %s", ErrSmokeCheck, reason, excerpt(out))
	}

	// Step 8: config gate. A rejected Caddyfile aborts BEFORE any
	// service (re)start and before the existing version is touched.
	if testConfig != "" {
		out, err := in.Exec.Validate(ctx, bin, testConfig)
		if err != nil {
			return nil, fmt.Errorf("%w: %s; caddy output: %s", ErrConfigGate, err, excerpt(out))
		}
	}

	// Cancellation after the candidate is fully validated, before the
	// existing version is moved (HIGH-2: no new mutation once canceled).
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Step 9 (Force only): exchange the existing dir for the candidate
	// through a same-filesystem backup name. Rename is atomic on POSIX,
	// so after BOTH renames the live dir is the candidate; if EITHER
	// rename fails, the existing dir is restored/kept byte-identical.
	backupDir := versionDir + ".old"
	if existing {
		if err := refuseUnsafeDir(backupDir); err != nil {
			return nil, err
		}
		if err := in.Rename(versionDir, backupDir); err != nil {
			return nil, fmt.Errorf("%w: moving existing version aside: %v", ErrInstallAborted, err)
		}
		backupRestorable := true
		defer func() {
			if backupRestorable {
				// Success path: the backup is removed below. Failure
				// paths restore it BEFORE this deferred cleanup runs.
				_ = backupRestorable
			}
		}()
		if err := in.Rename(candidateDir, versionDir); err != nil {
			// Second-step failure: put the existing dir back exactly
			// where it was (HIGH-1).
			if rerr := in.Rename(backupDir, versionDir); rerr != nil {
				return nil, fmt.Errorf("%w: activating candidate failed (%v) and restoring the previous version also failed (%v)", ErrInstallAborted, err, rerr)
			}
			return nil, fmt.Errorf("%w: activating candidate: %v (previous version restored)", ErrInstallAborted, err)
		}
		// Success: the candidate now IS the version dir; remove the old
		// backup. The candidate cleanup defer must not run.
		candidateOK = true
		if err := os.RemoveAll(backupDir); err != nil {
			// The live dir is already the new version; a backup that
			// could not be removed is residue, not a correctness failure.
			// Report it so the operator can clean up.
			return nil, fmt.Errorf("origin: installed but could not remove backup %s: %w", backupDir, err)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(versionDir), 0o755); err != nil {
			return nil, fmt.Errorf("origin: prefix: %w", err)
		}
		if err := in.Rename(candidateDir, versionDir); err != nil {
			// Cross-device fallback: move the single expected tree.
			if err := moveTree(candidateDir, versionDir); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInstallAborted, err)
			}
		}
		candidateOK = true
	}

	return &Installed{
		Version:     version,
		Arch:        string(arch),
		TarURL:      tarURL,
		TarSHA512:   sha512Hex,
		Path:        filepath.Join(versionDir, "caddy"),
		InstalledAt: time.Now().UTC(),
	}, nil
}

// refuseUnsafeDir removes path when it is a REGULAR directory (stale
// transaction residue from a crashed run is swept) and refuses —
// without touching — a symlink or non-directory object (HIGH-1: no
// recursive removal ever follows a planted link).
func refuseUnsafeDir(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return nil // absent: nothing to sweep
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("origin: refusing unsafe existing path %s (symlink or non-directory)", path)
	}
	return os.RemoveAll(path)
}

// prepareStageDir creates the staging directory inside the prefix (so
// the candidate build + the final exchange are atomic same-filesystem
// renames). It sweeps only the transient stage dirs it owns
// (.caddy-stage-*); the version-candidate (.new) and backup (.old)
// transaction names are reconciled exclusively by
// reconcileInstallResidue so the crash-recovery decision happens in
// exactly one place (HIGH-R2-1).
func prepareStageDir(prefix string) (string, error) {
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		return "", fmt.Errorf("origin: prefix: %w", err)
	}
	entries, err := os.ReadDir(prefix)
	if err != nil {
		return "", fmt.Errorf("origin: prefix: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".caddy-stage-") {
			_ = os.RemoveAll(filepath.Join(prefix, e.Name()))
		}
	}
	stage, err := os.MkdirTemp(prefix, ".caddy-stage-*")
	if err != nil {
		return "", fmt.Errorf("origin: staging: %w", err)
	}
	return stage, nil
}

// reconcileInstallResidue recovers the persistent states of a crashed
// force exchange (review HIGH-R2-1) and runs BEFORE Install detects the
// existing version, so the detection sees the true on-disk state:
//
//   - <version>.old with NO live peer: the crash landed between the two
//     exchange renames; the backup is the ONLY copy of a previously
//     working version and is restored atomically (in.Rename) to its
//     live name.
//   - <version>.old WITH a live peer: ambiguous (the candidate may
//     already be live); fail closed and refuse to clean either up.
//   - <version>.new: an abandoned candidate build; removed only after
//     Lstat proves it is a regular directory (never a symlink).
//   - any other residue at these names that is a symlink or
//     non-directory: refuse without touching it (a planted link must
//     never redirect a recursive removal).
func (in *Installer) reconcileInstallResidue() error {
	// The exchange seam may be unset when this runs standalone (tests,
	// future ops tools); default to the same os.Rename the production
	// Install path uses so the restore is never a nil-function call.
	rename := in.Rename
	if rename == nil {
		rename = os.Rename
	}
	caddyRoot := filepath.Join(in.Prefix, "caddy")
	sub, err := os.ReadDir(caddyRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("origin: cannot inspect caddy install residue: %w", err)
	}
	for _, e := range sub {
		name := e.Name()
		if strings.HasSuffix(name, ".new") {
			if err := removeRegularResidue(filepath.Join(caddyRoot, name)); err != nil {
				return err
			}
		}
	}
	for _, e := range sub {
		name := e.Name()
		if !strings.HasSuffix(name, ".old") {
			continue
		}
		backup := filepath.Join(caddyRoot, name)
		if err := requireRegularResidueDir(backup); err != nil {
			return err
		}
		live := filepath.Join(caddyRoot, strings.TrimSuffix(name, ".old"))
		_, err := os.Lstat(live)
		switch {
		case os.IsNotExist(err):
			if err := rename(backup, live); err != nil {
				return fmt.Errorf("origin: cannot restore interrupted install backup %s: %w", backup, err)
			}
		case err != nil:
			return fmt.Errorf("origin: cannot inspect interrupted install live version %s: %w", live, err)
		default:
			return fmt.Errorf("origin: ambiguous interrupted install: both %s and %s exist; refusing cleanup (remove one explicitly first)", live, backup)
		}
	}
	return nil
}

func removeRegularResidue(path string) error {
	if err := requireRegularResidueDir(path); err != nil {
		return err
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("origin: cannot remove abandoned install candidate %s: %w", path, err)
	}
	return nil
}

func requireRegularResidueDir(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("origin: cannot inspect install residue %s: %w", path, err)
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("origin: refusing unsafe install residue %s (symlink or non-directory)", path)
	}
	return nil
}

// RemoveVersion deletes a version dir (cleanup support). It refuses to
// delete outside the prefix or through a symlink (HIGH-1: a planted
// link must not redirect a recursive removal).
func (in *Installer) RemoveVersion(version string) error {
	dir, err := VersionDir(in.Prefix, version)
	if err != nil {
		return err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	absPrefix, err := filepath.Abs(in.Prefix)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(absDir, absPrefix+string(os.PathSeparator)) {
		return fmt.Errorf("origin: refusing to remove %s (outside prefix %s)", dir, in.Prefix)
	}
	if st, err := os.Lstat(dir); err == nil {
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("origin: refusing to remove %s (symlink or non-directory)", dir)
		}
	}
	return os.RemoveAll(dir)
}

// cleanupVersionDir removes a half-installed candidate/version dir.
func cleanupVersionDir(dir string) { _ = os.RemoveAll(dir) }

// firstField returns the first whitespace-delimited field of s (the
// version in `caddy version` output).
func firstField(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// moveTree mirrors src into dst (cross-device fallback for the atomic
// same-filesystem rename in Install).
func moveTree(src, dst string) error {
	if err := copyTree(src, dst); err != nil {
		return err
	}
	return os.RemoveAll(src)
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		rc, err := os.Open(path)
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, rc)
		return err
	})
}
