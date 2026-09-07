package xray

import (
	"archive/zip"
	"bytes"
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
	ErrDownload       = errors.New("xray: download failed")
	ErrExtract        = errors.New("xray: extraction failed")
	ErrZipEntry       = errors.New("xray: unsafe or oversized zip entry (refusing)")
	ErrSmokeCheck     = errors.New("xray: 'xray version' smoke check failed (binary not runnable)")
	ErrConfigGate     = errors.New("xray: 'xray run -test' rejected the generated config (install aborted before any service change)")
	ErrInstallAborted = errors.New("xray: install aborted; no service was started and the previous version (if any) is untouched")
)

// maxExtractedBytes caps the total extracted size (a real Xray release
// is < 250 MiB with geodata; this bounds zip-bomb style abuse while
// leaving generous headroom).
const maxExtractedBytes = 250 << 20

// maxSingleEntryBytes caps a single zip entry.
const maxSingleEntryBytes = 100 << 20

// Downloader fetches a release asset. It is a type so tests substitute a
// local server or static bytes — the install logic itself is network-
// independent.
type Downloader interface {
	Fetch(url string) (io.ReadCloser, error)
}

// HTTPDownloader is the production Downloader (stdlib HTTP client;
// redirect-following, TLS by default — github.com release URLs).
type HTTPDownloader struct{}

// Fetch implements Downloader.
func (HTTPDownloader) Fetch(url string) (io.ReadCloser, error) {
	resp, err := httpGet(url)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDownload, err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("%w: upstream returned status %d", ErrDownload, resp.StatusCode)
	}
	return resp.Body, nil
}

// Executor is the managed-transport boundary to the xray binary
// (architecture doc §2.2: a managed-transport adapter, not a re-
// implementation). The installer shells out through this interface so
// every L1/L2 test runs against a fake.
type Executor interface {
	// VersionOutput runs "<bin> version" and returns its combined
	// output. The installer checks that it contains "Xray".
	VersionOutput(bin string) (string, error)
	// RunTest runs "<bin> run -test -config <cfg>" and returns the
	// combined output. Non-nil error or non-zero exit = the gate
	// failed and NOTHING may be (re)started.
	RunTest(bin, config string) (string, error)
	// Keypair runs "<bin> x2025 reality keypair" and returns its
	// output (the private key line — handled by T3; the installer
	// only needs the call to succeed).
	Keypair(bin string) (string, error)
}

// OSExecutor runs the real binary.
type OSExecutor struct{}

// VersionOutput implements Executor.
func (OSExecutor) VersionOutput(bin string) (string, error) {
	return runCombined(bin, "version")
}

// RunTest implements Executor.
func (OSExecutor) RunTest(bin, config string) (string, error) {
	return runCombined(bin, "run", "-test", "-config", config)
}

// Keypair implements Executor.
func (OSExecutor) Keypair(bin string) (string, error) {
	return runCombined(bin, "x2025", "reality", "keypair")
}

func runCombined(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Return the output alongside the error: the gates embed a
		// bounded excerpt (see excerpt) so a rejected config is
		// diagnosable. The generated config carries only PUBLIC
		// Reality parameters (public key, UUID, SNI, dest) and xray
		// error lines do not echo secrets, so a bounded echo is safe.
		return string(out), fmt.Errorf("xray: %v", err)
	}
	return string(out), nil
}

// Installer installs a pinned Xray release into the project prefix
// (versioned layout) and records the manifest. It is pure filesystem +
// Downloader + Executor: no systemd, no user management (those are the
// deploy CLI's job, T4/T5) — but everything it does is safe to repeat:
// a re-install into an existing version dir fails fast unless Force.
type Installer struct {
	Prefix      string
	DL          Downloader
	Exec        Executor
	Force       bool // overwrite an existing version dir
	WithGeodata bool // extract geoip.dat/geosite.dat (default: skip)

	// Chmod sets the executable bit on the installed binary. It is a
	// field (default: os.Chmod) so a failure is injectable in tests.
	Chmod func(path string, mode os.FileMode) error
}

// Installed records what Install placed on disk (the manifest row).
type Installed struct {
	Version     string    `json:"version"`
	Arch        string    `json:"arch"`
	ZipURL      string    `json:"zipUrl"`
	ZipSHA256   string    `json:"zipSha256"` // the .dgst value, verified
	Path        string    `json:"path"`      // absolute path of the xray binary
	InstalledAt time.Time `json:"installedAt"`
}

// Install runs the full §4.1 pipeline:
//
//  1. resolve version+arch → zip URL + .dgst URL
//  2. download zip + .dgst
//  3. parse .dgst (fail closed if no SHA2-256 line)
//  4. verify zip SHA-256 (constant time; fail closed on mismatch)
//  5. extract into a STAGING dir (zip-slip + size caps)
//  6. stage → version dir (rename within the prefix)
//  7. `xray version` smoke check
//  8. `xray run -test -config <cfg>` gate (if cfg given)
//
// On ANY failure after step 4 the staged/version dir is removed — a
// failed install never leaves a half version on disk, and a previously
// active version is untouched (rollback = keep the old dir, which is
// what this guarantees).
func (in *Installer) Install(version string, arch Arch, testConfig string) (*Installed, error) {
	if in.Prefix == "" {
		return nil, fmt.Errorf("xray: empty prefix")
	}
	if !ValidVersion(version) {
		return nil, fmt.Errorf("xray: invalid version %q", version)
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
	zipURL, err := ZipURL(version, arch)
	if err != nil {
		return nil, err
	}
	dgstURL, err := DigestURL(version, arch)
	if err != nil {
		return nil, err
	}

	// Steps 1-3: fetch both assets.
	zipBody, err := in.DL.Fetch(zipURL)
	if err != nil {
		return nil, err
	}
	defer zipBody.Close()
	dgstBody, err := in.DL.Fetch(dgstURL)
	if err != nil {
		return nil, err
	}
	defer dgstBody.Close()
	dgstData, err := io.ReadAll(io.LimitReader(dgstBody, maxDgstBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: digest", ErrDownload)
	}
	if int64(len(dgstData)) > maxDgstBytes {
		return nil, fmt.Errorf("%w: sidecar is larger than %d bytes", ErrDgstTooLarge, maxDgstBytes)
	}
	sha256Hex, err := ParseDigest(dgstData)
	if err != nil {
		return nil, err
	}

	// Step 4: buffer the zip (bounded by the entry caps via the
	// extraction guard) and verify in constant time. Buffering keeps
	// the verify→extract order clean and re-reads the same bytes.
	zipBytes, err := readBounded(zipBody, maxExtractedBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: zip", ErrDownload)
	}
	if err := VerifyFile(zipBytes, sha256Hex); err != nil {
		return nil, err
	}

	// Step 5: stage INSIDE the prefix so step 6's move is an atomic
	// same-filesystem rename on Linux (a /tmp → /opt rename would be
	// cross-device and fall back to a non-atomic copy). Stale stage
	// dirs from a crashed install are swept first (prefix-scoped only).
	if err := os.MkdirAll(in.Prefix, 0o755); err != nil {
		return nil, fmt.Errorf("xray: prefix: %w", err)
	}
	entries, err := os.ReadDir(in.Prefix)
	if err != nil {
		return nil, fmt.Errorf("xray: prefix: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), ".xray-stage-") {
			_ = os.RemoveAll(filepath.Join(in.Prefix, e.Name()))
		}
	}
	stage, err := os.MkdirTemp(in.Prefix, ".xray-stage-*")
	if err != nil {
		return nil, fmt.Errorf("xray: staging: %w", err)
	}
	defer os.RemoveAll(stage)
	if err := extractZip(zipBytes, stage, in.WithGeodata); err != nil {
		return nil, err
	}

	// Step 6: move into the versioned layout (atomic rename within the
	// prefix; the copyTree fallback covers exotic cross-device setups).
	versionDir, err := VersionDir(in.Prefix, version)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(versionDir); err == nil {
		if !in.Force {
			return nil, fmt.Errorf("xray: %s already exists (use Force to overwrite); existing versions are preserved for rollback", versionDir)
		}
		if err := os.RemoveAll(versionDir); err != nil {
			return nil, fmt.Errorf("xray: removing existing version dir: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(versionDir), 0o755); err != nil {
		return nil, fmt.Errorf("xray: prefix: %w", err)
	}
	if err := os.Rename(stage, versionDir); err != nil {
		// Cross-device fallback: copy then remove the stage.
		if err := copyTree(stage, versionDir); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInstallAborted, err)
		}
	}
	bin := filepath.Join(versionDir, "xray")
	if err := in.Chmod(bin, 0o755); err != nil {
		// Must clean up like every other post-move step: otherwise a
		// poisoned (non-executable) version dir would survive, and a
		// later install would refuse it without Force.
		cleanupVersionDir(versionDir)
		return nil, fmt.Errorf("xray: chmod: %w", err)
	}

	// Step 7: smoke check.
	out, err := in.Exec.VersionOutput(bin)
	if err != nil || !strings.Contains(out, "Xray") {
		cleanupVersionDir(versionDir)
		reason := "output did not contain 'Xray'"
		if err != nil {
			reason = err.Error()
		}
		return nil, fmt.Errorf("%w: %s; xray output: %s", ErrSmokeCheck, reason, excerpt(out))
	}

	// Step 8: config gate. A rejected config aborts BEFORE any
	// service (re)start — the whole point of §4.1 step 5.
	if testConfig != "" {
		out, err := in.Exec.RunTest(bin, testConfig)
		if err != nil {
			cleanupVersionDir(versionDir)
			return nil, fmt.Errorf("%w: %s; xray output: %s", ErrConfigGate, err, excerpt(out))
		}
	}

	return &Installed{
		Version:     version,
		Arch:        string(arch),
		ZipURL:      zipURL,
		ZipSHA256:   sha256Hex,
		Path:        bin,
		InstalledAt: time.Now().UTC(),
	}, nil
}

// RemoveVersion deletes a version dir (cleanup --older-than support).
// It refuses to delete outside the prefix.
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
		return fmt.Errorf("xray: refusing to remove %s (outside prefix %s)", dir, in.Prefix)
	}
	return os.RemoveAll(dir)
}

// cleanupVersionDir removes a half-installed version dir; a failure
// here is logged by the caller via the returned error chain (it only
// happens when the dir could not be created in the first place).
func cleanupVersionDir(dir string) { _ = os.RemoveAll(dir) }

// readBounded reads at most max bytes from r, failing if r has more.
func readBounded(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("xray: download exceeds %d bytes", max)
	}
	return data, nil
}

// excerptMax bounds the xray output embedded in a gate error.
const excerptMax = 2000

// excerpt returns a bounded, trimmed form of xray output for error
// display. The generated config carries only public parameters (public
// key, UUID, SNI, dest) — the tunnel secret and the Reality private key
// never reach xray — so a bounded echo is not a secret leak.
func excerpt(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(no output)"
	}
	if len(s) > excerptMax {
		return s[:excerptMax] + " ... (truncated)"
	}
	return s
}

// extractZip unpacks the (already verified) zip into dst with
// zip-slip protection, per-entry and total size caps, and optional
// geodata filtering. The official release layout is flat (xray,
// geoip.dat, geosite.dat, LICENSE, README.md) but the guard is general.
func extractZip(data []byte, dst string, withGeodata bool) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("%w: not a zip archive", ErrExtract)
	}
	absDst, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	var total int64
	for _, f := range zr.File {
		if !withGeodata && isGeoData(f.Name) {
			continue
		}
		target, err := safeJoin(absDst, f.Name)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrZipEntry, err)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("%w: %v", ErrExtract, err)
			}
			continue
		}
		if f.UncompressedSize64 > maxSingleEntryBytes {
			return fmt.Errorf("%w: %s (%d bytes)", ErrZipEntry, f.Name, f.UncompressedSize64)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("%w: %v", ErrExtract, err)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrExtract, err)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode().Perm()|0o100)
		if err != nil {
			rc.Close()
			return fmt.Errorf("%w: %v", ErrExtract, err)
		}
		// Cap the ACTUAL bytes written, not just the declared size
		// (a hostile zip can under-declare UncompressedSize64).
		n, cerr := io.Copy(out, io.LimitReader(rc, maxSingleEntryBytes))
		rc.Close()
		out.Close()
		if cerr != nil {
			return fmt.Errorf("%w: %v", ErrExtract, cerr)
		}
		total += n
		if n > maxSingleEntryBytes || total > maxExtractedBytes {
			return fmt.Errorf("%w: entry or total extracted size", ErrZipEntry)
		}
	}
	// The release must contain the binary itself.
	if _, err := os.Stat(filepath.Join(absDst, "xray")); err != nil {
		return fmt.Errorf("%w: no 'xray' binary in archive", ErrExtract)
	}
	return nil
}

func isGeoData(name string) bool {
	base := filepath.Base(name)
	return base == "geoip.dat" || base == "geosite.dat"
}

// safeJoin joins base and a (possibly nested) zip entry path, refusing
// absolute paths, empty names, and any ".." segment. Traversal is
// rejected on the RAW name (before cleaning — filepath.Clean would
// silently fold "/../x" into "/x", which is exactly the confusion a
// zip-slip guard must not make). Entry names are attacker-controlled,
// so errors do not echo them.
func safeJoin(base, name string) (string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" {
		return "", fmt.Errorf("zip entry with empty name")
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("zip entry with absolute path")
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", fmt.Errorf("zip entry attempts directory traversal")
		}
	}
	target := filepath.Join(base, filepath.FromSlash(name))
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("zip entry escapes target dir")
	}
	return target, nil
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
