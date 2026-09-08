package origin

import (
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
// local bytes — the install logic itself is network-independent.
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

// Executor is the managed boundary to the caddy binary. The installer
// and activator shell out through this interface so every L1/L2 test
// runs against a fake.
type Executor interface {
	// VersionOutput runs "<bin> version" and returns its combined
	// output. The installer checks that its FIRST field equals the
	// pinned version (output is "v2.11.4 h1:<build-hash>").
	VersionOutput(bin string) (string, error)
	// Validate runs "<bin> validate --config <cfg>" and returns the
	// combined output. Non-nil error or non-zero exit = the gate
	// failed and NOTHING may be (re)started.
	Validate(bin, config string) (string, error)
}

// OSExecutor runs the real binary.
type OSExecutor struct{}

// VersionOutput implements Executor.
func (OSExecutor) VersionOutput(bin string) (string, error) {
	return runCombined(bin, "version")
}

// Validate implements Executor.
func (OSExecutor) Validate(bin, config string) (string, error) {
	return runCombined(bin, "validate", "--config", config)
}

func runCombined(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
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
type Installer struct {
	Prefix string
	DL     Downloader
	Exec   Executor
	Force  bool // overwrite an existing version dir

	// Chmod sets the executable bit on the installed binary. It is a
	// field (default: os.Chmod) so a failure is injectable in tests.
	Chmod func(path string, mode os.FileMode) error
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
//  6. stage → version dir <prefix>/caddy/<version>/ (rename within the
//     prefix)
//  7. `caddy version` smoke check (first field == version)
//  8. `caddy validate --config <cfg>` gate (if cfg given)
//
// On ANY failure after step 4 the staged/version dir is removed — a
// failed install never leaves a half version on disk, and a previously
// active version is untouched (rollback = keep the old dir).
func (in *Installer) Install(version string, arch CaddyArch, testConfig string) (*Installed, error) {
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

	// Step 2-3: fetch the checksums file and parse the SHA-512 line.
	ckData, err := fetchChecksums(in.DL, ckURL)
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
	tarBody, err := in.DL.Fetch(tarURL)
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

	// Step 5: stage INSIDE the prefix so step 6's move is an atomic
	// same-filesystem rename on Linux. Stale stage dirs from a crashed
	// install are swept first (prefix-scoped only).
	stage, err := prepareStageDir(in.Prefix)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	if err := extractTar(tarBytes, stage); err != nil {
		return nil, err
	}

	// Step 6: move into the versioned layout (atomic rename within the
	// prefix).
	versionDir, err := VersionDir(in.Prefix, version)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(versionDir); err == nil {
		if !in.Force {
			return nil, fmt.Errorf("origin: %s already exists (use Force to overwrite); existing versions are preserved for rollback", versionDir)
		}
		if err := os.RemoveAll(versionDir); err != nil {
			return nil, fmt.Errorf("origin: removing existing version dir: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(versionDir), 0o755); err != nil {
		return nil, fmt.Errorf("origin: prefix: %w", err)
	}
	if err := os.Rename(stage, versionDir); err != nil {
		// Cross-device fallback: move the single expected tree.
		if err := moveTree(stage, versionDir); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInstallAborted, err)
		}
	}
	bin := filepath.Join(versionDir, "caddy")
	if err := in.Chmod(bin, 0o755); err != nil {
		// Must clean up like every other post-move step: otherwise a
		// poisoned (non-executable) version dir would survive.
		cleanupVersionDir(versionDir)
		return nil, fmt.Errorf("origin: chmod: %w", err)
	}

	// Step 7: smoke check — the FIRST field of `caddy version` must
	// equal the pinned version ("v2.11.4 h1:<hash>").
	out, err := in.Exec.VersionOutput(bin)
	if err != nil || firstField(out) != version {
		cleanupVersionDir(versionDir)
		reason := "first field of 'caddy version' != " + version
		if err != nil {
			reason = err.Error()
		}
		return nil, fmt.Errorf("%w: %s; caddy output: %s", ErrSmokeCheck, reason, excerpt(out))
	}

	// Step 8: config gate. A rejected Caddyfile aborts BEFORE any
	// service (re)start.
	if testConfig != "" {
		out, err := in.Exec.Validate(bin, testConfig)
		if err != nil {
			cleanupVersionDir(versionDir)
			return nil, fmt.Errorf("%w: %s; caddy output: %s", ErrConfigGate, err, excerpt(out))
		}
	}

	return &Installed{
		Version:     version,
		Arch:        string(arch),
		TarURL:      tarURL,
		TarSHA512:   sha512Hex,
		Path:        bin,
		InstalledAt: time.Now().UTC(),
	}, nil
}

// prepareStageDir creates the staging directory inside the prefix (so
// the final move is an atomic same-filesystem rename), sweeping stale
// stage dirs from a previously crashed install first.
func prepareStageDir(prefix string) (string, error) {
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		return "", fmt.Errorf("origin: prefix: %w", err)
	}
	entries, err := os.ReadDir(prefix)
	if err != nil {
		return "", fmt.Errorf("origin: prefix: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), ".caddy-stage-") {
			_ = os.RemoveAll(filepath.Join(prefix, e.Name()))
		}
	}
	stage, err := os.MkdirTemp(prefix, ".caddy-stage-*")
	if err != nil {
		return "", fmt.Errorf("origin: staging: %w", err)
	}
	return stage, nil
}

// RemoveVersion deletes a version dir (cleanup support). It refuses to
// delete outside the prefix.
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
	return os.RemoveAll(dir)
}

// cleanupVersionDir removes a half-installed version dir.
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
