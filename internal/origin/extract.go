package origin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Extraction size caps. A real Caddy release is < 45 MiB; these bound
// tar-bomb style abuse while leaving generous headroom.
const (
	// maxExtractedBytes caps the TOTAL extracted size.
	maxExtractedBytes = 100 << 20
	// maxSingleEntryBytes caps a single tar entry.
	maxSingleEntryBytes = 50 << 20
)

// extractTar unpacks the (already verified) tar.gz into dst with
// tar-slip protection, per-entry and total size caps. The official
// release layout is FLAT (no top-level directory): caddy, LICENSE,
// README.md — the guard is general regardless.
func extractTar(data []byte, dst string) error {
	gz, err := newGunzipReader(data)
	if err != nil {
		return fmt.Errorf("%w: not a gzip archive", ErrExtract)
	}
	tr := tar.NewReader(gz)
	absDst, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrExtract, err)
		}
		target, err := safeJoin(absDst, hdr.Name)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrTarEntry, err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("%w: %v", ErrExtract, err)
			}
		case tar.TypeReg:
			if hdr.Size > maxSingleEntryBytes {
				return fmt.Errorf("%w: %s (%d bytes)", ErrTarEntry, hdr.Name, hdr.Size)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("%w: %v", ErrExtract, err)
			}
			mode := os.FileMode(hdr.Mode) & 0o777
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrExtract, err)
			}
			// Cap the ACTUAL bytes written, not just the declared
			// size (a hostile tar can under-declare hdr.Size).
			n, cerr := io.Copy(out, io.LimitReader(tr, maxSingleEntryBytes+1))
			cerr2 := out.Close()
			if cerr != nil {
				return fmt.Errorf("%w: %v", ErrExtract, cerr)
			}
			if cerr2 != nil {
				return fmt.Errorf("%w: %v", ErrExtract, cerr2)
			}
			if n > maxSingleEntryBytes {
				return fmt.Errorf("%w: %s (declared %d, wrote %d)", ErrTarEntry, hdr.Name, hdr.Size, n)
			}
			total += n
			if total > maxExtractedBytes {
				return fmt.Errorf("%w: total extracted size", ErrTarEntry)
			}
		case tar.TypeSymlink, tar.TypeLink:
			// Refuse link entries outright: the release ships plain
			// files, and a hostile link could redirect a later write.
			return fmt.Errorf("%w: %s (link entries are not allowed)", ErrTarEntry, hdr.Name)
		default:
			// Ignore unknown types (we only need regular files + dirs);
			// never follow them.
		}
	}
	// The release must contain the binary itself.
	if _, err := os.Stat(filepath.Join(absDst, "caddy")); err != nil {
		return fmt.Errorf("%w: no 'caddy' binary in archive", ErrExtract)
	}
	return nil
}

// newGunzipReader wraps data in a gzip reader (bytes in, decompressed
// reader out).
func newGunzipReader(data []byte) (io.Reader, error) {
	return gzip.NewReader(bytes.NewReader(data))
}

// safeJoin joins base and a (possibly nested) tar entry path, refusing
// absolute paths, empty names, and any ".." segment. Traversal is
// rejected on the RAW name (before cleaning — filepath.Clean would
// silently fold "/../x" into "/x"). Entry names are attacker-controlled,
// so errors do not echo them.
func safeJoin(base, name string) (string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" {
		return "", fmt.Errorf("tar entry with empty name")
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("tar entry with absolute path")
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", fmt.Errorf("tar entry attempts directory traversal")
		}
	}
	target := filepath.Join(base, filepath.FromSlash(name))
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("tar entry escapes target dir")
	}
	return target, nil
}
