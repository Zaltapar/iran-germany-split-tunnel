package xray

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Extraction size caps. A real Xray release is < 250 MiB with geodata;
// these bound zip-bomb style abuse while leaving generous headroom.
const (
	// maxExtractedBytes caps the TOTAL extracted size.
	maxExtractedBytes = 250 << 20
	// maxSingleEntryBytes caps a single zip entry.
	maxSingleEntryBytes = 100 << 20
)

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

// copyTree mirrors src into dst (the cross-device fallback for the
// atomic same-filesystem rename in Install).
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
