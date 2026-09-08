package origin

import (
	"fmt"
	"io"
)

// fetchChecksums downloads the upstream checksums file, bounds its
// size, and returns the raw bytes (parsed by ParseChecksumFile). Fail
// closed: an oversized, unreadable, or empty sidecar aborts the
// install.
func fetchChecksums(dl Downloader, url string) ([]byte, error) {
	body, err := dl.Fetch(url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, maxChecksumBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: checksums file", ErrDownload)
	}
	if int64(len(data)) > maxChecksumBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrChecksumTooLarge, len(data))
	}
	return data, nil
}

// readBounded reads at most max bytes from r, failing if r has more.
func readBounded(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("origin: download exceeds %d bytes", max)
	}
	return data, nil
}
