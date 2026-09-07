package xray

import (
	"fmt"
	"io"
)

// fetchDigest downloads the .dgst sidecar, bounds its size, and parses
// the SHA-256 line — the §4.1 pipeline steps 2-3. Fail closed: an
// oversized, unreadable, or malformed sidecar aborts the install.
func fetchDigest(dl Downloader, url string) (string, error) {
	body, err := dl.Fetch(url)
	if err != nil {
		return "", err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, maxDgstBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: digest", ErrDownload)
	}
	if int64(len(data)) > maxDgstBytes {
		return "", fmt.Errorf("%w: sidecar is larger than %d bytes", ErrDgstTooLarge, maxDgstBytes)
	}
	return ParseDigest(data)
}

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
