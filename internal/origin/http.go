package origin

import (
	"fmt"
	"net/http"
	"time"
)

// defaultHTTPClient is the production client for release downloads:
// TLS by default, bounded timeouts, redirect-following (github.com
// release URLs 302 to the CDN edge).
var defaultHTTPClient = &http.Client{
	Timeout: 10 * time.Minute,
}

// httpGet performs a GET and returns the response (caller closes the
// body). Only 200 bodies are consumed by callers.
func httpGet(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("origin: %v", err)
	}
	req.Header.Set("User-Agent", "split-tunnel-deploy/1.0")
	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("origin: %v", err)
	}
	return resp, nil
}
