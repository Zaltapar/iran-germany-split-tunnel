package origin

import (
	"context"
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
// body). Only 200 bodies are consumed by callers. The request carries
// the caller's ctx (HIGH-2: NewRequestWithContext), so a canceled ctx
// aborts the transfer promptly; the client's own Timeout is the outer
// backstop for a caller that supplies no deadline.
func httpGet(ctx context.Context, url string) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("origin: %v", err)
	}
	req.Header.Set("User-Agent", "split-tunnel-deploy/1.0")
	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		// Preserve context cancellation/deadline as the returned error
		// class (HIGH-2): callers must see context.Canceled /
		// context.DeadlineExceeded, not a wrapped *url.Error.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("origin: %v", err)
	}
	return resp, nil
}
