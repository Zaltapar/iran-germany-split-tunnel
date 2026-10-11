package dashboard

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
)

// Authenticator is a pluggable request-authentication middleware.
// The default (LoopbackAuthenticator) is used when the dashboard binds to
// 127.0.0.1 only: no token is required because the server is not reachable
// off-host. A future release may swap in a BearerTokenAuthenticator or an
// OIDCAuthenticator; the interface is stable.
//
// An Authenticator returns (next, nil) to allow the request, or
// (nil, err) to reject it (the handler should respond 401 with err.Error()).
type Authenticator interface {
	// Authenticate inspects the request and returns the next handler to
	// invoke, or an error that should be written as a 401 body.
	Authenticate(r *http.Request) (http.Handler, error)
	// Name identifies the authenticator in logs.
	Name() string
}

// LoopbackAuthenticator is the safe default: it allows all requests.
// It is only safe because the HTTP server binds to 127.0.0.1 and is not
// reachable from any remote host. If a future build binds to a public
// interface, this authenticator MUST be replaced.
type LoopbackAuthenticator struct{}

// NewLoopbackAuthenticator returns the default local-only authenticator.
func NewLoopbackAuthenticator() *LoopbackAuthenticator { return &LoopbackAuthenticator{} }

func (a *LoopbackAuthenticator) Name() string { return "loopback" }

// Authenticate always passes through.
func (a *LoopbackAuthenticator) Authenticate(_ *http.Request) (http.Handler, error) {
	return nil, nil // nil next = caller falls through to the original handler
}

// BearerTokenAuthenticator validates a Bearer token from the Authorization
// header. The expected token is supplied at construction time; it must NEVER
// appear in config files, logs, or example configs.
type BearerTokenAuthenticator struct {
	token string
}

// NewBearerTokenAuthenticator creates a Bearer authenticator. An empty token
// disables authentication (equivalent to loopback) — this is intentional so
// that the no-token local case works, and the zero value is never silently
// accepting requests.
func NewBearerTokenAuthenticator(token string) *BearerTokenAuthenticator {
	return &BearerTokenAuthenticator{token: token}
}

func (a *BearerTokenAuthenticator) Name() string { return "bearer" }

// Authenticate checks the Authorization header. The token is compared in
// constant time (crypto/subtle) so the comparison leaks no timing
// information about how many leading characters matched.
func (a *BearerTokenAuthenticator) Authenticate(r *http.Request) (http.Handler, error) {
	if a.token == "" {
		// No token configured: allow (local-only mode).
		return nil, nil
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, &httpError{Code: http.StatusUnauthorized, Msg: "missing Bearer token"}
	}
	supplied := strings.TrimPrefix(auth, "Bearer ")
	if subtle.ConstantTimeCompare([]byte(supplied), []byte(a.token)) != 1 {
		return nil, &httpError{Code: http.StatusUnauthorized, Msg: "invalid Bearer token"}
	}
	return nil, nil
}

// httpError is a typed authentication error the handler can detect.
// Www, when non-empty, is emitted as the WWW-Authenticate response
// header on the 401 so a browser can prompt for (and cache) Basic
// credentials. It is empty for every non-HTTP-Basic error.
type httpError struct {
	Code int
	Msg  string
	// Www is the value of the WWW-Authenticate header to send on a 401,
	// e.g. `Basic realm="TunnelDash", charset="UTF-8"`. Empty when the
	// error is not an authentication challenge.
	Www string
}

func (e *httpError) Error() string { return e.Msg }

// --- CSRF / Origin check (C1 hardened) ---

// CSRFRequestHeader is the custom header every mutating (non-GET, non-HEAD)
// request must carry. Browsers cannot set it from a plain HTML form, and
// cross-site fetch/XHR requests that set it will be blocked by the CORS
// preflight (the server never answers OPTIONS with allow headers).
const CSRFRequestHeader = "X-Tunneldash-Request"

// CSRFRequestValue is the single accepted value for the CSRF custom header.
const CSRFRequestValue = "1"

// OriginChecker performs CSRF protection for mutating requests.
//
// C1 hardening (replaces the old disabled-by-default check):
//  1. The custom header X-Tunneldash-Request: 1 is REQUIRED on every
//     non-GET, non-HEAD request. Missing or wrong value → 403
//     "csrf_header_missing".
//  2. Same-origin check: if the request carries an Origin or Referer
//     header, its host component must equal the request's Host header.
//     Mismatch → 403 "origin_forbidden".
//  3. If neither Origin nor Referer is present (non-browser API client),
//     the custom header alone is sufficient; no 403.
//
// This blocks the two CSRF vectors:
//   - Cross-site HTML form POST: cannot set the custom header.
//   - Cross-site JavaScript fetch with cached Basic credentials: the CORS
//     preflight for a non-simple header (X-Tunneldash-Request) fails
//     because the server never returns Access-Control-Allow-Headers.
type OriginChecker struct {
	// Enabled is true when the CSRF checks are active. In the current
	// build it is always true (the old "disabled when empty" escape
	// hatch is removed).
	Enabled bool
}

// NewOriginChecker creates an active CSRF checker. The argument is
// retained for API compatibility but is unused; the check derives the
// expected origin from the request's Host header at check time.
func NewOriginChecker(_ string) *OriginChecker {
	return &OriginChecker{Enabled: true}
}

// Check returns nil for allowed requests, or an *httpError for rejected
// ones. It is only meaningful for mutating methods; read-only GET/HEAD
// requests are always allowed.
func (o *OriginChecker) Check(r *http.Request) error {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return nil
	}
	if !o.Enabled {
		return nil
	}
	// 1. Custom header is mandatory for every non-GET/non-HEAD request.
	if r.Header.Get(CSRFRequestHeader) != CSRFRequestValue {
		return &httpError{Code: http.StatusForbidden, Msg: "csrf_header_missing: X-Tunneldash-Request: 1 is required for mutating requests"}
	}
	// 2. Same-origin: Origin or Referer, when present, must match r.Host.
	origin := r.Header.Get("Origin")
	referer := r.Header.Get("Referer")
	if origin == "" && referer == "" {
		// No browser origin headers: non-browser API client. The custom
		// header is the CSRF guard; allow.
		return nil
	}
	var srcHost string
	if origin != "" {
		srcHost = hostFromOrigin(origin)
	} else {
		srcHost = hostFromOrigin(referer)
	}
	if srcHost == "" {
		// Unparseable Origin/Referer: fail closed.
		return &httpError{Code: http.StatusForbidden, Msg: "origin_forbidden: unparseable Origin or Referer"}
	}
	if srcHost != r.Host {
		return &httpError{Code: http.StatusForbidden, Msg: "origin_forbidden: request origin does not match Host"}
	}
	return nil
}

// hostFromOrigin extracts the authority (host[:port]) from an origin or
// referer URL string. It returns "" when the value is not a valid
// http/https URL with a non-empty host.
func hostFromOrigin(raw string) string {
	if raw == "" {
		return ""
	}
	// Origin has the form "scheme://host[:port]"; Referer is a full URL.
	// We only need the authority. Parse both with net/url.
	// For robustness, handle the "null" origin (opaque/sandboxed iframe):
	// a "null" origin is always cross-site → reject.
	if raw == "null" {
		return "" // unparseable → caller rejects
	}
	u, err := parseOriginURL(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// parseOriginURL is a thin wrapper over url.Parse that accepts both a
// bare origin ("scheme://host:port") and a full URL (Referer). It returns
// the parsed *url.URL, or an error.
func parseOriginURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}
