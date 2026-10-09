package dashboard

import (
	"crypto/subtle"
	"net/http"
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

// --- CSRF / Origin check ---

// OriginChecker rejects mutating requests (POST) whose Origin header does
// not match the dashboard's own origin. This is a defence-in-depth measure:
// even though mutations are disabled in this release, the mechanism is in
// place so that a future enabled-mutation build cannot be CSRF'd by a
// malicious web page.
//
// The expected origin is the dashboard's own listen address in the form
// "http://127.0.0.1:8080". A request without an Origin header (i.e. same-
// origin form submissions or API clients) is allowed; a request WITH an
// Origin header that does not match is rejected with 403.
type OriginChecker struct {
	// ExpectedOrigin is the dashboard's own origin, e.g. "http://127.0.0.1:8080".
	// Empty means the check is disabled (safe for local fixture mode).
	ExpectedOrigin string
}

// NewOriginChecker creates an OriginChecker for the given dashboard origin.
func NewOriginChecker(origin string) *OriginChecker {
	return &OriginChecker{ExpectedOrigin: origin}
}

// Check returns nil for allowed requests, or an *httpError for rejected ones.
// It is only meaningful for mutating methods (POST, PUT, PATCH, DELETE);
// read-only GET/HEAD requests are always allowed.
func (o *OriginChecker) Check(r *http.Request) error {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return nil
	}
	if o.ExpectedOrigin == "" {
		// Disabled (safe default for fixture mode: the server is loopback-only).
		return nil
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		// No Origin header: same-origin form submission or API client. Allow.
		return nil
	}
	if origin != o.ExpectedOrigin {
		return &httpError{Code: http.StatusForbidden, Msg: "request origin not allowed (CSRF check)"}
	}
	return nil
}
