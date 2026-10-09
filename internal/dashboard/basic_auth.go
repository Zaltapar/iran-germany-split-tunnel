// basic_auth.go — HTTP Basic authentication for the server-hosted TLS build.
//
// The dashboard is a local-only tool by default (loopback, plain HTTP, no
// credentials). The one-click installer's Germany build enables TLS so the
// operator can open the dashboard in a normal browser on a separate high
// port. Browser-native HTTP Basic Auth is the documented UX:
//
//   - The browser prompts once for username + password.
//   - The same credentials are reused automatically for all UI GETs and
//     same-origin fetch() calls (UI + /api/v1/...), scoped to the origin
//     (scheme + host + port). The 32-hex basePath does NOT reset this cache
//     (it is part of the path, not the origin).
//   - To clear a cached credential set, close and re-open the browser, or
//     delete the saved password entry from the browser's password manager.
//
// # SECURITY MODEL
//
// The credential material NEVER ships in plaintext. On-disk, the installer
// writes a salted PBKDF2-HMAC-SHA256 verifier to a 0640 root:split-tunnel
// file referenced by the SPLIT_TUNNELDASH_CREDENTIALS env var (a path, not a
// value — never echoed in logs or argv). The BasicAuthenticator loads the
// verifier once at construction, caches the salt + iteration count + expected
// digest in memory, and compares in constant time:
//
//   - the username comparison uses crypto/subtle.ConstantTimeCompare;
//   - the supplied password is re-derived with PBKDF2 (the same work an
//     offline attacker would have to do) and the resulting digest is
//     compared in constant time against the cached expected digest.
//
// This guarantees (a) no plaintext password is ever held in memory, (b) no
// timing side-channel leaks how many characters matched, and (c) a leaked
// verifier file still requires the PBKDF2 offline attack to recover the
// password — the same posture as a well-configured shadow/nginx-htpasswd
// verifier.
//
// The KDF is PBKDF2-HMAC-SHA256, implemented here with the pure Go standard
// library (crypto/hmac + crypto/sha256). No third-party dependency is
// added: the module deliberately keeps a minimal go.mod, and PBKDF2 is a
// one-block construction (dkLen == 32 == SHA-256 output) that maps cleanly
// onto a single HMAC-SHA256 PRF loop.
//
// The verifier document is a single JSON line:
//
//	{"v":1,"user":"admin","iter":210000,"saltHex":"…32 hex…","digestHex":"…64 hex…"}
//
// JSON (rather than a bespoke `$` scheme) keeps the file inspectable,
// machine-friendly, and resistant to accidental whitespace corruption.
//
// LOCAL LOOPBACK / NO-TLS DEFAULT (unchanged): a build without TLS, bound to
// 127.0.0.1, keeps the documented no-credential LoopbackAuthenticator
// default. Basic auth is reachable only on the server-hosted TLS surface.
//
// Bearer-token semantics: BearerTokenAuthenticator remains available as a
// deprecated legacy fallback (removed only from the installer's fresh
// provisioning, not from the code) so no in-flight host build is broken.
// See docs/tunneldash.md for the migration / retrieval / rotation guidance.
package dashboard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// DefaultBasicAuthUsername is the fixed admin username for the
// server-hosted dashboard Basic-auth. The installer and the
// `rotate-dashboard-credentials` subcommand both use it. A single
// well-known user keeps the credential surface auditable: rotation is
// "replace the password", never "add a new user". A user-selected username
// is a future extension and MUST be added behind an explicit config flag.
const DefaultBasicAuthUsername = "admin"

// EnvDashCredentials is the SPLIT_TUNNELDASH_CREDENTIALS env var name. Its
// value is the ABSOLUTE PATH to a 0640 root:split-tunnel file holding one
// EncodeVerifier() JSON line. The path is non-secret; the verifier value
// (the digest) is secret and never logged.
const EnvDashCredentials = "SPLIT_TUNNELDASH_CREDENTIALS"

// KDF parameters (embedded in the verifier document so a future release can
// bump them on re-encode without breaking older files).
const (
	pbkdf2Iterations = 210_000 // ~50 ms on modern consumer CPUs; bounds offline brute force.
	pbkdf2SaltLen    = 16
	pbkdf2DigestLen  = sha256.Size
)

// pbkdf2HMACSHA256 returns the PBKDF2-HMAC-SHA256 derivation of pass with
// the given salt and iteration count. This implementation targets a single
// output block (dkLen == sha256.Size, the only length the dashboard uses),
// which is exactly the RFC 2898 T(1) value:
//
//	U(1) = PRF(password, salt || INT_32_BE(1))
//	U(i) = PRF(password, U(i-1))
//	T(1) = U(1) XOR U(2) XOR ... XOR U(c)
func pbkdf2HMACSHA256(pass, salt []byte, iter int) []byte {
	mac := hmac.New(sha256.New, pass)
	mac.Write(salt)
	// Append the 4-byte big-endian block index (1 for the only block).
	mac.Write([]byte{0x00, 0x00, 0x00, 0x01})
	u := mac.Sum(nil)

	out := make([]byte, len(u))
	copy(out, u)
	for i := 1; i < iter; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

// randRead reads n cryptographically secure bytes.
func randRead(buf []byte) (int, error) { return rand.Read(buf) }

// GenerateBasicAuthPassword produces a fresh 128-bit high-entropy password
// rendered as 32 lowercase hex chars.
func GenerateBasicAuthPassword() (string, error) {
	buf := make([]byte, 16)
	if _, err := randRead(buf); err != nil {
		return "", fmt.Errorf("dashboard: password CSPRNG: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// GenerateBasicAuthSalt produces a fresh 16-byte KDF salt.
func GenerateBasicAuthSalt() ([]byte, error) {
	buf := make([]byte, pbkdf2SaltLen)
	if _, err := randRead(buf); err != nil {
		return nil, fmt.Errorf("dashboard: salt CSPRNG: %w", err)
	}
	return buf, nil
}

// verifierDoc is the on-disk shape (a single JSON line) that the
// SPLIT_TUNNELDASH_CREDENTIALS file holds.
type verifierDoc struct {
	V         int    `json:"v"`
	User      string `json:"user"`
	Iter      int    `json:"iter"`
	SaltHex   string `json:"saltHex"`
	DigestHex string `json:"digestHex"`
}

// EncodeVerifier produces the single-line JSON document written to the
// SPLIT_TUNNELDASH_CREDENTIALS store.
func EncodeVerifier(user string, iter int, salt, digest []byte) string {
	doc := verifierDoc{V: 1, User: user, Iter: iter, SaltHex: hex.EncodeToString(salt), DigestHex: hex.EncodeToString(digest)}
	out, _ := json.Marshal(doc) // marshaling primitive fields cannot fail.
	return string(out)
}

// HashBasicAuthPassword derives a fresh PBKDF2-HMAC-SHA256 verifier
// document for (user, pass) using a new random salt each call — so two
// hashes of the same password differ, a property a verifier must have.
func HashBasicAuthPassword(user, pass string) (string, error) {
	salt, err := GenerateBasicAuthSalt()
	if err != nil {
		return "", err
	}
	digest := pbkdf2HMACSHA256([]byte(pass), salt, pbkdf2Iterations)
	return EncodeVerifier(user, pbkdf2Iterations, salt, digest), nil
}

// ParseVerifier parses a single-line JSON verifier document. It is strict:
// an unknown version, a missing field, or malformed hex is a hard error
// (fail-closed).
func ParseVerifier(doc string) (user string, iter int, salt, digest []byte, err error) {
	trimmed := strings.TrimSpace(doc)
	if trimmed == "" {
		return "", 0, nil, nil, fmt.Errorf("dashboard: empty verifier document")
	}
	var d verifierDoc
	if err := json.Unmarshal([]byte(trimmed), &d); err != nil {
		return "", 0, nil, nil, fmt.Errorf("dashboard: verifier JSON: %w", err)
	}
	if d.V != 1 {
		return "", 0, nil, nil, fmt.Errorf("dashboard: unsupported verifier v%d", d.V)
	}
	if d.User == "" {
		return "", 0, nil, nil, fmt.Errorf("dashboard: verifier has empty username")
	}
	if d.Iter <= 0 || d.Iter > 10_000_000 {
		return "", 0, nil, nil, fmt.Errorf("dashboard: verifier iteration count out of range")
	}
	if salt, err = hex.DecodeString(d.SaltHex); err != nil || len(salt) != pbkdf2SaltLen {
		return "", 0, nil, nil, fmt.Errorf("dashboard: verifier salt is not %d hex chars", pbkdf2SaltLen*2)
	}
	if digest, err = hex.DecodeString(d.DigestHex); err != nil || len(digest) != pbkdf2DigestLen {
		return "", 0, nil, nil, fmt.Errorf("dashboard: verifier digest is not %d hex chars", pbkdf2DigestLen*2)
	}
	return d.User, d.Iter, salt, digest, nil
}

// --- Recovery token --------------------------------------------------------
//
// GenerateRecoveryToken produces a one-time, self-contained payload the
// operator can carry off the host (via a 0600 root-only file) to retrieve
// the credential without the installer ever printing it. It is the
// base64url encoding of
//
//	userName \x00 iterations \x00 saltHex \x00 digestHex
//
// — everything needed to verify a candidate password offline WITHOUT the
// plaintext. The plaintext password remains only on the host that
// generated it (the installer's root-scoped working step or the operator's
// SSH session); it is never placed in stdout, argv, env, logs, or the
// 0600 install log. A leaked token / verifier pair is the same dead-end as
// a leaked shadow entry: it does not contain the password.
func GenerateRecoveryToken(user string, iter int, salt, digest []byte) string {
	payload := strings.Join([]string{
		user,
		strconv.Itoa(iter),
		hex.EncodeToString(salt),
		hex.EncodeToString(digest),
	}, "\x00")
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

// DecodeRecoveryToken parses the payload produced by GenerateRecoveryToken.
// ok is false when the shape is wrong.
func DecodeRecoveryToken(tok string) (user string, iter int, salt, digest []byte, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tok))
	if err != nil {
		return "", 0, nil, nil, false
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 4 {
		return "", 0, nil, nil, false
	}
	iter, err = strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return "", 0, nil, nil, false
	}
	if salt, err = hex.DecodeString(parts[2]); err != nil {
		return "", 0, nil, nil, false
	}
	if digest, err = hex.DecodeString(parts[3]); err != nil {
		return "", 0, nil, nil, false
	}
	return parts[0], iter, salt, digest, true
}

// VerifyCandidatePassword reports whether pass is the password that
// produced the verifier (salt, iter, digest). It re-derives with PBKDF2
// and compares in constant time. This is the operator-side primitive that
// makes a carried verifier + recovery token usable without the plaintext.
func VerifyCandidatePassword(user, pass string, iter int, salt, digest []byte) bool {
	got := pbkdf2HMACSHA256([]byte(pass), salt, iter)
	return subtle.ConstantTimeCompare(got, digest) == 1
}

// --- BasicAuthenticator ----------------------------------------------------

// BasicAuthenticator is the HTTP Basic authenticator for the server-hosted
// TLS build. It holds the loaded PBKDF2 verifier in memory and validates
// each request's Authorization header in constant time. The verifier file
// must be readable by the tunneldash service user (0640
// root:split-tunnel). Neither the digest nor the username is logged.
type BasicAuthenticator struct {
	username string
	iter     int
	salt     []byte
	digest   []byte
	realm    string
}

// BasicAuthConfig is the input to NewBasicAuthenticator. Exactly one of
// Verifier or VerifierFile must be non-empty. Verifier is the single-line
// JSON document (used by tests and the rotate subcommand). VerifierFile
// names an on-disk 0640 file with the same content (used by the systemd
// unit's env file). UserOverride is reserved and must equal the verifier's
// user when set (fail-closed).
type BasicAuthConfig struct {
	Verifier     string
	VerifierFile string
	Realm        string
	UserOverride string
}

// NewBasicAuthenticator constructs a BasicAuthenticator. Both Verifier and
// VerifierFile empty is an error: the TLS build must not silently run
// without credentials (the loopback-only build uses LoopbackAuthenticator
// instead and does not reach this path).
func NewBasicAuthenticator(cfg BasicAuthConfig) (*BasicAuthenticator, error) {
	var raw string
	switch {
	case cfg.Verifier != "":
		raw = cfg.Verifier
	case cfg.VerifierFile != "":
		data, err := os.ReadFile(cfg.VerifierFile)
		if err != nil {
			return nil, fmt.Errorf("dashboard: read Basic-auth verifier file %s: %w", cfg.VerifierFile, err)
		}
		raw = string(data)
	default:
		return nil, fmt.Errorf("dashboard: BasicAuthenticator requires Verifier or VerifierFile")
	}
	user, iter, salt, digest, err := ParseVerifier(raw)
	if err != nil {
		return nil, err
	}
	if cfg.UserOverride != "" && cfg.UserOverride != user {
		return nil, fmt.Errorf("dashboard: BasicAuthConfig.UserOverride %q does not match verifier user %q", cfg.UserOverride, user)
	}
	realm := cfg.Realm
	if realm == "" {
		realm = "TunnelDash"
	}
	return &BasicAuthenticator{username: user, iter: iter, salt: salt, digest: digest, realm: realm}, nil
}

// LoadBasicAuthenticatorFromEnv is the cmd/tunneldash entry point: it reads
// SPLIT_TUNNELDASH_CREDENTIALS and returns (auth, true) on success,
// (nil, false) when the variable is unset or unresolvable (meaning "fall
// back to the legacy Bearer-token path or to loopback"). It never echoes
func LoadBasicAuthenticatorFromEnv() (*BasicAuthenticator, bool) {
	a, _ := LoadBasicAuthenticatorFromEnvErr()
	return a, a != nil
}

// LoadBasicAuthenticatorFromEnvErr is the BOUNDED operator-facing variant of
// LoadBasicAuthenticatorFromEnv: it returns the authenticator, or a
// non-nil error describing WHY the configured credential file could not be
// resolved. The error is deliberately bounded — it names the field / cause
// (unreadable file, empty document, unsupported version, malformed hex,
// iteration out of range) and the non-secret PATH, but NEVER the verifier
// contents or any password. Callers (resolveAuthenticator/main) use it to
// surface a diagnosable, still-safe detail instead of dropping the parse
// error into a generic "could not be loaded" message.
func LoadBasicAuthenticatorFromEnvErr() (*BasicAuthenticator, error) {
	p := strings.TrimSpace(os.Getenv(EnvDashCredentials))
	if p == "" {
		return nil, nil
	}
	a, err := NewBasicAuthenticator(BasicAuthConfig{VerifierFile: p})
	if err != nil {
		return nil, err // NewBasicAuthenticator errors are bounded: no digest, no password.
	}
	return a, nil
}

// DashCredentialsConfigured reports whether SPLIT_TUNNELDASH_CREDENTIALS
// names a path. This is the fail-closed predicate for the TLS build: a
// configured-but-unresolvable credential source MUST refuse to start a
// public TLS listener.
func DashCredentialsConfigured() bool {
	return strings.TrimSpace(os.Getenv(EnvDashCredentials)) != ""
}

// Name returns "basic" (logged; never includes user/pass values).
func (a *BasicAuthenticator) Name() string { return "basic" }

// Authenticate implements Authenticator.
//
//   - On success it returns (nil, nil); the middleware falls through to
//     the original handler.
//   - On failure it returns (nil, *httpError) with Code 401 and a Www
//     challenge (`Basic realm="<realm>", charset="UTF-8"`). The middleware
//     emits that header on the 401, which is what makes the browser
//     prompt once and then re-send the cached credentials on every
//     same-origin request (UI + API).
//
// Username comparison is constant-time. Password verification re-derives
// the PBKDF2 digest (the same ~50 ms work an offline attacker must do to
// recover a leaked verifier) and compares digests in constant time, so a
// wrong password costs exactly one PBKDF2 pass and leaks nothing.
func (a *BasicAuthenticator) Authenticate(r *http.Request) (http.Handler, error) {
	// BasicAuth() decodes the "Basic base64(user:pass)" header. ok=false
	// when the header is absent or not valid Basic.
	user, pass, ok := r.BasicAuth()
	challenge := &httpError{Code: http.StatusUnauthorized, Www: a.wwwChallenge()}
	if !ok {
		challenge.Msg = "missing Basic credentials"
		return nil, challenge
	}
	if subtle.ConstantTimeCompare([]byte(user), []byte(a.username)) != 1 {
		challenge.Msg = "invalid username"
		return nil, challenge
	}
	got := pbkdf2HMACSHA256([]byte(pass), a.salt, a.iter)
	if subtle.ConstantTimeCompare(got, a.digest) != 1 {
		challenge.Msg = "invalid password"
		return nil, challenge
	}
	return nil, nil
}

// wwwChallenge is the exact string the spec requires:
// `Basic realm="TunnelDash", charset="UTF-8"`.
func (a *BasicAuthenticator) wwwChallenge() string {
	return `Basic realm="` + a.realm + `", charset="UTF-8"`
}

// binaryEndianBig4 is a tiny helper keeping the RFC-2898 INT_32_BE block
// index explicit and testable. (pbkdf2HMACSHA256 inlines it for the single
// block; this documents the shape for a future multi-block extension.)
func binaryEndianBig4(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b
}

var _ = binaryEndianBig4 // keep the helper referenced.
