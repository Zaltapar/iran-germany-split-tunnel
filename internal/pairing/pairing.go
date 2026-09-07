// Package pairing implements the cross-host pairing exchange for the
// split-tunnel deployment (architecture doc, section 6.1; task T1).
//
// The exchange is two versioned blobs that the operator carries between the
// two hosts (clipboard / scp — there is no control channel in v1):
//
//	Blob A:  Iran  -> Germany   tunnel secret + Iran-side endpoint facts
//	Blob B:  Germany -> Iran    Reality PUBLIC parameters + down-carrier target
//
// The Reality PRIVATE key is generated and kept on Germany by the caller
// (task T3); it never enters any blob and no parser here accepts a field
// that could carry it (unknown JSON fields are rejected).
//
// Wire form (all ASCII, single line):
//
//	"splat-v1." + base64url(payload) + "." + base64url(sha256(payload))
//
// where payload is deterministic JSON (struct field order, no maps).
//
// Secret-safety contract (architecture doc, section 8):
//   - GenerateTunnelSecret uses crypto/rand (32 bytes, 64 hex chars) and is
//     checked against the Phase-6 policy (mux.ValidateSecretMaterial);
//   - no method returns the transmittable form except Encode (the explicit
//     "hand this to the other operator" call); String/Summary are redacted;
//   - error messages never echo blob contents or secret material — they
//     name the offending field only;
//   - Redact masks 32+-char hex runs (64-hex secrets, 40-hex digests) in
//     arbitrary text so deploy log lines can be passed through it.
package pairing

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
)

// BlobFormat is the wire prefix; the version is encoded both in the prefix
// and in the payload's "v" field (the prefix is the fast reject, the field
// is the authority).
const (
	BlobFormat = "splat-v1"
	// Version is the payload schema version this package speaks.
	Version = 1
)

// Error sentinels. Parse returns one of these (possibly wrapped with an
// aggregated field report); none of them include blob contents.
var (
	ErrMalformed = errors.New("pairing: malformed blob")
	ErrChecksum  = errors.New("pairing: checksum mismatch (blob tampered or truncated in transit)")
	ErrVersion   = errors.New("pairing: unsupported blob version")
	ErrWrongRole = errors.New("pairing: blob role mismatch (A/B)")
	ErrFields    = errors.New("pairing: invalid fields")
	ErrEmpty     = errors.New("pairing: empty blob")
)

// roleA/roleB are the payload "role" markers.
const (
	roleA = "a"
	roleB = "b"
)

// ---------------------------------------------------------------------------
// Field validation (shared helpers; fail closed, aggregate problems)
// ---------------------------------------------------------------------------

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var shortIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
var hex32RunRe = regexp.MustCompile(`[0-9a-fA-F]{32,}`)

// validHost reports whether h is a valid public host: an IP literal (v4 or
// v6) or an RFC 1123 hostname. No port, no scheme, no whitespace, no
// underscores. This is the boundary against operator-supplied input that
// later lands in config files and (never) in shell commands.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return true
	}
	if strings.ContainsAny(h, " \t\n:/_") {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false // a bare label is not a public domain name we accept
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			default:
				return false
			}
		}
	}
	return true
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// validUploadDomain validates the public WebSocket origin domain carried in
// blob A (host part of wss://<domain>/upload).
func validUploadDomain(d string) bool {
	return validHost(d)
}

// validRealityPublicKey validates a base64 (StdEncoding) X25519 public key:
// exactly 32 bytes when decoded.
func validRealityPublicKey(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\n\r") {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// validateTunnelSecret reuses the Phase-6 policy as the single source of
// truth (never re-implemented here).
func validateTunnelSecret(s string) error { return mux.ValidateSecretMaterial(s, false) }

// problems aggregates field errors into one fail-closed message that names
// fields, never values.
func fieldErr(problems []string) error {
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrFields, strings.Join(problems, "; "))
}

// ---------------------------------------------------------------------------
// Secret generation
// ---------------------------------------------------------------------------

// GenerateTunnelSecret returns a fresh 256-bit random tunnel secret encoded
// as 64 hex chars — the documented recommended form (openssl rand -hex 32
// equivalent) — and verifies it against the Phase-6 policy before returning.
func GenerateTunnelSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("pairing: %w", err)
	}
	s := hex.EncodeToString(buf)
	if err := validateTunnelSecret(s); err != nil {
		// Practically impossible for 256-bit random input; fail closed
		// rather than return a policy-violating secret.
		return "", fmt.Errorf("pairing: generated secret failed policy check: %w", err)
	}
	return s, nil
}

// GenerateShortID returns a fresh 16-hex-char Reality shortId (8 random
// bytes).
func GenerateShortID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("pairing: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// GenerateUUID returns a fresh RFC 4122 version-4 UUID (lowercase).
func GenerateUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("pairing: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ---------------------------------------------------------------------------
// Blob A (Iran -> Germany)
// ---------------------------------------------------------------------------

// BlobA carries everything Germany needs from Iran: the tunnel secret and
// the public upload origin domain.
type BlobA struct {
	V            int    `json:"v"`
	Role         string `json:"role"`
	Secret       string `json:"secret"`
	UploadDomain string `json:"uploadDomain"`
}

// NewBlobA validates its inputs and builds an in-memory BlobA. It never
// transmits anything; Encode produces the wire form explicitly.
func NewBlobA(secret, uploadDomain string) (*BlobA, error) {
	var problems []string
	if err := validateTunnelSecret(secret); err != nil {
		problems = append(problems, "secret: "+err.Error())
	}
	if !validUploadDomain(uploadDomain) {
		problems = append(problems, "uploadDomain: invalid public domain")
	}
	if err := fieldErr(problems); err != nil {
		return nil, err
	}
	return &BlobA{V: Version, Role: roleA, Secret: secret, UploadDomain: uploadDomain}, nil
}

// Encode renders the canonical wire form.
func (a *BlobA) Encode() (string, error) {
	if err := a.validate(); err != nil {
		return "", err
	}
	return encodeBlob(a)
}

func (a *BlobA) validate() error {
	var problems []string
	if a.Secret == "" {
		problems = append(problems, "secret: missing")
	} else if err := validateTunnelSecret(a.Secret); err != nil {
		problems = append(problems, "secret: "+err.Error())
	}
	if !validUploadDomain(a.UploadDomain) {
		problems = append(problems, "uploadDomain: invalid public domain")
	}
	return fieldErr(problems)
}

// ParseBlobA decodes and fully validates a blob A. Every failure is one of
// the package sentinels; none echo the blob contents.
func ParseBlobA(s string) (*BlobA, error) {
	b, err := parse(s, roleA)
	if err != nil {
		return nil, err
	}
	a, ok := b.(*BlobA)
	if !ok {
		return nil, fmt.Errorf("%w: expected role %q", ErrWrongRole, roleA)
	}
	return a, nil
}

// Summary is a redacted, log-safe one-line description. The secret never
// appears.
func (a *BlobA) Summary() string {
	return fmt.Sprintf("blobA{version=%d, uploadDomain=%s, secret=<redacted>}", a.V, a.UploadDomain)
}

func (a *BlobA) String() string { return a.Summary() }

// ---------------------------------------------------------------------------
// Blob B (Germany -> Iran)
// ---------------------------------------------------------------------------

// PublicParams are the Reality/VLESS PUBLIC parameters Iran's outbound
// needs. No private material may ever be represented here.
type PublicParams struct {
	RealityPublicKey string `json:"realityPublicKey"` // base64 StdEncoding, 32 bytes decoded
	ShortID          string `json:"shortId"`          // 16 hex chars
	UUID             string `json:"uuid"`             // RFC 4122 v4, lowercase
}

// DownTarget is Germany's public down-carrier endpoint (the Reality
// inbound).
type DownTarget struct {
	Host string `json:"host"` // public IP or domain of the Germany host
	Port int    `json:"port"` // Reality inbound port
}

// BlobB carries everything Iran needs from Germany: the public Reality
// parameters and the down-carrier target.
type BlobB struct {
	V       int          `json:"v"`
	Role    string       `json:"role"`
	Public  PublicParams `json:"public"`
	Germany DownTarget   `json:"germany"`
}

// NewBlobB validates its inputs and builds an in-memory BlobB.
func NewBlobB(p PublicParams, g DownTarget) (*BlobB, error) {
	b := &BlobB{V: Version, Role: roleB, Public: p, Germany: g}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// Encode renders the canonical wire form.
func (b *BlobB) Encode() (string, error) {
	if err := b.validate(); err != nil {
		return "", err
	}
	return encodeBlob(b)
}

func (b *BlobB) validate() error {
	var problems []string
	if !validRealityPublicKey(b.Public.RealityPublicKey) {
		problems = append(problems, "public.realityPublicKey: must be base64 encoding a 32-byte key")
	}
	if !shortIDRe.MatchString(b.Public.ShortID) {
		problems = append(problems, "public.shortId: must be 16 lowercase hex chars")
	}
	if !uuidV4Re.MatchString(b.Public.UUID) {
		problems = append(problems, "public.uuid: must be an RFC 4122 version-4 UUID (lowercase)")
	}
	if !validHost(b.Germany.Host) {
		problems = append(problems, "germany.host: invalid public host")
	}
	if !validPort(b.Germany.Port) {
		problems = append(problems, "germany.port: must be 1..65535")
	}
	return fieldErr(problems)
}

// ParseBlobB decodes and fully validates a blob B.
func ParseBlobB(s string) (*BlobB, error) {
	b, err := parse(s, roleB)
	if err != nil {
		return nil, err
	}
	res, ok := b.(*BlobB)
	if !ok {
		return nil, fmt.Errorf("%w: expected role %q", ErrWrongRole, roleB)
	}
	return res, nil
}

// Summary is a log-safe one-line description. Every value here is public
// by definition, but the summary never includes the tunnel secret (it is
// not in this blob).
func (b *BlobB) Summary() string {
	return fmt.Sprintf("blobB{version=%d, uuid=%s, shortId=%s, down=%s:%d}",
		b.V, b.Public.UUID, b.Public.ShortID, b.Germany.Host, b.Germany.Port)
}

func (b *BlobB) String() string { return b.Summary() }

// ---------------------------------------------------------------------------
// Wire encode/decode
// ---------------------------------------------------------------------------

// encodeBlob renders the deterministic JSON payload, then the
// "splat-v1.<b64url(payload)>.<b64url(sha256(payload))>" form.
func encodeBlob(v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("pairing: encode: %w", err)
	}
	sum := sha256.Sum256(payload)
	return BlobFormat + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// parse decodes the wire form and returns the typed, validated blob, or a
// sentinel error. The generic shape check (prefix, part count, checksum,
// strict JSON, version) happens before the role-specific cast.
func parse(s, wantRole string) (any, error) {
	if s == "" {
		return nil, ErrEmpty
	}
	if strings.TrimSpace(s) != s {
		return nil, fmt.Errorf("%w: surrounding whitespace", ErrMalformed)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 dot-separated parts", ErrMalformed)
	}
	if parts[0] != BlobFormat {
		return nil, fmt.Errorf("%w: unknown format prefix", ErrMalformed)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url", ErrMalformed)
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(got) != sha256.Size {
		return nil, fmt.Errorf("%w: checksum is not a 32-byte digest", ErrMalformed)
	}
	sum := sha256.Sum256(payload)
	// Constant-time: a tamper must not be distinguishable by timing.
	if subtle.ConstantTimeCompare(got, sum[:]) != 1 {
		return nil, ErrChecksum
	}

	// Decode into a generic envelope to read version + role before the
	// role-specific cast. This decode is LENIENT on extra fields; the
	// strict per-type decode below is the unknown-field guard.
	var env struct {
		V    int    `json:"v"`
		Role string `json:"role"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("%w: payload is not a JSON object", ErrMalformed)
	}
	if env.V != Version {
		return nil, fmt.Errorf("%w: got %d, this build speaks %d", ErrVersion, env.V, Version)
	}
	if env.Role != wantRole {
		var other string
		if env.Role == roleA {
			other = "A (Iran to Germany)"
		} else if env.Role == roleB {
			other = "B (Germany to Iran)"
		} else {
			other = "unknown"
		}
		return nil, fmt.Errorf("%w: this is a blob %s; pass it to the matching role", ErrWrongRole, other)
	}

	// Strict second decode into the concrete type (unknown fields rejected).
	if wantRole == roleA {
		var a BlobA
		if err := strictDecode(payload, &a); err != nil {
			return nil, err
		}
		if err := a.validate(); err != nil {
			return nil, err
		}
		return &a, nil
	}
	var b BlobB
	if err := strictDecode(payload, &b); err != nil {
		return nil, err
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// strictDecode decodes the payload into v with unknown fields rejected.
// Error hygiene: Go's JSON errors embed VALUE fragments (e.g.
// `cannot unmarshal string "..."`), which would echo blob contents. Only
// unknown-field errors (which name FIELD names only) are surfaced verbatim;
// everything else collapses to a generic sentinel message.
func strictDecode(payload []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "unknown field") {
			return fmt.Errorf("%w: %s", ErrMalformed, msg)
		}
		return fmt.Errorf("%w: invalid payload for this role", ErrMalformed)
	}
	return nil
}

// Redact masks 32+-character hex runs (64-hex tunnel secrets, 40-hex
// digests, long hex IDs) with a fixed marker so deploy log lines can be
// passed through it before reaching the journal. It is deliberately
// conservative: short hex (16-char shortIds, ports) and non-hex tokens are
// left alone.
func Redact(text string) string {
	return hex32RunRe.ReplaceAllString(text, "<redacted>")
}
