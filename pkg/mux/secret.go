package mux

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strconv"
	"strings"
)

// DeriveSecret derives a 32-byte binary secret from a string using SHA256.
func DeriveSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// ValidateSecret verifies a shared secret using constant-time comparison.
func ValidateSecret(provided []byte, expected []byte) bool {
	return subtle.ConstantTimeCompare(provided, expected) == 1
}

// MinSecretLen is the minimum acceptable length (in characters) of the
// SPLIT_SECRET value. 32 characters of arbitrary text gives the SHA-256
// derivation at least ~160 bits of input entropy headroom against
// dictionary attacks; the RECOMMENDED way to generate a secret is
// `openssl rand -hex 32` (64 hex chars, 256 bits of randomness).
const MinSecretLen = 32

// Errors returned by ValidateSecretMaterial.
var (
	ErrSecretEmpty     = errors.New("secret: empty secret")
	ErrSecretKnownWeak = errors.New("secret: value is a known insecure placeholder")
	ErrSecretTooShort  = errors.New("secret: shorter than " + strconv.Itoa(MinSecretLen) + " characters (use: openssl rand -hex 32)")
)

// knownWeakSecrets are exact (case-insensitive) values that must never be
// used in production, no matter how they are configured.
var knownWeakSecrets = []string{
	"password", "passw0rd", "admin", "test", "secret", "changeme",
	"change-me", "split-secret", "default", "qwerty", "letmein",
	"123456", "12345678", "1234567890", "iloveyou",
}

// knownWeakPrefixes are case-insensitive prefixes of the standard
// placeholder values shipped in docs/examples ("CHANGE-ME-SECRET...",
// "YOUR-SECRET-HERE...").
var knownWeakPrefixes = []string{"change-me", "your-secret"}

// ValidateSecretMaterial is the startup policy for the SPLIT_SECRET value:
// it rejects empty secrets, the well-known placeholder/default values (the
// blocklist is ALWAYS enforced), and — unless allowWeak is set (the
// SPLIT_ALLOW_WEAK_SECRET=1 development/test bypass) — values shorter than
// MinSecretLen. The secret itself is never logged by this function.
func ValidateSecretMaterial(secret string, allowWeak bool) error {
	if secret == "" {
		return ErrSecretEmpty
	}
	low := strings.ToLower(secret)
	for _, w := range knownWeakSecrets {
		if low == w {
			return ErrSecretKnownWeak
		}
	}
	for _, p := range knownWeakPrefixes {
		if strings.HasPrefix(low, p) {
			return ErrSecretKnownWeak
		}
	}
	if !allowWeak && len(secret) < MinSecretLen {
		return ErrSecretTooShort
	}
	return nil
}
