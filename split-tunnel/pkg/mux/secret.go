package mux

import (
	"crypto/sha256"
	"crypto/subtle"
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
