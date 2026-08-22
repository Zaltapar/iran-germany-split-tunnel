package mux

import (
	"crypto/sha256"
	"crypto/subtle"
)

func DeriveSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func ValidateSecret(provided []byte, expected []byte) bool {
	return subtle.ConstantTimeCompare(provided, expected) == 1
}
