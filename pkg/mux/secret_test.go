package mux

import (
	"bytes"
	"testing"
)

// TestDeriveSecretDeterministic verifies the same string always derives the
// same 32-byte secret.
func TestDeriveSecretDeterministic(t *testing.T) {
	a := DeriveSecret("passphrase")
	b := DeriveSecret("passphrase")
	if len(a) != 32 {
		t.Fatalf("DeriveSecret len = %d, want 32", len(a))
	}
	if !bytes.Equal(a, b) {
		t.Error("DeriveSecret is not deterministic")
	}
}

// TestDeriveSecretDistinct verifies different strings derive different
// secrets.
func TestDeriveSecretDistinct(t *testing.T) {
	if bytes.Equal(DeriveSecret("a"), DeriveSecret("b")) {
		t.Error("different inputs produced identical secrets")
	}
}

// TestValidateSecret covers the constant-time comparison paths.
func TestValidateSecret(t *testing.T) {
	s := DeriveSecret("shared")
	if !ValidateSecret(s, s) {
		t.Error("equal secrets rejected")
	}
	other := DeriveSecret("shared2")
	if ValidateSecret(s, other) {
		t.Error("different secrets accepted")
	}
	if ValidateSecret(s[:31], s) {
		t.Error("different-length secrets accepted")
	}
	if ValidateSecret(nil, s) {
		t.Error("nil vs secret accepted")
	}
}
