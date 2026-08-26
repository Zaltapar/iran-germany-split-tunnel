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

// TestValidateSecretMaterial covers the startup secret policy (Phase 6):
// blocklisted placeholders are always rejected, short values are rejected
// unless the dev bypass is set, and strong values pass.
func TestValidateSecretMaterial(t *testing.T) {
	strong := "0123456789abcdef0123456789abcdef01234567" // 40 chars

	cases := []struct {
		name      string
		secret    string
		allowWeak bool
		wantErr   error
	}{
		{"empty", "", false, ErrSecretEmpty},
		{"password blocklisted", "password", false, ErrSecretKnownWeak},
		{"password case-insensitive", "PASSWORD", true, ErrSecretKnownWeak},
		{"test blocklisted even with bypass", "test", true, ErrSecretKnownWeak},
		{"change-me prefix blocklisted", "CHANGE-ME-SECRET-USE-A-LONG-RANDOM-STRING", true, ErrSecretKnownWeak},
		{"your-secret prefix blocklisted", "your-secret-here-0123456789abcdef0123456789", true, ErrSecretKnownWeak},
		{"short rejected", "weak-short-secret-abc", false, ErrSecretTooShort},
		{"short allowed with bypass", "weak-short-secret-abc", true, nil},
		{"strong ok", strong, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSecretMaterial(tc.secret, tc.allowWeak)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if err != tc.wantErr {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
