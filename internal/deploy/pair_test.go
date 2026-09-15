package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

func TestPairingAAndBDelegateToT1(t *testing.T) {
	p := Pairing{}
	secret := strings.Repeat("a", 64)
	a, stateA, err := p.GenerateA(secret, "upload.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if stateA.State != "a-generated" || len(stateA.Fingerprints) != 1 || strings.Contains(stateA.Fingerprints[0], secret) {
		t.Fatalf("stateA = %+v", stateA)
	}
	blobA, appliedA, err := p.ApplyA(a)
	if err != nil || blobA == nil || appliedA.State != "a-applied" {
		t.Fatalf("ApplyA: blob=%v state=%+v err=%v", blobA, appliedA, err)
	}

	b, stateB, err := p.GenerateB(pairing.PublicParams{
		RealityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ShortID:          "0123456789abcdef",
		UUID:             "550e8400-e29b-41d4-a716-446655440000",
		SNI:              "www.example.org",
	}, pairing.DownTarget{Host: "203.0.113.10", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if stateB.State != "b-generated" || len(stateB.Fingerprints) != 1 {
		t.Fatalf("stateB = %+v", stateB)
	}
	blobB, appliedB, err := p.ApplyB(b)
	if err != nil || blobB == nil || appliedB.State != "finalized" {
		t.Fatalf("ApplyB: blob=%v state=%+v err=%v", blobB, appliedB, err)
	}
}

func TestPairingRejectsTamperAndRoleCollision(t *testing.T) {
	p := Pairing{}
	secret := strings.Repeat("b", 64)
	encoded, _, err := p.GenerateA(secret, "upload.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.ApplyA(encoded + "x"); err == nil {
		t.Fatal("tampered blob accepted")
	}
	if _, _, err := p.ApplyAGermany(encoded+"x", "203.0.113.10", installedConfigPath(t, defaultInstalledParams())); err == nil {
		t.Fatal("tampered blob accepted (ApplyAGermany)")
	}
	if err := ValidatePairRole(PairingState{PeerRole: RoleIran}, RoleIran); err == nil {
		t.Fatal("same local/peer role accepted")
	}
	if err := ValidatePairRole(PairingState{PeerRole: RoleGermany}, RoleIran); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// ApplyAGermany — Germany `pair apply` consuming Blob A and emitting Blob B
// ---------------------------------------------------------------------------
const installedUUID = "550e8400-e29b-41d4-a716-446655440000"
const installedShortID = "0123456789abcdef"
const installedSNI = "www.example.org"
const installedDownHost = "203.0.113.10"

// fixedPrivateRaw is the documented fixed non-production test vector
// (internal/xray keygen_test.go): a TEST key, never a deployed one.
const fixedPrivateRaw = "gAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHkA"

func defaultInstalledParams() xray.RealityParams {
	return xray.RealityParams{SNI: installedSNI, ShortID: installedShortID, UUID: installedUUID}
}

// installedConfigPath renders a real Germany config through the authoritative
// generator into the test directory and returns its path (the Germany
// ApplyAGermany reads back its Blob B from this file).
func installedConfigPath(t *testing.T, params xray.RealityParams) string {
	t.Helper()
	// Fixed, documented non-production vectors: the private key is the
	// clamped 32-byte test scalar (base64 RawURL); the public field only has
	// to satisfy the render-time shape check (32 RawURL bytes) — the reader
	// DERIVES the real public key from the private key.
	kp := &xray.Keypair{PrivateRaw: fixedPrivateRaw, PublicRaw: strings.Repeat("A", 43)}
	out, err := xray.RenderGermanyConfig(params, kp)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xray-germany.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func germanyStoreWith(t *testing.T, fp string) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{
		Role:       RoleGermany,
		Generation: "g-test",
		Paths:      Paths{StateRoot: store.Root},
		Firewall:   FirewallState{Backend: "none"},
	}
	m.Components.Xray = ComponentState{Version: xrayPinnedForTest, RealityFingerprint: fp}
	if _, err := store.Commit(m, "test"); err != nil {
		t.Fatal(err)
	}
	return store
}

const xrayPinnedForTest = "v26.3.27"

func TestApplyAGermanyEmitsDeterministicBlobB(t *testing.T) {
	store := germanyStoreWith(t, realityFingerprint(defaultInstalledParams()))
	p := Pairing{Store: store}
	secret := strings.Repeat("c", 64)
	blobA, _, err := p.GenerateA(secret, "upload.example.org")
	if err != nil {
		t.Fatal(err)
	}

	blobB, state, err := p.ApplyAGermany(blobA, installedDownHost, installedConfigPath(t, defaultInstalledParams()))
	if err != nil {
		t.Fatal(err)
	}
	if state.PeerRole != RoleIran || state.State != "a-applied" || len(state.Fingerprints) != 2 {
		t.Fatalf("state = %+v", state)
	}
	if state.Fingerprints[0] != fingerprint(blobA) || state.Fingerprints[1] != fingerprint(blobB) {
		t.Fatal("fingerprints must be [blobA, blobB]")
	}
	parsed, err := pairing.ParseBlobB(blobB)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Germany.Host != installedDownHost || parsed.Germany.Port != 443 {
		t.Fatalf("down target = %+v", parsed.Germany)
	}
	if parsed.Public.ShortID != installedShortID || parsed.Public.UUID != installedUUID || parsed.Public.SNI != installedSNI {
		t.Fatalf("public params = %+v", parsed.Public)
	}
	// The public key must be the DERIVATION of the installed private key —
	// not a fresh pair (Blob B has to match the installed inbound).
	installed, err := xray.ReadInstalledRealityParams(installedConfigPath(t, defaultInstalledParams()))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Public.RealityPublicKey != installed.RealityPublicKey {
		t.Fatal("blob B public key does not match the installed inbound")
	}

	// Re-apply (Blob B lost scenario) re-emits the SAME blob deterministically.
	again, stateAgain, err := p.ApplyAGermany(blobA, installedDownHost, installedConfigPath(t, defaultInstalledParams()))
	if err != nil {
		t.Fatal(err)
	}
	if again != blobB {
		t.Fatal("re-apply must emit the identical Blob B")
	}
	if stateAgain.State != "a-applied" {
		t.Fatalf("re-apply state = %+v", stateAgain)
	}

}

func TestApplyAGermanyNilStoreSkipsFingerprintGuard(t *testing.T) {
	p := Pairing{}
	blobA, _, err := p.GenerateA(strings.Repeat("d", 64), "upload.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.ApplyAGermany(blobA, installedDownHost, installedConfigPath(t, defaultInstalledParams())); err != nil {
		t.Fatalf("nil-store (unit-test/legacy) path must succeed: %v", err)
	}
}

func TestApplyAGermanyRejectsFingerprintMismatch(t *testing.T) {
	// The committed manifest recorded DIFFERENT Reality public parameters than
	// the live config carries — the config on disk is not what this host
	// deployed, so emitting a blob from it would poison the hand-off.
	other := xray.RealityParams{SNI: "different.example.org", ShortID: installedShortID, UUID: installedUUID}
	store := germanyStoreWith(t, realityFingerprint(other))
	p := Pairing{Store: store}
	blobA, _, err := p.GenerateA(strings.Repeat("e", 64), "upload.example.org")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = p.ApplyAGermany(blobA, installedDownHost, installedConfigPath(t, defaultInstalledParams()))
	if err == nil || !strings.Contains(err.Error(), "do not match the committed deployment") {
		t.Fatalf("error = %v, want fail-closed mismatch", err)
	}
}

func TestApplyAGermanyRejectsInvalidInputs(t *testing.T) {
	p := Pairing{}
	blobA, _, err := p.GenerateA(strings.Repeat("f", 64), "upload.example.org")
	if err != nil {
		t.Fatal(err)
	}
	// A Blob B is not a Blob A.
	blobB, _, err := p.GenerateB(pairing.PublicParams{
		RealityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ShortID:          installedShortID,
		UUID:             installedUUID,
		SNI:              installedSNI,
	}, pairing.DownTarget{Host: installedDownHost, Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	_, _, errWrong := p.ApplyAGermany(blobB, installedDownHost, installedConfigPath(t, defaultInstalledParams()))
	if errWrong == nil || !errors.Is(errWrong, pairing.ErrWrongRole) {
		t.Fatalf("Blob B fed to apply: error = %v, want role mismatch", errWrong)
	}
	// A host the Blob B validator refuses must fail closed BEFORE any state.
	if _, _, err := p.ApplyAGermany(blobA, "not a host!", installedConfigPath(t, defaultInstalledParams())); err == nil {
		t.Fatal("invalid down host accepted")
	}
	// A missing config file is a read failure.
	_, _, errMissing := p.ApplyAGermany(blobA, installedDownHost, filepath.Join(t.TempDir(), "gone.json"))
	if errMissing == nil || !errors.Is(errMissing, xray.ErrInstalledConfigRead) {
		t.Fatalf("error = %v, want config read failure", errMissing)
	}
}

// TestApplyAGermanyStateHasNoSecrets commits the emitted state and scans the
// persisted manifest bytes for any raw blob or secret material — only SHA-256
// fingerprints may reach disk.
func TestApplyAGermanyStateHasNoSecrets(t *testing.T) {
	store := germanyStoreWith(t, realityFingerprint(defaultInstalledParams()))
	p := Pairing{Store: store}
	secret := strings.Repeat("7", 64)
	blobA, _, err := p.GenerateA(secret, "upload.example.org")
	if err != nil {
		t.Fatal(err)
	}
	blobB, state, err := p.ApplyAGermany(blobA, installedDownHost, installedConfigPath(t, defaultInstalledParams()))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	manifest.Pairing = state
	if _, err := store.Commit(manifest, "pair-apply"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(store.Root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{blobA, blobB, secret, fixedPrivateRaw} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("committed state contains raw material %q", forbidden)
		}
	}
	// The committed fingerprints must be the digests of the raw blobs.
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Pairing.Fingerprints) != 2 {
		t.Fatalf("fingerprints = %v", loaded.Pairing.Fingerprints)
	}
	if loaded.Pairing.Fingerprints[0] != fingerprint(blobA) || loaded.Pairing.Fingerprints[1] != fingerprint(blobB) {
		t.Fatal("committed fingerprints do not match [blobA, blobB]")
	}
}
