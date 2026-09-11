package deploy

import (
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
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
	if err := ValidatePairRole(PairingState{PeerRole: RoleIran}, RoleIran); err == nil {
		t.Fatal("same local/peer role accepted")
	}
	if err := ValidatePairRole(PairingState{PeerRole: RoleGermany}, RoleIran); err != nil {
		t.Fatal(err)
	}
}
