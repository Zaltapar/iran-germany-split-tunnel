package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
)

// Pairing is the deploy boundary for the existing T1 exchange. It stores only
// state/fingerprints; blob values are returned to the CLI for one-time display.
type Pairing struct {
	Store *Store
}

func (p Pairing) GenerateA(secret, uploadDomain string) (string, PairingState, error) {
	blob, err := pairing.NewBlobA(secret, uploadDomain)
	if err != nil {
		return "", PairingState{}, err
	}
	encoded, err := blob.Encode()
	if err != nil {
		return "", PairingState{}, err
	}
	return encoded, PairingState{PeerRole: RoleGermany, State: "a-generated", Fingerprints: []string{fingerprint(encoded)}}, nil
}

func (p Pairing) ApplyA(encoded string) (*pairing.BlobA, PairingState, error) {
	blob, err := pairing.ParseBlobA(encoded)
	if err != nil {
		return nil, PairingState{}, err
	}
	return blob, PairingState{PeerRole: RoleIran, State: "a-applied", Fingerprints: []string{fingerprint(encoded)}}, nil
}

func (p Pairing) GenerateB(public pairing.PublicParams, target pairing.DownTarget) (string, PairingState, error) {
	blob, err := pairing.NewBlobB(public, target)
	if err != nil {
		return "", PairingState{}, err
	}
	encoded, err := blob.Encode()
	if err != nil {
		return "", PairingState{}, err
	}
	return encoded, PairingState{PeerRole: RoleIran, State: "b-generated", Fingerprints: []string{fingerprint(encoded)}}, nil
}

func (p Pairing) ApplyB(encoded string) (*pairing.BlobB, PairingState, error) {
	blob, err := pairing.ParseBlobB(encoded)
	if err != nil {
		return nil, PairingState{}, err
	}
	return blob, PairingState{PeerRole: RoleGermany, State: "finalized", Fingerprints: []string{fingerprint(encoded)}}, nil
}

func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func ValidatePairRole(state PairingState, role string) error {
	if role != RoleIran && role != RoleGermany {
		return fmt.Errorf("deploy: invalid pairing role")
	}
	if state.PeerRole != "" && state.PeerRole == role {
		return fmt.Errorf("deploy: pairing peer role equals local role")
	}
	return nil
}
