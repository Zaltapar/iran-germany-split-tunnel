package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/pairing"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
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

// ApplyAGermany is the Germany-side `pair apply` (architecture doc §6.1): it
// consumes and validates a Blob A and derives the RETURN Blob B from the
// host's INSTALLED Reality configuration, so apply is complete and
// idempotent — a first apply transitions to "a-applied" AND emits Blob B, and
// a re-run (e.g. after Blob B was lost in transit) re-emits the SAME Blob B
// without regenerating anything.
//
// Blob B determinism by construction: the public Reality parameters are read
// from the live Germany Xray config at configPath — the public key is DERIVED
// from the installed private key (xray.ReadInstalledRealityParams), never
// freshly generated, so it always matches the installed inbound — and the
// down port comes from that inbound too; only the host is supplied by the
// caller (operator env or auto-detected interface address). When the
// committed manifest asserts a Reality public-parameter fingerprint, the
// read-back parameters must reproduce it, or the live config is not what this
// host deployed and apply fails closed. The fingerprint's guard scope is the
// PUBLIC parameters only (SNI/shortId/UUID, never the keypair — see
// realityFingerprint), so it authenticates parameters, not keys: the derived
// public key matches the live inbound only because the deployment restarts
// xray-germany whenever the config BYTES rotate (LinuxAdapter.applyUnit,
// DEFECT-1). A stale inbound would otherwise make Blob B un-authenticatable.
//
// The returned state is "a-applied" with fingerprints [A, B] — digests only.
// Raw blobs, the tunnel secret, and all key material never enter state, logs,
// or errors. On ANY error no state is returned and nothing is committed.
func (p Pairing) ApplyAGermany(encoded, downHost, configPath string) (string, PairingState, error) {
	_, aState, err := p.ApplyA(encoded)
	if err != nil {
		return "", PairingState{}, err
	}
	installed, err := xray.ReadInstalledRealityParams(configPath)
	if err != nil {
		return "", PairingState{}, err
	}
	if p.Store != nil {
		if current, lerr := p.Store.Load(); lerr != nil {
			if !errors.Is(lerr, os.ErrNotExist) {
				return "", PairingState{}, lerr
			}
		} else if recorded := recordedRealityFingerprint(current.Components.Xray); recorded != "" {
			if got := realityFingerprint(xray.RealityParams{SNI: installed.SNI, ShortID: installed.ShortID, UUID: installed.UUID}); got != recorded {
				return "", PairingState{}, fmt.Errorf("deploy: installed Germany Reality parameters do not match the committed deployment; refusing to emit a pairing blob")
			}
		}
	}
	encodedB, _, err := p.GenerateB(pairing.PublicParams{
		RealityPublicKey: installed.RealityPublicKey,
		ShortID:          installed.ShortID,
		UUID:             installed.UUID,
		SNI:              installed.SNI,
	}, pairing.DownTarget{Host: downHost, Port: installed.Port})
	if err != nil {
		return "", PairingState{}, err
	}
	// The committed state stays a-applied (apply owns it); the Blob B
	// fingerprint rides along with Blob A's so re-apply and audit see both.
	return encodedB, PairingState{
		PeerRole:     aState.PeerRole,
		State:        aState.State,
		Fingerprints: []string{fingerprint(encoded), fingerprint(encodedB)},
	}, nil
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
