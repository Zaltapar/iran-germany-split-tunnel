// peercheck.go — the SO_PEERCRED peer-identity check, design §3.2.
//
// The agent accepts only connections from the dashboard user/process:
// the kernel-attested uid/gid plus a canonical /proc/<pid>/exe check.
// The design is split into two seams so unit tests exercise the exact
// decision logic without a real socket:
//
//   - CredentialSource: pulls the kernel-attested credentials from a
//     live connection. Platform-specific (Linux SO_PEERCRED in
//     peercheck_linux.go; a fail-closed stub everywhere else).
//   - PeerPolicy: the pure accept/reject decision over a credential
//     record. A missing attestation (available=false) always rejects
//     (fail closed), per the design.
//
// Tests inject a fakeCredentialSource to cover accept, wrong-uid,
// wrong-exe and unavailable (fail-closed) cases deterministically.
package controlagent

import (
	"fmt"
	"net"
)

// PeerCredentials is one kernel-attested peer identity record.
type PeerCredentials struct {
	PID int
	UID int
	GID int
	// ExePath is the resolved /proc/<pid>/exe target ("" when it
	// could not be resolved, which is always a reject).
	ExePath string
}

// CredentialSource pulls attested credentials for a live connection.
type CredentialSource interface {
	// PeerCredentials returns the attested peer credentials and whether
	// the attestation mechanism is available on this host. When
	// available is false the peer MUST be refused (fail closed).
	PeerCredentials(conn net.Conn) (PeerCredentials, bool, error)
}

// PeerPolicy binds the attestation to the exact expected identity:
// the dashboard uid/gid and the canonical tunneldash binary path.
// Both are operator-configured, never derived from the connection
// itself.
type PeerPolicy struct {
	ExpectedUID int
	ExpectedGID int
	// CanonicalExe is the absolute path the peer's /proc/<pid>/exe
	// must equal.
	CanonicalExe string
}

// Enforce runs the pure accept/reject decision for one peer record.
// The decision is separate from the syscall layer so it is
// unit-testable without a socket.
func (p *PeerPolicy) Enforce(creds PeerCredentials, available bool) error {
	if !available {
		return fmt.Errorf("%w: peer attestation unavailable on this host (fail closed)", ErrPeerRejected)
	}
	if creds.PID <= 0 {
		return fmt.Errorf("%w: peer pid not attested (fail closed)", ErrPeerRejected)
	}
	if creds.UID != p.ExpectedUID {
		return fmt.Errorf("%w: peer uid %d != expected %d", ErrPeerRejected, creds.UID, p.ExpectedUID)
	}
	if creds.GID != p.ExpectedGID {
		return fmt.Errorf("%w: peer gid %d != expected %d", ErrPeerRejected, creds.GID, p.ExpectedGID)
	}
	if creds.ExePath == "" {
		return fmt.Errorf("%w: peer exe path could not be resolved (fail closed)", ErrPeerRejected)
	}
	if creds.ExePath != p.CanonicalExe {
		return fmt.Errorf("%w: peer exe is not the canonical dashboard binary", ErrPeerRejected)
	}
	return nil
}

// fakeCredentialSource is the test double: it returns a fixed record
// and availability flag, so Enforce remains the only decision point
// under test.
type fakeCredentialSource struct {
	creds     PeerCredentials
	available bool
}

func (f *fakeCredentialSource) PeerCredentials(_ net.Conn) (PeerCredentials, bool, error) {
	return f.creds, f.available, nil
}
