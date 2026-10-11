//go:build !linux

// peercheck_other.go — non-Linux hosts cannot do SO_PEERCRED. The
// source is unavailable (fail closed): every peer is rejected, and the
// pure decision logic (PeerPolicy.Enforce) is still fully
// unit-testable through an injected fakeCredentialSource.
package controlagent

import (
	"errors"
	"net"
)

// unavailableCredentialSource is the fail-closed default on every
// platform without SO_PEERCRED.
type unavailableCredentialSource struct{}

// NewUnavailableCredentialSource returns the fail-closed CredentialSource
// used on non-Linux builds.
func NewUnavailableCredentialSource() CredentialSource {
	return unavailableCredentialSource{}
}

func (unavailableCredentialSource) PeerCredentials(_ net.Conn) (PeerCredentials, bool, error) {
	// available=false: PeerPolicy.Enforce will reject.
	return PeerCredentials{}, false, errors.New("SO_PEERCRED unavailable on this host")
}
