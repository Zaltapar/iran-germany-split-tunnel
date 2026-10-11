// peercheck_test.go — the pure peer-identity decision (design §3.2),
// driven through the injected CredentialSource so no real socket is
// needed. Accept, wrong-uid, wrong-gid, wrong-exe, unresolvable exe,
// and unavailable-attestation (fail closed) are all asserted.
package controlagent

import (
	"errors"
	"testing"
)

func TestPeerPolicyAccept(t *testing.T) {
	p := &PeerPolicy{ExpectedUID: 123, ExpectedGID: 456, CanonicalExe: "/usr/local/bin/tunneldash"}
	got := p.Enforce(PeerCredentials{PID: 42, UID: 123, GID: 456, ExePath: "/usr/local/bin/tunneldash"}, true)
	if got != nil {
		t.Fatalf("expected accept, got %v", got)
	}
}

func TestPeerPolicyRejectWrongUID(t *testing.T) {
	p := &PeerPolicy{ExpectedUID: 123, ExpectedGID: 456, CanonicalExe: "/usr/local/bin/tunneldash"}
	got := p.Enforce(PeerCredentials{PID: 42, UID: 999, GID: 456, ExePath: "/usr/local/bin/tunneldash"}, true)
	if !errors.Is(got, ErrPeerRejected) {
		t.Fatalf("expected ErrPeerRejected, got %v", got)
	}
}

func TestPeerPolicyRejectWrongGID(t *testing.T) {
	p := &PeerPolicy{ExpectedUID: 123, ExpectedGID: 456, CanonicalExe: "/usr/local/bin/tunneldash"}
	got := p.Enforce(PeerCredentials{PID: 42, UID: 123, GID: 777, ExePath: "/usr/local/bin/tunneldash"}, true)
	if !errors.Is(got, ErrPeerRejected) {
		t.Fatalf("expected ErrPeerRejected, got %v", got)
	}
}

func TestPeerPolicyRejectWrongExe(t *testing.T) {
	p := &PeerPolicy{ExpectedUID: 123, ExpectedGID: 456, CanonicalExe: "/usr/local/bin/tunneldash"}
	got := p.Enforce(PeerCredentials{PID: 42, UID: 123, GID: 456, ExePath: "/tmp/evil"}, true)
	if !errors.Is(got, ErrPeerRejected) {
		t.Fatalf("expected ErrPeerRejected, got %v", got)
	}
}

func TestPeerPolicyRejectUnresolvableExe(t *testing.T) {
	p := &PeerPolicy{ExpectedUID: 123, ExpectedGID: 456, CanonicalExe: "/usr/local/bin/tunneldash"}
	got := p.Enforce(PeerCredentials{PID: 42, UID: 123, GID: 456, ExePath: ""}, true)
	if !errors.Is(got, ErrPeerRejected) {
		t.Fatalf("expected ErrPeerRejected for empty exe, got %v", got)
	}
}

func TestPeerPolicyRejectNoPID(t *testing.T) {
	p := &PeerPolicy{ExpectedUID: 123, ExpectedGID: 456, CanonicalExe: "/usr/local/bin/tunneldash"}
	got := p.Enforce(PeerCredentials{PID: 0, UID: 123, GID: 456, ExePath: "/usr/local/bin/tunneldash"}, true)
	if !errors.Is(got, ErrPeerRejected) {
		t.Fatalf("expected ErrPeerRejected for pid<=0, got %v", got)
	}
}

// TestPeerPolicyUnavailableFailsClosed is the platform guarantee: when the
// attestation mechanism is unavailable (non-Linux, or getsockopt
// failure) the decision MUST reject. This is the unit that makes the
// "fail closed when unavailable" stance testable on any OS.
func TestPeerPolicyUnavailableFailsClosed(t *testing.T) {
	p := &PeerPolicy{ExpectedUID: 123, ExpectedGID: 456, CanonicalExe: "/usr/local/bin/tunneldash"}
	creds := PeerCredentials{PID: 42, UID: 123, GID: 456, ExePath: "/usr/local/bin/tunneldash"}
	got := p.Enforce(creds, false)
	if !errors.Is(got, ErrPeerRejected) {
		t.Fatalf("expected fail-closed rejection, got %v", got)
	}
}
