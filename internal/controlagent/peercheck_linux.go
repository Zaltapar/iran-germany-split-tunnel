//go:build linux

// peercheck_linux.go — the production SO_PEERCRED attestation, design
// §3.2. Linux-only (SYS_GETSOCKOPT + SOL_SOCKET/SO_PEERCRED).
// Everything else is fail-closed by construction.
package controlagent

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// sopcCredentialSource pulls the kernel-attested credentials for a
// live unix-socket connection and resolves the peer's exe path from
// /proc/<pid>/exe.
type sopcCredentialSource struct{}

// NewSOPCCredentialSource returns the Linux SO_PEERCRED CredentialSource.
func NewSOPCCredentialSource() CredentialSource {
	return sopcCredentialSource{}
}

// ControlPlaneCredentialSource is the platform-neutral constructor the
// CLI wires into the agent (on Linux this is the SO_PEERCRED source; on
// every other platform it is the fail-closed unavailable source, so a
// stray `control-agent` start on a laptop never accepts a peer).
func ControlPlaneCredentialSource() CredentialSource { return NewSOPCCredentialSource() }

// PeerCredentials implements CredentialSource for a live connection.
func (sopcCredentialSource) PeerCredentials(conn net.Conn) (PeerCredentials, bool, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return PeerCredentials{}, false, fmt.Errorf("%w: connection is not a unix socket", ErrPeerRejected)
	}
	raw := unixConn.SyscallConn()

	var (
		cred       syscall.Ucred
		credDone   chan struct{} = make(chan struct{})
		syscallErr syscall.Errno
	)
	raw.Control(func(fd uintptr) {
		buf := (*[unsafe.Sizeof(syscall.Ucred{})]byte)(unsafe.Pointer(&cred))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT, fd,
			syscall.SOL_SOCKET, syscall.SO_PEERCRED,
			uintptr(unsafe.Pointer(buf)),
			uintptr(unsafe.Sizeof(cred)), 0,
		)
		syscallErr = errno
		if errno == 0 {
			close(credDone)
		}
	})
	select {
	case <-credDone:
	default:
		if syscallErr != 0 {
			return PeerCredentials{}, false, fmt.Errorf("%w: getsockopt(SO_PEERCRED): %v", ErrPeerRejected, syscallErr)
		}
		return PeerCredentials{}, false, fmt.Errorf("%w: getsockopt(SO_PEERCRED) did not complete", ErrPeerRejected)
	}

	// Resolve /proc/<pid>/exe. A resolution failure (proc not mounted,
	// process exited between getsockopt and readlink, ...) leaves
	// ExePath empty, which PeerPolicy.Enforce always rejects (fail
	// closed).
	uid := int(cred.Uid)
	gid := int(cred.Gid)
	pid := int(cred.Pid)
	exePath, _ := os.Readlink("/proc/" + itoa(pid) + "/exe")
	return PeerCredentials{PID: pid, UID: uid, GID: gid, ExePath: exePath}, true, nil
}

// itoa is a tiny helper to avoid importing strconv just for the
// /proc path (pid is small and non-negative by construction).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
