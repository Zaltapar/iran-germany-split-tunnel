// issue21_classifier_test.go — Issue #21: unit test for the dial-error to
// SOCKS5 status classifier (bootstrapAckStatus). This locks the exact mapping
// the Germany node uses to build the FrameBootstrapAck payload, so a future
// refactor that flips a classification (e.g. treating a refused connect as a
// DNS failure) fails fast.
package node

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/routing"
)

// fakeTimeoutNetErr is a minimal net.Error with a controllable Timeout() so
// the classifier's "net.Error timed out -> 0x06" branch can be exercised
// without a real socket.
type fakeTimeoutNetErr struct{ timeout bool }

func (e fakeTimeoutNetErr) Error() string   { return "i/o timeout" }
func (e fakeTimeoutNetErr) Timeout() bool   { return e.timeout }
func (e fakeTimeoutNetErr) Temporary() bool { return true }

func TestBootstrapAckStatusClassification(t *testing.T) {
	// A DNSError that is NOT a timeout ("no such host") must classify as
	// host-unreachable/DNS (0x04), whereas a timed-out net.Error is 0x06 —
	// the ordering of the checks matters, so both are covered.
	dnsNoHost := &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}
	cases := []struct {
		name string
		err  error
		want byte
	}{
		{"nil (target accepted)", nil, 0x00},
		{"routing blocked", routing.ErrBlocked, 0x02},
		{"governor dial timeout", ErrTargetDialTimeout, 0x06},
		{"breaker open", ErrTargetBreakerOpen, 0x01},
		{"warp unreachable", routing.ErrWarpUnreachable, 0x01},
		{"deadline exceeded", os.ErrDeadlineExceeded, 0x06},
		{"net error timed out", fakeTimeoutNetErr{timeout: true}, 0x06},
		{"dns no such host", dnsNoHost, 0x04},
		{"conn refused (raw)", syscall.ECONNREFUSED, 0x05},
		{"conn refused (wrapped op)", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, 0x05},
		{"network unreachable", syscall.ENETUNREACH, 0x03},
		{"host unreachable", syscall.EHOSTUNREACH, 0x04},
		{"timed out (kernel)", syscall.ETIMEDOUT, 0x06},
		{"dns via error string", errors.New(`resolve "x": no such host`), 0x04},
		{"generic unrecognized", errors.New("boom"), 0x01},
	}
	for _, tc := range cases {
		if got := bootstrapAckStatus(tc.err); got != tc.want {
			t.Errorf("bootstrapAckStatus(%s) = 0x%02x, want 0x%02x", tc.name, got, tc.want)
		}
	}
}
