package node_test

// Regression tests for the client-conn ownership during StartSession
// setup (external test: uses the topology harness from node_test.go).

import (
	"io"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// TestStartSessionFailureKeepsClientConnOpen is the regression test for
// the client-conn ownership defect: StartSession handed clientConn to
// session.NewSession at birth, so a SETUP failure (destination encoding
// failure, registration failure, header write failure) closed the
// client conn through the session's teardown — and the caller's
// socksReply(clientConn, 0x06) was then written to an already-closed
// conn: the SOCKS error reply was silently lost and the client saw a
// connection reset instead of a general-failure reply.
//
// The failure is triggered DETERMINISTICALLY with an invalid address
// type (WriteDestinationBuffer returns 0 for AddrType 0), so no
// carrier state manipulation or timing is involved.
func TestStartSessionFailureKeepsClientConnOpen(t *testing.T) {
	tp := newTopo(t, 3*time.Second)
	tp.setup()

	clientApp, clientIr := testutil.NewMemPipe()
	defer clientApp.Close()
	dest := &session.Destination{AddrType: 0, Addr: "x", Port: 80} // invalid type → encoding failure

	s, err := tp.iran.StartSession(clientIr, dest)
	if err == nil {
		t.Fatal("StartSession: expected an error for an invalid destination")
	}
	if s != nil {
		t.Fatalf("StartSession returned a session on failure: %v", s)
	}

	// The client conn must still be OPEN and deliverable: the caller
	// sends the SOCKS error reply after a setup failure. A write
	// deadline makes a broken conn fail fast instead of hanging.
	clientApp.SetDeadline(time.Now().Add(2 * time.Second))
	reply := []byte{0x05, 0x06, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0} // general failure
	if _, err := clientApp.Write(reply); err != nil {
		t.Fatalf("SOCKS error reply not deliverable after a setup failure: %v "+
			"(the session closed a conn it did not own)", err)
	}
	clientIr.SetDeadline(time.Now().Add(2 * time.Second))
	var buf [12]byte
	if _, err := io.ReadFull(clientIr, buf[:]); err != nil {
		t.Fatalf("reading the SOCKS error reply: %v", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x06 {
		t.Fatalf("reply = %v, want SOCKS5 general failure (0x05 0x06)", buf[:2])
	}
}
