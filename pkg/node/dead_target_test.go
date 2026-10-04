package node_test

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// TestDeadTargetIsDroppedCleanly is the regression pin for the 93.184.215.14
// false alarm: when Germany's target dial fails (a dead / unreachable
// destination — today's probe used a stale example.com A record that timed
// out), the session must be DROPPED CLEANLY, not half-wired and not reported
// as a data-flow regression. Concretely, this test proves, through the REAL
// two-node production paths:
//
//  1. Germany's bootstrapUpStream reached the target dial and it failed
//     exactly once (no retry) -> node.go:1145 "target %s dial failed" ->
//     the drop() closure writes a FrameClose over the up carrier
//     (node.go:1126) and deregisters the stream.
//  2. Germany NEVER wired the session into its store (the drop happens
//     before store.Add), and its TargetDialFailure metric is exactly 1.
//  3. Iran's up watcher (startUpWatcher, relays.go:456) received the peer
//     FrameClose and closed its session with the clean peer-close reason
//     "up stream closed by peer" — NOT a data/socket error.
//  4. The CLIENT connection was closed by teardown (session.go:528), so no
//     byte can ever flow on it: the 0-byte proxy response that today's
//     misdiagnosis saw is the EXPECTED, CORRECT outcome of a clean drop.
//
// The up-carrier close is the BENIGN teardown artifact (relays.go:198), the
// effect of this clean drop, not a regression. This test is the pin that
// keeps it from being misread again.
func TestDeadTargetIsDroppedCleanly(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	logger := log.New(io.Discard, "", 0)
	secretB := []byte(secret)

	// Germany: the target dial ALWAYS fails (the dead 93.184.215.14 case:
	// i/o timeout). Counted so the test proves the dial was attempted
	// exactly once — reached bootstrap, failed, dropped, no retry.
	var dialAttempts int32
	de, err := node.NewNode(node.Config{
		Role: node.RoleGermany, Grace: 2 * time.Second,
		RelayBufSize: 4096, BufferBytes: 256 << 10, KeepAliveInterval: time.Hour,
		TargetDial: func(addr string) (net.Conn, error) {
			atomic.AddInt32(&dialAttempts, 1)
			return nil, errors.New("i/o timeout")
		},
	}, logger, secretB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(de.Close)

	iran, err := node.NewNode(node.Config{
		Role: node.RoleIran, Grace: 2 * time.Second,
		RelayBufSize: 4096, BufferBytes: 256 << 10, KeepAliveInterval: time.Hour,
	}, logger, secretB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iran.Close)

	// Install both carriers over in-memory pipes, exactly as node_test.go's
	// installUp/installDown do. Up: Iran=server, Germany=client. Down:
	// Iran=client, Germany=server.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	upIr, upDe := testutil.NewMemPipe()
	upDeReady := make(chan struct{})
	go func() {
		defer close(upDeReady)
		br, err := mux.CarrierAuth(ctx, upDe, true, mux.RoleUpload, secretB)
		if err != nil {
			return
		}
		de.InstallUp(upDe, br)
	}()
	if irBr, err := mux.CarrierAuth(ctx, upIr, false, mux.RoleUpload, secretB); err != nil {
		t.Fatalf("up auth (iran): %v", err)
	} else {
		iran.InstallUp(upIr, irBr)
	}

	downIr, downDe := testutil.NewMemPipe()
	downDeReady := make(chan struct{})
	go func() {
		defer close(downDeReady)
		br, err := mux.CarrierAuth(ctx, downDe, false, mux.RoleDownload, secretB)
		if err != nil {
			return
		}
		de.InstallDown(downDe, br)
	}()
	if dBr, err := mux.CarrierAuth(ctx, downIr, true, mux.RoleDownload, secretB); err != nil {
		t.Fatalf("down auth (iran): %v", err)
	} else {
		iran.InstallDown(downIr, dBr)
	}

	// Both carriers ready on BOTH nodes before a session is started.
	select {
	case <-upDeReady:
	case <-time.After(5 * time.Second):
		t.Fatal("germany up carrier never installed")
	}
	select {
	case <-downDeReady:
	case <-time.After(5 * time.Second):
		t.Fatal("germany down carrier never installed")
	}

	// Open a client socket (Iran-adopted) and start a session toward the
	// dead target. StartSession writes the destination FrameHeader over the
	// up carrier; it does NOT wait for Germany's (failing) bootstrap.
	clientNode, clientIr := testutil.NewMemPipe()
	t.Cleanup(func() { clientNode.Close(); clientIr.Close() })
	dest := &session.Destination{AddrType: session.AddrTypeIPv4, Addr: "93.184.215.14", Port: 443}

	s, err := iran.StartSession(clientIr, dest)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	// Germany bootstraps the stream, its TargetDial fails, it drops the
	// session and emits a FrameClose. Iran's up watcher turns that into a
	// clean session close. Wait for the clean drop to complete on BOTH ends.
	eventually(t, 10*time.Second, "dead target dropped (Iran session closed by peer)", func() bool {
		return s.State() == session.StateClosed
	})

	// (1) The target dial was reached and failed exactly once (no retry).
	if got := atomic.LoadInt32(&dialAttempts); got != 1 {
		t.Fatalf("germany target dial attempts = %d, want 1 (reached bootstrap, failed, dropped, no retry)", got)
	}
	// (2) Germany counted the dial failure and NEVER wired a session.
	if ds := de.Metrics().Snapshot(); ds.TargetDialFailure != 1 {
		t.Fatalf("germany TargetDialFailure = %d, want 1", ds.TargetDialFailure)
	}
	if got := de.Store().Count(); got != 0 {
		t.Fatalf("germany session store = %d after a dead target, want 0 (dropped, not half-wired)", got)
	}
	// (3) Iran's session was closed by the peer's FrameClose (the clean
	// drop) — the peer reason, never a socket/data error.
	if got := s.Reason(); got != "up stream closed by peer" {
		t.Fatalf("iran session close reason = %q, want %q (peer dropped it at a dead target)", got, "up stream closed by peer")
	}
	// (4) The CLIENT connection was closed by teardown: no byte can flow.
	// This is the correct outcome today's probe misread as a regression.
	clientNode.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, rerr := clientNode.Read([]byte{0}); rerr == nil {
		t.Fatal("client connection was NOT closed after the clean drop (a read succeeded)")
	}
}
