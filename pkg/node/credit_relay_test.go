package node

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// This file gates Phase B Slices 4-5:
//
//   - TestCreditEmitterNoOverAckOnPartialWrite (SF-1 / B1): a socket whose
//     Write returns (len-5, nil) must produce NO credit and a session close.
//     A real net.TCPConn cannot yield that shape (the stdlib couples
//     n<len(p) to err!=nil), so only a hand-written fake can — which is
//     exactly the B1 over-ack scenario the spec calls out.
//   - TestCreditsInertWhenDisabled: with the SPLIT_CREDITS_ENABLED flag off
//     (the default) a normal full download completes and every credit
//     counter stays at zero — byte-identical to the pre-credit behaviour.

// shortWriteSock is a net.Conn stub that performs a SHORT, error-free write
// (returns len(p)-5, nil). It is the deterministic B1 over-ack stand-in.
// Every other net.Conn method is a no-op / panic-free stub.
type shortWriteSock struct {
	writeCalls int
	writeShort int // short-write delta (Write returns len(p)-writeShort, nil)
}

func (s *shortWriteSock) Read(p []byte) (int, error) {
	// Down-path consumer never reads the client socket; block forever.
	select {}
}
func (s *shortWriteSock) Write(p []byte) (int, error) {
	if len(p) <= s.writeShort {
		return 0, nil // degenerate guard; real frames are far larger
	}
	return len(p) - s.writeShort, nil
}
func (s *shortWriteSock) Close() error                     { return nil }
func (s *shortWriteSock) SetDeadline(time.Time) error      { return nil }
func (s *shortWriteSock) SetReadDeadline(time.Time) error  { return nil }
func (s *shortWriteSock) SetWriteDeadline(time.Time) error { return nil }
func (s *shortWriteSock) LocalAddr() net.Addr              { return noopAddr{} }
func (s *shortWriteSock) RemoteAddr() net.Addr             { return noopAddr{} }

// TestCreditEmitterNoOverAckOnPartialWrite drives the down receiver with a
// socket that short-writes every frame. The B1 enforced shape must credit
// NOTHING (not even the short bytes) and terminate the stream; the session
// is closed with the client-socket write-error reason.
func TestCreditEmitterNoOverAckOnPartialWrite(t *testing.T) {
	cfg := Config{
		Role:                    RoleIran,
		Grace:                   2 * time.Second,
		RelayBufSize:            256,
		BufferBytes:             4096,
		KeepAliveInterval:       time.Hour,
		SessionBufferTotalBytes: 1 << 20,
		CreditsEnabled:          true,
	}
	n, err := NewNode(cfg, log.New(io.Discard, "", 0), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })

	upA, upB := testutil.NewMemPipe()
	downA, downB := testutil.NewMemPipe()
	_ = upB
	upH := n.InstallUp(upA, nil)
	downH := n.InstallDown(downA, nil)
	if upH == nil || downH == nil {
		t.Fatal("carrier install returned nil handle")
	}

	// Inject the short-write fake via the session's client-conn field: the
	// down relay reads sess.ClientConn (netConn = net.Conn alias), so no
	// socket parameter is needed.
	sock := &shortWriteSock{writeShort: 5}
	var id session.SessionID
	sess := session.NewSession(id, &session.Destination{}, sock, nil, n.ctx)
	sess.StreamIDUp = 1
	sess.StreamIDDown = 1
	sess.UpAtt = session.NewAttachment(n.cfg.Grace, nil)
	sess.DownAtt = session.NewAttachment(n.cfg.Grace, nil)
	if !sess.Activate() {
		t.Fatal("session activation failed")
	}
	if !sess.UpAtt.Attach(upH.gen) || !sess.DownAtt.Attach(downH.gen) {
		t.Fatal("attachment attach failed")
	}
	t.Cleanup(func() { sess.Close("test cleanup") })

	// The per-carrier-epoch down consumer writes download frames to sock.
	if ch := downH.carrier.Register(1); ch != nil {
		n.startChannelConsumer(sess, session.DirDown, downH, ch)
	}

	before := n.Metrics().Snapshot()

	// One data frame; the relay's socket write will short-return (len-5, nil).
	const payload = "PARTIAL-WRITE-PROBE"
	if err := mux.WriteFrame(downB, 1, mux.FrameData, []byte(payload)); err != nil {
		t.Fatalf("push data frame: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sess.State() == session.StateClosed || sess.State() == session.StateClosing {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	// B1: a partial/failed write must terminate the stream with the
	// client-socket write-error reason (never continue on a half-write).
	wantReason := "client socket write error"
	if got := sess.Reason(); got != wantReason {
		t.Fatalf("close reason = %q, want %q (a short write must close the session)", got, wantReason)
	}

	// B1 invariant: Σ bytesConsumed ≤ Σ bytes actually written. A short write
	// that was NOT fully accepted must credit NOTHING — neither the 5 short
	// bytes nor len(payload).
	after := n.Metrics().Snapshot()
	if got := after.RelayCreditConsumedBytesTotal - before.RelayCreditConsumedBytesTotal; got != 0 {
		t.Fatalf("RelayCreditConsumedBytesTotal grew by %d on a partial write; B1 forbids crediting un-accepted bytes", got)
	}
	if got := after.RelayCreditEmittedTotal - before.RelayCreditEmittedTotal; got != 0 {
		t.Fatalf("RelayCreditEmittedTotal grew by %d on a partial write; no credit may be emitted", got)
	}
	if got := after.RelaySocketWriteErrors - before.RelaySocketWriteErrors; got != 1 {
		t.Fatalf("RelaySocketWriteErrors delta = %d, want exactly 1 (the partial write is a socket write error)", got)
	}
}

// TestCreditsInertWhenDisabled verifies that with the feature flag OFF
// (default) a normal full download of ≥ creditBatchBytes still completes,
// and that NO credit counter ever moves — i.e. behaviour is byte-identical
// to the pre-credit build.
func TestCreditsInertWhenDisabled(t *testing.T) {
	cfg := Config{
		Role:                    RoleIran,
		Grace:                   2 * time.Second,
		RelayBufSize:            256,
		BufferBytes:             4096,
		KeepAliveInterval:       time.Hour,
		SessionBufferTotalBytes: 1 << 20,
		// CreditsEnabled stays false (the default-off flag, §15).
	}
	n, err := NewNode(cfg, log.New(io.Discard, "", 0), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if n.creditEmitter != nil || n.creditGate != nil {
		t.Fatal("credit machinery must be nil (inert) when CreditsEnabled is false")
	}
	t.Cleanup(func() { n.Close() })

	upA, upB := testutil.NewMemPipe()
	downA, downB := testutil.NewMemPipe()
	_ = upB
	upH := n.InstallUp(upA, nil)
	downH := n.InstallDown(downA, nil)
	if upH == nil || downH == nil {
		t.Fatal("carrier install returned nil handle")
	}

	clientNode, clientTest := testutil.NewMemPipe()
	var id session.SessionID
	sess := session.NewSession(id, &session.Destination{}, clientNode, nil, n.ctx)
	sess.StreamIDUp = 1
	sess.StreamIDDown = 1
	sess.UpAtt = session.NewAttachment(n.cfg.Grace, nil)
	sess.DownAtt = session.NewAttachment(n.cfg.Grace, nil)
	if !sess.Activate() {
		t.Fatal("session activation failed")
	}
	if !sess.UpAtt.Attach(upH.gen) || !sess.DownAtt.Attach(downH.gen) {
		t.Fatal("attachment attach failed")
	}
	t.Cleanup(func() { sess.Close("test cleanup") })

	if ch := downH.carrier.Register(1); ch != nil {
		n.startChannelConsumer(sess, session.DirDown, downH, ch)
	}

	before := n.Metrics().Snapshot()

	// A single MaxPayload frame is ≥ creditBatchBytes, so IF credits were on
	// a credit would be due here; with them off, nothing may be emitted.
	payload := make([]byte, mux.MaxPayload)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := mux.WriteFrame(downB, 1, mux.FrameData, payload); err != nil {
		t.Fatalf("push download frame: %v", err)
	}
	if got := readExact(t, clientTest, len(payload), "inert download"); string(got) != string(payload) {
		t.Fatalf("download bytes differ; want the full payload delivered")
	}

	after := n.Metrics().Snapshot()
	if got := after.RelayCreditEmittedTotal - before.RelayCreditEmittedTotal; got != 0 {
		t.Fatalf("RelayCreditEmittedTotal grew by %d; credits must be inert when disabled", got)
	}
	if got := after.RelayCreditConsumedBytesTotal - before.RelayCreditConsumedBytesTotal; got != 0 {
		t.Fatalf("RelayCreditConsumedBytesTotal grew by %d; credits must be inert when disabled", got)
	}
	if got := after.RelayCreditSentBytesTotal - before.RelayCreditSentBytesTotal; got != 0 {
		t.Fatalf("RelayCreditSentBytesTotal grew by %d; credits must be inert when disabled", got)
	}
	if got := after.RelayCreditGateParkTotal - before.RelayCreditGateParkTotal; got != 0 {
		t.Fatalf("RelayCreditGateParkTotal grew by %d; the gate must be inert when disabled", got)
	}
	if got := after.RelayCreditDroppedTotal - before.RelayCreditDroppedTotal; got != 0 {
		t.Fatalf("RelayCreditDroppedTotal grew by %d; no credit may be dropped when disabled", got)
	}
}
