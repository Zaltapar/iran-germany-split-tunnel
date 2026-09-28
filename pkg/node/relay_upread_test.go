package node

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// This file pins the targeted fix for the client-socket read defect on the
// Iran up leg. A single non-EOF read error on the client socket (a RST, a
// "use of closed network connection" from a concurrent teardown, or a
// teardown artifact under load) used to be fatal for the WHOLE session via
// sess.Close — killing the in-flight DOWN download. The fix (upReadErrorPolicy
// + the relayShapeA up branch) downgrades that error to a tolerated up
// half-close so the download finishes; benign teardown artifacts are
// suppressed entirely (no counter, no re-close). The target/down read path is
// UNCHANGED: a non-EOF target read error stays fatal.
//
// The integrity invariant is NOT weakened: ordered DATA is either delivered or
// the stream is explicitly terminated. No DATA is dropped here.

// faultSock is a controllable net.Conn whose Read first drains a fixed byte
// buffer and then returns a fixed error (or blocks forever when no error is
// set). It is the deterministic fault-injection stand-in for the client /
// target socket.
type faultSock struct {
	mu      sync.Mutex
	data    []byte
	err     error
	readErr bool // whether the next drained read reports err
}

// seedRead arms one read that yields data then err together (the
// "read returned bytes AND a non-EOF error" shape a real RST can produce).
func (f *faultSock) seedRead(data string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data = []byte(data)
	f.err = err
	if data != "" {
		f.readErr = true // report err on the read that delivers data
	} else {
		f.readErr = false // block until the buffer drains; then err
	}
}

func (f *faultSock) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.data) > 0 {
		n := copy(p, f.data)
		f.data = f.data[n:]
		if f.readErr {
			f.readErr = false
			return n, f.err
		}
		return n, nil
	}
	if f.err != nil {
		return 0, f.err
	}
	// Idle socket: block so an untriggered relay parks (never observed in
	// these tests, which always drive a read that returns).
	select {}
}

func (f *faultSock) Write(p []byte) (int, error) { return len(p), nil }
func (f *faultSock) Close() error                { return nil }
func (f *faultSock) SetDeadline(time.Time) error { return nil }
func (f *faultSock) SetReadDeadline(time.Time) error {
	return nil
}
func (f *faultSock) SetWriteDeadline(time.Time) error { return nil }
func (f *faultSock) LocalAddr() net.Addr              { return noopAddr{} }
func (f *faultSock) RemoteAddr() net.Addr             { return noopAddr{} }

type noopAddr struct{}

func (noopAddr) Network() string { return "fault" }
func (noopAddr) String() string  { return "fault" }

// newRelayReadNode builds a bare Iran node (no TargetDial, hour keepalive so
// pings never interfere, large aggregate budget so the fault relay never
// parks on charge) with an installed up + down carrier and a live session
// (up attached to the up carrier, down attached to the down carrier, the
// per-carrier-epoch down consumer running). It returns the node, the session,
// the test-side of the client socket, and the peer end of the down carrier
// (to push download frames).
func newRelayReadNode(t *testing.T) (*Node, *session.Session, *testutil.MemConn, *testutil.MemConn) {
	t.Helper()
	cfg := Config{
		Role:                    RoleIran,
		Grace:                   2 * time.Second,
		RelayBufSize:            256,
		BufferBytes:             4096,
		KeepAliveInterval:       time.Hour,
		SessionBufferTotalBytes: 1 << 20,
	}
	n := NewNode(cfg, log.New(io.Discard, "", 0), []byte("0123456789abcdef0123456789abcdef"))
	t.Cleanup(func() { n.Close() })

	upA, upB := testutil.NewMemPipe()
	downA, downB := testutil.NewMemPipe()
	_ = upB // up frames are not driven in these tests; up writes go to upA's carrier
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

	// The per-carrier-epoch down consumer (shape B) delivers download
	// frames to the client socket.
	if ch := downH.carrier.Register(1); ch != nil {
		n.startChannelConsumer(sess, session.DirDown, downH, ch)
	}
	return n, sess, clientTest, downB
}

// readExact drains exactly n bytes from c within the deadline.
func readExact(t *testing.T, c *testutil.MemConn, n int, what string) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	got, err := io.ReadFull(c, buf)
	if err != nil {
		t.Fatalf("reading %s: %v (got %d/%d)", what, err, got, n)
	}
	_ = c.SetReadDeadline(time.Time{})
	return buf
}

// runUpRelay starts the up relayShapeA on sock and waits for it to return.
func runUpRelay(t *testing.T, n *Node, sess *session.Session, sock netConn) {
	t.Helper()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		n.relayShapeA(sess, session.DirUp, sock)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("up relay did not return (parked)")
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
//  1. A non-EOF up read error during an active download is tolerated as a
//     half-close: the down download COMPLETES, the session is NOT force-closed
//     mid-download, and the up side is closed.
//
// ---------------------------------------------------------------------------
func TestUpReadErrorDuringActiveDownloadIsToleratedAsHalfClose(t *testing.T) {
	n, sess, clientTest, downB := newRelayReadNode(t)
	sock := &faultSock{}
	// One read delivers up bytes AND a genuine non-EOF error (a RST shape):
	// the up relay must tolerate it, NOT tear down the session.
	sock.seedRead("GET\n", errors.New("read: connection reset by peer"))
	go func() {
		n.relayShapeA(sess, session.DirUp, sock)
	}()

	// Drive the in-flight download on the down carrier (Germany→client).
	// The download must survive the up error: the up half-close must not have
	// cancelled the session.
	const payload = "DOWNLOAD-DATA-OK"
	if err := mux.WriteFrame(downB, 1, mux.FrameData, []byte(payload)); err != nil {
		t.Fatalf("push download frame: %v", err)
	}

	// Wait for the up relay to have run its half-close. The session must
	// still be alive on the down direction (not force-closed).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sess.DirClosed(session.DirUp) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !sess.DirClosed(session.DirUp) {
		t.Fatalf("up direction not half-closed after a non-EOF up read error")
	}
	if sess.State() == session.StateClosed {
		t.Fatalf("session force-closed mid-download; want it to stay up for the down transfer (state=%s)", sess.State())
	}
	if got := sess.Reason(); got == "client socket read error" {
		t.Fatal("up read error was treated as a fatal session close (the defect)")
	}

	// The download COMPLETES: all bytes reach the client.
	if got := readExact(t, clientTest, len(payload), "download after up half-close"); string(got) != payload {
		t.Fatalf("download = %q, want %q (the in-flight transfer must finish)", got, payload)
	}

	// Complete the down side cleanly so the finalizeDrain timer no-ops.
	sess.MarkDirClosed(session.DirDown, "target EOF")
}

// ---------------------------------------------------------------------------
//  2. With the session already Closing/Closed, a non-EOF up read error must NOT
//     double-count RelaySocketReadError and must NOT re-run teardown.
//
// ---------------------------------------------------------------------------
func TestUpReadErrorWhenSessionAlreadyClosingIsSuppressed(t *testing.T) {
	var id session.SessionID
	sess := session.NewSession(id, nil, nil, nil, nil)
	if !sess.Activate() {
		t.Fatal("activation failed")
	}
	// A concurrent goroutine's teardown already owns the close.
	sess.Close("prior teardown")

	// The classifier must suppress (no counter, no re-close).
	if p := upReadErrorPolicy(sess, errors.New("use of closed network connection")); p != upReadSuppressed {
		t.Fatalf("upReadErrorPolicy on a Closing/Closed session = %v, want upReadSuppressed", p)
	}
	// Teardown is a sync.Once: it does not re-run and the reason is stable.
	stateBefore := sess.State()
	reasonBefore := sess.Reason()
	sess.Close("late re-close attempt") // no-op: already Closing/Closed
	if sess.State() != stateBefore || sess.Reason() != reasonBefore {
		t.Fatalf("re-close changed session state/reason (state %v->%v, reason %q->%q); teardown must not re-run",
			stateBefore, sess.State(), reasonBefore, sess.Reason())
	}
}

// ---------------------------------------------------------------------------
//  3. A benign os.ErrClosed / net.ErrClosed from the up read is suppressed
//     (no counter, no close) even while the session is still Active.
//
// ---------------------------------------------------------------------------
func TestUpReadErrorBenignErrClosedIsSuppressed(t *testing.T) {
	var id session.SessionID
	sess := session.NewSession(id, nil, nil, nil, nil)
	if !sess.Activate() {
		t.Fatal("activation failed")
	}
	if p := upReadErrorPolicy(sess, net.ErrClosed); p != upReadSuppressed {
		t.Fatalf("net.ErrClosed policy = %v, want upReadSuppressed", p)
	}
	if p := upReadErrorPolicy(sess, os.ErrClosed); p != upReadSuppressed {
		t.Fatalf("os.ErrClosed policy = %v, want upReadSuppressed", p)
	}
	// A genuine, non-benign error while Active is NOT suppressed — it is
	// downgraded to a tolerated up half-close (never suppressed, never fatal).
	if p := upReadErrorPolicy(sess, errors.New("connection reset by peer")); p != upReadHalfClose {
		t.Fatalf("genuine error policy = %v, want upReadHalfClose", p)
	}
}

// ---------------------------------------------------------------------------
//  4. A genuine non-EOF, non-benign error on a NOT-closing session still
//     increments RelaySocketReadError (the metric stays truthful) and results
//     in the up half-close (not a full fatal close) per the new policy.
//
// ---------------------------------------------------------------------------
func TestUpReadErrorGenuineStillCounted(t *testing.T) {
	n, sess, _, _ := newRelayReadNode(t)
	before := n.Metrics().Snapshot().RelaySocketReadErrors

	sock := &faultSock{}
	sock.seedRead("", errors.New("read: connection reset by peer"))
	runUpRelay(t, n, sess, sock)

	if !sess.DirClosed(session.DirUp) {
		t.Fatalf("genuine up read error did not half-close the up direction")
	}
	if sess.State() == session.StateClosed {
		t.Fatalf("genuine up read error force-closed the whole session; want a half-close")
	}
	after := n.Metrics().Snapshot().RelaySocketReadErrors
	if after-before != 1 {
		t.Fatalf("RelaySocketReadErrors delta = %d, want exactly 1 (truthful count)", after-before)
	}
}

// ---------------------------------------------------------------------------
//  5. The target/down read path (Germany side) must STILL treat a non-EOF
//     error as fatal: the metric is incremented and the session is closed with
//     the target-read reason. This guards that the up tolerance cannot mask a
//     real target failure.
//
// ---------------------------------------------------------------------------
func TestDownReadErrorStillFatalOnTargetSide(t *testing.T) {
	cfg := Config{
		Role:                    RoleGermany,
		Grace:                   2 * time.Second,
		RelayBufSize:            256,
		BufferBytes:             4096,
		KeepAliveInterval:       time.Hour,
		SessionBufferTotalBytes: 1 << 20,
	}
	n := NewNode(cfg, log.New(io.Discard, "", 0), []byte("0123456789abcdef0123456789abcdef"))
	t.Cleanup(func() { n.Close() })

	downA, _ := testutil.NewMemPipe()
	downH := n.InstallDown(downA, nil)
	if downH == nil {
		t.Fatal("down carrier not installed")
	}
	targetNode, _ := testutil.NewMemPipe()
	var id session.SessionID
	sess := session.NewSession(id, &session.Destination{}, nil, targetNode, n.ctx)
	sess.StreamIDDown = 1
	sess.DownAtt = session.NewAttachment(n.cfg.Grace, nil)
	if !sess.Activate() {
		t.Fatal("activation failed")
	}
	if !sess.DownAtt.Attach(downH.gen) {
		t.Fatal("down attach failed")
	}

	before := n.Metrics().Snapshot().RelaySocketReadErrors
	sock := &faultSock{}
	sock.seedRead("", errors.New("target read: connection reset"))
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		n.relayShapeA(sess, session.DirDown, sock)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("down relay did not return")
	}
	wg.Wait()

	if sess.State() != session.StateClosed && sess.State() != session.StateClosing {
		t.Fatalf("down read error did not close the session; state=%s", sess.State())
	}
	if sess.Reason() != "target socket read error" {
		t.Fatalf("down read close reason = %q, want the fatal target-read reason", sess.Reason())
	}
	after := n.Metrics().Snapshot().RelaySocketReadErrors
	if after-before != 1 {
		t.Fatalf("RelaySocketReadErrors delta = %d, want exactly 1 (fatal target read must stay counted)", after-before)
	}
}
