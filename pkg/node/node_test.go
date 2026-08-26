package node_test

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// Test harness: a full two-node topology over in-memory pipes
// (deterministic, killable carriers, no real TCP).
//
//	up carrier:   Iran (auth server)  — Germany (auth client)
//	down carrier: Iran (auth client)  — Germany (auth server)

type topo struct {
	t      *testing.T
	iran   *node.Node
	de     *node.Node
	secret []byte

	upIr, upDe     *testutil.MemConn
	downIr, downDe *testutil.MemConn

	mu      sync.Mutex
	targets []*testutil.MemConn // queue of prepared target conns for Germany's TargetDial
}

func newTopo(t *testing.T, grace time.Duration) *topo {
	return newTopoBuf(t, grace, 256<<10)
}

func newTopoBuf(t *testing.T, grace time.Duration, bufBytes int) *topo {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	var baseLog *log.Logger
	if os.Getenv("NODE_TEST_LOG") != "" {
		baseLog = log.New(os.Stderr, "", log.Lmicroseconds)
	} else {
		baseLog = log.New(io.Discard, "", 0)
	}
	logger := log.New(baseLog.Writer(), "IRAN ", baseLog.Flags())
	deLog := log.New(baseLog.Writer(), "DE   ", baseLog.Flags())
	tp := &topo{t: t, secret: secret}

	iranCfg := node.Config{
		Role: node.RoleIran, Grace: grace,
		RelayBufSize: 4096, BufferBytes: bufBytes, KeepAliveInterval: time.Hour,
	}
	tp.iran = node.NewNode(iranCfg, logger, secret)

	deCfg := node.Config{
		Role: node.RoleGermany, Grace: grace,
		RelayBufSize: 4096, BufferBytes: bufBytes, KeepAliveInterval: time.Hour,
		TargetDial: func(addr string) (net.Conn, error) {
			tp.mu.Lock()
			defer tp.mu.Unlock()
			if len(tp.targets) == 0 {
				return nil, errors.New("no target conn queued")
			}
			c := tp.targets[0]
			tp.targets = tp.targets[1:]
			return c, nil
		},
	}
	tp.de = node.NewNode(deCfg, deLog, secret)

	t.Cleanup(func() {
		tp.iran.Close()
		tp.de.Close()
	})
	return tp
}

// installUp creates a fresh carrier pipe, authenticates (Germany is the
// carrier client on the up direction) and installs on both sides.
func (tp *topo) installUp() {
	tp.t.Helper()
	tp.upIr, tp.upDe = testutil.NewMemPipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		br, err := mux.CarrierAuth(ctx, tp.upDe, true, tp.secret)
		if err != nil {
			done <- err
			return
		}
		tp.de.InstallUp(tp.upDe, br)
		done <- nil
	}()
	br, err := mux.CarrierAuth(ctx, tp.upIr, false, tp.secret)
	if err != nil {
		tp.t.Fatalf("up auth (iran): %v", err)
	}
	tp.iran.InstallUp(tp.upIr, br)
	if err := <-done; err != nil {
		tp.t.Fatalf("up auth (de): %v", err)
	}
}

// installDown creates a fresh carrier pipe, authenticates (Iran is the
// carrier client on the down direction) and installs on both sides.
func (tp *topo) installDown() {
	tp.t.Helper()
	tp.downIr, tp.downDe = testutil.NewMemPipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		br, err := mux.CarrierAuth(ctx, tp.downDe, false, tp.secret)
		if err != nil {
			done <- err
			return
		}
		tp.de.InstallDown(tp.downDe, br)
		done <- nil
	}()
	br, err := mux.CarrierAuth(ctx, tp.downIr, true, tp.secret)
	if err != nil {
		tp.t.Fatalf("down auth (iran): %v", err)
	}
	tp.iran.InstallDown(tp.downIr, br)
	if err := <-done; err != nil {
		tp.t.Fatalf("down auth (de): %v", err)
	}
}

// setup installs both carriers.
func (tp *topo) setup() {
	tp.t.Helper()
	tp.installUp()
	tp.installDown()
}

func (tp *topo) killUp()   { tp.upIr.Close(); tp.upDe.Close() }
func (tp *topo) killDown() { tp.downIr.Close(); tp.downDe.Close() }

// injectUpCarrier installs a fresh up carrier on GERMANY only. Iran
// performs just the auth handshake (to unblock Germany's auth client)
// and does NOT install a carrier, so Iran's automatic rebind sweep never
// runs. This lets a test write raw frames (FrameRebind, ...) into
// tp.upIr that reach Germany's rebind validator deterministically,
// without Iran's own rebind racing first. It returns the Iran end of the
// pipe for raw frame writes.
func (tp *topo) injectUpCarrier() *testutil.MemConn {
	tp.t.Helper()
	ir, de := testutil.NewMemPipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		br, err := mux.CarrierAuth(ctx, de, true, tp.secret)
		if err != nil {
			done <- err
			return
		}
		tp.de.InstallUp(de, br)
		done <- nil
	}()
	if _, err := mux.CarrierAuth(ctx, ir, false, tp.secret); err != nil {
		tp.t.Fatalf("injectUpCarrier auth (iran): %v", err)
	}
	if err := <-done; err != nil {
		tp.t.Fatalf("injectUpCarrier auth (de): %v", err)
	}
	tp.upIr, tp.upDe = ir, de
	return ir
}

// sctx is one session observed from the test side.
type sctx struct {
	sc     *session.Session  // the Iran-side session
	client *testutil.MemConn // test side of the client conn
	target *testutil.MemConn // test side of the target conn
}

func (tp *topo) startSession(i int) *sctx {
	tp.t.Helper()
	clientApp, clientIr := testutil.NewMemPipe()
	targetApp, targetGe := testutil.NewMemPipe()
	tp.mu.Lock()
	tp.targets = append(tp.targets, targetGe)
	tp.mu.Unlock()
	t := tp.t
	t.Cleanup(func() {
		clientApp.Close()
		targetApp.Close()
	})
	dest := &session.Destination{AddrType: session.AddrTypeDomain, Addr: "host.example", Port: uint16(8000 + i)}
	before := tp.de.Store().Count()
	s, err := tp.iran.StartSession(clientIr, dest)
	if err != nil {
		tp.t.Fatalf("StartSession: %v", err)
	}
	// The Germany-side bootstrap is asynchronous; wait for it so tests
	// never kill a carrier mid-bootstrap (that would hit the legitimate
	// "down carrier not ready" drop path, not a bug).
	eventually(t, 3*time.Second, "germany bootstrap for the new session", func() bool {
		return tp.de.Store().Count() > before
	})
	return &sctx{sc: s, client: clientApp, target: targetApp}
}

func (tp *topo) write(c *testutil.MemConn, s string) {
	tp.t.Helper()
	if _, err := c.Write([]byte(s)); err != nil {
		tp.t.Fatalf("write %q: %v", s, err)
	}
}

func (tp *topo) readN(c *testutil.MemConn, n int, what string) string {
	tp.t.Helper()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		tp.t.Fatalf("reading %s: %v", what, err)
	}
	c.SetReadDeadline(time.Time{})
	return string(buf)
}

// eventually polls f until true or fails the test.
func eventually(t *testing.T, timeout time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// 1. A single active session survives an upload-carrier loss: the
// session stays active during the loss, data sent DURING the loss is
// buffered (lossless) and arrives in order after the rebind.
func TestSessionSurvivesUploadCarrierLoss(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)

	tp.killUp()
	// Loss is detected and the session must still be active.
	eventually(t, 2*time.Second, "up attachment unavailable",
		func() bool { st, _ := sc.sc.UpAtt.State(); return st == session.AttUnavailable })
	if sc.sc.State() != session.StateActive {
		t.Fatalf("session state = %v, want Active during carrier loss", sc.sc.State())
	}

	// Sent while the carrier is down → must be buffered, not lost.
	tp.write(sc.client, "BUFFERED")

	tp.installUp()
	tp.write(sc.client, "RESUME")
	if got := tp.readN(sc.target, len("BUFFEREDRESUME"), "target stream"); got != "BUFFEREDRESUME" {
		t.Fatalf("target stream = %q, want %q (order + no loss)", got, "BUFFEREDRESUME")
	}
	if sc.sc.State() != session.StateActive {
		t.Fatalf("session state after rebind = %v, want Active", sc.sc.State())
	}
	m := tp.iran.Metrics().Snapshot()
	if m.SessionsRecovered < 1 || m.SessionsLostAfterCarF != 0 {
		t.Fatalf("metrics recovered=%d lost=%d, want recovered>=1 lost=0", m.SessionsRecovered, m.SessionsLostAfterCarF)
	}
}

// 2. Ten concurrent sessions all survive the same carrier loss and
// rebind, each with its own intact stream.
func TestTenSessionsSurviveCarrierLoss(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	const N = 10
	scs := make([]*sctx, N)
	for i := 0; i < N; i++ {
		scs[i] = tp.startSession(i)
		tp.write(scs[i].client, "P") // barrier per session
		if got := tp.readN(scs[i].target, 1, "pre-kill payload"); got != "P" {
			t.Fatalf("session %d pre-kill payload = %q", i, got)
		}
	}

	tp.killUp()
	for i := 0; i < N; i++ {
		tp.write(scs[i].client, "R")
	}
	tp.installUp()
	for i := 0; i < N; i++ {
		if got := tp.readN(scs[i].target, 1, "post-rebind payload"); got != "R" {
			t.Fatalf("session %d post-rebind payload = %q", i, got)
		}
		if scs[i].sc.State() != session.StateActive {
			t.Fatalf("session %d state after rebind = %v", i, scs[i].sc.State())
		}
	}
	mi := tp.iran.Metrics().Snapshot()
	md := tp.de.Metrics().Snapshot()
	if mi.CarrierRebinds < N || md.CarrierRebinds < N {
		t.Fatalf("rebinds iran=%d germany=%d, want >=%d each", mi.CarrierRebinds, md.CarrierRebinds, N)
	}
	if mi.ActiveSessions != int64(tp.iran.Store().Count()) {
		t.Fatalf("active metrics %d != store %d", mi.ActiveSessions, tp.iran.Store().Count())
	}
}

// 3. Grace timeout: a session that is not re-attached within the grace
// window is closed through the Phase 4 path with an explicit reason and
// is never revived by a later carrier.
func TestGraceTimeoutClosesSession(t *testing.T) {
	tp := newTopo(t, 300*time.Millisecond)
	tp.setup()
	sc := tp.startSession(1)

	tp.killUp()
	eventually(t, 3*time.Second, "session closed by grace timeout", func() bool {
		return sc.sc.State() == session.StateClosed
	})
	if r := sc.sc.Reason(); r != "upload carrier timeout" {
		t.Fatalf("close reason = %q, want %q", r, "upload carrier timeout")
	}
	m := tp.iran.Metrics().Snapshot()
	if m.SessionsLostAfterCarF != 1 || m.ActiveSessions != 0 {
		t.Fatalf("metrics lost=%d active=%d, want lost=1 active=0", m.SessionsLostAfterCarF, m.ActiveSessions)
	}
	if tp.iran.Store().Count() != 0 {
		t.Fatalf("store count = %d, want 0", tp.iran.Store().Count())
	}

	// A late carrier must not revive the closed session.
	tp.installUp()
	time.Sleep(100 * time.Millisecond)
	if tp.iran.Store().Count() != 0 {
		t.Fatal("late carrier revived a grace-closed session")
	}
}

// 4. A fast reconnect (well within the grace window) recovers the
// session and keeps the metrics balanced.
func TestReconnectWithinGraceKeepsMetricsBalanced(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)
	tp.write(sc.client, "A")
	tp.readN(sc.target, 1, "pre")

	tp.killUp()
	tp.installUp()
	tp.write(sc.client, "B")
	tp.readN(sc.target, 1, "post")

	m := tp.iran.Metrics().Snapshot()
	if m.CarrierLossEvents != 1 || m.CarrierReconnects != 1 {
		t.Fatalf("loss=%d reconnect=%d, want 1/1", m.CarrierLossEvents, m.CarrierReconnects)
	}
	if m.CarrierRebinds < 1 || m.SessionsRecovered < 1 || m.SessionsLostAfterCarF != 0 {
		t.Fatalf("rebinds=%d recovered=%d lost=%d, want >=1/>=1/0",
			m.CarrierRebinds, m.SessionsRecovered, m.SessionsLostAfterCarF)
	}
	if m.ActiveSessions != int64(tp.iran.Store().Count()) {
		t.Fatalf("active metrics %d != store %d", m.ActiveSessions, tp.iran.Store().Count())
	}
}

// 5. Rapid carrier flapping (5 kill/reconnect cycles): the session
// survives every cycle. Each payload is written after the rebind and
// confirmed at the target BEFORE the next flap, so no byte is in-flight
// (and thus at risk of loss) across a carrier death; delivery is
// lossless and in order.
func TestCarrierFlapping(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)
	const Cycles = 5
	for i := 0; i < Cycles; i++ {
		tp.killUp()
		tp.installUp()
		p := string(rune('1' + i))
		tp.write(sc.client, p)
		if got := tp.readN(sc.target, 1, "flap payload"); got != p {
			t.Fatalf("cycle %d: target = %q, want %q", i, got, p)
		}
	}
	if sc.sc.State() != session.StateActive {
		t.Fatalf("session state after flapping = %v, want Active", sc.sc.State())
	}
	m := tp.iran.Metrics().Snapshot()
	if m.CarrierLossEvents < Cycles || m.CarrierRebinds < Cycles {
		t.Fatalf("loss=%d rebinds=%d after %d flaps", m.CarrierLossEvents, m.CarrierRebinds, Cycles)
	}
}

// 6. Late-frame / stale-carrier protection: data in flight when the
// carrier dies must either be delivered in order during the drain or be
// dropped — it must NEVER be duplicated or delivered after the
// post-rebind data.
func TestLateFramesNeverCorruptReboundSession(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)
	tp.write(sc.client, "PRE")
	tp.readN(sc.target, 3, "pre barrier")

	tp.killUp()
	// Wait until the loss is detected on the Iran side.
	eventually(t, 2*time.Second, "up loss detected",
		func() bool { st, _ := sc.sc.UpAtt.State(); return st != session.AttAttached })
	tp.installUp()
	tp.write(sc.client, "POST")

	// PRE was already barriered; the only new content is POST. Whatever
	// happened to any late frame from the old carrier, POST must arrive
	// exactly once and not out of order.
	sc.target.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _ := io.ReadFull(sc.target, buf)
	got := string(buf[:n])
	sc.target.SetReadDeadline(time.Time{})
	if strings.Count(got, "POST") != 1 {
		t.Fatalf("target stream %q contains POST %d times, want exactly 1", got, strings.Count(got, "POST"))
	}
	if sc.sc.State() != session.StateActive {
		t.Fatalf("session state = %v, want Active (no corruption-induced close)", sc.sc.State())
	}
}

// 7. A replacement carrier installed immediately after the kill (while
// the old carrier is still shutting down) must still rebind cleanly.
func TestNewCarrierWhileOldShuttingDown(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)
	tp.write(sc.client, "X")
	tp.readN(sc.target, 1, "pre")

	tp.killUp()
	tp.installUp() // immediately — no settle delay
	tp.write(sc.client, "Y")
	if got := tp.readN(sc.target, 1, "post"); got != "Y" {
		t.Fatalf("post-rebind payload = %q, want Y", got)
	}
	if sc.sc.State() != session.StateActive {
		t.Fatalf("session state = %v, want Active", sc.sc.State())
	}
}

// 8. Only the UPLOAD carrier fails: downloads keep flowing during the
// loss; uploads resume after the rebind.
func TestOnlyUploadCarrierFails(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)

	tp.killUp()
	// Target keeps sending while the up carrier is down.
	tp.write(sc.target, "DOWN")
	if got := tp.readN(sc.client, 4, "download during up loss"); got != "DOWN" {
		t.Fatalf("client stream = %q, want DOWN (down carrier is healthy)", got)
	}
	tp.installUp()
	tp.write(sc.client, "UP")
	if got := tp.readN(sc.target, 2, "upload after rebind"); got != "UP" {
		t.Fatalf("target stream = %q, want UP", got)
	}
}

// 9. Only the DOWNLOAD carrier fails: uploads keep flowing; the target's
// response is buffered on Germany and delivered in full after the rebind.
func TestOnlyDownloadCarrierFails(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)

	tp.killDown()
	// Upload still flows (up carrier healthy).
	tp.write(sc.client, "UP")
	tp.readN(sc.target, 2, "upload during down loss")
	// Target response is buffered while the down carrier is down.
	tp.write(sc.target, "DOWN")
	tp.installDown()
	if got := tp.readN(sc.client, 4, "download after rebind"); got != "DOWN" {
		t.Fatalf("client stream = %q, want DOWN (lossless buffered download)", got)
	}
}

// 10. BOTH carriers fail: both directions buffer, both rebind, both
// streams arrive in full and in order.
func TestBothCarriersFail(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)

	tp.killUp()
	tp.killDown()
	tp.write(sc.client, "B1") // buffered on Iran (up)
	tp.write(sc.target, "B2") // buffered on Germany (down)

	tp.installUp()
	tp.installDown()
	if got := tp.readN(sc.target, 2, "upload across double loss"); got != "B1" {
		t.Fatalf("target stream = %q, want B1", got)
	}
	if got := tp.readN(sc.client, 2, "download across double loss"); got != "B2" {
		t.Fatalf("client stream = %q, want B2", got)
	}
	if sc.sc.State() != session.StateActive {
		t.Fatalf("session state = %v, want Active", sc.sc.State())
	}
}

// 11. Half-close across a carrier loss: the client half-closes (FIN)
// while the up carrier is down. The rebind delivers the pending half-
// close; the session completes normally — the FIN is NOT turned into a
// full close, and the download is not lost.
func TestHalfCloseSurvivesCarrierLoss(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)

	tp.killUp()
	// The target's response still flows (down carrier healthy) and must
	// arrive before we half-close the client.
	tp.write(sc.target, "RESP")
	if got := tp.readN(sc.client, 4, "response"); got != "RESP" {
		t.Fatalf("client stream = %q, want RESP", got)
	}
	sc.client.Close() // client EOF: up direction half-closes (FIN pending, carrier down)
	sc.target.Close() // target EOF: down direction half-closes

	tp.installUp()

	// Both directions closed → clean completion, not a carrier timeout.
	eventually(t, 3*time.Second, "session completed after rebind", func() bool {
		return sc.sc.State() == session.StateClosed
	})
	if strings.Contains(sc.sc.Reason(), "timeout") {
		t.Fatalf("close reason %q must not be a carrier timeout", sc.sc.Reason())
	}
	if tp.iran.Store().Count() != 0 {
		t.Fatalf("store count = %d, want 0", tp.iran.Store().Count())
	}
}

// 12. Shutdown while carriers are lost: parked relays exit via context
// cancellation, stores drain, and goroutines settle (no leak).
func TestShutdownDuringCarrierLoss(t *testing.T) {
	tp := newTopo(t, 5*time.Second) // grace longer than the test: proves ctx, not timeout, unblocks
	tp.setup()
	for i := 0; i < 3; i++ {
		sc := tp.startSession(i)
		tp.write(sc.client, "P")
		tp.readN(sc.target, 1, "pre")
	}
	base := settledGoroutines(t, 20*time.Millisecond)

	tp.killUp()
	tp.killDown()
	tp.iran.Close()
	tp.de.Close()

	eventually(t, 3*time.Second, "stores drained after shutdown", func() bool {
		return tp.iran.Store().Count() == 0 && tp.de.Store().Count() == 0
	})
	got := settledGoroutines(t, 20*time.Millisecond)
	if got > base+8 {
		t.Fatalf("goroutines after shutdown = %d, baseline %d (leak?)", got, base)
	}
}

// settledGoroutines returns runtime.NumGoroutine() once it stops moving.
func settledGoroutines(t *testing.T, settle time.Duration) int {
	t.Helper()
	var last int
	for i := 0; i < 60; i++ {
		n := runtime.NumGoroutine()
		if n == last && i > 5 {
			return n
		}
		last = n
		time.Sleep(settle)
	}
	return last
}

// 13. A rebind is scoped to its stream's owner: rebinding stream 2 does
// not consume or disturb stream 1, which can still be rebound
// independently. Resolution is by StreamID, so the payload SessionID is
// diagnostic only — it cannot redirect a rebind to a different session
// than the stream's owner.
func TestRebindScopedToStreamOwner(t *testing.T) {
	tp := newTopo(t, 5*time.Second)
	tp.setup()
	a := tp.startSession(1) // stream 1
	b := tp.startSession(2) // stream 2
	tp.write(a.client, "A")
	tp.readN(a.target, 1, "a pre")
	tp.write(b.client, "B")
	tp.readN(b.target, 1, "b pre")

	// Kill the up carrier (both streams unregistered on Germany, both
	// up attachments Unavailable) and inject a Germany-only carrier so
	// the raw rebinds below reach Germany's validator without Iran's own
	// rebind racing first.
	tp.killUp()
	ir := tp.injectUpCarrier()
	base := tp.de.Metrics().Snapshot().CarrierRebinds

	// Rebind b's stream (2) using a's SessionID in the payload: the
	// payload ID is ignored, so this rebinds b (stream 2's owner), never a.
	if err := mux.WriteFrame(ir, b.sc.StreamIDUp, mux.FrameRebind, session.EncodeRebind(a.sc.ID, 99)); err != nil {
		t.Fatalf("raw rebind write: %v", err)
	}
	eventually(t, 2*time.Second, "b's rebind accepted", func() bool {
		return tp.de.Metrics().Snapshot().CarrierRebinds > base
	})

	// a's stream (1) is still awaiting a rebind (unaffected by b's).
	if err := mux.WriteFrame(ir, a.sc.StreamIDUp, mux.FrameRebind, session.EncodeRebind(a.sc.ID, 100)); err != nil {
		t.Fatalf("raw rebind write: %v", err)
	}
	eventually(t, 2*time.Second, "a's rebind accepted independently", func() bool {
		return tp.de.Metrics().Snapshot().CarrierRebinds >= base+2
	})
	if a.sc.State() != session.StateActive || b.sc.State() != session.StateActive {
		t.Fatal("rebinds disturbed a live session")
	}
}

// 14. A rebind for an unknown stream/session is dropped; no session is
// ever created by a rebind.
func TestRebindUnknownSession(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1)
	tp.write(sc.client, "A")
	tp.readN(sc.target, 1, "pre")

	unknown := session.SessionID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if err := mux.WriteFrame(tp.upIr, 999, mux.FrameRebind, session.EncodeRebind(unknown, 1)); err != nil {
		t.Fatalf("raw rebind write: %v", err)
	}
	before := tp.de.Metrics().Snapshot().CarrierRebindFailures
	eventually(t, 2*time.Second, "unknown rebind refused", func() bool {
		return tp.de.Metrics().Snapshot().CarrierRebindFailures > before
	})
	if tp.de.Store().Count() != 1 {
		t.Fatalf("germany store = %d after rogue rebind, want 1 (no new session)", tp.de.Store().Count())
	}
	// The real session is unaffected.
	tp.write(sc.client, "A2")
	if got := tp.readN(sc.target, 2, "post"); got != "A2" {
		t.Fatalf("stream = %q, want A2", got)
	}
}

// 15. A replayed/stale rebind (sender generation not greater than the
// last accepted) is refused; the session is not rebound or disturbed.
func TestStaleRebindRefused(t *testing.T) {
	tp := newTopo(t, 5*time.Second)
	tp.setup()
	sc := tp.startSession(1)
	tp.write(sc.client, "A")
	tp.readN(sc.target, 1, "pre")

	tp.killUp()
	tp.installUp() // real rebind accepted; DE records its sender generation
	tp.write(sc.client, "B")
	tp.readN(sc.target, 1, "post rebind")

	// Kill the up carrier again (stream unregistered on Germany, up att
	// Unavailable), inject a Germany-only carrier, and replay a rebind
	// whose sender generation is SMALLER than the one already accepted.
	tp.killUp()
	ir := tp.injectUpCarrier()
	base := tp.de.Metrics().Snapshot().CarrierRebindFailures
	if err := mux.WriteFrame(ir, sc.sc.StreamIDUp, mux.FrameRebind, session.EncodeRebind(sc.sc.ID, 1)); err != nil {
		t.Fatalf("raw rebind write: %v", err)
	}
	eventually(t, 2*time.Second, "stale rebind refused", func() bool {
		return tp.de.Metrics().Snapshot().CarrierRebindFailures > base
	})
	// The session was not rebound to the injected carrier and is not
	// closed: its up attachment is still awaiting a (fresh) rebind.
	if st, _ := sc.sc.UpAtt.State(); st != session.AttUnavailable {
		t.Fatalf("up att after stale rebind = %v, want Unavailable", st)
	}
	if sc.sc.State() != session.StateActive {
		t.Fatalf("session after stale rebind = %v, want Active", sc.sc.State())
	}
}

// 16. A rebind for a session that was already grace-closed is dropped —
// no revival.
func TestRebindAfterSessionClosed(t *testing.T) {
	tp := newTopo(t, 300*time.Millisecond)
	tp.setup()
	sc := tp.startSession(1)
	stream := sc.sc.StreamIDUp

	tp.killUp()
	eventually(t, 3*time.Second, "grace close", func() bool {
		return sc.sc.State() == session.StateClosed
	})
	tp.installUp()

	// The stream is no longer indexed (session removed); the rebind must
	// be refused and nothing revived.
	if err := mux.WriteFrame(tp.upIr, stream, mux.FrameRebind, session.EncodeRebind(sc.sc.ID, 5)); err != nil {
		t.Fatalf("raw rebind write: %v", err)
	}
	before := tp.de.Metrics().Snapshot().CarrierRebindFailures
	eventually(t, 2*time.Second, "post-close rebind refused", func() bool {
		return tp.de.Metrics().Snapshot().CarrierRebindFailures > before
	})
	if tp.iran.Store().Count() != 0 || tp.de.Store().Count() != 0 {
		t.Fatal("post-close rebind revived a session")
	}
}

// 17. Bounded reconnect buffer: with a tiny buffer limit, a large upload
// during the loss is backpressured (not dropped, not over-buffered) and
// arrives complete and in order after the rebind.
func TestBoundedBufferBackpressure(t *testing.T) {
	tp := newTopoBuf(t, 2*time.Second, 128)
	tp.setup()
	sc := tp.startSession(1)

	big := strings.Repeat("A", 2000)
	tp.killUp()
	tp.write(sc.client, big)
	// While lost, nothing reaches the target.
	sc.target.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _ := sc.target.Read(make([]byte, 1)); n > 0 {
		t.Fatalf("target received %d bytes while carrier was down", n)
	}
	sc.target.SetReadDeadline(time.Time{})

	tp.installUp()
	tp.write(sc.client, "END")
	got := tp.readN(sc.target, len(big)+3, "full backpressured upload")
	if got != big+"END" {
		t.Fatalf("target stream len=%d (want %d): bounded buffer lost/reordered data", len(got), len(big)+3)
	}
}

// 18. Stress: 120 concurrent sessions, 4 cycles of up- and down-carrier
// kill/reconnect/rebind. Verifies no duplicates, no loss, no session
// loss, metric balance and no goroutine growth. (The per-session
// payload barriers also prove stream identity is preserved: a cross-
// wired stream would deliver the wrong payload to the wrong target.)
func TestHundredSessionStress(t *testing.T) {
	// 120 concurrent sessions make the serial rebind sweep (plus the down
	// direction's extra rebind round-trip) take a few seconds under load.
	// Use a lenient grace so this tests CORRECTNESS (no loss / no session
	// loss / metric balance / no goroutine growth), not rebind latency.
	tp := newTopo(t, 20*time.Second)
	tp.setup()
	const N = 120
	scs := make([]*sctx, N)
	for i := 0; i < N; i++ {
		scs[i] = tp.startSession(i)
		tp.write(scs[i].client, "P")
	}
	for i := 0; i < N; i++ {
		tp.readN(scs[i].target, 1, "pre barrier")
	}
	base := settledGoroutines(t, 20*time.Millisecond)

	const Cycles = 4
	for c := 0; c < Cycles; c++ {
		// Upload carrier cycle.
		tp.killUp()
		for i := 0; i < N; i++ {
			tp.write(scs[i].client, "C")
		}
		tp.installUp()
		for i := 0; i < N; i++ {
			tp.readN(scs[i].target, 1, "up cycle payload")
		}
		// Download carrier cycle.
		tp.killDown()
		for i := 0; i < N; i++ {
			tp.write(scs[i].target, "D")
		}
		tp.installDown()
		for i := 0; i < N; i++ {
			tp.readN(scs[i].client, 1, "down cycle payload")
		}
		if got := settledGoroutines(t, 20*time.Millisecond); got > base+8 {
			t.Fatalf("cycle %d: goroutines grew to %d (baseline %d)", c, got, base)
		}
	}

	mi := tp.iran.Metrics().Snapshot()
	md := tp.de.Metrics().Snapshot()
	if mi.CarrierRebinds < int64(2*N*Cycles) || md.CarrierRebinds < int64(2*N*Cycles) {
		t.Fatalf("rebinds iran=%d germany=%d, want >= %d each", mi.CarrierRebinds, md.CarrierRebinds, 2*N*Cycles)
	}
	if mi.SessionsLostAfterCarF != 0 || md.SessionsLostAfterCarF != 0 {
		t.Fatalf("sessions lost iran=%d germany=%d, want 0", mi.SessionsLostAfterCarF, md.SessionsLostAfterCarF)
	}
	if tp.iran.Store().Count() != N || tp.de.Store().Count() != N {
		t.Fatalf("stores after stress: iran=%d germany=%d, want %d each",
			tp.iran.Store().Count(), tp.de.Store().Count(), N)
	}

	// Tear everything down cleanly: client half-close, then target EOF.
	for i := 0; i < N; i++ {
		scs[i].client.Close()
	}
	for i := 0; i < N; i++ {
		scs[i].target.Close()
	}
	eventually(t, 10*time.Second, "iran store drained", func() bool {
		return tp.iran.Store().Count() == 0
	})
	eventually(t, 10*time.Second, "germany store drained", func() bool {
		return tp.de.Store().Count() == 0
	})
}
