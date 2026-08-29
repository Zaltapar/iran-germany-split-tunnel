// Command e2e-pipe-test runs a full end-to-end test of the production
// Phase 5 engine (pkg/node) in-process over in-memory pipes — no real
// network needed, and no hand-rolled carrier/session logic of its own.
//
// This is the production wiring: both sides are node.Node instances.
// Carriers are installed via InstallUp/InstallDown AFTER a real v1
// CarrierAuth handshake, and every lifecycle rule the production
// binaries rely on is the one from pkg/node:
//
//   - the stream stays registered until its relays have actually
//     terminated (deregistration runs in the node's OnClose hook, which
//     the Phase 4 lifecycle fires only after every relay/consumer
//     epoch has exited) — a late FrameClose can therefore never open
//     a phantom stream;
//   - carrier loss → loss sweep (generation-guarded detach) → grace
//     window → Iran rebind sweep (FrameRebind) → Germany re-attach;
//   - the bounded per-direction reconnect buffer carries data read
//     during the outage and flushes it in order on re-attach;
//   - half-close survives carrier replacement (a direction that
//     logically finished is never re-bound).
//
// Scenarios:
//  1. normal upload/download round trip (client FIN + target EOF);
//  2. up-carrier loss + recovery (upload data read during the outage
//     is buffered and delivered in order after the rebind);
//  3. down-carrier loss + recovery (the buffered target response
//     drains after the rebind);
//  4. both carriers flapping (deterministic rebind-mechanism test: two
//     kill/reinstall cycles; asserts session survival, both directions
//     re-attached on both nodes, exact loss/rebind metrics — and
//     deliberately does NOT assert in-flight download bytes survive the
//     failing carrier, which Phase 5 does not guarantee).
//
// Usage: go run ./e2e-pipe-test
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

func fail(format string, args ...any) {
	fmt.Printf("FAIL: "+format+"\n", args...)
	os.Exit(1)
}

const (
	testGrace  = 5 * time.Second
	testBuffer = 256 << 10
)

// ============================================================
// topology: two production nodes over in-memory pipes
//
//	up carrier:   Iran (auth server) — Germany (auth client)
//	down carrier: Iran (auth client) — Germany (auth server)
// ============================================================

type topo struct {
	iran   *node.Node
	de     *node.Node
	secret []byte

	upIr, upDe     *testutil.MemConn
	downIr, downDe *testutil.MemConn

	targets   []*testutil.MemConn
	targetsMu sync.Mutex
}

func newTopo() *topo {
	secret := []byte("0123456789abcdef0123456789abcdef")
	iranCfg := node.Config{
		Role: node.RoleIran, Grace: testGrace, BufferBytes: testBuffer,
		RelayBufSize: 4096, KeepAliveInterval: time.Hour,
	}
	var logWriter io.Writer = io.Discard
	if os.Getenv("E2E_LOG") != "" {
		logWriter = os.Stderr
	}
	logger := log.New(logWriter, "IRAN ", log.Lmicroseconds)
	deLogger := log.New(logWriter, "DE   ", log.Lmicroseconds)
	tp := &topo{secret: secret}
	tp.iran = node.NewNode(iranCfg, logger, secret)

	deCfg := node.Config{
		Role: node.RoleGermany, Grace: testGrace, BufferBytes: testBuffer,
		RelayBufSize: 4096, KeepAliveInterval: time.Hour,
		TargetDial: func(addr string) (net.Conn, error) {
			tp.targetsMu.Lock()
			defer tp.targetsMu.Unlock()
			if len(tp.targets) == 0 {
				return nil, fmt.Errorf("no target conn queued for %s", addr)
			}
			c := tp.targets[0]
			tp.targets = tp.targets[1:]
			return c, nil
		},
	}
	tp.de = node.NewNode(deCfg, deLogger, secret)
	return tp
}

// installUp installs a fresh up carrier on both sides (auth first).
func (tp *topo) installUp() {
	tp.upIr, tp.upDe = testutil.NewMemPipe()
	authenticateUp(tp)
}

// authenticateUp runs the v1 handshake (Germany = carrier client on up)
// and installs both ends on their nodes.
func authenticateUp(tp *topo) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		br, err := mux.CarrierAuth(ctx, tp.upDe, true, mux.RoleUpload, tp.secret)
		if err != nil {
			done <- err
			return
		}
		tp.de.InstallUp(tp.upDe, br)
		done <- nil
	}()
	br, err := mux.CarrierAuth(ctx, tp.upIr, false, mux.RoleUpload, tp.secret)
	if err != nil {
		fail("e2e up auth (iran): %v", err)
	}
	tp.iran.InstallUp(tp.upIr, br)
	if err := <-done; err != nil {
		fail("e2e up auth (de): %v", err)
	}
}

// installDown installs a fresh down carrier on both sides (auth first).
func (tp *topo) installDown() {
	tp.downIr, tp.downDe = testutil.NewMemPipe()
	authenticateDown(tp)
}

// authenticateDown runs the v1 handshake (Iran = carrier client on
// down) and installs both ends on their nodes.
func authenticateDown(tp *topo) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		br, err := mux.CarrierAuth(ctx, tp.downDe, false, mux.RoleDownload, tp.secret)
		if err != nil {
			done <- err
			return
		}
		tp.de.InstallDown(tp.downDe, br)
		done <- nil
	}()
	br, err := mux.CarrierAuth(ctx, tp.downIr, true, mux.RoleDownload, tp.secret)
	if err != nil {
		fail("e2e down auth (iran): %v", err)
	}
	tp.iran.InstallDown(tp.downIr, br)
	if err := <-done; err != nil {
		fail("e2e down auth (de): %v", err)
	}
}

func (tp *topo) killUp()   { tp.upIr.Close(); tp.upDe.Close() }
func (tp *topo) killDown() { tp.downIr.Close(); tp.downDe.Close() }

// allDirectionsAttached reports whether, on BOTH nodes, every session
// is Active with both direction attachments attached and both carriers
// Ready — i.e. a carrier flap has fully converged on both sides.
func allDirectionsAttached(tp *topo) bool {
	for _, n := range []*node.Node{tp.iran, tp.de} {
		if !n.UpReady() || !n.DownReady() {
			return false
		}
		sess := n.Store().Snapshot()
		if len(sess) != 1 {
			return false
		}
		s := sess[0]
		if s.State() != session.StateActive {
			return false
		}
		if st, _ := s.UpAtt.State(); st != session.AttAttached {
			return false
		}
		if st, _ := s.DownAtt.State(); st != session.AttAttached {
			return false
		}
	}
	return true
}

// downCarrierDead waits until the DOWN carrier is fully torn down on
// both nodes (dispatcher exited, loss sweep settled, handle slot
// cleared). After this, DownReady() is deterministically false, so a
// fresh bootstrap cannot race a mid-teardown carrier and drop the
// stream on "down carrier not ready".
func (tp *topo) downCarrierDead() {
	wait("down carriers fully torn down", 10*time.Second, func() bool {
		return !tp.iran.DownReady() && !tp.de.DownReady()
	})
}

func (tp *topo) losses() (up, down int64) {
	ir := tp.iran.Metrics().Snapshot()
	return ir.CarrierLossEvents, tp.de.Metrics().Snapshot().CarrierLossEvents
}

// rebindCounts returns the per-side rebind counters WITHOUT asserting
// balance: the Iran sweep counts a rebind the moment its session
// re-attaches locally, while Germany counts only after it has received
// and processed the FrameRebind — so the counters are momentarily
// unbalanced during the sweep and converge afterwards.
func (tp *topo) rebindCounts() (iran, de int64) {
	ir := tp.iran.Metrics().Snapshot()
	ds := tp.de.Metrics().Snapshot()
	return ir.CarrierRebinds, ds.CarrierRebinds
}

// wait polls until cond() is true or the deadline expires.
func wait(what string, d time.Duration, cond func() bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	fail("e2e: timed out waiting for %s", what)
}

// ============================================================
// client / target helpers
// ============================================================

// readN reads until want bytes have been received, the connection
// errors, or the deadline expires, and returns everything read.
func readN(c net.Conn, want int, d time.Duration) []byte {
	var out []byte
	buf := make([]byte, 1024)
	_ = c.SetReadDeadline(time.Now().Add(d))
	for len(out) < want {
		n, err := c.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			return out
		}
	}
	return out
}

// waitSessionGone asserts the node's store and active metric settle to
// zero — proof every session fully tore down (no orphaned
// registrations, no metric imbalance).
func waitSessionGone(tp *topo) {
	wait("session teardown", 10*time.Second, func() bool {
		ir := tp.iran.Metrics().Snapshot()
		de := tp.de.Metrics().Snapshot()
		return tp.iran.Store().Count() == 0 && tp.de.Store().Count() == 0 &&
			ir.ActiveSessions == 0 && de.ActiveSessions == 0
	})
}

func startSession(tp *topo, clientPeer net.Conn) {
	if _, err := tp.iran.StartSession(clientPeer, &session.Destination{
		AddrType: session.AddrTypeDomain, Addr: "example.com", Port: 443,
	}); err != nil {
		fail("StartSession: %v", err)
	}
}

func queueTarget(tp *topo, peer *testutil.MemConn) {
	tp.targetsMu.Lock()
	tp.targets = append(tp.targets, peer)
	tp.targetsMu.Unlock()
}

// ============================================================
// scenario 1: normal upload/download round trip
// ============================================================

func scenarioNormal(tp *topo) {
	fmt.Println("scenario 1: normal round trip")
	client, clientPeer := testutil.NewMemPipe()
	tgt, tgtPeer := testutil.NewMemPipe()
	queueTarget(tp, tgtPeer)
	go func() {
		buf := make([]byte, 64)
		n, _ := tgt.Read(buf)
		if string(buf[:n]) != "HELLO" {
			fail("target payload mismatch: %q", buf[:n])
		}
		_, _ = tgt.Write([]byte("WORLD-RESPONSE"))
		tgt.Close() // target EOF → down half-close
	}()

	startSession(tp, clientPeer)

	if _, err := client.Write([]byte("HELLO")); err != nil {
		fail("client write: %v", err)
	}
	data := readN(client, 14, 5*time.Second)
	if string(data) != "WORLD-RESPONSE" {
		fail("client payload mismatch: %q", data)
	}
	fmt.Println("  client received the target response")
	client.Close() // client FIN → up half-close
	waitSessionGone(tp)
	fmt.Println("  session torn down (both directions closed)")
}

// ============================================================
// scenario 2: up-carrier loss + recovery (upload resumes)
// ============================================================

func scenarioUpLoss(tp *topo) {
	fmt.Println("scenario 2: up-carrier loss + recovery (upload resumes)")
	client, clientPeer := testutil.NewMemPipe()
	tgt, tgtPeer := testutil.NewMemPipe()
	queueTarget(tp, tgtPeer)
	// The target echoes each request. "MORE" is uploaded DURING the
	// up-carrier outage and must survive in Iran's bounded reconnect
	// buffer, then be delivered in order after the rebind.
	go func() {
		buf := make([]byte, 64)
		n, _ := tgt.Read(buf)
		if string(buf[:n]) != "HELLO" {
			fail("target payload mismatch: %q", buf[:n])
		}
		_, _ = tgt.Write([]byte("ECHO-1"))
		n, _ = tgt.Read(buf)
		if string(buf[:n]) != "MORE" {
			fail("target did not receive the post-outage upload: %q", buf[:n])
		}
		_, _ = tgt.Write([]byte("ECHO-2"))
		tgt.Close()
	}()

	startSession(tp, clientPeer)
	if _, err := client.Write([]byte("HELLO")); err != nil {
		fail("client write: %v", err)
	}
	// The first echo must have reached the client (full round trip up).
	first := readN(client, 6, 5*time.Second)
	if string(first) != "ECHO-1" {
		fail("client first-echo mismatch: %q", first)
	}

	irRebindsBefore, _ := tp.rebindCounts()
	lossUpBefore, _ := tp.losses()
	tp.killUp()
	// The loss sweep (generation-guarded detach + grace start) must
	// have settled BEFORE the replacement is installed.
	wait("up carrier loss accounted", 5*time.Second, func() bool {
		up, _ := tp.losses()
		return up >= lossUpBefore+1
	})
	fmt.Println("  up carrier lost; session still alive in its grace window")
	if tp.iran.Store().Count() != 1 {
		fail("session lost during grace window")
	}
	// Upload DURING the outage: Iran's relay buffers these bytes.
	if _, err := client.Write([]byte("MORE")); err != nil {
		fail("client write during outage: %v", err)
	}

	// Replacement: Germany first (it must be ready to receive the
	// FrameRebind), then Iran (its rebind sweep runs on install and
	// flushes the buffered upload bytes in order).
	tp.upIr, tp.upDe = testutil.NewMemPipe()
	authenticateUp(tp)
	wait("up rebind", 5*time.Second, func() bool {
		ir, de := tp.rebindCounts()
		return ir == irRebindsBefore+1 && de == irRebindsBefore+1
	})
	fmt.Println("  up carrier replaced; session rebound (same stream)")

	rest := readN(client, 6, 5*time.Second)
	if string(rest) != "ECHO-2" {
		fail("client post-rebind echo mismatch: %q", rest)
	}
	fmt.Println("  upload read during the outage survived the rebind, in order")
	client.Close()
	waitSessionGone(tp)
}

// ============================================================
// scenario 3: down-carrier loss + recovery (download drains)
// ============================================================

func scenarioDownLoss(tp *topo) {
	fmt.Println("scenario 3: down-carrier loss + recovery")
	client, clientPeer := testutil.NewMemPipe()
	tgt, tgtPeer := testutil.NewMemPipe()
	queueTarget(tp, tgtPeer)
	// The target answers PING with PONG, but only AFTER the down
	// carrier is already down (the scenario kills it first): Germany's
	// down relay therefore reads the response with NO carrier attached,
	// so it is guaranteed to sit in the bounded reconnect buffer until
	// the rebind — a fully deterministic outage path.
	go func() {
		buf := make([]byte, 64)
		n, _ := tgt.Read(buf)
		if string(buf[:n]) != "PING" {
			fail("target payload mismatch: %q", buf[:n])
		}
		time.Sleep(100 * time.Millisecond)
		_, _ = tgt.Write([]byte("PONG-PONG-PONG"))
		// Stay open across the rebind so the down direction is still
		// ACTIVE (a half-closed direction is correctly never rebound);
		// the target EOF then lands on the REBOUND carrier and
		// half-closes the down direction normally.
		time.Sleep(1 * time.Second)
		tgt.Close()
	}()

	baseDown := tp.de.Metrics().Snapshot().TotalBytesDown
	startSession(tp, clientPeer)
	if _, err := client.Write([]byte("PING")); err != nil {
		fail("client write: %v", err)
	}
	// The bootstrap must be COMPLETE on Germany (session registered,
	// down direction attached) BEFORE the down carrier is killed —
	// otherwise the kill could race the bootstrap's DownReady() check.
	wait("germany bootstrap complete", 5*time.Second, func() bool {
		return tp.de.Store().Count() == 1
	})

	// Kill the down carrier BEFORE the target responds. PING is still
	// in flight on the up direction, so PONG (100 ms later) is read by
	// Germany during the outage — into the bounded buffer, not into a
	// dying carrier's queue.
	irRebindsBefore, _ := tp.rebindCounts()
	_, lossDownBefore := tp.losses()
	tp.killDown()
	wait("down carrier loss accounted", 5*time.Second, func() bool {
		_, down := tp.losses()
		return down >= lossDownBefore+1
	})
	if tp.iran.Store().Count() != 1 {
		fail("session lost during grace window")
	}
	// The response must now be buffered (bytesDown counts socket reads
	// on Germany; cumulative across scenarios, hence the baseline).
	wait("response read during the outage", 5*time.Second, func() bool {
		return tp.de.Metrics().Snapshot().TotalBytesDown >= baseDown+14
	})
	fmt.Println("  down carrier lost; response buffered in the reconnect buffer")

	// Replacement: Germany first (FrameRebind receiver), then Iran.
	tp.downIr, tp.downDe = testutil.NewMemPipe()
	authenticateDown(tp)
	wait("down rebind", 5*time.Second, func() bool {
		ir, de := tp.rebindCounts()
		return ir == irRebindsBefore+1 && de == irRebindsBefore+1
	})
	fmt.Println("  down carrier replaced; session rebound (same stream)")

	data := readN(client, 14, 5*time.Second)
	if string(data) != "PONG-PONG-PONG" {
		fail("client data across down-rebind mismatch: %q", data)
	}
	fmt.Println("  client received the buffered response after the rebind")
	client.Close()
	waitSessionGone(tp)
}

// ============================================================
// scenario 4: deterministic carrier-flap rebind-mechanism test
//
// WHAT THIS PROVES (and what it deliberately does NOT prove):
//
//   - After every flap of BOTH carriers, the logical session survives
//     and BOTH direction attachments on BOTH nodes re-attach to the
//     replacement carrier (up via Iran's rebind sweep + Germany's
//     FrameRebind handling, down symmetrically). The session is never
//     closed on the grace timer and no rebind is refused.
//
//   - It does NOT assert that arbitrary user bytes already in flight
//     on a direction at the instant that carrier fails survive the flap.
//     Phase 5 guarantees ordered lossless delivery of bytes READ into a
//     direction's bounded reconnect buffer during the outage (the upload
//     case, proven in scenario 2); it does not guarantee preservation of
//     bytes already handed to a carrier's write path at the moment that
//     carrier dies. Such in-flight bytes belong to the dead carrier's
//     epoch and are dropped by design (no retransmission exists).
//
// DETERMINISM: the target connection stays open for the entire flap
// window, so no direction ever half-closes inside a flap (a half-closed
// direction is correctly never rebound, which would make convergence
// legitimately impossible). The flap window is bracketed: uploads are
// delivered and the session is fully attached before the first kill, and
// each cycle converges (both attachments re-attached on both nodes)
// before the next kill, so every rebind frame is processed exactly once.
// No correctness step below relies on a wall-clock sleep.
// ============================================================

func scenarioFlapping(tp *topo) {
	fmt.Println("scenario 4: deterministic carrier-flap rebind mechanism")
	client, clientPeer := testutil.NewMemPipe()
	tgt, tgtPeer := testutil.NewMemPipe()
	queueTarget(tp, tgtPeer)
	// The target stays OPEN for the whole flap window and closes only
	// when the scenario's post-convergence BYE marker reaches it, so
	// both directions remain logically active and re-bindable across
	// every flap. (A client FIN does NOT propagate to the target
	// connection — the engine half-closes directions, it does not relay
	// peer closes — so the target must be closed by data, not by EOF.)
	go func() {
		buf := make([]byte, 64)
		if n, _ := tgt.Read(buf); string(buf[:n]) != "FLAP" {
			fail("target payload mismatch: %q", buf[:n])
		}
		flapDelivered <- struct{}{}
		// Block for the BYE marker (or the target pipe being closed),
		// then close: the target EOF lands on the FINAL (healthy)
		// carrier and half-closes the down direction.
		_, _ = tgt.Read(buf)
		tgt.Close()
		targetClosed <- struct{}{}
	}()

	startSession(tp, clientPeer)
	if _, err := client.Write([]byte("FLAP")); err != nil {
		fail("client write: %v", err)
	}
	// Gate on end-to-end delivery BEFORE the first kill: the bootstrap is
	// complete, the upload reached the target, and the full session is
	// attached on both nodes. A carrier death cannot lose a FrameHeader
	// the peer never saw (rebinds never create sessions).
	wait("bootstrap delivered to target", 5*time.Second, func() bool {
		return targetSawFlap()
	})

	lossUpBefore, lossDownBefore := tp.losses()
	irRebindsBefore, deRebindsBefore := tp.rebindCounts()
	const Cycles = 2
	for cycle := 0; cycle < Cycles; cycle++ {
		// Kill BOTH directions, settle both loss sweeps, then replace
		// both (up: de-then-iran; down: de-then-iran).
		tp.killUp()
		tp.killDown()
		wait("losses accounted", 5*time.Second, func() bool {
			up, down := tp.losses()
			return up >= lossUpBefore+1 && down >= lossDownBefore+1
		})
		// The logical session must survive the flap in its grace window.
		if tp.iran.Store().Count() != 1 || tp.de.Store().Count() != 1 {
			fail("session lost during flapping (cycle %d)", cycle)
		}
		tp.upIr, tp.upDe = testutil.NewMemPipe()
		authenticateUp(tp)
		tp.downIr, tp.downDe = testutil.NewMemPipe()
		authenticateDown(tp)
		// Convergence gate BEFORE the next kill: every rebind frame of
		// this cycle must have been processed on BOTH nodes (both
		// direction attachments re-attached). Gating the next kill on
		// convergence makes each cycle exactly +1 rebind per direction
		// per side — and a rebind frame can only be lost to a FASTER next
		// kill, which this gate rules out.
		wait("flap cycle converged", 5*time.Second, func() bool {
			return allDirectionsAttached(tp)
		})
		// Per-cycle loss metric accounting (rebinds are asserted once
		// below, after the loop, for the exact per-direction total).
		u, d := tp.losses()
		if u < lossUpBefore+1 || d < lossDownBefore+1 {
			fail("loss metrics after cycle %d: up %d down %d", cycle, u, d)
		}
		lossUpBefore, lossDownBefore = u, d
	}

	// The session survived the full flap window.
	if st := sessionState(tp); st != session.StateActive {
		fail("session state after flapping: %v, want Active", st)
	}
	// Exactly Cycles rebinds per direction per side (2 up + 2 down).
	ir, de := tp.rebindCounts()
	want := int64(2 * Cycles)
	if ir != irRebindsBefore+want || de != deRebindsBefore+want {
		fail("flap rebind counts: iran %d germany %d, want +_%d each (base iran %d germany %d)",
			ir, de, want, irRebindsBefore, deRebindsBefore)
	}
	// No rebind was refused on either side.
	if irF, deF := rebindFailureCounts(tp); irF != 0 || deF != 0 {
		fail("flap rebind refusals: iran %d germany %d", irF, deF)
	}
	// No session was lost to the grace timer.
	if lost := sessionsLostAfterCarF(tp); lost != 0 {
		fail("sessions lost to grace during flapping: %d", lost)
	}
	fmt.Printf("  %d full flap cycles survived; session Active, %d rebinds/side, 0 refusals\n", Cycles, want)

	// Clean shutdown, in this exact order:
	//  1. BYE marker up the (re-bound, healthy) up direction → the
	//     target closes → target EOF half-closes the down direction;
	//  2. client FIN half-closes the up direction;
	//  3. both directions half-closed on both nodes → full teardown.
	if _, err := client.Write([]byte("BYE")); err != nil {
		fail("client BYE write: %v", err)
	}
	select {
	case <-targetClosed:
	case <-time.After(5 * time.Second):
		fail("target never received the BYE marker after the flaps")
	}
	client.Close()
	waitSessionGone(tp)
}

// flapDelivered is signaled by the target goroutine once the FLAP upload
// has been read off the target connection — i.e. the session's bootstrap
// and the full upload path are end-to-end delivered.
var flapDelivered = make(chan struct{}, 1)

// targetClosed is signaled by the target goroutine after the target
// connection is closed (post-BYE), i.e. the target EOF has been emitted.
var targetClosed = make(chan struct{}, 1)

// targetSawFlap reports whether the FLAP upload reached the target.
func targetSawFlap() bool {
	select {
	case <-flapDelivered:
		return true
	default:
		return false
	}
}

// sessionState returns the single session's logical state on the Iran
// node (the stream owner), or an invalid state if the count is wrong.
func sessionState(tp *topo) session.State {
	sess := tp.iran.Store().Snapshot()
	if len(sess) != 1 {
		return session.StateClosed
	}
	return sess[0].State()
}

// rebindFailureCounts returns the CarrierRebindFailures on both nodes.
func rebindFailureCounts(tp *topo) (int64, int64) {
	return tp.iran.Metrics().Snapshot().CarrierRebindFailures,
		tp.de.Metrics().Snapshot().CarrierRebindFailures
}

// sessionsLostAfterCarF returns SessionsLostAfterCarF summed across nodes.
func sessionsLostAfterCarF(tp *topo) int64 {
	return tp.iran.Metrics().Snapshot().SessionsLostAfterCarF +
		tp.de.Metrics().Snapshot().SessionsLostAfterCarF
}

// ============================================================

func main() {
	tp := newTopo()
	defer func() {
		tp.iran.Close()
		tp.de.Close()
	}()

	tp.installUp()
	tp.installDown()
	fmt.Println("AUTH: both carriers authenticated on both nodes")

	baselineIranRebinds, _ := tp.rebindCounts()

	scenarioNormal(tp)
	scenarioUpLoss(tp)
	scenarioDownLoss(tp)
	scenarioFlapping(tp)

	// Final invariants.
	ir := tp.iran.Metrics().Snapshot()
	de := tp.de.Metrics().Snapshot()
	if ir.CarrierRebindFailures != 0 || de.CarrierRebindFailures != 0 {
		fail("unexpected rebind failures: iran %d germany %d", ir.CarrierRebindFailures, de.CarrierRebindFailures)
	}
	if ir.SessionsLostAfterCarF != 0 || de.SessionsLostAfterCarF != 0 {
		fail("sessions lost to grace timeout: iran %d germany %d", ir.SessionsLostAfterCarF, de.SessionsLostAfterCarF)
	}
	if ir.CarrierRebinds != de.CarrierRebinds {
		fail("rebind imbalance: iran %d germany %d", ir.CarrierRebinds, de.CarrierRebinds)
	}
	// up-loss (1) + down-loss (1) + flapping (2 cycles x 2 directions)
	if ir.CarrierRebinds != baselineIranRebinds+6 {
		fail("expected 6 total rebinding, got %d", ir.CarrierRebinds-baselineIranRebinds)
	}
	if ir.TotalSessions != 4 || de.TotalSessions != 4 {
		fail("expected 4 sessions each side: iran %d germany %d", ir.TotalSessions, de.TotalSessions)
	}
	if ir.ActiveSessions != 0 || de.ActiveSessions != 0 ||
		tp.iran.Store().Count() != 0 || tp.de.Store().Count() != 0 {
		fail("orphaned sessions after teardown")
	}
	if ir.SessionsRecovered != de.SessionsRecovered {
		fail("recovered-session imbalance: iran %d germany %d", ir.SessionsRecovered, de.SessionsRecovered)
	}

	// No goroutine growth: capture the pre-shutdown count, fully shut
	// both nodes down, and require the count to settle (not grow).
	gBefore := runtime.NumGoroutine()
	tp.iran.Close()
	tp.de.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > gBefore {
		time.Sleep(20 * time.Millisecond)
	}
	if gAfter := runtime.NumGoroutine(); gAfter > gBefore {
		fail("goroutine growth after shutdown: %d -> %d", gBefore, gAfter)
	}
	fmt.Printf("  goroutine count settled: %d -> %d\n", gBefore, runtime.NumGoroutine())

	fmt.Println("E2E PIPE TEST: PASS")
	os.Exit(0)
}
