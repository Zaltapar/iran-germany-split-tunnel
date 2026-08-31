package node_test

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

func discardLogger(prefix string) *log.Logger {
	return log.New(io.Discard, prefix, 0)
}

// newTopoLiveness builds the standard test topology but with an ACTIVE,
// fast keepalive + liveness (10ms ping, 3 missed rounds ≈ 30ms to
// declare a blackholed carrier dead) and a generous 1s grace window, so
// a liveness-detected loss has time to be replaced and re-bound.
func newTopoLiveness(t *testing.T) *topo {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	const grace = 1 * time.Second
	iranCfg := node.Config{
		Role: node.RoleIran, Grace: grace,
		RelayBufSize: 4096, BufferBytes: 64 << 10,
		KeepAliveInterval: 10 * time.Millisecond, LivenessRounds: 3,
	}
	iran := node.NewNode(iranCfg, discardLogger("IRAN "), secret)
	tp := &topo{t: t, secret: secret}
	deCfg := node.Config{
		Role: node.RoleGermany, Grace: grace,
		RelayBufSize: 4096, BufferBytes: 64 << 10,
		KeepAliveInterval: 10 * time.Millisecond, LivenessRounds: 3,
		// Same target-dial hook as the standard harness: bootstrap pops
		// the prepared target conn from the queue (no real TCP dial).
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
	de := node.NewNode(deCfg, discardLogger("DE   "), secret)
	tp.iran = iran
	tp.de = de
	t.Cleanup(func() {
		iran.Close()
		de.Close()
	})
	return tp
}

// TestNodeLivenessBlackholeRebind: the integration test that a
// blackholed up-carrier (packets dropped — a path the OS will never
// time out on its own) is DETECTED by the keepalive liveness, enters
// the NORMAL carrier-loss machinery (generation detached, grace
// window), and — when a fresh authenticated carrier is re-established
// — REBINDS the existing session (same stream ID) so data flows again.
// No independent teardown path is involved: detection ends in a
// standard Close, and recovery is the Phase 5 rebind sweep.
func TestNodeLivenessBlackholeRebind(t *testing.T) {
	tp := newTopoLiveness(t)
	tp.setup()
	sc := tp.startSession(0)

	if !tp.iran.UpReady() {
		t.Fatal("up carrier not ready after setup")
	}

	// BLACKHOLE the up path: writes succeed into the void, reads block
	// forever (no RST/FIN/timeout). The carrier must detect this via
	// the liveness (3 missed pings ≈ 30ms), NOT via any read error.
	tp.upIr.Blackhole()
	tp.upDe.Blackhole()

	// Wait for the liveness to declare the carrier dead (standard
	// Close -> blocked read unblocked -> read loop ends -> carrier
	// lost). ~30ms + shutdown; 2s is a wide safety margin, not a
	// timing assumption the logic depends on.
	deadline := time.Now().Add(2 * time.Second)
	for tp.iran.UpReady() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if tp.iran.UpReady() {
		t.Fatal("liveness did not detect the blackholed up carrier")
	}
	// The session must still be alive in its grace window (not killed
	// by the loss) — that is the point of the rebind machinery.
	if sc.sc.State() != session.StateActive {
		t.Fatalf("session state = %v after blackhole loss, want Active (in grace)", sc.sc.State())
	}

	// The liveness Close already unblocked the blackholed read
	// (rwc.Close -> EOF), so the old carrier is fully gone; install a
	// fresh up carrier (both ends authenticate). Iran's rebind sweep
	// re-attaches the session to the new generation.
	tp.killUp()
	tp.installUp()

	// The session must have REBOUND (still Active, not replaced).
	eventually(t, 2*time.Second, "up carrier re-ready after liveness loss",
		func() bool { return tp.iran.UpReady() })
	eventually(t, 2*time.Second, "up attachment re-attached",
		func() bool { st, _ := sc.sc.UpAtt.State(); return st == session.AttAttached })
	if sc.sc.State() != session.StateActive {
		t.Fatalf("session state = %v after rebind, want Active", sc.sc.State())
	}

	// Data must flow again end-to-end through the rebound carrier.
	payload := []byte(fmt.Sprintf("post-blackhole-payload-%d", time.Now().UnixNano()))
	if _, err := sc.client.Write(payload); err != nil {
		t.Fatalf("writing post-blackhole payload: %v", err)
	}
	sc.target.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(sc.target, got); err != nil {
		t.Fatalf("data did not flow after liveness rebind: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch after rebind: got %q want %q", got, payload)
	}
}
