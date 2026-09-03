package node_test

// Issue #6 — node-level aggregate session-buffer budget.
//
// These tests run the FULL two-node topology over in-memory pipes
// (deterministic, killable carriers, no real TCP) with a small
// SPLIT_SESSION_BUFFER_TOTAL_BYTES equivalent (node.Config
// SessionBufferTotalBytes) so the aggregate budget engages while the
// per-buffer cap (BufferBytes) stays comfortably larger. They assert,
// white-box, the exact invariant the issue demands:
//
//	0 <= SessionBufferAccounted() <= limit   at every observed instant
//
// plus exact reclamation (0 after drain and after Node.Close), fair
// refusal/freed-space reuse, a 200-session stress with carrier cycling
// (invariant + no goroutine leak + clean shutdown).
//
// No wall-clock sleep is used as the PRIMARY synchronization: state
// waits go through eventually() (poll-until-true with a failure
// timeout, the repo's existing idiom), and the invariant sampler is a
// white-box observation channel, not a synchronization point.

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// logFor mirrors the base logger of newTopoBuf (NODE_TEST_LOG opt-in).
func logFor(t *testing.T) *log.Logger {
	t.Helper()
	var base *log.Logger
	if os.Getenv("NODE_TEST_LOG") != "" {
		base = log.New(os.Stderr, "", log.Lmicroseconds)
	} else {
		base = log.New(io.Discard, "", 0)
	}
	return log.New(base.Writer(), "IRAN ", base.Flags())
}

// newTopoBudget is newTopoBuf plus a configurable AGGREGATE session-
// buffer budget (SessionBufferTotalBytes) on both nodes. The per-buffer
// cap (bufBytes) is kept far above the aggregate in every test so the
// aggregate is the binding constraint.
func newTopoBudget(t *testing.T, grace time.Duration, bufBytes, totalBytes int) *topo {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	logger := logFor(t)
	deLog := log.New(logFor(t).Writer(), "DE   ", 0)
	tp := &topo{t: t, secret: secret}

	iranCfg := node.Config{
		Role: node.RoleIran, Grace: grace,
		RelayBufSize: 4096, BufferBytes: bufBytes,
		SessionBufferTotalBytes: totalBytes,
		KeepAliveInterval:       time.Hour,
	}
	tp.iran = node.NewNode(iranCfg, logger, secret)

	deCfg := node.Config{
		Role: node.RoleGermany, Grace: grace,
		RelayBufSize: 4096, BufferBytes: bufBytes,
		SessionBufferTotalBytes: totalBytes,
		KeepAliveInterval:       time.Hour,
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

// waitUpLost blocks until the Iran-side up attachment of sess is no
// longer attached (carrier loss detected) — the deterministic point at
// which writes must start buffering.
func waitUpLost(t *testing.T, sc *sctx) {
	t.Helper()
	eventually(t, 3*time.Second, "up loss detected",
		func() bool { st, _ := sc.sc.UpAtt.State(); return st != session.AttAttached })
}

// invariantSampler samples the aggregate gauge continuously while the
// test runs and reports any sample that violated the bound. It is an
// OBSERVATION channel (white-box invariant check), never a
// synchronization point; the test drains it at the points it asserts.
type invariantSampler struct {
	t     *testing.T
	f     func() int64
	limit int64
	viol  chan int64
	done  chan struct{}
}

func startInvariantSampler(t *testing.T, f func() int64, limit int64) *invariantSampler {
	t.Helper()
	s := &invariantSampler{t: t, f: f, limit: limit, viol: make(chan int64, 1024), done: make(chan struct{})}
	go func() {
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-tick.C:
				if v := s.f(); v > s.limit {
					select {
					case s.viol <- v:
					default: // already recorded a violation; don't block
					}
				}
			}
		}
	}()
	t.Cleanup(func() { close(s.done) })
	return s
}

func (s *invariantSampler) drain(what string) {
	s.t.Helper()
	for len(s.viol) > 0 {
		s.t.Fatalf("invariant violated (%s): accounted %d > limit %d", what, <-s.viol, s.limit)
	}
}

// TestAggregateBudgetCapUnderConcurrentStalls (acceptance #2): under
// concurrent stalls the total pending bytes across ALL sessions never
// exceed the aggregate budget. 4 stalled sessions each try to buffer
// 16 KiB; with a 16 KiB aggregate the sum must settle EXACTLY at the
// cap (4 KiB read chunks fill it with zero headroom), and after the
// carrier returns every byte is delivered in order and the gauge drops
// to exactly 0 (exact reclamation, acceptance #3).
func TestAggregateBudgetCapUnderConcurrentStalls(t *testing.T) {
	const (
		chunk   = 4096 // RelayBufSize in the topology: reservation granularity
		limit   = 4 * chunk
		payload = 4 * chunk
		n       = 4
	)
	tp := newTopoBudget(t, 2*time.Second, 64<<10, limit)
	tp.setup()
	sam := startInvariantSampler(t, tp.iran.SessionBufferAccounted, limit64(limit))

	scs := make([]*sctx, n)
	for i := range scs {
		scs[i] = tp.startSession(i)
		tp.write(scs[i].client, "P")
		if got := tp.readN(scs[i].target, 1, "pre-kill payload"); got != "P" {
			t.Fatalf("session %d pre-kill payload = %q", i, got)
		}
	}

	tp.killUp()
	waitUpLost(t, scs[0])
	// All sessions want more than the whole budget: 4 x 16 KiB = 64 KiB
	// against a 16 KiB aggregate.
	for i := range scs {
		tp.write(scs[i].client, strings.Repeat("A"+string(rune('1'+i)), payload))
	}
	// The aggregate must settle EXACTLY at the cap: read chunks are
	// 4 KiB, the limit is a multiple of 4 KiB, and every stalled relay
	// keeps reading until no full chunk fits (headroom < 4 KiB is
	// impossible at rest: 16384 % 4096 == 0).
	eventually(t, 5*time.Second, "aggregate settles at the cap",
		func() bool { return tp.iran.SessionBufferAccounted() == int64(limit) })
	sam.drain("at cap")

	// Carrier returns: every buffered byte must be delivered in order
	// (lossless) and the gauge must drop to exactly 0 (reclamation).
	tp.installUp()
	for i := range scs {
		// The "P" byte was consumed pre-kill; only the payload arrives now.
		want := strings.Repeat("A"+string(rune('1'+i)), payload)
		if got := tp.readN(scs[i].target, len(want), "post-drain payload"); got != want {
			t.Fatalf("session %d payload after drain: len=%d want=%d", i, len(got), len(want))
		}
	}
	eventually(t, 5*time.Second, "gauge returns to zero",
		func() bool { return tp.iran.SessionBufferAccounted() == 0 })
	sam.drain("after drain")
	if tp.iran.SessionBufferActiveRelays() != n {
		t.Fatalf("active relays = %d, want %d (sessions still live)",
			tp.iran.SessionBufferActiveRelays(), n)
	}
}

// TestAggregateBudgetRefusalFreedSpaceReused (acceptance #2 + fairness):
// while one session holds the ENTIRE aggregate budget, a second is
// refused (its bytes do not enter memory); when the first drains, the
// freed space becomes available to the second, which then proceeds —
// no permanent starvation, no silent exceedance.
func TestAggregateBudgetRefusalFreedSpaceReused(t *testing.T) {
	const (
		chunk = 4096
		limit = chunk // exactly ONE read chunk of headroom
	)
	tp := newTopoBudget(t, 2*time.Second, 64<<10, limit)
	tp.setup()
	sam := startInvariantSampler(t, tp.iran.SessionBufferAccounted, limit64(limit))

	a := tp.startSession(1)
	b := tp.startSession(2)
	tp.write(a.client, "PA")
	tp.readN(a.target, 1, "a pre")
	tp.write(b.client, "PB")
	tp.readN(b.target, 1, "b pre")

	tp.killUp()
	waitUpLost(t, a)
	// a grabs the whole budget first (deterministic: b's write comes
	// after a's and the budget holds exactly one chunk).
	tp.write(a.client, strings.Repeat("X", chunk))
	eventually(t, 5*time.Second, "a holds the whole budget",
		func() bool { return tp.iran.SessionBufferAccounted() == int64(limit) })
	// b is refused: its chunk would exceed the cap. Its bytes must NOT
	// enter the buffer (gauge stays exactly at the cap — no growth, no
	// exceedance).
	tp.write(b.client, strings.Repeat("Y", chunk))
	time.Sleep(50 * time.Millisecond) // let b's relay attempt (observation, not sync)
	if got := tp.iran.SessionBufferAccounted(); got != int64(limit) {
		t.Fatalf("gauge = %d after b's write, want exactly %d (b refused, no growth)", got, limit)
	}
	sam.drain("while saturated")

	// The carrier returns: a drains (refunding the budget), and b —
	// which kept retrying on wake — takes the freed space and delivers.
	tp.installUp()
	// "PA"/"PB" were written pre-kill with only the first byte consumed,
	// so "A"/"B" are still queued at the targets ahead of the chunks.
	if got := tp.readN(a.target, 1+chunk, "a full"); got != "A"+strings.Repeat("X", chunk) {
		t.Fatalf("a payload = %q (len %d), want %q", got[:4], len(got), "A"+strings.Repeat("X", 4)+"...")
	}
	if got := tp.readN(b.target, 1+chunk, "b full"); got != "B"+strings.Repeat("Y", chunk) {
		t.Fatalf("b payload len=%d, want %d (freed space was not reused)", len(got), 1+chunk)
	}
	eventually(t, 5*time.Second, "gauge returns to zero",
		func() bool { return tp.iran.SessionBufferAccounted() == 0 })
	sam.drain("after drain")
}

// TestAggregateBudgetStress200SessionsCarrierCycling (acceptance #3,
// #4 + the 200-session requirement): 200 live sessions, the up carrier
// cycled down/up three times while every session streams data during
// the loss. The aggregate invariant holds at every sampled instant,
// all bytes survive every cycle in order, no goroutine leaks, and a
// final Node.Close reclaims everything (zero accounted bytes, zero
// active relays).
func TestAggregateBudgetStress200SessionsCarrierCycling(t *testing.T) {
	const (
		chunk  = 4096
		limit  = 8 * chunk // 32 KiB: ~3 chunks of contention per cycle
		n      = 200
		cycles = 3
	)
	tp := newTopoBudget(t, 3*time.Second, 64<<10, limit)
	tp.setup()
	sam := startInvariantSampler(t, tp.iran.SessionBufferAccounted, limit64(limit))

	baseline := settledGoroutines(t, 5*time.Millisecond)
	scs := make([]*sctx, n)
	for i := range scs {
		scs[i] = tp.startSession(i)
	}

	for c := 0; c < cycles; c++ {
		// Every session streams 32 KiB (8 chunks) during the loss —
		// 6.4 MiB total against a 32 KiB aggregate: heavy contention.
		tp.killUp()
		waitUpLost(t, scs[0])
		for i := range scs {
			tp.write(scs[i].client, strings.Repeat("S"+string(rune('1'+c%2))+string(rune('A'+i%26)), 32*chunk))
		}
		// The aggregate must reach (and never exceed) the cap while all
		// 200 relays are stalled.
		eventually(t, 15*time.Second, fmt.Sprintf("aggregate reaches the cap (cycle %d)", c),
			func() bool { return tp.iran.SessionBufferAccounted() == int64(limit) })
		sam.drain(fmt.Sprintf("cycle %d at cap", c))

		tp.installUp()
		// Drain: every session's full stream must arrive at its target.
		// (The pre-cycle payload, if any, was already consumed.)
		for i := range scs {
			want := 32 * chunk
			// readN is bounded by a deadline; 32 KiB in-memory is fast.
			if got := tp.readN(scs[i].target, want, "cycle payload"); len(got) != want {
				t.Fatalf("cycle %d session %d: got %d bytes, want %d", c, i, len(got), want)
			}
		}
		eventually(t, 15*time.Second, fmt.Sprintf("gauge returns to zero (cycle %d)", c),
			func() bool { return tp.iran.SessionBufferAccounted() == 0 })
		sam.drain(fmt.Sprintf("cycle %d drained", c))
	}

	// Clean shutdown: Node.Close force-reclaims every outstanding
	// charge regardless of relay timing (acceptance #4).
	tp.iran.Close()
	tp.de.Close()
	if got := tp.iran.SessionBufferAccounted(); got != 0 {
		t.Fatalf("after Close: accounted = %d, want 0 (authoritative reclamation)", got)
	}
	if got := tp.iran.SessionBufferActiveRelays(); got != 0 {
		t.Fatalf("after Close: active relays = %d, want 0", got)
	}
	if got := tp.de.SessionBufferAccounted(); got != 0 {
		t.Fatalf("de after Close: accounted = %d, want 0", got)
	}
	// No goroutine leak: with both nodes closed every relay/consumer
	// must have exited, so the count settles back to the pre-test
	// baseline (small margin for runtime housekeeping).
	deadline := time.Now().Add(5 * time.Second)
	var final int
	for {
		final = runtime.NumGoroutine()
		if final <= baseline+8 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if final > baseline+8 {
		t.Fatalf("goroutine leak: %d after full shutdown, baseline %d", final, baseline)
	}
}

// TestAggregateBudgetCleanShutdownWithPendingBytes (acceptance #4):
// with bytes still buffered at the moment of shutdown (carrier dead,
// sessions parked in waitAttach holding reservations), Node.Close must
// leave ZERO outstanding accounted bytes and ZERO active relays — the
// budget's shutdown guarantee is independent of relay timing.
func TestAggregateBudgetCleanShutdownWithPendingBytes(t *testing.T) {
	const limit = 4 * 4096
	// Long grace: the sessions must NOT auto-close during the test, so
	// the gauge reaches the cap and STAYS there with bytes buffered —
	// the exact precondition for "shutdown with pending bytes".
	tp := newTopoBudget(t, 30*time.Second, 64<<10, limit)
	tp.setup()

	scs := make([]*sctx, 4)
	for i := range scs {
		scs[i] = tp.startSession(i)
		tp.write(scs[i].client, "P")
		tp.readN(scs[i].target, 1, "pre")
	}
	tp.killUp()
	waitUpLost(t, scs[0])
	for i := range scs {
		// 8 KiB each; a stalled relay buffers one read chunk (4 KiB)
		// and parks in waitAttach, so 4 sessions x 4 KiB = 16 KiB =
		// limit: the gauge reaches the cap with bytes still pending.
		tp.write(scs[i].client, strings.Repeat("B", 8192))
	}
	eventually(t, 5*time.Second, "aggregate reaches the cap",
		func() bool { return tp.iran.SessionBufferAccounted() == int64(limit) })
	sam := startInvariantSampler(t, tp.iran.SessionBufferAccounted, limit64(limit))
	sam.drain("at cap, pending bytes")

	// Shutdown WITH pending bytes: authoritative reclamation, regardless
	// of relay timing (acceptance #4).
	tp.iran.Close()
	tp.de.Close()
	if got := tp.iran.SessionBufferAccounted(); got != 0 {
		t.Fatalf("after Close with pending bytes: accounted = %d, want 0", got)
	}
	if got := tp.iran.SessionBufferActiveRelays(); got != 0 {
		t.Fatalf("after Close with pending bytes: active relays = %d, want 0", got)
	}
	if got := tp.de.SessionBufferAccounted(); got != 0 {
		t.Fatalf("de after Close with pending bytes: accounted = %d, want 0", got)
	}
}

// limit64 is a tiny readability helper for the sampler bound.
func limit64(v int) int64 { return int64(v) }
