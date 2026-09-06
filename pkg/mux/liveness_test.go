package mux

import (
	"bufio"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// TestLivenessBlackholeDetected: a carrier whose peer never answers
// pings (a silent peer is, to the carrier, a blackholed path: writes
// succeed, no traffic returns) must be declared dead after exactly the
// configured number of missed rounds and torn down through the
// STANDARD Close path (read loop ends, Dispatch returns,
// ShutdownDone fires). No independent teardown path exists — this is
// the only path.
func TestLivenessBlackholeDetected(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 10*time.Millisecond)
	defer c.Close()
	c.SetLivenessRounds(3)
	go c.Dispatch()

	// Wait for the carrier to declare itself dead. Detection is
	// 3 rounds * 10ms = ~30ms; a 2s deadline is a wide safety margin,
	// not a timing assumption the logic depends on.
	deadline := time.Now().Add(2 * time.Second)
	for c.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Ready() {
		t.Fatal("carrier still Ready after the peer went silent: blackhole not detected")
	}
	// Standard teardown: the self-Close interrupts the blocked read
	// (rwc.Close -> EOF). ReadErr is only set once the read loop has
	// actually exited, so wait for ALL carrier goroutines to be done
	// before inspecting it (Ready() latches false on closing=true,
	// which precedes the read loop's exit).
	waitForShutdownDone(t, c)
	if err := c.ReadErr(); err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadErr = %v, want io.EOF (standard close path)", err)
	}
}

// TestLivenessNoFalsePositiveThenDetect: a HEALTHY peer that answers
// every ping must keep the carrier alive for many rounds (no false
// positives on a long-lived connection); when the path is then
// dropped (Blackhole: writes succeed into the void, reads block
// forever — a blackhole the OS will never time out on), the carrier
// must detect it within the configured rounds.
func TestLivenessNoFalsePositiveThenDetect(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 10*time.Millisecond)
	defer c.Close()
	c.SetLivenessRounds(3)
	go c.Dispatch()

	// Peer: answers every ping with a pong until the pipe dies.
	go func() {
		br := bufio.NewReader(b)
		for {
			f, err := ReadFrame(br)
			if err != nil {
				return // pipe closed (test end) or dead
			}
			if f.Type == FramePing {
				_ = WriteFrame(b, 0, FramePong, []byte{0})
			}
		}
	}()

	// Phase 1: healthy for 400ms — far more than the 30ms it would
	// take to die, even under 10x scheduling slowdown (30 rounds are
	// observed, not 3). A false positive would close the carrier here.
	time.Sleep(400 * time.Millisecond)
	if !c.Ready() {
		t.Fatal("false positive: a healthy pong-answering peer caused the carrier to die")
	}

	// Phase 2: drop the path (both directions). The peer's read now
	// blocks; the test-end Close unblocks it (EOF) so it exits.
	b.Blackhole()

	// Phase 3: detection within the configured rounds (~30ms).
	deadline := time.Now().Add(2 * time.Second)
	for c.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Ready() {
		t.Fatal("carrier still Ready after the path was blackholed")
	}
	waitForShutdownDone(t, c)
}

// TestLivenessDisabledWithoutPing: a carrier constructed with a zero
// ping interval has no liveness loop at all (preserves the historical
// behavior for tests that build raw carriers); it stays Ready while
// the peer is silent.
func TestLivenessDisabledWithoutPing(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0) // no keepalive / liveness
	defer c.Close()
	go c.Dispatch()

	// Silent peer, no pings, no liveness: must NOT die by itself.
	time.Sleep(50 * time.Millisecond)
	if !c.Ready() {
		t.Fatal("carrier with pingInterval=0 died without any liveness loop")
	}
}

// TestLivenessRoundsOneNoFalsePositive: L5 staging regression (carrier
// flapping on a healthy path). The first tick after construction is a
// priming round: with rounds=1 it must NOT declare the carrier dead at
// t=interval just because the priming ping's pong has not been latched
// yet. A healthy pong-answering peer must keep the carrier alive for
// many intervals with rounds=1, and a blackholed peer must still be
// detected in (rounds+1) intervals = 2 * interval.
func TestLivenessRoundsOneNoFalsePositive(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 10*time.Millisecond)
	defer c.Close()
	c.SetLivenessRounds(1)
	go c.Dispatch()

	// Peer: answers every ping with a pong (healthy path).
	go func() {
		br := bufio.NewReader(b)
		for {
			f, err := ReadFrame(br)
			if err != nil {
				return
			}
			if f.Type == FramePing {
				_ = WriteFrame(b, 0, FramePong, []byte{0})
			}
		}
	}()

	// 15 intervals with rounds=1. Pre-fix, the carrier died at the
	// FIRST tick (the guaranteed first-round miss).
	time.Sleep(150 * time.Millisecond)
	if !c.Ready() {
		t.Fatal("false positive: rounds=1 declared a healthy path dead (priming round counted as a miss)")
	}

	// Now blackhole: detection must take (1+1) rounds = 2 intervals
	// (priming already happened; the first real round may legitimately
	// miss if the last pong predates it). Bounded deadline, no
	// timing assumption the logic depends on.
	b.Blackhole()
	deadline := time.Now().Add(2 * time.Second)
	for c.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Ready() {
		t.Fatal("carrier still Ready after the path was blackholed (rounds=1)")
	}
	waitForShutdownDone(t, c)
}

// TestLivenessRoundsOneDetectionBound: with rounds=1 a SILENT peer (no
// pong ever) must be declared dead in exactly 2 intervals (priming
// round + 1 missed round), not 1. This pins the documented
// (LivenessRounds + 1) * interval detection bound used by the RUNBOOK
// blackhole scenario.
func TestLivenessRoundsOneDetectionBound(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 10*time.Millisecond)
	defer c.Close()
	c.SetLivenessRounds(1)
	go c.Dispatch()
	// Peer stays silent: it never answers the pings.

	// The carrier must live for >= 1.5 intervals: pre-fix, the
	// guaranteed first-round miss killed it at 1 interval (10 ms).
	// Poll until dead (bounded deadline = safety margin, not a logic
	// assumption), then check the observed time-to-death.
	start := time.Now()
	deadline := time.Now().Add(2 * time.Second)
	for c.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Ready() {
		t.Fatal("silent peer not declared dead within (rounds+1)*interval")
	}
	elapsed := time.Since(start)
	if elapsed < 15*time.Millisecond {
		t.Fatalf("carrier died after %v: rounds=1 counted the priming round as a miss (want >= 1.5 intervals)", elapsed)
	}
	waitForShutdownDone(t, c)
}
