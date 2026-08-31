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
