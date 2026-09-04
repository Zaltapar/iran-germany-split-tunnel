package node

import (
	"io"
	"log"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestWaitCarriersNoBusySpin (Issue #7 busy-spin regression).
//
// Property under test: when ONE direction is already READY (its ready
// channel is CLOSED) and the other is absent, waitCarriers must BLOCK
// (park in the select) -- it must NOT select on the closed ready
// channel, which would leave a ready case on every iteration and spin
// the loop at full CPU until the deadline.
//
// The fix: waitCarriers selects only on the NOT-READY direction(s); a
// nil channel disables that case, so the already-ready (closed) channel
// can never be selected.
//
// Deterministic discriminator (a STABLE state, not a transient one):
//   - A correctly-blocking waiter parks in the select (goroutine state
//     "[select]") and HOLDS it for the whole wait, because no case is
//     ever ready. It reaches the parked state within microseconds of
//     starting and stays there until the deadline.
//   - A busy-spinner ALWAYS has a ready case (the closed channel) and
//     therefore NEVER parks: its state is only ever "running" or
//     "runnable", never "[select]".
//
// So "reaches and holds the parked [select] state" is a SOUND
// discriminator: the correct implementation produces it; the buggy one
// structurally cannot.
//
// We POLL for that stable state (bounded window), deliberately IGNORING
// the transient "running"/"runnable" states the goroutine passes through
// while getting to its first select. (An earlier version took a SINGLE
// early sample and failed on a transient "runnable" -- invalid, because
// any goroutine, including a correctly-blocking one, is "runnable"
// before it parks, and under the -race detector that pre-park window is
// wide enough that an early sample lands on it.) Polling for the stable
// end state removes the scheduler dependence without weakening the
// assertion: a spinner still fails, on the window timeout.
func TestWaitCarriersNoBusySpin(t *testing.T) {
	n := NewNode(Config{
		Role: RoleIran, Grace: time.Second,
		RelayBufSize: 4096, BufferBytes: 64 << 10,
		BootstrapWait:     3 * time.Second, // long: the waiter outlives the probe
		KeepAliveInterval: time.Hour,
	}, log.New(io.Discard, "", 0), []byte("0123456789abcdef0123456789abcdef"))
	defer n.Close()
	a, _ := pipePair(t)
	n.InstallUp(a, nil) // up ready (closed channel), down absent -> the spin scenario

	waitDone := make(chan error, 1)
	go func() {
		_, _, err := n.waitCarriers()
		waitDone <- err
	}()

	// Wait for the waiter to reach AND hold the stable parked [select]
	// state. Fails (window timeout) iff it never parks -- i.e., it is
	// spinning (keeps a ready select case, i.e. selects the closed
	// ready channel).
	parked := pollGoroutineState(t, 2*time.Second, "(*Node).waitCarriers",
		func(state string) bool { return state == "select" })
	if !parked {
		t.Fatal("waitCarriers never reached a stable parked [select] state within 2s -- " +
			"BUSY-SPIN suspected (a ready select case is present, i.e. it selects the " +
			"closed ready channel); want the waiter blocked in [select]")
	}

	// The wait itself must still be bounded (deadline fires at 3s).
	select {
	case err := <-waitDone:
		if err == nil {
			t.Fatal("waitCarriers must time out when the down carrier never arrives")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waitCarriers did not honor its deadline")
	}
}

// pollGoroutineState polls the stack state of the (unique) goroutine
// whose stack contains frame until want(state) holds or the window
// expires; returns whether want was satisfied. Transient states that do
// not satisfy want are re-polled (not failed on), so this asserts a
// STABLE end state rather than a single transient sample. The 5 ms poll
// interval is a scheduling allowance for the goroutine to reach its
// first select (guaranteed for the correct implementation); it is not a
// synchronization dependency -- the asserted state, once reached, is
// stable for the remainder of the wait.
func pollGoroutineState(t *testing.T, window time.Duration, frame string, want func(string) bool) bool {
	t.Helper()
	deadline := time.Now().Add(window)
	for {
		if state, found := goroutineState(t, frame); found && want(state) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// goroutineState returns the runtime stack state (e.g. "select",
// "running", "runnable") of the (unique) goroutine whose stack contains
// the given frame, for white-box assertions.
func goroutineState(t *testing.T, frame string) (string, bool) {
	t.Helper()
	buf := make([]byte, 64<<10)
	for {
		nb := runtime.Stack(buf, true) // all=true: dump every goroutine
		if nb <= len(buf) {
			break
		}
		buf = make([]byte, nb)
	}
	var cur, found string
	for _, line := range strings.Split(string(buf), "\n") {
		if strings.HasPrefix(line, "goroutine ") {
			if i := strings.Index(line, "["); i >= 0 && strings.HasSuffix(line, "]:") {
				cur = line[i+1 : len(line)-2]
			}
			continue
		}
		if found == "" && strings.Contains(line, frame) {
			found = cur
		}
	}
	return found, found != ""
}
