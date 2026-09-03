package node

import (
	"io"
	"log"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestWaitCarriersNoBusySpin (Issue #7 busy-spin regression): while one
// direction is already READY (its ready channel is CLOSED), a
// waitCarriers that selects on both signals re-selects the closed
// channel every iteration and spins at full CPU until the deadline.
// The fix selects only on the NOT-READY direction (nil channel disables
// the other case), so the waiter BLOCKS.
//
// Deterministic discriminator: a blocked waiter's goroutine stack state
// is "[select]" (parked in selectgo, no ready case); a spinner's state
// is "[running]" (selectgo always finds the closed case ready). We
// sample the waiter's state from a dedicated goroutine (so the test
// thread being descheduled on a loaded host cannot mask the sample)
// with a generous bounded window.
func TestWaitCarriersNoBusySpin(t *testing.T) {
	n := NewNode(Config{
		Role: RoleIran, Grace: time.Second,
		RelayBufSize: 4096, BufferBytes: 64 << 10,
		BootstrapWait:     3 * time.Second,
		KeepAliveInterval: time.Hour,
	}, log.New(io.Discard, "", 0), []byte("0123456789abcdef0123456789abcdef"))
	defer n.Close()
	a, _ := pipePair(t)
	n.InstallUp(a, nil) // up ready, down absent → the busy-spin scenario

	waitDone := make(chan error, 1)
	go func() {
		_, _, err := n.waitCarriers()
		waitDone <- err
	}()

	// Sample the waiter's stack state from a separate goroutine: the
	// first time its frame appears, record the state. (A spinner would
	// show "running"; a blocked waiter shows "select".)
	type sample struct {
		state string
		found bool
	}
	sampleCh := make(chan sample, 1)
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			state, found := goroutineState(t, "(*Node).waitCarriers")
			if found {
				sampleCh <- sample{state, true}
				return
			}
			if time.Now().After(deadline) {
				sampleCh <- sample{"", false}
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	var got sample
	select {
	case got = <-sampleCh:
	case <-time.After(10 * time.Second): // generous on loaded hosts
		t.Fatal("could not observe the waitCarriers goroutine (sampler timed out)")
	}
	if !got.found {
		t.Fatal("waitCarriers goroutine never observed on the stack (did it return early?)")
	}
	if strings.Contains(got.state, "running") {
		t.Fatalf("waitCarriers goroutine state is %q — BUSY-SPIN (selecting the closed ready channel); want blocked [select]", got.state)
	}
	if !strings.Contains(got.state, "select") {
		t.Fatalf("waitCarriers goroutine state is %q, want blocked [select]", got.state)
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

// goroutineState returns the runtime stack state (e.g. "select",
// "running") of the (unique) goroutine whose stack contains the given
// frame, for white-box assertions.
func goroutineState(t *testing.T, frame string) (string, bool) {
	t.Helper()
	buf := make([]byte, 64<<10)
	for {
		// all=true: every goroutine (false would dump only this one).
		nb := runtime.Stack(buf, true)
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
