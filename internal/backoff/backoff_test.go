package backoff

import (
	"context"
	"testing"
	"time"
)

// TestScheduleDoubling verifies 2s -> 4s -> 8s -> ... with the 60s cap,
// the production schedule.
func TestScheduleDoubling(t *testing.T) {
	b := New(2*time.Second, 60*time.Second)
	want := []time.Duration{2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		if got := b.Next(); got != w*time.Second {
			t.Fatalf("Next() #%d = %v, want %v", i+1, got, w*time.Second)
		}
	}
}

// TestReset returns the schedule to base after a successful
// establishment.
func TestReset(t *testing.T) {
	b := New(time.Second, 64*time.Second)
	for i := 0; i < 5; i++ {
		b.Next()
	}
	if b.Attempts() != 5 {
		t.Fatalf("Attempts = %d, want 5", b.Attempts())
	}
	b.Reset()
	if got := b.Next(); got != time.Second {
		t.Fatalf("Next after Reset = %v, want 1s", got)
	}
}

// TestSleepJitterBounds verifies Sleep waits within [d/2, d] of the
// scheduled delay — no faster (busy-loop risk), no slower than the cap.
//
// The cap check carries a small wall-clock tolerance: the jitter range
// is INCLUSIVE of d (Int63n(d/2+1) can yield j = d/2, so a sleep of
// exactly the cap is legitimate production behavior, and the cap is
// preserved by construction: j = d/2 + [0, d/2] <= d). Measuring that
// exact-boundary sleep with wall clock on a loaded host can overshoot by
// a few milliseconds (timer + scheduling granularity), so the upper
// bound is d + tolerance, NOT a strict d. The tolerance is sized to be
// far smaller than any real regression (a 2x delay would still fail).
func TestSleepJitterBounds(t *testing.T) {
	const (
		delay = 100 * time.Millisecond
		// tolerance: wall-clock measurement error on a loaded host for a
		// timer whose legitimate worst case is exactly the cap.
		tolerance = 20 * time.Millisecond
	)
	b := New(delay, delay) // d always 100ms
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	if err := b.Sleep(ctx); err != nil {
		t.Fatalf("Sleep: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < delay/2-5*time.Millisecond {
		t.Fatalf("Sleep returned after %v, jitter lower bound ~50ms violated", elapsed)
	}
	if elapsed > delay+tolerance {
		t.Fatalf("Sleep returned after %v, cap 100ms (+%v tolerance) violated", elapsed, tolerance)
	}
}

// TestSleepCancellation verifies shutdown cancels a pending sleep
// immediately (requirement: reconnect goroutine must terminate on
// process shutdown).
func TestSleepCancellation(t *testing.T) {
	b := New(2*time.Second, 60*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.Sleep(ctx) }()
	time.Sleep(50 * time.Millisecond) // let the sleep start
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Sleep returned nil after context cancel, want ctx.Err()")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Sleep did not return promptly after cancel")
	}
}

// TestSleepRespectsCtxAlreadyDone returns immediately when the context
// is already cancelled.
func TestSleepRespectsCtxAlreadyDone(t *testing.T) {
	b := New(time.Second, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := b.Sleep(ctx); err == nil {
		t.Fatal("Sleep with pre-cancelled ctx returned nil")
	}
	if time.Since(start) > time.Second {
		t.Fatal("Sleep with pre-cancelled ctx blocked")
	}
}

// TestWindowClamp verifies the bounded reconnect window: base 1s / cap 10s /
// window 30s / clamp 2s yields nominal delays 1, 2, 4, 8, 10, 10 (the
// cumulative reaches 35 >= 30 here) and then clamps to 2, 2, 2, ... so the
// carrier keeps being retried at the clamp cadence once the outage outlives
// the window.
func TestWindowClamp(t *testing.T) {
	b := NewBounded(time.Second, 10*time.Second, 30*time.Second, 2*time.Second)
	want := []time.Duration{1, 2, 4, 8, 10, 10, 2, 2, 2, 2}
	for i, w := range want {
		if got := b.Next(); got != w*time.Second {
			t.Fatalf("Next() #%d = %v, want %v", i+1, got, w*time.Second)
		}
	}
}

// TestNewBoundedDisabledIsPureExponential proves the pre-fix pure-exponential
// behavior is reachable: window=0, or clamp=0, disables the bound and the
// schedule is byte-for-byte the exponential-doubling-with-cap form.
func TestNewBoundedDisabledIsPureExponential(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 10, 10}
	for name, bb := range map[string]*Backoff{
		"window=0":       NewBounded(time.Second, 10*time.Second, 0, 0),
		"clamp=0":        NewBounded(time.Second, 10*time.Second, 30*time.Second, 0),
		"window=0,clamp": NewBounded(time.Second, 10*time.Second, 0, 2*time.Second),
	} {
		for i, w := range want {
			if got := bb.Next(); got != w*time.Second {
				t.Fatalf("%s: Next() #%d = %v, want %v", name, i+1, got, w*time.Second)
			}
		}
	}
}

// TestNewDelegatesToNewBounded proves New(base, max) is NewBounded(base, max,
// 0, 0): the pre-fix constructor's behavior is unchanged.
func TestNewDelegatesToNewBounded(t *testing.T) {
	want := []time.Duration{2, 4, 8, 16, 32, 60, 60}
	b := New(2*time.Second, 60*time.Second)
	for i, w := range want {
		if got := b.Next(); got != w*time.Second {
			t.Fatalf("New Next() #%d = %v, want %v", i+1, got, w*time.Second)
		}
	}
}

// TestResetZeroesWindow verifies a successful carrier establishment (Reset)
// zeroes BOTH the attempt counter and the cumulative window, so a fresh
// failure episode gets a full new reconnect window.
func TestResetZeroesWindow(t *testing.T) {
	b := NewBounded(time.Second, 10*time.Second, 30*time.Second, 2*time.Second)
	for i := 0; i < 6; i++ {
		b.Next()
	}
	if !b.WindowExhausted() {
		t.Fatalf("WindowExhausted = false, want true after six Next() calls (cumulative 35 >= 30)")
	}
	if b.Attempts() != 6 {
		t.Fatalf("Attempts = %d, want 6", b.Attempts())
	}
	b.Reset()
	if b.Attempts() != 0 {
		t.Fatalf("Attempts after Reset = %d, want 0", b.Attempts())
	}
	if got := b.Next(); got != time.Second {
		t.Fatalf("Next after Reset = %v, want 1s", got)
	}
	if b.WindowExhausted() {
		t.Fatalf("WindowExhausted after Reset = true, want false (window restarted)")
	}
}

// TestWindowExhaustedFlips verifies WindowExhausted() is false until the
// cumulative nominal delay reaches the window (here after the 6th call), true
// thereafter, and always false when the bound is disabled.
func TestWindowExhaustedFlips(t *testing.T) {
	b := NewBounded(time.Second, 10*time.Second, 30*time.Second, 2*time.Second)
	for i := 0; i < 5; i++ {
		b.Next()
	}
	if b.WindowExhausted() {
		t.Fatalf("WindowExhausted after five Next() calls = true, want false (cumulative 25 < 30)")
	}
	b.Next() // sixth: cumulative 35 >= 30
	if !b.WindowExhausted() {
		t.Fatalf("WindowExhausted after six Next() calls = false, want true (cumulative 35 >= 30)")
	}

	// Disabled bound: window present but clamp=0 — never exhausted.
	b2 := NewBounded(time.Second, 10*time.Second, 30*time.Second, 0)
	for i := 0; i < 20; i++ {
		b2.Next()
	}
	if b2.WindowExhausted() {
		t.Fatalf("disabled bound (clamp=0) reported WindowExhausted, want false")
	}
}

// TestClampCappedAtMax verifies a clamp requested above the cap is capped at
// max: even with a huge clamp, no Next() delay ever exceeds max once the
// window is exhausted (the cap stays a real cap).
func TestClampCappedAtMax(t *testing.T) {
	b := NewBounded(time.Second, 10*time.Second, 30*time.Second, 100*time.Second)
	for i := 0; i < 10; i++ {
		if got := b.Next(); got > 10*time.Second {
			t.Fatalf("Next() #%d = %v, exceeds cap 10s (clamp must be capped at max)", i+1, got)
		}
	}
}

// TestSleepBoundedByClampAfterWindow verifies that once the window is
// exhausted, each jittered Sleep() is bounded by the per-attempt clamp. The
// wall-clock tolerance mirrors TestSleepJitterBounds (the jitter is
// inclusive of the clamp, so measuring exactly-the-clamp on a loaded host can
// overshoot a few milliseconds; a 2x regression would still fail).
func TestSleepBoundedByClampAfterWindow(t *testing.T) {
	const (
		base, max, window = 10 * time.Millisecond, 40 * time.Millisecond, 100 * time.Millisecond
		clamp             = 20 * time.Millisecond
		// tolerance: wall-clock measurement error for a timer whose
		// legitimate worst case is exactly the clamp.
		tolerance = 20 * time.Millisecond
	)
	b := NewBounded(base, max, window, clamp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Burn through the nominal window: the first four Next() calls push the
	// cumulative nominal delay to 10+20+40+40 = 110ms >= 100ms window.
	for i := 0; i < 4; i++ {
		b.Next()
	}
	if !b.WindowExhausted() {
		t.Fatalf("WindowExhausted = false, want true after four Next() calls")
	}
	// Every subsequent sleep is clamped to 20ms (jitter [10ms, 20ms]).
	for i := 0; i < 3; i++ {
		start := time.Now()
		if err := b.Sleep(ctx); err != nil {
			t.Fatalf("Sleep #%d: %v", i+1, err)
		}
		elapsed := time.Since(start)
		if elapsed > clamp+tolerance {
			t.Fatalf("Sleep #%d returned after %v, clamp 20ms (+%v tolerance) violated", i+1, elapsed, tolerance)
		}
		if elapsed < clamp/2-5*time.Millisecond {
			t.Fatalf("Sleep #%d returned after %v, jitter lower bound ~10ms violated", i+1, elapsed)
		}
	}
}
