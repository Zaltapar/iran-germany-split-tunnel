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
