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

// TestSleepJitterBounds verifies Sleep waits within [d/2, d) of the
// scheduled delay — no faster (busy-loop risk), no slower than the cap.
func TestSleepJitterBounds(t *testing.T) {
	b := New(100*time.Millisecond, 100*time.Millisecond) // d always 100ms
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	if err := b.Sleep(ctx); err != nil {
		t.Fatalf("Sleep: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 45*time.Millisecond {
		t.Fatalf("Sleep returned after %v, jitter lower bound ~50ms violated", elapsed)
	}
	if elapsed >= 100*time.Millisecond {
		t.Fatalf("Sleep returned after %v, cap 100ms violated", elapsed)
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
