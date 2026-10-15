// Package backoff provides the carrier reconnect backoff schedule
// (Phase 5): exponential doubling with a cap, randomized jitter, reset
// after a successful authenticated carrier, and context-cancellable
// sleeps so process shutdown never waits out a pending reconnect delay.
//
// Schedule (base 2s, cap 60s): 2, 4, 8, 16, 32, 60, 60, ... seconds,
// each randomized into [d/2, d] (inclusive) — no reconnect storm, no
// busy-loop; the cap is a real cap (the jitter never exceeds d).
//
// Bounded reconnect window (NewBounded): a pure exponential schedule
// amplifies a brief underlay/egress blip into a multi-minute user-
// visible outage — with base 2s / cap 60s the first six failed attempts
// sleep a cumulative 2+4+8+16+32+60 = 122 seconds in the worst case, so
// the carrier keeps sitting in a 60-second sleep long after the
// underlay has recovered. NewBounded adds a THRESHOLD-triggered clamp:
// once the cumulative nominal delay since the last Reset reaches window,
// every further delay is clamped to clamp (when clamp > 0), guaranteeing
// the carrier is retried at least every clamp seconds once an outage
// outlives the window. Window is a threshold, NOT a hard cap on total
// sleep — the cumulative may overshoot window by up to one max delay
// before the clamp engages on the NEXT call (e.g. 1,2,4,8,10,10 sums to
// 35 with window 30; the 6th delay is still 10, clamping starts at the
// 7th). The invariants hold: no reconnect storm, no busy-loop, and
// the cap is a real cap (the jitter still never exceeds the scheduled
// delay, and clamp is itself capped at max at construction time).
package backoff

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// Backoff is a small exponential backoff schedule. It is safe for use
// by a single goroutine at a time (the reconnect loop); the mutex is
// belt-and-braces for test access.
type Backoff struct {
	mu        sync.Mutex
	base, max time.Duration
	attempts  int
	// Bounded reconnect window (zero = disabled, pure exponential):
	window time.Duration // cumulative nominal sleep bound per episode
	clamp  time.Duration // per-attempt delay once the window is exhausted
	slept  time.Duration // cumulative NOMINAL delay since the last Reset
	rnd    *rand.Rand
}

// New creates a backoff that starts at base and never exceeds max.
// Non-positive values are sanitized (base 1ms, max = base) so the
// schedule is always well-defined.
func New(base, max time.Duration) *Backoff {
	// No window bound: pure exponential backoff, byte-for-byte the
	// pre-bounded-window behavior.
	return NewBounded(base, max, 0, 0)
}

// NewBounded builds a reconnect schedule with a cumulative nominal-delay
// threshold (window) per failure episode. Once the cumulative nominal delay
// handed out by Next() since the last Reset reaches window (b.slept >= window),
// every subsequent Next() call clamps its scheduled delay to min(d, clamp).
//
// Note that window is a threshold checked BEFORE adding the current attempt's
// delay, NOT a hard cap on cumulative sleep: the attempt that crosses window
// still receives its normal exponential (max-capped) delay, so cumulative
// nominal sleep before clamping begins on the next attempt can reach at most
// window - 1ns + max. Once exhausted, the carrier is retried at least every
// clamp duration, preventing a brief underlay blip from amplifying into a
// multi-minute outage.
//
// window <= 0 or clamp <= 0 disables the bound (pure exponential backoff,
// the pre-fix behavior). clamp > max is sanitized down to max.
func NewBounded(base, max, window, clamp time.Duration) *Backoff {
	if base <= 0 {
		base = time.Millisecond
	}
	if max < base {
		max = base
	}
	// A clamp larger than the cap would defeat the cap; it is meaningless
	// anyway because the scheduled delay never exceeds max, so the clamp
	// branch (clamp < d) could never fire. Cap it at max.
	if clamp > 0 && clamp > max {
		clamp = max
	}
	// Sanitize the window only when the bound is actually enabled;
	// window <= 0 or clamp <= 0 disables it regardless of the other.
	if window > 0 && clamp <= 0 {
		window = 0
	}
	if window <= 0 && clamp > 0 {
		clamp = 0
	}
	return &Backoff{
		base:   base,
		max:    max,
		window: window,
		clamp:  clamp,
		rnd:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Next returns the delay for the NEXT failed attempt and advances the
// schedule: base, base*2, base*4, ... capped at max. When a bounded
// reconnect window is enabled (NewBounded), the cumulative NOMINAL delay
// is tracked; once it reaches the window, every further delay is
// clamped to the per-attempt clamp.
func (b *Backoff) Next() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	exp := uint(0)
	if b.attempts > 30 {
		exp = 30
	} else {
		exp = uint(b.attempts)
	}
	d := b.base << exp
	if d <= 0 || d > b.max {
		d = b.max
	}
	// Bounded window: once the cumulative nominal delay since the last
	// Reset reaches window, clamp every further delay to the per-attempt
	// clamp. The NOMINAL d (not the jittered sleep) is used for the
	// cumulative counter so the schedule stays deterministic and
	// testable; Sleep()'s jitter is untouched.
	if b.window > 0 && b.clamp > 0 && b.slept >= b.window && b.clamp < d {
		d = b.clamp
	}
	b.slept += d
	b.attempts++
	return d
}

// Attempts reports how many delays have been handed out since the last
// Reset (useful for logging and tests).
func (b *Backoff) Attempts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempts
}

// Reset restarts the schedule at base and zeroes the cumulative window —
// called after a carrier was successfully ESTABLISHED AND AUTHENTICATED,
// so a healthy carrier that later dies starts its own fresh schedule and
// a fresh failure episode gets its own full reconnect window.
func (b *Backoff) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attempts = 0
	b.slept = 0
}

// WindowExhausted reports whether the bounded reconnect window (if
// enabled) has been reached: once true, the schedule clamps every
// further delay to the per-attempt clamp. It is always false when the
// bound is disabled (window <= 0 or clamp <= 0), and useful for logging
// and tests.
func (b *Backoff) WindowExhausted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.window > 0 && b.clamp > 0 && b.slept >= b.window
}

// Sleep waits for the next (jittered) delay. It returns ctx.Err()
// immediately if ctx is cancelled while waiting — shutdown must never
// block on a pending reconnect delay.
func (b *Backoff) Sleep(ctx context.Context) error {
	d := b.Next()
	// Jitter into [d/2, d] (inclusive): keeps the worst case at d (so
	// the cap stays a real cap) while decorrelating nodes that share a
	// failure.
	j := d / 2
	if d/2 > 0 {
		j += time.Duration(b.rnd.Int63n(int64(d/2) + 1))
	}
	select {
	case <-time.After(j):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
