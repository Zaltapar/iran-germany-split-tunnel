// Package backoff provides the carrier reconnect backoff schedule
// (Phase 5): exponential doubling with a cap, randomized jitter, reset
// after a successful authenticated carrier, and context-cancellable
// sleeps so process shutdown never waits out a pending reconnect delay.
//
// Schedule (base 2s, cap 60s): 2, 4, 8, 16, 32, 60, 60, ... seconds,
// each randomized into [d/2, d) — no reconnect storm, no busy-loop.
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
	rnd       *rand.Rand
}

// New creates a backoff that starts at base and never exceeds max.
// Non-positive values are sanitized (base 1ms, max = base) so the
// schedule is always well-defined.
func New(base, max time.Duration) *Backoff {
	if base <= 0 {
		base = time.Millisecond
	}
	if max < base {
		max = base
	}
	return &Backoff{base: base, max: max, rnd: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

// Next returns the delay for the NEXT failed attempt and advances the
// schedule: base, base*2, base*4, ... capped at max.
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

// Reset restarts the schedule at base — called after a carrier was
// successfully ESTABLISHED AND AUTHENTICATED, so a healthy carrier that
// later dies starts its own fresh schedule.
func (b *Backoff) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attempts = 0
}

// Sleep waits for the next (jittered) delay. It returns ctx.Err()
// immediately if ctx is cancelled while waiting — shutdown must never
// block on a pending reconnect delay.
func (b *Backoff) Sleep(ctx context.Context) error {
	d := b.Next()
	// Jitter into [d/2, d): keeps the worst case at d (so the cap stays
	// a real cap) while decorrelating nodes that share a failure.
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
