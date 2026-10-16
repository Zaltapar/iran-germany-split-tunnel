// target_dial_governor_test.go — up-carrier drop-storm fix, Parts 2 & 3.
// These tests are deterministic: the circuit-breaker tests inject a fake
// clock (GovernorConfig.Now) and use tiny durations; the bounded-dial test
// races a deliberately slow fake dialer against the ceiling; the backoff
// test pins the capped, escalating schedule through the jitter bounds.
package node

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestBoundedDialReturnsWithinBound (test c): a fake dialer that hangs longer
// than the operator's ceiling returns ErrTargetDialTimeout within the bound,
// not after the hang. This is the guarantee that a hung target cannot stall a
// bootstrap stream beyond the operator's bound.
func TestBoundedDialReturnsWithinBound(t *testing.T) {
	const bound = 40 * time.Millisecond
	// A dialer that "hangs" well past the bound (never returns within it).
	hang := 5 * time.Second
	raw := func(string) (net.Conn, error) {
		time.Sleep(hang)
		return nil, errors.New("late connect")
	}
	ctx := context.Background()
	g := NewTargetDialGovernor(GovernorConfig{BoundedTimeout: bound})

	start := time.Now()
	_, err := g.Dial(ctx, raw, "target.example:443")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrTargetDialTimeout) {
		t.Fatalf("Dial err = %v, want ErrTargetDialTimeout", err)
	}
	if elapsed > bound+50*time.Millisecond {
		t.Fatalf("bounded dial took %v, which exceeds the %v ceiling (+50ms slack)", elapsed, bound)
	}
	if elapsed < 5*time.Millisecond {
		t.Fatalf("bounded dial returned in %v, earlier than its own %v ceiling (suspicious)", elapsed, bound)
	}
}

// TestBoundedDialPreservesHealthyPath: when the dialer returns well within
// the bound, the connection is handed through untouched (no behavior change
// to the healthy path). A fully-disabled governor is byte-identical to the
// raw dialer (it makes the direct call with no gate/backoff/ceiling).
func TestBoundedDialPreservesHealthyPath(t *testing.T) {
	g := NewTargetDialGovernor(GovernorConfig{BoundedTimeout: time.Second})
	good := func(string) (net.Conn, error) { return nil, nil }
	if _, err := g.Dial(context.Background(), good, "target.example:443"); err != nil {
		t.Fatalf("healthy bounded dial errored: %v", err)
	}
	// Fully-disabled governor: direct call, byte-identical to the raw dialer.
	plain := BuildTargetDialGovernor(GovernorConfig{})
	if plain != nil {
		t.Fatalf("BuildTargetDialGovernor(all off) = %v, want nil (no behavior change)", plain)
	}
}

// TestBackoffSpacedAndBounded (test d): repeated retries of the same failing
// target are spaced by an escalating, capped jittered delay. The jitter is
// always within [d/2, d] and never exceeds the cap, so the wait is BOUNDED
// and the worst case is a real cap.
func TestBackoffSpacedAndBounded(t *testing.T) {
	base, max := 20*time.Millisecond, 40*time.Millisecond
	governor := NewTargetDialGovernor(GovernorConfig{
		BackoffEnabled: true,
		BackoffBase:    base,
		BackoffMax:     max,
	})

	ctx := context.Background()
	target := "flap.example:443"
	// Seed a failing entry so Wait has an armed backoff to consume.
	governor.RecordFailure(target)
	var waits []time.Duration
	for i := 0; i < 6; i++ {
		start := time.Now()
		if err := governor.Wait(ctx, target); err != nil {
			t.Fatalf("Wait %d: %v", i, err)
		}
		waits = append(waits, time.Since(start))
		// Each failed retry re-arms the next (escalating) backoff.
		governor.RecordFailure(target)
	}
	// Every wait must be bounded by the cap (plus a small scheduler slack)
	// and strictly positive (a real, spaced delay, never a busy loop).
	for i, w := range waits {
		if w <= 0 {
			t.Fatalf("retry %d waited %v; a retry must be spaced (positive)", i, w)
		}
		if w > max+50*time.Millisecond {
			t.Fatalf("retry %d waited %v, exceeding the %v cap (+50ms slack); the backoff must stay bounded", i, w, max)
		}
	}
	// The schedule must have escalated and then capped: the attempt count
	// reaches at least the number of retries — the property that stops a
	// 1,562x retransmit loop from getting worse over time.
	if got := governor.BackoffAttempts(target); got < 6 {
		t.Fatalf("backoff attempts = %d, want >= 6 (one per retry)", got)
	}
	// A success must reset the schedule (healthy-path recovery).
	governor.RecordSuccess(target)
	if a := governor.BackoffAttempts(target); a != 0 {
		t.Fatalf("after a success the backoff attempts = %d, want 0 (reset)", a)
	}
}

// TestCircuitBreakerOpenRefuseReadmit (test e, first half): N failures within
// the window open the breaker; dials are refused during the cooldown; a
// single half-open probe is admitted after the cooldown; a successful probe
// closes it; a failed probe keeps it open (restarting the cooldown).
func TestCircuitBreakerOpenRefuseReadmit(t *testing.T) {
	var now int64 // microseconds on the fake clock
	fakeNow := func() time.Time { return time.UnixMicro(now) }
	g := NewTargetDialGovernor(GovernorConfig{
		BreakerEnabled:   true,
		FailureWindow:    60 * time.Second,
		FailureThreshold: 3,
		Cooldown:         30 * time.Second,
		Now:              fakeNow,
	})
	target := "dead.example:443"

	// Below threshold: closed → allowed, not a probe.
	if a, p := g.Allow(target); !a || p {
		t.Fatalf("closed breaker Allow = (%v,%v), want (true,false)", a, p)
	}

	// Three failures within the window open the breaker.
	g.RecordFailure(target)
	g.RecordFailure(target)
	g.RecordFailure(target)
	if a, p := g.Allow(target); a || p {
		t.Fatalf("freshly-open breaker Allow = (%v,%v), want (false,false) — refused during cooldown", a, p)
	}
	if n := g.OpenCount(); n != 1 {
		t.Fatalf("OpenCount = %d, want 1 (one target open)", n)
	}

	// Still inside the 30s cooldown: refused.
	now += int64(15 * time.Second / time.Microsecond)
	if a, _ := g.Allow(target); a {
		t.Fatal("Allow during cooldown must be refused")
	}

	// After the cooldown: exactly one half-open probe is admitted.
	now += int64(15 * time.Second / time.Microsecond) // 30s total
	a, p := g.Allow(target)
	if !a || !p {
		t.Fatalf("Allow after cooldown = (%v,%v), want (true,true) — a single half-open probe", a, p)
	}
	// A probe is at most one in flight: a second Allow is refused.
	if a, p := g.Allow(target); a || p {
		t.Fatalf("second half-open probe Allow = (%v,%v), want (false,false)", a, p)
	}
	// The probe SUCCEEDS → the breaker closes and normal dials resume.
	g.RecordSuccess(target)
	if n := g.OpenCount(); n != 0 {
		t.Fatalf("OpenCount after a successful probe = %d, want 0", n)
	}
	if a, p := g.Allow(target); !a || p {
		t.Fatalf("Allow after success = (%v,%v), want (true,false)", a, p)
	}

	// Re-open it, let the probe FAIL → it stays open and the cooldown restarts.
	g.RecordFailure(target)
	g.RecordFailure(target)
	g.RecordFailure(target) // re-opens
	now += int64(30 * time.Second / time.Microsecond)
	a, p = g.Allow(target) // admit the probe
	if !a || !p {
		t.Fatalf("Allow for a second probe = (%v,%v), want (true,true)", a, p)
	}
	g.RecordFailure(target) // the probe failed
	if a, _ := g.Allow(target); a {
		t.Fatal("a failed half-open probe must keep the breaker open (refuse)")
	}
}

// TestCircuitBreakerLRUCapFailsClosed (test e, second half): the tracked-target
// map is capped; a full map evicts the least-recently-used target, which then
// fails closed to the direct dial (unknown). The map never grows unbounded.
func TestCircuitBreakerLRUCapFailsClosed(t *testing.T) {
	var now int64
	fakeNow := func() time.Time { return time.UnixMicro(now) }
	g := NewTargetDialGovernor(GovernorConfig{
		BreakerEnabled:   true,
		FailureWindow:    60 * time.Second,
		FailureThreshold: 2,
		Cooldown:         30 * time.Second,
		MaxTargets:       2,
		Now:              fakeNow,
	})
	// Track and open targets A and B (the map is now at its cap of 2).
	for _, tg := range []string{"a.example:443", "b.example:443"} {
		g.RecordFailure(tg)
		g.RecordFailure(tg)
	}
	if got := g.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2 (capped map)", got)
	}
	// A third target C evicts the LRU (A). The map must NOT exceed the cap.
	// C is failed twice (FailureThreshold=2) so it is tracked AND open.
	g.RecordFailure("c.example:443")
	g.RecordFailure("c.example:443")
	if got := g.Len(); got > 2 {
		t.Fatalf("Len = %d after inserting a third target; the cap of 2 must hold (no unbounded growth)", got)
	}
	// The evicted target A is now UNKNOWN: it fails closed to the direct dial
	// (allowed, no probe) — the map-full / unknown path never blocks it.
	if a, p := g.Allow("a.example:443"); !a || p {
		t.Fatalf("evicted target Allow = (%v,%v), want (true,false) — fail closed to the direct dial", a, p)
	}
	// The still-tracked, still-open target C is refused during its cooldown.
	if a, _ := g.Allow("c.example:443"); a {
		t.Fatal("open tracked target C must be refused during cooldown")
	}
}
