// target_dial_governor.go implements the up-carrier drop-storm fix Parts 2
// and 3: a bounded target-dial timeout with jittered per-target retry
// backoff, and a per-target dial-failure circuit breaker. Everything here is
// DISABLED by default, so the healthy path is byte-identical to the pre-fix
// build; each knob is env-gated (see internal/config) and only engages when an
// operator opts in.
//
// The two guarantees that must never be broken:
//
//   - a bounded dial can never be UNBOUNDED (a misconfigured <=0 bound falls
//     back to a direct call of the raw dialer, never to "no ceiling");
//   - the circuit breaker fails CLOSED TO DIRECT DIAL (it never blocks a
//     healthy target): an unknown target, an LRU-evicted target, or a target
//     not being tracked all just do the ordinary direct dial.
package node

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"
)

// dialBackoff is a pkg/node-local jittered exponential backoff schedule for
// per-target dial retries (Part 2). It mirrors the semantics of the repo's
// internal/backoff package (exponential doubling with a cap, each delay
// randomized into [d/2, d], reset after a success) but lives in pkg/node
// because the architecture boundary forbids pkg/* from importing internal/*.
// Each per-target schedule has its OWN RNG so concurrent targets never share a
// locked random source (the dispatcher and many bootstrapUpStream goroutines
// can call it concurrently).
type dialBackoff struct {
	mu        sync.Mutex
	base, max time.Duration
	count     int
	rnd       *rand.Rand
}

// newDialBackoff builds a jittered backoff starting at base, capped at max.
// Non-positive values are sanitized so the schedule is always well-defined.
func newDialBackoff(base, max time.Duration) *dialBackoff {
	if base <= 0 {
		base = time.Millisecond
	}
	if max < base {
		max = base
	}
	return &dialBackoff{base: base, max: max, rnd: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

// nextDelay returns the delay for the NEXT attempt and advances the schedule:
// base, base*2, base*4, ... capped at max, each jittered into [d/2, d]
// (inclusive) so the cap is a real cap and retries of a shared failing target
// decorrelate. The returned value is the jittered duration to sleep.
func (b *dialBackoff) nextDelay() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	exp := uint(b.count)
	if exp > 30 {
		exp = 30
	}
	d := b.base << exp
	if d <= 0 || d > b.max {
		d = b.max
	}
	b.count++
	// Jitter into [d/2, d]: keeps the worst case at d (the cap stays a real
	// cap) while decorrelating targets that share a failure.
	j := d / 2
	if d/2 > 0 {
		j += time.Duration(b.rnd.Int63n(int64(d/2) + 1))
	}
	return j
}

// reset restarts the schedule at base — called after a target dial SUCCEEDS,
// so a target that later fails again starts its own fresh schedule.
func (b *dialBackoff) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.count = 0
}

// attempts reports how many delays have been handed out since the last reset.
func (b *dialBackoff) attempts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count
}

// ErrTargetBreakerOpen is returned by TargetDialGovernor.Dial when the
// per-target circuit breaker is open and its cooldown has not elapsed, so the
// dial is refused fast instead of spending a (possibly long) timeout on a
// target that is known to be failing. bootstrapUpStream surfaces this to the
// client as a fast, clean, fail-closed drop.
var ErrTargetBreakerOpen = errors.New("target dial breaker open (cooldown)")

// ErrTargetDialTimeout is returned when a bounded dial exceeds the operator's
// ceiling and the in-flight attempt is abandoned.
var ErrTargetDialTimeout = errors.New("target dial exceeded the bounded timeout")

// dialBounded races fn(addr) against a ctx deadline of `timeout`. When
// timeout <= 0 it calls fn directly (no goroutine, no ceiling) — the
// pre-fix behavior, byte-identical. When timeout > 0, fn is spawned so it can
// never leak blocked on the select; the first of {fn returning, deadline,
// ctx done} wins. The spawned dial cannot be cancelled (fn is an opaque
// dial func with no context); it completes to its own internal ceiling (the
// default dialer is already bounded to 10s), so any wrapper leak is bounded,
// not unbounded.
func dialBounded(ctx context.Context, timeout time.Duration, fn func(string) (net.Conn, error), addr string) (net.Conn, error) {
	if fn == nil {
		return nil, errors.New("target dialer is nil")
	}
	if timeout <= 0 {
		return fn(addr)
	}
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan dialResult, 1)
	go func() {
		c, e := fn(addr)
		resCh <- dialResult{c, e}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-resCh:
		return r.conn, r.err
	case <-timer.C:
		return nil, ErrTargetDialTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// GovernorConfig parameterizes a TargetDialGovernor. All timing knobs have
// library defaults lifted in NewTargetDialGovernor; a zeroed config (breaker
// off, backoff off, BoundedTimeout 0) yields a nil governor from
// BuildTargetDialGovernor, i.e. no behavior change to the retry/refusal
// logic (byte-identical to the pre-fix build).
type GovernorConfig struct {
	// BoundedTimeout is the per-dial ceiling (Part 2). 0 = no extra ceiling
	// (the raw dialer's own internal bound stands — byte-identical default).
	BoundedTimeout time.Duration
	// BreakerEnabled turns on the per-target circuit breaker (Part 3).
	BreakerEnabled bool
	// FailureWindow is the rolling window over which consecutive failures are
	// counted before the breaker opens. Default 60s.
	FailureWindow time.Duration
	// FailureThreshold is the number of failures within FailureWindow that
	// opens the breaker for a target. Default 5.
	FailureThreshold int
	// Cooldown is how long an open breaker stays open before it admits a
	// single half-open probe. Default 30s.
	Cooldown time.Duration
	// BackoffEnabled turns on the jittered per-target retry backoff (Part 2).
	BackoffEnabled bool
	// BackoffBase / BackoffMax bound the exponential schedule (jittered into
	// [d/2, d]). Default 500ms / 30s.
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// MaxTargets caps the tracked-target map (LRU). Default 1024. When the
	// cap is reached a new target evicts the least-recently-used one; an
	// evicted/unknown target always fails closed to the direct dial.
	MaxTargets int
	// Now is the clock. A deterministic source is injectable for tests.
	Now func() time.Time
	// RndSource seeds the jitter. Zero → time-based seed.
	RndSource int64
}

const (
	defaultFailureWindow    = 60 * time.Second
	defaultFailureThreshold = 5
	defaultCooldown         = 30 * time.Second
	defaultBackoffBase      = 500 * time.Millisecond
	defaultBackoffMax       = 30 * time.Second
	defaultMaxTargets       = 1024
)

// governorEntry is the per-target breaker + backoff state.
type governorEntry struct {
	// circuit breaker (Part 3)
	open        bool
	openedAt    time.Time
	failures    int
	windowStart time.Time
	halfProbed  bool
	// jittered retry backoff (Part 2); nil when backoff is disabled
	bo         *dialBackoff
	pendingRet bool
}

// TargetDialGovernor is a bounded, per-target dial-failure circuit breaker
// plus a jittered retry backoff, keyed by target string (host:port). It is
// safe for concurrent use. It holds at most MaxTargets entries (LRU), and it
// fails closed to the direct dial for any target it does not track.
type TargetDialGovernor struct {
	mu sync.Mutex

	// static configuration
	bound          time.Duration
	breakerEnabled bool
	window         time.Duration
	threshold      int
	cooldown       time.Duration
	backoffEnabled bool
	boffBase       time.Duration
	boffMax        time.Duration
	maxTargets     int

	now     func() time.Time
	rnd     *rand.Rand
	entries map[string]*governorEntry
	// order holds the LRU recency order, least-recent first.
	order []string
}

// NewTargetDialGovernor lifts zero values to the documented library defaults
// and builds a live governor.
func NewTargetDialGovernor(cfg GovernorConfig) *TargetDialGovernor {
	if cfg.FailureWindow <= 0 {
		cfg.FailureWindow = defaultFailureWindow
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = defaultFailureThreshold
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = defaultCooldown
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = defaultBackoffBase
	}
	if cfg.BackoffMax <= 0 || cfg.BackoffMax < cfg.BackoffBase {
		cfg.BackoffMax = defaultBackoffMax
	}
	if cfg.MaxTargets <= 0 {
		cfg.MaxTargets = defaultMaxTargets
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	seed := cfg.RndSource
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &TargetDialGovernor{
		bound:          cfg.BoundedTimeout,
		breakerEnabled: cfg.BreakerEnabled,
		window:         cfg.FailureWindow,
		threshold:      cfg.FailureThreshold,
		cooldown:       cfg.Cooldown,
		backoffEnabled: cfg.BackoffEnabled,
		boffBase:       cfg.BackoffBase,
		boffMax:        cfg.BackoffMax,
		maxTargets:     cfg.MaxTargets,
		now:            now,
		rnd:            rand.New(rand.NewSource(seed)),
		entries:        make(map[string]*governorEntry),
	}
}

// BuildTargetDialGovernor lifts a GovernorConfig into a live governor. It
// returns nil when every feature is disabled (breaker off, backoff off, and
// no bounded timeout) so the node stays byte-identical to the pre-fix build:
// bootstrapUpStream then dials directly with no gate, backoff, or ceiling.
func BuildTargetDialGovernor(gc GovernorConfig) *TargetDialGovernor {
	if !gc.BreakerEnabled && !gc.BackoffEnabled && gc.BoundedTimeout <= 0 {
		return nil
	}
	return NewTargetDialGovernor(gc)
}

// Dial performs ONE governed dial of target via rawDial: it consults the
// breaker (Part 3), waits the target's jittered retry backoff (Part 2), runs
// the bounded dial (Part 2), and records the outcome. When the governor is
// fully disabled (bound 0, breaker off, backoff off) it is byte-identical to
// rawDial(target) — the pre-fix path.
func (g *TargetDialGovernor) Dial(ctx context.Context, rawDial func(string) (net.Conn, error), target string) (net.Conn, error) {
	if rawDial == nil {
		return nil, errors.New("target dialer is nil")
	}
	// A fully-disabled governor (no bound, breaker off, backoff off) is the
	// fast path: direct dial, byte-identical to the pre-fix build.
	if g.bound <= 0 && !g.breakerEnabled && !g.backoffEnabled {
		return rawDial(target)
	}
	// Part 3: circuit-breaker gate. Unknown / evicted / breaker-disabled
	// targets fail closed to the direct dial (allowed=true, probe=false).
	allowed, probe := g.Allow(target)
	if !allowed {
		return nil, ErrTargetBreakerOpen
	}
	// Part 2: jittered retry backoff (spaced, bounded). A no-op when
	// backoff is disabled or this target has no armed retry.
	if err := g.Wait(ctx, target); err != nil {
		return nil, err
	}
	// Part 2: bounded dial (ceiling). bound<=0 → direct call (byte-identical).
	conn, err := dialBounded(ctx, g.bound, rawDial, target)
	if err != nil {
		g.RecordFailure(target)
		// A failed half-open probe keeps the breaker open (restart cooldown);
		// RecordFailure handles the open-vs-closed distinction internally.
		return nil, err
	}
	g.RecordSuccess(target)
	if probe {
		// A successful half-open probe is already closed by RecordSuccess.
	}
	return conn, nil
}

// touchMRU returns target's entry (creating it with LRU eviction if absent)
// and moves it to most-recently-used. It NEVER fails closed; a map at
// capacity simply evicts the least-recently-used target, which thereafter
// behaves as unknown (direct dial). Caller holds g.mu.
func (g *TargetDialGovernor) touchMRU(target string) *governorEntry {
	e, ok := g.entries[target]
	if !ok {
		if len(g.entries) >= g.maxTargets && len(g.order) > 0 {
			evict := g.order[0]
			g.order = g.order[1:]
			delete(g.entries, evict)
		}
		e = &governorEntry{}
		g.entries[target] = e
		g.order = append(g.order, target)
		return e
	}
	for i, t := range g.order {
		if t == target {
			g.order = append(g.order[:i], g.order[i+1:]...)
			g.order = append(g.order, target)
			break
		}
	}
	return e
}

// Allow reports whether a dial to target may proceed. It returns (allowed,
// probe):
//
//   - breaker disabled, or target unknown/evicted → (true, false)
//     (fail closed to the direct dial);
//   - breaker open and cooldown NOT elapsed         → (false, false) (refused);
//   - breaker open and cooldown elapsed            → (true, true)
//     (admit a single half-open probe);
//   - breaker closed                               → (true, false).
func (g *TargetDialGovernor) Allow(target string) (allowed bool, probe bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.breakerEnabled {
		return true, false
	}
	e, ok := g.entries[target]
	if !ok {
		return true, false // unknown / evicted → fail to the direct dial
	}
	g.touchMRU(target)
	if !e.open {
		return true, false
	}
	if g.now().Sub(e.openedAt) < g.cooldown {
		return false, false // still in cooldown: refuse
	}
	if e.halfProbed {
		return false, false // a probe is already in flight: refuse
	}
	e.halfProbed = true
	return true, true
}

// RecordSuccess closes the breaker for target and resets its retry backoff.
// It does NOT create an entry for a target that has never failed: a target
// that only ever succeeds is not tracked, keeping the map bounded to the set
// of actually-failing targets.
func (g *TargetDialGovernor) RecordSuccess(target string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.entries[target]
	if !ok {
		return
	}
	e.open = false
	e.halfProbed = false
	e.failures = 0
	e.windowStart = time.Time{}
	e.pendingRet = false
	if g.backoffEnabled && e.bo != nil {
		e.bo.reset()
	}
}

// RecordFailure counts a dial failure for target. When the breaker is enabled
// and the rolling window holds enough failures it opens; when the target is
// already open (a failed half-open probe) it restarts the cooldown so the
// target stays closed. It also arms the target's jittered retry backoff.
func (g *TargetDialGovernor) RecordFailure(target string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.touchMRU(target)
	now := g.now()
	if e.open {
		// A half-open probe failed: keep the breaker open and restart the
		// cooldown (the target is still failing).
		e.openedAt = now
		e.halfProbed = false
	} else {
		if e.windowStart.IsZero() {
			e.windowStart = now
		}
		// Slide the rolling window: reset the counter when the window has
		// elapsed (a target that recovered between windows is re-admitted).
		if now.Sub(e.windowStart) >= g.window {
			e.failures = 0
			e.windowStart = now
		}
		e.failures++
		if g.breakerEnabled && e.failures >= g.threshold {
			e.open = true
			e.halfProbed = false
			e.openedAt = now
		}
	}
	if g.backoffEnabled {
		if e.bo == nil {
			e.bo = newDialBackoff(g.boffBase, g.boffMax)
		}
		e.pendingRet = true
	}
}

// Wait blocks for the target's current jittered retry backoff delay (Part 2)
// and returns ctx.Err() if the context is cancelled while waiting. It is a
// no-op (returns nil immediately) when backoff is disabled, when the target
// is unknown / has no armed retry, or after a success-reset. Callers invoke
// it only after Allow() admitted the attempt.
func (g *TargetDialGovernor) Wait(ctx context.Context, target string) error {
	if !g.backoffEnabled {
		return nil
	}
	g.mu.Lock()
	var bo *dialBackoff
	if e, ok := g.entries[target]; ok && e.pendingRet && e.bo != nil {
		bo = e.bo
		e.pendingRet = false
	}
	g.mu.Unlock()
	if bo == nil {
		return nil
	}
	// Jittered, capped delay for the next retry; cancelable on ctx so a
	// shutdown never waits out a pending backoff.
	d := bo.nextDelay()
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// BackoffAttempts reports the target's retry-backoff attempt count (0 when
// backoff is disabled or the target is unknown) — a test/observability hook
// proving the schedule is escalating and capped.
func (g *TargetDialGovernor) BackoffAttempts(target string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.entries[target]; ok && e.bo != nil {
		return e.bo.attempts()
	}
	return 0
}

// OpenCount reports how many tracked targets currently have an open breaker —
// a bounded gauge for the metrics surface (breaker state, Part 4).
func (g *TargetDialGovernor) OpenCount() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	var n int64
	for _, e := range g.entries {
		if e.open {
			n++
		}
	}
	return n
}

// Len reports the number of tracked targets (for the memory-bound test).
func (g *TargetDialGovernor) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.entries)
}
