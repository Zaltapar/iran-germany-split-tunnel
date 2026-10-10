// intel_test.go — Phase 3 (gate G3) deterministic unit tests for the carrier-
// intelligence policy engine (pkg/node/intel.go).
//
// Every test uses an injected clock (mutableClock) so the score ordering,
// gate exclusion, hysteresis, exponential cooldown, half-open readmission,
// connect-RTT weight-0, probe-budget invariant, and static-vs-adaptive
// behavior are all fully deterministic. These are the acceptance tests S1/S2/
// S3/S4 from plans/multi-carrier-intelligence-design.md §10 (Phase 3).

package node

import (
	"strings"
	"testing"
	"time"
)

// mutableClock is the injected clock. All "now" values in a test are derived
// from it, so the policy is a pure function of (inputs, clock).
type mutableClock struct{ t time.Time }

func (c *mutableClock) now() time.Time          { return c.t }
func (c *mutableClock) advance(d time.Duration) { c.t = c.t.Add(d) }

var testEpoch = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)

const (
	downA = CarrierID("down-a")
	downB = CarrierID("down-b")
)

// newPolicyAt builds a policy in the given mode with the default starting
// values and returns it along with a mutable clock anchored at testEpoch.
func newPolicyAt(t *testing.T, mode string, ids []CarrierID) (*Policy, *mutableClock) {
	t.Helper()
	clk := &mutableClock{t: testEpoch}
	cfg := PolicyConfigDefaults()
	cfg.Mode = mode
	p, err := NewPolicy(clk.now, cfg, ids)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p, clk
}

// newProbingPolicy builds an adaptive policy with active probing enabled (and
// a required operator URL), so the probe/H1 paths are exercised.
func newProbingPolicy(t *testing.T, ids []CarrierID) (*Policy, *mutableClock) {
	t.Helper()
	clk := &mutableClock{t: testEpoch}
	cfg := PolicyConfigDefaults()
	cfg.Mode = PolicyAdaptive
	cfg.ProbingEnabled = true
	cfg.ProbeURL = "https://probe.internal/ok"
	p, err := NewPolicy(clk.now, cfg, ids)
	if err != nil {
		t.Fatalf("NewPolicy(probing): %v", err)
	}
	return p, clk
}

// --- white-box helpers ------------------------------------------------------

// setGoodput fills the carrier's recent goodput ring with `g` MiB/s (all
// samples identical, so p10 == g) and bounds the written count to `samples`.
// With samples >= 10 the p10 is a "real" percentile. The other score terms
// stay neutral/zero, so the total is 0.35*g + 0.475 with default weights.
func setGoodput(t *testing.T, p *Policy, id CarrierID, g float64, samples int) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	for i := 0; i < samples; i++ {
		h.goodputRing[i] = g
	}
	h.goodputWrites = int64(samples)
}

// forceActive puts a carrier into Active with a dwelled ActiveSince so the
// ActiveHealthReset window does not interfere with the test.
func forceActive(t *testing.T, p *Policy, id CarrierID, at time.Time) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	h.State = stateActive
	h.ActiveSince = at.Add(-time.Hour)
}

// scoreOf returns the carrier's freshly computed score components at `now`
// (white-box call of the unexported scoreLocked).
func scoreOf(t *testing.T, p *Policy, id CarrierID, now time.Time) ScoreComponents {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.scoreLocked(p.health[id], now)
}

// healthOf returns a reference to a carrier's health for direct mutation.
func healthOf(t *testing.T, p *Policy, id CarrierID) *CarrierHealth {
	t.Helper()
	return p.health[id]
}

// excludeNow calls the unexported excludeLocked to force an exclusion with a
// given reason and advancing the exclusion streak (design §6.5).
func excludeNow(t *testing.T, p *Policy, id CarrierID, now time.Time, reason string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.excludeLocked(p.health[id], now, reason)
}

// cooldownPeriodOf reads the carrier's last-set cooldown period.
func cooldownPeriodOf(t *testing.T, p *Policy, id CarrierID) time.Duration {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.health[id].CooldownPeriod
}

// exclusionStreakOf reads the carrier's exclusion streak counter.
func exclusionStreakOf(t *testing.T, p *Policy, id CarrierID) int {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.health[id].ExclusionStreak
}

// stringSlices maps []CarrierID to []string for Join.
func stringSlices(in []CarrierID) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// --- S1: score ordering -----------------------------------------------------

// TestScoreOrdering proves the score is a deterministic function of the
// measured goodput: a faster carrier (higher p10 goodput) always scores
// higher than a slower one, with all other terms held neutral.
func TestScoreOrdering(t *testing.T) {
	cases := []struct {
		name string
		a, b float64 // MiB/s goodput for the two carriers
		want string  // which carrier should win
	}{
		{"fast beats slow", 1.0, 0.4, string(downA)},
		{"slow loses", 0.4, 1.0, string(downB)},
		{"tie on goodput", 0.7, 0.7, string(downA)}, // lexical tie-break -> A
		{"sub-sla below floor", 0.2, 0.6, string(downB)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, clk := newPolicyAt(t, PolicyStatic, []CarrierID{downA, downB})
			now := clk.now()
			setGoodput(t, p, downA, tc.a, 12)
			setGoodput(t, p, downB, tc.b, 12)
			forceActive(t, p, downA, now)
			forceActive(t, p, downB, now)
			p.Evaluate(now)
			sa, sb := p.Score(downA), p.Score(downB)
			switch tc.want {
			case string(downA):
				if !(sa >= sb) {
					t.Fatalf("want A>=B, got A=%.4f B=%.4f", sa, sb)
				}
			case string(downB):
				if !(sb > sa) {
					t.Fatalf("want B>A, got A=%.4f B=%.4f", sa, sb)
				}
			}
		})
	}
}

// --- S1: hard-gate exclusion ------------------------------------------------

// TestGatesExclude proves each hard gate (H2/H3/H4/success/stall) and the
// informational not_active gate exclude the carrier, in gate-priority order.
func TestGatesExclude(t *testing.T) {
	id := downA
	t.Run("H2_flap", func(t *testing.T) {
		p, clk := newPolicyAt(t, PolicyStatic, []CarrierID{id})
		for i := 0; i < 3; i++ { // FlapLimit = 3
			p.RecordFlap(id, clk.now())
		}
		comp := scoreOf(t, p, id, clk.now())
		if comp.Eligible || comp.GateReason != "H2 flap" {
			t.Fatalf("H2 flap: got eligible=%v reason=%q", comp.Eligible, comp.GateReason)
		}
	})
	t.Run("H3_auth", func(t *testing.T) {
		p, clk := newPolicyAt(t, PolicyStatic, []CarrierID{id})
		p.RecordAuthFail(id, clk.now())
		comp := scoreOf(t, p, id, clk.now())
		if comp.Eligible || comp.GateReason != "H3 auth" {
			t.Fatalf("H3 auth: got eligible=%v reason=%q", comp.Eligible, comp.GateReason)
		}
	})
	t.Run("H4_zero_delivery", func(t *testing.T) {
		p, clk := newPolicyAt(t, PolicyStatic, []CarrierID{id})
		h := healthOf(t, p, id)
		h.HasPending = true
		h.LastDeliveredAt = clk.now().Add(-40 * time.Second) // >= HardGateZeroDeliver (30s)
		comp := scoreOf(t, p, id, clk.now())
		if comp.Eligible || comp.GateReason != "H4 stall" {
			t.Fatalf("H4 stall: got eligible=%v reason=%q", comp.Eligible, comp.GateReason)
		}
	})
	t.Run("success_ratio", func(t *testing.T) {
		p, clk := newPolicyAt(t, PolicyStatic, []CarrierID{id})
		h := healthOf(t, p, id)
		for i := 0; i < 40; i++ {
			h.SuccessRing[i] = false
		}
		h.SuccessRing[0] = true // 1 ok out of 40 attempts -> Laplace ~0.048 < 0.50
		h.SuccessOK = 1
		h.SuccessWrites = 40
		comp := scoreOf(t, p, id, clk.now())
		if comp.Eligible || comp.GateReason != "success_ratio" {
			t.Fatalf("success_ratio: got eligible=%v reason=%q", comp.Eligible, comp.GateReason)
		}
	})
	t.Run("stall_rate", func(t *testing.T) {
		p, clk := newPolicyAt(t, PolicyStatic, []CarrierID{id})
		h := healthOf(t, p, id)
		// Healthy success ring so success_ratio does not fire first.
		for i := 0; i < 40; i++ {
			h.SuccessRing[i] = true
		}
		h.SuccessOK = 40
		h.SuccessWrites = 40
		h.DeliveredBytes = 1 << 20 // 1 MiB delivered
		h.StallCount = 100         // -> 100 stalls per 100 MiB >> HardGateMaxStallRate (10)
		comp := scoreOf(t, p, id, clk.now())
		if comp.Eligible || comp.GateReason != "stall_rate" {
			t.Fatalf("stall_rate: got eligible=%v reason=%q", comp.Eligible, comp.GateReason)
		}
	})
	t.Run("H1_probe_fail", func(t *testing.T) {
		p, clk := newProbingPolicy(t, []CarrierID{id})
		h := healthOf(t, p, id)
		h.ConsecProbeFails = 2 // H1: two consecutive probe failures
		comp := scoreOf(t, p, id, clk.now())
		if comp.Eligible || comp.GateReason != "H1 probe" {
			t.Fatalf("H1 probe: got eligible=%v reason=%q", comp.Eligible, comp.GateReason)
		}
	})
	t.Run("not_active_is_informational", func(t *testing.T) {
		p, clk := newPolicyAt(t, PolicyStatic, []CarrierID{id})
		// Candidate state (not yet admitted) is not a hard exclusion, just not
		// a new-stream candidate.
		comp := scoreOf(t, p, id, clk.now())
		if comp.Eligible || comp.GateReason != "not_active" {
			t.Fatalf("not_active: got eligible=%v reason=%q", comp.Eligible, comp.GateReason)
		}
	})
}

// --- S1/S2: hysteresis ------------------------------------------------------

// TestHysteresisNoSwitchOnNoise proves a challenger that beats the incumbent
// by LESS than the 0.10 margin for many consecutive ticks never triggers a
// switch (design §6.5 / acceptance S2).
func TestHysteresisNoSwitchOnNoise(t *testing.T) {
	p, clk := newPolicyAt(t, PolicyAdaptive, []CarrierID{downA, downB})
	now := clk.now()
	// t0: A is strictly best -> A becomes the incumbent.
	setGoodput(t, p, downA, 1.0, 12)
	setGoodput(t, p, downB, 0.4, 12)
	forceActive(t, p, downA, now)
	forceActive(t, p, downB, now)
	p.Evaluate(now)
	if p.Incumbent() != downA {
		t.Fatalf("incumbent = %q, want A (highest score at t0)", p.Incumbent())
	}
	// Now A degrades to 0.5 and B to 0.6: B beats A by only ~0.035 (< 0.10).
	for i := 0; i < 6; i++ {
		clk.advance(61 * time.Second)
		setGoodput(t, p, downA, 0.5, 12)
		setGoodput(t, p, downB, 0.6, 12)
		p.Evaluate(clk.now())
	}
	if p.SwitchCount() != 0 {
		t.Fatalf("noisy challenger caused %d switch(es), want 0", p.SwitchCount())
	}
	if p.Incumbent() != downA {
		t.Fatalf("incumbent flipped to %q on sub-margin noise, want A", p.Incumbent())
	}
}

// TestHysteresisSwitchOnDecisiveChallenge proves that once a challenger beats
// the incumbent by >= 0.10 for HysteresisTicks consecutive ticks AND the
// incumbent has dwelled >= MinDwell, the switch happens exactly once.
func TestHysteresisSwitchOnDecisiveChallenge(t *testing.T) {
	p, clk := newPolicyAt(t, PolicyAdaptive, []CarrierID{downA, downB})
	now := clk.now()
	setGoodput(t, p, downA, 1.0, 12)
	setGoodput(t, p, downB, 0.4, 12)
	forceActive(t, p, downA, now)
	forceActive(t, p, downB, now)
	p.Evaluate(now) // A incumbent
	if p.Incumbent() != downA {
		t.Fatalf("incumbent = %q, want A", p.Incumbent())
	}
	// Decisive: A degrades to 0.5 (0.65), B rises to 1.0 (0.825): beat by 0.175.
	for ticks := 1; ticks <= 2; ticks++ {
		clk.advance(61 * time.Second) // dwell >= 60s satisfied
		setGoodput(t, p, downA, 0.5, 12)
		setGoodput(t, p, downB, 1.0, 12)
		p.Evaluate(clk.now())
		if p.Incumbent() != downA {
			t.Fatalf("switched too early at tick %d", ticks)
		}
	}
	clk.advance(61 * time.Second)
	setGoodput(t, p, downA, 0.5, 12)
	setGoodput(t, p, downB, 1.0, 12)
	p.Evaluate(clk.now()) // 3rd consecutive tick -> switch
	if p.Incumbent() != downB {
		t.Fatalf("incumbent = %q after decisive 3-tick challenge, want B", p.Incumbent())
	}
	if p.SwitchCount() != 1 {
		t.Fatalf("SwitchCount = %d, want exactly 1", p.SwitchCount())
	}
}

// --- S1: exponential cooldown + half-open readmission -----------------------

// TestCooldownDoublingAndCap proves the exclusion cooldown doubles per
// consecutive exclusion and caps at MaxCooldown (design §6.5: 30s -> 60s ->
// 120s -> 240s -> 480s -> cap 15m). The doubling is a property of the
// exclusion-streak counter, verified here directly against the real
// excludeLocked period math (independent of the lifecycle guard that
// short-circuits when the carrier is already Excluded).
func TestCooldownDoublingAndCap(t *testing.T) {
	p, clk := newPolicyAt(t, PolicyAdaptive, []CarrierID{downA})
	now := clk.now()
	h := healthOf(t, p, downA)
	maxCD := p.SanitizedConfig().MaxCooldown

	want := []struct {
		streak int
		period time.Duration
	}{
		{1, 30 * time.Second},
		{2, 60 * time.Second},
		{3, 120 * time.Second},
		{4, 240 * time.Second},
		{5, 480 * time.Second},
		{6, 15 * time.Minute},  // 960s would exceed the 15m cap -> capped
		{20, 15 * time.Minute}, // still capped
	}
	for _, w := range want {
		p.mu.Lock()
		// Each exclusion in the real lifecycle lands Active/Healthy; place the
		// carrier in Active so excludeLocked performs the state transition and
		// the doubling period is set from the current streak.
		h.State = stateActive
		h.ExclusionStreak = w.streak - 1
		p.excludeLocked(h, now, "test")
		p.mu.Unlock()
		if got := cooldownPeriodOf(t, p, downA); got != w.period {
			t.Fatalf("streak %d: cooldown = %s, want %s", w.streak, got, w.period)
		}
		if got := exclusionStreakOf(t, p, downA); got != w.streak {
			t.Fatalf("streak = %d, want %d", got, w.streak)
		}
	}
	_ = maxCD
}

// TestHalfOpenReadmission proves that after the cooldown elapses the carrier
// moves Excluded -> HalfOpen, and that 3 consecutive passes readmit it to
// Active (design §6.5 readmission). The exclusion streak is deliberately
// PRESERVED across readmission (exponential backoff only forgives after
// ActiveHealthReset of sustained health), so the readmitted carrier is ready
// to double its cooldown on the next exclusion.
func TestHalfOpenReadmission(t *testing.T) {
	p, clk := newPolicyAt(t, PolicyStatic, []CarrierID{downA}) // probing OFF: passive admission
	now := clk.now()
	forceActive(t, p, downA, now)

	// Exclude it, then force the cooldown to be already elapsed.
	excludeNow(t, p, downA, now, "H2 flap")
	h := healthOf(t, p, downA)
	h.CooldownUntil = now // cooldown already elapsed

	// Evaluate: Excluded with cooldown elapsed -> HalfOpen.
	p.Evaluate(now)
	if p.State(downA) != stateHalfOpen {
		t.Fatalf("state = %s, want half_open after cooldown", p.State(downA))
	}

	// Three consecutive clean completions (passive admission, probing OFF)
	// readmit the carrier.
	for pass := 1; pass <= 3; pass++ {
		p.RecordStreamOutcome(downA, true, 50*time.Millisecond, now)
		p.Evaluate(now)
		if pass < 3 && p.State(downA) != stateHalfOpen {
			t.Fatalf("still not readmitted after %d passes: state=%s", pass, p.State(downA))
		}
	}
	if p.State(downA) != stateActive {
		t.Fatalf("state = %s, want active after 3 readmission passes", p.State(downA))
	}
	// The streak is preserved (it was 1 after the single exclusion) so the
	// next exclusion doubles to the 60 s period, not the 30 s initial.
	if got := exclusionStreakOf(t, p, downA); got != 1 {
		t.Fatalf("exclusion streak = %d, want 1 (preserved for exponential backoff)", got)
	}
}

// --- S4: connect RTT has weight 0 -----------------------------------------

// TestConnectRTTNeverChangesSelection proves that recording TCP connect RTT
// alone (which has weight 0 in the score, design §6.1) never changes the
// selection sequence in adaptive smooth-WRR mode.
func TestConnectRTTNeverChangesSelection(t *testing.T) {
	seq := func(recordRTT bool) []CarrierID {
		p, clk := newPolicyAt(t, PolicyAdaptive, []CarrierID{downA, downB})
		now := clk.now()
		setGoodput(t, p, downA, 0.6, 12)
		setGoodput(t, p, downB, 0.6, 12) // identical scores
		forceActive(t, p, downA, now)
		forceActive(t, p, downB, now)
		if recordRTT {
			// Huge spread in connect RTT: B connects 100x slower than A.
			p.RecordConnectRTT(downA, 20*time.Millisecond)
			p.RecordConnectRTT(downB, 2000*time.Millisecond)
		}
		p.Evaluate(now)
		var out []CarrierID
		for i := 0; i < 8; i++ {
			out = append(out, p.PickForNewStream(now))
		}
		return out
	}
	plain, withRTT := seq(false), seq(true)
	if strings.Join(stringSlices(plain), ",") != strings.Join(stringSlices(withRTT), ",") {
		t.Fatalf("connect RTT changed the selection:\n no-rtt=%v\n with-rtt=%v\n (RTT must have weight 0)", plain, withRTT)
	}
}

// --- S3: probe byte budget is never exceeded ------------------------------

// TestProbeBudgetNeverExceeded proves the hard daily byte budget (design §6.4,
// D7) is never exceeded: CanProbe refuses any probe that would push the day's
// usage above the cap, and the counter resets only on the midnight roll.
func TestProbeBudgetNeverExceeded(t *testing.T) {
	clk := &mutableClock{t: testEpoch}
	cfg := PolicyConfigDefaults()
	cfg.Mode = PolicyAdaptive
	cfg.ProbingEnabled = true
	cfg.ProbeURL = "https://probe.internal/ok"
	cfg.ProbeDailyBudgetBytes = 100 * 1024 // 100 KiB hard cap
	p, err := NewPolicy(clk.now, cfg, []CarrierID{downA})
	if err != nil {
		t.Fatal(err)
	}

	const probe = 20 * 1024 // 20 KiB per quick probe
	exhausted := false
	for i := 0; i < 50; i++ {
		if !p.CanProbe(downA, probe, clk.now()) {
			exhausted = true
			break
		}
		p.RecordProbe(downA, true, 1.0, probe, clk.now(), false)
		if used := p.ProbeBytesUsedToday(downA); used > cfg.ProbeDailyBudgetBytes {
			t.Fatalf("probe budget exceeded: used %d > cap %d", used, cfg.ProbeDailyBudgetBytes)
		}
	}
	if !exhausted {
		t.Fatalf("budget never exhausted within %d probes", 50)
	}
	if p.CanProbe(downA, 1, clk.now()) {
		t.Fatalf("CanProbe true after the day's budget is exhausted")
	}

	// Day roll: advance past local midnight -> usage resets, probes allowed again.
	clk.advance(25 * time.Hour)
	if !p.CanProbe(downA, probe, clk.now()) {
		t.Fatalf("probes still refused after the day rolled over")
	}
	p.RecordProbe(downA, true, 1.0, probe, clk.now(), false)
	if used := p.ProbeBytesUsedToday(downA); used != probe {
		t.Fatalf("post-rollover usage = %d, want a fresh %d", used, probe)
	}
}

// TestProbingWithoutURLFailsClosed proves the fail-closed constructor rule:
// enabling probing with no operator probe URL is a startup error (design §6.4).
func TestProbingWithoutURLFailsClosed(t *testing.T) {
	cfg := PolicyConfigDefaults()
	cfg.ProbingEnabled = true
	cfg.ProbeURL = ""
	if _, err := NewPolicy(time.Now, cfg, []CarrierID{downA}); err == nil {
		t.Fatalf("expected a fail-closed error for probing without a URL")
	}
}

// --- requirement 6: static policy disables adaptive switching --------------

// TestStaticPolicyDisablesAdaptiveSwitching proves that in static mode the
// hysteresis/switch bookkeeping is a no-op: even a far-better challenger
// never displaces the static-priority primary, and PickForNewStream always
// returns the first eligible Active carrier in priority order.
func TestStaticPolicyDisablesAdaptiveSwitching(t *testing.T) {
	p, clk := newPolicyAt(t, PolicyStatic, []CarrierID{downA, downB})
	now := clk.now()
	// A is primary (priority order). B is far better on score.
	setGoodput(t, p, downA, 0.6, 12)
	setGoodput(t, p, downB, 1.0, 12)
	forceActive(t, p, downA, now)
	forceActive(t, p, downB, now)

	for i := 0; i < 20; i++ {
		clk.advance(61 * time.Second)
		p.Evaluate(clk.now())
		if p.SwitchCount() != 0 {
			t.Fatalf("static mode recorded %d switch(es) at iter %d; static must never switch", p.SwitchCount(), i)
		}
	}
	// Static selection: always the first eligible Active in priority order.
	for i := 0; i < 6; i++ {
		if got := p.PickForNewStream(now); got != downA {
			t.Fatalf("static PickForNewStream = %q, want primary A every time", got)
		}
	}
}

// --- requirement 7: per-carrier metrics only when enabled -----------------

// TestPerCarrierMetricsOnlyWhenEnabled proves /metrics emits the per-carrier
// health and per-carrier loss/reconnect lines ONLY when multi-carrier is
// enabled (single-carrier output stays byte-identical).
func TestPerCarrierMetricsOnlyWhenEnabled(t *testing.T) {
	// Single-carrier metrics: no per-carrier lines at all.
	single := NewMetrics().Render()
	if strings.Contains(single, "carrier_loss_events{") {
		t.Fatalf("single-carrier /metrics leaked a per-carrier loss line:\n%s", single)
	}
	if strings.Contains(single, "carrier_health_") {
		t.Fatalf("single-carrier /metrics leaked a Phase 3 health line:\n%s", single)
	}

	// Multi-carrier metrics with a policy attached: the lines appear.
	p, _ := newPolicyAt(t, PolicyAdaptive, []CarrierID{downA, downB})
	m := NewMetrics()
	m.SetMultiCarrier([]CarrierID{downA, downB})
	m.SetPolicy(p)
	out := m.Render()
	if !strings.Contains(out, "carrier_loss_events{") {
		t.Fatalf("multi-carrier /metrics missing per-carrier loss line:\n%s", out)
	}
	if !strings.Contains(out, "carrier_health_state{") {
		t.Fatalf("multi-carrier /metrics missing the Phase 3 health gauge family:\n%s", out)
	}
}
