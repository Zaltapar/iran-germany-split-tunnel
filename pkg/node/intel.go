// intel.go — Phase 3 of plans/multi-carrier-intelligence-design.md.
//
// Deterministic carrier-intelligence policy: per-carrier health windows,
// bounded active probing with a hard daily byte budget, a weighted score
// with hard gates, hysteresis (margin + tick count + minimum dwell),
// exponential cooldown with half-open readmission, and smooth weighted
// round-robin for top-K new-stream assignment.
//
// The engine is a pure function of (PolicyConfig, injected clock, health
// inputs), so unit tests are deterministic (Gate G3 S1/S2/S4). No wall
// clock is read inside the engine; the caller supplies `now`.
//
// Design references (all in plans/multi-carrier-intelligence-design.md):
//
//	§6.2 per-CarrierID metric definitions
//	§6.3 score formula (G/S/N/T/R; weights 0.35/0.25/0.15/0.10/0.15)
//	§6.4 active probing (bounded cost, hard daily budget)
//	§6.5 lifecycle, hysteresis, cooldown, readmission
//	§7.1 selection for new streams (deterministic)
//	§7.5 observability
//
// Invariants (design §6.1, user requirement R2):
//   - Connect RTT is recorded for diagnostics only and has WEIGHT 0 in the
//     score. It can never promote or demote a carrier (test S4 proves it).
//   - Only measured application-level outcomes drive the score: delivered
//     goodput, stream completion, stalls, TTFB, and reset/flap stability.
//
// Rollback (design §10 Phase 3): the "static" policy mode re-enables the
// Phase 2 static-priority selection (first Active/ready carrier in config
// order). The scoring path stays compiled but inert. Pinned streams and the
// Phase 2 loss-failover path are unaffected in both modes.
package node

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// carrierState is the lifecycle state of one carrier in the Phase 3 policy
// engine (design §6.5):
//
//	Candidate → Active:   AdmitPassesCand probes pass and score >= AdmitScore
//	Active    → Excluded: a hard gate fails
//	Excluded  → HalfOpen: the cooldown has elapsed
//	HalfOpen  → Active:   AdmitPassesHalf full probes pass at the SLA floor
//	HalfOpen  → Excluded: a probe fails and the cooldown doubles
type carrierState uint8

const (
	stateCandidate carrierState = iota
	stateActive
	stateExcluded
	stateHalfOpen
)

// stateStrings are the fixed, code-owned names used in logs and the JSON
// snapshot. They never carry attacker-controlled values.
var stateStrings = [...]string{"candidate", "active", "excluded", "half_open"}

func (s carrierState) String() string {
	if int(s) < len(stateStrings) {
		return stateStrings[s]
	}
	return "unknown"
}

// PolicyMode selects the new-stream selection algorithm.
const (
	// PolicyStatic is the Phase 2 rollback: the first Active/ready carrier in
	// the configured static-priority order is primary. Hysteresis, cooldown,
	// and the score are NOT consulted for selection. This is the default.
	PolicyStatic = "static"
	// PolicyAdaptive is the Phase 3 algorithm: hard gates, weighted score,
	// hysteresis, exponential cooldown, half-open readmission, and a smooth
	// weighted round-robin over the top-K Active carriers for new-stream
	// assignment (design §7.1).
	PolicyAdaptive = "adaptive"
)

// PolicyConfig parameterizes the Phase 3 policy engine. Zero (or out-of-range)
// fields are sanitized to the documented starting values below. All timing
// values come from the injected clock, so the engine is deterministic under
// test.
//
// Documented starting values (design §6.3, §6.4, §6.5). The design leaves the
// weights/thresholds as starting points to be tuned from Phase 2 external
// traces; the values chosen here are recorded in the Phase 3 completion note.
type PolicyConfig struct {
	// Mode is PolicyStatic or PolicyAdaptive. Sanitized to PolicyStatic when
	// empty (Phase 2 rollback default: adaptive switching is OFF).
	Mode string
	// TopK is the number of top-scored Active carriers used for new-stream
	// assignment (design §7.1, D13). 0 or negative sanitizes to 2. It is
	// capped at the number of configured carriers by the engine.
	TopK int
	// TTFBBaseline is the Phase 0 baseline p50 (A3) used to normalize the T
	// term. 0 sanitizes to 500ms.
	TTFBBaseline time.Duration
	// SLAFloorMiBps is the R1 target goodput floor used by the G term and by
	// probe pass/fail. 0 sanitizes to 1.0 (1 MiB/s).
	SLAFloorMiBps float64

	// Hard gates (design §6.3 + user requirement "not Active, success below
	// threshold, stall rate above threshold" all exclude a carrier):
	HardGateMinSuccess   float64 // success ratio strictly below this excludes
	HardGateMaxStallRate float64 // stalls per 100 MiB above this excludes
	// HardGateZeroDeliver is the H4 window: zero delivered bytes for this
	// duration while pending bytes exist excludes the carrier.
	HardGateZeroDeliver time.Duration

	// Flap / reset / auth windows feeding H2 / R / H3.
	FlapWindow     time.Duration
	FlapLimit      int
	ResetWindow    time.Duration
	ResetLimit     int
	AuthFailWindow time.Duration

	// Hysteresis parameters (design §6.5).
	HysteresisMargin float64       // challenger must beat incumbent by this much
	HysteresisTicks  int           // ...for this many consecutive ticks
	MinDwell         time.Duration // ...and incumbent must have dwelled this long
	// EvalInterval is the documented tick interval; a hint for the transport
	// layer's timer. The engine itself is driven by explicit Evaluate calls.
	EvalInterval time.Duration

	// Cooldown (design §6.5): initial value, doubling cap, active-health reset.
	InitialCooldown   time.Duration
	MaxCooldown       time.Duration
	ActiveHealthReset time.Duration

	// Admission thresholds (design §6.5).
	AdmitScore      float64
	AdmitPassesCand int
	AdmitPassesHalf int

	// Probing (design §6.4).
	// ProbeDailyBudgetBytes is the HARD daily cap; when reached, no further
	// probes run for the day regardless of passive data (passive scoring
	// continues). A value of 0 disables the budget gate (all probes allowed —
	// a test-only sentinel); a NEGATIVE value is a config error (validated in
	// internal/config and coerced here to the default).
	ProbingEnabled           bool
	ProbeURL                 string // operator-configured; REQUIRED when ProbingEnabled
	ProbeDailyBudgetBytes    int64
	ProbeQuickBytes          int64
	ProbeFullBytes           int64
	ProbeQuickInterval       time.Duration
	ProbeFullInterval        time.Duration
	ProbeYieldMiBps          float64
	ProbePassQuickFloorMiBps float64
	ProbePassFullFloorMiBps  float64

	// Score weights (design §6.3). Sanitized to 0.35/0.25/0.15/0.10/0.15.
	// They are independent gates, not a probability, so they need not sum to 1.
	WGoodput, WSuccess, WStall, WTTFB, WReset float64
}

// PolicyConfigDefaults returns the documented starting values. The engine uses
// these when the corresponding fields are zero or out of range.
func PolicyConfigDefaults() PolicyConfig {
	const MiB = 1 << 20
	const KiB = 1024
	return PolicyConfig{
		Mode:          PolicyStatic, // Phase 2 rollback default: adaptive OFF
		TopK:          2,
		TTFBBaseline:  500 * time.Millisecond,
		SLAFloorMiBps: 1.0,

		HardGateMinSuccess:   0.50,
		HardGateMaxStallRate: 10.0,
		HardGateZeroDeliver:  30 * time.Second,

		FlapWindow:     10 * time.Minute,
		FlapLimit:      3,
		ResetWindow:    10 * time.Minute,
		ResetLimit:     3,
		AuthFailWindow: 60 * time.Second,

		HysteresisMargin: 0.10,
		HysteresisTicks:  3,
		MinDwell:         60 * time.Second,
		EvalInterval:     10 * time.Second,

		InitialCooldown:   30 * time.Second,
		MaxCooldown:       15 * time.Minute,
		ActiveHealthReset: 30 * time.Minute,

		AdmitScore:      0.60,
		AdmitPassesCand: 2,
		AdmitPassesHalf: 3,

		ProbingEnabled:           false,
		ProbeURL:                 "",
		ProbeDailyBudgetBytes:    96 * MiB,
		ProbeQuickBytes:          128 * KiB,
		ProbeFullBytes:           2 * MiB,
		ProbeQuickInterval:       5 * time.Minute,
		ProbeFullInterval:        60 * time.Minute,
		ProbeYieldMiBps:          0.2,
		ProbePassQuickFloorMiBps: 0.5,
		ProbePassFullFloorMiBps:  1.0,

		WGoodput: 0.35, WSuccess: 0.25, WStall: 0.15, WTTFB: 0.10, WReset: 0.15,
	}
}

// ProbeURLMissingError is returned by NewPolicy when ProbingEnabled is true
// but ProbeURL is empty. There is deliberately no third-party default (design
// §6.4); probing without a URL fails closed at construction.
func ProbeURLMissingError() error {
	return fmt.Errorf("intel: probe URL is required when probing is enabled (no third-party default)")
}

// NewPolicy creates a policy engine for the given carrier IDs (in the
// configured static-priority order) using an injected clock for
// determinism. Zero fields in cfg are sanitized to the documented starting
// values. It returns an error when probing is enabled without a URL.
func NewPolicy(now func() time.Time, cfg PolicyConfig, ids []CarrierID) (*Policy, error) {
	if now == nil {
		now = time.Now
	}
	cfg = sanitizePolicyConfig(cfg)
	if cfg.ProbingEnabled && cfg.ProbeURL == "" {
		return nil, ProbeURLMissingError()
	}
	p := &Policy{
		cfg:    cfg,
		now:    now,
		health: make(map[CarrierID]*CarrierHealth, len(ids)),
		wrr:    make(map[CarrierID]int),
		ids:    append([]CarrierID(nil), ids...),
	}
	for _, id := range p.ids {
		p.health[id] = &CarrierHealth{ID: id, State: stateCandidate}
	}
	return p, nil
}

// sanitizePolicyConfig fills zero/out-of-range fields with the documented
// starting values. It returns a copy; the caller's value is not mutated.
func sanitizePolicyConfig(c PolicyConfig) PolicyConfig {
	d := PolicyConfigDefaults()
	if c.Mode != PolicyStatic && c.Mode != PolicyAdaptive {
		c.Mode = d.Mode
	}
	if c.TopK <= 0 {
		c.TopK = d.TopK
	}
	if c.TTFBBaseline <= 0 {
		c.TTFBBaseline = d.TTFBBaseline
	}
	if c.SLAFloorMiBps <= 0 {
		c.SLAFloorMiBps = d.SLAFloorMiBps
	}
	if c.HardGateMinSuccess <= 0 || c.HardGateMinSuccess > 1 {
		c.HardGateMinSuccess = d.HardGateMinSuccess
	}
	if c.HardGateMaxStallRate < 0 {
		c.HardGateMaxStallRate = d.HardGateMaxStallRate
	}
	if c.HardGateZeroDeliver <= 0 {
		c.HardGateZeroDeliver = d.HardGateZeroDeliver
	}
	if c.FlapWindow <= 0 {
		c.FlapWindow = d.FlapWindow
	}
	if c.FlapLimit <= 0 {
		c.FlapLimit = d.FlapLimit
	}
	if c.ResetWindow <= 0 {
		c.ResetWindow = d.ResetWindow
	}
	if c.ResetLimit <= 0 {
		c.ResetLimit = d.ResetLimit
	}
	if c.AuthFailWindow <= 0 {
		c.AuthFailWindow = d.AuthFailWindow
	}
	if c.HysteresisMargin <= 0 {
		c.HysteresisMargin = d.HysteresisMargin
	}
	if c.HysteresisTicks <= 0 {
		c.HysteresisTicks = d.HysteresisTicks
	}
	if c.MinDwell <= 0 {
		c.MinDwell = d.MinDwell
	}
	if c.EvalInterval <= 0 {
		c.EvalInterval = d.EvalInterval
	}
	if c.InitialCooldown <= 0 {
		c.InitialCooldown = d.InitialCooldown
	}
	if c.MaxCooldown <= 0 {
		c.MaxCooldown = d.MaxCooldown
	}
	if c.ActiveHealthReset <= 0 {
		c.ActiveHealthReset = d.ActiveHealthReset
	}
	if c.AdmitScore <= 0 || c.AdmitScore > 1 {
		c.AdmitScore = d.AdmitScore
	}
	if c.AdmitPassesCand <= 0 {
		c.AdmitPassesCand = d.AdmitPassesCand
	}
	if c.AdmitPassesHalf <= 0 {
		c.AdmitPassesHalf = d.AdmitPassesHalf
	}
	if c.ProbeDailyBudgetBytes < 0 {
		c.ProbeDailyBudgetBytes = d.ProbeDailyBudgetBytes
	}
	if c.ProbeQuickBytes <= 0 {
		c.ProbeQuickBytes = d.ProbeQuickBytes
	}
	if c.ProbeFullBytes <= 0 {
		c.ProbeFullBytes = d.ProbeFullBytes
	}
	if c.ProbeQuickInterval <= 0 {
		c.ProbeQuickInterval = d.ProbeQuickInterval
	}
	if c.ProbeFullInterval <= 0 {
		c.ProbeFullInterval = d.ProbeFullInterval
	}
	if c.ProbePassQuickFloorMiBps <= 0 {
		c.ProbePassQuickFloorMiBps = d.ProbePassQuickFloorMiBps
	}
	if c.ProbePassFullFloorMiBps <= 0 {
		c.ProbePassFullFloorMiBps = d.ProbePassFullFloorMiBps
	}
	if c.ProbeYieldMiBps <= 0 {
		c.ProbeYieldMiBps = d.ProbeYieldMiBps
	}
	if c.WGoodput <= 0 {
		c.WGoodput = d.WGoodput
	}
	if c.WSuccess <= 0 {
		c.WSuccess = d.WSuccess
	}
	if c.WStall <= 0 {
		c.WStall = d.WStall
	}
	if c.WTTFB <= 0 {
		c.WTTFB = d.WTTFB
	}
	if c.WReset <= 0 {
		c.WReset = d.WReset
	}
	return c
}

// CarrierHealth is the per-carrier rolling measurement window plus lifecycle
// state (design §6.2, §6.5). All timestamps come from the injected clock so
// tests are deterministic. The struct is a value type; Policy copies it on
// read (Health) so callers hold a stable snapshot.
//
// Invariants:
//   - ConnectRTTLast is recorded but NEVER enters the score (weight 0,
//     design §6.1). It is diagnostic only.
//   - ProbeBytesToday is the running portion of the hard daily budget; once it
//     reaches the budget, probes are refused until the day rolls over.
type CarrierHealth struct {
	ID    CarrierID
	State carrierState

	// Passive rolling windows (design §6.2).
	GoodputEWMA     float64     // MiB/s, 60 s half-life
	goodputRing     [50]float64 // instantaneous MiB/s samples (G-term p10)
	goodputCursor   int
	goodputWrites   int64
	passiveLastAt   time.Time
	DeliveredBytes  int64 // cumulative delivered bytes (stall-rate denominator)
	LastDeliveredAt time.Time
	LastPendingAt   time.Time
	HasPending      bool

	SuccessRing   [50]bool
	SuccessCursor int
	SuccessWrites int // monotonic total stream-outcome writes
	SuccessOK     int // count of true among the written window

	StallCount    int64
	StallTotalDur time.Duration
	LastStallAt   time.Time

	TTFBRing   [50]time.Duration
	TTFBCursor int
	TTFBWrites int

	Resets          [64]time.Time
	ResetsCursor    int
	Flaps           [64]time.Time
	FlapsCursor     int
	AuthFails       [32]time.Time
	AuthFailsCursor int
	Rebinds         int64

	// Probe (design §6.4).
	ProbeGoodputEWMA   float64 // MiB/s, 10 min half-life
	probeLastAt        time.Time
	ProbeBytesToday    int64
	ProbeDayStamp      time.Time
	LastProbePassFull  time.Time
	LastProbePassQuick time.Time
	LastFullProbeAt    time.Time
	LastQuickProbeAt   time.Time
	ConsecProbeFails   int

	// Diagnostics only, weight 0 in the score (design §6.1).
	ConnectRTTLast time.Duration

	// Lifecycle (design §6.5).
	CooldownUntil   time.Time
	CooldownPeriod  time.Duration
	ExcludedSince   time.Time
	ExclusionStreak int
	ActiveSince     time.Time
	HalfOpenPasses  int
	CandidatePasses int
	LastScore       float64
	GateReason      string
}

// Policy is the deterministic Phase 3 policy engine. All public methods are
// safe for concurrent use. The internal health map is bounded to the IDs
// passed to NewPolicy (no open-ended cardinality).
type Policy struct {
	mu sync.Mutex

	cfg    PolicyConfig
	now    func() time.Time
	ids    []CarrierID
	health map[CarrierID]*CarrierHealth
	wrr    map[CarrierID]int
	// Hysteresis bookkeeping for the primary/standby ordering (design §6.5):
	// the incumbent and the challenger it is (or is not) losing to, plus how
	// many consecutive ticks the challenger has beaten it by the margin.
	incumbent       CarrierID
	challenger      CarrierID
	challengerTicks int
	lastSwitchAt    time.Time
	switchCount     int64 // monotonic switch counter (observable)
	// lastEval is when the most recent Evaluate ran.
	lastEval time.Time
}

// SanitizedConfig returns the effective (post-sanitize) configuration.
func (p *Policy) SanitizedConfig() PolicyConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg
}

// CarrierIDs returns the configured static-priority order.
func (p *Policy) CarrierIDs() []CarrierID {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]CarrierID, len(p.ids))
	copy(out, p.ids)
	return out
}

// Mode returns the policy's mode.
func (p *Policy) Mode() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.Mode
}

// Adaptive reports whether the policy is in adaptive mode. In static mode,
// PickForNewStream returns the first Active/ready carrier in static-priority
// order (Phase 2 behavior) and the scoring/hysteresis path is inert.
func (p *Policy) Adaptive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.Mode == PolicyAdaptive
}

// --- measurement inputs (called by the transport layer / node) ---------

// RecordPassiveBytes feeds a passive delivery sample into the carrier's
// goodput EWMA and the goodput sample ring (design §6.2: application bytes
// delivered, EWMA 60 s half-life; the G term additionally uses the p10 of
// recent instantaneous samples — user requirement "p10 goodput of recent
// transfers in MiB/s"). `bytes` is the number of application bytes delivered
// since the last call; `now` is the sample time from the injected clock. A
// positive delivery also clears the pending flag (H4: data is flowing).
func (p *Policy) RecordPassiveBytes(id CarrierID, bytes int64, now time.Time) {
	if bytes <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return
	}
	h.DeliveredBytes += bytes
	h.LastDeliveredAt = now
	h.HasPending = false
	// Instantaneous rate over the sample interval (MiB/s).
	const halflifeS = 60.0
	var instRate float64
	if !h.passiveLastAt.IsZero() {
		dt := now.Sub(h.passiveLastAt).Seconds()
		if dt > 0 {
			instRate = float64(bytes) / 1048576.0 / dt
		}
	}
	// Record the sample into the ring for the G-term p10.
	h.goodputRing[h.goodputCursor] = instRate
	h.goodputCursor = (h.goodputCursor + 1) % len(h.goodputRing)
	h.goodputWrites++
	// EWMA update.
	var alpha float64
	if !h.passiveLastAt.IsZero() {
		dt := now.Sub(h.passiveLastAt).Seconds()
		if dt <= 0 {
			dt = 1
		}
		alpha = 1.0 - math.Pow(0.5, dt/halflifeS)
		if alpha > 1 {
			alpha = 1
		}
	} else {
		alpha = 1.0 // first sample seeds the EWMA directly
	}
	h.GoodputEWMA = (1-alpha)*h.GoodputEWMA + alpha*instRate
	h.passiveLastAt = now
}

// RecordPending marks that pending bytes exist at `now` (drives the H4 gate).
func (p *Policy) RecordPending(id CarrierID, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return
	}
	h.HasPending = true
	h.LastPendingAt = now
}

// RecordStall records one stall event (>= 5 s of pending bytes with zero
// delivered), contributing to the stall count and the stall-rate gate.
func (p *Policy) RecordStall(id CarrierID, dur time.Duration, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return
	}
	h.StallCount++
	h.StallTotalDur += dur
	h.LastStallAt = now
}

// RecordStreamOutcome records a session outcome (success/failure) and its TTFB
// (stream open to first DATA byte consumed). It updates the Laplace-smoothed
// success ratio and the TTFB p50 ring (design §6.2).
//
// Passive-admission (user requirement 1): when active probing is disabled, a
// clean completion on a not-yet-admitted carrier counts as one admission
// "pass" for its current state. This is what makes passive-only operation
// (probes OFF — the default, and the R1 scenario where health must come from
// real transfers) functional: a carrier that is actually delivering clean
// streams proves itself usable without any probe. When probing is enabled the
// design's probe-pass rule governs admission, so passive outcomes are NOT
// double-counted as probe passes (only as the S/T rings they feed).
func (p *Policy) RecordStreamOutcome(id CarrierID, ok bool, ttfb time.Duration, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return
	}
	// Success ring with eviction accounting.
	if h.SuccessWrites >= len(h.SuccessRing) {
		if h.SuccessRing[h.SuccessCursor] {
			h.SuccessOK--
		}
	}
	h.SuccessRing[h.SuccessCursor] = ok
	if ok {
		h.SuccessOK++
	}
	h.SuccessWrites++
	h.SuccessCursor = (h.SuccessCursor + 1) % len(h.SuccessRing)
	// TTFB ring.
	h.TTFBRing[h.TTFBCursor] = ttfb
	h.TTFBCursor = (h.TTFBCursor + 1) % len(h.TTFBRing)
	h.TTFBWrites++
	// Passive admission evidence: a clean completion on a not-yet-admitted
	// carrier advances its pass counter, but only when probing is disabled
	// (probes otherwise own the admission decision, design §6.5).
	if ok && !p.cfg.ProbingEnabled {
		switch h.State {
		case stateCandidate:
			h.CandidatePasses++
		case stateHalfOpen:
			h.HalfOpenPasses++
		}
	}
}

// RecordReset records a carrier loss not caused by local shutdown (read
// error, liveness timeout, peer close with error). It feeds the R term and
// the H2 flap gate (design §6.2).
func (p *Policy) RecordReset(id CarrierID, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return
	}
	h.Resets[h.ResetsCursor] = now
	h.ResetsCursor = (h.ResetsCursor + 1) % len(h.Resets)
}

// RecordFlap records an Up→Down→Up transition within the flap window. The
// transport layer detects a flap as a loss followed by a ready install on the
// same CarrierID and calls this on each such pair.
func (p *Policy) RecordFlap(id CarrierID, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return
	}
	h.Flaps[h.FlapsCursor] = now
	h.FlapsCursor = (h.FlapsCursor + 1) % len(h.Flaps)
}

// RecordAuthFail records a failed carrier authentication (feeds H3).
func (p *Policy) RecordAuthFail(id CarrierID, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return
	}
	h.AuthFails[h.AuthFailsCursor] = now
	h.AuthFailsCursor = (h.AuthFailsCursor + 1) % len(h.AuthFails)
}

// RecordRebind records a rebind event onto this carrier (a stream moved here
// after a loss on another carrier).
func (p *Policy) RecordRebind(id CarrierID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return
	}
	h.Rebinds++
}

// RecordConnectRTT records the observed TCP connect time. It is kept for
// diagnostics and is given WEIGHT 0 in the score (design §6.1): it never
// influences selection (test S4 proves connect RTT alone cannot change the
// selected carrier).
func (p *Policy) RecordConnectRTT(id CarrierID, rtt time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return
	}
	h.ConnectRTTLast = rtt
}

// --- bounded active probing (design §6.4) --------------------------------

// CanProbe reports whether a probe of `bytes` may run for id under the daily
// byte budget. When ProbingEnabled is false it always reports false. When the
// budget is 0 the gate is disabled (all probes allowed). The budget is never
// exceeded: a probe is refused when it would push ProbeBytesToday above the
// cap (test S3).
func (p *Policy) CanProbe(id CarrierID, bytes int64, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil || !p.cfg.ProbingEnabled {
		return false
	}
	if p.cfg.ProbeDailyBudgetBytes > 0 {
		p.rollProbeDay(h, now)
		if h.ProbeBytesToday+bytes > p.cfg.ProbeDailyBudgetBytes {
			return false
		}
	}
	return true
}

// rollProbeDay resets the daily budget at the local-midnight boundary. The day
// stamp is the date of the last reset; deterministic under the injected clock.
func (p *Policy) rollProbeDay(h *CarrierHealth, now time.Time) {
	if h.ProbeDayStamp.IsZero() {
		h.ProbeDayStamp = now
		return
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	stamp := time.Date(h.ProbeDayStamp.Year(), h.ProbeDayStamp.Month(), h.ProbeDayStamp.Day(), 0, 0, 0, 0, h.ProbeDayStamp.Location())
	if today.After(stamp) {
		h.ProbeBytesToday = 0
		h.ProbeDayStamp = now
	}
}

// RecordProbe records the outcome of a bounded probe transfer. ok=true means
// the probe completed within its deadline and its measured goodput met the
// floor for its kind. The byte cost is charged against the daily budget.
// FULL probes advance admission progress (Candidate/HalfOpen); quick probes
// never decide readmission (design §6.5).
func (p *Policy) RecordProbe(id CarrierID, ok bool, goodputMiBps float64, bytes int64, now time.Time, full bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return
	}
	// The byte cost is charged against the daily budget ONLY for probe bytes
	// actually sent; a failed (timed-out) probe carries few or no bytes.
	if bytes > 0 && p.cfg.ProbingEnabled {
		p.rollProbeDay(h, now)
		h.ProbeBytesToday += bytes
	}
	if ok {
		// Probe goodput EWMA (10 min half-life), fixed 1 s nominal sample
		// interval for determinism.
		const halflifeS = 600.0
		alpha := 1.0 - math.Pow(0.5, 1.0/halflifeS)
		h.ProbeGoodputEWMA = (1-alpha)*h.ProbeGoodputEWMA + alpha*goodputMiBps
		h.ConsecProbeFails = 0
		if full {
			h.LastProbePassFull = now
			h.LastFullProbeAt = now
			if h.State == stateHalfOpen {
				h.HalfOpenPasses++
			} else if h.State == stateCandidate {
				h.CandidatePasses++
			}
		} else {
			h.LastProbePassQuick = now
			h.LastQuickProbeAt = now
			if h.State == stateCandidate {
				h.CandidatePasses++
			}
		}
	} else {
		h.ConsecProbeFails++
		h.HalfOpenPasses = 0
		h.CandidatePasses = 0
		if full {
			h.LastFullProbeAt = now
		} else {
			h.LastQuickProbeAt = now
		}
	}
}

// DueProbe reports whether a probe of the given kind is due for id at `now`
// under the documented cadence and yield rules (design §6.4):
//   - a FULL probe is due on each admission and every ProbeFullInterval;
//   - a QUICK probe is due every ProbeQuickInterval ONLY while passive
//     goodput is below ProbeYieldMiBps (an idle carrier); it is suspended
//     while the carrier carries real traffic above the yield threshold;
//   - neither kind is due when probing is disabled or the byte budget is
//     exhausted (CanProbe is the authoritative budget check; the caller must
//     still confirm before launching the transfer).
func (p *Policy) DueProbe(id CarrierID, now time.Time, full bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil || !p.cfg.ProbingEnabled {
		return false
	}
	if !p.CanProbe(id, 1, now) {
		return false
	}
	if full {
		// A full probe is also run once on each admission (the install path
		// calls RecordProbe with full=true); the interval rule is the
		// recurring one.
		interval := p.cfg.ProbeFullInterval
		anchor := h.LastFullProbeAt
		if anchor.IsZero() {
			return true // never probed: the on-admission probe is due
		}
		return now.Sub(anchor) >= interval
	}
	// Quick probe: idle carriers only (yield rule, design §6.4).
	if h.GoodputEWMA > p.cfg.ProbeYieldMiBps {
		return false
	}
	anchor := h.LastQuickProbeAt
	if anchor.IsZero() {
		return true
	}
	return now.Sub(anchor) >= p.cfg.ProbeQuickInterval
}

// ProbesAllowed reports whether ANY probe may run for id right now (probing
// enabled AND the budget not yet exhausted).
func (p *Policy) ProbesAllowed(id CarrierID, now time.Time) bool {
	return p.CanProbe(id, 1, now)
}

// ProbeBytesUsedToday returns the carrier's running daily probe-byte usage.
func (p *Policy) ProbeBytesUsedToday(id CarrierID) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h := p.health[id]; h != nil {
		return h.ProbeBytesToday
	}
	return 0
}

// --- scoring ------------------------------------------------------------

// ScoreComponents is the exposed, human-readable breakdown of a carrier's
// score (design §6.3). G/S/N/T/R are each in [0,1]; Total is the weighted
// sum.
type ScoreComponents struct {
	Goodput    float64
	Success    float64
	Stall      float64
	TTFB       float64
	Reset      float64
	Total      float64
	Neutral    []string // terms that fell back to a neutral/probe value
	Eligible   bool
	GateReason string
}

// Evaluate runs one policy tick for all configured carriers: computes each
// score, applies the hard gates, advances the lifecycle state machine, and
// (in adaptive mode only) updates the hysteresis bookkeeping. It is called by
// the transport layer on a 10 s timer and by tests with an injected clock.
// It is deterministic for a given (health, clock) input.
func (p *Policy) Evaluate(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, id := range p.ids {
		h := p.health[id]
		comp := p.scoreLocked(h, now)
		h.LastScore = comp.Total
		h.GateReason = ""
		if !comp.Eligible && comp.GateReason != "" {
			h.GateReason = comp.GateReason
		}
		p.advanceLifecycle(h, comp, now)
	}
	// The per-carrier health/lifecycle updates above run in BOTH modes:
	// admission, exclusion, and cooldown are properties of carrier health,
	// independent of the selection mode. What the mode controls is the
	// PRIMARY/STANDBY HYSTERESIS bookkeeping below — the thing that actually
	// moves the preferred carrier. In static mode (the Phase 2 rollback) the
	// hysteresis/switch path is a NO-OP: score ordering never changes
	// selection (requirement 6 "static policy disables adaptive switching").
	p.lastEval = now
	if p.cfg.Mode != PolicyAdaptive {
		return
	}

	// Adaptive: hard-gate exclusion of the incumbent is immediate; otherwise
	// a challenger must beat the incumbent by the margin for the required
	// consecutive ticks and the incumbent must have dwelled for MinDwell.
	eligible := p.eligibleActiveLocked(now)
	if len(eligible) == 0 {
		p.incumbent = ""
		p.challenger = ""
		p.challengerTicks = 0
		return
	}

	best := p.bestEligibleLocked(eligible)
	if p.incumbent == "" {
		// Initial admission establishes the incumbent and starts its dwell.
		p.incumbent = best
		p.lastSwitchAt = now
		p.challenger = ""
		p.challengerTicks = 0
		return
	}

	incumbentHealth := p.health[p.incumbent]
	incumbentEligible := incumbentHealth != nil && p.isEligibleSet(eligible, p.incumbent)
	if !incumbentEligible {
		// Gate failure bypasses hysteresis for failover (design §6.5/§7.3).
		p.incumbent = best
		p.lastSwitchAt = now
		p.switchCount++
		p.challenger = ""
		p.challengerTicks = 0
		return
	}
	if best == p.incumbent {
		p.challenger = ""
		p.challengerTicks = 0
		return
	}

	incScore := incumbentHealth.LastScore
	challengerScore := p.health[best].LastScore
	if challengerScore >= incScore+p.cfg.HysteresisMargin {
		if p.challenger == best {
			p.challengerTicks++
		} else {
			p.challenger = best
			p.challengerTicks = 1
		}
	} else {
		p.challenger = ""
		p.challengerTicks = 0
	}
	if p.challenger == best && p.challengerTicks >= p.cfg.HysteresisTicks &&
		!now.Before(p.lastSwitchAt.Add(p.cfg.MinDwell)) {
		p.incumbent = best
		p.lastSwitchAt = now
		p.switchCount++
		p.challenger = ""
		p.challengerTicks = 0
	}
}

// bestEligibleLocked returns the highest-scored eligible carrier, breaking
// ties by CarrierID lexical order. The incumbent is handled separately by
// Evaluate so score ordering remains deterministic and testable.
func (p *Policy) bestEligibleLocked(eligible []CarrierID) CarrierID {
	var best CarrierID
	bestScore := -1.0
	for _, id := range eligible {
		s := p.health[id].LastScore
		if best == "" || s > bestScore || (s == bestScore && id < best) {
			best = id
			bestScore = s
		}
	}
	return best
}

// advanceLifecycle moves one carrier's state machine (design §6.5) given its
// freshly computed score components. Caller holds p.mu.
func (p *Policy) advanceLifecycle(h *CarrierHealth, comp ScoreComponents, now time.Time) {
	switch h.State {
	case stateCandidate:
		if p.cfg.ProbingEnabled && h.ConsecProbeFails >= 2 {
			p.excludeLocked(h, now, "H1 probe")
		} else if h.CandidatePasses >= p.cfg.AdmitPassesCand && h.LastScore >= p.cfg.AdmitScore && !comp.gateExcluded() {
			h.State = stateActive
			h.ActiveSince = now
			h.CandidatePasses = 0
		} else if comp.gateExcluded() {
			p.excludeLocked(h, now, comp.GateReason)
		}
	case stateActive:
		switch {
		case p.flapCountLocked(h, now) >= p.cfg.FlapLimit:
			p.excludeLocked(h, now, "H2 flap")
		case p.authFailCountLocked(h, now) > 0:
			p.excludeLocked(h, now, "H3 auth")
		case h.HasPending && !h.LastDeliveredAt.IsZero() && now.Sub(h.LastDeliveredAt) >= p.cfg.HardGateZeroDeliver:
			p.excludeLocked(h, now, "H4 stall")
		case comp.gateExcluded():
			p.excludeLocked(h, now, comp.GateReason)
		default:
			// Healthy Active: reset the exclusion streak after the active-
			// health window (design §6.5).
			if now.Sub(h.ActiveSince) >= p.cfg.ActiveHealthReset {
				h.ExclusionStreak = 0
				h.CooldownPeriod = 0
			}
		}
	case stateExcluded:
		// Cooldown elapsed → HalfOpen.
		if !h.CooldownUntil.IsZero() && !now.Before(h.CooldownUntil) {
			h.State = stateHalfOpen
			h.ExcludedSince = time.Time{}
		}
	case stateHalfOpen:
		// A failed probe doubles the cooldown and re-excludes (design §6.5).
		if p.cfg.ProbingEnabled && h.ConsecProbeFails > 0 {
			p.excludeLocked(h, now, "half_open probe fail")
			break
		}
		if h.HalfOpenPasses >= p.cfg.AdmitPassesHalf {
			// Readmit to Active. The HalfOpen pass counter resets, but the
			// EXCLUSION STREAK is deliberately preserved (design §6.5: the
			// exponential cooldown doubling tracks consecutive exclusions and
			// is only forgiven after a sustained ActiveHealthReset window of
			// Active health — handled in the stateActive branch above). Reset
			//ting it here would make a flapping carrier always return to the
			// 30 s initial cooldown, defeating the exponential backoff.
			h.State = stateActive
			h.ActiveSince = now
			h.HalfOpenPasses = 0
		}
	}
}

// adoptStaticPrimary sets the incumbent to the first Active/ready carrier in
// static-priority order (Phase 2 behavior), ignoring score.
func (p *Policy) adoptStaticPrimary() {
	eligible := p.eligibleActiveLocked(p.lastEval)
	if len(eligible) == 0 {
		eligible = p.activeLocked()
	}
	if len(eligible) > 0 {
		p.incumbent = p.primaryOf(eligible)
	} else {
		p.incumbent = ""
	}
}

// eligibleActiveLocked returns the Active carriers that pass all hard gates,
// in static-priority order.
func (p *Policy) eligibleActiveLocked(now time.Time) []CarrierID {
	var out []CarrierID
	for _, id := range p.ids {
		h := p.health[id]
		if h.State != stateActive {
			continue
		}
		if p.scoreLocked(h, now).Eligible {
			out = append(out, id)
		}
	}
	return out
}

// activeLocked returns all Active-state carriers (gates ignored).
func (p *Policy) activeLocked() []CarrierID {
	var out []CarrierID
	for _, id := range p.ids {
		if p.health[id].State == stateActive {
			out = append(out, id)
		}
	}
	return out
}

// isEligibleSet reports whether id is in the (small) eligible slice.
func (p *Policy) isEligibleSet(eligible []CarrierID, id CarrierID) bool {
	for _, e := range eligible {
		if e == id {
			return true
		}
	}
	return false
}

// primaryOf returns the first carrier in static-priority order that is in the
// `candidates` set.
func (p *Policy) primaryOf(candidates []CarrierID) CarrierID {
	if len(candidates) == 0 {
		return ""
	}
	for _, id := range p.ids {
		for _, c := range candidates {
			if c == id {
				return id
			}
		}
	}
	return candidates[0]
}

// excludeLocked transitions the carrier to Excluded with the next cooldown.
// The cooldown doubles per consecutive exclusion, capped at MaxCooldown
// (design §6.5).
func (p *Policy) excludeLocked(h *CarrierHealth, now time.Time, reason string) {
	if h.State == stateExcluded {
		h.GateReason = reason
		return
	}
	h.State = stateExcluded
	h.ExcludedSince = now
	h.GateReason = reason
	h.ExclusionStreak++
	period := p.cfg.InitialCooldown
	for i := 1; i < h.ExclusionStreak; i++ {
		period *= 2
		if period > p.cfg.MaxCooldown {
			period = p.cfg.MaxCooldown
			break
		}
	}
	h.CooldownUntil = now.Add(period)
	h.CooldownPeriod = period
}

// scoreLocked computes the carrier's score components and eligibility (the
// pure function of a CarrierHealth at time now). Weights are the sanitized
// configured ones; below-minimum samples fall back to the probe value or the
// neutral 0.5 (design §6.3).
func (p *Policy) scoreLocked(h *CarrierHealth, now time.Time) ScoreComponents {
	var c ScoreComponents

	// G = min(1, p10_goodput_recent / SLA_floor). User requirement: use the
	// p10 of recent goodput samples (MiB/s) so a carrier that is mostly fast
	// with occasional slow samples still scores by its worst-case recent
	// sample (conservative for selection). When there are no passive samples
	// yet and a probe value exists, fall back to the probe goodput EWMA
	// (design §6.3). Otherwise G=0 (neutral for the missing-data case is
	// the EWMA/probe fallback, not the 0.5 neutral: goodput has a natural
	// floor of 0).
	p10 := p.goodputP10Locked(h)
	usedProbe := false
	if p10 <= 0 && h.ProbeGoodputEWMA > 0 {
		p10 = h.ProbeGoodputEWMA
		usedProbe = true
	}
	if usedProbe {
		c.Neutral = append(c.Neutral, "G(probe)")
	}
	c.Goodput = clamp01(p10 / p.cfg.SLAFloorMiBps)

	// S = (ok + 1) / (attempts + 2), Laplace-smoothed over the last 50.
	attempts := h.SuccessWrites
	if attempts > len(h.SuccessRing) {
		attempts = len(h.SuccessRing)
	}
	c.Success = float64(h.SuccessOK+1) / float64(attempts+2)
	if attempts < 10 {
		// Below the minimum sample count: neutral (design §6.3).
		c.Success = 0.5
		c.Neutral = append(c.Neutral, "S(neutral)")
	}

	// N = clamp(1 - stall_rate_per_100MiB / 4, 0, 1).
	stallRate := p.stallRatePer100MiB(h)
	c.Stall = clamp01(1.0 - stallRate/4.0)

	// T = clamp(1 - (ttfb_p50 / baseline - 1.5) / 2.5, 0, 1).
	ttfbP50 := p.ttfbP50Locked(h)
	if ttfbP50 > 0 && p.cfg.TTFBBaseline > 0 {
		ratio := ttfbP50.Seconds() / p.cfg.TTFBBaseline.Seconds()
		c.TTFB = clamp01(1.0 - (ratio-1.5)/2.5)
	} else {
		c.TTFB = 0.5
		c.Neutral = append(c.Neutral, "T(neutral)")
	}

	// R = 1 - min(1, resets_per_10min / ResetLimit).
	resets := p.resetCountLocked(h, now)
	c.Reset = 1.0 - math.Min(1.0, float64(resets)/float64(p.cfg.ResetLimit))

	c.Total = p.cfg.WGoodput*c.Goodput + p.cfg.WSuccess*c.Success +
		p.cfg.WStall*c.Stall + p.cfg.WTTFB*c.TTFB + p.cfg.WReset*c.Reset
	c.Total = clamp01(c.Total)

	// Hard gates (design §6.3 + user requirement). First matching reason
	// wins; a gate sets GateReason and clears Eligible.
	switch {
	case p.cfg.ProbingEnabled && h.ConsecProbeFails >= 2:
		c.GateReason = "H1 probe"
	case p.flapCountLocked(h, now) >= p.cfg.FlapLimit:
		c.GateReason = "H2 flap"
	case p.authFailCountLocked(h, now) > 0:
		c.GateReason = "H3 auth"
	case h.HasPending && !h.LastDeliveredAt.IsZero() && now.Sub(h.LastDeliveredAt) >= p.cfg.HardGateZeroDeliver:
		c.GateReason = "H4 stall"
	case c.Success < p.cfg.HardGateMinSuccess:
		c.GateReason = "success_ratio"
	case stallRate > p.cfg.HardGateMaxStallRate:
		c.GateReason = "stall_rate"
	}
	// A carrier that has not yet been admitted is not a new-stream
	// candidate; this is an informational gate (excluded from the eligible
	// set) rather than a hard-exclusion reason.
	if c.GateReason == "" && h.State != stateActive {
		c.GateReason = "not_active"
	}
	c.Eligible = c.GateReason == ""
	return c
}

// goodputP10Locked returns the 10th percentile of the recent passive goodput
// samples (design §6.2 G term; user requirement "p10 goodput of recent
// transfers in MiB/s"). With fewer than 10 samples the p10 is the minimum
// (conservative). Deterministic for a given ring.
func (p *Policy) goodputP10Locked(h *CarrierHealth) float64 {
	n := int(h.goodputWrites)
	if n > len(h.goodputRing) {
		n = len(h.goodputRing)
	}
	if n <= 0 {
		return 0
	}
	tmp := make([]float64, n)
	if n < len(h.goodputRing) {
		copy(tmp, h.goodputRing[:n])
	} else {
		copy(tmp, h.goodputRing[:])
	}
	sort.Float64s(tmp)
	// p10: the sample at index floor(0.10*n); for n<10 the index is 0 (min).
	idx := int(0.1 * float64(n))
	if idx >= n {
		idx = n - 1
	}
	if idx < 0 {
		idx = 0
	}
	return tmp[idx]
}

// gateExcluded reports whether the gate reason is a hard exclusion (not the
// informational "not_active").
func (c *ScoreComponents) gateExcluded() bool {
	switch c.GateReason {
	case "H1 probe", "H2 flap", "H3 auth", "H4 stall", "success_ratio", "stall_rate":
		return true
	}
	return false
}

// stallRatePer100MiB is the carrier's stall rate: stalls per 100 MiB
// delivered. With no delivered bytes the rate is 0 (stalls are only
// meaningful once data flows; H4 covers the zero-delivery case).
func (p *Policy) stallRatePer100MiB(h *CarrierHealth) float64 {
	if h.DeliveredBytes <= 0 {
		return 0
	}
	return float64(h.StallCount) * 100.0 * 1048576.0 / float64(h.DeliveredBytes)
}

// ttfbP50Locked returns the p50 TTFB over the written ring entries.
func (p *Policy) ttfbP50Locked(h *CarrierHealth) time.Duration {
	n := h.TTFBWrites
	if n > len(h.TTFBRing) {
		n = len(h.TTFBRing)
	}
	if n == 0 {
		return 0
	}
	tmp := make([]time.Duration, n)
	if n < len(h.TTFBRing) {
		// Not full: the written entries are slots 0..n-1 (cursor == writes).
		copy(tmp, h.TTFBRing[:n])
	} else {
		// Full: all slots are written; order is irrelevant for a p50.
		copy(tmp, h.TTFBRing[:])
	}
	sort.Slice(tmp, func(i, j int) bool { return tmp[i] < tmp[j] })
	return tmp[n/2]
}

// resetCountLocked counts resets within the reset window (the R term).
func (p *Policy) resetCountLocked(h *CarrierHealth, now time.Time) int {
	cutoff := now.Add(-p.cfg.ResetWindow)
	n := 0
	for _, ts := range h.Resets {
		if !ts.IsZero() && ts.After(cutoff) {
			n++
		}
	}
	return n
}

// flapCountLocked counts flaps within the flap window (the H2 gate).
func (p *Policy) flapCountLocked(h *CarrierHealth, now time.Time) int {
	cutoff := now.Add(-p.cfg.FlapWindow)
	n := 0
	for _, ts := range h.Flaps {
		if !ts.IsZero() && ts.After(cutoff) {
			n++
		}
	}
	return n
}

// authFailCountLocked counts auth failures within the auth-fail window (H3).
func (p *Policy) authFailCountLocked(h *CarrierHealth, now time.Time) int {
	cutoff := now.Add(-p.cfg.AuthFailWindow)
	n := 0
	for _, ts := range h.AuthFails {
		if !ts.IsZero() && ts.After(cutoff) {
			n++
		}
	}
	return n
}

// --- selection ----------------------------------------------------------

// PickForNewStream returns the next carrier for a NEW stream. It does NOT
// affect pinned streams (design §7.2).
//
//   - static mode: the first Active/ready carrier in static-priority order
//     (Phase 2 behavior).
//   - adaptive mode: a smooth weighted round-robin over the top-K Active
//     carriers that pass the gates, with weights round(100 * score^2). Given
//     the same metric snapshot and the same stream sequence the assignment is
//     identical (deterministic, testable).
//
// It returns "" when no carrier is eligible.
func (p *Policy) PickForNewStream(now time.Time) CarrierID {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cfg.Mode != PolicyAdaptive {
		// Static: first eligible Active in priority order; fall back to the
		// first Active even if gated so a transient gate cannot stall new
		// streams entirely.
		for _, id := range p.ids {
			h := p.health[id]
			if h.State != stateActive {
				continue
			}
			if p.scoreLocked(h, now).Eligible {
				return id
			}
		}
		for _, id := range p.ids {
			if p.health[id].State == stateActive {
				return id
			}
		}
		return ""
	}

	eligible := p.eligibleActiveLocked(now)
	if len(eligible) == 0 {
		return ""
	}
	k := p.cfg.TopK
	if k > len(eligible) {
		k = len(eligible)
	}
	// Rank by score descending; tie-break: the current incumbent first, then
	// lexical CarrierID. This keeps the hysteresis-stable primary preferred.
	ranked := make([]CarrierID, len(eligible))
	copy(ranked, eligible)
	sort.SliceStable(ranked, func(i, j int) bool {
		si := p.health[ranked[i]].LastScore
		sj := p.health[ranked[j]].LastScore
		if si != sj {
			return si > sj
		}
		if ranked[i] == p.incumbent {
			return true
		}
		if ranked[j] == p.incumbent {
			return false
		}
		return ranked[i] < ranked[j]
	})
	top := ranked
	if k < len(top) {
		top = top[:k]
	}
	return p.smoothWRR(top, now)
}

// smoothWRR runs one smooth weighted round-robin step over `top` and records
// the virtual-counter state in p.wrr. Weights are round(100*score^2). The
// classic SWRR algorithm: add each slot's weight to its virtual value, pick
// the highest, subtract the winner's value from the rest. Caller holds p.mu.
func (p *Policy) smoothWRR(top []CarrierID, now time.Time) CarrierID {
	type slot struct {
		id     CarrierID
		weight int
		virt   int
	}
	slots := make([]slot, len(top))
	total := 0
	for i, id := range top {
		s := p.health[id].LastScore
		w := int(math.Round(100.0 * s * s))
		if w < 0 {
			w = 0
		}
		slots[i] = slot{id: id, weight: w, virt: p.wrr[id]}
		total += w
	}
	if total == 0 {
		// No carrier has a positive weight (all scores 0): fall back to the
		// highest-priority eligible carrier in static order. Deterministic.
		return p.primaryOf(top)
	}
	maxV := -1
	maxIdx := 0
	for i := range slots {
		slots[i].virt += slots[i].weight
		if slots[i].virt > maxV {
			maxV = slots[i].virt
			maxIdx = i
		}
	}
	for i := range slots {
		if i != maxIdx {
			slots[i].virt -= slots[maxIdx].virt
		}
		p.wrr[slots[i].id] = slots[i].virt
	}
	return slots[maxIdx].id
}

// Incumbent returns the current primary carrier (the one hysteresis protects).
// In static mode it is the first Active in priority order.
func (p *Policy) Incumbent() CarrierID {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.incumbent
}

// CooldownRemaining reports how much longer a carrier's current cooldown
// lasts (0 when not in an active cooldown).
func (p *Policy) CooldownRemaining(id CarrierID, now time.Time) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil || h.State != stateExcluded || h.CooldownUntil.IsZero() {
		return 0
	}
	if rem := h.CooldownUntil.Sub(now); rem > 0 {
		return rem
	}
	return 0
}

// State returns the carrier's lifecycle state.
func (p *Policy) State(id CarrierID) carrierState {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h := p.health[id]; h != nil {
		return h.State
	}
	return stateCandidate
}

// LastGateReason returns the last hard-gate reason recorded for the carrier
// ("" when no gate fired on the last tick).
func (p *Policy) LastGateReason(id CarrierID) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h := p.health[id]; h != nil {
		return h.GateReason
	}
	return ""
}

// Score returns the carrier's last computed score.
func (p *Policy) Score(id CarrierID) float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h := p.health[id]; h != nil {
		return h.LastScore
	}
	return 0
}

// EvalInterval returns the documented policy tick interval for the transport
// layer's timer (design §6.5: 10 s default).
func (p *Policy) EvalInterval() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.EvalInterval
}

// SwitchCount returns the number of hysteresis-driven primary switches so far
// (observable for tests and the decision log).
func (p *Policy) SwitchCount() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.switchCount
}

// GoodputP10 returns the carrier's p10 of recent passive goodput samples in
// MiB/s (the G-term input, design §6.2). Deterministic for a given sample
// window.
func (p *Policy) GoodputP10(id CarrierID) float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h := p.health[id]; h != nil {
		return p.goodputP10Locked(h)
	}
	return 0
}

// SuccessRatio returns the carrier's Laplace-smoothed success ratio over the
// recent stream outcomes (the S-term input).
func (p *Policy) SuccessRatio(id CarrierID) float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return 0
	}
	attempts := h.SuccessWrites
	if attempts > len(h.SuccessRing) {
		attempts = len(h.SuccessRing)
	}
	return float64(h.SuccessOK+1) / float64(attempts+2)
}

// StallRatePer100MiB returns the carrier's stall rate (stalls per 100 MiB
// delivered) — the N-term input.
func (p *Policy) StallRatePer100MiB(id CarrierID) float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h := p.health[id]; h != nil {
		return p.stallRatePer100MiB(h)
	}
	return 0
}

// TTFBP50 returns the carrier's p50 time-to-first-byte.
func (p *Policy) TTFBP50(id CarrierID) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h := p.health[id]; h != nil {
		return p.ttfbP50Locked(h)
	}
	return 0
}

// ResetCount returns the carrier's reset count within the reset window (the
// R-term input).
func (p *Policy) ResetCount(id CarrierID, now time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h := p.health[id]; h != nil {
		return p.resetCountLocked(h, now)
	}
	return 0
}

// FlapCount returns the carrier's flap count within the flap window (the H2
// gate input).
func (p *Policy) FlapCount(id CarrierID, now time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h := p.health[id]; h != nil {
		return p.flapCountLocked(h, now)
	}
	return 0
}

// Health returns a copy of the carrier's current health snapshot for
// observability. It is safe to use after the lock is released.
func (p *Policy) Health(id CarrierID) *CarrierHealth {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.health[id]
	if h == nil {
		return nil
	}
	cp := *h
	return &cp
}

// --- observability (design §7.5) ---------------------------------------

// HealthSnapshot is the JSON-serializable per-node health surface for the
// future dashboard. It contains NO secrets: carrier IDs, states, scores,
// gate reasons, and cooldowns only.
type HealthSnapshot struct {
	Mode      string            `json:"mode"`
	Adaptive  bool              `json:"adaptive"`
	Carriers  []CarrierSnapshot `json:"carriers"`
	Incumbent string            `json:"incumbent,omitempty"`
	LastEval  time.Time         `json:"last_eval,omitempty"`
}

// CarrierSnapshot is one carrier's health, non-secret fields only.
type CarrierSnapshot struct {
	ID                   string  `json:"id"`
	State                string  `json:"state"`
	Score                float64 `json:"score"`
	GoodputMiBps         float64 `json:"goodput_mibps"`
	ProbeGoodputMiBps    float64 `json:"probe_goodput_mibps"`
	SuccessRatio         float64 `json:"success_ratio"`
	StallCount           int64   `json:"stall_count"`
	StallRatePer100MiB   float64 `json:"stall_rate_per_100_mib"`
	TTFBP50MS            int64   `json:"ttfb_p50_ms"`
	FlapCount            int     `json:"flap_count"`
	ResetCount           int     `json:"reset_count"`
	Rebinds              int64   `json:"rebinds"`
	ConnectRTTMS         int64   `json:"connect_rtt_ms"`
	GateReason           string  `json:"gate_reason,omitempty"`
	Eligible             bool    `json:"eligible"`
	CooldownRemainingSec int64   `json:"cooldown_remaining_sec"`
	ProbeBytesToday      int64   `json:"probe_bytes_today"`
	ProbeBudgetBytes     int64   `json:"probe_budget_bytes"`
	ProbeExhausted       bool    `json:"probe_exhausted"`
}

// HealthSnapshotNow produces the JSON health snapshot for the node's current
// health at `now`. It is safe to call from the dashboard goroutine.
func (p *Policy) HealthSnapshotNow(now time.Time) HealthSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()

	snap := HealthSnapshot{
		Mode:      p.cfg.Mode,
		Adaptive:  p.cfg.Mode == PolicyAdaptive,
		Incumbent: string(p.incumbent),
		LastEval:  p.lastEval,
	}
	for _, id := range p.ids {
		h := p.health[id]
		comp := p.scoreLocked(h, now)
		cs := CarrierSnapshot{
			ID:                 string(id),
			State:              h.State.String(),
			Score:              comp.Total,
			GoodputMiBps:       h.GoodputEWMA,
			ProbeGoodputMiBps:  h.ProbeGoodputEWMA,
			SuccessRatio:       comp.Success,
			StallCount:         h.StallCount,
			StallRatePer100MiB: p.stallRatePer100MiB(h),
			TTFBP50MS:          p.ttfbP50Locked(h).Milliseconds(),
			FlapCount:          p.flapCountLocked(h, now),
			ResetCount:         p.resetCountLocked(h, now),
			Rebinds:            h.Rebinds,
			ConnectRTTMS:       h.ConnectRTTLast.Milliseconds(),
			GateReason:         h.GateReason,
			Eligible:           comp.Eligible,
			ProbeBytesToday:    h.ProbeBytesToday,
			ProbeBudgetBytes:   p.cfg.ProbeDailyBudgetBytes,
			ProbeExhausted:     p.cfg.ProbingEnabled && p.cfg.ProbeDailyBudgetBytes > 0 && h.ProbeBytesToday >= p.cfg.ProbeDailyBudgetBytes,
		}
		if h.State == stateExcluded && !h.CooldownUntil.IsZero() {
			if rem := h.CooldownUntil.Sub(now); rem > 0 {
				cs.CooldownRemainingSec = int64(rem.Seconds())
			}
		}
		snap.Carriers = append(snap.Carriers, cs)
	}
	return snap
}

// SnapshotJSON produces the JSON encoding of the current health snapshot. It is
// the single function the future dashboard collector will call (design §7.5).
// No secret material is present in the struct fields.
func (p *Policy) SnapshotJSON(now time.Time) ([]byte, error) {
	return json.Marshal(p.HealthSnapshotNow(now))
}

// --- /metrics surface helpers (design §7.5) ------------------------------
//
// The /metrics surface must never expose a caller-controlled label value.
// These map the bounded, code-owned state and gate-reason strings to fixed
// integer ordinals so the per-carrier health gauges stay a closed, secret-
// free line set. The legends are recorded in the Phase 3 completion note.

// gateReasonOrdinal maps a CarrierSnapshot.GateReason to a fixed ordinal:
// 0 none, 1 H1 probe, 2 H2 flap, 3 H3 auth, 4 H4 stall, 5 success_ratio,
// 6 stall_rate, 7 not_active, 8 other.
func gateReasonOrdinal(reason string) int {
	switch reason {
	case "":
		return 0
	case "H1 probe":
		return 1
	case "H2 flap":
		return 2
	case "H3 auth":
		return 3
	case "H4 stall":
		return 4
	case "success_ratio":
		return 5
	case "stall_rate":
		return 6
	case "not_active":
		return 7
	default:
		return 8
	}
}

// stateOrdinal maps a CarrierSnapshot.State name to a fixed ordinal matching
// the carrierState iota order (0 candidate, 1 active, 2 excluded, 3 half_open).
func stateOrdinal(name string) int {
	switch name {
	case "candidate":
		return 0
	case "active":
		return 1
	case "excluded":
		return 2
	case "half_open":
		return 3
	default:
		return 4
	}
}

// EligibleMetric returns the snapshot's eligible flag as a 0/1 metric value.
func (cs CarrierSnapshot) EligibleMetric() int {
	if cs.Eligible {
		return 1
	}
	return 0
}

// --- helpers ------------------------------------------------------------

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
