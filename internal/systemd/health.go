// health.go — bounded health waits and read-only health checks
// (design §4.9 step 8, §4.10).
//
// WaitActive polls `systemctl is-active` every 250 ms in the CALLER's
// goroutine (no goroutines in this package) until:
//
//   - the state is EXACTLY "active" (first word) → success;
//   - the state is "failed" → immediate failure (a crash loop that
//     systemd parked is not retried here — that is bounded by
//     StartLimitBurst and observable by doctor, T7);
//   - the deadline expires → ErrWaitNotActive (wrapping the context
//     error). "activating (auto-restart)" — the state of a crash-looping
//     binary during RestartSec — is NOT success (HIGH-2).
package systemd

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// waitPollInterval is the is-active poll period. Reassigned ONLY by _test.go
// (shrunk to milliseconds) so the wait tests run deterministically with zero
// meaningful wall-clock sleep; production keeps the 250 ms period.
var waitPollInterval = 250 * time.Millisecond

// Health is the read-only health snapshot of one unit.
type Health struct {
	Unit      string `json:"unit"`
	Active    bool   `json:"active"`    // state == "active"
	State     string `json:"state"`     // active|activating|failed|inactive|unknown
	MetricsOK bool   `json:"metricsOk"` // true when probed and HTTP 200 (false when not probed or failed)
	Probed    bool   `json:"probed"`    // the metrics endpoint was probed
	Error     string `json:"error,omitempty"`
}

// WaitActive blocks until unit is exactly "active", "failed" (immediate),
// or the deadline/ctx fires. Bounded: at most timeout/pollInterval polls.
// It NEVER starts, restarts or otherwise mutates the unit.
func (m *ServiceManager) WaitActive(ctx context.Context, unit string, timeout time.Duration) error {
	if err := contextCheck(ctx); err != nil {
		return err
	}
	if err := checkUnitName(unit); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		state, err := m.State(ctx, unit)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrUnitState, err)
		}
		switch state {
		case "active":
			return nil
		case "failed":
			return fmt.Errorf("%w: unit %s is failed", ErrUnitState, unit)
		}
		if time.Now().After(deadline) {
			if cerr := ctx.Err(); cerr != nil {
				return fmt.Errorf("%w: %s (last state: %s)", ErrWaitNotActive, unit, cerr)
			}
			return fmt.Errorf("%w: %s (last state: %s)", ErrWaitNotActive, unit, state)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %s (last state: %s)", ErrWaitNotActive, unit, ctx.Err())
		case <-time.After(waitPollInterval):
		}
	}
}

// HealthCheck is a PURE read-only snapshot: is-active + (optionally) an
// HTTP 200 probe of the metrics endpoint. It never starts or restarts
// anything (doctor semantics — T7 reuses this). metricsPort <= 0 skips the
// probe (Probed=false, MetricsOK=false).
func HealthCheck(ctx context.Context, m *ServiceManager, unit string, metricsPort int) (Health, error) {
	if err := contextCheck(ctx); err != nil {
		return Health{}, err
	}
	if err := checkUnitName(unit); err != nil {
		return Health{}, err
	}
	h := Health{Unit: unit}
	state, err := m.State(ctx, unit)
	if err != nil {
		return h, err
	}
	h.State = state
	h.Active = state == "active"
	if metricsPort > 0 {
		h.Probed = true
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		url := "http://127.0.0.1:" + strconv.Itoa(metricsPort) + "/metrics"
		req, rerr := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
		if rerr != nil {
			h.Error = "metrics: " + rerr.Error()
			return h, nil
		}
		resp, perr := http.DefaultClient.Do(req)
		if perr != nil {
			h.Error = "metrics: " + perr.Error()
			return h, nil
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			h.MetricsOK = true
		} else {
			h.Error = "metrics: HTTP " + strconv.Itoa(resp.StatusCode)
		}
	}
	return h, nil
}
