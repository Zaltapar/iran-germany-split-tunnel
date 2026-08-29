package node

import (
	"fmt"
	"strings"
	"sync"
)

// Metrics is the per-node metrics set. The counters are plain cumulative
// totals; the /metrics handler renders them as text (same style as the
// pre-Phase-5 per-binary metrics).
type Metrics struct {
	mu sync.Mutex

	activeSessions int64
	totalSessions  int64
	bytesUp        int64
	bytesDown      int64
	errs           int64

	// Phase 5 carrier-reconnect counters
	carrierLossEvents     int64
	carrierReconnects     int64
	carrierRebinds        int64
	carrierRebindFailures int64
	sessionsRecovered     int64
	sessionsLostAfterCarF int64
}

// NewMetrics creates a zeroed metrics set.
func NewMetrics() *Metrics { return &Metrics{} }

// SessionStarted counts a new session (active +1, total +1).
func (m *Metrics) SessionStarted() {
	m.mu.Lock()
	m.activeSessions++
	m.totalSessions++
	m.mu.Unlock()
}

// SessionEnded un-counts a closed session.
func (m *Metrics) SessionEnded() {
	m.mu.Lock()
	m.activeSessions--
	m.mu.Unlock()
}

// AddUp adds upload bytes (client → target direction).
func (m *Metrics) AddUp(n int64) {
	m.mu.Lock()
	m.bytesUp += n
	m.mu.Unlock()
}

// AddDown adds download bytes (target → client direction).
func (m *Metrics) AddDown(n int64) {
	m.mu.Lock()
	m.bytesDown += n
	m.mu.Unlock()
}

// Error counts an error event.
func (m *Metrics) Error() {
	m.mu.Lock()
	m.errs++
	m.mu.Unlock()
}

// CarrierLossEvent counts a carrier death.
func (m *Metrics) CarrierLossEvent() {
	m.mu.Lock()
	m.carrierLossEvents++
	m.mu.Unlock()
}

// CarrierReconnect counts a carrier (re)establishment after a loss.
func (m *Metrics) CarrierReconnect() {
	m.mu.Lock()
	m.carrierReconnects++
	m.mu.Unlock()
}

// Rebind counts a successful session re-attach to a replacement carrier.
func (m *Metrics) Rebind() {
	m.mu.Lock()
	m.carrierRebinds++
	m.mu.Unlock()
}

// RebindFailure counts a failed or refused rebind.
func (m *Metrics) RebindFailure() {
	m.mu.Lock()
	m.carrierRebindFailures++
	m.mu.Unlock()
}

// SessionRecovered counts a session that survived a carrier loss.
func (m *Metrics) SessionRecovered() {
	m.mu.Lock()
	m.sessionsRecovered++
	m.mu.Unlock()
}

// SessionLostAfterFailure counts a session closed by grace timeout.
func (m *Metrics) SessionLostAfterFailure() {
	m.mu.Lock()
	m.sessionsLostAfterCarF++
	m.mu.Unlock()
}

// Snapshot is a point-in-time copy of all counters.
type Snapshot struct {
	ActiveSessions        int64
	TotalSessions         int64
	TotalBytesUp          int64
	TotalBytesDown        int64
	Errors                int64
	CarrierLossEvents     int64
	CarrierReconnects     int64
	CarrierRebinds        int64
	CarrierRebindFailures int64
	SessionsRecovered     int64
	SessionsLostAfterCarF int64
}

func (m *Metrics) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{
		ActiveSessions:        m.activeSessions,
		TotalSessions:         m.totalSessions,
		TotalBytesUp:          m.bytesUp,
		TotalBytesDown:        m.bytesDown,
		Errors:                m.errs,
		CarrierLossEvents:     m.carrierLossEvents,
		CarrierReconnects:     m.carrierReconnects,
		CarrierRebinds:        m.carrierRebinds,
		CarrierRebindFailures: m.carrierRebindFailures,
		SessionsRecovered:     m.sessionsRecovered,
		SessionsLostAfterCarF: m.sessionsLostAfterCarF,
	}
}

// Render is the /metrics body.
func (m *Metrics) Render() string {
	s := m.Snapshot()
	var b strings.Builder
	fmt.Fprintf(&b, "active_sessions %d\n", s.ActiveSessions)
	fmt.Fprintf(&b, "total_sessions %d\n", s.TotalSessions)
	fmt.Fprintf(&b, "total_bytes_up %d\n", s.TotalBytesUp)
	fmt.Fprintf(&b, "total_bytes_down %d\n", s.TotalBytesDown)
	fmt.Fprintf(&b, "errors %d\n", s.Errors)
	fmt.Fprintf(&b, "carrier_loss_events %d\n", s.CarrierLossEvents)
	fmt.Fprintf(&b, "carrier_reconnects %d\n", s.CarrierReconnects)
	fmt.Fprintf(&b, "carrier_rebinds %d\n", s.CarrierRebinds)
	fmt.Fprintf(&b, "carrier_rebind_failures %d\n", s.CarrierRebindFailures)
	fmt.Fprintf(&b, "sessions_recovered %d\n", s.SessionsRecovered)
	fmt.Fprintf(&b, "sessions_lost_after_carrier_failure %d\n", s.SessionsLostAfterCarF)
	return b.String()
}
