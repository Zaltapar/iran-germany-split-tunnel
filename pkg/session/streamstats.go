package session

import (
	"sync/atomic"
	"time"
)

// SessionStats contains the small, fixed set of atomic lifecycle flags used
// by node telemetry. It carries no identifiers, payload data, or peer values.
type SessionStats struct {
	FirstByte      atomic.Bool
	CleanHalfClose atomic.Bool
	Terminated     atomic.Bool
	// DataUndeliverable records that a stream was terminated by the
	// deliver-or-fail policy (an in-order DATA frame could not be queued for
	// a live stream). It is set by a carrier callback, distinct from
	// Terminated (sustained overflow), and is checked before it so a
	// data-gap close is never mislabelled as overflow.
	DataUndeliverable atomic.Bool
	// OpenNanos is the time.Now().UnixNano() stamp at session creation (the
	// stream-open instant), stamped once in NewSession. It is a
	// diagnostic/telemetry input for the Phase 3 TTFB metric (stream open to
	// first DATA byte consumed); it is not secret and carries no peer data.
	OpenNanos int64
	// FirstByteNanos is the time.Now().UnixNano() at which the session's
	// first payload byte was consumed (0 when no byte was ever seen), set
	// exactly once alongside MarkFirstByte.
	FirstByteNanos int64
}

// MarkFirstByte transitions FirstByte exactly once and reports whether this
// call won the transition.
func (s *SessionStats) MarkFirstByte() bool {
	if s == nil {
		return false
	}
	return s.FirstByte.CompareAndSwap(false, true)
}

// MarkCleanHalfClose records a clean peer half-close idempotently.
func (s *SessionStats) MarkCleanHalfClose() {
	if s != nil {
		s.CleanHalfClose.Store(true)
	}
}

// MarkFirstByteNanos records the first-byte instant (UnixNano) exactly once,
// so a stream's time-to-first-byte is measurable (Phase 3 TTFB metric). The
// first byte has already been marked by MarkFirstByte; this only stamps the
// clock. Safe to call concurrently (atomic).
func (s *SessionStats) MarkFirstByteNanos(nanos int64) {
	if s == nil {
		return
	}
	for {
		old := atomic.LoadInt64(&s.FirstByteNanos)
		if old != 0 {
			return // already stamped
		}
		if atomic.CompareAndSwapInt64(&s.FirstByteNanos, 0, nanos) {
			return
		}
	}
}

// TTFB is the time-to-first-byte (stream open to first DATA byte consumed),
// or 0 when no byte was seen or the open instant was not stamped. It is a
// read-only diagnostic/telemetry value (Phase 3).
func (s *SessionStats) TTFB() time.Duration {
	if s == nil {
		return 0
	}
	open := atomic.LoadInt64(&s.OpenNanos)
	first := atomic.LoadInt64(&s.FirstByteNanos)
	if open <= 0 || first <= 0 || first < open {
		return 0
	}
	return time.Duration(first - open)
}

// MarkTerminated records carrier overflow termination without touching the
// session's mutex-protected close reason.
func (s *SessionStats) MarkTerminated() {
	if s != nil {
		s.Terminated.Store(true)
	}
}

// MarkDataUndeliverable records a deliver-or-fail termination (an in-order
// DATA frame was undeliverable to this stream). Like MarkTerminated it only
// touches an atomic flag, never the session's reason string, so it is safe
// from a carrier callback.
func (s *SessionStats) MarkDataUndeliverable() {
	if s != nil {
		s.DataUndeliverable.Store(true)
	}
}
