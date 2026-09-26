package session

import "sync/atomic"

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
