package session

import "sync/atomic"

// SessionStats contains the small, fixed set of atomic lifecycle flags used
// by node telemetry. It carries no identifiers, payload data, or peer values.
type SessionStats struct {
	FirstByte      atomic.Bool
	CleanHalfClose atomic.Bool
	Terminated     atomic.Bool
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
