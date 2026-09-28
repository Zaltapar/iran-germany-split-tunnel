package node

import (
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// TestConsumerStallBeyondOverflowWaitCleansAbortsWithDataUndeliverable is
// the classifier + metrics half of the clean-abort end-to-end pin (the
// carrier-side half with the same name lives in pkg/mux
// consumer_stall_test.go). It proves that a stream aborted by the
// deliver-or-fail DATA path is classified and rendered as
// data_undeliverable — the real node wiring, exactly as
// telemetry_test.go exercises it (OnStreamDataUndeliverable marks the
// session's DataUndeliverable flag; the close hook then runs
// closeReasonClass and credits the fixed metric):
//   - closeReasonClass yields ReasonDataUndeliverable (checked BEFORE
//     the generic overflow class, even when the Terminated flag is
//     latched too — the same precedence telemetry_test pins), and
//   - the metrics Render contains exactly one
//     session_close_reason{reason="data_undeliverable"} credit.
func TestConsumerStallBeyondOverflowWaitCleansAbortsWithDataUndeliverable(t *testing.T) {
	var id session.SessionID
	s := session.NewSession(id, nil, nil, nil, nil)
	s.Activate()

	// What the node wiring does when the carrier's
	// OnStreamDataUndeliverable fires on a DATA-aborted stream (node.go):
	// mark the session's flag — the close reason string is set later, by
	// the session-close hook, not by the callback.
	s.Stats.MarkDataUndeliverable()
	// A clean-abort of a stalled stream also latches the generic
	// Terminated flag (the overflow classifier's input). The data-gap
	// class must win regardless — that is the ordering bug this taxonomy
	// guards against (a silent byte hole mislabelled as overflow).
	s.Stats.MarkTerminated()
	s.Close("target EOF")
	s.SetDataUndeliverableReason() // the node close hook's real call

	if got := closeReasonClass(s); got != ReasonDataUndeliverable {
		t.Fatalf("closeReasonClass = %d, want ReasonDataUndeliverable", got)
	}

	// Exactly one close-credit on the data_undeliverable bucket — the same
	// fixed-enum call the node close hook makes.
	m := NewMetrics()
	m.SessionClosed(closeReasonClass(s))
	snap := m.Snapshot()
	if snap.CloseReasonDataUndeliverable != 1 {
		t.Fatalf("CloseReasonDataUndeliverable = %d, want exactly 1", snap.CloseReasonDataUndeliverable)
	}
	if snap.CloseReasonOverflow != 0 {
		t.Fatalf("CloseReasonOverflow = %d, want 0 (the data-gap close must not leak into overflow)", snap.CloseReasonOverflow)
	}
	out := m.Render()
	assertRenderPrivacy(t, out)
	if n := strings.Count(out, "session_close_reason{reason=\"data_undeliverable\"}"); n != 1 {
		t.Fatalf("data_undeliverable close-reason lines = %d, want exactly one", n)
	}
	if !strings.Contains(out, "session_close_reason{reason=\"data_undeliverable\"} 1") {
		t.Fatalf("Render lacks a single data_undeliverable credit:\n%s", out)
	}
}
