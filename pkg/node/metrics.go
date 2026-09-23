package node

import (
	"fmt"
	"strings"
	"sync"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// CloseReason is the fixed, code-owned close-reason enum. Callers cannot
// supply a metric label string; unknown values are normalized to other.
type CloseReason uint8

const (
	ReasonOther CloseReason = iota
	ReasonClientEOF
	ReasonTargetEOF
	ReasonCarrier
	ReasonOverflow
	ReasonTimeout
)

var closeReasonNames = [...]string{
	ReasonOther: "other", ReasonClientEOF: "client_eof", ReasonTargetEOF: "target_eof",
	ReasonCarrier: "carrier", ReasonOverflow: "overflow", ReasonTimeout: "timeout",
}

// closeReasonClass maps the session's fixed, code-owned reason strings and
// atomic termination flag to one of exactly six classes. The order is
// intentional: overflow wins over a later target EOF, then timeout wins over
// carrier wording, followed by carrier, EOF classes, and other.
func closeReasonClass(s *session.Session) CloseReason {
	if s == nil {
		return ReasonOther
	}
	if s.Stats.Terminated.Load() {
		return ReasonOverflow
	}
	reason := s.Reason()
	if strings.Contains(reason, "overflow") {
		return ReasonOverflow
	}
	if strings.Contains(reason, "timeout") || strings.Contains(reason, "did not finish") {
		return ReasonTimeout
	}
	if strings.Contains(reason, "carrier") ||
		strings.Contains(reason, "reattach") ||
		strings.Contains(reason, "grace") ||
		strings.Contains(reason, "stream registration failed") ||
		strings.Contains(reason, "up-carrier header write failed") ||
		strings.Contains(reason, "closed by peer") {
		return ReasonCarrier
	}
	if strings.Contains(reason, "client EOF") || strings.Contains(reason, "client socket EOF") {
		return ReasonClientEOF
	}
	if strings.Contains(reason, "target EOF") || strings.Contains(reason, "target socket EOF") {
		return ReasonTargetEOF
	}
	return ReasonOther
}

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

	// Phase 5 carrier-reconnect counters. Rebind refusal counters are fixed
	// reason buckets: they are bounded, non-secret, and do not retain IDs.
	carrierLossEvents         int64
	carrierReconnects         int64
	carrierRebinds            int64
	carrierRebindFailures     int64
	rebindUnknownPeer         int64
	rebindStaleGeneration     int64
	rebindOtherRefusal        int64
	sessionsRecovered         int64
	sessionsLostAfterCarF     int64
	graceTimeoutTerminalClose int64

	// Issue #6: aggregate session-buffer budget. sessionBufferReclaimed
	// counts bytes returned to (or force-reclaimed by) the budget — a
	// health signal: steady growth with a flat gauge means normal
	// flush/discard churn; a jump at Node.Close means shutdown
	// reclamation.
	sessionBufferReclaimed int64

	// Session lifecycle and target-dial outcomes.
	sessionFirstByteSeen  int64
	sessionClosedPreFirst int64
	sessionMidTransfer    int64
	sessionCleanComplete  int64
	targetDialOK          int64
	targetDialFail        int64

	// Shape-A relay accounting and bounded-buffer observations.
	relayBytesRead       int64
	relayBytesWritten    int64
	relayPendingHigh     int64
	relayBufferHighBytes int64
	relayWriteFail       int64
	relayBufferFull      int64
	relaySocketReadErr   int64
	relaySocketWriteErr  int64

	// Fixed six-class close-reason accounting.
	closeReasonClientEOF int64
	closeReasonTargetEOF int64
	closeReasonCarrier   int64
	closeReasonOverflow  int64
	closeReasonTimeout   int64
	closeReasonOther     int64
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

// RebindFailure counts a failed or refused rebind without retaining a reason.
func (m *Metrics) RebindFailure() {
	m.RebindRefusal("other")
}

// RebindRefusal counts a bounded, non-secret rebind refusal reason.
// Unknown/missing peer incarnation is intentionally one fixed bucket: the
// metrics surface never exposes session IDs or peer-provided values.
func (m *Metrics) RebindRefusal(reason string) {
	m.mu.Lock()
	m.carrierRebindFailures++
	switch reason {
	case "unknown_peer":
		m.rebindUnknownPeer++
	case "stale_generation":
		m.rebindStaleGeneration++
	default:
		m.rebindOtherRefusal++
	}
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
	m.graceTimeoutTerminalClose++
	m.mu.Unlock()
}

// AddSessionBufferReclaimed adds bytes reclaimed from the aggregate
// session-buffer budget (flushed, discarded, or force-reclaimed at
// Node.Close).
func (m *Metrics) AddSessionBufferReclaimed(n int64) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	m.sessionBufferReclaimed += n
	m.mu.Unlock()
}

// SessionFirstByteSeen counts a session that observed its first payload byte.
func (m *Metrics) SessionFirstByteSeen() {
	m.mu.Lock()
	m.sessionFirstByteSeen++
	m.mu.Unlock()
}

// SessionClosedBeforeFirstByte counts a session closed before payload flowed.
func (m *Metrics) SessionClosedBeforeFirstByte() {
	m.mu.Lock()
	m.sessionClosedPreFirst++
	m.mu.Unlock()
}

// SessionMidTransfer counts a session that saw payload and ended uncleanly.
func (m *Metrics) SessionMidTransfer() {
	m.mu.Lock()
	m.sessionMidTransfer++
	m.mu.Unlock()
}

// SessionCleanComplete counts a session that completed both half-closes
// without a carrier, timeout, or overflow termination.
func (m *Metrics) SessionCleanComplete() {
	m.mu.Lock()
	m.sessionCleanComplete++
	m.mu.Unlock()
}

// TargetDialSuccess counts a target dial that returned a connection.
func (m *Metrics) TargetDialSuccess() {
	m.mu.Lock()
	m.targetDialOK++
	m.mu.Unlock()
}

// TargetDialFailure counts a target dial failure without retaining its error
// or destination address.
func (m *Metrics) TargetDialFailure() {
	m.mu.Lock()
	m.targetDialFail++
	m.mu.Unlock()
}

// AddRelayBytesRead adds shape-A socket-read bytes.
func (m *Metrics) AddRelayBytesRead(n int64) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	m.relayBytesRead += n
	m.mu.Unlock()
}

// AddRelayBytesWritten adds bytes successfully written to a carrier.
func (m *Metrics) AddRelayBytesWritten(n int64) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	m.relayBytesWritten += n
	m.mu.Unlock()
}

func (m *Metrics) RelayPendingHigh(n int64) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	if n > m.relayPendingHigh {
		m.relayPendingHigh = n
	}
	m.mu.Unlock()
}

func (m *Metrics) RelayBufferHigh(n int64) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	if n > m.relayBufferHighBytes {
		m.relayBufferHighBytes = n
	}
	m.mu.Unlock()
}

func (m *Metrics) RelayWriteFailure() {
	m.mu.Lock()
	m.relayWriteFail++
	m.mu.Unlock()
}

func (m *Metrics) RelayBufferFull() {
	m.mu.Lock()
	m.relayBufferFull++
	m.mu.Unlock()
}

func (m *Metrics) RelaySocketReadError() {
	m.mu.Lock()
	m.relaySocketReadErr++
	m.mu.Unlock()
}

func (m *Metrics) RelaySocketWriteError() {
	m.mu.Lock()
	m.relaySocketWriteErr++
	m.mu.Unlock()
}

// SessionClosed records exactly one fixed close-reason class. Values outside
// the enum are deliberately collapsed into other.
func (m *Metrics) SessionClosed(r CloseReason) {
	if r < ReasonClientEOF || r > ReasonTimeout {
		r = ReasonOther
	}
	m.mu.Lock()
	switch r {
	case ReasonClientEOF:
		m.closeReasonClientEOF++
	case ReasonTargetEOF:
		m.closeReasonTargetEOF++
	case ReasonCarrier:
		m.closeReasonCarrier++
	case ReasonOverflow:
		m.closeReasonOverflow++
	case ReasonTimeout:
		m.closeReasonTimeout++
	default:
		m.closeReasonOther++
	}
	m.mu.Unlock()
}

// Snapshot is a point-in-time copy of all counters.
type Snapshot struct {
	ActiveSessions            int64
	TotalSessions             int64
	TotalBytesUp              int64
	TotalBytesDown            int64
	Errors                    int64
	CarrierLossEvents         int64
	CarrierReconnects         int64
	CarrierRebinds            int64
	CarrierRebindFailures     int64
	RebindUnknownPeer         int64
	RebindStaleGeneration     int64
	RebindOtherRefusal        int64
	SessionsRecovered         int64
	SessionsLostAfterCarF     int64
	GraceTimeoutTerminalClose int64
	SessionBufferReclaimed    int64

	SessionsFirstByteSeen         int64
	SessionsClosedBeforeFirstByte int64
	SessionsMidTransfer           int64
	SessionsCleanComplete         int64
	TargetDialSuccess             int64
	TargetDialFailure             int64
	RelayBytesRead                int64
	RelayBytesWritten             int64
	RelayPendingHighBytes         int64
	RelayBufferHighBytes          int64
	RelayWriteFailures            int64
	RelayBufferFull               int64
	RelaySocketReadErrors         int64
	RelaySocketWriteErrors        int64
	CloseReasonClientEOF          int64
	CloseReasonTargetEOF          int64
	CloseReasonCarrier            int64
	CloseReasonOverflow           int64
	CloseReasonTimeout            int64
	CloseReasonOther              int64
}

func (m *Metrics) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{
		ActiveSessions:                m.activeSessions,
		TotalSessions:                 m.totalSessions,
		TotalBytesUp:                  m.bytesUp,
		TotalBytesDown:                m.bytesDown,
		Errors:                        m.errs,
		CarrierLossEvents:             m.carrierLossEvents,
		CarrierReconnects:             m.carrierReconnects,
		CarrierRebinds:                m.carrierRebinds,
		CarrierRebindFailures:         m.carrierRebindFailures,
		RebindUnknownPeer:             m.rebindUnknownPeer,
		RebindStaleGeneration:         m.rebindStaleGeneration,
		RebindOtherRefusal:            m.rebindOtherRefusal,
		SessionsRecovered:             m.sessionsRecovered,
		SessionsLostAfterCarF:         m.sessionsLostAfterCarF,
		GraceTimeoutTerminalClose:     m.graceTimeoutTerminalClose,
		SessionBufferReclaimed:        m.sessionBufferReclaimed,
		SessionsFirstByteSeen:         m.sessionFirstByteSeen,
		SessionsClosedBeforeFirstByte: m.sessionClosedPreFirst,
		SessionsMidTransfer:           m.sessionMidTransfer,
		SessionsCleanComplete:         m.sessionCleanComplete,
		TargetDialSuccess:             m.targetDialOK,
		TargetDialFailure:             m.targetDialFail,
		RelayBytesRead:                m.relayBytesRead,
		RelayBytesWritten:             m.relayBytesWritten,
		RelayPendingHighBytes:         m.relayPendingHigh,
		RelayBufferHighBytes:          m.relayBufferHighBytes,
		RelayWriteFailures:            m.relayWriteFail,
		RelayBufferFull:               m.relayBufferFull,
		RelaySocketReadErrors:         m.relaySocketReadErr,
		RelaySocketWriteErrors:        m.relaySocketWriteErr,
		CloseReasonClientEOF:          m.closeReasonClientEOF,
		CloseReasonTargetEOF:          m.closeReasonTargetEOF,
		CloseReasonCarrier:            m.closeReasonCarrier,
		CloseReasonOverflow:           m.closeReasonOverflow,
		CloseReasonTimeout:            m.closeReasonTimeout,
		CloseReasonOther:              m.closeReasonOther,
	}
}

// Render is the /metrics body. It is intentionally a hand-written line list:
// no map or user-controlled value can add a metric series or leak a secret.
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
	fmt.Fprintf(&b, "carrier_rebind_unknown_peer %d\n", s.RebindUnknownPeer)
	fmt.Fprintf(&b, "carrier_rebind_stale_generation %d\n", s.RebindStaleGeneration)
	fmt.Fprintf(&b, "carrier_rebind_other_refusal %d\n", s.RebindOtherRefusal)
	fmt.Fprintf(&b, "sessions_recovered %d\n", s.SessionsRecovered)
	fmt.Fprintf(&b, "carrier_grace_timeout_terminal_close %d\n", s.GraceTimeoutTerminalClose)
	fmt.Fprintf(&b, "sessions_lost_after_carrier_failure %d\n", s.SessionsLostAfterCarF)
	fmt.Fprintf(&b, "session_buffer_reclaimed %d\n", s.SessionBufferReclaimed)

	fmt.Fprintf(&b, "sessions_first_byte_seen %d\n", s.SessionsFirstByteSeen)
	fmt.Fprintf(&b, "sessions_closed_before_first_byte %d\n", s.SessionsClosedBeforeFirstByte)
	fmt.Fprintf(&b, "sessions_mid_transfer %d\n", s.SessionsMidTransfer)
	fmt.Fprintf(&b, "sessions_clean_complete %d\n", s.SessionsCleanComplete)
	fmt.Fprintf(&b, "target_dial_success %d\n", s.TargetDialSuccess)
	fmt.Fprintf(&b, "target_dial_failure %d\n", s.TargetDialFailure)
	fmt.Fprintf(&b, "relay_bytes_read %d\n", s.RelayBytesRead)
	fmt.Fprintf(&b, "relay_bytes_written %d\n", s.RelayBytesWritten)
	fmt.Fprintf(&b, "relay_pending_high_bytes %d\n", s.RelayPendingHighBytes)
	fmt.Fprintf(&b, "relay_buffer_high_bytes %d\n", s.RelayBufferHighBytes)
	fmt.Fprintf(&b, "relay_write_failures %d\n", s.RelayWriteFailures)
	fmt.Fprintf(&b, "relay_buffer_full %d\n", s.RelayBufferFull)
	fmt.Fprintf(&b, "relay_socket_read_errors %d\n", s.RelaySocketReadErrors)
	fmt.Fprintf(&b, "relay_socket_write_errors %d\n", s.RelaySocketWriteErrors)
	fmt.Fprintf(&b, "session_close_reason{reason=\"client_eof\"} %d\n", s.CloseReasonClientEOF)
	fmt.Fprintf(&b, "session_close_reason{reason=\"target_eof\"} %d\n", s.CloseReasonTargetEOF)
	fmt.Fprintf(&b, "session_close_reason{reason=\"carrier\"} %d\n", s.CloseReasonCarrier)
	fmt.Fprintf(&b, "session_close_reason{reason=\"overflow\"} %d\n", s.CloseReasonOverflow)
	fmt.Fprintf(&b, "session_close_reason{reason=\"timeout\"} %d\n", s.CloseReasonTimeout)
	fmt.Fprintf(&b, "session_close_reason{reason=\"other\"} %d\n", s.CloseReasonOther)
	return b.String()
}
