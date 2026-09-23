package node

import (
	"context"
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

func telemetrySession(reason string) *session.Session {
	var id session.SessionID
	s := session.NewSession(id, nil, nil, nil, context.Background())
	s.Activate()
	s.Close(reason)
	return s
}

func TestCloseReasonClassification(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		want   CloseReason
	}{
		{"client eof", "client EOF", ReasonClientEOF},
		{"target eof", "target EOF", ReasonTargetEOF},
		{"carrier", "carrier stream registration failed", ReasonCarrier},
		{"reattach", "session reattach failed", ReasonCarrier},
		{"grace", "carrier grace expired", ReasonCarrier},
		{"peer", "up stream closed by peer", ReasonCarrier},
		{"timeout", "download carrier timeout", ReasonTimeout},
		{"did not finish", "target did not finish after client EOF", ReasonTimeout},
		{"other", "activation failed", ReasonOther},
		{"empty", "", ReasonOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := closeReasonClass(telemetrySession(tc.reason)); got != tc.want {
				t.Fatalf("closeReasonClass(%q) = %d, want %d", tc.reason, got, tc.want)
			}
		})
	}
}

func TestCloseReasonCarriesOverflowFirst(t *testing.T) {
	s := telemetrySession("target EOF")
	s.Stats.MarkTerminated()
	if got := closeReasonClass(s); got != ReasonOverflow {
		t.Fatalf("terminated target EOF class = %d, want overflow", got)
	}
}

func TestSessionClosedCountedExactlyOnce(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m.SessionClosed(CloseReason(i % 9))
		}(i)
	}
	wg.Wait()
	s := m.Snapshot()
	total := s.CloseReasonClientEOF + s.CloseReasonTargetEOF + s.CloseReasonCarrier +
		s.CloseReasonOverflow + s.CloseReasonTimeout + s.CloseReasonOther
	if total != 50 {
		t.Fatalf("close reason total = %d, want 50 for direct fixed-enum calls", total)
	}

	// The node teardown hook is registered once and Session's lifecycle makes
	// concurrent Close calls execute that hook exactly once.
	n := NewNode(Config{Role: RoleIran}, log.New(io.Discard, "", 0), nil)
	var id session.SessionID
	sess := session.NewSession(id, nil, nil, nil, n.Context())
	sess.OnClose(func() { n.onSessionClosed(sess) })
	sess.Activate()
	wg = sync.WaitGroup{}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess.Close("activation failed")
		}()
	}
	wg.Wait()
	ns := n.Metrics().Snapshot()
	closeTotal := ns.CloseReasonClientEOF + ns.CloseReasonTargetEOF + ns.CloseReasonCarrier +
		ns.CloseReasonOverflow + ns.CloseReasonTimeout + ns.CloseReasonOther
	if closeTotal != 1 {
		t.Fatalf("node close reason total = %d, want 1", closeTotal)
	}
}

func TestMetricsRenderNoSecrets(t *testing.T) {
	m := NewMetrics()
	m.SessionStarted()
	m.SessionFirstByteSeen()
	m.TargetDialSuccess()
	m.AddRelayBytesRead(123)
	m.AddRelayBytesWritten(456)
	m.SessionClosed(ReasonClientEOF)
	out := m.Render()
	assertRenderPrivacy(t, out)
	if got := strings.Count(out, "session_close_reason{"); got != 6 {
		t.Fatalf("close reason lines = %d, want 6", got)
	}
}

func assertRenderPrivacy(t *testing.T, out string) {
	t.Helper()
	plain := regexp.MustCompile(`^[a-z0-9_]+\s+[0-9]+(\.[0-9]+)?$`)
	labelled := regexp.MustCompile(`^session_close_reason\{reason="(client_eof|target_eof|carrier|overflow|timeout|other)"\}\s+[0-9]+$`)
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		if !plain.MatchString(line) && !labelled.MatchString(line) {
			t.Fatalf("metrics line violates fixed privacy form: %q", line)
		}
	}
	for _, forbidden := range []string{":", "/", "0x"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("metrics output contains forbidden %q: %q", forbidden, out)
		}
	}
	if regexp.MustCompile(`[0-9a-fA-F]{16,}`).MatchString(out) {
		t.Fatalf("metrics output contains a long hex run: %q", out)
	}
}

func TestFirstByteCountedOnce(t *testing.T) {
	m := NewMetrics()
	s := &session.Session{}
	var wg sync.WaitGroup
	var winners int
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Stats.MarkFirstByte() {
				mu.Lock()
				winners++
				mu.Unlock()
				m.SessionFirstByteSeen()
			}
		}()
	}
	wg.Wait()
	if winners != 1 || m.Snapshot().SessionsFirstByteSeen != 1 {
		t.Fatalf("first-byte CAS winners=%d metric=%d, want 1/1", winners, m.Snapshot().SessionsFirstByteSeen)
	}
}

func TestTargetDialCounters(t *testing.T) {
	m := NewMetrics()
	m.TargetDialSuccess()
	m.TargetDialFailure()
	s := m.Snapshot()
	if s.TargetDialSuccess != 1 || s.TargetDialFailure != 1 {
		t.Fatalf("dial counters = success %d failure %d, want 1/1", s.TargetDialSuccess, s.TargetDialFailure)
	}
	if strings.Contains(m.Render(), "example.com") || strings.Contains(m.Render(), "443") {
		t.Fatal("dial address appeared in metrics")
	}
}

func TestMetricsRenderConcurrent(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.AddRelayBytesRead(1)
				m.RelayPendingHigh(int64(j))
				_ = m.Render()
			}
		}()
	}
	wg.Wait()
	assertRenderPrivacy(t, m.Render())
}
