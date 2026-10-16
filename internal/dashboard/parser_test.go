package dashboard

import (
	"math"
	"testing"
)

func TestParseMetricsTextSimpleNames(t *testing.T) {
	input := "active_sessions 12\ntotal_sessions 500\ntotal_bytes_up 99999999\n"
	samples, errs := ParseMetricsText(input)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(samples) != 3 {
		t.Fatalf("expected 3 samples, got %d", len(samples))
	}
	want := map[string]float64{
		"active_sessions": 12,
		"total_sessions":  500,
		"total_bytes_up":  99999999,
	}
	for _, s := range samples {
		if s.Labels != nil {
			t.Errorf("sample %q has unexpected labels: %v", s.Name, s.Labels)
		}
		got, ok := want[s.Name]
		if !ok {
			t.Errorf("unexpected sample name %q", s.Name)
			continue
		}
		if math.Abs(s.Value-got) > 1e-9 {
			t.Errorf("sample %q: value = %f, want %f", s.Name, s.Value, got)
		}
	}
}

func TestParseMetricsTextWithLabels(t *testing.T) {
	input := "session_close_reason{reason=\"client_eof\"} 42\nsession_close_reason{reason=\"carrier\"} 7\n"
	samples, errs := ParseMetricsText(input)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(samples))
	}
	for _, s := range samples {
		if s.Name != "session_close_reason" {
			t.Errorf("expected name session_close_reason, got %q", s.Name)
		}
		reason, ok := s.Labels["reason"]
		if !ok {
			t.Errorf("sample %q: missing 'reason' label", s.Name)
			continue
		}
		if reason != "client_eof" && reason != "carrier" {
			t.Errorf("unexpected reason label: %q", reason)
		}
	}
}

func TestParseMetricsTextMultiLabel(t *testing.T) {
	input := "metric{a=\"1\",b=\"2\"} 100\n"
	samples, _ := ParseMetricsText(input)
	if len(samples) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(samples))
	}
	s := samples[0]
	if s.Name != "metric" {
		t.Errorf("name = %q, want metric", s.Name)
	}
	if s.Labels["a"] != "1" || s.Labels["b"] != "2" {
		t.Errorf("labels = %v, want {a:1 b:2}", s.Labels)
	}
}

func TestParseMetricsTextMalformed(t *testing.T) {
	// Various malformed lines: no value, no name, bad float, empty label block.
	input := "no_value_at_all\n  \nbad_metric abc\nmetric{unterminated} 5\n"
	samples, errs := ParseMetricsText(input)
	// "no_value_at_all" is a single word with no space → parse error.
	// "bad_metric abc" → abc is not a valid float → parse error.
	// "metric{unterminated} 5" → missing closing brace → parse error.
	// Empty/whitespace lines are skipped silently.
	if len(samples) != 0 {
		t.Errorf("expected 0 valid samples, got %d: %v", len(samples), samples)
	}
	if len(errs) == 0 {
		t.Error("expected parse errors for malformed lines, got none")
	}
}

func TestParseMetricsTextRealMetrics(t *testing.T) {
	// Exact output shape from pkg/node/metrics.go Render().
	input := `active_sessions 5
total_sessions 120
total_bytes_up 1000000
total_bytes_down 2000000
carrier_loss_events 3
carrier_reconnects 4
target_dial_success 100
target_dial_failure 2
relay_bytes_read 1000000
relay_bytes_written 2000000
session_close_reason{reason="client_eof"} 50
session_close_reason{reason="data_undeliverable"} 1
relay_credit_emitted_total 50000
`
	samples, errs := ParseMetricsText(input)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(samples) != 13 {
		t.Fatalf("expected 13 samples, got %d", len(samples))
	}
	// Verify the close_reason samples carry the right labels.
	foundUndeliverable := false
	for _, s := range samples {
		if s.Name == "session_close_reason" && s.Labels["reason"] == "data_undeliverable" {
			foundUndeliverable = true
			if s.Value != 1 {
				t.Errorf("data_undeliverable value = %f, want 1", s.Value)
			}
		}
	}
	if !foundUndeliverable {
		t.Error("data_undeliverable close-reason sample not found")
	}
}

// --- ComputeRates tests ---

func TestComputeRatesNormal(t *testing.T) {
	prev := []MetricSample{
		{Name: "total_bytes_up", Value: 1_000_000},
		{Name: "total_bytes_down", Value: 500_000},
	}
	curr := []MetricSample{
		{Name: "total_bytes_up", Value: 2_000_000},
		{Name: "total_bytes_down", Value: 700_000},
	}
	rates := ComputeRates(prev, curr, 10.0) // 10-second window
	if r, ok := rates["total_bytes_up"]; !ok {
		t.Fatal("total_bytes_up rate missing")
	} else if math.Abs(r.PerSec-100_000) > 1 { // 1e6 / 10s
		t.Errorf("total_bytes_up rate = %f, want 100000", r.PerSec)
	}
	if r, ok := rates["total_bytes_down"]; !ok {
		t.Fatal("total_bytes_down rate missing")
	} else if math.Abs(r.PerSec-20_000) > 1 { // 200000 / 10s
		t.Errorf("total_bytes_down rate = %f, want 20000", r.PerSec)
	}
}

func TestComputeRatesCounterReset(t *testing.T) {
	// A counter reset (curr < prev) must be detected and produce rate 0 with Reset=true.
	prev := []MetricSample{
		{Name: "total_bytes_up", Value: 9_000_000},
	}
	curr := []MetricSample{
		{Name: "total_bytes_up", Value: 1_000}, // reset
	}
	rates := ComputeRates(prev, curr, 10.0)
	r, ok := rates["total_bytes_up"]
	if !ok {
		t.Fatal("rate for total_bytes_up missing")
	}
	if !r.Reset {
		t.Error("counter reset not flagged")
	}
	if r.PerSec != 0 {
		t.Errorf("rate after reset = %f, want 0", r.PerSec)
	}
}

func TestComputeRatesWithLabels(t *testing.T) {
	prev := []MetricSample{
		{Name: "session_close_reason", Labels: map[string]string{"reason": "carrier"}, Value: 10},
	}
	curr := []MetricSample{
		{Name: "session_close_reason", Labels: map[string]string{"reason": "carrier"}, Value: 20},
	}
	rates := ComputeRates(prev, curr, 5.0)
	key := sampleKey(curr[0])
	if r, ok := rates[key]; !ok {
		t.Fatalf("labeled rate missing for key %q", key)
	} else if math.Abs(r.PerSec-2.0) > 1e-9 { // 10 / 5s
		t.Errorf("labeled rate = %f, want 2.0", r.PerSec)
	}
}

func TestComputeRatesEmptyWindow(t *testing.T) {
	prev := []MetricSample{{Name: "total_bytes_up", Value: 0}}
	curr := []MetricSample{{Name: "total_bytes_up", Value: 100}}
	rates := ComputeRates(prev, curr, 0) // zero window
	if len(rates) != 0 {
		t.Errorf("expected no rates for zero window, got %v", rates)
	}
}

func TestSampleKeyDeterminism(t *testing.T) {
	s := MetricSample{
		Name:   "metric",
		Labels: map[string]string{"b": "2", "a": "1"},
	}
	s2 := MetricSample{
		Name:   "metric",
		Labels: map[string]string{"a": "1", "b": "2"},
	}
	if sampleKey(s) != sampleKey(s2) {
		t.Error("sampleKey is not deterministic for the same labels in different insertion order")
	}
}
