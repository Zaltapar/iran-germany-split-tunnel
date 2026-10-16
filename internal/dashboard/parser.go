package dashboard

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseMetricsText parses the hand-rendered plain-text metric output produced
// by the splitter's /metrics endpoint. It handles both:
//   - "name value"
//   - `name{label="..."} value`
//
// Malformed lines are collected into errors but do not abort parsing.
func ParseMetricsText(text string) ([]MetricSample, []string) {
	var samples []MetricSample
	var errors []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sample, err := parseMetricLine(line)
		if err != nil {
			errors = append(errors, fmt.Sprintf("malformed metric line: %q: %v", line, err))
			continue
		}
		samples = append(samples, sample)
	}
	return samples, errors
}

func parseMetricLine(line string) (MetricSample, error) {
	var namePart, valuePart string
	if idx := strings.LastIndex(line, " "); idx >= 0 {
		namePart = line[:idx]
		valuePart = line[idx+1:]
	} else {
		return MetricSample{}, fmt.Errorf("no space separating name and value")
	}
	if namePart == "" {
		return MetricSample{}, fmt.Errorf("empty metric name")
	}
	val, err := strconv.ParseFloat(strings.TrimSpace(valuePart), 64)
	if err != nil {
		return MetricSample{}, fmt.Errorf("invalid value %q: %w", valuePart, err)
	}
	sample := MetricSample{Value: val}

	// Parse optional label section: name{key="val",key2="val2"}
	if end := strings.Index(namePart, "{"); end >= 0 {
		sample.Name = namePart[:end]
		labelPart := namePart[end+1:]
		if !strings.HasSuffix(labelPart, "}") {
			return MetricSample{}, fmt.Errorf("unterminated label block")
		}
		raw := labelPart[:len(labelPart)-1]
		if raw != "" {
			sample.Labels = parseLabels(raw)
			// A non-empty label block must yield at least one label; a bare
			// "name{garbage}" with no key="val" pair is malformed, so fail
			// closed rather than fabricating an empty-labeled series.
			if len(sample.Labels) == 0 {
				return MetricSample{}, fmt.Errorf("malformed label block: %q", raw)
			}
		}
	} else {
		sample.Name = namePart
	}
	if sample.Name == "" {
		return MetricSample{}, fmt.Errorf("empty metric name after label parse")
	}
	return sample, nil
}

// parseLabels parses a Prometheus-style label block: key="val",key2="val2".
func parseLabels(block string) map[string]string {
	labels := map[string]string{}
	for _, pair := range strings.Split(block, ",") {
		eq := strings.Index(pair, "=")
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(pair[:eq])
		v := strings.TrimSpace(pair[eq+1:])
		// Strip surrounding quotes.
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		labels[k] = v
	}
	return labels
}

// ComputeRates takes a previous and current sample set and returns computed
// per-second rates for known monotonic counters. Counter resets (current <
// previous) are detected and reported via Rate.Reset; the rate is set to 0.
func ComputeRates(prev, curr []MetricSample, windowSec float64) map[string]Rate {
	rates := map[string]Rate{}
	if windowSec <= 0 {
		return rates
	}
	prevBy := map[string]float64{}
	for _, s := range prev {
		key := sampleKey(s)
		prevBy[key] = s.Value
	}
	for _, s := range curr {
		key := sampleKey(s)
		// Only compute rates for names that look like counters or bytes.
		if !isCounterName(s.Name) {
			continue
		}
		p, ok := prevBy[key]
		if !ok {
			continue
		}
		delta := s.Value - p
		if delta < 0 {
			// Counter reset detected.
			rates[key] = Rate{PerSec: 0, Window: fmt.Sprintf("%gs", windowSec), Reset: true}
			continue
		}
		rates[key] = Rate{PerSec: delta / windowSec, Window: fmt.Sprintf("%gs", windowSec)}
	}
	return rates
}

// sampleKey returns a stable key for a sample including labels.
func sampleKey(s MetricSample) string {
	if len(s.Labels) == 0 {
		return s.Name
	}
	parts := make([]string, 0, len(s.Labels))
	// Sort labels for deterministic key.
	ks := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		ks = append(ks, k)
	}
	// Simple insertion sort (label count is small).
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	for _, k := range ks {
		parts = append(parts, k+"="+s.Labels[k])
	}
	return s.Name + "{" + strings.Join(parts, ",") + "}"
}

// isCounterName returns true for metric names that represent monotonic
// counters or cumulative byte totals for which a per-second rate is meaningful.
func isCounterName(name string) bool {
	switch name {
	case "total_bytes_up", "total_bytes_down",
		"carrier_loss_events", "carrier_reconnects",
		"target_dial_success", "target_dial_failure",
		"relay_credit_emitted_total", "relay_credit_dropped_total",
		"relay_credit_sent_bytes_total", "relay_credit_consumed_bytes_total",
		"relay_bytes_read", "relay_bytes_written",
		"session_close_reason", "close_reason":
		return true
	}
	if strings.HasSuffix(name, "_total") || strings.HasSuffix(name, "_events") {
		return true
	}
	return false
}
