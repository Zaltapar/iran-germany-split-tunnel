package dashboard

import (
	"math"
	"testing"
	"time"
)

func TestHistoryRingKeepsNewestInChronologicalOrder(t *testing.T) {
	h := NewHistory(4, 0)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		if !h.Record("srv.sessions", base.Add(time.Duration(i)*time.Second), float64(i)) {
			t.Fatalf("record %d refused", i)
		}
	}
	pts := h.Points("srv.sessions", 0)
	if len(pts) != 4 {
		t.Fatalf("retained %d points, want 4 (ring capacity)", len(pts))
	}
	for i, p := range pts {
		if want := float64(6 + i); p.V != want {
			t.Errorf("point %d = %v, want %v (oldest-first newest window)", i, p.V, want)
		}
	}
	if got := h.Len("srv.sessions"); got != 4 {
		t.Errorf("Len = %d, want 4", got)
	}
}

func TestHistoryPointsLimitReturnsNewest(t *testing.T) {
	h := NewHistory(8, 0)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 8; i++ {
		h.Record("srv.sessions", base.Add(time.Duration(i)*time.Second), float64(i))
	}
	pts := h.Points("srv.sessions", 2)
	if len(pts) != 2 || pts[0].V != 6 || pts[1].V != 7 {
		t.Fatalf("limit=2 gave %+v, want values [6 7]", pts)
	}
}

func TestHistorySameTimestampReplacesValue(t *testing.T) {
	h := NewHistory(4, 0)
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h.Record("srv.sessions", ts, 1)
	h.Record("srv.sessions", ts, 5)
	if h.Len("srv.sessions") != 1 {
		t.Fatalf("duplicate timestamp grew the series: Len=%d", h.Len("srv.sessions"))
	}
	if v := h.Points("srv.sessions", 0)[0].V; v != 5 {
		t.Errorf("value = %v, want 5 (replaced)", v)
	}
}

func TestHistoryRefusesInvalidInput(t *testing.T) {
	h := NewHistory(4, 0)
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		key  string
		t    time.Time
		v    float64
	}{
		{"malformed key", "bad key!", ts, 1},
		{"empty key", "", ts, 1},
		{"path-like key", "../etc", ts, 1},
		{"zero time", "srv.x", time.Time{}, 1},
		{"NaN", "srv.x", ts, math.NaN()},
		{"+Inf", "srv.x", ts, math.Inf(1)},
	}
	for _, c := range cases {
		if h.Record(c.key, c.t, c.v) {
			t.Errorf("%s: Record accepted, want refused", c.name)
		}
	}
	if len(h.Keys()) != 0 {
		t.Errorf("refused input created series: %v", h.Keys())
	}
}

func TestHistorySeriesCapIsBounded(t *testing.T) {
	h := NewHistory(4, 2)
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !h.Record("a.x", ts, 1) || !h.Record("b.x", ts, 1) {
		t.Fatal("first two series must be accepted")
	}
	if h.Record("c.x", ts, 1) {
		t.Error("third series accepted beyond the cap")
	}
	if !h.Record("a.x", ts.Add(time.Second), 2) {
		t.Error("existing series must keep accepting points at the cap")
	}
	if n := len(h.Keys()); n != 2 {
		t.Errorf("series count = %d, want 2", n)
	}
}

func TestHistoryCapacityClamped(t *testing.T) {
	if got := NewHistory(0, 0).Capacity(); got != DefaultHistoryPoints {
		t.Errorf("zero capacity -> %d, want default %d", got, DefaultHistoryPoints)
	}
	if got := NewHistory(MaxHistoryPoints+100, 0).Capacity(); got != MaxHistoryPoints {
		t.Errorf("oversized capacity -> %d, want %d", got, MaxHistoryPoints)
	}
}

func TestHistoryNilSafe(t *testing.T) {
	var h *History
	if h.Record("a.x", time.Now(), 1) {
		t.Error("nil History accepted a point")
	}
	if h.Points("a.x", 0) != nil || h.Keys() != nil || h.Has("a.x") || h.Len("a.x") != 0 {
		t.Error("nil History read methods must return zero values")
	}
}

func TestRecordSnapshotHistoryDerivesRatesAndCarrierSeries(t *testing.T) {
	h := NewHistory(16, 0)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(10 * time.Second)
	carrier := map[string]string{"carrier": "carrier-a"}

	first := &ServerSnapshot{
		ServerID: "iran", Status: Fresh, CollectedAt: t0,
		Metrics: &ParsedMetrics{CollectedAt: t0, Samples: []MetricSample{
			{Name: "total_bytes_up", Value: 0},
			{Name: "carrier_health_score", Labels: carrier, Value: 0.5},
		}},
	}
	recordSnapshotHistory(h, first, nil, time.Time{})

	second := &ServerSnapshot{
		ServerID: "iran", Status: Fresh, CollectedAt: t1,
		MemoryMB: 512, UptimeSec: 7200,
		Metrics: &ParsedMetrics{CollectedAt: t1, Samples: []MetricSample{
			{Name: "total_bytes_up", Value: 10 * histMiB},
			{Name: "carrier_health_score", Labels: carrier, Value: 0.8},
		}},
	}
	recordSnapshotHistory(h, second, first.Metrics.Samples, t0)

	if !h.Has("iran.carrier.carrier-a.score") || h.Len("iran.carrier.carrier-a.score") != 2 {
		t.Errorf("carrier score series not recorded per refresh: keys=%v", h.Keys())
	}
	if h.Len("iran.up_mibps") != 1 {
		t.Fatalf("up_mibps should exist only once a rate window exists; Len=%d", h.Len("iran.up_mibps"))
	}
	if v := h.Points("iran.up_mibps", 0)[0].V; math.Abs(v-1.0) > 1e-6 {
		t.Errorf("up_mibps = %v, want 1.0 (10 MiB over 10 s)", v)
	}
	if v := h.Points("iran.mem_used_mib", 0); len(v) != 1 || v[0].V != 512 {
		t.Errorf("mem_used_mib series = %+v, want one point of 512", v)
	}
	if v := h.Points("iran.uptime_hours", 0); len(v) != 1 || v[0].V != 2 {
		t.Errorf("uptime_hours series = %+v, want one point of 2", v)
	}
}
