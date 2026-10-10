package dashboard

// history.go — bounded, in-memory timeseries for the Dashboard v2 charts.
//
// One fixed-capacity ring buffer per series key. Points are appended on every
// collector refresh (see Cache.Refresh / RefreshServer). Memory is bounded by
// capacity × maxSeries; nothing is written to disk. When a ring is full the
// oldest point is overwritten. A new series key is refused (not evicted) once
// the series cap is reached, so an operator- or peer-influenced identifier can
// never grow memory without bound.

import (
	"math"
	"regexp"
	"sort"
	"sync"
	"time"
)

const (
	// DefaultHistoryPoints is the default retention per series. At the default
	// 10 s refresh this is one hour of history.
	DefaultHistoryPoints = 360
	// MaxHistoryPoints caps the configurable retention (about 12 h at 10 s).
	MaxHistoryPoints = 4320
	// maxHistorySeries bounds the number of distinct series keys.
	maxHistorySeries = 512

	histMiB = 1 << 20
	histGiB = 1 << 30
)

// seriesKeyPattern: server IDs and carrier IDs are embedded in series keys,
// so the key alphabet is closed. Anything else is rejected.
var seriesKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,120}$`)

// validSeriesKey reports whether k is an acceptable series key.
func validSeriesKey(k string) bool { return seriesKeyPattern.MatchString(k) }

// HistoryPoint is one timestamped sample.
type HistoryPoint struct {
	T time.Time `json:"t"`
	V float64   `json:"v"`
}

// seriesRing is a fixed-capacity circular buffer. buf grows to capacity and
// then wraps; next is the slot that will be overwritten once full. While the
// buffer is not yet full, next is always 0.
type seriesRing struct {
	buf  []HistoryPoint
	next int
}

// History is the bounded store of all series. It is safe for concurrent use.
type History struct {
	mu        sync.Mutex
	capacity  int
	maxSeries int
	series    map[string]*seriesRing
}

// NewHistory creates a store with the given per-series capacity and series
// cap. Zero or negative values take the documented defaults; capacity is
// clamped to MaxHistoryPoints.
func NewHistory(capacity, maxSeries int) *History {
	if capacity <= 0 {
		capacity = DefaultHistoryPoints
	}
	if capacity > MaxHistoryPoints {
		capacity = MaxHistoryPoints
	}
	if maxSeries <= 0 {
		maxSeries = maxHistorySeries
	}
	return &History{
		capacity:  capacity,
		maxSeries: maxSeries,
		series:    make(map[string]*seriesRing),
	}
}

// Capacity returns the per-series retention in points.
func (h *History) Capacity() int {
	if h == nil {
		return 0
	}
	return h.capacity
}

// Record appends one point to the series key. It returns false (and stores
// nothing) when the key is malformed, the value is NaN/Inf, the timestamp is
// zero, or the series cap would be exceeded by a new key. A point whose
// timestamp equals the newest stored point replaces that point's value, so
// repeated refreshes within the same clock tick do not duplicate samples.
func (h *History) Record(key string, t time.Time, v float64) bool {
	if h == nil || !validSeriesKey(key) || t.IsZero() || math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.series[key]
	if !ok {
		if len(h.series) >= h.maxSeries {
			return false
		}
		r = &seriesRing{buf: make([]HistoryPoint, 0, h.capacity)}
		h.series[key] = r
	}
	p := HistoryPoint{T: t, V: v}
	if len(r.buf) < h.capacity {
		if n := len(r.buf); n > 0 && r.buf[n-1].T.Equal(t) {
			r.buf[n-1].V = v
			return true
		}
		r.buf = append(r.buf, p)
		return true
	}
	last := (r.next - 1 + h.capacity) % h.capacity
	if r.buf[last].T.Equal(t) {
		r.buf[last].V = v
		return true
	}
	r.buf[r.next] = p
	r.next = (r.next + 1) % h.capacity
	return true
}

// Has reports whether a series with this key exists.
func (h *History) Has(key string) bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.series[key]
	return ok
}

// Len returns the number of retained points for key (0 when absent).
func (h *History) Len(key string) int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if r, ok := h.series[key]; ok {
		return len(r.buf)
	}
	return 0
}

// Points returns up to limit most-recent points in chronological order
// (limit <= 0 means all retained points). The result is a copy.
func (h *History) Points(key string, limit int) []HistoryPoint {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.series[key]
	if !ok {
		return nil
	}
	n := len(r.buf)
	ordered := make([]HistoryPoint, 0, n)
	if n < h.capacity {
		ordered = append(ordered, r.buf...)
	} else {
		ordered = append(ordered, r.buf[r.next:]...)
		ordered = append(ordered, r.buf[:r.next]...)
	}
	if limit > 0 && len(ordered) > limit {
		ordered = ordered[len(ordered)-limit:]
	}
	return ordered
}

// Keys returns all series keys in sorted order.
func (h *History) Keys() []string {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	keys := make([]string, 0, len(h.series))
	for k := range h.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// recordSnapshotHistory derives the chart series from one collected snapshot
// and appends one point per series. prev/prevAt are the previous cumulative
// metric samples and their collection time, used to turn counters into rates.
// Only aggregate, non-secret values are recorded; series names are fixed
// suffixes under the server ID (and carrier ID for carrier series).
func recordSnapshotHistory(h *History, snap *ServerSnapshot, prev []MetricSample, prevAt time.Time) {
	if h == nil || snap == nil || !validSeriesKey(snap.ServerID) || snap.CollectedAt.IsZero() {
		return
	}
	sid := snap.ServerID
	t := snap.CollectedAt

	if snap.Metrics != nil {
		cur := snap.Metrics.Samples
		window := snap.Metrics.CollectedAt.Sub(prevAt).Seconds()
		var rates map[string]Rate
		if len(prev) > 0 && !prevAt.IsZero() && window > 0 {
			rates = ComputeRates(prev, cur, window)
		}
		for _, sm := range cur {
			switch sm.Name {
			case "active_sessions":
				if len(sm.Labels) == 0 {
					h.Record(sid+".sessions", t, sm.Value)
				}
			case "carrier_loss_events":
				if len(sm.Labels) == 0 {
					h.Record(sid+".carrier_losses", t, sm.Value)
				}
			case "total_bytes_up", "total_bytes_down":
				if len(sm.Labels) != 0 {
					continue
				}
				if r, ok := rates[sampleKey(sm)]; ok {
					suffix := ".up_mibps"
					if sm.Name == "total_bytes_down" {
						suffix = ".down_mibps"
					}
					h.Record(sid+suffix, t, r.PerSec/histMiB)
				}
			case "carrier_health_score", "carrier_health_goodput_mibps", "carrier_health_success_ratio":
				cid := sm.Labels["carrier"]
				if cid == "" || !validSeriesKey(cid) {
					continue
				}
				suffix := ".score"
				switch sm.Name {
				case "carrier_health_goodput_mibps":
					suffix = ".goodput_mibps"
				case "carrier_health_success_ratio":
					suffix = ".success_ratio"
				}
				h.Record(sid+".carrier."+cid+suffix, t, sm.Value)
			}
		}
	}
	if snap.MemoryMB > 0 {
		h.Record(sid+".mem_used_mib", t, float64(snap.MemoryMB))
	}
	if snap.DiskBytes > 0 {
		h.Record(sid+".disk_used_gib", t, float64(snap.DiskBytes)/histGiB)
	}
	if snap.UptimeSec > 0 {
		h.Record(sid+".uptime_hours", t, snap.UptimeSec/3600)
	}
}
