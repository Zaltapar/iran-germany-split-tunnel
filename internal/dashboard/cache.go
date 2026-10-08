package dashboard

import (
	"context"
	"sync"
	"time"
)

// Cache holds the most recent snapshot per server with a timestamp, plus
// the previous metrics sample set for rate computation. It is safe for
// concurrent use.
type Cache struct {
	mu          sync.RWMutex
	cfg         *DashboardConfig
	coll        map[string]Collector // serverID → Collector
	snapshots   map[string]*ServerSnapshot
	prevMetrics map[string][]MetricSample
	prevTime    map[string]time.Time
	nowFn       func() time.Time
}

// NewCache creates a Cache for the given config.
func NewCache(cfg *DashboardConfig) *Cache {
	c := &Cache{
		cfg:         cfg,
		coll:        make(map[string]Collector, len(cfg.Servers)),
		snapshots:   make(map[string]*ServerSnapshot, len(cfg.Servers)),
		prevMetrics: make(map[string][]MetricSample),
		prevTime:    make(map[string]time.Time),
		nowFn:       time.Now,
	}
	for _, s := range cfg.Servers {
		c.coll[s.ID] = NewCollector(s.SourceType)
	}
	return c
}

// SetNowFn overrides the clock (for tests).
func (c *Cache) SetNowFn(f func() time.Time) { c.nowFn = f }

// ServerIDs returns the configured server IDs.
func (c *Cache) ServerIDs() []string {
	ids := make([]string, 0, len(c.cfg.Servers))
	for _, s := range c.cfg.Servers {
		ids = append(ids, s.ID)
	}
	return ids
}

// Snapshot returns the current cached snapshot for a server.
// If the cache is empty or stale beyond 2× the refresh interval, the status
// is downgraded to Stale.
func (c *Cache) Snapshot(serverID string) (*ServerSnapshot, error) {
	c.mu.RLock()
	snap, ok := c.snapshots[serverID]
	c.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	if snap.Status == Fresh {
		elapsed := c.nowFn().Sub(snap.CollectedAt)
		maxFresh := time.Duration(c.cfg.RefreshSec) * 2 * time.Second
		if elapsed > maxFresh {
			// Return a copy with Stale status.
			s2 := *snap
			s2.Status = Stale
			return &s2, nil
		}
	}
	return snap, nil
}

// Refresh collects fresh snapshots for all servers. Previous metrics are
// retained for rate computation.
func (c *Cache) Refresh(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, s := range c.cfg.Servers {
		coll := c.coll[s.ID]
		if coll == nil {
			continue
		}
		snap, err := coll.Collect(ctx, s)
		if err != nil && snap == nil {
			// Total collection failure: store an unreachable snapshot.
			snap = &ServerSnapshot{
				ServerID:    s.ID,
				Status:      Unreachable,
				CollectedAt: c.nowFn(),
				Errors:      []string{err.Error()},
			}
		}
		if snap != nil {
			// Move previous metrics for rate computation.
			if snap.Metrics != nil {
				c.prevMetrics[s.ID] = snap.Metrics.Samples
				c.prevTime[s.ID] = snap.Metrics.CollectedAt
			}
			c.snapshots[s.ID] = snap
		}
	}
}

// RefreshServer collects a fresh snapshot for one server.
func (c *Cache) RefreshServer(ctx context.Context, serverID string) error {
	srv, err := c.getServerCfg(serverID)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	coll := c.coll[serverID]
	if coll == nil {
		return nil
	}
	snap, err := coll.Collect(ctx, *srv)
	if err != nil && snap == nil {
		snap = &ServerSnapshot{
			ServerID:    serverID,
			Status:      Unreachable,
			CollectedAt: c.nowFn(),
			Errors:      []string{err.Error()},
		}
	}
	if snap != nil && snap.Metrics != nil {
		c.prevMetrics[serverID] = snap.Metrics.Samples
		c.prevTime[serverID] = snap.Metrics.CollectedAt
	}
	if snap != nil {
		c.snapshots[serverID] = snap
	}
	return nil
}

// RatesFor returns computed rates for the given server using the previous
// cached metrics and the current snapshot's metrics.
func (c *Cache) RatesFor(serverID string) map[string]Rate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snap, ok := c.snapshots[serverID]
	if !ok || snap.Metrics == nil {
		return nil
	}
	prev, okPrev := c.prevMetrics[serverID]
	if !okPrev {
		return nil
	}
	prevTime, okTime := c.prevTime[serverID]
	if !okTime {
		return nil
	}
	window := snap.Metrics.CollectedAt.Sub(prevTime).Seconds()
	if window <= 0 {
		return nil
	}
	return ComputeRates(prev, snap.Metrics.Samples, window)
}

// ServerConfig returns the config for a server ID.
func (c *Cache) ServerConfig(serverID string) (*ServerConfig, bool) {
	for i := range c.cfg.Servers {
		if c.cfg.Servers[i].ID == serverID {
			s := c.cfg.Servers[i]
			return &s, true
		}
	}
	return nil, false
}

func (c *Cache) getServerCfg(serverID string) (*ServerConfig, error) {
	for i := range c.cfg.Servers {
		if c.cfg.Servers[i].ID == serverID {
			s := c.cfg.Servers[i]
			return &s, nil
		}
	}
	return nil, &unknownServerError{ID: serverID}
}

type unknownServerError struct{ ID string }

func (e *unknownServerError) Error() string { return "unknown server ID: " + e.ID }

// AllSnapshots returns all cached snapshots.
func (c *Cache) AllSnapshots() []ServerSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ServerSnapshot, 0, len(c.snapshots))
	for _, s := range c.cfg.Servers {
		if snap, ok := c.snapshots[s.ID]; ok {
			out = append(out, *snap)
		}
	}
	return out
}

// Config returns the dashboard config.
func (c *Cache) Config() *DashboardConfig { return c.cfg }
