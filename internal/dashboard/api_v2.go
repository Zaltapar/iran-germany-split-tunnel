package dashboard

// api_v2.go — Dashboard v2 read-only JSON API (/api/v2/...).
//
// Every v2 route is mounted under the same basePath prefix and the same
// middleware chain as v1 (security headers, method whitelist, HTTP Basic
// auth). The v2 surface is GET/HEAD only: any other method is answered with
// 405 before a handler runs, and no handler has a write path.
//
// Handlers read the cache's most recent snapshots and never trigger a
// collection, so a v2 request cannot contact a host. The poll loop remains the
// only collection driver and is also the only producer of timeseries points.
//
// Gaps are reported explicitly (null values plus "missingMetrics" /
// "unavailable" lists) instead of being fabricated.

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	v2Prefix            = "/api/v2/"
	v2Allow             = "GET, HEAD"
	v2MaxSeriesPerQuery = 16
	v2DefaultPoints     = 120
	v2DefaultEvents     = 100
)

// v2MissingHostMetrics are host gauges the current collectors do not provide.
// They are reported as null with this explicit list, never as zero.
var v2MissingHostMetrics = []string{"cpuPercent", "loadAvg1", "loadAvg5", "loadAvg15"}

// v2CarrierUnavailable are per-carrier measurements that the Phase 3 policy
// engine computes but does not export on /metrics today.
var v2CarrierUnavailable = []string{
	"p10_goodput_mibps", "ttfb_p50_ms", "flap_count", "stall_count", "rebinds", "probe_budget_bytes",
}

// carrierStateNames and gateReasonNames mirror the code-owned ordinals that
// pkg/node writes on /metrics (stateOrdinal / gateReasonOrdinal). Unknown
// ordinals map to "unknown" / "other".
var carrierStateNames = [...]string{"candidate", "active", "excluded", "half_open", "unknown"}
var gateReasonNames = [...]string{"", "H1 probe", "H2 flap", "H3 auth", "H4 stall", "success_ratio", "stall_rate", "not_active", "other"}

// v2CollectorEventTypes maps a host badge to its event type name. Explicit
// names avoid derived strings such as "collector_collector_missing".
var v2CollectorEventTypes = map[string]string{
	"stale":             "collector_stale",
	"unreachable":       "collector_unreachable",
	"collector-missing": "collector_missing",
}

// v2Notes are fixed, honest statements about data coverage shown in the UI.
var v2Notes = []string{
	"CPU and load average are not provided by the current collectors; they are reported as missing.",
	"Carrier p10 goodput, TTFB p50, flap count, stall count and per-carrier rebinds are computed by the policy engine but are not exported on /metrics; they are reported as unavailable.",
	"Routing and outbound views show the dashboard configuration only; no live routing or outbound state is collected in this phase.",
}

// --- response types --------------------------------------------------------

type v2Meta struct {
	GeneratedAt    time.Time `json:"generatedAt"`
	ReadOnly       bool      `json:"readOnly"`
	ConfigReadOnly bool      `json:"configReadOnly"`
	RefreshSec     int       `json:"refreshSec"`
	HistoryPoints  int       `json:"historyPointsPerSeries"`
}

type v2Host struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Role             string         `json:"role"`
	SourceType       string         `json:"sourceType"`
	Status           SnapshotStatus `json:"status"`
	Badges           []string       `json:"badges"`
	CollectedAt      *time.Time     `json:"collectedAt,omitempty"`
	AgeSec           int64          `json:"ageSec"`
	CollectorMissing bool           `json:"collectorMissing"`
	Message          string         `json:"message,omitempty"`
	MemUsedMiB       *int64         `json:"memUsedMiB"`
	DiskUsedGiB      *float64       `json:"diskUsedGiB"`
	UptimeHours      *float64       `json:"uptimeHours"`
	ActiveSessions   *int64         `json:"activeSessions"`
	CarrierLosses    *int64         `json:"carrierLossEvents"`
	ErrorsTotal      *int64         `json:"errorsTotal"`
	UpMiBps          *float64       `json:"upMiBps"`
	DownMiBps        *float64       `json:"downMiBps"`
	CPUPercent       *float64       `json:"cpuPercent"`
	LoadAvg1         *float64       `json:"loadAvg1"`
	LoadAvg5         *float64       `json:"loadAvg5"`
	LoadAvg15        *float64       `json:"loadAvg15"`
	MissingMetrics   []string       `json:"missingMetrics"`
	Errors           []string       `json:"errors,omitempty"`
}

type v2Carrier struct {
	ServerID             string   `json:"serverId"`
	Carrier              string   `json:"carrier"`
	State                string   `json:"state"`
	Score                *float64 `json:"score"`
	GoodputMiBps         *float64 `json:"goodputMiBps"`
	SuccessRatio         *float64 `json:"successRatio"`
	StallRatePer100MiB   *float64 `json:"stallRatePer100MiB"`
	Eligible             *bool    `json:"eligible"`
	GateReason           string   `json:"gateReason"`
	CooldownRemainingSec *int64   `json:"cooldownRemainingSec"`
	ProbeBytesToday      *int64   `json:"probeBytesToday"`
	LossEvents           *int64   `json:"lossEvents"`
	Reconnects           *int64   `json:"reconnects"`
	Unavailable          []string `json:"unavailable"`
}

type v2OutboundView struct {
	OutboundConfig
	Status     string   `json:"status"`
	Validation []string `json:"validation"`
}

type v2RoutingView struct {
	Source               string        `json:"source"`
	Declared             bool          `json:"declared"`
	LiveRoutingCollected bool          `json:"liveRoutingCollected"`
	Schema               string        `json:"schema"`
	Valid                bool          `json:"valid"`
	Errors               []string      `json:"errors"`
	Policy               RoutingPolicy `json:"policy"`
}

type v2Event struct {
	Time     time.Time `json:"time"`
	Level    string    `json:"level"`
	Type     string    `json:"type"`
	ServerID string    `json:"serverId,omitempty"`
	Message  string    `json:"message"`
}

type v2Counts struct {
	Hosts                 int `json:"hosts"`
	HostsStale            int `json:"hostsStale"`
	HostsUnreachable      int `json:"hostsUnreachable"`
	HostsCollectorMissing int `json:"hostsCollectorMissing"`
	Carriers              int `json:"carriers"`
	CarriersEligible      int `json:"carriersEligible"`
	Outbounds             int `json:"outbounds"`
	OutboundsEnabled      int `json:"outboundsEnabled"`
	RoutingRules          int `json:"routingRules"`
}

// --- routing ---------------------------------------------------------------

// handleV2 dispatches every /api/v2/... request. It runs after the shared
// middleware (basePath, security headers, auth), so it is never reachable
// unauthenticated.
func (s *Server) handleV2(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// C1: POST is allowed for the new /api/v2/changes/validate route
		// (read-only control validation; no apply, no mutator call).
		// C2: POST is allowed for /api/v2/changes/{id}/apply (the
		// forwarded control-apply op; the handler is flag-gated and the
		// agent owns every host mutation).
		if r.Method == http.MethodPost {
			parts := v2Segments(r.URL.Path)
			if len(parts) == 2 && parts[0] == "changes" && parts[1] == "validate" {
				s.c1HandleChangesValidate(w, r)
				return
			}
			if len(parts) == 3 && parts[0] == "changes" && parts[2] == "apply" {
				s.c2HandleChangesApply(w, r, parts[1])
				return
			}
			// C3 inbound editing surface (per-capability gated in the
			// handler; the method whitelist already allowed POST).
			if len(parts) == 3 && parts[0] == "changes" && parts[2] == "inbounds-validate" {
				s.c3HandleInboundsValidate(w, r, parts[1])
				return
			}
			if len(parts) == 3 && parts[0] == "changes" && parts[2] == "inbounds-apply" {
				s.c3HandleInboundsApply(w, r, parts[1])
				return
			}
		}
		w.Header().Set("Allow", v2Allow)
		writeJSONError(w, http.StatusMethodNotAllowed, "dashboard v2 API is read-only: only GET and HEAD are allowed")
		return
	}
	parts := v2Segments(r.URL.Path)
	now := s.cache.nowFn()

	if len(parts) > 0 {
		switch parts[0] {
		case "revisions":
			if len(parts) == 1 {
				s.c2HandleRevisions(w, r)
				return
			}
		case "audit":
			if len(parts) == 1 {
				s.c2HandleAudit(w, r)
				return
			}
		case "overview":
			if len(parts) == 1 {
				s.v2Overview(w, now)
				return
			}
		case "hosts":
			if len(parts) == 1 {
				writeJSON(w, http.StatusOK, s.v2HostsResponse(now))
				return
			}
		case "carriers":
			if len(parts) == 1 {
				writeJSON(w, http.StatusOK, s.v2CarriersResponse(now))
				return
			}
		case "outbounds":
			if len(parts) == 1 {
				writeJSON(w, http.StatusOK, s.v2OutboundsResponse(now))
				return
			}
		case "routing":
			if len(parts) == 1 {
				writeJSON(w, http.StatusOK, s.v2RoutingView())
				return
			}
		case "config":
			if len(parts) == 1 {
				writeJSON(w, http.StatusOK, s.v2ConfigResponse(now))
				return
			}
		case "events":
			if len(parts) == 1 {
				s.v2Events(w, r, now)
				return
			}
		case "timeseries":
			if len(parts) == 1 {
				s.v2Timeseries(w, r, now)
				return
			}
		case "schema":
			if len(parts) == 1 {
				writeJSON(w, http.StatusOK, ConceptSchemas())
				return
			}
			if len(parts) == 2 {
				// C1: the new policy-multi-carrier concept is not in
				// ConceptSchemas() (which lists the legacy outbound /
				// routing-rule / routing-policy concepts). Handle it
				// explicitly before falling through to the 404.
				if parts[1] == policyMultiCarrierConcept {
					s.c1HandleSchemaPolicyMultiCarrier(w)
					return
				}
				// C3: the Reality inbound editing concepts (public fields
				// only; key refs as fingerprints, never key material).
				if _, ok := c3SchemaForConcept(parts[1]); ok {
					s.c3HandleInboundsSchema(w, parts[1])
					return
				}
				if c, ok := conceptSchemaByName(parts[1]); ok {
					writeJSON(w, http.StatusOK, c)
					return
				}
			}
		case "validate":
			// Validation is a contract stub in this phase: GET describes what
			// a future POST will accept. POST is rejected by the method guard
			// above, so nothing is validated-and-stored.
			if len(parts) == 2 {
				if c, ok := conceptSchemaByName(parts[1]); ok {
					writeJSON(w, http.StatusOK, v2ValidateContract{
						Concept:    c.Concept,
						Method:     http.MethodPost,
						Status:     "stub",
						Applied:    false,
						Message:    "validation endpoint is a stub in this read-only phase; POST is rejected until the editing phase",
						Schema:     "/api/v2/schema/" + c.Concept,
						FieldCount: len(c.Fields),
					})
					return
				}
			}
		}
	}
	writeJSONError(w, http.StatusNotFound, "unknown v2 endpoint")
}

type v2ValidateContract struct {
	Concept    string `json:"concept"`
	Method     string `json:"method"`
	Status     string `json:"status"`
	Applied    bool   `json:"applied"`
	Message    string `json:"message"`
	Schema     string `json:"schema"`
	FieldCount int    `json:"fieldCount"`
}

// v2Segments splits "/api/v2/a/b" into ["a","b"]; "/api/v2/" yields nil.
func v2Segments(p string) []string {
	p = strings.Trim(strings.TrimPrefix(p, v2Prefix), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// --- builders --------------------------------------------------------------

func v2Float(f float64) *float64 { return &f }
func v2Int(i int64) *int64       { return &i }
func v2Bool(b bool) *bool        { return &b }

func carrierStateName(ord int) string {
	if ord < 0 || ord >= len(carrierStateNames)-1 {
		return carrierStateNames[len(carrierStateNames)-1]
	}
	return carrierStateNames[ord]
}

func gateReasonName(ord int) string {
	if ord < 0 || ord >= len(gateReasonNames) {
		return "other"
	}
	return gateReasonNames[ord]
}

// v2EndpointLabel reduces a metrics URL to "scheme://host:port". Userinfo,
// path, and query (where tokens or basePaths could live) are dropped.
func v2EndpointLabel(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "[unparseable endpoint]"
	}
	return u.Scheme + "://" + u.Host
}

// v2EffectiveStatus downgrades a Fresh snapshot to Stale once it is older
// than two refresh intervals, mirroring Cache.Snapshot, and returns the
// matching UI badges.
func (s *Server) v2EffectiveStatus(snap *ServerSnapshot, now time.Time) (SnapshotStatus, []string) {
	status := snap.Status
	if status == Fresh && now.Sub(snap.CollectedAt) > time.Duration(s.cfg.RefreshSec)*2*time.Second {
		status = Stale
	}
	badges := []string{}
	switch status {
	case Stale:
		badges = append(badges, "stale")
	case Unreachable:
		badges = append(badges, "unreachable")
	case Unsupported:
		badges = append(badges, "collector-missing")
	}
	return status, badges
}

func (s *Server) v2BuildHost(srv ServerConfig, snap *ServerSnapshot, now time.Time) v2Host {
	h := v2Host{
		ID:             srv.ID,
		Name:           srv.Name,
		Role:           srv.Role,
		SourceType:     srv.SourceType,
		Badges:         []string{},
		MissingMetrics: append([]string(nil), v2MissingHostMetrics...),
	}
	if snap == nil {
		h.Status = "pending"
		h.Badges = append(h.Badges, "no-data")
		h.Message = "no snapshot collected yet"
		return h
	}
	status, badges := s.v2EffectiveStatus(snap, now)
	h.Status = status
	h.Badges = badges
	collectedAt := snap.CollectedAt
	h.CollectedAt = &collectedAt
	if !snap.CollectedAt.IsZero() {
		h.AgeSec = int64(now.Sub(snap.CollectedAt).Seconds())
	}
	switch status {
	case Unsupported:
		h.CollectorMissing = true
		h.Message = "collector missing: no metrics source is configured for this host"
	case Unreachable:
		h.Message = "collector unreachable; no fresh values were collected in the last poll"
	case Stale:
		h.Message = "snapshot is older than two refresh intervals"
	}
	for _, e := range snap.Errors {
		h.Errors = append(h.Errors, RedactString(e))
	}

	if snap.MemoryMB > 0 {
		h.MemUsedMiB = v2Int(snap.MemoryMB)
	}
	if snap.DiskBytes > 0 {
		h.DiskUsedGiB = v2Float(float64(snap.DiskBytes) / histGiB)
	}
	if snap.UptimeSec > 0 {
		h.UptimeHours = v2Float(snap.UptimeSec / 3600)
	}
	if snap.Metrics != nil {
		for _, sm := range snap.Metrics.Samples {
			if len(sm.Labels) != 0 {
				continue
			}
			switch sm.Name {
			case "active_sessions":
				h.ActiveSessions = v2Int(int64(sm.Value))
			case "carrier_loss_events":
				h.CarrierLosses = v2Int(int64(sm.Value))
			case "errors":
				h.ErrorsTotal = v2Int(int64(sm.Value))
			}
		}
		rates := s.cache.RatesFor(srv.ID)
		if r, ok := rates["total_bytes_up"]; ok {
			h.UpMiBps = v2Float(r.PerSec / histMiB)
		}
		if r, ok := rates["total_bytes_down"]; ok {
			h.DownMiBps = v2Float(r.PerSec / histMiB)
		}
	}
	return h
}

// v2HostList builds one view per configured server, in configuration order.
func (s *Server) v2HostList(now time.Time) []v2Host {
	byID := map[string]*ServerSnapshot{}
	snaps := s.cache.AllSnapshots()
	for i := range snaps {
		byID[snaps[i].ServerID] = &snaps[i]
	}
	out := make([]v2Host, 0, len(s.cfg.Servers))
	for _, srv := range s.cfg.Servers {
		out = append(out, s.v2BuildHost(srv, byID[srv.ID], now))
	}
	return out
}

// v2CarriersFrom extracts the per-carrier gauges exported by pkg/node with a
// carrier label. Only label values from the closed series-key alphabet are
// accepted.
func v2CarriersFrom(serverID string, snap *ServerSnapshot) []v2Carrier {
	if snap == nil || snap.Metrics == nil {
		return nil
	}
	byID := map[string]*v2Carrier{}
	get := func(id string) *v2Carrier {
		c, ok := byID[id]
		if !ok {
			c = &v2Carrier{
				ServerID:    serverID,
				Carrier:     id,
				State:       "unknown",
				Unavailable: append([]string(nil), v2CarrierUnavailable...),
			}
			byID[id] = c
		}
		return c
	}
	for _, sm := range snap.Metrics.Samples {
		id := sm.Labels["carrier"]
		if id == "" || !validSeriesKey(id) {
			continue
		}
		switch sm.Name {
		case "carrier_health_state":
			get(id).State = carrierStateName(int(sm.Value))
		case "carrier_health_score":
			get(id).Score = v2Float(sm.Value)
		case "carrier_health_goodput_mibps":
			get(id).GoodputMiBps = v2Float(sm.Value)
		case "carrier_health_success_ratio":
			get(id).SuccessRatio = v2Float(sm.Value)
		case "carrier_health_stall_rate_per_100_mib":
			get(id).StallRatePer100MiB = v2Float(sm.Value)
		case "carrier_health_eligible":
			get(id).Eligible = v2Bool(sm.Value >= 1)
		case "carrier_health_gate_reason":
			get(id).GateReason = gateReasonName(int(sm.Value))
		case "carrier_health_cooldown_remaining_sec":
			get(id).CooldownRemainingSec = v2Int(int64(sm.Value))
		case "carrier_health_probe_bytes_today":
			get(id).ProbeBytesToday = v2Int(int64(sm.Value))
		case "carrier_loss_events":
			get(id).LossEvents = v2Int(int64(sm.Value))
		case "carrier_reconnects":
			get(id).Reconnects = v2Int(int64(sm.Value))
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]v2Carrier, 0, len(ids))
	for _, id := range ids {
		out = append(out, *byID[id])
	}
	return out
}

func (s *Server) v2CarrierList() []v2Carrier {
	var out []v2Carrier
	for _, srv := range s.cfg.Servers {
		snap, _ := s.cache.Snapshot(srv.ID)
		out = append(out, v2CarriersFrom(srv.ID, snap)...)
	}
	if out == nil {
		out = []v2Carrier{}
	}
	return out
}

func (s *Server) v2Meta(now time.Time) v2Meta {
	return v2Meta{
		GeneratedAt:    now,
		ReadOnly:       true,
		ConfigReadOnly: s.cfg.ReadOnly,
		RefreshSec:     s.cfg.RefreshSec,
		HistoryPoints:  s.cache.History().Capacity(),
	}
}

func (s *Server) v2OutboundViews() []v2OutboundView {
	out := make([]v2OutboundView, 0, len(s.cfg.Outbounds))
	for _, o := range s.cfg.Outbounds {
		status := "configured; live state is not collected in this phase"
		if !o.Enabled {
			status = "disabled"
		}
		errs := ValidateOutbound(o)
		if errs == nil {
			errs = []string{}
		}
		out = append(out, v2OutboundView{
			OutboundConfig: o,
			Status:         status,
			Validation:     errs,
		})
	}
	return out
}

func (s *Server) v2RoutingView() v2RoutingView {
	view := v2RoutingView{
		Source: "dashboard-config",
		Schema: "/api/v2/schema/" + ConceptRoutingPolicy,
		Policy: RoutingPolicy{Mode: "split", Rules: []RoutingRule{}},
	}
	if s.cfg.Routing != nil {
		view.Declared = true
		view.Policy = *s.cfg.Routing
		if view.Policy.Rules == nil {
			view.Policy.Rules = []RoutingRule{}
		}
	}
	view.Errors = ValidateRoutingPolicy(view.Policy, s.cfg.Outbounds)
	if view.Errors == nil {
		view.Errors = []string{}
	}
	view.Valid = len(view.Errors) == 0
	return view
}

// v2ConfigValues returns the dashboard configuration as redacted key/value
// pairs. It never includes the TLS basePath, certificate or key paths,
// credential sources, SSH identity or known-hosts paths, or any URL
// userinfo/path. Only whether TLS and a basePath are configured is shown.
func (s *Server) v2ConfigValues() []ConfigValue {
	var out []ConfigValue
	add := func(key, value string) {
		out = append(out, RedactConfigValue(key, value, false, false))
	}
	tlsOn := s.cfg.TLS != nil && s.cfg.TLS.Enabled
	add("listenAddr", s.cfg.ListenAddr)
	add("readOnly", strconv.FormatBool(s.cfg.ReadOnly))
	add("refreshSec", strconv.Itoa(s.cfg.RefreshSec))
	add("maxLogEntries", strconv.Itoa(s.cfg.MaxLogEntries))
	add("maxAudit", strconv.Itoa(s.cfg.MaxAudit))
	add("historyPointsPerSeries", strconv.Itoa(s.cache.History().Capacity()))
	add("tls.enabled", strconv.FormatBool(tlsOn))
	add("tls.basePathConfigured", strconv.FormatBool(s.cfg.BasePath() != ""))
	for _, srv := range s.cfg.Servers {
		p := "servers." + srv.ID + "."
		add(p+"name", srv.Name)
		add(p+"role", srv.Role)
		add(p+"sourceType", srv.SourceType)
		add(p+"address", srv.Address)
		if srv.MetricsURL != "" {
			add(p+"metricsEndpoint", v2EndpointLabel(srv.MetricsURL))
		}
	}
	for _, o := range s.cfg.Outbounds {
		p := "outbounds." + o.Name + "."
		add(p+"protocol", o.Protocol)
		add(p+"port", strconv.Itoa(o.Port))
		add(p+"serverName", o.ServerName)
		add(p+"transport", o.Transport)
		add(p+"enabled", strconv.FormatBool(o.Enabled))
	}
	mode := "split"
	rules := 0
	if s.cfg.Routing != nil {
		mode = s.cfg.Routing.Mode
		rules = len(s.cfg.Routing.Rules)
	}
	add("routing.mode", mode)
	add("routing.rules", strconv.Itoa(rules))
	return out
}

// --- handlers --------------------------------------------------------------

func (s *Server) v2Overview(w http.ResponseWriter, now time.Time) {
	hosts := s.v2HostList(now)
	carriers := s.v2CarrierList()
	var c v2Counts
	c.Hosts = len(hosts)
	for _, h := range hosts {
		switch h.Status {
		case Unreachable:
			c.HostsUnreachable++
		}
		for _, b := range h.Badges {
			switch b {
			case "stale":
				c.HostsStale++
			case "collector-missing":
				c.HostsCollectorMissing++
			}
		}
	}
	c.Carriers = len(carriers)
	for _, car := range carriers {
		if car.Eligible != nil && *car.Eligible {
			c.CarriersEligible++
		}
	}
	c.Outbounds = len(s.cfg.Outbounds)
	for _, o := range s.cfg.Outbounds {
		if o.Enabled {
			c.OutboundsEnabled++
		}
	}
	if s.cfg.Routing != nil {
		c.RoutingRules = len(s.cfg.Routing.Rules)
	}
	mode := "split"
	if s.cfg.Routing != nil {
		mode = s.cfg.Routing.Mode
	}
	writeJSON(w, http.StatusOK, struct {
		Meta        v2Meta   `json:"meta"`
		Counts      v2Counts `json:"counts"`
		RoutingMode string   `json:"routingMode"`
		Hosts       []v2Host `json:"hosts"`
		Notes       []string `json:"notes"`
	}{
		Meta:        s.v2Meta(now),
		Counts:      c,
		RoutingMode: mode,
		Hosts:       hosts,
		Notes:       v2Notes,
	})
}

func (s *Server) v2HostsResponse(now time.Time) any {
	return struct {
		Meta  v2Meta   `json:"meta"`
		Hosts []v2Host `json:"hosts"`
	}{Meta: s.v2Meta(now), Hosts: s.v2HostList(now)}
}

func (s *Server) v2CarriersResponse(now time.Time) any {
	return struct {
		Meta     v2Meta      `json:"meta"`
		Carriers []v2Carrier `json:"carriers"`
		Notes    []string    `json:"notes"`
	}{Meta: s.v2Meta(now), Carriers: s.v2CarrierList(), Notes: []string{v2Notes[1]}}
}

func (s *Server) v2OutboundsResponse(now time.Time) any {
	return struct {
		Meta      v2Meta           `json:"meta"`
		Outbounds []v2OutboundView `json:"outbounds"`
		Empty     string           `json:"empty,omitempty"`
	}{
		Meta:      s.v2Meta(now),
		Outbounds: s.v2OutboundViews(),
		Empty:     emptyMessage(len(s.cfg.Outbounds), "no outbounds are declared in the dashboard config"),
	}
}

func (s *Server) v2ConfigResponse(now time.Time) any {
	return struct {
		Meta   v2Meta        `json:"meta"`
		Values []ConfigValue `json:"values"`
		Notes  []string      `json:"notes"`
	}{
		Meta:   s.v2Meta(now),
		Values: s.v2ConfigValues(),
		Notes:  []string{"read-only view; basePath, credentials, key paths, SSH paths and URL secrets are never shown"},
	}
}

func emptyMessage(n int, msg string) string {
	if n == 0 {
		return msg
	}
	return ""
}

// v2Events merges audit events with per-host collector state changes and
// returns the newest first, bounded by limit. Every message is redacted.
func (s *Server) v2Events(w http.ResponseWriter, r *http.Request, now time.Time) {
	limit := v2DefaultEvents
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n <= 0 {
			writeJSONError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	if s.cfg.MaxLogEntries > 0 && limit > s.cfg.MaxLogEntries {
		limit = s.cfg.MaxLogEntries
	}
	var events []v2Event
	for _, ev := range s.audit.LastN(limit) {
		level := "info"
		switch ev.EventType {
		case "apply_blocked", "apply_rejected", "apply_failed":
			level = "warn"
		}
		events = append(events, v2Event{
			Time:     ev.Timestamp,
			Level:    level,
			Type:     ev.EventType,
			ServerID: ev.ServerID,
			Message:  RedactString(ev.Detail),
		})
	}
	for _, h := range s.v2HostList(now) {
		for _, b := range h.Badges {
			if b != "stale" && b != "unreachable" && b != "collector-missing" {
				continue
			}
			t := now
			if h.CollectedAt != nil {
				t = *h.CollectedAt
			}
			msg := h.Message
			if len(h.Errors) > 0 {
				msg += ": " + strings.Join(h.Errors, "; ")
			}
			events = append(events, v2Event{
				Time:     t,
				Level:    "warn",
				Type:     v2CollectorEventTypes[b],
				ServerID: h.ID,
				Message:  RedactString(msg),
			})
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	if len(events) > limit {
		events = events[:limit]
	}
	if events == nil {
		events = []v2Event{}
	}
	writeJSON(w, http.StatusOK, struct {
		Meta   v2Meta    `json:"meta"`
		Events []v2Event `json:"events"`
	}{Meta: s.v2Meta(now), Events: events})
}

// v2Timeseries: GET /api/v2/timeseries lists the retained series keys.
// GET /api/v2/timeseries?series=a,b&limit=N returns up to limit most-recent
// points per series, oldest first. Keys must match the closed series alphabet.
func (s *Server) v2Timeseries(w http.ResponseWriter, r *http.Request, now time.Time) {
	hist := s.cache.History()
	raw := strings.TrimSpace(r.URL.Query().Get("series"))
	if raw == "" {
		keys := hist.Keys()
		if keys == nil {
			keys = []string{}
		}
		writeJSON(w, http.StatusOK, struct {
			Meta   v2Meta   `json:"meta"`
			Series []string `json:"series"`
		}{Meta: s.v2Meta(now), Series: keys})
		return
	}
	parts := strings.Split(raw, ",")
	if len(parts) > v2MaxSeriesPerQuery {
		writeJSONError(w, http.StatusBadRequest, "too many series in one query (max 16)")
		return
	}
	limit := v2DefaultPoints
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n <= 0 {
			writeJSONError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	if limit > hist.Capacity() {
		limit = hist.Capacity()
	}
	type seriesOut struct {
		Key    string         `json:"key"`
		Found  bool           `json:"found"`
		Points []HistoryPoint `json:"points"`
	}
	out := make([]seriesOut, 0, len(parts))
	for _, p := range parts {
		k := strings.TrimSpace(p)
		if !validSeriesKey(k) {
			writeJSONError(w, http.StatusBadRequest, "invalid series key")
			return
		}
		pts := hist.Points(k, limit)
		if pts == nil {
			pts = []HistoryPoint{}
		}
		out = append(out, seriesOut{Key: k, Found: hist.Has(k), Points: pts})
	}
	writeJSON(w, http.StatusOK, struct {
		Meta   v2Meta      `json:"meta"`
		Series []seriesOut `json:"series"`
	}{Meta: s.v2Meta(now), Series: out})
}
