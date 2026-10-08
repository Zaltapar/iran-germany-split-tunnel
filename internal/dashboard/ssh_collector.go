package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SSHCollector is a secure, READ-ONLY remote host collector over SSH.
//
// It shells out to the ssh binary with a fixed argv; the remote command is
// never a free-form string. Every remote query is one of the fixed allowlisted
// commands built by the Build*Args helpers in ssh_config.go.
//
// The collector is completely testable without a real ssh connection: it
// accepts a CommandRunner interface that tests can fake.
type SSHCollector struct {
	Runner CommandRunner
	Now    func() time.Time
}

// NewSSHCollector returns an SSHCollector that uses ExecCommandRunner for
// real execution. Pass a fake Runner in tests.
func NewSSHCollector() *SSHCollector {
	return &SSHCollector{
		Runner: ExecCommandRunner{},
		Now:    time.Now,
	}
}

// NewSSHCollectorWithRunner returns an SSHCollector with an injected runner.
func NewSSHCollectorWithRunner(r CommandRunner) *SSHCollector {
	return &SSHCollector{Runner: r, Now: time.Now}
}

// Collect implements the Collector interface. For each server with a valid
// SSHConfig, it runs the fixed remote commands and assembles a snapshot.
// The unprivileged account restriction is noted in the snapshot when
// PIDs or certain fields are unavailable.
func (s *SSHCollector) Collect(ctx context.Context, cfg ServerConfig) (*ServerSnapshot, error) {
	now := s.Now()
	snap := &ServerSnapshot{
		ServerID:    cfg.ID,
		CollectedAt: now,
	}

	// If no SSH sub-config is provided, fail closed without contacting anything.
	if cfg.SSH == nil {
		snap.Status = Unsupported
		snap.Errors = append(snap.Errors, fmt.Sprintf("server %q: sourceType=ssh but no SSH sub-config provided; no host was contacted", cfg.ID))
		return snap, nil
	}

	sc := cfg.SSH
	// Validate and normalize the SSH config.
	if err := ValidateSSHConfig(sc, cfg.Role); err != nil {
		snap.Status = Unreachable
		snap.Errors = append(snap.Errors, fmt.Sprintf("ssh config invalid: %v", err))
		return snap, nil
	}

	// Per-command context with a hard deadline so no individual command can
	// hang the whole refresh.
	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(sc.CommandTimeoutSec)*time.Second)
	defer cancel()

	// Track whether we got any useful data so we can set the right status.
	gotData := false

	// --- hostname ---
	if _, errOut, err := s.Runner.Run(cmdCtx, BuildFullArgs(sc, BuildHostnameArgs())); err != nil {
		snap.Errors = append(snap.Errors, fmt.Sprintf("hostname failed: %s", sanitizeErr(err, errOut)))
	} else {
		gotData = true
	}

	// --- uptime -s (seconds since boot) ---
	if out, _, err := s.Runner.Run(cmdCtx, BuildFullArgs(sc, BuildUptimeArgs())); err == nil {
		snap.UptimeSec = parseUptimeSince(out, now)
		gotData = true
	} else {
		snap.Errors = append(snap.Errors, "uptime: "+sanitizeErr(err, ""))
	}

	// --- systemctl show for each configured service ---
	for _, unit := range sc.Services {
		if !IsValidUnit(unit) {
			snap.Errors = append(snap.Errors, fmt.Sprintf("invalid unit %q skipped", unit))
			continue
		}
		out, errOut, err := s.Runner.Run(cmdCtx, BuildFullArgs(sc, BuildSystemctlArgs(unit)))
		if err != nil {
			snap.Errors = append(snap.Errors, fmt.Sprintf("systemctl show %s: %s", unit, sanitizeErr(err, errOut)))
			continue
		}
		snap.Services = append(snap.Services, parseSystemctlShow(unit, out)...)
		gotData = true
	}

	// --- ss -tlnp (listeners) ---
	if out, errOut, err := s.Runner.Run(cmdCtx, BuildFullArgs(sc, BuildSSArgs())); err == nil {
		snap.Listeners = parseSSOutput(out)
		gotData = true
	} else {
		// Permission-limited: the unprivileged user may not see PIDs.
		// Still parse whatever we got; note the limitation.
		if out != "" {
			snap.Listeners = parseSSOutput(out)
		}
		snap.Errors = append(snap.Errors, fmt.Sprintf("ss: %s (PIDs may require root)", sanitizeErr(err, errOut)))
	}

	// --- free -b (memory) ---
	if out, _, err := s.Runner.Run(cmdCtx, BuildFullArgs(sc, BuildFreeArgs())); err == nil {
		snap.MemoryMB = parseFreeOutput(out)
		gotData = true
	}

	// --- df -B1 / (disk) ---
	if out, _, err := s.Runner.Run(cmdCtx, BuildFullArgs(sc, BuildDFArgs())); err == nil {
		snap.DiskBytes = parseDFOutput(out)
		gotData = true
	}

	// --- bounded journalctl for each configured service ---
	// Use s.Now() for the since window so tests can control time.
	since := ""
	if sc.MaxJournalSinceSec > 0 {
		since = s.Now().Add(-time.Duration(sc.MaxJournalSinceSec) * time.Second).UTC().Format(time.RFC3339)
	}
	for _, unit := range sc.Services {
		if !IsValidUnit(unit) {
			continue
		}
		lines := sc.MaxJournalLines
		out, errOut, err := s.Runner.Run(cmdCtx, BuildFullArgs(sc, BuildJournalArgs(unit, lines, since)))
		if err != nil {
			snap.Errors = append(snap.Errors, fmt.Sprintf("journalctl %s: %s", unit, sanitizeErr(err, errOut)))
			continue
		}
		entries := parseJournalOutput(out, now)
		snap.Logs = append(snap.Logs, entries...)
		gotData = true
	}

	// Cap log entries to the per-server cap if set.
	maxLogs := cfg.MaxLogEntries
	if maxLogs == 0 {
		// No per-server cap; the caller (Cache) can cap globally.
		maxLogs = 0
	}
	if maxLogs > 0 && len(snap.Logs) > maxLogs {
		snap.Logs = snap.Logs[len(snap.Logs)-maxLogs:]
	}

	// --- curl /metrics (remote loopback port) ---
	if out, errOut, err := s.Runner.Run(cmdCtx, BuildFullArgs(sc, BuildMetricsArgs(sc))); err == nil {
		samples, parseErrs := ParseMetricsText(out)
		snap.Metrics = &ParsedMetrics{CollectedAt: now, Samples: samples, Errors: parseErrs}
		gotData = true
	} else {
		snap.Errors = append(snap.Errors, fmt.Sprintf("metrics curl: %s", sanitizeErr(err, errOut)))
	}

	// --- cat state.json (redacted) ---
	if out, errOut, err := s.Runner.Run(cmdCtx, BuildFullArgs(sc, BuildStateArgs(sc))); err == nil {
		cv := parseStateJSON(out)
		snap.Config = append(snap.Config, cv...)
		gotData = true
	} else {
		snap.Errors = append(snap.Errors, fmt.Sprintf("state.json: %s", sanitizeErr(err, errOut)))
	}

	// Note that this collector runs as the configured unprivileged account;
	// PIDs from `ss` and some systemctl fields may be unavailable.
	snap.Errors = append(snap.Errors, "running as unprivileged account: PIDs and some systemd fields may be unavailable")

	if gotData {
		snap.Status = Fresh
	} else {
		snap.Status = Unreachable
	}
	return snap, nil
}

// parseUptimeSince extracts the boot time from `uptime -s` output.
// Format: "Thu Oct  7 15:23:45 2026"
var uptimePattern = regexp.MustCompile(`\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\d{4})`)

// monthAbbr maps 3-letter month names to time.Month values.
var monthAbbr = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

func parseUptimeSince(out string, now time.Time) float64 {
	m := uptimePattern.FindStringSubmatch(strings.TrimSpace(out))
	if m == nil {
		return 0
	}
	mon, ok := monthAbbr[m[1]]
	if !ok {
		return 0
	}
	day, _ := strconv.Atoi(m[2])
	hour, _ := strconv.Atoi(m[3])
	min, _ := strconv.Atoi(m[4])
	sec, _ := strconv.Atoi(m[5])
	year, _ := strconv.Atoi(m[6])
	boot := time.Date(year, mon, day, hour, min, sec, 0, now.Location())
	if boot.After(now) {
		boot = boot.AddDate(-1, 0, 0)
	}
	return now.Sub(boot).Seconds()
}

// parseSystemctlShow parses `systemctl show <unit> -p ActiveState,SubState,UnitFileState,MainPID`
// output which looks like:
//
//	ActiveState=active
//	SubState=running
//	UnitFileState=enabled
//	MainPID=12345
func parseSystemctlShow(unit, out string) []ServiceState {
	activeState := ""
	subState := ""
	enabled := ""
	mainPID := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ActiveState="):
			activeState = strings.TrimPrefix(line, "ActiveState=")
		case strings.HasPrefix(line, "SubState="):
			subState = strings.TrimPrefix(line, "SubState=")
		case strings.HasPrefix(line, "UnitFileState="):
			enabled = strings.TrimPrefix(line, "UnitFileState=")
		case strings.HasPrefix(line, "MainPID="):
			pidStr := strings.TrimPrefix(line, "MainPID=")
			// MainPID is 0 when the service is not running.
			mainPID, _ = strconv.Atoi(pidStr)
		}
	}
	if activeState == "" {
		activeState = "unknown"
	}
	return []ServiceState{
		{
			Unit:     unit + ".service",
			State:    activeState,
			Active:   activeState == "active",
			SubState: subState,
			Enabled:  enabled,
			MainPID:  mainPID,
		},
	}
}

// parseSSOutput parses `ss -tlnp` output. Lines look like:
//
//	Listen  0  128  127.0.0.1:9101  0.0.0.0:*  users:(("splitter",pid=123,fd=5))
func parseSSOutput(out string) []ListenerState {
	var listeners []ListenerState
	pidPat := regexp.MustCompile(`pid=(\d+)`)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Net") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Standard `ss -tlnp` columns: State Recv-Q Send-Q Local Address:Port
		// Peer Address:Port Process. The first field is "LISTEN" (state) and
		// fields[3] is the local address:port.
		if !strings.EqualFold(fields[0], "LISTEN") {
			continue
		}
		localAddr := fields[3]
		pid := 0
		if m := pidPat.FindStringSubmatch(line); m != nil {
			pid, _ = strconv.Atoi(m[1])
		}
		listeners = append(listeners, ListenerState{
			Protocol: "tcp",
			Address:  localAddr,
			PID:      pid,
		})
	}
	return listeners
}

// parseFreeOutput parses `free -b` output to extract used memory in MiB.
func parseFreeOutput(out string) int64 {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Mem:") {
			fields := strings.Fields(trimmed)
			// fields: ["Mem:", "total", "used", "free", ...]
			if len(fields) >= 3 {
				used, _ := strconv.ParseInt(fields[2], 10, 64)
				return used / (1024 * 1024)
			}
		}
	}
	return 0
}

// parseDFOutput parses `df -B1 /` output for used bytes on the root FS.
func parseDFOutput(out string) int64 {
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // header row
		}
		fields := strings.Fields(line)
		// df -B1 / output: Filesystem 1B-blocks Used Available Capacity Mounted
		if len(fields) >= 5 {
			used, _ := strconv.ParseInt(fields[2], 10, 64)
			return used
		}
	}
	return 0
}

// journalLinePattern matches a `journalctl -o short-iso` line:
//
//	2026-10-07 10:00:00 host unit[pid]: message
//
// The actual short-iso format is "YYYY-MM-DD HH:MM:SS host ident[pid]: msg".
var journalLinePattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$`)

// parseJournalOutput parses `journalctl -u <unit> -o short-iso` output.
// Lines: "YYYY-MM-DD HH:MM:SS host ident[pid]: message"
func parseJournalOutput(out string, now time.Time) []LogEntry {
	var entries []LogEntry
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ts time.Time
		rest := line
		if m := journalLinePattern.FindStringSubmatch(line); m != nil {
			parsed, err := time.Parse("2006-01-02 15:04:05", m[1]+" "+m[2])
			if err != nil {
				parsed = now
			}
			ts = parsed
			rest = m[4]
		}
		if ts.IsZero() {
			ts = now
		}
		level := "INFO"
		upper := strings.ToUpper(rest)
		if strings.Contains(upper, "ERROR") {
			level = "ERROR"
		} else if strings.Contains(upper, "WARN") {
			level = "WARN"
		}
		entries = append(entries, LogEntry{
			Timestamp: ts,
			Level:     level,
			Message:   rest,
		})
	}
	return entries
}

// --- state.json parsing and redaction ---
//
// parseStateJSON uses an explicit allowlist of safe, non-secret fields.
// No secret value can reach the UI because only known fields are projected
// and each value passes through RedactConfigValue which masks any residual
// sensitive content.

// parseStateJSON parses /etc/split-tunnel/state.json and extracts a safe,
// redacted subset of configuration values for display. It never returns raw
// secret material: only an explicit allowlist of non-sensitive fields is
// projected; every value is additionally passed through RedactConfigValue
// which masks any embedded secrets.
func parseStateJSON(raw string) []ConfigValue {
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	// Do NOT DisallowUnknownFields: state.json may evolve; unknown fields
	// are silently ignored for display purposes.
	if err := dec.Decode(&m); err != nil {
		return []ConfigValue{{
			Key:      "STATE_JSON",
			Value:    "unreadable: " + sanitizeErrText(err.Error()),
			Redacted: false,
		}}
	}

	results := make([]ConfigValue, 0, 16)
	if role, ok := m["role"].(string); ok {
		c := RedactConfigValue("state.role", role, false, false)
		results = append(results, c)
	}
	if gen, ok := m["generation"].(string); ok {
		c := RedactConfigValue("state.generation", gen, false, false)
		results = append(results, c)
	}
	if scheme, ok := m["schema"].(float64); ok {
		c := RedactConfigValue("state.schema", strconv.FormatFloat(scheme, 'f', 0, 64), false, false)
		results = append(results, c)
	}
	if updatedAt, ok := m["updatedAt"].(string); ok {
		c := RedactConfigValue("state.updatedAt", updatedAt, false, false)
		results = append(results, c)
	}
	if manifestHash, ok := m["manifestHash"].(string); ok {
		c := RedactConfigValue("state.manifestHash", manifestHash, false, false)
		results = append(results, c)
	}
	if configFp, ok := m["configFingerprint"].(string); ok {
		c := RedactConfigValue("state.configFingerprint", configFp, false, false)
		results = append(results, c)
	}
	if services, ok := m["services"].([]any); ok {
		for _, s := range services {
			if sm, ok := s.(map[string]any); ok {
				if unit, ok := sm["unit"].(string); ok {
					c := RedactConfigValue("state.service.unit", unit, false, false)
					results = append(results, c)
				}
			}
		}
	}
	if pairing, ok := m["pairing"].(map[string]any); ok {
		if state, ok := pairing["state"].(string); ok {
			c := RedactConfigValue("state.pairing.state", state, false, false)
			results = append(results, c)
		}
		if peerRole, ok := pairing["peerRole"].(string); ok {
			c := RedactConfigValue("state.pairing.peerRole", peerRole, false, false)
			results = append(results, c)
		}
	}
	return results
}

// sanitizeErr truncates an error to a concise, displayable string. It never
// includes raw remote stderr (which could contain secrets), only the Go-level
// error message.
func sanitizeErr(err error, _ string) string {
	if err == nil {
		return "ok"
	}
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

func sanitizeErrText(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
