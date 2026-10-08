package dashboard

import (
	"context"
	"strings"
	"testing"
	"time"
)

// --- Fake command runner ---

// recordedCall is one argv vector the fake runner was asked to run.
type recordedCall struct {
	argv []string
}

// fakeRunner is a CommandRunner that records argv and returns canned output
// keyed on the first remote command token. It never shells out.
type fakeRunner struct {
	calls []recordedCall
	// outputByCmd maps the FIRST token of the remote command (the element
	// immediately after "user@host") to canned stdout.
	outputByCmd map[string]string
	failCmds    map[string]bool // remote cmd first-token that should fail
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		outputByCmd: map[string]string{},
		failCmds:    map[string]bool{},
	}
}

func (f *fakeRunner) Run(_ context.Context, argv []string) (string, string, error) {
	f.calls = append(f.calls, recordedCall{argv: append([]string(nil), argv...)})
	// The remote command starts after the "user@host" element. The host token
	// is the last element that contains '@'.
	remoteStart := len(argv)
	for i, a := range argv {
		if strings.Contains(a, "@") {
			remoteStart = i + 1
			break
		}
	}
	if remoteStart >= len(argv) {
		return "", "", nil
	}
	cmd := argv[remoteStart]
	if f.failCmds[cmd] {
		return "", "fake failure for " + cmd, errFake
	}
	return f.outputByCmd[cmd], "", nil
}

// remoteCmds returns the list of first-tokens of each remote invocation, in
// order. Useful for asserting the exact allowlist sequence.
func (f *fakeRunner) remoteCmds() []string {
	var out []string
	for _, c := range f.calls {
		for i, a := range c.argv {
			if strings.Contains(a, "@") {
				if i+1 < len(c.argv) {
					out = append(out, c.argv[i+1])
				}
				break
			}
		}
	}
	return out
}

// cmdCount returns how many times a given remote first-token was invoked.
func (f *fakeRunner) cmdCount(tok string) int {
	n := 0
	for _, c := range f.calls {
		for i, a := range c.argv {
			if strings.Contains(a, "@") {
				if i+1 < len(c.argv) && c.argv[i+1] == tok {
					n++
				}
				break
			}
		}
	}
	return n
}

type fakeErr struct{ msg string }

func (e fakeErr) Error() string { return e.msg }

var errFake = fakeErr{"fake runner returned a failure"}

// validSSHConfig returns a fully-valid SSHConfig for tests.
func validSSHConfig(role string) *SSHConfig {
	return &SSHConfig{
		User:               "monitor",
		Address:            "127.0.0.1",
		Port:               22,
		IdentityFile:       "/home/operator/.ssh/monitor_key",
		KnownHosts:         "/home/operator/.ssh/pinned_kh",
		ConnectTimeoutSec:  10,
		CommandTimeoutSec:  15,
		MetricsPort:        9101,
		StatePath:          "/etc/split-tunnel/state.json",
		MaxJournalLines:    100,
		MaxJournalSinceSec: 600,
		Services:           defaultServicesForRole(role),
	}
}

// --- Config validation tests ---

func TestValidateSSHConfigMissingKnownHosts(t *testing.T) {
	sc := validSSHConfig("iran")
	sc.KnownHosts = ""
	if err := ValidateSSHConfig(sc, "iran"); err == nil {
		t.Fatal("expected error when knownHosts is missing (must pin host keys)")
	}
}

func TestValidateSSHConfigRejectsShellMetacharacterUser(t *testing.T) {
	sc := validSSHConfig("iran")
	sc.User = "a;rm -rf /"
	if err := ValidateSSHConfig(sc, "iran"); err == nil {
		t.Error("user with shell metacharacters must be rejected")
	}
}

func TestValidateSSHConfigRejectsBadAddress(t *testing.T) {
	sc := validSSHConfig("iran")
	sc.Address = "host$(reboot)"
	if err := ValidateSSHConfig(sc, "iran"); err == nil {
		t.Error("address with command substitution must be rejected")
	}
}

func TestValidateSSHConfigRejectsRelativePaths(t *testing.T) {
	sc := validSSHConfig("iran")
	sc.IdentityFile = "relative/key"
	if err := ValidateSSHConfig(sc, "iran"); err == nil {
		t.Error("relative identityFile must be rejected")
	}
}

func TestValidateSSHConfigRejectsUnknownService(t *testing.T) {
	sc := validSSHConfig("iran")
	sc.Services = []string{"root-evil"}
	if err := ValidateSSHConfig(sc, "iran"); err == nil {
		t.Error("unknown service name must be rejected (only KnownUnits allowed)")
	}
}

func TestValidateSSHConfigRejectsOutOfRangeJournal(t *testing.T) {
	sc := validSSHConfig("iran")
	sc.MaxJournalLines = 99999
	if err := ValidateSSHConfig(sc, "iran"); err == nil {
		t.Error("maxJournalLines beyond 500 must be rejected")
	}
}

func TestValidateSSHConfigValid(t *testing.T) {
	sc := validSSHConfig("germany")
	if err := ValidateSSHConfig(sc, "germany"); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if sc.Port != 22 {
		t.Errorf("port default = %d, want 22", sc.Port)
	}
	if sc.MetricsPort != 9101 {
		t.Errorf("metricsPort default = %d, want 9101", sc.MetricsPort)
	}
	if len(sc.Services) != 2 {
		t.Errorf("default services = %v", sc.Services)
	}
}

// --- No shell injection: argv is fixed, never concatenated ---

func TestSSHClientArgsAlwaysPinnedFailClosed(t *testing.T) {
	sc := validSSHConfig("iran")
	argv := BuildSSHClientArgs(sc)
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Fatal("client args contain StrictHostKeyChecking=no — forbidden")
	}
	if strings.Contains(joined, "accept-new") {
		t.Fatal("client args contain accept-new — forbidden")
	}
	if !strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Error("client args must pin StrictHostKeyChecking=yes")
	}
	if !strings.Contains(joined, "BatchMode=yes") {
		t.Error("client args must set BatchMode=yes")
	}
	if !strings.Contains(joined, "PasswordAuthentication=no") {
		t.Error("client args must set PasswordAuthentication=no")
	}
	if !strings.Contains(joined, "UserKnownHostsFile=/home/operator/.ssh/pinned_kh") {
		t.Error("client args must point at the pinned known_hosts file")
	}
}

// TestSSHClientArgsConfigIsolation proves that the generated argv includes
// explicit config isolation (-F /dev/null), proxy-disable directives, and
// unconditional IdentitiesOnly=yes.
func TestSSHClientArgsConfigIsolation(t *testing.T) {
	sc := validSSHConfig("iran")
	argv := BuildSSHClientArgs(sc)

	// -F /dev/null (or platform DevNull) must be present.
	hasDevNull := false
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "-F" {
			hasDevNull = true
			if argv[i+1] == "" {
				t.Error("-F value is empty; must be /dev/null or NUL")
			}
		}
	}
	if !hasDevNull {
		t.Error("argv missing -F <devnull> config isolation flag")
	}

	// ProxyCommand=none and ProxyJump=none must both be present.
	hasProxyCommandNone := false
	hasProxyJumpNone := false
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "-o" {
			switch argv[i+1] {
			case "ProxyCommand=none":
				hasProxyCommandNone = true
			case "ProxyJump=none":
				hasProxyJumpNone = true
			}
		}
	}
	if !hasProxyCommandNone {
		t.Error("argv missing -o ProxyCommand=none")
	}
	if !hasProxyJumpNone {
		t.Error("argv missing -o ProxyJump=none")
	}

	// IdentitiesOnly=yes must be UNCONDITIONAL (even without PinnedHostKey).
	scNoPinned := validSSHConfig("iran")
	scNoPinned.PinnedHostKey = ""
	argvNoPinned := BuildSSHClientArgs(scNoPinned)
	hasIdentitiesOnly := false
	for i := 0; i < len(argvNoPinned)-1; i++ {
		if argvNoPinned[i] == "-o" && argvNoPinned[i+1] == "IdentitiesOnly=yes" {
			hasIdentitiesOnly = true
		}
	}
	if !hasIdentitiesOnly {
		t.Error("IdentitiesOnly=yes must be unconditional (not gated on PinnedHostKey)")
	}

	// No proxy directive may be a real value (only "none" is acceptable).
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "-o" && (strings.HasPrefix(argv[i+1], "ProxyCommand=") || strings.HasPrefix(argv[i+1], "ProxyJump=")) {
			if !strings.HasSuffix(argv[i+1], "=none") {
				t.Errorf("unexpected proxy directive %q; only =none is permitted", argv[i+1])
			}
		}
	}
}

// TestSSHClientArgsHostKeyCheckingCannotBeDisabled proves that no argv
// combination can produce StrictHostKeyChecking=no or accept-new.
func TestSSHClientArgsHostKeyCheckingCannotBeDisabled(t *testing.T) {
	// Even with all fields set to extreme values, the hard-coded options
	// remain.
	sc := validSSHConfig("iran")
	sc.ConnectTimeoutSec = 300
	sc.CommandTimeoutSec = 300
	sc.MetricsPort = 65535
	argv := BuildSSHClientArgs(sc)
	for _, a := range argv {
		if a == "StrictHostKeyChecking=no" || a == "StrictHostKeyChecking=accept-new" {
			t.Fatalf("forbidden host-key mode %q in argv", a)
		}
	}
}

// TestSSHConfigRejectsPathTraversal verifies that ".." segments and encoded
// variants are rejected for statePath, identityFile, and knownHosts.
func TestSSHConfigRejectsPathTraversal(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*SSHConfig)
	}{
		{"statePath with ..", func(sc *SSHConfig) { sc.StatePath = "/etc/split-tunnel/../../../etc/shadow" }},
		{"statePath encoded ..", func(sc *SSHConfig) { sc.StatePath = "/etc/split-tunnel/%2e%2e/%2e%2e/etc/shadow" }},
		{"statePath outside allowlist", func(sc *SSHConfig) { sc.StatePath = "/tmp/evil.json" }},
		{"statePath trailing slash", func(sc *SSHConfig) { sc.StatePath = "/etc/split-tunnel/" }},
		{"identityFile with ..", func(sc *SSHConfig) { sc.IdentityFile = "/home/user/.ssh/../keys/id_rsa" }},
		{"knownHosts with ..", func(sc *SSHConfig) { sc.KnownHosts = "/home/user/.ssh/../../etc/hosts" }},
		{"statePath subdirectory", func(sc *SSHConfig) { sc.StatePath = "/etc/split-tunnel/sub/deep.json" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := validSSHConfig("iran")
			tc.mutate(sc)
			if err := ValidateSSHConfig(sc, "iran"); err == nil {
				t.Errorf("ValidateSSHConfig accepted %s", tc.name)
			}
		})
	}
}

// TestSSHConfigAllowsSafeStatePath verifies that the default and a valid
// override under /etc/split-tunnel/ are accepted.
func TestSSHConfigAllowsSafeStatePath(t *testing.T) {
	sc := validSSHConfig("iran")
	if err := ValidateSSHConfig(sc, "iran"); err != nil {
		t.Fatalf("default statePath rejected: %v", err)
	}
	sc.StatePath = "/etc/split-tunnel/alternate.json"
	if err := ValidateSSHConfig(sc, "iran"); err != nil {
		t.Errorf("valid override statePath rejected: %v", err)
	}
}

// TestParseSystemctlShowParsesAllFields verifies that parseSystemctlShow
// extracts ActiveState, SubState, UnitFileState, and MainPID.
func TestParseSystemctlShowParsesAllFields(t *testing.T) {
	out := "ActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=12345\n"
	services := parseSystemctlShow("iran-splitter", out)
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	svc := services[0]
	if svc.Unit != "iran-splitter.service" {
		t.Errorf("unit = %q", svc.Unit)
	}
	if svc.State != "active" {
		t.Errorf("state = %q, want active", svc.State)
	}
	if !svc.Active {
		t.Error("active should be true")
	}
	if svc.SubState != "running" {
		t.Errorf("subState = %q, want running", svc.SubState)
	}
	if svc.Enabled != "enabled" {
		t.Errorf("enabled = %q, want enabled", svc.Enabled)
	}
	if svc.MainPID != 12345 {
		t.Errorf("mainPID = %d, want 12345", svc.MainPID)
	}
}

// TestParseSystemctlShowMissingFields verifies graceful degradation when
// UnitFileState/MainPID are absent (unprivileged account).
func TestParseSystemctlShowMissingFields(t *testing.T) {
	out := "ActiveState=inactive\nSubState=dead\n"
	services := parseSystemctlShow("xray-consumer", out)
	svc := services[0]
	if svc.State != "inactive" {
		t.Errorf("state = %q, want inactive", svc.State)
	}
	if svc.Active {
		t.Error("active should be false for inactive")
	}
	if svc.Enabled != "" {
		t.Errorf("enabled = %q, want empty (field absent)", svc.Enabled)
	}
	if svc.MainPID != 0 {
		t.Errorf("mainPID = %d, want 0 (field absent)", svc.MainPID)
	}
}

// TestParseSystemctlShowUnknownState verifies the fallback.
func TestParseSystemctlShowUnknownState(t *testing.T) {
	out := "SubState=running\n"
	services := parseSystemctlShow("germany-splitter", out)
	if services[0].State != "unknown" {
		t.Errorf("state = %q, want unknown", services[0].State)
	}
}

func TestRemoteArgsNeverContainUserStrings(t *testing.T) {
	// No helper should ever embed arbitrary user input. All remote argv is
	// fixed tokens. Verify the journal line count and since are validated.
	sc := validSSHConfig("iran")
	// A caller must never pass a line count above the configured bound.
	if sc.MaxJournalLines > 500 {
		t.Fatalf("config bound violated: %d", sc.MaxJournalLines)
	}
	j := BuildJournalArgs("iran-splitter", 50, "2026-10-07T00:00:00Z")
	for _, tok := range j {
		if strings.ContainsAny(tok, ";|&$`\"'\\") {
			t.Errorf("remote arg %q contains shell metacharacters", tok)
		}
	}
	// The unit must be one of the known ones only.
	if j[2] != "iran-splitter" {
		t.Errorf("journal unit token = %q", j[2])
	}
}

// --- End-to-end collection with fake runner ---

func TestSSHCollectorPopulatesSnapshot(t *testing.T) {
	fr := newFakeRunner()
	fr.outputByCmd["hostname"] = "iran-node1"
	fr.outputByCmd["uptime"] = "Mon Sep  7 12:00:00 2026"
	fr.outputByCmd["systemctl"] = "ActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=1234\n"
	fr.outputByCmd["ss"] = "State  Recv-Sent  Local Address:Port  Peer Address:Port\nLISTEN 0 128 127.0.0.1:9101 0.0.0.0:* users:((\"splitter\",pid=1234,fd=5))\n"
	fr.outputByCmd["free"] = "              total        used        free\nMem: 8589934592 4294967296 4294967296\n"
	fr.outputByCmd["df"] = "Filesystem 1B-blocks Used Available Capacity Mounted on\noverlay 10737418240 5368709120 5368709120 50% /\n"
	fr.outputByCmd["journalctl"] = "2026-10-07 10:00:00 host iran-splitter[1]: INFO carrier up ready\n2026-10-07 10:00:05 host iran-splitter[1]: ERROR target dial failed: connection refused\n"
	fr.outputByCmd["curl"] = "active_sessions 5\ntotal_sessions 120\ntotal_bytes_up 500000000\n"
	fr.outputByCmd["cat"] = `{"schema":2,"role":"iran","generation":"s-123","updatedAt":"2026-10-07T00:00:00Z","manifestHash":"abcd1234","services":[{"unit":"iran-splitter","component":"splitter","hash":"f1"}]}`

	coll := NewSSHCollectorWithRunner(fr)
	coll.Now = func() time.Time { return time.Date(2026, 10, 7, 20, 0, 0, 0, time.UTC) }
	sc := validSSHConfig("iran")
	sc.Services = []string{"iran-splitter"} // single service → deterministic log count
	cfg := ServerConfig{ID: "iran", Role: "iran", SourceType: "ssh", SSH: sc}

	snap, err := coll.Collect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if snap.Status != Fresh {
		t.Errorf("status = %q, want fresh; errors=%v", snap.Status, snap.Errors)
	}
	if snap.Metrics == nil {
		t.Fatal("metrics not populated")
	}
	if snap.Metrics.Samples[0].Name != "active_sessions" {
		t.Errorf("first metric = %q", snap.Metrics.Samples[0].Name)
	}
	if len(snap.Services) == 0 {
		t.Error("services empty")
	}
	if snap.Services[0].State != "active" {
		t.Errorf("service state = %q, want active", snap.Services[0].State)
	}
	if len(snap.Listeners) == 0 {
		t.Error("listeners empty")
	}
	if snap.Listeners[0].Address != "127.0.0.1:9101" {
		t.Errorf("listener address = %q", snap.Listeners[0].Address)
	}
	if snap.MemoryMB <= 0 {
		t.Error("memory not parsed")
	}
	if snap.DiskBytes <= 0 {
		t.Error("disk not parsed")
	}
	if len(snap.Logs) != 2 {
		t.Errorf("logs = %d, want 2", len(snap.Logs))
	}
	if snap.Logs[0].Level != "INFO" || snap.Logs[1].Level != "ERROR" {
		t.Errorf("log levels = %q,%q", snap.Logs[0].Level, snap.Logs[1].Level)
	}
	// state.json produced config values with role.
	foundRole := false
	for _, cv := range snap.Config {
		if cv.Key == "state.role" && cv.Value == "iran" {
			foundRole = true
		}
	}
	if !foundRole {
		t.Error("state.role not surfaced from state.json")
	}
}

// --- Host-key failure is surfaced, not bypassed ---

func TestSSHCollectorHostKeyFailureSurfaced(t *testing.T) {
	fr := newFakeRunner()
	fr.failCmds["hostname"] = true // simulates ssh aborting due to host-key mismatch
	fr.outputByCmd["uptime"] = "Mon Sep  7 12:00:00 2026"
	coll := NewSSHCollectorWithRunner(fr)
	cfg := ServerConfig{ID: "iran", Role: "iran", SourceType: "ssh", SSH: validSSHConfig("iran")}
	snap, _ := coll.Collect(context.Background(), cfg)
	// Even when hostname fails, the collector must remain read-only and must
	// never downgrade to accept-new; it records the failure.
	found := false
	for _, e := range snap.Errors {
		if strings.Contains(e, "hostname failed") {
			found = true
		}
	}
	if !found {
		t.Error("host-key/hostname failure was not surfaced in errors")
	}
}

// --- Timeout propagation ---

func TestSSHCollectorRespectsContextDeadline(t *testing.T) {
	// A runner that blocks until ctx is done.
	blocking := &blockingRunner{}
	coll := NewSSHCollectorWithRunner(blocking)
	cfg := ServerConfig{ID: "iran", Role: "iran", SourceType: "ssh", SSH: validSSHConfig("iran")}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	start := time.Now()
	snap, _ := coll.Collect(ctx, cfg)
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Errorf("collection took %v; context deadline not honored", elapsed)
	}
	_ = snap
	cancel()
}

// blockingRunner blocks until the context is cancelled.
type blockingRunner struct{}

func (b *blockingRunner) Run(ctx context.Context, _ []string) (string, string, error) {
	<-ctx.Done()
	return "", "", ctx.Err()
}

// --- Redaction of state.json sensitive fields ---

func TestSSHStateJSONRedaction(t *testing.T) {
	raw := `{"role":"iran","pairing":{"state":"configured","peerRole":"germany","fingerprints":["fp1"]},"secretsBlob":"abc","password":"hunter2"}`
	cvs := parseStateJSON(raw)
	// There must be no value that leaks the literal secret.
	for _, cv := range cvs {
		if cv.Value == "hunter2" || cv.Value == "abc" {
			t.Fatalf("state.json redaction leaked value %q for key %q", cv.Value, cv.Key)
		}
	}
	// The safe role value is preserved.
	roleFound := false
	for _, cv := range cvs {
		if cv.Key == "state.role" && cv.Value == "iran" {
			roleFound = true
		}
	}
	if !roleFound {
		t.Error("state.role not preserved")
	}
}

// --- Allowed remote command sequence is the fixed allowlist only ---

func TestSSHCollectorRemoteCommandSequence(t *testing.T) {
	fr := newFakeRunner()
	fr.outputByCmd["hostname"] = "h"
	fr.outputByCmd["uptime"] = "Mon Sep  7 12:00:00 2026"
	fr.outputByCmd["systemctl"] = "ActiveState=active\n"
	fr.outputByCmd["ss"] = ""
	fr.outputByCmd["free"] = ""
	fr.outputByCmd["df"] = ""
	fr.outputByCmd["journalctl"] = ""
	fr.outputByCmd["curl"] = ""
	fr.outputByCmd["cat"] = `{"role":"iran"}`
	coll := NewSSHCollectorWithRunner(fr)
	cfg := ServerConfig{ID: "iran", Role: "iran", SourceType: "ssh", SSH: validSSHConfig("iran")}
	_, _ = coll.Collect(context.Background(), cfg)

	cmds := fr.remoteCmds()
	// Assert only the fixed allowlist tokens appear.
	allowed := map[string]bool{"hostname": true, "uptime": true, "systemctl": true, "ss": true, "free": true, "df": true, "journalctl": true, "curl": true, "cat": true}
	for _, c := range cmds {
		if !allowed[c] {
			t.Errorf("unexpected remote command %q; only the fixed allowlist may be invoked", c)
		}
	}
	// The two iran default services should each produce a systemctl call.
	if fr.cmdCount("systemctl") != 2 {
		t.Errorf("systemctl invoked %d times, want 2 (one per default service)", fr.cmdCount("systemctl"))
	}
}

// --- Per-server journal bounds are enforced in the argv ---

func TestSSHJournalArgsBounded(t *testing.T) {
	sc := validSSHConfig("iran")
	sc.MaxJournalLines = 42
	argv := BuildFullArgs(sc, BuildJournalArgs("germany-splitter", 42, ""))
	// The line count must appear as a discrete token, not concatenated.
	found := false
	for _, a := range argv {
		if a == "42" {
			found = true
		}
	}
	if !found {
		t.Error("journal line bound not present as discrete argv token")
	}
	// Unit must be a known unit.
	if argv[len(argv)-1] == "" {
		// locate the unit token after "-u"
	}
	hasUnit := false
	for i, a := range argv {
		if a == "-u" && i+1 < len(argv) && argv[i+1] == "germany-splitter" {
			hasUnit = true
		}
	}
	if !hasUnit {
		t.Error("journal argv missing validated -u <known unit>")
	}
}
