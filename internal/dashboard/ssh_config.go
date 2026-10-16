package dashboard

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// KnownUnits is the strict allowlist of systemd service names the SSH
// collector may ever query. No other unit name is accepted anywhere in the
// remote command surface. This mirrors the four deployment units:
//   - iran-splitter, germany-splitter (the two splitter services)
//   - xray-consumer, xray-germany (the two xray services)
var KnownUnits = []string{"iran-splitter", "germany-splitter", "xray-consumer", "xray-germany"}

// defaultStatePath is the only sensible default for the read-only state file.
// Operators may override it to another /etc/split-tunnel/ path, but the value
// is always validated against a strict absolute-path charset so it can never
// become a shell injection or path traversal vector.
const defaultStatePath = "/etc/split-tunnel/state.json"

// defaultMetricsPort is the SPLIT_METRICS_PORT default used when an operator
// does not configure one. The collector curls this loopback port only.
const defaultMetricsPort = 9101

// SSHConfig is the strict, per-server configuration for the read-only SSH
// collector. It is used ONLY when a server's SourceType is "ssh" and an
// explicit, complete sub-config is provided.
//
// Security invariants enforced by ValidateSSHConfig / BuildSSHClientArgs:
//
//   - Host keys are always pinned and verified: StrictHostKeyChecking is
//     hard-coded to "yes" and a pinned known_hosts path is REQUIRED. The
//     values "no" and "accept-new" are never produced, so an unknown or
//     changed host key fails the connection closed.
//   - BatchMode=yes and PasswordAuthentication=no: no interactive prompt and
//     no password auth are ever attempted.
//   - Config isolation: -F /dev/null disables all user/system SSH config
//     file reading. ProxyCommand and ProxyJump are explicitly set to "none".
//     IdentitiesOnly=yes is unconditional.
//   - No arbitrary remote command string is ever accepted. The collector
//     only ever runs the fixed allowlist built by the Build*Args helpers,
//     with service names, line counts, and since-windows validated here.
//   - The configured SSH user is expected to be an unprivileged account.
//     Details that require privilege (process PIDs from `ss -tlnp`, some
//     systemctl/journal fields) are surfaced as optional and may simply be
//     absent; the collector never escalates.
type SSHConfig struct {
	// User is the unprivileged SSH login account on the remote host.
	User string `json:"user"`
	// Address is the SSH host (hostname or IP). It may differ from the
	// server's public data-plane address.
	Address string `json:"address"`
	// Port is the SSH port; 0 means default 22.
	Port int `json:"port,omitempty"`
	// IdentityFile is the local path to the private key used for auth.
	// It is referenced by path only; its contents are never read into the
	// dashboard or logged.
	IdentityFile string `json:"identityFile"`
	// KnownHosts is the local path to a pinned known_hosts file. REQUIRED:
	// host-key verification always runs against this file.
	KnownHosts string `json:"knownHosts"`
	// PinnedHostKey optionally records the expected host public key
	// (e.g. "ssh-ed25519 AAAAC3...") for audit. When set it MUST also be
	// present in KnownHosts for verification to succeed. It is never used
	// to bypass verification.
	PinnedHostKey string `json:"pinnedHostKey,omitempty"`
	// ConnectTimeoutSec bounds the ssh connection; default 10, 1..300.
	ConnectTimeoutSec int `json:"connectTimeoutSec,omitempty"`
	// CommandTimeoutSec bounds every individual remote command via
	// exec.CommandContext; default 15, 1..300.
	CommandTimeoutSec int `json:"commandTimeoutSec,omitempty"`
	// MetricsPort is the loopback /metrics port on the remote host that
	// `curl` reads; default 9101, 1..65535.
	MetricsPort int `json:"metricsPort,omitempty"`
	// StatePath is the state file `cat` reads; default
	// /etc/split-tunnel/state.json. Must be absolute and free of shell
	// metacharacters or path traversal.
	StatePath string `json:"statePath,omitempty"`
	// MaxJournalLines bounds `journalctl -n`; default 200, 1..500.
	MaxJournalLines int `json:"maxJournalLines,omitempty"`
	// MaxJournalSinceSec bounds the `--since` window; default 600, 0..86400.
	// A value of 0 disables the since window (line bound still applies).
	MaxJournalSinceSec int `json:"maxJournalSinceSec,omitempty"`
	// Services is the explicit subset of KnownUnits to query. When empty it
	// defaults to the role-appropriate units (see defaultServicesForRole).
	Services []string `json:"services,omitempty"`
}

// CommandRunner executes a fully-formed argv vector (never a shell string)
// and returns captured stdout/stderr. It is the injection point that lets
// tests substitute a fake and guarantee no real ssh is ever run.
//
// Implementations must:
//   - run the exact argv without a shell (no "-c", no "sh -c").
//   - respect ctx cancellation and per-command deadlines.
//   - never write secrets to stdout that they return.
type CommandRunner interface {
	Run(ctx context.Context, argv []string) (stdout, stderr string, err error)
}

// ExecCommandRunner is the production CommandRunner. It executes the ssh
// binary with the exact argv supplied. The remote command is passed as
// discrete argv elements, so no user-controlled string is ever concatenated
// into a shell.
type ExecCommandRunner struct {
	// SSHBin is the ssh executable; empty means "ssh" from PATH.
	SSHBin string
}

// Run implements CommandRunner via exec.CommandContext.
func (e ExecCommandRunner) Run(ctx context.Context, argv []string) (string, string, error) {
	bin := e.SSHBin
	if bin == "" {
		bin = "ssh"
	}
	cmd := exec.CommandContext(ctx, bin, argv...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	return out.String(), errOut.String(), err
}

// sshUserPattern allows normal usernames without any shell metacharacters.
var sshUserPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// sshHostPattern allows hostnames and IPv4/IPv6 literals; no colons (port is
// separate) or whitespace.
var sshHostPattern = regexp.MustCompile(`^[A-Za-z0-9._\-\[\]:]{1,255}$`)

// sshPathPattern allows an absolute path with no shell/whitespace injection.
// It permits only alphanumerics, dots, underscores, hyphens, and forward
// slashes. A leading "/" is required; no relative segments.
var sshPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)

// sshStatePathPrefix is the only allowed directory root for statePath
// overrides. The default is /etc/split-tunnel/state.json; operators may
// point to another file under /etc/split-tunnel/ but nothing else.
const sshStatePathPrefix = "/etc/split-tunnel/"

// validateSSPath enforces the safe-path invariants for any SSH config path
// field (identityFile, knownHosts):
//   - must match sshPathPattern (absolute, safe charset)
//   - must NOT contain ".." as a path segment (traversal)
//   - must NOT end with a trailing slash
func validateSSPath(p, field string) error {
	if !sshPathPattern.MatchString(p) {
		return fmt.Errorf("dashboard: ssh %s %q must be an absolute path with no shell metacharacters", field, p)
	}
	// Reject any ".." path segment.
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("dashboard: ssh %s %q contains a parent-dir segment '..' which is forbidden", field, p)
		}
	}
	// Reject trailing slash (e.g. "/etc/foo/")
	if strings.HasSuffix(p, "/") && p != "/" {
		return fmt.Errorf("dashboard: ssh %s %q must not end with a trailing slash", field, p)
	}
	return nil
}

// validateStatePath enforces the statePath invariants on top of validateSSPath:
//   - must be the default /etc/split-tunnel/state.json, OR
//   - must be a file path directly under /etc/split-tunnel/ (no subdirs)
func validateStatePath(p string) error {
	if err := validateSSPath(p, "statePath"); err != nil {
		return err
	}
	if p == defaultStatePath {
		return nil
	}
	// Must be directly under /etc/split-tunnel/ with a simple filename.
	if !strings.HasPrefix(p, sshStatePathPrefix) {
		return fmt.Errorf("dashboard: ssh statePath %q must be %q or a file directly under %s", p, defaultStatePath, sshStatePathPrefix)
	}
	rel := strings.TrimPrefix(p, sshStatePathPrefix)
	// No subdirectories, no extra slashes.
	if strings.Contains(rel, "/") || rel == "" {
		return fmt.Errorf("dashboard: ssh statePath %q must be a file directly under %s (no subdirectories)", p, sshStatePathPrefix)
	}
	return nil
}

// pinnedKeyPattern loosely validates an OpenSSH host public key line.
var pinnedKeyPattern = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-(nistp256|nistp384|nistp521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+[A-Za-z0-9+/=]+`)

// IsValidUnit reports whether u is one of the four deployment units.
func IsValidUnit(u string) bool {
	for _, k := range KnownUnits {
		if u == k {
			return true
		}
	}
	return false
}

// defaultServicesForRole returns the role-appropriate default units.
func defaultServicesForRole(role string) []string {
	if role == "germany" {
		return []string{"germany-splitter", "xray-germany"}
	}
	return []string{"iran-splitter", "xray-consumer"}
}

// ValidateSSHConfig validates and normalizes an SSHConfig in place, returning
// an error describing the first invariant violation. It is fail-closed: any
// missing pin, forbidden strict-mode value, or out-of-range bound is an error.
func ValidateSSHConfig(sc *SSHConfig, role string) error {
	if sc == nil {
		return fmt.Errorf("dashboard: ssh config is nil")
	}

	if !sshUserPattern.MatchString(sc.User) {
		return fmt.Errorf("dashboard: ssh user %q must match [A-Za-z0-9._-]{1,64}", sc.User)
	}
	if !sshHostPattern.MatchString(sc.Address) {
		return fmt.Errorf("dashboard: ssh address %q is not a valid host (no spaces, no shell metacharacters)", sc.Address)
	}
	if sc.Port == 0 {
		sc.Port = 22
	}
	if sc.Port < 1 || sc.Port > 65535 {
		return fmt.Errorf("dashboard: ssh port %d out of range 1..65535", sc.Port)
	}

	if sc.IdentityFile == "" {
		return fmt.Errorf("dashboard: ssh identityFile is required (referenced by path, never read here)")
	}
	if err := validateSSPath(sc.IdentityFile, "identityFile"); err != nil {
		return err
	}

	// Host-key pinning is mandatory and fail-closed.
	if sc.KnownHosts == "" {
		return fmt.Errorf("dashboard: ssh knownHosts (pinned host-key file) is required; StrictHostKeyChecking=no is never permitted")
	}
	if err := validateSSPath(sc.KnownHosts, "knownHosts"); err != nil {
		return err
	}
	if sc.PinnedHostKey != "" {
		if !pinnedKeyPattern.MatchString(strings.TrimSpace(sc.PinnedHostKey)) {
			return fmt.Errorf("dashboard: ssh pinnedHostKey must be an OpenSSH host public key line")
		}
	}

	if sc.ConnectTimeoutSec == 0 {
		sc.ConnectTimeoutSec = 10
	}
	if sc.ConnectTimeoutSec < 1 || sc.ConnectTimeoutSec > 300 {
		return fmt.Errorf("dashboard: ssh connectTimeoutSec %d out of range 1..300", sc.ConnectTimeoutSec)
	}
	if sc.CommandTimeoutSec == 0 {
		sc.CommandTimeoutSec = 15
	}
	if sc.CommandTimeoutSec < 1 || sc.CommandTimeoutSec > 300 {
		return fmt.Errorf("dashboard: ssh commandTimeoutSec %d out of range 1..300", sc.CommandTimeoutSec)
	}
	if sc.MetricsPort == 0 {
		sc.MetricsPort = defaultMetricsPort
	}
	if sc.MetricsPort < 1 || sc.MetricsPort > 65535 {
		return fmt.Errorf("dashboard: ssh metricsPort %d out of range 1..65535", sc.MetricsPort)
	}
	if sc.StatePath == "" {
		sc.StatePath = defaultStatePath
	}
	if err := validateStatePath(sc.StatePath); err != nil {
		return err
	}

	if sc.MaxJournalLines == 0 {
		sc.MaxJournalLines = 200
	}
	if sc.MaxJournalLines < 1 || sc.MaxJournalLines > 500 {
		return fmt.Errorf("dashboard: ssh maxJournalLines %d out of range 1..500", sc.MaxJournalLines)
	}
	if sc.MaxJournalSinceSec < 0 || sc.MaxJournalSinceSec > 86400 {
		return fmt.Errorf("dashboard: ssh maxJournalSinceSec %d out of range 0..86400", sc.MaxJournalSinceSec)
	}

	if len(sc.Services) == 0 {
		sc.Services = defaultServicesForRole(role)
	}
	for _, u := range sc.Services {
		if !IsValidUnit(u) {
			return fmt.Errorf("dashboard: ssh services contains unknown unit %q; allowed: %s", u, strings.Join(KnownUnits, ", "))
		}
	}
	return nil
}

// BuildSSHClientArgs returns the ssh client argv (options + user@host, before
// the remote command). It hard-codes the secure option set. The result is
// shared by every query; it never contains a remote command string.
//
// Config isolation:
//   - "-F "+os.DevNull disables ALL user/system SSH config file reading
//     (no ~/.ssh/config, no /etc/ssh/ssh_config), so no ProxyCommand,
//     ProxyJump, HostKeyAlias, or any other inherited option can leak in.
//     On Linux/macOS this is /dev/null; on Windows it is NUL.
//   - "ProxyCommand=none" and "ProxyJump=none" are set explicitly so that
//     even if a config file were somehow read, no proxy directive is active.
//   - "IdentitiesOnly=yes" is UNCONDITIONAL: only the explicitly provided
//     -i key is used; no agent keys, no config-file identity files.
//
// Host-key verification:
//   - StrictHostKeyChecking=yes is hard-coded. The values "no" and
//     "accept-new" are NEVER produced.
//   - UserKnownHostsFile is always the pinned path; no fallback to
//     ~/.ssh/known_hosts.
func BuildSSHClientArgs(sc *SSHConfig) []string {
	argv := []string{
		// Config isolation: neutralize user/system SSH configuration.
		// os.DevNull resolves to /dev/null (Linux/macOS) or NUL (Windows).
		// The SSH collector is designed for Linux-only deployment (the
		// remote commands are Linux systemctl/ss/free/df/journalctl).
		"-F", os.DevNull,
		// Explicitly disable proxy directives (defence in depth even though
		// -F already prevents config inheritance).
		"-o", "ProxyCommand=none",
		"-o", "ProxyJump=none",
		// Identity isolation: only the explicitly provided key is used.
		// UNCONDITIONAL — not gated on PinnedHostKey.
		"-i", sc.IdentityFile,
		"-o", "IdentitiesOnly=yes",
		// No interactive prompts, no password auth.
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		// Fail closed on any host-key that is not in the pinned file.
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + sc.KnownHosts,
		"-o", "ConnectTimeout=" + strconv.Itoa(sc.ConnectTimeoutSec),
	}
	if sc.Port != 22 {
		argv = append(argv, "-p", strconv.Itoa(sc.Port))
	}
	argv = append(argv, fmt.Sprintf("%s@%s", sc.User, sc.Address))
	return argv
}

// BuildFullArgs concatenates the ssh client args with a fixed remote command.
func BuildFullArgs(sc *SSHConfig, remote []string) []string {
	argv := BuildSSHClientArgs(sc)
	return append(argv, remote...)
}

// BuildHostnameArgs is the fixed argv for `hostname`.
func BuildHostnameArgs() []string { return []string{"hostname"} }

// BuildUptimeArgs is the fixed argv for `uptime -s`.
func BuildUptimeArgs() []string { return []string{"uptime", "-s"} }

// BuildSystemctlArgs is the fixed argv for `systemctl show <unit> -p <props>`.
// unit MUST already be validated with IsValidUnit by the caller.
func BuildSystemctlArgs(unit string) []string {
	return []string{"systemctl", "show", unit, "-p", "ActiveState,SubState,UnitFileState,MainPID"}
}

// BuildSSArgs is the fixed argv for `ss -tlnp`.
func BuildSSArgs() []string { return []string{"ss", "-tlnp"} }

// BuildFreeArgs is the fixed argv for `free -b`.
func BuildFreeArgs() []string { return []string{"free", "-b"} }

// BuildDFArgs is the fixed argv for `df -B1 /`.
func BuildDFArgs() []string { return []string{"df", "-B1", "/"} }

// BuildJournalArgs is the fixed argv for a bounded `journalctl` query.
// unit MUST be IsValidUnit; lines MUST be within 1..500; since MUST be an
// RFC3339 string (possibly empty). No free-form string is accepted.
func BuildJournalArgs(unit string, lines int, since string) []string {
	argv := []string{"journalctl", "-u", unit, "-n", strconv.Itoa(lines), "--no-pager", "-q", "-o", "short-iso"}
	if since != "" {
		argv = append(argv, "--since", since)
	}
	return argv
}

// BuildMetricsArgs is the fixed argv that curls the remote loopback metrics
// port with a hard timeout. The address is always the remote loopback
// (127.0.0.1 on the host), so it can never reach a non-local endpoint.
func BuildMetricsArgs(sc *SSHConfig) []string {
	return []string{
		"curl", "-sS", "--max-time", strconv.Itoa(sc.ConnectTimeoutSec),
		fmt.Sprintf("http://127.0.0.1:%d/metrics", sc.MetricsPort),
	}
}

// BuildStateArgs is the fixed argv that cats the state file (path validated
// in ValidateSSHConfig so it can never traverse or inject).
func BuildStateArgs(sc *SSHConfig) []string {
	return []string{"cat", sc.StatePath}
}
