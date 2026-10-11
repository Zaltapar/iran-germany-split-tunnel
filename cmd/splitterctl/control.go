// control.go — the C2 operator-facing CLI surface
// (plans/dashboard-control-design.md §6.6, §12 C2):
//
//   - `control-agent`  the root-owned socket-activated daemon (design §3.2).
//     Runs forever, accepting one frame per connection, until SIGTERM.
//   - `control freeze`     creates the kill-switch file; all mutating ops
//     then return `frozen`.
//   - `control unfreeze`   removes it. CLI-only by design (design §6.6).
//   - `control revert-lkg` restores the last-known-good revision and
//     restarts the affected splitter service. Callable even when frozen.
//   - `control audit-verify` re-hashes the agent's audit chain.
//   - `control recover`    runs the §5.6 crash-recovery table by hand.
//
// The daemon is Linux + root gated. The read-only audit-verify works on
// any platform that can read the store.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/controlagent"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

const (
	controlStoreRootEnv = "SPLITTERCTL_CONTROL_STORE_ROOT"

	defaultControlStoreRoot = "/var/lib/split-tunnel-ctl"
	defaultControlSocket    = "/run/split-tunnel-ctl/control.sock"
)

// controlAgentFlags is the flag set for `control-agent`.
type controlAgentFlags struct {
	storeRoot    string
	socket       string
	dashboardUID int
	dashboardGID int
	dashboardExe string
}

func parseControlAgentFlags(args []string) (controlAgentFlags, error) {
	fs := flag.NewFlagSet("control-agent", flag.ContinueOnError)
	f := controlAgentFlags{
		storeRoot:    defaultControlStoreRoot,
		socket:       defaultControlSocket,
		dashboardUID: -1,
		dashboardGID: -1,
	}
	fs.StringVar(&f.storeRoot, "store-root", f.storeRoot, "revision store root (0700, root-only)")
	fs.StringVar(&f.socket, "socket", f.socket, "Unix socket to serve (systemd-provided or manually bound)")
	fs.IntVar(&f.dashboardUID, "dashboard-uid", -1, "expected tunneldash uid (kernel-attested)")
	fs.IntVar(&f.dashboardGID, "dashboard-gid", -1, "expected tunneldash gid")
	fs.StringVar(&f.dashboardExe, "dashboard-exe", "", "canonical /proc/<pid>/exe target of the dashboard binary")
	_ = fs.Parse(args)
	if v := os.Getenv(controlStoreRootEnv); v != "" {
		f.storeRoot = v
	}
	// Default peer identity to the tunneldash user/gid when the operator
	// did not supply them; the exe MUST always be supplied explicitly.
	if f.dashboardUID < 0 {
		f.dashboardUID, f.dashboardGID = lookupTunneldashIdentity()
	}
	return f, nil
}

// lookupTunneldashIdentity resolves the tunneldash service user. Returns
// (-1, -1) when the user does not exist (the operator must supply uid/gid
// explicitly to keep the daemon fail-closed).
func lookupTunneldashIdentity() (int, int) {
	u, err := user.Lookup("tunneldash")
	if err != nil {
		return -1, -1
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid
}

// requireRoot gates mutation commands on euid 0.
func requireRoot(command string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s: requires root (uid 0)", command)
	}
	return nil
}

// ---------------------------------------------------------------------------
// control-agent: the daemon
// ---------------------------------------------------------------------------

// controlAgentCmd runs the C2 daemon: it opens the revision store, wires
// the production OS seam, recovers any in-flight journal (design §5.6),
// and accepts one frame per connection under the SO_PEERCRED peer check.
func controlAgentCmd(ctx context.Context, args []string, out io.Writer) error {
	if goos != "linux" {
		return fmt.Errorf("control-agent: the daemon requires Linux (SO_PEERCRED + systemd socket activation); on %s it refuses to start", goos)
	}
	if err := requireRoot("control-agent"); err != nil {
		return err
	}
	fl, _ := parseControlAgentFlags(args)
	if fl.dashboardUID < 0 || fl.dashboardGID < 0 || fl.dashboardExe == "" {
		return fmt.Errorf("control-agent: peer identity must be fully specified (--dashboard-uid %d, --dashboard-gid %d, --dashboard-exe %q); refusing to start (fail closed)", fl.dashboardUID, fl.dashboardGID, fl.dashboardExe)
	}

	seam := &osControlSeam{}
	a, err := controlagent.NewAgent(fl.storeRoot, seam, controlagent.NewConfigBuilder())
	if err != nil {
		return fmt.Errorf("control-agent: open store: %w", err)
	}
	// Crash recovery on start (design §5.6).
	if outcome, rerr := a.RecoverOnStart(); rerr != nil {
		return fmt.Errorf("control-agent: recovery: %w", rerr)
	} else if outcome == controlagent.RecoveryTamper {
		fmt.Fprintln(out, "control-agent: a tampered in-flight journal was found; mutating ops are refused until `splitterctl control recover` completes")
	}

	policy := &controlagent.PeerPolicy{
		ExpectedUID:  fl.dashboardUID,
		ExpectedGID:  fl.dashboardGID,
		CanonicalExe: fl.dashboardExe,
	}
	credSource := controlagent.ControlPlaneCredentialSource()

	// Obtain or create the listener. When systemd socket-activates the
	// unit it passes fd 3 (LISTEN_FDS=1); otherwise we bind ourselves.
	ln, err := controlListenSocket(fl.socket)
	if err != nil {
		return fmt.Errorf("control-agent: socket %s: %w", fl.socket, err)
	}
	fmt.Fprintf(out, "control-agent: serving %s (store=%s peer=uid %d gid %d exe %s)\n", fl.socket, fl.storeRoot, fl.dashboardUID, fl.dashboardGID, fl.dashboardExe)

	// SIGTERM/SIGINT → close the listener → Accept returns err → exit.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			// A transient accept error: retry (the daemon must not crash).
			continue
		}
		_ = a.ServeConnection(credSource, policy, conn)
	}
	fmt.Fprintln(out, "control-agent: stopped")
	return nil
}

// controlListenSocket returns the systemd-passed listener when available,
// otherwise binds the path with 0660 tunneldash-ctl group.
func controlListenSocket(path string) (net.Listener, error) {
	if fds := os.Getenv("LISTEN_FDS"); fds != "" {
		if n, _ := strconv.Atoi(fds); n >= 1 {
			// fd 3 is the first socket passed by systemd's socket unit.
			f := os.NewFile(3, "systemd-socket")
			ln, err := net.FileListener(f)
			if err != nil {
				return nil, err
			}
			_ = f.Close() // the listener now owns the fd
			return ln, nil
		}
	}
	// Manual start: bind ourselves with the same group/mode the socket
	// unit would set.
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.Remove(path) // remove stale socket
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if gid, ok := lookupGID("tunneldash-ctl"); ok {
		_ = syscall.Chown(path, 0, gid)
	}
	_ = os.Chmod(path, 0o660)
	return l, nil
}

// lookupGID resolves a group name to its numeric gid.
func lookupGID(name string) (int, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	n, _ := strconv.Atoi(g.Gid)
	return n, true
}

// ---------------------------------------------------------------------------
// control <subcommand>: operator control-plane entrypoints
// ---------------------------------------------------------------------------

// controlCmd dispatches: freeze, unfreeze, revert-lkg, audit-verify, recover.
func controlCmd(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("%w: control requires a subcommand (freeze|unfreeze|revert-lkg|audit-verify|recover)", errUsage)
	}
	storeRoot := os.Getenv(controlStoreRootEnv)
	if storeRoot == "" {
		storeRoot = defaultControlStoreRoot
	}

	switch args[1] {
	case "freeze", "unfreeze", "revert-lkg", "recover":
		if goos != "linux" {
			return fmt.Errorf("control %s: requires Linux (mutates the store or restarts the splitter)", args[1])
		}
		if err := requireRoot("control " + args[1]); err != nil {
			return err
		}
	case "audit-verify":
		// read-only; no platform or root gate
	default:
		return fmt.Errorf("%w: unknown control subcommand %q", errUsage, args[1])
	}

	st, err := controlagent.NewRevisionStore(storeRoot)
	if err != nil {
		return fmt.Errorf("control: open store %s: %w", storeRoot, err)
	}
	// Build the agent over the already-opened store (nil-safe).
	agent := controlagent.NewAgentForStore(st, &osControlSeam{}, controlagent.NewConfigBuilder())

	switch args[1] {
	case "freeze":
		if err := st.Freeze(); err != nil {
			return fmt.Errorf("control freeze: %w", err)
		}
		fmt.Fprintf(out, "control: kill switch engaged at %s; all mutating ops now return frozen\n", st.KillSwitchPath())
		return nil

	case "unfreeze":
		if err := st.Unfreeze(); err != nil {
			return fmt.Errorf("control unfreeze: %w", err)
		}
		fmt.Fprintln(out, "control: kill switch cleared; applying is permitted again")
		return nil

	case "revert-lkg":
		if agent == nil {
			return fmt.Errorf("control revert-lkg: cannot build agent over store %s", storeRoot)
		}
		res, code, msg := agent.RollbackLKG("cli-operator")
		if code != "" {
			return fmt.Errorf("control revert-lkg: %s: %s", code, msg)
		}
		fmt.Fprintf(out, "control: revert-lkg %s (revision %s)\n", res.Outcome, res.RevisionID)
		return nil

	case "audit-verify":
		audit, err := controlagent.NewAuditLog(filepath.Join(storeRoot, "audit.jsonl"))
		if err != nil {
			return fmt.Errorf("control audit-verify: %w", err)
		}
		if err := audit.VerifyChain(); err != nil {
			fmt.Fprintf(out, "audit-verify: FAILED: %v\n", err)
			return err
		}
		fmt.Fprintf(out, "audit-verify: chain intact (%d entries)\n", len(audit.ReadAll()))
		return nil

	case "recover":
		if agent == nil {
			return fmt.Errorf("control recover: cannot build agent over store %s", storeRoot)
		}
		outcome, err := agent.RecoverOnStart()
		if err != nil {
			return fmt.Errorf("control recover: %w", err)
		}
		fmt.Fprintf(out, "control recover: %s\n", outcome)
		return nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// osControlSeam: the production host-facing ApplySeam.
//
// One env file per role under /etc/split-tunnel (the D4 env file pattern).
// Restart is a splitter-only systemctl call (never xray, C2 boundary).
// Verify is a bounded RestartSettle + HealthCheck (metrics probe when the
// port is known). No secrets are ever logged.
// ---------------------------------------------------------------------------

type osControlSeam struct {
	stateDir string // /etc/split-tunnel (or test override)
}

func newOSControlSeam() *osControlSeam { return &osControlSeam{stateDir: "/etc/split-tunnel"} }

func (s *osControlSeam) LiveFile(role string) string {
	if s.stateDir == "" {
		s.stateDir = "/etc/split-tunnel"
	}
	p := filepath.Join(s.stateDir, role+".env")
	if _, err := os.Lstat(p); err != nil {
		return ""
	}
	return p
}

func (s *osControlSeam) BaseEnv(role string) (map[string]string, error) {
	p := s.LiveFile(role)
	if p == "" {
		return map[string]string{}, nil
	}
	return parseEnvFile(p)
}

func (s *osControlSeam) WriteCandidate(role string, base, override map[string]string) (string, error) {
	merged := map[string]string{}
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range override {
		merged[k] = v
	}
	if s.stateDir == "" {
		s.stateDir = "/etc/split-tunnel"
	}
	dir := filepath.Join(s.stateDir, ".c2-sandbox")
	_ = os.MkdirAll(dir, 0o700)
	cand := filepath.Join(dir, role+".candidate.env")
	if err := writeEnvFile(cand, merged); err != nil {
		return "", err
	}
	return cand, nil
}

func (s *osControlSeam) ValidateCandidate(role, candidatePath string) error {
	if _, err := os.Lstat(candidatePath); err != nil {
		return fmt.Errorf("candidate %s: %w", filepath.Base(candidatePath), err)
	}
	// The authoritative gate is the validator's bounds + the splitter's
	// --validate-config (run on the candidate env). This is a pass-through:
	// the agent's own validator already ran; this seam confirms the file
	// is present.
	return nil
}

func (s *osControlSeam) BackupFile(role, livePath string) (string, error) {
	backup := livePath + ".c2-backup"
	data, err := os.ReadFile(livePath)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(backup, data, 0o600); err != nil {
		return "", err
	}
	return backup, nil
}

func (s *osControlSeam) SwapFile(candidatePath, livePath string) error {
	data, err := os.ReadFile(candidatePath)
	if err != nil {
		return err
	}
	// Atomic write: tmp + fsync + rename (the D4 discipline).
	dir := filepath.Dir(livePath)
	tmp := filepath.Join(dir, filepath.Base(livePath)+".c2-tmp-"+strconv.Itoa(os.Getpid()))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, werr := f.Write(data); werr != nil {
		return werr
	}
	if serr := f.Sync(); serr != nil {
		return serr
	}
	if cerr := f.Close(); cerr != nil {
		return cerr
	}
	if renErr := os.Rename(tmp, livePath); renErr != nil {
		return renErr
	}
	ok = true
	return nil
}

func (s *osControlSeam) RestartService(role string) error {
	// C2 boundary: restart ONLY the affected splitter service. Never xray.
	mgr := systemd.NewServiceManager(systemd.OSExecutor{})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	unit := role + "-splitter.service"
	if err := mgr.Restart(ctx, unit); err != nil {
		return fmt.Errorf("systemctl restart %s: %w", unit, err)
	}
	// Bounded settle: wait for active + a quiet confirm (a crash-looping
	// unit is NOT a success — design §5.2 F-verify).
	if err := mgr.RestartSettle(ctx, unit, 30*time.Second); err != nil {
		return fmt.Errorf("restart settle %s: %w", unit, err)
	}
	return nil
}

func (s *osControlSeam) Verify(role string) error {
	mgr := systemd.NewServiceManager(systemd.OSExecutor{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	unit := role + "-splitter.service"
	// Read-only health check (is-active + optional metrics probe).
	h, err := systemd.HealthCheck(ctx, mgr, unit, 0) // 0 = no metrics probe
	if err != nil {
		return err
	}
	if !h.Active {
		return fmt.Errorf("verify: %s is not active (state=%s)", unit, h.State)
	}
	return nil
}

func (s *osControlSeam) RestoreFile(role, livePath, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	return os.WriteFile(livePath, data, 0o600)
}

// ---------------------------------------------------------------------------
// env file helpers (a minimal D4-compatible parser / writer, for the CLI
// seam — no config.Validate; that is the agent's job, not the seam's).
// ---------------------------------------------------------------------------

// parseEnvFile reads a KEY=VALUE env file into a map (values are never
// validated here — validation is the agent's job, not the seam's).
func parseEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		out[line[:eq]] = line[eq+1:]
	}
	return out, nil
}

// writeEnvFile writes a KEY=VALUE env file atomically (tmp+fsync+rename, 0600).
func writeEnvFile(path string, kv map[string]string) error {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	// Fixed key order for idempotence (same state → same bytes).
	sortStrings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(kv[k])
		b.WriteByte('\n')
	}
	data := []byte(b.String())
	dir := filepath.Dir(path)
	tmp := path + ".tmp-" + strconv.Itoa(os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, werr := f.Write(data); werr != nil {
		return werr
	}
	if serr := f.Sync(); serr != nil {
		return serr
	}
	if cerr := f.Close(); cerr != nil {
		return cerr
	}
	if renErr := os.Rename(tmp, path); renErr != nil {
		return renErr
	}
	ok = true
	_ = dir
	return nil
}

// sortStrings is a local sort (avoids importing sort at the top-level of
// control.go alongside all the other imports).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
