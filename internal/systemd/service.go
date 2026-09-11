// service.go — the managed-transport seam: SystemdExecutor (the analog of
// xray.Executor), the OS default (exec.CommandContext, separated args,
// NEVER a shell), and the ServiceManager (stateless; every method is
// ctx-bounded).
//
// Every command this package runs goes through SystemdExecutor.Run with a
// fixed argv — there is no shell anywhere in this package (grep-enforced).
// The unit/state/journal output is bounded before it may appear in an
// error (excerpt, T2/T3 pattern); env-file values never reach an executor
// call, so they can never be echoed back.
package systemd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// SystemdExecutor is the managed-transport boundary for every external
// command (systemctl, systemd-analyze, journalctl, id, useradd). Tests
// substitute a fake with an ordered call log + canned outputs; the OS
// default shells out with exec.CommandContext (separated args, no shell).
type SystemdExecutor interface {
	Run(ctx context.Context, args ...string) (string, error)
}

// OSExecutor is the production SystemdExecutor: exec.CommandContext(name,
// args...) with CombinedOutput. Name and args are separate argv entries —
// no shell, no interpolation.
type OSExecutor struct{}

// Run executes args[0] with args[1:] and returns the combined output
// (trimmed). A non-zero exit is an error carrying the bounded output.
func (OSExecutor) Run(ctx context.Context, args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("systemd: executor: no command given")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return s, fmt.Errorf("%s: %v: %s", args[0], err, excerpt(s))
	}
	return s, nil
}

// ServiceManager bundles the executor with the injectable OS seams
// (RootCheck, PidAlive). It is stateless and safe to share; construct one
// per deploy operation via NewServiceManager.
type ServiceManager struct {
	// Ex is the managed-transport boundary (nil → OSExecutor).
	Ex SystemdExecutor
	// RootCheck gates every mutating operation (nil → euid check).
	RootCheck func() error
	// PidAlive reports whether a pid is alive (nil → /proc lstat on
	// Linux, false elsewhere — used to fail closed on concurrent applies).
	PidAlive func(int) bool
	// rootOwner is an INTERNAL seam (unexported — not part of the T8
	// contract): reports whether a file is root-owned. Default is
	// isRootOwned (Linux Stat_t / NSS); on non-Linux hosts the owner bit
	// does not exist, and the _test.go files substitute a permissive fake
	// so the transaction logic stays testable cross-platform (design §6
	// Linux-gating).
	rootOwner func(os.FileInfo) bool
}

// NewServiceManager builds a ServiceManager with the OS defaults injected
// for any nil seam.
func NewServiceManager(ex SystemdExecutor) *ServiceManager {
	m := &ServiceManager{Ex: ex}
	m.defaults()
	return m
}

// defaults fills any nil seam with the OS default (platform file).
func (m *ServiceManager) defaults() {
	if m.Ex == nil {
		m.Ex = OSExecutor{}
	}
	if m.RootCheck == nil {
		m.RootCheck = defaultRootCheck
	}
	if m.PidAlive == nil {
		m.PidAlive = defaultPidAlive
	}
	if m.rootOwner == nil {
		m.rootOwner = isRootOwned
	}
}

// contextCheck fails fast on an already-canceled context (bounded ops).
func contextCheck(ctx context.Context) error {
	if ctx == nil {
		return errors.New("systemd: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// rootCheck applies the manager's RootCheck (or the OS default when the
// manager is nil — standalone functions are always root-gated).
func (m *ServiceManager) rootCheck() error {
	if m != nil {
		m.defaults()
		return m.RootCheck()
	}
	return defaultRootCheck()
}

// run is the manager's executor (defaults applied).
func (m *ServiceManager) run(ctx context.Context, args ...string) (string, error) {
	m.defaults()
	return m.Ex.Run(ctx, args...)
}

// --- ServiceManager methods (design §4.10) -----------------------------

// Reload runs `systemctl daemon-reload`.
func (m *ServiceManager) Reload(ctx context.Context) error {
	_, err := m.run(ctx, "systemctl", "daemon-reload")
	return err
}

// Enable runs `systemctl enable <unit>` (idempotent).
func (m *ServiceManager) Enable(ctx context.Context, unit string) error {
	if err := checkUnitName(unit); err != nil {
		return err
	}
	_, err := m.run(ctx, "systemctl", "enable", unit)
	return err
}

// Disable runs `systemctl disable <unit>`.
func (m *ServiceManager) Disable(ctx context.Context, unit string) error {
	if err := checkUnitName(unit); err != nil {
		return err
	}
	_, err := m.run(ctx, "systemctl", "disable", unit)
	return err
}

// Start runs `systemctl start <unit>`.
func (m *ServiceManager) Start(ctx context.Context, unit string) error {
	if err := checkUnitName(unit); err != nil {
		return err
	}
	_, err := m.run(ctx, "systemctl", "start", unit)
	return err
}

// Stop runs `systemctl stop <unit>`.
func (m *ServiceManager) Stop(ctx context.Context, unit string) error {
	if err := checkUnitName(unit); err != nil {
		return err
	}
	_, err := m.run(ctx, "systemctl", "stop", unit)
	return err
}

// Restart runs `systemctl restart <unit>`.
func (m *ServiceManager) Restart(ctx context.Context, unit string) error {
	if err := checkUnitName(unit); err != nil {
		return err
	}
	_, err := m.run(ctx, "systemctl", "restart", unit)
	return err
}

// IsEnabled runs `systemctl is-enabled <unit>` (exit status is the answer;
// output is "enabled"/"disabled"/"static"/...).
func (m *ServiceManager) IsEnabled(ctx context.Context, unit string) (string, error) {
	if err := checkUnitName(unit); err != nil {
		return "", err
	}
	return m.run(ctx, "systemctl", "is-enabled", unit)
}

// State runs `systemctl is-active <unit>` and returns the FIRST WORD of
// the output, mapped into {active, activating, failed, inactive, unknown}.
// HIGH-2: `is-active` prints `activating (auto-restart)` for a
// crash-looping binary during RestartSec — the state name is the first
// word, and callers (WaitActive) treat ONLY exactly "active" as success.
func (m *ServiceManager) State(ctx context.Context, unit string) (string, error) {
	if err := checkUnitName(unit); err != nil {
		return "", err
	}
	out, err := m.run(ctx, "systemctl", "is-active", unit)
	state := "unknown"
	if field := strings.Fields(out); len(field) > 0 {
		state = field[0]
	}
	switch state {
	case "active", "activating", "deactivating", "failed", "inactive":
	default:
		state = "unknown"
	}
	if err != nil {
		// is-active exits non-zero for every non-active state; the state
		// string (not the exec error) is the signal.
		return state, nil
	}
	return state, nil
}

// JournalTail returns the last n journal lines for a unit (read-only,
// bounded). n is capped at 200. The journal is NOT passed any env-file
// path or env value — the secret is structurally absent from the call
// (asserted by test 13).
func (m *ServiceManager) JournalTail(ctx context.Context, unit string, n int) (string, error) {
	if err := checkUnitName(unit); err != nil {
		return "", err
	}
	if n <= 0 {
		n = 20
	}
	if n > 200 {
		n = 200
	}
	return m.run(ctx, "journalctl", "-u", unit, "-n", strconv.Itoa(n), "--no-pager", "-q", "-o", "short-iso")
}

// OSReport reports the host OS for diagnostics (read-only; never in a
// unit file). Exposed so T7 doctor can render its evidence.
func OSReport() string { return runtime.GOOS + "/" + runtime.GOARCH }
