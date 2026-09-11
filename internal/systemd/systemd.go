// Package systemd owns every systemd-facing action of the product (T5;
// design plans/t5-design.md):
//
//   - byte-pinned, deterministic unit generation (RenderUnit + goldens);
//   - D4 env-file management: secrets live ONLY in 0600 root:root env files
//     that systemd reads as root before dropping privileges — never in unit
//     files;
//   - service user and directory provisioning with a converged permission
//     chain (non-root services must read their own configs);
//   - transactional unit application with backup, verification, atomic swap,
//     enable/restart and health verification, and two-case rollback
//     (restore-known-good vs converge-to-not-deployed);
//   - bounded health waits (exact "active" semantics — an
//     "activating (auto-restart)" unit is NEVER a success) and read-only
//     diagnostics.
//
// The package is the service-management half of the L5 acceptance path and
// the integration contract for cmd/splitterctl (T8). Rules enforced by
// construction and by tests:
//
//   - stdlib only; no pkg/* imports (internal/* may use internal/config);
//   - zero goroutines (WaitActive polls in the caller's goroutine);
//   - no package globals; every mutation takes context.Context, is
//     root-checked, and fails closed;
//   - no shell: exec.CommandContext(name, args...) with separated args;
//   - field-only errors: env-file values (including the 64-hex secret) never
//     appear in any error, unit byte string, or journal echo.
//
// OS-specific behavior (chown, /proc pid liveness, the real OSExecutor) is
// Linux-gated (runtime.GOOS == "linux") — the target platform. The injected
// fakes keep the unit tests fully cross-platform.
package systemd

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Role is the deployment role. Values are the config.RoleGermany /
// config.RoleIran strings (reused, not redeclared).
type Role string

// Component is the managed component a Spec describes.
type Component string

const (
	RoleGermany Role = "germany"
	RoleIran    Role = "iran"

	ComponentSplitter Component = "splitter"
	ComponentXray     Component = "xray"
	ComponentOrigin   Component = "origin"
)

// Service user and group (design §4.1/§4.8). A single non-root user runs all
// four units; capabilities are granted per unit where a low port must be
// bound.
const (
	ServiceUser  = "split-tunnel"
	ServiceGroup = "split-tunnel"
)

// Fixed managed paths (design §4.1 — NOT user inputs; eliminating them as
// inputs removes a whole injection class). These constants are the
// canonical production values and the T8 contract.
const (
	UnitDir      = "/etc/systemd/system"
	WantsDir     = "/etc/systemd/system/multi-user.target.wants"
	StateDir     = "/etc/split-tunnel"
	LogDir       = "/var/log/split-tunnel"
	DataDir      = "/var/lib/split-tunnel"
	BinaryPrefix = "/opt/split-tunnel"
)

// UnitsBackupDir holds RemoveUnit's bounded unit-file backups.
const UnitsBackupDir = StateDir + "/units-backup"

// Managed-path variables. They default to the canonical constants above;
// ONLY the _test.go files of this package reassign them (each test
// restores via t.Cleanup) so filesystem behavior can be exercised on any
// host without touching /etc. No production code path ever mutates them —
// by construction they are assigned only in test files (grep-enforced).
// The rendered UNIT BYTES are unaffected: they always carry the canonical
// absolute paths (the renderer reads the constants, not these variables).
var (
	unitDir        = UnitDir
	wantsDir       = WantsDir
	stateDir       = StateDir
	logDir         = LogDir
	dataDir        = DataDir
	binaryPrefix   = BinaryPrefix
	unitsBackupDir = UnitsBackupDir
)

// nowUnixNano supplies the embedded timestamp of managed backup names
// (<live>.bak-<unixnano>). Reassigned ONLY by _test.go with a counter: the
// Windows clock has ~14 ms resolution, so rapid back-to-back backups in a
// test could otherwise share a name and corrupt the keep-N sweep count.
var nowUnixNano = func() int64 { return time.Now().UnixNano() }

// EnvFile returns the D4 env-file path for a role (0600 root:root; systemd
// reads it as root before Setuid — proven on staging).
func EnvFile(role Role) string {
	return stateDir + "/" + string(role) + ".env"
}

// XrayBinaryPath is the unit ExecStart target: the version-independent
// "current" pointer that EnsureBinaryPointer manages (design §4.7 — xray
// upgrades never rewrite the unit).
const XrayBinaryPath = BinaryPrefix + "/xray/current/xray"

// unitNameRE guards every unit name this package writes: lowercase
// alphanumeric + dash, a single ".service" suffix — no "..", no ".", no
// ".d/" override injection, no path separators.
var unitNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.service$`)

// maxBinPathLen bounds an ExecStart binary path (defense in depth; the real
// guard is "absolute + no whitespace").
const maxBinPathLen = 4096

// Errors. Every error is field-only: no env-file values, no secret material.
var (
	// ErrNotRoot: a mutating operation was attempted without root.
	ErrNotRoot = errors.New("systemd: operation requires root (running unprivileged)")
	// ErrSpec: the Spec is invalid (field-only detail in the wrapped message).
	ErrSpec = errors.New("systemd: invalid spec")
	// ErrPreflight: a preflight check failed (nothing was modified).
	ErrPreflight = errors.New("systemd: preflight failed (nothing modified)")
	// ErrVerify: systemd-analyze verify rejected the candidate unit
	// (the candidate was removed; nothing live was touched).
	ErrVerify = errors.New("systemd: systemd-analyze verify rejected the unit")
	// ErrUnsafeTarget: a managed path exists as a symlink or non-regular
	// object and the operation refuses to proceed through it.
	ErrUnsafeTarget = errors.New("systemd: refusing unsafe existing target (symlink or non-regular file)")
	// ErrApplyInProgress: a leftover candidate encodes a still-alive pid —
	// another apply is presumably in flight (fail closed).
	ErrApplyInProgress = errors.New("systemd: another apply may be in progress (live pid found in candidate name)")
	// ErrUnitState: the unit is not in the state the operation requires.
	ErrUnitState = errors.New("systemd: unit state does not match the operation requirement")
	// ErrWaitNotActive: WaitActive's deadline expired without the unit
	// reaching exactly "active".
	ErrWaitNotActive = errors.New("systemd: unit did not reach state active before the deadline")
	// ErrRollback: the rollback itself failed (the apply already failed;
	// the operator must intervene).
	ErrRollback = errors.New("systemd: rollback failed (manual intervention required)")
)

// Step names used in structured error context.
const (
	StepPreflight  = "preflight"
	StepRender     = "render"
	StepCandidate  = "candidate-write"
	StepVerify     = "verify"
	StepBackup     = "backup"
	StepSwap       = "swap"
	StepReload     = "daemon-reload"
	StepEnable     = "enable"
	StepTransition = "start/restart"
	StepHealth     = "health-wait"
	StepRollback   = "rollback"
)

// firstErr returns the first non-nil error (house pattern, internal/xray).
func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// unitPath returns the absolute path of a unit inside the managed unit dir
// (unitDir — canonical /etc/systemd/system, test-redirectable). The name is
// validated first; the result is always unitDir + "/" + name.
func unitPath(unit string) (string, error) {
	if !unitNameRE.MatchString(unit) {
		return "", fmt.Errorf("%w: unit name %q must match %s", ErrSpec, unit, unitNameRE.String())
	}
	return unitDir + "/" + unit, nil
}

// canonicalEnvFile is the CANONICAL (production) env-file path — the
// renderer validates against this constant-derived value (never the
// test-redirectable variable) so the golden bytes are host-independent.
func canonicalEnvFile(role Role) string {
	return StateDir + "/" + string(role) + ".env"
}

// checkUnitName validates a unit name for any executor call (defense in
// depth: unit names passed to systemctl/journalctl are regex-checked).
func checkUnitName(unit string) error {
	if !unitNameRE.MatchString(unit) {
		return fmt.Errorf("%w: unit name %q must match %s", ErrSpec, unit, unitNameRE.String())
	}
	return nil
}

// rootCheck is the package-level root gate (standalone functions). It is a
// var (like nowUnixNano / waitPollInterval) so ONLY _test.go files can
// substitute a permissive gate and exercise the standalone functions
// (WriteEnvFile, Ensure*, EnsureBinaryPointer) on any host; never
// reassigned outside _test.go (AST-grep enforced).
var rootCheck = defaultRootCheck
