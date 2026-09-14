package deploy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/firewall"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/origin"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

// LinuxAdapter is the production composition root for one role operation. It
// owns orchestration order and the in-flight ownership record only;
// artifact/config/unit/firewall policy remains in T2-T6. It must be
// constructed from a complete validated request.
type LinuxAdapter struct {
	Request InstallRequest

	// Store is the deployment state store for the canonical state root;
	// the adapter uses it ONLY to read the in-flight journal during
	// recovery (it never writes the manifest — Transaction owns that).
	Store    *Store
	Services *systemd.ServiceManager
	Firewall firewall.Manager
	Xray     *xray.Installer
	Origin   origin.OriginProvider

	units           []systemd.Spec
	firewallState   firewall.Snapshot
	firewallApplied bool
	xrayBinary      string

	// configChanged records whether this transaction changes the projected
	// env configuration (the planner's config.fingerprint change). It is
	// runtime-only: the persisted identity is Manifest.ConfigFingerprint.
	configChanged bool

	// recoveryOps is the seam for the T5 operations recovery performs.
	// nil → the real T5 calls (systemd.RemoveUnit / RollbackLast /
	// RollbackEnvFile). It exists ONLY so the adapter's journal-driven
	// ownership logic can be exercised deterministically without a root Linux
	// host; it reimplements no T5 policy.
	recoveryOps recoveryOps

	// In-flight ownership (runtime only; never persisted — the persisted
	// journal is the pre-state record written before mutation begins).
	// CleanupFresh uses the disk journal plus these sets.
	inFlightUnits []string
	inFlightFiles []string
}

// managedBinaryPrefix is the managed binary prefix (systemd.BinaryPrefix). It
// is a package var — mirroring systemd's own test-redirectable managed-path
// vars — so the prefix-bounded directory removal in recovery and the journal's
// containment check can be exercised on a temporary tree. Production never
// reassigns it; only _test.go files do (restored via t.Cleanup).
var managedBinaryPrefix = systemd.BinaryPrefix

// recoveryOps abstracts the T5 operations journal-driven recovery needs.
// Production delegates to the authoritative T5 package (systemdRecoveryOps).
type recoveryOps interface {
	RemoveUnit(ctx context.Context, m *systemd.ServiceManager, s systemd.Spec) error
	RemoveUnitIfAbsent(ctx context.Context, m *systemd.ServiceManager, s systemd.Spec) error
	RollbackLast(ctx context.Context, m *systemd.ServiceManager, s systemd.Spec) error
	// ReapplyUnit re-applies a committed unit spec from the manifest. It is
	// the convergence fallback for DEFECT-3: when RollbackLast finds no
	// managed backup to restore (the unit was created by a fresh install and
	// never backed up), recovery re-renders and re-applies the committed
	// unit instead of failing, so a crashed upgrade converges.
	ReapplyUnit(ctx context.Context, m *systemd.ServiceManager, s systemd.Spec) error
	RollbackEnvFile(ctx context.Context, role systemd.Role) error
}

// systemdRecoveryOps is the production recoveryOps: a thin delegation to T5.
type systemdRecoveryOps struct{}

func (systemdRecoveryOps) RemoveUnit(ctx context.Context, m *systemd.ServiceManager, s systemd.Spec) error {
	return systemd.RemoveUnit(ctx, m, s)
}

func (systemdRecoveryOps) RemoveUnitIfAbsent(ctx context.Context, m *systemd.ServiceManager, s systemd.Spec) error {
	return systemd.RemoveUnitIfAbsent(ctx, m, s)
}

func (systemdRecoveryOps) RollbackLast(ctx context.Context, m *systemd.ServiceManager, s systemd.Spec) error {
	return systemd.RollbackLast(ctx, m, s)
}

// ReapplyUnit converges a committed unit by re-rendering it from its spec and
// applying it through T5's transactional ApplyUnit (a byte no-op when the live
// bytes already match, a validated/backed-up swap otherwise).
func (systemdRecoveryOps) ReapplyUnit(ctx context.Context, m *systemd.ServiceManager, s systemd.Spec) error {
	_, err := systemd.ApplyUnit(ctx, m, s)
	return err
}

func (systemdRecoveryOps) RollbackEnvFile(ctx context.Context, role systemd.Role) error {
	return systemd.RollbackEnvFile(ctx, role)
}

// ops returns the adapter's recovery-operations seam (real T5 by default).
func (a *LinuxAdapter) ops() recoveryOps {
	if a.recoveryOps != nil {
		return a.recoveryOps
	}
	return systemdRecoveryOps{}
}

// NewLinuxAdapter constructs production dependencies. It intentionally
// refuses non-Linux execution and non-canonical T5 paths; tests should use the
// existing deploy Adapter fake rather than weakening T5's production paths.
func NewLinuxAdapter(request InstallRequest, serviceExec systemd.SystemdExecutor, firewallExec firewall.Executor) (*LinuxAdapter, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("deploy: LinuxAdapter requires Linux")
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if request.StateRoot != systemd.StateDir || request.EnvPath != systemd.EnvFile(systemd.Role(request.Role)) {
		return nil, fmt.Errorf("deploy: request paths do not match canonical T5 paths")
	}
	if request.ConfigPath != "" && request.Role == RoleGermany && request.ConfigPath != systemd.StateDir+"/xray-germany.json" {
		return nil, fmt.Errorf("deploy: Germany config path does not match canonical T5 path")
	}
	if request.ConfigPath != "" && request.Role == RoleIran && request.ConfigPath != systemd.StateDir+"/Caddyfile" {
		return nil, fmt.Errorf("deploy: Iran config path does not match canonical T5 path")
	}

	store, err := NewStore(request.StateRoot)
	if err != nil {
		return nil, err
	}
	adapter := &LinuxAdapter{
		Request:  request,
		Store:    store,
		Services: systemd.NewServiceManager(serviceExec),
		Firewall: firewall.New(firewallExec),
		Xray:     &xray.Installer{Prefix: systemd.BinaryPrefix + "/xray"},
	}
	if request.Role == RoleIran && request.Origin.Mode != origin.ModeNone {
		provider, err := origin.New(request.Origin.Mode, origin.Deps{Prefix: systemd.BinaryPrefix, Dir: systemd.StateDir})
		if err != nil {
			return nil, err
		}
		adapter.Origin = provider
	}
	return adapter, nil
}

// BuildJournal derives the complete ownership-scoped pre-state journal for a
// desired state from the previous committed manifest. It performs no host
// mutation: file existence is read-only, and units are taken from the
// previous manifest (the authoritative record of what the project deployed).
// root must be the state root (journal file paths are validated against it).
func BuildJournal(root string, previous Manifest, desired DesiredState) (ArtifactJournal, error) {
	if desired.Role != RoleIran && desired.Role != RoleGermany {
		return ArtifactJournal{}, fmt.Errorf("deploy: journal role is invalid")
	}
	j := ArtifactJournal{Role: desired.Role}
	files := make([]string, 0, 3)
	if desired.Paths.Env != "" {
		files = append(files, desired.Paths.Env)
	}
	if desired.Paths.Config != "" {
		files = append(files, desired.Paths.Config)
	}
	sort.Strings(files)
	for _, f := range files {
		_, err := os.Lstat(f)
		switch {
		case err == nil:
			j.PreFiles = append(j.PreFiles, f)
		case os.IsNotExist(err):
			j.Files = append(j.Files, f)
		default:
			return ArtifactJournal{}, fmt.Errorf("deploy: journal file stat %s: %w", filepath.Base(f), err)
		}
	}
	for _, s := range desired.Services {
		j.Units = append(j.Units, s.Unit)
	}
	for _, s := range previous.Services {
		j.PreUnits = append(j.PreUnits, s.Unit)
	}
	sort.Strings(j.Units)
	sort.Strings(j.PreUnits)
	j.Firewall = desired.Firewall.Backend != "" && desired.Firewall.Backend != string(firewall.BackendNone)
	if desired.Role == RoleGermany && desired.Components.Xray.Version != "" {
		if d, err := xray.VersionDir(systemd.BinaryPrefix+"/xray", desired.Components.Xray.Version); err == nil {
			j.XrayDir = d
		}
	}
	if desired.Role == RoleIran && desired.Components.Origin.Version != "" {
		// VersionDir derives the canonical Caddy layout as
		// <prefix>/caddy/<version>. Pass the managed binary prefix itself;
		// passing <prefix>/caddy would duplicate the component directory.
		if d, err := origin.VersionDir(systemd.BinaryPrefix, desired.Components.Origin.Version); err == nil {
			j.OriginDir = d
		}
	}
	if err := j.validate(root); err != nil {
		return ArtifactJournal{}, err
	}
	return j, nil
}

func (a *LinuxAdapter) Prepare(ctx context.Context, desired DesiredState) error {
	if err := systemd.EnsureUser(ctx, a.Services.Ex); err != nil {
		return err
	}
	if err := systemd.EnsureStateDir(ctx); err != nil {
		return err
	}
	if err := systemd.EnsureLogDir(ctx, a.Services.Ex); err != nil {
		return err
	}
	if a.Request.Role == RoleIran && a.Origin != nil {
		if err := systemd.EnsureDataDir(ctx, a.Services.Ex); err != nil {
			return err
		}
	}
	env, err := a.Request.Env()
	if err != nil {
		return err
	}
	applied, _, err := systemd.WriteEnvFile(ctx, systemd.Role(a.Request.Role), env)
	if err != nil {
		return err
	}
	if applied {
		a.inFlightFiles = append(a.inFlightFiles, a.Request.EnvPath)
	}
	if a.Request.Role == RoleIran {
		if err := installCanonicalSplitter(a.Request.SplitterPath, canonicalIranSplitterPath()); err != nil {
			return err
		}
	}
	if a.Origin != nil {
		if err := a.Origin.Configure(ctx, a.Request.Origin); err != nil {
			return err
		}
		// Origin activation deliberately creates live Caddyfile candidates and
		// rollback artifacts as 0600. Converge only the live service-readable
		// file after activation; .prev/.tmp and iran.env remain private.
		if a.Request.Role == RoleIran && (a.Request.Origin.Mode == origin.ModeCaddy || (a.Request.Origin.Mode == origin.ModeCDN && a.Request.Origin.CDNSecurity == origin.CDNTLSOrigin)) {
			if err := systemd.EnsureStateDir(ctx); err != nil {
				return err
			}
		}
		if a.Request.Origin.Mode == origin.ModeCaddy || (a.Request.Origin.Mode == origin.ModeCDN && a.Request.Origin.CDNSecurity == origin.CDNTLSOrigin) {
			a.inFlightFiles = append(a.inFlightFiles, a.Request.ConfigPath)
		}
	}
	if a.Request.Role == RoleGermany {
		arch, err := xray.DefaultArch()
		if err != nil {
			return err
		}
		// The Xray config does not exist until Activate; do not ask the
		// installer to validate a not-yet-created config.
		installed, err := a.Xray.Install(a.Request.XrayVersion, arch, "")
		if err != nil {
			return err
		}
		a.xrayBinary = installed.Path
		if err := systemd.EnsureBinaryPointer(ctx, systemd.PointerXray, a.Request.XrayVersion); err != nil {
			return err
		}
	}
	return nil
}

func (a *LinuxAdapter) Validate(ctx context.Context, desired DesiredState) error {
	plan, err := BuildSystemdPlan(a.Request)
	if err != nil {
		return err
	}
	if a.Request.Role == RoleGermany && a.xrayBinary == "" {
		return fmt.Errorf("deploy: Xray was not prepared")
	}
	for _, spec := range plan.Specs {
		if _, err := systemd.RenderUnit(spec); err != nil {
			return err
		}
	}
	a.units = plan.Specs
	return ctx.Err()
}

func (a *LinuxAdapter) Backup(context.Context, *Manifest) error { return nil }

// applyUnit applies one unit spec transactionally. It is the single place the
// adapter calls T5's ApplyUnit, so the configuration-change case is handled
// exactly once for every component.
//
// T5's ApplyUnit is a byte no-op when the live unit file already matches the
// rendered spec. That is correct for unit CONTENT, but a configuration-only
// change (splitterctl config set) rewrites the protected env file the unit
// reads via EnvironmentFile= while leaving the unit bytes identical — so a
// bare no-op would leave the running process on the old configuration until
// the next reboot. When the env projection changed (the desired configuration
// identity differs from the previous committed one), an unchanged unit is
// explicitly restarted through T5's own Restart, which is exactly the
// transition T5 performs after a real unit swap.
func (a *LinuxAdapter) applyUnit(ctx context.Context, spec systemd.Spec) error {
	result, err := systemd.ApplyUnit(ctx, a.Services, spec)
	if err != nil {
		return err
	}
	if !restartAfterConfigChange(result, a.configChanged) {
		return nil
	}
	if err := a.Services.Restart(ctx, unitName(spec)); err != nil {
		return fmt.Errorf("deploy: restart %s after configuration change: %w", unitName(spec), err)
	}
	return nil
}

// restartAfterConfigChange reports whether an applied unit must be restarted
// even though T5 found its bytes unchanged. That is exactly the
// configuration-only change case: the unit reads its configuration from the
// protected env file (EnvironmentFile=) which Prepare rewrote, so the running
// process still holds the old values. A unit whose bytes DID change is already
// transitioned by T5 (start/restart), so it never needs the extra restart.
func restartAfterConfigChange(result systemd.Result, configChanged bool) bool {
	return result.Unchanged && configChanged
}

func (a *LinuxAdapter) Activate(ctx context.Context, desired DesiredState) error {
	// Record whether this transaction changes the configuration identity
	// BEFORE mutating: the env file written in Prepare is already the new
	// one, so the comparison must use the manifest that was committed when
	// this transaction started.
	a.configChanged = false
	if previous, err := a.previousManifest(); err == nil {
		a.configChanged = desired.ConfigFingerprint != "" && previous.ConfigFingerprint != desired.ConfigFingerprint
	}
	if a.Request.Role == RoleGermany {
		keypair, err := xray.GenerateRealityKeypair(nil, a.xrayBinary)
		if err != nil {
			return err
		}
		if _, err := xray.ActivateGermanyConfig(xray.ActivateParams{
			Params:   a.Request.Reality,
			Keypair:  keypair,
			Dir:      systemd.StateDir,
			FileName: "xray-germany.json",
			Bin:      a.xrayBinary,
		}); err != nil {
			return err
		}
		a.inFlightFiles = append(a.inFlightFiles, a.Request.ConfigPath)
		if err := systemd.EnsureStateDir(ctx); err != nil {
			return err
		}
	}
	for _, spec := range a.units {
		spec = applyReadySpec(spec)
		if err := a.applyUnit(ctx, spec); err != nil {
			return err
		}
		a.inFlightUnits = append(a.inFlightUnits, unitName(spec))
	}
	return nil
}

// previousManifest returns the committed manifest this transaction started
// from, or os.ErrNotExist for a fresh install.
func (a *LinuxAdapter) previousManifest() (Manifest, error) {
	if a.Store == nil {
		return Manifest{}, os.ErrNotExist
	}
	return a.Store.Load()
}

func (a *LinuxAdapter) Transition(ctx context.Context, desired DesiredState) error {
	result, err := a.Firewall.Apply(ctx, a.Request.Firewall)
	if err != nil {
		return err
	}
	if !result.Unchanged {
		snapshot, err := a.Firewall.Inspect(ctx, a.Request.Firewall)
		if err != nil {
			return err
		}
		a.firewallState, a.firewallApplied = snapshot, true
	}
	return nil
}

func (a *LinuxAdapter) Health(ctx context.Context, desired DesiredState) error {
	for _, spec := range a.units {
		unit := spec.UnitName
		if unit == "" {
			switch spec.Component {
			case systemd.ComponentXray:
				unit = "xray-germany.service"
			case systemd.ComponentOrigin:
				unit = "iran-origin.service"
			default:
				unit = a.Request.Role + "-splitter.service"
			}
		}
		if err := a.Services.WaitActive(ctx, unit, systemdHealthTimeout); err != nil {
			return err
		}
	}
	if a.Origin != nil {
		health, err := a.Origin.Status(ctx)
		if err != nil || !health.Live {
			return fmt.Errorf("deploy: origin health failed: %v", err)
		}
	}
	return nil
}

// Restore returns a failed upgrade transaction to the previous committed
// state, or converges the host to a retained revision for an operator
// rollback (Store.Rollback). It is bounded by ownership and idempotent.
//
// Three dispatch paths:
//
//  1. In-flight recovery (journal present): precise revert of the crashed
//     transaction, bounded by the journal's pre-state:
//     a. in-flight units (replaced this transaction) → RollbackLast (T5's
//     managed backup of the previous unit file);
//     b. in-flight units never in the previous state → RemoveUnit (created
//     by this transaction, nothing to roll back to);
//     c. firewall applied this transaction → Remove the owned snapshot;
//     d. env file → RollbackEnvFile when the previous state had one;
//     e. previously-existing config files are left to their owner's rollback
//     artifact (T3 keeps <config>.prev for Germany);
//     f. previously-absent config files → remove.
//
//  2. Operator rollback (no journal, no in-flight units): bounded
//     convergence to the target manifest (see rollbackTo).
//
//  3. Inconsistent (no journal but in-flight units remain): fail closed —
//     the ownership record is ambiguous and manual recovery is required.
//
// Xray/origin binary directories are never removed here: T2/T4 leave old
// versions on disk, and the pointer still targets the version the previous
// state used (the adapter re-points only after Activate succeeds).
//
// Restore is the IN-PROCESS recovery path and may consult the runtime
// in-flight record. After a process crash that record is gone, so
// post-crash recovery uses RecoverJournal (journal-driven) instead.
func (a *LinuxAdapter) Restore(ctx context.Context, previous Manifest) error {
	// Refuse to "restore" a state that was never committed: a restore must
	// return the host to a real previous generation. A fresh install (no
	// previous generation) must use CleanupFresh instead — failing open here
	// would report success while leaving a half-built host.
	if previous.Generation == "" {
		return fmt.Errorf("deploy: LinuxAdapter restore requires a previous committed generation; a fresh install must use CleanupFresh")
	}
	var j ArtifactJournal
	haveJournal := false
	if a.Store != nil {
		if got, err := a.Store.ReadJournal(); err == nil {
			j = got
			haveJournal = true
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("deploy: restore: read journal: %w", err)
		}
	}
	if haveJournal && j.Role != a.Request.Role {
		return fmt.Errorf("deploy: restore: journal role %q does not match adapter role %q", j.Role, a.Request.Role)
	}
	if !haveJournal {
		if len(a.units) != 0 {
			return fmt.Errorf("%w: restore found in-flight units without a journal; manual recovery required", ErrTransaction)
		}
		return a.rollbackTo(ctx, previous)
	}
	// In-flight recovery is bounded by the journal's pre-state (the previous
	// manifest is the source of truth for unit pre-state; its PreUnits mirror
	// it). The unit set reverted here is the RUNTIME in-flight set, which is
	// the exact set this process attempted to replace.
	if err := a.revertUnits(ctx, j, previous, a.inFlightUnits); err != nil {
		return err
	}
	// Firewall: only the snapshot this process actually applied.
	if a.firewallApplied {
		if err := a.Firewall.Remove(ctx, a.firewallState); err != nil {
			return fmt.Errorf("deploy: restore firewall: %w", err)
		}
	}
	// Env file: the previous generation had one → restore its backup.
	if previous.Paths.Env != "" {
		if err := a.ops().RollbackEnvFile(ctx, systemd.Role(a.Request.Role)); err != nil {
			return fmt.Errorf("deploy: restore env file: %w", err)
		}
	}
	// Config files this transaction created (not recorded as pre-existing).
	if err := a.removeOwnedFiles(j, a.inFlightFiles, a.Request.EnvPath); err != nil {
		return fmt.Errorf("deploy: restore: %w", err)
	}
	return nil
}

// RecoverJournal is the POST-CRASH recovery entrypoint: it reconstructs the
// crashed transaction's ownership from the PERSISTED journal alone (the
// runtime in-flight sets are empty in a fresh process) and reverts the host.
//
//   - Fresh case (previous.Generation == ""): there is no committed previous
//     generation to converge to, so only artifacts the crashed transaction
//     created are removed — the owned firewall state, units in j.Units that
//     are NOT in j.PreUnits (reverse dependency order), files in j.Files that
//     are NOT in j.PreFiles, the xray/caddy binary pointer and the journal's
//     version dir (prefix-bounded). Restore is deliberately NOT called: a
//     fresh install has nothing to restore to.
//   - Upgrade case (a committed previous generation exists): converge to
//     previous using Restore's journal-driven semantics (unit rollback/removal
//     from the journal's unit sets plus previous.Services, env rollback, and
//     removal of files the transaction created).
//
// It is idempotent (already-reverted artifacts are absent → no-ops) and
// bounded by ctx. It never reads the runtime in-flight record, so it behaves
// identically in the crashed process's successor.
func (a *LinuxAdapter) RecoverJournal(ctx context.Context, j ArtifactJournal, previous Manifest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.Role != a.Request.Role {
		return fmt.Errorf("deploy: recovery: journal role %q does not match adapter role %q", j.Role, a.Request.Role)
	}
	// Validate every journal unit against the exact role-specific plan before
	// any destructive recovery operation. A syntactically valid service name is
	// not sufficient ownership proof: recovery must never act on a foreign unit.
	if _, err := a.recoveryPlanSpecs(append(append([]string{}, j.Units...), j.PreUnits...)); err != nil {
		return err
	}
	if previous.Generation == "" {
		return a.recoverFresh(ctx, j)
	}
	// Upgrade: converge to the committed previous generation. The journal's
	// unit set (j.Units) is the ownership record — the runtime in-flight set
	// is unavailable post-crash.
	if err := a.revertUnits(ctx, j, previous, j.Units); err != nil {
		return err
	}
	if previous.Paths.Env != "" {
		if err := a.ops().RollbackEnvFile(ctx, systemd.Role(a.Request.Role)); err != nil {
			return fmt.Errorf("deploy: recovery: env file: %w", err)
		}
	}
	if err := a.removeOwnedFiles(j, j.Files, a.Request.EnvPath); err != nil {
		return fmt.Errorf("deploy: recovery: %w", err)
	}
	return nil
}

// recoverFresh reverts a crashed FRESH install (no committed previous
// generation): everything the journal records as created is removed; nothing
// is restored. Order mirrors CleanupFresh (firewall → units reverse order →
// config files → binary pointer + version dir → env file).
func (a *LinuxAdapter) recoverFresh(ctx context.Context, j ArtifactJournal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.Firewall {
		// Reconstruct the owned rule set from the request (the journal only
		// records THAT the project applied a firewall, not the rules). A
		// failure here must not silently skip the removal: report it.
		snapshot, err := a.Firewall.Inspect(ctx, a.Request.Firewall)
		if err != nil {
			return fmt.Errorf("deploy: recovery: inspect firewall: %w", err)
		}
		if err := a.Firewall.Remove(ctx, snapshot); err != nil {
			return fmt.Errorf("deploy: recovery: firewall: %w", err)
		}
	}
	// Units the transaction created: j.Units minus j.PreUnits, reverse order.
	if err := a.removeUnitsReverse(ctx, subtractUnits(j.Units, j.PreUnits)); err != nil {
		return err
	}
	// Config files the transaction created: j.Files minus j.PreFiles.
	if err := a.removeOwnedFiles(j, j.Files, a.Request.EnvPath); err != nil {
		return fmt.Errorf("deploy: recovery: %w", err)
	}
	if err := a.removeOwnedVersionDirs(ctx, j); err != nil {
		return err
	}
	// Env file: removed ONLY when this transaction created it. BuildJournal
	// classifies the env path into Files (absent before → owned) vs PreFiles
	// (pre-existing → NOT owned). A fresh install normally has no prior env,
	// but a journal may record one that pre-existed (or that the crashed
	// transaction never reached); deleting it then would destroy a resource
	// this transaction does not own. Mirrors removeOwnedFiles.
	if envOwnedByJournal(j, a.Request.EnvPath) {
		if err := os.Remove(a.Request.EnvPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("deploy: recovery: env file: %w", err)
		}
	}
	return nil
}

// envOwnedByJournal reports whether the env file at envPath was created by
// the journal's transaction: present in j.Files (absent before the
// transaction) and NOT in j.PreFiles (which would mean it pre-existed and is
// left to its owner's rollback path). This is the exact ownership rule
// removeOwnedFiles applies to config files.
func envOwnedByJournal(j ArtifactJournal, envPath string) bool {
	if envPath == "" {
		return false
	}
	for _, f := range j.PreFiles {
		if f == envPath {
			return false
		}
	}
	for _, f := range j.Files {
		if f == envPath {
			return true
		}
	}
	return false
}

// removeUnitsReverse removes the given unit names in reverse dependency order
// through T5's RemoveUnit (via the unitOps seam). Absent units are no-ops
// (RemoveUnit tolerates a missing live file), so the sweep is idempotent.
func (a *LinuxAdapter) removeUnitsReverse(ctx context.Context, units []string) error {
	for i := len(units) - 1; i >= 0; i-- {
		spec, err := a.unitSpecFor(units[i])
		if err != nil {
			return err
		}
		if err := a.ops().RemoveUnitIfAbsent(ctx, a.Services, spec); err != nil {
			return fmt.Errorf("deploy: recovery: unit %s: %w", units[i], err)
		}
	}
	return nil
}

// removeOwnedVersionDirs removes the binary pointer and the journal's version
// directory (XrayDir for Germany, OriginDir for Iran). The removal is
// prefix-bounded and symlink-safe (removePrefixDir). Shared by CleanupFresh
// and recoverFresh so both paths derive ownership identically.
func (a *LinuxAdapter) removeOwnedVersionDirs(ctx context.Context, j ArtifactJournal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.Request.Role == RoleGermany {
		// Only the "current" symlink and the journal's XrayDir are
		// project-owned by THIS transaction; other version dirs belong to
		// previous installs and are untouched.
		if err := os.Remove(managedBinaryPrefix + "/xray/current"); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("deploy: recovery: xray pointer: %w", err)
		}
		if j.XrayDir != "" {
			if err := removePrefixDir(j.XrayDir, managedBinaryPrefix); err != nil {
				return fmt.Errorf("deploy: recovery: %w", err)
			}
		}
	}
	if a.Request.Role == RoleIran && j.OriginDir != "" {
		if err := removePrefixDir(j.OriginDir, managedBinaryPrefix); err != nil {
			return fmt.Errorf("deploy: recovery: %w", err)
		}
	}
	return nil
}

// revertUnits rolls back (or removes) the given units in reverse dependency
// order, bounded by the journal's pre-state and previous.Services. A unit in
// previous.Services (or j.PreUnits) is pre-existing → RollbackLast restores
// its managed backup; otherwise it was created by the transaction → RemoveUnit.
func (a *LinuxAdapter) revertUnits(ctx context.Context, j ArtifactJournal, previous Manifest, units []string) error {
	prevUnits := map[string]bool{}
	for _, s := range previous.Services {
		prevUnits[s.Unit] = true
	}
	for _, u := range j.PreUnits {
		prevUnits[u] = true
	}
	for i := len(units) - 1; i >= 0; i-- {
		unit := units[i]
		spec, err := a.unitSpecFor(unit)
		if err != nil {
			return err
		}
		if !prevUnits[unit] {
			if err := a.ops().RemoveUnitIfAbsent(ctx, a.Services, spec); err != nil {
				return fmt.Errorf("deploy: recovery: remove unit %s: %w", unit, err)
			}
			continue
		}
		if err := a.ops().RollbackLast(ctx, a.Services, spec); err != nil {
			// DEFECT-3 convergence: a pre-existing unit with NO managed
			// backup to restore (created by a fresh install, never backed
			// up) must not deadlock recovery. The unit's committed content
			// is reconstructible from the request, so re-apply it instead
			// of failing; recovery stays ownership-scoped and the host
			// converges to the previous state.
			if errors.Is(err, systemd.ErrNoUnitBackup) {
				// The re-apply RENDERS unit bytes (unlike RemoveUnit/
				// RollbackLast, which consume only the unit name), so it
				// must use the SAME spec the normal apply path writes —
				// dependency ordering (RequiresUnits/OriginEnabled) and
				// the canonical env path included. recoverySpecFor derives
				// that spec from the single authoritative source
				// (BuildSystemdPlan), so the fallback converges to the
				// committed unit bytes rather than a divergent minimal one.
				faithful, ferr := a.recoverySpecFor(unit)
				if ferr != nil {
					return ferr
				}
				if rerr := a.ops().ReapplyUnit(ctx, a.Services, faithful); rerr != nil {
					return fmt.Errorf("deploy: recovery: re-apply unit %s after missing backup: %w", unit, rerr)
				}
				continue
			}
			return fmt.Errorf("deploy: recovery: rollback unit %s: %w", unit, err)
		}
	}
	return nil
}

// unitSpecFor reconstructs a minimal T5 spec for a unit NAME recorded in the
// journal (post-crash recovery has no runtime specs). The component is derived
// from the canonical unit name so RemoveUnit/RollbackLast target the right
// managed file; both operations derive the file from the unit name, so the
// remaining spec fields are informational. The unit name is validated by T5
// (Spec.unitName) inside those operations.
//
// unitSpecFor is deliberately name-scoped: it is correct ONLY for the
// name-consuming operations (RemoveUnit, RollbackLast, DisableUnit). It does
// NOT render bytes, so it must never feed ApplyUnit — use recoverySpecFor for
// that, which reproduces the committed unit content.
func (a *LinuxAdapter) unitSpecFor(unit string) (systemd.Spec, error) {
	plan, err := BuildSystemdPlan(a.Request)
	if err != nil {
		return systemd.Spec{}, fmt.Errorf("deploy: recovery: build unit plan: %w", err)
	}
	for _, spec := range plan.Specs {
		if unitName(spec) == unit {
			spec.UnitName = unit
			return applyReadySpec(spec), nil
		}
	}
	return systemd.Spec{}, fmt.Errorf("deploy: recovery: unit %s is not part of the request's plan", unit)
}

func (a *LinuxAdapter) recoveryPlanSpecs(units []string) (map[string]systemd.Spec, error) {
	plan, err := BuildSystemdPlan(a.Request)
	if err != nil {
		return nil, fmt.Errorf("deploy: recovery: build unit plan: %w", err)
	}
	allowed := make(map[string]systemd.Spec, len(plan.Specs))
	for _, spec := range plan.Specs {
		spec = applyReadySpec(spec)
		spec.UnitName = unitName(spec)
		allowed[spec.UnitName] = spec
	}
	for _, unit := range units {
		if _, ok := allowed[unit]; !ok {
			return nil, fmt.Errorf("deploy: recovery: unit %s is not part of the request's plan", unit)
		}
	}
	return allowed, nil
}

// applyReadySpec returns the spec exactly as the apply path must write it.
// BuildSystemdPlan emits the request's VERSIONED xray artifact path, but the
// xray unit is version-independent by design (design §4.7 — an xray upgrade
// never rewrites the unit) and must always run the "current" pointer. Both the
// normal apply path (Activate) and the DEFECT-3 recovery re-apply normalise
// through this ONE helper, so the bytes written on the host have a single
// source of truth instead of two divergent copies of the same rule.
func applyReadySpec(spec systemd.Spec) systemd.Spec {
	if spec.Component == systemd.ComponentXray {
		spec.BinPath = systemd.XrayBinaryPath
	}
	return spec
}

// recoverySpecFor returns the FULLY-FAITHFUL spec for a unit NAME recorded in
// the journal, suitable for rendering/ApplyUnit. It derives the spec from the
// single authoritative source, BuildSystemdPlan(a.Request), which is exactly
// what the normal apply path (Validate/Activate) installs, so the DEFECT-3
// recovery fallback converges to the committed unit BYTES rather than a
// divergent minimal spec:
//
//   - the Germany splitter keeps its RequiresUnits=[xray-germany.service]
//     dependency (After=/Wants= ordering);
//   - the Iran splitter keeps its OriginEnabled flag (the origin-mode-driven
//     After=/Wants= reference to iran-origin.service);
//   - the canonical EnvFile is used (BuildSystemdPlan reads it from the
//     authoritative systemd.EnvFile helper — the same value unitSpecFor sets).
//
// The spec is then passed through applyReadySpec — the SAME normalisation
// Activate uses — so an xray re-apply is a byte no-op. The requested unit name
// is pinned onto the matched plan spec so the operation targets the journal's
// unit even if the plan's derived name were to differ.
func (a *LinuxAdapter) recoverySpecFor(unit string) (systemd.Spec, error) {
	plan, err := BuildSystemdPlan(a.Request)
	if err != nil {
		return systemd.Spec{}, fmt.Errorf("deploy: recovery: build unit plan: %w", err)
	}
	for _, spec := range plan.Specs {
		if unitName(spec) != unit {
			continue
		}
		spec = applyReadySpec(spec)
		spec.UnitName = unit
		return spec, nil
	}
	return systemd.Spec{}, fmt.Errorf("deploy: recovery: unit %s is not part of the request's plan", unit)
}

// removeOwnedFiles removes each file in owned that is NOT recorded as
// pre-existing in j.PreFiles and is not the env file (env is handled by its
// own rollback/removal path). Absent files are no-ops (idempotent).
func (a *LinuxAdapter) removeOwnedFiles(j ArtifactJournal, owned []string, envPath string) error {
	preFiles := map[string]bool{}
	for _, f := range j.PreFiles {
		preFiles[f] = true
	}
	for _, f := range owned {
		if preFiles[f] || f == envPath {
			continue
		}
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove config %s: %w", filepath.Base(f), err)
		}
	}
	return nil
}

// subtractUnits returns the entries of all that are not present in exclude.
func subtractUnits(all, exclude []string) []string {
	skip := make(map[string]bool, len(exclude))
	for _, u := range exclude {
		skip[u] = true
	}
	var out []string
	for _, u := range all {
		if !skip[u] {
			out = append(out, u)
		}
	}
	return out
}

// recordedRealityFingerprint resolves the Reality public-parameter fingerprint
// a manifest records for Germany. Schema 2 keeps it in the dedicated
// RealityFingerprint field; schema 1 predated that field and overloaded the
// binary-hash field (its sha256 held the fingerprint), so a legacy manifest
// falls back to SHA256. It returns "" when neither is recorded, which the
// rollback guard treats as a mismatch (fail closed).
func recordedRealityFingerprint(c ComponentState) string {
	if c.RealityFingerprint != "" {
		return c.RealityFingerprint
	}
	return c.SHA256
}

// rollbackTo converges the host to the target manifest for an operator
// rollback (Store.Rollback). It is bounded by ownership and runs the same
// validation and health gates as an ordinary deployment: every target unit is
// re-rendered from the manifest and pushed through T5's ApplyUnit (a byte
// no-op when unchanged, a validated swap otherwise). Convergence order:
//
//  1. guards (fail closed) — see below;
//  2. xray binary pointer → the target's xray version (version dirs persist,
//     so the pointer is exact for any number of steps; the xray unit is
//     version-independent and is never rewritten);
//  3. units: RemoveUnit for current units the target does not have, then
//     ApplyUnit for each target unit (idempotent);
//  4. health: WaitActive on every target unit.
//
// Guards (fail closed): the target's firewall rules, Reality parameters, and
// origin state are compared against the current request. When any differ, the
// target's artifact is not reconstructible from the retained manifest (rule
// set, Reality keypair, and Caddyfile plan are not persisted in full), so the
// rollback is refused rather than applied partially. The env file is never
// rewritten here: its content (which carries the secret) is not recorded in
// the manifest, only a digest, so a revision's configuration is not
// reconstructible. The rollback therefore converges unit/origin artifacts to
// the target revision while the live env file keeps the configuration the
// operator supplied in the environment — which the guards above keep
// compatible with the target (origin/Reality/firewall are derived from it).
func (a *LinuxAdapter) rollbackTo(ctx context.Context, target Manifest) error {
	if target.Firewall.RulesHash != firewallFingerprint(a.Request.Firewall) {
		return fmt.Errorf("%w: rollback: firewall rules differ from the current deployment and are not reconstructible; manual firewall recovery required", ErrTransaction)
	}
	if a.Request.Role == RoleGermany {
		// recordedRealityFingerprint keeps a schema-1 revision rollbackable:
		// its overloaded sha256 still holds the fingerprint.
		if got := realityFingerprint(a.Request.Reality); recordedRealityFingerprint(target.Components.Xray) != got {
			return fmt.Errorf("%w: rollback: Reality parameters differ from the current deployment and the prior keypair is not retained; manual recovery required", ErrTransaction)
		}
	}
	if a.Request.Role == RoleIran {
		o := target.Components.Origin
		if o.Mode != string(a.Request.Origin.Mode) || o.Version != a.Request.OriginVersion || o.Domain != a.Request.Origin.Domain {
			return fmt.Errorf("%w: rollback: origin state differs from the current deployment and is not reconstructible; manual recovery required", ErrTransaction)
		}
	}
	// 2: xray pointer (Germany only; exact for any number of steps).
	if a.Request.Role == RoleGermany && target.Components.Xray.Version != "" {
		if err := systemd.EnsureBinaryPointer(ctx, systemd.PointerXray, target.Components.Xray.Version); err != nil {
			return fmt.Errorf("deploy: rollback: xray pointer: %w", err)
		}
	}
	// 3: units. Converge the live units to the target's shape.
	targetSpecs, err := a.targetUnitSpecs(target)
	if err != nil {
		return err
	}
	targetUnits := map[string]bool{}
	for _, spec := range targetSpecs {
		targetUnits[unitName(spec)] = true
	}
	plan, err := BuildSystemdPlan(a.Request)
	if err != nil {
		return err
	}
	// Remove units the current deployment has that the target does not
	// (reverse dependency order: dependents before their dependencies).
	for i := len(plan.Specs) - 1; i >= 0; i-- {
		spec := plan.Specs[i]
		unit := unitName(spec)
		if targetUnits[unit] {
			continue
		}
		if err := systemd.RemoveUnit(ctx, a.Services, spec); err != nil {
			return fmt.Errorf("deploy: rollback remove unit %s: %w", unit, err)
		}
	}
	// Apply each target unit (idempotent: a no-op when the live bytes already
	// match; otherwise a validated, backed-up swap + restart).
	for _, spec := range targetSpecs {
		if _, err := systemd.ApplyUnit(ctx, a.Services, spec); err != nil {
			return fmt.Errorf("deploy: rollback unit %s: %w", unitName(spec), err)
		}
	}
	// 4: health — the same exact-active gate as an ordinary deployment.
	for _, spec := range targetSpecs {
		if err := a.Services.WaitActive(ctx, unitName(spec), systemdHealthTimeout); err != nil {
			return fmt.Errorf("deploy: rollback health %s: %w", unitName(spec), err)
		}
	}
	return nil
}

// targetUnitSpecs reconstructs the T5 unit specs for a retained manifest from
// its recorded components. The unit bytes are a pure function of
// (role, component, BinPath, OriginVersion, OriginEnabled), all of which are
// derivable from the manifest: the xray unit is version-independent (it runs
// the "current" pointer), the origin unit runs the pinned caddy binary from
// the versioned layout, and the splitter unit runs the recorded binary path.
func (a *LinuxAdapter) targetUnitSpecs(target Manifest) ([]systemd.Spec, error) {
	role := systemd.Role(a.Request.Role)
	hasOrigin := false
	for _, s := range target.Services {
		if s.Component == "origin" {
			hasOrigin = true
			break
		}
	}
	var specs []systemd.Spec
	for _, s := range target.Services {
		switch s.Component {
		case "xray":
			specs = append(specs, systemd.Spec{
				Role:      systemd.RoleGermany,
				Component: systemd.ComponentXray,
				BinPath:   systemd.XrayBinaryPath,
			})
		case "origin":
			specs = append(specs, systemd.Spec{
				Role:          systemd.RoleIran,
				Component:     systemd.ComponentOrigin,
				BinPath:       systemd.BinaryPrefix + "/caddy/" + target.Components.Origin.Version + "/caddy",
				OriginVersion: target.Components.Origin.Version,
			})
		case "splitter":
			spec := systemd.Spec{
				Role:          role,
				Component:     systemd.ComponentSplitter,
				BinPath:       target.Components.Splitter.Path,
				EnvFile:       systemd.EnvFile(role),
				OriginEnabled: hasOrigin,
			}
			if role == systemd.RoleGermany {
				// The germany splitter unit requires the xray unit file
				// (BuildSystemdPlan sets the same requirement).
				spec.RequiresUnits = []string{"xray-germany.service"}
			}
			specs = append(specs, spec)
		default:
			return nil, fmt.Errorf("%w: rollback: unknown service component %q", ErrTransaction, s.Component)
		}
	}
	return specs, nil
}

// CleanupFresh removes only artifacts this fresh transaction created when no
// previous manifest exists to restore. Sweep order: firewall (when applied)
// → this transaction's units in reverse creation order → in-flight config
// files not recorded as pre-existing in the journal → the xray/caddy
// binary pointer and the journal's version dir (when present) → the env
// file. A fresh install has no previously-existing units by definition; the
// journal's pre-state records still bound the file sweep defensively.
//
// CleanupFresh is the IN-PROCESS path: it uses the runtime in-flight sets.
// Its post-crash twin is recoverFresh (journal-driven); both share the
// removeUnitsReverse / removeOwnedFiles / removeOwnedVersionDirs helpers so
// ownership is derived identically.
func (a *LinuxAdapter) CleanupFresh(ctx context.Context, desired DesiredState) error {
	if a.firewallApplied {
		if err := a.Firewall.Remove(ctx, a.firewallState); err != nil {
			return err
		}
	}
	for i := len(a.units) - 1; i >= 0; i-- {
		if err := a.ops().RemoveUnit(ctx, a.Services, a.units[i]); err != nil {
			return err
		}
	}
	var j ArtifactJournal
	jerr := os.ErrNotExist
	if a.Store != nil {
		j, jerr = a.Store.ReadJournal()
	}
	if err := a.removeOwnedFiles(j, a.inFlightFiles, a.Request.EnvPath); err != nil {
		return err
	}
	if jerr == nil {
		if err := a.removeOwnedVersionDirs(ctx, j); err != nil {
			return err
		}
	}
	if err := os.Remove(a.Request.EnvPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// removePrefixDir removes a project-owned version directory only when it is
// strictly inside the managed binary prefix. It is the symlink-safe,
// prefix-bounded replacement for a raw os.RemoveAll on a persisted journal
// field: a malformed or tampered journal must never direct a recursive
// deletion outside prefix (defense in depth — the prefix is re-asserted here
// and not merely trusted from journal validation). A symlink is removed as a
// link only, never followed into its target; a non-directory is refused.
func removePrefixDir(dir, prefix string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("deploy: resolve %s: %w", filepath.Base(dir), err)
	}
	absPrefix, err := filepath.Abs(prefix)
	if err != nil {
		return fmt.Errorf("deploy: resolve binary prefix: %w", err)
	}
	if abs != absPrefix && !within(absPrefix, abs) {
		return fmt.Errorf("deploy: refusing to remove %s outside binary prefix", filepath.Base(dir))
	}
	return removeWithinPrefix(abs)
}

// removeWithinPrefix Lstat's a path that the caller has already verified is
// inside the managed prefix and removes it without following symlinks: a
// symlink is unlinked (never recursed into), a directory is removed
// recursively, and any other object is refused. Kept separate from the
// prefix check so the symlink/non-directory branches are unit-testable
// without writing to the fixed production prefix.
func removeWithinPrefix(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		// A symlinked version dir: unlink the link only. Recursing would
		// delete the (arbitrary) link target.
		return os.Remove(path)
	}
	if !st.IsDir() {
		return fmt.Errorf("deploy: refusing to remove non-directory %s", filepath.Base(path))
	}
	return os.RemoveAll(path)
}

// removeStoreOwnedDir is the store-owned analogue of removePrefixDir: it
// removes a recursive target that lives below the state root WITHOUT a binary
// prefix. The caller has already derived the path from store-owned state
// (never from untrusted input); it re-asserts containment under root as
// defense in depth and delegates the symlink-refusing, non-directory-refusing
// removal to removeWithinPrefix, so no destructive logic is duplicated.
func removeStoreOwnedDir(path, root string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("deploy: resolve %s: %w", filepath.Base(path), err)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("deploy: resolve state root: %w", err)
	}
	if !within(absRoot, abs) {
		return fmt.Errorf("deploy: refusing to remove %s outside the state root", filepath.Base(path))
	}
	return removeWithinPrefix(abs)
}

// Uninstall removes the currently-committed deployment for the adapter's
// role. Like CleanupFresh it is bounded by ownership: only units recorded in
// the committed manifest (previous.Services), the env file, the config file,
// and owned firewall rules. Binary version directories are left in place
// (they are harmless without units; purge semantics are a documented
// limitation until the artifact journal is revision-scoped).
func (a *LinuxAdapter) Uninstall(ctx context.Context, previous Manifest) error {
	for i := len(previous.Services) - 1; i >= 0; i-- {
		spec := systemd.Spec{
			Role:      systemd.Role(a.Request.Role),
			Component: componentFor(previous.Services[i].Component),
			UnitName:  previous.Services[i].Unit,
		}
		if err := systemd.RemoveUnit(ctx, a.Services, spec); err != nil {
			return err
		}
	}
	if previous.Firewall.Backend != "" && previous.Firewall.Backend != string(firewall.BackendNone) {
		snapshot, err := a.Firewall.Inspect(ctx, a.Request.Firewall)
		if err != nil {
			return err
		}
		if err := a.Firewall.Remove(ctx, snapshot); err != nil {
			return err
		}
	}
	if previous.Paths.Env != "" {
		if err := os.Remove(previous.Paths.Env); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if previous.Paths.Config != "" {
		if err := os.Remove(previous.Paths.Config); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func componentFor(c string) systemd.Component {
	switch c {
	case "xray":
		return systemd.ComponentXray
	case "origin":
		return systemd.ComponentOrigin
	default:
		return systemd.ComponentSplitter
	}
}

// unitName mirrors the T5 default unit naming for a spec (explicit
// spec.UnitName wins; otherwise derived from role+component). The specs
// this adapter builds always use the derived names, so this is exact.
// installCanonicalSplitter copies the operator-supplied artifact into the
// managed Iran location without following a destination symlink. The source
// may be a staging path; it is never emitted into a unit or manifest.
func installCanonicalSplitter(source, target string) error {
	if source == target {
		return nil
	}
	st, err := os.Lstat(source)
	if err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("deploy: Iran splitter source must be a regular file")
	}
	if dst, err := os.Lstat(target); err == nil {
		if dst.Mode()&os.ModeSymlink != 0 || !dst.Mode().IsRegular() {
			return fmt.Errorf("deploy: refusing unsafe Iran splitter target")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("deploy: stat Iran splitter target: %w", err)
	}
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("deploy: open Iran splitter source: %w", err)
	}
	defer in.Close()
	parent := filepath.Dir(target)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("deploy: Iran splitter managed directory is not a real directory")
	}
	tmp := target + ".tmp-" + fmt.Sprint(os.Getpid())
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return fmt.Errorf("deploy: stage Iran splitter: %w", err)
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("deploy: copy Iran splitter: %w", err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("deploy: sync Iran splitter: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("deploy: close Iran splitter: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("deploy: activate Iran splitter: %w", err)
	}
	ok = true
	return nil
}

func unitName(spec systemd.Spec) string {
	if spec.UnitName != "" {
		return spec.UnitName
	}
	switch spec.Component {
	case systemd.ComponentXray:
		return "xray-germany.service"
	case systemd.ComponentOrigin:
		return "iran-origin.service"
	default:
		return string(spec.Role) + "-splitter.service"
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

const systemdHealthTimeout = 30 * 1000000000
