package deploy

import (
	"context"
	"fmt"
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

	// In-flight ownership (runtime only; never persisted — the persisted
	// journal is the pre-state record written before mutation begins).
	// CleanupFresh uses the disk journal plus these sets.
	inFlightUnits []string
	inFlightFiles []string
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
		if d, err := origin.VersionDir(systemd.BinaryPrefix+"/caddy", desired.Components.Origin.Version); err == nil {
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
	if a.Origin != nil {
		if err := a.Origin.Configure(ctx, a.Request.Origin); err != nil {
			return err
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

func (a *LinuxAdapter) Activate(ctx context.Context, desired DesiredState) error {
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
		if spec.Component == systemd.ComponentXray {
			spec.BinPath = systemd.XrayBinaryPath
		}
		if _, err := systemd.ApplyUnit(ctx, a.Services, spec); err != nil {
			return err
		}
		a.inFlightUnits = append(a.inFlightUnits, unitName(spec))
	}
	return nil
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
	prevUnits := map[string]bool{}
	for _, s := range previous.Services {
		prevUnits[s.Unit] = true
	}
	// Unit rollback / removal, reverse dependency order. The previous
	// manifest is the single source of truth for unit pre-state (the
	// journal's PreUnits mirror it); file recovery below is bounded by
	// the journal's PreFiles (empty when no journal was written).
	for i := len(a.units) - 1; i >= 0; i-- {
		spec := a.units[i]
		unit := unitName(spec)
		inFlight := contains(a.inFlightUnits, unit)
		if !inFlight {
			// This transaction never replaced the unit (failure before
			// Activate, or the swap itself failed and T5's ApplyUnit
			// already restored the live unit file): nothing to revert.
			continue
		}
		if !prevUnits[unit] {
			// Created by this transaction: remove it entirely.
			if err := systemd.RemoveUnit(ctx, a.Services, spec); err != nil {
				return fmt.Errorf("deploy: restore unit %s: %w", unit, err)
			}
			continue
		}
		if err := systemd.RollbackLast(ctx, a.Services, spec); err != nil {
			return fmt.Errorf("deploy: restore unit %s: %w", unit, err)
		}
	}
	// 3: firewall.
	if a.firewallApplied {
		if err := a.Firewall.Remove(ctx, a.firewallState); err != nil {
			return fmt.Errorf("deploy: restore firewall: %w", err)
		}
	}
	// 4: env file.
	if previous.Paths.Env != "" {
		if err := systemd.RollbackEnvFile(ctx, systemd.Role(a.Request.Role)); err != nil {
			return fmt.Errorf("deploy: restore env file: %w", err)
		}
	}
	// 6: config files this transaction created.
	preFiles := map[string]bool{}
	for _, f := range j.PreFiles {
		preFiles[f] = true
	}
	for _, f := range a.inFlightFiles {
		if !preFiles[f] && f != a.Request.EnvPath {
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("deploy: restore config %s: %w", filepath.Base(f), err)
			}
		}
	}
	return nil
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
// rewritten here: it is invariant across revisions in the current product
// (there is no config-set mutation), and its content (which carries the
// secret) is not recorded in the manifest.
func (a *LinuxAdapter) rollbackTo(ctx context.Context, target Manifest) error {
	if target.Firewall.RulesHash != firewallFingerprint(a.Request.Firewall) {
		return fmt.Errorf("%w: rollback: firewall rules differ from the current deployment and are not reconstructible; manual firewall recovery required", ErrTransaction)
	}
	if a.Request.Role == RoleGermany {
		if got := realityFingerprint(a.Request.Reality); target.Components.Xray.SHA256 != got {
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
func (a *LinuxAdapter) CleanupFresh(ctx context.Context, desired DesiredState) error {
	if a.firewallApplied {
		if err := a.Firewall.Remove(ctx, a.firewallState); err != nil {
			return err
		}
	}
	for i := len(a.units) - 1; i >= 0; i-- {
		if err := systemd.RemoveUnit(ctx, a.Services, a.units[i]); err != nil {
			return err
		}
	}
	var j ArtifactJournal
	jerr := os.ErrNotExist
	if a.Store != nil {
		j, jerr = a.Store.ReadJournal()
	}
	preFiles := map[string]bool{}
	if jerr == nil {
		for _, f := range j.PreFiles {
			preFiles[f] = true
		}
	}
	for _, f := range a.inFlightFiles {
		if !preFiles[f] && f != a.Request.EnvPath {
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	if jerr == nil {
		if a.Request.Role == RoleGermany {
			// Remove the binary pointer and the version dir this transaction
			// installed. Only the "current" symlink and the journal's
			// XrayDir are project-owned by THIS transaction; other version
			// dirs are untouched (they belong to previous installs).
			if err := os.Remove(systemd.BinaryPrefix + "/xray/current"); err != nil && !os.IsNotExist(err) {
				return err
			}
			if j.XrayDir != "" {
				if err := os.RemoveAll(j.XrayDir); err != nil {
					return err
				}
			}
		}
		if a.Request.Role == RoleIran && j.OriginDir != "" {
			if err := os.RemoveAll(j.OriginDir); err != nil {
				return err
			}
		}
	}
	if err := os.Remove(a.Request.EnvPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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
