package deploy

import (
	"context"
	"fmt"
	"runtime"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/firewall"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/origin"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

// LinuxAdapter is the production composition root for one role operation. It
// owns orchestration order only; artifact/config/unit/firewall policy remains
// in T2-T6. It must be constructed from a complete validated request.
type LinuxAdapter struct {
	Request InstallRequest

	Services *systemd.ServiceManager
	Firewall firewall.Manager
	Xray     *xray.Installer
	Origin   origin.OriginProvider

	units           []systemd.Spec
	firewallState   firewall.Snapshot
	firewallApplied bool
	xrayBinary      string
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

	adapter := &LinuxAdapter{
		Request:  request,
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
	if _, _, err := systemd.WriteEnvFile(ctx, systemd.Role(a.Request.Role), env); err != nil {
		return err
	}
	if a.Origin != nil {
		if err := a.Origin.Configure(ctx, a.Request.Origin); err != nil {
			return err
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
		if a.Request.Role == RoleGermany && a.xrayBinary == "" {
			return fmt.Errorf("deploy: Xray was not prepared")
		}
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

func (a *LinuxAdapter) Restore(ctx context.Context, previous Manifest) error {
	return fmt.Errorf("deploy: LinuxAdapter restore requires retained artifact journal for generation %s", previous.Generation)
}

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
	return nil
}

func (a *LinuxAdapter) Uninstall(ctx context.Context, previous Manifest) error {
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
	return nil
}

const systemdHealthTimeout = 30 * 1000000000
