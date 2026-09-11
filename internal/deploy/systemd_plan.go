package deploy

import (
	"fmt"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/origin"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

// SystemdPlan is the pure T8-to-T5 handoff. It contains the protected env
// projection and canonical T5 unit specs, but performs no filesystem,
// privilege, systemd, or process operations.
type SystemdPlan struct {
	Env   map[string]string
	Specs []systemd.Spec
}

// BuildSystemdPlan validates the request and builds the exact units required
// for the selected role. Unit bytes remain owned by systemd.RenderUnit; this
// function only selects components, paths, and dependency relationships.
func BuildSystemdPlan(request InstallRequest) (SystemdPlan, error) {
	if err := request.Validate(); err != nil {
		return SystemdPlan{}, err
	}
	env, err := request.Env()
	if err != nil {
		return SystemdPlan{}, err
	}
	splitter := systemd.Spec{
		Role:      systemd.Role(request.Role),
		Component: systemd.ComponentSplitter,
		BinPath:   request.SplitterPath,
		EnvFile:   systemd.EnvFile(systemd.Role(request.Role)),
	}
	if request.Role == RoleIran && request.Origin.Mode != origin.ModeNone {
		splitter.OriginEnabled = true
	}
	plan := SystemdPlan{Env: env, Specs: []systemd.Spec{splitter}}
	if request.Role == RoleGermany {
		plan.Specs = append([]systemd.Spec{
			{
				Role:      systemd.RoleGermany,
				Component: systemd.ComponentXray,
				BinPath:   request.XrayPath,
			},
		}, plan.Specs...)
		plan.Specs[1].RequiresUnits = []string{"xray-germany.service"}
		return plan, nil
	}
	if request.Origin.Mode == origin.ModeCaddy || (request.Origin.Mode == origin.ModeCDN && request.Origin.CDNSecurity == origin.CDNTLSOrigin) {
		if request.OriginVersion == "" {
			return SystemdPlan{}, fmt.Errorf("deploy: origin unit requires an origin version")
		}
		originSpec := systemd.Spec{
			Role:          systemd.RoleIran,
			Component:     systemd.ComponentOrigin,
			BinPath:       request.OriginPath,
			OriginVersion: request.OriginVersion,
		}
		plan.Specs = append([]systemd.Spec{originSpec}, plan.Specs...)
	}
	return plan, nil
}
