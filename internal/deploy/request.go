package deploy

import (
	"fmt"
	"path/filepath"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/origin"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
)

// InstallRequest is the complete non-interactive input for a role deployment.
// Secret is intentionally not part of DesiredState and is consumed only by a
// host adapter when it writes the protected T5 env file.
type InstallRequest struct {
	Role   string
	Config config.Config

	Origin origin.Plan

	StateRoot  string
	EnvPath    string
	ConfigPath string

	SplitterVersion string
	SplitterPath    string
	XrayVersion     string
	XrayPath        string
	OriginVersion   string
}

// Validate checks all operator-controlled fields before an adapter can mutate
// the host. Role-specific config and origin validation remain delegated to the
// authoritative packages; this layer only validates deployment metadata.
func (r InstallRequest) Validate() error {
	if r.Role != RoleIran && r.Role != RoleGermany {
		return fmt.Errorf("deploy: invalid install role")
	}
	if err := r.Config.Validate(r.Role); err != nil {
		return fmt.Errorf("deploy: invalid splitter config: %w", err)
	}
	if err := origin.ValidatePlan(r.Origin); err != nil {
		return fmt.Errorf("deploy: invalid origin plan: %w", err)
	}
	if r.SplitterVersion == "" || r.SplitterPath == "" {
		return fmt.Errorf("deploy: splitter artifact metadata is incomplete")
	}
	if r.Role == RoleGermany && (r.XrayVersion == "" || r.XrayPath == "") {
		return fmt.Errorf("deploy: Germany Xray artifact metadata is incomplete")
	}
	if r.XrayVersion != "" && !xray.ValidVersion(r.XrayVersion) {
		return fmt.Errorf("deploy: invalid Xray version")
	}
	if r.OriginVersion != "" && !origin.ValidVersion(r.OriginVersion) {
		return fmt.Errorf("deploy: invalid origin version")
	}
	if r.StateRoot == "" || !filepath.IsAbs(r.StateRoot) {
		return fmt.Errorf("deploy: state root must be absolute")
	}
	if r.EnvPath == "" || !filepath.IsAbs(r.EnvPath) {
		return fmt.Errorf("deploy: env path must be absolute")
	}
	if r.ConfigPath != "" && !filepath.IsAbs(r.ConfigPath) {
		return fmt.Errorf("deploy: config path must be absolute")
	}
	if r.Role == RoleIran && r.Origin.Mode == origin.ModeNone {
		return fmt.Errorf("deploy: Iran public deployment cannot use none origin")
	}
	return nil
}

// Desired converts a validated request into planner state. It does not read,
// write, install, or start anything.
func (r InstallRequest) Desired() (DesiredState, error) {
	if err := r.Validate(); err != nil {
		return DesiredState{}, err
	}
	d := DesiredState{
		Role: r.Role,
		Components: Components{
			Splitter: ComponentState{Version: r.SplitterVersion, Path: r.SplitterPath},
			Xray:     ComponentState{Version: r.XrayVersion, Path: r.XrayPath},
			Origin:   OriginState{Mode: string(r.Origin.Mode), Domain: r.Origin.Domain, Version: r.OriginVersion},
		},
		Paths:   Paths{StateRoot: r.StateRoot, Env: r.EnvPath, Config: r.ConfigPath},
		Pairing: PairingState{State: "none"},
	}
	return d, nil
}
