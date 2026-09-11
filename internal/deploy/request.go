package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/firewall"
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
	OriginPath      string

	Firewall firewall.Plan
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
	if err := firewall.ValidatePlan(r.Firewall); err != nil {
		return fmt.Errorf("deploy: invalid firewall plan: %w", err)
	}
	if r.SplitterVersion == "" || r.SplitterPath == "" || !filepath.IsAbs(r.SplitterPath) {
		return fmt.Errorf("deploy: splitter artifact metadata is incomplete or unsafe")
	}
	if r.Role == RoleGermany && (r.XrayVersion == "" || r.XrayPath == "" || !filepath.IsAbs(r.XrayPath)) {
		return fmt.Errorf("deploy: Germany Xray artifact metadata is incomplete or unsafe")
	}
	if r.XrayVersion != "" && !xray.ValidVersion(r.XrayVersion) {
		return fmt.Errorf("deploy: invalid Xray version")
	}
	if r.OriginVersion != "" && !origin.ValidVersion(r.OriginVersion) {
		return fmt.Errorf("deploy: invalid origin version")
	}
	if r.Role == RoleIran && r.Origin.Mode != origin.ModeNone && (r.OriginVersion == "" || r.OriginPath == "" || !filepath.IsAbs(r.OriginPath)) {
		return fmt.Errorf("deploy: Iran origin artifact metadata is incomplete or unsafe")
	}
	if r.StateRoot == "" || !filepath.IsAbs(r.StateRoot) {
		return fmt.Errorf("deploy: state root must be absolute")
	}
	if r.EnvPath == "" || !filepath.IsAbs(r.EnvPath) || !within(r.StateRoot, r.EnvPath) {
		return fmt.Errorf("deploy: env path must be an absolute path below state root")
	}
	if r.ConfigPath != "" && (!filepath.IsAbs(r.ConfigPath) || !within(r.StateRoot, r.ConfigPath)) {
		return fmt.Errorf("deploy: config path must be an absolute path below state root")
	}
	if r.Role == RoleIran && r.Origin.Mode == origin.ModeNone {
		return fmt.Errorf("deploy: Iran public deployment cannot use none origin")
	}
	return nil
}

// Env returns the complete validated key/value projection consumed by T5's
// protected env-file writer. The secret is intentionally returned only to the
// caller performing the env-file mutation; Desired never includes it.
func (r InstallRequest) Env() (map[string]string, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	c := r.Config
	env := map[string]string{
		config.EnvSecret: c.Secret,
	}
	if r.Role == RoleIran {
		env[config.EnvSocksListen] = c.SocksListen
		env[config.EnvWsListen] = c.WsListen
		env[config.EnvDownCarrier] = c.DownCarrierAddr
	} else {
		env[config.EnvUpWsUrl] = c.UpWsUrl
		env[config.EnvDownListen] = c.DownListen
	}
	if c.MetricsPort != 0 {
		env[config.EnvMetricsPort] = strconv.Itoa(c.MetricsPort)
	}
	if c.AllowWeakSecret {
		env[config.EnvAllowWeak] = strconv.FormatBool(c.AllowWeakSecret)
	}
	if c.RelayBufSize != 0 {
		env[config.EnvRelayBuf] = strconv.Itoa(c.RelayBufSize)
	}
	if c.QueueBytesPerStream != 0 {
		env[config.EnvQueueBytes] = strconv.Itoa(c.QueueBytesPerStream)
	}
	if c.QueueFramesPerStream != 0 {
		env[config.EnvQueueFrames] = strconv.Itoa(c.QueueFramesPerStream)
	}
	if c.QueueBytesTotal != 0 {
		env[config.EnvQueueTotal] = strconv.Itoa(c.QueueBytesTotal)
	}
	if c.OverflowWaitMs != 0 {
		env[config.EnvOverflowMs] = strconv.Itoa(c.OverflowWaitMs)
	}
	if c.CarrierGraceMs != 0 {
		env[config.EnvCarrierGrace] = strconv.Itoa(c.CarrierGraceMs)
	}
	if c.BootstrapWaitMs != 0 {
		env[config.EnvBootstrapWait] = strconv.Itoa(c.BootstrapWaitMs)
	}
	if c.SessionBufBytes != 0 {
		env[config.EnvSessionBuf] = strconv.Itoa(c.SessionBufBytes)
	}
	if c.SessionBufTotal != 0 {
		env[config.EnvSessionBufTotal] = strconv.Itoa(c.SessionBufTotal)
	}
	if c.LivenessRounds != 0 {
		env[config.EnvLivenessRounds] = strconv.Itoa(c.LivenessRounds)
	}
	return env, nil
}

func within(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." {
		return false
	}
	prefix := ".." + string(filepath.Separator)
	return len(rel) < len(prefix) || rel[:len(prefix)] != prefix
}

func firewallFingerprint(plan firewall.Plan) string {
	parts := make([]string, 0, len(plan.Allow)+len(plan.Deny)+len(plan.CDNEgress)+2)
	parts = append(parts, string(plan.Backend), plan.Role)
	for _, rule := range append(append([]firewall.Rule{}, plan.Allow...), plan.Deny...) {
		parts = append(parts, fmt.Sprintf("%d/%s/%s/%s", rule.Port, rule.Protocol, rule.Action, rule.Comment))
	}
	parts = append(parts, plan.CDNEgress...)
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

// Desired converts a validated request into planner state. It does not read,
// write, install, or start anything.
func (r InstallRequest) Desired() (DesiredState, error) {
	if err := r.Validate(); err != nil {
		return DesiredState{}, err
	}
	services := []ServiceState{{Unit: r.Role + "-splitter.service", Component: "splitter"}}
	if r.Role == RoleGermany {
		services = append([]ServiceState{{Unit: "xray-germany.service", Component: "xray"}}, services...)
	} else if r.Origin.Mode != origin.ModeNone {
		services = append([]ServiceState{{Unit: "iran-origin.service", Component: "origin"}}, services...)
	}
	d := DesiredState{
		Role: r.Role,
		Components: Components{
			Splitter: ComponentState{Version: r.SplitterVersion, Path: r.SplitterPath},
			Xray:     ComponentState{Version: r.XrayVersion, Path: r.XrayPath},
			Origin:   OriginState{Mode: string(r.Origin.Mode), Domain: r.Origin.Domain, Version: r.OriginVersion},
		},
		Paths:    Paths{StateRoot: r.StateRoot, Env: r.EnvPath, Config: r.ConfigPath},
		Services: services,
		Pairing:  PairingState{State: "none"},
		Firewall: FirewallState{Backend: string(r.Firewall.Backend), Ownership: firewall.Marker, RulesHash: firewallFingerprint(r.Firewall)},
	}
	return d, nil
}
