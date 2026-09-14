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
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
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

	// SplitterSHA256 and XraySHA256 are OPTIONAL artifact content hashes. They
	// are intentionally not required by Validate: the current CLI contract
	// carries only a version and a path, so no authoritative binary hash is
	// available. When set (e.g. by an operator tool that verified a download),
	// Desired records them as true binary hashes and the planner detects an
	// in-place replacement that keeps the same path/version. When empty the
	// field is left unasserted rather than fabricated.
	SplitterSHA256 string
	XraySHA256     string

	Reality xray.RealityParams

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
	if r.Role == RoleGermany {
		if err := xray.ValidateRealityParams(r.Reality); err != nil {
			return fmt.Errorf("deploy: invalid Germany Reality parameters: %w", err)
		}
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

func realityFingerprint(params xray.RealityParams) string {
	sum := sha256.Sum256([]byte(params.SNI + "\n" + params.ShortID + "\n" + params.UUID))
	return hex.EncodeToString(sum[:])
}

// originCaddyfileHash is the SHA-256 of the rendered Caddyfile for a plan, or
// "" when the mode generates no Caddyfile (none, cdn plainOrigin). It reuses
// the authoritative renderer (origin.RenderCaddyfile) rather than duplicating
// the template.
func originCaddyfileHash(p origin.Plan) string {
	data, err := origin.RenderCaddyfile(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// unitContentHash is the SHA-256 of the exact unit bytes the apply path writes
// for a spec, or "" when the spec cannot be rendered in the current
// environment (e.g. an artifact path that RenderUnit rejects). Rendering is
// delegated to the authoritative systemd.RenderUnit — never re-implemented —
// and a render failure leaves the hash unasserted instead of failing the plan,
// because the adapter's Validate phase renders the same spec inside the
// transaction and surfaces a real failure there.
func unitContentHash(spec systemd.Spec) string {
	data, err := systemd.RenderUnit(spec)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// managedPaths returns every fixed managed path the adapter uses, derived from
// the authoritative internal/systemd constants (never hard-coded duplicates).
func managedPaths(r InstallRequest) Paths {
	return Paths{
		StateRoot:      r.StateRoot,
		Env:            r.EnvPath,
		Config:         r.ConfigPath,
		UnitDir:        systemd.UnitDir,
		WantsDir:       systemd.WantsDir,
		LogDir:         systemd.LogDir,
		DataDir:        systemd.DataDir,
		BinaryPrefix:   systemd.BinaryPrefix,
		UnitsBackupDir: systemd.UnitsBackupDir,
	}
}

// desiredServices projects the canonical unit plan into planner service state.
// Unit bytes remain owned by systemd.RenderUnit; this only hashes the exact
// spec the apply path writes (applyReadySpec normalises the xray pointer, the
// same normalisation Activate applies).
func desiredServices(plan SystemdPlan) []ServiceState {
	services := make([]ServiceState, 0, len(plan.Specs))
	for _, spec := range plan.Specs {
		spec = applyReadySpec(spec)
		services = append(services, ServiceState{
			Unit:      unitName(spec),
			Component: string(spec.Component),
			Hash:      unitContentHash(spec),
		})
	}
	return services
}

// ConfigValueKind is the value type of one operator-settable configuration
// field, as the CLI must parse it before the authoritative validator sees it.
type ConfigValueKind string

const (
	ConfigString ConfigValueKind = "string"
	ConfigBool   ConfigValueKind = "bool"
	ConfigInt    ConfigValueKind = "int"
)

// ConfigKey describes one operator-settable splitter configuration field in
// terms of the authoritative internal/config projection. The CLI uses this
// table to parse `config set KEY=VALUE` without re-declaring any env name or
// validation rule: every entry names the config.Env* constant that
// InstallRequest.Env projects it to, and the value is validated by
// Config.Validate(role) inside request.Validate.
type ConfigKey struct {
	// Name is the canonical CLI spelling (lower-case, dot-separated).
	Name string
	// EnvVar is the internal/config environment variable this field projects
	// to. It is never empty for a settable key.
	EnvVar string
	// Roles lists the deployment roles the field applies to.
	Roles []string
	// Kind is how the CLI parses the value.
	Kind ConfigValueKind
}

// ConfigKeys is the complete set of configuration fields `config set` accepts,
// in documentation order. A field absent from this table is either explicitly
// refused (ConfigKeyRefusals) or unknown (a usage error).
var ConfigKeys = []ConfigKey{
	{Name: "socks.listen", EnvVar: config.EnvSocksListen, Roles: []string{RoleIran}, Kind: ConfigString},
	{Name: "ws.listen", EnvVar: config.EnvWsListen, Roles: []string{RoleIran}, Kind: ConfigString},
	{Name: "down.carrier.addr", EnvVar: config.EnvDownCarrier, Roles: []string{RoleIran}, Kind: ConfigString},
	{Name: "up.ws.url", EnvVar: config.EnvUpWsUrl, Roles: []string{RoleGermany}, Kind: ConfigString},
	{Name: "down.listen", EnvVar: config.EnvDownListen, Roles: []string{RoleGermany}, Kind: ConfigString},
	{Name: "secret", EnvVar: config.EnvSecret, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigString},
	{Name: "allow.weak.secret", EnvVar: config.EnvAllowWeak, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigBool},
	{Name: "metrics.port", EnvVar: config.EnvMetricsPort, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
	{Name: "relay.buf", EnvVar: config.EnvRelayBuf, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
	{Name: "stream.queue.bytes", EnvVar: config.EnvQueueBytes, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
	{Name: "stream.queue.frames", EnvVar: config.EnvQueueFrames, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
	{Name: "stream.queue.total.bytes", EnvVar: config.EnvQueueTotal, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
	{Name: "stream.overflow.ms", EnvVar: config.EnvOverflowMs, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
	{Name: "carrier.grace", EnvVar: config.EnvCarrierGrace, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
	{Name: "bootstrap.wait", EnvVar: config.EnvBootstrapWait, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
	{Name: "session.buffer.bytes", EnvVar: config.EnvSessionBuf, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
	{Name: "session.buffer.total.bytes", EnvVar: config.EnvSessionBufTotal, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
	{Name: "liveness.rounds", EnvVar: config.EnvLivenessRounds, Roles: []string{RoleIran, RoleGermany}, Kind: ConfigInt},
}

// ConfigKeyKeepAlive is the canonical spelling of the one configuration field
// that has NO environment projection and is therefore refused by `config set`.
const ConfigKeyKeepAlive = "keepalive.interval"

// ConfigKeyRefusals maps every CLI spelling of a deliberately non-settable
// configuration field to the reason the operator is shown.
//
// KeepAliveInterval (config.DefaultKeepAlive, 30s) is a fixed deployment
// constant: it has no config.Env* variable, so InstallRequest.Env — the ONLY
// configuration channel the managed units read (the env file) — cannot carry
// it. Accepting the key would let an operator believe a change took effect
// while the running process kept the fixed value, so it is refused explicitly
// and named.
var ConfigKeyRefusals = map[string]string{
	ConfigKeyKeepAlive: "the keepalive interval is a fixed deployment constant (30s) with no environment variable, so it cannot be changed through the protected env file",
	"keepalive":        "the keepalive interval is a fixed deployment constant (30s) with no environment variable, so it cannot be changed through the protected env file",
}

// NormalizeConfigKey canonicalizes a CLI configuration key for lookup:
// lower-cased with '.', '-' and '_' removed, so socks.listen, SOCKS_LISTEN and
// socks-listen are the same field. It performs no validation.
func NormalizeConfigKey(key string) string {
	return strings.NewReplacer(".", "", "-", "", "_", "").Replace(strings.ToLower(strings.TrimSpace(key)))
}

// LookupConfigKey resolves a CLI key (in any accepted spelling) to its
// ConfigKey. ok is false for a field that is not settable.
func LookupConfigKey(key string) (ConfigKey, bool) {
	normalized := NormalizeConfigKey(key)
	for _, k := range ConfigKeys {
		if NormalizeConfigKey(k.Name) == normalized {
			return k, true
		}
	}
	return ConfigKey{}, false
}

// ConfigKeyRefusal returns the documented refusal reason for a
// deliberately non-settable key, or "" when the key is not a known refusal.
func ConfigKeyRefusal(key string) string {
	normalized := NormalizeConfigKey(key)
	for name, reason := range ConfigKeyRefusals {
		if NormalizeConfigKey(name) == normalized {
			return reason
		}
	}
	return ""
}

// ConfigFingerprint returns the configuration identity of the request: the
// digest of the projected env map (Env) in canonical key order. It is the
// value Desired records as DesiredState.ConfigFingerprint and the planner
// compares, so `config set` can tell an operator whether the requested
// configuration actually differs from the committed one WITHOUT the CLI
// re-implementing any comparison.
//
// The digest is non-invertible: no env value (least of all the shared secret)
// is recoverable from it, and it is never printed.
func (r InstallRequest) ConfigFingerprint() (string, error) {
	env, err := r.Env()
	if err != nil {
		return "", err
	}
	return envFingerprint(env), nil
}

// envFingerprint is the canonical digest of a projected env map: keys sorted,
// each rendered as "KEY=VALUE" and joined by newlines. The map is the exact
// projection T5 renders into the protected env file, so an equal
// configuration yields an equal digest and any changed value — the shared
// secret included — yields a different one.
func envFingerprint(env map[string]string) string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(env[k])
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
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
//
// Services are derived from the single authoritative unit plan
// (BuildSystemdPlan), so the manifest records exactly the units the adapter
// deploys — including the cdn plainOrigin case, where no origin unit exists.
func (r InstallRequest) Desired() (DesiredState, error) {
	if err := r.Validate(); err != nil {
		return DesiredState{}, err
	}
	plan, err := BuildSystemdPlan(r)
	if err != nil {
		return DesiredState{}, err
	}
	paths := managedPaths(r)
	for _, spec := range plan.Specs {
		paths.UnitFiles = append(paths.UnitFiles, systemd.UnitDir+"/"+unitName(spec))
	}
	if r.Role == RoleGermany {
		// The version-independent managed pointer the xray unit runs. It is
		// derived from the authoritative systemd constant with a string
		// operation (not filepath.Dir) so the recorded value is the canonical
		// Unix path on every host — the manifest must be host-independent.
		paths.BinaryPointer = strings.TrimSuffix(systemd.XrayBinaryPath, "/xray")
	}
	splitterPath := r.SplitterPath
	if r.Role == RoleIran {
		splitterPath = canonicalIranSplitterPath()
	} else {
		splitterPath = canonicalGermanySplitterPath()
	}
	xray := ComponentState{Version: r.XrayVersion, Path: r.XrayPath, SHA256: r.XraySHA256}
	if r.Role == RoleGermany {
		// The Reality public-parameter fingerprint is xray/germany-only and is
		// kept in its own field, never overloaded onto the binary hash.
		xray.RealityFingerprint = realityFingerprint(r.Reality)
	}
	d := DesiredState{
		Role: r.Role,
		// The configuration identity is derived from the SAME env projection
		// the adapter writes (BuildSystemdPlan already produced it), so the
		// recorded digest always describes what T5 actually rendered.
		ConfigFingerprint: envFingerprint(plan.Env),
		Components: Components{
			Splitter: ComponentState{Version: r.SplitterVersion, Path: splitterPath, SHA256: r.SplitterSHA256},
			Xray:     xray,
			Origin: OriginState{
				Mode:           string(r.Origin.Mode),
				Version:        r.OriginVersion,
				Domain:         r.Origin.Domain,
				UpstreamAddr:   r.Origin.UpstreamAddr,
				OriginPort:     r.Origin.OriginPort,
				ACMEChallenge:  string(r.Origin.ACMEChallenge),
				ACMEEmail:      r.Origin.ACMEEmail,
				CDNSecurity:    string(r.Origin.CDNSecurity),
				CDNOriginTrust: string(r.Origin.CDNOriginTrust),
				CaddyfileHash:  originCaddyfileHash(r.Origin),
			},
		},
		Paths:    paths,
		Services: desiredServices(plan),
		// Desired expresses only install's pairing baseline. install does not
		// own pairing: the pair generate|apply|finalize commands do. The
		// controller carries a committed pairing state forward over this
		// baseline so a re-apply neither detects spurious drift nor clobbers
		// the committed state.
		Pairing:  PairingState{State: PairingStateNone},
		Firewall: FirewallState{Backend: string(r.Firewall.Backend), Ownership: firewall.Marker, RulesHash: firewallFingerprint(r.Firewall)},
	}
	return d, nil
}
