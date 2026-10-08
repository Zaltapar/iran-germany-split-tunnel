package systemd

// extra_units.go — renderer for the one-click installer's additional units:
//   - xray-consumer.service   (Iran: project-managed Xray consumer)
//   - tunneldash.service       (Germany: dashboard host, hardened)
//
// These are pure functions of a small set of validated constants. The
// unit names are fixed; the renderer emits deterministic bytes (golden
// tested). The units carry NO secret material: all paths are the fixed
// canonical constants, and environment is wired through EnvironmentFile=
// (the D4 pattern) or is absent.

import (
	"fmt"
	"regexp"
	"strings"
)

// basePathRE validates a dashboard BasePath: a 32-char lowercase hex
// string. The installer generates one via crypto/rand and passes it here
// only as a *fixed string constant* in the rendered unit (it is part of
// the access surface, not a secret in the D4 sense; it is stored in
// /etc/split-tunnel/dashboard.env).
var basePathRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ExtraUnitSpec is the minimal input for the two extra units. It is
// intentionally far smaller than Spec: the injection surface is the two
// binary paths and (for tunneldash) the dashboard base path.
type ExtraUnitSpec struct {
	Unit       string // "xray-consumer.service" or "tunneldash.service"
	BinPath    string // ExecStart binary (absolute)
	BasePath   string // tunneldash only: 32-hex ("" for xray-consumer)
	EnvFile    string // tunneldash only: absolute env file path ("" for xray-consumer)
	ConfigPath string // tunneldash: absolute dashboard config.json path
}

// RenderExtraUnit renders one of the two extra units. Output is
// deterministic (LF, single trailing newline).
func RenderExtraUnit(s ExtraUnitSpec) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	switch s.Unit {
	case "xray-consumer.service":
		return renderXrayConsumer(s), nil
	case "tunneldash.service":
		return renderTunneldash(s), nil
	default:
		return nil, fmt.Errorf("%w: unknown extra unit %q", ErrSpec, s.Unit)
	}
}

func (s ExtraUnitSpec) validate() error {
	if s.Unit != "xray-consumer.service" && s.Unit != "tunneldash.service" {
		return fmt.Errorf("%w: unknown unit name %q", ErrSpec, s.Unit)
	}
	if !unitNameRE.MatchString(s.Unit) {
		return fmt.Errorf("%w: unit name %q must match %s", ErrSpec, s.Unit, unitNameRE.String())
	}
	if s.BinPath == "" {
		return fmt.Errorf("%w: BinPath is empty", ErrSpec)
	}
	if !isAbsPath(s.BinPath) {
		return fmt.Errorf("%w: BinPath must be absolute", ErrSpec)
	}
	if strings.ContainsAny(s.BinPath, " \t\n") {
		return fmt.Errorf("%w: BinPath must not contain whitespace", ErrSpec)
	}
	if len(s.BinPath) > maxBinPathLen {
		return fmt.Errorf("%w: BinPath exceeds %d bytes", ErrSpec, maxBinPathLen)
	}
	switch s.Unit {
	case "xray-consumer.service":
		if s.BasePath != "" || s.EnvFile != "" || s.ConfigPath != "" {
			return fmt.Errorf("%w: xray-consumer carries no BasePath/EnvFile/ConfigPath", ErrSpec)
		}
	case "tunneldash.service":
		if !basePathRE.MatchString(s.BasePath) {
			return fmt.Errorf("%w: tunneldash BasePath must be 32 lowercase hex chars", ErrSpec)
		}
		if s.EnvFile == "" || !isAbsPath(s.EnvFile) {
			return fmt.Errorf("%w: tunneldash EnvFile must be an absolute path", ErrSpec)
		}
		if s.ConfigPath == "" || !isAbsPath(s.ConfigPath) {
			return fmt.Errorf("%w: tunneldash ConfigPath must be an absolute path", ErrSpec)
		}
	}
	return nil
}

// renderXrayConsumer emits the Iran Xray consumer unit. It runs as
// split-tunnel (non-root), reads its config from the state dir, and logs
// to the project log dir. The binary is the versioned xray "current"
// pointer (same as Germany's xray-germany.service pattern).
func renderXrayConsumer(s ExtraUnitSpec) []byte {
	var b strings.Builder
	b.WriteString("# xray-consumer.service\n")
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Xray core (Iran up-carrier consumer, VLESS+Reality)\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("StartLimitIntervalSec=300\n")
	b.WriteString("StartLimitBurst=10\n")
	b.WriteString("\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("User=" + ServiceUser + "\n")
	b.WriteString("Group=" + ServiceGroup + "\n")
	b.WriteString("ExecStart=" + s.BinPath + " run -config " + StateDir + "/xray-consumer.json\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=5\n")
	b.WriteString("RestartPreventExitStatus=23\n")
	b.WriteString("LimitNOFILE=100000\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("ProtectSystem=full\n")
	b.WriteString("ProtectHome=true\n")
	b.WriteString("ReadWritePaths=" + LogDir + "\n")
	b.WriteString("StandardOutput=journal\n")
	b.WriteString("StandardError=journal\n")
	b.WriteString("SyslogIdentifier=xray-consumer\n")
	b.WriteString("\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return []byte(b.String())
}

// renderTunneldash emits the hardened Germany dashboard unit. It runs as
// split-tunnel (non-root), reads its config + env file, and is confined
// to the project log dir + state dir for read-only state.
func renderTunneldash(s ExtraUnitSpec) []byte {
	var b strings.Builder
	b.WriteString("# tunneldash.service\n")
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Split-tunnel monitoring dashboard (tunneldash)\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("StartLimitIntervalSec=300\n")
	b.WriteString("StartLimitBurst=10\n")
	b.WriteString("\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("User=" + ServiceUser + "\n")
	b.WriteString("Group=" + ServiceGroup + "\n")
	b.WriteString("EnvironmentFile=" + s.EnvFile + "\n")
	b.WriteString("ExecStart=" + s.BinPath + " -config " + s.ConfigPath + "\n")
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=5\n")
	b.WriteString("LimitNOFILE=65535\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("ProtectSystem=full\n")
	b.WriteString("ProtectHome=true\n")
	b.WriteString("ProtectKernelTun=true\n")
	b.WriteString("ProtectKernelModules=true\n")
	b.WriteString("ProtectControlGroups=true\n")
	b.WriteString("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n")
	b.WriteString("RestrictNamespaces=user\n")
	b.WriteString("RestrictRealtime=true\n")
	b.WriteString("RestrictSUIDSGID=true\n")
	b.WriteString("LockPersonality=true\n")
	b.WriteString("MemoryDenyWriteExecute=true\n")
	b.WriteString("SystemCallArchitectures=native\n")
	b.WriteString("CapabilityBoundingSet=\n")
	b.WriteString("ReadWritePaths=" + LogDir + "\n")
	b.WriteString("StandardOutput=journal\n")
	b.WriteString("StandardError=journal\n")
	b.WriteString("SyslogIdentifier=tunneldash\n")
	b.WriteString("\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return []byte(b.String())
}
