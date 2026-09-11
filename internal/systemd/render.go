// render.go — deterministic systemd unit renderer (design §4.6).
//
// RenderUnit is a pure function: no I/O, no globals, no clock. The same Spec
// always produces the same bytes; the five committed goldens
// (testdata/golden/) pin those bytes exactly (LF, single trailing newline).
//
// Injection surface: the renderer deliberately accepts almost nothing.
// The unit name, the description, every path and the restart/hardening
// policy are fixed per (role, component) — the only caller-controlled
// values are BinPath (validated: absolute, no whitespace, bounded), the
// caddy version (validated: vM.m.p shape, no path characters) and two
// boolean/derived choices. There is no value-carrying Environment= line in
// any generated splitter unit, so a secret can never reach a unit file
// (D4).
package systemd

import (
	"fmt"
	"regexp"
	"strings"
)

// Spec is the input to RenderUnit and to ApplyUnit. See design §6 for the
// T8 integration contract.
type Spec struct {
	Role      Role
	Component Component
	// BinPath is the ExecStart target (xray: the "current" pointer path).
	// Absolute, no whitespace, ≤ 4096 bytes; checked again in ApplyUnit's
	// preflight (must exist and be a regular file).
	BinPath string
	// EnvFile is the D4 env-file path for splitter units ("" for xray and
	// origin — they carry no env lines, caddy excepted: its XDG_DATA_HOME
	// is a fixed path constant, not a secret).
	EnvFile string
	// UnitName is derived by default ("<role>-splitter.service" /
	// "xray-<role>.service" / "<role>-origin.service"); overridable within
	// unitNameRE.
	UnitName string
	// Description is IGNORED (fixed per component; an input-driven
	// description is an injection vector with zero operational value).
	// Documented trap: setting it has no effect.
	Description string
	// OriginVersion: origin component only — the pinned caddy version
	// (T8 passes origin.PinnedVersion). Must match vM.m.p.
	OriginVersion string
	// OriginEnabled: iran splitter only — false renders the 5th golden
	// (no reference to iran-origin.service when origin mode is none).
	OriginEnabled bool
	// RequiresUnits: unit names that MUST exist as files before ApplyUnit
	// proceeds (preflight-enforced; e.g. germany-splitter →
	// ["xray-germany.service"]).
	RequiresUnits []string
}

// versionRE validates a pinned version token (same shape as the T2/T4
// pins: vM.m.p) — also rejects path separators and whitespace.
var versionRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// defaultUnitName derives the canonical unit name for a spec.
func (s Spec) defaultUnitName() (string, error) {
	switch s.Component {
	case ComponentSplitter:
		return string(s.Role) + "-splitter.service", nil
	case ComponentXray:
		if s.Role != RoleGermany {
			return "", fmt.Errorf("%w: component %q is germany-only (got role %q)", ErrSpec, s.Component, s.Role)
		}
		return "xray-germany.service", nil
	case ComponentOrigin:
		if s.Role != RoleIran {
			return "", fmt.Errorf("%w: component %q is iran-only (got role %q)", ErrSpec, s.Component, s.Role)
		}
		return "iran-origin.service", nil
	default:
		return "", fmt.Errorf("%w: unknown component %q", ErrSpec, s.Component)
	}
}

// unitName returns the effective unit name (derived when empty).
func (s Spec) unitName() (string, error) {
	name := s.UnitName
	if name == "" {
		var err error
		name, err = s.defaultUnitName()
		if err != nil {
			return "", err
		}
	}
	if !unitNameRE.MatchString(name) {
		return "", fmt.Errorf("%w: unit name %q must match %s", ErrSpec, name, unitNameRE.String())
	}
	return name, nil
}

// validate checks every field at render time (fail before any I/O).
func (s Spec) validate() error {
	if s.Role != RoleGermany && s.Role != RoleIran {
		return fmt.Errorf("%w: role must be %q or %q (got %q)", ErrSpec, RoleGermany, RoleIran, s.Role)
	}
	if _, err := s.unitName(); err != nil {
		return err
	}
	if s.Component == ComponentOrigin && s.Role != RoleIran {
		return fmt.Errorf("%w: component %q is iran-only (got role %q)", ErrSpec, s.Component, s.Role)
	}
	if s.Component == ComponentXray && s.Role != RoleGermany {
		return fmt.Errorf("%w: component %q is germany-only (got role %q)", ErrSpec, s.Component, s.Role)
	}
	if s.BinPath == "" {
		return fmt.Errorf("%w: BinPath is empty", ErrSpec)
	}
	if !isAbsPath(s.BinPath) {
		return fmt.Errorf("%w: BinPath must be absolute (got a non-absolute path)", ErrSpec)
	}
	if strings.ContainsAny(s.BinPath, " \t\n") {
		return fmt.Errorf("%w: BinPath must not contain whitespace", ErrSpec)
	}
	if len(s.BinPath) > maxBinPathLen {
		return fmt.Errorf("%w: BinPath exceeds %d bytes", ErrSpec, maxBinPathLen)
	}
	switch s.Component {
	case ComponentSplitter:
		want := canonicalEnvFile(s.Role)
		if s.EnvFile != want {
			return fmt.Errorf("%w: splitter EnvFile must be %q (got %q)", ErrSpec, want, s.EnvFile)
		}
		if s.OriginVersion != "" {
			return fmt.Errorf("%w: OriginVersion is origin-only (got it on component %q)", ErrSpec, s.Component)
		}
	case ComponentXray:
		if s.EnvFile != "" {
			return fmt.Errorf("%w: xray units carry no env file (got %q)", ErrSpec, s.EnvFile)
		}
		if s.OriginVersion != "" {
			return fmt.Errorf("%w: OriginVersion is origin-only (got it on component %q)", ErrSpec, s.Component)
		}
	case ComponentOrigin:
		if s.EnvFile != "" {
			return fmt.Errorf("%w: origin units carry no env file (got %q)", ErrSpec, s.EnvFile)
		}
		if !versionRE.MatchString(s.OriginVersion) {
			return fmt.Errorf("%w: OriginVersion must match vM.m.p (got a malformed version token)", ErrSpec)
		}
	}
	for _, u := range s.RequiresUnits {
		if !unitNameRE.MatchString(u) {
			return fmt.Errorf("%w: RequiresUnits entry %q must match %s", ErrSpec, u, unitNameRE.String())
		}
	}
	return nil
}

// descriptions are FIXED per (role, component) — byte-pinned by the
// goldens. An input-driven description is an injection vector for zero
// operational value, so Spec.Description is ignored.
var descriptions = map[Role]map[Component]string{
	RoleGermany: {
		ComponentSplitter: "germany-splitter (asymmetric split-tunnel)",
		ComponentXray:     "Xray core (Germany down-carrier, VLESS+Reality)",
	},
	RoleIran: {
		ComponentSplitter: "iran-splitter (asymmetric split-tunnel)",
		ComponentOrigin:   "Caddy up-carrier origin (iran)",
	},
}

// unitBase is the unit name without the ".service" suffix.
func unitBase(name string) string { return name[:len(name)-len(".service")] }

// RenderUnit renders the unit file for s. Output is deterministic
// (golden-pinned): LF line endings, keys in a fixed order per section, a
// single trailing newline. It performs no I/O.
func RenderUnit(s Spec) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	name, err := s.unitName()
	if err != nil {
		return nil, err
	}

	base := unitBase(name)
	var b strings.Builder
	b.WriteString("# " + name + "\n")
	b.WriteString("[Unit]\n")
	b.WriteString("Description=" + descriptions[s.Role][s.Component] + "\n")
	after, wants := s.orderingTargets()
	b.WriteString("After=" + strings.Join(after, " ") + "\n")
	b.WriteString("Wants=" + strings.Join(wants, " ") + "\n")
	b.WriteString("StartLimitIntervalSec=300\n")
	b.WriteString("StartLimitBurst=10\n")
	b.WriteString("\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("User=" + ServiceUser + "\n")
	b.WriteString("Group=" + ServiceGroup + "\n")
	// Key order inside [Service] is golden-pinned per component:
	// ExecStart/Environment first, then Restart, RestartSec, the
	// per-component restart extras, and LimitNOFILE — byte-identical to
	// testdata/golden/ (design §4.6).
	switch s.Component {
	case ComponentSplitter:
		b.WriteString("ExecStart=" + s.BinPath + "\n")
		b.WriteString("EnvironmentFile=" + s.EnvFile + "\n")
		b.WriteString("Restart=always\n")
	case ComponentXray:
		b.WriteString("ExecStart=" + s.BinPath + " run -config " + StateDir + "/xray-germany.json\n")
		b.WriteString("Restart=on-failure\n")
	case ComponentOrigin:
		b.WriteString("Environment=XDG_DATA_HOME=" + DataDir + "\n")
		b.WriteString("ExecStart=" + s.BinPath + " run --config " + StateDir + "/Caddyfile --adapter caddyfile\n")
		b.WriteString("Restart=on-failure\n")
	}
	b.WriteString("RestartSec=5\n")
	switch s.Component {
	case ComponentXray:
		// RestartPreventExitStatus=23: a config error keeps the unit down
		// (observable) instead of looping — design §4.3 (§11 finding 12).
		b.WriteString("RestartPreventExitStatus=23\n")
		b.WriteString("AmbientCapabilities=CAP_NET_BIND_SERVICE\n")
		b.WriteString("CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n")
		b.WriteString("LimitNOFILE=100000\n")
	default:
		b.WriteString("LimitNOFILE=65535\n")
	}
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("ProtectSystem=full\n")
	b.WriteString("ProtectHome=true\n")
	switch s.Component {
	case ComponentXray:
		b.WriteString("ReadWritePaths=" + LogDir + "\n")
	case ComponentOrigin:
		b.WriteString("ReadWritePaths=" + DataDir + "\n")
	}
	b.WriteString("StandardOutput=journal\n")
	b.WriteString("StandardError=journal\n")
	b.WriteString("SyslogIdentifier=" + base + "\n")
	b.WriteString("\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return []byte(b.String()), nil
}

// orderingTargets returns the (After, Wants) target lists in canonical
// order: network-online.target first, then the same-role companion unit.
// Wants (never Requires/BindsTo): the splitter must keep running if its
// companion dies (design §4.2).
func (s Spec) orderingTargets() (after, wants []string) {
	after = append(after, "network-online.target")
	wants = append(wants, "network-online.target")
	switch s.Component {
	case ComponentXray:
		// germany-splitter orders AFTER xray; xray itself only wants the network.
	case ComponentSplitter:
		if s.Role == RoleGermany {
			after = append(after, "xray-germany.service")
			wants = append(wants, "xray-germany.service")
		}
		if s.Role == RoleIran && s.OriginEnabled {
			after = append(after, "iran-origin.service")
			wants = append(wants, "iran-origin.service")
		}
	}
	return after, wants
}

// isAbsPath: absolute for the target platform. Linux is the deployment
// platform; the Windows prefix is accepted too so the renderer (a pure
// function) stays testable cross-platform.
func isAbsPath(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	// Windows absolute form: drive letter + colon + separator
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}
