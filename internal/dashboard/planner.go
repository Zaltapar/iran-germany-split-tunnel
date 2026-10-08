package dashboard

import (
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// Safe config keys exposed by the dashboard change planner. This allowlist
// is a strict subset of internal/deploy.ConfigKeys: only non-secret,
// low-risk values are exposed. Secrets, SSH keys, pairing blobs, WARP
// controls, firewall commands, and arbitrary environment keys are
// NEVER in this table.
//
// The dashboard deliberately does not import internal/deploy to keep the
// package tree minimal; the allowlist mirrors deploy.ConfigKeys for the
// keys it exposes and is kept in sync by tests.

// ConfigKeySpec describes one safe, operator-settable configuration field
// the dashboard can plan (but not apply in this release).
type ConfigKeySpec struct {
	// EnvVar is the environment variable name this field projects to.
	EnvVar string
	// Kind is "string", "enum", "bool", or "int".
	Kind string
	// Roles lists the deployment roles the field applies to.
	Roles []string
	// Enums lists the allowed values for enum-kind fields.
	Enums []string
	// Min/Max are the inclusive bounds for int-kind fields.
	Min int64
	Max int64
	// RequiresRestart marks keys whose value is read at process start.
	RequiresRestart bool
	// Description is a short human-readable note shown in the UI.
	Description string
}

// SafeConfigKeys is the dashboard's allowlist. Unknown keys are rejected
// with a clear error.
var SafeConfigKeys = []ConfigKeySpec{
	{
		EnvVar: "SPLIT_METRICS_PORT", Kind: "int",
		Roles: []string{"iran", "germany"},
		Min:   1, Max: 65535, RequiresRestart: true,
		Description: "Loopback-only /metrics listener port; 0 disables metrics",
	},
	{
		EnvVar: "SPLIT_RELAY_BUF", Kind: "int",
		Roles: []string{"iran", "germany"},
		Min:   1024, Max: 8 << 20, RequiresRestart: true,
		Description: "Relay socket read chunk size in bytes",
	},
	{
		EnvVar: "SPLIT_TARGET_ADDR_POLICY", Kind: "enum",
		Roles:           []string{"iran", "germany"},
		Enums:           []string{"default", "prefer-ipv4", "ipv4-only"},
		RequiresRestart: false,
		Description:     "Egress-target address-family policy; ipv4-only is a hard A-record filter and breaks AAAA-only endpoints",
	},
	{
		EnvVar: "SPLIT_TARGET_ONLY_IPV4", Kind: "bool",
		Roles:           []string{"iran", "germany"},
		RequiresRestart: false,
		Description:     "Legacy hard only-IPv4 compatibility flag; prefer SPLIT_TARGET_ADDR_POLICY",
	},
	{
		EnvVar: "SPLIT_STREAM_OVERFLOW_MS", Kind: "int",
		Roles: []string{"iran", "germany"},
		Min:   0, Max: 30000, RequiresRestart: true,
		Description: "Maximum overflow wait in milliseconds",
	},
}

// lookupSafeKey finds the spec for an environment variable name.
func lookupSafeKey(envVar string) (*ConfigKeySpec, bool) {
	for i := range SafeConfigKeys {
		if SafeConfigKeys[i].EnvVar == envVar {
			return &SafeConfigKeys[i], true
		}
	}
	return nil, false
}

// --- Change planning ---

// ChangeRequest is one typed key/value change proposed by a caller.
type ChangeRequest struct {
	// Key is the environment variable name (e.g. "SPLIT_RELAY_BUF").
	Key   string
	Value string
}

// PlanResult is the dry-run plan produced by PlanChanges.
type PlanResult struct {
	PlanID          string
	ServerID        string
	Changes         []ConfigChange
	RestartRequired bool
	AffectedUnits   []string
	Warnings        []string
	Unchanged       bool
}

// validationPattern for int-kind values: optional leading sign forbidden,
// digits only, bounded length to prevent overflow.
var intValuePattern = regexp.MustCompile(`^\d{1,10}$`)

// PlanChanges validates a set of ChangeRequests against the safe allowlist
// and the server's role, producing a redacted, restart-aware plan. It never
// writes files, executes commands, or contacts a host.
//
// planID may be "" to auto-generate one.
func PlanChanges(serverID, role, planID string, changes []ChangeRequest) (*PlanResult, error) {
	if role != "iran" && role != "germany" {
		return nil, fmt.Errorf("dashboard: unknown role %q", role)
	}
	if len(changes) == 0 {
		return nil, fmt.Errorf("dashboard: no changes supplied")
	}
	if planID == "" {
		planID = fmt.Sprintf("plan-%d", time.Now().UnixNano())
	}

	res := &PlanResult{
		PlanID:        planID,
		ServerID:      serverID,
		AffectedUnits: affectedUnitsForRole(role),
	}

	for _, ch := range changes {
		spec, ok := lookupSafeKey(ch.Key)
		if !ok {
			return nil, fmt.Errorf(
				"dashboard: key %q is not in the safe allowlist; only these keys are accepted: %s",
				ch.Key, safeKeyNames())
		}
		if !roleAllowed(spec, role) {
			return nil, fmt.Errorf("dashboard: key %q does not apply to role %q", ch.Key, role)
		}

		before := currentConfigValue(serverID, ch.Key)
		after, warn, err := validateValue(spec, ch.Value, role)
		if err != nil {
			return nil, fmt.Errorf("dashboard: key %q: %w", ch.Key, err)
		}
		res.Warnings = append(res.Warnings, warn...)

		cc := ConfigChange{
			Key:             ch.Key,
			Before:          before,
			After:           after,
			RequiresRestart: spec.RequiresRestart,
		}
		// Mask the value when it is sensitive (defensive; safe keys are not,
		// but future keys might be).
		redacted, wasRedacted := RedactValue(after)
		cc.After = redacted
		cc.Redacted = wasRedacted
		res.Changes = append(res.Changes, cc)
		if spec.RequiresRestart {
			res.RestartRequired = true
		}
	}

	// Key-specific cross-checks.
	if err := checkKeyInteractions(res.Changes); err != nil {
		return nil, err
	}

	res.Unchanged = len(res.Changes) == 0
	return res, nil
}

func safeKeyNames() string {
	out := make([]string, 0, len(SafeConfigKeys))
	for _, k := range SafeConfigKeys {
		out = append(out, k.EnvVar)
	}
	return join(out)
}

func roleAllowed(spec *ConfigKeySpec, role string) bool {
	for _, r := range spec.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// validateValue checks a raw value against the spec and returns the
// normalised value plus warnings.
func validateValue(spec *ConfigKeySpec, value, role string) (string, []string, error) {
	var warns []string
	switch spec.Kind {
	case "int":
		if !intValuePattern.MatchString(value) {
			return "", nil, fmt.Errorf("expected an integer, got %q", value)
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return "", nil, fmt.Errorf("integer out of range: %w", err)
		}
		if n < spec.Min || n > spec.Max {
			return "", nil, fmt.Errorf("value %d out of range %d..%d", n, spec.Min, spec.Max)
		}
		// Normalise to canonical integer form.
		return strconv.FormatInt(n, 10), warns, nil
	case "bool":
		switch value {
		case "true", "false", "1", "0", "t", "f", "TRUE", "False":
		default:
			return "", nil, fmt.Errorf("expected a boolean (true/false, 1/0), got %q", value)
		}
		b, _ := strconv.ParseBool(value)
		return strconv.FormatBool(b), warns, nil
	case "enum":
		for _, allowed := range spec.Enums {
			if value == allowed {
				// ipv4-only is documented as risky; warn the operator.
				if value == "ipv4-only" {
					warns = append(warns, "SPLIT_TARGET_ADDR_POLICY=ipv4-only is a hard A-record filter: it breaks AAAA-only endpoints. Use prefer-ipv4 unless you have confirmed all targets resolve to IPv4.")
				}
				return value, warns, nil
			}
		}
		return "", nil, fmt.Errorf("invalid value %q; allowed: %s", value, join(spec.Enums))
	case "string":
		return value, warns, nil
	default:
		return "", nil, fmt.Errorf("unsupported kind %q", spec.Kind)
	}
}

// checkKeyInteractions enforces cross-key invariants between planned changes.
func checkKeyInteractions(changes []ConfigChange) error {
	byKey := map[string]string{}
	for _, c := range changes {
		byKey[c.Key] = c.After
	}
	onlyIPv4, hasOnlyIPv4 := byKey["SPLIT_TARGET_ONLY_IPV4"]
	_, hasPolicy := byKey["SPLIT_TARGET_ADDR_POLICY"]
	policy, hasPolicyVal := byKey["SPLIT_TARGET_ADDR_POLICY"]
	// A contradictory pair: TargetOnlyIPv4=true together with prefer-ipv4
	// in the SAME plan is a conflict (mirrors config validation).
	if hasOnlyIPv4 && hasPolicyVal && onlyIPv4 == "true" && policy == "prefer-ipv4" {
		return fmt.Errorf("conflicting changes: SPLIT_TARGET_ONLY_IPV4=true contradicts SPLIT_TARGET_ADDR_POLICY=prefer-ipv4")
	}
	_ = hasPolicy
	return nil
}

// currentConfigValue looks up the currently-cached value for a key.
// In this first release it is resolved from the cache if present, and
// otherwise reports the built-in default (empty string).
func currentConfigValue(serverID, key string) string {
	// Cache is consulted lazily by the API layer; the planner itself stays
	// pure. The API injects the "before" value via the plan request context.
	// For the standalone planner the before value is empty (unknown).
	return ""
}

// affectedUnitsForRole returns the systemd units a change in the given role
// would touch. This is informational; nothing is actually restarted.
func affectedUnitsForRole(role string) []string {
	if role == "iran" {
		return []string{"iran-splitter.service"}
	}
	return []string{"germany-splitter.service"}
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// --- Audit log ---

// AuditLog is a bounded, thread-safe local audit event store.
type AuditLog struct {
	mu     sync.RWMutex
	events []AuditEvent
	cap    int
}

// NewAuditLog creates a bounded audit log.
func NewAuditLog(capacity int) *AuditLog {
	if capacity <= 0 {
		capacity = 500
	}
	return &AuditLog{cap: capacity}
}

// Add records an event. Events beyond the cap are dropped from the front.
func (a *AuditLog) Add(e AuditEvent) {
	if e.ID == "" {
		e.ID = fmt.Sprintf("evt-%d", time.Now().UnixNano())
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	if len(a.events) > a.cap {
		// Drop from the front.
		n := len(a.events) - a.cap
		a.events = a.events[n:]
	}
}

// Events returns a copy of the current events, most recent last.
func (a *AuditLog) Events() []AuditEvent {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]AuditEvent, len(a.events))
	copy(out, a.events)
	return out
}

// LastN returns the most recent n events.
func (a *AuditLog) LastN(n int) []AuditEvent {
	all := a.Events()
	if n <= 0 || n >= len(all) {
		return all
	}
	return all[len(all)-n:]
}
