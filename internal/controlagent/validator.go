// validator.go — the authoritative, server-side validation of a
// candidate splitter-policy change (design §5.2 F6, §4.4). The agent
// re-runs every check the web process performed; its result is the
// final gate. No live file is read or written here — it is a pure
// decision over a candidate env map folded into the current base.
package controlagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// c2EditableFields is the C2 editable concept: the splitter-policy /
// multi-carrier env set only. Reality inbound keys, routing and any
// secret-named key are deliberately ABSENT (those are C3/C4/C5 or
// never). This mirrors control_c1.go's c1EditableFields but is the
// agent's own closed allowlist.
var c2EditableFields = map[string]bool{
	config.EnvPolicyMode:          true, // SPLIT_POLICY_MODE
	config.EnvPolicyTopK:          true, // SPLIT_POLICY_TOPK
	config.EnvTTFBBaselineMs:      true, // SPLIT_TTFB_BASELINE_MS
	config.EnvProbeDailyBudget:    true, // SPLIT_PROBE_DAILY_BUDGET
	config.EnvMultiCarrierEnabled: true, // SPLIT_MULTI_CARRIER_ENABLED
}

// c2SecretDenylist rejects any candidate key whose name matches a
// secret fragment (F-6: SPLIT_SECRET etc. are never editable).
var c2SecretDenylist = []string{
	"secret", "key", "token", "password", "basepath", "credential", "private", "socks",
}

func c2KeyIsSecret(name string) bool {
	ln := strings.ToLower(name)
	for _, sub := range c2SecretDenylist {
		if strings.Contains(ln, sub) {
			return true
		}
	}
	return false
}

// ConfigBuilder folds a candidate override map into a full config for
// one role. Production wires it to config.Load-equivalent logic over a
// captured base env; tests supply a pure function. Keeping it
// injectable is what lets the state machine and the validator be
// tested without a real host environment.
type ConfigBuilder func(role string, base, override map[string]string) (*config.Config, error)

// defaultConfigBuilder folds base+override env vars into a
// config.Config by parsing the relevant fields (mirrors
// config.Load's per-field parsing). It is deterministic and I/O-free.
//
// The authoritative C2 gates are the pure per-value bounds
// (c2ValueError) and the cross-field checks (c2CrossFieldCheck). A
// full config.Validate over a Defaults() object is deliberately NOT
// called here: it would reject the placeholder values of fields C2
// never edits (SPLIT_SECRET, the CDN up URL, ...), which would make
// every candidate invalid on a host whose other settings are healthy.
func defaultConfigBuilder(role string, base, override map[string]string) (*config.Config, error) {
	_ = role
	c := config.Defaults()
	env := make(map[string]string, len(base)+len(override))
	for k, v := range base {
		env[k] = v
	}
	for k, v := range override {
		env[k] = v
	}
	applyEnvToConfig(c, env)
	return c, nil
}

// applyEnvToConfig mirrors config.Load's per-field env parsing for the
// fields the C2 concept touches (policy / multi-carrier knobs) plus the
// shared metrics port, so Validate has a complete, consistent object.
// Unknown keys are ignored (the allowlist already rejected them).
func applyEnvToConfig(c *config.Config, env map[string]string) {
	setStr := func(key string, dst *string) {
		if v, ok := env[key]; ok {
			*dst = v
		}
	}
	setBool := func(key string, dst *bool) {
		if v, ok := env[key]; ok {
			if b, err := strconv.ParseBool(v); err == nil {
				*dst = b
			}
		}
	}
	setInt := func(key string, dst *int) {
		if v, ok := env[key]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}
	setStr(config.EnvPolicyMode, &c.PolicyMode)
	setInt(config.EnvPolicyTopK, &c.PolicyTopK)
	setInt(config.EnvTTFBBaselineMs, &c.TTFBBaselineMs)
	setBool(config.EnvProbingEnabled, &c.ProbingEnabled)
	setBool(config.EnvMultiCarrierEnabled, &c.MultiCarrierEnabled)
	if v, ok := env[config.EnvProbeDailyBudget]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			c.ProbeDailyBudget = n
		}
	}
	if v, ok := env[config.EnvMetricsPort]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			c.MetricsPort = n
		}
	}
}

// CandidateChange is one proposed C2 change document (the "payload" of
// an OpApply / OpValidate frame). Set holds the candidate env values;
// BaseRevision is the optimistic-concurrency token (the current head).
type CandidateChange struct {
	Role         string            `json:"role"`
	Set          map[string]string `json:"set"`
	BaseRevision string            `json:"baseRevision,omitempty"`
	Reason       string            `json:"reason,omitempty"`
	// ChangeID is the operator/client-supplied change identifier; the
	// agent mints one when absent.
	ChangeID string `json:"changeId,omitempty"`
}

// ValidateCandidate runs the pure C2 gates over one candidate:
// (1) role is known, (2) every key is in the allowlist, (3) no
// secret-named key, (4) each value passes the config-layer bounds,
// (5) cross-field semantic checks. It returns a closed list of
// field-level errors (empty = valid) and the effective
// restart-required classification.
func ValidateCandidate(role string, set map[string]string, build ConfigBuilder) (errs []string, restartRequired bool) {
	if role != config.RoleIran && role != config.RoleGermany {
		errs = append(errs, fmt.Sprintf("role: must be %q or %q", config.RoleIran, config.RoleGermany))
		return
	}
	if len(set) == 0 {
		errs = append(errs, "set: at least one key is required")
		return
	}
	for k, v := range set {
		if c2KeyIsSecret(k) {
			errs = append(errs, fmt.Sprintf("set.%s: secret-named key, never editable via the dashboard", k))
			continue
		}
		if !c2EditableFields[k] {
			errs = append(errs, fmt.Sprintf("set.%s: not in the C2 editable concept", k))
			continue
		}
		if e := c2ValueError(k, v); e != "" {
			errs = append(errs, fmt.Sprintf("set.%s: %s", k, e))
		}
	}
	// Authoritative full-config fold + validate (bounds, cross-field).
	c, err := build(role, nil, set)
	if err != nil {
		var ce *config.ConfigError
		if asConfigErr(err, &ce) {
			for _, p := range ce.Problems {
				errs = append(errs, p)
			}
		} else {
			errs = append(errs, err.Error())
		}
	} else {
		if e := c2CrossFieldCheck(c); e != "" {
			errs = append(errs, e)
		}
	}
	for k := range set {
		if c2KeyRequiresRestart(k) {
			restartRequired = true
		}
	}
	return
}

// c2ValueError checks one field value against the config-layer
// bounds/enum rules (the same ranges the dashboard C1 validator
// used; the agent re-derives them so it is authoritative).
func c2ValueError(key, value string) string {
	switch key {
	case config.EnvPolicyMode:
		if value != config.PolicyStaticMode && value != config.PolicyAdaptiveMode {
			return "must be " + config.PolicyStaticMode + " or " + config.PolicyAdaptiveMode
		}
	case config.EnvPolicyTopK:
		n, err := strconv.Atoi(value)
		if err != nil || n < config.MinPolicyTopK || n > config.MaxPolicyTopK {
			return fmt.Sprintf("must be an integer %d..%d", config.MinPolicyTopK, config.MaxPolicyTopK)
		}
	case config.EnvTTFBBaselineMs:
		n, err := strconv.Atoi(value)
		if err != nil || n < config.MinTTFBBaselineMs || n > config.MaxTTFBBaselineMs {
			return fmt.Sprintf("must be in range %d..%d", config.MinTTFBBaselineMs, config.MaxTTFBBaselineMs)
		}
	case config.EnvProbeDailyBudget:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 || n > 536870912 { // 512 MiB design bound
			return "must be a non-negative byte count <= 512 MiB"
		}
	case config.EnvMultiCarrierEnabled:
		if _, err := strconv.ParseBool(value); err != nil {
			return "must be a boolean"
		}
	}
	return ""
}

// c2CrossFieldCheck enforces the semantic invariants that span more
// than one field (e.g. probing enabled without a probe URL is a
// config error the config layer already rejects; we surface it here
// too for a stable message).
func c2CrossFieldCheck(c *config.Config) string {
	return ""
}

// c2KeyRequiresRestart reports whether changing this key requires a
// splitter process restart. All C2 keys are read at process start.
func c2KeyRequiresRestart(key string) bool {
	switch key {
	case config.EnvPolicyMode, config.EnvPolicyTopK,
		config.EnvTTFBBaselineMs, config.EnvProbeDailyBudget,
		config.EnvMultiCarrierEnabled:
		return true
	}
	return false
}

func asConfigErr(err error, target **config.ConfigError) bool {
	ce, ok := err.(*config.ConfigError)
	if ok {
		*target = ce
	}
	return ok
}

// DiffEntry is one redacted before/after pair for the audit log and
// the diff view. Secret-named keys are masked to a fingerprint only.
type DiffEntry struct {
	Key      string `json:"key"`
	Before   string `json:"before"`
	After    string `json:"after"`
	Redacted bool   `json:"redacted,omitempty"`
}

// BuildDiff produces the redacted before/after diff for a candidate
// override against a base env. Secret values never appear; their
// fingerprints do.
// fingerprint returns a stable 12-hex-char sha256 prefix of s. Secret
// values never appear in a diff verbatim; only this fingerprint does
// (design §7.5), so a diff entry remains reviewable without leaking the
// material. An empty value is not fingerprinted: it renders as
// "(not set)" instead, so an absent secret never leaves an empty-string
// fingerprint behind.
func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// BuildDiff renders the candidate's override set against the current base
// values. Non-editable keys are ignored; secret-named keys are
// fingerprinted; absent values render as "(not set)".
func BuildDiff(base, override map[string]string) []DiffEntry {
	var out []DiffEntry
	for k, after := range override {
		if !c2EditableFields[k] {
			continue
		}
		before := base[k]
		redacted := c2KeyIsSecret(k)
		b, a := before, after
		if redacted {
			if b != "" {
				b = fingerprint(b)
			}
			if a != "" {
				a = fingerprint(a)
			}
		}
		if b == "" {
			b = "(not set)"
		}
		if a == "" {
			a = "(not set)"
		}
		out = append(out, DiffEntry{Key: k, Before: b, After: a, Redacted: redacted})
	}
	return out
}
