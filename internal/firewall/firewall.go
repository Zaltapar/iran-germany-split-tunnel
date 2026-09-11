// Package firewall manages only project-owned host firewall rules.
//
// It never invokes a shell, flushes a ruleset, changes the host default
// policy, or removes rules it did not create. Production callers use the
// UFW or nftables adapters; tests inject an Executor or use Fake.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const Marker = "split-tunnel"

type Backend string

const (
	BackendAuto Backend = "auto"
	BackendUFW  Backend = "ufw"
	BackendNFT  Backend = "nftables"
	BackendNone Backend = "none"
)

var (
	ErrInvalidPlan = errors.New("firewall: invalid plan")
	ErrConflict    = errors.New("firewall: port conflict")
	ErrAmbiguous   = errors.New("firewall: multiple active managers")
	ErrUnsupported = errors.New("firewall: unsupported backend")
)

type Rule struct {
	Port     int
	Protocol string
	Action   string
	Comment  string
}

type Plan struct {
	Backend   Backend
	Role      string
	Allow     []Rule
	Deny      []Rule
	CDNEgress []string
}

type Snapshot struct {
	Backend Backend
	Rules   []Rule
}

type Result struct {
	Backend   Backend
	Added     []Rule
	Removed   []Rule
	Unchanged bool
}

type Executor interface {
	Run(context.Context, ...string) (string, error)
}

type OSExecutor struct{}

func (OSExecutor) Run(ctx context.Context, args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("firewall: empty command")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("firewall: %s failed: %w", args[0], err)
	}
	return text, nil
}

type Manager interface {
	Detect(context.Context) (Backend, error)
	Inspect(context.Context, Plan) (Snapshot, error)
	Apply(context.Context, Plan) (Result, error)
	Remove(context.Context, Snapshot) error
}

type manager struct {
	ex Executor
}

func New(ex Executor) Manager {
	if ex == nil {
		ex = OSExecutor{}
	}
	return &manager{ex: ex}
}

func (m *manager) Detect(ctx context.Context) (Backend, error) {
	if runtime.GOOS != "linux" {
		return BackendNone, nil
	}
	ufw := commandExists("ufw")
	nft := commandExists("nft")
	if ufw && nft {
		// UFW is a frontend over nftables on some hosts. Inspecting both
		// cannot safely establish ownership, so auto mode fails closed.
		return "", ErrAmbiguous
	}
	if ufw {
		return BackendUFW, nil
	}
	if nft {
		return BackendNFT, nil
	}
	return BackendNone, nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (m *manager) Inspect(ctx context.Context, p Plan) (Snapshot, error) {
	if err := validatePlan(p); err != nil {
		return Snapshot{}, err
	}
	b, err := m.backend(ctx, p.Backend)
	if err != nil {
		return Snapshot{}, err
	}
	if b == BackendNone {
		return Snapshot{Backend: b}, nil
	}
	out, err := m.ex.Run(ctx, backendCommand(b, "inspect")...)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Backend: b, Rules: parseRules(b, out)}, nil
}

func (m *manager) Apply(ctx context.Context, p Plan) (Result, error) {
	if err := validatePlan(p); err != nil {
		return Result{}, err
	}
	b, err := m.backend(ctx, p.Backend)
	if err != nil {
		return Result{}, err
	}
	if b == BackendNone {
		return Result{Backend: b, Unchanged: true}, nil
	}
	s, err := m.Inspect(ctx, p)
	if err != nil {
		return Result{}, err
	}
	want := append(append([]Rule{}, p.Allow...), p.Deny...)
	missing := difference(want, s.Rules)
	if len(missing) == 0 {
		return Result{Backend: b, Unchanged: true}, nil
	}
	added := make([]Rule, 0, len(missing))
	for _, r := range missing {
		args := ruleCommand(b, "add", r)
		if _, err := m.ex.Run(ctx, args...); err != nil {
			// Restore the pre-apply firewall snapshot before returning. If
			// an inverse command fails, preserve that fact in the returned
			// error so deploy can stop and require operator recovery.
			for i := len(added) - 1; i >= 0; i-- {
				if _, rollbackErr := m.ex.Run(ctx, ruleCommand(b, "remove", added[i])...); rollbackErr != nil {
					return Result{Backend: b, Added: added}, fmt.Errorf("firewall: apply failed: %w; rollback failed: %v", err, rollbackErr)
				}
			}
			return Result{Backend: b, Added: added}, fmt.Errorf("firewall: apply %s/%d: %w", r.Protocol, r.Port, err)
		}
		added = append(added, r)
	}
	return Result{Backend: b, Added: added}, nil
}

func (m *manager) Remove(ctx context.Context, s Snapshot) error {
	if s.Backend == BackendNone {
		return nil
	}
	for _, r := range s.Rules {
		if r.Comment != Marker {
			continue
		}
		if _, err := m.ex.Run(ctx, ruleCommand(s.Backend, "remove", r)...); err != nil {
			return fmt.Errorf("firewall: remove %s/%d: %w", r.Protocol, r.Port, err)
		}
	}
	return nil
}

func (m *manager) backend(ctx context.Context, requested Backend) (Backend, error) {
	if requested != "" && requested != BackendAuto {
		if requested != BackendUFW && requested != BackendNFT && requested != BackendNone {
			return "", fmt.Errorf("%w: %q", ErrUnsupported, requested)
		}
		return requested, nil
	}
	return m.Detect(ctx)
}

// ValidatePlan exposes pure firewall-plan validation to deployment
// orchestration. It performs no command execution or host mutation.
func ValidatePlan(p Plan) error { return validatePlan(p) }

func validatePlan(p Plan) error {
	if p.Role != "iran" && p.Role != "germany" {
		return fmt.Errorf("%w: role must be iran or germany", ErrInvalidPlan)
	}
	if p.Backend != "" && p.Backend != BackendAuto && p.Backend != BackendUFW && p.Backend != BackendNFT && p.Backend != BackendNone {
		return fmt.Errorf("%w: unknown backend", ErrInvalidPlan)
	}
	for _, r := range append(append([]Rule{}, p.Allow...), p.Deny...) {
		if r.Port < 1 || r.Port > 65535 || r.Protocol != "tcp" || (r.Action != "allow" && r.Action != "deny") {
			return fmt.Errorf("%w: invalid rule", ErrInvalidPlan)
		}
		if r.Comment != "" && r.Comment != Marker {
			return fmt.Errorf("%w: unmanaged comment", ErrInvalidPlan)
		}
	}
	return nil
}

func difference(want, have []Rule) []Rule {
	var out []Rule
	for _, r := range want {
		found := false
		for _, h := range have {
			if sameRule(r, h) {
				found = true
				break
			}
		}
		if !found {
			out = append(out, r)
		}
	}
	return out
}

func sameRule(a, b Rule) bool {
	return a.Port == b.Port && a.Protocol == b.Protocol && a.Action == b.Action && a.Comment == b.Comment
}

func backendCommand(b Backend, op string) []string {
	switch b {
	case BackendUFW:
		return []string{"ufw", "status", "number"}
	case BackendNFT:
		return []string{"nft", "list", "table", "inet", "split_tunnel"}
	default:
		return []string{string(b), op}
	}
}

func ruleCommand(b Backend, op string, r Rule) []string {
	port := strconv.Itoa(r.Port) + "/" + r.Protocol
	switch b {
	case BackendUFW:
		if op == "remove" {
			return []string{"ufw", "delete", r.Action, port}
		}
		return []string{"ufw", r.Action, port, "comment", Marker}
	case BackendNFT:
		verb := "add"
		if op == "remove" {
			verb = "delete"
		}
		return []string{"nft", verb, "rule", "inet", "split_tunnel", "input", r.Protocol, "dport", strconv.Itoa(r.Port), r.Action}
	default:
		return []string{string(b), op, port}
	}
}

func parseRules(b Backend, text string) []Rule {
	// Parsing is deliberately conservative: only lines carrying the stable
	// project marker become owned rules. Unknown output is never treated as
	// project ownership.
	var rules []Rule
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, Marker) {
			continue
		}
		fields := strings.Fields(line)
		action := "allow"
		for _, field := range fields {
			switch strings.ToLower(field) {
			case "allow", "deny", "reject":
				action = strings.ToLower(field)
			}
		}
		if action == "reject" {
			action = "deny"
		}
		for _, field := range fields {
			if strings.HasSuffix(field, "/tcp") {
				parts := strings.Split(field, "/")
				port, err := strconv.Atoi(parts[0])
				if err == nil && port > 0 && port <= 65535 {
					rules = append(rules, Rule{Port: port, Protocol: "tcp", Action: action, Comment: Marker})
				}
			}
		}
	}
	return rules
}
