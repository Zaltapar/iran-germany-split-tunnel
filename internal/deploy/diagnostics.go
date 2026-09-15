package deploy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

type Severity string

const (
	SeverityPass Severity = "pass"
	SeverityWarn Severity = "warn"
	SeverityFail Severity = "fail"
)

type Finding struct {
	ID       string
	Severity Severity
	Summary  string
	Action   string
	Redacted bool
}

type Check struct {
	ID  string
	Run func(context.Context) Finding
}

type Diagnostics struct {
	Store  *Store
	Checks []Check
}

func (d Diagnostics) Run(ctx context.Context) []Finding {
	findings := make([]Finding, 0, len(d.Checks)+1)
	if d.Store != nil {
		if _, err := d.Store.Load(); err != nil {
			findings = append(findings, Finding{ID: "state.integrity", Severity: SeverityFail, Summary: "deployment state is unreadable or tampered", Action: "restore a retained revision or run recovery", Redacted: true})
		} else {
			findings = append(findings, Finding{ID: "state.integrity", Severity: SeverityPass, Summary: "deployment state integrity verified", Redacted: true})
		}
	}
	for _, check := range d.Checks {
		if check.Run == nil {
			findings = append(findings, Finding{ID: check.ID, Severity: SeverityFail, Summary: "diagnostic check is not configured", Action: "reconfigure the diagnostic provider", Redacted: true})
			continue
		}
		f := check.Run(ctx)
		if f.ID == "" {
			f.ID = check.ID
		}
		f.Redacted = true
		findings = append(findings, f)
	}
	return findings
}

// StateDirCheck returns the read-only doctor check for the state-directory
// permission chain (DEFECT-2). The chain must be 0750 root:split-tunnel with
// live service-readable configs 0640 root:split-tunnel (T5's EnsureStateDir
// contract); a drift — most importantly a 0700 directory — locks the
// User=split-tunnel services out of the very configs they start with, and a
// converged no-op install does NOT heal it because Transaction.Apply returns
// before any adapter phase runs.
//
// The check inspects and reports only: it NEVER chmods, chowns, writes, or
// removes anything (systemd.AuditStateDirAt has that as a tested hard
// invariant). Remediation is delegated to the lifecycle commands, which
// converge the chain at entry via LinuxAdapter.ConvergeStateDir.
//
// Severity: the drift is FAIL when it arms the actual defect — a live
// service-readable config exists inside a directory the User=split-tunnel
// services cannot enter (the staging trap: restart then cannot read the
// 0640 config) — and WARN otherwise (drift on a tree with no live config:
// a copied/extracted state root read with SPLITTERCTL_STATE_ROOT, or a
// pre-activation directory). Both carry the same remediation action. A
// doctor run over a foreign temp tree (dev hosts, CI fixtures) can never be
// a hard failure of the deployment verdict.
//
// dir is the state root the run was pointed at (production:
// systemd.StateDir; a doctor run with SPLITTERCTL_STATE_ROOT audits the root
// it was given — the CLI contract).
func StateDirCheck(dir string) Check {
	return Check{ID: StateDirCheckID, Run: func(context.Context) Finding {
		audit, err := systemd.AuditStateDirAt(dir)
		return buildStateDirFinding(audit, err)
	}}
}

// StateDirCheckID is the doctor check id for the state-dir permission chain.
const StateDirCheckID = "state.dir"

// buildStateDirFinding renders the audit snapshot as a Finding. It is PURE
// (no I/O) so the verdict logic is assertable on any host, including one
// where the Unix owner bits do not exist.
func buildStateDirFinding(audit systemd.StateDirAudit, err error) Finding {
	if err != nil {
		return Finding{ID: StateDirCheckID, Severity: SeverityFail,
			Summary: "state directory audit failed: " + err.Error(),
			Action:  "inspect the state directory; re-run install/upgrade/recover to converge it"}
	}
	problems := audit.Problems()
	if !audit.Exists || len(problems) == 0 {
		return Finding{ID: StateDirCheckID, Severity: SeverityPass,
			Summary: "state directory matches the converged permission chain"}
	}
	summaries := make([]string, 0, len(problems))
	arms := false
	for _, p := range problems {
		summaries = append(summaries, p.Detail)
		switch p.Kind {
		case systemd.ProblemMode, systemd.ProblemGroup, systemd.ProblemSymlink, systemd.ProblemNotDir:
			arms = true
		}
	}
	// The drift is a hard failure exactly when it arms the staging trap: a
	// live service-readable config sits in a directory the service group
	// cannot enter (or whose access bits are wrong). Owner-only drift, or
	// drift on a tree with no live config, is a warning: it deviates from
	// the documented chain but does not yet break a service start.
	severity := SeverityWarn
	if arms && len(audit.Configs) > 0 {
		severity = SeverityFail
	}
	return Finding{ID: StateDirCheckID, Severity: severity,
		Summary: "state directory permission-chain drift: " + strings.Join(summaries, "; "),
		Action:  "run install or upgrade (any lifecycle command re-converges the state dir at entry, even on a no-op plan); doctor itself is read-only and changes nothing"}
}

func HasFailures(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == SeverityFail {
			return true
		}
	}
	return false
}

func StateFinding(err error) Finding {
	if err == nil {
		return Finding{ID: "state.integrity", Severity: SeverityPass, Summary: "deployment state integrity verified", Redacted: true}
	}
	severity := SeverityFail
	action := "restore a retained revision or run recovery"
	if errors.Is(err, ErrTampered) {
		action = "do not mutate the host; restore state from a trusted revision"
	}
	return Finding{ID: "state.integrity", Severity: severity, Summary: fmt.Sprintf("deployment state unavailable: %T", err), Action: action, Redacted: true}
}
