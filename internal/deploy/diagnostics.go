package deploy

import (
	"context"
	"errors"
	"fmt"
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
