package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/xray"
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

// PairingStalenessCheck returns the read-only doctor check for pairing
// staleness (DEFECT-3). It compares the committed pairing identity against a
// re-derivation of the installed Reality config's PUBLIC parameters, and
// surfaces the explicit pairingStale marker a config-rotating transaction
// leaves on the committed manifest.
//
// Two independent signals both mean "the emitted pairing blob no longer
// authenticates the live inbound, run `pair apply` to re-emit":
//
//   - the explicit marker: a config-rotating Activate regenerated the Reality
//     keypair, which is INVISIBLE to the public-params fingerprint (SNI/
//     shortID/UUID-hash), so only the marker records it.
//   - public-param drift: the installed config's SNI/shortID/UUID re-derive to
//     a fingerprint different from the committed Components.Xray.
//     RealityFingerprint (the config was edited out-of-band).
//
// It is a WARN (remediation = re-emit, not repair) whenever either signal
// fires, and a FAIL when the installed config is unreadable or mis-shaped
// (the re-derivation itself is impossible). It is PASS when not applicable
// (no committed Germany Reality config: a fresh host, an Iran manifest, or a
// Germany manifest with no config path) or when both signals are clean. It is
// READ-ONLY: it stats/reads the committed config and never writes. It echoes
// no key material — only the public-parameter verdict and the sentinel
// classification of a read failure.
func PairingStalenessCheck(store *Store) Check {
	return Check{ID: PairingStalenessCheckID, Run: func(context.Context) Finding {
		m, err := store.Load()
		if err != nil {
			if os.IsNotExist(err) {
				return buildPairingStalenessFinding(pairingStalenessFacts{applicable: false}, nil)
			}
			return buildPairingStalenessFinding(pairingStalenessFacts{applicable: true, configErr: err}, nil)
		}
		if m.Role != RoleGermany || m.Paths.Config == "" {
			return buildPairingStalenessFinding(pairingStalenessFacts{applicable: false}, nil)
		}
		facts := pairingStalenessFacts{
			applicable:          true,
			marker:              m.Pairing.PairingStale,
			recordedFingerprint: m.Components.Xray.RealityFingerprint,
		}
		installed, ierr := xray.ReadInstalledRealityParams(m.Paths.Config)
		if ierr != nil {
			facts.configErr = ierr
			return buildPairingStalenessFinding(facts, nil)
		}
		facts.installedFingerprint = realityFingerprint(xray.RealityParams{SNI: installed.SNI, ShortID: installed.ShortID, UUID: installed.UUID})
		facts.paramDrift = facts.recordedFingerprint != "" && facts.recordedFingerprint != facts.installedFingerprint
		return buildPairingStalenessFinding(facts, nil)
	}}
}

// PairingStalenessCheckID is the doctor check id for pairing staleness.
const PairingStalenessCheckID = "pairing.staleness"

// pairingStalenessFacts is the host-observed input to the pure pairing-
// staleness verdict renderer. It carries only public, secret-free facts.
type pairingStalenessFacts struct {
	applicable           bool
	marker               bool
	recordedFingerprint  string
	installedFingerprint string
	paramDrift           bool
	configErr            error
}

// buildPairingStalenessFinding renders the observed facts as a Finding. It
// is PURE (no I/O) so the verdict logic is assertable on any host.
func buildPairingStalenessFinding(f pairingStalenessFacts, err error) Finding {
	if err != nil {
		return Finding{ID: PairingStalenessCheckID, Severity: SeverityFail,
			Summary: "pairing staleness check failed: " + err.Error(),
			Action:  "re-run doctor"}
	}
	if !f.applicable {
		return Finding{ID: PairingStalenessCheckID, Severity: SeverityPass,
			Summary: "pairing staleness not applicable (no committed Germany Reality config)"}
	}
	if f.configErr != nil {
		return Finding{ID: PairingStalenessCheckID, Severity: SeverityFail,
			Summary: "installed Germany Reality config cannot be re-derived (" + pairingConfigErrClass(f.configErr) + "); the pairing B-fingerprint cannot be verified",
			Action:  "inspect the committed config path; run install or upgrade to re-converge it, then run pair apply to re-emit"}
	}
	if !f.marker && !f.paramDrift {
		return Finding{ID: PairingStalenessCheckID, Severity: SeverityPass,
			Summary: "pairing B-fingerprint matches the installed Reality config"}
	}
	var reasons []string
	if f.marker {
		reasons = append(reasons, "a config-rotating transaction marked the pairing stale (regenerated Reality keypair)")
	}
	if f.paramDrift {
		reasons = append(reasons, "the installed Reality public params drifted from the committed fingerprint")
	}
	return Finding{ID: PairingStalenessCheckID, Severity: SeverityWarn,
		Summary: "pairing B-fingerprint is stale: " + strings.Join(reasons, "; "),
		Action:  "run pair apply to re-emit the pairing blob, then pair finalize; doctor is read-only and changes nothing"}
}

// pairingConfigErrClass maps a ReadInstalledRealityParams failure to a
// secret-free, sentinel-based class (never echoing config bytes or key
// material).
func pairingConfigErrClass(err error) string {
	switch {
	case errors.Is(err, xray.ErrInstalledConfigRead):
		return "config path unreadable"
	case errors.Is(err, xray.ErrInstalledConfig):
		return "config shape invalid"
	case errors.Is(err, xray.ErrInstalledKey):
		return "installed Reality key failed validation"
	default:
		return "config read failed"
	}
}
