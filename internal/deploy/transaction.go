package deploy

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Phase string

const (
	PhasePreflight  Phase = "preflight"
	PhasePrepare    Phase = "prepare"
	PhaseValidate   Phase = "validate"
	PhaseBackup     Phase = "backup"
	PhaseActivate   Phase = "activate"
	PhaseTransition Phase = "transition"
	PhaseHealth     Phase = "health"
	PhaseCommit     Phase = "commit"
	// PhaseRecover is the outcome phase of an explicit post-crash recovery
	// (Controller.Recover). It is not part of a Transaction's step sequence.
	PhaseRecover Phase = "recover"
)

var (
	ErrTransaction = errors.New("deploy: transaction failed")
	ErrRecovered   = errors.New("deploy: transaction recovered previous state")
)

type Step struct {
	Phase Phase
	Name  string
	Run   func(context.Context) error
}

type Transaction struct {
	Store *Store
	// Journal is written before mutation begins and removed only after commit.
	// Its contents must be ownership-scoped and secret-free.
	Journal  ArtifactJournal
	Previous Manifest
	Desired  DesiredState
	Steps    []Step
	Recover  func(context.Context, Manifest) error
	Now      func() time.Time
	// Converge optionally re-asserts the state-directory permission chain
	// (the adapter's EnsureStateDir) at the start of the transaction —
	// BEFORE the no-op early return — so a converged install/upgrade/re-
	// apply still heals a drifted /etc/split-tunnel. It is idempotent and
	// mutates no deployment artifacts; nil means the adapter offers no
	// convergence hook.
	Converge func(context.Context) error
	// AuditLive optionally audits the LIVE state of the MANAGED deployment
	// objects (the adapter's AuditLiveDrift) and is consulted ONLY when the
	// plan converges to a no-op (DEFECT-2): it reports whether a managed
	// object diverges from the committed state (unit file bytes vs the
	// committed render, managed binary presence/mode) or returns an error
	// (fail closed). A clean audit returns the same no-op as before; a
	// drifted one falls through to the full journal + apply sequence so the
	// objects re-converge through the normal apply semantics. nil means the
	// adapter offers no live audit (the no-op early return stands unchallenged).
	AuditLive func(context.Context) (bool, error)
	// MarkPairingStale optionally reports whether this transaction's activate
	// phase rotated the live pairing configuration (DEFECT-3): when a config-
	// rotating activate changed the managed Reality keypair, the committed
	// pairing B-fingerprint no longer matches the on-disk config, so `pair
	// apply` must re-emit Blob B. Consulted ONLY on a successful commit,
	// after the apply steps: a true value marks the committed manifest's
	// pairing state with the explicit pairingStale flag doctor surfaces and
	// `pair apply` clears. nil means the adapter offers no pairing marker
	// (the documented host fakes), so the commit stays unmarked.
	MarkPairingStale func() bool
}

type Result struct {
	Manifest Manifest
	Plan     Plan
	Phase    Phase
	Changed  bool
}

func (t *Transaction) Apply(ctx context.Context) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: nil context", ErrTransaction)
	}
	if t.Store == nil {
		return Result{}, fmt.Errorf("%w: nil store", ErrTransaction)
	}
	// Lifecycle-entry convergence (DEFECT-2): must run before the plan's
	// no-op early return, otherwise a converged re-apply never heals a
	// drifted state dir and a User=split-tunnel service cannot read its
	// config after any restart.
	if t.Converge != nil {
		if err := t.Converge(ctx); err != nil {
			return Result{}, fmt.Errorf("%w: converge state dir: %w", ErrTransaction, err)
		}
	}
	var current *Manifest
	if t.Previous.Generation != "" {
		current = &t.Previous
	}
	plan, err := PlanDesired(current, t.Desired)
	if err != nil {
		return Result{}, err
	}
	if plan.Unchanged {
		drifted := false
		if t.AuditLive != nil {
			// Live drift audit (DEFECT-2): the plan is a no-op against the
			// committed state, but the planner never sees the live
			// filesystem — a managed unit file or binary may have drifted
			// since the last commit. A read error is fail-closed: the host
			// state is unknown, so the transaction must not report success.
			var err error
			drifted, err = t.AuditLive(ctx)
			if err != nil {
				return Result{}, fmt.Errorf("%w: audit live drift: %w", ErrTransaction, err)
			}
		}
		if !drifted {
			// Clean no-op: zero adapter phases, zero executor calls, zero
			// PID churn — the converged re-apply guarantee.
			return Result{Manifest: t.Previous, Plan: plan}, nil
		}
		// Drifted: fall through to the full transaction below. The journal
		// is written, the apply phases run the normal byte-exact logic
		// (ApplyUnit is a no-op per unit whose bytes already match, a
		// validated swap for the drifted ones), and a new generation is
		// committed so the healed state is recorded.
	}
	// The in-flight journal is written BEFORE the first mutation and is the
	// sole ownership record for recovery. Its contents must be complete and
	// secret-free; a journal that cannot be validated is a fatal,
	// pre-mutation failure (nothing on the host has changed yet).
	if t.Journal.Role == "" {
		t.Journal.Role = t.Desired.Role
	}
	if t.Journal.Generation == "" {
		t.Journal.Generation = fmt.Sprintf("pending-%d", t.now().UnixNano())
	}
	if err := t.Journal.validate(t.Store.Root); err != nil {
		return Result{}, fmt.Errorf("%w: journal: %v", ErrTransaction, err)
	}
	if err := t.Store.WriteJournal(t.Journal); err != nil {
		return Result{}, fmt.Errorf("%w: write journal: %v", ErrTransaction, err)
	}
	// On every failure path the journal remains in place: it is the
	// evidence an operator (or a later splitterctl doctor) needs to
	// finish recovery. Only a successful commit removes it (below).
	for _, step := range t.Steps {
		if err := ctx.Err(); err != nil {
			return t.fail(step.Phase, err)
		}
		if step.Run == nil {
			return t.fail(step.Phase, fmt.Errorf("%w: nil step %s", ErrTransaction, step.Name))
		}
		if err := step.Run(ctx); err != nil {
			return t.fail(step.Phase, fmt.Errorf("%s: %w", step.Name, err))
		}
	}
	pairing := t.Desired.Pairing
	// Pairing staleness marker (DEFECT-3): consulted after the apply steps so
	// it reflects whether THIS transaction's activate rotated the live config.
	// A fresh, non-rotating commit leaves the marker unset (pair apply clears
	// it later by committing the re-emitted pairing state).
	if t.MarkPairingStale != nil && t.MarkPairingStale() {
		pairing.PairingStale = true
	}
	m := Manifest{
		Schema:            SchemaVersion,
		Role:              t.Desired.Role,
		Components:        t.Desired.Components,
		Paths:             t.Desired.Paths,
		Pairing:           pairing,
		Services:          append([]ServiceState(nil), t.Desired.Services...),
		Firewall:          t.Desired.Firewall,
		ConfigFingerprint: t.Desired.ConfigFingerprint,
	}
	label := "install"
	if t.Previous.Generation != "" {
		label = "upgrade"
	}
	committed, err := t.Store.Commit(m, label)
	if err != nil {
		return t.fail(PhaseCommit, err)
	}
	// The commit is authoritative and last: only now may the in-flight
	// journal be removed. The journal is intentionally NOT part of the
	// committed manifest — it carries recovery-only ownership data.
	if err := t.Store.ClearJournal(); err != nil {
		return Result{}, fmt.Errorf("%w at %s: committed manifest but journal removal failed: %v", ErrTransaction, PhaseCommit, err)
	}
	return Result{Manifest: committed, Plan: plan, Phase: PhaseCommit, Changed: true}, nil
}

func (t *Transaction) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// fail recovers previous state when possible. A recovery failure is FATAL
// and unrecovered: the in-flight journal remains on disk so an operator can
// finish the recovery manually (the journal is the only ownership record).
func (t *Transaction) fail(phase Phase, cause error) (Result, error) {
	if t.Recover == nil {
		return Result{Phase: phase}, fmt.Errorf("%w at %s: %v (journal retained)", ErrTransaction, phase, cause)
	}
	recoveryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := t.Recover(recoveryCtx, t.Previous); err != nil {
		return Result{Phase: phase}, fmt.Errorf("%w at %s: %v; recovery failed: %w (journal retained)", ErrTransaction, phase, cause, err)
	}
	return Result{Phase: phase}, fmt.Errorf("%w at %s: %v (%w)", ErrTransaction, phase, cause, ErrRecovered)
}
