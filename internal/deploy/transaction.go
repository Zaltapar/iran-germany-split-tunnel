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
	var current *Manifest
	if t.Previous.Generation != "" {
		current = &t.Previous
	}
	plan, err := PlanDesired(current, t.Desired)
	if err != nil {
		return Result{}, err
	}
	if plan.Unchanged {
		return Result{Manifest: t.Previous, Plan: plan}, nil
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
	m := Manifest{
		Schema:     SchemaVersion,
		Role:       t.Desired.Role,
		Components: t.Desired.Components,
		Paths:      t.Desired.Paths,
		Pairing:    t.Desired.Pairing,
		Services:   append([]ServiceState(nil), t.Desired.Services...),
		Firewall:   t.Desired.Firewall,
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
