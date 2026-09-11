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
	Store    *Store
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
	for _, step := range t.Steps {
		if err := ctx.Err(); err != nil {
			return t.fail(ctx, step.Phase, err)
		}
		if step.Run == nil {
			return t.fail(ctx, step.Phase, fmt.Errorf("%w: nil step %s", ErrTransaction, step.Name))
		}
		if err := step.Run(ctx); err != nil {
			return t.fail(ctx, step.Phase, fmt.Errorf("%s: %w", step.Name, err))
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
		return t.fail(ctx, PhaseCommit, err)
	}
	return Result{Manifest: committed, Plan: plan, Phase: PhaseCommit, Changed: true}, nil
}

func (t *Transaction) fail(ctx context.Context, phase Phase, cause error) (Result, error) {
	if t.Recover == nil {
		return Result{Phase: phase}, fmt.Errorf("%w at %s: %v", ErrTransaction, phase, cause)
	}
	recoveryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := t.Recover(recoveryCtx, t.Previous); err != nil {
		return Result{Phase: phase}, fmt.Errorf("%w at %s: %v; recovery failed: %w", ErrTransaction, phase, cause, err)
	}
	return Result{Phase: phase}, fmt.Errorf("%w at %s: %v (%w)", ErrTransaction, phase, cause, ErrRecovered)
}
