package deploy

import "context"

// Adapter is the host-side composition boundary for T8. Concrete production
// wiring belongs outside the state/planner core and must delegate each action
// to the authoritative T1–T6 package. Implementations must be idempotent and
// must not persist the manifest themselves.
type Adapter interface {
	Prepare(context.Context, DesiredState) error
	Validate(context.Context, DesiredState) error
	Backup(context.Context, *Manifest) error
	Activate(context.Context, DesiredState) error
	Transition(context.Context, DesiredState) error
	Health(context.Context, DesiredState) error
	// Restore is used only when a committed previous manifest exists:
	// a failed transaction calls it to return the host to that manifest,
	// and an operator rollback (Store.Rollback) calls it to converge the
	// host to a retained revision. It must be bounded by ownership.
	Restore(context.Context, Manifest) error
	// CleanupFresh removes only artifacts recorded as created by this
	// transaction when a fresh install has no previous manifest to restore.
	CleanupFresh(context.Context, DesiredState) error
	Uninstall(context.Context, Manifest) error
}

// ApplyDesired executes a desired-state transaction through one injected host
// adapter. Planning and manifest commit remain owned by Transaction; this
// helper only maps the adapter lifecycle to the transaction phases.
func ApplyDesired(ctx context.Context, store *Store, previous Manifest, desired DesiredState, adapter Adapter) (Result, error) {
	if adapter == nil {
		return Result{}, ErrTransaction
	}
	journal, err := BuildJournal(store.Root, previous, desired)
	if err != nil {
		return Result{}, err
	}
	tx := Transaction{
		Store:    store,
		Journal:  journal,
		Previous: previous,
		Desired:  desired,
		Recover: func(recoveryCtx context.Context, old Manifest) error {
			if old.Generation == "" {
				return adapter.CleanupFresh(recoveryCtx, desired)
			}
			return adapter.Restore(recoveryCtx, old)
		},
		Steps: []Step{
			{Phase: PhasePreflight, Name: "prepare", Run: func(stepCtx context.Context) error {
				return adapter.Prepare(stepCtx, desired)
			}},
			{Phase: PhaseValidate, Name: "validate", Run: func(stepCtx context.Context) error {
				return adapter.Validate(stepCtx, desired)
			}},
			{Phase: PhaseBackup, Name: "backup", Run: func(stepCtx context.Context) error {
				return adapter.Backup(stepCtx, manifestPointer(previous))
			}},
			{Phase: PhaseActivate, Name: "activate", Run: func(stepCtx context.Context) error {
				return adapter.Activate(stepCtx, desired)
			}},
			{Phase: PhaseTransition, Name: "transition", Run: func(stepCtx context.Context) error {
				return adapter.Transition(stepCtx, desired)
			}},
			{Phase: PhaseHealth, Name: "health", Run: func(stepCtx context.Context) error {
				return adapter.Health(stepCtx, desired)
			}},
		},
	}
	return tx.Apply(ctx)
}

func manifestPointer(m Manifest) *Manifest {
	copy := m
	return &copy
}
