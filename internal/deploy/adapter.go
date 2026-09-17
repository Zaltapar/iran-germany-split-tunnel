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
	// host to a retained revision. It must be bounded by ownership. It is
	// an IN-PROCESS recovery path: it may consult the adapter's runtime
	// ownership record, so it is NOT sufficient after a process crash —
	// post-crash recovery must use RecoverJournal.
	Restore(context.Context, Manifest) error
	// CleanupFresh removes only artifacts recorded as created by this
	// transaction when a fresh install has no previous manifest to restore.
	// Like Restore it is an IN-PROCESS path that may consult the adapter's
	// runtime ownership record; RecoverJournal is the post-crash
	// equivalent.
	CleanupFresh(context.Context, DesiredState) error
	// RecoverJournal performs ownership-scoped recovery from a persisted
	// journal after a process crash. It must derive what to remove from the
	// JOURNAL, not from runtime state (the runtime ownership record is empty
	// in a fresh process). previous.Generation == "" means a fresh install
	// (no committed previous generation) and selects owned-artifact cleanup;
	// a committed previous generation selects convergence to previous
	// (Restore semantics). It must be idempotent, bounded by ctx, and must
	// leave unrelated host resources untouched.
	RecoverJournal(ctx context.Context, j ArtifactJournal, previous Manifest) error
	Uninstall(context.Context, Manifest) error
}

// StateDirConverger is the OPTIONAL adapter capability for the lifecycle-entry
// convergence of the state-directory permission chain (T5's EnsureStateDir:
// /etc/split-tunnel 0750 root:split-tunnel, live configs 0640
// root:split-tunnel). ApplyDesired runs it BEFORE planning so that even a
// transaction which converges to a no-op re-converges the directory: T3 and
// the origin provider write their artifacts 0600, and a drifted 0700 state
// dir otherwise survives a converged no-op install indefinitely (the
// transaction returns before any adapter phase, and Prepare is what usually
// runs EnsureStateDir) — leaving User=split-tunnel services unable to read
// their own configs after a restart. Implementations must be idempotent,
// write no journal or manifest, and delete no artifacts.
type StateDirConverger interface {
	ConvergeStateDir(context.Context) error
}

// convergeStateDir resolves the optional StateDirConverger capability of an
// adapter (nil when the adapter does not implement it — the documented host
// fakes, which must not gain hidden mutation hooks).
func convergeStateDir(adapter Adapter) func(context.Context) error {
	if c, ok := adapter.(StateDirConverger); ok {
		return c.ConvergeStateDir
	}
	return nil
}

// LiveAuditor is the OPTIONAL adapter capability for the live-state drift
// audit of MANAGED deployment objects (DEFECT-2). The planner diffs
// manifest-desired against manifest-current and never sees the live
// filesystem, so a host whose managed unit files (or managed binaries) have
// drifted since the last commit converges to a reported no-op ("already
// converged") while the live state stays broken. ApplyDesired runs the audit
// ONLY when the plan is a no-op: it compares the live unit bytes against the
// committed render and checks the managed binary path/mode, and reports drift
// (or a read error, which the transaction treats as fail-closed). On drift the
// transaction falls through to the full apply so the objects re-converge
// through the normal apply semantics; a clean audit returns the same zero-
// PID-churn no-op as before (the af86f12 guarantee). Implementations must be
// read-only: the audit observes, it never writes.
type LiveAuditor interface {
	AuditLiveDrift(context.Context) (bool, error)
}

// auditLiveDrift resolves the optional LiveAuditor capability of an adapter
// (nil when the adapter does not implement it — the documented host fakes).
func auditLiveDrift(adapter Adapter) func(context.Context) (bool, error) {
	if a, ok := adapter.(LiveAuditor); ok {
		return a.AuditLiveDrift
	}
	return nil
}

// PairingStaleMarker is the OPTIONAL adapter capability that reports whether
// the just-executed transaction rotated the live pairing configuration
// (DEFECT-3). When a config-rotating activate changed the managed Reality
// keypair, the committed pairing B-fingerprint is now stale — the live
// inbound is serving a keypair the on-disk pairing blob no longer matches, so
// `pair apply` must re-emit Blob B before the exchange can authenticate. The
// transaction consults this ONLY on a successful commit: a true value marks
// the committed manifest's pairing state with an explicit pairingStale flag
// that doctor surfaces and `pair apply` clears. nil means the adapter offers
// no pairing marker (the documented host fakes), so the commit stays
// unmarked.
type PairingStaleMarker interface {
	MarkPairingStale() bool
}

// markPairingStale resolves the optional PairingStaleMarker capability of an
// adapter (nil when the adapter does not implement it).
func markPairingStale(adapter Adapter) func() bool {
	if a, ok := adapter.(PairingStaleMarker); ok {
		return a.MarkPairingStale
	}
	return nil
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
		// Lifecycle-entry convergence (DEFECT-2): runs inside Transaction
		// before planning, so it executes even when the plan is a no-op and
		// no adapter phase ever runs. The controller still performs no host
		// mutation itself — the mutation is the adapter's EnsureStateDir.
		Converge: convergeStateDir(adapter),
		// Live drift audit (DEFECT-2): consulted only on a no-op plan, so a
		// drifted managed object still re-converges while a clean host keeps
		// the zero-PID-churn no-op.
		AuditLive: auditLiveDrift(adapter),
		// Pairing staleness marker (DEFECT-3): consulted on commit so a config-
		// rotating activate records that the committed B-fingerprint is now
		// stale and `pair apply` must re-emit Blob B.
		MarkPairingStale: markPairingStale(adapter),
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
