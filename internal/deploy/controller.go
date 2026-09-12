package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Controller is the T8 operation entrypoint used by cmd/splitterctl. It
// maps one operator command onto the transaction + host adapter pair and
// owns the state-load boundaries. It performs no host mutation itself:
// every mutation flows through the injected Adapter inside a Transaction.
type Controller struct {
	Store   *Store
	Adapter Adapter
}

func (c *Controller) check() error {
	if c.Store == nil {
		return fmt.Errorf("%w: nil store", ErrTransaction)
	}
	if c.Adapter == nil {
		return fmt.Errorf("%w: nil adapter", ErrTransaction)
	}
	return nil
}

// Previous returns the committed manifest, or an empty Manifest when nothing
// is installed. os.ErrNotExist is the documented "not installed" condition.
func (c *Controller) Previous() (Manifest, error) {
	m, err := c.Store.Load()
	if err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// ApplyRequest runs a full desired-state transaction for the request's role.
// The request must already be complete and validated (NewLinuxAdapter does
// this at construction); the controller re-validates as a final gate.
func (c *Controller) ApplyRequest(ctx context.Context, request InstallRequest) (Result, error) {
	if err := c.check(); err != nil {
		return Result{}, err
	}
	if _, stale, err := c.StaleJournal(); err != nil {
		return Result{}, err
	} else if stale {
		return Result{}, fmt.Errorf("%w: an in-flight journal is present; finish recovery before installing", ErrTransaction)
	}
	if err := request.Validate(); err != nil {
		return Result{}, err
	}
	desired, err := request.Desired()
	if err != nil {
		return Result{}, err
	}
	previous, err := c.Store.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("%w: load current state: %v", ErrTransaction, err)
	}
	if previous.Generation != "" && previous.Role != desired.Role {
		return Result{}, fmt.Errorf("deploy: host is installed as %q; refusing to install %q on the same state root", previous.Role, desired.Role)
	}
	return ApplyDesired(ctx, c.Store, previous, desired, c.Adapter)
}

// Rollback restores the host to a retained revision through the adapter and
// commits a new "rollback" revision only after the host is healthy. This is
// what makes rollback truthful — it re-converges the host (units/env/
// firewall/pointers via the authoritative T2–T6 packages), it does not only
// rewrite state. Failure leaves the current manifest untouched.
func (c *Controller) Rollback(ctx context.Context, revisionID string) (Manifest, error) {
	if err := c.check(); err != nil {
		return Manifest{}, err
	}
	// A stale journal means a previous mutation crashed mid-flight; the
	// operator must finish recovery before rollback is attempted again.
	if _, stale, err := c.StaleJournal(); err != nil {
		return Manifest{}, err
	} else if stale {
		return Manifest{}, fmt.Errorf("%w: an in-flight journal is present; finish recovery before rolling back", ErrTransaction)
	}
	return c.Store.Rollback(ctx, revisionID, c.Adapter.Restore)
}

// Uninstall removes the committed deployment for the host's role. The state
// manifest is removed only after the adapter has torn down units/env/firewall
// successfully (commit-last in reverse: host first, state second). With purge
// the revisions directory and any in-flight journal are removed too; without
// it the revision history is retained as forensic evidence.
func (c *Controller) Uninstall(ctx context.Context, purge bool) error {
	if err := c.check(); err != nil {
		return err
	}
	previous, err := c.Store.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if previous.Generation == "" {
		return fmt.Errorf("deploy: nothing installed (no committed state)")
	}
	if err := c.Adapter.Uninstall(ctx, previous); err != nil {
		return fmt.Errorf("deploy: uninstall: %w", err)
	}
	// State removal after the host is clean.
	if err := os.Remove(c.Store.manifestPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("deploy: uninstall: remove state: %v", err)
	}
	if purge {
		if err := c.Store.ClearJournal(); err != nil {
			return err
		}
		if err := os.RemoveAll(c.Store.revisionsDir()); err != nil {
			return fmt.Errorf("deploy: uninstall: purge revisions: %v", err)
		}
	}
	return nil
}

// StaleJournal reports a leftover in-flight journal (crashed mutation). A
// stale journal means the host may be inconsistent; doctor surfaces it and
// the operator must finish recovery before any new mutation is accepted.
func (c *Controller) StaleJournal() (ArtifactJournal, bool, error) {
	if c.Store == nil {
		return ArtifactJournal{}, false, fmt.Errorf("%w: nil store", ErrTransaction)
	}
	j, err := c.Store.ReadJournal()
	if err != nil {
		if os.IsNotExist(err) {
			return ArtifactJournal{}, false, nil
		}
		return ArtifactJournal{}, false, err
	}
	return j, true, nil
}
