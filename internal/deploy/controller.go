package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Controller is the application-facing T8 deployment service. It owns state
// loading and operation classification; host mutation remains delegated to the
// injected Adapter and artifact restoration callback.
type Controller struct {
	Store   *Store
	Adapter Adapter
}

// ApplyRequest validates a complete operator request, converts it to
// secret-free desired state, and converges the host through the injected
// adapter. Request-specific secret handling remains the adapter's responsibility
// through InstallRequest.Env; it is never serialized into deployment state.
func (c *Controller) ApplyRequest(ctx context.Context, request InstallRequest) (Result, error) {
	desired, err := request.Desired()
	if err != nil {
		return Result{}, err
	}
	return c.Apply(ctx, desired)
}

// Apply converges the host to desired state. An absent state file is treated
// as a fresh install; an existing state must pass integrity validation before
// any adapter method is called.
func (c *Controller) Apply(ctx context.Context, desired DesiredState) (Result, error) {
	if c == nil || c.Store == nil {
		return Result{}, fmt.Errorf("%w: nil controller store", ErrTransaction)
	}
	if c.Adapter == nil {
		return Result{}, fmt.Errorf("%w: nil controller adapter", ErrTransaction)
	}
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: nil context", ErrTransaction)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	previous, err := c.Store.Load()
	if err != nil {
		// Missing state is the only condition treated as a fresh install;
		// tampered or malformed state must block mutation.
		if !os.IsNotExist(err) {
			return Result{}, fmt.Errorf("%w: load current state: %v", ErrTransaction, err)
		}
		previous = Manifest{}
	}
	return ApplyDesired(ctx, c.Store, previous, desired, c.Adapter)
}

// Rollback restores a retained revision through the same injected adapter used
// by Apply. The adapter is responsible for restoring files, services, and
// firewall state in dependency order and for running health gates.
func (c *Controller) Rollback(ctx context.Context, revisionID string) (Manifest, error) {
	if c == nil || c.Store == nil {
		return Manifest{}, fmt.Errorf("%w: nil controller store", ErrTransaction)
	}
	if c.Adapter == nil {
		return Manifest{}, fmt.Errorf("%w: nil controller adapter", ErrTransaction)
	}
	return c.Store.Rollback(ctx, revisionID, c.Adapter.Restore)
}

// Uninstall stops and removes only project-owned artifacts through the adapter.
// The manifest remains available for recovery evidence until an explicit purge
// operation is added by the host adapter.
func (c *Controller) Uninstall(ctx context.Context) error {
	if c == nil || c.Store == nil || c.Adapter == nil {
		return fmt.Errorf("%w: incomplete uninstall controller", ErrTransaction)
	}
	m, err := c.Store.Load()
	if err != nil {
		return fmt.Errorf("%w: load current state: %v", ErrTransaction, err)
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrTransaction)
	}
	if err := c.Adapter.Uninstall(ctx, m); err != nil {
		return fmt.Errorf("%w: uninstall: %w", ErrTransaction, err)
	}
	return nil
}

// ErrStateNotFound is retained as a named extension point for callers that
// provide a Store implementation with an explicit missing-state sentinel.
var ErrStateNotFound = errors.New("deploy: state not found")
