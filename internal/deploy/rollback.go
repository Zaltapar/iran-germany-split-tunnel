package deploy

import (
	"context"
	"errors"
	"fmt"
)

// RestoreFunc restores the project-owned artifacts represented by target and
// must run the same validation and health gates as an ordinary deployment.
// The manifest is committed only after RestoreFunc returns nil.
type RestoreFunc func(context.Context, Manifest) error

// Rollback restores a retained revision through restore, then commits a new
// manifest preserving the current revision history. It never mutates state
// when the target cannot be loaded, has a different role, or restoration
// fails. Artifact restoration is deliberately injected so this package does
// not duplicate systemd, Xray, origin, or firewall policy.
func (s *Store) Rollback(ctx context.Context, revisionID string, restore RestoreFunc) (Manifest, error) {
	if ctx == nil {
		return Manifest{}, fmt.Errorf("%w: nil context", ErrTransaction)
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	if s == nil {
		return Manifest{}, fmt.Errorf("%w: nil store", ErrTransaction)
	}
	if restore == nil {
		return Manifest{}, fmt.Errorf("%w: rollback restore is not configured", ErrTransaction)
	}

	current, err := s.Load()
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: load current state: %v", ErrTransaction, err)
	}
	target, err := s.ReadRevision(revisionID)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: read revision: %v", ErrTransaction, err)
	}
	if target.Role != current.Role {
		return Manifest{}, fmt.Errorf("%w: rollback role mismatch", ErrTransaction)
	}
	if target.Generation == current.Generation && target.ManifestHash == current.ManifestHash {
		return Manifest{}, fmt.Errorf("%w: target is already active", ErrTransaction)
	}
	if err := restore(ctx, target); err != nil {
		return Manifest{}, fmt.Errorf("%w: restore revision: %w", ErrTransaction, err)
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, fmt.Errorf("%w: rollback canceled after restore: %v", ErrTransaction, err)
	}

	// Keep all currently retained history, including the state being replaced;
	// Commit appends a new rollback revision and applies normal ten-item pruning.
	target.Revisions = append([]Revision(nil), current.Revisions...)
	committed, err := s.Commit(target, "rollback")
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: commit rollback: %v", ErrTransaction, err)
	}
	return committed, nil
}

// IsRollbackUnavailable identifies errors that should be reported as a
// fail-closed operator action rather than retried as an ordinary install.
func IsRollbackUnavailable(err error) bool {
	return errors.Is(err, ErrTransaction)
}
