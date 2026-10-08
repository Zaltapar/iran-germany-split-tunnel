package dashboard

import (
	"context"
	"fmt"
	"sync/atomic"
)

// Mutator applies a planned configuration change to a server. This is an
// injectable interface so that tests can verify plan behavior without
// touching a real host. The default (nil) Mutator rejects all applies.
//
// In this first release, NO real Mutator is wired in: the apply endpoint
// always returns HTTP 403 with a "mutations disabled" body when the
// dashboard is in its safe default mode. A future release may inject a
// Mutator that shells out to `splitterctl config set` over SSH; that is
// explicitly OUT OF SCOPE for this task and must never be enabled by
// default.
type Mutator interface {
	// ApplyPlan applies a previously-created plan. It must return a clear
	// error if the plan is unknown, stale, or the server is unreachable.
	ApplyPlan(ctx context.Context, serverID, planID string) error
}

// nilMutator is the default: it records that a call was attempted so
// tests can assert "the fake mutator was not called" semantics.
type nilMutator struct {
	attempts atomic.Int64
}

// NewNilMutator returns the safe default mutator that refuses every apply.
func NewNilMutator() *nilMutator { return &nilMutator{} }

// Attempts returns how many ApplyPlan calls were made (for test assertions).
func (n *nilMutator) Attempts() int64 { return n.attempts.Load() }

// ApplyPlan always fails: no mutation is performed.
func (n *nilMutator) ApplyPlan(_ context.Context, _, _ string) error {
	n.attempts.Add(1)
	return fmt.Errorf("mutations disabled: this dashboard build has no active mutator; no host was contacted")
}
