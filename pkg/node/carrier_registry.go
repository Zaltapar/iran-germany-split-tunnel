// carrier_registry.go — Phase 1 of plans/multi-carrier-intelligence-design.md
//
// Transport abstraction and per-direction carrier registry with exactly
// ONE entry per direction. This file is behavior-neutral: the Node
// keeps its existing single-handle semantics (replace-on-install,
// node-global generation counter) and merely exposes them through a
// registry whose fixed CarrierID identifies the sole carrier. No wire
// format, config, or metric change is made here.
package node

import (
	"errors"
	"fmt"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// CarrierID is a stable, non-secret identifier for a carrier instance.
// It may appear in logs and the dashboard (design §4.1).
type CarrierID string

// Default carrier IDs for the existing single-carrier topology. These
// are the only CarrierIDs a Phase 1 Node will ever hold.
const (
	// DefaultUpCarrierID is the sole up (upload) carrier: VLESS over
	// WebSocket via CDN (Iran side), accepted on Germany.
	DefaultUpCarrierID CarrierID = "up-cdn-ws"
	// DefaultDownCarrierID is the sole down (download) carrier:
	// VLESS+Reality over TCP (Germany side), dialed from Iran.
	DefaultDownCarrierID CarrierID = "down-reality"
)

// Carrier family names (public, non-secret).
const (
	// FamilyCDNWS is a VLESS-over-WebSocket carrier fronted by a CDN.
	FamilyCDNWS = "cdn-ws"
	// FamilyReality is a VLESS+Reality (XTLS) carrier over TCP.
	FamilyReality = "reality"
)

// CarrierDescriptor is the stable identity of a carrier instance.
// Immutable after construction; it never contains secret material.
type CarrierDescriptor struct {
	ID     CarrierID
	Dir    session.Direction
	Family string
}

// String is a stable log prefix, e.g. "carrier[down/down-reality]".
func (d CarrierDescriptor) String() string {
	dir := "up"
	if d.Dir == session.DirDown {
		dir = "down"
	}
	return fmt.Sprintf("carrier[%s/%s]", dir, d.ID)
}

// ErrUnknownCarrierID is returned when an install names a CarrierID
// that is not this registry's fixed Phase 1 identity.
var ErrUnknownCarrierID = errors.New("node: unknown carrier id for this registry (Phase 1 permits exactly one carrier per direction)")

// carrierRegistry holds the ONE installed carrier for one direction.
// All methods must be called with the Node mutex held (the registry
// has no lock of its own, matching the existing up/down slot
// discipline under n.mu).
//
// Phase 1 invariants:
//   - there is exactly one slot; a second carrier with a DIFFERENT
//     CarrierID cannot be expressed through this API at all;
//   - installing the SAME CarrierID replaces the current entry
//     (the existing replace-on-install semantics, design §4.2);
//   - generation is owned by the Node (n.genSeq, node-global and
//     lockstep across both nodes), so replacement increments it and
//     the on-wire rebind generations are unchanged.
type carrierRegistry struct {
	desc CarrierDescriptor
	h    *carrierHandle // the sole entry; nil when no carrier is installed
}

// newCarrierRegistry creates the per-direction registry with its
// fixed Phase 1 descriptor.
func newCarrierRegistry(desc CarrierDescriptor) *carrierRegistry {
	return &carrierRegistry{desc: desc}
}

// Descriptor returns the registry's fixed carrier identity.
func (r *carrierRegistry) Descriptor() CarrierDescriptor { return r.desc }

// ID is the registry's fixed CarrierID.
func (r *carrierRegistry) ID() CarrierID { return r.desc.ID }

// Handle returns the sole entry, or nil when no carrier is installed.
func (r *carrierRegistry) Handle() *carrierHandle { return r.h }

// Generation is the current entry's generation (0 when empty).
// Generations are allocated by the Node (n.genSeq), which keeps both
// nodes in lockstep and the rebind wire payload byte-identical to the
// pre-registry build.
func (r *carrierRegistry) Generation() uint64 {
	if r.h == nil {
		return 0
	}
	return r.h.gen
}

// Ready reports whether the sole entry is installed and its read loop
// is alive. This is the registry view of the legacy UpReady/DownReady
// single-carrier check.
func (r *carrierRegistry) Ready() bool {
	return r.h != nil && r.h.carrier.Ready()
}

// Add installs h under the given CarrierID. Phase 1 semantics:
//   - id == r.desc.ID: replace the current entry (return the previous
//     handle, which the caller closes per the existing install flow);
//   - id != r.desc.ID: rejected — the registry has no second slot and
//     no other identity is known. The current entry is untouched.
//
// The replacement is a same-carrier reconnect (existing behavior);
// the Node bumps the generation through n.genSeq before calling.
func (r *carrierRegistry) Add(id CarrierID, h *carrierHandle) (*carrierHandle, error) {
	if h == nil {
		return r.h, errors.New("node: cannot install a nil carrier handle")
	}
	if id != r.desc.ID {
		return r.h, fmt.Errorf("%w: registry %q, got %q", ErrUnknownCarrierID, r.desc.ID, id)
	}
	old := r.h
	r.h = h
	return old, nil
}

// ClearIf removes the entry if it still points at h (the loss-sweep
// backstop: a dying carrier only clears the slot if it is still
// current).
func (r *carrierRegistry) ClearIf(h *carrierHandle) {
	if r.h == h {
		r.h = nil
	}
}

// Clear unconditionally empties the slot.
func (r *carrierRegistry) Clear() {
	r.h = nil
}

// Count is the number of installed carriers. In Phase 1 it is always
// 0 or 1; the registry structurally cannot hold more than one.
func (r *carrierRegistry) Count() int {
	if r.h == nil {
		return 0
	}
	return 1
}
