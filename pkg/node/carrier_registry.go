// carrier_registry.go — Phase 2 of plans/multi-carrier-intelligence-design.md
//
// Per-direction carrier registry. Phase 1 held exactly ONE entry per
// direction (a fixed CarrierID). Phase 2 generalizes the DOWN direction to a
// STATIC-ORDER list of carrier instances (D1: two VLESS+Reality instances,
// different listener/SNI) while the UP direction remains single-carrier
// (D5: no second up carrier).
//
// Behavior neutrality: when multi-carrier is disabled the down registry
// holds exactly one entry (DefaultDownCarrierID) and the up registry holds
// exactly one entry (DefaultUpCarrierID) — byte-identical to the Phase 1
// build. All methods are called with the Node mutex held (the registry has
// no lock of its own, matching the existing up/down slot discipline under
// n.mu).
//
// Generation: each installed handle carries a monotonically increasing
// node-global generation (owned by the Node, n.genSeq, lockstep across both
// nodes), so the on-wire rebind generations stay unchanged and each
// generation maps to exactly one handle.
package node

import (
	"errors"
	"fmt"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// CarrierID is a stable, non-secret identifier for a carrier instance.
// It may appear in logs and the dashboard (design §4.1).
type CarrierID string

// Default carrier IDs for the existing single-carrier topology. When
// multi-carrier is disabled these are the ONLY CarrierIDs a Node holds.
const (
	// DefaultUpCarrierID is the sole up (upload) carrier: VLESS over
	// WebSocket via CDN (Iran side), accepted on Germany.
	DefaultUpCarrierID CarrierID = "up-cdn-ws"
	// DefaultDownCarrierID is the primary down (download) carrier:
	// VLESS+Reality over TCP (Germany side), dialed from Iran.
	DefaultDownCarrierID CarrierID = "down-reality-a"
	// SecondDownCarrierID is the SECOND down instance (D1): a second
	// VLESS+Reality listener on a different loopback port and a distinct
	// TLS 1.3 SNI (D3), dialed from Iran's second consumer inbound (D4).
	SecondDownCarrierID CarrierID = "down-reality-b"
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

// String is a stable log prefix, e.g. "carrier[down/down-reality-a]".
func (d CarrierDescriptor) String() string {
	dir := "up"
	if d.Dir == session.DirDown {
		dir = "down"
	}
	return fmt.Sprintf("carrier[%s/%s]", dir, d.ID)
}

// ErrUnknownCarrierID is returned when an install or rebind names a
// CarrierID that is not in this registry's known (allowed) set. Fail-closed:
// an unknown ID is never installed and never re-attached (design §4.4).
var ErrUnknownCarrierID = errors.New("node: unknown carrier id for this registry")

// carrierRegistry holds the installed carriers for one direction, keyed by
// CarrierID, with a STATIC priority order (index 0 = primary). This is the
// Phase 2 static-priority policy (design §7.1): the first Active/ready
// carrier in order is primary, the rest are standby.
//
// Invariants:
//   - the allowed set + order are fixed at construction (from config);
//   - installing the same ID replaces that entry (per-ID reconnect);
//   - installing an ID outside the allowed set is rejected
//     (ErrUnknownCarrierID) and leaves the other entries untouched;
//   - generation is owned by the Node (n.genSeq, node-global, lockstep),
//     so replacement bumps it and the rebind wire generations are
//     unchanged.
type carrierRegistry struct {
	dir     session.Direction
	allowed map[CarrierID]bool
	order   []CarrierID // static priority order, index 0 = primary
	handles map[CarrierID]*carrierHandle
}

// newCarrierRegistry creates a registry with a single fixed carrier (the
// Phase 1 / single-carrier shape). The up direction always uses this.
func newCarrierRegistry(desc CarrierDescriptor) *carrierRegistry {
	return &carrierRegistry{
		dir:     desc.Dir,
		allowed: map[CarrierID]bool{desc.ID: true},
		order:   []CarrierID{desc.ID},
		handles: make(map[CarrierID]*carrierHandle),
	}
}

// newMultiCarrierRegistry creates a registry that accepts the ordered set of
// carrier IDs (index 0 = primary, static priority). Used for the down
// direction when multi-carrier is enabled.
func newMultiCarrierRegistry(dir session.Direction, ids []CarrierID) *carrierRegistry {
	allowed := make(map[CarrierID]bool, len(ids))
	for _, id := range ids {
		allowed[id] = true
	}
	return &carrierRegistry{
		dir:     dir,
		allowed: allowed,
		order:   append([]CarrierID(nil), ids...),
		handles: make(map[CarrierID]*carrierHandle, len(ids)),
	}
}

// Descriptor returns the registry's primary carrier identity.
func (r *carrierRegistry) Descriptor() CarrierDescriptor {
	return CarrierDescriptor{ID: r.order[0], Dir: r.dir, Family: FamilyOfID(r.order[0])}
}

// ID is the registry's primary CarrierID.
func (r *carrierRegistry) ID() CarrierID { return r.order[0] }

// KnownIDs returns the static priority order (index 0 = primary).
func (r *carrierRegistry) KnownIDs() []CarrierID {
	out := make([]CarrierID, len(r.order))
	copy(out, r.order)
	return out
}

// IsKnown reports whether id is in the registry's allowed set.
func (r *carrierRegistry) IsKnown(id CarrierID) bool {
	return r.allowed[id]
}

// SingleEntry reports whether the registry is the single-carrier (Phase 1 /
// disabled) shape: exactly one allowed ID.
func (r *carrierRegistry) SingleEntry() bool { return len(r.order) == 1 }

// Handle returns the entry for id, or nil when none is installed.
func (r *carrierRegistry) Handle(id CarrierID) *carrierHandle {
	return r.handles[id]
}

// Primary returns the highest-priority entry that is installed AND ready
// (the static-priority "primary"), or nil when no carrier is ready. For a
// single-carrier registry this is the sole entry.
func (r *carrierRegistry) Primary() *carrierHandle {
	for _, id := range r.order {
		if h := r.handles[id]; h != nil && h.carrier.Ready() {
			return h
		}
	}
	return nil
}

// Ready reports whether at least one entry is installed and its read loop is
// alive ("at least one carrier installed" — design §4.2).
func (r *carrierRegistry) Ready() bool {
	for _, id := range r.order {
		if h := r.handles[id]; h != nil && h.carrier.Ready() {
			return true
		}
	}
	return false
}

// ReadyIDs returns the carrier IDs (in static priority order) that currently
// have a ready entry. This is the target set for a rebind: a lost carrier's
// pinned streams move to the first ready carrier OTHER than the lost one.
func (r *carrierRegistry) ReadyIDs() []CarrierID {
	var out []CarrierID
	for _, id := range r.order {
		if h := r.handles[id]; h != nil && h.carrier.Ready() {
			out = append(out, id)
		}
	}
	return out
}

// ReadyExcept returns the installed-and-ready handles in static priority order,
// EXCLUDING the entry currently installed under id. This is the failover set
// used on carrier loss: the lost carrier's pinned streams re-attach to the
// surviving Active carriers (design §7.1 static priority). A nil/unknown id
// excludes nothing.
func (r *carrierRegistry) ReadyExcept(exclude CarrierID) []*carrierHandle {
	var out []*carrierHandle
	for _, id := range r.order {
		if id == exclude {
			continue
		}
		if h := r.handles[id]; h != nil && h.carrier.Ready() {
			out = append(out, h)
		}
	}
	return out
}

// Generation returns the current entry's generation for id (0 when not
// installed).
func (r *carrierRegistry) Generation(id CarrierID) uint64 {
	if h := r.handles[id]; h != nil {
		return h.gen
	}
	return 0
}

// Add installs h under id.
//   - id not allowed: rejected (ErrUnknownCarrierID), no entry touched.
//   - id allowed: replace that entry (return the previous handle, which the
//     caller closes per the install flow).
//
// Generations are allocated by the Node before calling.
func (r *carrierRegistry) Add(id CarrierID, h *carrierHandle) (*carrierHandle, error) {
	if h == nil {
		return nil, errors.New("node: cannot install a nil carrier handle")
	}
	if !r.allowed[id] {
		return nil, fmt.Errorf("%w: registry %q, got %q", ErrUnknownCarrierID, r.ID(), id)
	}
	old := r.handles[id]
	r.handles[id] = h
	return old, nil
}

// ClearIf removes the entry for id if it still points at h (the loss-sweep
// backstop: a dying carrier only clears its own slot when it is still
// current for that ID).
func (r *carrierRegistry) ClearIf(id CarrierID, h *carrierHandle) {
	if r.handles[id] == h {
		r.handles[id] = nil
	}
}

// Clear unconditionally empties the slot for id.
func (r *carrierRegistry) Clear(id CarrierID) {
	r.handles[id] = nil
}

// Handles returns the installed entries in static priority order. Nil
// entries (an uninstalled slot) are included so callers can iterate the
// full known set; the caller skips nils.
func (r *carrierRegistry) Handles() []*carrierHandle {
	out := make([]*carrierHandle, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.handles[id])
	}
	return out
}

// Count is the number of installed carriers (0..len(order)).
func (r *carrierRegistry) Count() int {
	n := 0
	for _, id := range r.order {
		if r.handles[id] != nil {
			n++
		}
	}
	return n
}

// CloseAll closes every installed carrier (node shutdown).
func (r *carrierRegistry) CloseAll() {
	for _, id := range r.order {
		if h := r.handles[id]; h != nil {
			h.carrier.Close()
		}
	}
}

// FamilyOfID maps a CarrierID to its transport family (public, non-secret).
func FamilyOfID(id CarrierID) string {
	switch id {
	case DefaultUpCarrierID:
		return FamilyCDNWS
	default:
		return FamilyReality
	}
}
