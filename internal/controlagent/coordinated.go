// coordinated.go — the C4 coordinated two-host apply
// (plans/dashboard-control-design.md §12 C4, D10).
//
// A multi-carrier or carrier-parameter change is a COUPLED change:
// Germany and Iran must agree on the same values. This file models the
// two-phase handshake over the C4 engine (c4.go):
//
//	Phase 1 (prepare)  both hosts render + validate + `xray -test` where
//	                   applicable. NO live-file writes, NO restarts.
//	Phase 2 (commit)   both hosts swap + restart + verify + commit. On
//	                   ANY side's failure that side auto-rolls-back
//	                   (c4.go guarantee); if exactly one side committed,
//	                   the committed side is reverted so BOTH hosts stay
//	                   in the same state (the coupling invariant).
//
// Abort-on-prepare-failure: if either side's prepare fails, BOTH sides
// abort (discard the prepared transactions) and the live files on both
// hosts are untouched.
//
// Single-agent case (D10): until the peer host runs its own agent, the
// flow CANNOT commit on that side. Instead it STAGES a Blob B export for
// the peer and reports "peer change required" — it does not pretend the
// peer is coordinated. The StagedPeerSide below is that half.
//
// No secret ever crosses the handshake: receipts carry only outcome,
// error codes, revision ids and Blob B FINGERPRINTS (never content).
package controlagent

import (
	"sync"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

// ---------------------------------------------------------------------------
// The coordinated-side contract
// ---------------------------------------------------------------------------

// PeerReceipt is one side's prepare/commit/abort/rollback result as seen
// by the coordinator. It is secret-free by construction: only outcomes,
// closed error codes, revision ids, and blob fingerprints ride here.
type PeerReceipt struct {
	Role     string `json:"role"`
	ChangeID string `json:"changeId"`
	// Outcome is the closed set: "prepared", "committed", "rolled-back",
	// "rolled-back-lkg", "aborted", "staged" (a staged peer blob).
	Outcome string `json:"outcome"`
	// Code is the agent's closed error code ("" when the phase succeeded).
	Code string `json:"code,omitempty"`
	// Message is a redacted, operator-safe note (never a secret value).
	Message string `json:"message,omitempty"`
	// Revision is the revision id this phase produced ("" when none).
	Revision string `json:"revision,omitempty"`
	// BlobFingerprint is set for a staged peer (no live agent): the Blob B
	// export's sha256 prefix. The blob CONTENT is never returned.
	BlobFingerprint string `json:"blobFingerprint,omitempty"`
	// PeerChangeRequired states that the peer host must apply a staged
	// change before the tunnel reaches steady state (D10).
	PeerChangeRequired bool `json:"peerChangeRequired,omitempty"`
}

// CoordinatedSide is one host's half of a coupled apply. In production
// the local half is the dashboard's own agent socket and the remote half
// is the peer agent's socket; in tests BOTH halves wrap in-process agents
// (AgentPeer) so the two-phase handshake is provable.
type CoordinatedSide interface {
	// Prepare runs the no-live-write phase on this side and holds the
	// apply lock until the matching Commit/Abort.
	Prepare(role, changeID string, change CandidateChange) (PeerReceipt, error)
	// Commit writes the prepared transaction on this side.
	Commit(role, changeID string) (PeerReceipt, error)
	// Abort discards this side's prepared transaction (no writes).
	Abort(role, changeID string) (PeerReceipt, error)
	// RollbackLKG reverts this side's last committed C4 revision (the
	// "committed side must match the failed side" repair).
	RollbackLKG(role, actor string) (PeerReceipt, error)
}

// ---------------------------------------------------------------------------
// AgentPeer: wrap one in-process *Agent as a CoordinatedSide
// ---------------------------------------------------------------------------

// AgentPeer adapts a local *Agent into a CoordinatedSide so a two-agent
// test (and a future socket transport) can drive the coordinated
// handshake. It remembers each side's prepared handle by changeID and
// faults (Faults) are injected per-phase for the fault-injection tests.
type AgentPeer struct {
	Agent *Agent
	// Faults, when non-nil, are injected into Prepare/Commit on this
	// side (the test's fault map for this host).
	Faults Faults
	// XrayGate, when set, is used by this side's C4 engine for
	// xray-affected changes (tests wire a fake).
	XrayGate XrayGate

	mu      sync.Mutex
	pending map[string]*c4Prepared
}

// NewAgentPeer wraps agent as a coordinated side.
func NewAgentPeer(agent *Agent) *AgentPeer {
	agent.XrayGate = nil // set via the Faults/XrayGate fields when needed
	return &AgentPeer{Agent: agent, pending: map[string]*c4Prepared{}}
}

// SetXrayGate wires the xray gate into the wrapped agent (test helper).
func (p *AgentPeer) SetXrayGate(g XrayGate) { p.Agent.XrayGate = g }

// Prepare implements CoordinatedSide over the C4 engine's prepare phase.
func (p *AgentPeer) Prepare(role, changeID string, change CandidateChange) (PeerReceipt, error) {
	change.ChangeID = changeID
	op := C4ApplyOp{Change: change, Actor: "coordinator"}
	ph, res, code, msg := p.Agent.PrepareC4(op, c4MCConcept(), p.Faults)
	if ph != nil {
		p.mu.Lock()
		p.pending[changeID] = ph
		p.mu.Unlock()
	}
	rc := PeerReceipt{Role: role, ChangeID: changeID, Outcome: res.Outcome, Code: code, Message: msg, Revision: res.RevisionID}
	return rc, nil
}

// Commit implements CoordinatedSide over the C4 engine's commit phase.
func (p *AgentPeer) Commit(role, changeID string) (PeerReceipt, error) {
	p.mu.Lock()
	ph := p.pending[changeID]
	delete(p.pending, changeID)
	p.mu.Unlock()
	if ph == nil {
		return PeerReceipt{Role: role, ChangeID: changeID, Outcome: "failed", Code: "no_prepared_transaction", Message: "commit without a matching prepare on this host"}, nil
	}
	res, code, msg := p.Agent.CommitC4(ph, p.Faults)
	return PeerReceipt{Role: role, ChangeID: changeID, Outcome: res.Outcome, Code: code, Message: msg, Revision: res.RevisionID}, nil
}

// Abort implements CoordinatedSide (discard the prepared transaction).
func (p *AgentPeer) Abort(role, changeID string) (PeerReceipt, error) {
	p.mu.Lock()
	ph := p.pending[changeID]
	delete(p.pending, changeID)
	p.mu.Unlock()
	if ph == nil {
		return PeerReceipt{Role: role, ChangeID: changeID, Outcome: "aborted"}, nil
	}
	res := p.Agent.AbortC4(ph)
	return PeerReceipt{Role: role, ChangeID: changeID, Outcome: res.Outcome}, nil
}

// RollbackLKG implements CoordinatedSide (revert the last committed C4
// revision — the coupled repair for a committed-while-peer-failed host).
func (p *AgentPeer) RollbackLKG(role, actor string) (PeerReceipt, error) {
	res, code, msg := p.Agent.RollbackLKG(actor)
	return PeerReceipt{Role: role, Outcome: res.Outcome, Code: code, Message: msg, Revision: res.RevisionID}, nil
}

// ---------------------------------------------------------------------------
// StagedPeerSide: the single-agent (D10) fallback
// ---------------------------------------------------------------------------

// StagedPeerSide is the CoordinatedSide used when the peer host does NOT
// yet run an agent. It prepares a no-op, "commits" by staging a Blob B
// export for the peer (0600 file, fingerprint only), and ALWAYS reports
// peerChangeRequired. It never writes to the peer host. This is the
// honest "until both hosts run the agent, stage a Blob B export and say
// peer change required" path — it does NOT pretend coordination.
type StagedPeerSide struct {
	Role string // the peer role that must receive the blob (e.g. "iran")
	// StageBlob stages a Blob B export for the peer host and returns its
	// fingerprint. nil → the side reports "staging unavailable".
	StageBlob func(changeID string) (fingerprint string, err error)
}

// Prepare is a no-op on the staged side (the peer has no live agent to
// prepare against); it always succeeds with outcome "staged".
func (s *StagedPeerSide) Prepare(role, changeID string, change CandidateChange) (PeerReceipt, error) {
	return PeerReceipt{Role: s.Role, ChangeID: changeID, Outcome: "staged", PeerChangeRequired: true}, nil
}

// Commit on the staged side STAGES the peer blob (no peer write) and
// reports peerChangeRequired.
func (s *StagedPeerSide) Commit(role, changeID string) (PeerReceipt, error) {
	rc := PeerReceipt{Role: s.Role, ChangeID: changeID, Outcome: "staged", PeerChangeRequired: true}
	if s.StageBlob != nil {
		fp, err := s.StageBlob(changeID)
		if err != nil {
			rc.Outcome = "staged"
			rc.PeerChangeRequired = true
			rc.Code = "blob_staging_failed"
			rc.Message = "could not stage the peer Blob B export: " + err.Error()
			return rc, nil
		}
		rc.BlobFingerprint = fp
	}
	return rc, nil
}

// Abort on the staged side is a no-op (nothing was written to the peer).
func (s *StagedPeerSide) Abort(role, changeID string) (PeerReceipt, error) {
	return PeerReceipt{Role: s.Role, ChangeID: changeID, Outcome: "aborted"}, nil
}

// RollbackLKG on the staged side is a no-op (the peer was never changed).
func (s *StagedPeerSide) RollbackLKG(role, actor string) (PeerReceipt, error) {
	return PeerReceipt{Role: s.Role, Outcome: "staged"}, nil
}

// ---------------------------------------------------------------------------
// Coordinator: the two-phase handshake
// ---------------------------------------------------------------------------

// CoordinatedPlan is one coupled C4 change spanning both hosts. Both
// CandidateChanges MUST carry the same ChangeID (the coupling token that
// proves "Germany and Iran agree"); the coordinator enforces it.
type CoordinatedPlan struct {
	ChangeID string
	Actor    string
	// Germany's candidate env change (role germany).
	Germany CandidateChange
	// Iran's candidate env change (role iran).
	Iran CandidateChange
}

// CoordinatedResult is the outcome of one coordinated apply.
type CoordinatedResult struct {
	// Outcome: "committed" (both sides applied + verified), "aborted"
	// (a prepare failed, both sides untouched), "rolled-back" (a commit
	// failed and the committed side was reverted), or "staged" (the peer
	// has no live agent; a Blob B export was staged, peer change
	// required).
	Outcome  string      `json:"outcome"`
	ChangeID string      `json:"changeId"`
	Germany  PeerReceipt `json:"germany"`
	Iran     PeerReceipt `json:"iran"`
	// PeerChangeRequired states the operator must carry a staged change to
	// the peer host (the staged-peer case).
	PeerChangeRequired string `json:"peerChangeRequired,omitempty"`
	// BlobFingerprint is the staged peer blob's fingerprint ("" when no
	// blob was staged).
	BlobFingerprint string `json:"blobFingerprint,omitempty"`
}

// Coordinator drives a coupled C4 change across two sides.
type Coordinator struct {
	Germany CoordinatedSide
	Iran    CoordinatedSide
}

// NewCoordinator builds a coordinator over two sides (either two live
// agents, or one live agent + one staged peer).
func NewCoordinator(germany, iran CoordinatedSide) *Coordinator {
	return &Coordinator{Germany: germany, Iran: iran}
}

// CoupledApply runs the two-phase handshake:
//
//  1. Prepare BOTH sides (no writes anywhere).
//  2. If either prepare failed → ABORT both (both live files untouched).
//  3. Commit BOTH sides.
//  4. If exactly one side committed and the other failed (auto-rolled
//     back inside the engine) → roll back the COMMITTED side so both
//     hosts stay in the same state.
//
// The staged-peer case (a side reports outcome "staged") degrades to a
// "staged" result: the live side is NOT committed, and a Blob B export is
// staged for the peer (the honest D10 path).
func (co *Coordinator) CoupledApply(plan CoordinatedPlan) CoordinatedResult {
	if plan.ChangeID == "" {
		plan.ChangeID = "c4-coord"
	}
	plan.Germany.ChangeID = plan.ChangeID
	plan.Iran.ChangeID = plan.ChangeID

	// Phase 1: prepare both (no writes on either host).
	gr, _ := co.Germany.Prepare(config.RoleGermany, plan.ChangeID, plan.Germany)
	ir, _ := co.Iran.Prepare(config.RoleIran, plan.ChangeID, plan.Iran)

	// Abort-on-prepare-failure: a failed prepare on either side aborts
	// BOTH; both live files are untouched (prepare never wrote them).
	// The staged-peer case is NOT a prepare failure: a staged side
	// reports "staged", which means the peer has no live agent.
	preparedOK := gr.Outcome == "prepared" && ir.Outcome == "prepared"
	if !preparedOK {
		if gr.Outcome == "staged" || ir.Outcome == "staged" {
			// Do not commit the live side: the coupling invariant
			// requires both hosts. Stage the peer blob and report.
			return co.stagedResult(plan, gr, ir)
		}
		// A side whose prepare SUCCEEDED holds a prepared transaction
		// (and the apply lock); abort it to discard it. A side whose
		// prepare FAILED has nothing to discard; normalize its receipt to
		// "aborted" while keeping its Code so the operator sees why.
		if gr.Outcome == "prepared" {
			gr, _ = co.Germany.Abort(config.RoleGermany, plan.ChangeID)
		} else {
			gr.Outcome = "aborted"
		}
		if ir.Outcome == "prepared" {
			ir, _ = co.Iran.Abort(config.RoleIran, plan.ChangeID)
		} else {
			ir.Outcome = "aborted"
		}
		return CoordinatedResult{Outcome: "aborted", ChangeID: plan.ChangeID, Germany: gr, Iran: ir}
	}

	// Phase 2: commit both.
	gc, _ := co.Germany.Commit(config.RoleGermany, plan.ChangeID)
	ic, _ := co.Iran.Commit(config.RoleIran, plan.ChangeID)

	gCommitted := gc.Outcome == "committed"
	iCommitted := ic.Outcome == "committed"

	switch {
	case gCommitted && iCommitted:
		return CoordinatedResult{Outcome: "committed", ChangeID: plan.ChangeID, Germany: gc, Iran: ic}

	case gCommitted && !iCommitted:
		// Iran failed (auto-rolled-back); revert Germany to match.
		rr, _ := co.Germany.RollbackLKG(config.RoleGermany, plan.Actor)
		return CoordinatedResult{Outcome: "rolled-back", ChangeID: plan.ChangeID, Germany: rr, Iran: ic,
			PeerChangeRequired: "the Iran side's commit failed; the Germany side was reverted to keep both hosts coupled"}

	case iCommitted && !gCommitted:
		// Germany failed (auto-rolled-back); revert Iran to match.
		rr, _ := co.Iran.RollbackLKG(config.RoleIran, plan.Actor)
		return CoordinatedResult{Outcome: "rolled-back", ChangeID: plan.ChangeID, Germany: gc, Iran: rr,
			PeerChangeRequired: "the Germany side's commit failed; the Iran side was reverted to keep both hosts coupled"}

	default:
		// Both failed and auto-rolled-back: both hosts are back to the
		// pre-change state (the coupling invariant holds).
		return CoordinatedResult{Outcome: "rolled-back", ChangeID: plan.ChangeID, Germany: gc, Iran: ic,
			PeerChangeRequired: "both sides' commits failed; both hosts auto-rolled-back to the pre-change state"}
	}
}

// stagedResult is the single-agent (D10) outcome: the live side is NOT
// committed (the coupling invariant requires both hosts), and a Blob B
// export is staged for the peer host, which reports "peer change
// required". The result NEVER implies a coordinated apply happened.
//
// It aborts the live (prepared) side so the operator's live host is
// untouched, then "commits" the STAGED side — which for a
// StagedPeerSide stages the peer Blob B export and returns its
// fingerprint (never the content) — and copies that fingerprint + the
// peer-change notice into the result.
func (co *Coordinator) stagedResult(plan CoordinatedPlan, gr, ir PeerReceipt) CoordinatedResult {
	res := CoordinatedResult{Outcome: "staged", ChangeID: plan.ChangeID, Germany: gr, Iran: ir}
	switch {
	case gr.Outcome == "staged" && ir.Outcome == "prepared":
		// Iran is live (prepared); Germany is the staged peer. Keep Iran
		// untouched and stage a Blob B export for the Germany host.
		ir, _ = co.Iran.Abort(config.RoleIran, plan.ChangeID)
		res.Iran = ir
		st, _ := co.Germany.Commit(config.RoleGermany, plan.ChangeID)
		res.Germany = st
		res.BlobFingerprint = st.BlobFingerprint
		res.PeerChangeRequired = "stage a Blob B export for the Germany host; the Iran side is not committed until the peer applies it (peer change required)"
	case ir.Outcome == "staged" && gr.Outcome == "prepared":
		// Germany is live (prepared); Iran is the staged peer. Keep
		// Germany untouched and stage a Blob B export for the Iran host.
		gr, _ = co.Germany.Abort(config.RoleGermany, plan.ChangeID)
		res.Germany = gr
		st, _ := co.Iran.Commit(config.RoleIran, plan.ChangeID)
		res.Iran = st
		res.BlobFingerprint = st.BlobFingerprint
		res.PeerChangeRequired = "stage a Blob B export for the Iran host; the Germany side is not committed until the peer applies it (peer change required)"
	}
	return res
}
