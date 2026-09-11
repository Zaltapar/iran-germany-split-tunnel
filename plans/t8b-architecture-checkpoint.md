# T8-B Architecture Checkpoint

Date: 2026-09-11
Baseline: `main` at `e7143b3`

## Audit result

The repository has the T8 state/planner, transaction coordinator, pairing boundary, guarded rollback, typed adapter boundary, request validation, protected env projection, pure systemd handoff planning, and strict/read-only `splitterctl` surface. It does not yet have concrete Linux role adapters or executable mutation command wiring.

Authoritative ownership remains:

- `internal/pairing`: blob format, validation, secret/UUID/Reality identifiers, opposite-role checks.
- `internal/xray`: pinned Xray download/digest verification, key generation, Germany config rendering, Xray config activation gate.
- `internal/origin`: pinned Caddy/provider installation, origin plan validation/configuration/status.
- `internal/systemd`: service user/directories, protected env files, canonical unit rendering/application, service transitions/health/uninstall.
- `internal/firewall`: owned-rule inspection/apply/remove with UFW/nftables/none backends.
- `internal/deploy`: desired state, transaction/recovery coordination, request-to-plan conversion, manifest persistence, composition only.
- `cmd/splitterctl`: parsing, input collection, safe rendering, exit status; no deployment policy.

No duplicate T2-T6 implementation was found. The current missing composition root is the only intended new policy layer.

## Staging baseline (read-only audit)

Configured SSH profiles `iran-node` and `germany-node` are reachable Linux hosts, but neither is clean:

- Iran: enabled/running `iran-splitter.service`; listeners `10900`, `9001`, `9100`; `/etc/split-tunnel/iran.env`; project binaries and `l5cli` under `/opt/split-tunnel`.
- Germany: enabled/running `germany-splitter.service`; listeners `9002`, `9101`, `11001`, `11002`; `/etc/split-tunnel/germany.env` plus a backup; project binaries/backups and `l5cli` under `/opt/split-tunnel`.
- No cleanup or mutation was performed. Existing resources remain classified as project/test-owned pending a stronger ownership manifest; unknown/external resources must not be touched.
- A clean Ubuntu acceptance host is still required for the final clean-machine claim.

## Required implementation decisions

1. Fresh install uses an explicit cleanup/recovery contract, not `Restore(Manifest{})`. The adapter will track only artifacts it successfully owns in a transaction journal and remove/revert those artifacts on failure. If cleanup fails, the journal remains and state is not committed.
2. `DesiredState` must include complete service and firewall projections; request conversion must be deterministic and secret-free.
3. Concrete adapter construction occurs in one composition root. It delegates all mutations to T2-T6 and uses injected interfaces for L1-L3 tests; production defaults use the canonical Linux paths and root gates.
4. Pairing blobs may be printed only for explicit pairing operations. Manifest/revisions contain only state/fingerprints.
5. Iran never manages external Xray/3x-ui. Germany owns only the project Xray installation/config/service.
6. Every mutation is context-bounded, structured-argv, ownership-scoped, idempotent, and commit-last.

## Current findings

- CRITICAL: 0 from this audit.
- HIGH: 1 integration gap: no concrete Linux adapter/composition root yet. This is the active T8-B implementation target, not a bypass justification.
- HIGH: 1 security hygiene issue outside T8 logic: `.roo/mcp.json` contains credential-like inline MCP tokens. Values are not reproduced here; they must be rotated and removed from tracked configuration in a separate security milestone before release.
- MEDIUM: staging hosts are reused/non-clean; do not claim clean-machine acceptance from them.
