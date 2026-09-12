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

## Implementation checkpoint (2026-09-12)

Implemented locally on `main` (`10b4b84`, `8432962`, `ac573c6`); full local suite green on Windows. Linux staging validation and a clean-Ubuntu acceptance run are still pending, so T8-B is not claimed complete.

### CLI mutation contract (`cmd/splitterctl`)

`install`, `rollback`, `uninstall`, and `recover` are wired to the real Linux adapter + controller. All four are Linux-gated (`install requires Linux` style error on non-Linux hosts) because the canonical state root is only a valid absolute path on Linux; tests redirect the `goos`/state-root variables rather than weakening the gate.

- Deployment secrets come from the existing `SPLIT_*` contract via `config.Load(role)`; `install` additionally requires `SPLITTERCTL_SPLITTER_BIN` (absolute) + `SPLITTERCTL_SPLITTER_VERSION`, `SPLITTERCTL_XRAY_VERSION` (default pin) for Germany, and the Germany Reality trio (`SPLITTERCTL_REALITY_SNI`/`_SHORT_ID`/`_UUID`) or the Iran origin set (`SPLITTERCTL_ORIGIN_MODE` caddy|cdn, `SPLITTERCTL_UPLOAD_DOMAIN`, plus mode-specific `SPLITTERCTL_ORIGIN_PORT`/`SPLITTERCTL_ACME_EMAIL`/`SPLITTERCTL_ACME_CHALLENGE`/`SPLITTERCTL_CDN_SECURITY`/`SPLITTERCTL_CDN_ORIGIN_TRUST`). Optional `SPLITTERCTL_FIREWALL_BACKEND` (default none) and `SPLITTERCTL_FW_ALLOW`/`SPLITTERCTL_FW_DENY` (comma-separated TCP ports, marker-commented owned rules).
- Canonical paths are fixed by the adapter, not operator-selectable: state `/etc/split-tunnel`, env `/etc/split-tunnel/<role>.env`, Germany config `/etc/split-tunnel/xray-germany.json`, Iran Caddyfile `/etc/split-tunnel/Caddyfile` (caddy and cdn-tlsOrigin only), binaries under `/opt/split-tunnel/{xray,caddy}/<version>/`. The origin version is fixed to the pinned Caddy version because the origin provider only installs the pin; the Xray version is operator-selectable.
- Errors are field-only (name of the missing/invalid variable, never a value); read-only commands keep the `SPLITTERCTL_STATE_ROOT` override.
- `rollback`/`uninstall` re-derive the request from the current manifest's role environment (manifests store fingerprints, not secrets), so the original deployment env must still be available; divergence is refused by the rollback guards, not silently papered over.
- `upgrade` and `config set` remain `notWired` with an honest printed rationale: in-place binary/config mutation is out of T8-B scope because the safe path is a new `install` revision (commit-last) plus `rollback`, and there is no tested hot-swap primitive for the running splitter.

### Journal lifecycle (fail-closed)

The artifact journal is written atomically (`0600`) before the first mutation and retained on every failure path, including successful in-process recovery; it is cleared only after a committed revision or by explicit operator acknowledgement. Consequences are surfaced, not hidden:

- `install` and `rollback` refuse to start while a stale journal exists ("finish recovery before installing/rolling back").
- `recover` (report mode) prints the in-flight scope (role, generation, touched units/files, firewall flag) with guidance; `recover --ack` clears the journal after the operator has verified the host. `--ack` with no journal is an error.

### Bounded rollback semantics

`LinuxAdapter.Restore` has three paths: journal present (precise in-flight revert of owned artifacts only), no journal with no in-flight units (re-rendered convergence `rollbackTo`: fail-closed guards, xray pointer re-point, unit apply/remove to the target shape, health wait on every target unit), and no journal with in-flight units (fail-closed `ErrTransaction`).

Documented limitations (intentional):

- The re-rendered-convergence path refuses when the firewall rule set, Germany Reality parameters, or Iran origin shape differ from the current request — those are not reconstructible from the manifest and must be re-provisioned deliberately.
- The env file is never rolled back (secrets are not retained in revisions; env changes take effect on the next successful install).
- Pairing is not rolled back (pair state is a separate boundary, not a deployment artifact).
- Uninstalling a firewall deployment requires the same firewall env as at install time (the inspection plan comes from the request).
- `Desired()` records an origin service entry for all non-none modes while the unit is only rendered for caddy/cdn-tlsOrigin (cdn plainOrigin leaves a manifest-only entry; known cosmetic inconsistency).

### Validation status

- Windows: `go build ./...`, `go vet`, full `go test ./...` green (adapter/transaction/controller tests use injected executors; CLI tests are deterministic cross-platform via test-redirectable vars).
- Linux: not yet executed. Required before any T8 completion claim: `go test` on a real Linux host, transaction fault-injection against the real systemd/executor paths, and a clean-Ubuntu L5 acceptance run (staging profiles `iran-node`/`germany-node` are non-clean and only evidence the baseline).
- CI (GitHub Actions, Linux) is authoritative for race/symlink-sensitive cases; results for `8432962`/`ac573c6` must be green before merge-gate sign-off.

## Current findings

- CRITICAL: 0 from this audit.
- HIGH: 1 integration gap: no concrete Linux adapter/composition root yet. RESOLVED locally by `bf1bcda` + `10b4b84` + `8432962` + `ac573c6`; downgraded to a Linux-validation item pending the staging runs above.
- HIGH: 1 security hygiene issue outside T8 logic: `.roo/mcp.json` contains credential-like inline MCP tokens. Values are not reproduced here; they must be rotated and removed from tracked configuration in a separate security milestone before release.
- MEDIUM: staging hosts are reused/non-clean; do not claim clean-machine acceptance from them.
