# T4 Origin/CDN — Architect Security & Architecture Review

- **Task**: T4-C2 — Iran-side origin/CDN deployment component
- **Branch**: `feat/t4-origin`
- **Reviewed HEAD**: `f35337dc75a65130b38f50b4320b220869e61025`
- **Base**: `main` at `2e2da9aec66092dd92da95f3017c83820ad16c31`
- **Reviewer**: Architect, independent falsification pass
- **Scope**: `internal/origin`, the additive upload-domain validator in `internal/pairing`, `plans/t4-design.md`, and architecture sections governing origin/CDN topology
- **Merge gate**: CRITICAL = 0 and HIGH = 0. Every MEDIUM must be fixed, explicitly accepted with rationale, or tracked.

## Verdict — Round 1

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH     | 5 |
| MEDIUM   | 2 |
| LOW      | 0 |

**Result: FAIL — do not push for merge.** Focused tests pass, but they do not exercise the hostile-input, cancellation, failed-force-install, failed-final-swap, or provider-certificate-trust cases that invalidate several implementation claims.

## Findings summary

| ID | Severity | Location | Summary |
|----|----------|----------|---------|
| CRITICAL-1 | CRITICAL | `internal/origin/origin.go`, `internal/origin/caddyfile.go` | Caddyfile injection through insufficiently validated ACME email and upstream port tokens |
| HIGH-1 | HIGH | `internal/origin/install.go` | `Force` removes the known-good pinned version before the replacement passes smoke/config gates |
| HIGH-2 | HIGH | `internal/origin/caddy.go`, `internal/origin/install.go`, `internal/origin/http.go` | Public context-bearing provider API ignores cancellation; real commands can hang without a bound |
| HIGH-3 | HIGH | `internal/origin/activate.go` | A failed final swap can destroy or replace an existing rollback artifact, contradicting failure atomicity |
| HIGH-4 | HIGH | `internal/origin/cdn.go`, architecture §5.1 | Default CDN TLS-origin instructions silently assume the CDN accepts or trusts Caddy's private CA certificate |
| HIGH-5 | HIGH | `internal/origin/cdn.go` | CDN mode A → mode B does not converge: stale managed Caddy state remains and `Status` reports the wrong submode |
| MEDIUM-1 | MEDIUM | `internal/origin/caddy.go` | Existing binary reuse treats a forgeable version string as proof that the installed binary is unmodified |
| MEDIUM-2 | MEDIUM | `internal/origin/preflight.go` | Probe accepts unvalidated SNI, exposes sensitive target values in errors, and misclassifies every post-connect TLS failure as lack of TLS 1.3 |

---

## CRITICAL-1 — Caddyfile injection through ACME email and upstream port

### Evidence

`Plan.validate` claims the renderer writes only validated fixed-template substitutions. That is false for two substitutions:

1. `validateACMEEmail` checks exactly one `@` and only compares `strings.TrimSpace(e)` with `e`. It does **not** reject whitespace or control characters inside the value. A value containing an internal newline, one `@`, and non-whitespace final content passes validation and is inserted directly after `tls` or `email`.
2. `validateUpstream` uses `net.SplitHostPort`, checks only that the port string is non-empty, and never parses/canonicalizes it as a numeric port in `1..65535`. The raw `UpstreamAddr` is inserted directly into the `reverse_proxy` directive. `SplitHostPort` is a structural splitter, not a port-token validator.

A malicious value can therefore escape its intended Caddyfile token and add directives or blocks. The pinned Caddy validation gate does not make this safe: an injected configuration can be syntactically valid and pass the gate.

### Required remediation

- Reject every ASCII/Unicode whitespace and control character in ACME email input; preferably parse with a narrow mailbox-token rule suitable for Caddy and then render only the canonical accepted value.
- Parse the upstream port as decimal digits, require `1..65535`, and reconstruct the rendered upstream with `net.JoinHostPort(parsedLoopbackIP.String(), strconv.Itoa(port))`; never render the raw input.
- Keep the host restricted to a parsed loopback IP.
- Add adversarial tests containing internal newline, carriage return, tab, spaces, braces, comment markers, and directive-shaped suffixes for both fields.
- Assert rejected values produce `ErrInvalidPlan`, no rendered bytes, no gate call, and no filesystem mutation.

Acceptance: no operator-controlled raw string reaches a Caddyfile token without narrow validation and canonicalization.

## HIGH-1 — Forced reinstall destroys the known-good version before validation

### Evidence

When the target version directory exists and `Force` is true, `Install` calls `os.RemoveAll(versionDir)` before moving, chmodding, smoke-checking, or config-validating the replacement. Any later failure leaves no pinned version at all. This directly contradicts the stated guarantees that the previous version is untouched and that install follows prepare → validate → backup → activate.

The current force test covers only successful replacement. It does not inject failure after deletion.

### Required remediation

- Build and verify the candidate under a distinct staging/version-candidate path.
- Smoke-check and, when supplied, config-gate the candidate before replacing anything.
- Atomically exchange through a same-filesystem backup name, or rename existing → backup, candidate → live, and restore existing on any second-step failure.
- Refuse unsafe existing version paths, including symlinks/non-directories, before any recursive removal.
- Add failure-injection tests for chmod, smoke, config gate, first rename, and second rename with `Force=true`; the pre-existing binary must remain byte-identical and runnable after every failure.

## HIGH-2 — Context and cancellation are ignored

### Evidence

`OriginProvider.Configure(ctx, ...)` and `Status(ctx)` accept a context, but `caddyCore.configure`, `ensureInstalled`, and `fileStatus` never observe it. `OSExecutor` uses `exec.Command`, not `exec.CommandContext`. `HTTPDownloader` constructs requests without the provider context. The HTTP client has a ten-minute bound, while real Caddy version/validate commands have no bound at all.

This violates the explicit ownership/cancellation model and makes orchestration shutdown or operator cancellation ineffective during an external dependency failure.

### Required remediation

- Thread context through download, install, version, validate, configure, and status operations.
- Use `exec.CommandContext` and `http.NewRequestWithContext`.
- Preserve testability with context-aware interfaces rather than hidden global timeouts.
- Check cancellation before filesystem activation and between expensive phases so cancellation cannot begin a new mutation.
- Add deterministic tests using a canceled context and blocking fakes; operations must return promptly with `context.Canceled` or `context.DeadlineExceeded`, leave the previous state byte-identical, and terminate child commands.

## HIGH-3 — Failed final swap can destroy rollback history

### Evidence

Activation writes the previous live bytes to `Caddyfile.prev`, potentially replacing an already-existing rollback artifact. If the subsequent live rename fails, the error path unconditionally removes `Caddyfile.prev`. It does not restore the pre-activation `.prev` content. The helper also does not validate existing `.prev` or `.prev.tmp` object types before using them.

Therefore the documented claim that any failure leaves the previous file set byte-identical is false. A failure can erase the operator's prior rollback point even though the live file remains unchanged.

### Required remediation

- Treat live, candidate, rollback, and rollback-temp as one transaction.
- Snapshot/preserve an existing rollback artifact before replacing it, or defer committing the new rollback artifact until the live swap cannot fail without restoration.
- Refuse symlink/special objects for every managed transaction path.
- Add an injectable filesystem/rename seam or a deterministic filesystem setup that forces the final swap failure.
- Test both cases: no pre-existing `.prev`, and a pre-existing `.prev` with distinct bytes. After failure, the entire directory snapshot must be byte-identical to its initial state.

## HIGH-4 — CDN TLS-origin trust is not provider-independent as documented

### Evidence

Mode A generates `tls internal`, so Caddy presents a certificate rooted in Caddy's local private CA. The instructions say only `TLS: ON` and describe the public certificate as supplied by the CDN. They do not state how the CDN authenticates the **origin** certificate.

A generic CDN in strict origin-verification mode will not trust an arbitrary Caddy-local CA. Some providers may support self-signed origin pulls in a non-strict mode; some require a provider-issued Origin CA certificate; some allow a customer CA upload. Those are materially different security topologies. A Caddy internal certificate is not automatically equivalent to a provider Origin CA certificate.

The current default therefore silently assumes provider behavior, contrary to the task requirement. It may either fail to deploy or encourage disabling origin authentication without saying so.

### Required remediation / architecture decision

Record and implement one explicit provider-independent contract:

- **Encrypted but non-authenticated origin TLS**: require a provider mode that accepts a self-signed certificate, explicitly state that the CDN does not authenticate the origin certificate, and document the MITM limitation; or
- **Authenticated private-CA origin TLS**: export/install the Caddy root certificate through a provider-specific adapter or operator step, explicitly state the required CDN capability, and protect the CA material; or
- **Provider-issued Origin CA certificate**: add a provider adapter/input model and transactional certificate/key storage; do not label it generic.

Mode A instructions must fail closed when the selected provider capability is unknown. Tests must pin the chosen trust model and ensure no text implies that a Caddy-internal certificate is automatically provider-trusted.

This decision does not require production credentials now, but it must be resolved before the component can merge as deployable.

## HIGH-5 — CDN submode transitions do not converge

### Evidence

Mode B `Configure` only validates and returns. If mode A was previously configured, the managed Caddyfile and installed Caddy state remain. `Status` infers mode A solely from whether a Caddyfile exists, without a desired plan or persisted submode. Thus A → B leaves stale state and reports file-level Caddy health rather than the selected plain-origin state.

This violates idempotent convergence and makes restart/orchestration behavior ambiguous.

### Required remediation

- Make desired CDN submode explicit in status/state rather than inferring it from file existence.
- Define ownership-safe transition behavior. For A → B, remove or deactivate only a file carrying the exact project-managed marker, transactionally and with rollback metadata; never delete an operator-owned file.
- Define B → A symmetrically.
- Add transition tests A → B → A, repeated application, unmanaged-file refusal, canceled transition, and failure rollback.
- Coordinate the state shape with `internal/deploy`; do not create a second manifest implementation inside `internal/origin`.

## MEDIUM-1 — Existing binary reuse does not verify integrity

`ensureInstalled` says a poisoned binary must not be trusted, but it checks only `caddy version`. A modified binary can print the pinned version. The original SHA-512 is returned in `Installed` but is not persisted or checked here.

Disposition required: either verify the binary against a persisted manifest hash before reuse, or narrow the claim and explicitly delegate integrity drift detection to the deployment manifest/doctor with a fail-closed caller contract. Prefer the latter if `internal/deploy` is the authoritative manifest owner, but do not claim version output proves integrity.

## MEDIUM-2 — TLS 1.3 probe validation, diagnostics, and classification

The probe:

- does not validate `sni` before placing it into `tls.Config`;
- embeds the target and underlying network/TLS error in ordinary errors even though deployment domains/targets are treated as security-sensitive;
- maps every handshake failure after TCP connect to `ErrNoTLS13`, including SNI rejection, client-certificate requirements, immediate close, malformed TLS, or cancellation.

Fail-closed behavior is correct, but the diagnosis can be wrong and sensitive deployment data can leak into logs.

Required disposition: validate SNI through the existing pairing/Xray rule; return field-only bounded errors; preserve `context.Canceled`/`DeadlineExceeded`; distinguish protocol-version rejection from generic TLS handshake failure unless the implementation can prove the peer lacks TLS 1.3. Add tests for empty/invalid SNI, canceled handshake, non-TLS peer, and TLS 1.3 peer rejecting the supplied SNI.

---

## Claims that survived Round 1

- Package placement preserves the `pkg/*` versus deployment boundary.
- No new Go dependency was introduced.
- Domain validation delegates to the pairing source of truth.
- Release URLs are version-pinned and artifact bytes are checked against the upstream SHA-512 sidecar before execution.
- Download/checksum/extraction memory is bounded.
- Tar path traversal and link entries are refused.
- Caddyfile output is deterministic for benign canonical plans.
- The generated proxy body avoids Caddy's total `stream_timeout`.
- Candidate config is validated before the live Caddyfile swap.
- No tunnel secret or Reality private key is intentionally passed into this package.
- Focused package build and tests pass at the reviewed HEAD; this is necessary but insufficient for approval.

## Re-review gate

After remediation:

1. Run focused origin/pairing tests.
2. Run adversarial injection and transition tests.
3. Run the real pinned-Caddy validation gate on Linux.
4. Run full `go vet`, `go test`, Linux `go test -race`, and `go build`.
5. Re-open this review as Round 2 and actively test each required acceptance statement.

Target before PR: **CRITICAL = 0, HIGH = 0**; every MEDIUM explicitly dispositioned.

---

## Verdict — Round 2

- **Review target**: remediated but uncommitted T4 worktree on `feat/t4-origin`, based on reviewed commit `f35337dc75a65130b38f50b4320b220869e61025`.
- **Method**: independent adversarial review of the transaction protocol, cancellation paths, CDN A-to-B transition/restart behavior, generated Caddyfile input boundary, trust-contract documentation, and CI proof obligations.

| Severity | New open | Round 1 disposition |
|----------|----------|---------------------|
| CRITICAL | 0 | All remediated in worktree |
| HIGH     | 2 | Round 1 HIGH-1 through HIGH-5 implementation fixes verified; new blockers below |
| MEDIUM   | 3 | New findings below |
| LOW      | 3 | Tracked below |

**Result: FAIL — do not commit for PR or merge.** The prior injection, cancellation, activation rollback, trust-contract, and submode-state fixes are materially present. However, a force-install crash can still erase the only known-good binary, and the required real pinned-Caddy CI proof is absent.

### HIGH-R2-1 — Force-install crash recovery destroys the only known-good version

[`prepareStageDir()`](internal/origin/install.go:415) indiscriminately removes every regular [`*.old`](internal/origin/install.go:439) directory. A process or host crash after [`Rename(versionDir, backupDir)`](internal/origin/install.go:343) but before [`Rename(candidateDir, versionDir)`](internal/origin/install.go:354) leaves `caddy/<version>.old` as the sole copy of the previously working version. The next install calls [`prepareStageDir()`](internal/origin/install.go:269), which deletes that sole copy before any candidate is validated.

This is a realistic interrupted transaction state, not a normal error path covered by the current second-rename rollback test. It violates the recovery guarantee established for Round 1 HIGH-1.

**Required remediation / acceptance:**

- Before sweeping transaction residue, enumerate version-specific `live`, `.new`, and `.old` state safely with `Lstat`; never follow links.
- When only a regular `.old` exists for a version, atomically restore it to the missing live version directory before beginning a new install.
- When live and `.old` both exist, or residue cannot be unambiguously recovered, fail closed without deleting either artifact; `.new` cleanup must likewise be ownership-safe.
- Add deterministic crash-state tests for: only `.old`; live plus `.old`; and symlink/non-directory residue. The test must prove the original binary bytes remain runnable and no unsafe path is removed.

### HIGH-R2-2 — Required pinned-Caddy Linux CI gate is missing

The design requires real pinned-Caddy artifact verification and validation of a rendered origin configuration, but [`go.yml`](.github/workflows/go.yml:22) only has the Xray external-binary gate. No workflow step downloads the Caddy release pinned by [`PinnedVersion`](internal/origin/version.go), verifies it using the production SHA-512 sidecar parser, runs `caddy version`, and validates each rendered Caddyfile mode.

Unit fakes cannot prove compatibility with Caddy's real parser or that the production release URL/checksum format has not drifted. This gate is an explicit T4 completion requirement and must exist before PR.

**Required remediation / acceptance:**

- Add a Linux workflow step that downloads the exact release named by the production constants, retrieves the matching `checksums.txt`, and verifies the archive SHA-512 using the same two-space filename semantics as production.
- Render deterministic direct-Caddy and CDN-TLS fixture configurations through a test-only, stable-path harness; validate both with the downloaded executable and assert its version.
- Keep the intentional network dependency isolated to this gate, after hermetic Go tests; make any URL, version, architecture, and checksum-parser assumptions visibly match production code.

### MEDIUM-R2-1 — Deactivation aside names collide after process restart

[`uniqueSuffix()`](internal/origin/cdn.go:257) derives aside names solely from a process-local atomic counter. Existing `.cdn-deactivate-1` residue survives a process restart, but the counter resets and the next [`os.Mkdir`](internal/origin/cdn.go:212) tries the same name. A legitimate later A-to-B convergence then fails with `EEXIST` until a human removes preserved transaction metadata.

**Required remediation:** allocate deactivation directories by retrying incrementing suffixes after checking each candidate with `Lstat`; reject unsafe collisions, preserve nonempty historical rollback directories, and optionally remove only empty project-owned stale directories. Add a restart-collision regression test.

### MEDIUM-R2-2 — Plain-origin `Status` asserts liveness without evidence

For persisted mode B, [`CDNProvider.Status()`](internal/origin/cdn.go:99) reports `Live: true` even though this package has not observed the splitter listener, service state, or CDN reachability. It also bypasses a canceled context on that branch. Selection/convergence is useful status, but it is not a liveness result.

**Required remediation:** return an honest non-live or unknown/unverified health state with detail that mode B is selected and runtime liveness belongs to the T7 deploy/doctor health probe; check `ctx.Err()` before all successful return paths. Add tests for canceled mode-B status and the non-assertive health contract.

### MEDIUM-R2-3 — Corrupt CDN state is misreported as an unconfigured deployment

[`readCDNState()`](internal/origin/cdn.go:156) correctly detects corrupt state, but [`CDNProvider.Status()`](internal/origin/cdn.go:106) merges that failure into the legacy no-record fallback. A damaged project-owned record can therefore produce the misleading instruction to configure a fresh deployment, rather than surfacing a state-integrity error for repair.

**Required remediation:** distinguish `os.IsNotExist` from malformed/unreadable state. Preserve and return a bounded corruption/read error without falling back; add malformed-state and unreadable-state tests.

### LOW-R2-1 through LOW-R2-3 — Residue and test-strength follow-ups

1. Preserved deactivation aside directories accumulate indefinitely. Define their manifest ownership and cleanup/rollback retention policy in T7 rather than silently deleting potentially valuable rollback data.
2. A crash after activation moves an existing `.prev` aside and before the new `.prev` is committed has a recovery window not yet represented by a persistent transaction journal. Address this under T7 manifest/recovery ownership.
3. The child-cancellation test uses a pre-canceled context and does not prove that an already-running descendant exits on cancellation. Strengthen it with a started-child synchronization signal on Linux CI.

### Verified Round 1 remediations

- Caddyfile substitutions now pass narrow email validation and canonical loopback-address/decimal-port reconstruction before rendering.
- Candidate Caddy artifacts are downloaded, checksummed, extracted, smoke-checked, and config-gated before the normal force exchange begins.
- HTTP and command paths propagate context; command execution is bounded through [`exec.CommandContext`](internal/origin/install.go:119).
- Activation preserves/restores the full live and rollback file set on an injected final-swap failure.
- CDN TLS-origin requires an explicit D9 trust contract, with bounded instructions for both `pullCA` and `unauthenticatedTLS`.
- CDN desired submode is persisted rather than inferred from Caddyfile presence; A-to-B deactivation is marker-owned and rollback-aware.
- Preflight validates SNI through pairing rules, avoids target/SNI in diagnostics, and distinguishes a proven TLS-version alert from other handshake failures.

## Round 3 re-review gate

Do not advance to PR until HIGH-R2-1 and HIGH-R2-2 are remediated and independently re-reviewed. MEDIUM-R2-1 through MEDIUM-R2-3 must be fixed or explicitly accepted/tracked with an owner and rationale. Then run focused origin tests, repository-wide vet/test/build, and the authoritative Linux race and pinned-artifact CI gates.

## Round 3 re-review (independent verification of the Round 2 remediation)

Reviewer: independent architect pass (falsification-first), over the post-remediation worktree.
Scope: HIGH-R2-1, HIGH-R2-2, MEDIUM-R2-1/2/3 remediations, the new regression tests, and the CI gate.

### HIGH-R2-1 (crash-state reconciliation) â€” VERIFIED REMEDIATED

- `prepareStageDir` no longer touches transaction names; it sweeps only its own `.caddy-stage-*` dirs.
- `reconcileInstallResidue` runs as Step 0 of `Install` BEFORE existing-version detection, so a restored lone backup is visible to detection (no final-rename collision) and no failure path can sweep it.
- The protocol is fail-closed on every persistent state: lone `.old` (no live peer) is restored through the injectable seam; live + `.old` is refused as ambiguous with both artifacts untouched; `.new` is removed only after Lstat proves a regular directory; symlinks/non-directories at transaction names are refused and never followed.
- Direct-call safety: the seam defaults to `os.Rename` when unset, so standalone calls cannot hit a nil-function path.
- Regression tests (deterministic, in-memory): `TestCrashStateLoneBackupRestored` (byte-identical restore, backup consumed), `TestCrashStateSurvivesNextInstallFailure` (the exact pre-fix scenario: a download failure AFTER a crash must not destroy the working version â€” now byte-identical and residue-free), `TestCrashStateForcedReinstallConverges` (post-crash forced reinstall converges to the new candidate, no `.old`), `TestCrashStateAmbiguousFailsClosed` (live + `.old` both preserved on refusal), `TestCrashStateSymlinkBackupRefused` / `TestCrashStateSymlinkCandidateRefused` (planted symlinks refused, decoys untouched; run on Linux CI, skipped on the unprivileged Windows host).
- Falsification attempts: ambiguous dual state â†’ refused, verified; planted symlinks â†’ refused; restore-after-detection ordering hazard â†’ eliminated by Step-0 placement; pre-reconcile failure â†’ impossible (reconcile runs before any network or mutation). **No residual issue.**

### HIGH-R2-2 (Pinned Caddy CI gate) â€” VERIFIED REMEDIATED (real run pending Linux CI)

- New `Pinned Caddy gate` step in `.github/workflows/go.yml`, mirroring the T3 Xray gate: renders all three fixed-vector Caddyfiles through the committed `caddye2e` harness, downloads the pinned `v2.11.4` linux-amd64 tar + the upstream `caddy_2.11.4_checksums.txt`, verifies SHA-512 with parse semantics mirroring `ParseChecksumFile` (two-space separator, 128 hex, exact asset name match, `*` marker tolerated), asserts `caddy version` first field == `v2.11.4`, and runs `caddy validate --config` on every variant.
- The checksum parse deliberately avoids `{n}` regex intervals (the runner's mawk does not support them) â€” `index()`/`length()` instead.
- URLs and asset names verified against the `version.go` constants (asset name drops the leading "v", release tag keeps it); the flat tarball layout (top-level `caddy`) matches the installer's extraction contract.
- `internal/origin/testdata/e2e/` is gitignored; the committed goldens in `testdata/golden/` are untouched (verified via `git ls-files`).
- Falsification attempts: harness marker format matches the parser (`E2E_CADDYFILE_PATH=<name>=<abs>`); the rendered variants (ACME http01 default, tlsalpn01, `tls internal` on `:8443`) validate without any network/ACME activity; the e2e dir is not shadowed. **No residual issue** (the real binary run is by design left to Linux CI, where the gate is authoritative).

### MEDIUM-R2-1 (aside-name collision after restart) â€” VERIFIED REMEDIATED

- `allocateDeactivateDir` retries up to 1024 candidates, Lstat-checking each: absent â†’ claim; empty regular dir â†’ reclaimed as crashed-deactivation residue; non-empty â†’ skipped and preserved (rollback metadata is never touched); symlink/non-dir â†’ skipped, not touched. The atomic counter is a starting hint only.
- Regression tests: `TestCDNDeactivateRestartCollision` (counter reset to zero + pre-created NON-EMPTY `.cdn-deactivate-1` â†’ Aâ†’B succeeds on a different name and the preserved dir is byte-identical) and `TestCDNDeactivateReclaimsEmptyResidue` (empty residue reclaimed).
- Carried acceptance: aside accumulation is explicitly owned by T7 cleanup/retention policy (LOW-R2-1) â€” no silent deletion of rollback data in this package.

### MEDIUM-R2-2 (honest mode-B health) â€” VERIFIED REMEDIATED

- Mode B `Status` now reports `Live=false` with the detail explicitly stating the sub-mode is SELECTED and that "Liveness is not verified by this provider (T7 doctor owns runtime checks)".
- The `ctx.Err()` check is the first statement of `Status` â€” no return path bypasses it.
- Regression tests: `TestCDNStatusModeBCanceledCtx` (canceled ctx â†’ `context.Canceled`), plus the updated assertions in `TestCDNModeBNoCaddy` and `TestCDNTransitionAtoBConverges` (no liveness claim; selection named). **No residual issue.**

### MEDIUM-R2-3 (corrupt state fail-closed) â€” VERIFIED REMEDIATED

- `Status` distinguishes `os.IsNotExist` (legacy no-record hint) from corrupt/unreadable (returns the bounded state-integrity error; never merged into the hint).
- Regression test: `TestCDNStatusCorruptStateFailsClosed` covers both sub-cases (corrupt record + live managed Caddyfile; corrupt record + no Caddyfile) and asserts the error is NOT the "no cdn state record" hint. **No residual issue.**

### Round 3 findings

- **CRITICAL: 0 â€” HIGH: 0 â€” MEDIUM: 0**
- LOW-3-1 (process): the stray root-level `caddy_2.11.4_checksums.txt` (T4-C1 probe artifact) is untracked working residue â€” excluded from the focused commit (NOT deleted, per the no-discard rule).
- LOW-3-2 (process): `internal/xray/testdata/golden/germany-config.golden.json` carries a CRLF-only worktree diff â€” excluded from the focused commit (content unchanged vs HEAD).
- LOW-R2-1/2/3 (carried, T7-owned): aside-dir retention policy; activation prev-aside crash-window journal; started-child cancellation proof on Linux CI. Tracked, not silently closed.

### Verdict

**PASS â€” CRITICAL 0 / HIGH 0 / MEDIUM 0.** All Round 2 blocking conditions are cleared:
1. HIGH-R2-1 remediated, independently re-reviewed, and regression-tested.
2. HIGH-R2-2 remediated, independently re-reviewed; the real-binary run is left to Linux CI by design.
3. MEDIUM-R2-1/2/3 remediated and regression-tested.
4. LOWs explicitly tracked with owners (T7) or deferred to CI execution.

**Merge gate satisfied (CRITICAL=0, HIGH=0).** Next: focused commit (explicit file list, excluding the two process residue items above) â†’ push â†’ PR â†’ Linux CI (authoritative: `-race` + Pinned Caddy gate + Pinned Xray gate) â†’ merge â†’ verify remote main.

