# Phase 2 Multi-Carrier — Final Report — 2026-10-14

Closing report for the Phase 2 multi-carrier audit deliverables. Branch
`audit/multi-carrier-phase2`, HEAD `285e26e` (`feat/multi-carrier-phase2`).
All work is **in the working tree, uncommitted** — nothing was committed,
pushed, or merged; the pre-existing uncommitted changes in `.gitignore` and
`plans/observability-presets-cli-geofiles-plan.md` were preserved.

Companions:
[`phase2-audit-2026-10-14.md`](./phase2-audit-2026-10-14.md),
[`phase2-defect-register-2026-10-14.md`](./phase2-defect-register-2026-10-14.md),
[`phase2-deployment-rollback-2026-10-14.md`](./phase2-deployment-rollback-2026-10-14.md).

---

## 1. Files changed

Captured from `git diff --stat` / `git status` on the audit branch (toolchain
`go1.27.0 windows/amd64`). **Modified (25 tracked):**

| File | ± | Role in the fix set |
|---|---|---|
| `pkg/node/node.go` | +408 | `handleRebind`/`handleStreamReset`/`onCarrierLost` (survivor loop) / `applyTCPKeepAlive` / `bootstrapUpStream` / `StartSessionAndWait` / `bootstrapAckStatus` |
| `pkg/session/session.go` | +192 | `bootstrapC`, `ResolveBootstrap`, `WaitBootstrap`, `clientConnGate`, `AwaitClientConn`, `ClientConnAdopted`, `BootstrapEndedWithoutResult` |
| `internal/dashboard/static/app.js` | +399 | UI modernization (views, cards, ARIA, diagnostics) |
| `internal/dashboard/static/style.css` | +98 | UI styling for new sections |
| `pkg/mux/frame.go` | +108 | `FrameReset` (0x08), `FrameBootstrapAck` (0x09) + payloads |
| `pkg/node/metrics.go` | +63 | `stream_resets_received`, `bootstrap_acks_received`, relay/close-reason counters |
| `internal/config/config.go` | +88 | `SPLIT_TCP_KEEPALIVE_MS`, loopback `DefaultDownListen` |
| `cmd/iran-splitter/main.go` | +68 | `handleSOCKS5Conn` accurate status reply; `TCPKeepAliveMs` wiring |
| `pkg/mux/carrier.go` | +55 | `OnStreamReset` / `OnStreamBootstrapAck` routing in `Dispatch` |
| `pkg/node/relays.go` | +52 | bootstrap-gate client-disconnect aborts; down-relay `AwaitClientConn` |
| `internal/backoff/backoff.go` | +36 | `NewBounded` threshold-semantics doc |
| `internal/config/config_test.go` | +32 | `TestDefaultDownListenIsLoopback` |
| `internal/backoff/backoff_test.go` | +59 | threshold-semantics + 14 total backoff tests |
| `.github/workflows/go.yml` | ±52 | CI one-click installer + branch trigger |
| `integration/twoproc_test.go` | ±46 | carrier-ID markers; S10 `0x01` contract |
| `docs/tunneldash.md` | +128 | UI doc update |
| `cmd/germany-splitter/main.go` | ±20 | loopback down-listener warning; `TCPKeepAliveMs` |
| `internal/dashboard/static_assets_test.go` | ±25 | `TestNoDuplicateDataView` + invariants |
| `internal/dashboard/static/index.html` | ±40 | view attributes, skip-link, sections |
| `docs/socks5-usage.md` | +36 | status-byte semantics (this deliverable) |
| `docs/carrier-reconnect-backoff.md` | ±8 | threshold semantics |
| `README.md` | +9 | `SPLIT_DOWN_LISTEN` loopback default; `SPLIT_TCP_KEEPALIVE_MS`/`SPLIT_RECONNECT_*` rows (this deliverable) |
| `install-oneclick.sh` | ±4 | loopback default |
| `install.sh` | ±2 | loopback default prompt |
| `.gitignore` | +4 | pre-existing uncommitted change (preserved) |

**Untracked new test files (8):** `pkg/node/issue20_test.go`,
`pkg/node/issue20_e2e_test.go`, `pkg/node/issue21_classifier_test.go`,
`pkg/node/issue21_e2e_test.go`, `pkg/node/keepalive_test.go`,
`pkg/node/multicarrier_edge_test.go`, `pkg/mux/frame_reset_test.go`,
`cmd/iran-splitter/socks_handle_test.go`, plus `internal/dashboard/ui_test.go`.
**Untracked new docs (this deliverable set):** `docs/protocol-frames.md` and
the four `docs/reviews/phase2-*.md` files.
**Untracked pre-existing (preserved):** `plans/observability-presets-cli-geofiles-plan.md`.

---

## 2. Bugs fixed (by severity)

| Sev | Issue | Fix | Regression |
|---|---|---|---|
| **P1** | #20 stranded session / refused rebind | `FrameReset` (0x08) + idempotent `handleStreamReset` (generation guard) + `onCarrierLost` survivor fallback loop + exact-once close | `issue20_test.go`, `issue20_e2e_test.go`, `frame_reset_test.go`, `multicarrier_edge_test.go` |
| **P1** | #21 false SOCKS5 `0x00` | `FrameBootstrapAck` (0x09) + `session.bootstrapC`/`WaitBootstrap`/`StartSessionAndWait` + pure `bootstrapAckStatus(err)` classifier + `clientConnGate` ordering | `issue21_classifier_test.go`, `issue21_e2e_test.go`, `socks_handle_test.go` |
| **P2** | #19 no OS TCP keepalive | `SPLIT_TCP_KEEPALIVE_MS` (default 30 s, 0 disables) → `node.Config.TCPKeepAliveMs` → `applyTCPKeepAlive` | `keepalive_test.go` (7) |
| **P2** | #10/backoff imprecise `window` semantics | documented as a pre-attempt threshold (not a hard cap) + tests | `backoff_test.go` (14 pass) |
| **P2** | Section 7 down-listener all-interfaces | `DefaultDownListen` `:9002` → `127.0.0.1:9002` + non-loopback journal warning | `config_test.go` `TestDefaultDownListenIsLoopback` |
| **P2** | two-process L4 gate blocked | corrected stale marker strings; S10 → `0x01` for `BootstrapEndedWithoutResult` | `integration/twoproc_test.go` |
| **P3** | #12 CI gap for one-click installer | `.github/workflows/go.yml` `bash -n` + harness execution + branch trigger | in-tree `bash -n` |
| **P3** | dashboard UI defect + modernization | fixed duplicate/missing `data-view`; tunnel-state banner, stale-telemetry badge, `unmeasured` carrier cards, ARIA/skip-link/focus-visible, copy-diagnostics, distinct 401/403/503 | `ui_test.go` (10), `static_assets_test.go` (5) |

**Rejected hypotheses (non-defects):** PR #30 "missing fix" (already
integrated — `fdd7cbc` is an ancestor), metrics-listener exposure (always
loopback, default off), routing fail-open (verified fail-closed), dashboard
auth/CSRF/TLS/CSP weakening (verified intact). **Deferred non-defects:**
bounded-recovery timing (Section 6, correct as designed), credit flow
control (Section 8, inert unless enabled, SUBTASK 25 storm fix preserved),
per-stream carrier pinning (Section 9 — **not** bandwidth bonding; each stream
is pinned to a single carrier for failover/priority, bytes never span
carriers).

---

## 3. Remaining risks

1. **Real-transport proof outstanding** — `FrameReset` / `FrameBootstrapAck`
   and the accurate SOCKS5 status bytes are unit/two-process verified but not
   yet proven over the real CDN-WebSocket + VLESS+Reality transport. This is
   the single BLOCKED gate (§5 below).
2. **Down-listener default change** — operators relying on the `0.0.0.0:9002`
   / `:9002` default must set `SPLIT_DOWN_LISTEN` explicitly; otherwise the
   bind silently narrows to loopback.
3. **New metric counters** have no production baseline; confirm
   `stream_resets_received` / `bootstrap_acks_received` move on induced
   flaps post-rollout.
4. **`SPLIT_TCP_KEEPALIVE_MS`** changes socket-reaping timing (30 s vs ~2 h
   OS default); set `=0` to restore pre-fix behavior.
5. **`go test -race` and the Linux two-process gate** are CI-only (cannot run
   on the Windows dev host); their green status is asserted by the workflow,
   not observed here.

---

## 4. UI improvements

The dashboard (loopback-only, read-only, fixture/loopback-sourced — it never
touches production) received: the duplicate-`network`/missing-`outbounds`
view fix; a tunnel-state banner with color-independent icons; a
stale-telemetry badge; carrier detail cards that render `unmeasured` for
unexported fields (never a fabricated zero); ARIA `role`/`aria-live`, a
skip-link, and visible `:focus-visible` outlines; a copy-diagnostics button
(redacted JSON); and distinct 401/403/503 error states. All security
invariants (no external URLs, relative assets, CSP, no inline
styles/scripts, loopback bind, CSRF, TLS headers, Basic auth) are preserved
and re-asserted by `ui_test.go` + `static_assets_test.go`.

---

## 5. Exact commands executed (and results)

All on `go1.27.0 windows/amd64` in the repo root.

```
$ go version
go version go1.27.0 windows/amd64

$ git merge-base --is-ancestor fdd7cbc HEAD && echo PR30_PARENT_IS_ANCESTOR
PR30_PARENT_IS_ANCESTOR            # PR #30 up-read fix already integrated

$ go build ./... && go test ./...
ok  cmd/{germany,iran}-splitter, cmd/splitterctl, integration
ok  integration/socks5, internal/{archtest,backoff,config,dashboard,
    controlagent,deploy,firewall,origin,pairing,systemd,testutil,xray}
ok  pkg/{mux,node,routing,session}            # all green

$ go test ./pkg/node/ -run 'TestIssue20|TestIssue21|TestKeepAlive|TestMultiDown' -v
# TestFrameResetTerminatesStrandedSession PASS,
# TestCarrierLossFailoverToSurvivorDown PASS, TestFrameResetGenerationGuard PASS,
# TestIssue20_StrandedSessionTwoNodeReset PASS (0.41s),
# TestBootstrapAckStatusClassification PASS, TestStartSessionAndWait* PASS,
# TestKeepAlive*/TestApplyKeepAlive* PASS
# (all PASS)

$ go test ./pkg/mux/ -run 'TestEncodeParseReset|TestBootstrapAck|TestResetFrame|TestMalformed' -v
# PASS

$ go test ./internal/backoff/ -v
# 14/14 PASS (incl. TestWindowThresholdSemanticsExactAndOvershoot)

$ go test ./internal/config/ -run 'TestDefaultDownListenIsLoopback' -v
# PASS

$ go test ./cmd/iran-splitter/ -run 'TestHandleSOCKS5' -v
# PASS (SuccessPayload / TargetRefused / DNSFailure / Timeout)

$ go test ./internal/dashboard/ -run 'TestIndex|TestStatic|TestNoDuplicate|TestCSP' -v
# PASS (12 UI + 5 asset tests)
```

In-tree installer syntax check: `bash -n install-oneclick.sh` and
`bash -n install-oneclick.test.sh` → both PASS (the full Linux CI job runs
these plus the harness and `go test -race`).

---

## 6. Explicit release-gate statement

> **PRODUCTION RELEASE IS BLOCKED.**
>
> The Phase 2 multi-carrier fixes are correct and fully
> unit/integration-verified in-tree on `go1.27.0 windows/amd64`, and the build
> is safe to **stage-deploy**. It **must not be released to production** until
> the human operator runs the full 20-scenario matrix from
> [`integration/RUNBOOK.md`](../../integration/RUNBOOK.md) on the staging
> topology — **twice, once with `go test -race` builds** — and records the
> results in `IMPLEMENTATION_STATUS.md`.
>
> Before release the operator MUST additionally confirm over the real
> transport: (a) SOCKS `0x00` is observed **only** after a real target
> accept, and failed targets return the accurate non-zero code; (b)
> `stream_resets_received` ticks on an induced refused rebind and the stranded
> session is terminated (not retried indefinitely); (c)
> `bootstrap_acks_received` ticks on each bootstrap; (d) the down-listener
> binds `127.0.0.1:9002` (or the operator's explicit `SPLIT_DOWN_LISTEN`);
> (e) `SPLIT_TCP_KEEPALIVE_MS` (30 s) is visible via `ss`.
>
> Any scenario failure is fixed (new commit + **full** matrix re-run) or filed
> as its own issue with the repro. **The gate does not close on a failing
> scenario.**

Full human-operator rollout and rollback steps: see
[`phase2-deployment-rollback-2026-10-14.md`](./phase2-deployment-rollback-2026-10-14.md).
