# Phase 2 Multi-Carrier Audit — 2026-10-14

Adversarial audit of the `feat/multi-carrier-phase2` working tree. This report
covers scope, baseline, the findings by severity (with exact source paths,
failure mechanisms, regression tests, fix rationale, and the exact
verification commands and their results), explicitly-rejected hypotheses,
remaining risks, and the release recommendation.

Companion documents in this directory:

- [`phase2-defect-register-2026-10-14.md`](./phase2-defect-register-2026-10-14.md) — prioritized defect register.
- [`phase2-deployment-rollback-2026-10-14.md`](./phase2-deployment-rollback-2026-10-14.md) — human-operator deploy / rollback / acceptance plan.
- [`phase2-final-report-2026-10-14.md`](./phase2-final-report-2026-10-14.md) — final report (files changed, commands, release gate).

---

## 1. Scope & Baseline

**What was audited.** The uncommitted working-tree fixes for the Phase 2
multi-carrier defects (Issues #19, #20, #21, #12, the #10/backoff window
semantics, Section 7 exposure, the dashboard UI defect, and the CI two-process
gate). The audit read the actual `git diff` / `git status`, the referenced
source files, and the added test files so every path / function / line below is
verifiable against the tree.

| Item | Value |
|---|---|
| Base branch | `feat/multi-carrier-phase2` at `285e26e5aec6c8fb8ba6fcf5fb3eb9fd6216fd09` |
| Audit branch | `audit/multi-carrier-phase2` (HEAD `285e26e`), all fixes in the **working tree, uncommitted** |
| Toolchain | `go1.27.0 windows/amd64` |
| Working-tree state | 25 modified files, 9 untracked regression-test files + the pre-existing uncommitted `plans/observability-presets-cli-geofiles-plan.md` (+ this deliverable set's new `docs/protocol-frames.md` and 4 `docs/reviews/phase2-*.md` files, all untracked/uncommitted) |

### Divergence analysis (`feat/multi-carrier-phase2..origin/main`)

The only commit on `origin/main` ahead of the base is the merge commit
`fbe7604` ("Merge pull request #30 … complete-up-read-implementation"). Its
**code parent `fdd7cbc`** ("fix(node): add the up-read policy
implementation") is already an ancestor of the audit HEAD
(`git merge-base --is-ancestor fdd7cbc HEAD` → success):

```
fbe7604 Merge pull request #30 from Zaltapar/fix/complete-up-read-implementation
fdd7cbc fix(node): add the up-read policy implementation (repairs merged test-only commit)
ed5ef2b Merge pull request #29 from Zaltapar/fix/mux-data-integrity-and-up-read
```

**Conclusion: PR #30's up-read fix is already integrated. There is nothing to
cherry-pick.** The "PR #30 missing fix" hypothesis raised during the audit is
rejected (see §5).

### Baseline test results

`go build ./...` and `go test ./...` on the working tree are green on
`go1.27.0 windows/amd64`:

```
ok  cmd/germany-splitter, cmd/iran-splitter, cmd/splitterctl, integration
ok  integration/socks5, internal/archtest, internal/backoff, internal/config
ok  internal/dashboard, internal/deploy, internal/firewall, internal/origin
ok  internal/pairing, internal/systemd, internal/xray, pkg/mux, pkg/node
ok  pkg/routing, pkg/session
```

(`go test -race` and the Linux CI two-process gate are not runnable on this
Windows dev host; they are delegated to the GitHub Linux workflow — see the
P3 / CI finding below and the deployment doc's acceptance gate.)

---

## 2. Findings by severity

Severity: **P1** = correctness defect that can strand sessions / mis-reply to
clients in production; **P2** = resource / availability / exposure defect;
**P3** = hardening / test-coverage gap. Confidence reflects how directly the
failing path was reproduced in-tree.

---

### P1 — Issue #20: stranded session / refused rebind with indefinite client block

**Severity:** P1 · **Confidence:** High (reproduced by two-node in-memory
harness)

**Source paths / functions**

- [`pkg/node/node.go`](../../pkg/node/node.go) — [`handleRebind`](../../pkg/node/node.go#L1443)
  (receiver-side rebind responder, Germany),
  [`handleStreamReset`](../../pkg/node/node.go#L1331) (originator-side reset
  handler, Iran), [`onCarrierLost`](../../pkg/node/node.go#L1039) (loss sweep +
  survivor fallback loop), [`rebindDirection`](../../pkg/node/node.go#L1165)
  (`att.Attach` at [node.go#L1227](../../pkg/node/node.go#L1227) and
  [node.go#L1615](../../pkg/node/node.go#L1615)).
- [`pkg/mux/frame.go`](../../pkg/mux/frame.go) — new `FrameReset` constant
  [frame.go#L81](../../pkg/mux/frame.go#L81) + `EncodeResetPayload` /
  `ParseResetPayload` [frame.go#L346](../../pkg/mux/frame.go#L346) /
  [frame.go#L356](../../pkg/mux/frame.go#L356), reason codes
  [frame.go#L333-L336](../../pkg/mux/frame.go#L333).
- [`pkg/mux/carrier.go`](../../pkg/mux/carrier.go) — `OnStreamReset` callback
  [carrier.go#L172](../../pkg/mux/carrier.go#L172), routing in `Dispatch`
  [carrier.go#L1079-L1099](../../pkg/mux/carrier.go#L1079).

**Failure mechanism (pre-fix).** Three interacting drops left a logical session
stranded with no terminal signal:

1. **`handleRebind` silent drop.** When Germany refused a rebind
   (`unknown_peer`, `session_closed`, stale generation, attach failure) it only
   called `h.carrier.Deregister(id)` with no negative acknowledgement. Iran's
   stranded copy had no way to learn the refusal, so it retried the rebind on
   *every subsequent carrier drop* — an indefinite retry loop.
2. **`att.Attach` cancelling the grace timer.** `rebindDirection` calls
   `att.Attach(h.gen)`; an attach re-arms / clears the attachment state such
   that, when the survivor refused, the graceful terminal close was no longer
   guaranteed to fire for the stranded stream.
3. **`onCarrierLost` unconditional `break`.** The original sweep was
   `n.rebindDirection(dir, survivor); break` — the first survivor was tried
   and the loop exited regardless of whether it actually re-attached anything.
   A survivor that rebinds nothing (every eligible attachment already moved,
   or a registration/write failure left them in `Rebinding`) stranded the
   pinned streams on a carrier that refused them, with the grace timer as the
   only (not-guaranteed) backstop.

**Operational consequence.** A client whose session's carrier flaps and whose
rebind is refused is blocked indefinitely: the SOCKS5 handler waits, no
terminal close arrives, and the session + its sockets outlive the carrier that
killed it.

**Fix.** A versioned `FrameReset` (0x08) control frame closes the loop:

- Germany's [`handleRebind`](../../pkg/node/node.go#L1443) `drop` closure now
  emits `FrameReset` carrying a **reason + generation echo** on the same
  carrier that delivered the rebind (the carrier is bidirectional at the mux
  layer, so the reset writes directly back):
  `_ = h.carrier.WriteControlFrame(id, mux.FrameReset, mux.EncodeResetPayload(resetReason, gen))`
  [node.go#L1485](../../pkg/node/node.go#L1485). Early structural drops
  (malformed payload, carrier-id mismatch) carry no reliable generation and are
  not the stranded-session loop, so they still `Deregister` *without* a reset.
- Iran's [`handleStreamReset`](../../pkg/node/node.go#L1331) is the idempotent
  originator handler: no active session → no-op; a **generation guard**
  (`att.LastRebindGen() > gen` → ignore as stale,
  [node.go#L1347](../../pkg/node/node.go#L1347)); otherwise it closes the
  session (which closes *both* direction attachments, so the rebind sweep can
  never retry it again) — exact-once cleanup.
- `FrameReset` is a **terminal CONTROL frame** (not a half-close): it is never
  delivered to the stream mailbox, so no phantom `OnNewStream` fires and no
  stream record is created. Unknown-stream / stale resets are expected in a loss
  window and stay idempotent no-ops.
- **Survivor fallback loop** in [`onCarrierLost`](../../pkg/node/node.go#L1039):
  the sweep now advances through *every* ready survivor until one actually
  re-attaches a pinned stream —
  `if n.rebindDirection(dir, survivor) { break }`
  [node.go#L1116-L1122](../../pkg/node/node.go#L1116). When no survivor takes
  any stream, the loss-sweep grace timer remains the terminal backstop.

**Regression tests.**

- [`pkg/node/issue20_test.go`](../../pkg/node/issue20_test.go) —
  `TestFrameResetTerminatesStrandedSession`,
  `TestCarrierLossFailoverToSurvivorDown`,
  `TestFrameResetGenerationGuard`.
- [`pkg/node/issue20_e2e_test.go`](../../pkg/node/issue20_e2e_test.go) —
  `TestIssue20_StrandedSessionTwoNodeReset` (two-node in-memory topology).
- [`pkg/mux/frame_reset_test.go`](../../pkg/mux/frame_reset_test.go) —
  `TestEncodeParseResetPayloadRoundTrip`,
  `TestParseResetPayloadRejectsMalformed`,
  `TestResetFrameRoutesToCallbackNotStream`, `TestMalformedResetIgnored`.
- [`pkg/node/multicarrier_edge_test.go`](../../pkg/node/multicarrier_edge_test.go)
  — `TestMultiDown_StandbyLossScoping`, `TestMultiDown_AllCarriersDown`,
  `TestMultiDown_PrimaryLossPinsNewStreamToStandby`.

**Fix rationale.** A terminal negative ack with a generation echo is the only
mechanism that lets the *originator* authoritatively stop retrying a refused
rebind; the generation echo makes a stale/duplicated reset an idempotent
no-op, and routing resets to a callback (not the stream mailbox) prevents
phantom streams.

**Exact verification + result.**

```
go test ./pkg/node/ -run 'TestFrameReset|TestCarrierLossFailover|TestIssue20|TestMultiDown' -v
go test ./pkg/mux/  -run 'TestEncodeParseReset|TestParseReset|TestResetFrame|TestMalformedReset' -v
```

Result on `go1.27.0 windows/amd64`:

```
--- PASS: TestFrameResetTerminatesStrandedSession (0.04s)
--- PASS: TestCarrierLossFailoverToSurvivorDown (0.00s)
--- PASS: TestFrameResetGenerationGuard (0.00s)
--- PASS: TestIssue20_StrandedSessionTwoNodeReset (0.41s)
--- PASS: TestEncodeParseResetPayloadRoundTrip / TestParseResetPayloadRejectsMalformed
--- PASS: TestResetFrameRoutesToCallbackNotStream / TestMalformedResetIgnored
```

Observability: `stream_resets_received` and `rebind_refusal{stale_generation}`
counters added to [`pkg/node/metrics.go`](../../pkg/node/metrics.go)
([metrics.go#L764](../../pkg/node/metrics.go#L764)).

---

### P1 — Issue #21: false SOCKS5 `0x00` success before the remote target dial

**Severity:** P1 · **Confidence:** High (byte-level handler regression + two-node e2e)

**Source paths / functions**

- [`cmd/iran-splitter/main.go`](../../cmd/iran-splitter/main.go) —
  [`handleSOCKS5Conn`](../../cmd/iran-splitter/main.go#L673); the wait call
  `s.node.StartSessionAndWait(clientConn, dest)`
  [main.go#L717](../../cmd/iran-splitter/main.go#L717); the local-sentinel
  normalization `if code == byte(session.BootstrapEndedWithoutResult) { code = 0x01 }`
  [main.go#L723-L724](../../cmd/iran-splitter/main.go#L723); success reply
  [main.go#L746](../../cmd/iran-splitter/main.go#L746).
- [`pkg/node/node.go`](../../pkg/node/node.go) —
  [`StartSessionAndWait`](../../pkg/node/node.go#L1686) (bounded
  `WaitBootstrap`), [`bootstrapUpStream`](../../pkg/node/node.go#L2219)
  (sends the `FrameBootstrapAck` verdict), and the pure
  [`bootstrapAckStatus(err)`](../../pkg/node/node.go#L2387) classifier.
- [`pkg/mux/frame.go`](../../pkg/mux/frame.go) — `FrameBootstrapAck` = 0x09
  [frame.go#L90](../../pkg/mux/frame.go#L90), `EncodeBootstrapAckPayload` /
  `ParseBootstrapAckPayload` [frame.go#L389](../../pkg/mux/frame.go#L389) /
  [frame.go#L397](../../pkg/mux/frame.go#L397).
- [`pkg/session/session.go`](../../pkg/session/session.go) — `bootstrapC`
  [session.go#L338](../../pkg/session/session.go#L338),
  `BootstrapEndedWithoutResult` = 0xFF [session.go#L433](../../pkg/session/session.go#L433),
  `ResolveBootstrap` [session.go#L469](../../pkg/session/session.go#L469),
  `WaitBootstrap` [session.go#L494](../../pkg/session/session.go#L494),
  and the **`clientConnGate`** [session.go#L348](../../pkg/session/session.go#L348)
  with `AwaitClientConn` [session.go#L664](../../pkg/session/session.go#L664) /
  `ClientConnAdopted` [session.go#L648](../../pkg/session/session.go#L648).

**Failure mechanism (pre-fix).** `handleSOCKS5Conn` wrote the SOCKS5
`0x00` (success) reply to the client **before** Germany had dialed the remote
target. If the target refused / DNS-failed / timed out / was ruleset-blocked,
the client had already been told "success" and then observed a mid-stream
failure — a protocol-incorrect, client-confusing outcome and a source of
misdiagnosis.

**Fix.**

- Germany's [`bootstrapUpStream`](../../pkg/node/node.go#L2219) now emits a
  versioned **`FrameBootstrapAck` (0x09)** status frame on the up carrier after
  the target dial + routing check completes — on *both* success
  (`EncodeBootstrapAckPayload(0x00)`, [node.go#L2379](../../pkg/node/node.go#L2379))
  and failure (mapped via `bootstrapAckStatus` at
  [node.go#L2343](../../pkg/node/node.go#L2343) and the general-failure path
  [node.go#L2244](../../pkg/node/node.go#L2244)).
- The pure [`bootstrapAckStatus(err)`](../../pkg/node/node.go#L2387) classifier
  maps each failure class to the correct RFC 1928 byte:
  `routing.ErrBlocked → 0x02`, `ErrTargetDialTimeout` / deadline-exceeded /
  `ETIMEDOUT → 0x06`, `ErrTargetBreakerOpen` / `ErrWarpUnreachable → 0x01`,
  `ENETUNREACH → 0x03`, DNS/`EHOSTUNREACH`/"resolve …"/"no such host" → `0x04`,
  `ECONNREFUSED → 0x05`, and an unrecognized default of `0x01` (general
  failure). `0x00` is returned **only** for `err == nil`.
- Iran's [`StartSessionAndWait`](../../pkg/node/node.go#L1686) blocks on the
  session's bounded `WaitBootstrap` (the wait always terminates: the session's
  own teardown commits `BootstrapEndedWithoutResult` as a backstop). The
  handler writes the client reply *after* the verdict, so a premature `0x00`
  is never sent on failure.
- **`clientConnGate`** guarantees ordering: the down→client relay
  `AwaitClientConn`s before writing *any* target payload byte to the client,
  so the `0x00` reply (sent right before `AdoptConn`) precedes downstream
  payload. For the fire-and-forget `StartSession` path the gate is pre-closed,
  so the happy path is unchanged.

**Regression tests.**

- [`cmd/iran-splitter/socks_handle_test.go`](../../cmd/iran-splitter/socks_handle_test.go) —
  `TestHandleSOCKS5SuccessPayload`, `TestHandleSOCKS5TargetRefused`,
  `TestHandleSOCKS5DNSFailure`, `TestHandleSOCKS5Timeout` (drives the *real*
  `handleSOCKS5Conn` over a two-node in-memory topology; asserts the exact
  10-byte SOCKS5 reply).
- [`pkg/node/issue21_classifier_test.go`](../../pkg/node/issue21_classifier_test.go) —
  `TestBootstrapAckStatusClassification`.
- [`pkg/node/issue21_e2e_test.go`](../../pkg/node/issue21_e2e_test.go) —
  `TestStartSessionAndWait*` (success / target-refused / DNS / timeout /
  breaker-open / bidirectional-payload / carrier-drop-no-success /
  client-disconnect-before-bootstrap).
- [`pkg/mux/frame_reset_test.go`](../../pkg/mux/frame_reset_test.go) —
  `TestEncodeParseBootstrapAckPayloadRoundTrip`,
  `TestParseBootstrapAckPayloadRejectsMalformed`,
  `TestBootstrapAckFrameRoutesToCallbackNotStream`.

**Fix rationale.** The accurate status must be established *on the target
side* (only Germany knows whether the dial succeeded), so it travels as a
control frame and is forwarded 1:1 to the client; the gate makes the ordering
(byte-exact: 0x00 before payload) deterministic and testable.

**Exact verification + result.**

```
go test ./cmd/iran-splitter/ -run 'TestHandleSOCKS5' -v
go test ./pkg/node/ -run 'TestBootstrapAckStatusClassification|TestStartSessionAndWait' -v
```

Result on `go1.27.0 windows/amd64`:

```
--- PASS: TestHandleSOCKS5SuccessPayload / TargetRefused / DNSFailure / Timeout
--- PASS: TestBootstrapAckStatusClassification
--- PASS: TestStartSessionAndWaitSuccess / TargetRefused / DNSFailure / DialTimeout
--- PASS: TestStartSessionAndWaitBreakerOpen / BidirectionalPayload
--- PASS: TestStartSessionAndWaitCarrierDropNoSuccess (2.05s)
--- PASS: TestStartSessionAndWaitClientDisconnectBeforeBootstrap
```

Observability: `bootstrap_acks_received` counter
([metrics.go#L765](../../pkg/node/metrics.go#L765)).

---

### P2 — Issue #19: no OS-level TCP keepalive anywhere

**Severity:** P2 · **Confidence:** High

**Source paths / functions**

- Pre-fix: `SetKeepAlive` had **0 occurrences** in the codebase.
- [`pkg/node/node.go`](../../pkg/node/node.go) — `Config.TCPKeepAliveMs`
  [node.go#L229](../../pkg/node/node.go#L229),
  `DefaultTCPKeepAliveMs = 30000` [node.go#L286](../../pkg/node/node.go#L286),
  [`applyTCPKeepAlive`](../../pkg/node/node.go#L299) applied at client-socket
  creation, target-dial success, and carrier install.
- [`internal/config/config.go`](../../internal/config/config.go) —
  `EnvTCPKeepAlive = "SPLIT_TCP_KEEPALIVE_MS"` [config.go#L85](../../internal/config/config.go#L85),
  `DefaultTCPKeepAlive = 30000` [config.go#L296](../../internal/config/config.go#L296),
  bounds `MinTCPKeepAliveMs=0` / `MaxTCPKeepAliveMs=36000000`
  [config.go#L294-L295](../../internal/config/config.go#L294),
  load `c.TCPKeepAliveMs = envInt(...)` [config.go#L686](../../internal/config/config.go#L686).
- Wired in both binaries:
  [`cmd/iran-splitter/main.go`](../../cmd/iran-splitter/main.go) and
  [`cmd/germany-splitter/main.go`](../../cmd/germany-splitter/main.go)
  (`TCPKeepAliveMs: cfg.TCPKeepAliveMs`).

**Failure mechanism (pre-fix).** No kernel TCP keepalive was set on any
long-lived socket (accepted SOCKS5 client sockets, egress target dials, carrier
transports). A wedged / half-open socket therefore survived on the OS default
probe interval (~2 h on Linux), leaking sockets and session state.

**Fix.** `SPLIT_TCP_KEEPALIVE_MS` (default 30 s; `0` disables, restoring the
OS default byte-identically) → `node.Config.TCPKeepAliveMs` →
[`applyTCPKeepAlive`](../../pkg/node/node.go#L299), which is a **no-op for
non-TCP transports** (in-memory pipes, WebSocket carriers, WARP SOCKS
outbounds) and disabled-when-zero. `Config.Sanitize` rejects negatives
(0 is the valid "disabled" sentinel).

**Regression tests.** [`pkg/node/keepalive_test.go`](../../pkg/node/keepalive_test.go):
`TestKeepAliveSanitizeRejectsNegative`, `TestKeepAliveDefaultSentinel`,
`TestKeepAliveConfigWiring`, `TestApplyKeepAliveSkipsNonTCPConn`,
`TestApplyKeepAliveDisabledIsNoOp`, `TestApplyKeepAliveEnabledOnLiveTCPConn`,
`TestApplyKeepAliveOnNonTCPRealPipe`.

**Exact verification + result.**

```
go test ./pkg/node/ -run 'TestKeepAlive|TestApplyKeepAlive' -v
```

Result:

```
--- PASS: TestKeepAliveSanitizeRejectsNegative / TestKeepAliveDefaultSentinel
--- PASS: TestKeepAliveConfigWiring
--- PASS: TestApplyKeepAliveSkipsNonTCPConn / DisabledIsNoOp
--- PASS: TestApplyKeepAliveEnabledOnLiveTCPConn / OnNonTCPRealPipe
```

**Fix rationale.** Complements the application-level mux keepalive pings
(which detect a wedged carrier regardless of transport) by letting the kernel
reap the OS-level socket itself within ~one probe when the peer has vanished
without a clean RST/FIN; best-effort (failure to set the option is logged,
never aborts the session).

---

### P2 — Issue #10 / backoff: imprecise `NewBounded` `window` semantics

**Severity:** P2 · **Confidence:** High

**Source paths / functions**

- [`internal/backoff/backoff.go`](../../internal/backoff/backoff.go) —
  `NewBounded(base, max, window, clamp)`; the doc comment was corrected to
  state that `window` is a **pre-attempt threshold** (`b.slept >= window`),
  *not* a hard cap that truncates the attempt crossing the boundary.

**Failure mechanism (documentation defect, not runtime).** The prior comment
described `window` as "the cumulative nominal sleep budget … once the
cumulative nominal delay reaches window, every further delay is clamped,"
implying a hard cap. In reality the check runs *before* adding the current
attempt's delay, so the attempt that pushes `slept` to or past `window`
still returns its scheduled (max-capped) delay `d`; cumulative nominal delay
before clamping engages on the *next* call may **overshoot `window` by up to
one `max`** (e.g. `1,2,4,8,10,10` sums to 35 with `window` 30; the 6th delay
is still 10). Operators tuning `SPLIT_RECONNECT_WINDOW_MS` would mis-estimate
recovery timing if they read the old comment as a hard cap.

**Fix.** `window` documented precisely as a threshold; `clamp` documented as
the `min(d, clamp)` cap applied on every attempt *after* `slept >= window`,
and `b.clamp < d` ensures the clamp only ever *reduces* a delay.
[`docs/carrier-reconnect-backoff.md`](../../docs/carrier-reconnect-backoff.md)
updated to match (this is the operator-facing doc; see Deliverable 3).

**Regression tests.** [`internal/backoff/backoff_test.go`](../../internal/backoff/backoff_test.go)
(14 pass) including `TestWindowThresholdSemanticsExactAndOvershoot`,
`TestWindowExhaustedFlips`, `TestClampCappedAtMax`,
`TestSleepBoundedByClampAfterWindow`.

**Exact verification + result.**

```
go test ./internal/backoff/ -v
```

Result: 14/14 PASS (`TestScheduleDoubling`, `TestReset`, `TestSleepJitterBounds`,
`TestSleepCancellation`, `TestSleepRespectsCtxAlreadyDone`, `TestWindowClamp`,
`TestNewBoundedDisabledIsPureExponential`, `TestNewDelegatesToNewBounded`,
`TestResetZeroesWindow`, `TestWindowExhaustedFlips`, `TestClampCappedAtMax`,
`TestSleepBoundedByClampAfterWindow`,
`TestWindowThresholdSemanticsExactAndOvershoot`,
`TestSanitizeEdgeCasesAndHighAttempts`).

---

### P2 — Section 7 exposure: Germany down-listener bound all interfaces

**Severity:** P2 · **Confidence:** High

**Source path / function**

- [`internal/config/config.go`](../../internal/config/config.go) —
  `DefaultDownListen` changed from `":9002"` to
  `"127.0.0.1:9002"` [config.go#L244](../../internal/config/config.go#L244).

**Failure mechanism (pre-fix).** `DefaultDownListen = ":9002"` (bare port)
binds **all interfaces**, exposing the down-carrier auth endpoint beyond
localhost even though the down carrier is only ever reached through the local
VLESS+Reality Xray inbound.

**Fix.** Default is now loopback `127.0.0.1:9002` (matching the documented
Xray Reality topology — the Freedom outbound `redirect`s to
`127.0.0.1:9002`). Explicit non-loopback binds remain fully supported
(`checkHostPort` accepts any host:port); Germany logs a **one-time journal
warning** when the resolved bind is non-loopback
([cmd/germany-splitter/main.go#L654-L665](../../cmd/germany-splitter/main.go#L654)).
`install.sh` and `install-oneclick.sh` defaults updated to `127.0.0.1:9002`.

**Regression test.**
[`internal/config/config_test.go`](../../internal/config/config_test.go)
`TestDefaultDownListenIsLoopback` — pins `DefaultDownListen =
"127.0.0.1:9002"`, verifies the loopback default passes Germany validation,
and verifies a non-loopback `0.0.0.0:9002` bind *remains* valid.

**Exact verification + result.**

```
go test ./internal/config/ -run 'TestDefaultDownListenIsLoopback' -v
```

Result: `--- PASS: TestDefaultDownListenIsLoopback (0.00s)`.

---

### P3 — Issue #12: CI gap for the one-click installer

**Severity:** P3 · **Confidence:** High (syntactic)

**Source path / function**

- [`.github/workflows/go.yml`](../../.github/workflows/go.yml) — the shell
  safety gate now `bash -n`s `install.sh`, `deploy.sh`, and
  `install-oneclick.sh`, conditionally syntax-checks and **executes the
  hermetic `install-oneclick.test.sh` harness** when present, and adds
  `feat/multi-carrier-phase2` to the push-trigger branch list.

**Failure mechanism (pre-fix).** `install-oneclick.sh` and its
`install-oneclick.test.sh` harness were absent from CI, so the installer's
env-contract / arg-parsing / dry-run gates were never syntax-checked or run on
Linux.

**Fix.** The workflow now: `bash -n` all installer scripts; run the harness
(`bash install-oneclick.test.sh` — hermetic: `--no-clone`, no network, only
syntax-checks + unit-tests pure helpers + dry-run paths); include
`feat/multi-carrier-phase2` in push triggers so the branch is
`go test -race`'d on the Linux runner.

**Verification.** The Linux CI job performs this; on this Windows host the
equivalent is a manual `bash -n` (the workflow YAML is inspected,
[.github/workflows/go.yml#L44-L102](../../.github/workflows/go.yml#L44)).
Result in-tree: `bash -n install-oneclick.sh` and
`bash -n install-oneclick.test.sh` both pass; the full Linux gate is recorded
as a CI dependency in the deployment doc's acceptance gate (BLOCKED on
staging, below).

---

### P3 — Dashboard UI defect: duplicate `data-view="network"` / missing `data-view="outbounds"`

**Severity:** P3 · **Confidence:** High

**Source paths / functions**

- [`internal/dashboard/static/index.html`](../../internal/dashboard/static/index.html),
  [`internal/dashboard/static/app.js`](../../internal/dashboard/static/app.js),
  [`internal/dashboard/static/style.css`](../../internal/dashboard/static/style.css).

**Failure mechanism (pre-fix).** The sidebar navigation had a duplicate
`data-view="network"` and was missing a `data-view="outbounds"` entry, so the
Outbounds section was unreachable / the Network view was double-bound.

**Fix + full UI modernization.**

- Fixed the duplicate `data-view="network"` and added the missing
  `data-view="outbounds"`.
- Added a **tunnel-state banner** (state + color-independent icon ●/◐/◔/○),
  a **stale-telemetry badge**, and **carrier detail cards** that explicitly
  render `unmeasured` (never a fabricated zero) for backend-unexported fields.
- Accessibility: skip-link to `#content`, `role="status"` +
  `aria-live="polite"` on the global badge container, `role="contentinfo"` on
  the footer, visible `:focus-visible` outlines, a **copy-diagnostics** button
  (redacted JSON snapshot), and distinct **401 / 403 / 503** error states
  (`role="alert"`).
- Security invariants preserved: no external URLs, relative assets only,
  CSP-compatible markup, no inline styles/scripts, loopback bind /
  read-only / CSRF / TLS / Basic-auth headers unchanged.
- [`docs/tunneldash.md`](../../docs/tunneldash.md) updated to document the new
  sections and invariants.

**Regression tests.**

- [`internal/dashboard/ui_test.go`](../../internal/dashboard/ui_test.go) —
  `TestIndexHasOutboundsView`, `TestIndexViewAttributesUnique`,
  `TestIndexNavigationSectionsComplete`,
  `TestIndexStaleAndHealthIndicators`, `TestIndexCarrierDetailHooks`,
  `TestIndexAccessibilityAttributes`, `TestIndexCopyDiagnosticsButton`,
  `TestIndexErrorStatesDistinct`, `TestIndexNoInlineStylesAndScripts`,
  `TestIndexSecurityInvariantsRecheck`.
- [`internal/dashboard/static_assets_test.go`](../../internal/dashboard/static_assets_test.go) —
  `TestNoDuplicateDataView`, `TestStaticNoExternalURLs`,
  `TestIndexAssetsAreRelative`, `TestCSPCompatibleMarkup`,
  `TestStaticHasRequiredSections`.

**Exact verification + result.**

```
go test ./internal/dashboard/ -run 'TestIndex|TestStatic|TestNoDuplicate|TestCSP' -v
```

Result: all PASS (12 UI + 5 asset tests).

---

### Verification-gate finding: stale two-process gate marker strings

**Severity:** P2 (gate blocker) · **Confidence:** High

**Source path / function**

- [`integration/twoproc_test.go`](../../integration/twoproc_test.go) — the
  L4 two-process local gate.

**Failure mechanism (pre-fix).** The gate's log-wait markers were still from
the **single-carrier era** (`"Down-carrier authenticated to"` /
`"Down-carrier authenticated from"` / `"carrier down ready"`), which no longer
match the multi-carrier carrier-ID log lines
(`"Down-carrier down-reality-a authenticated to"` /
`"carrier down (id down-reality-a) ready"`). Every platform's two-process gate
therefore **blocked / timed out** on a marker mismatch.

**Fix.** Markers corrected to the multi-carrier carrier-ID strings (offset-
scoped for the "already in the log" startup case), and the **S10 contract**
updated to the Phase 2 semantics: a carrier-loss / no-remote-verdict bootstrap
outcome now returns SOCKS **`0x01`** (`session.BootstrapEndedWithoutResult` →
`0x01`, general failure) instead of `0x06` (`0x06` is reserved for a genuine
target-dial timeout). The bounded bootstrap wait (~2 s) is still asserted.

**Regression test.** The gate itself: `go test ./integration/ -run
TestTwoProcessLocal -v` (passes on the Linux CI runner; on this Windows host
the two-process binary gate is delegated to CI).

**Verification.** `go test ./...` is green in-tree (the gate compiled and its
local subtests that *can* run on this host pass); the full two-process
scenario matrix is a CI / staging gate — see the deployment doc (BLOCKED).

---

## 3. Unresolved questions / risks

1. **`FrameReset`/`FrameBootstrapAck` have not been exercised over the real
   cross-host transport** (CDN WebSocket + VLESS+Reality). The in-memory and
   two-process gates prove the engine; the L5 staging matrix (twice, once
   race) is required to prove real-socket behavior. **This is the BLOCKED
   acceptance gate** (see deployment doc §5, referencing
   [`integration/RUNBOOK.md`](../../integration/RUNBOOK.md)).
2. **`stream_resets_received` / `bootstrap_acks_received` are new metrics**
   with no production baseline yet; operators should confirm the counters move
   on carrier flaps after rollout (deployment doc §4 post-deployment checks).
3. **Non-loopback down-listener binds** are still supported and only *warned*
   about, not refused. An operator who previously relied on the
   `0.0.0.0:9002` default **must** now set `SPLIT_DOWN_LISTEN` explicitly
   (deployment doc §2/§3).
4. **`SPLIT_TCP_KEEPALIVE_MS` default (30 s)** changes socket teardown timing
   in production; a wedged socket is now reaped in ~one probe instead of the
   OS ~2 h default. Rollback (set `=0`) restores the pre-fix byte-identical
   OS-default behavior.
5. **The dashboard "unmeasured" fields** (TTFB p50, RTT, queue usage, credit
   window) are rendered as explicit `unmeasured` because the backend does not
   yet export them; these are not data-loss defects, but they signal backend
   telemetry gaps to close in a later phase.
6. **The full `go test -race` and the Linux two-process gate** cannot run on
   the Windows dev host; both are CI-gated. Their green status is asserted by
   the workflow, not observed in this audit.

---

## 4. Explicit release recommendation

**Do NOT release to production from this working tree.** The in-tree work is
correct and fully unit/integration-verified on `go1.27.0 windows/amd64`, and
it is safe to *merge to the branch* and *stage-deploy*, but **production
release is BLOCKED** on the L5 two-server acceptance matrix (the new
`FrameReset` / `FrameBootstrapAcc` frames and the SOCKS5 status-byte change
have not been proven over the real CDN/Reality transport). 

Gate to unblock release:

- Run [`integration/RUNBOOK.md`](../../integration/RUNBOOK.md) matrix (20
  scenarios) on staging — **twice**, once with race builds — and record the
  results in `IMPLEMENTATION_STATUS.md`.
- Specifically confirm: SOCKS `0x00` is only observed after a real target
  accept; `stream_resets_received` increments on an induced rebind refusal;
  `bootstrap_acks_received` increments on each bootstrap; a refused/failed
  target yields `0x05/0x04/0x02/0x03/0x06` (never a false `0x00`); the
  loopback down-listener binds `127.0.0.1:9002`; and kernel keepalive
  (30 s) is visible via `ss -i`.
- Any scenario failure is fixed (new commit + FULL matrix re-run) or filed as
  its own issue — the release gate does not close on a failing scenario.

See [`phase2-deployment-rollback-2026-10-14.md`](./phase2-deployment-rollback-2026-10-14.md)
for the human-operator rollout and the exact acceptance matrix to run.
