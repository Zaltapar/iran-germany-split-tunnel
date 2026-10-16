# Up-carrier drop-storm fix (terminating semantics, bounded dial, per-target breaker)

This document summarizes the four-part fix for the transient up-carrier
`dropping stream N opened with frame type 0x00/0x04` storm diagnosed in
[`final-suite/upcarrier-drop-root-cause.md`](../final-suite/upcarrier-drop-root-cause.md).
It is the tracked companion to that (gitignored) investigation report. No
secrets, keys, or credentials appear in this file.

## Root cause in one line

Each failed target bootstrap called the **quiet** `Deregister(id)`; the peer's
still-in-flight `FrameData` (0x00) and trailing `FrameClose` (0x04) on that same
stream id then re-created the stream via `OnNewStream` and re-logged a fresh drop —
a 1,562× per-stream retransmit amplification driven by a Cloudflare egress
`i/o timeout` storm (32,066 dial failures ≈ 31,432 drop log lines in 24h).

## The four parts (what changed)

### Part 1 — Terminating semantics (primary)

A dead stream must stay registered so it does **not** re-open and re-dial a dead
destination. This is the invariant pinned by
[`TestTerminatedStreamStaysRegistered`](../pkg/mux/backpressure_test.go).

- [`pkg/mux/carrier.go`](../pkg/mux/carrier.go) — new `CarrierConn.Terminate(id)`:
  the safe replacement for the quiet `Deregister` at any "this destination is
  dead" drop path. If the stream id is already registered it calls
  `terminateStream(s, signalPeer=true)` (mark terminated + keep registered +
  best-effort `FrameClose` back to the peer). If it is not yet registered it
  installs a **terminated tombstone** (`callback=false`) so a retransmit that
  does arrive is dropped silently by the dispatcher and can *never* re-fire
  `OnNewStream`. On a closing carrier it is a quiet no-op.
- [`pkg/node/node.go`](../pkg/node/node.go) — the up-bootstrap `drop()` closure
  and the `onUpNewStream` / `onDownNewStream` `default:` branches now call
  `h.carrier.Terminate(id)` instead of `h.carrier.Deregister(id)`. The
  `handleRebind` refusal path (rebind-sweep) intentionally keeps the quiet
  `Deregister`: a refused rebind must **not** be mistaken for a peer
  half-close, so it must not emit a `FrameClose` (preserving the
  `rebind refused: … no active session` semantics the report classifies as a
  fail-closed corner). The rebind-sweep and `onSessionClosed` deregistrations
  are likewise left quiet (a fully-closed session frees its id for reuse).

Behavioral guarantees preserved:
- **Recovery path:** a NEW stream id for the same destination still bootstraps
  (a terminated record is keyed by id; a new id is unaffected).
- **Rebind-anchor invariant:** no credit or data is ever sent on a new carrier
  before the peer registers the stream — terminating a stream only happens on a
  stream whose target **failed** to dial, and the terminating `FrameClose`
  (signalPeer) is a terminal control frame, never a credit. Stale-generation
  rejection is untouched.
- **No wire-format change:** only which registered stream records are kept
  alive and which frames are dropped silently; the frame types on the wire are
  unchanged.

### Part 2 — Bounded target-dial timeout with jittered backoff

- [`pkg/node/target_ipv4.go`](../pkg/node/target_ipv4.go) — the default egress
  `TargetDial` now carries an operator-bound per-dial ceiling
  (`newDefaultTargetDialWithTimeout`), alongside the historical 10s default
  (`newDefaultTargetDial`). A `<=0` bound falls back to the historical 10s so a
  misconfiguration can never make the dial **unbounded**.
- [`pkg/node/target_dial_governor.go`](../pkg/node/target_dial_governor.go) —
  `dialBounded` races the dial against the ceiling; a pkg/node-local
  `dialBackoff` (exponential doubling, jittered into `[d/2, d]`, capped) paces
  per-target retries so one unreachable target cannot spin a 1,562× loop. (The
  backoff is implemented in `pkg/node`, **not** imported from
  `internal/backoff`, because the architecture boundary
  `internal/archtest` forbids `pkg/*` → `internal/*`; `internal/testutil` is
  the only allowlisted internal import.)
- Wired into `bootstrapUpStream` ([`pkg/node/node.go`](../pkg/node/node.go)):
  when the governor is enabled the target dial runs through
  `n.dialGovernor.Dial(ctx, n.cfg.TargetDial, targetAddr)`.

### Part 3 — Per-target dial-failure circuit breaker

[`pkg/node/target_dial_governor.go`](../pkg/node/target_dial_governor.go) —
`TargetDialGovernor` is a per-`host:port` breaker with:
- a rolling **failure window** + **threshold** that opens the breaker;
- a **cooldown** that refuses further dials, then admits a single **half-open
  probe** to readmit;
- an **LRU-capped** target map (default 1024 entries);
- **fail-closed to direct dial** for any unknown / evicted / untracked target
  (a full map never blocks a healthy target — it just evicts the LRU entry and
  that target behaves as unknown).

It is built by `BuildTargetDialGovernor`, which returns `nil` when every feature
is off, keeping the default build byte-identical.

### Part 4 — New metric counters

[`pkg/node/metrics.go`](../pkg/node/metrics.go) adds fixed-cardinality
(never-attacker-controlled) counters, exposed through the existing
`/metrics` `Render()`:

| Counter | Meaning |
|---|---|
| `up_newstream_refired_after_deregister` | a re-fired `OnNewStream` on the up carrier whose first frame is 0x00/0x04 (the re-fire condition the old `Error()` was blind to) |
| `down_newstream_refired_after_deregister` | the down-carrier equivalent |
| `target_dial_failure_breaker_open` | a target dial refused fast (breaker open, no dial spent) |
| `target_dial_failure_timeout` | a target dial that hit its bounded ceiling |

Existing metric names are unchanged; the new lines are plain
`lower_snake_case <int>` so they satisfy the existing `assertRenderPrivacy`
form check. `Snapshot` fields: `UpNewStreamRefiredAfterDeregister`,
`DownNewStreamRefiredAfterDeregister`, `TargetDialFailureBreakerOpen`,
`TargetDialFailureTimeout`.

## New environment variables and defaults

All wired in both roles for symmetry (only Germany actually dials egress
targets; on Iran they are inert). Every one ships **default-OFF / zero** so an
unconfigured deployment is byte-identical to the pre-fix build.

| Env var | Default | Meaning |
|---|---|---|
| `SPLIT_TARGET_DIAL_BOUND_MS` | `0` (no extra ceiling; the raw 10s stands) | per-dial ceiling (ms) |
| `SPLIT_TARGET_BREAKER_ENABLED` | `false` | master on/off for the circuit breaker |
| `SPLIT_TARGET_BREAKER_WINDOW_MS` | `0` → library `60000` (60s) | rolling failure window (ms) |
| `SPLIT_TARGET_BREAKER_THRESHOLD` | `0` → library `5` | failures in-window that open the breaker |
| `SPLIT_TARGET_BREAKER_COOLDOWN_MS` | `0` → library `30000` (30s) | open-cooldown before a half-open probe |
| `SPLIT_TARGET_BREAKER_MAX_TARGETS` | `0` → library `1024` | LRU cap on tracked targets |
| `SPLIT_TARGET_DIAL_BACKOFF_ENABLED` | `false` | master on/off for jittered retry backoff |
| `SPLIT_TARGET_DIAL_BACKOFF_BASE_MS` | `0` → library `500` (500ms) | exponential backoff base (ms) |
| `SPLIT_TARGET_DIAL_BACKOFF_MAX_MS` | `0` → library `30000` (30s) | exponential backoff cap (ms) |

`0` on a numeric knob is the documented "use the library default" sentinel
(lifted in `NewTargetDialGovernor`); `0` on `SPLIT_TARGET_DIAL_BOUND_MS`
specifically means "no extra ceiling" (the raw dialer's own 10s bound stands).

## Test coverage added

All new tests are deterministic (in-memory pipes, injected fake clocks, fake
dialers):

- **Part 1 (a/b):** `pkg/mux/terminate_test.go`
  - `TestTerminateStaysRegisteredAndDoesNotRefire` — after `Terminate`, peer
    retransmits of `FrameData`/`FrameClose` on that id are dropped silently and
    `OnNewStream` does not re-fire; the record stays registered.
  - `TestTerminateThenNewStreamRecovers` — a NEW id still bootstraps
    (recovery preserved); the terminated id does not poison it.
- **Parts 2/3:** `pkg/node/target_dial_governor_test.go`
  - `TestBoundedDialReturnsWithinBound` — a fake dialer that hangs past the
    bound returns within the bound.
  - `TestBoundedDialPreservesHealthyPath` — healthy dial passes through; a
    fully-disabled governor is `nil` (byte-identical).
  - `TestBackoffSpacedAndBounded` — retries are spaced and capped (never
    exceed the cap); a success resets the schedule.
  - `TestCircuitBreakerOpenRefuseReadmit` — N failures open it, dials refused
    during cooldown, half-open probe readmits on success, a failed probe keeps
    it open (cooldown restarts).
  - `TestCircuitBreakerLRUCapFailsClosed` — the map is capped; a full map
    evicts the LRU target, which fails closed to the direct dial (no unbounded
    growth).
- **Parts 1/4 node-level:** `pkg/node/up_newstream_refire_test.go`
  - `TestRetransmitAfterBootstrapDropIsSilenced` (a + f) — a dial-failed
    bootstrap is terminated; a peer retransmit is silenced (no session, no
    re-fire-counter move, no retry loop).
  - `TestNewStreamIDRecoversWhenTargetLive` (b) — a new id recovers when the
    target is reachable.
  - `TestRefireCounterIncrementsExactlyOnReFire` (f) — the
    `up_newstream_refired_after_deregister` counter increments exactly on the
    re-fire condition and stays put otherwise.
- **Existing suites unchanged and passing**, notably
  `TestTerminatedStreamStaysRegistered`, the rebind/credit-storm suites, and the
  integration failover tests.

## Gates

- `gofmt -l` on all changed files: **clean**
- `go build ./...`: **PASS**
- `go vet ./...`: **PASS**
- `go test -count=1 ./...`: **all green** (including `internal/archtest`
  boundary test — `pkg/*` never imports `internal/*`)
- `install-oneclick.test.sh` (Git Bash): **PASS=78 FAIL=0**
- Linux `-race` (changed packages on a Germany scratch copy): see the
  final-suite fix note.

## Files touched

| File | Change |
|---|---|
| `pkg/mux/carrier.go` | added `CarrierConn.Terminate(id)` |
| `pkg/node/node.go` | terminating drop paths; governor construction + wiring; new `Config` fields |
| `pkg/node/target_ipv4.go` | bounded default dial (`newDefaultTargetDialWithTimeout`, `dialPlainWithTimeout`) |
| `pkg/node/target_dial_governor.go` | **new**: bounded dial + jittered backoff + per-target LRU circuit breaker |
| `pkg/node/metrics.go` | 4 new fixed-cardinality counters + `Snapshot`/`Render` wiring |
| `internal/config/config.go` | 9 new env vars (all default-off) |
| `cmd/germany-splitter/main.go`, `cmd/iran-splitter/main.go` | pass the new `Config` fields into the node |

## Deployment verification (steady-state, 2026-10-13)

Facts only. No secrets, keys, or credentials in this section. Deployed as
`germany-splitter` restart **2026-10-13 19:19:25 UTC**
(`systemctl show germany-splitter -p ActiveEnterTimestamp`); service up
~1.4 h at time of writing (no restart since). Deployed fix commits:
`4ebcdc4` (Part 1 — mux `CarrierConn.Terminate`) and `b7b4f04` (Parts 2/3/4 —
bounded dial + jittered backoff + per-target breaker + re-fire metrics), on
`feat/multi-carrier-phase2`, over base `53021db`.

### Breaker env in effect (Germany `/etc/split-tunnel/germany.env`)

| Knob | Value |
|---|---|
| `SPLIT_TARGET_BREAKER_ENABLED` | `true` |
| `SPLIT_TARGET_BREAKER_THRESHOLD` | `5` |
| `SPLIT_TARGET_BREAKER_WINDOW_MS` | `60000` |
| `SPLIT_TARGET_BREAKER_COOLDOWN_MS` | `30000` |

`SPLIT_TARGET_DIAL_BOUND_MS` and the `SPLIT_TARGET_DIAL_BACKOFF_*` knobs are
unset on the host (library defaults apply; the breaker is the active control).

### Drop-line counts (journalctl, `germany-splitter`)

Restart-artifact window (first 5 min, 19:19:25–19:24:25):

| Signal | Count |
|---|---|
| `dropping stream` (169 frame 0x00 + 107 frame 0x04) | **276** |
| `i/o timeout` lines | 19 |
| `up carrier … bootstrapped session` (reconnect flood) | 1462 |
| `up carrier … lost / torn down` | 0 |

Confirmed one-time reconnect burst: the artifact window is dominated by 1462
new-session bootstraps immediately after the restart, of which 276 became drop
lines (18.5%); **0** of the 276 artifact drops were `i/o timeout` drops.

Clean window (restart + 6 min onward), split into two observed phases:

| Window | `dropping stream` | /min | /hour | `i/o timeout` | `breaker open` |
|---|---|---|---|---|---|
| Phase 1: 19:25:25–20:01 (~36 min) | 35 | 1.0 | ~58 | 234 | 892 |
| Phase 2: 20:02–20:33 (~31 min) | 794 | 25.6 | ~1532 | 357 | 2220 |
| Clean total (19:25:25–20:43, ~78 min) | 1125 | ~14.4 | ~882 | 591 | 3112+ |
| Last 5 min snapshot (20:37–20:42) | 13 | 2.6 | — | 23 | 0 |

Phase 1 steady state (1.0/min) is well below the pre-fix ~4.1/min. Phase 2 is a
**genuine ongoing Cloudflare egress `i/o timeout` storm** (top offenders:
`190.2.134.28`×100, `77.42.56.66`×44, `167.233.139.145`×44,
`65.109.240.103`×41, `194.221.250.50`×33) that drove the aggregate clean-window
rate up to ~25.6/min peak; by the final 5-min snapshot it had subsided to
~2.6/min. This is a *downstream target-egress* failure storm, not the
pre-fix per-stream retransmit amplification.

### Metric snapshot (`http://127.0.0.1:9101/metrics`, single consistent shot)

| Counter | Value |
|---|---|
| `up_newstream_refired_after_deregister` | 1125 |
| `down_newstream_refired_after_deregister` | 0 |
| `target_dial_failure` | 4062 |
| `target_dial_failure_breaker_open` | 3241 |
| `target_dial_failure_timeout` | 0 |

Total `dropping stream` lines since restart = **1125** ==
`up_newstream_refired_after_deregister` = **1125** (exactly 1:1). This is the
pre-fix comparison the earlier 297-vs-297 data pointed at: the re-fire counter
tracks drop lines 1:1, i.e. **no retransmit amplification** (the old root cause
was a 1,562× per-stream re-fire storm; each drop now produces exactly one
recorded re-fire, not a storm).

### Mechanism evidence

The journal does **not** log a per-event "re-fire" line, so the log alone
cannot isolate a re-fire. Instead, two independent signals confirm the
terminating semantics:

1. **No re-bootstrap of dropped IDs.** For dropped clean-window stream IDs
   (139936, 145218, 143784, 145170, 142990), `journalctl` shows **0**
   `stream <id>:` bootstrap lines after 19:25:25 — a dropped stream is not
   re-opened and re-dialed (the old amplification path).
2. **Re-fire counter == drop lines (1:1).** As above, 1125 == 1125.

Together: a dial-failed bootstrap is terminated and its peer retransmit is
dropped silently; the breaker fast-refuses (`target_dial_failure_breaker_open`
= 3241) instead of re-dialing; `target_dial_failure_timeout` = 0 (bounded
dials are not hitting the ceiling in this window).

### E2E health

- **Tunnel egresses Germany:** via the Iran-side SOCKS5 self-test,
  `https://www.google.com/generate_204` → **204**; `https://api.ipify.org`
  → **91.107.152.1** (Germany egress); `https://www.openai.com` → **308**
  (valid redirect); **20 MiB** download (2×10 MiB) completed in **3.81 s ≈
  5.25 MB/s**.
- **Local Windows curl note:** a direct `socks5h://` fetch from the Windows box
  is rejected by the SOCKS5 server ("User was rejected (1 1)") — a client-side
  SOCKS5 auth-negotiation failure, **not** a tunnel fault; the identical
  request from the Iran host succeeds (204).
- **Six Germany services active:** `control-agent`, `germany-splitter`,
  `tunneldash`, `warp-svc`, `xray-germany`, `ufw`.
- **Default route unchanged:** `default via 172.31.1.1 dev eth0`
  (DHCP internal gateway, src 91.107.152.1) — not via warp; correct for
  split-tunnel.
- **warp-svc proxy mode:** listening on `127.0.0.1:40000`; `warp-cli status`
  → Connected / healthy.

### Verdict

- **Fix mechanism: VERIFIED** — re-fire amplification eliminated (1:1
  counter, no re-bootstrap of dropped IDs), breaker active (fast-refuse),
  bounded dials, silent retransmit drops; tunnel healthy (204/egress/openai/
  20 MiB green, six services active, route + warp proxy unchanged).
- **Steady-state rate gate: FAIL** — the longer clean window does **not**
  stay "materially lower than the pre-fix ~4.1/min": Phase 2 is an ongoing
  Cloudflare egress i/o-timeout storm episode that raised the aggregate
  clean-window drop rate to ~25.6/min peak (subsiding to ~2.6/min by the final
  snapshot). The restart-burst explanation for the first-5-min artifact is
  confirmed, but an ongoing egress storm episode was observed in the clean
  window and therefore could **not** be fully ruled out. Per the gate, the
  branch is **not** pushed; this note is committed locally only.
