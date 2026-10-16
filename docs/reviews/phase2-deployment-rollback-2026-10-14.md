# Phase 2 Multi-Carrier — Deployment & Rollback Plan (Human Operator)

For the operator deploying the Phase 2 multi-carrier build (HEAD `285e26e` +
the uncommitted working-tree fixes). Companion to
[`phase2-audit-2026-10-14.md`](./phase2-audit-2026-10-14.md) and
[`phase2-final-report-2026-10-14.md`](./phase2-final-report-2026-10-14.md).

**This is a human-executed plan.** The Go fixes are unit/integration-verified
on `go1.27.0 windows/amd64`; the production acceptance gate is **BLOCKED** on
the L5 staging matrix (§5) and must be run by the operator with the real
transport before this build is declared releasable.

---

## 1. What changed operationally (the "gotchas")

| Area | Change | Operator action |
|---|---|---|
| Down-carrier listener default | `DefaultDownListen` `":9002"` → `"127.0.0.1:9002"` | **If you previously relied on the `0.0.0.0:9002` (or bare `:9002`) default, you MUST now set `SPLIT_DOWN_LISTEN` explicitly** to your previous bind. Otherwise the listener drops to loopback-only. |
| Kernel TCP keepalive | New `SPLIT_TCP_KEEPALIVE_MS` (default `30000`, `0` disables) | Nothing required for defaults; set `0` only to reproduce pre-fix OS-default keepalive behavior. |
| Reconnect backoff | `SPLIT_RECONNECT_*` semantics documented as threshold, not hard cap | Optional tuning; defaults unchanged (`1000/10000/30000/2000`). |
| SOCKS5 status bytes | Accurate RFC 1928 codes; `0x00` only after target accept | Verify client tooling tolerates non-zero codes on real target failures. |
| New control frames | `FrameReset` (0x08), `FrameBootstrapAck` (0x09) | Both nodes must be upgraded **together** (a mixed-version pair cannot interpret the new control frames). |
| Two-process gate | Markers corrected to carrier-ID strings; S10 now expects `0x01` | CI only; no host action. |

---

## 2. Pre-deployment checklist

Verify **before** rollout on both hosts:

- [ ] **Backup the current binaries and env files.**
  - Binaries: `cp /usr/local/bin/iran-splitter /usr/local/bin/iran-splitter.pre-phase2`
        (and `germany-splitter`); confirm a pre-deploy snapshot in `backups/`
        (git-ignored, never committed).
  - Env: `cp /etc/split-tunnel/iran.env /etc/split-tunnel/iran.env.pre-phase2`
        and `... germany.env ...`.
  - Xray config: `cp` the live Xray JSON before touching anything.
- [ ] **Confirm the build SHA.** Both binaries built from the same
  `285e26e` + working-tree fixes; record `git rev-parse HEAD` and the
  `go version` used (`go1.27.0`).
- [ ] **Confirm both hosts will be upgraded in the same window.**
  `FrameReset` / `FrameBootstrapAck` are understood only by the new build — a
  mixed old/new pair will drop the new control frames as protocol noise.
- [ ] **Capture current listener binds** (`ss -ltnp` on both) so you can prove
  the post-deploy diff is only the intended down-listener change.
- [ ] **Record a metrics baseline** (`curl -fsS http://127.0.0.1:<metrics>/metrics`
  on both) so post-deploy counters (`stream_resets_received`,
  `bootstrap_acks_received`, `carrier_loss_events`) have a starting point.
- [ ] **Staging preflights** (read-only, per [`integration/RUNBOOK.md`](../../integration/RUNBOOK.md) §2.3):
  `systemctl is-active`, `ss -ltnp`, metrics HTTP 200, DNS + TLS/WS reachability.
- [ ] **Decide `SPLIT_DOWN_LISTEN`.** If the production Germany host today
  runs the `0.0.0.0:9002`/`:9002` default and the firewall *already* blocks
  direct inbound to :9002, you may keep loopback and remove the firewall
  rule. If a non-loopback bind is genuinely required, **set
  `SPLIT_DOWN_LISTEN=<host:port>` explicitly** (the new default is loopback;
  Germany logs a one-time "NON-LOOPBACK bind" journal warning in that case).
- [ ] **Decide `SPLIT_TCP_KEEPALIVE_MS`.** Default `30000` is safe. Set
  `=0` only to restore the pre-fix OS-default keepalive.

---

## 3. Deployment steps

### 3.1 Upgrade order (Germany first, then Iran)

The **down carrier is the data-return path**; bringing up the new Germany
listener (loopback) and the new frame handlers first keeps the existing up
carrier stable while Iran connects. Do **not** leave the pair mixed for more
than the rollout window.

1. **Germany host:**
   - `systemctl stop germany-splitter`
   - Install the new `germany-splitter` binary (over the backed-up one).
   - Edit `/etc/split-tunnel/germany.env`:
     - set `SPLIT_DOWN_LISTEN=127.0.0.1:9002` **unless** you are keeping a
       non-loopback bind (then set your previous value explicitly).
     - (optional) `SPLIT_TCP_KEEPALIVE_MS=30000` (or `0` to disable).
   - `systemctl daemon-reload`
   - `systemctl start germany-splitter`
   - Verify: `journalctl -u germany-splitter -n 40` shows `germany-splitter
     started`; confirm **no** "NON-LOOPBACK bind" warning if you used
     loopback (or confirm it *is* present and expected if you used a
     non-loopback bind).
   - `ss -ltnp | grep 9002` → listener owned by `germany-splitter` on the
     intended interface (loopback expected).

2. **Iran host:**
   - `systemctl stop iran-splitter`
   - Install the new `iran-splitter` binary.
   - Edit `/etc/split-tunnel/iran.env`:
     - (optional) `SPLIT_TCP_KEEPALIVE_MS=30000` (or `0`).
     - `SPLIT_RECONNECT_BASE_MS` / `MAX_MS` / `WINDOW_MS` / `CLAMP_MS` —
       leave at defaults unless a tuning incident is open; see
       `docs/carrier-reconnect-backoff.md` for the threshold (not hard-cap)
       semantics of `SPLIT_RECONNECT_WINDOW_MS`.
   - `systemctl daemon-reload`
   - `systemctl start iran-splitter`
   - Verify: `journalctl -u iran-splitter -n 40` shows `iran-splitter
     started` and up-carrier authenticated.

### 3.2 Config / env change summary

| Variable | Host | Default / required | Notes |
|---|---|---|---|
| `SPLIT_DOWN_LISTEN` | Germany | `127.0.0.1:9002` (new default) | **Set explicitly if you previously used `0.0.0.0:9002`/`:9002` and need that bind.** |
| `SPLIT_TCP_KEEPALIVE_MS` | both | `30000` | `0` disables (pre-fix behavior). Range 0..36000000. |
| `SPLIT_RECONNECT_BASE_MS` | both | `1000` | unchanged default |
| `SPLIT_RECONNECT_MAX_MS` | both | `10000` | unchanged default |
| `SPLIT_RECONNECT_WINDOW_MS` | both | `30000` | threshold, not hard cap (may overshoot by one `MAX`) |
| `SPLIT_RECONNECT_CLAMP_MS` | both | `2000` | cap after `slept >= window` |

---

## 4. Rollback procedure

Rollback restores the pre-Phase-2 binaries **and** the down-listener
behavior. Because the default down-listener changed, a bare binary rollback
*also* changes the bind — you must restore the env too.

1. **Stop both services** (Germany then Iran, so no dangling session holds a
   new-version control frame):
   ```
   systemctl stop iran-splitter
   systemctl stop germany-splitter
   ```
2. **Restore binaries:**
   ```
   cp /usr/local/bin/iran-splitter.pre-phase2    /usr/local/bin/iran-splitter
   cp /usr/local/bin/germany-splitter.pre-phase2 /usr/local/bin/germany-splitter
   ```
3. **Restore env** (undo the Phase 2 keys; the old build has no
   `SPLIT_TCP_KEEPALIVE_MS` and the old `DefaultDownListen` is `:9002`):
   ```
   cp /etc/split-tunnel/iran.env.pre-phase2    /etc/split-tunnel/iran.env
   cp /etc/split-tunnel/germany.env.pre-phase2 /etc/split-tunnel/germany.env
   # If you had set SPLIT_DOWN_LISTEN explicitly to 0.0.0.0:9002, keep that
   # line (the old default was :9002, so an explicit non-loopback value is
   # still correct under the old binary).
   systemctl daemon-reload
   ```
4. **Start in reverse order** (Germany first so the down listener is up
   before Iran re-dials):
   ```
   systemctl start germany-splitter
   systemctl start iran-splitter
   ```
5. **Verify:** both `started`, carriers re-authenticated within the backoff
   schedule, an end-to-end SOCKS CONNECT succeeds. The old build has no
   `stream_resets_received` / `bootstrap_acks_received` counters — their
   absence in `/metrics` is expected and confirms the rollback took.

> **Do NOT mix versions:** a rolled-back old node paired with a new node will
> drop the new control frames as protocol noise. Roll both hosts before
> resuming traffic.

---

## 5. Post-deployment verification

### 5.1 Metrics / log lines to check (both hosts)

- `systemctl is-active iran-splitter germany-splitter` → `active`.
- `journalctl -u <unit> -n 60`: `... started`, `Up-carrier authenticated`,
  `Down-carrier <id> authenticated to/from`. **No** `rebind refused` storm
  and **no** repeated `stale_generation` churn at steady state.
- `curl -fsS http://127.0.0.1:<metrics>/metrics` — confirm the **new**
  counters exist and are at/baseline:
  - `stream_resets_received` (Iran; increments on each peer `FrameReset`).
  - `bootstrap_acks_received` (Iran; increments on each `FrameBootstrapAck`).
  - `carrier_loss_events` / `carrier_loss_events{carrier="down-reality-a"}`
    (unchanged semantics; should stay flat at steady state).
- **Loopback bind:** `ss -ltnp | grep 9002` → bound to `127.0.0.1` (or your
  explicit `SPLIT_DOWN_LISTEN` value); if a non-loopback bind was used, confirm
  the one-time "NON-LOOPBACK bind" journal warning is present and expected.
- **Keepalive:** on the Iran/Germany host, `ss -i <upstream-fd>` or
  `cat /proc/<pid>/net/...` / `ip route get` + `ss` should reflect a 30 s
  keepalive on the long-lived carrier sockets (absent when
  `SPLIT_TCP_KEEPALIVE_MS=0`).

### 5.2 The SOCKS5 status-byte behavior change

- A CONNECT to a **reachable, accepted** target → `0x00` (unchanged happy
  path).
- A CONNECT to a **refused / DNS-failing / blocked / unreachable / timed-out**
  target now returns the **accurate** code (`0x05/0x04/0x02/0x03/0x06`)
  instead of a false `0x00`. Confirm with a deliberately-bad destination
  (closed port → `0x05`, unresolvable host → `0x04`).
- A CONNECT that loses carriers before a verdict (bounded ~2 s wait) returns
  `0x01` (general) — not `0x06` (the Phase 2 `BootstrapEndedWithoutResult →
  0x01` contract).

### 5.3 Confirm the new frames appear

- Induce a down-carrier flap (e.g. briefly drop the down path, per
  [`integration/RUNBOOK.md`](../../integration/RUNBOOK.md) scenario 7/8).
  If a rebind is **refused**, the Iran host should log a peer reset and
  `stream_resets_received` should tick.
- On every bootstrap, `bootstrap_acks_received` should tick on the Iran host.
  `0x00` on the wire only when the target actually accepted.

---

## 6. Production acceptance gate — **BLOCKED**

**Status: BLOCKED.** The new control frames (`FrameReset`,
`FrameBootstrapAck`), the accurate SOCKS5 status bytes, and the loopback
down-listener have **not** been proven over the real CDN-WebSocket +
VLESS+Reality transport. The in-memory and two-process gates prove the
engine only.

**The operator must run the full matrix from
[`integration/RUNBOOK.md`](../../integration/RUNBOOK.md) §3 (20 scenarios) on
the staging topology — twice, once with `go test -race` builds — and record
the results in `IMPLEMENTATION_STATUS.md`** ("Integration test record", format
in RUNBOOK §4). Specifically the operator's matrix must include:

- **Scenario 1/2** — SOCKS `0x00` on real accept; a bad target now yields the
  accurate non-zero byte (this is the D21 proof over real transport).
- **Scenario 7/8** — up/down carrier failure mid-session: rebind completes;
  on a *refused* rebind, confirm `stream_resets_received` increments and the
  stranded session is terminated (D20 proof) rather than retried indefinitely.
- **Scenario 9/17** — clean reconnect / repeated flapping: no reconnect storm
  under the documented `SPLIT_RECONNECT_*` threshold semantics;
  `sessions_lost_after_carrier_failure` stays 0.
- **Scenario 11** — blackhole: keepalive (now `SPLIT_TCP_KEEPALIVE_MS`
  default 30 s + `SPLIT_LIVENESS_ROUNDS`) detects and tears down the carrier.
- **Scenario 12/13** — wrong-secret / malformed peer: still rejected at the
  v1 handshake; no panic.
- **Scenario 18** — resource settling: no fd/goroutine growth (the new
  control-frame callbacks must not leak).

**Verdict gate (RUNBOOK §3 "No unresolved CRITICAL/HIGH finding"):** any
scenario failure is either fixed (new commit + FULL matrix re-run) or filed as
its own issue with the repro. **The release gate does not close on a failing
scenario.** Only when the full matrix passes (twice, incl. race) may this
build be declared production-releasable.

Until that gate is green, this build is safe to **stage-deploy** but **must
not be released to production.**
