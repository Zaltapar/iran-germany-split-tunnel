# Iran–Germany Asymmetric Split-Tunnel

A dual-carrier, frame-multiplexed relay that tunnels client traffic from
Iran to Germany with asymmetric upload/download paths. The Iran node exposes a
local SOCKS5 ingress on `127.0.0.1:10900`; each client connection is multiplexed
as a logical stream over a **WebSocket up-carrier** (upload bytes, riding a CDN
edge to avoid the asymmetric underlay) and a **TCP down-carrier** (download
bytes, tunneled under VLESS+Reality on the German host). One direction per
carrier—no cross-traffic. Phase 2 multi-carrier support adds a second,
hot-standby down-carrier with bounded carrier-reconnect semantics so a brief
underlay blip cannot amplify into a multi-minute outage.

## Architecture

```
Client (Iran)
  │
  ▼
Iran SOCKS5 ingress  127.0.0.1:10900   (RFC 1928 + RFC 1929 auth)
  │  (StreamID per connection)
  │
  ├─► Up-carrier: WebSocket  127.0.0.1:9001  →  nginx / CDN  →  wss://<cdn>/upload
  │       (upload bytes, FrameHeader, control frames)
  │
  └─► Down-carrier: TCP  127.0.0.1:9002  (behind VLESS+Reality Xray inbound)
          (download bytes, response data)
          │
          ▼
      germany-splitter  dials real target → Internet

Metrics:
  ├─ Iran   node  127.0.0.1:<SPLIT_METRICS_PORT>  /metrics
  ├─ Germany node  127.0.0.1:<SPLIT_METRICS_PORT>  /metrics
  └─ tunneldash  127.0.0.1:8080/  (loopback + TLS + basePath + Basic auth)
```

The German egress node (`germany-splitter`) dials `wss://<cdn>/upload` to
complete the up-carrier handshake and listens on the down-carrier loopback port
reached via the local VLESS+Reality Xray inbound. When `SPLIT_MULTI_CARRIER_ENABLED`
is set a second down-carrier pair (`SPLIT_DOWN_LISTEN_2` /
`SPLIT_DOWN_CARRIER_ADDR_2`) is added; the routing engine selects the best
carrier per stream (hot-standby failover, never cross-stream bonding).

## Key Features

- **Bounded carrier reconnect** (`SPLIT_RECONNECT_*`) — a cumulative sleep window
  (default 30 s) with per-attempt clamp (default 2 s) so a persistent underlay
  outage does not keep the node in a multi-minute reconnect loop.
- **TCP keepalive** (`SPLIT_TCP_KEEPALIVE_MS`, default 30 s) — kernel probes on
  client, target, and carrier sockets detect half-open connections within one
  probe instead of the OS default (~2 h).
- **Loopback-only down-carrier default** — `DefaultDownListen` is
  `127.0.0.1:9002`; the down-carrier is reached only through the local
  VLESS+Reality Xray inbound, never directly from the Internet. Non-loopback
  binds remain supported by setting `SPLIT_DOWN_LISTEN` explicitly.
- **Accurate SOCKS5 connection-result semantics** (RFC 1928) — status byte
  `0x00` is returned to the client **only after** the German node confirms the
  remote target connection succeeded (`FrameBootstrapAck`, 0x09, Issue #21).
  All other failure cases return the correct non-zero status byte.
- **Explicit stream reset** (`FrameReset`, 0x08, Issue #20) — when a rebind is
  refused the German node sends a versioned `FrameReset` carrying a generation
  echo and reason code; the Iran node handles it idempotently (stale-generation
  guard) so the stranded session is terminated exactly once.
- **Multi-carrier selection with hot-standby failover** —
  `SPLIT_MULTI_CARRIER_ENABLED` adds a second down-carrier; the routing engine
  pins each stream to one carrier and fails over to the standby on loss,
  never spanning bytes across carriers.
- **tunneldash** — loopback-only, read-only monitoring dashboard (TLS + random
  basePath + HTTP Basic auth when server-hosted). No production mutations.
- **Secret redaction & fail-closed routing** — all log output and dashboard JSON
  redact `SPLIT_SECRET`, SOCKS passwords, and key material; the routing engine
  refuses every unmatched destination when no default rule is set (fail-closed).

## Protocol Overview

Frame header (7 bytes):

```
Offset  Size  Field
0       4     StreamID (uint32, BE)
4       1     Type     (uint8)
5       2     Length   (uint16, BE, payload size, max 65535)
7       Len   Payload
```

Frame catalog (full documentation in
[`docs/protocol-frames.md`](docs/protocol-frames.md)):

| Type | Name | Purpose |
|------|------|---------|
| `0x00` | `FrameData` | user payload |
| `0x01` | `FrameAuth` | shared-secret handshake (SHA-256-derived, constant-time) |
| `0x02` | `FramePing` | keepalive ping |
| `0x03` | `FramePong` | keepalive pong |
| `0x04` | `FrameClose` | stream close / half-close |
| `0x05` | `FrameHeader` | stream header: encoded target destination |
| `0x06` | `FrameRebind` | re-attach an existing session to a new carrier |
| `0x07` | `FrameCredit` | receiver-side flow-control credit (inert unless enabled) |
| `0x08` | `FrameReset` | stream-level negative ack (Phase 2, Issue #20) |
| `0x09` | `FrameBootstrapAck` | bootstrap target-dial result (Phase 2, Issue #21) |

## Configuration Reference

All variables are read by `internal/config` at startup. Unset / empty means
"use the default". The defaults below are the current audited values
(verified against `internal/config/config.go` `Defaults()`).

### Iran node (`iran-splitter`)

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLIT_SOCKS_LISTEN` | `127.0.0.1:10900` | SOCKS5 ingress listener |
| `SPLIT_SOCKS_USER` | *(empty)* | RFC 1929 username (empty = auth off) |
| `SPLIT_SOCKS_PASS` | *(empty)* | RFC 1929 password (never logged) |
| `SPLIT_SOCKS_ALLOWED_SOURCES` | *(empty)* | source-IP allowlist (empty = allow all) |
| `SPLIT_WS_LISTEN` | `127.0.0.1:9001` | up-carrier WebSocket listener |
| `SPLIT_DOWN_CARRIER_ADDR` | `127.0.0.1:10802` | down-carrier dial target (local VLESS+Reality Xray outbound) |
| `SPLIT_UP_WS_URL` | *(placeholder)* | CDN WebSocket URL (must be set in production) |
| `SPLIT_SECRET` | *(placeholder)* | shared secret (must be set; strength-validated) |
| `SPLIT_METRICS_PORT` | `0` (off) | Prometheus `/metrics` listener (loopback) |
| `SPLIT_RELAY_BUF` | `32768` (32 KiB) | socket read chunk size |
| `SPLIT_CARRIER_GRACE` | `5000` ms | grace window per direction after carrier loss |
| `SPLIT_RECONNECT_BASE_MS` | `1000` | exponential backoff base |
| `SPLIT_RECONNECT_MAX_MS` | `10000` | exponential backoff cap |
| `SPLIT_RECONNECT_WINDOW_MS` | `30000` | cumulative reconnect-sleep bound (0 = disabled) |
| `SPLIT_RECONNECT_CLAMP_MS` | `2000` | per-attempt delay once window exhausted (0 = disabled) |
| `SPLIT_TCP_KEEPALIVE_MS` | `30000` (30 s) | kernel TCP keepalive probe period (0 = off) |
| `SPLIT_BOOTSTRAP_WAIT_MS` | `0` (lib. 30 s) | bounded bootstrap wait for a down carrier |
| `SPLIT_SESSION_BUFFER_BYTES` | `262144` (256 KiB) | per-direction reconnect buffer |
| `SPLIT_SESSION_BUFFER_TOTAL_BYTES` | `0` (lib. 32 MiB) | node-level aggregate session buffer |
| `SPLIT_LIVENESS_ROUNDS` | `0` (lib. 3) | consecutive unanswered pings before carrier is dead |
| `SPLIT_STREAM_QUEUE_BYTES` | `0` (lib. default) | per-stream queue bound |
| `SPLIT_STREAM_QUEUE_FRAMES` | `0` (lib. default) | per-stream frame count bound |
| `SPLIT_STREAM_QUEUE_TOTAL_BYTES` | `0` (lib. 256 MiB cap) | aggregate queue bound |
| `SPLIT_STREAM_OVERFLOW_MS` | `0` (lib. 30 s) | max time to wait for overflow credit |
| `SPLIT_CREDITS_ENABLED` | `false` | credit-plane master on/off |
| `SPLIT_MULTI_CARRIER_ENABLED` | `false` | second down-carrier + routing engine on/off |
| `SPLIT_DOWN_CARRIER_ADDR_2` | *(empty, host required)* | second down-carrier dial target |

### Germany node (`germany-splitter`)

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLIT_DOWN_LISTEN` | `127.0.0.1:9002` | down-carrier listener |
| `SPLIT_UP_WS_URL` | *(placeholder)* | CDN WebSocket URL (must be set) |
| `SPLIT_SECRET` | *(placeholder)* | shared secret |
| `SPLIT_METRICS_PORT` | `0` (off) | Prometheus `/metrics` |
| `SPLIT_MULTI_CARRIER_ENABLED` | `false` | enable second down-carrier |
| `SPLIT_DOWN_LISTEN_2` | *(empty)* | second down-carrier listener |
| `SPLIT_DOWN_CARRIER2_SNI` | *(empty)* | TLS 1.3 SNI for second Xray inbound |
| `SPLIT_ROUTING_RULES_FILE` | *(empty = routing off)* | JSON rules file path |
| `SPLIT_ROUTING_DEFAULT` | *(empty = use file)* | `direct` or `warp` fallback |
| `SPLIT_WARP_SOCKS_ADDR` | `127.0.0.1:40000` | WARP SOCKS5 forwarder address |
| `SPLIT_ROUTING_DEBUG` | `false` | per-dial debug log |

### Shared (both nodes)

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLIT_POLICY_MODE` | `static` | carrier-intelligence policy (`static` or `adaptive`) |
| `SPLIT_POLICY_TOPK` | `2` | top-K carriers to score (1–8) |
| `SPLIT_PROBING_ENABLED` | `false` | active carrier probing on/off |
| `SPLIT_PROBE_URL` | *(empty, required when enabled)* | probe target URL |
| `SPLIT_PROBE_DAILY_BUDGET` | `100663296` (96 MiB) | daily byte cap for probes |
| `SPLIT_TTFB_BASELINE_MS` | `0` (lib. 500 ms) | TTFB baseline for adaptive scoring |
| `SPLIT_TARGET_ONLY_IPV4` | `false` | resolve targets to A records only |
| `SPLIT_TARGET_ADDR_POLICY` | `default` | egress address-family policy |
| `SPLIT_TARGET_DIAL_BOUND_MS` | `0` | per-dial ceiling (0 = no extra ceiling) |
| `SPLIT_TARGET_BREAKER_ENABLED` | `false` | per-target dial circuit breaker |
| `SPLIT_TARGET_DIAL_BACKOFF_ENABLED` | `false` | jittered backoff on target dial |

## Quick Start / Deployment

The one-click installer provisions both roles on their respective hosts:

```bash
# On the Iran host:
./install-oneclick.sh --role iran

# On the Germany host:
./install-oneclick.sh --role germany
```

`install.sh` is the interactive variant. `splitterctl` is the transactional
deployment CLI (state root `/etc/split-tunnel`):

```
splitterctl status
splitterctl doctor
splitterctl pair generate
splitterctl rollback --to <state-id>
```

The full deployment/rollback runbook is at
[`docs/reviews/phase2-deployment-rollback-2026-10-14.md`](docs/reviews/phase2-deployment-rollback-2026-10-14.md).

## Dashboard

`tunneldash` is a read-only monitoring panel. It never contacts, mutates, or
deploys to a production host.

**Local development (fixture mode, no config):**

```bash
go build -o tunneldash ./cmd/tunneldash
./tunneldash
# → UI at http://127.0.0.1:8080/
# → API at http://127.0.0.1:8080/api/v1/
```

**Server-hosted (TLS + basePath + Basic auth):** when the config carries a
complete TLS section (`tls.enabled`, `certFile`, `keyFile`, and a 32-hex
`basePath`) the dashboard binds over TLS on a public port, mounts all routes
under `/<basePath>/`, and requires HTTP Basic auth. The basePath is an access
secret, not a substitute for authentication.

See [`docs/tunneldash.md`](docs/tunneldash.md) for the full reference.

## Testing

Unit tests (all packages):

```bash
go test ./...
```

Two-process integration harness (L4 gate, requires two processes;
`RUN_TWOPROC=1` opts in):

```bash
RUN_TWOPROC=1 go test ./integration/
```

The L5 real-transport acceptance matrix (21 checks covering SOCKS5 egress
identity, carrier reconnect, `FrameReset`, `FrameBootstrapAck`,
`FrameBootstrapAck` status bytes, and multi-carrier failover) was executed
against the staging build `0e60a34` on 2026-10-15 and passed **21/21**
(0 FAIL, 0 BLOCKED, 0 SKIP). The matrix is documented in
[`integration/RUNBOOK.md`](integration/RUNBOOK.md) and the evidence is in
[`docs/reviews/phase2-final-report-2026-10-14.md`](docs/reviews/phase2-final-report-2026-10-14.md).

## Security Posture

- **Loopback-only listeners** — SOCKS5, WebSocket, down-carrier, metrics, and
  tunneldash all bind to `127.0.0.1` by default. The down-carrier is reached
  only through the local VLESS+Reality Xray inbound, never directly from the
  Internet.
- **Mutual authentication** — the shared `SPLIT_SECRET` is derived to a
  SHA-256 key and compared in constant time; the `FrameAuth` handshake
  authenticates both directions.
- **Fail-closed routing** — when no routing rule matches a destination and
  `SPLIT_ROUTING_DEFAULT` is empty the routing engine refuses the dial rather
  than falling back to `direct`.
- **Secret redaction** — `SPLIT_SECRET`, SOCKS passwords, and key material are
  never written to logs. The dashboard redacts all sensitive fields before
  rendering.
- **Dashboard security model** — loopback-only bind (fail-closed at startup);
  `readOnly=true` by default (all POST mutations refused); no CORS; no
  inline styles/scripts; CSP headers; pinned host keys (SSH collector);
  fixed-argv command allowlist (no shell injection).

## Status & Documentation Index

| Document | Path |
|----------|------|
| Phase 2 audit report | [`docs/reviews/phase2-audit-2026-10-14.md`](docs/reviews/phase2-audit-2026-10-14.md) |
| Defect register | [`docs/reviews/phase2-defect-register-2026-10-14.md`](docs/reviews/phase2-defect-register-2026-10-14.md) |
| Deployment / rollback runbook | [`docs/reviews/phase2-deployment-rollback-2026-10-14.md`](docs/reviews/phase2-deployment-rollback-2026-10-14.md) |
| Final report (incl. L5 21/21 evidence) | [`docs/reviews/phase2-final-report-2026-10-14.md`](docs/reviews/phase2-final-report-2026-10-14.md) |
| Protocol frame catalog | [`docs/protocol-frames.md`](docs/protocol-frames.md) |
| SOCKS5 usage & status-byte semantics | [`docs/socks5-usage.md`](docs/socks5-usage.md) |
| tunneldash reference | [`docs/tunneldash.md`](docs/tunneldash.md) |
| Carrier reconnect backoff | [`docs/carrier-reconnect-backoff.md`](docs/carrier-reconnect-backoff.md) |
| Key-rotation runbook | [`docs/key-rotation-runbook.md`](docs/key-rotation-runbook.md) |
| Integration test runbook | [`integration/RUNBOOK.md`](integration/RUNBOOK.md) |
| Implementation status | [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) |

**L5 real-transport acceptance matrix: 21/21 PASS on staging, build `0e60a34`,
2026-10-15.** Production acceptance is contingent on the operator completing
the L6 soak test (24–48 h on staging post-rollout) as described in the
deployment/rollback runbook.
