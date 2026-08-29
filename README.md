# Iran-Germany Asymmetric Split-Tunnel

Dual-carrier frame-multiplexed relay for Xray/3x-ui with shared secret authentication.
Uploads ride a WebSocket carrier through a CDN; downloads ride a direct TCP carrier
tunneled over VLESS+Reality. One direction per carrier — no cross-traffic.

## Architecture

```
                                    Iran node                                        Germany node
┌──────────────────────────────────────────────────────┐        ┌──────────────────────────────────────────────┐
│ Client → local Xray → iran-splitter (SOCKS5 :10900)  │        │ germany-splitter                             │
│        │                                             │        │   │                                         │
│        ├─ Up-carrier (upload): WS server :9001       │ nginx  │   │ dials wss://<cdn>/upload                │
│        │     (nginx → CDN /upload path) ─────────────┼───────►├───┘                                         │
│        │                                             │        │   │                                         │
│        └─ Down-carrier (download): dials             │  Xray  │   │                                         │
│             127.0.0.1:10802 (VLESS+Reality) ─────────┼───────►├──► TCP listener :9002                       │
└──────────────────────────────────────────────────────┘        │   │                                         │
                                                                 │   ▼ net.DialTimeout → real destination      │
                                                                 │ Internet                                   │
                                                                 └──────────────────────────────────────────────┘
```

- **Up-carrier** (Iran `:9001` → CDN → Germany): client upload bytes, `FrameHeader`, control.
- **Down-carrier** (Iran via local Xray → Germany `:9002`): target response bytes only.
- **Frame protocol**: 7-byte header (`StreamID 4B BE | Type 1B | Length 2B BE`) + payload (max 65535 B).
- **Auth**: symmetric `FrameAuth` with SHA-256-derived secret + constant-time comparison.
- **Stream model**: one `StreamID` per session, shared by both carriers. The first frame of a
  stream on the up-carrier is `FrameHeader` (encoded destination); Germany dials the target and
  echoes response bytes back on the down-carrier with the same `StreamID`.

## Quick Start

### Install (interactive installer)

The installer asks for every setting (role, shared secret, ports, CDN domain,
Xray inbound tag, nginx, metrics) with sensible defaults — just press Enter to
accept. It then installs the Go toolchain if needed, builds the binary for the
role, runs the binary's OWN pre-install configuration gate
(`<role>-splitter --validate-config`, the same `internal/config` validation
the production binary uses at startup) and only writes/starts the systemd
service if that gate passes. On the Iran role it also merges the Xray config
and configures nginx, then prints the exact next steps for the other node.

```bash
# Iran node (the installer generates the shared secret for you)
sudo bash install.sh
# or remotely:
curl -fsSL https://raw.githubusercontent.com/Zaltapar/iran-germany-split-tunnel/main/install.sh | sudo bash -s
```

**Secret handling.** Without `--secret` the installer generates a 256-bit
secret (`openssl rand -hex 32`), stores it at `/root/.split-tunnel-secret`
(mode 600), and shows it MASKED in the summary (use `--show-secret` to
reveal). Transfer the secret to the other node as a FILE, not a command-line
argument:

```bash
# on the Iran node, after the install:
scp /root/.split-tunnel-secret root@<germany>:~/.split-tunnel-secret

# Germany node (non-interactive; the secret never appears on the command line)
curl -fsSL https://raw.githubusercontent.com/Zaltapar/iran-germany-split-tunnel/main/install.sh | sudo bash -s \
  -- germany --yes --up-ws-url wss://<cdn-domain>/upload --secret-file ~/.split-tunnel-secret
```

Every question also has a flag (see `install.sh --help`), so the installer can
run fully non-interactive with `--yes`. Re-running the installer on an
existing installation is an **upgrade**: it pre-fills the current unit's
values as prompt defaults, backs up the old unit
(`<unit>.service.bak.<ts>`) and binary (`<role>-splitter.bak`), and keeps the
existing shared secret unless you supply a new one. To remove the service,
binary and managed nginx config: `sudo bash install.sh uninstall
[iran|germany]` (rollback backups are kept and listed in the output;
`ufw` rules are NOT removed automatically — see the printed hints).

### Manual build & deploy (without the installer)

```bash
go build -o iran-splitter ./cmd/iran-splitter
go build -o germany-splitter ./cmd/germany-splitter
```

### Deploy Iran Server

```bash
sudo cp iran-splitter /usr/local/bin/
sudo cp systemd/iran-splitter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now iran-splitter
```

### Deploy Germany Server

```bash
sudo cp germany-splitter /usr/local/bin/
sudo cp systemd/germany-splitter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now germany-splitter
```

## Configuration

| Variable | Iran | Germany | Default | Description |
|----------|:----:|:-------:|---------|-------------|
| `SPLIT_SOCKS_LISTEN` | ✓ | | `127.0.0.1:10900` | SOCKS5 listener (local Xray connects here) |
| `SPLIT_WS_LISTEN` | ✓ | | `127.0.0.1:9001` | Up-carrier WebSocket server (path `/upload`, front with nginx → CDN) |
| `SPLIT_DOWN_CARRIER_ADDR` | ✓ | | `127.0.0.1:10802` | Down-carrier dial target (local Xray VLESS+Reality outbound) |
| `SPLIT_UP_WS_URL` | | ✓ | `wss://cdn.example.com/upload` | Up-carrier WebSocket URL (CDN domain) |
| `SPLIT_DOWN_LISTEN` | | ✓ | `:9002` | Down-carrier TCP listener |
| `SPLIT_SECRET` | ✓ | ✓ | placeholder | **Must match on both nodes** (min 32 chars; blocklisted placeholders rejected at startup) |
| `SPLIT_ALLOW_WEAK_SECRET` | ✓ | ✓ | unset | `=1` bypasses the secret length check (development/test only; blocklist still enforced) |
| `SPLIT_METRICS_PORT` | ✓ | ✓ | `0` (off) | Local HTTP metrics port |
| `SPLIT_RELAY_BUF` | ✓ | ✓ | `32768` | Relay buffer size in bytes |
| `SPLIT_STREAM_QUEUE_BYTES` | ✓ | ✓ | `1048576` (1 MiB) | Max payload bytes buffered per stream before that stream (not the carrier) is terminated |
| `SPLIT_STREAM_QUEUE_FRAMES` | ✓ | ✓ | `16` | Max frames buffered per stream |
| `SPLIT_STREAM_QUEUE_TOTAL_BYTES` | ✓ | ✓ | `33554432` (32 MiB) | Aggregate queued bytes across all streams per carrier |
| `SPLIT_STREAM_OVERFLOW_MS` | ✓ | ✓ | `100` | How long a stalled stream may hold its buffer (ms) before termination |

### Configuration validation

Both binaries share one centralized configuration layer
(`internal/config`): **load (env → defaults) → parse → validate →
construct**. A node never opens a listener or starts a goroutine until
`config.Load` succeeds, and a startup failure reports **every** problem
at once (aggregated list) instead of one-at-a-time:

* empty / unset variable = "use the default";
* integers are strictly parsed (`abc`, negatives and out-of-range values
  are config errors, never silent zeros); `SPLIT_ALLOW_WEAK_SECRET`
  must be a real boolean (`1/0/true/false`);
* addresses must be `host:port` (bare `:port` allowed for listeners,
  bracketed IPv6 like `[::1]:9001`, explicit host required for dial
  targets);
* `SPLIT_UP_WS_URL` must be `ws(s)://host/upload` — the placeholder
  `wss://cdn.example.com/upload` is rejected, as are wrong paths;
* port collisions between the app's own listeners (and the metrics
  port) are detected at config time;
* `SPLIT_STREAM_QUEUE_*` / `SPLIT_STREAM_OVERFLOW_MS` values of `0`
  keep the library defaults; the aggregate budget must cover at least
  one stream's share;
* the Phase 6 secret policy applies (blocklist always, length minimum
  unless `SPLIT_ALLOW_WEAK_SECRET=1`); error messages never contain the
  secret value.

`SPLIT_STREAM_QUEUE_*` and `SPLIT_STREAM_OVERFLOW_MS` ship the value `0`
by default, which the runtime resolves to `mux.DefaultStreamLimits`
(16 frames / 1 MiB per stream, 32 MiB per carrier, 100 ms) via
`mux.SanitizeLimits`.

**Pre-install dry-run.** Both binaries accept `--validate-config` as their
first argument: they run the full load→parse→validate path above, print the
result, and exit WITHOUT opening any listener. `install.sh` uses this as its
configuration gate (the exact environment values that go into the systemd
unit are passed in), and it is also a convenient manual dry-run:

```bash
SPLIT_SECRET=... SPLIT_UP_WS_URL=wss://cdn.example.org/upload \
  ./germany-splitter --validate-config
```

## Xray Config (Iran)

```json
{
  "outbounds": [
    {"tag": "up-cdn"},
    {"tag": "down-direct"},
    {
      "tag": "to-splitter",
      "protocol": "socks",
      "settings": {"servers": [{"address": "127.0.0.1", "port": 10900}]}
    }
  ],
  "routing": {
    "rules": [
      {"type": "field", "inboundTag": ["your-inbound-tag"], "outboundTag": "to-splitter"}
    ]
  }
}
```

## Frame Protocol

Header (7 bytes): `StreamID uint32 BE | Type uint8 | Length uint16 BE` — payload max 65535 bytes.

| Type | Value | Description |
|------|-------|-------------|
| Data | 0x00 | User data payload |
| Auth | 0x01 | v1 challenge/response authentication (StreamID 0, handshake phase only) |
| Ping | 0x02 | Keepalive ping (StreamID 0) |
| Pong | 0x03 | Keepalive pong (StreamID 0) |
| Close | 0x04 | Stream close |
| Header | 0x05 | Stream destination (first frame of a new stream, up-carrier only) |

**Carrier handshake** (both directions, v1 — see below): a three-message
HMAC challenge/response. The raw secret (or any function of it) is never
sent on the wire; both ends prove possession of the shared secret with
fresh per-handshake nonces, and the carrier ROLE and protocol VERSION are
bound into the MACs. The whole handshake is bounded by a 15 s timeout.
After auth, both sides run `CarrierConn` (single read loop, single
dispatcher, serialized writes, keepalive pings). No application frame is
accepted before authentication completes.

**Session lifecycle**:
1. Iran accepts a SOCKS5 `CONNECT`, waits for both carriers, sends `FrameHeader(destination)`
   on the up-carrier, then relays client bytes as `FrameData` (upload only).
2. Germany's dispatcher creates the stream on the first `FrameHeader` (`OnNewStream`), dials the
   target (`net.DialTimeout` 10 s), registers the session, and starts:
   - up relay: up-carrier `FrameData` → target socket
   - down relay: target socket → down-carrier `FrameData` (download only)
3. Teardown: each session runs an explicit state machine
   (`Pending → Active → Closing → Closed` with per-direction half-close).
   Client EOF → Iran `FrameClose` (up) + up half-close: the target's
   in-flight response keeps flowing. Target EOF → Germany `FrameClose`
   (down) + down half-close. Any hard failure (carrier loss, socket
   error, cancellation) tears the session down through one authoritative
   `Session.Close(reason)`: socket close, stream deregistration, store
   unindex and metric decrement each run exactly once, no matter how
   many directions request termination at once. `FrameClose` for an
   unknown/late stream is a no-op.

## Local end-to-end test

`go run ./e2e-pipe-test` runs the full protocol (auth on both carriers, header bootstrap,
upload/download relays, teardown) in-process over `net.Pipe` — no real network needed.

## Security

**Shared secret.** Set `SPLIT_SECRET` identically on both nodes. Generate it with
`openssl rand -hex 32` (256 bits) and never reuse secrets across deployments.
At startup the splitters **fail fast** on:

* empty secrets;
* known insecure placeholder values (`password`, `test`, `CHANGE-ME-SECRET…`,
  `YOUR-SECRET-HERE…`, …) — this blocklist is always enforced;
* values shorter than 32 characters, unless `SPLIT_ALLOW_WEAK_SECRET=1`
  is set explicitly for development/test.

The secret is never logged; auth-failure logs never reveal *which* check
failed to the remote peer (the connection is simply closed; details are
local-only).

**Authentication protocol (v1).** A three-message mutual HMAC-SHA256
challenge/response, all on `FrameAuth`/StreamID 0:

1. **Challenge** (responder → initiator): `version | role | timestamp | nonce_s(16B)`
2. **Response** (initiator → responder): `version | role | ts_c | echo(ts_s, nonce_s) | nonce_c(16B) | HMAC-SHA256(secret, challenge ‖ ts_c ‖ nonce_c)`
3. **Confirmation** (responder → initiator): `version | role | nonce_s2(16B) | HMAC-SHA256(secret, challenge ‖ response ‖ nonce_s2)`

Properties:

* **Mutual** — both ends prove the secret (the initiator via the response
  MAC, the responder via the confirmation MAC);
* **Replay-resistant** — every handshake uses fresh 128-bit nonces covered
  by both MACs, and the response must echo the *current* challenge
  (no nonce store needed, hence nothing unbounded to maintain);
* **Role-bound** — the carrier role (`U` upload / `D` download) is inside
  both MAC transcripts: a valid secret cannot authenticate the wrong
  carrier direction;
* **Versioned** — `AuthVersion = 1`; unknown versions are rejected before
  MAC verification. **v0 (pre-hardening) peers are NOT compatible: upgrade
  both nodes together.**
* **Freshness** — both ends accept peer timestamps within ±60 s
  (defense in depth on top of the nonce replay protection);
* **Bounded** — a hard 15 s handshake timeout (socket deadline) applies
  even when the caller has no deadline, so a silent peer cannot hold a
  connection forever.

**Frame-context enforcement.** After auth, `FrameAuth` is rejected, and
application frames (`Data`/`Header`/`Rebind`/`Close`) on the reserved
control StreamID 0 terminate the carrier. StreamID 0 can never be
registered as a stream. Oversized/truncated frames, unknown frame types
and malformed rebind payloads are dropped or the stream is terminated —
never a panic.

**WebSocket exposure (Iran `/upload`).** The up-carrier endpoint is a
machine-to-machine endpoint: path is restricted to `/upload` (everything
else is 404), non-GET methods get 405, unauthenticated requests are
bounded by `ReadHeaderTimeout`, concurrent handshakes are capped (16,
HTTP 503 when saturated), and after 10 auth failures within 60 s the
endpoint returns HTTP 429 until the window lapses. The permissive
`CheckOrigin` policy is deliberate (carrier dialers send no Origin;
browsers are not legitimate clients) — the security boundary is the v1
authentication plus TLS/Reality in the transport.

**Metrics.** The metrics endpoint binds to `127.0.0.1` only and exposes
counts and byte totals — no secrets, tokens or destination details.

**Firewall.** Only these inbound ports should be reachable, and only from
their expected source:

* Iran: `SPLIT_WS_LISTEN` (default `127.0.0.1:9001`) — via CDN/nginx only, never
  direct;
* Germany: `SPLIT_DOWN_LISTEN` (default `:9002`) — from the download
  carrier transport (Xray inbound) only;
* metrics port — local tools only.

**Rebind security.** `FrameRebind` can only re-attach an EXISTING active
session: it is authenticated by the v1 handshake, direction-bound,
requires the attachment to be in a rebindable state, and the sender's
carrier generation must be strictly greater than the last accepted one
(stale/replay protection). Rebinds never create sessions.

## Metrics

```bash
curl http://127.0.0.1:9100/metrics
```

## License

Internal use.