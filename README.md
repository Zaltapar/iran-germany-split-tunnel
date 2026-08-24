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

### Build

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
| `SPLIT_WS_LISTEN` | ✓ | | `0.0.0.0:9001` | Up-carrier WebSocket server (path `/upload`, front with nginx → CDN) |
| `SPLIT_DOWN_CARRIER_ADDR` | ✓ | | `127.0.0.1:10802` | Down-carrier dial target (local Xray VLESS+Reality outbound) |
| `SPLIT_UP_WS_URL` | | ✓ | `wss://cdn.example.com/upload` | Up-carrier WebSocket URL (CDN domain) |
| `SPLIT_DOWN_LISTEN` | | ✓ | `:9002` | Down-carrier TCP listener |
| `SPLIT_SECRET` | ✓ | ✓ | placeholder | **Must match on both nodes** |
| `SPLIT_METRICS_PORT` | ✓ | ✓ | `0` (off) | Local HTTP metrics port |
| `SPLIT_RELAY_BUF` | ✓ | ✓ | `32768` | Relay buffer size in bytes |

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
| Auth | 0x01 | Shared-secret authentication (StreamID 0, payload = 32-byte derived secret) |
| Ping | 0x02 | Keepalive ping (StreamID 0) |
| Pong | 0x03 | Keepalive pong (StreamID 0) |
| Close | 0x04 | Stream close |
| Header | 0x05 | Stream destination (first frame of a new stream, up-carrier only) |

**Carrier handshake** (both directions, symmetric):
1. Initiator sends `FrameAuth(derived secret)`.
2. Responder validates in constant time, replies `FrameAuth` (echo) + `FramePong[0]`.
3. Initiator completes after the pong. Both sides then run `CarrierConn` (single read loop,
   single dispatcher, serialized writes, keepalive pings).

**Session lifecycle**:
1. Iran accepts a SOCKS5 `CONNECT`, waits for both carriers, sends `FrameHeader(destination)`
   on the up-carrier, then relays client bytes as `FrameData` (upload only).
2. Germany's dispatcher creates the stream on the first `FrameHeader` (`OnNewStream`), dials the
   target (`net.DialTimeout` 10 s), registers the session, and starts:
   - up relay: up-carrier `FrameData` → target socket
   - down relay: target socket → down-carrier `FrameData` (download only)
3. Teardown: client EOF → Iran `FrameClose` (up); target EOF → Germany `FrameClose` (down);
   both sides deregister streams and close sockets. `FrameClose` for an unknown/late stream is a
   no-op.

## Local end-to-end test

`go run ./e2e-pipe-test` runs the full protocol (auth on both carriers, header bootstrap,
upload/download relays, teardown) in-process over `net.Pipe` — no real network needed.

## Metrics

```bash
curl http://127.0.0.1:9100/metrics
```

## License

Internal use.