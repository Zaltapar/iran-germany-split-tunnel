# Iran-Germany Asymmetric Split-Tunnel

Dual-carrier frame-multiplexed relay for Xray/3x-ui with shared secret authentication.

## Architecture

```
Client → Iran Xray → iran-splitter ===[Up-Carrier:9001]===[CDN Path]=== germany-splitter ===[Down-Carrier:9002]===[Direct Path]=== Internet
```

- **Up-carrier** (port 9001): Goes through CDN path for better upload
- **Down-carrier** (port 9002): Direct path for better download
- **Frame protocol**: 7-byte header (StreamID 4B + Type 1B + Length 2B)
- **Auth**: Shared secret with SHA256 derivation + constant-time comparison

## Quick Start

### Build

```bash
cd split-tunnel
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

| Variable | Iran Default | Germany Default | Description |
|----------|-------------|-----------------|-------------|
| `SPLIT_LISTEN` | `127.0.0.1:10900` | — | SOCKS5 listen (Iran only) |
| `SPLIT_CARRIER_UP` | `germany:9001` | — | Up-carrier address (Iran) |
| `SPLIT_CARRIER_DOWN` | `germany:9002` | — | Down-carrier address (Iran) |
| `SPLIT_LISTEN_DOWN` | — | `:9002` | Down-carrier listen (Germany) |
| `SPLIT_SECRET` | — | — | **Must match on both servers** |
| `SPLIT_METRICS_PORT` | `0` | `0` | HTTP metrics port (0=off) |

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

| Type | Value | Description |
|------|-------|-------------|
| Data | 0x00 | User data payload |
| Auth | 0x01 | Shared secret authentication |
| Ping | 0x02 | Keepalive ping |
| Pong | 0x03 | Keepalive pong |
| Close | 0x04 | Stream close |

## Metrics

```bash
curl http://127.0.0.1:9100/metrics
```

## License

Internal use.
