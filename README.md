# Iran-Germany Asymmetric Split-Tunnel

Dual-carrier frame-multiplexed relay for Xray/3x-ui with WebSocket CDN transport for upload and raw TCP for download.

## Architecture

```
Client → Iran Xray → iran-splitter (SOCKS5:10900)
                            ├── up-carrier (WS listener :9001, from CDN)
                            └── down-carrier (TCP dialer → 127.0.0.1:10802)
                                                      ↓ via Xray tunnel to Germany
                                              germany-splitter
                            ├── up-carrier (WS dialer → wss://cdn/upload)
                            └── down-carrier (TCP listener :9002)
                                                      ↓
                                              Real destination (internet)
```

- **Up-carrier (upload: client → internet)**: WebSocket through ArvanCloud CDN
- **Down-carrier (download: internet → client)**: Raw TCP via Xray VLESS+Reality tunnel
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
| `SPLIT_SOCKS_LISTEN` | `127.0.0.1:10900` | — | SOCKS5 listen (Iran only) |
| `SPLIT_WS_LISTEN` | `127.0.0.1:9001` | — | WS listen for CDN (Iran) |
| `SPLIT_DOWN_CARRIER_ADDR` | `127.0.0.1:10802` | — | Xray outbound dial (Iran) |
| `SPLIT_DOWN_LISTEN` | — | `:9002` | TCP listen for down-carrier (Germany) |
| `SPLIT_UP_WS_URL` | — | `wss://cdn.example.com/upload` | CDN WebSocket URL (Germany) |
| `SPLIT_SECRET` | — | — | **Must match on both servers** |
| `SPLIT_METRICS_PORT` | `0` | `0` | HTTP metrics port (0=off) |

## Xray Config (Iran)

```json
{
  "outbounds": [
    {"tag": "to-splitter",
     "protocol": "socks",
     "settings": {"servers":[{"address":"127.0.0.1","port":10900}]}
    },
    {"tag": "down-tunnel",
     "protocol": "socks",
     "settings": {"servers":[{"address":"127.0.0.1","port":10802}]}
    }
  ],
  "routing": {
    "rules": [
      {"type":"field","inboundTag":["user-inbound"],"outboundTag":"to-splitter"}
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
