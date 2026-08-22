# Iran-Germany Asymmetric Split-Tunnel

Dual-carrier frame-multiplexed relay for Xray/3x-ui with shared secret authentication.

## Architecture

- **Up-carrier** (port 9001): Goes through CDN path for better upload
- **Down-carrier** (port 9002): Direct path for better download
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
| `SPLIT_SOCKS_LISTEN` | `127.0.0.1:10900` | — | SOCKS5 listen (Iran) |
| `SPLIT_WS_LISTEN` | `127.0.0.1:9001` | — | WS listen (CDN) |
| `SPLIT_DOWN_CARRIER_ADDR` | `127.0.0.1:10802` | — | Down-carrier dial (Iran) |
| `SPLIT_UP_WS_URL` | — | `wss://cdn.example.com/upload` | WS dial (Germany) |
| `SPLIT_DOWN_LISTEN` | — | `:9002` | Down-carrier listen (Germany) |
| `SPLIT_SECRET` | — | — | **Must match on both** |
| `SPLIT_METRICS_PORT` | `0` | `0` | HTTP metrics port (0=off) |

## Metrics

```bash
curl http://127.0.0.1:9100/metrics
```
