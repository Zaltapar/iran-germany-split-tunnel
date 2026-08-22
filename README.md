# Iran-Germany Asymmetric Split-Tunnel

Dual-carrier frame-multiplexed relay for Xray/3x-ui. Upload goes through CDN (good upload), download goes through direct tunnel (good download).

## Quick Install (Automatic)

```bash
# Iran server:
curl -fsSL https://raw.githubusercontent.com/Zaltapar/iran-germany-split-tunnel/main/install.sh | sudo bash -s -- iran

# Germany server:
curl -fsSL https://raw.githubusercontent.com/Zaltapar/iran-germany-split-tunnel/main/install.sh | sudo bash -s -- germany

# With flags (non-interactive):
curl -fsSL https://raw.githubusercontent.com/Zaltapar/iran-germany-split-tunnel/main/install.sh | sudo bash -s -- iran --secret YOUR_SECRET --metrics-port 9100
```

## Architecture

```
Client → Iran Xray → iran-splitter
                       ├── SOCKS5 :10900 (from Xray)
                       ├── WS :9001 (from Nginx/CDN)
                       └── TCP → 127.0.0.1:10802 (Xray download tunnel → Germany)
                                                      ↓
                                              germany-splitter
                       ├── WS dialer → wss://cdn/upload (upload)
                       └── TCP :9002 (receives from Iran)
                                                      ↓
                                              Real destination
```

## Configuration

| Variable | Iran | Germany | Description |
|----------|------|---------|-------------|
| `SPLIT_SOCKS_LISTEN` | `127.0.0.1:10900` | — | SOCKS5 for Xray |
| `SPLIT_WS_LISTEN` | `127.0.0.1:9001` | — | WS from CDN/Nginx |
| `SPLIT_DOWN_CARRIER_ADDR` | `127.0.0.1:10802` | — | Xray download tunnel |
| `SPLIT_DOWN_LISTEN` | — | `:9002` | TCP listen for Iran |
| `SPLIT_UP_WS_URL` | — | `wss://cdn.example.com/upload` | CDN WebSocket |
| `SPLIT_SECRET` | **must match** | **must match** | Shared auth secret |
| `SPLIT_METRICS_PORT` | `0` | `0` | HTTP metrics port (0=off) |

## Manual Build

```bash
cd split-tunnel
curl -fsSL -o iran-splitter https://github.com/Zaltapar/iran-germany-split-tunnel/releases/latest/download/iran-splitter
curl -fsSL -o germany-splitter https://github.com/Zaltapar/iran-germany-split-tunnel/releases/latest/download/germany-splitter
sudo cp iran-splitter germany-splitter /usr/local/bin/
```

Or build from source:
```bash
cd split-tunnel
GOOS=linux GOARCH=amd64 go build -o iran-splitter ./cmd/iran-splitter
GOOS=linux GOARCH=amd64 go build -o germany-splitter ./cmd/germany-splitter
```

## Xray Config (Iran)

```json
{
  "outbounds": [
    {"tag": "up-cdn", "protocol": "freedom", "settings": {}},
    {"tag": "down-direct", "protocol": "freedom", "settings": {}},
    {
      "tag": "to-splitter",
      "protocol": "socks",
      "settings": {"servers": [{"address": "127.0.0.1", "port": 10900}]}
    }
  ],
  "routing": {
    "rules": [
      {"type":"field","inboundTag":["your-user-inbound"],"outboundTag":"to-splitter"}
    ]
  }
}
```

## Nginx Config (Iran)

```nginx
server {
    listen 9001;  # or your WS port
    location /upload {
        proxy_pass http://127.0.0.1:9001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
    }
}
```

## Metrics

```bash
curl http://127.0.0.1:9100/metrics
```

## License

Internal use.
