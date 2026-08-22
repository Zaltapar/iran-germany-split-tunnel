# Iran–Germany Asymmetric Split-Tunnel

Resell VPN access with transparent asymmetric routing: upload traffic traverses one outbound (e.g., ArvanCloud CDN with great upload), download traverses another (e.g., direct with good download). No end-user client changes required.

## Architecture

```
End-user client
       │
       ▼
┌──────────────────────────────────────────────────────────────────┐
│ Iran Server                                                      │
│                                                                  │
│  3x-ui inbound (VLESS/VMess/Trojan)                             │
│       │ routing rule → to-splitter                               │
│       ▼                                                          │
│  iran-splitter (new Go daemon)                                   │
│       │                          │                               │
│       ▼ (helper-up SOCKS)        ▼ (helper-down SOCKS)           │
│  127.0.0.1:10801              127.0.0.1:10802                    │
│       │                          │                               │
│       ▼ (outbound: up-cdn)       ▼ (outbound: down-direct)       │
└───────┼──────────────────────────┼───────────────────────────────┘
        │                          │
        │  Session ID + Header     │  Session ID only
        │  Destination address     │
        ▼                          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Germany Server                                                   │
│                                                                  │
│  Xray inbound: up-cdn           Xray inbound: down-direct        │
│       │                              │                           │
│       ▼                              ▼                           │
│  germany-splitter (new Go daemon)                                │
│       │                                                          │
│       ▼ real destination dial                                    │
│  Open internet                                                   │
└──────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Location | Port | Purpose |
|-----------|----------|------|---------||
| iran-splitter | Iran server | 127.0.0.1:10900 | Receives Xray connections, splits to two legs |
| helper-up (SOCKS) | Iran server | 127.0.0.1:10801 | Xray outbound path to Germany up-leg |
| helper-down (SOCKS) | Iran server | 127.0.0.1:10802 | Xray outbound path to Germany down-leg |
| germany-splitter | Germany server | 127.0.0.1:10901/10902 | Reassembles sessions, dials real destination |

## Session Protocol

### Up-leg (first connection to Germany)
1. Session ID (16 bytes random)
2. Destination address:
   - Address type (1 byte): 1=IPv4, 3=domain, 4=IPv6
   - Address (variable)
   - Port (2 bytes, big-endian)
3. Raw data stream

### Down-leg (second connection to Germany)
1. Session ID (16 bytes random)
2. Waits for up-leg to establish destination connection (up to 3s timeout)
3. Data stream

## Quick Start

### 1. Build

```bash
cd split-tunnel
go build -o iran-splitter ./cmd/iran-splitter
go build -o germany-splitter ./cmd/germany-splitter
```

### 2. Deploy Iran Server

```bash
# Copy binary
sudo cp iran-splitter /usr/local/bin/

# Configure systemd
sudo cp systemd/iran-splitter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable iran-splitter
sudo systemctl start iran-splitter

# Check logs
journalctl -u iran-splitter -f
```

### 3. Deploy Germany Server

```bash
# Copy binary
sudo cp germany-splitter /usr/local/bin/

# Configure systemd
sudo cp systemd/germany-splitter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable germany-splitter
sudo systemctl start germany-splitter

# Check logs
journalctl -u germany-splitter -f
```

### 4. Update Xray Config

Replace your Xray config with the templates in `config/`:

**Iran server:** `config/iran-xray-config.json`
**Germany server:** `config/germany-xray-config.json`

## Configuration

### iran-splitter

| Environment Variable | Default | Description |
|---------------------|---------|-------------||
| `SPLIT_LISTEN` | `127.0.0.1:10900` | Address Xray connects to |
| `SPLIT_UP_SOCKS` | `127.0.0.1:10801` | Helper-up SOCKS port |
| `SPLIT_DOWN_SOCKS` | `127.0.0.1:10802` | Helper-down SOCKS port |
| `SPLIT_METRICS_PORT` | `0` | Metrics HTTP port (0=disabled) |
| `SPLIT_RELAY_BUF` | `32768` | Relay buffer size in bytes |

### germany-splitter

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SPLIT_UP_LISTEN` | `127.0.0.1:10901` | Up-leg listener address |
| `SPLIT_DOWN_LISTEN` | `127.0.0.1:10902` | Down-leg listener address |
| `SPLIT_METRICS_PORT` | `0` | Metrics HTTP port (0=disabled) |
| `SPLIT_RELAY_BUF` | `32768` | Relay buffer size in bytes |
| `SPLIT_WAIT_TIMEOUT` | `3000` | Wait timeout for session in ms |

## Metrics

Both splitters expose Prometheus-style metrics at `/metrics`:

```
active_sessions 5
total_sessions 142
total_bytes_up 1048576
total_bytes_down 5242880
errors 0
session_count 5
```

### Monitoring Example

```bash
# Iran splitter metrics
curl -s http://127.0.0.1:9100/metrics

# Germany splitter metrics
curl -s http://127.0.0.1:9101/metrics
```

## Troubleshooting

### Session timeout

```bash
# Check active sessions
curl -s http://127.0.0.1:9100/metrics | grep active

# Check error rate
journalctl -u iran-splitter --since "5 minutes ago" | grep -i error
```

### Connection failures

```bash
# Verify listeners are active
ss -tlnp | grep -E '10900|10801|10802'

# Check Xray config syntax
xray config format config.json

# Test splitter connectivity
curl -s http://127.0.0.1:9100/metrics
```

### High error count

1. Check Germany splitter can reach the destination
2. Verify both Xray outbounds are working independently
3. Check network latency between Iran and Germany servers
4. Review firewall rules on both servers

## UDP Note

This implementation supports TCP only. UDP-based protocols (Hysteria2, TUIC, QUIC) require separate handling.

## Performance Notes

- Each session uses 3 TCP connections instead of 1
- Buffer size can be tuned via `SPLIT_RELAY_BUF`
- Monitor `LimitNOFILE` in systemd service for high-concurrency use
- Metrics endpoint helps track active sessions and byte counts

## License

Internal use by reseller.
