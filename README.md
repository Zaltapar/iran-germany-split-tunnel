# Iran-Germany Asymmetric Split-Tunnel

Frame-multiplexed split-tunnel for Xray/3x-ui with shared secret authentication.

## Architecture

```
Client -> Iran Xray -> iran-splitter ===[MUX Carrier:9000]=== germany-splitter -> Internet
```

- Single persistent carrier connection (WebSocket/TCP) between splitters
- 7-byte frame header: StreamID (4B) + Type (1B) + Length (2B)
- Per-session virtual streams multiplexed over carrier
- SHA256 shared secret authentication on connect

## Quick Start

### Build

```bash
cd split-tunnel
go build -o iran-splitter ./cmd/iran-splitter
go build -o germany-splitter ./cmd/germany-splitter
```

### Deploy

```bash
# Iran server
sudo cp iran-splitter /usr/local/bin/
sudo cp systemd/iran-splitter.service /etc/systemd/system/
sudo systemctl enable --now iran-splitter

# Germany server
sudo cp germany-splitter /usr/local/bin/
sudo cp systemd/germany-splitter.service /etc/systemd/system/
sudo systemctl enable --now germany-splitter
```

### Configure Secret

Set matching `SPLIT_SECRET` environment variable on both servers.

## Configuration

| Variable | Iran Default | Germany Default | Description |
|---|---|---|---|
| `SPLIT_LISTEN` | `127.0.0.1:10900` | `:9000` | Local listen address |
| `SPLIT_CARRIER` | `germany-server:9000` | - | Germany carrier addr (Iran only) |
| `SPLIT_SECRET` | - | - | Shared secret (must match both sides) |
| `SPLIT_METRICS_PORT` | `0` | `0` | Metrics HTTP port (0=disabled) |
| `SPLIT_RELAY_BUF` | `32768` | `32768` | Relay buffer size |

## Frame Protocol

| Type | Value | Description |
|---|---|---|
| Data | 0x00 | User data payload |
| Auth | 0x01 | Shared secret authentication |
| Ping | 0x02 | Keepalive ping |
| Pong | 0x03 | Keepalive pong |
| Close | 0x04 | Stream close |

## Metrics

```
curl http://127.0.0.1:<metrics_port>/metrics
```

## License

Internal use.
