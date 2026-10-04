# SOCKS5 Proxy Usage (split-tunnel Iran)

## Connection Details

| Field | Value |
|-------|-------|
| Host | `188.121.111.122` |
| Port | `10900` |
| Username | `u4afa4d96ea1f9451` |
| Password | See `final-suite/socks5-credentials.txt` (not stored here) |
| Auth | Required (username/password) |

> **Note:** Traffic flows: your machine → Iran (188.121.111.122:10900) → Germany → Internet.
> All egress traffic exits via Germany.

## Client Configurations

### curl

```bash
# Replace PASS with the value from final-suite/socks5-credentials.txt
curl -x "socks5h://u4afa4d96ea1f9451:PASS@188.121.111.122:10900" \
     https://example.com/
```

### Browser (Firefox / Chrome via extensions)

- Host: `188.121.111.122`
- Port: `10900`
- Type: SOCKS5 with authentication
- Username: `u4afa4d96ea1f9451`
- Password: *(from `final-suite/socks5-credentials.txt`)*

For Chrome: use the FoxyProxy or SwitchyOmega extension.
For Firefox: Settings → Network Settings → Manual Proxy Configuration:
  - SOCKS Host: `188.121.111.122`, Port: `10900`
  - "SOCKS Proxy" + "SOCKS5" checkbox + "Use this SOCKS proxy for DNS lookup"
  - SOCKS Username: `u4afa4d96ea1f9451`
  - SOCKS Password: *(from credential file)*

### proxychains

```ini
# /etc/proxychains4.conf
proxychains 4
strict_chain
tcp_only
quiet

[ProxyList]
socks5 188.121.111.122 10900 u4afa4d96ea1f9451 PASS
```

Replace `PASS` with the password from `final-suite/socks5-credentials.txt`.

### Environment variables (curl, wget, etc.)

```bash
export ALL_PROXY="socks5h://u4afa4d96ea1f9451:PASS@188.121.111.122:10900"
export HTTPS_PROXY="$ALL_PROXY"
export HTTP_PROXY="$ALL_PROXY"
```

## Reboot Safety

- `iran-splitter` unit is **enabled** (auto-starts on boot) and `Restart=always`
  (auto-restarts on crash). The proxy will be available after any reboot.

## Security Notes

- The `SPLIT_SOCKS_ALLOWED_SOURCES` allowlist is **NOT set**, meaning the proxy
  accepts connections from any source IP. If you want to restrict access,
  set `SPLIT_SOCKS_ALLOWED_SOURCES=YOUR_IP` in `/etc/split-tunnel/iran.env`
  and restart `iran-splitter`.
- The SOCKS5 credentials are in `final-suite/socks5-credentials.txt` (mode 0600).
  Do not commit this file to version control.

## Verification

To verify the proxy is working:

```bash
curl -x "socks5h://u4afa4d96ea1f9451:PASS@188.121.111.122:10900" \
     -sS -o /dev/null -w "%{http_code}\n" https://example.com/
# Expected: 200
```
