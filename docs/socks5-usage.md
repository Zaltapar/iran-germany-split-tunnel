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

## Connection-Result Semantics (SOCKS5 status bytes)

As of the Phase 2 multi-carrier work, the Iran SOCKS5 handler returns the
**accurate** RFC 1928 connection-status byte instead of an unconditional
`0x00`. This is the client-visible behavior change introduced by
[`FrameBootstrapAck`](../protocol-frames.md) (Issue #21).

- **`0x00` (success) is sent only after the remote target connection
  actually succeeded** on the Germany node. The handler
  (`handleSOCKS5Conn`, `StartSessionAndWait`) **blocks** for Germany's
  bootstrap verdict before replying, and a
  `clientConnGate` guarantees the `0x00` reply is written to the client
  *before* any downstream payload byte reaches the client.
- On failure the client receives the **specific RFC 1928 code** (internal
  details stay in the log, not on the wire):

  | Byte | Meaning |
  |---|---|
  | `0x01` | general failure (unrecognized error, per-target breaker open, WARP unreachable, or no remote verdict before the bounded wait) |
  | `0x02` | connection not allowed by ruleset (routing block) |
  | `0x03` | network unreachable |
  | `0x04` | host unreachable / DNS failure |
  | `0x05` | connection refused |
  | `0x06` | target dial timed out |

- A local teardown (carrier loss, client abort, node shutdown) that ends the
  stream before any remote verdict arrives is reported as a general `0x01`
  (`BootstrapEndedWithoutResult` is normalized, never `0xFF` reaches the
  wire).

**Practical effect for client tooling:** a `curl`/browser CONNECT that
"worked" on the pre-fix build but whose target was refused or blocked now
surfaces as an accurate non-zero status instead of a false success followed by
a mid-stream drop. Clients that hard-depended on a bogus `0x00` will now see
the real outcome — this is the intended, more-correct behavior.

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
