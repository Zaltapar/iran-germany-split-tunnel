# Deployment record — control plane + WARP outbound (2026-10-13)

Facts-only record. No credentials, no key material, no basePath.

## Germany (root@91.107.152.1, Hetzner, Ubuntu 24.04)

### Deployed binaries (verified by sha256)

| Binary | Source commit | sha256 (prefix) |
|---|---|---|
| `/opt/split-tunnel/germany-splitter` | 609ee95 | `501270da...` |
| `/opt/split-tunnel/splitterctl` | 609ee95 (re-deployed later, AB59857B) | `AB59857B...` |
| `/opt/split-tunnel/tunneldash` | 8c83583 | `E49719C1...` |

### Service state
- `germany-splitter` active.
- `xray-germany` active; config at `/etc/split-tunnel/xray-germany.json`, mode `0640`, owner `root:split-tunnel-xray` (C5 key isolation live).
- `tunneldash` active; control-agent socket active.

### C4 routing
- Routing ON with rules: `.openai.com -> warp`, `.warp-test.example -> warp`, default `direct`.
- Direct egress verified: `91.107.152.1`.
- WARP egress verified via SOCKS5 `socks5h://127.0.0.1:40000`: `104.28.193.116`.
- Fail-closed verified: stopping `warp-svc` causes WARP-routed flows to fail closed.

### Dashboard control plane (proven end-to-end)
- validate `200`, apply `200`, freeze `423`, unfreeze `200`, audit `3` entries, flag-off `503`.
- Final safe state: `routingApply=off`, `applyEnabled=on`, `socketPath` set.

## Iran (188.121.111.122)

### Deployed binaries
- `/opt/split-tunnel/iran-splitter` sha256 `82d9482c...`
- `/opt/split-tunnel/splitterctl` sha256 `AB59857B...` (re-deployed after Germany control-CLI fix)

### Service state
- `iran-splitter` active; control-agent socket active with peer uid 999 / gid 988 / exe `/opt/split-tunnel/tunneldash`.
- env byte-identical to the verified baseline.
- SOCKS5 on port 204 verified; egress `91.107.152.1`.

## Linux-only defects found and fixed in 609ee95

1. **`internal/controlagent/peercheck_linux.go` — SO_PEERCRED optlen pointer.**
   `getsockopt(SO_PEERCRED)` passed the optlen *value* (`unsafe.Sizeof(cred)` = 12)
   as the 6th `SYS_GETSOCKOPT` argument. The kernel requires a *pointer* to a
   `socklen_t`; it dereferenced address 12 and returned `EFAULT`, so the peer check
   always failed closed and every dashboard control call RST'd to `503
   agent_unavailable`. Production-only on Linux (the `//go:build linux` path never
   compiles on the Windows test host, and unit tests use a fake credential source).
   Verified fixed with standalone probes `peercred_probe.go` / `peercred_probe2.go`
   (archived in `final-suite/`).

2. **`cmd/splitterctl/control.go` — control CLI argv index.**
   `main.go` strips the `control` verb before dispatch (`args[1:]`), but
   `controlCmd` indexed its subcommand at `args[1]`, so every C2 operator
   subcommand (freeze/unfreeze/revert-lkg/audit-verify/recover) hit the
   `len(args)<2` guard and returned a usage error. Fixed by aligning
   `controlCmd` to the actual call convention (subcommand at index 0), matching
   `controlC3Cmd`.

## Backup paths and rollback

Germany:
- Backup dir: `/root/split-tunnel-backups-<TS>-tunneldash-control`
  (dashboard `config.json` + `tunneldash` binary + ownership record +
  `MANIFEST.sha256`, manifest verified with `sha256sum -c`).
- WARP install backup: `/root/split-tunnel-backups-20261012080559-warp`
  (apt sources, keyrings, warp-svc mask record, `MANIFEST.sha256`).
- Rollback:
  ```
  cd /root/split-tunnel-backups-<TS>-tunneldash-control
  sha256sum -c MANIFEST.sha256
  install -m 640 -o root -g split-tunnel config.json /etc/split-tunnel/dashboard/config.json
  install -m 755 tunneldash-before /opt/split-tunnel/tunneldash
  systemctl restart tunneldash
  ```
- WARP rollback (undo install only): `systemctl stop warp-svc && systemctl mask warp-svc
  && warp-cli disconnect && apt-get remove -y cloudflare-warp` (default route and
  tunnel services were never touched).

Iran:
- Backup dir: `/root/split-tunnel-backups-<TS>-<component>` (binary + env +
  ownership record + manifest).
- Rollback: `sha256sum -c MANIFEST.sha256` then restore binary + env and
  `systemctl restart iran-splitter`.
