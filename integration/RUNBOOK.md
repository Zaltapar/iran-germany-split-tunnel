# Issue #9 — Two-Server Production Acceptance (L5) Runbook

This runbook is the L5 half of Issue #9. L4 (the two-process local gate)
lives in `integration/twoproc_test.go`; this document defines the REAL
two-server acceptance test: two staging endpoints, real network between
them, the full 20-scenario matrix, and the record format.

**Status: HARNESS DESIGNED, AWAITING STAGING INFRASTRUCTURE.** The GitHub
issue MUST NOT be closed until the matrix below has actually been executed
on the staging topology (twice, once with race builds) and the results are
recorded in `IMPLEMENTATION_STATUS.md` ("Integration test record" section).

---

## 1. What Issue #9 must prove

The in-process tests (`pkg/node`, `e2e-pipe-test`) and the L4 gate prove
the engine and the local wiring. They do NOT prove:

1. The real binaries survive a real cross-host deployment (OS TCP stack,
   TIME_WAIT, backlog, real RTT/jitter on both carrier paths).
2. The documented consumer path works with a REAL Xray (inbound → routing
   → SOCKS outbound → splitter).
3. The carrier transports behave over their real paths (CDN WebSocket
   termination, VLESS+Reality tunneling).
4. Resource behavior (memory/goroutines/fds) is bounded under real
   multi-session load on real hosts.
5. Failure/recovery (process death, carrier loss, blackhole) works with
   systemd-managed processes on two machines.

## 2. Staging topology

```
                        INTERNET
   ┌──────────────┐   ┌──────────────────────────────────────────┐
   │  CLIENT (3)  │   │              STAGING NETWORK              │
   │ SOCKS5 test  │   │                                            │
   │ client +     │   │   ┌─────────────┐      ┌─────────────┐   │
   │ Xray(10 opt)├───┼───►│  IRAN (1)   │      │ GERMANY (2)  │   │
   └──────────────┘   │   │ :10900 socks│◄────►│ :9002 down   │   │
                      │   │ :9001 ws    │ CDN  │ up ws client │   │
                      │   │ →Reality    │ path │ → target     │   │
                      │   └─────────────┘      └─────────────┘   │
                      │                                            │
                      │   down-carrier: Iran Reality outbound     │
                      │     → internet → Germany :443 Reality    │
                      │     inbound → 127.0.0.1:9002             │
                      └──────────────────────────────────────────┘
```

### 2.1 Required vs optional vs test-only

| Dependency | Class | Notes |
|---|---|---|
| Iran staging host | **required** | see 2.2 |
| Germany staging host | **required** | see 2.2 |
| Client host | **required** | any host that can reach Iran's SOCKS port and Germany's internet (for the down-carrier dial test); may be the Iran host |
| Public domain for the up-carrier | **required** | the Germany node dials `wss://<domain>/upload`; a bare IP cannot (the config validator requires a host, and the production path is CDN-fronted) |
| CDN in the up path | **optional** | a direct TLS-terminated origin (nginx + cert on the domain) is a SUFFICIENT stand-in; run the matrix once with it, and once through the real CDN if available |
| VLESS+Reality on the down carrier | **required for L5** | this IS the down-carrier transport; the L4 gate substitutes a local TCP proxy |
| Xray on Iran (scenario 10) | **optional but strongly recommended** | proves the documented consumer path; the splitter's SOCKS server is exercised directly in all other scenarios |
| iptables / tc netem access | **test-only** | needed for the blackhole + loss/jitter scenarios |
| systemd | **required** | restart/recovery semantics are the systemd ones |

### 2.2 Host requirements

| | Iran (1) | Germany (2) | Client (3) |
|---|---|---|---|
| OS | Linux (any recent; the binaries are pure Go) | same | any |
| CPU/RAM | 1 vCPU / 1 GiB minimum (test load is small) | same | trivial |
| Outbound ports | → Germany Reality inbound (443) | → Iran CDN domain (443) | → Iran SOCKS port |
| Inbound ports | SOCKS port (from client + Iran Xray only), WS origin port (CDN/origin only) | Reality inbound port (from the Internet — Reality is the auth boundary), nothing else | — |
| Firewall | allow client→SOCKS; allow origin→WS; block everything else | allow inbound Reality port; block direct :9002 (only the Reality tunnel reaches it) | — |
| Splitter config | `SPLIT_SOCKS_LISTEN=127.0.0.1:<socks>`, `SPLIT_WS_LISTEN=127.0.0.1:9001`, `SPLIT_DOWN_CARRIER_ADDR=127.0.0.1:<reality-local>`, `SPLIT_METRICS_PORT=<m>` | `SPLIT_UP_WS_URL=wss://<domain>/upload`, `SPLIT_DOWN_LISTEN=127.0.0.1:9002`, `SPLIT_METRICS_PORT=<m>` | SOCKS client pointed at Iran |
| Secrets | `SPLIT_SECRET=<64-hex>` | same value | — |

Secrets are **generated per staging run** (`openssl rand -hex 32`) and are
never written into this repo or the results record (Issue #9 acceptance #6).

**The two hosts are staging-only. Nothing in this procedure touches the
production servers. Do not run the matrix against production.**

### 2.3 Provisioning (one-time, per host)

```
Iran:
  sudo bash install.sh iran   (guided; or non-interactive with flags)
  + nginx/CDN origin for /upload → 127.0.0.1:9001
  + (optional) Xray configured per README "Xray Config (Iran)"
Germany:
  sudo bash install.sh germany --up-ws-url wss://<domain>/upload
  + Xray/3x-ui inbound: VLESS+Reality on the public port, delivering the
    tunneled TCP bytes to 127.0.0.1:9002  (operator's own Xray config;
    this project does not manage it)
```

Verify baseline before the matrix: both units active, both metrics
endpoints up, `curl --socks5-hostname 127.0.0.1:<socks> https://example.com`
works from the client host.

## 3. Acceptance matrix (20 scenarios)

Legend: **A** = assertion (objective; "looks connected" is never an
assertion). Every scenario lists setup / action / assertion / timeout.
The L4 gate implements scenarios 1–2, 4–9, 11–13, 14, 15, 16, 18 (partial),
19 over local sockets; the L5 run adds the real-network variants plus
scenarios 3, 10, 17, 18 (full), 20.

| # | Scenario | Setup | Action | Assertion (objective) | Timeout |
|---|---|---|---|---|---|
| 1 | SOCKS5 CONNECT (IPv4) | topology up | client CONNECTs to `104.x.y.z:<port>` (or a staging-local IPv4) | SOCKS reply 0x00; TCP established through the tunnel (echo 1 byte); `total_sessions` +1 on both nodes; `session_count` returns to 0 after FIN | 30 s |
| 2 | Domain destination | as 1 | CONNECT to `example.com:443` (real DNS on Germany) | reply 0x00; TLS handshake bytes flow both ways (capture first 5 bytes of each direction); no `errors` delta | 30 s |
| 3 | IPv6 destination | Germany has IPv6 egress | CONNECT to `[2001:4860:4860::8888]:443` (or any public AAAA) | reply 0x00; bytes flow; `total_bytes_up`/`_down` deltas ≥ 1 | 30 s |
| 4 | Sustained upload | echo target (staging HTTP echo or netcat) | client → 10 MiB through the tunnel | sha256 of the echoed bytes == sha256 of the payload; `total_bytes_up` delta ≥ 10 MiB; no `errors` | 120 s |
| 5 | Sustained download | target with ≥10 MiB static file | download through the tunnel | sha256 matches; `total_bytes_down` delta ≥ 10 MiB | 120 s |
| 6 | Simultaneous sessions | as 1 | 16 concurrent CONNECTs, each transferring 1 MiB | all 16 checksums exact; `total_sessions` delta ≥ 16; `active_sessions` settles to 0; no session >5 s in Pending | 120 s |
| 7 | Upload-carrier failure | live session transferring | `iptables -I OUTPUT -p tcp --dport <cdn> -j DROP` on Germany (or kill the CDN leg) | both nodes log `carrier up lost`; within grace+reconnect the session rebinds (`sessions_recovered` +1 on Iran OR `carrier_rebinds` +1); transfer completes with exact checksum | 90 s |
| 8 | Download-carrier failure | live session | `iptables -I OUTPUT -p tcp --dport <reality-in> -j DROP` on Iran (or kill the Reality tunnel) | both nodes log `carrier down lost`; rebind completes; data intact | 90 s |
| 9 | Carrier reconnect/rebind (clean) | as 7/8 but restore immediately | drop for exactly 3 s, restore | `carrier_reconnects` +1 on the dialing side; `carrier_loss_events` +1; session data intact; `sessions_lost_after_carrier_failure` == 0 | 90 s |
| 10 | Xray consumer path | Xray on Iran per README | Xray inbound (VLESS) → routing rule → `to-splitter` SOCKS outbound → tunnel | a request issued through the Xray inbound (e.g. `curl --proxy socks5h://127.0.0.1:<socks>` is the splitter-direct equivalent; the Xray path is verified by a client configured for the Xray VLESS inbound reaching the internet) succeeds with exact content; `total_sessions` +1 | 60 s |
| 11 | Blackhole detection | `SPLIT_LIVENESS_ROUNDS=1` (staging value), keepalive 30 s | `iptables -I INPUT -p tcp --dport <cdn> -j DROP` on Iran one-way (packets silently lost, no RST) | within `30s × 1 round + ε` the node logs carrier loss and tears the carrier down; `carrier_loss_events` +1; no hung session | 120 s |
| 12 | Authentication failure | topology up | a rogue process dials Germany `:9002` (or the up path) with a wrong secret | connection closed during the handshake; `errors` unchanged or +1 locally; the real carrier keeps working (next session succeeds) | 30 s |
| 13 | Malformed peer | topology up | a rogue process opens the up/down path, upgrades/accepts, then sends garbage frames | the connection is terminated or the frames dropped; NO panic (process still active: `systemctl is-active` == active); no session created | 30 s |
| 14 | Client half-close | echo target | client `CloseWrite` mid-session | target observes FIN (echo server logs EOF); the session ends cleanly; `session_count` → 0 | 30 s |
| 15 | Target half-close | target that reads then `CloseWrite`s | download until target FIN | client observes EOF; `session_count` → 0; no `errors` | 30 s |
| 16 | Target failure | a reachable host with a closed port | CONNECT to the closed port | SOCKS reply **0x06** — by design the relay maps every target-dial failure (refused/unreachable/timeout) to general-failure on the wire (no reason leakage, `pkg/node` StartSession error path); the round trip is BOUNDED (≤ ~15 s = 10 s target dial + bootstrap) — no hang, never 0x00; `total_sessions` +1 with immediate close | 30 s |
| 17 | Repeated flapping | as 7 | 5× {drop 3 s → restore 5 s} | after each cycle: session intact (data checksum at the end), `sessions_lost_after_carrier_failure` == 0, `carrier_loss_events` +5, no goroutine/fd growth beyond one per cycle | 10 min |
| 18 | Resource settling | idle 5 min → 16-session burst (scenario 6) → idle 5 min | sample `ps` RSS + `ls /proc/<pid>/fd | wc -l` + metrics gauges every 10 s | RSS after settling ≤ peak + 10 MiB; fd count returns to the idle baseline ±2; `session_count` == 0; `session_buffered_bytes` == 0 | 15 min |
| 19 | Graceful shutdown | topology up, no active sessions | `systemctl stop germany-splitter` then `systemctl stop iran-splitter` | each exits 0; journal shows `... stopped` as the last line; no zombie conns (fd count 0 before exit) | 30 s each |
| 20 | Restart/recovery | as 19 | `systemctl start` both, then run scenario 1 | carriers re-authenticate within the backoff schedule; a new session works; metrics counters are fresh (new processes) | 90 s |

**"No unresolved CRITICAL/HIGH finding"** gate: any scenario failure is
either fixed (new commit, re-run the FULL matrix) or filed as its own issue
with the repro. The issue does not close with a failing scenario.

## 4. Execution record format

After each full run, append to `IMPLEMENTATION_STATUS.md` under a new
`## Integration test record` section:

```
### L5 run N — <date, UTC> — commit <sha>
- Hosts: Iran <distro/kernel>, Germany <distro/kernel>, client <distro>
- Go <version> (race: yes/no), binaries built from <sha>
- Topology: up=<domain via CDN|direct-origin>, down=VLESS+Reality,
  keepalive=30s, liveness=1, grace=<default>
- Matrix: 20/20 pass | pass list | failures (→ issue refs)
- Resources: peak RSS Iran/Germany, fd baseline→burst→settled
- Run twice: run 2 = <same result / deltas>
- Verdict: ACCEPT / REJECT (with reason)
```

## 5. Reproducibility

- Two operators can reproduce from this file: provisioning (2.3),
  firewall (2.2), matrix (3), record format (4).
- The L4 gate is the fast regression for everything except scenarios 3, 10,
  11 (real blackhole), 17 (multi-cycle), 18 (host-level resources): run
  L4 in CI-on-demand (`workflow_dispatch`), L5 on staging per release.