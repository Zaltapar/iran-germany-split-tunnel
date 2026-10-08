# Tunneldash — Local-Only Monitoring Dashboard

## What This Is

`tunneldash` is a read-only web dashboard and JSON API for monitoring the
Iran and Germany splitter nodes of the split-tunnel deployment. It is a
**local development tool only**: it runs on your workstation, displays
fixture or loopback-collected data, and never writes to or mutates a
production host.

> **⚠️ This implementation does NOT contact, modify, restart, install on,
> or deploy to either production host.**
> It does NOT call Arvan APIs. It does NOT use SSH. No SSH keys, private
> credentials, or secret values are read, copied, or displayed by the
> dashboard.

---

## Safe Defaults (Fail-Closed)

| Invariant | How it is enforced |
|-----------|-------------------|
| Binds to `127.0.0.1` only | `validateListenAddr` refuses any non-loopback host at startup. A non-loopback address causes a hard error before the server starts. |
| Mutations disabled | `readOnly=true` by default. The apply endpoint returns `403 "mutations disabled"` and short-circuits before the (nil) mutator is ever called. |
| No external host access | The default fixture source never dials any address. The HTTP source dials only the `metricsUrl` you configure — in the example config this is empty. The SSH source fails closed: if a server has `sourceType: "ssh"` but no `ssh` sub-config, it contacts nothing and reports `unsupported`; if a sub-config is present it is validated (pinned host keys, fixed command allowlist) before any connection is attempted. |
| Pinned host keys (SSH) | When the SSH collector is enabled, `StrictHostKeyChecking=yes`, `BatchMode=yes`, `PasswordAuthentication=no`, `IdentitiesOnly=yes`, and a pinned `knownHosts` file are hard-coded. Config isolation via `-F /dev/null` and explicit `ProxyCommand=none`/`ProxyJump=none` prevent any inherited SSH config from altering behaviour. The insecure values `no` and `accept-new` are never produced; an unknown or changed host key fails the connection closed. |
| No shell injection (SSH) | Remote commands are a fixed argv allowlist (`hostname`, `uptime -s`, `systemctl show <known>`, `ss -tlnp`, `free -b`, `df -B1 /`, bounded `journalctl`, loopback `curl /metrics`, `cat state.json`). No free-form string from the UI or config ever reaches a shell. Unit names, line counts, and since-windows are validated against enums/bounds. |
| Secrets never displayed | The SSH sub-config carries only absolute *paths* to the identity and pinned known-hosts files — never key material. `state.json` fields matching sensitive markers are redacted before display. |
| No command execution | There is no shell, SSH, or remote-exec endpoint in the API. The only POST endpoints are `config/plan` (dry-run, no mutation) and `config/apply` (refused when `readOnly=true`). |
| No secrets in config | The dashboard config schema (`DashboardConfig`) has no fields for secrets. `RedactConfigValue` masks every value for keys matching `IsSensitiveKey` before it leaves the server. |
| No CORS by default | No `Access-Control-*` headers are set. A future authenticated build may add them explicitly; wildcard CORS is never enabled. |
| Bounded requests | All POST bodies are capped at 64 KiB. Query-param limits (`?limit=N`) are clamped to `maxLogEntries`/`maxAudit`. |
| Path traversal blocked | Server IDs must match `[a-zA-Z0-9_-]{1,64}`. `..`, encoded slashes, and `%2e%2e` are all rejected. |
| Panic recovery | The middleware recovers from panics, logs a stack trace, and returns a JSON `500` without leaking internals. |

---

## Running the Dashboard

### Quick Start (fixture mode, no config file needed)

```bash
# Build
go build -o tunneldash ./cmd/tunneldash

# Run with default config (two fixture servers, loopback bind)
./tunneldash
# → UI at http://127.0.0.1:8080/
# → API at http://127.0.0.1:8080/api/v1/
```

### With a Config File

```bash
# Copy the example and edit it
cp config/tunneldash-example.json my-config.json
./tunneldash -config my-config.json
```

### Flag Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | built-in fixture | Path to a dashboard config JSON file |
| `-listen` | `127.0.0.1:8080` | Override the listen address (must be loopback) |
| `-read-only` | `true` | Force read-only mode (apply endpoint always 403) |
| `-fixture` | `false` | Force fixture data source for all servers |
| `-help` | — | Print flag help |

### Environment Variables

| Variable | Effect |
|----------|--------|
| `DASHBOARD_CONFIG` | Config file path (same as `-config`) |
| `DASHBOARD_LISTEN` | Listen address override (same as `-listen`) |
| `DASHBOARD_READONLY` | Set to `false` to disable read-only (requires a real mutator; the nil mutator still refuses applies) |

---

## Configuration File Schema

```json
{
  "listenAddr": "127.0.0.1:8080",
  "readOnly": true,
  "refreshSec": 10,
  "maxLogEntries": 200,
  "maxAudit": 500,
  "servers": [
    {
      "id": "iran",
      "name": "Iran Splitter",
      "role": "iran",
      "address": "188.121.111.122",
      "metricsUrl": "",
      "sourceType": "fixture",
      "allowMutations": false
    }
  ]
}
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `listenAddr` | string | `127.0.0.1:8080` | Must be loopback; non-loopback is refused at startup |
| `readOnly` | bool | `true` | When true, apply endpoint returns 403 |
| `refreshSec` | int | `10` | Background poll interval in seconds |
| `maxLogEntries` | int | `200` | Cap on `?limit=` for the logs endpoint |
| `maxAudit` | int | `500` | Bounded audit log capacity |
| `servers[].id` | string | — | Unique, must match `[a-zA-Z0-9_-]{1,64}` |
| `servers[].role` | string | — | `"iran"` or `"germany"` |
| `servers[].metricsUrl` | string | `""` | URL to fetch plain-text metrics from (HTTP source only) |
| `servers[].sourceType` | string | `"fixture"` | `"fixture"`, `"http"`, or `"ssh"` (ssh fails closed unless a valid `ssh` sub-config is present) |
| `servers[].ssh` | object | `null` | Strict remote SSH collector config; see [SSH collector](#ssh-collector-sub-config) below |
| `servers[].allowMutations` | bool | `false` | Per-server mutation gate (only relevant when a real mutator is injected) |

The config file must **never** contain secrets. Fields for `SPLIT_SECRET`,
SOCKS credentials, SSH keys, or pairing blobs are not part of the schema
and will be rejected if present (unknown fields are ignored by Go's JSON
decoder; only the fields listed above are used). The `ssh` sub-config
references the identity and pinned known-hosts files **by absolute path
only**; their contents are never read into the dashboard, logged, or
displayed.

<a id="ssh-collector-sub-config"></a>
### SSH collector sub-config

When `sourceType` is `"ssh"`, the `ssh` object must be a complete, pinned
connection description. Missing host-key pinning or any out-of-range bound
rejects the config at load time — the dashboard fails closed and does not
dial a host.

```json
{
  "id": "iran",
  "role": "iran",
  "sourceType": "ssh",
  "ssh": {
    "user": "monitor",
    "address": "188.121.111.122",
    "port": 22,
    "identityFile": "/home/operator/.ssh/monitor_key",
    "knownHosts": "/home/operator/.ssh/pinned_kh",
    "pinnedHostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
    "connectTimeoutSec": 10,
    "commandTimeoutSec": 15,
    "metricsPort": 9101,
    "statePath": "/etc/split-tunnel/state.json",
    "maxJournalLines": 200,
    "maxJournalSinceSec": 600,
    "services": ["iran-splitter", "xray-consumer"]
  }
}
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `user` | string | — | Unprivileged SSH login; must match `[A-Za-z0-9._-]{1,64}`. No shell metacharacters. |
| `address` | string | — | SSH host (name or IP); no spaces or metacharacters. |
| `port` | int | `22` | 1–65535 |
| `identityFile` | string | — | **Required.** Absolute path to the private key. Referenced by path only; contents never read. |
| `knownHosts` | string | — | **Required.** Absolute path to a pinned `known_hosts`. Host-key verification always runs against this file. |
| `pinnedHostKey` | string | — | Optional audit copy of the expected host public key; must also appear in `knownHosts`. |
| `connectTimeoutSec` | int | `10` | 1–300 |
| `commandTimeoutSec` | int | `15` | 1–300. Binds every remote command via `exec.CommandContext`. |
| `metricsPort` | int | `9101` | 1–65535. `curl` reads `http://127.0.0.1:<port>/metrics` on the remote host. |
| `statePath` | string | `/etc/split-tunnel/state.json` | Must be the default path or a file directly under `/etc/split-tunnel/` (no subdirectories, no `..` segments, no trailing slash, no metacharacters). |
| `maxJournalLines` | int | `200` | 1–500. Bounds `journalctl -n`. |
| `maxJournalSinceSec` | int | `0` | 0–86400. Bounds the `--since` window; 0 means line-bound only. |
| `services` | string[] | role default | Must be a subset of the known units. |

**Fixed remote command allowlist.** The collector invokes only:
`hostname`, `uptime -s`, `systemctl show <unit> -p ActiveState,SubState,UnitFileState,MainPID`
(for `services` only), `ss -tlnp`, `free -b`, `df -B1 /`,
`journalctl -u <unit> -n <lines> [--since <rfc3339>] --no-pager -q -o short-iso`,
`curl -sS --max-time <t> http://127.0.0.1:<metricsPort>/metrics`,
and `cat <statePath>`. The remote command is always passed as a discrete
argv vector — never a shell string — so no user input can be concatenated
into a shell.

**Known units** (`services` may only name these): `iran-splitter`,
`germany-splitter`, `xray-consumer`, `xray-germany`.
**Unprivileged-account note.** The configured `user` is expected to be a
non-root monitoring account. Some details therefore may be unavailable and
the collector surfaces that honestly: `ss -tlnp` process PIDs and parts of
`systemctl show` (e.g. `MainPID`) typically require root; when missing they
are omitted rather than guessed. The dashboard now parses and displays
`UnitFileState` (as `enabled`) and `MainPID` (as `mainPid`) from
`systemctl show` so operators can see service enablement state and the
current PID when the account has sufficient privileges.
`journalctl` access depends on the user
having read access to the journal (e.g. membership in the `adm` group).
**Host-key enforcement.** The generated ssh argv always includes
`-F <os.DevNull> -o ProxyCommand=none -o ProxyJump=none -i <identityFile>
-o IdentitiesOnly=yes -o BatchMode=yes -o PasswordAuthentication=no
-o StrictHostKeyChecking=yes -o UserKnownHostsFile=<knownHosts>
-o ConnectTimeout=<t>`.

- `os.DevNull` is `/dev/null` on Linux/macOS, `NUL` on Windows. The SSH
  collector is designed for the Linux-only deployment (the remote commands
  are Linux systemctl/ss/free/df/journalctl).
- `ProxyCommand=none` and `ProxyJump=none` are set explicitly so no proxy
  directive is ever active, even as defence in depth.
- `IdentitiesOnly=yes` is UNCONDITIONAL: only the explicitly provided key
  is used; agent keys and config-file identity files are never attempted.
- The insecure values `no` / `accept-new` are never produced. A mismatched
  or unknown host key aborts the connection; the snapshot records the
  failure and remains read-only.

**Redaction.** Before display, the read of `<statePath>` is parsed using an
explicit allowlist of safe, non-secret fields (role, generation, schema,
updatedAt, manifestHash, configFingerprint, service units, pairing state,
pairing peerRole). Every projected value is additionally passed through
`RedactConfigValue`, which masks any embedded secrets. No secret material
is ever displayed; unknown or sensitive fields in `state.json` are simply
not projected.

---

## API Endpoints

All endpoints are under `/api/v1/` and return `application/json`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/overview` | Health summary, all server cards, last collection timestamp, warnings |
| `GET` | `/api/v1/servers` | List of configured servers (id, name, role, address, source) |
| `GET` | `/api/v1/servers/{id}` | Full snapshot + computed rates for one server |
| `GET` | `/api/v1/servers/{id}/metrics` | Parsed metrics + per-second rates |
| `GET` | `/api/v1/servers/{id}/logs?limit=N` | Bounded log entries (clamped to `maxLogEntries`) |
| `GET` | `/api/v1/servers/{id}/config` | Allowlisted, redacted config values + mutability metadata |
| `POST` | `/api/v1/servers/{id}/config/plan` | Dry-run change plan (validates, returns diff, never applies) |
| `POST` | `/api/v1/servers/{id}/config/apply` | **Returns 403 in default build.** No mutation performed. |
| `GET` | `/api/v1/audit?limit=N` | Bounded local audit event log |
| `GET` | `/api/v1/health` | Dashboard process health + uptime |
| `GET` | `/api/v1/config-keys` | The safe config allowlist (for UI form rendering) |

### Error Schema

All non-2xx responses use:

```json
{ "error": "short message", "details": "optional context" }
```

### `config/plan` Request

```json
{
  "planId": "my-plan-id",
  "changes": [
    { "key": "SPLIT_TARGET_ADDR_POLICY", "value": "prefer-ipv4" },
    { "key": "SPLIT_METRICS_PORT", "value": "9101" }
  ]
}
```

Allowed keys (from `SafeConfigKeys`):

| Key | Type | Roles | Range / Values | Restart |
|-----|------|-------|----------------|---------|
| `SPLIT_METRICS_PORT` | int | both | 1–65535 | yes |
| `SPLIT_RELAY_BUF` | int | both | 1024–8388608 | yes |
| `SPLIT_TARGET_ADDR_POLICY` | enum | both | `default` \| `prefer-ipv4` \| `ipv4-only` | no |
| `SPLIT_TARGET_ONLY_IPV4` | bool | both | `true` / `false` | no |
| `SPLIT_STREAM_OVERFLOW_MS` | int | both | 0–30000 | yes |

Keys that are **never** accepted: `SPLIT_SECRET`, `SPLIT_SOCKS_PASS`,
`SPLIT_SOCKS_USER`, any SSH key material, pairing blobs, WARP controls,
firewall commands, arbitrary environment keys, systemd unit text, or raw
shell commands.

> **`ipv4-only` warning**: `SPLIT_TARGET_ADDR_POLICY=ipv4-only` is a hard
> A-record filter. It breaks AAAA-only endpoints. The planner emits a
> warning when this value is selected.

### `config/apply` Response (default build)

```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "mutations disabled",
  "details": "this dashboard build is read-only; no host was contacted
    and no files were written..."
}
```

The nil mutator is provably **never called** when `readOnly=true`:
the gate short-circuits and writes the 403 before delegating.
`TestAPIServerConfigApplyRefused` asserts `nilMut.Attempts() == 0`.

---

## Web UI

The embedded UI (`/`) is a no-build HTML/CSS/JS dashboard:

- **Overview cards** for Iran and Germany: status badge, active sessions,
  bytes/s up/down, carrier loss events, last collection timestamp.
- **Per-server detail view**: metric table with rates, queue pressure,
  logs, safe config view.
- **Polling**: configurable interval (default 5 s); manual refresh button.
- **Stale / Unreachable / Unsupported badges** on each card.
- **Dry-run plan form** for `SPLIT_TARGET_ADDR_POLICY`,
  `SPLIT_TARGET_ONLY_IPV4`, `SPLIT_METRICS_PORT`, `SPLIT_RELAY_BUF`.
- **Apply button** is disabled and nonfunctional; it is explicitly labeled
  "disabled / read-only" and the server rejects any apply attempt.
- **Warning banner**: "Local fixture / read-only mode. No production hosts
  were contacted. No secrets are displayed."
- No external CDN, no remote fonts, no remote scripts. All assets are
  embedded in the binary via `embed.FS`.

---

## Metric Parsing

The dashboard parses the same hand-rendered plain-text format produced by
`pkg/node/metrics.go` `Metrics.Render()`:

```
active_sessions 5
total_sessions 120
total_bytes_up 1000000
session_close_reason{reason="carrier"} 15
```

- `name value` — plain counter.
- `name{label="..."} value` — labeled counter.
- `# comment` lines and blank lines are skipped.
- Malformed lines are collected into `ParsedMetrics.Errors` without aborting
  the parse.
- Counter resets (current < previous) are detected: the rate is set to 0 and
  `Rate.Reset` is flagged `true` rather than producing a negative throughput.

---

## Secret Redaction

`RedactString` and `RedactConfigValue` ensure that the following patterns
never appear in any API response or UI rendering:

- PEM private key blocks (`-----BEGIN ... PRIVATE KEY-----`).
- Bearer tokens (`Authorization: Bearer <jwt>`).
- JWT strings (three base64url segments).
- URL-embedded credentials (`https://user:pass@host`).
- Sensitive `KEY=VALUE` assignments where the key contains a marker from
  `sensitiveVarMarkers` (secret, password, passwd, pass, token, credential,
  auth, private_key, apikey, ssh_key, socks_user, socks_pass).
- Any key name matching `IsSensitiveKey` is fully masked to `[REDACTED]`
  before display.

Tests in `redact_test.go` prove that secret strings never appear in the
returned `ConfigValue.Value` for known sensitive keys.

---

## Host-Connected Architecture (SSH Read-Only Collector — Implemented, Local Tests Only)

A secure, READ-ONLY SSH host collector is now implemented behind
`sourceType: "ssh"`. It is exercised **only with fake command runners in
tests** — enabling it in a real config is an explicit operator decision and
this change did not contact any host.

- **Fixed allowlist, no shell injection.** The collector runs a strict argv
  allowlist (`hostname`, `uptime -s`, `systemctl show <known unit>`,
  `ss -tlnp`, `free -b`, `df -B1 /`, bounded `journalctl`, loopback
  `curl /metrics`, `cat <statePath>`). The remote command is passed as a
  discrete argv vector via `exec.CommandContext`; no UI/config string is ever
  concatenated into a shell. Unit names, line counts, and since-windows are
  validated against enums/bounds.
- **Pinned, fail-closed host keys.** The generated ssh argv always sets
  `BatchMode=yes`, `PasswordAuthentication=no`, `StrictHostKeyChecking=yes`,
  and a required `UserKnownHostsFile`. The insecure values `no`/`accept-new`
  are never produced; an unknown or changed host key aborts the connection.
- **Bounded outputs and timeouts.** Every remote command runs under
  `exec.CommandContext` with the configured `commandTimeoutSec`; journal
  lines and since-windows are capped. `state.json` fields matching
  sensitive markers are redacted before display.
- **Unprivileged account.** The collector runs as the configured
  non-root `user`; PIDs and some `systemctl`/`journal` fields may be
  unavailable and are omitted rather than guessed.

The following remain **out of scope for this release** and still require
separate design/review before any host access:

1. **Live production use** — no `ssh` sub-config is configured in the
   shipped example; the default config stays fixture-only.
2. **Real mutator** — an `internal/dashboard`-injected mutator that calls
   `splitterctl config set` over SSH or a local agent RPC. It must:
   - be behind an explicit `readOnly=false` AND `allowMutations=true` gate;
   - be tested with a fake mutator before any production use;
   - record every apply in the audit log;
   - never accept arbitrary shell strings from the HTTP request.
3. **Real mutator** — an `internal/dashboard`-injected mutator that calls
`splitterctl config set` over SSH or a local agent RPC. It must:
- be behind an explicit `readOnly=false` AND `allowMutations=true` gate;
- be tested with a fake mutator before any production use;
- record every apply in the audit log;
- never accept arbitrary shell strings from the HTTP request.
4. **Authenticated remote access** — `BearerTokenAuthenticator` is
implemented and tested; it is not wired into the default build. A
future release may serve the dashboard over a local VPN or WireGuard
tunnel to the host and use a bearer token for cross-host API access.

---

## Server-Hosted Mode: TLS + BasePath + Admin Token (One-Click Installer)

The default build stays local-only (loopback, plain HTTP, fixture data). The
one-click installer's Germany deployment runs a **server-hosted** variant
(`NewTLSServer`, `cmd/tunneldash` with the `tls` config block) that keeps
every fail-closed invariant and adds a deliberately narrow public surface.

### Config Schema Extension

```json
"tls": {
  "enabled": true,
  "certFile": "/etc/split-tunnel/dashboard/tls/cert.pem",
  "keyFile":  "/etc/split-tunnel/dashboard/tls/key.pem",
  "basePath":  "3f9c…hex…  (exactly 32 lowercase hex chars)"
}
```

| Invariant | Enforcement |
|-----------|-------------|
| Public bind only with complete TLS | `validateListenAddrSecure`: a non-loopback `listenAddr` is accepted ONLY when `tls.enabled` + `certFile` + `keyFile` + a valid 32-hex `basePath` are all present (`TLSConfig.IsSecure`). Any other non-loopback bind is refused exactly as in the local build. |
| basePath is an access secret | When set, ALL routes (UI + `/api/v1/...`) are mounted under `/<basePath>/`; requests outside the prefix return `404`. The random path is the first layer of access control. |
| Security headers | In TLS mode every response carries `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. |
| Admin bearer token | `LoadAdminToken` reads `SPLIT_TUNNELDASH_TOKEN` (explicit value) or `SPLIT_TUNNELDASH_TOKEN_FILE` (0600 file, by path only). The value is never logged or echoed. It gates mutation endpoints; read endpoints remain reachable under TLS + basePath. |
| Mutations stay disabled | `readOnly` defaults to `true`; `config/apply` returns 403 regardless of the token. |
| Iran-side reachability | The dashboard is hosted on **Germany only**; it never binds a public port on Iran. Iran data is collected by the pinned-SSH collector described above. |

### TLS Provisioning: Existing PEMs vs certbot DNS-01 (Arvan)

The dashboard TLS cert/key live under
`/etc/split-tunnel/dashboard/tls/{cert,key}.pem`
(0640 `root:split-tunnel`). The installer has two ways to populate them:

- **Existing** (`--cert/--key`, or `--dashboard-cert-mode existing`): the
  operator supplies a PEM pair. This is the simplest path when you already
  hold a valid cert for the dashboard domain (e.g. one your CDN/CDN-CDN
  provider handed out).
- **certbot-arvan** (`--dashboard-domain <fqdn> --dashboard-cert-mode
  certbot-arvan`): the installer drives Let's Encrypt DNS-01 through the
  ArvanCloud API via the reusable hook
  [`scripts/certbot-arvan-dns.sh`](../scripts/certbot-arvan-dns.sh). This is
  the correct choice when the dashboard is reached directly by FQDN
  (DNS-only A record, not CDN-proxied) **and** port 443 is already owned by
  xray — no HTTP-01 on :80 or ACME-HTTPS on :443 is needed. The hook reads
  the Arvan API key from a 0600 env file (`ARVAN_API_KEY_FILE`, default
  `/etc/split-tunnel/arvan/env`), creates the `_acme-challenge.<leaf>` TXT
  record on the Arvan zone, waits for public DNS propagation, and deletes
  the record after the challenge is verified. The key is passed to `curl`
  via a 0600 `-K` config file and is never printed to stdout, logs, or
  argv.

After the first successful issuance the installer writes a certbot
**deploy hook** to
`/etc/letsencrypt/renewal-hooks/deploy/split-tunnel-dashboard.sh` that
re-copies the live PEMs into the TLS dir and `systemctl restart
tunneldash.service` on every `certbot renew` (driven by the `certbot.timer`).

See [oneclick-install.md](oneclick-install.md) for the full prerequisites,
exact commands, renewal, and rollback procedure.

### Token / BasePath / Cert Rotation

1. Generate new values: `openssl rand -hex 16` (basePath),
   `openssl rand -hex 32` (token), and replace the PEMs under
   `/etc/split-tunnel/dashboard/tls/` for cert rotation.
2. Update `tls.basePath` in the config JSON and the 0600 token file
   (`/etc/split-tunnel/dashboard/token` — referenced by the env file via
   `SPLIT_TUNNELDASH_TOKEN_FILE` only, never by value).
3. `systemctl reload tunneldash` (the hardened unit permits the reload;
   the basePath value is never printed by the installer or CLI — read it
   from `/etc/split-tunnel/dashboard/config.json` and keep it recorded).

### Verification Commands

```bash
# Format check (must be empty)
gofmt -l ./internal/dashboard/ ./cmd/tunneldash/

# Build
go build ./internal/dashboard/... ./cmd/tunneldash/...

# Vet
go vet ./internal/dashboard/... ./cmd/tunneldash/...

# Run all tests
go test ./internal/dashboard/... -count=1 -v

# Race detector (Linux only; skip on Windows)
go test ./internal/dashboard/... -count=1 -race
```

---

## Explicit Statement

**This task did not contact, modify, install on, restart, or deploy to
either production host (188.121.111.122 / 91.107.152.1). No SSH sessions
were opened. No Arvan API calls were made. No git commit or push was
performed. No files were written to `/etc/split-tunnel/` on either host.**

All data displayed in fixture mode is synthetic and deterministic; it does
not represent live production state.
