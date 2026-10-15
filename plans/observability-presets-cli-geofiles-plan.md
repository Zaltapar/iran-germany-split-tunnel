# Implementation Plan — Log Levels, Live Logs, Routing Presets, Refined Dashboard, Operator CLI, Geofiles

Status: DESIGN ONLY. No code, config, or tracked file was changed. No host was contacted.
Branch context: `feat/multi-carrier-phase2`.
Scope: 6 requested features — (A) log level, (B) live logs, (C) routing presets, (D) refined dashboard, (E) Linux CLI commands, (F) geofiles / searchable website groups.

Evidence labels:
- [V] Verified by reading the named file/lines during this session.
- [P] Taken from a plans/ doc, not re-read in code.
- [A] Assumption; must be verified before the phase that depends on it.

Line references are to the files as they exist on this branch.

---

# PART 1 — CURRENT-STATE MAP

## 1.1 Dashboard (`cmd/tunneldash/main.go` + `internal/dashboard/`)

### Entry point: `cmd/tunneldash/main.go` (261 lines, `package main`)

| Function | Lines | Role |
|---|---|---|
| [`main()`](cmd/tunneldash/main.go:51) | 51–227 | Flags, config load/override, component wiring, signal handling, serve |
| [`resolveAuthenticator()`](cmd/tunneldash/main.go:236) | 236–260 | Basic-auth PBKDF2 → deprecated Bearer → loopback fallback; returns the fail-closed error the caller decides on |
| `var buildInfo` | 49 | `-ldflags -X main.buildInfo=<sha>` stamp from `scripts/build-linux.sh` |

Flag surface ([`main.go:61-86`](cmd/tunneldash/main.go:61)): `-config`, `-listen`, `-read-only`, `-fixture`, `-validate-config`, `-version`. Framework is **stdlib `flag`** with a custom `fs.Usage`. Env overrides `DASHBOARD_CONFIG`, `DASHBOARD_LISTEN`, `DASHBOARD_READONLY` (documented [`main.go:78-84`](cmd/tunneldash/main.go:78)).

Wiring order in `main()` ([`main.go:143-186`](cmd/tunneldash/main.go:143)):
1. `cache := dashboard.NewCache(cfg)` (line 143)
2. `audit := dashboard.NewAuditLog(cfg.MaxAudit)` (line 144)
3. `auth, err := resolveAuthenticator()` (line 153); TLS build fails closed on error, loopback build falls back (lines 155-164)
4. `server := dashboard.NewTLSServer(cfg, cache, audit, nil, auth)` (line 167) — **nil mutator** = the safe default
5. `server.SetControlAgent(dashboard.NewControlClient(cfg.Control.SocketPath))` when `cfg.Control.SocketPath != ""` (lines 181-185)
6. `ctx, cancel := context.WithCancel(...)` + SIGINT/SIGTERM (lines 187-197)
7. TLS branch → [`server.ListenAndServeTLS(ctx)`](internal/dashboard/tls.go:154) (line 213); plain branch → [`server.ListenAndServe(ctx)`](internal/dashboard/server.go:171) (line 224)

There is **no `-log-level` flag and no log-level plumbing anywhere in main.go**; all output is `log.Printf`/`log.Fatalf` (22 call sites, [`main.go:107,108,132,138,157,162,183,195,201,203,206,208,212,214,219,221,222,225,241`](cmd/tunneldash/main.go:107)).

### HTTP framework and routes

**stdlib `net/http` + `http.NewServeMux()`** — no third-party router. `gorilla/websocket` is in `go.mod` but is used only by the splitters' carrier transport (`cmd/germany-splitter/main.go:62`), not by the dashboard.

[`Server.Router()`](internal/dashboard/server.go:97) registers (lines 101-113):

```
mux.HandleFunc("/api/v1/overview",       s.apiHandler(s.handleOverview))
mux.HandleFunc("/api/v1/servers",        s.apiHandler(s.handleServers))
mux.HandleFunc("/api/v1/servers/",       s.apiHandler(s.handleServerSub))
mux.HandleFunc("/api/v1/audit",          s.apiHandler(s.handleAudit))
mux.HandleFunc("/api/v1/health",         s.apiHandler(s.handleHealth))
mux.HandleFunc("/api/v1/config-keys",    s.apiHandler(s.handleConfigKeys))
mux.HandleFunc("/api/v2/",               s.handleV2)          // GET/HEAD only + a closed POST set
mux.HandleFunc("/",                      s.serveUI)           // embedded UI
```

**API v2 dispatch** is hand-rolled path-segment routing in [`handleV2`](internal/dashboard/api_v2.go:160): `v2Segments(path)` → `parts[0]` switch (lines 221-335). Current read endpoints:

| Route | Handler | Lines |
|---|---|---|
| `/api/v2/overview` | [`v2Overview`](internal/dashboard/api_v2.go:670) | 233-237 |
| `/api/v2/hosts` | [`v2HostsResponse`](internal/dashboard/api_v2.go:723) | 238-242 |
| `/api/v2/carriers` | [`v2CarriersResponse`](internal/dashboard/api_v2.go:730) | 243-247 |
| `/api/v2/outbounds` | [`v2OutboundsResponse`](internal/dashboard/api_v2.go:738) | 248-252 |
| `/api/v2/routing` | [`v2RoutingView`](internal/dashboard/api_v2.go:600) | 253-257 |
| `/api/v2/config` | [`v2ConfigResponse`](internal/dashboard/api_v2.go:750) | 258-262 |
| `/api/v2/events?limit=N` | [`v2Events`](internal/dashboard/api_v2.go:771) | 263-267 |
| `/api/v2/timeseries?series=...&points=N` | [`v2Timeseries`](internal/dashboard/api_v2.go:837) | 268-272 |
| `/api/v2/schema/{concept}` | `ConceptSchemas()` / C1/C3/C4 branches | 273-315 |
| `/api/v2/validate/{concept}` | stub, 405 on POST | 316-333 |
| `/api/v2/revisions`, `/api/v2/audit` | C2 forwarding | 223-232 |
| POST `/api/v2/changes/validate` | [`c1HandleChangesValidate`](internal/dashboard/control_c1.go) | 169-172 |
| POST `/api/v2/changes/{id}/apply` | [`c2HandleChangesApply`](internal/dashboard/control_c2.go) | 173-176 |
| POST `/api/v2/changes/{id}/inbounds-validate\|inbounds-apply\|inbounds-rotate` | C3 | 179-193 |
| POST `/api/v2/changes/{id}/routing-validate\|routing-apply` | [`c4HandleRoutingValidate`](internal/dashboard/control_c4.go:367) / [`c4HandleRoutingApply`](internal/dashboard/control_c4.go:464) | 197-204 |
| POST `/api/v2/changes/{id}/multicarrier-validate\|multicarrier-apply` | C4 | 205-212 |

v1 endpoints ([`server.go:327-800`](internal/dashboard/server.go:327)): `handleOverview`, `handleServers`, `handleServerSub` (dispatch to `handleServerMetrics` :494, `handleServerLogs` :524, `handleServerConfig` :581, `handleConfigPlan` :620, `handleConfigApply` :681), `handleAudit` :762, `handleHealth` :784, `handleConfigKeys` :799.

### UI serving

[`ui.go`](internal/dashboard/ui.go) — **`//go:embed static/*`** (line 11-12). [`serveUI`](internal/dashboard/ui.go:18) serves `static/index.html` at `/` and assets under `/static/` with `mimeFromExt` (line 57). Assets: `static/index.html`, `static/app.js`, `static/style.css`. **No templates, no external CDN** — enforced by [`TestStaticNoExternalURLs`](internal/dashboard/static_assets_test.go:42).

The UI is a **vanilla-JS single page with hash routing** (`app.js`): nav links `#overview #hosts #tunnels #routing #outbounds #inbounds #control #network #config #logs` ([`static/index.html:18-28`](internal/dashboard/static/index.html:18)). Renderers: `renderOverview` :456, `renderHosts` :518, `renderCarriers` :546, `renderRouting` :604, `renderOutbounds` :838, `renderInbounds` :1029, `renderControl` :1053, `renderNetwork` :1215, `renderConfig` :1238, `renderEvents` :1265, `renderV1Detail` :1348. Data fetch is `getJSON`/`v2()` helpers (:106, :133) over `fetch` with `setInterval(refresh, sec*1000)` polling (:1462-1463).

### Live/streaming capability today

**None.** No SSE, no WebSocket, no `EventSource`. The only "live" mechanism is **client-side polling** (`state.pollTimer = setInterval(...)`, [`app.js:1463`](internal/dashboard/static/app.js:1463)) against the GET endpoints, plus a server-side background [`pollLoop`](internal/dashboard/server.go:219) that refreshes the `Cache` every `RefreshSec`. This is the single most important constraint for the "live logs" design.

### How it gets its data

- **[`Cache`](internal/dashboard/cache.go)** holds `ServerSnapshot`s; `Refresh` drives the [`Collector`](internal/dashboard/collector.go) chain: `fixture` / `http` / `ssh`.
- **SSH collector** ([`ssh_collector.go`](internal/dashboard/ssh_collector.go)) shells out to `ssh` with a **fixed argv allowlist** (`BuildJournalArgs`, `BuildSystemctlArgs`, `BuildSSArgs`, `BuildFreeArgs`, `BuildDFArgs`, `BuildMetricsArgs`, `BuildStateArgs` in `ssh_config.go`) and **parses `journalctl` output** into `LogEntry`s ([`ssh_collector.go:135-148`](internal/dashboard/ssh_collector.go:135)).
- [`KnownUnits`](internal/dashboard/ssh_config.go:19) = `iran-splitter`, `germany-splitter`, `xray-consumer`, `xray-germany` (**note: `tunneldash` is NOT in this allowlist** — it must be added for the dashboard to tail its own logs).
- **`LogEntry`** shape ([`types.go:54-59`](internal/dashboard/types.go:54)): `{Timestamp, Level, Message}` — **`Level` already exists in the model** but is populated from journal short-iso parsing only.

### Docs read

- [`docs/tunneldash.md`](docs/tunneldash.md) — 722 lines. Safe-defaults table (lines 19-34), flag reference (62-68), env vars (70-76), config schema (80-116), control-plane section (118-186), SSH collector sub-config (188+). Key invariants that constrain this plan: **loopback-only bind by default** (line 23), **mutations disabled by default** (line 24), **fixed argv allowlist, no free-form remote command** (line 27), **no secrets displayed** (line 28), **bounded requests 64 KiB** (line 32), **path traversal blocked** (line 33).
- [`plans/dashboard-control-design.md`](plans/dashboard-control-design.md) — 1611 lines. §3.2 the chosen trust model: root-owned `splitterctl control-agent` on `/run/split-tunnel-ctl/control.sock` with `SO_PEERCRED` + `/proc/<pid>/exe` check (lines 106-115); the web process never runs xray/systemctl/writes `/etc/split-tunnel` (line 109). Protocol v1 newline-delimited JSON, one frame per connection, `MaxFrameBytes = 16 KiB` (lines 117-119). §12 C2/C3/C4 phasing. **F-8 (no live routing)** at line 83 and **D9** are directly relevant: the dashboard's `routing-rule`/`routing-policy` concepts are display-only; the real engine is `pkg/routing`.

---

## 1.2 Routing engine (`pkg/routing/`)

Pure package — **no `internal/*` imports** (enforced by `internal/archtest`), no I/O beyond the rules file.

### Rule struct (verbatim, [`pkg/routing/rule.go:190-232`](pkg/routing/rule.go:190))

```go
type Rule struct {
	ID string `json:"id"`          // required, non-empty, unique
	Enabled bool `json:"enabled"` // absent key => ENABLED
	Match Match `json:"match"`
	Action string `json:"action"` // "direct" | "warp" | "block"
	Fallback string `json:"fallback,omitempty"` // "direct" only, warp-only
	Comment string `json:"comment,omitempty"`

	mCIDR      *net.IPNet
	mKW        string
	mDom       string
	mDomSuffix bool
}

type Match struct {
	Domain   string `json:"domain,omitempty"`    // ".x.com" suffix or "x.com" exact
	Keyword  string `json:"keyword,omitempty"`   // case-insensitive substring
	IPCIDR   string `json:"ip_cidr,omitempty"`   // literal-IP hosts only
	PortMin  int    `json:"port_min,omitempty"`
	PortMax  int    `json:"port_max,omitempty"`
}

type RuleSet struct {
	Version        int    `json:"version"`         // must be 1
	DefaultAction  string `json:"default_action"`  // "direct"|"warp" (never "block")
	Rules          []Rule `json:"rules"`           // first match wins
}
```

### Config-file format (verbatim shape)

```json
{
  "version": 1,
  "default_action": "direct",
  "rules": [
    {"id":"instagram-warp","enabled":true,
     "match":{"domain":".instagram.com"},
     "action":"warp","fallback":"direct","comment":"Meta via WARP"},
    {"id":"block-ads","enabled":true,
     "match":{"keyword":"ads"},"action":"block"}
  ]
}
```

### Load / validate / apply

- [`LoadRulesFile(path)`](pkg/routing/rule.go:450) — `os.Stat` size gate (`MaxConfigBytes = 64 KiB`, line 84), `os.ReadFile`, → [`ParseRules`](pkg/routing/rule.go:470).
- [`ParseRules`](pkg/routing/rule.go:470) — `dec.DisallowUnknownFields()` at top level AND inside every rule ([`Rule.UnmarshalJSON`](pkg/routing/rule.go:238), also strict). → [`RuleSet.Sanitize`](pkg/routing/rule.go:285).
- [`Sanitize`](pkg/routing/rule.go:285) — version must be 1; `default_action` empty → `"direct"`; `"block"` default refused; `MaxRules = 500`; unique non-empty ids; per-rule [`validateRule`](pkg/routing/rule.go:323).
- [`validateRule`](pkg/routing/rule.go:323) — action required/valid; fallback only `"direct"` and only on warp; **at least one match criterion required (no catch-alls)**; domain validated by [`validateDomain`](pkg/routing/rule.go:405) (lowercase RFC 1123, no wildcards, leading `.` allowed); CIDR via `net.ParseCIDR`; port range 1..65535 and `min<=max`. Precomputes `mCIDR/mKW/mDom/mDomSuffix`.

### Hot-reload: **NONE.** Rules are pinned at construction. Explicit in [`engine.go:12-16`](pkg/routing/engine.go:12): "Existing sessions are unaffected by a later rule-set change (rules are pinned at dial time — a rules reload **RESTARTS the splitter service**, which is the C4 apply path's documented behavior)". The engine is immutable after [`New`](pkg/routing/engine.go:111) and safe for concurrent use (line 47-49).

### Matching capabilities ([`pkg/routing/matcher.go`](pkg/routing/matcher.go))

[`matchRule`](pkg/routing/matcher.go:54): enabled check → [`PortInRange`](pkg/routing/matcher.go:40) AND-precondition → OR of [`matchDomain`](pkg/routing/matcher.go:78) / [`matchKeyword`](pkg/routing/matcher.go:93) / [`matchCIDR`](pkg/routing/matcher.go:100).
- Domain: suffix (`.example.com`) or exact, case-insensitive, **never matches an IP literal**.
- Keyword: case-insensitive substring on the raw host string (names AND IPs).
- CIDR: `net.IPNet.Contains` on literal-IP hosts only (v4 and v6).
- **NO regex** (deliberate, rule.go:150-155), **NO geosite/geoip**.
- [`Evaluate`](pkg/routing/matcher.go:122): first enabled match wins; returns `(OutboundKind, ruleID)` where `ruleID==""` means the default applied.

### Actions

[`OutboundKind`](pkg/routing/rule.go:87): `OutboundDirect` (0), `OutboundWarp` (1), `OutboundBlock` (2). [`ParseOutboundKind`](pkg/routing/rule.go:115) accepts exactly `direct|warp|block`; unknown is a hard error.

### WARP and how a rule is marked WARP-routed

A rule is WARP-routed by `"action":"warp"`. [`Engine.Dial`](pkg/routing/engine.go:186) → [`dialWarp`](pkg/routing/engine.go:242) issues a **SOCKS5h CONNECT** (domain-form atype 0x03, IP-form atype 0x01) to `warpAddr`. Health gate (engine.go:204-218): when the endpoint is **unreachable** and `rule.Fallback=="direct"` → fall back to `e.direct(addr)`; otherwise **fail closed** with `ErrWarpUnreachable` (rule.go:141). A reachable endpoint that refuses the CONNECT (REP 4-7) returns as-is, **no fallback**. `New` (engine.go:122-131) requires `WARPAddr` whenever any rule or the default is warp (`ErrWARPAddrNotConfigured`, line 105).

Debug logging is injected: `Config.DebugLogging func(format string, args ...any)` (engine.go:87), nil by default; wired in [`cmd/germany-splitter/main.go:217-220`](cmd/germany-splitter/main.go:217) from `cfg.RoutingDebug`. The per-dial line is `"routing: <host>:<port> → <outbound> (rule <id>)"`.

### Existing "policy" enums

- `routing.DefaultAction`: `direct|warp` (never `block`).
- `routing.Fallback`: `""|direct`.
- **`internal/config` target address-family policy** ([`docs/target-ipv4-policy.md:10-11`](docs/target-ipv4-policy.md:10), [`internal/config/config.go:486-488`](internal/config/config.go:486)): `SPLIT_TARGET_ADDR_POLICY` = `default|prefer-ipv4|ipv4-only`, plus the legacy bool `SPLIT_TARGET_ONLY_IPV4`. This is the **precedent to copy** for a new enum knob: a `Config` string field + an `Env*` const + a `Default*` const + an allowed-set string named in validation errors (`targetAddrPolicyAllowed`, config.go:391) + `envString` in `Load` + a `check*` function in `Validate`.
- `internal/config` Phase-3 `PolicyMode`: `static|adaptive` (config.go:53-54, 173).

---

## 1.3 Existing CLI (`cmd/splitterctl/`)

### Framework: **hand-rolled dispatcher + stdlib `flag` per subcommand.** No cobra.

[`run(ctx, args, out, errOut)`](cmd/splitterctl/main.go:208) — a `switch args[0]` over the verb (lines 239-339). Package-level helpers: [`requireLinux`](cmd/splitterctl/main.go:201) (`goos` var, line 152), [`requireRoot`](cmd/splitterctl/control.go:93), `errUsage` sentinel (main.go:89), `printUsage` (main.go:1574).

### Full command list (from [`printUsage`](cmd/splitterctl/main.go:1574) + the dispatcher)

| Command | Lines | Transport |
|---|---|---|
| `version` | main.go:220-227 | none (buildInfo stamp) |
| `status` | main.go:240-244 → [`status`](cmd/splitterctl/main.go:1466) | reads `deploy.Store` (`/etc/split-tunnel/state.json`), no host calls |
| `doctor` | main.go:245-249 → [`doctor`](cmd/splitterctl/main.go:1485) | `deploy.Diagnostics` + `internal/systemd` ServiceManager (Linux) |
| `config show` | main.go:250-253 → [`configShow`](cmd/splitterctl/main.go:1554) | manifest read (redacted) |
| `config set KEY=VALUE...` | main.go:254-260 → [`configSetCommand`](cmd/splitterctl/main.go:537) | **transactional** `deploy.Controller.ApplyRequest` → writes `/etc/split-tunnel/<role>.env` + restarts units |
| `install iran\|germany` | main.go:261-265 → [`installCommand`](cmd/splitterctl/main.go:359) | `deploy.NewLinuxAdapter` + Controller |
| `install-extra xray-consumer\|tunneldash` | main.go:266-270 → [`installExtraCommand`](cmd/splitterctl/extra.go:98) | Controller + `internal/systemd.ApplyExtraUnit` |
| `rotate-dashboard-credentials [--fresh\|--if-missing\|--recover <dir>]` | main.go:271-275 → [`rotateDashboardCredentialsCommand`](cmd/splitterctl/dashboard_credentials.go:85) | files only |
| `pair generate\|apply\|finalize` | main.go:276-295 → [`pairCommand`](cmd/splitterctl/main.go:1231) | store + blob files |
| `upgrade [--xray\|--origin\|--splitter]` | main.go:296-304 → [`upgradeCommand`](cmd/splitterctl/main.go:621) | Controller |
| `rollback --to <id>` | main.go:305-309 → [`rollbackCommand`](cmd/splitterctl/main.go:695) | Controller |
| `uninstall [--purge]` | main.go:310-314 → [`uninstallCommand`](cmd/splitterctl/main.go:730) | Controller |
| `recover [--ack]` | main.go:315-322 → [`recoverCommand`](cmd/splitterctl/main.go:779) | Controller |
| `control-agent [flags]` | main.go:323-325 → [`controlAgentCmd`](cmd/splitterctl/control.go:107) | **Unix socket daemon** `/run/split-tunnel-ctl/control.sock`, `SO_PEERCRED` |
| `control freeze\|unfreeze\|revert-lkg\|audit-verify\|recover` | main.go:326-336 → [`controlCmd`](cmd/splitterctl/control.go:216) | revision store at `/var/lib/split-tunnel-ctl` |
| `control export-blob\|import-blob\|rotate-key` | main.go:330-335 → [`controlC3Cmd`](cmd/splitterctl/control_c3.go:280) | `osInboundSeam` → live xray configs + systemctl |

### Transport mechanisms already present (reusable primitives)

1. **`internal/systemd.ServiceManager`** ([`service.go`](internal/systemd/service.go)): `Start` :150, `Stop` :159, `Restart` :168, `IsEnabled` :178, `State` :190, **`JournalTail(ctx, unit, n)` :216** — already issues exactly `journalctl -u <unit> -n <n> --no-pager -q -o short-iso` (capped 200, default 20). Also `WaitActive`, `RestartSettle`, [`HealthCheck`](internal/systemd/health.go:125). Every unit name passes [`checkUnitName`](internal/systemd/systemd.go:227) against `unitNameRE = ^[a-z0-9][a-z0-9-]*\.service$` (line 138).
2. **Env-file read/write**: [`parseEnvFile`](cmd/splitterctl/control.go:460) / [`writeEnvFile`](cmd/splitterctl/control.go:481) (atomic tmp+fsync+rename, 0600, sorted keys).
3. **Unix-socket control client**: [`dashboard.NewControlClient(socketPath)`](internal/dashboard/control_c2.go:116) + `Call(ctx, op, reqID, changeID, idemKey, payload)`; server side is `controlagent` ([`protocol.go`](internal/controlagent/protocol.go)).
4. **`config set` key projection table**: `deploy.ConfigKeys` / [`deploy.LookupConfigKey`](cmd/splitterctl/main.go:416) / [`setConfigField`](cmd/splitterctl/main.go:451) — the single place a new knob must be registered to become CLI-settable.

### Ops scripts

- [`scripts/ops/f5-block.sh`](scripts/ops/f5-block.sh) — bounded iptables fault injection (self-restoring at T+90s). Not reusable for CLI design; a fault-injection helper, not an ops command.
- [`scripts/ops/f5-client.sh`](scripts/ops/f5-client.sh), `f6-block.sh`, `f6-client.sh`, `f5-serve.sh` — same family (Phase 2 F5/F6 staging helpers).
- [`scripts/ops/render_multi.py`](scripts/ops/render_multi.py), `render_consumer_multi.py` — config renderers.
- [`scripts/build-linux.sh`](scripts/build-linux.sh) — builds exactly 4 binaries into `dist_onclick/`: `TARGETS=(cmd/splitterctl cmd/iran-splitter cmd/germany-splitter cmd/tunneldash)` (line 59), `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 -trimpath -ldflags="-s -w -X main.buildInfo=${BUILD_COMMIT}"` (lines 61, 68-72), then writes `SHA256SUMS` (lines 79-84).

---

## 1.4 Logging

**There is no logger abstraction and no level system anywhere in the repo.**

| Layer | Mechanism | Evidence |
|---|---|---|
| `cmd/*/main.go` | stdlib `log` (default logger, `os.Stderr`, `log.LstdFlags`) | `cmd/germany-splitter/main.go:302` `logger := log.New(os.Stderr, "[germany-splitter] ", log.LstdFlags)`; `cmd/tunneldash/main.go` uses the package-level `log.Printf` |
| `pkg/node` | holds a **`*log.Logger`** and calls `n.logger.Printf` | [`Node.logger`](pkg/node/node.go:311); constructor [`NewNode(cfg, logger, secret)`](pkg/node/node.go:394). ~20 call sites: `pkg/node/node.go:737,753,766,876,949,993,1005,1026,1185,1198,1207,1239,1256,1282,1431,1656,1948,2065`; `pkg/node/relays.go:210,226,332` |
| `pkg/routing` | **function-typed sink** `debugLog func(format string, args ...any)`, nil = off | [`Engine.debugLog`](pkg/routing/engine.go:62); `Config.DebugLogging` :87; wired at `cmd/germany-splitter/main.go:217-220` from `SPLIT_ROUTING_DEBUG` |
| `internal/*` | stdlib `log` / plain `fmt.Fprintf(out, ...)` to an injected `io.Writer` | e.g. `cmd/splitterctl/*` write to `out io.Writer`; `internal/dashboard` has no logger at all |

**Levels: none.** The only level-like discriminator in the whole codebase is the **boolean** `SPLIT_ROUTING_DEBUG` ([`config.go:219`](internal/config/config.go:219), default `false`, `DefaultRoutingDebug` :369) gating the routing debug line, and the binary-name prefixes `[germany-splitter] `.

**Log destination: stdout/journal only.** Every unit file sets `StandardOutput=journal` / `StandardError=journal` ([`systemd/germany-splitter.service:22-23`](systemd/germany-splitter.service:22), [`internal/systemd/extra_units.go:163,209`](internal/systemd/extra_units.go:163)). `internal/systemd.LogDir = /var/log/split-tunnel` ([`systemd.go:84`](internal/systemd/systemd.go:84)) exists and is converged 0775 root:split-tunnel by [`EnsureLogDir`](internal/systemd/user.go:193) — but **only xray writes there** (render.go:240 `ReadWritePaths=`), no Go binary writes a log file.

**Structured logging: none.** No `slog` (Go 1.21 has it available), no JSON logs, no field-based API.

**Redaction today**: `internal/dashboard/redact.go` ([`RedactString`](internal/dashboard/redact.go), [`IsSensitiveKey`](internal/dashboard/redact.go), [`RedactConfigValue`](internal/dashboard/redact.go)) — used only on the dashboard display path. The splitter log lines are **not** redacted at the source; the design relies on never logging secrets (documented invariant in `pkg/routing/rule.go:63-64`, `engine.go:26-29`).

---

## 1.5 Config system (`internal/config/config.go`)

### `Config` struct — verbatim field list ([`config.go:415-544`](internal/config/config.go:415))

```go
type Config struct {
	// Role-specific
	SocksListen     string // Iran
	WsListen        string // Iran
	DownCarrierAddr string // Iran
	UpWsUrl         string // Germany
	DownListen      string // Germany
	SocksUser       string // Iran (RFC 1929)
	SocksPass       string // Iran (never logged)
	SocksAllowedSources string // Iran, comma CIDRs

	// Shared
	Secret               string
	AllowWeakSecret      bool          // SPLIT_ALLOW_WEAK_SECRET
	MetricsPort          int           // 0 = disabled; binds 127.0.0.1
	RelayBufSize         int
	KeepAliveInterval    time.Duration // fixed; no env var
	QueueBytesPerStream  int
	QueueFramesPerStream int
	QueueBytesTotal      int
	OverflowWaitMs       int

	CarrierGraceMs     int
	ReconnectBaseMs    int
	ReconnectMaxMs     int
	ReconnectWindowMs  int
	ReconnectClampMs   int
	BootstrapWaitMs    int
	SessionBufBytes    int
	SessionBufTotal    int
	LivenessRounds     int

	CreditsEnabled bool // SPLIT_CREDITS_ENABLED

	TargetOnlyIPv4   bool   // SPLIT_TARGET_ONLY_IPV4
	TargetAddrPolicy string // SPLIT_TARGET_ADDR_POLICY: default|prefer-ipv4|ipv4-only

	MultiCarrierEnabled bool
	DownListen2         string
	DownCarrierAddr2    string
	DownSNI2            string

	PolicyMode       string // static|adaptive
	PolicyTopK       int
	ProbingEnabled   bool
	ProbeURL         string
	ProbeDailyBudget int64
	TTFBBaselineMs   int

	RoutingRulesFile string // SPLIT_ROUTING_RULES_FILE (empty = routing OFF)
	RoutingDefault   string // SPLIT_ROUTING_DEFAULT: direct|warp
	WarpSocksAddr    string // SPLIT_WARP_SOCKS_ADDR
	RoutingDebug     bool   // SPLIT_ROUTING_DEBUG

	TargetDialBoundMs       int
	TargetBreakerEnabled    bool
	TargetBreakerWindowMs   int
	TargetBreakerThreshold  int
	TargetBreakerCooldownMs int
	TargetBreakerMaxTargets int
	TargetBackoffEnabled    bool
	TargetBackoffBaseMs     int
	TargetBackoffMaxMs      int
}
```

### `Load()` flow ([`config.go:621`](internal/config/config.go:621))

`Load(role)` → role guard → `c := Defaults()` → `var problems []string` → one `envString`/`envInt`/`envBool`/`envInt64` call per field (lines 628-~700) → `c.Validate(role)` → returns `(*Config, error)` where the error is a `*ConfigError` aggregating **all** problems ([`ConfigError`](internal/config/config.go:605), bulleted list). `envInt`/`envBool` push precise problems into `problems` on malformed values and return the default (config.go:1293, 1316).

### `Defaults()` ([`config.go:547`](internal/config/config.go:547))

Returns a `*Config` with every built-in default, reading **no environment**. Each field's default is a named `Default*` const in the `const` block at lines 225-409 (e.g. `DefaultRoutingRulesFile = ""`, `DefaultRoutingDefault = ""`, `DefaultWarpSocksAddr = "127.0.0.1:40000"`, `DefaultRoutingDebug = false`, `DefaultTargetAddrPolicy = "default"`).

### Validation / error surfacing

`Config.Validate(role)` calls per-concern checkers that append to `problems`: [`checkRouting`](internal/config/config.go:1139) (enum, WARP host:port, `routing.LoadRulesFile` parse), `checkHostPort` :1169, `checkNotReservedCarrierPort` :1201, `checkWsUrl` :1217, `checkSocksAllowedSources` :1044, plus `roleOwnedEndpoints` :1026 and `conflict` :1248. **Error text never echoes secret values** (pinned by [`TestSecretPolicyNeverLeaksValue`](internal/config/config_test.go:411) and `TestConfigSetSecretIsNeverEchoed`).

### Naming convention (must be followed exactly)

`SPLIT_` + `UPPER_SNAKE_CASE`, with a `_MS` suffix for millisecond durations (`SPLIT_CARRIER_GRACE`, `SPLIT_RECONNECT_BASE_MS`, `SPLIT_TARGET_DIAL_BOUND_MS`). Each new knob needs, in `internal/config/config.go`: an `Env*` const in the block at lines 58-220, a `Default*` const (plus `Min*`/`Max*` and an allowed-set string where it is an enum) in the block at 225-409, a `Config` field, a `Defaults()` line, a `Load()` line using the right helper, and a `Validate` check. Then register it in `deploy.ConfigKeys` so `config set` accepts it.

---

## 1.6 Geodata

**The project does not use geosite/geoip for routing. It only extracts the Xray release files.**

| Hit | Location |
|---|---|
| `extractZip(data, dst, withGeodata)` | [`internal/xray/extract.go:26`](internal/xray/extract.go:26) |
| `base == "geoip.dat" \|\| base == "geosite.dat"` | [`internal/xray/extract.go:87`](internal/xray/extract.go:87) |
| `WithGeodata bool // extract geoip.dat/geosite.dat (default: skip)` | [`internal/xray/install.go:117`](internal/xray/install.go:117) |
| Tests asserting extraction / non-extraction | [`internal/xray/install_test.go:89-92,269-272,298-300,314-317`](internal/xray/install_test.go:89) |

**Zero occurrences** of `geosite`/`geoip` in any `.md` doc, any `config/*.json`, the installer, or `pkg/routing`. The Xray configs ([`config/iran-xray-config.json`](config/iran-xray-config.json)) do not reference them either. `internal/xray.PinnedVersion`'s release zip is downloaded and the `.dat` files are **skipped by default** — so even the files are usually absent on the hosts.

**No existing catalog/group list of websites (instagram/meta/openai style) exists anywhere in the repo.** There is no `geosite`-style group file, no category list, and no preset catalog. This is greenfield.

---

## 1.7 Build & deployment

| Item | Value | Evidence |
|---|---|---|
| Binaries | `splitterctl`, `iran-splitter`, `germany-splitter`, `tunneldash` | [`scripts/build-linux.sh:59`](scripts/build-linux.sh:59) |
| Build flags | `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.buildInfo=<sha>"` | build-linux.sh:61,68-72 |
| Output | `dist_onclick/<name>-linux-amd64` + `SHA256SUMS` (gitignored) | build-linux.sh:66,79-84 |
| Config root | `/etc/split-tunnel/` (`systemd.StateDir`, 0750 root:split-tunnel) | [`systemd.go:83`](internal/systemd/systemd.go:83), [`StateDirMode`](internal/systemd/systemd.go:99) |
| Live env files | `/etc/split-tunnel/germany.env`, `/etc/split-tunnel/iran.env` (0640 root:split-tunnel) | [`canonicalEnvFile`](internal/systemd/systemd.go:221), [`EnsureStateDir`](internal/systemd/user.go:134) |
| Live xray configs | Germany `/etc/split-tunnel/xray-germany.json`; Iran `/etc/xray-consumer/config.json` | [`control_c3.go:56-73`](cmd/splitterctl/control_c3.go:56) |
| Dashboard config | `/etc/split-tunnel/dashboard/config.json` | [`docs/tunneldash.md:175`](docs/tunneldash.md:175) |
| Dashboard creds | `/etc/split-tunnel/dashboard/credentials` (0640 root:split-tunnel PBKDF2 verifier) + `credentials.recovery` (0600 root:root) | [`dashboard_credentials.go:69-71`](cmd/splitterctl/dashboard_credentials.go:69) |
| Control store / socket | `/var/lib/split-tunnel-ctl` (0700 root), `/run/split-tunnel-ctl/control.sock` (0660 root:tunneldash-ctl) | [`control.go:41-42`](cmd/splitterctl/control.go:41), design §3.2 |
| Log dir | `/var/log/split-tunnel` (0775 root:split-tunnel) | [`systemd.go:84`](internal/systemd/systemd.go:84), [`EnsureLogDir`](internal/systemd/user.go:193) |
| Binary prefix | `/opt/split-tunnel`; xray via `/opt/split-tunnel/xray/current/xray` | [`systemd.go:86,133`](internal/systemd/systemd.go:86) |

### systemd units

| Unit | Source | Notes |
|---|---|---|
| `germany-splitter.service` | [`systemd/germany-splitter.service`](systemd/germany-splitter.service) | `User=split-tunnel`, `EnvironmentFile=/etc/split-tunnel/germany.env`, `After/Wants=xray-germany.service`, `Restart=always`, journal |
| `iran-splitter.service` | [`systemd/iran-splitter.service`](systemd/iran-splitter.service) | mirror |
| `xray-germany.service` | [`render.go:207-208`](internal/systemd/render.go:207) | `run -config /etc/split-tunnel/xray-germany.json` |
| `xray-consumer.service` | [`extra_units.go:139-153`](internal/systemd/extra_units.go:139) | `run -config /etc/split-tunnel/xray-consumer.json` |
| `tunneldash.service` | [`extra_units.go:176+`](internal/systemd/extra_units.go:176) | `ReadWritePaths=/var/log/split-tunnel`, journal |
| `control-agent.service` / `.socket` | [`extra_units.go:225-261`](internal/systemd/extra_units.go:225) | root, `--log-dir /var/log/split-tunnel/control-agent` |
| `iran-origin.service` | [`render.go:212`](internal/systemd/render.go:212) | Iran only |

[`protectedUnitNames`](internal/systemd/uninstall.go:34) = germany-splitter, xray-germany, iran-splitter, iran-origin, xray-consumer, tunneldash — the safety guard for unit removal. **`tunneldash` is not in `dashboard.KnownUnits`** (ssh_config.go:19) — an asymmetry to fix.

---

## 1.8 Existing tests

| Area | Files | Style |
|---|---|---|
| routing | [`pkg/routing/rule_test.go`](pkg/routing/rule_test.go), `matcher_test.go`, `engine_test.go` (40 tests) | table-driven; raw JSON literals into `ParseRules`/`mustRules`; a **fake WARP SOCKS server** (`newFakeWarpSocks`) and `recordedDialer` |
| config | [`internal/config/config_test.go`](internal/config/config_test.go) (70 tests), `routing_test.go`, `multicarrier_test.go`, `phase3_test.go`, `telemetry_test.go` | `isolatedEnv(t)` + `validIran()`/`validGermany()` builders; assert on `*ConfigError` problem strings |
| dashboard | [`internal/dashboard/server_test.go`](internal/dashboard/server_test.go), `api_v2_test.go`, `api_v2_schema_test.go`, `control_c1..c4_test.go`, `ssh_collector_test.go`, `static_assets_test.go`, `redact_test.go`, `history_test.go`, `planner_test.go`, `collector_test.go`, `parser_test.go`, `tls_test.go`, `basic_auth_test.go`, `auth_test.go`, `config_test.go`, `control_wiring_test.go`, `control_dashboard_editors_test.go` (~260 tests) | `httptest`-style via `newTestServer(nil)` / `v2TLSServer(t, nil)` / `c4TestServer(t, true, flags)`; a **fake `C2Agent`** and a **fake `CommandRunner`** |
| archtest | [`internal/archtest/arch_test.go`](internal/archtest/arch_test.go) | **AST import scan** of every `pkg/*/*.go`; `internal/testutil` is the only allowlisted internal import |
| integration | [`integration/multicarrier_failover_test.go`](integration/multicarrier_failover_test.go), `twoproc_test.go`, `socks5/client_test.go`, [`integration/RUNBOOK.md`](integration/RUNBOOK.md) | two-process in-memory topology |
| cmd | `cmd/splitterctl/main_test.go` (1900+ lines), `dashboard_credentials_test.go`, `blob_out_m2_test.go`, `splitter_hash_h3_test.go`; `cmd/germany-splitter/{down_carrier_auth_limit,metrics,up_carrier_ws}_test.go`; `cmd/iran-splitter/{metrics,socks,ws}_test.go` | `withLinux(t)`, `t.Setenv("SPLITTERCTL_STATE_ROOT", t.TempDir())`, stub controllers |

### Architectural constraints from `internal/archtest/arch_test.go`

1. **`pkg/*` may not import `internal/*`** (only `internal/testutil`, test-only). This means:
   - A log-level type used by `pkg/routing` and `pkg/node` **must live in `pkg/`** (e.g. `pkg/logging`), not `internal/config`.
   - A **preset/geo catalog that expands into `routing.RuleSet` must live in `pkg/`** (e.g. `pkg/routingpresets` / `pkg/geocatalog`) if `pkg/routing` needs it; otherwise it lives in `internal/` and only `cmd/` uses it.
   - Redaction helpers needed by `pkg/` must be duplicated into `pkg/` (a small, self-contained copy of `internal/dashboard/redact.go` patterns).
2. `cmd/*` may import `internal/*` freely — so new `internal/` packages are safe for the dashboard and CLI surfaces.
3. The test parses imports only (`parser.ImportsOnly`), so it is cheap and will run in CI on every PR. A boundary regression **fails the build gate**.

---

# PART 2 — FEATURE DESIGNS

## A. Log level

### A.1 Design

**Type.** A new package `pkg/logging` (new directory, no `internal/*` imports, so `pkg/node` and `pkg/routing` may both import it):

```go
package logging

type Level int
const (
	LevelError Level = iota // 0
	LevelWarn               // 1
	LevelInfo               // 2  ← DEFAULT
	LevelDebug              // 3
)
func (l Level) String() string             // "error"|"warn"|"info"|"debug"
func ParseLevel(s string) (Level, error)   // case-insensitive; unknown → error naming the set
func (l Level) Enabled(candidate Level) bool { return candidate <= l }

// Logger is the stdlib-compatible sink the engine already speaks.
type Logger struct{ /* level atomic + inner *log.Logger */ }
func New(l *log.Logger, lvl Level) *Logger
func (g *Logger) Errorf/Warnf/Infof/Debugf(format string, args ...any)
func (g *Logger) Printf(format string, args ...any)  // maps to Infof — backward compat
func (g *Logger) Stdlib() *log.Logger                // drop-in for NewNode(cfg, logger, secret)
func (g *Logger) SetLevel(l Level)                   // atomic, runtime-changeable
func (g *Logger) Level() Level
```

**Why a `pkg/` package.** `pkg/node.Node.logger` is a concrete `*log.Logger` ([`node.go:311`](pkg/node/node.go:311)) with ~20 `n.logger.Printf` sites. Changing that type is a wide blast radius; instead we add a thin `Level` type that both `pkg/node` and `pkg/routing` can consult without importing `internal/`.

**Backward-compatible integration (preferred, minimal churn):** keep `Node.logger *log.Logger` and `Engine.Config.DebugLogging func(...)` exactly as they are, and do the filtering at the **construction site** in `cmd/*/main.go` by wrapping the real logger:

```go
// cmd/germany-splitter/main.go (replaces line 302)
base := log.New(os.Stderr, "[germany-splitter] ", log.LstdFlags)
gated := logging.New(base, cfg.LogLevel)
...
node.NewNode(nodeCfg, gated.Stdlib(), mux.DeriveSecret(cfg.Secret))
```

Implementation detail for zero-call-site churn: `logging.Logger.Stdlib()` returns a `*log.Logger` created with `log.New(levelFilterWriter{lvl, base}, prefix, flags)` where `levelFilterWriter` is an `io.Writer` that parses the leading `LEVEL:` token of each formatted line and drops it below the threshold. This preserves every existing `n.logger.Printf` call site byte-for-byte and keeps the `*log.Logger` constructor signature (`NewNode(cfg, logger, secret)`) unchanged — so **no test that passes `log.New(io.Discard, ...)` breaks**.

**Where filtering happens.** Two layers:
1. **Line-level (default path)** — `levelFilterWriter` in `pkg/logging`. Covers all existing `pkg/node` sites with no code change.
2. **Structured (new call sites)** — new code uses `g.Infof/Debugf` directly so no string parsing is needed.

**Env vars** (following the `SPLIT_*` convention exactly):

| Var | Type | Default | Applies to |
|---|---|---|---|
| `SPLIT_LOG_LEVEL` | enum `error\|warn\|info\|debug` | `info` | both splitters, tunneldash |
| `SPLIT_LOG_RING_BYTES` | int, 64 KiB..8 MiB | `262144` (256 KiB) | both splitters (feature B buffer) |
| `SPLIT_LOG_FILE` | string path, optional | `""` (journal only) | both splitters, tunneldash |

Defaults: `DefaultLogLevel = "info"`, `DefaultLogRingBytes = 256 << 10`. `SPLIT_LOG_LEVEL` is validated by `checkLogging(problems, c)` appended to `Validate`; an unknown value is an aggregated `ConfigError` naming `error|warn|info|debug` — mirroring `checkRouting`.

**Routing debug interaction.** `SPLIT_ROUTING_DEBUG` becomes a **derived convenience**: `RoutingDebug = envRoutingDebug || (cfg.LogLevel == "debug")`. Keep the field and the env var (backward compat; existing test at [`routing_test.go:234`](internal/config/routing_test.go:234) pins `SPLIT_ROUTING_DEBUG=notabool` → problem), but document that `SPLIT_LOG_LEVEL=debug` now implies it. This avoids breaking `internal/controlagent/c4.go:81` which lists `config.EnvRoutingDebug` in `c4RoutingFields`.

**Runtime change.** One path, already built: `splitterctl config set log.level=debug` → transactional env write + restart (existing `configSetCommand` path). It requires a restart because the level is read at start — the honest classification the C4 routing keys already use (`"restartRequired": true`). **Do not add a SIGHUP handler**: no unit file sets `ExecReload`, and adding signal handling to `pkg/node` is out of scope.

### A.2 Exact files

| File | Change |
|---|---|
| `pkg/logging/level.go` | **new** — `Level`, constants, `String`, `ParseLevel`, `Enabled` |
| `pkg/logging/logger.go` | **new** — `Logger`, `New`, `Errorf/Warnf/Infof/Debugf/Printf`, `Stdlib()`, `SetLevel`, `Level`, `levelFilterWriter` |
| `pkg/logging/level_test.go` | **new** — parse/round-trip, filter matrix, `Stdlib()` drops-below-threshold, `SetLevel` atomic |
| `internal/config/config.go` | +`LogLevel string`, `LogRingBytes int`, `LogFile string` fields; +`EnvLogLevel/EnvLogRingBytes/EnvLogFile` consts; +`DefaultLogLevel/DefaultLogRingBytes/Min+MaxLogRingBytes/LogLevelAllowed` consts; `Defaults()` lines; `Load()` lines; `checkLogging`; append to `Validate` |
| `internal/config/logging_test.go` | **new** — defaults, enum rejection, `Load` round-trip, aggregation |
| `cmd/germany-splitter/main.go` | replace line 302 with the gated logger; pass to `buildRoutingEngine` and `NewNode`; log the active level at start |
| `cmd/iran-splitter/main.go` | same |
| `cmd/tunneldash/main.go` | same; also add a `-log-level` flag mirroring the existing flag style |
| `internal/deploy/*` (ConfigKeys table) | register `log.level` so `config set log.level=debug` works |

**Blast radius:** 3 `cmd/*/main.go` files (1-3 lines each), 1 new `pkg/` package, ~60 lines in `internal/config`. **No existing test breaks** — the `*log.Logger` constructor signature is preserved and `isolatedEnv`-based config tests keep their defaults.

---

## B. Live logs

### B.1 Design

**Recommendation: SSE (`text/event-stream`), not WebSocket, not polling.**

Justification against the existing stack:
- The dashboard is **stdlib `net/http`** with a hand-rolled `ServeMux`. SSE is a plain `http.HandlerFunc` that writes `data: ...\n\n` — zero new dependencies, works through the existing middleware/auth/basePath chain unchanged.
- `gorilla/websocket` is already a dependency, but it is used only for the carrier transport and would force `Upgrade()` to bypass the `Server.Router()` middleware chain (the basePath/auth wrappers). It also sits awkwardly with HTTP Basic auth's browser flow.
- Polling (`?since=<seq>`) is what the UI does today and would keep working, but it cannot deliver sub-second latency and re-sends the auth header on every tick. SSE gives push semantics with one long-lived authenticated request.
- **Backpressure:** SSE over `net/http` has no flow control; a slow client is handled by the server's `WriteTimeout` (currently 30 s, `server.go:180`). Design: **server-side drop, never block the producer.** The ring buffer is the only shared state; the SSE handler reads from a cap-1 channel with a non-blocking send and **drops on full**.

**Capture: in-memory ring buffer in the splitter, exposed on the existing `/metrics` port.**

The splitters already run an HTTP server on `127.0.0.1:<SPLIT_METRICS_PORT>` ([`runMetrics`](cmd/germany-splitter/main.go:747), `metricsListenHost = "127.0.0.1"` line 741). Adding a log endpoint there is the smallest possible change and inherits the loopback-only bind.

```
GET /logs?since=<seq>&limit=<n>   → JSON { "seq": <last>, "entries": [...] }
```

`pkg/logging/ring.go`:

```go
package logging

type Entry struct {
	Seq   uint64    `json:"seq"`
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`   // already-redacted at emit
}

type Ring struct { /* mutex + []Entry + head + seq + cap bytes */ }

func NewRing(maxBytes int) *Ring
func (r *Ring) Add(level Level, msg string)      // drops oldest on cap; assigns seq
func (r *Ring) Since(seq uint64, limit int) (entries []Entry, last uint64)
func (r *Ring) Len() int
```

The `Ring` is the `io.Writer` sink: `logging.NewSink(ring, level)` returns a `*log.Logger`-compatible writer that (a) filters by level, (b) parses the `LEVEL:` prefix, (c) redacts. **`pkg/` cannot import `internal/`**, so redaction must be a small self-contained `redact.go` inside `pkg/logging` (patterns: PEM blocks, `Bearer <tok>`, `user:pass@host`, `KEY=value` for keys matching `secret|password|token|credential`). This duplicates ~40 lines from `internal/dashboard/redact.go`; acceptable and explicitly justified by the archtest boundary. Parity is pinned by a test that runs the same vectors through both.

**Exposure chain (how the dashboard gets it):**

1. Splitter: `cmd/germany-splitter/main.go` builds `ring := logging.NewRing(cfg.LogRingBytes)`, passes `logging.NewSink(ring, lvl)` to `NewNode`/routing, and registers `/logs` on the existing metrics mux.
2. Dashboard: a **new collector** `internal/dashboard/logs_collector.go` implementing the existing `Collector` interface. It fetches `http://127.0.0.1:<port>/logs?since=<lastSeq>` and appends `LogEntry`s (which **already have a `Level` field**, [`types.go:54`](internal/dashboard/types.go:54)) into the snapshot.
3. Remote hosts (the real deployment): the **SSH collector already tails journalctl** ([`ssh_collector.go:135-148`](internal/dashboard/ssh_collector.go:135)). For the server-hosted TLS dashboard the same `journalctl` allowlist path already works; **no new remote command is needed** — but `BuildJournalArgs` must gain an optional `--since` cursor and the collector must remember the last cursor so the poll is incremental. `KnownUnits` must add `"tunneldash"` and `"control-agent"`.
4. Live push to the browser: **new endpoint** `GET /api/v1/logs/stream?server=<id>&level=<lvl>` (SSE) on the dashboard server. It subscribes to a `*dashboard.LogHub`.

`internal/dashboard/loghub.go`:

```go
type LogHub struct { mu sync.RWMutex; subs map[chan LogEntry]struct{}; ring []LogEntry; max int }
func NewLogHub(max int) *LogHub
func (h *LogHub) Publish(entries ...LogEntry)   // append to ring + non-blocking send to each sub
func (h *LogHub) Subscribe() (<-chan LogEntry, func())
func (h *LogHub) Recent(n int) []LogEntry       // replayed on connect so the UI is never empty
```

The `pollLoop` ([`server.go:219`](internal/dashboard/server.go:219)) publishes each poll's new log entries into the hub; the SSE handler writes them as `event: log\ndata: {json}\n\n` with a 15 s `: keepalive\n\n` comment to hold proxies open. **Backpressure:** subscriber channels are cap-1 with a non-blocking send; a slow client simply misses lines (the UI then re-fetches `Recent` on reconnect). The SSE handler disables the write deadline for that response via `http.NewResponseController(w).SetWriteDeadline(time.Time{})` (Go 1.21 supports this) so a long-lived stream is not cut at 30 s.

**CLI equivalent:** `splitterctl logs [-f|--follow] [-n N] [--level L] [--unit U] [--since TS]`. Non-follow mode is a direct call to the existing `systemd.ServiceManager.JournalTail` (already capped at 200, already unit-name-guarded). `--follow` uses `exec.CommandContext(ctx, "journalctl", "-u", unit, "-f", "--no-pager", "-q", "-o", "short-iso")` with a bounded argv (no shell) and streams `scanner.Bytes()` to stdout — same allowlist discipline as `ExecCommandRunner`.

### B.2 Exact files

| File | Change |
|---|---|
| `pkg/logging/ring.go` | **new** — `Entry`, `Ring`, `NewRing`, `Add`, `Since`, `Len` |
| `pkg/logging/ring_test.go` | **new** — cap eviction, `Since` cursor semantics, concurrency under `-race` |
| `pkg/logging/redact.go` | **new** — `Redact(string) string` (self-contained; archtest forces the copy) |
| `pkg/logging/redact_test.go` | **new** — parity vectors vs `internal/dashboard/redact_test.go` |
| `cmd/germany-splitter/main.go` | build ring + sink in `runMetrics`; register `mux.HandleFunc("/logs", ...)` |
| `cmd/iran-splitter/main.go` | same |
| `cmd/tunneldash/main.go` | build the dashboard's own ring + hub so `tunneldash`'s own logs are streamable |
| `internal/dashboard/loghub.go` | **new** — `LogHub`, `Publish`, `Subscribe`, `Recent` |
| `internal/dashboard/loghub_test.go` | **new** — bounded subs, drop-not-block, replay |
| `internal/dashboard/logs_collector.go` | **new** — `LogsCollector` implementing `Collector` |
| `internal/dashboard/logs_collector_test.go` | **new** — fake `CommandRunner`/httptest source |
| `internal/dashboard/server.go` | `mux.HandleFunc("/api/v1/logs/stream", s.apiHandler(s.handleLogsStream))`; `NewLogHub` in `NewServer`; `pollLoop` publishes |
| `internal/dashboard/server.go` `handleLogsStream` | **new** — SSE writer, `text/event-stream`, `X-Accel-Buffering: no`, keepalive ticker, ctx cancel |
| `internal/dashboard/ssh_config.go` | `KnownUnits` += `tunneldash`, `control-agent`; `BuildJournalArgs` gains a `--since` cursor |
| `internal/dashboard/ssh_collector.go` | incremental journal cursor per unit; publish to hub |
| `internal/dashboard/types.go` | `ServerConfig.LogsURL string \`json:"logsUrl,omitempty"\`` ; `DashboardConfig.LiveLogs bool \`json:"liveLogs"\`` |
| `internal/dashboard/static/app.js` | `renderLogs` uses `EventSource(API_V1 + "/logs/stream?server=...")` with a polling fallback; level filter chips |
| `internal/dashboard/static/index.html` | logs section markup |
| `internal/dashboard/static_assets_test.go` | extend `TestStaticNoExternalURLs`/CSP assertions to the new markup |
| `cmd/splitterctl/logs.go` | **new** — `logsCmd` (see E) |
| `cmd/splitterctl/main.go` | dispatch `logs`; add to `printUsage` |
| `cmd/splitterctl/logs_test.go` | **new** — fake executor asserts exact `journalctl` argv; `-f` bounded |

**Blast radius:** 2 splitter mains (+~25 lines each), 1 dashboard server file (routes + hub wiring), 4 new `internal/dashboard` files, 1 new `cmd/splitterctl` file, ~80 lines of JS. Existing tests: `TestStaticNoExternalURLs` and `TestStaticHasRequiredSections` must be **extended, not weakened**.

---

## C. Routing presets (countries or websites → block/direct/warp)

### C.1 Design

**Catalog format: JSON, embedded with `//go:embed`, plus an optional on-disk override.**

Placement: **`pkg/routingpresets`** (a sibling package, not nested inside `pkg/routing`) so that `pkg/routing` can import it and `cmd/` can too, all under `pkg/` — no archtest violation either way.

```go
package routingpresets

// Group is one selectable catalog entry.
type Group struct {
	ID       string   `json:"id"`       // "instagram", "meta", "openai", "google"
	Name     string   `json:"name"`     // "Instagram / Meta"
	Category string   `json:"category"` // "social"|"ai"|"video"|"news"|"cdn"|"ads"|"country"
	Action   string   `json:"action"`   // suggested default: "warp"|"direct"|"block"
	Domains  []string `json:"domains"`  // [".instagram.com", ".cdninstagram.com"]
	Keywords []string `json:"keywords,omitempty"`
	Comment  string   `json:"comment,omitempty"`
}

type Catalog struct {
	Version int     `json:"version"`   // must be 1
	Groups  []Group `json:"groups"`
}

// Selection is what the operator actually picks.
type Selection struct {
	GroupID  string `json:"groupId"`            // catalog entry
	Action   string `json:"action"`             // "block"|"direct"|"warp" (may override the group's suggestion)
	Fallback string `json:"fallback,omitempty"` // "direct" when action=warp
}

//go:embed catalog.json
var catalogFS embed.FS

func LoadCatalog() (*Catalog, error)                  // parse + validate embedded
func (c *Catalog) Search(q string) []Group            // name/id/category/domain substring, case-insensitive
func (c *Catalog) ByID(id string) (Group, bool)
func (c *Catalog) Expand(sel []Selection, base *routing.RuleSet) (*routing.RuleSet, error)
```

**Expansion into rules.** One selected group → **one rule per domain** (not one giant keyword rule), so operators can see and disable individual domains. IDs are deterministic and stable: `instagram-1`, `instagram-2`, ... This matters because `RuleSet.Sanitize` requires **unique non-empty ids** and enforces `MaxRules = 500` — so expansion must be bounded: reject a selection set whose expanded rule count exceeds `routing.MaxRules`, with an error naming the count (same phrasing style as `rule.go:301`).

**Conflict merge semantics** (deterministic, documented):
1. Expanded rules are **appended in catalog order, then selection order**; first-match-wins means **earlier selections shadow later ones** — the operator sees this in the preview.
2. A group selected twice → the **second selection is refused** at validation ("group %q selected more than once"), not silently merged.
3. The operator's hand-written rules are preserved: `Expand` takes a `base *routing.RuleSet` whose rules are emitted **first** (so hand-written rules always win over preset expansion).
4. `default_action` comes from the caller (config `SPLIT_ROUTING_DEFAULT` or the file's), never from a preset — a preset can never set a block default.

**Validation.** `Catalog.Validate()` enforces: `version == 1`; unique non-empty group ids; every domain passes the same `validateDomain` rules — **reuse `routing`'s validator by exposing it**: add `routing.ValidateDomainPattern(s string) error` as a thin exported wrapper over the existing private `validateDomain` ([`rule.go:405`](pkg/routing/rule.go:405)). No duplicate logic. Every `Action` in `direct|warp|block`. `Fallback` only on warp. **The result of `Expand` is re-run through `rs.Sanitize()`**, so a preset can never produce an illegal rule set.

**How presets are selected.** Three surfaces, one data path:
1. **Config knob**: `SPLIT_ROUTING_PRESETS` — comma-separated `group[:action][:fallback]` tokens, e.g. `instagram:warp:direct,openai:direct,tiktok:block`. Parsed by `config` into `RoutingPresets string`, validated by `checkRouting` (each group id must exist in the catalog; the action must be legal). `Defaults()` = `""` (no presets). `internal/config` importing `pkg/routingpresets` is legal (`internal/*` may import `pkg/*`).
2. **CLI**: `splitterctl routing presets list|search <q>|apply <group>[:action]...|show` (see E).
3. **Dashboard**: search + multi-select in the Routing panel; POSTs a selection to `/api/v2/changes/{id}/routing-validate` as a `presets` field alongside `rules`.

**How a preset reaches the live rules file.** The **rules file is a JSON file on disk referenced by `SPLIT_ROUTING_RULES_FILE`**, and the C4 apply path already validates and restarts on change. The design:
- Add `presets []Selection` to the C4 routing-apply payload (strict-decoded struct `c4ApplyRequest` gains the field; `DisallowUnknownFields` already protects the rest).
- The **agent** (`internal/controlagent/c4.go`) renders the final rules file: `base rules` + `catalog.Expand(presets)` → `RuleSet` → `json.MarshalIndent` → written through the existing `osControlSeam.WriteCandidate`/`SwapFile`/`RestartService` transaction. The agent already does exactly this for env changes; the rules-file write is the same seam with a different target path.
- **The env-file `SPLIT_ROUTING_PRESETS` is a *selection record only*** (documented as such). It is NOT a second source of truth: on every apply the agent re-renders the rules file from the current file contents (as base) + the recorded selection. If the file was hand-edited, the hand edits are the base and are preserved.

### C.2 Exact files

| File | Change |
|---|---|
| `pkg/routingpresets/catalog.go` | **new** — `Group`, `Catalog`, `Selection`, `LoadCatalog`, `Search`, `ByID`, `Expand`, `Validate`, embed |
| `pkg/routingpresets/catalog.json` | **new** — v1 catalog: `meta`/`instagram`, `openai`, `google`, `youtube`, `twitter`, `telegram`, `tiktok`, `netflix`, `spotify`, `cloudflare`, `ads` (block), plus `country-ir`/`country-cn`/`country-ru` CIDR-style groups expressed as domains where possible |
**How a preset reaches the live rules file.** This is the critical integration point: the **rules file is a JSON file on disk referenced by `SPLIT_ROUTING_RULES_FILE`**, and the C4 apply path already validates and restarts on change. The design:

- Add `presets []Selection` to the C4 routing-apply payload (strict-decoded struct `c4ApplyRequest` gains the field; `DisallowUnknownFields` already protects the rest).
- The **agent** (`internal/controlagent/c4.go`) renders the final rules file: `base rules` + `catalog.Expand(presets)` → `RuleSet` → `json.MarshalIndent` → written through the existing `osControlSeam.WriteCandidate`/`SwapFile`/`RestartService` transaction. The agent already does exactly this for env changes; the rules-file write is the same seam with a different target path.
