# Self-Contained Deployment Architecture — Design Report (v0.2)

Status: **DESIGN ONLY — no implementation yet.** This is the AUDIT → ARCHITECT →
DESIGN → REUSE RESEARCH → PLAN deliverable for the "self-contained deployment"
direction change.

**Review gate (see §21): PASSED — CRITICAL = 0, HIGH = 0.** v0.1 was reviewed
independently in ARCHITECT mode; 3 HIGH findings were fixed in v0.2 (H1 Iran
Xray config spec, H2 ACME port-80 firewall gap, H3 CDN-mode origin TLS
ambiguity) plus 6 MEDIUM clarifications. MEDIUM/LOW items are tracked in §21
and must be closed by the implementation tasks that own them (noted inline).

Repository state this was written against (verified from GitHub, not from memory):

- `main` @ `2dcf14d` — L4 two-process gate fully green on Linux (S1–S11).
- `l5-harness` @ `2b37e4e` — L5 run A recorded; **VERDICT BLOCKED** (required
  transports absent: CDN/TLS up, VLESS+Reality down; path blackholes established
  TCP). Issue #9 open. Findings #19 (infra gap + path), #20 (stranded session),
  #21 (S16 0x00-vs-0x06) open.

## 0. The direction change, precisely

The previous model (documented in the README and RUNBOOK §2.3) was:

- **Iran** — the project's `install.sh` installs the splitter, detects the
  user's *existing* Xray/3x-ui, merges a `to-splitter` SOCKS outbound + routing
  rule into it, and emits an nginx snippet for the CDN origin.
- **Germany** — the project installs *only* the splitter. The operator's **own**
  Xray/3x-ui provides the VLESS+Reality inbound that delivers tunneled TCP to
  `127.0.0.1:9002`, and the operator's **own** CDN/nginx provides the up-carrier
  TLS origin. The README states this explicitly: "Xray/3x-ui is a CONSUMER of
  this project, not a managed component" and "the down-carrier arrives through
  **your own** VLESS+Reality inbound."

The new requirement **inverts the Germany side** and **sharpens the Iran side**:

- **Iran** stays minimal and **never** owns the user's Xray/3x-ui. The user
  connects to their existing Xray/3x-ui; the project's only Iran-side job is a
  local **SOCKS5 endpoint** the user points a SOCKS **outbound** at. The user
  must not change their Xray architecture beyond adding one outbound.
- **Germany** must be **self-contained**. The user must not install Xray-core,
  create an inbound, generate Reality keys, write a Reality config, copy an Xray
  config, create systemd units, wire Xray to the splitter, or configure the
  transport stack. **This project's deployment system installs and configures
  all of it.** The user supplies only the externally-derived parameters:
  Reality destination/SNI, domain/DNS info, the pairing secret, and optional
  port choices. Everything derivable is generated.

**Architectural rule (non-negotiable):** keep the **product engine**
(`pkg/node`, `pkg/session`, `pkg/mux`) separate from **deployment orchestration**.
Do NOT embed Xray-core's protocol implementation into the Go splitter unless a
research finding proves it necessary (it is not — Xray-core is a managed
transport component). The splitter keeps its own protocol/session/carrier logic;
Xray-core is a supervised child that terminates the transport and hands raw TCP
to the splitter. Do not turn the splitter into an Xray panel.

## 1. Current architecture assessment

### 1.1 What exists and is load-bearing

- **Product engine** — `pkg/node` (single authoritative session/carrier engine;
  generation-aware rebind; bounded backpressure; authoritative idempotent
  `Session.Close`; TCP half-close preserved), `pkg/mux` (frame protocol, auth v1,
  carrier liveness), `pkg/session`. `cmd/iran-splitter` and `cmd/germany-splitter`
  are **thin transport wrappers** over `pkg/node`. This is correct and must not
  be rewritten.
- **Configuration** — `internal/config` is the authoritative validator (18
  env vars, role-based, fail-fast, aggregated errors, secret policy via
  `mux.ValidateSecretMaterial`). The 0-means-library-default convention is
  consistent. The installer mirrors these bounds exactly (Phase 8 invariant:
  shell never stricter than the binary gate).
- **Iran installer** — already does the two things the Iran role needs under the
  new model: (a) install the splitter + systemd unit, (b) detect the user's
  existing Xray/3x-ui and **merge** the `to-splitter` SOCKS outbound + routing
  rule (with a backup + optional service restart). It also emits the nginx
  snippet for the CDN origin.
- **Germany installer** — installs only the splitter. It has **no** Xray
  management, no Reality, no up-carrier TLS origin. This is the gap the new
  direction closes.
- **Acceptance harness** — `integration/` (L4 two-process gate + L5 RUNBOOK +
  `l5cli` + SOCKS5 client). The L5 matrix already lists VLESS+Reality down and
  CDN up as *required*; it just was not executable because staging had neither.
  The new deployment system is precisely what makes that matrix executable.

### 1.2 Exact carrier topology (source of truth: RUNBOOK §2, README diagram)

```
                    UPLOAD (up-carrier)
  Iran splitter (WS server :9001)  ── nginx/CDN (TLS origin) ──  Germany splitter
  [SPLIT_WS_LISTEN, localhost]          wss://<domain>/upload        (WS CLIENT)
        SPLIT_DOWN_CARRIER_ADDR=127.0.0.1:10802        SPLIT_UP_WS_URL=wss://<domain>/upload

                    DOWNLOAD (down-carrier)
  Iran splitter (DIALS 127.0.0.1:10802 = a LOCAL VLESS+Reality OUTBOUND)
        │  (Iran's local Xray outbound)
        ▼
  ─── internet ───►  Germany: VLESS+Reality INBOUND (public :443)
                        └─ forward → 127.0.0.1:9002 (Germany SPLIT_DOWN_LISTEN)
```

- **Up-carrier:** Iran is the WS **server/origin**; **Germany dials** it through
  the CDN (`wss://<domain>/upload`). Carries client upload bytes, `FrameHeader`,
  control.
- **Down-carrier:** **Iran dials** a **local** VLESS+Reality **outbound** on
  `127.0.0.1:10802`; that Xray outbound goes over the internet to **Germany's**
  VLESS+Reality **inbound**, which forwards the tunneled TCP to Germany's
  `:9002`. Carries target response bytes only.

**Key structural consequence:** the **down-carrier Reality keys are a
cross-host pair** — Iran's *outbound* needs Germany's Reality **public** key +
SNI + port; Germany's *inbound* holds the Reality **private** key. The Reality
key pair is therefore **generated on Germany** (private key stays there) and the
public key + SNI + port are part of the **pairing hand-off** the operator copies
to Iran. The **shared tunnel secret** (`SPLIT_SECRET`) is separate and also
cross-host. Two distinct secrets, two distinct hand-offs — this is clarified in
§8.

### 1.3 What the direction change does and does not touch

- **Touches (new work):** Germany self-contained deployment (Xray-core +
  Reality + up-carrier TLS origin + systemd + firewall + health + installer UX),
  pairing model, a high-level CLI, deployment testing (L2–L4), and closing the
  L5 infra gap.
- **Does not touch:** `pkg/node`/`pkg/session`/`pkg/mux` behavior, the frame
  protocol, auth v1, rebind/liveness, backpressure. #20 and #21 are **product**
  issues and are tracked separately — they are **prerequisites for a clean L5
  ACCEPT** but are **not** part of the deployment architecture.

## 2. Desired architecture

### 2.1 Layering

```
┌──────────────────────────────────────────────────────────────┐
│  PRODUCT ENGINE (unchanged)                                   │
│  pkg/node  pkg/session  pkg/mux   cmd/{iran,germany}-splitter │
└──────────────────────────────────────────────────────────────┘
              ▲ (thin transport wrappers call the engine)
┌──────────────────────────────────────────────────────────────┐
│  DEPLOYMENT ORCHESTRATION (new; Go, in cmd/splitterctl)       │
│  internal/deploy     — plan/apply/rollback/uninstall engine   │
│  internal/xray       — Xray-core install, Reality, config gen │
│  internal/origin     — up-carrier TLS origin (Caddy) provider │
│  internal/systemd    — unit gen, ordering, enable, health     │
│  internal/firewall   — ufw/nftables rules (idempotent)        │
│  internal/pairing    — secret + Reality hand-off generation   │
│  internal/doctor     — whole-deployment diagnostics           │
└──────────────────────────────────────────────────────────────┘
```

Rationale for the exact layout:

- **`cmd/splitterctl`** is the single new binary: the high-level CLI
  (`splitterctl install|upgrade|rollback|uninstall|doctor|status|pair`). The
  two splitter binaries stay exactly as they are. The CLI is a *client of* the
  `internal/*` deploy packages; the engine packages never import them.
- **`internal/` (Go) instead of shell** for the orchestration: the existing
  shell installer (~1.4k lines, bash) is the right tool for a first install,
  but the required upgrade/rollback/doctor/pairing/idempotence semantics, Xray
  artifact verification, and the clean-machine test (L4) are far more reliable
  in Go (deterministic, unit-testable, and checked against `internal/config`
  by construction). **Decision D1:** a thin `install.sh` (bootstrap: download
  the pinned `splitterctl` binary, verify its checksum, run
  `splitterctl install`) **and** the Go CLI. The bootstrap is the
  `curl | sudo bash` entry point but is small, pinned, and checksum-verified —
  it embeds no deployment logic (avoids "curl|bash runs arbitrary remote
  code": the script's only job is fetch-verify-execute of a pinned artifact).
- **`internal/xray` is a managed-transport adapter, not an Xray
  reimplementation** — it shells out to the `xray` binary for `version`,
  `x2025 reality keypair`, `run -test` (config validation), and `run`. No Xray
  protocol code is written in Go (answer to the direction's explicit question:
  embedding is **not** necessary; §12 dependency decisions).
- The deploy packages take an `Executor` interface (command runner, file
  writer, systemctl client) so L2 tests run them against fakes on any OS, and
  L4 runs them for real on a clean Ubuntu container.

### 2.2 Product/deployment boundary (invariants)

1. `pkg/*` never imports `internal/deploy`/`internal/xray`/etc. (import
   direction is one-way; enforced by a CI import test).
2. The deploy layer never reimplements validation the engine owns: generated
   config is validated by the **splitter binary's own config gate** (existing
   `--validate-config` behavior) and `xray run -test` — single source of truth
   preserved.
3. Deploy writes are *atomic* (write-tmp + rename), *backed up* (versioned
   `.bak-<ts>`), and *idempotent* (converge to desired state; a second run is a
   no-op unless inputs changed).
4. Every deploy mutation is recorded in a **manifest** (what was written, where,
   backup path, rollback recipe) — this makes `rollback` and `doctor` possible
   and prevents a half-finished install from being unknowable.
5. Secrets: the tunnel secret and the Reality private key live only in
   root-only files (0600) and are never printed, never logged, never in git,
   never in the manifest (the manifest records *paths* and *fingerprints*, not
   values).

## 3. Exact deployment topology (target)

### 3.1 Iran (user-facing; minimal)

```
USER
  │
  ▼
existing Xray/3x-ui (UNTOUCHED by this project except an OPTIONAL outbound merge)
  │  SOCKS5 outbound (user adds ONE outbound pointing at the splitter)
  ▼
iran-splitter  (systemd: iran-splitter.service)
  ├─ SOCKS5 127.0.0.1:10900        ← Xray outbound lands here
  ├─ WS server 127.0.0.1:9001      ← up-carrier origin (localhost only)
  │     ▲
  │     └─ Caddy/nginx (TLS origin on 443 → :9001)  OR  CDN back-to-origin here
  ├─ dials 127.0.0.1:10802 (down-carrier)
  │     ▲
  │     └─ (default, project-managed) iran-xray: dokodemo-door :10802 →
  │          VLESS+Reality outbound → Germany Reality inbound
  └─ metrics 127.0.0.1:<m>
```

Iran exposure to the Internet: **one** origin endpoint (the WS `/upload` TLS
origin on 443, or the CDN back-to-origin port). The SOCKS port and `:9001` are
**localhost-only**.

**Decision D2 (Iran down-carrier Xray):** the direction scopes *Germany* as
self-contained, and the user's existing Iran Xray/3x-ui is out of ownership.
Adding a VLESS+Reality **outbound** to the user's existing Xray config is a
one-block addition (like the existing `to-splitter` merge) but still touches the
user's Xray. To honor "the user must not have to modify the existing Xray
architecture beyond pointing an outbound at the splitter's SOCKS5 endpoint,"
the **default** design gives the project its **own** tiny Xray instance on Iran
(`iran-xray`, managed, non-root) whose *only* job is: serve a
`dokodemo-door` inbound on `127.0.0.1:10802` and forward it over a
VLESS+Reality outbound to Germany. The user's existing Xray keeps exactly one
change: a SOCKS outbound to `127.0.0.1:10900`. An **optional** mode
(`--merge-into-existing-xray`) can instead merge the Reality outbound into the
user's Xray config (reusing the existing merge machinery) for users who prefer a
single Xray process. Both modes first-class; default is the separate managed
process (cleaner ownership, trivial uninstall, zero risk to the user's panel).

### 3.2 Germany (self-contained; project owns everything)

```
INTERNET
  │  443 (VLESS+Reality inbound — the ONLY public port)
  ▼
xray-germany (managed Xray-core; systemd: xray-germany.service; non-root)
  ├─ inbound: VLESS + Reality (dest/SNI = operator-chosen, e.g. www.example.com:443)
  └─ outbound: freedom (redirect 127.0.0.1:9002) (opaque TCP hand-off)
  │  (Reality keypair generated by the installer; private key never leaves)
  ▼  127.0.0.1:9002
germany-splitter (systemd: germany-splitter.service)
  ├─ down-carrier TCP listener 127.0.0.1:9002 (localhost only; only Xray reaches it)
  ├─ up-carrier WS CLIENT → wss://<upload-domain>/upload (CDN or direct origin)
  └─ metrics 127.0.0.1:<m>

upload-domain DNS:  CNAME → CDN  OR  A/AAAA → Iran's origin IP
```

Germany exposure: **one** public port — the VLESS+Reality inbound (443).
`:9002` is **localhost-only** (the Reality inbound is the auth boundary;
matches RUNBOOK §2.2 "block direct :9002").

**Decision D3 (Xray → splitter handoff):** the Xray inbound must deliver the
*raw tunneled TCP bytes* (the splitter's own frame/auth protocol) to
`127.0.0.1:9002`. The outbound is a `freedom` with
`settings.redirect = "127.0.0.1:9002"`: at the pinned Xray v26.3.27 tag,
`dokodemo-door` is registered as an INBOUND protocol only (the
`inboundConfigLoader` in `infra/conf/xray.go`), so a dokodemo-door **outbound**
fails `xray run -test` with `unknown config id: dokodemo-door`. freedom's
`redirect` sets a `DestinationOverride` (infra/conf/freedom.go) that forces
every dial target to the fixed endpoint (proxy/freedom/freedom.go) — exactly
the opaque-TCP hand-off. The inbound is the single VLESS+Reality inbound on
443; routing sends all its traffic to that outbound. This is the
"inbound/outbound relationship" the direction asks us to determine: a
**one-inbound → one-freedom(redirect)-outbound** topology, validated by
`xray run -test` with the real pinned binary and by an L5 carrier handshake
test (a real `FrameAuth` over the Reality tunnel).

### 3.3 Public vs localhost matrix

| Endpoint | Host | Bind | Internet? | Reason |
|---|---|---|---|---|
| VLESS+Reality inbound | Germany | 0.0.0.0:443 | **yes** | down-carrier transport; Reality is the auth boundary |
| WS origin (upload) | Iran | 0.0.0.0:443 (Caddy) or the CDN origin port | **yes** (origin) | up-carrier transport; auth = tunnel secret over TLS/WS |
| HTTP 80 (ACME HTTP-01) | Iran | 0.0.0.0:80 | **yes** — caddy direct mode only | certificate acquisition; Caddy 301-redirects non-ACME to HTTPS. Not opened in cdn mode (no ACME there) |
| `:9002` down listener | Germany | 127.0.0.1:9002 | **no** | only the local Xray inbound may reach it |
| `:9001` WS server | Iran | 127.0.0.1:9001 | **no** | only the local Caddy/nginx may reach it |
| SOCKS `:10900` | Iran | 127.0.0.1:10900 | **no** | only the user's local Xray may reach it |
| `:10802` down serve | Iran | 127.0.0.1:10802 | **no** | only `iran-splitter` dials it; only `iran-xray` serves it |
| metrics (both) | both | 127.0.0.1:<m> | **no** | diagnostics only |

## 4. Xray integration design

Research basis: the **official `XTLS/Xray-install`** script (read in full) and
the `XTLS/Xray-core` release model.

### 4.1 Installation (Q1)

- **Do not** curl|bash the upstream script on production hosts. `internal/xray`
  performs the same *steps* the official script uses, with the project's own
  pin + verification + manifest:
  1. Resolve the pinned version (§4.2) →
     `https://github.com/XTLS/Xray-core/releases/download/<v>/Xray-linux-<arch>.zip`.
  2. Download the zip **and** its `.dgst` sidecar (the official release
     publishes `<zip>.dgst` containing a `SHA2-256: <hex>` line — the
     upstream-supported checksum, satisfying "verify checksums where the
     upstream distribution supports it").
  3. Verify SHA-256 in constant time; **fail closed** on mismatch or missing
     `.dgst` (releases without a `.dgst` are rejected — §4.2 pin floor).
  4. Extract into a **project-owned prefix** (default
     `/opt/split-tunnel/xray/<version>/`): binary (+ geo dat files only with
     `--with-geodata`; the carrier topology needs no geo rules, so geodata is
     skipped by default to keep installs small).
  5. `xray version` smoke check, then `xray run -test -config <generated>` as
     the gate **before** any service is (re)started.
- Managed user: a dedicated system user `split-tunnel` (non-root) for all
  managed processes; `NoNewPrivileges=true` in every unit. Xray binds 443 ⇒
  granted narrowly: `AmbientCapabilities=CAP_NET_BIND_SERVICE` +
  `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (not the broader set the
  upstream script uses). The splitter binds only >1024 localhost ports ⇒ no
  capabilities.

### 4.2 Version pinning (Q2)

- A single **pinned Xray version constant** in the deploy code
  (`xraycore.PinnedVersion`, chosen at implementation time as the newest stable
  release whose zip has a `.dgst` and which ships the
  `x2025 reality keypair` subcommand — both true of all recent stable releases).
- The pin is **per project release** (bumped deliberately), never "latest" —
  reproducibility and rollback depend on it. The manifest records the exact
  installed version + sha256.
- An L2/CI test resolves the pinned version's release assets via the GitHub API
  and asserts the zip + `.dgst` URLs exist (fails the build if the pin
  points at nothing); L4 re-verifies the download on a clean host.

### 4.3 Upgrades (Q3) & rollback (Q4)

- **Upgrade** = re-plan against the new desired state (newer pinned Xray
  and/or new splitter binary). The planner diffs desired vs current (manifest +
  live probes: `xray version`, `systemctl cat`, file hashes) and emits only the
  changing steps, ordered: download+verify new Xray → write new config to
  `<path>.new` → `xray run -test` on `.new` → atomic swap →
  `systemctl restart` in dependency order → health probe. The old version stays
  on disk (versioned layout) until `splitterctl cleanup --older-than 30d`, so
  rollback is a pointer swap, not a re-download.
- **Rollback** = restore the manifest's last *successful* state: previous Xray
  version dir, previous config (versioned backup), previous splitter binary
  (kept as `.prev` under `/opt/split-tunnel/bin/`), restart in dependency order,
  health probe. Rollback never prompts and never touches files outside the
  project prefix.
- **Splitter binary distribution:** prebuilt GitHub release artifacts
  (`iran-splitter`, `germany-splitter`, `splitterctl` per arch), each with a
  `.sha256` the bootstrap/installer verifies. Building from source remains a
  fallback flag (`--from-source`, current `install.sh` behavior).

### 4.4 Reality key generation (Q5)

- Generated on **Germany** at install time by shelling out to
  `xray x2025 reality keypair` (exact flag confirmed against the pinned version
  at implementation time; stable across recent releases). Output: X25519
  **private** key + derived **public** key.
- Private key → root-only deploy state (`/etc/split-tunnel/germany.json`, 0600)
  and embedded in the generated Xray config (0600). **Never printed, never
  logged, never in the pairing output, never in git.**
- Public key + SNI + port + shortId + UUID → the **pairing hand-off** (printed
  once, stored in the Iran-side state file) — §8.
- **UUID:** the VLESS client ID, generated on Germany at install time
  (UUIDv4). In the Reality model it is not the auth factor (the handshake is),
  but it is paired with the keypair and travels in the hand-off. One UUID —
  this is a machine-to-machine link, **not** a multi-user server (no
  3x-ui-style user management; explicitly out of scope).
- **Rotation:** `splitterctl rotate-reality` regenerates the pair on Germany,
  re-emits the hand-off; the operator re-applies on Iran (`splitterctl pair
  apply`). Documented operator action, not automatic (cross-host automatic
  rotation without a control channel is out of scope; a stale key simply fails
  the carrier handshake and `doctor` identifies it as the cause).

### 4.5 Exact Xray topology — Germany (Q6, Q7, Q8)

```jsonc
// /etc/split-tunnel/xray-germany.json  (0600; generated, never hand-edited)
{
  "log": { "loglevel": "warning", "error": "/var/log/split-tunnel/xray-germany.error.log" },
  "inbounds": [{
    "tag": "split-down",
    "listen": "0.0.0.0", "port": 443,
    "protocol": "vless",
    "settings": { "clients": [ { "id": "<UUID>" } ], "decryption": "none" },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "dest": "<SNI>:443",            // derived from SNI (never operator input)
        "serverNames": ["<SNI>"],
        "privateKey": "<REALITY-PRIVATE>",
        "shortIds": ["<16-hex>"]
      }
    }
  }],
  "outbounds": [{
    "tag": "to-splitter",
    "protocol": "freedom",
    "settings": { "redirect": "127.0.0.1:9002" }   // dokodemo-door is inbound-only at v26.3.27
  }],
  "routing": { "rules": [
    { "inboundTag": ["split-down"], "outboundTag": "to-splitter" }
  ]}
}
```

- **Q7 (how Xray connects to the splitter):** the freedom(redirect) outbound IS
  the connection — Xray terminates VLESS+Reality and forwards the opaque TCP
  stream to `127.0.0.1:9002`, where `germany-splitter`'s down-carrier listener
  runs its own `FrameAuth` handshake. Two auth layers, each doing its job:
  Reality authenticates/stealths the *transport*; the tunnel secret
  authenticates the *peer* (a correct Reality client with the wrong tunnel
  secret is still rejected by the splitter — defense in depth preserved).
- **Q8 (how the splitter exposes the required endpoint):** unchanged —
  `SPLIT_DOWN_LISTEN=127.0.0.1:9002`. The engine is untouched; the deploy
  simply generates the env.
- `dest` (Reality camouflage target) must be a real TLS 1.3 site reachable
  from Germany. The installer **validates** it at install time (TCP reachability
  + TLS 1.3 probe, bounded 10 s); unreachable `dest` fails the install, a
  suboptimal `dest` (e.g. no TLS 1.3) fails hard because Reality requires it —
  both are preflight, not runtime surprises.

### 4.6 Iran Xray (D2 default mode)

A minimal `iran-xray` config (0600): one `dokodemo-door` **inbound** on
`127.0.0.1:10802` (the splitter's down dial lands in Xray) → one `vless`
**outbound** to Germany:

```jsonc
{
  "inbounds": [{
    "tag": "split-down-serve",
    "listen": "127.0.0.1", "port": 10802,
    "protocol": "dokodemo-door",
    "settings": { "address": "<germany-host-or-ip>", "port": 443 }   // logical destination (required field)
  }],
  "outbounds": [{
    "tag": "reality-out",
    "protocol": "vless",
    "settings": { "vnext": [{ "address": "<germany-host-or-ip>", "port": 443,
        "users": [{ "id": "<UUID>", "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
    "streamSettings": { "network": "tcp", "security": "reality",
      "realitySettings": { "fingerprint": "chrome", "serverName": "<SNI>",
        "publicKey": "<REALITY-PUBLIC>", "shortId": "<16-hex>", "spiderX": "/" } }
  }],
  "routing": { "rules": [ { "inboundTag": ["split-down-serve"], "outboundTag": "reality-out" } ] }
}
```

- A `dokodemo-door` **inbound** requires `settings.address`/`settings.port`
  (the logical destination of the incoming stream); with the routing rule
  above, the vless `vnext` is the actual destination. (v0.1 wrote
  `address: "unused"`, which fails `xray -test` — fixed in v0.2, review H1.)
- The generated file is gated by `xray -test -config` before any restart, and
  a golden-file test pins the shape (T3) so a config regression fails CI, not
  the install.
- Vision flow requires TLS 1.3 on `dest` (checked in preflight). `iran-xray`
  binds no public port.
- `--merge-into-existing-xray` mode (D2 option) must add **all three** pieces
  to the user's Xray — the dokodemo-door inbound, the vless outbound, and the
  routing rule — with the existing backup + preview mechanism (the v0.1 merge
  machinery only handled outbound + routing; an inbound merge is new —
  review M4). The preview shows the exact JSON diff before applying.

## 5. CDN integration design (up-carrier)

### 5.1 Where the WS path terminates (Q9, Q10)

Iran's `:9001` is localhost; the public up path is `wss://<upload-domain>/upload`.
Behind a **provider abstraction** (`internal/origin`, interface
`OriginProvider { Configure(ctx, Plan) error; Status(ctx) (Health, error) }`):

1. **`caddy` (default, self-contained)** — the project installs a local
   **Caddy** reverse-proxy on **Iran** with an auto-managed certificate
   (Let's Encrypt ACME — **HTTP-01 by default** so it works before the
   certificate exists; TLS-ALPN-01 only as an operator-acknowledged fallback
   when port 80 is unusable) for `<upload-domain>`:
   `location /upload → 127.0.0.1:9001` with the exact WS upgrade headers the
   current nginx snippet uses (Upgrade/Connection, 3600 s read/send timeouts).
   Caddy is chosen over nginx because **nginx cannot do ACME** — with nginx the
   operator would need a certificate, which violates "the user must not
   manually configure the transport stack." Caddy's on-demand ACME is the only
   self-contained way to satisfy "public domain with CDN **or direct TLS
   origin**" with zero operator TLS work. Caddy is a pinned, checksummed
   artifact (official `caddy` distro), installed under the same project prefix,
   running as `split-tunnel` with the same narrow capability set.
   Q10 answer: **yes, the project needs a reverse proxy on Iran (Caddy) in
   direct-origin mode**; in CDN mode the CDN terminates TLS and the origin
   behind the CDN may be plain-WS-on-a-local-port or Caddy — both supported.
2. **`cdn` (operator CDN, e.g. Cloudflare)** — the operator points their CDN
   at Iran's origin (CNAME to the CDN, or A/AAAA per the CDN's requirement).
   No **ACME** in this mode (the domain resolves to the CDN, so an origin
   challenge cannot complete without a DNS-01 API — explicitly out of v1
   scope). Two origin options, both operator-config-free:
   - **A (default): TLS origin.** The project installs Caddy on the origin
     port with a **self-signed (internal CA) certificate**; the CDN's origin
     pull is TLS to that certificate (origin-verification / "Origin CA" style
     per the CDN). TLS end-to-end from the user to the origin.
   - **B: plain origin.** No Caddy; the splitter's own WS listener serves the
     origin (`SPLIT_WS_LISTEN=0.0.0.0:<origin-port>` — the WS upgrade, the
     `/upload` path restriction, and the handshake limit are native to the
     splitter). The CDN's origin pull is plain HTTP/WS. An explicit security
     note is printed: the CDN→origin leg is unencrypted; auth v1 still
     authenticates every connection (no key material in the clear — a
     challenge, one-time nonces, and a keyed MAC only), but the protocol
     traffic is visible on the origin port; choose A for a hardened origin.
   The installer prints, per mode, the exact CDN origin configuration (host,
   port, TLS setting, path `/upload`, WebSocket enabled, Upgrade/Connection
   headers, idle timeout ≥ 3600 s) and the exact DNS record. No
   provider-specific API calls in v1 — **provider adapters are a later
   extension point** (the interface isolates them); v1 treats every CDN as
   "operator configures the CDN in their console, we tell them exactly what."
   This honors "do not assume a particular CDN provider" and "if a
   provider-specific API is required, isolate it behind an adapter" without
   inventing a Cloudflare dependency. (v0.1 was vague about origin TLS here —
   fixed in v0.2, review H3.)
3. **`none` (testing only)** — bare `ws://<iran-ip>:9001/upload` for L4-style
   local tests; explicitly rejected by the config validator for the public
   deployment (the existing `checkWsUrl` already accepts `ws://` for staging —
   keep that for tests, but `splitterctl install` for a real domain defaults to
   `wss://`).

### 5.2 What must be publicly exposed (Q11) — summary

- **Germany:** `0.0.0.0:443` (Reality inbound). Nothing else.
- **Iran:** the origin port for `<upload-domain>` (443 in caddy mode; the
  CDN's back-to-origin port in cdn mode). Nothing else.
- Everything else is in §3.3 (localhost-only).

## 6. CLI / installer design

### 6.1 Command surface (the "cleanest design")

One binary, two roles, subcommands that map 1:1 to operations:

```
splitterctl install iran     [--non-interactive --defaults]  [--merge-into-existing-xray]
splitterctl install germany  --sni <SNI> --dest <SNI>:443 --domain <upload-domain>
                             [--origin caddy|cdn] [--down-port 443]
splitterctl pair generate    (on Iran: emits the pairing blob to copy to Germany)
splitterctl pair apply       (on Germany: consumes the blob; generates Reality;
                              prints the RETURN blob to copy back to Iran)
splitterctl pair finalize    (on Iran: consumes the return blob)
splitterctl status           (both: services, ports, carrier state, metrics)
splitterctl doctor           (both: full diagnostics, §6.4)
splitterctl upgrade          [--xray] [--splitter]
splitterctl rollback         [--to <state-id>]
splitterctl uninstall        [--purge]   (explicit confirmation; never auto)
splitterctl config show|set  (inspect/change non-secret config, re-validates)
```

**Pairing flow (the only cross-host human step):**

1. `splitterctl install iran` → installs splitter + iran-xray + Caddy(origin),
   generates `SPLIT_SECRET` (256-bit, `crypto/rand`), prints **pairing blob A**
   (contains the tunnel secret + Iran public endpoint facts: upload domain,
   down Reality target = Germany placeholder, ports). The user copies blob A to
   Germany (one string; scp/clipboard).
2. `splitterctl install germany --pairing <blobA> ...` → installs Xray-core,
   generates the **Reality keypair + UUID + shortId** locally, writes the
   Germany config, installs services, and prints **return blob B** (contains
   the Reality *public* key, SNI, shortId, UUID, port — no private key, no
   tunnel secret). The user copies blob B to Iran.
3. `splitterctl pair finalize` on Iran → writes the `iran-xray` outbound from
   blob B, restarts `iran-xray`, probes the carrier path end-to-end (opens the
   down dial and checks for a Reality+FrameAuth handshake), and prints the
   **SOCKS5 endpoint** the user points their existing Xray outbound at.

Blobs are base64 + a format tag + a checksum; they contain **only** what the
receiving side needs and are validated on receipt (tamper/typo detection).
Secrets inside blobs are printed **once**, to the terminal, never logged, and
persist only to 0600 state files on the receiving host. The tunnel secret is
generated on **Iran** (the "hosting" side of the user-facing endpoint) — the
existing installer already generates it on the Iran node, and that behavior is
preserved (compatibility + the user's muscle memory). The Reality private key
is generated on **Germany** and never transits.

**Idempotence (mandatory):** every subcommand is safe to re-run. `install`
detects an existing installation (state file `/etc/split-tunnel/state.json` +
`systemctl` probes + binary version) and **converges**: unchanged inputs →
"already installed, nothing to do"; changed inputs → upgrade semantics with a
clear diff of what will change, and a `--reconfigure` confirmation for
destructive deltas (port moves, SNI change, secret rotation). A failed install
leaves the previous state intact (manifest rollback on any error) — the answer
to Q24 (prevent destroying an existing server): **no step runs before all
preflight checks pass; every step is reversible; state is versioned; the user's
existing Xray is never touched in default mode.**

### 6.2 Interactive vs non-interactive

- Default: interactive wizard (the existing `install.sh` UX, ported to Go:
  `ask`/`ask_valid`/`ask_yesno` patterns, defaults shown, validators identical
  to `internal/config` bounds).
- `--non-interactive` + flags (or a `splitterctl install --file deploy.yaml`
  desired-state file) for automation and the L4 clean-machine test.

### 6.3 Bootstrap entry point

```
curl -fsSL https://<repo>/install.sh | sudo bash -s -- <role> [flags...]
```

`install.sh` (v2, small) only: parses the role, fetches the pinned
`splitterctl` artifact for the platform, verifies its `.sha256` (the expected
hash is embedded in the script at release time), and execs
`splitterctl install <role> [flags]`. Nothing else.

### 6.4 `doctor` (Q23)

`splitterctl doctor` runs a fixed, read-only check list and prints a
pass/fail/warn table with the exact next action per failure:

- state file present & versioned; services enabled+active (`systemctl is-active`);
- ports bound as designed (§3.3) — `ss -ltnp` parsed;
- config gate: re-run the binary's `--validate-config` (fails closed on drift);
- `xray run -test` on the live config; Xray version == manifest version;
- up path: `wss://<domain>/upload` reachable + WS upgrade from Germany (a
  bounded probe with a *wrong* secret must get the challenge, proving the
  transport works and auth is enforced);
- down path: Reality preflight (dest TLS 1.3 reachability), then a
  FrameAuth probe from Iran's down dial (correct secret ⇒ carrier installs);
- carrier state from metrics endpoints (up/down ready, generations);
- firewall rules present (ufw/nftables query) matching §3.3;
- disk/log space for `/var/log/split-tunnel` (logrotate present);
- clock skew (auth v1 tolerance ±300 s — warn if >120 s);
- known-issue hints (#20 stranded-session signature: refused-rebind counter
  climbing with a live stream; #19 blackhole signature: RTO backoff on carrier
  conns).

## 7. Configuration schema

### 7.1 Runtime (splitter) — unchanged

The 18 `SPLIT_*` env vars remain exactly as they are (`internal/config` is the
source of truth; the deploy layer generates them into the units). No new
runtime env vars are needed for the new transports: Germany's
`SPLIT_UP_WS_URL` becomes `wss://<domain>/upload` (generated from the domain
input) and `SPLIT_DOWN_LISTEN` becomes `127.0.0.1:9002`; Iran's
`SPLIT_DOWN_CARRIER_ADDR` becomes `127.0.0.1:10802` (the managed `iran-xray`).

### 7.2 Deploy state (new; `/etc/split-tunnel/`, 0600, owned by root)

```jsonc
{
  "version": 1,                       // state schema version
  "role": "germany",
  "installedAt": "...", "updatedAt": "...",
  "splitter": { "version": "vX.Y.Z", "sha256": "..." , "path": "/opt/split-tunnel/bin/germany-splitter" },
  "xray":     { "version": "v25.x.y", "sha256": "...", "path": "/opt/split-tunnel/xray/v25.x.y/xray" },
  "origin":   { "mode": "caddy", "domain": "upload.example.com", "caddyVersion": "..." },  // iran
  "reality":  { "uuid": "...", "shortId": "...", "publicKey": "...", "privateKey": "<never serialized; file-ref only>" }, // germany
  "secrets":  { "tunnel": "file:/etc/split-tunnel/secret.key (0600)" },  // path ref, never value
  "endpoints": { "socks": "127.0.0.1:10900", "ws": "127.0.0.1:9001", "down": "127.0.0.1:9002",
                 "downCarrier": "127.0.0.1:10802", "realityIn": "443", "uploadDomain": "upload.example.com" },
  "peering":  { "peerRole": "iran", "pairState": "finalized" },
  "states": [ { "id": "s1", "ts": "...", "label": "install", "manifest": "manifests/s1.json" } ]  // rollback points
}
```

Rules: secret *values* live in separate 0600 files (`secret.key`,
`reality-private.key`) referenced by path; the state file is 0600; the state
file is the **only** place rollback reads from; any manual edit outside
`splitterctl` is detected (checksum) and `doctor` warns.

## 8. Secret-management design

Two independent secrets, two different lifecycles:

| Secret | Generated on | Travels? | Stored (value) | Used by |
|---|---|---|---|---|
| Tunnel secret (`SPLIT_SECRET`) | Iran (existing behavior) | yes — pairing blob A → Germany | 0600 file + systemd `Environment=` (root-only unit file, as today) | both splitters (auth v1) |
| Reality private key | Germany | **never** | 0600 file + embedded in Xray config (0600) | xray-germany inbound |
| Reality public key + SNI + shortId + UUID | Germany | yes — return blob B → Iran | Iran state (not secret-grade but paired) | iran-xray outbound |

- Generation: `crypto/rand` (Go) everywhere; 256-bit hex for the tunnel secret
  (satisfies the existing `mux.ValidateSecretMaterial` policy — the deploy
  re-runs that validator before enabling services).
- **Never printed twice** (printed exactly once at generation, to the tty, with
  a "shown once" notice); **never logged** (all deploy log lines pass through a
  redaction filter that masks the secret, the private key, and any 32+ hex
  runs); **never in git** (the state dir is on-host only; CI never reads it);
  **never in the manifest** (fingerprints only).
- **Rotation:** `splitterctl pair rotate-secret` (tunnel) and
  `rotate-reality` (Reality) — both re-emit the cross-host blob, both
  require the peer to apply before the old value is discarded, both are
  documented two-step (no silent cross-host rotation).
- Unit files: the tunnel secret stays in the systemd unit via
  `Environment=SPLIT_SECRET=...` in a 0600 root-owned unit (existing,
  proven) — or, cleaner, `EnvironmentFile=/etc/split-tunnel/env` (0600);
  **Decision D4:** switch to `EnvironmentFile` so the unit file itself carries
  no secret (easier `systemctl cat` hygiene, same security level).

## 9. Upgrade / rollback design (Q17, Q21, Q22)

- **State machine:** every completed `install`/`upgrade`/`pair` writes a new
  state entry (`states[]`) = snapshot of the manifest (file hashes, versions,
  service list, firewall rules) + backups of anything overwritten. At most N=10
  states retained (oldest pruned, their backups with them).
- **Upgrade:** plan → preflight (all green) → apply steps in order, each step
  journaled (step id, command, exit, duration) → health gate → commit state.
  If any step fails or the health gate fails: **automatic** rollback to the
  previous committed state (best-effort, logged), then exit non-zero with the
  failure report. The system is never left in a mixed version (splitter v2 +
  config v1) for longer than the rollback takes; mixed states are also
  detectable by `doctor` (version cross-checks).
- **Config-change safety (Q17):** `config set` writes the new value → runs the
  binary config gate + `xray run -test` against the *projected* config → only
  then swaps and restarts the affected service (least restart: port change
  restarts splitter only; SNI change restarts xray-germany only). A failed
  projection aborts with nothing changed.
- **Rollback:** `splitterctl rollback [--to sN]` restores that state: binaries
  (from versioned dirs/backups), configs (from backups), units, firewall rules,
  then restarts in dependency order + health gate. Rollback of the *pairing*
  (new Reality pair) is by re-applying the previous return blob (kept in
  states).

## 10. Firewall / systemd design (Q12, Q13, Q15, Q16)

### 10.1 systemd ordering (Q13)

```
Germany:
  network-online.target
    └─ xray-germany.service          (After=network-online; Restart=on-failure;
                                       RestartPreventExitStatus=23; CAP_NET_BIND_SERVICE)
        └─ germany-splitter.service  (After=xray-germany; Wants=xray-germany;
                                       Restart=always RestartSec=5 — existing behavior)
Iran:
  network-online.target
    ├─ iran-xray.service              (After=network-online; Restart=on-failure;
                                       non-root; no caps — binds only 127.0.0.1:10802)
    ├─ caddy.service (origin caddy; After=network-online; Restart=on-failure;
                     CAP_NET_BIND_SERVICE for 443)        [caddy mode only]
    └─ iran-splitter.service          (After=iran-xray + origin; Restart=always)
```

- Dependency is `After=`/`Wants=` (not `Requires=`): if Xray dies, the splitter
  must keep running (carriers reconnect — that is the product's designed
  behavior, proven in L5 run A); systemd restarts Xray independently. The
  splitter's own backoff + liveness handle the carrier outage; this is exactly
  the "session lifetime independent of carrier lifetime" invariant.
- **Q15 (Xray fails):** `Restart=on-failure` — the carrier loss is observed by
  the splitter (log + metrics), in-flight sessions survive the rebind window or
  fail bounded; `doctor` flags "xray flap" (restart count in last 10 min) as
  the root cause. No cascade stop of the splitter. **Bounded-restart policy
  (review M6):** the managed Xray units additionally set
  `StartLimitIntervalSec=300` / `StartLimitBurst=10` — a crash-looping Xray
  enters `failed` state *explicitly* (visible in `status`/`doctor`) instead of
  restart-flapping forever and pinning a CPU core in backoff; the splitter
  stays up either way (carriers just stay lost until the operator acts).
- **Q16 (splitter fails):** `Restart=always` (existing). Xray keeps running;
  when the splitter returns, Iran re-dials and Germany re-accepts (new
  generations; sessions that outlived the outage are already closed per the
  engine's rules).
- All managed units: `User=split-tunnel` (except root for file ownership
  during install), `NoNewPrivileges=true`, `LimitNOFILE=65535` (splitter, as
  today; Xray 100000), journald output, `SyslogIdentifier` per service.

### 10.2 Firewall (Q13)

- Provider abstraction again (`internal/firewall`): **ufw** (Ubuntu default)
  implemented first, **nftables** raw as a fallback when ufw is absent,
  **none** mode for tests/CDN-fronted-where-CDN-filters.
- Rules are applied as **managed chains** (ufw: dedicated comments
  `# split-tunnel`; nftables: dedicated table `split_tunnel`) so `uninstall`
  removes exactly what the project added and `doctor` can verify them.
- Germany: allow in 443/tcp (only if not already allowed by another app —
  detect first; if 443 is taken by an existing service the install **fails
  with guidance**, it never displaces it); deny in everything else is left to
  the host's policy (the project never sets a default-deny on a server it
  doesn't own); **explicitly ensure 9002 is not reachable externally** (if the
  host policy is default-allow, the project adds a deny-in for 9002).
- Iran: allow in the origin port (443 in caddy direct mode; the origin port in
  cdn mode). **In caddy direct mode, also allow 80/tcp** — required for ACME
  HTTP-01 on first install (chicken-and-egg: TLS-ALPN-01 needs the very
  certificate that HTTP-01 issues; the installer uses HTTP-01 by default and
  falls back to TLS-ALPN-01 only when the operator says port 80 is unusable,
  which then requires the A record to resolve first — documented ordering,
  §14). In cdn mode, if the operator supplies the CDN's egress ranges, rules
  are restricted to them (flag `--cdn-egress-cidrs`). Never open
  9001/10900/10802 externally. Conflict detection (review M5): before
  installing, probe 443/80 (and the origin port) — if another service already
  binds them (via `ss -ltnp`), the install **fails with guidance**
  (reconfigure that service or choose different ports); it never displaces an
  existing service — the same policy as Germany 443.
- Idempotent: applying twice is a no-op (rules checked before adding).

## 11. Clean-machine test strategy (Q25) + test pyramid

- **L1 — unit (CI, all OS):** `internal/xray` (config generation golden files,
  keypair parsing, `.dgst` verification against fixture zips, version pin
  resolution), `internal/origin` (Caddyfile generation), `internal/firewall`
  (rule diffing against fake `ufw` output), `internal/deploy` (planner
  diff/rollback against a fake `Executor`), `internal/pairing` (blob encode/
  decode/tamper). No network, no root.
- **L2 — installer-logic tests (CI, Linux containers):** run
  `splitterctl install` end-to-end **inside a container with a fake systemctl
  shim** (records unit files, does not start real services) + fake `ufw` —
  asserts: idempotence (run twice → second is no-op), all files generated at
  0600 where required, units reference only generated paths, config gate
  green, manifest written, rollback restores. This catches schema/drift bugs
  cheaply, every PR.
- **L3 — failure injection (CI, Linux containers):** same harness with
  faulting shims: Xray download returns bad checksum (must fail closed, no
  partial state), `xray run -test` fails on a bad config (install aborts,
  previous state intact), systemctl restart fails mid-upgrade (auto-rollback
  fires), pairing blob corrupted in transit (rejected), 443 occupied by a
  rogue listener (install fails with guidance).
- **L4 — clean Ubuntu VM/container deploy (CI, on-demand job, real):**
  two Ubuntu 24.04 containers/VMs (Iran + Germany) + one client; real systemd
  (or a documented `systemctl`-compatible shim where containers lack it —
  preferred: a tiny VM via the same runner class L4 two-proc uses), real
  `splitterctl install` on both with a **public test domain** (repo-owned,
  e.g. `*.split-tunnel-test.dev`) or a local CA + `--origin caddy` with
  `CADDY_INTERNAL` for the no-public-DNS variant; then run the **existing L5
  matrix** (the 20 scenarios) against the deployed system. This is the
  "fresh Ubuntu → installer → splitter → Xray → CDN/reverse proxy → real
  two-server tunnel → SOCKS5 → Internet" proof the direction requires.
  Internet egress for the down-carrier target test is allowed for this job
  only (explicitly intended, per the testing rules).
- **L5 — two real staging servers:** unchanged — but now the staging
  topology is produced by the installer itself (that is the point: L5 run B
  provisions Germany *with* `splitterctl install germany`, which closes the
  #19 infra gap). The operator supplies: the staging domain + DNS, the CDN
  choice, the Reality SNI/dest.
- **L6 — long-running deployed system:** 24–48 h soak on staging after L5
  passes: metrics scrape, RSS/fd settle (scenario 18 semantics), flap
  scenario 17, restart 20; record in `IMPLEMENTATION_STATUS.md`.

## 12. L5 test plan (with the new deployment)

1. **Provision:** `splitterctl install germany --sni ... --dest ... --domain
   <staging-upload-domain> --origin cdn` (operator pre-creates the CDN
   mapping + DNS record — the only two manual steps) and
   `splitterctl install iran` on staging Iran (staging Iran has a *test* Xray
   standing in for the user's 3x-ui; default mode, separate `iran-xray`).
2. **Pair:** blobs A → B → finalize; carrier probes green.
3. **Matrix:** run the existing 20-scenario matrix **twice** (normal +
   `-race` builds), exactly per RUNBOOK §3/§4, recorded in
   `IMPLEMENTATION_STATUS.md`. Scenario 10 (Xray consumer path) now uses the
   staging Iran Xray with the generated `to-splitter` outbound merge.
4. **Gate:** ACCEPT requires 20/20 ×2 **and** #20/#21 resolved (or explicitly
   documented as accepted conditions with their issues linked). L5 stays open
   until recorded (existing issue discipline).

## 13. Required operator inputs (minimal, honest)

| Input | Host | Why it cannot be generated |
|---|---|---|
| **Reality SNI + `dest`** (e.g. `www.microsoft.com:443`) | Germany | operator's camouflage choice; must be a TLS 1.3 site reachable from Germany. **Note (review M2):** Iran's *outbound* Reality traffic to Germany is *not* camouflaged — only Germany's *inbound* is. If Iran→Germany TCP to port 443 is itself blocked/flagged on the Iran side, Reality does not solve it; the design documents this explicitly and `doctor` distinguishes "Iran can't reach Germany 443 at TCP level" from "Reality handshake failing" |
| **Upload domain** (e.g. `upload.example.com`) | Iran+Germany | the operator's DNS; must point at Iran's origin (or their CDN) |
| **CDN choice + (if cdn) CDN origin config** | Iran | the operator's CDN account; v1 prints the exact config, no API |
| **DNS record for the upload domain** | operator's DNS | **A/AAAA → Iran IP** (direct) or **CNAME → their CDN** — the exact record is printed by the installer; DNS is the one thing the software cannot do for the user |
| (optional) port overrides, metrics on/off, geodata | both | preferences only |

**No other inputs.** No Xray config, no keys, no systemd, no nginx/Caddy
config, no firewall syntax. (If the operator's CDN requires API credentials to
*create* the mapping, that is the operator's CDN console — v1 does not call
CDN APIs; §5.1.)

## 14. Required DNS records

- `<upload-domain>` → **A/AAAA** to Iran's public IP (direct origin) **or**
  **CNAME** to the operator's CDN hostname (cdn mode). Exactly one record.
  Printed verbatim by `splitterctl install iran` with the expected value.
- No TXT records (Caddy ACME uses HTTP-01 on the domain's 80 or TLS-ALPN-01 on
  443; 80 must be reachable for HTTP-01 — the installer checks and, if 80 is
  blocked, uses TLS-ALPN-01 which needs the A record to already resolve;
  documented ordering: create the DNS record first, then run install).

## 15. Required CDN configuration

- cdn mode: origin host = Iran IP, origin port = 443 (caddy) or 9001+TLS
  (if the operator insists on nginx — not default), path `/upload`,
  **WebSocket enabled** on the CDN rule, headers Upgrade/Connection passed,
  idle timeout ≥ 3600 s, TLS terminated at the CDN. Printed as a copy-paste
  block per the two most common CDNs (Cloudflare, generic) with a "your CDN
  may differ — the requirements are: WS upgrade + these headers + timeouts"
  note. No assumptions, no API calls.

## 16. Required Xray/Reality configuration

- **Fully generated** (this is the point): `xray-germany.json` (§4.5),
  `iran-xray.json` (§4.6, default mode), the Reality keypair, UUID, shortId.
  The operator never sees or writes Xray JSON. (`--merge-into-existing-xray`
  mode adds the dokodemo-door inbound + vless outbound + routing rule to the
  user's config — §4.6 — with the preview diff + backup mechanism.)
  **Inbound port-conflict preflight (review M3):** before enabling
  `xray-germany`, the installer probes 443 (and 80 in caddy direct mode on
  Iran) and fails with guidance if occupied (see §10.2 conflict policy).

## 17. Issue breakdown (independently revertible tasks)

Each is one focused commit/PR; order respects dependencies:

1. **T0** `docs`: this design + implementation plan merged to `main` (reviewed).
2. **T1** `internal/pairing`: blob format (tag, payload, checksum), encode/
   decode, tamper tests. (L1)
3. **T2** `internal/xray`: version pin + release asset resolution + `.dgst`
   verify + install-into-prefix (fake-Executor L1/L2).
4. **T3** `internal/xray`: Reality keypair gen + Germany Xray config generation
   (golden files) + `run -test` gate.
5. **T4** `internal/origin`: Caddy provider (Caddyfile gen, ACME mode,
   install) + `none`/`cdn` providers + preflight (TLS 1.3 dest probe).
6. **T5** `internal/systemd`: unit generation (EnvironmentFile D4, caps,
   ordering) + enable/restart/health.
7. **T6** `internal/firewall`: ufw + nftables providers, managed chains,
   idempotence.
8. **T7** `internal/deploy`: planner (desired-vs-current diff), manifest,
   atomic writes, auto-rollback, state file schema.
9. **T8** `cmd/splitterctl`: CLI surface (install/pair/status/doctor/
   upgrade/rollback/uninstall/config) wired to T1–T7.
10. **T9** `install.sh` v2 bootstrap (fetch-verify-exec) + release artifacts
    workflow (build + sha256).
11. **T10** Iran `iran-xray` managed process + `--merge-into-existing-xray`
    mode (reuse existing merge).
12. **T11** L2/L3 CI (container harness + fault injection).
13. **T12** L4 clean-machine two-container job (on-demand) running the L5
    matrix.
14. **T13** L5 run B on staging with the installer (closes the #19 infra gap)
    + record; L6 soak.
15. **T14** README/RUNBOOK/IMPLEMENTATION_STATUS updates (new topology,
    operator-input table, DNS/CDN docs); retire `config/iran-xray-config.json`
    placeholder in favor of generated examples.

Cross-cutting (tracked separately, **not** in T1–T14): fix #20, fix #21
(product engine) — prerequisites for an L5 ACCEPT verdict, independent PRs.

## 18. Dependency / reuse decisions

| Item | Decision | Why |
|---|---|---|
| Xray-core | **reuse** (managed binary, pinned + `.dgst`-verified) | the down-carrier protocol is Reality; re-implementing is forbidden by the direction and unnecessary |
| Xray install mechanics | **reuse the steps** of official `XTLS/Xray-install` (release zip + `.dgst`, FHS-ish layout, `run -test`), **not the script** | reproducible, verifiable, manifest-backed; the script's own design (dgst check, version pin flag) validates the approach |
| Reality keypair | **reuse** `xray x2025 reality keypair` (CLI) | canonical, version-matched to the pinned binary; no crypto reimplementation |
| Up-carrier origin | **Caddy** (default) | ACME without operator work; single static binary; pinned artifact. nginx rejected for the default (no ACME) but supported as an operator mode in cdn setups |
| CDN | **operator-managed, v1 no API adapters** | "do not assume a provider"; the interface isolates future adapters |
| SOCKS5 client for tests | reuse `integration/socks5` | already proven |
| Installer language | **Go** (`splitterctl`) + thin pinned bootstrap shell | idempotence/rollback/doctor/testability; the shell path is retained as a fallback and for muscle memory |
| State store | on-host JSON + 0600 files | no new runtime dependency, no daemon |
| New Go deps for deploy | **none required** (stdlib: os/exec, crypto/rand, encoding, net). Caddy/Xray are external binaries, not Go deps | "no unnecessary dependencies" |
| Import boundary | `pkg/*` ← never ← `internal/deploy*` | enforced by CI import test |

## 19. Security risks & mitigations

1. **curl|bash bootstrap** → pinned artifact + embedded sha256 + the script
   contains no logic beyond fetch/verify/exec; the script itself is tiny and
   reviewed (auditable in seconds).
2. **Xray supply chain** → official XTLS release assets, `.dgst` SHA-256
   (upstream-published), pinned version, fail-closed verification, manifest
   records the hash. No third-party mirrors.
3. **Privilege** → non-root `split-tunnel` user for all managed processes;
   capabilities only where a <1024 bind requires them (narrow set);
   `NoNewPrivileges=true`; installer runs as root (unavoidable for systemd)
   but only touches the project prefix + its own units/rules.
4. **Secret exposure** → generated once, printed once, 0600 files, redaction
   filter in all logging, manifest stores fingerprints only, unit files carry
   no secret (EnvironmentFile D4), pairing blobs carry only what's needed,
   tamper-check on receipt.
5. **Host destruction** → preflight before any mutation; default mode never
   touches the user's Xray (D2); managed chains/tables for firewall; atomic
   writes + versioned backups + manifest auto-rollback; 443 conflict fails
   instead of displacing; uninstall is explicit-confirmation and scoped to the
   project's own artifacts (removes the user's Xray only if the user chose
   `--merge-into-existing-xray` *and* passes `--purge`, with the backup
   retained + shown).
6. **Public surface minimization** → §3.3: exactly two public endpoints, both
   protocol-authenticated (Reality; WS+tunnel-secret), everything else
   localhost; `doctor` re-verifies the surface on every run.
7. **Reality misconfiguration** (bad SNI/dest) → install-time preflight
   (TLS 1.3 reachability), documented operator input, `doctor` explains a
   failed carrier as Reality vs tunnel-secret vs network.
8. **Log leakage** → Xray loglevel warning, access log off for the carrier
   inbound, journald + logrotate; no secrets in any log line (filter tested).

## 20. Implementation sequence

Phase A (foundation, no behavior change): T0 → T1 → T2 → T3 (each: CODE →
tests → ARCHITECT review → fix → tests).
Phase B (orchestration): T4 → T5 → T6 → T7 (same loop).
Phase C (surface): T8 → T9 → T10 (same loop).
Phase D (proven): T11 → T12 (CI) → T13 (L5 run B + L6) → T14 (docs).
In parallel (product track, independent PRs): #20 fix, #21 fix — both with
regression tests + Linux race CI (never claimed without the actual CI run).
L5 closes only after: T13 record shows 20/20 ×2 on the installer-provisioned
staging, with #20/#21 resolved.

**Stop conditions:** satisfied for v0.2 (see §21): CRITICAL = 0, HIGH = 0.
Implementation (Phase A) may begin; each task still follows CODE/DEBUG → tests
→ ARCHITECT → fix → tests.

## 21. ARCHITECT review record (v0.1 → v0.2)

Independent review performed in ARCHITECT mode against v0.1, checking:
consistency with the current code (verified on GitHub `main`/`l5-harness`),
the product/deployment boundary, security properties, idempotence/rollback
completeness, and the honesty of "self-contained" claims.

**CRITICAL: 0.** No finding invalidates the architecture or contradicts a
hard constraint of the direction (engine untouched, no Xray embedding, no
panel, product/deployment separation).

**HIGH — all fixed in v0.2:**

- **H1 — Iran Xray config spec was invalid.** §4.6 v0.1 gave the
  `dokodemo-door` inbound `settings.address: "unused"`; a dokodemo-door
  inbound *requires* `address`/`port`, so `xray -test` (our own gate) would
  have failed the default Iran install. Fixed: explicit logical-destination
  setting + routing to the vless `vnext`; golden-file test pinned in T3.
- **H2 — ACME chicken-and-egg firewall gap.** Caddy direct mode needs port 80
  for HTTP-01, but the public-surface matrix never listed 80 and the
  firewall section never opened it — first install on a clean host would fail
  cert acquisition. Fixed: 80/tcp is a documented public port in caddy direct
  mode (Caddy 301-redirects non-ACME), TLS-ALPN-01 fallback is explicit,
  ordering (DNS before install) documented, cdn mode does not open 80.
- **H3 — CDN-mode origin TLS was unspecified.** v0.1 said "CDN back-to-origin"
  without saying what serves TLS at the origin when the domain resolves to
  the CDN (ACME impossible there). Fixed: two explicit options — (A) Caddy
  with a self-signed/internal-CA cert + CDN origin verification (TLS
  end-to-end, default), (B) plain origin served by the splitter's own WS
  listener with an explicit security note (no ACME, no extra process).

**MEDIUM — resolved in v0.2 (inline) or tracked to tasks:**

- **M1** — ACME method default now explicit (HTTP-01; ALPN-01 only with
  operator acknowledgement).
- **M2** — documented that Reality camouflages only the *inbound* (Germany)
  side; Iran→Germany 443 reachability is a separate, documented condition;
  `doctor` distinguishes TCP-level from handshake-level failure.
- **M3** — inbound port-conflict preflight (443/80/origin) added to install
  and `config set`; conflict fails with guidance, never displaces.
- **M4** — `--merge-into-existing-xray` scope corrected: it must merge
  inbound + outbound + routing (not only outbound + routing as the existing
  machinery does); preview diff shown before apply.
- **M5** — firewall conflict detection policy stated (probe before add;
  fail-with-guidance) for both hosts and all public ports.
- **M6** — managed Xray units get explicit restart bounds
  (`StartLimitIntervalSec=300`, `StartLimitBurst=10`) so a crash loop is a
  visible `failed` state, not silent flapping.

**LOW (accepted / deferred to implementation tasks):**

- **L1** — Caddy as the origin engine is a new runtime dependency on Iran
  (default mode); justified by "no operator TLS work," alternative (nginx +
  operator cert) is supported as a documented cdn-mode choice. Tracked in T4.
- **L2** — pairing blobs travel through the operator (clipboard/scp); a
  future control channel could automate rotation. Out of scope v1; the
  two-step rotation remains explicit.
- **L3** — `doctor`'s #20/#19 signature hints assume the metrics/log markers
  as of `main`; if #20/#21 change logging, the hints update in the same PR.
- **L4** — L4 clean-machine test on containers may need a
  `systemctl`-compatible shim if systemd is absent in the chosen runner
  class; the job must prefer a real-VM runner (the direction requires real
  systemd semantics) — decision recorded at T12, not earlier.

**Verdict:** v0.2 passes the gate (CRITICAL = 0, HIGH = 0). Proceed to
Phase A (T1→T3) with the standard per-task loop.