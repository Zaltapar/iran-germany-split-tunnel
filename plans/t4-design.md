# T4 — Origin (Caddy) provider + none/cdn providers + preflight (TLS 1.3 dest probe)

Status: DESIGN (architect). Baseline: main @ 2e2da9a (T3 Reality keygen + Germany Xray
config merged, PR #26, CI green). Scope source:
docs/self-contained-deployment-architecture.md §5.1 / §4.5 / §5.2 / §6.1 / §7.2 / §10.2 /
§11(L1) / §17(item 5) / §18. Deliverable is the `internal/origin` package (new). No new
Go dependencies. No staging deployment.

## 1. Verified topology (T4-B) — matches the stated intent exactly

Up-carrier path (the origin T4 owns) — verified against doc §1.2/§3.3/§5.1/§5.2,
cmd/iran-splitter/main.go (runUpCarrier), internal/config (DefaultWsListen):

    Internet user → wss://<upload-domain>/upload
        [Iran: origin provider in front of the WS listener]
        caddy mode (default): Caddy (pinned) on :443 (ACME HTTP-01) — or :<origin-port>
            → reverse_proxy /upload → 127.0.0.1:9001
        cdn mode A (TLS origin): Caddy on :<origin-port> with `tls internal` (self-signed)
            → reverse_proxy /upload → 127.0.0.1:9001
        cdn mode B (plain origin): NO Caddy; splitter listens 0.0.0.0:<origin-port>
        none mode (testing): NO Caddy; splitter listens 127.0.0.1:9001, direct ws://
        → [iran-splitter] SPLIT_WS_LISTEN (default 127.0.0.1:9001)
        → gorilla WS upgrade → mux.CarrierAuth(FrameAuth, RoleUpload, tunnel secret) → node

The origin provider is a pure edge: TLS termination + WS upgrade forwarding. It carries
NO tunnel secret and NO Reality key — those live in the splitter (mux.FrameAuth) and the
Xray config (T3) respectively. Two auth layers by design (doc §4.5 Q7 / §19.4): the
origin does transport TLS; the tunnel secret authenticates the peer.

### The WS forwarding contract (the nginx snippet the Caddyfile must replicate)
Verified verbatim from install.sh `show_nginx_snippet` (lines 1067-1083) and
`configure_nginx` (1139-1158):

    location /upload {
        proxy_pass http://127.0.0.1:<internal_port>;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

Caddy (pinned v2.11.4) reproduces this NATIVELY (verified against the pinned binary and
source at tag v2.11.4):
- `reverse_proxy /upload 127.0.0.1:9001` → proxy_http_version 1.1 + proxy_pass.
- WS upgrade: Caddy re-injects `Connection: Upgrade` / `Upgrade: <type>` for the backend
  itself (reverseproxy.go:838-843 at tag v2.11.4) — no `header_up` needed. (The
  `header_up -Origin` is NOT required: the splitter never reads Origin.)
- `Host`: Caddy preserves the client Host by default (`r.Host = reqHost`,
  reverseproxy.go:691) — equivalent to `proxy_set_header Host $host`.
- `X-Forwarded-For`: Caddy auto-adds X-Forwarded-* (reverseproxy.go:867-879,
  addForwardedHeaders). The splitter does NOT read XFF/X-Real-IP (it logs only
  `r.RemoteAddr` — cmd/iran-splitter/main.go:270-296), so the exact header set is
  functionally equivalent to the nginx snippet.
- read/send timeout 3600s: `transport http { read_timeout 3600s; write_timeout 3600s }`.

ARCHITECT VERIFICATION (the WS-stream timeout semantics — the design-critical part):
- The upgraded WS stream is not a normal response copy: on 101, Caddy HIJACKS the
  front connection and pipes it to the backend via `switchProtocolCopier`
  (streaming.go:60+ handleUpgradeResponse). The stream lives until an I/O error or the
  client request context is done (streaming.go backConnCloseCh) — there is NO total
  stream-time cap by default.
- The backend TCP conn IS wrapped in `tcpRWTimeoutConn` when read/write timeouts are set
  (httptransport.go:355-361): every Read/Write sets a per-OPERATION deadline of
  `now + timeout` (httptransport.go:840/852). This is exactly nginx's
  `proxy_read_timeout`/`proxy_send_timeout` semantics (idle time between consecutive
  operations, NOT total connection time) — so a long-lived idle carrier is NOT killed
  at 3600s; only a 3600s stall on the backend leg is.
- The hijacked FRONT connection is removed from the server's idle tracking (Hijack), so
  no front-side idle timeout can drop the carrier either.
- `stream_timeout` (reverse_proxy's `StreamTimeout`) is a TOTAL-elapsed-time cap
  (streaming.go timeoutc) — it is NEVER emitted in the generated Caddyfile: it would
  kill a long-lived carrier. (Decision D7.)

Decision: the generated Caddyfile is the MINIMAL functional body (site block +
reverse_proxy + transport timeouts). It does NOT restate the WS upgrade/Host/XFF headers
because Caddy applies them by default (verified). Adding `header_up` would be redundant
and would make the golden noisier without changing behavior. The 3600s timeouts ARE
stated (Caddy's default upstream idle is shorter and would drop a long-lived carrier).

## 2. Pinned Caddy (v2.11.4) ground truth — verified against the real release

Verified on a clean Linux host (Ubuntu 24.04) by downloading the real release and the
real pinned source at tag v2.11.4. This is the supply-chain + behavior pin for T4.

### 2.1 Release artifact (caddyserver/caddy, tag v2.11.4)
- Asset naming: `caddy_2.11.4_<os>_<arch>.tar.gz`.
- Linux archs present: amd64, arm64, armv5, armv6, armv7, ppc64le, riscv64, s390x.
  **NO linux 386** (differs from Xray, which has linux-32). ⇒ the Caddy arch set is
  a DIFFERENT enum than Xray's; do not reuse xray.Arch.
- Checksum: `caddy_2.11.4_checksums.txt`, format `<SHA-512 hex>  <name>` (TWO spaces,
  128 hex chars = SHA-512, NOT SHA-256). 42 lines. Verified: the downloaded
  `caddy_2.11.4_linux_amd64.tar.gz` sha512 = `8220d1f0…b1c9` matches the file exactly.
  ⇒ Caddy install verifies **SHA-512** (crypto/sha512), not SHA-256 like Xray's `.dgst`.
- Tar layout (top-level, no nested dir): `LICENSE`, `README.md`, `caddy`.
  ⇒ extraction must pick the `caddy` entry (zip-slip/size caps still apply; the entry
  is a single ~45MB static binary).
- `caddy version` → `v2.11.4 h1:<build>`. First field = the version. Smoke check =
  first field == PinnedVersion.

### 2.2 Config gate (the `xray run -test` equivalent)
- `caddy validate --config <file>`: exit 0 = valid, nonzero = invalid. STRONGER than
  `adapt` (validate runs the full provision). Verified: valid golden → 0, malformed
  (`frobnicate`) → 1.
- `caddy adapt --config <file>`: prints the adapted JSON, exit 0 on success. Used for
  the hermetic golden (byte-stable) and as a lighter gate.
- BOTH are deterministic: adapt twice on the same file = byte-identical JSON (verified).

### 2.3 The three Caddyfile modes (each verified to `adapt`/`validate` exit 0)
1. **caddy / ACME default (HTTP-01)** — public cert, self-contained:
       # Managed by split-tunnel installer - do not edit by hand
       <domain> {
           reverse_proxy /upload 127.0.0.1:9001 {
               transport http {
                   read_timeout 3600s
                   write_timeout 3600s
               }
           }
       }
   - No `tls` directive ⇒ Caddy's default ACME = **HTTP-01** (works before the cert
     exists), listens `:443` + opens `:80` for the challenge. Adapted JSON: `listen`
     `[:443]`, host matcher `[<domain>]`.
2. **caddy / ALPN-01 fallback** (operator acknowledges port 80 unusable):
       <domain> {
           tls {
               issuer acme {
                   disable_http_challenge
               }
           }
           reverse_proxy /upload 127.0.0.1:9001 { … }
       }
   - VERIFIED syntax (tag v2.11.4, caddyconfig/httpcaddyfile/builtins.go parseTLS:
     `issuer <mod>` routes to `tls.issuance.acme`; `disable_http_challenge` is a
     subdirective of the ACME issuer). Adapted JSON: `challenges:{http:{disabled:true}}`.
     Requires the A record to resolve first (documented ordering, doc §14).
3. **cdn / TLS-origin (mode A)** — self-signed, no ACME:
       <domain>:<originPort> {
           tls internal
           reverse_proxy /upload 127.0.0.1:9001 { … }
       }
   - VERIFIED: site `<domain>:8443` + `tls internal` listens ONLY `:8443` (NOT :443/:80),
     host matcher is the BARE domain `[<domain>]` (so a CDN sending `Host: <domain>` with
     no port still matches). Adapted JSON: `listen [:8443]`. `tls internal` =
     Caddy's internal-CA self-signed issuer (`{"module":"internal"}`).

### 2.4 Managed marker
- A leading `# …` comment line is valid Caddyfile (verified: golden with marker →
  adapt/validate exit 0, deterministic). The generator emits exactly one marker line:
  `# Managed by split-tunnel installer - do not edit by hand`. Idempotence (T7) keys
  off this marker; a re-Configure with unchanged Plan is a byte-no-op.

## 3. Design

### 3.1 Files (all NEW; package `internal/origin`)

| File | Content |
|---|---|
| origin.go (new) | `OriginProvider` interface (doc §5.1): `Configure(ctx, Plan) error; Status(ctx) (Health, error)`. `Plan` (validated operator input: Mode, Domain, UpstreamAddr, OriginPort, ACMEChallenge, ACMEEmail) + `Health` (Mode, Live, Detail). `Mode` enum: `caddy`, `cdn`, `none`. Provider constructors `NewCaddy()`, `NewCDN()`, `NewNone()` returning `OriginProvider`. `New(mode, deps) (OriginProvider, error)` registry. Exported `ValidDomain(d string) bool` (single source of truth for the public origin domain — see §3.5). |
| caddyfile.go (new) | `RenderCaddyfile(Plan) ([]byte, error)`: deterministic Caddyfile bytes for the three modes (§2.3). Fixed layout, tabs (Caddyfile is tab-indented), 2-space-free, trailing newline, managed marker first. NO timestamps, NO map iteration (byte-identical across runs). `none` mode + `cdn` mode B (plain origin) return `ErrNoCaddyfile` (caller must not expect a file). Pure function: no I/O. |
| caddyfile_test.go (new) | Golden files: `testdata/golden/caddy-*.golden.Caddyfile` for all three modes + fixed-vector Plans. Run render twice → byte-identical (determinism). Every golden from §2.3. Negative: `none`/cdn-B → ErrNoCaddyfile; bad domain → ErrInvalidPlan (nothing rendered). |
| version.go (new) | Caddy pin: `PinnedVersion = "v2.11.4"`, `CaddyArch` enum (linux-amd64/arm64/armv5/armv6/armv7/ppc64le/riscv64/s390x — **no 386**), `ArchForGOARCH`, `TarName(arch)`, `TarURL`, `ChecksumURL` (`caddy_2.11.4_checksums.txt`), `ParseChecksumFile` (SHA-512, two-space format), `ValidVersion` (`^v\d+\.\d+\.\d+$`). Mirrors internal/xray/version.go but SHA-512 + tar.gz + own arch set. |
| version_test.go (new) | Table: TarName/URL per arch; ParseChecksumFile happy/malformed/oversized/wrong-hash-length; ArchForGOARCH (amd64/arm64/arm/386→error); ValidVersion. `TestPinnedCaddyAssetsExist` (network, SKIP if offline): GitHub API release v2.11.4 has `caddy_2.11.4_linux_amd64.tar.gz` + `caddy_2.11.4_checksums.txt`. Mirrors xray/pin_test.go. |
| install.go (new) | Caddy installer mirroring internal/xray/install.go: `Downloader` interface (Fetch), `Executor` interface (`VersionOutput(bin)`), `Installer{Prefix, DL, Exec, Force, Chmod}`. `Install(version, arch, configPath) (*Installed, error)`: resolve URLs → download tar.gz + checksums.txt → parse SHA-512 line for the tar → **SHA-512 verify (constant time, fail closed)** → extract to STAGING dir (tar-slip + size caps) → stage → versioned dir `<prefix>/caddy/<version>/` → `caddy version` smoke (first field == version) → `caddy validate --config <configPath>` gate (if given) → on ANY failure after verify, remove staged/version dir (previous version untouched). Errors are sentinels; no bytes echoed. |
| install_test.go (new) | Fake Downloader (httptest or static bytes) + fake Executor. Happy path (0600/0755 perms, manifest row, version dir layout); bad checksum → fail closed (no version dir, no partial); tar-slip entry → refuse; oversized entry → refuse; smoke-fail (version mismatch) → remove staged; validate-gate-fail → remove staged, nothing started; re-install existing version dir → fail fast unless Force. Mirrors xray/install_test.go. |
| activate.go (new) | Transactional activation of the generated Caddyfile, mirroring internal/xray/activate.go: (1) render via RenderCaddyfile; (2) write 0600 `<dir>/<file>.tmp` (O_EXCL), fsync; (3) `Executor` `Validate(configPath)` gate — on fail remove tmp, dir byte-identical, nothing changed; (4) if live file exists, copy to `<file>.prev` (0600); (5) `os.Rename(tmp, live)` atomic. Lstat symlink refusal on live+tmp. Sentinel errors. No service restart (T5's job). |
| activate_test.go (new) | Fake executor: gate-fail → dir byte-identical (no tmp, prev untouched); gate-pass → .prev of old + new live; perms 0600; symlink refused; dir-not-writable fails clean. Mirrors xray/activate_test.go. |
| cdn.go (new) | `cdn` provider. Mode A (TLS origin): Configure renders the §2.3.3 Caddyfile and activates it (via activate.go) on `OriginPort`; Status reports the Caddy live state. Mode B (plain origin): Configure is a no-op (NO Caddy) but returns the required splitter env (`SPLIT_WS_LISTEN=0.0.0.0:<origin-port>`) + the explicit security note (CDN→origin leg unencrypted; auth v1 still authenticates — challenge/nonces/keyed MAC only, no key material in clear). `CDNOriginInstructions(plan) (string, error)`: deterministic per-mode text — exact CDN origin config (host, port, TLS setting, path `/upload`, WebSocket enabled, Upgrade/Connection headers, idle timeout ≥ 3600s) + exact DNS record (A/AAAA → Iran origin, or CNAME → CDN per mode). **No provider-specific API calls in v1** (doc §5.1: adapters are a later extension point isolated by the interface). |
| cdn_test.go (new) | Mode A renders+activates the tls-internal golden; Mode B renders no Caddyfile + returns the env + the security note; CDNOriginInstructions is deterministic + contains the required fields (path /upload, WS, ≥3600s, DNS record) for both modes. |
| none.go (new) | `none` provider (testing only). Configure: no Caddy, no file; validates UpstreamAddr is a loopback `ws://`-reachable target and returns the direct `ws://<host>:<port>/upload` URL. Status: reports "no origin (direct WS, testing only)". `RejectForPublicDeploy(reason)`: the config-validator hook that REJECTS `none` for a public deployment (doc §5.1.3: keep `ws://` acceptance for staging, but a real domain install defaults to `wss://`). |
| none_test.go (new) | Configure returns the direct ws URL; rejects a non-loopback upstream for `none` (testing-only); RejectForPublicDeploy returns an error for a public domain. |
| preflight.go (new) | The TLS 1.3 dest probe (doc §4.5): `ProbeTLS13(ctx, target, sni string) (*ProbeResult, error)` where `target` = `host:port`. (1) TCP dial with a bounded timeout; (2) TLS ClientHello offering ONLY TLS 1.3 (`MinVersion = MaxVersion = tls.VersionTLS13`) with the SNI; (3) total budget 10s. `ProbeResult{Reachable, TLS13 bool}`. Fail-closed semantics: unreachable → error; reachable but no TLS 1.3 → `ErrNoTLS13` (suboptimal dest fails HARD because Reality/vision requires TLS 1.3). Pure network stdlib (net + crypto/tls), no Caddy dependency — reusable for the Germany Reality dest validation. |
| preflight_test.go (new) | Hermetic: start a local `tls.Listener` on 127.0.0.1 with a self-signed cert (MaxVersion TLS 1.3) → probe reports Reachable+TLS13. A TLS 1.2-only listener (MaxVersion TLS 1.2) → ErrNoTLS13. A closed port → unreachable error. ctx timeout honored (no >10s in tests; use short ctx). Deterministic, no public network. |
| internal/pairing/pairing.go (EDIT) | Add ONE exported wrapper `ValidUploadDomain(d string) bool { return validUploadDomain(d) }` — exactly the T3 `ValidSNI` pattern (thin export over the existing unexported core; no rule duplicated). `origin.ValidDomain` delegates to it. No behavior change to T1. |
| internal/pairing/pairing_test.go (EDIT) | One test: `ValidUploadDomain` agrees with `NewBlobA`'s domain acceptance (same rule, both entry points). |

Nothing in `pkg/*`, nothing in `internal/config`, nothing in `cmd/*` (T8 wires the CLI).
`internal/origin` imports only stdlib (net, crypto/tls, os/exec, encoding, path, etc.) —
so the archtest boundary (pkg/* never imports internal/*) stays green and no new Go dep.

### 3.2 The `OriginProvider` contract (doc §5.1, exact)

    type OriginProvider interface {
        Configure(ctx context.Context, plan Plan) error   // idempotent; converge or no-op
        Status(ctx context.Context) (Health, error)
    }

- `Configure` is idempotent (T7's convergence calls it on every install/upgrade):
  unchanged Plan → byte-no-op (marker + content compare); changed Plan → re-render +
  re-activate behind the validate gate.
- `Status` is read-only (no mutation): reports whether the origin is live (Caddy binary
  present + config valid + (for caddy) the service up). It NEVER returns a secret.
- `Plan` is the validated operator input (one value, all providers):
    type Plan struct {
        Mode         Mode            // caddy | cdn | none
        Domain       string          // upload domain (ValidDomain); empty for none
        UpstreamAddr string          // "127.0.0.1:9001" (the WS listener) — validated
        OriginPort   int             // cdn mode origin port (443 default; caddy=443 fixed)
        ACMEChallenge ACMEChallenge  // http01 (default) | tlsAlpn01 (fallback)
        ACMEEmail    string          // ACME contact (optional; only for caddy mode)
        CDNSecurity  CDNSecurity     // mode A (tls origin) | mode B (plain origin)
    }
- `Plan.validate()` is fail-closed and names fields, never values (mirrors xray
  RealityParams.validate / pairing.fieldErr).

### 3.3 Validation (single source of truth — no rule duplication)
- Domain: `origin.ValidDomain` wraps the SAME rule as pairing's `validHost` (IP literal
  or RFC1123, ≤253 chars, ≥2 labels, no port/scheme/ws/underscore). To AVOID duplicating
  the rule (project rule), `origin` re-exports pairing's validator by calling
  `pairing.ValidUploadDomain` IF pairing exports it — pairing currently has `validHost`
  (unexported) + `validUploadDomain` (unexported) + exported `ValidSNI/ValidUUID/
  ValidShortID`. Decision: add ONE exported `pairing.ValidUploadDomain(d string) bool`
  (a one-line wrapper over the existing unexported `validUploadDomain`, exactly like the
  existing `ValidSNI` wrapper) and have `origin.ValidDomain` delegate to it. This is the
  same "export a thin wrapper, reuse the core" pattern T3 used for SNI — no rule is
  re-implemented.
- UpstreamAddr: must parse as host:port. Loopback is required wherever a Caddyfile is
  generated (`caddy` mode and `cdn` mode A — the origin fronts a LOCAL WS listener) and
  in `none` mode (it builds the direct `ws://<host>:<port>/upload` test URL) — public
  upstreams are rejected (the origin must front the local splitter, never dial out).
  `cdn` mode B (plain origin) generates NO Caddyfile and uses NO upstream — the field
  is ignored (validation skips it for mode B).
- OriginPort: 1..65535; caddy mode is fixed 443 (ACME); cdn mode is operator-chosen
  (default 443); none ignores it.
- ACMEChallenge: only meaningful for caddy mode; http01 (default) | tlsAlpn01.
- ACMEEmail: optional; if present, a syntactic email (contains exactly one `@`, no
  whitespace) — NOT a full mailbox RFC check (Caddy only needs it as the ACME contact).
- CDNSecurity: only for cdn mode; tlsOrigin (A) | plainOrigin (B).

### 3.4 Secret hygiene
- The origin carries NO secret: no tunnel secret, no Reality key, no ACME private key in
  the generated Caddyfile. The only generated file is the 0600 Caddyfile (public facts:
  domain, upstream, timeouts). `Status`/`Health` never return a cert or key. ACME
  private certs are written by Caddy itself under its storage path (T5 sets that to the
  0700 prefix), never by this package.
- `caddy version` output contains a build hash (not a secret) — safe to echo in the
  smoke check. `caddy validate`/`adapt` error lines reference the config path + directive
  (public facts), never a secret — a bounded excerpt is safe (same reasoning as T3's
  gate-failure echo, which carries only public Reality params).

### 3.5 Install pipeline (mirrors T2/T3 exactly)
    1. resolve version+arch → tar.gz URL + checksums.txt URL
    2. download tar.gz + checksums.txt
    3. parse checksums.txt (fail closed if no SHA-512 line for the tar)
    4. verify tar.gz SHA-512 (constant time; fail closed on mismatch)
    5. extract into a STAGING dir (tar-slip + size caps; pick the `caddy` entry)
    6. stage → version dir <prefix>/caddy/<version>/ (rename within the prefix)
    7. `caddy version` smoke check (first field == version)
    8. `caddy validate --config <cfg>` gate (if cfg given)
On ANY failure after step 4 the staged/version dir is removed — a failed install never
leaves a half-version, and a previously active version is untouched (rollback = keep the
old dir). The `caddy` provider's `Configure` = (install-if-missing) → (render+activate the
Caddyfile). Idempotence: a re-Configure with the pinned version already present skips the
download (version-dir exists + smoke OK) and only re-runs the render+activate gate.

### 3.6 Out of scope for T4 (explicit, tracked elsewhere)
- **systemd unit for caddy** (`caddy.service`, After=network-online, Restart=on-failure,
  CAP_NET_BIND_SERVICE) → T5 (`internal/systemd`). T4 leaves the binary + 0600 Caddyfile
  on disk; T5 wraps it in a unit and (re)starts it. `Status` in T4 reports file-level
  liveness, not systemd state.
- **Firewall 443/80 rules + conflict preflight (M3/M5)** → T6 (`internal/firewall`). T4's
  preflight is the TLS 1.3 DEST probe only, not the port-conflict probe.
- **`splitterctl install` CLI wiring** → T8 (`cmd/splitterctl`). T4 is the library; T8
  calls `origin.New(mode, deps)` and drives Configure/Status.
- **State manifest `origin` field** (`{"mode","domain","caddyVersion"}`) → T7
  (`internal/deploy`). T4 exposes `Installed`/`Health` so T7 can serialize them.
- **CDN provider-specific API adapters** → explicitly out of v1 (doc §5.1). v1 emits
  operator-facing instructions only; the interface isolates future adapters.
- **Caddyfile on-the-fly ACME enrollment** (actually obtaining the Let's Encrypt cert) →
  happens at Caddy RUNTIME (T5 starts the service). T4 only generates + validates the
  Caddyfile; it does NOT talk to ACME. (This is why `caddy validate` — not a live ACME
  handshake — is the T4 gate.)

### 3.7 Pre-deployment compatibility
Both endpoints ship the same project version (pre-deployment), so no blob/schema compat
shims are needed. The only cross-package edit is the additive exported wrapper
`pairing.ValidUploadDomain` (§3.3) — additive + validated, not a behavior change to T1.

## 4. Security review checklist (to be cleared in the ARCHITECT loop)
1. Caddyfile injection via Domain: Domain is validated (ValidDomain → validHost) BEFORE
   it is written; the render is a fixed template with a single validated substitution —
   no operator-injectable directive/brace. A malicious domain cannot escape the site
   line (no `:`, no `{`, no whitespace, no newline — validHost rejects them).
2. Command injection: install/activate shell out via `exec.Command(bin, args...)` with
   ARGV (no shell, no string concat) — the binary path + config path are the only args;
   config path is traversal-guarded (raw `..` + separator check, O_NOFOLLOW on write).
3. Supply chain: pinned version + SHA-512 (upstream-published checksums.txt) + fail-closed
   verify + manifest records the hash. No third-party mirrors.
4. Path traversal / symlink: staging + version dir under the prefix; tar-slip + size
   caps on extract; Lstat symlink refusal on the live/tmp Caddyfile (O_EXCL, O_NOFOLLOW).
5. Permission hygiene: Caddyfile + `.prev` 0600; caddy binary 0755; version dir 0755.
   No secret in any generated file.
6. Secrets never logged: the origin has no secret; `caddy version` build hash +
   validate/adapt public-fact error lines are the only echoes (bounded excerpt).
7. Preflight fail-closed: unreachable dest or no TLS 1.3 → install fails (ErrNoTLS13 /
   dial error), never a runtime surprise. Bounded 10s, no unbounded retry.
8. No public upstream: caddy/cdn/none UpstreamAddr must be loopback (the origin fronts
   the local splitter; cdn mode B has no upstream); a public upstream is rejected at
   validation.

## 5. Test plan (hermetic, no public network, no root)
- L1 (CI, all OS): caddyfile golden + determinism; version pin URL/parse table;
  install (fake Downloader/Executor, fixture tar.gz); activate (fake executor, gate
  ordering, perms, symlink); cdn (mode A/B render + instructions); none (direct URL +
  public-deploy reject); preflight (local TLS 1.3 / 1.2-only / closed-port listeners,
  short ctx). No network, no root.
- L2/CI pin check: `TestPinnedCaddyAssetsExist` (network, SKIP offline) asserts the
  pinned release has the tar.gz + checksums.txt (mirrors xray pin_test).
- Real-binary gate (Linux CI, mirrors the T3 "Pinned Xray gate"): download the pinned
  `caddy_2.11.4_linux_amd64.tar.gz` + `caddy_2.11.4_checksums.txt`, verify SHA-512,
  extract, `caddy version` smoke, render the fixed-vector Caddyfile, and `caddy
  validate --config <golden>` MUST exit 0. (CI runner is non-root; `caddy validate` needs
  no root — no /var/log path in the Caddyfile, unlike the Xray error log.)
- Determinism: every render + instruction function run twice → byte-identical.
- Concurrency: T4 has NO goroutines and activations are serial in
  production (single deploy user, T3/xray model). The fixed tmp name is
  created O_EXCL and a stale REGULAR tmp is treated as crash residue
  (cleaned up) while a SYMLINK tmp is refused — tested deterministically
  (TestActivateStaleTmpCrashRecovery). A genuinely concurrent 2-writer
  race is out-of-model (same as T3) and deliberately not asserted.
## 6. Verification plan (before PR)
1. Local: `gofmt -l` clean, `go vet ./...`, `go test ./...`, `go test -race ./...`,
   `go build ./...` (Windows dev box).
2. germany-node (root, Linux) real-binary gate: fresh clone, gofmt/vet/test/race/build,
   then the pinned-Caddy gate (SHA-512 verify + `caddy version` + `caddy validate` on
   the rendered golden) — mirrors /root/t3-regate.sh.
3. ARCHITECT review → remediation loop until CRITICAL=0 / HIGH=0.
4. Push, focused PR, CI green (incl. the new/extended pinned-Caddy CI step), merge.
5. Docs: IMPLEMENTATION_STATUS.md T4 bullet + README consistency + a docs/reviews
   t4-*.md review record.

## 7. Open questions / decisions recorded
- D1: Caddyfile = minimal functional body (no explicit WS/Host/XFF headers; Caddy is
  native). Verified behavior-preserving against the nginx snippet (§1).
- D2: Caddy checksum = SHA-512 (upstream checksums.txt), NOT SHA-256 — a deliberate
  deviation from Xray's `.dgst` SHA-256, forced by the upstream artifact. Recorded here
  so the ARCHITECT review sees it is intentional, not a copy-paste bug.
- D3: Caddy arch set has no linux-386 (upstream) — a separate `CaddyArch` enum, not a
  reuse of `xray.Arch`.
- D4: preflight (TLS 1.3 dest probe) lives in `internal/origin` per the task breakdown
  even though it validates the Germany Reality dest — it is a generic, Caddy-free
  network probe (preflight.go) and is the install-time validation T4 owns. The Germany
  caller (T8/T10) invokes it with `dest` + `SNI`.
- D5: `caddy` mode OriginPort is fixed 443 (ACME); `cdn` mode OriginPort is
  operator-chosen (default 443). `none` ignores it.
- D6: T4 does NOT start the Caddy service (T5) and does NOT open the firewall (T6) and
  does NOT talk to ACME (Caddy runtime). T4 = binary install + 0600 Caddyfile +
  validate gate + providers + dest preflight.
- D7 (architect review): the generated Caddyfile NEVER sets reverse_proxy's
  `stream_timeout`. Verified at tag v2.11.4 (streaming.go): `stream_timeout` is a
  TOTAL-elapsed-time cap on the hijacked WS pipe — it would kill a long-lived carrier.
  The 3600s `read_timeout`/`write_timeout` are per-OPERATION idle deadlines on the
  backend TCP conn (`tcpRWTimeoutConn`, httptransport.go:355-361/840/852) — nginx-
  `proxy_read_timeout`-equivalent, idle-safe. This is the load-bearing difference and
  it is pinned in the golden + a dedicated test asserting the Caddyfile contains
  `read_timeout`/`write_timeout` and NOT `stream_timeout`.
- D8 (architect review): `Status(ctx) (Health, error)` in T4 is FILE-LEVEL liveness
  (binary present at the versioned path, Caddyfile present + `caddy validate` passes,
  binary version == pinned). It does NOT probe systemd (T5) and does NOT open sockets —
  so it is safe to call pre-service-start and in tests without root.
