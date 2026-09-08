# T3 — Reality key generation + Germany Xray config generation

Status: DESIGN (architect). Baseline: main @ 2974caf8 (T1 pairing + T2 Xray installer merged, CI green).
Scope source: docs/self-contained-deployment-architecture.md §4.4/§4.5/§8/§17(item 4).
Deliverable is the Germany-side Reality/Xray config generator in `internal/xray` (+ minimal
`internal/pairing` extension). No staging deployment. No new Go dependencies.

## 1. Verified topology (T3-B) — matches the stated intent exactly

Down-carrier path (verified against doc §1.2/§3.2/§3.3/§4.5, integration/RUNBOOK.md §2,
cmd/germany-splitter/main.go runDownCarrier, pkg/mux CarrierAuth):

    Internet → [Germany Xray-core v26.3.27]
                inbound "split-down": VLESS + Reality, 0.0.0.0:443
                routing: inboundTag split-down → outbound "to-splitter"
                outbound "to-splitter": dokodemo-door → 127.0.0.1:9002
             → [germany-splitter] SPLIT_DOWN_LISTEN (default ":9002", internal/config/config.go)
             → mux.CarrierAuth(FrameAuth, RoleDownload, tunnel secret) → node.InstallDown

Up-carrier path (unchanged, T2-era): Iran 3x-ui/Xray → SOCKS :10900 → iran-splitter →
WS up-carrier to Germany wss endpoint (Caddy, T4). Iran-side Xray inbound (dokodemo-door
127.0.0.1:10802 + VLESS outbound with flow xtls-rprx-vision) is T10, explicitly out of scope.

Two auth layers by design (doc §4.5 Q7): Reality authenticates/stealths the transport;
the tunnel secret (mux.FrameAuth) authenticates the peer. Xray hands the splitter a raw
opaque TCP stream — so the Germany outbound MUST be dokodemo-door (not a proxy protocol).

## 2. Pinned-version (v26.3.27) ground truth — verified against the tag

Verified via raw.githubusercontent.com / api.github.com git-trees at ref v26.3.27
(GitHub MCP cannot target tags; the full recursive tree was fetched).

1. Keypair command is `xray x25519` (NOT `x2025 reality keypair`).
   - main/commands/all/x25519.go: flags `-i "private key (base64.RawURLEncoding)"`, `--std-encoding`.
   - main/commands/all/curve25519.go output: exactly three lines
       PrivateKey: <enc>
       Password (PublicKey): <enc>
       Hash32: <enc>
     Default encoding = base64.RawURLEncoding (43 chars, unpadded). `--std-encoding`
     = base64.StdEncoding (44 chars, padded). Private key is clamped; Hash32 = blake3(pub).
   - Full recursive tree @ tag: NO x2025 file exists anywhere.
   - ⇒ T2 latent bug: internal/xray/install.go OSExecutor.Keypair runs
     `xray x2025 reality keypair` — would fail on the pinned binary. T3 consumes
     Keypair, so the fix is T3-in-scope (flagged in the review).

2. Config JSON layer (operator-facing) is the infra/conf adapter, NOT the raw proto:
   - infra/conf/xray.go `Config`: json keys `log`, `routing`, `dns`, `inbounds`, `outbounds`,
     `policy`, ... — classic shape confirmed.
   - InboundDetourConfig: `tag`, `listen`, `port`, `protocol`, `settings`, `streamSettings`,
     `sniffing`.
   - OutboundDetourConfig: `tag`, `protocol`, `settings`.
   - StreamConfig: `network`, `security`, `realitySettings` (json tag confirmed).
   - REALITYConfig (server side, selected when dest/target present):
     `dest` (json.RawMessage — string or number; "<SNI>:443" is parsed as tcp dest),
     `serverNames` []string (required non-empty), `privateKey` string, `shortIds` []string
     (hex, each ≤16 chars), `xver`, `show`, `maxTimeDiff`, ...
   - DECODING OF privateKey at the pinned tag (transport_internet.go REALITYConfig.Build):
     `base64.RawURLEncoding.DecodeString(privateKey)` and MUST be 32 bytes.
     StdEncoding base64 (with padding) is NOT accepted.
   - shortIds are hex strings in JSON (adapter hex-decodes to [8]byte).
   - DokodemoConfig: `address`, `port`, `followRedirect`, ... (dokodemo.go confirmed).
   - VLESS inbound settings: `clients` [{id, flow?}], `decryption` (inbound/config.proto).
   - core/config.proto (proto layer) uses singular `inbound`/`outbound` — irrelevant to
     JSON output; the adapter is authoritative.

3. Encoding decision (corrects the pre-verification assumption):
   - Run the keypair as plain `xray x25519` (default RawURL output, no flags).
   - `privateKey` in generated config  ← the RawURL line (43 chars) verbatim.
   - `PublicParams.RealityPublicKey` in BlobB ← SAME bytes, re-encoded StdEncoding
     (44 chars) — required by pairing.validRealityPublicKey (Std b64, 32 bytes).
     One keypair, two encodings of the same 32 public bytes; never re-randomize.
   - The generator therefore parses the `Password (PublicKey):` line with
     base64.RawURLEncoding (strict 32-byte check) and derives both forms.
   - `xray run -test` with the pinned binary is the final arbiter (CI, see §7).

## 3. Design (T3-C)

### 3.1 Files (all new unless noted; `internal/xray` package)

| File | Content |
|---|---|
| internal/xray/keygen.go (new) | `GenerateRealityKeypair(ctx, bin string) (*Keypair, error)`; `Keypair{PrivateRaw, PublicRaw, PrivateStd, PublicStd}` (Private* fields unexported-in-spirit: the type is internal, no public API prints them). Runs `xray x25519` via the existing structured `runCombined` (exec.Command args, no shell). Parses the 3 labeled lines; strict: exactly 3 lines, exact prefixes, RawURL decode == 32 bytes, public re-derivation NOT required (binary does ECDH); errors are sentinels, never echo key material. |
| internal/xray/keygen_test.go (new) | Fake-exec table tests: happy path, missing line, wrong line count, non-b64, wrong length, uppercase hex shortId not here (config), error string contains no key bytes. |
| internal/xray/realityconfig.go (new) | `RealityParams` (operator-validated input struct, see §3.4); `RenderGermanyConfig(p RealityParams, keypair) ([]byte, error)` — deterministic JSON, fixed key order (hand-built via ordered writer or fixed struct set with explicit field order), 2-space indent, trailing newline. Output = doc §4.5 shape verbatim: log{loglevel, error?}, inbounds[0]=split-down vless+reality (clients[{id}], decryption none, dest "<SNI>:443", serverNames [SNI], privateKey RawURL, shortIds [16hex]), outbounds[0]=to-splitter dokodemo-door 127.0.0.1:9002, routing rule split-down→to-splitter. NO flow (server side), NO sniffing (opaque TCP must not be sniffed/overridden), NO extra outbounds. |
| internal/xray/realityconfig_test.go (new) | Golden files: internal/xray/testdata/golden/germany-config.golden.json + fixed-vector input. Same logical input → byte-identical output (run twice, compare). Every golden case from the spec (§5). |
| internal/xray/activate.go (new) | `ActivateGermanyConfig(Activate{Dir, FileName, Bin, Executor, Log})`: (1) render; (2) write 0600 to `xray-germany.json.tmp` in same dir; fsync; (3) `Executor.RunTest(bin, tmp)` gate — on failure: remove tmp, return ErrConfigGate-equivalent (new sentinel), NOTHING changed; (4) if live file exists: copy to `<name>.prev` (0600) [rollback artifact]; (5) rename tmp → live (atomic same-fs); (6) chown-free, owner = deploy user. No service restart here (T5+ job). Symlink safety: `os.Lstat` the target first, refuse if symlink (OpenFile O_NOFOLLOW on write, create-only flags). |
| internal/xray/activate_test.go (new) | Fake executor: gate-fail leaves dir byte-identical (incl. no .tmp, no .prev change); gate-pass creates .prev of old content + new live; permissions asserted 0600 (os.Stat); symlink target refused; dir-not-writable fails clean. |
| internal/xray/install.go (EDIT — T3 in scope) | `OSExecutor.Keypair` args `"x2025","reality","keypair"` → `"x25519"`; doc comment updated (command, flags, output contract). Interface method signature unchanged; fake in install_test.go updated to record new args. No other behavior changes. |
| internal/xray/keygen CI hook (see §7) | A small `TestPinnedBinaryKeygenAndConfigGate` (build tag `xraye2e`, excluded from default runs) OR CI-only script step — decision: CI script step (below), no new tag needed. |
| internal/pairing/pairing.go (EDIT) | `PublicParams` gains `SNI string json:"sni"` (validated: DNS hostname, RFC1123, ≤253 chars, no port, no underscores-in-label hard reject optional — use existing validHost core + no "443"-suffix rule). `BlobB.validate()` enforces it. Rationale: doc §8 explicitly lists SNI in the blob B hand-off; current schema lacks it (pre-deployment, both endpoints ship the same project version — no compat shims needed). Strict decoder already rejects unknown fields, so this is additive+validated, not loose. |
| internal/pairing/pairing_test.go (EDIT) | SNI round-trip, missing-SNI rejection, malformed-SNI cases (uppercase ok/normalized? — decision: reject uppercase to keep golden deterministic; lowercase required), SNI never contains ':'. |
| cmd/ (none) | No new commands in T3. `splitterctl install germany` wiring is T5. |

Nothing in pkg/*, nothing in internal/config, pkg/node untouched (arch test stays green).

### 3.2 Key lifecycle (security)

- Generation: only on the Germany host, by the deploy step, via the pinned binary.
- Private key: (a) embedded in the 0600 Xray config (doc §4.4), (b) the `.prev` backup is
  ALSO 0600 and contains the previous private key (accepted: doc §4.3 keeps versioned
  config backups under the project prefix; rotation retires old keys via new pairing).
- Private key NEVER: in any blob (A or B), in git (config dir + .prev in .gitignore —
  verify/extend .gitignore), in logs (all new log lines use `pairing.Redact`-style
  masking; keygen errors are sentinel-only), in test fixtures (golden files use a
  FIXED vector keypair committed as testdata — that key is test-only, generated once,
  and documented as non-prod).
- Public key/UUID/shortId/SNI: public by design; travel in blob B; UUID+shortId+SNI
  generated ON GERMANY by T3 generators (reuse pairing.GenerateUUID/GenerateShortID —
  single source, no duplicate implementations per tunnel-rules).

### 3.3 Determinism

- `RenderGermanyConfig` is a pure function of (validated params, keypair encodings).
  No timestamps, no maps iterated for output (slices in fixed order), fixed 2-space
  indent, fixed key order (hand-ordered JSON writer — not a struct with unknown future
  fields). Golden file pins the exact bytes.
- Blob B encoding is already deterministic (pairing); SNI addition keeps it so.

### 3.4 Input validation (all fail-fast, errors list field+reason, never echo secret material)

| Input | Rule |
|---|---|
| SNI (serverNames) | non-empty DNS hostname, RFC1123 labels (letters/digits/hyphen, no leading/trailing hyphen), total ≤253, lowercase required; NO IP literal (Reality SNI is a domain by design; IPs break the TLS camouflage contract) |
| dest | derived, not operator-input: `SNI + ":443"` (doc §4.5: dest = "<SNI>:443"). Port fixed 443 in T3 (TLS 1.3 site contract; the Reality inbound itself listens on 443 too). Dest-reachability TLS 1.3 preflight is install-time (doc §4.5) → T5's preflight, NOT T3 (T3 = offline generation + `-test`). |
| UUID | pairing.validUUID v4 lowercase (reuse) |
| shortId | pairing.shortIDRe (16 lowercase hex) (reuse) |
| publicKey (from keypair) | RawURL b64, exactly 32 bytes (keygen parse); StdEncoding re-encode for blob B |
| privateKey (from keypair) | RawURL b64, exactly 32 bytes, clamped shape not re-checked (binary did it) — but we DO reject if decode len != 32 |
| key material presence | `RenderGermanyConfig` refuses a zero-value keypair (missing key material rejection) |
| listen/port | fixed 0.0.0.0:443 in T3 (operator port choice `--down-port` arrives with T5; keeping T3 minimal and golden-stable) |

### 3.5 `xray run -test` gate (spec items 7–9)

- Unit/integration: `ActivateGermanyConfig` with fake `Executor` proves the GATE
  ORDERING (render → write tmp → RunTest → backup+rename; any failure = no change).
- Real binary: CI (Linux) step, after `go test ./...`:
    1. install the pinned release via the T2 installer itself (dogfooding:
       `go run ./cmd/... ` no — a tiny `go test -tags xraye2e` OR a workflow step that
       downloads the zip into the runner and runs):
       - `<bin> version` contains "Xray"
       - `<bin> x25519` → 3 lines, parse with OUR keygen parser (exported via test
         harness in same package? No — the parser is internal; the CI step is a shell
         that re-implements line checks via grep -c. Simpler and dependency-free:
         workflow YAML asserts `grep -c '^PrivateKey: ' == 1` etc.)
       - generate the golden config by running a small Go test helper
         `TestE2ERenderGolden` (tag `xraye2e`) that renders with a fixed vector and
         writes to a temp path, then
       - `<bin> run -test -config <that file>` must exit 0.
    This is the explicitly-intended internet dependency (release download), isolated in
    its own CI step so the deterministic unit suite stays hermetic (tunnel-rules:
    "no public-Internet access unless explicitly intended" — it is explicitly intended
    and documented as such in the PR).

### 3.6 Rollback + permissions (spec items 10–11)

- `.prev` kept per activation (single generation, documented; T5 manifest tracks the
  last-known-good path for full rollback per doc §4.3).
- All writes: tmp in same dir → fsync → rename; file mode 0600 for the config and .prev
  (contains private key); tmp created with 0600 (O_CREATE|O_EXCL|O_NOFOLLOW); dir
  existence is the deployer's job (T5 creates /etc/split-tunnel with 0700).
- Refuse: existing symlink at target, target not a regular file, non-writable dir.

## 4. Spec-item traceability (the 12 deliverable requirements)

1. keygen local on Germany → keygen.go (bin path is the pinned install path).
2. keys/UUID/shortId generated only where required → Germany: keypair+UUID+shortId (T3);
   Iran: nothing in T3 (T10).
3. private key never transmitted → no field for it in any blob; arch test + a pairing
   regression test (`TestPrivateKeyNeverInBlobB` style, mirroring existing
   `TestUnknownFieldRejected`).
4. T1 pairing integration → PublicParams.SNI extension + generator accepts
   pairing-validated values; generator output feeds `NewBlobB` in T5 (T3 provides the
   validated values, not the blob emission).
5. deterministic JSON → §3.3 + golden.
6. operator input validation → §3.4.
7/8/9. `-test` gate → §3.5 (unit ordering + real binary in CI).
10. old config kept → `.prev` (§3.6).
11. explicit permissions → 0600 everywhere secret-bearing (§3.6).
12. no secret logging → sentinel errors, Redact-style masking, test asserts key bytes
   absent from error strings and from `Summary()` output.

## 5. Golden/test-vector matrix (T3-J; all hermetic, fake executor, no network)

1. valid input → bytes == golden file; render-twice identical.
2. missing SNI → rejected, named field, no panic.
3. malformed SNI: uppercase, trailing dot, IP literal, label-leading-hyphen, >253,
   empty, "sni:443" → all rejected.
4. invalid UUID (v1, uppercase, 35 chars, non-hex) → rejected.
5. invalid shortId (15 hex, 17 hex, uppercase, 'g' char, empty) → rejected.
6. missing/zero keypair → rejected (missing key material).
7. keypair parse: 2 lines / 4 lines / wrong prefix / non-b64 / 31-byte / 33-byte /
   CRLF line endings (accept) / trailing blank line (reject as 4th content? — decision:
   allow ONE trailing newline only, else reject).
8. BlobB: SNI present round-trips; missing SNI rejected; private-key-looking field
   injected into JSON → strict decode rejects (unknown field).
9. activate: gate-fail → dir unchanged (byte-compare pre/post, incl. mtime-free compare
   of contents); gate-pass → old content preserved byte-identical in .prev; perms 0600.
10. :9002 only appears as dokodemo target 127.0.0.1:9002 (grep golden); 443 is the only
    listen port; no other public listeners in the config (structural assert on parsed
    JSON in the test).
11. error strings never contain the private key bytes (table over all failure modes).
12. determinism: 100 renders → 1 distinct byte string (checksum).

## 6. Security-review pre-pass (T3-K will formalize)

- exec: `runCombined` = exec.Command with literal args; keygen adds NO user-controlled
  args (bin path from installer manifest; no flags in T3). No shell anywhere. ✔
- injection surface: SNI/UUID/shortId land in JSON string fields → rendered via
  encoding/json (or our ordered writer MUST json-escape identically — the golden test
  pins escaping; a writer that string-concats JSON is a CRITICAL, so the ordered writer
  will marshal each value with json.Marshal and assemble manually).
- path traversal: activate takes Dir from caller (T5 = fixed prefix); we add
  `filepath.Clean` + refuse `..` components + O_NOFOLLOW + Lstat check.
- symlink race: create-only tmp name `xray-germany.json.tmp` with O_EXCL; a pre-planted
  symlink at the tmp path is refused (O_NOFOLLOW). Rename over live file (not the tmp)
  is the classic safe pattern; live path Lstat-checked for symlink immediately before.
  Residual TOCTOU between Lstat and rename is bounded (same prefix, 0700 dir, single
  deploy user) and documented as accepted (matches T2's rename pattern).
- secret-in-error: sentinel errors only; the ONE place xray output is echoed (RunTest
  failure excerpt) contains the generated CONFIG which DOES include privateKey —
  mitigation: gate-failure log prints only the EXCERPT of xray's stderr/stdout (as T2
  does), and a unit test asserts our error path does not embed the rendered bytes;
  T2 already accepted bounded xray-output echo (xray does not echo privateKey in
  errors — verified: REALITYConfig.Build error message DOES include the privateKey
  string on decode failure! `errors.New("invalid \"privateKey\": ", c.PrivateKey)`).
  ⇒ DECISION: on RunTest failure, log NO config bytes at all — only the xray output
  excerpt with the privateKey value string-masked (replace the exact key string with
  "<redacted>") before echoing. This is the one place a real leak existed in xray's
  own errors; masking it is mandatory. Unit test proves masking.
- permissions: 0600 asserted in tests (mode bits only; Windows test uses
  os.FileMode(0600) == mode & 0777 — the CI Linux run is authoritative).

## 7. CI / Linux gate (T3-L)

- Existing .github/workflows/go.yml (ubuntu-latest, go 1.21, gofmt/vet/test/race/build):
  unchanged behavior for the hermetic suite.
- NEW step `Pinned Xray gate` (after `go test`, before cross-compile builds):
    1. `go test -tags xraye2e -run TestE2ERenderGolden ./internal/xray/` → writes
       testdata/e2e/tmp/germany-e2e.json (fixed vector) into a temp dir; prints its
       path via a marker line.
    2. Download v26.3.27 zip+dgst (pinned URL from internal/xray/version.go constants —
       echoed by the same test as a helper, or hardcoded in YAML to force pin match).
       sha256sum -c. Unzip. `xray version | grep -q Xray`.
    3. `xray x25519` line-shape grep assertions (3 lines, exact prefixes).
    4. `xray run -test -config <step1 path>` → must exit 0.
  Failure mode = red CI; this is the "do not call T3 complete before Linux CI is green"
  gate. (go-version 1.21 stays; no toolchain changes.)
- Local Linux verification on germany-node (ssh, go1.27.1, background session + log)
  before opening the PR, per project habit.

## 8. Out of scope (explicit)

- Service units, systemd restart, `splitterctl` commands → T5.
- Iran-side config (dokodemo inbound 10802 + vless outbound + flow) → T10.
- Dest TLS 1.3 reachability preflight (real network) → T5 preflight (T3 validates
  SHAPE of SNI only; the `-test` gate does not touch the network).
- Caddy/origin → T4 (next task after T3 merge).
- README/IMPLEMENTATION_STATUS.md update → final commit of T3 (repo rules).

## 9. Execution order (code mode)

1. Fix `OSExecutor.Keypair` (x2025→x25519) + its fake + docs.  (T3-D root)
2. keygen.go + keygen_test.go.  (T3-D)
3. pairing PublicParams.SNI + tests.  (T3-F/G shared)
4. realityconfig.go + golden + matrix tests 1–8,10–12.  (T3-E/G/J)
5. activate.go + tests 9,11.  (T3-H/I)
6. CI step + xraye2e helper; local Linux run.  (T3-L prep)
7. ARCHITECT review doc (docs/reviews/t3-reality-config-review.md) → remediate →
   re-review until CRITICAL=0 HIGH=0.  (T3-K)
8. Full suite + PR (squash, focused) + merge; IMPLEMENTATION_STATUS.md; clean tree.
9. T4 (internal/origin/Caddy) automatically after merge.  (T3-M)
