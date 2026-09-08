# T3 Reality Config — Architect Security & Architecture Review

- **Task**: T3 — Germany-side Reality keygen + Xray config generation
- **Branch**: `feat/t3-reality-config` (base `2974caf8`)
- **Reviewer**: Architect
- **Scope**: `internal/xray/keygen.go`, `internal/xray/realityconfig.go`, `internal/xray/activate.go`, `internal/pairing/pairing.go` (SNI), and their tests.
- **Standard**: CRITICAL = 0 and HIGH = 0 required before merge (per T3 spec mandatory loop).

## Verdict (Round 3 — FINAL)

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH     | 0 |
| MEDIUM   | 0 |
| LOW      | 0 |

**Result: PASS** — CRITICAL-2 (real-binary gate) remediated and verified against the
pinned v26.3.27 binary on Linux. Round 2's PASS (code review) is superseded by this
gate-driven round.

### Round 3 — CRITICAL-2: `dokodemo-door` is not a valid OUTBOUND protocol

Found by the **real-binary Linux gate** on germany-node (commit 8d9849d):
`xray run -test` against the rendered golden config failed with

```
failed to load outbound detour config for protocol dokodemo-door
> infra/conf: unknown config id: dokodemo-door
```

Root cause (verified at the pinned tag, commit d2758a0 == the binary's build hash):
`infra/conf/xray.go` registers `dokodemo-door` in the **inbound** loader
(line 27) but NOT in the **outbound** loader (line 40). The doc §4.5 / design doc
assumed a dokodemo-door *outbound*; the hermetic fake-Executor suite never runs the
real binary, so it could not catch this.

Fix: outbound `freedom` + `settings.redirect = "127.0.0.1:9002"`.
Verified: (a) the pinned binary accepts the rendered config (`Configuration OK.`,
exit 0); (b) the runtime override is semantically correct —
`infra/conf/freedom.go:143` builds a `DestinationOverride` from `redirect`, and
`proxy/freedom/freedom.go:97-110` replaces the dial target's address and port with
the fixed endpoint for every connection (TCP and UDP).

### Round 3 verification (evidence)

- [`realityconfig.go`](internal/xray/realityconfig.go) outbound is now
  `Protocol: "freedom"`, `freedomSettings{Redirect: "127.0.0.1:9002"}`; doc comment
  records why dokodemo-door is unusable as an outbound at the pinned tag.
- Golden regenerated: `"protocol": "freedom"`, `"settings": { "redirect":
  "127.0.0.1:9002" }`; `TestGoldenMatchesCommittedFile` + 100× determinism green.
- [`realityconfig_test.go`](internal/xray/realityconfig_test.go) structural audit
  reworked: 443 is the ONLY numeric port field, 0.0.0.0 the ONLY listen, and
  9002/127.0.0.1 appear ONLY inside the redirect string (exactly once).
- germany-node (Go 1.27.1, Ubuntu 24.04.4) full gate at the fix commit:
  `gofmt -l` clean, `go vet`, `go test ./...`, `go test -race ./...`, `go build`,
  then real pinned binary: sha256 vs `.dgst` OK, `xray version` OK, `x25519`
  3-line shape OK, `xray run -test -config <rendered>` → `Configuration OK.`
- Docs corrected in lockstep: architecture doc §3.2/§4.5 + JSON example + Q7,
  plans/t3-design.md §1/§2/§3.1/§5, IMPLEMENTATION_STATUS.md T3 bullet.

## Verdict (Round 2 — code review, superseded by Round 3 gate)

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH     | 0 |
| MEDIUM   | 0 |
| LOW      | 0 |

**Result: PASS** — CRITICAL-1, LOW-1, LOW-2 all remediated and verified. T3-K
(code review) complete; the real-binary gate (Round 3) found and fixed one further
CRITICAL (CRITICAL-2).

### Round 2 verification (evidence)

- [`keygen.go:129`](internal/xray/keygen.go:129) now reads `if priv[0]&0x07 != 0 || priv[31]&0xc0 != 0x40`
  with a comment that explicitly warns the unclamped bits (bit 3 of byte 0, bits 0-5 of
  byte 31) are random and must NOT be checked. Matches the pinned v26.3.27 source
  (`&= 0xf8; &= 0x7f; |= 0x40`) exactly.
- [`keygen_test.go:26`](internal/xray/keygen_test.go:26) fixture byte corrected to `0x40`;
  vector comment updated to `b[0] & 0x07 == 0, b[31] & 0xc0 == 0x40`.
- Negative cases: "unclamped private low bits" (`0x8f`), "unclamped private high bits"
  (`0xe0`, bit 7 set), and new "unclamped private bit6 missing" (`0x20`, bit 6 clear)
  all still reject.
- Positive regression pin: `TestParseX25519OutputClampRegression` accepts
  `b[0]=0x88` (bit 3 set) + `b[31]=0x44` (bit 5 clear) — the exact shape the buggy check
  rejected; guards against re-introducing the over-strict invariant.
- [`activate.go:167`](internal/xray/activate.go:167) masks `PrivateRaw, PublicRaw,
  PrivateStd, PublicStd` (defense-in-depth for the Std form).
- Golden regenerated (`privateKey ...HkA`, 32-byte clamped `0x40` last byte);
  `TestGoldenMatchesCommittedFile`, 100× determinism, structural audit, and the full
  `go test ./... -count=1` + `go vet` suite are green.

## History — Round 1 (superseded)

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH     | 0 |
| MEDIUM   | 0 |
| LOW      | 2 |

**Result: FAIL** — CRITICAL-1 and LOW-1/LOW-2 remediated in round 2 (above).

---

## Findings

| ID | Sev | Location | Summary |
|----|-----|----------|---------|
| CRITICAL-1 | CRITICAL | [`internal/xray/keygen.go:128`](internal/xray/keygen.go:128) | X25519 clamp check is wrong: rejects ~75% of **real** keys produced by the pinned binary |
| LOW-1 | LOW | [`internal/xray/activate.go:163`](internal/xray/activate.go:163) | `maskSecrets` masks only Raw encodings; add Std encodings as defense-in-depth (not an active leak) |
| LOW-2 | LOW | [`internal/xray/keygen_test.go:124`](internal/xray/keygen_test.go:124) | Test comment says "low nibble"; the binary clears only the low 3 bits (value still valid) |

---

## CRITICAL-1 — Wrong X25519 clamp invariant (breaks real keygen)

### Evidence (authoritative — verified at the pinned tag)

`XTLS/Xray-core` @ `v26.3.27`, `main/commands/all/curve25519.go`, `genCurve25519`:

```go
// Modify random bytes using algorithm described at:
// https://cr.yp.to/ecdh.html
// (Just to make sure printing the real private key)
privateKey[0]  &= 248   // 0xF8
privateKey[31] &= 127   // 0x7F
privateKey[31] |= 64    // 0x40
```

This is the standard X25519 scalar clamp. The **exact** resulting invariants are:

- **Byte 0**: bits 0,1,2 cleared; **bit 3 is random** (not clamped).
  - Invariant: `priv[0] & 0x07 == 0` (low **3** bits, not the low nibble).
- **Byte 31**: bit 7 cleared, **bit 6 set**; bits 0-5 are random.
  - Invariant: `priv[31] & 0x80 == 0 && priv[31] & 0x40 == 0x40`
    i.e. `priv[31] & 0xc0 == 0x40`.

### The bug

[`keygen.go:128`](internal/xray/keygen.go:128):

```go
if priv[0]&0x0f != 0 || priv[31]&0xa0 != 0x20 {
    return nil, fmt.Errorf("%w: private key is not a clamped X25519 secret", ErrKeygenBadKey)
}
```

- `priv[0]&0x0f` requires the **full low nibble** (bits 0-3) to be zero. The binary only
  guarantees bits 0-2 are zero; **bit 3 is 50/50 random** → ~50% of real keys fail here.
- `priv[31]&0xa0 == 0x20` requires **bit 5 set** (0xa0 masks bits 7,5; 0x20 is bit 5).
  The binary sets **bit 6**, not bit 5; **bit 5 is 50/50 random** → ~50% of real keys fail here.

The two bytes are independent, so a genuine key passes both only with probability
½ · ½ = **¼**. **Roughly 3 of every 4 real keys generated by the pinned binary are
wrongly rejected** with `ErrKeygenBadKey`. On the real Germany server this means the
keygen step fails most of the time and the deployment cannot complete. This directly
violates T3 deliverable item (1) "generate Reality key material LOCALLY on Germany"
and (5) "generate deterministic Xray JSON from structured configuration".

The comment at [`keygen.go:123-127`](internal/xray/keygen.go:123) is self-contradictory:
it correctly cites `&= 0xf8; &= 0x7f; |= 0x40`, then mistranslates it as "low nibble of
byte 0 is zero … bit 5 of byte 31 is set" (should be "low **3 bits** … bit **6** set").

### Consequence — test fixture is also wrong

[`keygen_test.go:26`](internal/xray/keygen_test.go:26) sets `b[31] = 0x20` (bit 5 set).
That value satisfies the **buggy** check but **not** the correct one (`0x20 & 0xc0 == 0x00
≠ 0x40`). Fixing the check without fixing the fixture would break
`TestParseX25519OutputValid`. The fixture byte must become `0x40`.

### Required remediation

`keygen.go` — replace the check and correct the comment:

```go
// The binary applies the standard X25519 scalar clamp before printing
// (privateKey[0] &= 0xf8; privateKey[31] &= 0x7f; privateKey[31] |= 0x40):
// the low 3 bits of byte 0 are zero, bit 7 of byte 31 is clear and bit 6 of
// byte 31 is set. (Bit 3 of byte 0 and bits 0-5 of byte 31 remain random.)
// Re-checking the clamped bits catches a broken or tampered binary.
if priv[0]&0x07 != 0 || priv[31]&0xc0 != 0x40 {
    return nil, fmt.Errorf("%w: private key is not a clamped X25519 secret", ErrKeygenBadKey)
}
```

`keygen_test.go`:
- [`:26`](internal/xray/keygen_test.go:26): `b[31] = 0x40 // clamped: bit 7 clear, bit 6 set`.
- [`:17-18`](internal/xray/keygen_test.go:17): update the vector comment to
  `b[0] & 0x07 == 0, b[31] & 0xc0 == 0x40 (X25519 scalar clamp)`.
- [`:122-125`](internal/xray/keygen_test.go:122): rename case to "unclamped private low bits",
  comment `0x8f & 0x07 == 0x07 != 0` (value `0x8f` still rejected — no behavior change).
- [`:127-131`](internal/xray/keygen_test.go:127): `b[31]=0xe0` still violates (bit 7 set) —
  no change needed; keep the case to pin the bit-7 rule.
- Add one positive pin: a key with bit 3 of byte 0 set and bit 5 of byte 31 clear is
  **valid** (e.g. `b[0]=0x88`, `b[31]=0x44`) — this is exactly the value the old buggy
  check rejected, so it guards against regression.

---

## LOW-1 — Mask Std encodings too (defense-in-depth)

[`activate.go:163`](internal/xray/activate.go:163) masks `PrivateRaw`/`PublicRaw`. The only
source of xray output in the gate path is the rendered config, which embeds the **Raw**
encodings — so the **Std** encodings cannot currently appear in the echo. This is not an
active leak. However `Keypair` also carries `PrivateStd`/`PublicStd`; adding them to the
mask set is a zero-cost guard against a future change that surfaces the Std form in an
error or log. Recommend: `maskSecrets(out2, kp.PrivateRaw, kp.PublicRaw, kp.PrivateStd, kp.PublicStd)`.

## LOW-2 — Imprecise test comment

[`keygen_test.go:124`](internal/xray/keygen_test.go:124) comment "low nibble" should read
"low 3 bits". No behavior change.

---

## Security checklist (T3 spec)

| # | Concern | Verdict | Evidence |
|---|---------|---------|----------|
| 1 | Command injection / unsafe shell | PASS | All exec via `Executor` → `runCombined` → `exec.Command` structured args, no shell (`install.go`) |
| 2 | Private-key leakage | PASS* | keygen sentinels-only errors (no echo), `Keypair` has no `Stringer`, renderer errors name fields not values, gate output masked. *pending LOW-1 hardening |
| 3 | Insecure file permissions | PASS | 0600 from creation (O_EXCL) + fsync on tmp/`.prev`/backup (`activate.go`) |
| 4 | Secrets in errors | PASS | `maskSecrets` + `excerpt` choke point; keygen/render errors carry no material |
| 5 | Arbitrary Xray JSON fields | PASS | Fixed struct shapes, fixed key order; no operator-injectable top-level fields |
| 6 | User-controlled SNI/host/path | PASS | `pairing.ValidSNI` (RFC1123, no IP/port/scheme); `dest` derived; Dir/FileName traversal-guarded |
| 7 | Symlink / path traversal | PASS | Lstat refusal of symlink/non-regular at live+tmp, O_EXCL, raw-input `..` check; bounded TOCTOU documented |
| 8 | Config replacement races | PASS | O_EXCL tmp (concurrent run fails cleanly) + atomic `os.Rename` |

## Architecture checklist

| Concern | Verdict | Evidence |
|---------|---------|----------|
| No new external deps | PASS | stdlib only + `internal/pairing` |
| Reuse internal/xray + internal/pairing | PASS | SNI/UUID/shortId validators reused as single source of truth |
| pkg/* does not import internal/* | PASS | new code all in `internal/xray`; enforced by `internal/archtest` |
| Deterministic output | PASS | pure renderer, fixed field order, golden pinned, 100× render test |
| Session/carrier engine untouched | PASS | no `pkg/node` changes |

---

## Re-review gate

After remediation of CRITICAL-1 (and optional LOW-1/LOW-2), re-run:
`go test ./internal/xray/ ./internal/pairing/ -count=1` and re-open this document.
Target: **CRITICAL = 0, HIGH = 0** → T3-K complete.
