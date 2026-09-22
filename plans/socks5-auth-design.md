# SOCKS5 Username/Password Authentication (RFC 1929) — Implementation Specification

**Scope:** design only. No source file is modified by this task.
**Target:** `iran-splitter` (`cmd/iran-splitter`), Iran role only.
**Goal:** the Iran1 SOCKS endpoint can be bound publicly (`0.0.0.0:10900`) and used by a 3xui user on Iran2 with `SPLIT_SOCKS_USER` / `SPLIT_SOCKS_PASS` credentials enforced, while an unconfigured deployment behaves byte-for-byte as it does today.

---

## 0. Grounding — what the code does today

| Fact | Reference |
|---|---|
| `socksNegotiate()` accepts only method `0x00`, replies `0x05 0xFF` otherwise, and performs the CONNECT exchange | [`cmd/iran-splitter/socks.go:28`](cmd/iran-splitter/socks.go:28) |
| The method loop scans `methods[]` for `0x00` and replies `{0x05, 0x00}` | [`cmd/iran-splitter/socks.go:41`](cmd/iran-splitter/socks.go:41) |
| `handleSOCKS5Conn` does negotiate → `StartSession` → `socksReply(0x00)` with no credential check | [`cmd/iran-splitter/main.go:447`](cmd/iran-splitter/main.go:447) |
| `Splitter` struct holds `config`, `node`, `logger` (the natural home for the new credential fields) | [`cmd/iran-splitter/main.go:82`](cmd/iran-splitter/main.go:82) |
| `SPLIT_*` env names are declared in one const block | [`internal/config/config.go:47`](internal/config/config.go:47) |
| `SPLIT_ALLOW_WEAK_SECRET` is parsed with `strconv.ParseBool` and any non-bool value is a config error | [`internal/config/config.go:233`](internal/config/config.go:233) |
| Secret strength policy lives in `mux.ValidateSecretMaterial(secret, allowWeak)` — blocklist always enforced, `MinSecretLen` only when `!allowWeak` | [`internal/config/config.go:367`](internal/config/config.go:367), [`pkg/mux/secret.go:54`](pkg/mux/secret.go:54) |
| `mux.ValidateSecret` is the existing constant-time comparison (`subtle.ConstantTimeCompare`) | [`pkg/mux/secret.go:18`](pkg/mux/secret.go:18) |
| `Desired()` records `envFingerprint(plan.Env)` — a non-invertible SHA-256 over the projected `KEY=VALUE` lines; no secret is stored in state | [`internal/deploy/request.go:445`](internal/deploy/request.go:445), [`internal/deploy/request.go:374`](internal/deploy/request.go:374) |
| Env projection is `InstallRequest.Env()` (the only channel T5 writes) | [`internal/deploy/request.go:109`](internal/deploy/request.go:109) |
| CLI `config set` resolves keys through `deploy.ConfigKeys`, never re-declaring an env name or a validation rule | [`internal/deploy/request.go:282`](internal/deploy/request.go:282), [`cmd/splitterctl/main.go:359`](cmd/splitterctl/main.go:359) |
| The env file is `0600 root:root` (tmp+fsync+rename, symlink refused, backups `.bak-<nano>` kept latest-3) | [`internal/systemd/envfile.go:107`](internal/systemd/envfile.go:107), [`internal/systemd/envfile.go:132`](internal/systemd/envfile.go:132), [`internal/systemd/envfile.go:401`](internal/systemd/envfile.go:401) |
| Env-file keys must be *known* and *non-empty*; unknown keys are an `ErrSpec` | [`internal/systemd/envfile.go:234`](internal/systemd/envfile.go:234) |
| `config show` deliberately prints no config values, paths, or hashes | [`cmd/splitterctl/main.go:1496`](cmd/splitterctl/main.go:1496) |
| The pinned test `TestSocksNegotiateNoMethod` requires `0x02`-only to be **rejected** | [`cmd/iran-splitter/socks_test.go:101`](cmd/iran-splitter/socks_test.go:101) |
| Test helpers: `negotiate(t, req)` drives `socksNegotiate` over a `testutil.NewMemPipe` (unbounded, never blocks writers) | [`cmd/iran-splitter/socks_test.go:28`](cmd/iran-splitter/socks_test.go:28), [`internal/testutil/mempipe.go:110`](internal/testutil/mempipe.go:110) |
| The integration harness's SOCKS client is dependency-free and speaks **no-auth only** | [`integration/socks5/client.go:85`](integration/socks5/client.go:85) |
| Up-carrier already has an auth-failure backoff: 10 failures / 60 s window, reset on success | [`cmd/iran-splitter/main.go:210`](cmd/iran-splitter/main.go:210), [`cmd/iran-splitter/main.go:303`](cmd/iran-splitter/main.go:303) |
| CI gates: gofmt, go vet, `go test ./...`, `go test -race ./...`, ShellCheck, pinned Xray/Caddy, `go build` host + linux/amd64 | [`.github/workflows/go.yml:34`](.github/workflows/go.yml:34) |
| The installer's config gate runs `<bin> --validate-config` with the `SPLIT_*` values it will write | [`install.sh:879`](install.sh:879) |

---

## 1. Configuration design

### 1.1 Decision: two variables (`SPLIT_SOCKS_USER` + `SPLIT_SOCKS_PASS`), not one combined `SPLIT_SOCKS_AUTH=user:pass`

**Recommendation: two separate variables.**

Justification, against the three criteria named in the task:

1. **Parsing ambiguity with `:` in passwords.** A single `user:pass` variable forces a delimiter convention, and every plausible one is lossy: `strings.Cut` splits on the *first* colon (so a password containing `:` works, but a *username* containing `:` does not); `SplitN(…, 2, ":")`-style "split on the last colon" is the rule nobody writes correctly on the first try; and a password that is itself empty (`user:`) is indistinguishable from "user with no separator". SOCKS credentials are exactly the kind of value operators generate with `openssl rand -hex`, where `:` is rare but not excluded, and 3xui users type them into a GUI. Two variables make the mapping *structural*: no delimiter to escape, no ambiguity, no "why did my password get truncated".
2. **3xui client ergonomics.** 3xui/Xray outbound socks settings expose `user` and `pass` as two distinct fields (an object, not a query string). Two env variables map 1:1 onto the two fields an operator must fill in — there is no mental concatenation step, and a rotation touches only one variable.
3. **Consistency with existing `SPLIT_*` conventions.** The existing convention is one variable per atomic field, kebab/dot-CLI keys over one `config.Env*` constant each (`socks.listen`, `ws.listen`, `down.carrier.addr`, … at [`internal/deploy/request.go:283`](internal/deploy/request.go:283)). A combined `user:pass` would be the only multi-value variable in the project, would need bespoke parsing and bespoke CLI handling, and would put a secret inside a value whose *shape* must be parsed — which is the exact mistake the project avoids elsewhere.

**Rejected alternative:** `SPLIT_SOCKS_AUTH=user:pass` (split on the last `:`). It is the only combined form that is actually unambiguous for arbitrary passwords, but it breaks on a username containing `:`, cannot express "user set, password empty", and reintroduces a value-parsing rule that no other variable in the project has.

### 1.2 Exact variables and formats

New constants in the `internal/config` env-name block (immediately after `EnvSocksListen` at [`internal/config/config.go:48`](internal/config/config.go:48), keeping the `Env*` + alignment style):

```go
EnvSocksUser     = "SPLIT_SOCKS_USER"              // Iran — SOCKS5 RFC 1929 username
EnvSocksPass     = "SPLIT_SOCKS_PASS"              // Iran — SOCKS5 RFC 1929 password (never logged)
EnvAllowWeakSocks = "SPLIT_ALLOW_WEAK_SOCKS_SECRET" // Iran (bool) — bypass, see §5
```

New `Config` fields (Iran-specific group, after `SocksListen` at [`internal/config/config.go:143`](internal/config/config.go:143)):

```go
SocksUser            string // Iran: RFC 1929 username; empty = auth not configured
SocksPass            string // Iran: RFC 1929 password; never logged, never echoed in errors
SocksAuthAllowWeak   bool   // SPLIT_ALLOW_WEAK_SOCKS_SECRET (see §5)
```

Format rules (mirroring the documented env syntax in [`internal/config/config.go:13`](internal/config/config.go:13)):

| Variable | Type | Format | Notes |
|---|---|---|---|
| `SPLIT_SOCKS_USER` | string | non-empty when auth is configured; otherwise unset/empty | 1..255 bytes recommended (see §1.4); no newline possible (env-value hygiene, §4) |
| `SPLIT_SOCKS_PASS` | string | non-empty when auth is configured; otherwise unset/empty | Strength policy per §5 |
| `SPLIT_ALLOW_WEAK_SOCKS_SECRET` | bool | `strconv.ParseBool` (`1/0/t/f/true/false/…`), exactly like `EnvAllowWeak` | any other value is a config error naming the variable, never the value |

**Defaults:** empty for both credentials (`Defaults()` sets no value — the same "unset means the default" rule at [`internal/config/config.go:488`](internal/config/config.go:488)). `SocksAuthAllowWeak` defaults false.

**Precedence:** there is exactly one layer (the environment, read by `Load(role)`). No config file, no flag, no per-connection override. `envString` is used verbatim: a variable that is unset **or set to the empty string** means "not set", which is the project's documented convention and is what makes the "only one set / empty value" cases in §1.3 deterministic.

### 1.3 Exact behavior for every combination

Auth is considered **configured** iff *both* `SocksUser != ""` and `SocksPass != ""`. Define `socksAuthEnabled(c) = c.SocksUser != "" && c.SocksPass != ""`.

| `SPLIT_SOCKS_USER` | `SPLIT_SOCKS_PASS` | `socksAuthEnabled` | Startup behavior |
|---|---|---|---|
| set | set | **true** | normal start; SOCKS greeting advertises `0x02` (and `0x00` is **not** advertised — §2.2); RFC 1929 sub-negotiation enforced |
| set | unset/empty | false | **fail closed** — `Load` returns a `*ConfigError` with the two problems in §1.5; binary exits |
| unset/empty | set | false | **fail closed** — same |
| unset/empty | unset/empty | false | **auth disabled** — exact current behavior (greeting `0x00` only); start succeeds |

**Rationale for the asymmetric treatment (half-set → error, none-set → today's behavior):**

- *None set* must keep existing deployments byte-identical (requirement 8): the deployed Iran1 host has no auth variables at all and must keep working with `127.0.0.1:10900` and method `0x00`. Silently rejecting the greeting there would be a breaking change with no signal to the operator.
- *Half set* is a misconfiguration, not a mode. There is no sensible third state: "username without password" cannot authenticate anything, and treating it as "auth disabled" would mean an operator who typo'd one of the two lines gets an **unauthenticated** SOCKS endpoint — the worst possible failure direction (silently open instead of silently closed). Failing closed at `config.Load` is consistent with the project's stated load→parse→validate→construct discipline (["A binary must not open a listener … until config.Load has returned successfully"](internal/config/config.go:8)) and with the placeholder-URL approach at [`internal/config/config.go:76`](internal/config/config.go:76) (a defaults value that *fails fast* rather than half-working).

### 1.4 Validation rules for the credentials

In `Validate(role)` (Iran role only, next to the `mux.ValidateSecretMaterial` call at [`internal/config/config.go:367`](internal/config/config.go:367)):

1. **Pairing (cross-field).** If exactly one of `SocksUser`/`SocksPass` is non-empty → problem:
   `SPLIT_SOCKS_USER and SPLIT_SOCKS_PASS must be set together (a username without a password cannot authenticate anything); set both or neither`.
   **Never echo either value.**
2. **Username length when auth is enabled.** `1 <= len(SocksUser) <= 255`. RFC 1929 encodes the username as a 1-byte length field, so anything longer is not representable; rejecting it at startup is strictly better than rejecting a client inside the connection handler. Problem text: `SPLIT_SOCKS_USER: expected 1..255 bytes (RFC 1929 encodes the username length in one byte)`.
3. **Username emptiness** is impossible by construction of §1.3, so no separate rule.
4. **Password strength** — see §5.
5. **Role scoping.** These rules apply to `RoleIran` only. `Validate(RoleGermany)` must not reject a Germany config that leaves them empty (same pattern as the role switch at [`internal/config/config.go:266`](internal/config/config.go:266)). Nothing in `roleOwnedEndpoints` changes, so listener-collision checks are unaffected.

Note that `checkHostPort` already accepts a bind-all host (`""`, `0.0.0.0`) — [`internal/config/config.go:466`](internal/config/config.go:466) — so `SPLIT_SOCKS_LISTEN=0.0.0.0:10900` needs **no** validation change.

### 1.5 Exact aggregated error text (field-only, no values)

`Load` already aggregates every problem before returning (["Load reports ALL validation problems at once"](internal/config/config.go:9)), so the half-set case produces alongside any other problems:

```
configuration validation failed:
  - SPLIT_SOCKS_USER and SPLIT_SOCKS_PASS must be set together (a username without a password cannot authenticate anything); set both or neither
```

If both are set but the password is weak and no bypass is active, the second line is the password problem from §5. **No line ever contains a credential value.**

---

## 2. Protocol behavior

### 2.1 Sequence when auth IS configured

```
client                                    iran-splitter
  │ 05 02 00 02  ─────────────────────▶  greeting: VER=5, NMETHODS=2, methods = {no-auth, user/pass}
  │                                        // 0x00 is NOT advertised (see 2.2)
  │  ◀─────────────────────  05 02        method selection: user/password
  │ 01 01 <ul> <u..> <pl> <p..> ───────▶  RFC 1929 sub-negotiation request
  │       01 <ul> <u..> <pl> <p..>       VER=0x01, ULEN, UNAME, PLEN, PASSWD
  │  ◀─────────────────────  01 00        success → CONNECT proceeds
  │ 05 01 00 …                          SOCKS5 CONNECT request
```

### 2.2 Should `0x00` also be advertised when auth is configured? **No — do not advertise it.**

Justification:

- **Security:** advertising `0x00` invites the client to skip authentication entirely. A permissive client (or a buggy one, or one that prefers "no auth") would take the free path and get an unauthenticated session on an endpoint that is about to be bound to `0.0.0.0`. The credential check would then be dead code reachable only by a client that *chooses* to pay the cost.
- **It defeats the purpose of the change.** The point of this work is that the public port is *gated*. Any path that reaches a session without a credential check is a gate left open, and the attack that uses it requires no credential at all — trivially the most valuable one.
- **RFC 1929 requires mutual agreement anyway:** a server that wants auth must select `0x02`, and the sub-negotiation is mandatory once it does. Adding `0x00` to the list is not "more compatible"; it is strictly weaker.
- The existing client in the repo makes the correct-looking-but-wrong choice loudly: it writes `{0x05, 0x01, 0x00}` and errors with `"server requires auth method 0x%02x (only no-auth is supported)"` at [`integration/socks5/client.go:99`](integration/socks5/client.go:99). That is the desired failure mode for a client that has no credentials — a hard, obvious error, not a silent bypass.

So when auth is enabled the greeting is exactly `05 02 00 02` (NMETHODS=2, both methods listed so a conforming client sees the server's full policy; selection is `0x02`).

### 2.3 Sequence when auth is NOT configured

Exactly as today: the greeting is parsed, `0x00` must appear in the offered set, `{0x05, 0x00}` is written, and the CONNECT exchange follows. **The byte-for-byte behavior of [`cmd/iran-splitter/socks.go:28`](cmd/iran-splitter/socks.go:28) is preserved in this branch** — including the `0x05 0xFF` reply for an unacceptable method set and the `0x05 0x07` reply for a non-CONNECT command.

### 2.4 RFC 1929 sub-negotiation byte layout

Request (client → server), read after the method selection `{0x05, 0x02}`:

```
+-----+------+----------+------+----------+
| VER | ULEN |  UNAME   | PLEN |  PASSWD  |
+-----+------+----------+------+----------+
|  1  |  1   | 1..255   |  1   | 1..255   |
+-----+------+----------+------+----------+
```
`VER = 0x01` (sub-negotiation version, distinct from SOCKS's `0x05`).

Replies (server → client), exactly two bytes:

| Case | Bytes | Meaning |
|---|---|---|
| success | `01 00` | credentials accepted → continue with CONNECT |
| failure | `01 01` | credentials rejected → close (see §2.6) |

`0x01 0x01` is the only RFC 1929 failure status. Status `0xFF` belongs to the **method** stage (`0x05 0xFF`), not the sub-negotiation, and must not be used here. Conversely, when auth is configured and a client offers **only** `0x00`, the reply stays `0x05 0xFF` (the existing stage, existing bytes).

Reading rules: read 2 bytes (`VER`, `ULEN`); reject `VER != 0x01`; read `ULEN` bytes of username; read 1 byte `PLEN`; read `PLEN` bytes of password. **No allocation is ever driven by an untrusted length** beyond the single 255 bound that the 1-byte field already imposes — `make([]byte, int(ulen))` with `ulen` a `byte` is bounded by 255, so no oversized-length DoS is expressible. A malformed stream (short read, bad `VER`) produces an error and a close, never a panic.

### 2.5 Greeting advertisement matrix

| Config state | Advertised methods | Method-selection reply | Sub-negotiation |
|---|---|---|---|
| both vars set | `{0x00, 0x02}` | `05 02` when `0x02` offered; `05 FF` when only `0x00` offered | enforced |
| both vars empty | `{0x00}` (unchanged) | `05 00` when `0x00` offered; `05 FF` otherwise | never entered |
| exactly one var set | *n/a* — binary refuses to start | — | — |

Note the case "auth configured but the client offers only `0x00`: the method is not acceptable, so the reply is `05 FF` and the connection closes. That is the *same* reply the no-auth path gives for an irrelevant method set, which keeps the method stage uniform.

### 2.6 Malformed sub-negotiation → close, no retry

**Recommendation: one attempt, then close. Do not allow retries within one connection.**

Rules:
- Bad `VER` (`!= 0x01`), truncated username/password (EOF before `ULEN`/`PLEN` bytes), or an I/O error → return an error, write nothing (there is no valid RFC 1929 status for a malformed frame), close the connection.
- Wrong credentials → write `01 01`, then close.
- Never send `01 01` twice, never loop back to the method stage.

Justification for no-retry:
- RFC 1929/1929 clients (including 3xui) treat `01 01` as terminal and reconnect; a retry loop inside one connection buys nothing legitimate.
- An unlimited retry loop on a public port is a free credential-guessing oracle: an attacker would reconnect only if the loop allowed it, and the attacker's real socket churn is what a rate limiter/fail2ban sees. Closing immediately keeps one socket ↔ one attempt, which is what makes the host-level mitigations in §10 effective and countable.
- The alternative (a bounded 2–3 attempt counter) would be strictly more code, more state, and more ways to leak both the configured credentials' *length* and the comparison result through timing/counting, for a compatibility gain the actual client does not need.

### 2.7 Deadline handling

`handleSOCKS5Conn` sets a 15 s deadline before negotiating and clears it after a successful negotiation ([`cmd/iran-splitter/main.go:448`](cmd/iran-splitter/main.go:448)). The sub-negotiation adds at most ~513 bytes of reading inside that existing window, so **no new deadline constant is needed** and the relay phase stays deadline-free. Do not add a separate auth deadline (the existing 15 s is already tighter than any sensible auth timeout and it is one knob, not two).

---

## 3. Constant-time comparison

Both comparisons use **`crypto/subtle.ConstantTimeCompare`** — the project already uses it for the carrier secret at [`pkg/mux/secret.go:18`](pkg/mux/secret.go:18), and the same primitive is reused rather than re-implemented.

Shape of the helper (placed in `cmd/iran-splitter/socks.go`, next to the negotiation code):

```go
// socksCredsMatch reports whether the supplied username/password match the
// configured pair. Both fields are compared in constant time; a length
// mismatch is a plain rejection, not a slow path.
func socksCredsMatch(gotUser, gotPass, wantUser, wantPass string) bool
```

Rules:
1. **Always compare both fields.** Do not short-circuit on the username. If the username fails and the function returns immediately, the elapsed time distinguishes "wrong user" from "wrong password" and the password comparison is skipped for exactly the requests that guess the user correctly — turning a timing oracle into a username oracle. Compare the username, then the password, then AND the results:
   `userOK := subtle.ConstantTimeCompare([]byte(gotUser), []byte(wantUser)) == 1; passOK := …; return userOK && passOK`.
2. **Length handling:** `ConstantTimeCompare` returns `0` for different lengths (and for two empty slices returns `1`). Because a `byte`-driven length can never exceed 255 and the configured username is validated to be 1..255, a client can guess lengths only through the *configured* values' lengths, which are not secret policy here (the password length is, however, not protected by constant-time comparison either way — see §10; the mitigation is password strength, not comparison shape). Do **not** hash before comparing: a SHA-256 pre-hash would quietly make `ConstantTimeCompare` length-invariant but would also hide the real length rule and add a place to get wrong. Compare the raw bytes.
3. **Never branch the *log message* on which field failed.** A single log line, `"SOCKS5 auth failed from %s"` (with the remote address only) — nothing that names the failing field, the supplied username, or the password.
4. Reuse, don't fork, `mux.ValidateSecret` semantics: it is `subtle.ConstantTimeCompare(...) == 1` on derived bytes. Credentials are compared directly because the configured values are already the exact bytes the client must send (no SHA-256 derivation is part of RFC 1929), so `mux.ValidateSecret` is *not* the right call here — but its primitive is.

---

## 4. Credential handling and logging

**The password must never appear in logs, error messages, the manifest, or any state file.** The project's convention, which this design mirrors exactly:

- `mux.ValidateSecretMaterial` "never logs the secret" and `Config` marks `Secret` as "never logged, never echoed in errors" — [`internal/config/config.go:150`](internal/config/config.go:150), [`pkg/mux/secret.go:53`](pkg/mux/secret.go:53).
- `InstallRequest.Env()` returns the secret to the env-file writer only; `Desired()` records a non-invertible digest of the projected env — ["no env value (least of all the shared secret) is recoverable from it, and it is never printed"](internal/deploy/request.go:358).
- Env-file errors are field-only by construction: `WriteEnvFile`'s contract says "The kv VALUES never appear in any error string" — [`internal/systemd/envfile.go:106`](internal/systemd/envfile.go:106) — enforced by the `validateEnvKV` checks at [`internal/systemd/envfile.go:225`](internal/systemd/envfile.go:225).
- `config show` prints no values at all — [`cmd/splitterctl/main.go:1496`](cmd/splitterctl/main.go:1496).

Concretely for this change:

1. **Logging (runtime).** `handleSOCKS5Conn` currently logs `"SOCKS5 CONNECT → %s:%d from %s"` on success (destination + remote addr) and the negotiation error on failure (["SOCKS5 negotiation: %v (from %s)"](cmd/iran-splitter/main.go:452)). Both stay. The new paths log **only**:
   - success: nothing extra, or `SOCKS5 auth ok from <remote>` — no username.
   - failure: `SOCKS5 auth failed from <remote>` — no username, no password, no "wrong user vs wrong password" distinction.
   The destination of a session (`dest.Addr:dest.Port`) is unchanged behavior and stays as-is; the destination is not a credential.
2. **Error strings.** Every new error is a `socksError`-style sentinel or `fmt.Errorf` with no `%s`/`%v` of a credential: `errors.New("rfc1929: sub-negotiation version is not 0x01")`, `fmt.Errorf("rfc1929: bad username length")`, `errSocksAuthFailed = errors.New("socks: authentication failed")`. The config problems in §1.5 name only the env **variable names**.
3. **No credential in the journald echo surface.** `journal_test.go`'s `secretMarker` pattern (a token asserted absent from journal echoes, [`internal/systemd/testutil_test.go:22`](internal/systemd/testutil_test.go:22)) should be extended to a `socksPassMarker` so a future regression that logs the password fails a test, not a review.
4. **Manifest/state.** The password reaches the host only through `InstallRequest.Env()` → `WriteEnvFile` → `0600 root:root` file. `DesiredState` records `envFingerprint` (SHA-256 over the projected `KEY=VALUE` lines) which is non-invertible and never printed, exactly as for `SPLIT_SECRET` — see [`internal/deploy/request.go:445`](internal/deploy/request.go:445) and [`internal/deploy/request.go:374`](internal/deploy/request.go:374).
5. **CLI.** `config set socks.user=…` / `socks.pass=…` route through the same `setConfigField` switch at [`cmd/splitterctl/main.go:449`](cmd/splitterctl/main.go:449), whose comment already states "the VALUE is never echoed in an error" — the new `case` statements follow that contract, and `config show` still prints nothing (it prints role/version/origin/firewall/pairing only).

---

## 5. Password strength policy and the bypass

**Recommendation: reuse `SPLIT_ALLOW_WEAK_SECRET`; do not add a second bypass variable.**

Analysis of the two candidate policies:

| Option | Effect |
|---|---|
| (a) Enforce `mux.ValidateSecretMaterial` on the SOCKS password using the **existing** `SPLIT_ALLOW_WEAK_SECRET` bypass | one bypass variable governs all secret-shaped material; CI's `--validate-config` runs keep working (`SPLIT_SECRET=ci-only-secret-material-…` satisfies the policy on its own); zero new env surface |
| (b) A dedicated `SPLIT_ALLOW_WEAK_SOCKS_SECRET` | two booleans to document, set, and rotate; a deployment can end up with a strong tunnel secret and a weak admin password; the semantics of "weak bypass" get split for no benefit |

Reasons for (a):

1. **A weak-tunnel-secret bypass already exists and its semantics are exactly right**: the blocklist (`password`, `admin`, `123456`, …) is *always* enforced, only the `MinSecretLen` gate is bypassable — [`pkg/mux/secret.go:56`](pkg/mux/secret.go:56). That is precisely the posture a public credential wants: never `admin`, otherwise ≥32 chars unless the operator explicitly opts out.
2. **Adding a second variable is new public surface for a case nobody will legitimately need.** A production SOCKS password is generated once (`openssl rand -hex 24`), never typed. The only legitimate consumer of the bypass is a test harness, and the harness can set the existing variable (or just use a 32+ char value, as CI already does at [`.github/workflows/go.yml:74`](.github/workflows/go.yml:74)).
3. **Reuse keeps `Config` minimal and keeps one canonical rule.** The username must *not* go through this policy: usernames are not secrets, and forcing 32 chaos characters into a username that 3xui displays in a dropdown is actively harmful. Username rules are the length rule in §1.4 only.

Concrete validation, in the Iran branch of `Validate` after the pairing check:

```go
if c.SocksAuthEnabled() {
    if err := mux.ValidateSecretMaterial(c.SocksPass, c.AllowWeakSecret); err != nil {
        problems = append(problems, fmt.Sprintf(
            "%s: does not satisfy the minimum security requirements (%v); generate one with: openssl rand -hex 24",
            EnvSocksPass, err))
    }
}
```

The problem line names the variable and the reason, never the value — the same message shape as the `SPLIT_SECRET` line at [`internal/config/config.go:368`](internal/config/config.go:368).

Add a small predicate to `Config` so the enabled test has one home and the goroutine/negotiation path reads cleanly:

```go
// SocksAuthEnabled reports whether RFC 1929 authentication is configured
// (both SocksUser and SocksPass non-empty). Iran role only.
func (c *Config) SocksAuthEnabled() bool { return c.SocksUser != "" && c.SocksPass != "" }
```

---

## 6. File-by-file change list

### 6.1 `internal/config/config.go`
- **Add** `EnvSocksUser`, `EnvSocksPass` constants to the const block at [`:47`](internal/config/config.go:47).
- **Add** `DefaultSocksUser = ""`, `DefaultSocksPass = ""` to the defaults block at [`:71`](internal/config/config.go:71) (documented as "empty = auth disabled, preserving pre-RFC-1929 behavior").
- **Add** `MinSocksUserLen = 1`, `MaxSocksUserLen = 255` to the bounds block at [`:133`](internal/config/config.go:133).
- **Extend** `Config` with `SocksUser string`, `SocksPass string` in the Iran group at [`:143`](internal/config/config.go:143).
- **Extend** `Defaults()` [`:174`](internal/config/config.go:174) with the two empty defaults.
- **Extend** `Load` [`:215`](internal/config/config.go:215): `c.SocksUser = envString(EnvSocksUser, c.SocksUser)`; `c.SocksPass = envString(EnvSocksPass, c.SocksPass)` (no `SPLIT_ALLOW_WEAK_SOCKS_SECRET` parsing — §5 reuses `EnvAllowWeak` at [`:233`](internal/config/config.go:233)).
- **Extend** `Validate` [`:266`](internal/config/config.go:266) in the `case RoleIran:` branch: pairing cross-field check (§1.4) + `mux.ValidateSecretMaterial` password policy (§5).
- **Add** method `func (c *Config) SocksAuthEnabled() bool` (near `Validate` or after `Defaults`).
- **Must not** touch: `checkHostPort`, `conflict`, `bindsEverything` (a bind-all `SPLIT_SOCKS_LISTEN` is already valid), `roleOwnedEndpoints`.

### 6.2 `cmd/iran-splitter/socks.go`
- **Add** the SOCKS5/RFC 1929 constants block:
  `socksMethodNoAuth byte = 0x00`, `socksMethodUserPass byte = 0x02`, `socksVersion byte = 0x05`, `socksAuthVersion byte = 0x01`, `socksAuthSuccess byte = 0x00`, `socksAuthFailure byte = 0x01`.
- **Add** `var errSocksAuthFailed = errors.New("socks: authentication failed")` (no credential content).
- **Change signature** of the negotiator so it can *select* a method:
  ```go
  func socksNegotiate(rw io.ReadWriteCloser, creds *socksCredentials) (*session.Destination, error)
  ```
  with
  ```go
  // socksCredentials is the configured RFC 1929 pair. A nil receiver /
  // zero value means "authentication is not configured".
  type socksCredentials struct {
      enabled bool
      user    string
      pass    string
  }
  ```
  Built once at startup from `cfg` (`newSocksCredentials(cfg)`), so the per-connection hot path does no config lookups and the enabled flag is immutable.
- **Rewrite** the method-selection block at [`:41`](cmd/iran-splitter/socks.go:41):
  - compute `want := []byte{0x00}`; if `creds.enabled` → `want = []byte{0x00, 0x02}`;
  - select the first offered method that is in `want`, preferring `0x00` when present (preserves today's behavior when auth is off);
  - if none → write `{0x05, 0xFF}`, return the existing `errors.New("no acceptable auth method")` (unchanged string and bytes — `TestSocksNegotiateNoMethod` still passes against the no-auth config);
  - if the selected method is `0x02` → **write `{0x05, 0x02}`** and call the new sub-negotiation before touching the CONNECT stage.
- **Add**
  ```go
  func socksAuthNegotiate(rw io.ReadWriteCloser, want socksCredentials) error
  ```
  implementing §2.4 exactly: 2-byte header, `VER` check, bounded reads, `socksCredsMatch` (§3), write `01 00` on success and `01 01` + `errSocksAuthFailed` on failure. All read errors are returned as-is (they become the caller's close reason).
- **Add** `func socksCredsMatch(gotUser, gotPass, wantUser, wantPass string) bool` (§3).
- **Preserve verbatim**: everything from the CONNECT header read at [`:56`](cmd/iran-splitter/socks.go:56) onward, including the `0x07` reply and `session.ReadDestinationEx`.

### 6.3 `cmd/iran-splitter/main.go`
- **Extend** `Splitter` struct [`:82`](cmd/iran-splitter/main.go:82) with `socksCreds socksCredentials` (value type, set once at construction).
- **In `main()`** [`:151`](cmd/iran-splitter/main.go:151): `s := &Splitter{…, socksCreds: newSocksCredentials(cfg)}`.
- **In `handleSOCKS5Conn`** [`:450`](cmd/iran-splitter/main.go:450): pass `s.socksCreds` to `socksNegotiate`.
- **In the negotiation-error branch** [`:451`](cmd/iran-splitter/main.go:451): distinguish, for the log only, `errors.Is(err, errSocksAuthFailed)` → `s.logger.Printf("SOCKS5 auth failed from %s", clientConn.RemoteAddr())`. The existing generic line stays for every other error.
- **Optionally** in `runSocksServer` [`:432`](cmd/iran-splitter/main.go:432): extend the startup log to `"SOCKS5 listening on %s (auth: enabled|disabled)"`. This is an ops-signal improvement (an operator can confirm the mode in the journal) and contains no credential. Keep the `%s` of the listen address as today.
- **Add** the SOCKS auth-failure backoff wiring (§10 defense in depth, optional but recommended): reuse `recordAuthFail`/`authInBackoff` [`:303`](cmd/iran-splitter/main.go:303) from the up-carrier. Recommendation: **share the counters**, so a public-port brute force on either surface trips the same 429-style backoff; document that the counters are process-wide. If sharing is judged too coarse for the machine-to-machine carrier, add a *separate* pair of methods (`recordSocksAuthFail`/`socksAuthInBackoff`) with the same constants and have the SOCKS path reject new authenticated connections with an immediate `01 01` while the backoff is active. The default recommendation is **separate counters**, because the up-carrier backoff protects a single legitimate dialer while the SOCKS port is public, and coupling them lets an attacker DoS the legitimate Germany carrier by flooding port 10900.

### 6.4 `internal/deploy/request.go`
- **Extend** `InstallRequest.Env()` [`:109`](internal/deploy/request.go:109) in the `RoleIran` branch:
  ```go
  if c.SocksUser != "" && c.SocksPass != "" {
      env[config.EnvSocksUser] = c.SocksUser
      env[config.EnvSocksPass] = c.SocksPass
  }
  ```
  Emitting both or neither — never one — keeps the env file and the splitter's `Load` in agreement and keeps the "half set" state unrepresentable on disk. (No bypass key is projected; `SPLIT_ALLOW_WEAK_SECRET` is already projected at [`:128`](internal/deploy/request.go:128).)
- **Extend** `ConfigKeys` [`:282`](internal/deploy/request.go:282) with:
  `{Name: "socks.user", EnvVar: config.EnvSocksUser, Roles: []string{RoleIran}, Kind: ConfigString}` and the `socks.pass` equivalent. This is what makes `splitterctl config set socks.user=…` work with **no** new CLI code (the CLI resolves through this table at [`cmd/splitterctl/main.go:371`](cmd/splitterctl/main.go:371)).

### 6.5 `cmd/splitterctl/main.go`
- **Extend** `setConfigField` [`:449`](cmd/splitterctl/main.go:449) with `case "socks.user": c.SocksUser = value` and `case "socks.pass": c.SocksPass = value`. No other CLI change: `applyConfigOverrides`, the fingerprint comparison, and the transaction path are all key-agnostic.

### 6.6 `internal/systemd/envfile.go`
- **Add** `config.EnvSocksUser`, `config.EnvSocksPass` to `optionalEnvKeys` [`:48`](internal/systemd/envfile.go:48).
- **Add** the two `case config.EnvSocksUser: c.SocksUser = v` / `case config.EnvSocksPass: c.SocksPass = v` arms to the validation fold at [`:257`](internal/systemd/envfile.go:257) so `WriteEnvFile` re-validates the pair through the authoritative `Config.Validate` (which enforces the pairing rule and the password policy).
- **No** change to `renderEnvFile`'s fixed key order beyond the natural sorting of optional keys, and **no** change to the 0600/backup logic.

### 6.7 `integration/socks5/client.go`
- **Add** an `Auth` option to `Dial` so the harness can speak RFC 1929. Preferred shape (backward compatible — the existing 8 call sites at [`:748`](integration/twoproc_test.go:748), `:774`, `:968`, `:1002`, `:1039`, `:1083`, `:1158` stay unchanged):
  ```go
  type Credentials struct{ User, Pass string }

  func Dial(socksAddr, dest string, port int, timeout time.Duration) (*Client, error) {
      return DialWithAuth(socksAddr, dest, port, timeout, nil)
  }

  func DialWithAuth(socksAddr, dest string, port int, timeout time.Duration, creds *Credentials) (*Client, error)
  ```
- **Change** the greeting at [`:85`](integration/socks5/client.go:85): if `creds == nil` write `{0x05, 0x01, 0x00}` (unchanged); otherwise write `{0x05, 0x01, 0x02}` and implement the `VER/ULEN/UNAME/PLEN/PASSWD` exchange, treating a non-`0x02` method selection as an error and `01 01` as an auth failure.
- **Extend** the mock in `client_test.go` ([`:26`](integration/socks5/client_test.go:26), which currently hardcodes `{0x05, 0x00}` at [`:55`](integration/socks5/client_test.go:55)) to answer the `0x02` selection with a configurable status so the new client path is unit-tested.

### 6.8 `integration/twoproc_test.go`
- Add the two env vars to the Iran `startProc` map at [`:836`](integration/twoproc_test.go:836) (values from the generated secret, like `SPLIT_SECRET`) and thread `*socks5.Credentials` through `runTransfer`/`transfer` ([`:744`](integration/twoproc_test.go:744), [`:771`](integration/twoproc_test.go:771)) — see §7.2.

### 6.9 Docs (non-code, part of the change set)
- `docs/self-contained-deployment-architecture.md`: add the two variables to the secret/credential table around [`:753`](docs/self-contained-deployment-architecture.md:753).
- `IMPLEMENTATION_STATUS.md`: a one-paragraph entry in the established style (listeners, state).
- `cmd/splitterctl/main.go` package doc env list at [`:15`](cmd/splitterctl/main.go:15) — follow the existing `SPLIT_*` comment pattern.

---

## 7. Test plan

### 7.1 Unit tests — `cmd/iran-splitter/socks_test.go`

**Refactor first (no behavior change):** extend the existing `negotiate` helper at [`:28`](cmd/iran-splitter/socks_test.go:28) into a credentials-aware variant so every existing test keeps calling the same one-liner:

```go
// negotiate drives socksNegotiate with the given client bytes and creds.
func negotiate(t *testing.T, request []byte, creds *socksCredentials) (*session.Destination, error, []byte)

// negotiateNoAuth is today's negotiate(t, req) — auth not configured.
func negotiateNoAuth(t *testing.T, request []byte) (*session.Destination, error, []byte) {
    return negotiate(t, request, &socksCredentials{})
}
```
All existing call sites become `negotiateNoAuth(t, req)`. **`socksGreetingNoAuth`, `buildSocksRequest`, and every existing assertion are untouched.**

**Update to the pinned test `TestSocksNegotiateNoMethod`** ([`:101`](cmd/iran-splitter/socks_test.go:101)) — the only required change to existing assertions:

```go
func TestSocksNegotiateNoMethod(t *testing.T) {
	// Offer only user/password (0x02) with auth NOT configured: no
	// no-auth method is available, so the method stage must reject.
	// (When auth IS configured the very same client bytes are answered
	// with 0x05 0x02 and reach the sub-negotiation — see
	// TestSocksAuthConfiguredCorrectCredentials.)
	req := []byte{0x05, 0x01, 0x02}
	_, err, reply := negotiateNoAuth(t, req)
	if err == nil {
		t.Fatal("unacceptable method set accepted")
	}
	if len(reply) < 2 || reply[0] != 0x05 || reply[1] != 0xFF {
		t.Fatalf("reply = %v, want [0x05 0xFF]", reply)
	}
}
```
The change is **mechanical** (`negotiate` → `negotiateNoAuth`) plus a cross-reference comment; the assertions, the input bytes, and the semantics of what it pins are identical. It continues to guarantee that a client offering only `0x02` is rejected when auth is not configured — which is now one half of a two-sided pair, the other half being the new auth-configured test that the *same bytes* succeed under.

**New tests (all use `t.Setenv`-free direct construction of `&socksCredentials{enabled: true, user: "alice", pass: "s3cr3t-password-value"}`):**

| Test | Input | Assertions |
|---|---|---|
| `TestSocksAuthConfiguredCorrectCredentials` | `05 02 00 02` + valid `01 01 <5>alice <21>s3cret…` + CONNECT | method reply `[05 02]`; sub-negotiation reply `[01 00]`; CONNECT parsed → `dest.Addr == "example.com"`, `Port == 443`; no error |
| `TestSocksAuthConfiguredWrongPassword` | same, wrong password bytes | `[05 02]`; `[01 01]`; `errors.Is(err, errSocksAuthFailed)`; **`dest == nil`**; reply length exactly 4 (nothing after `01 01`) |
| `TestSocksAuthConfiguredWrongUsername` | valid password, wrong user | identical shape to wrong-password (proves no field-specific behavior leaks) |
| `TestSocksAuthConfiguredMethodNotOffered` | greeting `05 01 00` (client offers only no-auth) while auth is configured | `[05 00]` **must not** appear; reply is `[05 FF]`; error; dest nil (§2.2) |
| `TestSocksAuthMalformedSubNegotiationVersion` | `05 02 00 02` + `02 01 01 a` (VER=0x02) | error, no `01 00`/`01 01` reply, no panic |
| `TestSocksAuthMalformedSubNegotiationTruncatedUser` | `01 05 a` (declares 5, sends 1) + `SetDeadline(150ms)` on the server conn | error (deadline/EOF); no panic. Mirrors `TestSocksNegotiateTruncatedGreeting` at [`:146`](cmd/iran-splitter/socks_test.go:146) |
| `TestSocksAuthMalformedSubNegotiationTruncatedPass` | user read fine, `PLEN` declares 10, sends 2 | error, no success reply |
| `TestSocksAuthZeroLengthUsername` | `01 00 05 <5 bytes>` (ULEN=0) | rejected: a 0-length username cannot match a configured 1..255 username; error, no reply |
| `TestSocksAuthMaxLengthCredentials` | 255-byte user / 255-byte password, correct value | accepted (proves the 1-byte length bound is handled, not rejected) |
| `TestSocksNegotiateNoAuthStillMethod00` | `05 01 00` + CONNECT with creds `{}` | `[05 00]` and full CONNECT — the exact pre-change behavior (this is the explicit backward-compat pin alongside the updated test) |
| `TestSocksCredsMatchTimingShape` | table of user/pass matches and mismatches, including one empty field and mismatched lengths | only boolean correctness: correct pairs true, any single-field mismatch false; a case where the username is correct and the password is not (documents non-short-circuit) |
| `TestSocksNegotiateBadCommandWithAuth` | valid auth, then `05 02 00 01 8.8.8.8 53` (BIND) | method `[05 02]`, `[01 00]`, then `[05 07]` — the command-not-supported path is unchanged by auth, mirroring `TestSocksNegotiateBadCommand` at [`:125`](cmd/iran-splitter/socks_test.go:125) |

The truncated tests must set a **deadline on the server side conn** (`srv.SetDeadline`) exactly as the existing truncated tests do — `MemConn` blocks indefinitely on an empty queue otherwise ([`internal/testutil/mempipe.go:63`](internal/testutil/mempipe.go:63)).

### 7.2 Unit tests — `internal/config/config_test.go`

- **Extend `isolatedEnv`** [`:26`](internal/config/config_test.go:26) with `EnvSocksUser`, `EnvSocksPass` (this is what makes "unset or empty" deterministic — the helper's stated purpose).
- **Extend `TestDefaults`** [`:62`](internal/config/config_test.go:62) with `c.SocksUser == ""`, `c.SocksPass == ""`, `SocksAuthEnabled() == false` (the backward-compat default, pinned).
- **`TestValidateSocksAuthPairing`** — pure `Validate(RoleIran)` (no env), table:
  both empty → nil; both set (strong pass) → nil; user only → problem contains `SPLIT_SOCKS_PASS` and neither value; pass only → same; both set with a weak pass and `AllowWeakSecret == false` → problem naming `SPLIT_SOCKS_PASS`; same with `AllowWeakSecret == true` → nil; username 300 chars → the 1..255 problem.
- **`TestValidateSocksAuthIgnoredForGermany`** — a `validGermany()` with `SocksUser`/`SocksPass` set to arbitrary values must **not** be affected by the Iran-only pairing rule (i.e. `Validate(RoleGermany)` still passes with both empty; and setting only one does not add a Germany problem — the fields simply are not Iran's).
- **`TestLoadSocksAuthFromEnv`** — `isolatedEnv(t)` + `t.Setenv(EnvSecret, strongSecret)`:
  - both set + strong pass → `cfg.SocksAuthEnabled() == true`, values round-trip;
  - both unset → `SocksAuthEnabled() == false` (backward compat, asserted);
  - both set to `""` (explicitly empty) → same as unset;
  - user only → `Load` fails, problem names `SPLIT_SOCKS_PASS`;
  - pass only → `Load` fails, problem names `SPLIT_SOCKS_USER`;
  - both set but pass is `"password"` (blocklisted) → `Load` fails **even with** `EnvAllowWeak=1` (the always-enforced blocklist), and the error text contains neither credentials.
- **`TestLoadAggregatesSocksAuthProblems`** — extend the aggregation test at [`:546`](internal/config/config_test.go:546): user only **and** a short `SPLIT_SECRET` → 2+ problems, `Load` returns `*ConfigError`, no value in any line.

### 7.3 Unit tests — `internal/deploy/request_test.go`

- **Extend `validIranRequest()`** [`:24`](internal/deploy/request_test.go:24) with `c.SocksUser = "alice"` / `c.SocksPass = strings.Repeat("z", 40)` (a policy-satisfying value) so every existing projection/planner/golden test exercises the new keys, OR keep the fixture unchanged and add one dedicated test. **Recommendation: extend the fixture** (it makes `Env()`, `ConfigFingerprint`, and `Desired()` cover the new keys for free) — but then `TestInstallRequestEnvProjectionKeepsSecretOutOfDesiredState` [`:90`](internal/deploy/request_test.go:90) must be extended to assert the SOCKS password's absence from `desired` too, using the same idiom as the `SPLIT_SECRET` assertion.
- **`TestConfigFingerprintChangesWhenSocksPassChanges`** — mirror [`:112`](internal/deploy/request_test.go:112) (same request, different `SocksPass`) → fingerprints differ; two identical requests → equal; the digest never contains either credential.
- **`TestLookupConfigKeySocksUserPass`** — `LookupConfigKey("socks.user")`, `LookupConfigKey("SOCKS_PASS")` and `LookupConfigKey("socks-pass")` all resolve to the right `EnvVar` (proving `NormalizeConfigKey` at [`:324`](internal/deploy/request.go:324) handles them), and `LookupConfigKey("socks.auth")` is *not* settable (the rejected combined form).

### 7.4 Unit tests — `internal/systemd/envfile_test.go`

- **Extend** the Germany/Iran fixtures' kv maps with the two keys and assert:
  - `WriteEnvFile` rejects `user` without `pass` (ErrSpec from the config fold — the pairing rule is enforced at the env-file boundary too);
  - renders both keys in the optional block, in sorted order, LF, single trailing newline;
  - the rendered bytes contain the password exactly once and **no error from `validateEnvKV`** ever contains it;
  - `rollback` of a file containing the password still works (the round-trip path is unchanged).
- Assert the new keys are absent from a request that leaves them empty (idempotent render for a legacy deployment — this is the backward-compat pin at the env-file layer).

### 7.5 Unit tests — `cmd/splitterctl/main_test.go`

- Extend the `config set` test at [`:1414`](cmd/splitterctl/main_test.go:1414) region with a case that sets `socks.user=alice` and `socks.pass=<40-char value>` on an installed Iran request, asserts `keys: socks.user, socks.pass` in the output, asserts the **values do not** appear in stdout/stderr, and asserts a repeat is a true no-op (`fake.calls` empty, no journal) — reusing the existing pattern at [`:1452`](cmd/splitterctl/main_test.go:1452).
- Extend the `config show` "no leak" test at [`:1924`](cmd/splitterctl/main_test.go:1924) so the SOCKS password is one of the forbidden substrings.

### 7.6 Unit tests — `integration/socks5/client_test.go` + `twoproc_test.go`

- **`client_test.go`:** extend `startMock` ([`:26`](integration/socks5/client_test.go:26)) so the handler answers a `0x02` selection with a configurable sub-negotiation status. New tests:
  - `DialWithAuth` with correct credentials against a mock that replies `01 00` → tunnel established, data flows;
  - wrong credentials → the mock replies `01 01` → `DialWithAuth` returns a distinct error (new exported `AuthError`) and the conn is closed;
  - server selects a method the client did not offer → error mentioning the method byte (preserves the existing message shape at [`:101`](integration/socks5/client.go:101)).
  All existing `Dial` tests remain and must pass unchanged (nil-credentials path).
- **`twoproc_test.go`:** the existing scenarios (`S1_connect_sustained` [`:875`](integration/twoproc_test.go:875), S5 half-close, S6, S8 rebind, S9, S11) run **unchanged** when no auth env is set — that is the L4 gate's backward-compat proof. Add one new gated scenario:
  - **`S0a_socks_auth`** — start the Iran proc with `SPLIT_SOCKS_USER`/`SPLIT_SOCKS_PASS`; (i) `socks5.DialWithAuth` with **wrong** credentials must fail before any CONNECT; (ii) with correct credentials a full CONNECT + echo + checksum transfer must succeed (reusing `transfer`); (iii) a raw `05 01 00` greeting to the same listener must be answered `05 FF` (no no-auth bypass). This is the full CONNECT-through-tunnel-with-auth proof.
  `startProc` ([`:264`](integration/twoproc_test.go:264)) already appends an arbitrary env map, so no harness change is needed beyond the two vars.

### 7.7 Race detector

`go test -race ./...` must stay green (CI gate at [`.github/workflows/go.yml:88`](.github/workflows/go.yml:88)). The new state is immutable after construction (`Splitter.socksCreds` is written once in `main` before any goroutine starts, then read-only), so no new synchronization is introduced. The *only* new shared, mutable state is the optional per-process auth-failure backoff counters, which reuse the existing mutex-guarded pattern (`authFailMu`, [`:95`](cmd/iran-splitter/main.go:95)) — mirror those, do not invent a new lock.

---

## 8. Backward compatibility (explicit proof obligations)

1. **Default path is unchanged by construction.** With both env vars empty, `creds.enabled == false`, so `socksNegotiate` takes exactly the code path that exists today: offered-method scan for `0x00`, `{0x05, 0x00}` reply, CONNECT parse. The gate for this is the combination of the *updated* `TestSocksNegotiateNoMethod` and the new `TestSocksNegotiateNoAuthStillMethod00` (both drive the no-auth path byte-for-byte), plus `TestSocksNegotiateDomain/IPv4/IPv6/BadVersion/ZeroMethods/BadCommand/Truncated*/MaxDomainLength` which all keep passing without modification (they only need the helper rename).
2. **Deployment path is unchanged.** `Defaults()` adds only empty strings; `Validate` adds no problem when the pair is empty; `InstallRequest.Env()` emits nothing new; `requiredEnvKeys` is untouched so `WriteEnvFile` accepts a legacy env file byte-identically and reports `applied=false` (idempotence — [`internal/systemd/envfile.go:148`](internal/systemd/envfile.go:148)). `configFingerprint` of a legacy Iran request is therefore **unchanged**, which means the planner sees **no drift** and `splitterctl upgrade`/`config set` on a legacy host remains a no-op.
3. **Integration harness is unchanged** in its default form: `socks5.Dial` keeps writing `05 01 00` ([`integration/socks5/client.go:86`](integration/socks5/client.go:86)), so the L4 gate (`RUN_TWOPROC=1`, workflow_dispatch) runs the real binaries with no auth exactly as before.
4. **No unit golden changes.** The systemd unit renderer emits no values for the splitter, so `TestRenderGolden` and `TestRenderedUnitsContainNoSecretMaterial` ([:177`](internal/systemd/render_test.go:177)) are untouched and still pass; the new env keys live in the env file, never in a unit.
5. **CI.** gofmt/go vet/`go test`/`-race`/pinned gates/linux-amd64 build are all satisfied by the code above; no new dependency, no new toolchain feature (avoid `min`/`max` builtins — Go 1.21 is pinned at [`.github/workflows/go.yml:31`](.github/workflows/go.yml:31), so use the explicit form, and note the repo already uses the `max(…)` builtin at [`internal/systemd/envfile.go:393`](internal/systemd/envfile.go:393), which implies the module's Go directive is newer than the CI's toolchain — therefore **do not introduce builtins**; the safest is `if len(x) < keep { … }`).

---

## 9. Deployment sequence (today → authenticated public endpoint)

Assumes the supported path (`splitterctl`) and the current staging facts in `IMPLEMENTATION_STATUS.md` (Iran listeners `127.0.0.1:10900`, `127.0.0.1:9001`, `127.0.0.1:10802`).

**Phase 0 — prepare locally (no host change)**
1. `gofmt -l .` empty; `go vet ./...`; `go test ./...`; `go test -race ./...`.
2. `GOOS=linux GOARCH=amd64 go build ./cmd/iran-splitter` and record the SHA-256 (the H-3 boundary, [`cmd/splitterctl/main.go:872`](cmd/splitterctl/main.go:872)).
3. Generate credentials **on the operator workstation**, never on the server:
   `USER=alice` (any name, ≤255 bytes), `PASS=$(openssl rand -hex 24)` (48 chars → `mux.ValidateSecretMaterial` passes with margin). Store the pair in the operator's password manager; it is also what goes into 3xui on Iran2.

**Phase 1 — build the binary with the new code, keep the listener on loopback**
4. Stage the new splitter under the canonical prefix (`/opt/split-tunnel/…`) and set `SPLITTERCTL_SPLITTER_BIN` + `SPLITTERCTL_SPLITTER_VERSION` to it.
5. Export the operator env: `SPLIT_SOCKS_USER`, `SPLIT_SOCKS_PASS`, plus the existing `SPLIT_SECRET`, `SPLIT_WS_LISTEN`, `SPLIT_DOWN_CARRIER_ADDR`, `SPLITTERCTL_*` values. Leave `SPLIT_SOCKS_LISTEN=127.0.0.1:10900` for now.
6. `splitterctl upgrade --splitter` → this runs the full transaction (env fold → `config.Validate` → `WriteEnvFile` 0600 → `ApplyUnit` + restart). Then `splitterctl config set socks.user=<u> socks.pass=<p>` as a *separate* transaction so the credential change is its own auditable generation (the fingerprint-driven no-op detection at [`:519`](cmd/splitterctl/main.go:519) means a repeat is free).

**Phase 2 — verify auth is enforced BEFORE the bind flips (this is the safety gate)**
7. `systemctl show iran-splitter -p EnvironmentFiles` and `stat -c '%a %U:%G %n' /etc/split-tunnel/iran.env` → `600 root:root` (the contract at [`internal/systemd/user.go:10`](internal/systemd/user.go:10)).
8. From a host that can reach the **current** loopback listener, prove the method stage:
   - `printf '\x05\x01\x00' | timeout 3 nc 127.0.0.1 10900 | xxd` → must be `05ff` (no-auth is refused, because `0x00` is not advertised when auth is configured);
   - a small scripted client that sends `05 02 00 02` then `01 01 01 a 01 x` → must answer `01 01`;
   - the same with the correct credentials → `01 00` followed by a successful CONNECT (this is the L4 `S0a_socks_auth` scenario, runnable now on loopback).
9. `journalctl -u iran-splitter --since -10min` → confirm the startup line reports the auth mode and that **no password bytes** appear anywhere (grep the literal password; expect 0 hits — the `secretMarker`/`socksPassMarker` style assertion).
10. Confirm the legitimate local consumer still works: from Iran1, a 3xui outbound configured with the same credentials must connect through the SOCKS endpoint. **Do not proceed until 7–10 all hold.** If any of 8–9 fails, roll back with `splitterctl config set` removing the two keys (or `splitterctl rollback --to <previous-generation>`) while the port is still loopback — the blast radius is zero.

**Phase 3 — expose the port**
11. Defense-in-depth first, on the host: an nftables allow rule restricted to Iran2's source address (see §10) and an explicit default-deny for 10900/tcp. Make the firewall rule **before** the bind change so the port is never briefly open to the world.
12. One atomic step, `splitterctl config set socks.listen=0.0.0.0:10900` → new generation, unit restart, bind on all interfaces.
13. `ss -lntp | grep 10900` shows `0.0.0.0:10900` (or `*:10900`).
14. From **Iran2**: (a) correct credentials → full tunnel; (b) wrong credentials → immediate `01 01` and a closed socket; (c) `05 01 00` → `05ff`; (d) from a host that is **not** in the allow list → no TCP connect at all (the nftables gate).
15. Point the Iran2 3xui SOCKS outbound at `<iran1-ip>:10900` with `user`/`pass` = the generated pair, restart 3xui, and confirm an end-to-end request.

**Rollback at any point:** `splitterctl config set socks.listen=127.0.0.1:10900` (one generation back to loopback) and, if needed, remove the two keys in the same transaction style. Because `config set` compares fingerprints, an identical request is a proven no-op that touches nothing — a safe dry-run of the endpoint state.

**Credential rotation later:** `splitterctl config set socks.pass=<new>` (the password only) — one generation, one env-file rewrite (0600, backed up latest-3), one restart. The username only needs changing if the operator wants to invalidate every cached client config. Update 3xui on Iran2 after the restart returns.

---

## 10. Security review and residual risks

| # | Residual risk | Severity | Mitigation |
|---|---|---|---|
| 1 | **Online brute force on a public port.** The credentials are the only gate once the bind is `0.0.0.0`; SOCKS auth has no server-side lockout and a public port is scannable. | **High** | (a) Strong, high-entropy password by policy (§5) — the blocklist is unconditional and the length gate is the difference between a guessing campaign that succeeds in minutes and one that does not. (b) Rate limiting: install **fail2ban** with a journald filter on `SOCKS5 auth failed` (the log line is deliberately uniform, §4.1), `bantime ≥ 1h`, `findtime 10m`, `maxretry 5`; the journald systemd backend reads the same unit log the splitter writes. (c) In-process backoff (§6.3) so a burst from one source is answered slowly/refused rather than at full CPU. (d) nftables source restriction as the primary defense: allow 10900/tcp **only** from Iran2's address, default-deny. With (d) in place the brute-force surface is one known host, and (a)+(b) are the backstop. |
| 2 | **Credential in the env file.** `SPLIT_SOCKS_PASS` is a plaintext value in `/etc/split-tunnel/iran.env`. | Medium (pre-existing pattern) | The file is `0600 root:root`, tmp+fsync+rename, symlink-refusing ([`internal/systemd/envfile.go:132`](internal/systemd/envfile.go:132), [`:401`](internal/systemd/envfile.go:401)); systemd reads it as root before dropping privileges ([`internal/systemd/systemd.go:6`](internal/systemd/systemd.go:6)); it is **never** in a unit file, in the manifest, or in `config show`. The `.bak-<nano>` backups are equally 0600 and swept to the latest 3. Residual: any host compromise with root reads it — true of `SPLIT_SECRET` too, and accepted by the project's documented posture. |
| 3 | **Password length leakage.** `ConstantTimeCompare` returns 0 on length mismatch; the comparison itself is length-invariant in cost but the *decision* timing can still differ by a few instructions. | Low | Mitigated by password strength (48+ random chars make guessing infeasible regardless) — not by comparison shape. Do not attempt a home-grown length-hiding scheme; it adds complexity and false confidence. |
| 4 | **Timing oracle on username vs password.** | Low | Eliminated by always comparing both fields with no short-circuit (§3, rule 1). |
| 5 | **Credential in shell history / operator logs.** `config set socks.pass=…` and an `export SPLIT_SOCKS_PASS=…` step both put the secret on a command line. | Medium | The password is generated once and rotated rarely, so the exposure window is small but real. Mitigations: prefer `SPLIT_SOCKS_PASS="$(cat /root/socks.pass)"` over a literal argv value; if a file is used, stage it 0600 and `rm` it after; never pass it into a script that is itself logged; on an interactive shell use a leading space with `HISTCONTROL=ignorespace` for the one unavoidable manual entry. |
| 6 | **No per-user authorization, revocation, or accounting.** RFC 1929 here authenticates one fixed pair; there is no user table and no way to revoke a single consumer without rotating the shared secret. | Accepted (by design) | This is a single-operator tunnel, matching the project's posture that the SOCKS endpoint is not a multi-user server (["this is a machine-to-machine link, **not** a multi-user server (no 3xui-style user management; explicitly out of scope)"](docs/self-contained-deployment-architecture.md:412)). Rotation (`config set socks.pass=…`) revokes everyone at once; the nftables allow-list keeps the *set of possible clients* known even though they share credentials. |
| 7 | **Cleartext credentials on the wire.** RFC 1929 transmits the username/password in the clear inside the TCP stream — there is no TLS layer inside the SOCKS protocol itself. | **High if the port is wide open** | This is the decisive reason the nftables source restriction (risk 1d) is **mandatory**, not optional: it makes the only clients of a cleartext-credential endpoint a known, small set of hosts. If the port ever has to be reachable more widely than that, the correct next step is to terminate TLS in front of it (Caddy already fronts this host, [`internal/systemd/user.go:8`](internal/systemd/user.go:8)) — never to widen the credential's exposure instead. |
| 8 | **Denial of service by socket exhaustion / unauthenticated connection churn.** A public listener accepts connections that never complete the greeting, holding a goroutine each. | Low | The existing 15 s negotiation deadline ([`cmd/iran-splitter/main.go:448`](cmd/iran-splitter/main.go:448)) already bounds every unauthenticated connection to 15 s, and the accept loop spawns exactly one goroutine per accepted conn. If it is ever observed, the hardening is a bounded accept semaphore mirroring `maxConcurrentHandshakes` ([`cmd/iran-splitter/main.go:211`](cmd/iran-splitter/main.go:211)) plus the in-process backoff from §6.3. |
| 9 | **Env-file backup exposure.** Each env rewrite leaves a `.bak-<nano>` containing the previous password. | Low | Backups are 0600 root:root and swept to the latest 3 ([`internal/systemd/envfile.go:159`](internal/systemd/envfile.go:159)), and after a rotation the value they hold is a *retired* credential. Shredding retired backups would be a `splitterctl` enhancement, not a requirement. |
| 10 | **A hand-edited half-configured env file.** One of the two keys present, by an operator editing `/etc/split-tunnel/iran.env` directly. | Eliminated in-chain | `InstallRequest.Env()` emits both or neither (§6.4); `WriteEnvFile` re-validates the fold through `config.Validate`, so a future write that would land one key is refused ([`internal/systemd/envfile.go:300`](internal/systemd/envfile.go:300)); and even a hand-edited live file cannot produce a running unauthenticated endpoint because the splitter itself refuses to start on the half-set state (§1.3). Three independent layers, all fail-closed. |
| 11 | **`config set` value captured by shell history or a CI log.** | Medium | Same treatment as risk 5. Note the project already documents this posture for `SPLIT_SECRET`: the operator env file exists precisely so "the value never transits the shell history, a log, or a file" (see the `%OUT%/iran-upgrade.sh` pattern of re-exporting the committed secret instead of retyping it). The SOCKS credentials should be sourced the same way once committed. |

### 10.1 nftables defense-in-depth (recommended concrete shape)

The project's `firewall` package renders port-only rules — `nft rule inet split_tunnel input tcp dport <p> allow` — and its `Rule` type has **no source-address field** ([`internal/firewall/firewall.go:261`](internal/firewall/firewall.go:261)). A source restriction is therefore deliberately *outside* the project-owned firewall plan and must be an operator-managed rule:

```
nft add rule inet filter input tcp dport 10900 ip saddr <iran2-ip>/32 accept comment "split-tunnel SOCKS auth endpoint"
nft add rule inet filter input tcp dport 10900 drop comment "split-tunnel SOCKS: default deny"
```

The `drop` line is what matters: it is the difference between *authenticated but world-reachable* and *authenticated and reachable only from the host that should use it*. Order the accept before the drop. Keep both rules under a comment the project does **not** own — `internal/firewall` only removes rules carrying its own `Marker` ([`internal/firewall/firewall.go:304`](internal/firewall/firewall.go:304)) — so they survive a project firewall re-apply untouched.

### 10.2 fail2ban (recommended concrete shape)

```
# /etc/fail2ban/jail.d/split-tunnel-socks.local
[socks-auth]
enabled  = true
filter   = socks-auth
action   = nftables[name=socks-auth, port=10900, protocol=tcp]
logpath  = journalctl[unit=iran-splitter]
maxretry = 5
findtime = 600
bantime  = 3600
```

with `/etc/fail2ban/filter.d/socks-auth.conf` matching `SOCKS5 auth failed from <HOST>`. The single uniform log line mandated by §4.1 is exactly what makes this filter possible: anchorable, credential-free, and firing precisely once per failed attempt.

---

## 11. Sequencing summary (what must be true, in order)

1. Code + tests land, in dependency order: `internal/config` constants/fields/validation → `cmd/iran-splitter/socks.go` negotiation + constant-time compare → `cmd/iran-splitter/main.go` wiring + logging → `internal/deploy` + `cmd/splitterctl` + `internal/systemd` projection → `integration/socks5` client → unit tests → `go test ./...` and `go test -race ./...` green, `GOOS=linux GOARCH=amd64 go build ./...` green.
2. Stage the binary on Iran1 via the supported `splitterctl` path — **still bound to `127.0.0.1:10900`**.
3. Apply the credentials and **prove enforcement on loopback** (§9 Phase 2 steps 8–10). Nothing past this point runs until that proof exists.
4. Put the host firewall restriction in place (§10.1) → then, and only then, `config set socks.listen=0.0.0.0:10900`.
5. Verify from Iran2 (correct credentials, wrong credentials, and a non-allowed source), point the 3xui SOCKS outbound at it, then update `IMPLEMENTATION_STATUS.md` and the credential table in the architecture doc.

The one ordering rule that must never be inverted: **the port is never bound publicly before authentication has been demonstrated to reject both a credential-free greeting and wrong credentials.**