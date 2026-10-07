# Egress-target address-family policies

The Germany-side splitter dials **egress targets** — the logical
destinations that 3x-ui users reach through the tunnel (Meta, Google,
etc.). How it picks the address family (IPv4 vs IPv6) is one of two
orthogonal knobs, both opt-in and both OFF by default:

| Env var | Type | Default | Meaning |
|---------|------|---------|---------|
| `SPLIT_TARGET_ADDR_POLICY` | enum | `default` | `default` / `prefer-ipv4` / `ipv4-only` |
| `SPLIT_TARGET_ONLY_IPV4` | bool | `false` | hard A-record filter (legacy, equivalent to `ipv4-only`) |

The recommended knob for general traffic is
**`SPLIT_TARGET_ADDR_POLICY=prefer-ipv4`**. The hard filter
(`SPLIT_TARGET_ONLY_IPV4` / `ipv4-only`) is kept for operators who want
it but must be used with care — see "Evidence (the 96-refusal bug)"
below.

## The three policies

### `default` (the byte-identical baseline)

`SPLIT_TARGET_ADDR_POLICY=default` (or unset) leaves the dialer at the
historical `net.DialTimeout("tcp", addr, 10s)`: dual-stack resolution with
the OS address-family preference (RFC 6724). On a dual-homed Germany box
(empty `/etc/gai.conf`) that preference is typically **IPv6-first**, so a
domain that answers AAAA gets an IPv6 socket even when the IPv6 egress
leg is the fragile one. This is the pre-SUBTASK-42 behavior and is what
the node does unless an operator opts in.

### `prefer-ipv4` (RECOMMENDED — deterministic v4-first with v6 fallback)

`SPLIT_TARGET_ADDR_POLICY=prefer-ipv4`:

- **Domain, dual-stack (A + AAAA)** — resolve BOTH families, dial every
  IPv4 candidate first (sequentially, within a shared 10s budget), and
  fall back to the IPv6 candidates **only if no IPv4 candidate
  succeeded**. The v4 socket is the fast one (see "Evidence").
- **Domain, AAAA-only** — **dial IPv6**. This is the case the hard filter
  got wrong: under `prefer-ipv4` an AAAA-only host is never refused.
- **Domain, A-only** — dial the A record; the v6 fallback never runs
  (there is no AAAA record to fall back to).
- **Literal IPv4 / IPv6 address** — dial exactly as given; never
  rewritten, never re-resolved.

This is **preference, not prohibition**: it takes the v4 speed benefit
while keeping AAAA-only hosts working. The ordering is strict (try every
v4 candidate, then the v6 candidates), **not** the kernel's RFC 8305
happy-eyeballs race — see "Why it is not happy-eyeballs" below.

### `ipv4-only` (hard filter — use with care)

`SPLIT_TARGET_ADDR_POLICY=ipv4-only` (equivalent to
`SPLIT_TARGET_ONLY_IPV4=true`):

- Domain hosts resolve to **IPv4 (A) records only**, then the first
  reachable A record is dialed over `"tcp4"` within a shared 10s budget.
- A domain with **no A record** (AAAA-only) is **refused** with a clear
  error naming the policy. There is **no silent fallback to IPv6**.
- Literal IP addresses always bypass resolution and dial exactly as
  given (an IPv6 literal is never rewritten to IPv4).

**Use with care**: this is the filter that broke Instagram (96 stream
refusals on Meta's AAAA-only endpoints, evidence below). Prefer
`prefer-ipv4` unless you have a specific reason to hard-prohibit v6.

## Why it exists (the diagnosis)

Germany resolves dual-homed domains **IPv6-first** (empty `/etc/gai.conf`
+ RFC 6724 defaults). Live production had established v6 sockets to
Meta/Google. When the egress domain has both A and AAAA records and the
IPv6 path is fragile (MTU, NAT66, or a half-open v6 egress leg), the v6
socket is the slow one. Client-side IPv4-forced testing cut one domain's
dial from ~8s to ~1.5s, confirming the v6 egress leg is the fragile one.

The correct fix is therefore **preference, not prohibition**: try IPv4
first, but fall back to IPv6 if no IPv4 address is available (or if the
IPv4 dials fail). That is exactly `prefer-ipv4`.

The Iran-side `domainStrategy` in the Xray config governs Iran's own
outbound to the local SOCKS5 proxy, **not** the German egress — these
policies are orthogonal to it.

## Evidence

### The v4-speed benefit

| Signal | Before (dual-stack, v6-first) | After (prefer-ipv4 / ipv4-only) |
|--------|-------------------------------|---------------------------------|
| Egress domain with dual A/AAAA | IPv6 socket, ~8s to first byte | IPv4 socket, ~1.5s |

### The 96-refusal bug (why the hard filter is harmful)

On 2026-10-07 the hard filter (`SPLIT_TARGET_ONLY_IPV4=true`) was deployed
on the Germany host and then **reverted** because it actively broke
Instagram: **96 stream refusals in ~13 minutes**, every one on Meta's
**AAAA-only** endpoints (e.g. `netseer-ipaddr-assoc.*`) that the hard
filter refuses to dial. The hard filter is therefore worse than the
original problem (a slow v6 dial).

`prefer-ipv4` fixes exactly this regression: an AAAA-only domain still
dials over IPv6 (`TestPreferIPv4DomainAAAOnlyFallsBackToV6` in
[`pkg/node/target_ipv4_test.go`](../pkg/node/target_ipv4_test.go) is the
regression test for the 96-refusal bug).

| Policy | Dual A/AAAA domain | AAAA-only domain | Literal IPv6 |
|--------|--------------------|------------------|--------------|
| `default` | OS preference (often v6, ~8s) | v6 dial | v6 |
| `prefer-ipv4` | **v4 first, ~1.5s**; v6 only if v4 fails | **v6 dial (never refused)** | v6 |
| `ipv4-only` | v4 only | **REFUSED** (the 96-refusal bug) | v6 |

## Configuration

```ini
# Germany side (the only role that currently dials egress targets)
# Recommended:
SPLIT_TARGET_ADDR_POLICY=prefer-ipv4

# Hard filter (only if you specifically need to prohibit v6; use with care):
SPLIT_TARGET_ADDR_POLICY=ipv4-only     # or SPLIT_TARGET_ONLY_IPV4=true

# Iran side (set symmetrically; inert on this role — no egress target dial)
SPLIT_TARGET_ADDR_POLICY=prefer-ipv4
```

- **`SPLIT_TARGET_ADDR_POLICY` unset / empty** → `default` (byte-identical
  dual-stack behavior).
- **`default` / `prefer-ipv4` / `ipv4-only`** → parsed verbatim.
- **Any other value** → config error rejected at `--validate-config`,
  naming the allowed set (`default|prefer-ipv4|ipv4-only`).
- **`SPLIT_TARGET_ONLY_IPV4`** remains a real boolean (`1/0/true/false`);
  an invalid value is a config error, matching the `SPLIT_ALLOW_WEAK_SECRET`
  convention.
- **Contradiction**: `SPLIT_TARGET_ONLY_IPV4=true` combined with
  `SPLIT_TARGET_ADDR_POLICY=prefer-ipv4` is rejected at config load (hard
  refusal + soft fallback are mutually exclusive). `SPLIT_TARGET_ONLY_IPV4=true`
  combined with `default` or `ipv4-only` is compatible (the hard filter
  simply wins).

## Visibility

- `--validate-config` on both binaries prints the **active** policy
  (the strictest of the two knobs) and what it means for the deployment.
- At normal startup the Germany binary logs one line naming the active
  policy, e.g.:
  ```
  [germany-splitter] target dial policy: prefer-IPv4 active — domains dial v4 first, fall back to v6 when no v4 candidate succeeds; AAAA-only domains still succeed
  ```
  The Iran binary logs a corresponding "inert on this role" line when the
  field is set (config symmetry, no behavior change on Iran).

## Safety guarantees

- **Literal IP passthrough**: `net.ParseIP(host) != nil` → `dialPlain`
  (the historical dual-stack `net.DialTimeout("tcp")` path) under every
  policy. No family filter, no rewrite. An IPv6 literal stays IPv6.
- **Deterministic v4-first (not a race)**: `prefer-ipv4` tries every
  IPv4 candidate sequentially, then the IPv6 candidates. A v6 dial is
  never started while a v4 candidate is still in flight.
- **Timeout preserved**: the shared 10s budget (`targetDialTimeout`)
  covers resolution AND every dial attempt; a hung resolver or a slow
  first record cannot stall a bootstrap stream unboundedly.
- **Context propagation**: the resolution `context` is created with
  `context.WithTimeout(context.Background(), targetDialTimeout)` and
  cancelled in the same scope.
- **Custom `TargetDial` unchanged**: if a caller supplies their own
  `TargetDial` in `node.Config`, `Sanitize` leaves it alone — both policy
  fields are ignored in that case (the caller owns that dialer).

## Why it is not happy-eyeballs

RFC 8305 happy-eyeballs (and the `net.Dialer` with a bare `"tcp"`
network + `HappyEyeballs=true`) start **both** families concurrently and
let the first one that connects win. On a fragile v6 egress leg that
produces a v6 connection even when v4 is faster — the exact behavior the
original diagnosis was trying to avoid. The `prefer-ipv4` policy instead
enforces a **strict ordering**: every v4 candidate, then (only if all
v4 dials failed or none exist) the v6 candidates. This is "deterministic
v4-first with v6 fallback", not a race.

## Files

- [`internal/config/config.go`](../internal/config/config.go) —
  `EnvTargetAddrPolicy` const, `DefaultTargetAddrPolicy`, the
  `Config.TargetAddrPolicy` field, `Defaults()`, `Load()` wiring, and
  `Validate()` (unknown value rejected naming the allowed set; the
  `TargetOnlyIPv4=true` + `prefer-ipv4` contradiction rejected).
- [`pkg/node/node.go`](../pkg/node/node.go) — `Config.TargetAddrPolicy`
  field and the `Sanitize` merge (hard filter wins over preference).
- [`pkg/node/target_ipv4.go`](../pkg/node/target_ipv4.go) — the dialer
  implementation, the `dualStackLookup` resolver, and the `prefer-ipv4`
  v4-first/v6-fallback logic.
- [`pkg/node/target_ipv4_test.go`](../pkg/node/target_ipv4_test.go) —
  unit tests for filter/selection, AAAA-only behavior under both
  policies, v4-failure fallback, literal passthrough, and the
  hard-filter-precedence rule.
- [`internal/config/config_test.go`](../internal/config/config_test.go) —
  `TestLoadTargetAddrPolicyFromEnv`, `TestTargetAddrPolicyContradictionRejected`,
  `TestDefaultsTargetAddrPolicyPinned`.
- [`cmd/germany-splitter/main.go`](../cmd/germany-splitter/main.go) and
  [`cmd/iran-splitter/main.go`](../cmd/iran-splitter/main.go) — `node.NewNode`
  wiring and the `activeTargetAddrPolicy` startup/`--validate-config` log
  lines.

## Pre-deploy note

The new non-test code (the `prefer-ipv4` dialer, the resolver, the
config plumbing, the startup log lines) should be exercised under
`go test -race ./...` on a **Linux** host before deployment. This
Windows development host cannot run `-race`; the two-process integration
test (`RUN_TWOPROC=1 go test ./integration/...`) passes on Windows but
does not race-check the dial path.
