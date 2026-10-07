# Opt-in only-IPv4 egress-target policy

## What it is

`SPLIT_TARGET_ONLY_IPV4` is an opt-in configuration variable (default **false**,
i.e. off) that changes how the Germany-side splitter dials its **egress
targets** — the logical destinations that 3x-ui users reach through the
tunnel (Meta, Google, etc.).

When **off** (the default, preserving the historical behavior):

- The node's default `TargetDial` is `net.DialTimeout("tcp", addr, 10s)`.
- Domain hosts are resolved by the OS resolver with **dual-stack** semantics;
  the OS address-family preference (RFC 6724) picks which family to use.
- Literal IP addresses (v4 or v6) are dialed exactly as given.

When **on** (`SPLIT_TARGET_ONLY_IPV4=1` or `=true`):

- Domain hosts are resolved to **IPv4 (A) records only** via
  `net.Resolver.LookupHost`, then filtered to addresses where
  `net.IP.To4() != nil`, and the first reachable A record is dialed over
  `"tcp4"` within a shared 10s budget.
- A domain that has **no A record** (AAAA-only) is **refused** with a clear
  error naming the policy. There is **no silent fallback to IPv6**.
- **Literal IP addresses always bypass resolution** and dial exactly as given:
  an IPv6 literal is never rewritten to IPv4.

## Why it exists (the diagnosis)

Germany resolves dual-homed domains **IPv6-first** (empty `/etc/gai.conf` +
RFC 6724 defaults). Live production had established v6 sockets to Meta/Google.
When the egress domain has both A and AAAA records and the IPv6 path is
fragile (MTU, NAT66, or a half-open v6 egress leg), the v6 socket is the
slow one.

The 3x-ui users' egress is exactly this `TargetDial` — our code owns the
choice of address family. Client-side IPv4-forced testing cut one domain's
dial from ~8s to ~1.5s, confirming the v6 egress leg is the fragile one.

The Iran-side `domainStrategy` in the Xray config governs Iran's own
outbound to the local SOCKS5 proxy, **not** the German egress — this policy
is orthogonal to it.

## Evidence

| Signal | Before (dual-stack, v6-first) | After (IPv4-only) |
|--------|-------------------------------|-------------------|
| Egress domain with dual A/AAAA | IPv6 socket, ~8s to first byte | IPv4 socket, ~1.5s |
| AAAA-only domain under policy on | n/a (silent v6 dial) | **Explicit refusal** — no v6 fallback |
| Literal IPv6 address | dialed as v6 | **still dialed as v6** (no rewrite) |

## Configuration

```ini
# Germany side (the only role that currently dials egress targets)
SPLIT_TARGET_ONLY_IPV4=1

# Iran side (set symmetrically; inert on this role — no egress target dial)
SPLIT_TARGET_ONLY_IPV4=1
```

- **Unset / empty** → default `false` (pre-policy dual-stack behavior).
- **`true` / `1` / `t` / `TRUE`** (case-insensitive) → policy active.
- **`false` / `0` / `f` / `FALSE`** → policy explicitly off.
- **Any other value** → config error, rejected at `--validate-config` time,
  matching the `SPLIT_ALLOW_WEAK_SECRET` boolean convention.

## Visibility

- `--validate-config` on both binaries prints one line naming the policy
  state and what it means for the deployment.
- At normal startup, when the policy is active, the Germany binary logs:
  ```
  [germany-splitter] target dial policy: IPv4-only active (SPLIT_TARGET_ONLY_IPV4=1) — domains resolve to A records; AAAA-only domains refused
  ```
  The Iran binary logs a corresponding "inert on this role" line when the
  field is set (config symmetry, no behavior change on Iran).

## Safety guarantees

- **Literal IP passthrough**: `net.ParseIP(host) != nil` → `dialPlain` (the
  historical dual-stack `net.DialTimeout("tcp")` path). No family filter, no
  rewrite. An IPv6 literal stays IPv6.
- **No silent v6 fallback**: an empty A-record result after the `To4()`
  filter produces a `*net.OpError`-shaped message that explicitly names
  `SPLIT_TARGET_ONLY_IPV4` and the host. The stream is dropped at
  `bootstrapUpStream` with that message in the log; it is never dialed
  over IPv6.
- **Timeout preserved**: the shared 10s budget (`targetDialTimeout`) applies
  to both the resolution step and the dial attempt. A hung resolver cannot
  stall a bootstrap stream indefinitely.
- **Context propagation**: the resolution `context` is created with
  `context.WithTimeout(context.Background(), targetDialTimeout)` and
  cancelled via `defer cancel()` in the same scope.
- **Custom `TargetDial` unchanged**: if a caller supplies their own
  `TargetDial` in `node.Config`, `Sanitize` leaves it alone — the policy
  field is ignored in that case (the caller owns that dialer).

## Files

- [`internal/config/config.go`](../internal/config/config.go) — env const,
  default, `Load` wiring, `Validate` (no role-specific rule: the variable is
  accepted on both roles).
- [`pkg/node/node.go`](../pkg/node/node.go) — `Config.TargetOnlyIPv4` field
  and the `Sanitize` call to `newDefaultTargetDial`.
- [`pkg/node/target_ipv4.go`](../pkg/node/target_ipv4.go) — the dialer
  implementation and the filter.
- [`pkg/node/target_ipv4_test.go`](../pkg/node/target_ipv4_test.go) — unit
  tests for filter, off-by-default, AAAA-only refusal, literal IP
  passthrough, end-to-end A-record dial.
- [`internal/config/config_test.go`](../internal/config/config_test.go) —
  `TestLoadTargetOnlyIPv4FromEnv` (true/false/invalid parsing) and
  `TestDefaultsTargetOnlyIPv4False`.
- [`cmd/germany-splitter/main.go`](../cmd/germany-splitter/main.go) and
  [`cmd/iran-splitter/main.go`](../cmd/iran-splitter/main.go) — `node.NewNode`
  wiring and startup/`--validate-config` log lines.

## Pre-deploy note

The new non-test code (the dialer, the filter, the startup log lines) should
be exercised under `go test -race ./...` on a Linux host before deployment.
This Windows development host cannot run `-race`; the two-process
integration test (`RUN_TWOPROC=1 go test ./integration/...`) passes on
Windows but does not race-check the dial path.
