# Carrier Reconnect Backoff — Bounded Reconnect Window

## Symptom and root cause

The 2026-10-13 01:29–01:31 Iran-time incident was a ~2-minute user-visible
tunnel outage that was NOT proportional to the underlying underlay/egress
blip it was caused by. The carrier reconnect loop amplified a brief failure
into a multi-minute one.

Both splitter roles run a carrier reconnect loop that, on every failed
attempt, sleeps on an exponential backoff schedule. The schedule was
hardcoded as `backoff.New(2*time.Second, 60*time.Second)` in two places:

- [`cmd/germany-splitter/main.go`](../cmd/germany-splitter/main.go) — the up-carrier
  WebSocket client → CDN dial loop (`runUpCarrier`);
- [`cmd/iran-splitter/main.go`](../cmd/iran-splitter/main.go) — the down-carrier
  TCP client → local Xray dial loop (`runDownInstance`).

With base = 2s, cap = 60s, and per-attempt jitter in `[d/2, d]`, the six
consecutive failed attempts sleep, in the worst case:

```
2 + 4 + 8 + 16 + 32 + 60 = 122 seconds
```

before the 7th attempt even runs. The problem is that this is a *cumulative*
sleep: even after the underlay has recovered (say, 30s after the blip
started), the loop is still sitting in a 60-second sleep and will not
re-probe the carrier for up to another 60 seconds. A short, recovered
underlay failure therefore surfaces as a ~2-minute user-visible outage —
exactly the 01:29→01:31 window observed.

The fix is to bound the *total* reconnect sleeping within one failure
episode, so that once an outage outlives the bound the carrier is retried at
a steady, operator-visible cadence instead of a growing one.

## The bounded reconnect window

`internal/backoff` gains `NewBounded(base, max, window, clamp)` alongside the
existing `New(base, max)` (which now delegates to `NewBounded(base, max, 0, 0)`,
so the pre-fix pure-exponential behavior is byte-for-byte reachable). The
new fields:

- `window` — the cumulative *nominal* sleep budget for one failure episode.
- `clamp` — the per-attempt delay used once the window is exhausted.
- `slept` — the running cumulative of nominal delays since the last `Reset`.

In `Next()`, after the existing exponential-doubling-then-cap computation of
`d`, the schedule applies:

```go
if b.window > 0 && b.clamp > 0 && b.slept >= b.window && b.clamp < d {
    d = b.clamp
}
b.slept += d
```

The NOMINAL `d` (not the jittered sleep) is accumulated so the schedule is
deterministic and testable. The jitter in `Sleep()` is unchanged: it still
maps `d` into `[d/2, d]`, so the cap remains a real cap and the invariants
"no reconnect storm, no busy-loop; the cap is a real cap" still hold.
`Reset()` zeroes both the attempt counter and `slept` — a fresh failure
episode gets a fresh window.

### Resulting schedule (defaults)

With the defaults base = 1s, cap = 10s, window = 30s, clamp = 2s the
nominal delays are:

```
1, 2, 4, 8, 10, 10      (cumulative: 1, 3, 7, 15, 25, 35 — the 6th call
                         pushes the cumulative to 35 ≥ 30, exhausting the
                         window)
2, 2, 2, 2, ...         (every further attempt is clamped to 2s)
```

Worst-case cumulative sleep up to the 7th attempt is ~35s — versus 122s
before the fix. Each nominal delay is still jittered into `[d/2, d]`, so a
2s nominal sleep lands anywhere in `[1s, 2s]`.

## New environment variables and defaults

All four knobs are wired for **both roles** (both hosts run a reconnect
loop: Germany dials the up-carrier WS → CDN, Iran dials the down-carrier
TCP → local Xray). They live in the role-agnostic part of
`config.Load()`, not gated on `RoleIran`/`RoleGermany`.

| Env var | Default | Meaning |
|---|---|---|
| `SPLIT_RECONNECT_BASE_MS` | `1000` | carrier reconnect exponential backoff base (ms) |
| `SPLIT_RECONNECT_MAX_MS` | `10000` | carrier reconnect exponential backoff cap (ms) |
| `SPLIT_RECONNECT_WINDOW_MS` | `30000` | cumulative reconnect-sleep bound per failure episode (ms); `0` disables |
| `SPLIT_RECONNECT_CLAMP_MS` | `2000` | per-attempt delay once the window is exhausted (ms); `0` disables |

These are read by `config.Load` into the new `Config` fields
`ReconnectBaseMs`, `ReconnectMaxMs`, `ReconnectWindowMs`, `ReconnectClampMs`
(validated to the bounds in the table below) and consumed by the
`reconnectBackoff()` helper added to each binary.

### Configuration file location

These variables are delivered through the **existing** `EnvironmentFile=`
entries in the systemd units — `/etc/split-tunnel/germany.env` (Germany
role) and `/etc/split-tunnel/iran.env` (Iran role). **No unit-file change is
required.** Add or edit the four `SPLIT_RECONNECT_*` lines in the relevant
role's env file and `systemctl restart <service>` to apply.

### Validation bounds

| Env var | default | min | max |
|---|---|---|---|
| `SPLIT_RECONNECT_BASE_MS` | `1000` | `100` | `60000` |
| `SPLIT_RECONNECT_MAX_MS` | `10000` | `100` | `300000` |
| `SPLIT_RECONNECT_WINDOW_MS` | `30000` | `0` | `600000` |
| `SPLIT_RECONNECT_CLAMP_MS` | `2000` | `0` | `300000` |

## Escape hatch

Setting `SPLIT_RECONNECT_WINDOW_MS=0` (or `SPLIT_RECONNECT_CLAMP_MS=0`)
disables the bounded window entirely and restores the pre-fix pure
exponential backoff schedule (`base, base*2, base*4, ...` capped at `max`).
Both knobs default to non-zero, so the bounded window is ON by default; an
operator who wants the old behavior (for example to diagnose a specific
carrier) can turn it back off without reverting the code.

## Confirming a reconnect storm on the host

An operator investigating a suspected outage or a prolonged carrier loss
can inspect the journal for the per-episode "window exhausted" marker and
the surrounding reconnect attempts:

```bash
journalctl -u germany-splitter.service -u iran-splitter.service --since "01:25" --until "01:35" --no-pager
```

Each reconnect loop logs `"reconnect window exhausted; probing every <clamp>"`
**once per failure episode** (tracked with a per-loop bool and cleared on a
successful carrier reset) — this is the visible symptom that the bound is
doing its job (steady clamp-cadence probing instead of a growing sleep) and
that a transient blip is not amplifying into a multi-minute outage. The
log is emitted on the failure path, not on every probe, so it does not
spam the journal.

## Test coverage

`internal/backoff/backoff_test.go` gains deterministic tests (no real
sleeping beyond the small-duration `Sleep` bounds check):

- `TestWindowClamp` — `NewBounded(1s, 10s, 30s, 2s)` yields `1,2,4,8,10,10`
  then `2,2,2,2` (the cumulative reaches 35 ≥ 30 at the 6th call).
- `TestNewBoundedDisabledIsPureExponential` — `window=0` or `clamp=0`
  reproduces the pure exponential schedule exactly (proves the pre-fix
  behavior is reachable).
- `TestNewDelegatesToNewBounded` — `New(2s, 60s)` is byte-identical to the
  pre-fix `2,4,8,16,32,60,60` schedule.
- `TestResetZeroesWindow` — `Reset()` zeroes both `attempts` and the
  cumulative window (`WindowExhausted()` is false after a reset).
- `TestWindowExhaustedFlips` — `WindowExhausted()` flips false → true at the
  right point and stays false when the bound is disabled.
- `TestClampCappedAtMax` — a clamp requested above `max` is capped at `max`
  (no delay ever exceeds the cap).
- `TestSleepBoundedByClampAfterWindow` — after the window is exhausted, each
  jittered `Sleep()` is bounded by the clamp (small durations with the same
  wall-clock tolerance convention as the existing `TestSleepJitterBounds`).

All pre-existing tests (`TestScheduleDoubling`, `TestReset`,
`TestSleepJitterBounds`, `TestSleepCancellation`,
`TestSleepRespectsCtxAlreadyDone`) pass unmodified.
