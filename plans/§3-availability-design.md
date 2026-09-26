# §3 Availability Follow-Up — Design (READ-ONLY)

Goal: stop the public-SOCKS path from clean-aborting nearly every large
transfer, WITHOUT reintroducing a silent byte-hole. Companion to the shipped
integrity fix (Mechanism B). No code modified, no deploy.

## 0. Load-bearing finding that corrects the earlier draft

The per-stream mailbox is a **dual bound** — ≤ `MaxFrames` items AND ≤
`MaxBytesPerStream` bytes, whichever is hit first ([`fullLocked`,
queue.go:140-143`](pkg/mux/queue.go:140-143)). `MaxFrames` is a **hard
library constant = 16** ([`carrier.go:401`](pkg/mux/carrier.go:401)) and the
env `SPLIT_STREAM_QUEUE_FRAMES` is capped at that same 16
([`config.go:260`](internal/config/config.go:260)). With `MaxPayload`
65535 ([`frame.go:21`](pkg/mux/frame.go:21)), 16 × 65535 ≈ 1 MiB — so the
**frame cap, not the byte cap, is the binding ceiling** on a single stream.

Consequence: raising `SPLIT_STREAM_QUEUE_BYTES` (MaxBytesPerStream) to 4 MiB
is **inert for a single >1 MiB object** — the mailbox still stops accepting
at 16 frames / ~1 MiB. A 1.24 MB object needs ≥20 frames and **cannot** be
held in one mailbox under any env setting. Therefore the >1 MiB object must
*stream through* the mailbox at the receiver's drain pace, and the
**load-bearing remediation is upstream backpressure** (the producer stops
reading its source socket while the far mailbox is near-full), NOT a config
knob. This flips the earlier ranking: backpressure is the fix; config is a
supporting window.

Direction anchor (public SOCKS, response body): target → DE down-relay
(`relayShapeA(sess, DirDown, targetConn)`, [`relays.go:46`](pkg/node/relays.go:46),
Germany target→down) → DE writes FrameData to the down-carrier → IR down-mux
`Dispatch` → IR per-stream mailbox ([`carrier.go:734`](pkg/mux/carrier.go:734))
→ IR `startStreamRelay` writes to `ClientConn`
([`relays.go:337`](pkg/node/relays.go:337)). The overflowing mailbox is on
IR; the overfeeding producer is DE's target-reading relay. That matches the
telemetry (drops on IR `mux_down_dropped_data_frames`, 0 on DE up).

---

## 1. Grace path — pass refusal M into the applyPressure deadline

### Where M is produced
`M` = a refused in-order DATA push. Produced at
[`deliver()`](pkg/mux/carrier.go:791) line 813: `if s.q.TryPush(it) {...}`;
today a DATA refusal falls to `c.failUndeliverableData(s)` (line 825), which
terminates *immediately*.

### Change 1a — route the DATA refusal through the SAME deadline the
refused FrameClose already uses
Replace the line 825 call with the pressure path used by the `isClose`
branch (lines 799-803):
- retain the refused item in a new per-stream field
  `s.pendingRetry queueItem` (one slot; see 1d);
- stamp `if s.pressureStart.IsZero() { s.pressureStart = time.Now() }`;
- call `c.applyPressure(s)`.
`pendingRetry` + `pressureStart` are dispatcher-owned, same owner as the
existing `pressureStart` ([`carrier.go:478-480`](pkg/mux/carrier.go:478-480))
— **no new mutex, no `c.mu` on the hot path**.

### 1b — contiguity: retry the oldest undelivered item before the new one
On each subsequent frame for stream S, before pushing the new item, attempt
`TryPush(s.pendingRetry)` first; on success clear it and reset
`pressureStart` (mirrors line 814). The mailbox is FIFO
([`queue.go:41-42`](pkg/mux/queue.go:41-42)) and the worker pops in order, so
the oldest undelivered item (pendingRetry) is exactly what the next Pop frees
a slot for. At most ONE `pendingRetry` per stream ⇒ no reordering, no hole.

### 1c — the ONE termination site (unchanged structure, extended)
Keep `applyPressure` ([`carrier.go:851-864`](pkg/mux/carrier.go:851-864)) as
the single dispatcher-side termination site:
```
if s.pressureStart.IsZero() { s.pressureStart = time.Now(); return }
if time.Since(s.pressureStart) >= c.limitsLocked().OverflowWait {
    stats.overflowTerminated(wait)
    if pendingRetry set { stats.droppedDataFrame(); s.pendingRetry = zero }
    c.terminateStream(s, true)   // consumer sees nil; peer signalled
    if hadPendingData && c.OnStreamDataUndeliverable != nil {
        c.OnStreamDataUndeliverable(s.id)   // => data_undeliverable bucket
    }
}
```
A full-pop refusal that persists past `OverflowWait` (a **sustained** stall,
the "fullPopFailure" case) is the *only* thing that terminates. A transient
fill that drains before the deadline never terminates: the producer paused
(§2), the mailbox drains, no new frame arrives to re-check the deadline, and
the next resumed frame succeeds and **resets `pressureStart`** (line 814).
`failUndeliverableData` ([`carrier.go:834`](pkg/mux/carrier.go:834)) becomes
dead and is removed in the same change.

### 1d — invariants preserved
| Invariant | Guarantee |
|---|---|
| No silent live-stall-with-hole | The refused item is RETAINED (pendingRetry) and retried in FIFO order; a live stream never carries a missing byte. Termination only on a *sustained* full-pop refusal, which delivers `nil` + signals the peer (clean abort, no half-alive stream). |
| Dispatcher-never-blocks | Every step is a non-blocking `TryPush` + O(1) time compare. No `time.After`, no channel receive, no `c.mu` held across the retry. `TestSlowStreamDoesNotBlockDispatcher` still passes. |
| Per-stream isolation | `pendingRetry`/`pressureStart` are per-stream, dispatcher-owned; processing stream N never touches stream M. |
| Every dropped DATA counted | `droppedDataFrame()` fires exactly once, at the escalation moment (the frame that was retained and could not be delivered). `OnStreamDataUndeliverable` fires the same moment ⇒ `session_close_reason{data_undeliverable}` stays correct. |
| Bounded, c.mu-free | At most one pendingRetry/stream; TryPush takes `q.mu` only, which is never held while `c.mu` is taken (see the SetQueueStats/SetBudgetLimit pattern, [`carrier.go:430-465`](pkg/mux/carrier.go:430-465)). Confirmed: dispatcher does NOT hold `c.mu` for the retry. |

Worker-side note (unchanged): a *full but quiescent* mailbox whose consumer
stops popping still self-terminates via `streamWorker`'s own `OverflowWait`
deadline ([`carrier.go:951-963`](pkg/mux/carrier.go:951-963)) — the second,
independent deadline. Both terminate the SAME stream only.

---

## 2. Load-bearing backpressure — the producer stops reading while the far
mailbox is near-full

### Why the existing `relay_buffer_full` stays ~0 (the DE up=0 asymmetry)
The only current backpressure on the target-reading relay is
`len(pending) >= capacity` (256 KiB, `SPLIT_SESSION_BUFFER_BYTES`)
([`relays.go:105-111`](pkg/node/relays.go:105-111)), and it only fires when
`flushPending`/`WriteFrame` actually blocks. The WS down-carrier transport
has its own buffering, so DE's 256 KiB pending rarely fills before the
carrier absorbs it — the bottleneck is IR's **16-frame mailbox**, which DE
cannot see. Hence `relay_buffer_full` (DE up) ≈ 0 while IR
`mux_down_dropped_data_frames` climbs: DE keeps reading the 1.24 MB into the
carrier at target pace; IR's mailbox overflows.

### Exact change (cross-node high-water, contiguity-safe)
Expose O(1) per-stream mailbox occupancy on the receiver's mux:
```
// StreamMailboxBytes(id) -> current payload bytes in that stream's mailbox.
// takes q.mu only (never c.mu). Safe for the relay to poll per loop.
func (c *CarrierConn) StreamMailboxBytes(id uint32) int64
```
(new `StreamQueue` accessor returning `nBytes` under `q.mu`,
[see TryPush accounting, queue.go:188-204](pkg/mux/queue.go:188-204)).

Propagate the high-water to the producer. DE's target-relay already knows
its own occupancy; it must additionally stop when the **down-carrier's
transport is full** — the cleanest in-band signal is that
`h.carrier.WriteFrame(...)` in `flushPending`
([`relays.go:195`](pkg/node/relays.go:195)) is *backing up*. Two options,
prefer the first (no new wire field):

1. **Transport backpressure (preferred, no protocol change):** lower the
   DE target-relay pending high-water so the relay stops reading the target
   once the down-carrier write path has stalled. Concretely, change the
   comparison at [`relays.go:105`](pkg/node/relays.go:105) to also trip when
   the last `flushPending` could not fully drain (WriteFrame blocked / the
   carrier's writeCh is saturated). Since `pending` is the lossless reconnect
   window and is bounded at 256 KiB, the relay parks in `waitAttach`
   ([`relays.go:109`](pkg/node/relays.go:109)) — which is exactly
   "stop reading the destination socket until the far mailbox drains."
   Add a distinct counter `RelayMailboxBackpressured` (new, alongside
   `RelayBufferFull`, [`metrics.go:337`](pkg/node/metrics.go:337)) so the
   new signal is observable and separable from the carrier-loss case.

2. **Explicit high-water frame (fallback):** if the WS transport swallows
   backpressure (large buffers) so the write path never blocks, add a
   control payload field (e.g. a `FramePulse` with the receiver's current
   per-stream occupancy) so DE can compare against
   `n.cfg.StreamLimits.MaxBytesPerStream` (or its 16-frame ceiling) and park
   the target relay. This is a wire change and is only warranted if
   option 1's telemetry (post-§5) shows `RelayMailboxBackpressured`
   staying ~0 while IR drops persist.

### Contiguity-safety / no-silent-drop proof
The relay stops **reading** the source; bytes already read are held FIFO in
`pending` and flushed in order (`flushPending`, [`relays.go:180`](pkg/node/relays.go:180));
the far mailbox is FIFO; the worker hands to the consumer in order. No
reordering, no dropped byte on a live stream. `relay_buffer_full` remains the
carrier-loss signal; `RelayMailboxBackpressured` is the new mailbox-full
signal — after the change, DE up will show the latter > 0 during large
transfers (the asymmetry is fixed: DE is now actually backpressured).

---

## 3. Config — evidence-driven, and what it can / cannot do

| Env (host) | Field | Default | Hard cap ([`config.go:99-101`](internal/config/config.go:99-101)) | Verdict |
|---|---|---|---|---|
| `SPLIT_STREAM_QUEUE_BYTES` | `MaxBytesPerStream` | 1 MiB | 64 MiB | **Inert for one >1 MiB stream** — the 16-frame cap binds at ~1 MiB. Do NOT rely on it to hold a whole object. Keep at 1 MiB unless aggregate math needs a bump. |
| `SPLIT_STREAM_QUEUE_FRAMES` | `MaxFramesPerStream` | 16 | **16 (hard, [`:260`](internal/config/config.go:260))** | Cannot be raised via env. This is *the* reason >1 MiB must stream through. |
| `SPLIT_STREAM_OVERFLOW_MS` | `OverflowWait` | 100 ms | 30000 ms | **The supporting knob.** Raise to a value that covers the worst observed mailbox-drain time of a 1.24 MB object at client pace. Evidence-based range for staging: **2000–5000 ms** (must exceed the time DE, paused, needs IR's mailbox to drain under a stalled client). |
| `SPLIT_STREAM_QUEUE_TOTAL_BYTES` | `MaxBytesTotal` | 32 MiB | 256 MiB | Keep ≥ one stream's share; at c=1 no change. At c=32 large, this is the aggregate that bounds concurrency (see §4c). |

Memory equation (per node): `inflight ≤ Min(numStreams·MaxBytesPerStream,
MaxBytesTotal)`. At c=32 with 1 MiB/stream the aggregate caps true
concurrency of *fully-buffered* streams at `32 MiB / 1 MiB = 32`, but the
**frame cap means a stream can never fully buffer 1.24 MB**, so the real
steady-state occupancy is the transient in-flight window, bounded by
`MaxBytesTotal` (32 MiB) — no OOM risk from the backpressure change because
the producer now stops reading.

**Stance: DEPLOY-CONFIG, not a runtime library default.** The library
defaults (16 / 1 MiB / 100 ms) stay safe for small-object deployments.
`SPLIT_STREAM_OVERFLOW_MS` is raised on the staging hosts as an
evidence-driven value chosen from the drain-time telemetry in the retest —
never a speculative number. No library change to `MaxFrames` is recommended
(backpressure already handles >1 MiB; a larger frame cap would only grow
per-stream memory and is not demanded by the evidence).

---

## 4. Interaction

### 4a. Serial c=1, 1.24 MB, no contending clients
- **Today:** mailbox hard-caps at 16 frames/1 MiB. DE reads the target at
  full pace; IR mailbox overflows; `failUndeliverableData` fires within
  `OverflowWait` (100 ms) → clean abort. **Fails** (the observed 12/12).
- **With backpressure + grace (§1+§2):** DE stops reading the target once the
  down-carrier/IR-mailbox back up. The object **streams through** the 16-frame
  mailbox at the client's drain pace. A transient fill is caught by the grace
  deadline, which is long enough (raised `OverflowWait`) that it never
  elapses before the mailbox drains. **Passes** — no intermediary buffering
  of the whole object; ≤ `OverflowWait` pause, mailbox rides it out.

### 4b. 1.21 MB at default 1 MiB
Still **fails** at the default frame cap (1.21 MB > 16×65535 ≈ 1 MiB) — but
only if DE keeps overfeeding. With backpressure, 1.21 MB also streams
through, so it *passes* provided `OverflowWait` covers the drain. The minimal
`OverflowWait` that makes serial 1.24 MB pass is: enough that the mailbox,
once DE pauses, drains to the client before the deadline elapses — i.e.
`OverflowWait > (inflight_bytes / client_drain_rate)`; at serial the inflight
is ≤ 1 MiB, so a few hundred ms already suffices; the 2000–5000 ms staging
band is a safe, evidence-anchored margin. **Minimal mailbox size = unchanged
(1 MiB); the lever is `OverflowWait` + backpressure, not mailbox bytes.**

### 4c. t32 large vs t32 small
- **Small** (object < 16 frames): fits the mailbox; rides out any pause of
  ≤ mailbox size; unaffected by the frame cap. Completes.
- **Large** (1.24 MB × 32 concurrent): each object streams through, but the
  32 MiB aggregate (`MaxBytesTotal`) bounds total in-flight bytes. The single
  down-carrier + client drain rate is the throughput ceiling; under
  worst-case contention more than `MaxBytesTotal / working_set` objects can't
  keep a full window simultaneously, so some will exceed `OverflowWait` and
  be cleanly terminated (grace path, no hole). This is the **worst-case
  partial-success** band; the t32 large threshold is set accordingly (§5).

---

## 5. Acceptance — 2nd staging retest

Gates (all must hold; `sessions_clean_complete` = transfer finished and
verified byte-exact):

- **PASS(a) corruption:** `mux_down_dropped_data_frames` implies zero
  mid-stream corruption — every completed transfer is a byte-exact prefix;
  **0** `bad-record-mac` (rc56). New `RelayMailboxBackpressured` > 0 on DE
  during large transfers (asymmetry fixed) and ≈ 0 on small transfers.
- **PASS(c) availability** per-tier fail-rate `1 − clean_complete/total`:
  | tier | metric expression | threshold |
  |---|---|---|
  | serial c=1 | `1 − S{c=1}/T{c=1}` | ≤ 0.024 (pre-fix 2/84) |
  | t8 | `1 − S{c=8}/T{c=8}` | ≤ 0.05 (0 preferred) |
  | t16 | `1 − S{c=16}/T{c=16}` | ≤ 0.05 |
  | t32 large-only | `1 − S{c=32,large}/T{c=32,large}` | ≤ 0.1875 |
- **Serial 1.24 MB delivery:** `S{c=1, bytes≥1240000} ≥ 1` (at least one
  ≥1.24 MB object completes at c=1).
- **Worst-case partial-success clause (t32 large):** if 32 concurrent
  1.24 MB objects exceed the 32 MiB aggregate *and* the single down-carrier
  drain rate, a bounded subset is cleanly aborted by the grace path
  (session_close_reason{data_undeliverable} > 0 allowed, corruption still 0).
  t32 large-only is PASS at **≤ 0.1875**; higher is FAIL.

---

## 6. Ranked order & the single most-likely fix for serial c=1

| # | Change | Effect on serial c=1 (>1 MiB) |
|---|---|---|
| **1 (load-bearing)** | **Backpressure: DE target-relay stops reading while the down-carrier/IR mailbox is backed up** ([`relays.go:105-111`](pkg/node/relays.go:105-111) + new `RelayMailboxBackpressured`) | Converts "read at target pace into a capped mailbox" into "stream at client pace". The only change that actually makes a >1 MiB object fit the 16-frame mailbox by never trying to hold it whole. |
| 2 (supporting) | Grace: route DATA refusal into `applyPressure` + `pendingRetry`, single termination site ([`carrier.go:791/825/851`](pkg/mux/carrier.go:791)) | Turns a transient fill from an immediate abort into a bounded, self-healing pause; preserves every invariant. Necessary for safety, not sufficient alone. |
| 3 (knot to size #2) | `SPLIT_STREAM_OVERFLOW_MS` raised to 2000–5000 ms on staging | Gives the mailbox drain time; without it the grace deadline elapses too early and still aborts. Config-only, evidence-driven. |

**Single most-likely-to-satisfy serial c=1 given the causal evidence: the
backpressure change** (producer stops reading while the far mailbox is
backed up). The grace+config make that backpressure *safe* and *timed*, but
backpressure is what makes the >1 MiB object physically deliverable through
the hard 16-frame mailbox. Config alone cannot do it (the frame cap is
fixed); grace alone only delays the abort.
