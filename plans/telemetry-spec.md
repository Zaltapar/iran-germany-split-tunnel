# Telemetry specification: image-transfer failure attribution (queue pressure vs. public client leg)

**Status:** specification only. No source file is modified by this document.
**Scope:** add fixed-cardinality, non-secret telemetry that answers one question with data —
when an image transfer fails mid-body through the public tunnel, is the cause the splitter's
internal stream/carrier queue pressure (overflow termination, bounded mailbox exhaustion,
carrier write failure, relay buffering), or something on the public client leg (packet loss,
MTU, external close)?

**Evidence context (given, do not re-derive):** 837 fixed-URL attempts / 3 reps / interleaved
arms; public arm failed 146/207 vs loopback 38/207 vs direct 0/207; all failures were
post-first-byte; journal showed zero carrier loss / rebind / target-dial failure / deadline /
resource / generic error; loopback also degraded at concurrency 32; no nftables/limiter
evidence; metrics endpoint unreachable on production hosts (`SPLIT_METRICS_PORT` unset).

---

## 0. Design constraints (binding)

1. **No behaviour change.** The instrumentation observes; it must not alter queue semantics,
   backpressure ordering, termination policy, or timing. Every counter update is a plain
   atomic RMW added to a path that already executes. No new mutex is introduced on any hot
   path (see §2 for the high-water-mark design, which deliberately uses atomic-max rather
   than sampling under a lock).
2. **Fixed cardinality only.** No per-session labels, no session IDs, no UUIDs, no IPs, no
   ports, no hostnames, no URLs, no credentials, no error strings from the network stack.
   Every metric is either a monotonic counter or a gauge with a single, compile-time-known
   key set (§9).
3. **No new Go dependencies.** Counters are `sync/atomic` on `int64`; rendering is the
   existing hand-rolled text format in [`pkg/node/metrics.go`](pkg/node/metrics.go:194).
4. **Loopback-only metrics, permanently.** The listener address is computed from a single
   constant and can never be widened by configuration (§3).
5. **Permanent, low-overhead improvement.** The instrumentation is not removed after the
   matrix run; the deployment path only toggles whether the loopback endpoint is bound (§8).

---

## 1. Data model: three instrumentation surfaces

| Surface | File (new) | Owner | Lifetime |
|---|---|---|---|
| `mux.QueueStats` | `pkg/mux/qstats.go` | carrier-wide (one per `CarrierConn`) | carrier lifetime; exported through a stats accessor |
| `node.Metrics` (existing) | `pkg/node/metrics.go` | node-wide | process lifetime |
| `node.StreamStats` | `pkg/node/streamstats.go` | per-shape-A-relay aggregate (node) | node lifetime |

A `*mux.QueueStats` pointer lives on the node (`Node.stats`), is created in `NewNode`, and is
handed to every carrier created in `Node.install` — see §2. That gives one per-carrier
high-water set for up and down without any node-level lock contention.

### 1.1 `mux.QueueStats` — the queue-pressure surface

All fields are `int64`, all updates are `atomic.AddInt64` / the atomic-max primitive of §2.2.

```
// pkg/mux/qstats.go (new)

type QueueStats struct {
    // --- mailbox accounting (per push attempt) ---
    PushAccepted       int64 // TryPush returned true
    PushRejectedStream int64 // TryPush false: per-stream bounds (frames or bytes)
    PushRejectedTotal  int64 // TryPush false: carrier aggregate byte budget
    PushRejectedClosed int64 // TryPush false: mailbox closed (stream/carrier ending)

    // --- per-stream mailbox high-water marks (the single worst mailbox) ---
    StreamQueuedBytesHigh  int64 // max over all mailboxes of nBytes
    StreamQueuedFramesHigh int64 // max over all mailboxes of len(items)

    // --- carrier aggregate (the queuedBytes mirror) ---
    QueuedBytesNow  int64 // gauge: current aggregate payload bytes
    QueuedFramesNow int64 // gauge: current aggregate item count
    QueuedBytesHigh int64 // high-water mark of the aggregate bytes
    QueuedFramesHigh int64 // high-water mark of the aggregate items

    // --- overflow termination ---
    OverflowTerminations       int64 // terminateStream called from applyPressure
    OverflowTerminationsWorker int64 // terminateStream called from streamWorker

    // --- overflow wait timing (applyPressure pressureStart -> termination) ---
    OverflowWaitSumNanos int64
    OverflowWaitCount    int64
    OverflowWaitMaxNanos int64

    // --- carrier write/read failures ---
    WriteFailures   int64
    ReadFailures    int64
    ReadEOF         int64
    BlackholeDeaths int64
}

// Methods, all nil-safe and atomic-only (see 2.3):
//
//	push(n int)                  PushAccepted++, fold aggregate high-water
//	reject(reason rejectReason)  one of the four PushRejected* counters
//	observeStream(nBytes, nItems) atomic-max into StreamQueued*High
//	observeQueued(bytes, nItems)  atomic-max into Queued*High (called from
//	                             queue.go where queuedBytes/queuedItems change)
//	discard(nBytes, nItems)       fold pre-Close occupancy, then the close
//	overflowTerminated(d)        OverflowTerminations++, wait sum/count/max
//	overflowTerminatedWorker()   OverflowTerminationsWorker++
//	writeFailure()               WriteFailures++
//	readFailure(isEOF bool)      ReadEOF++ or ReadFailures++
//	blackholeDeath()             BlackholeDeaths++
//	render(prefix string)        the /metrics lines for one direction,
//	                             including the two float-second renderings
```

Metric names rendered at `/metrics` (exact, snake_case, prefixed with the direction label
`mux_up_` / `mux_down_`):

| Metric | Type | Meaning |
|---|---|---|
| `mux_<dir>_push_accepted` | counter | accepted mailbox items |
| `mux_<dir>_push_rejected_stream` | counter | refused: stream frames/bytes bound |
| `mux_<dir>_push_rejected_total` | counter | refused: 32 MiB aggregate budget |
| `mux_<dir>_push_rejected_closed` | counter | refused: mailbox closed |
| `mux_<dir>_overflow_terminations` | counter | stream killed by dispatcher pressure |
| `mux_<dir>_overflow_terminations_worker` | counter | stream killed by its own slow consumer |
| `mux_<dir>_overflow_wait_count` | counter | overflow waits observed |
| `mux_<dir>_overflow_wait_sum_seconds` / `_max_seconds` | sum / max | wait duration, rendered as float seconds |
| `mux_<dir>_queued_bytes_high` | gauge | high-water mark of aggregate queued payload bytes |
| `mux_<dir>_queued_frames_high` | gauge | high-water mark of aggregate queued items |
| `mux_<dir>_stream_queued_bytes_high` | gauge | high-water mark of a single mailbox's bytes |
| `mux_<dir>_stream_queued_frames_high` | gauge | high-water mark of a single mailbox's items |
| `mux_<dir>_carrier_write_failures` | counter | `rwc.Write` returned an error in `writeLoop` |
| `mux_<dir>_carrier_read_failures` | counter | `ReadFrame` returned an error in `readLoop` (non-EOF) |
| `mux_<dir>_carrier_read_eof` | counter | `ReadFrame` returned `io.EOF` |
| `mux_<dir>_blackhole_deaths` | counter | liveness loop closed the carrier |

> The direction suffix comes from the *carrier direction on the reporting node*, not from the
> frame's stream ID. Nothing per-stream is exported.

`StreamQueue` and `CarrierConn` already keep the exact state the high-water marks need:
`q.items` / `q.nBytes` are only read/written under `q.mu`, and `c.queuedBytes` is the
authoritative aggregate. §2.2 makes those observable without touching the lock ordering.

### 1.2 `node.Metrics` additions — session lifecycle + relay surface

New methods on the existing `Metrics` type (`pkg/node/metrics.go`), following the existing
mutex-protected counter style. All new fields are cumulative counters.

```
// pkg/node/metrics.go (extend the struct at :12)
sessionFirstByteSeen   int64   // sessions that delivered >=1 payload byte to the peer
sessionClosedPreFirst  int64   // sessions that closed before any byte flowed
sessionMidTransfer     int64   // >=1 byte transferred, then closed before clean completion
sessionCleanComplete   int64   // both directions half-closed with no error/overflow/carrier/timeout close
targetDialOK           int64
targetDialFail         int64
relayBytesRead         int64   // shape-A socket Read bytes (up on Iran, down on Germany)
relayBytesWritten      int64   // shape-A bytes written to the carrier
relayPendingHigh       int64   // high-water mark of the shape-A pending buffer length
relayBufferHighBytes   int64   // high-water mark of the node aggregate budget (session_buffered_bytes)
relayWriteFail         int64   // shape-A flushPending hits an unavailable carrier
relayBufferFull        int64   // shape-A backpressure: socket read stopped, pending buffer full
relaySocketReadErr     int64   // shape-A non-EOF socket read error
relaySocketWriteErr    int64   // shape-B socket write error
closeReasonClientEOF   int64
closeReasonTargetEOF   int64
closeReasonCarrier     int64
closeReasonOverflow    int64
closeReasonTimeout     int64
closeReasonOther       int64
```

Exact metric names (rendered in [`Metrics.Render`](pkg/node/metrics.go:195)):

```
sessions_first_byte_seen
sessions_closed_before_first_byte
sessions_mid_transfer
sessions_clean_complete
target_dial_success
target_dial_failure
relay_bytes_read
relay_bytes_written
relay_pending_high_bytes
relay_buffer_high_bytes
relay_write_failures
relay_buffer_full
relay_socket_read_errors
relay_socket_write_errors
session_close_reason{reason="client_eof|target_eof|carrier|overflow|timeout|other"}
```

`session_close_reason` is a **fixed six-value label set** — the only label in the whole
surface, its values are compile-time constants of a private type, and no caller can supply a
string (§4).

**Exact render order.** [`Metrics.Render`](pkg/node/metrics.go:195) appends the new lines
after the existing Issue #6 block (`session_buffer_reclaimed`, `:213`), in this order, then
the two directives' lines. The two binaries' handlers
([`cmd/iran-splitter/main.go:507`](cmd/iran-splitter/main.go:507),
[`cmd/germany-splitter/main.go:421`](cmd/germany-splitter/main.go:421)) additionally print
the direction-prefixed `mux_*` lines from each carrier's `QueueStats.render("mux_up_")` /
``mux_down_")`, after `session_buffered_bytes`. Deltas are computed by the operator from two
scrapes; nothing is rendered as a rate or a delta.

```
sessions_first_byte_seen <int>
sessions_closed_before_first_byte <int>
sessions_mid_transfer <int>
sessions_clean_complete <int>
target_dial_success <int>
target_dial_failure <int>
relay_bytes_read <int>
relay_bytes_written <int>
relay_pending_high_bytes <int>
relay_buffer_high_bytes <int>
relay_write_failures <int>
relay_buffer_full <int>
relay_socket_read_errors <int>
relay_socket_write_errors <int>
session_close_reason{reason="client_eof"} <int>
session_close_reason{reason="target_eof"} <int>
session_close_reason{reason="carrier"} <int>
session_close_reason{reason="overflow"} <int>
session_close_reason{reason="timeout"} <int>
session_close_reason{reason="other"} <int>
mux_up_push_accepted <int>
mux_up_push_rejected_stream <int>
mux_up_push_rejected_total <int>
mux_up_push_rejected_closed <int>
mux_up_stream_queued_bytes_high <int>
mux_up_stream_queued_frames_high <int>
mux_up_queued_bytes <int>
mux_up_queued_frames <int>
mux_up_queued_bytes_high <int>
mux_up_queued_frames_high <int>
mux_up_overflow_terminations <int>
mux_up_overflow_terminations_worker <int>
mux_up_overflow_wait_count <int>
mux_up_overflow_wait_sum_seconds <float>
mux_up_overflow_wait_max_seconds <float>
mux_up_carrier_write_failures <int>
mux_up_carrier_read_failures <int>
mux_up_carrier_read_eof <int>
mux_up_blackhole_deaths <int>
... the identical 20 lines with mux_down_ ...
```

`mux_<dir>_queued_bytes` / `mux_<dir>_queued_frames` are the *current* gauges (the `Now`
fields); they are the only gauges besides the two `_high` marks and the existing
`session_count` / `session_buffered_bytes`. The float lines render with `%.6f`, which is why
the privacy regex in §6.2 permits a decimal fraction.

### 1.3 Node-level gauges already present

`session_buffered_bytes` (aggregate usage, [`cmd/iran-splitter/main.go`](cmd/iran-splitter/main.go:512))
and `session_count` (`:509`) stay. Add the high-water companion `relay_buffer_high_bytes`.

---

## 2. Where to instrument (exact locations, minimal diff)

Every hunk below is additive: a counter increment, an atomic-max, or a method call on a new
struct. No control flow changes, no lock changes, no new lock ordering.

### 2.1 `pkg/mux/queue.go`

| # | Location | Change |
|---|---|---|
| Q1 | struct `StreamQueue` (`:36`) | add `stats *QueueStats` field (nil-safe: a nil `*QueueStats` makes every helper a no-op — see §2.3) |
| Q2 | `NewStreamQueue` (`:74`) | unchanged signature; add the `*QueueStats` argument **or** set it via a `SetStats` call. **Recommended:** keep the constructor and add `func (q *StreamQueue) SetStats(s *QueueStats)` called from `createStreamLocked` — this avoids touching the ~15 existing test call sites of `NewStreamQueue` (e.g. [`pkg/mux/queue_test.go`](pkg/mux/queue_test.go:11), [`pkg/mux/backpressure_test.go`](pkg/mux/backpressure_test.go:157)) |
| Q3 | `TryPush` (`:112`) | on the rejection branch, `q.stats.reject(reason)`; on the accept branch, `q.stats.push(len(it.payload))`. Both calls happen **inside the existing `q.mu` critical section** — they are two `atomic.AddInt64` on distinct cache lines and are cheaper than the `q.items = append(...)` already performed there |
| Q4 | `Pop` (`:139`) | after the `q.items = q.items[1:]` update, `q.stats.pop(len(it.payload))` (feeds the frame/byte high-water sampling of §2.2) |
| Q5 | `Close` (`:175`) | after `discarded := q.nBytes`, `q.stats.discard(discarded, len(q.items))` |

Rejection reason classification for Q3 — a single helper so the branch logic is obvious and
the three outcomes are mutually exclusive:

```go
func (q *StreamQueue) rejectReasonLocked(it queueItem) rejectReason {
    switch {
    case q.closed:
        return rejectClosed
    case len(q.items) >= q.maxFrames:
        return rejectStreamFrames
    case q.nBytes+len(it.payload) > q.maxBytes:
        return rejectStreamBytes
    default:
        return rejectAggregate
    }
}
```

This is called unconditionally in the `if` of [`TryPush`](pkg/mux/queue.go:115) — it is pure
integer arithmetic on already-loaded fields, no allocation, no I/O, and it is exactly the
same predicate set `fullLocked` already evaluates, so the added cost is a few ns.

### 2.2 High-water marks without hot-path locking

**Decision: atomic-max, not a sampling goroutine, not a new mutex.**

The reason is the existing lock discipline. `q.nBytes` and `len(q.items)` are only mutated
under `q.mu`, and the reason they are *inside* the lock is documented at [`pkg/mux/queue.go`](pkg/mux/queue.go:49):
a race-free check-then-add against the carrier-wide budget is impossible with an atomic
counter outside the lock. Any design that samples mailbox occupancy from a second goroutine
would have to take `q.mu` (adding lock traffic to the hot path) or would be able to read a
torn combination (nBytes from one instant, len(items) from another), producing high-water
marks that are not a snapshot of any real state — useless for an attribution decision.

Instead, the occupancy that is *already* computed under the lock is folded into a lock-free
high-water with a compare-and-swap loop. This is the standard atomic-max primitive; it costs
one `atomic.LoadInt64` on the common (non-record) path and a bounded CAS loop that only runs
when a new maximum is actually set:

```go
// pkg/mux/qstats.go
func (s *QueueStats) observeHighStream(nBytes, nItems int64) {
    if s == nil { return }
    for {
        old := atomic.LoadInt64(&s.streamQueuedBytesHigh)
        if nBytes <= old || atomic.CompareAndSwapInt64(&s.streamQueuedBytesHigh, old, nBytes) {
            break
        }
    }
    for {
        old := atomic.LoadInt64(&s.streamQueuedFramesHigh)
        if nItems <= old || atomic.CompareAndSwapInt64(&s.streamQueuedFramesHigh, old, nItems) {
            break
        }
    }
}
```

Exact fold sites — these four, and only these four:

- **TryPush** ([`pkg/mux/queue.go:122-126`](pkg/mux/queue.go:122)): after
  `q.items = append(...)` and `q.nBytes += ...` have executed, fold
  `(int64(q.nBytes), int64(len(q.items)))`. The post-push occupancy is the value that may be
  a new maximum.
- **Pop** ([`pkg/mux/queue.go:143-149`](pkg/mux/queue.go:143)): capture
  `hb, hf := int64(q.nBytes), int64(len(q.items))` **before** the removal at `:144`, and fold
  those after the arithmetic. Folding the pre-pop occupancy is redundant (the push that
  created it already folded it) but makes the invariant — "the mark is the maximum over all
  occupancies ever observed under `q.mu`" — hold without depending on that reasoning, at the
  cost of one atomic load. It must never fold the post-pop value, which is by construction
  smaller and therefore never a new maximum.
- **Carrier aggregate bytes:** `c.queuedBytes` is a plain `int64` mutated with `atomic.AddInt64`
  from inside `q.mu` (see [`pkg/mux/queue.go`](pkg/mux/queue.go:124)). Fold the post-update
  value into `queuedBytesHigh` at the same two points, using the value returned by the
  `atomic.AddInt64` itself (the return value is the post-add total, so no extra load):

```go
tot := atomic.AddInt64(q.budget, int64(len(it.payload)))   // existing line :125
atomic.AddInt64(&s.pushAccepted, 1)
s.observeHighQueued(tot)                                    // fold the returned total
```

  The frames aggregate is the sum of mailbox item counts; it is folded at the same points
  by having `StreamQueue` publish `len(q.items)` deltas to a carrier-owned counter
  `queuedItems int64` (new field on `CarrierConn`, `atomic.AddInt64` on `±1` per
  push/pop/close, under `q.mu`), then `observeHighFrames(atomic.LoadInt64(&c.queuedItems))`
  after those adds. This keeps the aggregate frame high-water as cheap as the byte one.

**Lock-order verification:** all new code runs either (a) under `q.mu` and touches only
`*QueueStats` atomics, or (b) under `c.mu` and touches only `*QueueStats` atomics. Nothing
new ever takes `c.mu` while holding `q.mu`, or `q.mu` while holding `c.mu`. The invariant
that keeps [`SetStreamLimits`](pkg/mux/carrier.go:395) correct — `SetBudgetLimit` takes each
mailbox's own lock and never `c.mu` — is untouched.

### 2.3 Nil-safety

`QueueStats` methods are all defined on the pointer receiver with an `if s == nil { return }`
guard, so the ~15 existing test sites that construct `StreamQueue` without stats keep
compiling and keep asserting the same behaviour. There is exactly one cost: one
well-predicted nil branch per hot-path call.

### 2.4 `pkg/mux/carrier.go`

| # | Location | Change |
|---|---|---|
| C1 | struct `CarrierConn` (`:52`) | add `stats *QueueStats` and `queuedItems int64` |
| C2 | `newCarrierConn` (`:152`) | no change to the constructor signature. The node sets `c.SetQueueStats(n.muxStats(dir))` right after construction in `install` (mirrors the existing `c.SetStreamLimits` / `c.SetLivenessRounds` calls at [`pkg/node/node.go`](pkg/node/node.go:448)). Add `func (c *CarrierConn) SetQueueStats(s *QueueStats)` which takes `c.mu`, assigns the pointer to every mailbox in `allStreams` via `q.SetStats`, and stores `c.stats`. Called before `Dispatch` starts (`install`'s goroutine at `:540`), so there is no window in which a mailbox is created without stats |
| C3 | `createStreamLocked` (`:431`) | pass `c.stats` into the new `StreamQueue` (`NewStreamQueue(...)` gains a variadic trailing `stats ...*QueueStats`, or is followed by `q.SetStats(c.stats)` — prefer the explicit call to keep the constructor diff minimal) |
| C4 | `readLoop` (`:204`) | in the `err != nil` branch at `:211`, classify `errors.Is(err, io.EOF)` and increment `carrier_read_eof` / `carrier_read_failures` before `return`. The `readErr` value itself is **not** copied into any metric |
| C5 | `writeLoop` (`:246`) | at `:253` after `_, err := c.rwc.Write(req.data)`, `if err != nil { c.stats.writeFailure() }` before the existing close-race check |
| C6 | `liveness` (`:546`) | at the `dead` branch `:569`, increment `blackhole_deaths` before `c.Close()` |
| C7 | `deliver` (`:727`) | no change (the accounting lives in `TryPush`) |
| C8 | `applyPressure` (`:757`) | at the termination decision `:762`, record the wait duration and the termination reason: `d := time.Since(s.pressureStart)` … `c.terminateStream(s, true)` becomes `c.stats.overflowTerminated(d)` **plus** the existing call. Note: `applyPressure` dispatcher-only, so `pressureStart` needs no synchronization change |
| C9 | `streamWorker` (`:819`) | at the `time.After` branch `:846` (consumer stopped reading), `c.stats.overflowTerminatedWorker()` before `c.terminateStream(s, false)`; and at `:835` (FrameClose handoff timed out) likewise |

**Overflow-wait histogram vs sum/count/max:** implement **sum + count + max** only. The
decision variable is "how close is the pressure duration to `OverflowWait`", and
max/count/avg answers that exactly; a bucket histogram would need a configurable bucket set
and adds ambiguity about bucket boundaries (see §6, decision rule R2).

### 2.5 `pkg/node/relays.go`

| # | Location | Change |
|---|---|---|
| A1 | `relayShapeA` (`:46`) | after `nread, rerr := sock.Read(buf)` and `nread > 0` (`:113`), add `n.metrics.AddRelayBytesRead(int64(nread))` and, guarded by the first-byte CAS of §2.6, credit `sessions_first_byte_seen` once. Records "the socket leg is producing data" on both nodes |
| A2 | `relayShapeA` (`:112`) | in the `rerr != nil` / non-EOF branch (`:141`), `n.metrics.RelaySocketReadError()` before `sess.Close(sockReadErr(dir))` |
| A3 | `relayShapeA` | after `pending = append(pending, buf[:nread]...)` (`:136`), fold `len(pending)` into `relay_pending_high_bytes` via the atomic-max of §2.2 (the relay is the single owner of `pending`, so no lock is needed) |
| A4 | `flushPending` (`:173`) | after a successful `WriteFrame` (`:188`), `n.metrics.AddRelayBytesWritten(int64(len(chunk)))`. In the failure branch, `n.metrics.RelayWriteFailure()` before `return false` (`:194`) |
| A5 | `relayShapeA` (`:105-110`) | at the `len(pending) >= capacity` backpressure branch, `n.metrics.RelayBufferFull()` — the count of times a relay had to stop reading its socket because the bounded reconnect buffer was full. This is the direct signal for "relay buffering" as a cause |
| A6 | `startStreamRelay` (`:328`) | in the socket-write failure branch (`:368`), `n.metrics.RelaySocketWriteError()` before `sess.Close(sockWriteErr(dir))` |
| A7 | `sessionBufferBudget` (`pkg/node/budget.go`) | after each admitted charge in `chargeWait` (`:155`) and each refund, fold `b.accounted` into `relay_buffer_high_bytes` (value read under `b.mu` — the load is already serialized there, so this is a read plus an atomic-max, no new lock) |

### 2.6 `pkg/node/node.go`

| # | Location | Change |
|---|---|---|
| N1 | `NewNode` (`:243`) | create the two per-direction `*mux.QueueStats` and store them on the node |
| N2 | `install` (`:434`) | after `c := mux.NewCarrierConn…` and before `go func(){ c.Dispatch() … }()` at `:540`, call `c.SetQueueStats(n.muxStats(dir))` — after `SetStreamLimits` (`:448`), before `Dispatch`, matching the existing comment at `:526` about ordering |
| N3 | `onSessionClosed` (`:926`) | the single session-teardown choke point (registered as the `OnClose` hook by both `StartSession` at `:864` and `bootstrapUpStream` at `:1083`). After `n.store.Remove`, classify and count the close reason (§4), the first-byte class (§5) and the clean-completion class. This is the ONLY place session counters are incremented, so no double counting is possible |
| N4 | `bootstrapUpStream` (`:1032`) | around the `TargetDial` call at `:1053`, increment `target_dial_success` / `target_dial_failure`. The destination address is **not** passed to the counter — only the boolean outcome |
| N5 | `onGraceTimeout` (`:407`) | already calls `SessionLostAfterFailure` (`:414`); the reason string already encodes the timeout (`carrierTimeoutReason`, `:1148`), so §4's classification picks it up at `onSessionClosed` |
| N6 | `SessionBufferAccounted` (`:310`) | unchanged; the high-water is folded at A7 |

**First-byte observation.** "First byte reached" must mean the same thing on both roles, and
it must not be satisfiable by the protocol's own control frames. The frame header
(`FrameHeader`, `pkg/mux/frame.go` `0x05`) is not payload — an image transfer can fail after
the header and before the first body byte, which is exactly the failure under investigation.
The only payload-byte ingestion points per role are:

* **Iran** — `relayShapeA(sess, session.DirUp, clientConn)` at [`relays.go:113`](pkg/node/relays.go:113):
  the first `nread > 0` from the client socket is the first upload payload byte.
* **Germany** — `relayShapeA(sess, session.DirDown, targetConn)` at [`relays.go:113`](pkg/node/relays.go:113):
  the first `nread > 0` from the target socket is the first download payload byte.

So the flag is set at the A1 site in both cases (same line, both roles), and nowhere else.
Notably it is **not** set on a successful carrier write: a download-only image (client sends
its request, the target streams the body) writes nothing on Iran's shape A until the client's
request has gone, which would make "first byte" depend on the request direction rather than
on the transfer actually starting. Setting it on socket ingestion is the symmetric,
direction-independent definition.

Implementation: an `atomic.Bool` per session (`SessionStats.FirstByte`), transitioned
false→true by a CAS at the A1 site, and read once at `onSessionClosed` to choose between the
`sessions_closed_before_first_byte` and the
`sessions_first_byte_seen`/`sessions_mid_transfer` counters. Because the CAS decides which
counter is credited and it happens before teardown can complete, no separate
"counter credited" flag is needed: `onSessionClosed` is the only reader and it runs after
every relay has stopped. Store the flag on a new `SessionStats` struct embedded in `Session`
(`pkg/session/session.go`, alongside `StreamIDUp` at `:308`) — three `atomic.Bool` fields, no
synchronization event added to the existing `mu`-guarded state machine.

**Session close accounting.** `onSessionClosed` runs exactly once per session (it is an
`OnClose` hook, and `Session.teardown` runs hooks under `s.once`). The sessions in question
are the node-side sessions (`StartSession` on Iran, `bootstrapUpStream` on Germany); a
session that never reached `Activate` still runs the hook, so **every** session created is
counted, including setup failures. That is the desired denominator.

**Session close accounting.** `onSessionClosed` runs exactly once per session (it is an
`OnClose` hook, and `Session.teardown` runs hooks under `s.once`). The sessions in question
are the node-side sessions (`StartSession` on Iran, `bootstrapUpStream` on Germany); a
session that never reached `Activate` still runs the hook, so **every** session created is
counted, including setup failures. That is the desired denominator.

---

## 3. Metrics exposure

### 3.1 Current state

`runMetrics` binds `fmt.Sprintf("127.0.0.1:%d", cfg.MetricsPort)` when
`cfg.MetricsPort > 0` — [`cmd/iran-splitter/main.go:169-172`](cmd/iran-splitter/main.go:169),
[`cmd/germany-splitter/main.go:174-177`](cmd/germany-splitter/main.go:174). `MetricsPort`
defaults to 0 = disabled ([`internal/config/config.go:257`](internal/config/config.go:257)),
and the collision check at [`config.go:349-356`](internal/config/config.go:349) already
rejects a metrics port that would collide with any role-owned listener.

**The listener address is already loopback-only by construction and there is no way to
widen it.** The `addr` string is built from a literal `"127.0.0.1:"` prefix plus an integer
port; `MetricsPort` is an `int` (`:173`), never a host:port string. `SPLIT_METRICS_PORT=0.0.0.0`
is a parse error (`envInt`) and `SPLIT_METRICS_PORT=70000` is out of range (both asserted in
[`internal/config/config_test.go:534-535`](internal/config/config_test.go:534)).

### 3.2 Recommendation

**Keep the endpoint opt-in, do NOT default it on, and make the loopback guarantee
structural and explicit in code.** Rationale:

1. The Iran host runs a **public** SOCKS listener (and is the host whose public leg is the
   one under investigation). An authenticated-metrics endpoint that is reachable from the
   internet converts a diagnostic feature into an information-disclosure and
   resource-exhaustion surface. Even a body of counters with no labels leaks: session
   counts, throughput rates, carrier-loss history, and whether the host is under pressure.
2. There is already a precedent incident in this project where a managed-environment rewrite
   dropped keys and changed bind behaviour
   ([`IMPLEMENTATION_STATUS.md:201-202`](IMPLEMENTATION_STATUS.md:201)). Any mechanism that
   lets configuration choose an address is a future instance of that failure. The address
   must not be a configurable string at all.
3. The existing opt-in is already sufficient and safe: enabling it is a single
   `SPLIT_METRICS_PORT` value. Nothing needs to change about *whether* it can be enabled.

### 3.3 Required hardening (small, permanent)

1. **Replace the `Sprintf` with a named constant and a single constructor** in both binaries:
   `const metricsListenHost = "127.0.0.1"` and
   `func metricsListenAddr(port int) string { return net.JoinHostPort(metricsListenHost, strconv.Itoa(port)) }`.
   The two call sites then read `go func(){ … s.runMetrics(metricsListenAddr(cfg.MetricsPort)) }()`.
   Add a unit test per binary asserting `metricsListenAddr(1)` has prefix `127.0.0.1:` (the
   port is irrelevant) — this pins the "never public" property in the same way
   [`internal/config/config_test.go`](internal/config/config_test.go:212) pins the collision rule.
2. **After the listener is created, assert the resolved address is loopback** and refuse to
   serve otherwise. `ln.Addr().(*net.TCPAddr).IP.IsLoopback()` — if false, `ln.Close()` and
   return an error. This is a belt-and-braces check that survives a future refactor that
   changes how `addr` is built; it is a one-time cost at startup and cannot be bypassed by
   configuration.
3. **Keep `SPLIT_METRICS_PORT` in the optional env keys** ([`internal/systemd/envfile.go:48`](internal/systemd/envfile.go:48))
   — no change. It is already projected only when set.
4. **Do not add authentication.** Loopback-only + no auth is the right pair here: an
   authenticated loopback endpoint adds a credential without adding an exposure reduction.
   Document this explicitly next to the handler.

---

## 4. Close-reason classification

### 4.1 The ambiguity to remove

`dirEOFReason` ([`pkg/node/relays.go:267`](pkg/node/relays.go:267)) returns the string
`"target EOF"` for `DirDown` and it is used both when the target half-closed cleanly (a
completed transfer) and when the target socket read failed or a `FrameClose` arrived from a
peer whose stream was overflow-terminated. `peerEOF` stamps `s.reason` via `MarkDirClosed`
(`:261`), and `MarkDirClosed` only sets `reason` if it is still empty
([`pkg/session/session.go:456`](pkg/session/session.go:456)), so the *first* reason wins and
later, more specific reasons are silently discarded. A metrics consumer reading the journal
cannot tell clean completion from failure.

### 4.2 Classification rule (exact, order-dependent)

Add `func closeReasonClass(s *session.Session) CloseReason` in `pkg/node/metrics.go`. It runs
inside `onSessionClosed` (N3), at which point `s.reason`, `s.State()` and `s.DirClosed(up/down)`
are all final and stable (teardown has completed; `State() == StateClosed`).

The classification uses **only** the already-recorded reason string and two booleans. No
error value, no byte content, no peer-provided value is consulted:

```go
type CloseReason uint8

const (
    ReasonOther CloseReason = iota
    ReasonClientEOF
    ReasonTargetEOF
    ReasonCarrier
    ReasonOverflow
    ReasonTimeout
)

var closeReasonNames = [...]string{
    ReasonOther: "other", ReasonClientEOF: "client_eof", ReasonTargetEOF: "target_eof",
    ReasonCarrier: "carrier", ReasonOverflow: "overflow", ReasonTimeout: "timeout",
}
```

`Close(reason string)` is a **private** method on `Metrics`
(`func (m *Metrics) SessionClosed(r CloseReason)`); the exported API never accepts a string,
so no call site can invent a seventh class.

Mapping (first match wins; all patterns are `strings.Contains` on `s.Reason()`, which is a
fixed, code-owned string set — verified against every `Close(...)` / `MarkDirClosed(...)`
call site in `pkg/node` and `pkg/session`):

| Class | Matched reason substrings | Call sites that produce them |
|---|---|---|
| `overflow` | `overflow` | *new*: `terminateStream` path — see §4.3 |
| `timeout` | `timeout`, `did not finish` | [`node.go:1147` `carrierTimeoutReason`](pkg/node/node.go:1147), [`node.go:1121` `target did not finish after client EOF`](pkg/node/node.go:1121) |
| `carrier` | `carrier`, `reattach`, `grace`, `stream registration failed`, `up-carrier header write failed` | [`node.go:873`](pkg/node/node.go:873), [`node.go:891`](pkg/node/node.go:891), [`node.go:417`](pkg/node/node.go:417), [`relays.go:317` `up stream closed by peer`](pkg/node/relays.go:317) is **not** carrier see below |
| `client_eof` | `client EOF` | [`relays.go:269`](pkg/node/relays.go:269) via `dirEOFReason(DirUp)` |
| `target_eof` | `target EOF` | [`relays.go:271`](pkg/node/relays.go:271) via `dirEOFReason(DirDown)` |
| `other` | anything else, including `""` | [`relays.go:133` budget shutdown](pkg/node/relays.go:133), [`relays.go:143`/`:370` socket read/write errors](pkg/node/relays.go:143), [`node.go:878` `activation failed`](pkg/node/node.go:878) |

Two corrections that must be made as part of this change, because they are the actual source
of the ambiguity:

1. **`"up stream closed by peer"`** ([`pkg/node/relays.go:317`](pkg/node/relays.go:317)) is the
   signal that the *Germany* side overflow-terminated or closed that stream. It is a
   carrier-side close from Iran's point of view, so classify it as `carrier`. Add the pattern
   `closed by peer` → `carrier`.
2. **Socket read/write errors** (`sockReadErr` / `sockWriteErr`,
   [`relays.go:156`](pkg/node/relays.go:156) and [`relays.go:380`](pkg/node/relays.go:380))
   currently produce `"client read error"` / `"target read error"` / `"client write failed"` /
   `"target write failed"` and fall into `other`. These are exactly the *public client leg*
   failures (`client write failed` = the client socket could not accept data = external
   close / MTU-ish behaviour downstream of us). Give them their own explicit substrings —
   change the reason strings to `client socket read error`, `client socket write error`,
   `target socket read error`, `target socket write error` — and classify
   `client socket` → `client_eof` **only for the read/EOF case**, `other` for the error case,
   and add two new counters (`relay_socket_read_errors`, `relay_socket_write_errors`, §1.2)
   that carry the public-leg-vs-internal distinction without touching the reason taxonomy.
   The counters are the attribution instrument; the reason class stays coarse.

**Disambiguating clean target EOF from failure EOF.** `target_eof` is recorded when the
down direction ended on an EOF/half-close that was **not** caused by a local termination.
The discriminator is the `Stats.Terminated` flag of §4.3, plus the attachment state: a
`frame == nil` received in [`startStreamRelay`](pkg/node/relays.go:359) while the attachment
is `AttAttached` for the current generation means the *peer* half-closed its side — a clean
target EOF for the download direction. The same `nil` received while the attachment is
`Unavailable`/`Detached` means the stream ended because the carrier (or an overflow
termination on the peer) went away — not a clean EOF.

Set `SessionStats.CleanHalfClose` only in the first case, at
[`pkg/node/relays.go:359`](pkg/node/relays.go:359):

```go
if frame == nil {
    if st, g := att.State(); st == session.AttAttached && g == h.gen {
        sess.Stats.markCleanHalfClose()   // atomic CAS, idempotent
    }
    n.peerEOF(sess, dir)
    return
}
```

`session_clean_complete` (§4.4) requires `CleanHalfClose == true` **and** `!Terminated`
**and** both directions closed **and** a `client_eof`/`target_eof` class. A session whose
`target EOF` arrived over a detached attachment is counted as `sessions_mid_transfer`
instead — which is the desired attribution for a mid-body failure.

The read of `att.State()` is the existing accessor ([`pkg/session/attachment.go:112`](pkg/session/attachment.go:112));
no new lock is taken, and the CAS on the session flag is a single atomic.

### 4.3 Propagating overflow termination into the session close

`mux.terminateStream` ([`pkg/mux/carrier.go:784`](pkg/mux/carrier.go:784)) has no knowledge of
the session. Two options:

* **Option A (chosen):** the node installs a hook on the carrier that fires when a stream is
  terminated, keyed by stream ID → session via `n.store`. `CarrierConn` gets one optional
  field, `OnStreamTerminated func(streamID uint32)`, set in `install` (`pkg/node/node.go:434`)
  (no behavior change when nil). The callback runs in the dispatcher (from `applyPressure`, C8)
  or the worker (C9), and the node does: `if sess := n.store.ByStream(id); sess != nil {
  sess.Stats.markTerminated() }` — an atomic flag store, plus increments
  `mux_<dir>_overflow_terminations` (already counted at the carrier level) and
  `session_close_reason_overflow` lazily at session close. The `SessionStore` already indexes
  by stream ID (`AddStream`, used at [`node.go:867`](pkg/node/node.go:867) and
  [`node.go:1093`](pkg/node/node.go:1093)); add the read side `ByStream(id) (*Session, bool)`.
  The dispatcher callback must not block: the map lookup is under the store's existing
  `RWMutex`, and the flag store is an atomic — both bounded, no channel send, no logging.
* Option B: encode the reason into the `nil` payload. Rejected: `nil` is the documented
  FrameClose/termination signal and consumers branch on `frame == nil`
  ([`pkg/node/relays.go:359`](pkg/node/relays.go:359)); changing the channel payload type
  would alter the handoff contract.

The reason string for an overflow-closed session becomes
`"stream overflow terminated"` — set at the node's `OnClose` time (in `onSessionClosed`,
*after* the existing `s.Reason()` has been read for classification), not by mutating the
session reason from the carrier callback. Classification therefore reads
`s.Reason()` **and** `s.Stats.Terminated`, and the order in §4.2 puts `overflow` first so a
session that was overflow-terminated and then saw a target EOF is attributed to the
overflow, which is the causally correct answer for this diagnostic.

**Why not record the reason at termination time in the session directly:** `Session.reason`
is `mu`-guarded and first-write-wins; writing from the carrier callback would race the
legitimate first reason from the relay and could steal the slot from an earlier, more
informative close. A separate atomic flag avoids touching the existing reason semantics
entirely.

### 4.4 Clean completion

`session_clean_complete` counts sessions where, at `onSessionClosed`:
`!Stats.Terminated` **and** both `DirClosed(DirUp)` and `DirClosed(DirDown)` are true **and**
the classified reason is `client_eof` or `target_eof`. Both directions half-closed by an EOF
with no termination, carrier, or timeout reason is a clean end. This gives the denominator
that makes the mid-transfer counter meaningful (§5).

---

## 5. Correlation method: the decision rule

**Procedure.** For each matrix arm (direct / loopback / public), record the failed-attempt
count *F* from the client's own measurement, and snapshot the splitter's `/metrics` before
and after the arm. Every decision uses **deltas**, never absolute values, because a node's
counters are cumulative across the whole soak.

Let the delta of a metric `X` be `ΔX`. Compute, per arm:

```
Δoverflow        = Δmux_up_overflow_terminations + Δmux_down_overflow_terminations
                   + Δmux_up_overflow_terminations_worker + Δmux_down_overflow_terminations_worker
Δpush_rej_stream = Σ_dir Δmux_<dir>_push_rejected_stream
Δpush_rej_total  = Σ_dir Δmux_<dir>_push_rejected_total
Δhw_stream_miB   = max over dirs of (mux_<dir>_stream_queued_bytes_high_after)   // high-water, NOT a delta
Δhw_frames       = max over dirs of (mux_<dir>_stream_queued_frames_high_after)
Δhw_total_miB    = max over dirs of (mux_<dir>_queued_bytes_high_after)
Δmid             = Δsessions_mid_transfer
Δpre_first       = Δsessions_closed_before_first_byte
Δcarrier         = Δcarrier_loss_events + Δcarrier_reconnects + Δcarrier_write_failures + Δrelay_write_failures
Δsock_read_err   = Δrelay_socket_read_errors
Δsock_write_err  = Δrelay_socket_write_errors
Δbuf_full        = Δrelay_buffer_full
Δclean           = Δsessions_clean_complete
```

`Δbuf_full` is the relay-buffering input: it counts the moments a shape-A relay had to stop
reading its socket because the bounded reconnect buffer was full — backpressure reaching the
client/target, which is exactly the "relay buffering" hypothesis in the question. It is
distinct from `Δrelay_write_failures`, which is "the carrier refused the write" (a
carrier-lifecycle event), whereas `Δbuf_full` is "the buffer, not the carrier, was the
constraint".

**Decision rule** (evaluate in order; the first rule that fires is the answer):

| Rule | Condition | Verdict |
|---|---|---|
| **R1 — queue pressure is causal** | `Δoverflow > 0` **and** `Δoverflow / Δmid ≥ 0.5` **and** `Δhw_stream_miB ≥ 0.75 × (MaxBytesPerStream / 1 MiB)` | Internal queue pressure (mailbox exhaustion → overflow termination) |
| **R2 — queue pressure, frame-bound variant** | `Δoverflow > 0` **and** `Δhw_frames ≥ 0.75 × MaxFramesPerStream` | Internal queue pressure, bounded by the frame count |
| **R3 — aggregate-budget pressure** | `Δpush_rej_total > 0` **and** `Δhw_total_miB ≥ 0.75 × 32 MiB` | Carrier-wide aggregate budget (32 MiB) is the constraint; per-stream limits are not |
| **R4 — mailbox pressure without termination** | `Δpush_rej_stream > 0` **and** `Δoverflow == 0` **and** `Δhw_stream_miB ≥ 0.5 × MaxBytesPerStream` | Mailboxes are saturating but recovering before `OverflowWait` (100 ms) — a latency/throughput cause, not a failure cause; re-run at lower concurrency to separate |
| **R4b — relay-buffer backpressure, not mailbox** | `Δbuf_full > 0` **and** `Δoverflow == 0` **and** `Δpush_rej_stream == 0` **and** `Δmid > 0` | The bound that flexed was the shape-A reconnect buffer (256 KiB per direction): the client/target was throttled mid-body, not a mux mailbox. Internal, but at the session/budget layer rather than the carrier layer — check `relay_pending_high_bytes` against `BufferBytes` to confirm |
| **R5 — public leg is implicated** | `Δmid > 0` **and** `Δoverflow == 0` **and** `Δpush_rej_stream == 0` **and** `Δpush_rej_total == 0` **and** `Δbuf_full == 0` **and** `Δhw_stream_miB < 0.5 × MaxBytesPerStream` **and** `Δhw_total_miB < 0.5 × 32 MiB` **and** `Δcarrier == 0` | No splitter-internal bound engaged: neither a mux mailbox, nor the aggregate budget, nor the reconnect buffer, nor the carrier. The public client leg (packet loss / MTU / external close) is implicated |
| **R6 — carrier transport, not queue** | `Δcarrier > 0` **and** `Δoverflow == 0` | The carrier transport failed; a queue-pressure verdict would be a misattribution |
| **R7 — public-leg socket failure** | `Δsock_read_err + Δsock_write_err > 0` | The client socket itself errored (external close, path MTU blackhole mid-body); corroborates R5 and names the direction |
| **R8 — inconclusive** | none of the above | Report which inputs were flat and raise the counters' resolution: the most likely gap is `OverflowWait` being too long to observe at this concurrency — see §5.1 |

**Cross-arm control that answers the original question.** The evidence already establishes
public ≫ loopback ≫ direct. Run all three arms and compare the *same* deltas:

* If **R1/R2/R3/R4 fires on all three arms** with comparable ratios, the cause is internal
  and concurrency-related (consistent with the observed loopback degradation at
  concurrency 32); the public leg is not implicated.
* If **R1/R2/R3/R4 fires on loopback/direct only weakly or not at all, and R5 fires on
  public only**, the public leg is implicated.
* If **R5 fires on all three arms**, the failure is arm-independent and the "public leg" is
  not special — the differentiator is something shared (e.g. the fixed URL's behaviour).

**Concurrency must be a controlled variable, not a confound.** Run each arm at concurrency
1, 8, 32 with 3 reps as before, and require the verdict to be stable across reps before
reporting. A verdict that appears only at concurrency 32 (where loopback also degraded) is
an internal-queue verdict regardless of arm.

**Sanity identities that must hold** (these catch instrumentation bugs, and are themselves
a test):

```
Δtotal_sessions            == Δsessions_clean_complete + Δsessions_mid_transfer
                              + Δsessions_closed_before_first_byte
session_active_sessions    == Δtotal_sessions - (all close-reason deltas summed)
mux_<dir>_push_accepted    >= mux_<dir>_stream_queued_frames_high   (never more items seen than pushes)
```

The first two are the accounting identities: every session is counted exactly once, and every
close-reason counter drains the same population. The third is the counter-vs-mark check that
catches a high-water fold running on a path the push counter does not.

### 5.1 If the counters come back flat and failures persist

A flat result at R8 is itself informative but must be escalated deliberately:

1. Confirm `SPLIT_METRICS_PORT` was set for the run and the endpoint was reachable (the
   evidence context says it was unreachable; that alone explains an all-flat result).
2. Confirm the arm's failed `F` is not zero — if `F > 0` but `Δmid == 0`, the failures
   happened **before** a session existed on the splitter, i.e. at the SOCKS/auth/TLS stage,
   which the evidence context already rules out; in that case `Δpre_first > 0` and the
   instrumentation is working and the verdict is R5 with a tighter definition.
3. If `F > 0`, `Δmid > 0`, and every internal counter is flat: **the failure is on the public
   client leg** (R5). The next diagnostic step is packet capture on the public path, not more
   internal instrumentation — the internal-state hypothesis has been falsified by data.

---

## 6. Tests

All new tests are deterministic, use existing helpers
(`testutil.NewMemPipe`, `bpLimits`, `waitTerminated` in
[`pkg/mux/backpressure_test.go`](pkg/mux/backpressure_test.go:14)), and are safe under
`-race`.

### 6.1 `pkg/mux`

| Test | File | What it proves |
|---|---|---|
| `TestQueueStatsRejectReasons` | `queue_stats_test.go` (new) | A mailbox at the frame bound rejects with `rejectStreamFrames`; at the byte bound with `rejectStreamBytes`; with an exhausted aggregate with `rejectAggregate`; a closed mailbox with `rejectClosed`. Four subtests, exact counter deltas |
| `TestQueueStatsHighWaterBytes` | `queue_stats_test.go` | Push 3 payloads of 400 B into a 4-frame/1 KiB mailbox; assert `streamQueuedBytesHigh == 1000` after each push and that it does not decrease after pops (high-water semantics) |
| `TestQueueStatsHighWaterFrames` | `queue_stats_test.go` | Same with 1-byte payloads and a 4-frame bound; asserts `streamQueuedFramesHigh == 4` |
| `TestQueueStatsHighWaterAggregate` | `queue_stats_test.go` | Three mailboxes sharing a `*int64` budget; asserts `queuedBytesHigh == Σ` and that a refused push leaves it unchanged |
| `TestQueueStatsNilSafe` | `queue_stats_test.go` | A queue with a nil `*QueueStats` behaves exactly as before (push/pop/close/budget), so existing tests are unaffected |
| `TestOverflowTerminationCounts` | `backpressure_test.go` (extend) | Drive `deliver` single-threaded on a stalled stream with `OverflowWait: 20 ms` (the existing single-threaded pattern of [`TestAggregateBudgetEnforced`](pkg/mux/backpressure_test.go:136)); assert `overflow_terminations == 1`, `overflow_wait_count >= 1`, `overflow_wait_max_seconds >= 0.02`, and that the carrier is still `Ready()` |
| `TestWorkerOverflowTerminationCounts` | `backpressure_test.go` (extend) | A consumer that stops reading; assert `overflow_terminations_worker == 1` (path C9) |
| `TestCarrierWriteFailureCounted` | `carrier_stats_test.go` (new) | Wrap a `MemConn` whose `Write` returns an error after N bytes; assert `carrier_write_failures >= 1` and the carrier closes through the normal path |
| `TestCarrierReadFailureAndEOFCounted` | `carrier_stats_test.go` | Close the peer side → `carrier_read_eof == 1`; blackhole then close → `carrier_read_failures >= 1` (MemConn has both behaviours, [`mempipe.go:45`](internal/testutil/mempipe.go:45)) |
| `TestBlackholeDeathCounted` | `carrier_stats_test.go` | `SetLivenessRounds(1)`, blackhole the peer, assert `blackhole_deaths == 1` within the window |
| `TestZeroPushRejectedWhenDrained` | `backpressure_test.go` (extend) | A consumer that keeps pace: `push_rejected_stream == 0` and `streamQueuedBytesHigh < MaxBytesPerStream` — proves the counters do not fire on healthy traffic |
| `TestStatsConcurrentNoRace` | `carrier_stats_test.go` | N streams × M pushes with concurrent consumers and a carrier `Close` mid-flight; run under `-race`. Asserts `push_accepted == push delivered to consumers + push_discarded` and no data race |

### 6.2 `pkg/node`

| Test | File | What it proves |
|---|---|---|
| `TestCloseReasonClassification` | `closereason_test.go` (new) | Table-driven over the exact reason strings from §4.2; asserts each maps to the expected class and that `""` maps to `other` |
| `TestCloseReasonCarriesOverflowFirst` | `closereason_test.go` | A session with `Stats.Terminated=true` **and** `Reason()=="target EOF"` classifies as `overflow` (order matters) |
| `TestSessionClosedCountedExactlyOnce` | `closereason_test.go` | 50 goroutines calling `Close` with different reasons; assert the sum of all close-reason counters is exactly 1 |
| `TestMidTransferCounter` | `nodemetrics_test.go` (new) | A session that transfers ≥1 byte then closes uncleanly → `sessions_mid_transfer == 1`; a clean session → `sessions_clean_complete == 1`; a session closed pre-first-byte → `sessions_closed_before_first_byte == 1`. Uses the existing in-process node test harness (`node_test.go`) |
| `TestFirstByteCountedOnce` | `nodemetrics_test.go` | Two relays racing a first byte; CAS guarantees exactly one increment |
| `TestTargetDialCounters` | `nodemetrics_test.go` | `TargetDial` returning success/failure → the two counters; asserts the dial address never appears in `Snapshot()` |
| `TestRelayPendingHighWater` | `relaystats_test.go` (new) | Fill a shape-A pending buffer across a carrier outage; assert `relay_pending_high_bytes == BufferBytes` and `relay_buffer_high_bytes <= SessionBufferTotalBytes` |
| `TestRelayBufferFullCounted` | `relaystats_test.go` | A stalled carrier with a full pending buffer → `relay_write_failures` and `relay_buffer_full` increment without the mailbox limits being touched |
| `TestMetricsRenderNoSecrets` | `relaystats_test.go` | Drive a session end to end with a real destination, then assert every rendered line matches one of exactly two forms: `^[a-z0-9_]+\s+[0-9]+(\.[0-9]+)?$` for plain counters/gauges, and `^session_close_reason\{reason="(client_eof\|target_eof\|carrier\|overflow\|timeout\|other)"\}\s+[0-9]+$` for the single labelled metric. Assert the output contains no `:` (a leaked host:port or URL), no `/`, no `0x`, and no run of 16+ hex characters (a leaked ID). Assert the six reason lines appear exactly once each, so a seventh class cannot be introduced silently |
| `TestMetricsRenderConcurrent` | `relaystats_test.go` | Concurrent `Render()` + counter increments under `-race`; asserts rendering completes and is internally consistent |

Privacy test enforcement is a single shared helper (inline in `relaystats_test.go`, e.g.
`assertRenderPrivacy(t, out string)`) that owns the two regexes and the four forbidden-substring
checks. It is called by `TestMetricsRenderNoSecrets` and by the render tests for the new
`mux` direction lines, so any future metric that carries a variable string fails CI
immediately at exactly one place.

### 6.3 `internal/config`

| Test | What it proves |
|---|---|
| `TestMetricsPortZeroDefault` (exists, `config_test.go:77`) — keep | default remains disabled |
| `TestMetricsPortNeverPublic` (new) | `Defaults().MetricsPort == 0`; a config with a metrics port still validates only when it does not collide; the *rendered* address is not configurable (assert `envInt` rejects `SPLIT_METRICS_PORT=0.0.0.0` — a numeric-parse failure, which is the structural argument of §3.1) |

### 6.4 `cmd/*` (both binaries)

| Test | What it proves |
|---|---|
| `TestMetricsListenAddrLoopbackOnly` (new, one per binary) | `metricsListenAddr(anything)` starts with `127.0.0.1:` |
| `TestRunMetricsRefusesNonLoopback` (new) | Start the handler on a listener whose address is not loopback (via the real `net.Listen` on a non-loopback interface if available, else by direct assertion on the guard) — assert the server returns an error and serves nothing |

---

## 7. CI

**The existing workflow is sufficient; no new step is required.**

[`.github/workflows/go.yml`](.github/workflows/go.yml) already runs, on every push to
`main` and `hardening/production-reliability` and on every PR:

| Gate | Line | Covers this change |
|---|---|---|
| `gofmt -l .` | [:34-35`](.github/workflows/go.yml:34) | formatting of all new files |
| `go vet ./...` | [:37-38`](.github/workflows/go.yml:37) | the new `atomic` usage, unused writes, printf-arg checks in the renderer |
| `go test ./...` | [:40-41`](.github/workflows/go.yml:40) | all new unit tests |
| ShellCheck / `bash -n` | [:43-61`](.github/workflows/go.yml:43) | no shell changes here, but the installer harness still runs |
| `go test -race ./...` | [:88-89`](.github/workflows/go.yml:88) | the concurrency tests in §6.1/§6.2 — this is the gate that matters for `pkg/mux` and `pkg/node` |
| linux/amd64 build | [:230-234`](.github/workflows/go.yml:230) | the deployed target |

Nothing in this spec adds a new build tag, a new dependency, a new tool, or a network
dependency, so the hermetic-unit / pinned-Xray / pinned-Caddy gates are unaffected.

**One recommendation (non-blocking):** if the new `pkg/mux` concurrency test proves flaky
under parallel package execution, add `-p 1` scoping to a focused job rather than weakening
the assertions — `go test -race ./pkg/mux/... ./pkg/node/... -count=2`. Do not add
`-short` skips to the new tests: the whole point is that they are deterministic.

---

## 8. Deployment path

### 8.1 Build

From a clean checkout at the instrumented revision, on any host with Go:

```bash
gofmt -l .                       # must be empty
go vet ./...
go test ./...
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o iran-splitter    ./cmd/iran-splitter
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o germany-splitter ./cmd/germany-splitter
```

Record `sha256sum` of both binaries and `go version -m <binary>` — `vcs.revision` is the
verified identity used in prior deployments
([`IMPLEMENTATION_STATUS.md:252-256`](IMPLEMENTATION_STATUS.md:252)).

### 8.2 Deploy via the supported path

The supported path is `splitterctl upgrade --splitter`, which is a full transaction (env fold
→ `config.Validate` → `WriteEnvFile` 0600 → `ApplyUnit` + restart). It requires the
environment to supply an actual change (version or path), so the new binary must be staged
at a **new** path/version rather than over the live one.

1. Stage the role binary on each host under a new path (e.g.
   `/opt/split-tunnel/iran-splitter-telemetry` / `/opt/split-tunnel/germany-splitter-telemetry`).
2. Run `splitterctl upgrade --splitter` with the environment pointing at the new artifact.
3. Verify: `sha256sum`, `go version -m` `vcs.revision`, `splitterctl doctor` (health,
   including the metrics probe — which will skip while the port is 0).
4. Both hosts must be upgraded before the matrix run, because the counters on each side are
   independent and the comparison is cross-node.

### 8.3 Enabling the metrics endpoint temporarily (loopback only)

```bash
splitterctl config set metrics.port=9101        # or the SPLIT_METRICS_PORT equivalent for the role
systemctl restart iran-splitter                 # Germany: germany-splitter
curl -s http://127.0.0.1:9101/metrics
```

`metrics.port` is an existing configurable key
([`internal/deploy/request.go:299`](internal/deploy/request.go:299)) and is projected to
`SPLIT_METRICS_PORT` at [`request.go:132`](internal/deploy/request.go:132). The listener
binds `127.0.0.1:9101` **only**, and the guard of §3.3 refuses to serve otherwise. Because
`splitterctl doctor` probes `127.0.0.1:<port>/metrics`
([`internal/systemd/health.go:143`](internal/systemd/health.go:143)), enabling it also makes
doctor's health check strictly better.

Pick a port that does not collide with any role listener — the validator rejects a collision
at [`internal/config/config.go:349-356`](internal/config/config.go:349).

### 8.4 Removing the instrumentation afterwards

**Do not remove it.** The change is designed to be permanent: fixed-cardinality counters, a
loopback-only endpoint that is off by default, and no behaviour change. Rollback, if ever
required, is the supported `splitterctl rollback --to <state-id>` path, which retains the
environment (it does not rewrite the env file —
[`IMPLEMENTATION_STATUS.md:753`](IMPLEMENTATION_STATUS.md:753)) and then restoration via
`upgrade --splitter`.

If the *endpoint* must be turned off after the run, that is a config-only transaction and
needs no code change and no redeployment:

```bash
splitterctl config set metrics.port=0
systemctl restart iran-splitter
```

---

## 9. Privacy and security review

### 9.1 Must never appear

| Class | Examples | Status |
|---|---|---|
| Session identifiers | `SessionID` (16 random bytes), `shortID` (first 4 bytes) | **Never** — not in any metric key or value. Session IDs appear only in log lines, which are out of scope for the metrics surface |
| Stream IDs | `StreamIDUp`/`StreamIDDown` (uint32) | **Never** — stream IDs are per-node counters but they correlate to a session, and the spec forbids per-stream metrics explicitly |
| IP addresses / ports | client peer address, target address:port | **Never** — `target_dial_success/failure` carries the boolean only; the dial address is not passed to any counter |
| Hostnames / URLs | `UpWsUrl`, destination domains | **Never** |
| Credentials | SOCKS user/pass, carrier secret | **Never** — no counter is incremented with credential material; no metric value is derived from it |
| Peer-provided values | rebind payloads, generated codes, error strings | **Never** — counters are code-owned constants; error values are classified by *where* they occurred, never propagated |
| Payload content | image bytes, headers | **Never** — only lengths are counted |

### 9.2 Structural enforcement

1. **No label sets at all except one fixed enum.** The only label in the entire surface is
   `session_close_reason{reason=…}` with six compile-time constants of a private
   `CloseReason` type. The `Metrics` method that consumes it
   (`SessionClosed(r CloseReason)`) cannot be called with a string.
2. **The renderer is a fixed line list.** [`Metrics.Render`](pkg/node/metrics.go:195) is a
   hand-rolled `strings.Builder` over an explicit field list. There is no map iteration, no
   `%v` over a user-controlled value, no per-series output. A new metric must be added as an
   explicit `Fprintf` line — which is what makes the privacy test of §6.2 possible.
3. **The test is the enforcement mechanism.** `TestMetricsRenderNoSecrets` asserts every
   rendered line matches `^[a-z0-9_]+\s+[0-9]+(\.[0-9]+)?$` (with the single, explicitly
   enumerated `reason="…"` label form permitted). Any attempt to render a variable string
   fails CI.
4. **`go vet`'s printf check** on every `fmt.Fprintf` in the renderer catches a format/verb
   mismatch that could accidentally interpolate a value.
5. **Loopback-only binding is structural, not conventional** (§3.1, §3.3): the address is not
   a configuration input, and a post-`Listen` assertion refuses to serve a non-loopback
   address.

### 9.3 Residual risk

The counters themselves are an information channel: they reveal session counts, throughput
rates, and pressure state. That is precisely what makes them diagnostic, and it is why the
endpoint stays off by default and loopback-only. The recommendation is **not** to expose it
publicly even with authentication.

---

## 10. Implementation checklist (for the implementer, in order)

1. `pkg/mux/qstats.go` (new): `QueueStats` (§1.1), the `rejectReason` enum, all methods
   atomic and nil-safe; `render(prefix)` produces the 20 direction lines of §1.
2. `pkg/node/streamstats.go` (new): `SessionStats` with `FirstByte`, `CleanHalfClose`,
   `Terminated` (three `atomic.Bool`), each nil-safe.
2. `pkg/mux/queue.go`: `stats` field, `SetStats`, reject-reason helper, hooks in
   `TryPush`/`Pop`/`Close` (`:112`, `:139`, `:175`).
3. `pkg/mux/carrier.go`: `stats` + `queuedItems` fields, `SetQueueStats`, hooks in
   `readLoop`/`writeLoop`/`liveness`/`applyPressure`/`streamWorker`
   (`:204`, `:246`, `:546`, `:757`, `:819`), `OnStreamTerminated` field + call in
   `terminateStream` (`:784`).
4. `pkg/node/streamstats.go` (new): per-session stats flags (`firstByte`,
   `cleanHalfClose`, `terminated`), atomic, nil-safe.
5. `pkg/session/session.go`: embed the stats struct in `Session` (one field addition at the
   struct, `:294`).
6. `pkg/session/session.go`: `SessionStore.ByStream(id)` read side.
7. `pkg/node/metrics.go`: new counters, `SessionClosed(CloseReason)`, `CloseReason` type +
   classifier, `Render` lines.
8. `pkg/node/relays.go`: A1–A6.
9. `pkg/node/node.go`: N1–N6.
10. `pkg/node/budget.go`: A7.
11. `cmd/iran-splitter/main.go`, `cmd/germany-splitter/main.go`: `metricsListenAddr` constant,
   loopback assertion, both `/metrics` handlers render the new surface.
12. Tests per §6.
13. Docs: `README.md` metrics list, `IMPLEMENTATION_STATUS.md` record.
