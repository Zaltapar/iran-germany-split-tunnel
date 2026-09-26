# Architecture Checkpoint — Receiver-Side Mailbox Pressure Propagation (Backpressure)

Status: **ARCHITECTURE CHECKPOINT — READ-ONLY.** No code, config, staging, or
infrastructure was modified. No commit was made. Image loading over the public
SOCKS path is **NOT** claimed fixed; this document only specifies the design that
a later phase may implement.

**Revision 2 (amended).** The adversarial re-review returned
*APPROVED-WITH-AMENDMENTS* with four new defects (R2-1–R2-4) and one
consistency fix (R2-5). This revision applies those amendments in place —
each is listed in the "AMENDMENTS (rev 2)" section below, which is the map from
amendment number to the sections it touched. The **D4 recommendation is
preserved** (re-validated by the re-review), and the **integrity invariant is
not weakened anywhere in this document**: *ordered DATA is either delivered or
the stream is explicitly terminated; DATA is never silently discarded.* Credit
is described throughout as an **optimization** that keeps the refused-DATA path
([`failUndeliverableData`](pkg/mux/carrier.go:834)) armed as a safety net.

Commit under test: `b2547229c0c65173615b463bbb97b5be5000cef2`.
The working tree additionally carries an **uncommitted** integrity fix
(`deliver()` routed through `failUndeliverableData`) that is NOT part of that
commit; every file:line below is read from the current working tree, and the
integrity defect language below describes the *fixed* tree.

---

## AMENDMENTS (rev 1) — applied per the review's APPROVED-WITH-AMENDMENTS verdict

**Preserved, not amended:** the D4 hybrid recommendation (§E, validated by the
review) and the integrity invariant above.

| # | Applied in | Amendment in one line |
|---|---|---|
| A1 | §E.2, §E.3, §D.5-Q10 | The credit gate exists **only** at the [`relayShapeA`](pkg/node/relays.go:66) loop head, before `sock.Read` ([`relays.go:113`](pkg/node/relays.go:113)); the in-`flushPending` gate is **deleted** and the socket-EOF flush path ([`relays.go:73-91`](pkg/node/relays.go:73)) is never credit-gated. Exact ordering stated. |
| A2 | §F Scenario 2, §D.5-Q11, §D1-Q11 | One named guard for the bidirectional exhaustion cycle: **the credit-floor guard** — a credit-parked down-relay still drains the target socket into `pending` up to `CreditFloorDrain` bytes. |
| A3 | §I Steps 1-3 | Bounded **`CreditEstablishTimeout`** (default **2 s**), independent of `Grace`, plus re-emission of the first credit frame on **rebind-attach**. |
| A4 | §E.2, §H, §I Step 1, §D1-Q15 | One rule everywhere: **default `CreditInitial` = unlimited (current behaviour)**; latch to credit-gated **only** on the first valid credit frame for that stream; "blocked until Step 2" deleted. |
| A5 | §E.1, §E.2, §E.4, §E.5 | Credit is **absolute** `cumulativeBytesPopped`; DE tracks its own `cumulativeSent` and derives `credit = cumulativeBytesPopped − cumulativeSent` (idempotent, self-healing); `creditVersion != 1` ⇒ reject and fall back to **unlimited** for that stream. |
| A6 | §E.3, §E.4, §E.5, §D.5-Q9 | `FINAL_CREDIT` is **deleted**; the peer-close distinction is **not** threaded through `queueItem`; half-close relies on the existing target-EOF `FrameClose` path ([`relays.go:73-91`](pkg/node/relays.go:73)). |
| A7 | §F worst-case bound, §D.5-Q6, §D1-Q6, U6 | Memory bound becomes `Σ_streams min(MaxBytesPerStream, creditWindow) ≤ MaxBytesTotal`; the unfounded `+ N·CreditThreshold` term is **removed**. |
| A8 | §G.1, §G.2 | §G.1 M1–M9 present; I8–I9 added in §G.2 (the review's **nine must-add tests**), each with its package. |
| A9 | §D.5-Q11, §D1-Q11 | "no deadlock" softened to **"none except the bidirectional target-exhaustion case, mitigated by the credit-floor guard (A2)"**. |

*Note (rev-3):* the numbered scenario subsections these maps once cited
(§F Scenario 3, §F Scenario 4) and the `U5`/`U8` entries **no longer exist as
named subsections** — that content was merged into the surviving sections during
the rev-2 reconstruction — so the cells above are repointed to the sections that
actually carry it (A4→§E.2, A6→§E.3, A8→§G.1 M1–M9 / I8–I9).

---

## AMENDMENTS (rev 2) — applied per the adversarial re-review

**Preserved, not amended:** the D4 design choice, A1 gate ordering, A3
`CreditEstablishTimeout`, A4 single initial-credit rule, A6 `FINAL_CREDIT`
deletion, A7 memory-bound correction, A8/M-test presence, Attack 1 (bounded
credit floor), Attack 2 (revert-to-unlimited ≡ pre-fix behaviour), and the
proof that over-credit is structurally impossible.

| # | Applied in | Amendment in one line |
|---|---|---|
| R2-1 | §E.1, §E.5 | Credit emission is moved **out** of the pop path: the pop path only counts `poppedBytesTotal` under `q.mu` (plain `uint64`, no callback, no second lock); a new node-level callback `OnStreamPopped(streamID, poppedBytesTotal uint64)` is installed on the carrier (modelled on `OnStreamTerminated`/`OnStreamDataUndeliverable` at [`node.go:468,473`](pkg/node/node.go:468)); the node handler writes `FrameCredit` on the DOWN carrier handle. No carrier write while `q.mu` is held. *(rev-3, Note C:)* Handler runs in the streamWorker goroutine; emission is a **BLOCKING** handoff on the same write path as other frames (`writeCh` cap 256 → `<-req.done` → one blocking `rwc.Write`, [carrier.go:307-329](pkg/mux/carrier.go:307), [carrier.go:279](pkg/mux/carrier.go:279)) — **not** a non-blocking control-frame path; carrier resolution is Ready-checked (`currentIfReady`, [node.go:360](pkg/node/node.go:360)) with the generation pinned, and a failed/not-ready write makes the credit **inert** (dropped, absorbed by `CreditEstablishTimeout`/revert-to-unlimited). |
| R2-2 | §E.4, §I Step 3, §D1-Q15 | The phantom `node.go:821` citation is **deleted**. Option (b) chosen: the FrameCredit payload has **no generation field** (18-byte payload unchanged); enforcement is structural — a credit frame is only ever produced by the CURRENT carrier's readLoop/dispatch on the receiving side, so a superseded carrier's frames are never delivered (its readLoop has exited); combined with the un-latched-until-first-valid-frame rule (A4), late/stale credit is inert. |
| R2-3 | §E.4 (new subsection) | Credit arithmetic specified: `creditWindow` is `uint64`; mandatory clamp `if cumulativeBytesPopped < cumulativeSent { credit := 0 }` (PARK, never wrap); on rebind both sides reset counters to 0 deterministically at attach so the first post-rebind frame anchors both; uint64 overflow at ~18.4 EiB is unreachable for a single stream (one line). |
| R2-4 | §F Cycle 1, §G.1 M7, §G.2 I8 | Cycle 1 diagram **redrawn**: the gate that exists is DE's DirDown credit gate (there is no shape-A up-relay on Germany; Germany DirUp is shape-B writing to the target via `startChannelConsumer` at [`node.go:1150`](pkg/node/node.go:1150)). Real residual chain: DE-DirDown parked on credit + DE-DirUp shape-B blocked in `sock.Write` to target (target receive buffer full) + IR up-mailbox full → bounded by `OverflowWait` ([`carrier.go:955`](pkg/mux/carrier.go:955)), deliver-or-fail ([`carrier.go:825`](pkg/mux/carrier.go:825)), grace ([`node.go:430`](pkg/node/node.go:430)), `finalizeDrain` 10 s timer ([`node.go:1161`](pkg/node/node.go:1161)) → ends in CLEAN ABORT. M7 redefined to assert both directions complete OR both fail cleanly without corruption, driving the real chain. |
| R2-5 | §D.5 row 10 | D.5 row 10 corrected: "park holds 0 budget (A1)" → "a parked relay holds ≤ `CreditFloorDrain` at the floor, 0 past it (A1/A2)" — consistent with §F and §D1-Q10. |

**Also applied (consistency):** `creditWindow` is defined at its first use in §D1-Q6 and referenced at every subsequent use (§F memory-bound, §D.5 row 6, U6). The integrity-invariant header is re-affirmed unweakened.

---

## 0. Provenance / established facts used

- Per-stream mailbox is a **dual bound**: ≤ `MaxFrames` items AND ≤
  `MaxBytesPerStream` bytes, whichever binds first
  ([`fullLocked`](pkg/mux/queue.go:140-143)).
- `MaxFrames = 16` is a **hard library constant**
  ([`carrier.go:401`](pkg/mux/carrier.go:401)); the env surface
  `SPLIT_STREAM_QUEUE_FRAMES` is clamped to the same 16
  (`internal/config/config.go:260` → `mux.MaxFrames`).
- `MaxPayload = 65535` ([`frame.go:21`](pkg/mux/frame.go:21)) ⇒ 16 × 65535 =
  1,048,560 bytes ≈ 1 MiB is the **hard maximum single-stream mailbox
  occupancy**. Raising `SPLIT_STREAM_QUEUE_BYTES` (cap 64 MiB,
  `internal/config/config.go:99`) is **inert** for a single object > 1 MiB.
- Integrity defect (proven, fixed in the working tree): the old dispatcher
  silently dropped a refused in-order DATA frame while leaving the stream
  alive, producing a byte hole (no seq number on frames,
  [`frame.go:14-18`](pkg/mux/frame.go:14-18)). The fix routes every refused
  DATA frame to [`failUndeliverableData`](pkg/mux/carrier.go:834) which
  terminates the stream cleanly (`deliver` → `terminateStream(s, true)`),
  delivering a **contiguous in-order prefix** then a `nil` end signal
  ([`carrier.go:791-826`](pkg/mux/carrier.go:791), test anchor
  [`deliver_fail_test.go:45`](pkg/mux/deliver_fail_test.go:45)).
- Race CI for this fix has passed in the current tree.
- Observed regression: a serial ~1.24 MB image aborts 12/12 via the public
  SOCKS path. Staging retest: **PASS(a)** (0 corruption) but **FAIL(c)**
  availability thresholds.
- Retest telemetry shape: Germany `relay_bytes_read == relay_bytes_written`
  ≈ full object (DE over-fed the carrier at target pace); Iran
  `mux_down` drop counters rise; `carrier_loss = 0`; Germany had **no**
  dropped data frames — every drop is on the **Iran down-path**
  (`mux_down_dropped_data_frames`).

---

## A. EXACT CURRENT DATA-FLOW AND BUFFERING MODEL

### A.1 Download path (public SOCKS response body) — the failing direction

```
target socket (DE)
  → relayShapeA(sess, DirDown, targetConn)   [relays.go:46, called from bootstrapUpStream relays.go:1152 / node.go:1152]
     ├─ reads 32 KiB chunks into `buf`      [relays.go:113]
     ├─ charges bytes to node aggregate     [relays.go:134 chargeWait]
     ├─ appends to `pending`               [relays.go:141]
     └─ flushPending()                      [relays.go:180]
          ├─ chunk ≤ MaxPayload 65535       [relays.go:192-193]
          └─ carrier.WriteFrame(streamID, FrameData, chunk)  [relays.go:195]
               → c.write(buf)               [carrier.go:307-329]
                    ├─ writeCh (cap 256)    [carrier.go:180]
                    └─ writeLoop → rwc.Write [carrier.go:272-298]
  ── down-carrier (TCP, DE :9002 ← IR dials) ──
  → IR readLoop: ReadFrame                  [carrier.go:229-264]
     └─ c.frames (cap 256)                  [carrier.go:179,259]
  → Dispatch (single goroutine)             [carrier.go:731-774]
     └─ deliver(s, it)                      [carrier.go:791]
          ├─ s.q.TryPush(it)                [carrier.go:813] → queue.go:178
          │    ├─ per-stream: frames ≥ 16   [queue.go:151]
          │    ├─ per-stream: bytes > 1 MiB [queue.go:153]
          │    ├─ aggregate: MaxBytesTotal 32 MiB [queue.go:187-193]
          │    └─ closed                    [queue.go:149]
          └─ refused ⇒ failUndeliverableData [carrier.go:825]
               → terminateStream(s, true)   [carrier.go:842]
  → streamWorker (one per stream)           [carrier.go:921-965]
     └─ q.Pop()                             [queue.go:214]
          └─ select s.ch <- payload, cap 1  [carrier.go:951-952]
               ├─ OverflowWait timeout ⇒ terminate own stream [carrier.go:955-963]
               └─ Close aborts via <-c.closed
  → startStreamRelay (IR, DirDown)          [relays.go:337]
     └─ frame, ok := <-ch                   [relays.go:353]
          └─ sock.Write(frame)  → client    [relays.go:380]
```

### A.2 Authoritative buffering inventory (download direction)

| # | Buffer | Size / cap | Where enforced | Owner |
|---|---|---|---|---|
| 1 | `pending` slice (DE, DirDown) | `BufferBytes`, default **256 KiB** (`SPLIT_SESSION_BUFFER_BYTES`) | [`relays.go:105-111`](pkg/node/relays.go:105) | shape-A relay goroutine |
| 2 | fixed socket read chunk `buf` | `RelayBufSize`, default **32 KiB** | [`relays.go:48`](pkg/node/relays.go:48) | same goroutine |
| 3 | node-level aggregate pending budget | `SessionBufferTotalBytes`, default **32 MiB** | [`chargeWait`](pkg/node/budget.go:174) | `sessionBufferBudget` |
| 4 | carrier write queue `writeCh` | **256** requests | [`carrier.go:180`](pkg/mux/carrier.go:180) | writeLoop |
| 5 | OS socket send buffer (down-carrier TCP) | kernel default (not configured in repo) | kernel | — |
| 6 | carrier read channel `c.frames` | **256** frames | [`carrier.go:179`](pkg/mux/carrier.go:179), [`carrier.go:259`](pkg/mux/carrier.go:259) | readLoop → Dispatch |
| 7 | `bufio.Reader` on read side | **64 KiB** | [`carrier.go:662`](pkg/mux/carrier.go:662) | readLoop |
| 8 | per-stream **mailbox** | **16 frames** ∧ **1 MiB bytes** ∧ aggregate **32 MiB** | [`carrier.go:401`](pkg/mux/carrier.go:401), [`DefaultStreamLimits`](pkg/mux/carrier.go:393-398), enforced in [`queue.go:140-193`](pkg/mux/queue.go:140) | dispatcher + worker |
| 9 | consumer channel `s.ch` | **1** item | [`carrier.go:502`](pkg/mux/carrier.go:502) | streamWorker |

`MaxBytesPerStream` (1 MiB) and `MaxBytesTotal` (32 MiB) come from
[`DefaultStreamLimits`](pkg/mux/carrier.go:393) and can be raised via env
(`MaxQueueBytesPerStream` 64 MiB / `MaxQueueBytesTotal` 256 MiB,
[`internal/config/config.go:99-101`](internal/config/config.go:99)); **`MaxFrames`
cannot be raised** ([`SanitizeLimits`](pkg/mux/carrier.go:406-410) clamps any
value > 16 back to 16; config clamps to `mux.MaxFrames`,
[`internal/config/config.go:260`](internal/config/config.go:260)).

### A.3 What backpressure actually exists today

**Germany (target-reading relay, DirDown):**
- Stops reading the target socket **only** when `len(pending) >= capacity`
  (256 KiB) → `waitAttach` ([`relays.go:105-111`](pkg/node/relays.go:105)),
  or when the node aggregate budget is saturated (`chargeWait` parks,
  [`budget.go:174`](pkg/node/budget.go:174)).
- `flushPending` calls `WriteFrame`, which calls [`write`](pkg/mux/carrier.go:307),
  which **blocks** on `c.writeCh <- req` (cap 256) and then on `<-req.done`
  ([`carrier.go:328`](pkg/mux/carrier.go:328)). So the write path *is*
  synchronous and *can* block — but only after the kernel TCP send buffer of
  the down-carrier is full (or the peer stalls reading). While `WriteFrame`
  blocks, **the relay goroutine is inside `flushPending` and therefore is not
  reading the target socket** — that is the only real backpressure today.
- Because `writeCh` (256) + kernel buffers absorb far more than 256 KiB, the
  DE `pending` full condition essentially never fires on a healthy carrier.
  This is exactly the telemetry: DE `relay_buffer_full ≈ 0`, DE
  `relay_bytes_read ≈ relay_bytes_written`.

**Iran (down-direction consumer):**
- The mailbox is bounded at 16 frames / 1 MiB. The dispatcher **never blocks**
  on a slow consumer (Phase 3, Issue B,
  [`carrier.go:723-730`](pkg/mux/carrier.go:723)). A refused DATA frame
  terminates the stream ([`carrier.go:825`](pkg/mux/carrier.go:825)).
- `streamWorker` has its own second deadline: a handoff parked longer than
  `OverflowWait` terminates the stream ([`carrier.go:955-963`](pkg/mux/carrier.go:955)).

### A.5 How today's abort actually reaches the client (abort propagation trace)

1. IR `terminateStream(s, true)` sends `nil` on `s.ch`
   ([`carrier.go:897`](pkg/mux/carrier.go:897)); IR `startStreamRelay` reads
   `nil` and calls `peerEOF(sess, DirDown)`
   ([`relays.go:368-373`](pkg/node/relays.go:368)).
2. `peerEOF` half-closes the Iran client socket
   ([`relays.go:265-268`](pkg/node/relays.go:265)) and marks DirDown closed
   ([`relays.go:270`](pkg/node/relays.go:270)). The client sees EOF on a
   truncated body → **clean abort, no corruption**.
3. On DE, the returned `FrameClose` lands on the down-carrier where Germany
   runs **no channel consumer** (`hasChannelConsumer(DirDown) == false` for
   Germany, [`node.go:735-740`](pkg/node/node.go:735)), so nothing acts on it
   until the worker's own `OverflowWait` deadline fires
   ([`carrier.go:955-963`](pkg/mux/carrier.go:955)).
4. Meanwhile DE's shape-A relay keeps reading the target socket and filing
   ≤ 65535-byte frames into the **terminated** stream; IR's `deliver`
   early-returns on `s.terminated`
   ([`carrier.go:792-794`](pkg/mux/carrier.go:792)). Those bytes are dropped
   with no accounting hole — consistent with the retest telemetry
   (`carrier_loss = 0`, all drops on the Iran down-path).

**The asymmetry (the crux):** on the **Iran side**, a slow client *does*
eventually stop the flow — by destroying the stream, cleanly. On the
**Germany side**, nothing stops the flow: the producer has no channel through
which "the far mailbox is full" can reach it. Germany therefore keeps reading
the 1.24 MB object at target pace and filing it into the carrier until the
single down-carrier + IR dispatcher squeezes it into 16 frames, at which point
IR terminates the stream cleanly.

### A.4 Direction-of-write note (why the two directions differ structurally)

Germany is **write-only** on the down direction (`hasChannelConsumer` returns
false for Germany down, [`node.go:735-740`](pkg/node/node.go:735)), so the only
thing DE ever receives from IR on the down carrier is FrameClose/Ping/Pong —
never anything describing the mailbox. The up direction has no data frames
toward Germany at all
([`startUpWatcher` ignores non-nil frames](pkg/node/relays.go:317-319)). **There
is no existing frame in either direction that can carry mailbox state.**

---

## B. EXACT FAILURE MECHANISM (with code anchors)

1. DE reads the target at full pace: `sock.Read(buf)` → `pending`
   ([`relays.go:113-141`](pkg/node/relays.go:113));
   `flushPending` writes ≤ 65535 bytes per frame
   ([`relays.go:192-195`](pkg/node/relays.go:192)).
2. 16 × 65535 = **1,048,560 bytes** is the hard per-stream mailbox ceiling
   ([`carrier.go:401`](pkg/mux/carrier.go:401) + [`queue.go:140-143`](pkg/mux/queue.go:140)).
   A 1.24 MB object = ≥ 20 frames. It **cannot** fit; it must **stream
   through** at the receiver's drain rate.
3. IR `Dispatch` routes each frame into the mailbox via
   [`deliver`](pkg/mux/carrier.go:791). Frames 1..16 (≤ 1,048,560 B) are
   accepted ([`queue.go:178-203`](pkg/mux/queue.go:178)). Frame 17 is refused
   by `fullLocked` ([`queue.go:151`](pkg/mux/queue.go:151)) unless ≥1 frame
   has been popped and written to the client socket in the meantime.
4. Because DE never pauses, the mailbox does not get the chance to drain at
   the client's rate; the 17th frame arrives inside
   `OverflowWait` (default 100 ms) and lands on
   [`failUndeliverableData`](pkg/mux/carrier.go:834) →
   [`terminateStream(s, true)`](pkg/mux/carrier.go:842): the consumer receives
   `nil` (clean end), a best-effort `FrameClose` goes back to DE
   ([`carrier.go:894`](pkg/mux/carrier.go:894)), and both ends tear the stream
   down. Client sees a **truncated download**, not corruption — PASS(a) holds,
   availability fails.
5. **Proof that DE has no per-frame acknowledgement:** frame decoding is
   [`ReadFrame`](pkg/mux/frame.go:94) with a fixed 7-byte header
   (`StreamID`, `Type`, `Length`, `Payload` — [`frame.go:14-18`](pkg/mux/frame.go:14-18));
   there is no sequence, ack, credit, or window field anywhere. `WriteFrame`
   returns only the local socket-write outcome
   ([`carrier.go:548-558`](pkg/mux/carrier.go:548)). The only IR→DE frames are
   `FramePong`, `FrameClose`, and (on the down carrier) nothing else — see
   A.4. Therefore **DE cannot know IR's mailbox occupancy, ever**, under the
   current wire protocol.
6. Graceful delivery requires `average(drain_rate_to_client) ≥
   average(fill_rate_from_target)`. The mailbox (1 MiB) is the only
   elastic buffer, so the client must pop concurrently while DE fills. If the
   client drains slower than DE fills, the mailbox saturates and the stream
   dies. This is a **rate** property, not a capacity property: no
   configuration value can substitute for pausing the producer.

---

## C. PRECISE BACKPRESSURE-PROPAGATION REQUIREMENT — decisive (a)/(b)/(c)

**Answer: (a) absent remote-capacity signal — with a fully quantified partial
(c).**

### C.1 The requirement, formalized

The receiver (IR) must expose, per stream: `free_capacity(id)` =
`MaxFramesPerStream - frames_queued` (and/or
`MaxBytesPerStream - bytes_queued`), a value the tail path already computes
under `q.mu` in [`fullLocked`](pkg/mux/queue.go:140).

The signal must reach the **one goroutine that can act on it**: DE's
`relayShapeA(DirDown)`. Its only reachable action is to park in
[`waitAttach`](pkg/node/relays.go:234), i.e. **stop reading the target
socket**.

**Granularity: per-stream (mandatory).** An aggregate signal
(`TotalQueuedBytes` of the whole carrier) would let one slow client stop
reading for **every** session → carrier-wide head-of-line blocking. IR must
emit per-stream credit for `StreamIDDown`.

### C.2 Decisive analysis of the sender side (does (c) hold?)

Read `WriteFrame` → [`write`](pkg/mux/carrier.go:307):
- It enqueues into `writeCh` (cap 256) and **waits for the writer goroutine
  to complete the socket write** ([`carrier.go:328`](pkg/mux/carrier.go:328)).
- `writeLoop` does one blocking `rwc.Write` per request
  ([`carrier.go:279`](pkg/mux/carrier.go:279)). For the down-carrier that is a
  plain TCP `net.Conn` (DE `net.Listen` → `handleDownConn`,
  [`cmd/germany-splitter/main.go:334,412`](cmd/germany-splitter/main.go:334));
  for the up-carrier it is `wsConn.Write` → `WriteMessage`
  ([`cmd/germany-splitter/main.go:56-61`](cmd/germany-splitter/main.go:56)).

Therefore, **yes, there is a real TCP-window path**: once the IR down-carrier
socket's receive buffer is full, `rwc.Write` blocks, `writeLoop` stops
draining `writeCh`, and after 256 in-flight requests `WriteFrame` itself
blocks — at which point DE's relay stops reading the target socket.

**But (c) is only partially true, and the quantification is the problem:**

1. `writeCh` capacity 256 requests × up to 65542 bytes (7-byte header +
   65535 payload) = up to **16 MiB** (16,777,752 B) of already-serialized
   frames that can be in flight before `WriteFrame` blocks — **16× the
   entire 1,048,560-byte mailbox** that is actually full. Against a 16-frame /
   1 MiB constraint, that is a 16:1 over-commit of the exact resource that is
   exhausted.
2. TCP send+receive buffers (kernel, ~64 KiB–several MiB, not pinned by this
   repo) add further slack: TCP only closes the window when the *kernel*
   buffers fill, which is far above 1 MiB of *application* occupancy.
3. The blocking path is **shared by every stream on the carrier**: when the
   down-carrier's write path backs up, **all** sessions' down-relays park
   together. That is exactly the carrier-wide HOL blocking a mux must avoid.
4. When the mailbox eventually terminates the stream, IR sends
   `FrameClose` — but DE's shape-A relay still holds up to 256 KiB of
   `pending` it will happily flush onto the now-dead stream: `flushPending`
   keeps writing `FrameData` to a terminated stream, which IR's dispatcher
   drops ([`deliver`](pkg/mux/carrier.go:792) early-returns on
   `s.terminated`). Not corruption — but the abort is *late and noisy*, not
   rate-limited.

**Conclusion.** The transport does have a backpressure path, but it engages
at ~16 MiB of instead of ~1 MiB, it is not per-stream, and it cannot be
tightened without shrinking `writeCh` (a global latency/throughput lever that
would hurt every small-object session). Specifically: to make (c) work,
`writeCh` would have to be sized so that
`cap(writeCh) × MaxPayload ≤ MaxBytesPerStream` — i.e. cap ≈ 16 — which would
serialize every stream's writes behind a 16-slot global queue and re-create
exactly the head-of-line blocking Phase 3 removed. **Hence (c) alone cannot
work, and the causal limitation is (a).**

---

## D. DESIGN ALTERNATIVES — 14 questions each

The question list below is the task's enumeration verbatim. That enumeration
contains 15 items (it splits "wire-protocol change" from "reconnect/rebind
generation compatibility"), so the table below has 15 rows and the wire
question is split into Q14a/Q14b rather than merged, so nothing is left
unanswered.

1. Authoritative FC state location
2. How IR communicates free capacity to DE
3. Behavior at zero capacity
4. Does DE stop reading the target socket
5. Cross-stream blocking (HOL)
6. Memory bound equation
7. Behavior under carrier loss / rebind
8. Per-stream frame ordering
9. Half-close safety (client EOF / target EOF)
10. Aggregate session-buffer budget interaction
11. Deadlock possibility
12. Starvation possibility
13. Delayed / lost signal behavior
14. Wire-protocol change
15. Reconnect / rebind generation compatibility

### D1. Explicit per-stream credit frames (WINDOW_UPDATE-style)

New frame type `FrameCredit {StreamID, creditBytes | creditFrames}` sent on
the **down-carrier** IR→DE. Receiver tracks per-stream `credit`; sender
blocks in `flushPending`/`relayShapeA` when credit is 0.

- **Q1:** sender-local per-stream credit counter, owned by the DE shape-A relay
  goroutine; latched only after a valid credit frame (A4). Receiver owns the
  absolute `cumulativeBytesPopped`.
- **Q2:** explicit frame; driven by Pop, so credit is returned exactly when
  the mailbox drains.
- **Q3:** sender stops issuing new DATA frames for that stream and parks
  (does not drop, does not terminate).
- **Q4:** **Yes** — the park site is the **single** gate at the top of
  `relayShapeA`'s loop, before `sock.Read` (see E.2/E.3; **A1** deletes the
  in-`flushPending` variant).
- **Q5:** No — credit is per-stream.
- **Q6:** `Σ_streams min(MaxBytesPerStream, creditWindow) ≤ MaxBytesTotal`
  where **`creditWindow := min(MaxBytesPerStream, creditGranted)`** is the
  effective per-stream allowance (i.e. the smaller of the mailbox's own
  per-stream ceiling and the sender's outstanding credit) — this is the term
  that appears throughout §F and U6. (**A7** — no `+ N·CreditThreshold`;
  `CreditThreshold` is emission hysteresis, not resident bytes).
- **Q7:** credits in flight on a dead carrier are dropped with the carrier;
  the new carrier re-establishes credit at **`CreditInitial` = UNLIMITED** and
  the relay is **not** blocked (A4); establishment is bounded by
  `CreditEstablishTimeout` (**A3**, see I).
- **Q8:** preserved — credit frames ride the same in-order channel and never
  precede DATA (they are not DATA).
- **Q9:** safe; the target-EOF `FrameClose` path ([`relays.go:73-91`](pkg/node/relays.go:73))
  is never credit-gated (**A1**), and **there is no `FINAL_CREDIT` flag**
  (**A6**) — DE's exit is driven by that existing close path.
- **Q10:** `pending` shrinks (producer parks **before** the read), so
  `chargeWait` pressure **decreases** — and, because the gate is only at the
  loop head (**A1**), a parked relay holds **at most** `CreditFloorDrain`
  bytes of aggregate budget at the floor, and **zero** past it (**A2**).
- **Q11:** no deadlock from the credit mechanism itself: credit emission is
  PoP-driven (unconditional on drain), never waiting on the sender. **One
  exception, stated rather than hidden: the bidirectional target-exhaustion
  cycle (Cycle 1, §F Scenario 2), mitigated by the credit-floor guard (A2).**
- **Q12:** no starvation: every pop refunds credit, and credit is absolute so
  duplicates cannot leak window (A5).
- **Q13:** a lost credit frame only delays resume, bounded by
  `CreditEstablishTimeout` (**A3**); after expiry credit reverts to unlimited.
- **Q14:** **new frame type** (`FrameCredit = 0x07`) → in-band negotiation; no
  `AuthVersion` bump (see H).
- **Q15:** Generation compatibility is enforced **structurally**, not by a
  field in the FrameCredit payload (R2-2): a credit frame is only ever
  produced by the CURRENT carrier's readLoop/dispatch on the receiving side;
  a superseded carrier's readLoop has exited, so its frames are never
  delivered. Combined with the un-latched-until-first-valid-frame rule (A4),
  late or stale credit is inert. Credit state reverts to `CreditInitial` =
  **UNLIMITED** on both sides at rebind (**A4**, see I).

### D2. Bounded per-stream intermediate buffering with receiver-paced resume

Keep the mailbox, but make the dispatcher *retry* a refused frame inside a
short grace window (`pendingRetry` + `applyPressure` deadline), so a
transient fill self-heals without terminating.

- **Q1:** mailbox occupancy itself (already authoritative, `q.nBytes` /
  `len(q.items)`).
- **Q2:** **none** — there is no signal; the retry is purely local. DE keeps
  over-feeding; only the *drop* is delayed.
- **Q3:** eventually terminates after the grace deadline — same abort, later.
- **Q4:** **No.**
- **Q5:** No (per-stream).
- **Q6:** `MaxBytesTotal` bounded, unchanged.
- **Q7:** unchanged.
- **Q8:** preserved (single retry slot, FIFO).
- **Q9:** safe.
- **Q10:** unchanged.
- **Q11:** no deadlock (retry is non-blocking, dispatcher-owned).
- **Q12:** same abort rate, slightly later.
- **Q13:** N/A.
- **Q14:** no wire change.
- **Q15:** unchanged from today (no credit state to reset).
- **Verdict: insufficient alone.** This is the earlier "grace" design: it
  raises the 0.024-bound serial transfer's survival only if the mailbox
  happens to drain before the deadline. It does not stop DE reading, so it
  cannot fix the 12/12 failure (the client was *not* slower than the target;
  the producer simply out-ran a 1 MiB hole with 1.24 MB of data).

### D3. Carrier-level TCP backpressure only (no new frame type)

Shrink `writeCh` so the carrier write path saturates near the mailbox size;
rely on TCP window + `pending` cap to park the relay.

- **Q1:** transport (kernel TCP window + `writeCh` occupancy).
- **Q2:** implicitly, by the carrier stalling (no capacity information at all —
  DE cannot distinguish "carrier full" from "mailbox full").
- **Q3:** DE parks in `waitAttach`, indistinguishable from carrier loss.
- **Q4:** Yes, but only after `cap(writeCh)×MaxPayload` bytes are in flight
  (~16.6 MiB today; would need cap ≈ 16 for 1 MiB fidelity).
- **Q5:** **Yes — carrier-wide.** Every stream's relay parks when the carrier
  write path stalls. This is precisely the head-of-line blocking Phase 3
  removed ([`queue.go:22-26`](pkg/mux/queue.go:22)).
- **Q6:** `≤ N·MaxBytesPerStream + cap(writeCh)·MaxPayload + tcp_buf`.
- **Q7:** unchanged (a stalled write path already means loss).
- **Q8:** preserved on the wire.
- **Q9:** safe.
- **Q10:** `pending` grows to its 256 KiB cap first (it stops reading earlier
  than the mailbox saturates) — but per-session, and only after the carrier
  write path stalls.
- **Q11:** a *deadlock risk* exists in the two-way case: DE's up relay
  (target writes) and down relay (target reads) share the carrier; if DE's
  write path is stalled by IR's TCP window while IR's mailbox for the same
  session is stalled by DE's own target socket being blocked... the cycle is
  broken only by the overflow timeout. Fragile.
- **Q12:** possible: one huge stream can slow unrelated streams.
- **Q13:** N/A (no signal to lose) — but no signal to recover with either.
- **Q14:** no wire change.
- **Q15:** no credit state; behavior identical to today across rebind.
- **Verdict: rejected** — Q5/Q11/Q12 fail and the sizing needed for fidelity
  (cap ≈ 16) destroys small-object throughput.

### D4. Hybrid (recommended): per-stream credit + carrier-level aggregate bound + TCP as last resort

Per-stream credit frames (D1) for fairness and availability, **plus** the
existing aggregate `MaxBytesTotal` and TCP window as safety nets (they already
exist; no work). The credit protocol is what gives the *per-stream, correct
granularity* signal; the aggregate/TCP paths remain as hard ceilings.

### D.5 Comparison table

| Q | D1 credit frames | D2 bounded+grace | D3 carrier-TCP | D4 hybrid (rec.) |
|---|---|---|---|---|
| 1 FC state | sender per-stream credit, un-latched=unlimited | mailbox occupancy | transport buffer | sender credit (+ agg ceiling) |
| 2 IR→DE signal | `FrameCredit` on down-carrier | **none** | implicit TCP stall | `FrameCredit` (+ implicit nets) |
| 3 zero capacity | park, no DATA | terminate after grace | park = carrier loss | park, no DATA |
| 4 DE stops reading | **yes, per-stream** | no | yes, carrier-wide | **yes, per-stream** |
| 5 cross-stream HOL | no | no | **yes** | no |
| 6 memory bound | `Σ min(Mb, creditWindow) ≤ Tot` **(A7)** | `≤ Tot` | `≤ Tot + Cap·64K + tcp` | `Σ min(Mb, creditWindow) ≤ Tot` **(A7)** |
| 7 loss / rebind | credits dropped, revert to un-latched/unlimited | unchanged | unchanged | credits dropped, revert to un-latched/unlimited |
| 8 ordering | preserved | preserved | preserved | preserved |
| 9 half-close | safe (target-EOF `FrameClose`; **no `FINAL_CREDIT` flag, A6**) | safe | safe | safe (target-EOF `FrameClose`) |
| 10 agg budget | lowers `pending` pressure; a parked relay holds ≤ `CreditFloorDrain` at the floor, 0 past it (**A1/A2**) | unchanged | raises `pending` first | lowers `pending` pressure |
| 11 deadlock | none **except** the bidirectional target-exhaustion cycle (Cycle 1), mitigated by the **credit-floor guard (A2)** | none | **possible cycle in 2-way** | none **except** Cycle 1, mitigated by the credit-floor guard **(A2, A9)** |
| 12 starvation | none (bounded by the A2 floor + `OverflowWait`) | abort-rate only | **possible** | none (bounded by the A2 floor) |
| 13 lost/delayed signal | resume delayed; `CreditEstablishTimeout` 2 s then revert to unlimited (**A3**) | n/a | n/a | same as D1 |
| 14 wire change | **yes, new frame** | no | no | **yes, new frame** |
| 15 rebind-generation compat | structural enforcement (R2-2: no gen field in payload; superseded carrier's readLoop has exited, frames never delivered; un-latched until first valid frame) | unchanged | unchanged | same as D1 |

**Reading note (A9):** the table no longer asserts more than §F supports. Rows
11 and 12 are stated as *"none except Cycle 1, mitigated by the credit-floor
guard (A2)"* — a named worst case with a named mitigation — rather than a bare
"none". Nothing in this table claims deadlock/HOL/starvation is *proven absent*
for the bidirectional case, and D3's genuinely *possible* cycle is left marked
as such, because D3 has no equivalent guard.

---

## E. RECOMMENDED DESIGN — D4 HYBRID, with state machines and pseudocode

### E.0 Why hybrid/D1 wins

1. **It is the only design whose signal has the right granularity** (per-stream
   `StreamIDDown`), which is what makes both the serial 1.24 MB case and the
   t8/t16/t32 fairness cases pass without carrier-wide HOL (D3 fails Q5/Q11/Q12).
2. **It removes the abort instead of delaying it**: DE parks before the
   mailbox can fill, so `dropped_data_frames` stays 0 (D2 merely postpones it).
3. **It preserves and strengthens the integrity invariant**: with a credit
   gate the sender never over-writes the mailbox, so the refused-DATA path
   becomes a *safety net that should never fire in normal operation*, not the
   primary mechanism.

### E.1 Receiver (Iran) state machine — per-stream credit emission — **[A5, R2-1]**

States: `FLOWING` (outstanding `creditWindow` > 0) → `PAUSED` (the stream's
effective `creditWindow` is down to 0) → `FLOWING`. Credit is **returned on
Pop**, i.e. exactly when bytes leave the mailbox and are handed to the
worker, so emission is unconditional and never waits on the sender.

**Emission is node-side, never in the mux pop path (R2-1).** Two hard
constraints drove this split:

- [`queue.go:61-67`](pkg/mux/queue.go:61) documents the deliberate lock order
  `c.mu → q.mu` and forbids a callback that would take another lock while
  `q.mu` is held — `budgetLimitLocked` is a plain value *precisely* for that
  reason. A carrier write (which needs `c.mu` / the write channel) inside the
  pop path would invert that order.
- `pkg/mux` cannot reach `pkg/node`'s carrier handle at all.

So the design splits into two halves:

**Half 1 — count only, in the mux, under `q.mu`.** The pop path
([`streamWorker`](pkg/mux/carrier.go:951) → [`q.Pop`](pkg/mux/queue.go:214))
does **nothing but add the popped payload bytes to a plain `uint64` counter on
the stream record** (`s.poppedBytesTotal`). It mutates that one counter under
`q.mu` and acquires **no other lock** — no `c.mu`, no carrier write, no
callback. This is the same class of value as `q.nBytes`
([`queue.go:44`](pkg/mux/queue.go:44)).

```
// pkg/mux: streamWorker, Pop path — COUNT ONLY, no second lock
it, ok := q.Pop()                 // under q.mu, as today
q.mu.Lock()
s.poppedBytesTotal += uint64(len(it.payload))   // counter, nothing else
total := s.poppedBytesTotal                       // capture
q.mu.Unlock()                  // q.mu released BEFORE the callback fires
if c.OnStreamPopped != nil { c.OnStreamPopped(s.id, total) }  // node-installed
select { case s.ch <- it.payload: ... }            // handoff unchanged
```

> **Prominent lock rule: NO carrier write while `q.mu` is held.** The pop path
> takes no second lock; `q.mu` is never held across a `c.mu` acquisition or a
> `WriteFrame`/control-frame write.

**Half 2 — emit, in the node, outside `q.mu`.** `pkg/node` installs a new
callback on the carrier, modelled on the two it already installs —
[`OnStreamTerminated`](pkg/node/node.go:468) and
[`OnStreamDataUndeliverable`](pkg/node/node.go:473):

```
c.OnStreamPopped = func(streamID uint32, poppedBytesTotal uint64) {
    // READY-CHECKED RESOLUTION + GENERATION PINNING (rev-3, Note C):
    // resolve through the Ready()-checked variant, not the plain current().
    h, gen := n.currentDownCarrierIfReady()   // n.mu + carrier.Ready(), atomic
    if h == nil { return }   // carrier absent or NOT ready ⇒ drop (inert), A3/§E.5
    pin(gen)                 // the emitter records the generation it emits against
    // BLOCKING HANDOFF (rev-3, Note C) — this is NOT a non-blocking write:
    // -> c.write() [carrier.go:307-329] enqueues on writeCh (cap 256) and then
    //    blocks on <-req.done; writeLoop does one blocking rwc.Write
    //    [carrier.go:279]. Under a saturated or dying carrier this blocks the
    //    streamWorker goroutine until the carrier resolves the request.
    // It must NOT be called while q.mu is held (lock rule, R2-1) — the pop
    // path releases q.mu before firing this callback.
    err := h.WriteFrame(streamID, FrameCredit,
        creditPayload(streamID, creditVersion=1, poppedBytesTotal))
        // same write path as FramePong/FrameClose; CANNOT reorder ahead of
        // this stream's DATA on the same carrier (single writeLoop).
    if err != nil { return } // credit frame INERT: see §E.5 failure policy
}
```

The **streamWorker goroutine** (the one that runs `Pop`) invokes
`OnStreamPopped` *after* it has released `q.mu`; the handler then writes the
`FrameCredit` on the **DOWN** carrier handle with the **pinned generation**,
entirely **outside `q.mu`**.

**This emission is a BLOCKING handoff, not a non-blocking "control-frame path"
(rev-3, Note C — corrected claim).** There is no free control-plane shortcut in
this tree: [`CarrierConn.write`](pkg/mux/carrier.go:307) sends the request on
`writeCh` (**cap 256**, [carrier.go:180](pkg/mux/carrier.go:180)) and then
**blocks on `<-req.done`**, while `writeLoop` performs one **blocking
`rwc.Write`** per request ([carrier.go:279](pkg/mux/carrier.go:279)). So a
credit emission is exactly as expensive as emitting any other frame. See §E.5
for the consequence and the inert-on-failure policy.

### E.2 Sender (Germany) state machine — single credit gate — **[A1, A2]**

DE holds a sender-local, **un-latched** per-stream credit (A4): before the
first valid `FrameCredit` for the stream arrives, `credit = unlimited`
(today's behaviour). On the first valid credit frame it latches, and thereafter
`credit = creditWindow = cumulativeBytesPopped − cumulativeSent` (A5, with the
R2-3 clamp below).

The gate is a **single site**: at the top of the
[`relayShapeA`](pkg/node/relays.go:46) `DirDown` loop, *before* `sock.Read` —
it decides whether to read the next chunk of the target. The in-`flushPending`
gate is **deleted** (A1), so the socket-EOF flush path is never credit-gated
(see E.3).

```
for {
    ...
    // single gate — before any socket read (A1): read the target only when
    // it will not push the mailbox past its per-stream ceiling.
    if creditIsLatched(id) && creditWindow == 0 {
        // A2 credit-floor guard: a parked down-relay still drains the
        // TARGET socket into `pending` up to CreditFloorDrain bytes, so the
        // two-way exhaustion cycle cannot hold; then park.
        n.waitAttach(sess, att)      // bounded by the grace timer
        continue
    }
    nread, _ := sock.Read(buf)       // read the target only when gated-open
    ...
}
```

**Credit-floor guard (A2):** even while parked on credit, the relay keeps
draining the target socket into `pending` up to `CreditFloorDrain` bytes. This
is the single named guard that breaks the two-way target-exhaustion cycle
(Cycle 1, §F) and is what makes M8 not fail against §D1-Q10.

### E.3 Gate ordering — why the EOF flush is never credit-gated — **[A1]**

Against [`relays.go:73-91`](pkg/node/relays.go:73): the loop's first branch
is `if socketEOF { ... }`, which either returns (when `pending` is empty and
`finSent`), sends the close frame, or flushes `pending` to completion — and
**none of these consult the credit gate.** The gate is reached **only** in the
`!socketEOF` fall-through, before `sock.Read`
([`relays.go:113`](pkg/node/relays.go:113)). The EOF flush is therefore
provably never credit-gated: a stream that has reached target-EOF always drains
to completion and half-closes regardless of credit — exactly the half-close
safety (A6, no `FINAL_CREDIT`).

### E.4 `FrameCredit` payload and credit arithmetic — **[A5, R2-2, R2-3]**

`FrameCredit = 0x07`, carried on the **down** carrier (IR→DE). The payload is
**18 bytes and carries NO generation field (R2-2, option b chosen):**

| offset | field | bytes |
|---|---|---|
| 0  | `creditVersion` (uint8, =1; any other value ⇒ reject → unlimited, A5) | 1 |
| 1  | `cumulativeBytesPopped` (**uint64 on the wire**, `binary.BigEndian`) | 8 |
| 9  | `creditWindow` (**uint32 on the wire**, 4 B, `binary.BigEndian` — informational; the defined term, see D1-Q6) | 4 |
| 13 | `flags` (uint8, 0; the `FINAL_CREDIT` bit is absent, A6) | 1 |
| 14 | `reserved` (0, `uint8`; pad to 4 B) | 4 |

**Byte order — `binary.BigEndian`, every field, no exceptions (rev-3, Note A).**
The whole repository is big-endian: the frame header
([`PutUint32`/`PutUint16`](pkg/mux/carrier.go:553) and
[`PutUint16`](pkg/mux/carrier.go:555)) and the reader
([`ReadFrame`](pkg/mux/frame.go:100)) are `binary.BigEndian`, as are the session
encoders (`attachment.go:301`, `attachment.go:313`, `session.go:95`,
`session.go:134`). Every field in this table is therefore written and read with
`binary.BigEndian.*`: **LE would produce frames the peer's `ReadFrame`
mis-parses.** The 18-byte total (1 + 8 + 4 + 1 + 4) is unaffected by byte order.

**No generation field.** Generation compatibility is enforced **structurally**,
not in-band: a `FrameCredit` is only ever **produced** by the **current** down
carrier's readLoop/dispatch on the receiving side; a superseded carrier's
readLoop has already exited, so any credit frame it would have emitted is never
delivered. Combined with the **un-latched-until-first-valid-credit-frame** rule
(A4), a late or stale credit is inert. The phantom `node.go:821` guard
(`gen <= att.LastRebindGen()`) belongs to the `FrameRebind` path
([`handleRebind`](pkg/node/node.go:802)) **only**, and is **not** cited for
credit frames (R2-2).

#### E.4.1 Credit arithmetic: type, clamp, rebind reset, wrap — **[R2-3]**

- **Type / sign (in-memory arithmetic types — NOT wire widths, rev-3, Note A):**
  `cumulativeBytesPopped`, `cumulativeSent`, and `creditWindow` are all
  **unsigned `uint64`** *as the values used by the comparison/subtraction
  arithmetic below*. The in-memory width is deliberately `uint64` so that the
  subtraction is homogeneous and cannot wrap on the `creditWindow` operand. The
  **wire** width is what §E.4's table fixes and is independent: `creditWindow` is
  **4 B big-endian on the wire**, `cumulativeBytesPopped` is 8 B big-endian, so
  the payload total stays **18 bytes (1 + 8 + 4 + 1 + 4)**. No signed value is
  ever stored; the subtraction below is performed with an explicit underflow
  guard.
- **Mandatory clamp (load-bearing, not cosmetic):** DE computes
  `credit = cumulativeBytesPopped − cumulativeSent` **only if**
  `cumulativeBytesPopped >= cumulativeSent`; **otherwise `credit := 0`** (PARK).
  This clamp is reachable during the un-latched / revert-to-unlimited windows,
  where DE sends freely and can outpace the next credit frame; without it the
  unsigned difference would wrap to a huge positive window and silently
  over-credit. It is therefore load-bearing, not cosmetic.
- **Rebind reset (deterministic):** at (re)bind-attach **both** sides reset
  their counters to 0 — IR's `cumulativeBytesPopped` and DE's `cumulativeSent`
  are **both anchored to 0**. This is the rule that avoids a bogus large window
  when §I Step 2's `popped=0` anchor would otherwise meet a stale non-zero
  `cumulativeSent`: the first post-rebind credit frame anchors **both** sides to
  0. Until both are anchored the stream runs un-latched = unlimited (A4), so a
  wrong anchor can never be observed as over-credit.
- **Wrap (one line):** `uint64` overflow at ~18.4 EiB is unreachable for a
  single stream (bounded by `MaxBytesPerStream`/`MaxBytesTotal` and by
  lifetime), so it is documented rather than guarded.

**INCREMENT 3 amendment (A4 latch condition relaxed at one call site).**
[`pkg/node/credit.go`](pkg/node/credit.go) `onCredit` now latches on **ANY**
valid credit frame for the current generation — including the on-attach
**anchor** (`popped = 0`) — rather than only a drained credit (`popped > 0`).
Rationale (live diagnosis): the anchor was the first credit, yet it did not
latch, so while un-latched the sender ran **unlimited**, outran the
per-stream mailbox (`MaxBytesPerStream`), `TryPush` was refused, and the
stream terminated as `data_undeliverable` before any latch could take
effect. The anchor now seeds a safe **initial window** = the carrier's
`MaxBytesPerStream` (derived in `NewNode`, `node.go`; falls back to
`mux.DefaultStreamLimits` when unavailable) so the sender is **bounded from
the first credit**. The integrity invariant is **unchanged**: credit still
only ever PARKS the sender; the `popped < cumSent` clamp to 0 (R2-3) is
preserved; and the refused-DATA `failUndeliverableData` safety net
(`pkg/mux/carrier.go:876`) remains armed and unchanged — `pkg/mux` is not
touched by this fix. The un-latched/unlimited branch is kept only for the
genuine no-credit-yet / mixed-generation case.

### E.5 Pop-path emission — reference pseudocode — **[R2-1]**

The only change to the mux pop path is **counting** under `q.mu`; all emission
is node-side and **outside** `q.mu`.

```
// pkg/mux: streamWorker, Pop path — COUNT ONLY, acquire no second lock
it, ok := q.Pop()
q.mu.Lock()
s.poppedBytesTotal += uint64(len(it.payload))   // counter only, nothing else
total := s.poppedBytesTotal
q.mu.Unlock()                  // q.mu released BEFORE the callback fires
if c.OnStreamPopped != nil { c.OnStreamPopped(s.id, total) }  // node-side, outside
select { case s.ch <- it.payload: ... }

// pkg/node: OnStreamPopped handler — OUTSIDE q.mu, on the streamWorker
// goroutine. BLOCKING handoff on the carrier write path; NOT a non-blocking
// control-frame path (rev-3, Note C). Ready-checked carrier resolution +
// generation pinning required (Note C item 2); a lost credit is INERT (item 3).
func(streamID uint32, poppedBytesTotal uint64) {
    h, gen := n.currentIfReady(session.DirDown)  // Ready()-CHECKED variant, atomic
    if h == nil { return }                       // not ready ⇒ drop (inert)
    // PIN the generation: capture `gen` from this same locked read and emit
    // against it, so a rebind resolved concurrently cannot place this credit
    // frame on a superseded / dying carrier (see §I Step 3).
    if err := h.WriteFrame(streamID, FrameCredit,
        creditPayload(streamID, 1, poppedBytesTotal)) ; err != nil {
        return   // INERT: never terminate the stream, never corrupt data
    }
}
```

**Blocking-handoff consequence (rev-3, Note C item 1 — corrected claim).** The
emission write is a **blocking** handoff, NOT a free non-blocking control-frame
write: [`CarrierConn.write`](pkg/mux/carrier.go:307) sends on `writeCh`
(**cap 256**, [carrier.go:180](pkg/mux/carrier.go:180)) and then blocks on
`<-req.done`, and `writeLoop` performs one blocking `rwc.Write` per request
([carrier.go:279](pkg/mux/carrier.go:279)). Under a saturated or dying carrier
this can **delay the `streamWorker` goroutine that would otherwise drain
`s.ch`** — the receiver's local handoff. The delay is **bounded by the same
write path every other frame uses**, so it introduces **no new unbounded wait**
(no new lock, no new timer); it is the same bound DATA and every control frame
already live under. The emission **must NOT be issued while `q.mu` is held**
(R2-1 lock rule stands, verbatim below) — hence the callback fires strictly
after `q.mu.Unlock()`.

**Failure policy (rev-3, Note C item 3).** If the carrier is **not ready**
(`currentIfReady` returns `nil`), the write fails, or the write races a
`Close` (`ErrCarrierClosed`, [carrier.go:312](pkg/mux/carrier.go:312) /
[carrier.go:292](pkg/mux/carrier.go:292)), the credit frame is treated as
**INERT — drop it.** Do **not** retry, do **not** terminate the stream, and do
**not** alter any DATA ordering. The receiving side's `CreditEstablishTimeout`
plus the revert-to-unlimited rule (A3/A4, §I Step 1) absorbs a missing credit:
the stream simply reverts to pre-fix unlimited behaviour. **A lost credit must
never terminate a stream or corrupt data.**

**Mitigation (rev-3, Note C item 4).** Because a lost/inert credit is absorbed
by revert-to-unlimited, the worst case of the blocking handoff is
**availability** (the sender falls back to unlimited and may hit the original
mailbox-pressure abort), **never integrity** — the refused-DATA safety net
([`failUndeliverableData`](pkg/mux/carrier.go:834)) stays armed on every path.

Because the pop path takes **no second lock**, no pseudocode path acquires a
lock that could invert `c.mu → q.mu` (R2-1 / self-check 1). The existing
M/U test notes assumed in-worker emission; they are amended here: the assertion
point for "credit was returned on drain" is now the node-side
`OnStreamPopped`/`WriteFrame` call (M9), **not** anything inside the mux pop
path.

---

## F. Failure scenarios and worst-case bound

### F.1 Scenario 1 — serial 1.24 MB download (the observed regression)

Under §B, a 1.24 MB object cannot fit the 16-frame / 1 MiB mailbox and must
stream through. With credit, DE parks **before** the mailbox fills, so
`dropped_data_frames` stays 0 and the object completes at the client's drain
rate instead of aborting at the 17th frame.

### F.2 Scenario 2 — two-way target exhaustion (Cycle 1) — **[A2, R2-4]**

Germany has **no shape-A up-relay**: Germany's DirUp is a **shape-B channel
consumer** that writes to the target
([`startChannelConsumer`](pkg/node/node.go:1150)); only **DirDown** runs
[`relayShapeA`](pkg/node/relays.go:46) on `targetConn`. The credit gate that
exists is therefore on **DE DirDown**, and Cycle 1 must gate **that**, not an
"up-relay" that does not exist.

```
   target ─reads─▶ DE DirDown relayShapeA ─[credit gate, parked on credit]  ◀ the gate
   DE DirUp shape-B ─[blocked in sock.Write to target: target recv buf full]
   IR up-mailbox full ─[OverflowWait ⇒ deliver-or-fail]
```

**Real residual chain, all bounded:** DE-DirDown parked on credit **+**
DE-DirUp shape-B blocked in `sock.Write` to the target (target receive buffer
full) **+** IR up-mailbox full → bounded by `OverflowWait`
([`carrier.go:955`](pkg/mux/carrier.go:955)) and the deliver-or-fail rule
([`carrier.go:825`](pkg/mux/carrier.go:825)), then **grace**
([`node.go:430`](pkg/node/node.go:430)) and `finalizeDrain`'s **10 s** timer
([`node.go:1161`](pkg/node/node.go:1161)). The chain **ends in a CLEAN
ABORT**, not "resolves when either client consumes": the A2 credit-floor guard
keeps DE draining the target up to `CreditFloorDrain` so the cycle cannot hold,
and the named timers guarantee the session closes. No DATA is silently
discarded (integrity invariant).

### F.3 Worst-case memory bound — **[A7]**

`Σ_streams min(MaxBytesPerStream, creditWindow) ≤ MaxBytesTotal`, where
`creditWindow := min(MaxBytesPerStream, creditGranted)` is the effective
per-stream allowance (defined once in [§D1-Q6](#d1) and referenced here and in
U6). The unfounded `+ N·CreditThreshold` term is **removed**; `CreditThreshold`
is emission hysteresis, not resident bytes.

---

## G. Tests — **[A8, R2-4]**

### G.1 Unit (pkg/mux)

- **M1–M9** presence confirmed; the emission assertion point is the node-side
  callback, not the mux pop path (E.5 note).
- **M7 `TestBidirectionalUploadDownloadCompletes` (redefined so it can fail
  [R2-4]):** with no up-path credit gate it would otherwise pass with the
  mechanism entirely absent. M7 must therefore **drive the real Cycle-1
  chain** — a target that **stops producing while its receive buffer fills**,
  with DE DirDown parked on credit and DE DirUp shape-B blocked in
  `sock.Write` — and assert **both directions complete OR both fail cleanly
  (session closed via the named timers) with zero corruption.** A test that
  only asserts "upload+download complete under a healthy target" cannot fail
  and is not load-bearing.

### G.2 Integration (pkg/node / e2e-pipe-test)

- **I8:** serial ~1.24 MB download completes with 0 dropped frames (the
  observed 12/12 regression).
- **I9:** two-way upload+download under a stalled target → clean abort,
  0 corruption, bounded by the grace / `finalizeDrain` timers.

---

## H. Wire-protocol / in-band negotiation

`FrameCredit = 0x07` is introduced in-band; **no `AuthVersion` bump** is
required. A receiver that does not understand the new type (an older DE) simply
never latches to credit-gated and stays **unlimited** — i.e. pre-fix behaviour
(revert-to-unlimited ≡ pre-fix, Attack 2), so the introduction is safe and
monotonic.

---

## I. Reconnect / rebind generation compatibility — **[A3, A4, R2-2, R2-3]**

- **Step 1 — establishment timeout (A3).** Bounded `CreditEstablishTimeout`
  (default **2 s**), independent of `Grace`. If no valid credit frame arrives
  for a stream within the window, the stream reverts to unlimited (A4).
- **Step 2 — re-emit on rebind-attach.** On (re)bind, IR re-emits the first
  credit frame for each stream with `popped=0` (the fresh carrier's
  `cumulativeBytesPopped` starts at 0). Per [§E.4.1], **both** sides' counters
  reset to 0 at attach, so DE anchors `cumulativeSent` to 0 and the first
  post-rebind frame anchors **both** sides — no bogus large window.
- **Step 3 — stale-credit enforcement (R2-2, option b).** The `node.go:821`
  `gen <= att.LastRebindGen()` guard is **NOT** cited for credit frames; it is
  `FrameRebind`-only ([`handleRebind`](pkg/node/node.go:802)). The **actual
  enforcement that exists** is structural: a credit frame can only be
  produced/dispatched by the **current** down carrier of the receiving side
  (a superseded carrier's readLoop has already exited, so its frames are never
  delivered), plus the **un-latched-until-first-valid-credit-frame** rule (A4).
  `FrameCredit` carries **no generation field** (§E.4).

---

## U. Invariants recap

- **Integrity invariant (unweakened):** ordered DATA is either delivered or the
  stream is explicitly terminated; **DATA is never silently discarded.**
  `FrameCredit` is described throughout as an **optimization**; the refused-DATA
  path ([`failUndeliverableData`](pkg/mux/carrier.go:834)) remains an **armed
  safety net** on every path.
- **No new path silently discards DATA:** credit can only *park* the sender; it
  never drops a queued byte. The only byte loss is the existing clean stream
  termination (A.5).
- **U6 — memory bound:** `Σ_streams min(MaxBytesPerStream, creditWindow) ≤
  MaxBytesTotal`, with `creditWindow := min(MaxBytesPerStream, creditGranted)`
  (defined in [§D1-Q6](#d1), referenced here and in §F.3).
- **Lock rule (R2-1):** NO carrier write while `q.mu` is held; credit emission
  is node-side, outside `q.mu`, and acquires no second lock in the pop path.
  Emission is a **blocking** carrier handoff (§E.5) whose delay is bounded by
  the same write path every frame uses; the emitter resolves the carrier
  through the **Ready()-checked** [`currentIfReady`](pkg/node/node.go:360)
  with the generation pinned, and drops (inert) any credit that cannot be
  written.
