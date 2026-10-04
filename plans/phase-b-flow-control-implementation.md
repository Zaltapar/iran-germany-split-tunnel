# Phase B — Credit Flow-Control: Implementation-Ready Design

> **Checkpoint 1.** This document is the Phase B design for the credit
> flow-control system, reconciled **against the Phase A code that ACTUALLY
> shipped** on `origin/main @ fbe7604` (the credit-free build that still
> delivers 0 bytes for a 1 MiB down transfer), not against the prose of
> [`plans/flow-control-architecture-v2.md`](flow-control-architecture-v2.md).
>
> **Document-only.** No production code, test, config, systemd unit, or the
> historical `plans/flow-control-architecture-v2.md` is modified. No deploy,
> no SSH, no build. Every claim below cites `path:line` against the shipped
> tree. Where the v2 design doc's prose disagrees with what shipped, this
> document states the **correction** (Section 1).
>
> Ground truth (measured, rc-scored, live staging):
> - Raw ceiling **121.4 MiB/s**.
> - 1 MiB DOWN single-stream → **0 bytes delivered**; 4/8/16 MiB abort via
>   `dropped_data_frames+1` → `session_close_reason{data_undeliverable}`
>   ([`pkg/mux/qstats.go:54`](../pkg/mux/qstats.go:54),
>   [`pkg/node/metrics.go:508`](../pkg/node/metrics.go:508)).
> - UP clean to 4 MiB; a **separate** carrier-reset defect between 4–8 MiB is
>   **out of Phase B scope** (v2 §14).
> - Classification: **D — splitter implementation**: the down-mux `TryPush`
>   refusal (`failUndeliverableData`, [`carrier.go:891`](../pkg/mux/carrier.go:891))
>   terminates the stream instead of backpressuring. Phase B makes the sender
>   pace to the receiver's credits so the mailbox never trips
>   `fullLocked`/`rejectAggregate`.

---

## REV 1 — resolved findings (audit map)

> This REV 1 pass resolves the 5 blockers (B1–B5), 8 should-fixes (S1–S8), and
> notes (E, O1, O2, O4) raised by the independent adversarial review of REV 0.
> Where a REV 1 change alters an earlier decision (UNLATCHED bound, anchor
> emission point, `MaxBytesTotal`, `SanitizeLimits` signature, writer-loop
> fairness), it is changed **consistently in every dependent section** (§5, §7,
> §9, §10, §11, §13, §14, Appendix). The approved architecture doc
> (`plans/flow-control-architecture-v2.md`, Architecture C) wins any conflict;
> each such conflict is recorded explicitly, not silently.

| Finding | Resolution | Where resolved |
|---|---|---|
| **B1** over-ack on partial write | Enforced shape `if nw, err := sock.Write(frame); err == nil && nw == len(frame) { credit nw } else { no credit; session closing }`; invariant **`Σ bytesConsumed ≤ Σ bytes actually written`** asserted as an invariant, not a threshold; `TestCreditEmitterNoOverAckOnPartialWrite` gates Slice 4; loopback invariant gates Slice 8 | §2, §11 (Slices 4/8), §12 |
| **B2** no anchor on fresh carrier + UNLATCHED = full cap | Anchor redefined as an **emitter-side credit emitted at attach time** (`bytesConsumed=0`, `creditGen=peerGen` from [`node.go:802`](../pkg/node/node.go:802)), emitted from `handleRebind` (Slice 6), not `startStreamRelay`; UNLATCHED bounded by `creditWindowMax + creditUnackedAllowance` = **640 KiB from attach** (not `MaxBytesPerStream`); `TestCreditGatePreLatchIsBounded` in Slice 2 | §5, §7, §11 (Slices 2/6), §14 |
| **B3** credit emission vs blocking-sensitive contexts | Explicit constraint: **no credit may be emitted from a context that must not block** (mux `Dispatch` / `OnNewStream`); the anchor is emitted from a spawned goroutine or the epoch's consumer goroutine; >64-session anchor drop is safe (cumulative) on cap-64 `ctrlCh` | §4, §11 (Slice 6) |
| **B4** gate has no wake channel | `creditLedger.ready chan struct{}` closed-and-replaced on each accepted credit that lowers `outstanding` (mirror of `StreamQueue.wake`/`wakeLocked`, [`queue.go:162`](../pkg/mux/queue.go:162)–[`168`](../pkg/mux/queue.go:168)); `creditPark` selects on it; `TestCreditGateWakesOnCredit` is a **MUST test in Slice 2** (before any wiring) and fails outright on the REV 0 design | §5, §9, §10, §11 (Slice 2), §12 |
| **B5** 8 MiB ⇒ 12th stream drops | `MaxBytesTotal` raised to **16 MiB** (23 full mailboxes: 23 × 704 KiB = 15.81 MiB ≤ 16 MiB); §6 arithmetic table amended; deviation from the approved doc's 8 MiB **recorded explicitly** as a reviewer-approved amendment; the ~65.2 MiB fixed floor dominates, so the memory argument is unaffected | §6, §11 (Slice 7), §14 |
| **S1** clamp reads node config | The clamp reads the **sender's carrier** limits — `c.limits` set by `SetStreamLimits` ([`carrier.go:483`](../pkg/mux/carrier.go:483)), reached via `n.current(dir)` ([`node.go:344`](../pkg/node/node.go:344)) through a new `CarrierConn.Limits()` accessor | §5, §11 (Slice 5), Appendix |
| **S2** uint64-wrap paragraph is noise | Deleted; replaced by the exact argument: generation is strictly-increasing and never-reused; `gen==0` is rejected up front; `!=` ([`frame.go:244`](../pkg/mux/frame.go:244)) makes wrap unreachable, so the check is exact | §7 |
| **S3** `recordSent` charged per `flushPending` call | Charge is **per chunk** — `n = len(chunk)` after each successful `WriteFrame` in the [`relays.go:277`](../pkg/node/relays.go:277)–[`295`](../pkg/node/relays.go:295) loop (a 256 KiB flush would otherwise overshoot the 64 KiB-granular gate 4×) | §5, §11 (Slice 5) |
| **S4** inconsistent 1 MiB baseline | A/B baseline re-anchored to the **no-credit build's raw ceiling (121.4 MiB/s)**, measured at t=0 on a small 16 KiB transfer; a 0-byte transfer has no rate, so the ~1,372 KB/s figure is deleted | §12 |
| **S5** `SanitizeLimits` change breaks `queue_test.go:127` | The approved doc wins: `SanitizeLimits` returns **`(StreamLimits, error)`** and fails loudly (v2 §10.4 ~:1600–1613 — the mux is the only place that sees the pair); call sites updated (`carrier.go:436` def, `:483`, `SetStreamLimits`, config path); the [`queue_test.go:127`](../pkg/mux/queue_test.go:127) amendment (silent-reset assertions at `:143`–`:151`) is **named in Slice 7's gate** | §11 (Slice 7), §14 |
| **S6** emitter key ambiguity | The emitter's per-stream record is keyed by **`(carrier, streamID)`** — up and down are separate carriers, so the pair is unambiguous on the rebind-reset path (stated, not implied) | §2 |
| **S7** missing admission counter | `credit_gate_admission_deferred` added — a stream parked before attach because the funded count was exceeded; without it the 12th-stream case is invisible (the same D4 blind-counter mistake) | §13 |
| **S8** silent degradation | `credit_degraded_reason{no_credit_peer, timeout}` added as a **fixed enum**, so a `SAFELY_CAPPED` degradation is operator-visible per reason | §13 |
| **E** writer-loop "strict priority" | Replaced with the accurate claim: **priority peek + arbitrary hand-off** (both-ready → Go's uniform-random select); starvation analysis added (credits rate-bounded by socket writes, 39 B each; ≈ 1.9 k/s carrier-wide at 121.4 MiB/s with 64 KiB batching — negligible bytes, non-free scheduling) | §4 |
| **O1** per-stream fairness of `ctrlCh` | Stated: a stream that never gets a slot out of the cap-64 `ctrlCh` **stalls its window while others drain**; bounded (cumulative heal) and visible via `credit_dropped_full` + `credit_gate_admission_deferred` | §4 |
| **O2** FINAL flag acceptance | Confirmed the receiver **accepts** `flags=1`: bit0 FINAL is explicitly allowed; bits1–7 reserved are rejected by `ValidateCreditPayload` ([`frame.go:293`](../pkg/mux/frame.go:293)); FINAL semantics defined (accepted, not an error — [`frame.go:156`](../pkg/mux/frame.go:156)) | §3 |
| **O4** rebind anchor-drop | `rebindDirection` ([`node.go:637`](../pkg/node/node.go:637)) iterates every session; the per-stream anchor into cap-64 `ctrlCh` drops at >64 concurrent sessions — **safe** (cumulative-absolute) and visible via `credit_dropped_full` / `credit_gate_admission_deferred` | §3, §4, §11 (Slice 6) |

## REV 2 — resolved findings (audit map)

| Finding | Resolution | Site |
|---|---|---|
| **SF-1** B1 partial-write stub type ambiguous | Named the concrete fake `faultSock` ([`relay_upread_test.go:35`](../pkg/node/relay_upread_test.go:35)), extended with a short-write mode `Write → (len(b)-5, nil)`; all other `net.Conn` methods no-op/panic. `netConn` is a **type alias to `net.Conn`** ([`relays.go:29`](../pkg/node/relays.go:29)); `startStreamRelay` ([`relays.go:424`](../pkg/node/relays.go:424)) takes **no** socket param — it reads `sess.TargetConn`/`sess.ClientConn`, so the fake injects via the session conn field. A real `net.TCPConn` **cannot** yield `(short, nil)` (stdlib couples `n<len(p)` to `err!=nil`) — a real TCP socket is NOT used. Stated in Slice 4's gate. | §11 (Slice 4) |
| **SF-2** B2 anchor no-wake unstated | Added one sentence to §5 `onCredit`: an anchor (`bytesConsumed==0`) sets `l.latched=true` with `consumed=0`/`lowered=false`, so `l.wakeLocked()` is NOT called; a later zero-consumed credit is likewise a no-op and also does not wake. Correct because the pre-latch sender is not parked (bounded by `creditPreLatchBound`), so nothing needs waking. | §5 |
| **SF-3** S5 call-site enumeration incomplete | Wrote the complete verified list: def [`carrier.go:436`](../pkg/mux/carrier.go:436), `SetStreamLimits` body [`carrier.go:483`](../pkg/mux/carrier.go:483), `node.go:142` `Config.Sanitize()` (= the `NewNode` site, now lined). `SetStreamLimits` gains an **`error`** return. `cmd/*/main.go` helpers confirmed unaffected. Slice 7's gate now names every edited file. | §11 (Slice 7), §14 |
| **SF-4** S1 `Limits()` locking unspecified | Added to §5: `CarrierConn.Limits()` acquires `c.mu`, copies the struct, releases before returning; caller uses the copy lock-free; no `c.mu` held while parked. Cited the true mutation site + lock (`carrier.go:482`/`483`). | §5, §11 (Slice 5) |
| **N-1** B3 anchor-goroutine leak window | Stated that the `go emitAnchor` spawned from `handleRebind` outlives `rebindDirection`; if the carrier dies first `TryWriteControlFrame` returns `(false, ErrCarrierClosed)` and the goroutine drops silently (observes `n.ctx`/`c.closing`), never blocks (drop-on-full), and cannot leak indefinitely (bounded by a `select` on `n.ctx.Done()`). | §4 |
| **N-2** B5 truncation wording | "23.0 full mailboxes" → "**23 full + ~56 KiB slack; the 24th trips `rejectAggregate`**". | §6 |
| **N-3** B4 harmless re-park | Noted that a `creditPark` timeout with a credit in flight is harmless: the credit closes `l.ready`, so the next `canSend` exits immediately — do not add a second timeout. | §5 |
| **N-4** stray comment outside a code fence | Moved the `// writeOne` comment + body inside its own code fence in §4. | §4 |

---

## 0. Reading guide & scope

Phase B ships the *behavioural* half of v2: the credit **gate on the DATA
sender**, the credit **emitter on the socket-Write-completing receiver**, and
the **`ctrlCh` control-plane priority** in the mux. Phase A already shipped
the wire codec + parse/validate + the `AuthVersion=2` bump and the `Dispatch`
`FrameCredit` case (a no-op). This document:

1. reconciles the v2 prose to what actually shipped (Section 1);
2. names every new symbol, struct field, signature, file, lock, and failure
   mode (Sections 2–10);
3. gives the ordered, independently-buildable slices with exact gate commands
   (Section 11);
4. gives the Phase B test matrix, metrics, config, and rollback (Sections 12–15).

Directions used throughout: **DOWN** = target → client (the failing path).
**DATA sender** for DOWN = the node reading the target and writing `FrameData`
on the down carrier (`relayShapeA` `DirDown`, `flushPending` →
`WriteFrame`). **Receiver** for DOWN = the node consuming the down stream and
writing to the client socket (`startStreamRelay`, `sock.Write`,
[`relays.go:467`](../pkg/node/relays.go:467)). The credit travels **back to
the DATA sender** on the sender-facing carrier; its `creditGen` is validated
against the generation of the carrier handle the credit **arrived on**.

---

## 1. Phase A reconciliation table

v2 §5.4 is a "decisions-only" record of Phase A. The table below verifies each
design-doc claim against the **shipped** symbol and flags every correction the
prose needs.

| # | v2 design-doc claim | Shipped code (`path:line`) | Verdict / correction |
|---|---|---|---|
| R1 | `FrameCredit = 0x07` exists | [`frame.go:72`](../pkg/mux/frame.go:72) | Confirmed. |
| R2 | `AuthVersion` bumped 1→2, verified before MAC on all 3 handshake msgs | [`auth.go:108`](../pkg/mux/auth.go:108); checks at [`auth.go:232`](../pkg/mux/auth.go:232) (`verifyResponse`), [`auth.go:381`](../pkg/mux/auth.go:381) (challenge), [`auth.go:398`](../pkg/mux/auth.go:398) (confirm) | Confirmed. A v1 peer dies **at auth** with `ErrAuthVersion` ([`auth.go:153`](../pkg/mux/auth.go:153)) — it never reaches `Dispatch`. **Upgrade implication:** the v2 doc §5.2 "atomic upgrade" is now *enforced by the auth layer itself*, not by convention: a partially-upgraded pair cannot even handshake. Section 11 states what else gates the upgrade (there is nothing else — auth is the gate). |
| R3 | `CreditPayload` struct, `Encode/DecodeCreditPayload`, `ValidateCreditPayload`, `ClampCreditWindow`, `StaleCreditGeneration` | [`frame.go:179`](../pkg/mux/frame.go:179), [`:190`](../pkg/mux/frame.go:190), [`:206`](../pkg/mux/frame.go:206), [`:281`](../pkg/mux/frame.go:281), [`:228`](../pkg/mux/frame.go:228), [`:244`](../pkg/mux/frame.go:244) | Confirmed. All present. |
| R4 | 39-byte frame = 7 B header + 32 B payload; field offsets | [`frame.go:121`](../pkg/mux/frame.go:121) (offset table), [`:146`](../pkg/mux/frame.go:146) (`CreditPayloadSize=32`), [`:188`](../pkg/mux/frame.go:188) (encode) | Confirmed exactly. |
| R5 | Connection-level sentinels `ErrCreditUnknownStream`, `ErrCreditMalformedLength` | [`frame.go:168`](../pkg/mux/frame.go:168), [`:176`](../pkg/mux/frame.go:176); enforced in `readLoop` [`carrier.go:272`](../pkg/mux/carrier.go:272)–`288` | Confirmed. **Correction to v2 §5.3/§12 Slice 2:** the doc's *Slice 2* ("Add FrameCredit type and payload … `Dispatch` switch") is **already shipped**; Phase B must not re-do it. `Dispatch`'s `FrameCredit` case is at [`carrier.go:800`](../pkg/mux/carrier.go:800)–`824`, and the `default:` unknown-type drop is at [`carrier.go:827`](../pkg/mux/carrier.go:827) — **not** `carrier.go:770` as v2 §N4/§5.2 cite. Update all those line references to `:827`. |
| R6 | `readLoop` pre-Dispatch checks: stream-0 credit → `ErrProtocolViolation`; unregistered → `ErrCreditUnknownStream`; len≠32 → `ErrCreditMalformedLength` | [`carrier.go:272`](../pkg/mux/carrier.go:272)–`288` | Confirmed. Note the **unregistered-stream rule is CONNECTION-level** (carrier terminated), not stream-level — a legitimate credit sender only targets an established stream. v2 §5.4 "Discrepancy noted" already records this; keep it. |
| R7 | `ValidateCreditPayload` does **not** reject an over-cap window; it **clamps** via `ClampCreditWindow` to `MaxBytesPerStream` | [`frame.go:228`](../pkg/mux/frame.go:228), [`:267`](../pkg/mux/frame.go:267) (doc comment: "windowGranted exceeding the cap is a CLAMP … not a reject") | Confirmed as a **deliberate Phase A decision** (v2 §5.4). **Correction:** v2 §6.5's `onCredit` sketch shows an ambiguous `if w > mux.MaxPayload` comment; the shipped, authoritative clamp is to **`MaxBytesPerStream`**, not `MaxPayload`. Phase B's sender gate must call `mux.ClampCreditWindow(w, maxBytesPerStream)` and adopt that value as its `window`. |
| R8 | Phase A `Dispatch` `FrameCredit` case is a **no-op** for valid credits; a comment notes `OnStreamPopped` is not wired | [`carrier.go:800`](../pkg/mux/carrier.go:800)–`824`, comment at [`carrier.go:815`](../pkg/mux/carrier.go:815) ("the credit ledger and OnStreamPopped wiring are Phase B") | Confirmed. Phase B's job: replace this no-op with the `OnStreamCredit` callback dispatch (Section 4/5) and wire `OnStreamPopped`-equivalent accounting at the socket-Write point (Section 2). |
| R9 | No `OnStreamPopped`/`OnStreamCredit`/`creditLedger`/`creditGate`/`creditPark`/`ctrlCh`/`ctrlWG`/`drainCtrl`/`setInitialWindow`/`TryWriteControlFrame`/`WriteControlFrame`/`relay_credit*` symbols exist | full-tree grep (verified in the task brief) | Confirmed — **all of these are introduced by Phase B** (Section 2, symbol set). |
| R10 | 19 test functions in `pkg/mux/frame_credit_test.go` covering the 13 required cases | [`frame_credit_test.go:72`](../pkg/mux/frame_credit_test.go:72)–`613` (`TestCreditEncodeDecodeRoundTrip` … `TestCreditPropertyRoundTripAndMutations`) | Confirmed. Phase B adds **node-side** tests only (Section 12); the mux codec tests stay as-is. |
| R11 | v2 §11.1 lock-ordering citation "carrier.go:1024-1026" | shipped `Close` comment at [`carrier.go:1080`](../pkg/mux/carrier.go:1080) ("q.mu is never taken while c.mu is held … acyclic") | **Line-number drift:** the invariant comment moved to `:1080` in the shipped tree. The *claim* (no `c.mu→q.mu` nesting) is correct. Phase B's new locks are leaf locks (Section 9) and must preserve this. |
| R12 | v2 §7.2 cites `carrier.go:307-329` (write) and `:1004-1016` (writeWG/drainWrites) for the ctrlCh mirror | shipped `write` at [`carrier.go:337`](../pkg/mux/carrier.go:337), `writeWG` at [`carrier.go:70`](../pkg/mux/carrier.go:70), `drainWrites` at [`carrier.go:366`](../pkg/mux/carrier.go:366), `Close` drain sequence at [`carrier.go:1072`](../pkg/mux/carrier.go:1072)–`1073` | **Line-number drift** (file grew after Phase A edits). Phase B mirrors these against the *current* line numbers in Section 4. |

**Bottom line of reconciliation:** Phase A shipped **more** than v2 §5.4's
prose implies in one respect (the `readLoop` connection-level checks and the
`Dispatch` case are real, tested code), and its §12 "Slice 2" is fully
**already done**. Phase B's true remaining work is: (a) `ctrlCh`/`ctrlWG`/
`drainCtrl` + `writeLoop` priority rewrite in the mux, (b) `TryWriteControlFrame`
+ blocking `WriteControlFrame`, (c) `OnStreamCredit` callback, (d) the
`creditLedger`/`creditGate` sender side, (e) the `creditEmitter` receiver side,
(f) the `relayShapeA` gate hook, (g) rebind-attach reset + **attach-time** anchor
credit, (h) the `704K/16MiB` limit change (B5 amendment) + loud `Sanitize`
(`(StreamLimits, error)`, S5) validation, (i) metrics, config, rollback.

---

## 2. Receiver side: credit emission (socket-Write completion)

**Where the counter lives (S6).** One `creditEmitter` per **node**, with a
per-stream record keyed by **`(carrier, streamID)`**: the node's
carrier-handle generation for that direction (`n.current(dir).gen`,
[`node.go:481`](../pkg/node/node.go:481)) paired with the `streamID`
(`streamIDOf(sess, dir)`, [`node.go:1185`](../pkg/node/node.go:1185)).
Up and down are **separate carriers**, so the pair is unambiguous on the
rebind-reset path: a rebind of the down carrier (new handle gen) can never
collide with an up record sharing the same `streamID` value — the new
carrier simply starts a fresh record. The per-stream record holds the two
counters that make the credit **cumulative-absolute**:

```
// pkg/node/credit.go (new)
type creditEmitter struct {
    mu       sync.Mutex                  // leaf; guards byStream only
    byStream map[carrierKey]*streamCredit // keyed by (carrier, streamID) — S6
    n        *Node
}

// carrierKey: the node's carrier-handle gen for the direction
// (n.current(dir).gen, node.go:481) + the logical streamID.
type carrierKey struct {
    handleGen uint64
    streamID  uint32
}

type streamCredit struct {
    consumed   uint64   // cumulative bytesConsumed for the current gen (monotonic, resets to 0 on rebind-attach)
    pending    uint64   // consumed bytes not yet carried in a written credit
    peerGen    uint64   // the SENDER's carrier gen, learned from the last FrameRebind payload; stamped into creditGen
    lastEmit   time.Time
}
```

**Mutex.** `creditEmitter.mu` is a **leaf lock** (never held while taking
`c.mu` or `q.mu`). The counter update happens in the `startStreamRelay`
goroutine **after** `sock.Write(frame)` returns successfully
([`relays.go:467`](../pkg/node/relays.go:467)), a point at which that
goroutine holds **no mux lock** — it has already popped the frame from the
stream channel and is writing to the socket. This is the v2 §6.1 "authoritative
release point (c)": the byte is accepted by the client kernel TCP stack, so it
is "consumed" and the tunnel may tell the sender it is free to send more.

**Exact update site (B1).** In [`startStreamRelay`](../pkg/node/relays.go:424),
the shipped write site ([`relays.go:467`](../pkg/node/relays.go:467)) is
`if _, err := sock.Write(frame); err != nil` — it **discards `n`** and
credits only in the `err == nil` branch. Today `net.Conn` couples
`n < len(frame)` to `err != nil`, so the two are equivalent — but nothing in
the REV 0 design or test matrix would catch a future refactor (a buffered
writer, an `io.Writer` wrapper, an API change) that returns
`n < len(frame)` with `err == nil` and silently over-acknowledges bytes
that never reached the client. Phase B therefore specifies the **code
shape that enforces the invariant**:

```
// relays.go, startStreamRelay — enforced write/credit shape (B1):
nw, err := sock.Write(frame)
if err == nil && nw == len(frame) {
    n.creditEmitter.recordConsumed(carrierKeyFor(sess, dir), uint64(nw))
} else {
    // failed OR partial write: credit NOTHING; the session is closing.
    n.metrics.Error()
    sess.Close(sockWriteErr(dir))
}
```

`recordConsumed` bumps `consumed` and `pending` (by exactly `nw` — never
`len(frame)`), and if `pending >= creditBatchBytes` (or
`time.Since(lastEmit) >= creditBatchMaxAge`), calls `emit`. **No new lock on
this path beyond the emitter leaf lock.**

**Over-ack invariant (B1).** The soundness invariant of the whole credit
system is **`Σ bytesConsumed ≤ Σ bytes actually written to the client
socket`**, asserted as an **invariant (never violated), not a threshold**.
A partial write that returned `nw < len(frame)` may be credited with at most
`nw` — and the enforced shape above instead closes the session and credits
nothing. Slice 4's gate test `TestCreditEmitterNoOverAckOnPartialWrite` (a
`net.Conn` stub whose `Write` returns `(len(frame)-5, nil)` — `err == nil`
with a short write) proves the no-over-ack property, and Slice 8's loopback
asserts the Σ invariant directly (Section 11).

**Half-duplex / already-half-closed client.** `peerEOF` half-closes the client
socket write side ([`relays.go:344`](../pkg/node/relays.go:344), `closeWrite`).
When the peer has half-closed, `startStreamRelay`'s `frame == nil` branch
([`relays.go:455`](../pkg/node/relays.go:455)) calls `peerEOF` and returns —
the relay stops, and any remaining `pending` is **force-flushed once** with
the `CreditFlagsFinal` bit (Section 3, `finalize`). No further `sock.Write`
occurs, so `recordConsumed` is not called again; the counter is simply done.
Because `consumed` is cumulative, the final credit carries the **last**
absolute value, so nothing is lost.

**`sockWriteErr` path (B1).** If `sock.Write` **fails or is short**
([`relays.go:467`](../pkg/node/relays.go:467) → `sess.Close(sockWriteErr(dir))`),
the relay returns and the stream ends. **Do NOT emit a credit on a failed or
partial write** — un-accepted bytes were not consumed, and creding `len` for
a short `n` is the over-ack class B1 forbids. The credit counter for that
stream is invalidated when the session ends; `creditEmitter` drops the record
in `onSessionClosed` (Section 7).

**Overflow behaviour / non-regression proof.** `consumed` and `pending` are
`uint64`. Within one carrier generation `consumed` only ever increases
(`recordConsumed` adds, `emit` subtracts into `pending` but never into
`consumed`), so it is **monotonic non-decreasing**; it cannot regress. A wrap
requires writing 2^64 bytes ≈ 16 EiB on one stream — not achievable
(limits are MiB-scale; a generation lasts seconds-to-minutes). On rebind,
`consumed` is reset to 0 **and** `peerGen` is advanced (Section 7), so a stale
credit from the previous gen is rejected by the gen check, not by the
monotonicity check. `pending` is bounded by `creditBatchBytes` (one emission
cycle) and resets to 0 after a successful `emit`; on a **dropped** emit it is
kept so the next `emit` carries the cumulative `consumed` (safe, Section 3).

**`bytesConsumed` vs `windowGranted` computation.** `bytesConsumed` = the
stream's `consumed` (cumulative, since gen-reset). `windowGranted` = the
emitter's current advertised window for that stream: `creditWindowMax`
(= 512 KiB, Section 5) in the initial/adapted model; **clamped on receipt** by
the sender via `mux.ClampCreditWindow`. The receiver advertises
`windowGranted` = the window it wants the sender to use, so it is a **hint**,
not a hard cap (the hard cap is the mailbox, Section 6).

---

## 3. Credit-emission batching + `TryWriteControlFrame`

**The rate-risk.** Emitting one `FrameCredit` per 32 KiB `Pop` is the D4
throttle's mechanism (v2 §0.5/§1). Batch instead:

- **Byte threshold** `creditBatchBytes = mux.MaxPayload` (64 KiB) — one credit
  per 64 KiB consumed (not per 32 KiB).
- **Time threshold** `creditBatchMaxAge` (default 100 ms) — so a slow,
  trickle-then-burst consumer is not starved of a credit; and a
  half-close/`finalize` flushes the partial `pending` immediately.
- Both are OR-ed in `recordConsumed`; `finalize` (half-close) is a forced
  emit regardless of size.

**FINAL flag semantics (O2).** The half-close force-flush (Section 2) emits
with `CreditFlagsFinal` (`flags = 1`). The receiver's `ValidateCreditPayload`
([`frame.go:281`](../pkg/mux/frame.go:281)) enforces `p.Flags &
CreditFlagsReservedMask != 0 → "reserved-flags"`: bit0 (`CreditFlagsFinal`,
[`frame.go:156`](../pkg/mux/frame.go:156)) is **explicitly allowed** ("when
set, no further credits are expected for this stream (accepted, not an
error)") while bits 1–7 are reserved and rejected. So `flags=1` is accepted
by the validator; **no Phase B change to `ValidateCreditPayload` is
required** — the FINAL bit is already in the allowed mask, and the semantics
("terminal, cumulative-absolute, no further credits") are defined by the
validator's doc comment.

**Non-blocking enqueue, drop-on-full.** `TryWriteControlFrame`
(Section 4) enqueues the encoded 39-byte credit on `ctrlCh` **without
blocking**. On a full `ctrlCh` (cap 64) it **drops** and returns
`(false, nil)`.

**What is lost on a drop — and why it is safe (O4).** Because `bytesConsumed`
is **cumulative-absolute**, a dropped credit loses *nothing durable*: the next
credit (next batch, next flush, or the half-close `finalize`) carries the
running `consumed` total, which already includes every byte the dropped one
would have reported. The only effect of a drop is a **delay** in the sender
re-gating — the sender keeps `outstanding` high for one extra batch cycle.
This is the exact property v2 §7.5 relies on: "the next credit carries the
cumulative `bytesConsumed`, so no information is lost." The drop counter
`credit_dropped_full` (Section 13) makes this observable so an operator is
not blind. **Consequence for the attach-time anchor (O4):** `rebindDirection`
([`node.go:637`](../pkg/node/node.go:637)) iterates *every* eligible session
and enqueues one anchor credit per stream into the cap-64 `ctrlCh`; beyond
**64 concurrent sessions on one carrier**, the excess anchors **drop on
full** — and the drop is **safe** by the cumulative-absolute property above
(the first non-dropped anchor, or the next ordinary credit, re-latches the
sender at the correct cumulative value). It is *visible*, never silent:
`credit_dropped_full` + `credit_gate_admission_deferred` (S7) count the
deferral. At ≤64 concurrent sessions on one carrier, no anchor drops.

---

## 4. `ctrlCh` + `ctrlWG` + `drainCtrl` + writer-loop change

All in [`pkg/mux/carrier.go`](../pkg/mux/carrier.go). Mirror the existing
`writeCh`/`writeWG`/`drainWrites` discipline exactly (shipped at
[`carrier.go:180`](../pkg/mux/carrier.go:180), [`:70`](../pkg/mux/carrier.go:70),
[`337`](../pkg/mux/carrier.go:337), [`366`](../pkg/mux/carrier.go:366),
[`1072`](../pkg/mux/carrier.go:1072)–`1073`).

**New `CarrierConn` fields:**

```
ctrlCh   chan writeReq       // cap 64 — control frames only
ctrlWG   sync.WaitGroup      // mirror of writeWG
// (drainCtrl is a method, not a field)
```

Constructed in `newCarrierConn` ([`carrier.go:177`](../pkg/mux/carrier.go:177)):
`ctrlCh: make(chan writeReq, 64)`. `live` count is unchanged (ctrlCh has no
goroutine of its own; the single `writeLoop` consumes both).

**`writeLoop` rewrite — priority peek + arbitrary hand-off (REV 1 E).** The
loop first **peeks** `ctrlCh` under a non-blocking `default`; when a control
frame is ready it is written *ahead of* the next DATA frame (priority). When
no control frame is ready, the loop enters a blocking select over
`c.closed`/`ctrlCh`/`writeCh` — and Go **resolves a blocking select with
multiple ready channels by uniform random choice**, not by priority. So the
accurate statement is: **priority peek for the ready-control case, arbitrary
(fair) hand-off when both channels are simultaneously ready**. REV 0's
"strict priority" claim is withdrawn: a DATA burst with no credit in flight
will **not** be starved behind a perpetually-queued control frame, because
the blocking arm alternates fairly between the two producers.

```
func (c *CarrierConn) writeLoop() {
    defer c.goroutineStopped()
    for {
        // 1. Priority PEEK: a READY control frame preempts the next DATA.
        select {
        case req := <-c.ctrlCh:
            c.writeOne(req)
            continue
        default:
        }
        // 2. No control ready: service ctrl or DATA, or exit on close.
        // Both channels ready here ⇒ Go picks uniformly at random:
        // DATA cannot be starved by a full ctrl queue.
        select {
        case <-c.closed:
            return // Close's drainCtrl()/drainWrites() resolve anything in flight
        case req := <-c.ctrlCh:
            c.writeOne(req)
        case req := <-c.writeCh:
            c.writeOne(req)
        }
    }
}
```

**Starvation analysis (E).** Credits are **rate-bounded by socket writes**:
one credit per ≥ 64 KiB consumed (B3: credits are produced only at
`sock.Write` completion in the relay goroutine, never from a
blocking-sensitive context), and each is 39 B. At the 121.4 MiB/s ceiling
with 64 KiB batching that is ≈ 1,913 credits/s carrier-wide — ≈ 74 KiB/s of
control bytes, <0.1 % of a saturated DATA stream. The priority peek is
therefore **not free scheduling** (each write costs a `writeOne`), but it is
**negligible in bytes**, and the random hand-off above guarantees no DATA
stream is starved. `credit_emitted`/`credit_dropped_full` (Section 13) make
this rate observable.
```
// writeOne: one rwc.Write + resolve req.done (ErrCarrierClosed if c.closed).
func (c *CarrierConn) writeOne(req writeReq) {
    _, err := c.rwc.Write(req.data)
    if err != nil { c.mu.Lock(); st := c.stats; c.mu.Unlock(); st.writeFailure() }
    select { case <-c.closed: err = ErrCarrierClosed; default: }
    req.done <- err
}
```

**Enqueue discipline (the `write`-mirror for ctrl).** Two functions:

- `TryWriteControlFrame(streamID uint32, typ uint8, payload []byte) (enq bool, err error)` —
  **non-blocking, drop-on-full.** Builds the encoded frame, then:
  `c.mu.Lock(); if c.closing {unlock; return false, ErrCarrierClosed}; c.ctrlWG.Add(1); unlock`
  → `select { case c.ctrlCh<-req: c.ctrlWG.Done(); return true,nil; default: c.ctrlWG.Done(); return false, nil }`.
  On a full `ctrlCh` it **never blocks** (the `default` arm drops, `Done()`
  so `ctrlWG.Wait()` cannot deadlock). **Used by the credit emitter.**
- `WriteControlFrame(streamID uint32, typ uint8, payload []byte) error` —
  **blocking** (mirror of `write` at [`carrier.go:337`](../pkg/mux/carrier.go:337)):
  `ctrlWG.Add` under `c.mu`, `select{case c.ctrlCh<-req: …case <-c.closed: Done; return ErrCarrierClosed}`, then `return <-req.done`.
  **Reserved for `FrameClose`** (a terminal signal that must not be dropped)
  and `FramePing`/`FramePong` keepalive. The no-deadlock proof (Section 10)
  rests on the **non-blocking** `TryWriteControlFrame` for credits.

**`drainCtrl()`** — exact mirror of `drainWrites`
([`carrier.go:366`](../pkg/mux/carrier.go:366)):
```
func (c *CarrierConn) drainCtrl() {
    for { select { case req := <-c.ctrlCh: req.done <- ErrCarrierClosed
                   default: return } }
}
```

**`Close` ordering.** Sequence in [`CarrierConn.Close`](../pkg/mux/carrier.go:1061):
after `close(c.closed)` + `rwc.Close()`:
```
c.ctrlWG.Wait();  c.drainCtrl()      // resolve in-flight + queued control frames FIRST
c.writeWG.Wait(); c.drainWrites()     // then DATA frames
```
Rationale: both `drain` calls resolve every `req.done` so no producer is left
waiting on a dead writer (the invariant asserted by
[`carrier_shutdown_test.go`](../pkg/mux/carrier_shutdown_test.go) —
`TestCloseResolvesAllQueuedWrites`, `TestWriterExitsAfterClose`). `ctrlWG`/
`drainCtrl` **must** be sequenced before `writeWG`/`drainWrites` so a
`FrameClose` on `ctrlCh` is never stranded while a DATA request on `writeCh`
is still being drained. `ctrlWG.Add` happens under `c.mu` exactly like
`writeWG.Add` ([`carrier.go:349`](../pkg/mux/carrier.go:349)), and every Add is
mutex-ordered before `closing=true` — the `WaitGroup` contract holds for both.

**Per-frame-type routing table (authoritative):**

| Frame type | Queue | Order-sensitive? | Ordering-safety argument |
|---|---|---|---|
| `FrameData` (0x00) | `writeCh` | **yes** | In-order user data; FIFO on `writeCh`. |
| `FrameHeader` (0x05) | `writeCh` | **yes** | Must be the stream's first frame; FIFO with its DATA. |
| `FrameRebind` (0x06) | `writeCh` | **yes** | Must be first on a re-bound stream ([`node.go:686`](../pkg/node/node.go:686)); FIFO with DATA. |
| `FrameClose` (0x04) | `ctrlCh` | no | Terminal; via blocking `WriteControlFrame` (never dropped). |
| `FrameCredit` (0x07) | `ctrlCh` | no | Cumulative; a late/dropped credit is healed by the next one (Section 3). |
| `FramePing`/`FramePong` (0x02/0x03) | `ctrlCh` | no | Keepalive; reordering vs DATA is benign (**deliberate, asserted by `liveness_test.go`**). |

**In-order proof for the ordering-sensitive types.** `FrameRebind`/
`FrameHeader`/`FrameData` for a given stream are **all** on `writeCh`, FIFO,
consumed by the single `writeLoop` in enqueue order. No ordering-sensitive
frame is ever on `ctrlCh`, so **none can overtake the stream's DATA**.
`ctrlCh` frames (Credit/Close/Ping/Pong) interleave *between* DATA writes but
never *between two frames of the same stream that must be ordered*; they
carry no in-stream byte-order. □

**Credit-latency bound.** A credit on `ctrlCh` is written before the next
`writeCh` DATA, so it is never queued behind up to 256 DATA frames. Worst-case
delay = one in-flight `rwc.Write` + ≤1 queued control frame (v2 §7.4: ~6.5 ms
at a 5 MB/s saturated write).

**Emission contexts — the no-block invariant (B3).** The REV 0 routing table
argued only about the *sender's own* frames; REV 1 adds the binding context
constraint that the reviewer flagged. `TryWriteControlFrame` is **non-blocking
by construction** (drop-on-full, Section 3), so it is *safe to call* from any
context — but the design still states it explicitly because **emitting a
credit is not free**: it is a 39 B encode + a `ctrlWG.Add` under `c.mu` + a
channel send. The rule:

> **No credit may be emitted inline from a mux context that must not block —
> `Dispatch` (the `readLoop`) and `OnNewStream` (stream-registration
> callbacks) both run in a context that must return to service the next
> frame without delay.** `OnStreamCredit` (the receiver-side accounting in
> [`carrier.go:800`](../pkg/mux/carrier.go:800)–`824`) must not *enqueue* a
> credit; it only records state. The **emitter** (`recordConsumed`/`emit`)
> runs in the `startStreamRelay` **goroutine** (its own stack, after
> `sock.Write`) — a context that *may* block on a channel send because it is
> not on the frame-service hot path.

The **attach-time anchor** (Section 2/7, B2) is the one credit that *cannot*
be produced by the relay goroutine (there is no DATA yet on a fresh carrier).
It is therefore emitted from **a spawned goroutine** (one per attach, `go
n.creditEmitter.emitAnchor(key)`) or from the **epoch's consumer goroutine**
(the `rebindDirection` attach worker, [`node.go:637`](../pkg/node/node.go:637)),
**never inline in `handleRebind`'s `Dispatch`/`OnNewStream` context**
([`node.go:802`](../pkg/node/node.go:802) parses `peerGen` synchronously but
the *emit* is handed to the spawned goroutine). Slice 6 records this as an
**explicit constraint**: "the anchor emit is `go`-spawned; `handleRebind` only
calls `recordPeerGen` + spawns — it never blocks on a `ctrlCh` send." Because
the anchor is cumulative-absolute, a dropped anchor (at >64 concurrent
sessions) is healed by the next credit; the drop is visible via
`credit_dropped_full`/`credit_gate_admission_deferred` (O4). **At ≤64
concurrent sessions the anchor never drops** (cap-64 `ctrlCh`), so a normal
single-stream attach is guaranteed-ordered.

**Anchor-goroutine drop semantics (N-1).** The `go
n.creditEmitter.emitAnchor(key)` spawned from `handleRebind` runs *after*
`rebindDirection` returns, so it may outlive the carrier the anchor is
addressed to. If the carrier dies first, `TryWriteControlFrame` returns
`(false, ErrCarrierClosed)` and the goroutine **drops the anchor silently**:
it observes `n.ctx` / `c.closing` (the session ctx / carrier close) and exits
— it never blocks on a full `ctrlCh` (drop-on-full, Section 3) and is bounded
by a `select` on `n.ctx.Done()`, so it **cannot leak indefinitely**.

**Per-stream fairness of `ctrlCh` (O1).** `ctrlCh` is a single cap-64 FIFO
shared by **all** streams' credits (and Close/Ping/Pong). A stream that never
gets a slot out of 64 (because other streams' credits/Close/Ping are
draining it faster) **stalls its window while the others drain** — its
sender's `outstanding` stays high until one of its own credits is written.
This is *bounded*, not a deadlock: every credit is cumulative-absolute, so
the next credit that does get a slot heals the full cumulative total, and
`CreditSafeTimeout` (2 s) bounds the worst-case wait to 64 KiB SAFELY_CAPPED.
It is *visible*: `credit_dropped_full` (the drop) + `relay_credit_gate_park`
(the sender-side stall) + `credit_safely_capped` (the degradation). No
per-stream `ctrlCh` budget is introduced (it would deadlock with the `pending`
gate, v2 §11.4); fairness is a *known, bounded, observable* property.

---

## 5. Sender side: the credit gate

**Enforcement point.** The gate is on the **DATA-sender**'s write path, i.e.
`relayShapeA` when `dir == session.DirDown && n.cfg.Role == RoleGermany` — the
region immediately **before** the existing `pending >= capacity` gate
([`relays.go:106`](../pkg/node/relays.go:106)) and before `flushPending`
issues `WriteFrame` ([`relays.go:282`](../pkg/node/relays.go:282)). It gates
**how much target data may be read + issued**, so it sits at the top of the
`relayShapeA` loop, before `sock.Read`:

```
// relayShapeA, DirDown/RoleGermany only, before the pending gate (S1):
// the clamp limit is the SENDER's CARRIER's live limit (c.limits,
// carrier.go:483), reached via n.current(dir) (node.go:344) — NOT
// n.cfg.StreamLimits, which would silently diverge from the mailbox cap
// the moment SetStreamLimits (carrier.go:483) or rebind moves the carrier
// to a different limit.
hdl := n.current(dir)                     // *carrierHandle, node.go:344
capBytes := uint64(hdl.carrier.Limits().MaxBytesPerStream) // CarrierConn.Limits() accessor
if l := n.creditGate.ledger(hdl.gen, streamIDOf(sess, dir)); l != nil {
    if !l.canSend(creditIssueChunk, capBytes) {
        n.creditPark(sess, dir, att)      // park at the CREDIT gate, not the pending gate
        continue
    }
}
```

**`CarrierConn.Limits()` locking (SF-4).** `c.limits` is mutated **only**
under `c.mu` — [`carrier.go:483`](../pkg/mux/carrier.go:483) inside
`SetStreamLimits`, which holds `c.mu.Lock()` from
[`carrier.go:482`](../pkg/mux/carrier.go:482). The hot path reads
`hdl.carrier.Limits().MaxBytesPerStream` on **every** `canSend`, so
`Limits()` must be lock-correct: it **acquires `c.mu`, copies the
`StreamLimits` struct, and releases before returning**; the caller then uses
the copy **lock-free**. **No `c.mu` is held while a `creditPark` caller is
parked.** (Reading `c.limits` without `c.mu` would be a data race against the
`carrier.go:483` mutation.)

**Pre-latch bound is `creditWindowMax + creditUnackedAllowance` = 640 KiB (B2, REV 1 change).**
REV 0 defined `canSend`'s UNLATCHED bound as `MaxBytesPerStream` (704 KiB) —
the reviewer proved that is the *exact* condition that trips `fullLocked` /
`rejectAggregate` (`queue.go:140` / `queue.go:187`) for a full RTT on a
fresh-carrier attach, reproducing the D4 defect Phase B exists to fix.
REV 1 replaces it: an **UNLATCHED** ledger is bounded from the *instant the
carrier attaches* by `creditWindowMax + creditUnackedAllowance = 512 + 128 =
**640 KiB**`, NOT by `MaxBytesPerStream`. This is the same 640 KiB the
latched non-capped path allows (`window=creditWindowMax` + allowance), so the
pre-latch and first-latched states share one bound — no UNLATCHED state
ever exceeds it. `TestCreditGatePreLatchIsBounded` (Slice 2) asserts that a
fresh `UNLATCHED` ledger refuses `canSend(640 KiB + 1)` with **no credit
received at all**.

**`creditPark` (B4, REV 1 change).** REV 0's `creditPark` selected only on
`{credit-lowers-outstanding (none connected), sess.Ctx.Done(),
CreditSafeTimeout}` — because `canSend` returned a plain `bool` and nothing
signalled a credit arrival, the only exit was the 2 s timeout, repeated
unboundedly: a **permanent ≤ 64 KiB / 2 s throttle** (exactly the 161× D4
class, designed-in and invisible to `relay_credit_gate_park`). REV 1 adds a
wake channel to the ledger:

```
// pkg/node/credit.go (new) — B4 wake channel, mirrors StreamQueue.wake/wakeLocked
// (queue.go:162-168): closed-and-replaced on each accepted credit that lowers
// outstanding; creditPark selects on it.
type creditLedger struct {
    mu           sync.Mutex
    outstanding  uint64
    lastSeen     uint64
    window       uint32
    latched      bool
    safelyCapped bool
    gen          uint64
    ready        chan struct{} // nil or open: parked waiters present; closed: woken
    nWaiters     int
}

// onCredit, after a successful accept that lowers outstanding:
//   l.wakeLocked()            // close ready, set to nil, nWaiters=0  (under l.mu)
// creditPark (mirrors waitAttach, relays.go:321 + queue.go:235-241):
//   l.mu.Lock()
//   if !l.canSend(chunk, cap) {
//       if l.ready == nil { l.ready = make(chan struct{}) }
//       l.nWaiters++; r := l.ready
//       l.mu.Unlock()
//       select { case <-r: case <-sess.Ctx.Done(): case <-time.After(CreditSafeTimeout): }
//   } else { l.mu.Unlock() }
```

`TestCreditGateWakesOnCredit` (Slice 2, **MUST test before any wiring — fails
outright on the REV 0 design**): park in a goroutine; `onCredit(...)`; assert
the parked `canSend` returns true **within ~10 ms** (not 2 s). The
§5/§7/§9/§10 "no remaining deadlock path" claims are re-verified against this
new wake channel (Section 9/10).

`n.creditPark` mirrors `waitAttach` ([`relays.go:321`](../pkg/node/relays.go:321));
**the two gates are independent:** the credit gate gates *issuing*; the
`pending >= 256 KiB` gate gates *buffering*; both must be satisfied to read
the target.

**Harmless re-park (N-3).** If `creditPark`'s `CreditSafeTimeout` fires while
a credit is *in flight* on `ctrlCh`, that credit still lands and closes
`l.ready`; the **next** `canSend` sees `l.ready` already closed and exits
**immediately** (a re-park is a no-op). Do **not** add a second timeout — one
`CreditSafeTimeout` plus the B4 wake channel is sufficient.

**The ledger (v2 §6.5, refined to ship against `mux` helpers):**

```
// pkg/node/credit.go (new)
type creditLedger struct {
    mu           sync.Mutex
    outstanding  uint64      // issued − credited, clamped >= 0
    lastSeen     uint64      // last accepted bytesConsumed
    window       uint32      // accepted windowGranted (clamped to MaxBytesPerStream)
    latched      bool        // after first valid credit
    safelyCapped bool       // degraded by CreditSafeTimeout
    gen          uint64      // pinned to the arriving-carrier gen at latch
    ready        chan struct{} // B4: closed-and-replaced on accepted credit (queue.go:162-168 mirror)
    nWaiters     int         // B4: parked creditPark callers
}

type creditGateManager struct {
    mu      sync.Mutex   // guards ledgers only; NEVER held while calling ledger methods
    ledgers map[uint32]*creditLedger
}
```

**Constants and their sources** (Section 14):

| Const | Value | Source |
|---|---|---|
| `creditUnackedAllowance` | `2 * mux.MaxPayload` = 128 KiB | [`frame.go:22`](../pkg/mux/frame.go:22) |
| `creditWindowMax` | `MaxBytesPerStream − allowance − MaxPayload` = 704−128−64 = **512 KiB** | `MaxBytesPerStream` (§10); `MaxPayload` [`frame.go:22`](../pkg/mux/frame.go:22) |
| `creditInitialWindow` | **512 KiB** (= `creditWindowMax`) | adaptive-down model, v2 §8.4 |
| `CreditSafeWindow` | `mux.MaxPayload` = **64 KiB** | v2 §4.1 (S2) |
| `CreditSafeTimeout` | **2 s** | v2 §4.1 |
| `creditBatchBytes` | `mux.MaxPayload` = 64 KiB | emitter (§3) |
| `creditPreLatchBound` | `creditWindowMax + creditUnackedAllowance` = **640 KiB** | B2: UNLATCHED bound (REV 1) |

**`canSend` (never "unlimited"; UNLATCHED bound = 640 KiB, B2):**
```
func (l *creditLedger) canSend(chunk, capBytes uint64) bool {
    l.mu.Lock(); defer l.mu.Unlock()
    limit := creditPreLatchBound           // B2: UNLATCHED bound = 640 KiB (NOT MaxBytesPerStream)
    if l.latched {
        if l.safelyCapped { limit = CreditSafeWindow }
        else { limit = uint64(l.window) + creditUnackedAllowance }
    }
    // capBytes is the CARRIER's live MaxBytesPerStream (S1), passed so the
    // clamp can never silently exceed the real mailbox cap:
    if limit > capBytes { limit = capBytes }
    return l.outstanding + chunk <= limit
}
```

**`onCredit` (called from the `OnStreamCredit` callback, Section 4 wiring;
B4 wake on success):**
```
func (l *creditLedger) onCredit(p mux.CreditPayload, arrivingGen, capBytes uint64) bool {
    l.mu.Lock(); defer l.mu.Unlock()
    if mux.StaleCreditGeneration(p.Gen, arrivingGen) { return false } // §9
    if p.Gen != l.gen { return false }                                // pinned-at-latch
    if p.BytesConsumed < l.lastSeen { return false }                   // out-of-order
    consumed := p.BytesConsumed - l.lastSeen
    if consumed > l.outstanding { consumed = l.outstanding }           // R2-3 clamp (no underflow)
    lowered := consumed > 0
    l.outstanding -= consumed
    l.lastSeen = p.BytesConsumed
    if l.latched {
        l.window = mux.ClampCreditWindow(p.WindowGranted, capBytes)    // S1: carrier cap, not cfg
        l.safelyCapped = false                                                // a live credit heals it
    }
    l.latched = true
    if lowered { l.wakeLocked() }          // B4: wake parked creditPark within ~µs, not 2 s
    return true
}
```

**Anchor no-wake (SF-2).** An anchor (`bytesConsumed == 0`) sets
`l.latched = true`, but with `consumed = 0` the `lowered = false` branch means
`l.wakeLocked()` is **NOT** called. This is correct: the pre-latch sender is
**not parked** — it is actively issuing, bounded by `creditPreLatchBound`
(640 KiB), so there is no parked `creditPark` caller to wake. A *subsequent*
zero-consumed credit for the same stream is likewise a no-op (the monotonic
`lastSeen` guard yields `consumed = 0` again) and **also does not wake**.

**`recordSent(n)` — per-chunk charge (S3).** `flushPending`'s write loop
([`relays.go:277`](../pkg/node/relays.go:277)–[`295`](../pkg/node/relays.go:295))
writes up to `MaxPayload` (64 KiB) chunks in a tight loop
`for len(*pending) > 0 { chunk := *pending; if len(chunk) > mux.MaxPayload {
chunk = chunk[:mux.MaxPayload] }; h.carrier.WriteFrame(…, chunk); …
*pending = (*pending)[len(chunk):] }`. REV 0 charged `recordSent(n)` **per
`flushPending` call** — a 256 KiB pending flush would therefore charge 256 KiB
against a 64 KiB-granular gate in one increment, overshooting `outstanding`
past `limit` by up to 4×. REV 1 charges **per chunk** — `n = len(chunk)` after
each successful `WriteFrame` in that loop:
```
// in flushPending's write loop, after each WriteFrame success (relays.go:291):
if l := n.creditGate.ledger(...); l != nil { l.recordSent(uint64(len(chunk))) }
```
`reset(gen)` (rebind-attach, Section 7) zeroes `outstanding`, `lastSeen`,
`latched=false`, `safelyCapped=false`, and sets `gen` to the
new carrier's gen.

**Precise definition of `outstanding` (per the REV 2 S1-A fix).** `outstanding`
is the **stream's OWN in-flight bytes only**: P4 (mailbox) + P5 (`s.ch`) + P6
(client kernel recv buffer) **plus the stream's own allocated share** of P1
(`writeCh`)/P2/P3 (`c.frames`). The **shared wholes** of P1/P3 (~16.3 MiB each,
per carrier, [`carrier.go:179`](../pkg/mux/carrier.go:179)/
[`carrier.go:180`](../pkg/mux/carrier.go:180)) are **outside** any single
stream's `outstanding` and **outside** `MaxBytesTotal` (Section 6.3 of v2;
fixed floor). It is decremented **only** by an accepted credit
(`onCredit`), which is the cumulative-absolute release point, so two credits
cannot subtract the same bytes (monotonic `lastSeen` guard). □

**Anchor sequence (B2, REV 1 change — the anchor is an EMITTER-side,
ATTACH-time credit, not a receiver-of-DATA credit).** REV 0 claimed the
receiver's socket-write relay "anchors" the sender — but the reviewer proved
that is impossible in the timeline: `peerGen` is learned from the
`FrameRebind` payload ([`node.go:802`](../pkg/node/node.go:802) parses it;
[`node.go:689`](../pkg/node/node.go:689) writes it), and the receiver's
socket-write relay **cannot emit before it has received DATA** — so there is
no DATA-credit anchor; the first credit is an ordinary one with
`bytesConsumed > 0`. Worse, on a fresh carrier after carrier loss the
sender's ledger was UNLATCHED with `limit = MaxBytesPerStream` (704 KiB) —
*exactly* the `fullLocked`/`rejectAggregate`-tripping condition for a full
RTT, reproducing the D4 defect Phase B exists to fix. REV 1 redefines the
anchor as an **emitter-side credit emitted at attach time**:

- `bytesConsumed = 0`, `creditGen = peerGen` (taken from the rebind already
  parsed at [`node.go:802`](../pkg/node/node.go:802)), `windowGranted =
  creditWindowMax`, `flags = 0`.
- Emitted from **`handleRebind`** (Slice 6) — i.e. when the receiver learns
  `peerGen` — **not** from `startStreamRelay`. Per B3 it is emitted from a
  **spawned goroutine** (`go n.creditEmitter.emitAnchor(key)`), never inline
  in the `Dispatch`/`OnNewStream` context (Section 4).
- Effect: the sender is latched **from the instant the carrier attaches**,
  so it is **bounded from the very first credit** — never unlimited — and
  **even before that first credit arrives**, the UNLATCHED ledger is bounded
  by `creditPreLatchBound` = 640 KiB (§5 above), not `MaxBytesPerStream`.

`TestCreditGatePreLatchIsBounded` (Slice 2) + `TestCreditGateWakesOnCredit`
(Slice 2) gate this.

**`CreditSafeTimeout` state machine + SAFELY_CAPPED.** The ledger is `UNLATCHED`
on attach, **bounded by `creditPreLatchBound` = 640 KiB** (B2 — *not*
`MaxBytesPerStream`). `creditGateManager` arms a per-stream 2 s timer from
attach (no valid credit yet). On expiry **before** any credit:
`safelyCapped=true`, `window=CreditSafeWindow` (64 KiB), `latched=true` — the
**SAFELY_CAPPED** state (bounded, **never unlimited**; v2 §4.1 S2). If parked
while latched and no credit arrives within `CreditSafeTimeout`: **same
SAFELY_CAPPED transition** (visible via `credit_safely_capped` +
`credit_degraded_reason{timeout}`; a no-credit peer drives
`credit_degraded_reason{no_credit_peer}` — S8). The **wake channel** (B4)
means the timer is only ever a *fallback* — a live accepted credit closes
`l.ready` and un-parks the relay within ~µs, so the 2 s timeout is no longer
the only exit (the REV 0 "designed-in 161× D4" path is gone). Invariant
(S2/§9.5): **once latched, no transition re-opens unlimited**; the only
terminal reset is `reset(gen)` on rebind, which re-enters `UNLATCHED`
(re-bounded by `creditPreLatchBound` = 640 KiB), then re-arms the timer. □

---

## 6. Mailbox-cap interaction (overflow-proof)

With `MaxBytesPerStream = 704 KiB` (the new per-stream hard cap) and the gate
bounding issued bytes to `window_max + allowance = 512 + 128 = 640 KiB`:

- **The enforcement that ACTUALLY holds is the hard cap in
  [`queue.go:140`](../pkg/mux/queue.go:140) (`fullLocked`) + the aggregate
  [`queue.go:187`](../pkg/mux/queue.go:187) (`rejectAggregate`).** A mailbox
  cannot exceed `min(maxFrames, MaxBytesPerStream, aggregate) = 704 KiB`
  regardless of the credit path; if it ever does go full the dispatcher's
  `failUndeliverableData` terminates the stream (integrity invariant, v2 §0.3)
  — that is *detection*, not silent overflow.
- **The gate is advisory (pacing).** Its invariant
  `outstanding ≤ 640 KiB` bounds the *per-stream own* in-flight terms; since P4
  (mailbox) ⊆ those terms, `P4 ≤ 640 KiB < 704 KiB = mailboxCap`. **The credit
  path cannot drive a mailbox to persistent-full.** □
- **`MaxBytesTotal` = 16 MiB (B5, REV 1 change).** REV 0's `8 MiB` yields
  `8 MiB ÷ 704 KiB ≈ 11.6` full mailboxes — the **12th concurrent full down
  mailbox trips `rejectAggregate` → `dropped_data_frames`** on a *normal*
  SOCKS client with 12 parallel fetches. Framing that as "admitted / no
  admission control in scope" was a regression against the entire point of
  Phase B: a **concurrency-driven `dropped_data_frames` is the very defect
  Phase B must not reproduce.** REV 1 adopts the reviewer's recommended option
  and **raises `MaxBytesTotal` to 16 MiB** (= 16 × 1024 KiB). The arithmetic:
  16 MiB ÷ 704 KiB = **23 full + ~56 KiB slack; the 24th** concurrent full
  mailbox (not the 12th) **trips `rejectAggregate`** — a genuinely heavy,
  not-a-bug,
  concurrency. **This deviates from the approved architecture doc** (v2 §10.4
  / §11 records `MaxBytesTotal = 8 MiB`); the deviation is **recorded
  explicitly as a reviewer-approved amendment (B5)**, not silently. The
  **~65.2 MiB fixed floor** (the shared `writeCh` + `c.frames` terms outside
  `MaxBytesTotal`, v2 §6.3/§10.1) **dominates** the memory argument, so
  doubling the aggregate budget from 8 → 16 MiB does **not** change the
  bounding conclusion. §11 Slice 7 and §14 default are updated to 16 MiB;
  `SanitizeLimits`'s loud-failure bound (§14/S5) is unchanged — it still
  rejects any `MaxBytesTotal < MaxBytesPerStream`, and 16 MiB > 704 KiB.
  Streams beyond the new trip point are still **admitted** (no admission
  control is in scope — v2 §10.3), and the residual `data_undeliverable`
  hazard is now instrumented by `credit_gate_admission_deferred` (S7) so the
  24th-stream case is **visible**, not a D4-class blind counter.

## 7. Generation pinning + reconnect / rebind

**How the node learns the arriving carrier's generation for the credit check.**
Two independent values, used at two different ends:

1. **Sender (gate) side:** the ledger validates `p.Gen` against
   `arrivingGen` = the gen of **the carrier handle the credit ARRIVED on**
   for that stream. For a down stream that is the sender's down
   `carrierHandle.gen` (`n.current(session.DirDown).gen`,
   [`node.go:344`](../pkg/node/node.go:344)), directly available — **no
   rebind-payload parsing needed on the sender** (v2 §9.1 REV 1, S3).
2. **Receiver (emitter) side:** the emitter must *stamp* the sender's gen into
   `creditGen`. It learns that value **from the `FrameRebind` payload** the
   sender wrote on rebind: `session.EncodeRebind(sess.ID, h.gen)`
   ([`node.go:689`](../pkg/node/node.go:689)); the receiver's
   `handleRebind` already does `session.ParseRebind(p)` → `gen`
   ([`node.go:802`](../pkg/node/node.go:802)). Phase B adds, keyed by
   `(carrier, streamID)` (S6 — §2): `n.creditEmitter.recordPeerGen(
   carrierKeyFor(sess, dir), gen)` in `handleRebind` (and on the initial
   attach), caching it as `streamCredit.peerGen`. Every emitted credit then
   carries `creditGen = peerGen`.

**Stale rejection (S2, REV 1: the wrap paragraph is deleted).** A stale credit
has `creditGen = old_gen`; the ledger's `gen = arrivingGen` (pinned at
latch, Section 5); since `old_gen != new_gen`, `onCredit` returns false and
**does not update `outstanding`** (v2 §9.3). The REV 0 "~5×10^10 years to
wrap 2^64" argument is deleted as noise: `gen` is a **strictly-increasing,
never-reused** counter (`genSeq++` once per reconnect,
[`node.go:480`](../pkg/node/node.go:480)), and `ValidateCreditPayload`
([`frame.go:248`](../pkg/mux/frame.go:248)) **rejects `gen == 0` up front**.
Because no two live generations ever share a value, the `!=` check in
`mux.StaleCreditGeneration` ([`frame.go:244`](../pkg/mux/frame.go:244)) is
**exact** — a wrap to a previously-used value is unreachable by
construction, so no wrap-safety analysis is needed. □

**What a rebind does.** On `handleRebind` / `rebindDirection` attach
([`node.go:637`](../pkg/node/node.go:637)): (1) **Sender:**
`creditLedger.reset(newGen)` — `outstanding=0`, `lastSeen=0`, `latched=false`,
`safelyCapped=false`, `gen=newGen`, `ready=nil`, `nWaiters=0` (B4). (2)
**Receiver:** the old carrier's worker exits (mailbox `Close`d); the
`creditEmitter`'s **new** `(carrier, streamID)` record (S6 — new carrier gen ⇒
fresh key, §2) starts with `consumed=0` and `peerGen` is stamped from the
rebind at [`node.go:802`](../pkg/node/node.go:802). (3) **Anchor (B2):** the
**emitter** spawns (`go emitAnchor`, B3 — never inline in the
`Dispatch`/`OnNewStream` context, §4) the attach-time anchor credit
(`bytesConsumed=0`, `creditGen=peerGen`, `windowGranted=creditWindowMax`,
`flags=0`) from `handleRebind` (Slice 6). No stream ever becomes unlimited:
after `reset`, the stream is `UNLATCHED` but **bounded by
`creditPreLatchBound` = 640 KiB** (B2 — REV 1, not `MaxBytesPerStream`), and
SAFELY_CAPPED (64 KiB) if the 2 s timer fires first. Beyond 64 concurrent
sessions on one carrier, the anchor drops on full — safe (cumulative) and
visible via `credit_dropped_full` / `credit_gate_admission_deferred` (O4/S7). □

---

## 8. Half-close and remote-terminate behavior

- **Peer half-closes the stream while the gate is parked.** The stream's
  mailbox receives `queueItem{isClose:true}`; the worker hands `nil` to
  `startStreamRelay` → `peerEOF` → the direction half-closes
  ([`relays.go:344`](../pkg/node/relays.go:344)). `creditEmitter.finalize`
  force-emits the last `pending` with `CreditFlagsFinal`. **The gate does not
  block the EOF-flush path** (v2 §4.4): `relayShapeA`'s `socketEOF` branch
  ([`relays.go:74`](../pkg/node/relays.go:74)) is reached *before* the credit
  gate, so the final `flushPending` + `sendCloseFrame` is **never credit-gated**.
  The credit gate's park is bounded by `CreditSafeTimeout` ∩ session ctx, so a
  parked-then-half-closed stream **cannot hang forever**: `creditPark` exits on
  `sess.Ctx.Done()` or the timeout.
- **Relay's `pending` buffer holds data at attach time.** At rebind-attach the
  `pending` slice's bytes survive and are flushed in order
  ([`relays.go:99`](../pkg/node/relays.go:99)). Phase B additionally resets the
  ledger (`outstanding=0`) so the re-gate starts clean; `pending` itself is
  gated by `MaxBytesPerStream`/aggregate as before.
- **Remote terminates the stream mid-flight.** `terminateStream`
  ([`carrier.go:940`](../pkg/mux/carrier.go:940)) closes the mailbox; the
  worker exits; `startStreamRelay` sees `ok=false` on `s.ch` and exits
  ([`relays.go:441`](../pkg/node/relays.go:441)). `creditLedger` and
  `creditEmitter` records are dropped in `onSessionClosed`. **No stream hangs:**
  every exit path is bounded by (a) `CreditSafeTimeout` (2 s) for gate parks,
  (b) the 5 s carrier `Grace` for carrier loss, or (c) `finalizeDrain`'s 10 s
  timer for a stuck post-EOF target ([`node.go:1161`](../pkg/node/node.go:1161)).
  The interaction: a gate-park that would otherwise outlive the drain is cut
  off because `creditPark` selects on `sess.Ctx.Done()`, and `finalizeDrain`
  closes the session at 10 s.

---

## 9. Lock-ordering proof

**Every mutex acquired in Phase B, in order, and the no-cycle argument.**
Existing discipline (shipped): there is **no `c.mu → q.mu` nesting anywhere**;
the hot path is `q.mu`-only and the aggregate budget limit is a plain value
precisely so no second lock is taken under `q.mu`
([`queue.go:51`](../pkg/mux/queue.go:51), invariant comment at
[`carrier.go:1080`](../pkg/mux/carrier.go:1080)).

Phase B introduces **three new leaf locks** and nests them under nothing:

| Lock | File | Held-while-taking |
|---|---|---|
| `creditLedger.mu` | `pkg/node/credit.go` | nothing (leaf) |
| `creditGateManager.mu` | `pkg/node/credit.go` | nothing (leaf; released **before** any `ledger` method call) |
| `creditEmitter.mu` | `pkg/node/credit.go` | nothing (leaf) |
| `ctrlWG` / `ctrlCh` | `pkg/mux/carrier.go` | `ctrlWG.Add` under `c.mu` only (mirror of `writeWG.Add`, [`carrier.go:349`](../pkg/mux/carrier.go:349)); no other lock |

**Specific proofs the task calls out:**

1. **Credit update at socket-Write completion** (emitter `recordConsumed`,
   called from `startStreamRelay` after [`relays.go:467`](../pkg/node/relays.go:467))
   runs in the relay goroutine holding **no mux lock** — it has popped from
   the stream channel already; `startStreamRelay` never holds `c.mu` or
   `q.mu` while calling `sock.Write`. It takes only `creditEmitter.mu` (leaf).
   **No mux lock on this path.** □
2. **The gate** (`canSend`, called in `relayShapeA` before `sock.Read`) takes
   only `creditGateManager.mu` (to fetch the ledger pointer, released) then
   `creditLedger.mu` (leaf). `relayShapeA` holds **no mux lock while parked**:
   `creditPark` (B4) mirrors `waitAttach` ([`relays.go:321`](../pkg/node/relays.go:321))
   but **also selects on the ledger's wake channel `l.ready`** (a plain
   `chan struct{}`, closed-and-replaced exactly like `StreamQueue.wake`/
   `wakeLocked`, [`queue.go:162`](../pkg/mux/queue.go:162)–[`168`](../pkg/mux/queue.go:168)).
   `l.ready` is a **leaf channel** — creating it / closing it / selecting on
   it happens under `l.mu` only, and never while a mux lock is held (it mirrors
   `StreamQueue.wake`/`wakeLocked`, [`queue.go:162`](../pkg/mux/queue.go:162)–
   [`168`](../pkg/mux/queue.go:168), whose doc comment says "Caller must hold
   q.mu"). `onCredit` performs the state update **and** calls `l.wakeLocked()`
   *in the same `l.mu`-held critical section*, so the wake is atomic with the
   `outstanding` mutation a parked reader observed via `canSend` — no lost
   wakeup, and no `c.mu`/`q.mu` nesting. **No mux lock on this path; the wake
   channel is a leaf.** □
3. **`OnStreamCredit`** (the new `CarrierConn` callback): the `Dispatch`
   `FrameCredit` case (`carrier.go:800`) currently takes `c.mu` **briefly** to
   look up the stream; Phase B calls `OnStreamCredit` **after releasing
   `c.mu`** — exactly like `OnNewStream`/`OnStreamTerminated` (called outside
   `c.mu`, [`carrier.go:777`](../pkg/mux/carrier.go:777)/
   [`carrier.go:943`](../pkg/mux/carrier.go:943)). `onCredit` then takes the
   ledger leaf lock. **No `c.mu → ledger.mu` nesting.** □
4. **`ctrlWG.Add` under `c.mu`** is the *only* multi-lock point: it is
   `c.mu` → (release) → channel, never `c.mu` held while acquiring another
   named mutex. The `WriteGroup` itself is not a mutex. □

**Conclusion: no new lock is introduced that nests under `c.mu` or `q.mu`; all
new locks are leaves; the `c.mu`→`q.mu`-free invariant is preserved. No cycle. □**

---

## 10. Deadlock / HOL / fairness analysis (every new wait edge)

- **Credit emitter blocked on a full `ctrlCh`.** Impossible: the emitter uses
  **non-blocking `TryWriteControlFrame`** (drop-on-full, `default` arm). It
  *never* blocks. A full `ctrlCh` (cap 64) just delays one credit; the next
  heals it (Section 3). □
- **Sender parked at the gate while the receiver is parked at `pending`.**
  These are on **two different nodes** (DE gate-parks at its own credit gate;
  IR/DE `pending`-gate is the relay's local buffer). They cannot form a
  circular wait across the wire: the sender's park is released **only by a
  credit**, and the credit is produced **only when the receiver writes the
  socket** (which happens whenever the receiver's `pending` drains). If both
  are stuck, `CreditSafeTimeout` (2 s, sender) and `Grace` (5 s, receiver)
  bound the wait — one side always wakes. The two gates are **independent**,
  so no edge links them back-to-back. □
- **`ctrlCh` full while `writeCh` full.** The single `writeLoop` drains both;
  `writeLoop` is the **sole consumer** of both, so a full `writeCh` cannot
  freeze a full `ctrlCh` — the same loop services `ctrlCh` with priority
  (Section 4). Producers on `ctrlCh` use drop-on-full (emitter) or blocking
  only for `FrameClose`/Ping/Pong (`WriteControlFrame`), which is bounded by
  the loop draining `ctrlCh`. No circular wait. □
- **`Close` racing an in-flight credit.** `Close` does `ctrlWG.Wait();
  drainCtrl()` **before** `writeWG.Wait(); drainWrites()` (Section 4). Every
  in-flight/queued control `req.done` is resolved; `TryWriteControlFrame`
  returns `(false, ErrCarrierClosed)` once `closing=true`; no producer is left
  on a dead writer. □
- **A sender parked at the credit gate (REV 0 deadlock, now closed — B4).**
  REV 0's `creditPark` had **no wake channel**: `canSend` returned a bare
  `bool`, `onCredit` mutated `outstanding` with no signal, and the only exit
  was `CreditSafeTimeout` (2 s) × unbounded repetition ⇒ a permanent
  ≤ 64 KiB / 2 s throttle (the 161× D4 class, designed in, and *invisible*
  to `relay_credit_gate_park`, which would report the gate "parking" as
  healthy). REV 1 adds `creditLedger.ready` (closed-and-replaced on each
  accepted credit that lowers `outstanding`, `l.wakeLocked()`, mirroring
  `StreamQueue.wake`/`wakeLocked`, [`queue.go:162`](../pkg/mux/queue.go:162)–
  [`168`](../pkg/mux/queue.go:168)); `creditPark` selects on `l.ready` *first*,
  so an accepted credit wakes a parked sender within ~µs. The 2 s
  `CreditSafeTimeout` is now a **fallback**, not the only exit. `ready` is a
  leaf channel under `l.mu` (Section 9 proof 2) — no mux-lock nesting, so no
  new cycle. The **`finalizeDrain` 10 s path** (below) still bounds any park
  that outlives the credit link. `TestCreditGateWakesOnCredit` (Slice 2)
  asserts this wake directly. □
- **The `finalizeDrain` 10 s path.** A post-EOF target not finishing in 10 s
  closes the session ([`node.go:1161`](../pkg/node/node.go:1161)), which cancels
  `sess.Ctx`, waking any `creditPark`/`waitAttach`/`chargeWait` park. Bounded. □

**Residual `writeCh` HOL risk (stated honestly with magnitude, v2 §11.4).**
`writeCh` (cap 256, ~16.3 MiB) is a **shared FIFO across all streams**; a
DATA burst from stream A can delay stream B's DATA by up to the full drain
time: **16.3 MiB ÷ carrier_rate ≈ 3.3 s at the 5 MB/s assumption (≈ 0.14 s at
the 121.4 MiB/s ceiling)**. This is **pre-existing** (not v2-introduced); v2
ships **without** a per-stream `writeCh` budget because such a budget would
**deadlock with the `pending` gate** (`relays.go:106`–`111`) — that mitigation
is explicitly out of scope and remains an operator-visible open item (v2
§11.4 item 4).

---

## 11. Implementation slices (ordered; each builds, leaves `./...` green)

> **Gate discipline (v2 N5/S6).** After the `writeLoop` rewrite, every slice's
> gate names the **existing** `pkg/mux` suite (a gate that skips
> `carrier_shutdown_test.go` is not green) and ends with **main stays green:**
> `go build ./... && go test ./...`. The `pkg/mux` files are:
> `carrier_test.go`, `carrier_shutdown_test.go`, `carrier_reader_test.go`,
> `queue_test.go`, `frame_test.go`, `frame_credit_test.go`, `liveness_test.go`,
> `security_test.go`, `auth_test.go`, `auth_ws_timeout_test.go`,
> `secret_test.go`, `carrier_close_race_test.go`, `deliver_fail_test.go`,
> `queue_stats_test.go`, `backpressure_test.go`, `consumer_stall_test.go`,
> `carrier_stats_test.go`.
>
> **Phase A (Slice 2 of the v2 doc) is ALREADY SHIPPED.** The v2 "Slice 1
> (ctrlCh)" and "Slice 2 (FrameCredit)" collapse here: Slice 2 is done;
> Phase B Slice 1 is the `ctrlCh` control plane.

**Slice 1 — mux control plane (`pkg/mux/carrier.go` + tests).**
Add `ctrlCh`/`ctrlWG`/`drainCtrl`, rewrite `writeLoop` to the priority peek,
add `TryWriteControlFrame` + `WriteControlFrame`, route
Credit/Close/Ping/Pong→`ctrlCh`, keep Data/Header/Rebind→`writeCh`, add the
`OnStreamCredit` callback field + wire it into the `Dispatch` `FrameCredit`
case (replacing the no-op), and sequence `Close` as `ctrlWG.Wait();
drainCtrl(); writeWG.Wait(); drainWrites()`.
*New tests:* `TestControlFramePriority`, `TestCtrlChBounded`,
`TestWriteLoopDeadlockFree`, `TestCtrlChDrainOnClose` (in
`carrier_test.go`/`carrier_shutdown_test.go`), `TestCreditFrameRidesCtrlCh`.
**Gate:** `go build ./... && go vet ./pkg/mux/... && go test ./pkg/mux/...`
(ALL mux files incl. `liveness_test.go` pong-ordering, REV S5) +
`go test ./...`.

**Slice 2 — `creditLedger` + `creditGateManager` (`pkg/node/credit.go`, new).**
Implement `creditLedger` (§5) **including the B4 wake channel**
(`ready chan struct{}` + `wakeLocked`, mirror of `StreamQueue.wake`/
`wakeLocked`, [`queue.go:162`](../pkg/mux/queue.go:162)–[`168`](../pkg/mux/queue.go:168)),
`canSend`/`recordSent`/`onCredit`/`reset` (with the **B2 UNLATCHED bound =
`creditPreLatchBound` 640 KiB** and the **S1 carrier-cap clamp**), the
constants, and the `CreditSafeTimeout` SAFELY_CAPPED timer. No wiring yet.
*New tests:* `TestCreditLedgerCanSend`, `TestCreditLedgerOnCredit`,
`TestCreditSafeTimeoutCapsNotUnlimited`, `TestCreditLedgerReset`,
**`TestCreditGateWakesOnCredit`** (B4 — **MUST, in Slice 2 before any wiring:**
park in a goroutine, `onCredit(...)`, assert the parked `canSend` returns true
within ~10 ms, not 2 s; **fails outright on the REV 0 no-wake design**), and
**`TestCreditGatePreLatchIsBounded`** (B2 — a fresh `UNLATCHED` ledger must
refuse `canSend(640 KiB + 1)` with **no credit received**). (in
`credit_test.go`, new). **Gate:** `go build ./... && go vet ./pkg/node/... &&
go test ./pkg/node/...` + `go test ./...`.

**Slice 3 — `creditEmitter` + batching (`pkg/node/credit.go`, extend).**
Implement `creditEmitter`/`streamCredit`, `recordConsumed`/`recordPeerGen`/
`emit`/`finalize`, the `creditBatchBytes`/`creditBatchMaxAge` thresholds,
wired to `TryWriteControlFrame`. *New tests:*
`TestCreditEmissionBatching` (128 KiB → 2 credits),
`TestCreditEmissionOnHalfClose`, `TestCreditEmitterDropOnFull`.
**Gate:** `go build ./... && go test ./pkg/node/...` + `go test ./...`.

**Slice 4 — receiver emission wiring (`pkg/node/relays.go`).**
Rewrite the `sock.Write` site ([`relays.go:467`](../pkg/node/relays.go:467)) to
the **enforced B1 shape** `if nw, err := sock.Write(frame); err == nil &&
nw == len(frame) { recordConsumed(key, uint64(nw)) } else { /* no credit */
sess.Close(sockWriteErr(dir)) }`; call `finalize` on the `frame==nil`
half-close branch; call `recordPeerGen` from `handleRebind`/attach in
[`node.go`](../pkg/node/node.go). *New test:*
**`TestCreditEmitterNoOverAckOnPartialWrite`** (SF-1) — the socket is injected
through the **existing** concrete fake `faultSock`
([`relay_upread_test.go:35`](../pkg/node/relay_upread_test.go:35)), extended
with a short-write mode whose `Write` returns `(len(b)-5, nil)`; every other
`net.Conn` method is a no-op / panic. `netConn` is **`type netConn =
net.Conn`** ([`relays.go:29`](../pkg/node/relays.go:29) — a *type alias* to
the stdlib, not a project-local interface), and `startStreamRelay`
([`relays.go:424`](../pkg/node/relays.go:424)) takes **no socket parameter** —
its socket is `sess.TargetConn` / `sess.ClientConn`
([`relays.go:426–431`](../pkg/node/relays.go:426)). So `faultSock` (a
`net.Conn`) is injectable directly via the session conn field. **A real
`net.TCPConn` is NOT used, and cannot be:** Go's stdlib *couples* a short
write (`n < len(p)`) to `err != nil`, so it can never produce the `(short,
nil)` shape this test needs — only a hand-written fake can. The `(short,
nil)` write must produce **no credit** and a session close (B1). **Gate:**
`go build ./... && go test ./pkg/node/...` + `go test ./...`.

**Slice 5 — sender gate wiring (`pkg/node/relays.go` + `node.go`).**
Add the `creditGate.ledger(carrier.gen, ...).canSend(...)` check in
`relayShapeA` (DirDown/RoleGermany) before the pending gate; `creditPark`
(with the B4 `l.ready` select); **`recordSent(uint64(len(chunk)))` per chunk**
inside `flushPending`'s write loop ([`relays.go:291`](../pkg/node/relays.go:291))
(S3); wire `c.OnStreamCredit` in `install`
([`node.go:468`](../pkg/node/node.go:468)) to `creditGate.onCredit`. **S1:**
the clamp limit is the **sender's carrier's** live limit — add a
`CarrierConn.Limits()` accessor (returns `c.limits`,
[`carrier.go:483`](../pkg/mux/carrier.go:483)) and pass
`n.current(dir).carrier.Limits().MaxBytesPerStream` into `canSend`/`onCredit` —
NOT `n.cfg.StreamLimits` (which silently diverges from the mailbox cap once
`SetStreamLimits` moves the carrier). **Gate:** `go build ./... &&
go test ./pkg/node/...` + `go test ./...`.

**Slice 6 — rebind-attach reset + attach-time anchor credit (`pkg/node/node.go`).**
In `rebindDirection`/`handleRebind`: `creditLedger.reset(newGen)` (sender;
zeroes `ready`/`nWaiters`, B4) and `creditEmitter` reset + `recordPeerGen`
(receiver, keyed `(carrier, streamID)`, S6); **emit the attach-time anchor
credit** (B2 — `bytesConsumed=0`, `creditGen=peerGen` from
[`node.go:802`](../pkg/node/node.go:802)) on the new carrier for each
re-bound stream. **Explicit B3 constraint (Slice 6 gate):** the anchor emit is
**`go`-spawned** (`go n.creditEmitter.emitAnchor(key)`) or runs in the epoch's
consumer goroutine — **never inline in `handleRebind`'s `Dispatch`/`OnNewStream`
context** ([`node.go:802`](../pkg/node/node.go:802) parses `peerGen`
synchronously, the *emit* is handed off). **O4:** beyond 64 concurrent
sessions on one carrier the anchor drops on full — safe (cumulative) and
visible via `credit_dropped_full` / `credit_gate_admission_deferred`.
*New test:* `TestAnchorEmittedAtAttachNotOnData` (B2). **Gate:**
`go build ./... && go test ./pkg/node/...` + `go test ./...`.

**Slice 7 — limit change + loud `Sanitize` (S5 signature) + config (mux +
`internal/config`).**
Change `DefaultStreamLimits` to `MaxBytesPerStream = 704 KiB`,
**`MaxBytesTotal = 16 MiB`** (B5 amendment; the approved doc says 8 MiB — the
deviation is recorded in §6 and §14, and the ~65.2 MiB fixed floor dominates
so the memory argument is unaffected) ([`carrier.go:423`](../pkg/mux/carrier.go:423)).
**S5 — the approved architecture doc wins on the signature:** v2 §10.4
(~:1600–1613) requires `SanitizeLimits` to **return `(StreamLimits, error)` and
fail loudly** (the mux is the *only* place that sees the pair, so the loud
failure belongs here, not in `internal/config`). REV 0's "keep the `mux`
signature, add `internal/config` validation" is **superseded**. Concretely:
change `SanitizeLimits` ([`carrier.go:436`](../pkg/mux/carrier.go:436)) to
`func SanitizeLimits(l StreamLimits) (StreamLimits, error)`, returning an error
when `l.MaxBytesTotal < l.MaxBytesPerStream`; update **every call site**.

**Complete `SanitizeLimits`/`SetStreamLimits` call-site list (verified full-tree
grep — SF-3):**
1. [`carrier.go:436`](../pkg/mux/carrier.go:436) — the definition itself (gains the `error` return).
2. [`carrier.go:483`](../pkg/mux/carrier.go:483) — `SetStreamLimits` body (`c.limits = SanitizeLimits(l)`).
3. [`node.go:142`](../pkg/node/node.go:142) — `Config.Sanitize()`, the call that `NewNode` ([`node.go:246`](../pkg/node/node.go:246)) runs: `c.StreamLimits = mux.SanitizeLimits(c.StreamLimits)`. (This **is** the "NewNode" site — now named and lined.)

**`SetStreamLimits` signature change (SF-3, explicit API change):** it
currently returns **nothing** ([`carrier.go:481`](../pkg/mux/carrier.go:481));
to propagate the loud error it becomes
`func (c *CarrierConn) SetStreamLimits(l StreamLimits) error`.

**Unaffected (do NOT edit):** the `streamLimits()` helpers in
[`cmd/iran-splitter/main.go:202`](../cmd/iran-splitter/main.go:202) and
[`cmd/germany-splitter/main.go:212`](../cmd/germany-splitter/main.go:212)
construct a `mux.StreamLimits` from config but do **not** call
`SanitizeLimits` — they stay as-is. (A mirror copy of `node.go:142` at
`node_b25.go:142`, if still in the build set, tracks `node.go:142`
identically.)

**The existing
[`queue_test.go:127`](../pkg/mux/queue_test.go:127) `TestSanitizeLimits`
asserts the *silent-reset* behaviour** (its `MaxBytesTotal=50 < 100` case at
`queue_test.go:143`–`151` expects the default to be returned, not an error) —
that test is **amended in this slice's gate** to assert the loud error
(`TestSanitizeLimitsFailsLoud`). Update the shipped config default
(`SetStreamLimits`, [`carrier.go:483`](../pkg/mux/carrier.go:483)) to the same
704/16-MiB pair **in this same slice**. *New tests:*
`TestMaxBytesPerStreamReduced`, **`TestMaxBytesTotalSetTo16MiB`** (B5),
`TestSanitizeLimitsFailsLoud`, **+ the `queue_test.go:127` amendment**.
**Gate (files edited):** [`pkg/mux/carrier.go`](../pkg/mux/carrier.go)
(`:436` def + `:481–:483` `SetStreamLimits`→`error`),
[`pkg/node/node.go`](../pkg/node/node.go) (`:142` propagate the error),
[`internal/config`](../internal/config) (config path),
[`pkg/mux/queue_test.go`](../pkg/mux/queue_test.go) (`:127` amendment).
`go build ./... && go test ./pkg/mux/... ./internal/...` + `go test ./...`.

**Slice 8 — integration loopback (`pkg/node/credit_test.go` extend).**
Two `Node`s over in-memory pipes; transfer 1/4/8 MiB DE→IR; assert 0
`dropped_data_frames`, 0 `data_undeliverable`, `relay_credit_gate_park > 0`,
rate ≥ 50 MB/s; **and the B1 over-ack loopback invariant —
`Σ bytesConsumed ≤ Σ bytes actually written to the client socket`, asserted as
an invariant (never violated), not a threshold.** **Gate:**
`go build ./... && go test -race ./pkg/node/...` + `go test ./...`.

**Slice 9 — live A/B methodology (operator, no code).** Per Section 12.

**Wire-version / upgrade consideration (R2, R5).** `AuthVersion` is **already
2** (shipped Phase A), and a v1 peer is rejected **at auth**
([`auth.go:232`](../pkg/mux/auth.go:232)/`381`/`398`) — so there is **nothing
else that gates the upgrade**: the handshake itself enforces it. A
**partially-upgraded pair cannot handshake at all** (it fails
`ErrAuthVersion`), so a node running Phase B (credit-enabled) against a node
without Phase B (credit-disabled but still `AuthVersion=2`) **does** handshake
(same auth version) and then: the non-credit side never emits credits, so the
credit side's ledger times out to **SAFELY_CAPPED (64 KiB)** via
`CreditSafeTimeout` and caps the stream to 64 KiB — **safe but slow**, never
unlimited and never a hang. This is the intended graceful-degradation path;
both ends must be upgraded to full speed. **Do not** deploy credit-enabled
builds to only one end expecting full throughput.

---

## 12. Phase B test matrix

**Unit** (in `pkg/node/credit_test.go`, `pkg/mux/carrier_test.go`):
ledger arithmetic (`canSend`/`recordSent`/`onCredit`), latch + `SAFELY_CAPPED`
timeout state machine, batching thresholds, `ClampCreditWindow`,
gen-rejection (`StaleCreditGeneration` / `onCredit` stale path),
`ctrlCh` priority + drain-on-close + drop-on-full.

**Integration loopback:** `TestLoopbackTransfer{1,4,8}MiB` — DE→IR over
in-memory pipes, `go test -race ./pkg/node/...`.

**Live-staging measurement with MANDATORY scoring.** For **every** transfer:
`PASS` ⟺ **`rc==0` AND `received==expected` AND checksum-match AND
`rate >= threshold`**. **HTTP 200 is NOT success** (curl returns 200 on a
truncated body).

**Baseline anchor (S4, REV 1 change).** REV 0 anchored the A/B baseline to
"≈ 1,372 KB/s for the 1 MiB down transfer" — but §0 states that 1 MiB down
transfer delivers **0 bytes** in the no-credit build, so a 0-byte baseline has
**no rate** and the criterion was undefined at t=0. REV 1 re-anchors the
rollback criterion to a baseline that *exists* at t=0: the **no-credit
build's raw ceiling, 121.4 MiB/s**, measured on a **small 16 KiB down
transfer** (16 KiB ≪ 704 KiB mailbox ⇒ never trips `fullLocked`/
`rejectAggregate` in *either* build, so it delivers the full raw ceiling in
the no-credit arm — a well-defined rate at t=0). The 1 MiB arm is scored on
`received==expected` (the D4 symptom is 0 bytes, not a rate).

**A/B rate methodology.** Measure **rate**, not pass/fail (the D4 bug was
caught *only* because rate was measured). Arms: (1) no-credit baseline, (2)
credit-enabled. Run each 5× on the **16 KiB transfer** (the baseline anchor
above); record bytes/sec + all counters in Section 13. The rate threshold is
explicit and must catch a **≥161×-class throttle**: `PASS` requires
`rate_v2 >= 0.5 × rate_baseline` where **`rate_baseline` is the no-credit
build's measured raw ceiling on the same 16 KiB transfer (≈ 121.4 MiB/s at the
ceiling; the measured no-credit 16 KiB rate is the anchor at t=0)**; a
`rate_v2` that drops to the ~8 KB/s D4 region is a **hard FAIL → immediate
rollback**.

**Race tests.** The mandatory Linux-semantics `-race` run is named to the
**staging host** that runs `iran-splitter` (the Iran staging box), **not** the
Windows workspace: `go test -race ./pkg/mux/... ./pkg/node/...` on that host.

**Rollback criteria.** Roll back if (a) `rate_v2 < 0.5 × rate_baseline` on
the 16 KiB anchor transfer, (b) any `dropped_data_frames`/
`data_undeliverable` appears that was absent in baseline, or (c)
`CreditSafeTimeout` latches the dominant transfer to 64 KiB sustainedly (a
sign the credit link is broken) — (c) is now reason-classified via
`credit_degraded_reason{no_credit_peer, timeout}` (S8), so a rollback trigger
names *which* degradation fired.

**The specific counter D4's instrumentation lacked.** D4 had
`relay_credit_block=0` because the relay parked at the **`pending` gate**
([`relays.go:106`](../pkg/node/relays.go:106)), not at the credit gate, so the
block counter was blind to the harm. Phase B adds the counter that actually
moves when the **credit gate** (not the pending gate) parks the relay:
**`relay_credit_gate_park`** (Section 13) — D4's `relay_credit_block` measured
the wrong gate; `relay_credit_gate_park` measures the real one.

---

## 13. Metrics + observability

New counters on [`pkg/node/metrics.go`](../pkg/node/metrics.go) `Metrics`
(fixed-cardinality, rendered by the existing `/metrics` `Render`, the
[`metrics.go:495`](../pkg/node/metrics.go:495)–`510` block). **No label is
attacker-controlled:** every new metric is an unlabeled node-local counter
(matches the existing `relay_*` / `session_close_reason{...}` style; the only
labelled family already shipped is the fixed `reason=` enum, `metrics.go:503`–`510`).

| Counter | Label(s) | Meaning / where it renders |
|---|---|---|
| `credit_emitted` | none | credits successfully written (emitter). >0 proves the credit link works. |
| `credit_consumed` | none | credits accepted by `onCredit` (sender). |
| `credit_stale_rejected` | none | `onCredit` gen/monotonic rejects. Sustained >0 = gen desync. |
| `credit_dropped_full` | none | `TryWriteControlFrame` drop-on-full. >0 = ctrlCh pressure (incl. anchor drops, O4). |
| `relay_credit_gate_park` | none | **the missing D4 counter** — credit-gate park events (distinct from the pending gate). |
| `relay_credit_gate_park_max_ms` | none | max single gate-park duration (HOL/backpressure visibility). |
| `credit_safely_capped` | none | streams degraded to the 64 KiB SAFELY_CAPPED window. |
| `credit_gate_admission_deferred` **(S7)** | none | a stream **parked before attach** because the funded count was exceeded — the admission case. Without it the 12th/24th-stream (aggregate-trip) case is **invisible**, the same D4 blind-counter mistake. |
| `credit_degraded_reason` **(S8)** | `reason ∈ {no_credit_peer, timeout}` (fixed enum) | classifies every `credit_safely_capped` event by **cause** — a no-credit peer (mixed upgrade, §11 wire-version) vs. a `CreditSafeTimeout` — so a `SAFELY_CAPPED` degradation is operator-visible per reason, not silent. Fixed-cardinality (2 values), matching the shipped `reason=` enum style (`metrics.go:503`–`510`). |

**How an operator confirms the gate works (without being blind):** watch
`relay_credit_gate_park` (the gate actually pacing), `credit_emitted`/
`credit_consumed` (the credit link alive end-to-end), and
`credit_safely_capped` (degradation). All render on the node's `/metrics`
endpoint next to the existing `relay_*` block — so the D4 failure mode
("0 blocks reported but 161× slower") is now **directly observable**: a slow
transfer with `relay_credit_gate_park ≈ 0` **and** `credit_emitted ≈ 0`
pinpoints the rebind-serialization arm rather than a silent gate.

---

## 14. Config / env surface

New keys in [`internal/config/config.go`](../internal/config/config.go)
(env-const block [`config.go:54`](../internal/config/config.go:54)):

| Key | Default | Purpose |
|---|---|---|
| `SPLIT_CREDITS_ENABLED` | `false` | Feature flag; master on/off (Section 15). |
| `SPLIT_STREAM_QUEUE_BYTES` | **704 KiB** | `MaxBytesPerStream` (existing key, new default — Slice 7). |
| `SPLIT_STREAM_QUEUE_TOTAL_BYTES` | **16 MiB** (B5) | `MaxBytesTotal` (existing key, new default — Slice 7). **REV 1 amendment:** the approved architecture doc says 8 MiB; the reviewer-approved B5 raises it to 16 MiB (23 full mailboxes) so a normal 12-parallel-fetch SOCKS client does **not** trip `rejectAggregate`. Recorded in §6. |
| `SPLIT_CREDIT_WINDOW_MAX` | 512 KiB | `creditWindowMax` = `MaxBytesPerStream − allowance − MaxPayload`. |
| `SPLIT_CREDIT_SAFE_TIMEOUT_MS` | 2000 | `CreditSafeTimeout`. |
| `SPLIT_CREDIT_BATCH_BYTES` | 64 KiB | `creditBatchBytes` (= `MaxPayload`). |

**Which slice changes `DefaultStreamLimits` + `SanitizeLimits` + shipped
config together: Slice 7** — all three move in the same slice so the
704/16-MiB pair ships atomically (v2 §10.4 B4d). **S5 (approved doc wins):**
`SanitizeLimits` returns **`(StreamLimits, error)`** and **fails loudly** when
`MaxBytesTotal < MaxBytesPerStream` — the mux is the *only* place that sees the
pair, so the loud failure is owned here (v2 §10.4 ~:1600–1613), *not* in
`internal/config`. The call sites updated in Slice 7 (complete, verified):
the `SanitizeLimits` definition ([`carrier.go:436`](../pkg/mux/carrier.go:436)),
`SetStreamLimits` ([`carrier.go:483`](../pkg/mux/carrier.go:483) — gains an
`error` return), `node.go:142` `Config.Sanitize()` (the `NewNode` site), and
the `internal/config` path — all now propagate the error, so a lone
704-KiB-per-stream build **cannot start**. The `cmd/*/main.go`
`streamLimits()` helpers do not call `SanitizeLimits` and are unaffected. The
existing [`queue_test.go:127`](../pkg/mux/queue_test.go:127) silent-reset
assertions are amended in Slice 7's gate.

---

## 15. Rollback plan (disable without redeploy)

- **Feature flag `SPLIT_CREDITS_ENABLED` (default `false`).** When off:
  `creditGate.ledger` returns nil (gate bypassed, `canSend` not called),
  `creditEmitter.recordConsumed` is a no-op, and `recordPeerGen` is a no-op —
  the **no-credit fallback is exactly today's shipped behaviour** (the
  `pending >= 256 KiB` gate + mailbox caps remain the enforcement). This is a
  **default-off** design: flipping the env flag to `false` (or restarting
  without it) returns the node to the no-credit path **without redeploying
  code** (a restart picks up the env var; the `ctrlCh` control plane stays in
  the binary but idle, carrying only Ping/Pong/Close).
- **Graceful degradation, not a hard off-switch, on a mixed pair** (Slice
  9/§11): a credit-enabled end talking to a no-credit end degrades the stream
  to `SAFELY_CAPPED` (64 KiB) after `CreditSafeTimeout` — bounded, safe, and a
  full rollback is simply `SPLIT_CREDITS_ENABLED=false` on both sides.

---

## Appendix — the exact symbol set Phase B introduces

**mux (`pkg/mux/carrier.go`):** `ctrlCh`, `ctrlWG`, `drainCtrl`, `writeOne`,
`TryWriteControlFrame`, `WriteControlFrame`, `OnStreamCredit` (callback field),
**`Limits()` accessor** (S1 — returns the live `c.limits`); `writeLoop`
rewritten (priority peek + arbitrary hand-off, E); `Close` re-sequenced;
`Dispatch` `FrameCredit` case now calls `OnStreamCredit`.
**node (`pkg/node/credit.go`, new):** `creditEmitter`, `streamCredit`
(`consumed`, `pending`, `peerGen`, `lastEmit`), **`carrierKey` (S6)** —
`(carrier, streamID)` record key; `creditLedger`
(`outstanding`, `lastSeen`, `window`, `latched`, `safelyCapped`, `gen`,
**`ready`/`nWaiters` — B4 wake channel**, **`wakeLocked`**),
`creditGateManager`, `canSend` (B2 UNLATCHED bound + S1 carrier cap),
`recordSent` (S3 per-chunk), `onCredit` (B4 wake), `reset`,
`recordConsumed` (B1 enforced shape), `recordPeerGen`, `emit`, `finalize`,
**`emitAnchor` (B2/B3 — `go`-spawned at attach)**, `creditPark` (B4 `ready`
select); consts `creditUnackedAllowance`, `creditWindowMax`,
`creditInitialWindow`, `CreditSafeWindow`, `CreditSafeTimeout`,
`creditBatchBytes`, `creditBatchMaxAge`, **`creditPreLatchBound` (B2, 640 KiB)**.
**node (`pkg/node/relays.go`, `node.go`):** gate hook in `relayShapeA`,
emission hook in `startStreamRelay` (B1 write shape), `OnStreamCredit` wiring
in `install`, reset/attach-time anchor in `rebindDirection`/`handleRebind`.
**mux (`pkg/mux/carrier.go`, S5):** `SanitizeLimits` →
`(StreamLimits, error)` loud-fail; call sites at `:436`/`:483`/config/`NewNode`.
**metrics (`pkg/node/metrics.go`):** the 9 counters in Section 13
(`credit_emitted`, `credit_consumed`, `credit_stale_rejected`,
`credit_dropped_full`, `relay_credit_gate_park`,
`relay_credit_gate_park_max_ms`, `credit_safely_capped`,
**`credit_gate_admission_deferred` (S7)**, **`credit_degraded_reason` (S8)**).
**config (`internal/config/config.go`):** the keys in Section 14.
**mux tests + node tests** named in Section 11/12.
