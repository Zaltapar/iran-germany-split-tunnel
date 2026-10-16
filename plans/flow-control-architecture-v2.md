# Flow-Control Architecture v2 — Design Document

> **Scope.** This document designs the v2 per-stream flow-control mechanism for the
> Iran→Germany split-tunnel. It supersedes the D4 hybrid design in
> [`plans/architecture-checkpoint-backpressure.md`](architecture-checkpoint-backpressure.md)
> (the "D4" checkpoint), which was implemented, A/B-tested on live staging, found to
> cause a ≥161× throttle, and reverted. This document is **design-only**: no
> production code, test, config, or systemd file is modified. No deployment is
> performed. No SSH is executed.

---

## REV 1 — resolved findings (audit map)

> This document was revised in place to resolve the adversarial architect's
> **NOT-APPROVED** verdict (4 blockers B1–B4, 5 should-fix S1–S5, 6 notes
> N1–N6). This table maps each finding to where it is resolved in REV 1.
> Section numbering is preserved (14 numbered sections + 2 appendices). Where
> an earlier decision changed (release point, mailbox cap, `N_max`, control-plane
> routing, timeout behaviour, wire format), **every** section that depended on
> it was updated to keep the document internally consistent.
>
> **REV 2 annotation (do not read as history):** REV 1's own "every dependent
> section was updated / internally consistent" claim **over-claimed** — the
> adversarial re-review (REV 2) verified B1–B4, S1–S5, N1–N6 in the body but
> returned APPROVED-WITH-AMENDMENTS with 12 residual defects (S1-A, S1-B, S2,
> S3, S4, S5, S6, N1–N6 below), fixed **in place** and mapped in the
> `## REV 2 — resolved findings (audit map)` table that follows this table.

| Finding | Resolution (REV 1 location) |
|---|---|
| **B1** D4 root cause mis-attributed | §1.1 (revised), §1.2 (revised). D4 credit was **cumulative-absolute** (`credit = cumulativeBytesPopped − cumulativeSent`), not per-chunk; the "one RTT per Pop" claim is **retracted**. The D4 credit source is **NOT in the tree** (`staging-credit-b254722/` binaries are the reverted no-credit build — 0 app-level credit symbols); the ledger arithmetic is sourced from the D4 checkpoint doc with `path:line`. The mechanism is stated as **UNRESOLVED-from-source** plus the single decisive measurement. |
| **B2** Throughput arithmetic inconsistent (~44×) | §1.4 (revised), §3.2 (revised), §8.1–§8.4 (revised). "One RTT per Pop" replaced by the measured per-chunk latency; all throughput numbers re-run consistently; `512 KiB / 90 ms ≈ 5.7 MB/s` vs the 1,372 KB/s baseline explicitly reconciled. |
| **B3** §7.2 ctrlCh blocks forever + reorders Rebind/DATA | §7.2 (revised). `ctrlCh` now has `writeWG`+`drainWrites` treatment and abortable enqueue on `c.closed`; `FrameRebind`/`FrameHeader` **stay on `writeCh`** (FIFO with DATA); only `FrameCredit`/`Ping`/`Pong` on `ctrlCh`. Per-frame-type routing table + in-order proof added. |
| **B4** Memory bound does not close | §10 (revised). Closed bound with explicit `N_max`; `writeCh`+`c.frames` treated as a separate fixed floor **outside** `MaxBytesTotal`; `DefaultStreamLimits`+`SanitizeLimits`+shipped config change in the **same** slice; `SanitizeLimits` proposed to **fail loudly**. |
| **S1** Release point (c) asserted not proven; (a) refutation circular | §6.1–§6.5 (revised). `outstanding` defined **precisely** (issued ∧ not credited ∧ not known-terminated); in-flight window (`writeCh` 256 + `c.frames` 256) added to the worst case; client-kernel-buffer over-acknowledgement window bound stated as a config requirement. _REV 2 note: the "MUST be recorded in §10" requirement had no ledger rows (S1-B) and the per-stream `outstanding` bound contradicted its own pipeline table (S1-A) — both fixed in REV 2._ |
| **S2** §9.5 "reconnect can never make unlimited" false | §9.5 (revised) + §4.1 state table. On `CreditEstablishTimeout` the stream latches to a **safe small window (`MaxPayload` = 64 KiB)** or terminates; it **never re-opens the un-latched/unlimited state** after a latch. |
| **S3** Stale-credit "structurally impossible" + gen-pinned inconsistent | §9.3 + §9.1 (revised). Anchor credit **carries `creditGen`**; the receiver derives its expectation from the carrier on which the frame **ARRIVED** (`h.gen` of the receiving carrier, directly available), **not** the rebind payload. "Structurally impossible" replaced by "prevented by generation pinning at arrival". |
| **S4** No `creditVersion`/`creditGen` handling for mixed peers; `Dispatch` drops unknown types | §5.2 + §5.3 (revised). Explicit `FrameCredit` case with validation; **REQUIREMENT + MUST test** that an unknown frame type never terminates a stream; version negotiation made explicit; **atomic-upgrade** requirement stated (both ends in the same maintenance window). |
| **S5** §11.4 fairness contradicted by its own mechanism | §11.4 (revised). Fairness claim **deleted**; residual HOL risk on the shared `writeCh` stated **honestly** with a mitigation plan (per-stream `writeCh` budget is NOT added, because it would deadlock with the `pending` gate; the honest statement is given instead). _REV 2 note: the Ping/Pong move off `writeCh` onto `ctrlCh` was unstated (RESIDUAL-S5) — now stated explicitly in §7.2 and Slice 1._ |
| **N1** Stale/wrong citations | §0.2, §2.1, §10, §11 fixed: "Dispatcher can stall… Phase 3" now cites [`queue.go:20-26`](../pkg/mux/queue.go:20) (not `carrier.go:723`); the aggregate-budget check cites [`queue.go:187-192`](../pkg/mux/queue.go:187). Every `path:line` re-verified. |
| **N2** DATA-starvation "10 μs/write ⇒ ~1 ms" estimate | §7.4 (revised). Replaced by a real worst-case analysis: a blocked `rwc.Write` of 32 KiB at 5 MB/s ≈ 6.5 ms; the resulting worst-case DATA delay is a **derived bound**, not a typical estimate. _REV 2 note: the shared-`writeCh` HOL magnitude was still only qualitative (RESIDUAL-N4) — now derived in §11.4._ |
| **N3** §5.1 payload field list accounted for only 18 bytes while claiming 25 | §5.1 (revised). The field list now **closes to a 32-byte payload** with every byte accounted for (`creditVersion` 1 + `creditGen` 8 + `bytesConsumed` 8 + `windowGranted` 4 + `flags` 1 + `reserved` 10 = 32). `creditGen` is **uint64 (8 B)** to match `carrierHandle.gen uint64` at [`node.go:155`](../pkg/node/node.go:155). **Total frame = 7 + 32 = 39 bytes.** |
| **N4** Slice 2 payload-length wire break vs D4 18-byte payload | §12 Slice 1/Slice 2 (revised) + §5.2. A **wire-format version bump** gates the slice ordering; **both ends must be upgraded atomically** (because `Dispatch` drops unknown types, [`carrier.go:770-771`](../pkg/mux/carrier.go:770)). |
| **N5** Per-slice gates must run the EXISTING `pkg/mux` suite | §12 (revised). Every slice gate names the **exact test files** to run, including the existing `pkg/mux` suite after the `writeLoop` rewrite ([`carrier_shutdown_test.go`](../pkg/mux/carrier_shutdown_test.go) asserts the `writeWG`/`drainWrites` contract being changed) and the "main stays green" step. _REV 2 note: the "exact" file list omitted 5 real `pkg/mux` test files and 5 of 10 slices still lacked the main-green step (RESIDUAL-N5/S6) — both fixed in REV 2._ |
| **N6** Which host runs the mandatory `-race` | §13.3 (revised). The mandatory Linux-semantics `-race` run is named to the **staging host** (the Iran staging box that hosts `iran-splitter`) with the exact command; the Windows workspace is NOT the race host. |

## REV 2 — resolved findings (audit map)

> The independent adversarial **re-review of REV 1 returned APPROVED-WITH-AMENDMENTS**
> (no blockers): B1–B4 / S1–S5 / N1–N6 verified resolved in the body, with 12
> residual defects. This table maps each REV 2 finding to where it is fixed in
> place (section numbers unchanged).

| REV 2 finding | Fix (location) |
|---|---|
| **S1-A** `outstanding` definition contradicted by its own pipeline table | §6.2 rewritten: `outstanding` redefined as **per-stream own in-flight** (shared P1/P2/P3 = "share allocated to this stream"; P4/P5/P6 = stream's own); the "Inside `outstanding`?" column now distinguishes **per-stream term** vs **shared per-carrier, outside `outstanding`**; the enforcement that actually holds is restated — the mailbox P4 is hard-capped at 704 KiB by [`queue.go:140-143`](../pkg/mux/queue.go:140)/[`queue.go:187-192`](../pkg/mux/queue.go:187), while the gate's per-stream limit `window + unackedAllowance = 640 KiB` bounds only the per-stream terms. Downstream re-statements: §8.4 (`outstanding ≤ 512 + 128 = 640 KiB` → per-stream terms), §11.2 case 3, §6.5 `canSend` (gate invariant, already per-stream). |
| **S1-B** S1's config requirement (IR client-socket recv buffer / DE carrier-socket send buffer "MUST be recorded in §10") had no §10.1 rows | §10.1: two new ledger rows added — **client-socket kernel recv buffer (IR)** and **carrier-socket kernel send buffer (DE)** — both "NO, bounded kernel config", both `(to be measured on first live run)`. §6.2 cross-ref updated. |
| **S2** `WriteControlFrame` specified as blocking, but the no-deadlock proof requires non-blocking | §12 Slice 1 now specifies **two** functions: `TryWriteControlFrame` (non-blocking, drop-on-full) for the credit emitter, and the blocking `WriteControlFrame` **reserved for `FrameClose`**; §7.5, §11.2 case 3, Slice 5, `TestCreditEmitterDropOnFull` and §13.1 all re-verified consistent on the non-blocking credit-emission path. |
| **S3** Stream 9 (and beyond) never specified; `N_max = 8` is not the enforcement | §10.3: new "Admission policy" paragraph — (i) streams beyond the funded count are **ADMITTED** (the aggregate cap is the only enforcement); (ii) the drop threshold is **~12** concurrent FULL mailboxes (`8 MiB ÷ 704 KiB ≈ 11.6` → ~12th trips `rejectAggregate` → `failUndeliverableData` → `dropped_data_frames`), **not 8**; (iii) **no admission control in scope for v2**; (iv) honest residual hazard at ≥12: the integrity invariant **can** terminate a stream — next thing to instrument is [`dropped_data_frames`](../pkg/mux/qstats.go) with `session_close_reason{data_undeliverable}`. |
| **S4** `N_max = 8` justified by the wrong investigation (§14.6, the UP-carrier reset study) | §10.2: `N_max = 8` restated as an **explicit operational assumption** (matching the observed maximum concurrency in the §0.4/§0.5 measurement campaign), with the §14.6 cross-reference **removed** and the confirmation deferred to Appendix B item 1 (which already asks the operator to confirm). |
| **S5** `FramePong` silently moves off `writeCh` — change unstated | §7.2: new statement that Ping/Pong move from `writeCh` (today's [`carrier.go:758-763`](../pkg/mux/carrier.go:758)) to `ctrlCh` — a **deliberate, benign, non-stream-ordering-sensitive** change (keepalive has no in-stream byte-order role); Slice 1's scope note names it and its gate now includes `liveness_test.go`'s pong-ordering assertions. |
| **S6** Gate discipline violated by 5 of 10 slices | Slices 4, 5, 6, 9 (and the preamble): each now carries the exact `**main stays green:** \`go build ./... && go test ./...\`` step, identical in wording to Slices 1/2/3/8. |
| **N1** §11.1 lock-order claim and citation are wrong | §11.1 rewritten: "**No lock nesting.** The hot path is `q.mu`-only; the budget limit is stored as a **plain value** precisely so no second lock is taken under `q.mu` ([`queue.go:51-56`](../pkg/mux/queue.go:51)). `q.mu` is **never taken while `c.mu` is held** — invariant at [`carrier.go:1024-1026`](../pkg/mux/carrier.go:1024): *"q.mu is never taken while c.mu is held anywhere else, so the lock ordering stays acyclic."* There is **no `c.mu → q.mu` nesting anywhere in the code.**" No-inversion conclusion retained. |
| **N2** The decisive measurement under-specifies H2 | §1.4 decision table: **5th arm added** — "all four D4 counters ≈ 0 with the transfer at ~8 KB/s → H2 (per-Pop `writeCredit` FIFO contention) or an unidentified stall; **no counter moves first** by construction; confirm with a pprof goroutine profile on a diagnostic build." The "none move" arm now scopes only to rebind-attach serialization. |
| **N3** §10.4 closing invariant re-includes `writeCh`/`c.frames` in the label | §10.4: the "+2 MiB" term renamed to **"headroom (2.5 MiB available)"** — the `writeCh`/`c.frames` per-share characterisation is **deleted**; the fixed 65.2 MiB floor stays outside `MaxBytesTotal` (per §10.1/§10.2); the inequality is shown **with and without** headroom — both readings close (5.63 MiB ≤ 8 MiB; 5.63 + 2.5 = 8.13 MiB ≈ 8 MiB). |
| **N4** Residual `writeCh` HOL magnitude asserted, not derived | §11.4: one-line derivation next to §7.4's ~6.5 ms control bound: worst-case delay of one stream behind a full `writeCh` = **16.3 MiB ÷ carrier rate ≈ 3.3 s at the 5 MB/s assumption** (≈ 0.14 s at the 121.4 MiB/s ceiling). §7.4 now cross-references the §11.4 derivation. |
| **N5** The "exact existing test files" list omits 5 real files | §12 preamble + Slices 1/2/8 test lists: `carrier_close_race_test.go`, `deliver_fail_test.go`, `queue_stats_test.go`, `backpressure_test.go`, `consumer_stall_test.go` **added** (all five verified present in `pkg/mux/`), plus `carrier_stats_test.go` discovered on verification. The list is now complete. |
| **N6** `uint64` wrap never addressed | §9.3: one-sentence wrap analysis — generations are monotonic `uint64` ([`node.go:480`](../pkg/node/node.go:480)); at ~1 generation per reconnect and ~10 reconnects/hour, exhausting the `uint64` space needs **~5 × 10^10 years**, so `onCredit`'s plain `gen != l.gen` `!=` check is safe against wrap (REV 2-N6). |

---

## 0. Scope, Ground Rules, and Verified Baseline

### 0.1 Topology reminder

```
client
  → Iran public SOCKS (188.121.111.122:10900, RFC1929)
  → iran-splitter
  → up-carrier (WebSocket, IR→DE)
  → germany-splitter
  → target (internet)

DOWN (target → client):
  target → DE targetConn
       → DE relayShapeA(DirDown)         [relays.go:46]
       → DE flushPending → WriteFrame     [relays.go:267, relays.go:282]
       → DE down-carrier writeCh/writeLoop [carrier.go:180, carrier.go:272]
       → TCP/REALITY (DE :443 → xray → IR :10802)
       → IR readLoop → c.frames (cap 256)  [carrier.go:229]
       → IR Dispatch (single goroutine)    [carrier.go:731]
       → IR deliver → s.q.TryPush          [carrier.go:791, queue.go:178]
       → IR streamWorker → q.Pop → s.ch    [carrier.go:921, queue.go:214]
       → IR startStreamRelay → sock.Write  [relays.go:424]
       → client
```

### 0.2 Verified constants (from current origin/main `fbe7604`)

| Constant | Value | Location |
|---|---|---|
| `MaxFrames` | 16 (hard cap, not raisable) | [`carrier.go:401`](../pkg/mux/carrier.go:401) |
| `MaxBytesPerStream` | 1 MiB | [`carrier.go:395`](../pkg/mux/carrier.go:395) |
| `MaxBytesTotal` | 32 MiB | [`carrier.go:396`](../pkg/mux/carrier.go:396) |
| `OverflowWait` | 100 ms | [`carrier.go:397`](../pkg/mux/carrier.go:397) |
| `MaxPayload` | 65535 | [`frame.go:21`](../pkg/mux/frame.go:21) |
| `writeCh` cap | 256 | [`carrier.go:180`](../pkg/mux/carrier.go:180) |
| `c.frames` cap | 256 | [`carrier.go:179`](../pkg/mux/carrier.go:179) |
| `BufferBytes` (per-dir pending) | 256 KiB default | [`node.go:127-128`](../pkg/node/node.go:127) |
| `RelayBufSize` (socket read chunk) | 32 KiB default | [`node.go:133-134`](../pkg/node/node.go:133) |
| `Grace` (carrier-loss window) | 5 s default | [`node.go:124-125`](../pkg/node/node.go:124) |

**Effective per-stream mailbox ceiling** = `min(16 × 65535, 1 MiB)` = **~1 MiB**.
Any object larger than ~1 MiB **must** stream through the mailbox; it cannot be
buffered whole. This is why enlarging the mailbox (constraint 2) is inert for the
failing case: the 1 MiB cap is already the binding constraint for a 1.24 MB object.

### 0.3 Integrity invariant (must be preserved)

An in-order in-stream DATA frame is either **DELIVERED** (queued by
`TryPush`) or the stream is **EXPLICITLY TERMINATED**
([`failUndeliverableData`](../pkg/mux/carrier.go:834) →
[`terminateStream`](../pkg/mux/carrier.go:883)). DATA is **never silently
dropped**. Metrics: [`dropped_data_frames`](../pkg/mux/qstats.go),
[`session_close_reason{data_undeliverable}`](../pkg/node/metrics.go:508).

### 0.4 Measured capacity ladder (validated, rc-scored)

| Test | Result |
|---|---|
| Raw ceiling | 121.4 MiB/s |
| DOWN 64 MiB single stream | Germany absorbed full 64 MiB; Iran delivered only ~26 MiB |
| Splitter DE→IR 1 MiB down | **0 bytes delivered** (abort via `dropped_data_frames+1` → `data_undeliverable`) |
| Splitter DE→IR 4/8/16 MiB | All abort via `dropped_data_frames+1` → `data_undeliverable` |
| UP clean | Up to 4 MiB clean; carrier reset between 4 and 8 MiB (**separate defect**, §14) |
| **Conclusion** | **D — splitter implementation** (down-mux `TryPush` refusal terminates instead of backpressuring), NOT infrastructure capacity |

### 0.5 D4 A/B measurement (live staging, reverted)

| Build | 1 MiB transfer time | Rate | `relay_credit_block` |
|---|---|---|---|
| No-credit (baseline) | 0.764 s | ≈1,372 KB/s | n/a (counter absent) |
| D4 credit build | ≥120 s | ≥8.3 KB/s | **0** (gate never parked) |

**≥161× throttle caused by D4's own code.** The D4 counters were **blind** to the
harm: `relay_credit_block=0` because the relay parked at the `pending >= capacity`
gate ([`relays.go:106-111`](../pkg/node/relays.go:106)), not at the credit gate.

---

## 1. D4 ≥161× Throttle Root Cause

> **REV 1 status: UNRESOLVED-from-source for the mechanism.** The exact
> mechanism that produced the measured 8.3 KB/s **cannot be derived from the
> source available in this tree**, for two independent reasons, both stated
> here so the operator does not build a design on a retracted claim. The
> v2 design in §2–§13 does **not** depend on that mechanism; it only requires
> that (i) credit release happens at the real consumption point (§6.1),
> (ii) control frames are not FIFO-queued behind DATA (§7), and (iii) the
> in-flight window is bounded (§6.2, §10). The single decisive measurement
> that **would** settle the mechanism is in §1.4.

### 1.1 Source availability (corrected — the D4 source is NOT in the tree)

The REV 0 text claimed the D4 credit symbols were "confirmed via the
base64-decoded symbol table of `germany-splitter.b64`". **That claim is
false and is retracted.** A direct scan of the backup tree
`staging-credit-b254722/` (both `germany-splitter` and `iran-splitter`,
~9.58 MB ELF each) finds:

- **0** occurrences of any application-level credit symbol
  (`creditLedger`, `OnStreamPopped`, `setInitialWindow`, `creditPark`,
  `relay_credit_block`, `writeCredit`, `creditGate`, `addSent`,
  `CreditFloorDrain`, `CreditEstablishTimeout`, `emitCreditAnchor`,
  `cumulativeBytesPopped`, `CreditPayload`, `FrameCredit`).
- The **only** 6 `credit` (case-insensitive) matches in each binary are Go
  **GC-runtime** symbols: `runtime.deductAssistCredit`,
  `runtime.gcFlushBgCredit`, `runtime.deductSweepCredit` — unrelated to this
  feature.
- The binaries **do** contain current-main symbols such as `StreamLimits`
  (6×) and `OnStreamTerminated`, i.e. they are a build of the **no-credit**
  (reverted) main, not the D4 credit build.

**Consequence:** the D4 credit implementation **cannot be grepped out of the
backup tree**. The authoritative statement of D4's ledger arithmetic is the
D4 checkpoint document,
[`plans/architecture-checkpoint-backpressure.md`](architecture-checkpoint-backpressure.md)
§E. The §1.2 ledger facts below are therefore cited to that document
(`path:line`), **not** to the binary. The operator must confirm which binary
was actually deployed for the live D4 A/B (the reverted no-credit build in
this folder does not contain the credit code).

### 1.2 D4 ledger arithmetic (verbatim, from the checkpoint doc §E)

The D4 credit was **CUMULATIVE-ABSOLUTE**, not a per-chunk allowance:

- `credit = creditWindow = cumulativeBytesPopped − cumulativeSent`
  ([`architecture-checkpoint-backpressure.md:628`](architecture-checkpoint-backpressure.md:628)).
- `cumulativeBytesPopped` is **uint64 on the wire**, BigEndian
  ([`architecture-checkpoint-backpressure.md:679`](architecture-checkpoint-backpressure.md:679)).
- **Mandatory clamp:** DE computes `credit = popped − sent` **only if**
  `popped >= sent`; otherwise `credit := 0` (PARK)
  ([`architecture-checkpoint-backpressure.md:718`](architecture-checkpoint-backpressure.md:718)).
- **INCREMENT 3** (the latching amendment actually shipped): `onCredit` latches
  on **ANY** valid credit frame of the current generation — **including the
  on-attach `popped=0` anchor** — and that anchor **seeds
  `setInitialWindow = MaxBytesPerStream`** (1 MiB)
  ([`architecture-checkpoint-backpressure.md:734-750`](architecture-checkpoint-backpressure.md:734)).

**This is the decisive property that RETRACTS the REV 0 root-cause model.** A
cumulative-absolute credit that acknowledges `N` released bytes **releases ALL
bytes up to `N` at once**. With the anchor seeding a 1 MiB initial window,
D4 was **not** a one-chunk-per-RTT gate: the sender held a 1 MiB window from
the first credit and was not re-gated per 32 KiB chunk. The REV 0 "stop-and-wait,
one full cross-border RTT per Pop ⇒ `32 KiB / 90 ms ≈ 355 KB/s` ceiling"
(D4-4) is therefore **unsupported and is retracted** (§1.4).

**Second retraction (D4-3 "addSent lag").** The REV 0 text said DE's
`cumulativeSent` "lags bytes in flight, so the relay parks early at the
pending-cap gate". That is **not supported**: on DE, `cumulativeSent`
advances on the **same path that writes DATA** — `flushPending` →
`WriteFrame` ([`relays.go:282`](../pkg/node/relays.go:282)). There is no
separate delayed `addSent` that runs ahead of the write. The only **normal**
park in a healthy no-credit build is the `pending >= 256 KiB` gate
([`relays.go:106-111`](../pkg/node/relays.go:106)) — and it **parks
identically in the no-credit build**. So `relay_credit_block = 0` is
explained by the relay parking at the shared `pending`/`relay_buffer_full`
path, **not** by a credit-gate miss caused by an `addSent` lag.

### 1.3 What the D4 measurements actually establish

From the live A/B (§0.5): no-credit = 0.764 s for 1 MiB (≈1,372 KB/s);
D4 = ≥120 s for 1 MiB (≈8.3 KB/s), with **`relay_credit_block = 0`** and
`relay_credit_floor_drain` not isolated in the recorded data.

What these numbers **do** establish:

1. **The throttle is ≥161×** (1,372 / 8.3) and is **D4-code-specific**
   (the no-credit build does not throttle).
2. **The credit gate did not park the relay** (`relay_credit_block = 0`).
   The relay parked on the ordinary `pending >= capacity` /
   `relay_buffer_full` path ([`relays.go:106-111`](../pkg/node/relays.go:106)),
   the same path the no-credit build uses.
3. **The 8.3 KB/s figure is 44× below the 355 KB/s RTT-bound ceiling** that
   REV 0 claimed was the mechanism. This 44× gap is **unaccounted for** by
   any RTT/stop-and-wait model, which is why the RTT-bound explanation is
   retracted.

What the numbers **do not** establish (and cannot be read off the recorded
data): *which* D4 path serialized the transfer to 8.3 KB/s. That is the
UNRESOLVED mechanism (§1.4).

### 1.4 Root-cause status + the single decisive measurement

**Status: UNRESOLVED-from-source.** From the available source (the checkpoint
doc §E + current main) we can state the cumulative-absolute ledger and the
anchor-seeded 1 MiB initial window, and we can state that `relay_credit_block
= 0` means the credit gate was **not** the parking site. But **the specific
serialization that produced 8.3 KB/s is not determinable from the source in
this tree** (the D4 credit source itself is absent, §1.1). Plausible
candidates, listed **only as hypotheses, none confirmed**:

- **(H1) Un-latched pre-anchor window.** Before the first valid credit, D4 ran
  **unlimited** (A4). If the anchor/initial-window latch was delayed on the
  cross-border conn, the sender outran the 1 MiB mailbox → `TryPush` refused →
  `dropped_data_frames`/`data_undeliverable` and repeated stream teardown,
  each teardown+rebind costing a full RTT + re-attach. (The INCREMENT 3
  rationale, [`architecture-checkpoint-backpressure.md:738-742`](architecture-checkpoint-backpressure.md:738),
  describes exactly this pre-fix failure mode.)
- **(H2) Per-Pop `writeCredit` FIFO contention.** One blocking
  `FrameCredit` per 32 KiB Pop, queued on the shared `writeCh` behind DATA
  ([`carrier.go:307`](../pkg/mux/carrier.go:307)), stalling the `streamWorker`
  drain path.
- **(H3) `pending`/`relay_buffer_full` saturation.** The relay parked at the
  256 KiB `pending` gate while the client leg drained slowly; credit frames
  piling up did not help because the gate is on the **pending** path, not the
  credit path (consistent with `relay_credit_block = 0`).

**The single decisive measurement (operator action).** Run the **actual D4
binary** under a 1 MiB down transfer and record **which counter moves FIRST**
— the one that moves first identifies the mechanism:

- `relay_credit_block` moves first → the credit gate (H-reversed);
- `relay_buffer_full` moves first → the `pending`-cap gate (H3);
- `dropped_data_frames` / `overflow_terminated*` moves first → mailbox
  overflow + stream teardown loop (H1);
- none move, only the carrier rebind/`carrier_reconnect` counters move, and
  the rate is normal (≥ KB/s) → a rebind-attach serialization;
- **(REV 2 N2 — H2 arm)** **all four ≈ 0 with the transfer at ~8 KB/s
  (counter SILENCE) → H2 (per-Pop `writeCredit` FIFO contention) or an
  unidentified stall.** H2 produces **no first-moving counter** by
  construction (its harm is a *rate* collapse, not a counter increment),
  so "none move" **does NOT route to rebind-attach** when the rate is
  ~8 KB/s. **Confirm H2 with a goroutine profile (pprof)** on a diagnostic
  build: a goroutine parked in `FrameCredit` queueing on the shared
  `writeCh` behind DATA is the H2 signature.

Record, alongside, the D4 1 MiB transfer time and the no-credit baseline
(0.764 s / 1,372 KB/s) under the **same** client, so the ≥161× factor is
reproduced. **Until this measurement is run, the D4 mechanism in this document
is declared UNRESOLVED and no v2 decision in §2–§13 rests on it.**

---

## 2. Candidate Architectures

### 2.1 Architecture A: Receiver-Side Per-Stream Credits (Window-Based, Receiver-Driven)

**Mechanism.** The receiver (IR, for the down direction) grants the sender (DE)
a **credit window** expressed in bytes. The sender may have at most
`creditWindow` bytes "in flight" (in the mailbox + in transit + in the kernel
send buffer) at any moment. The receiver releases credit **only when it has
actually consumed bytes from the mailbox AND the consumer (socket writer) has
acknowledged them** — i.e. at the **socket `Write` completion** point
(option (c)).

**Credit release point: (c) on successful socket `Write` by the relay.**

```
IR streamWorker:
  it, ok := q.Pop()          // mailbox drain
  s.ch <- it.payload         // handoff to startStreamRelay
  (no credit emitted here)

IR startStreamRelay:
  frame, ok := <-ch
  n, err := sock.Write(frame)
  if err == nil && n > 0:
      creditEmitter.emit(streamID, n)   // batched, see §7
```

**Why (c) and not (a) or (b):**

- **(a) `OnStreamPopped` (mailbox pop):** The mailbox pop is a **local** event
  on IR. It tells us the byte has left the mailbox and been handed to the
  `s.ch` channel. But the `s.ch` channel (cap 1) may be full (the
  startStreamRelay consumer hasn't read it yet), and the consumer's
  `sock.Write` may be blocked (client TCP recv buffer full). **Popping from
  the mailbox does NOT mean the byte has been consumed by the client.** If we
  grant credit on Pop, we are granting credit for bytes that may still be
  sitting in `s.ch` (1 frame) or in the startStreamRelay's local buffer, not
  yet in the client's kernel recv buffer.
  
  **Why (a) is insufficient (REV 1 — corrected, non-circular argument).**
  The argument is **mechanistic, not the D4 A/B.** A pop is a **mailbox-drain
  event**; it says nothing about whether the byte has left the *client kernel
  recv buffer* on the other end. The D4 A/B (8.3 KB/s,
  `relay_credit_block = 0`) **cannot be cited as proof that (a) is
  insufficient**, because D4's failure also involved the **un-latched
  pre-anchor window** (the sender ran unlimited until the first valid credit,
  §1.3 H1) — so that measurement is entangled with two variables (release point
  **and** latching) and cannot isolate the release point. The D4 A/B is
  therefore **excluded as evidence** here. The argument that (a) is the wrong
  release point rests on the state diagram alone: a pop occurs *before* the
  byte has crossed the `s.ch` handoff and *before* the client-socket
  `sock.Write`; neither is a consumption event, so credit granted at (a)
  over-acknowledges bytes still in the pipeline (§6.2 formalises the
  pipeline-width bound that makes the (c) choice load-bearing).

- **(b) Channel handoff to the relay/scanner:** The `s.ch <- it.payload`
  handoff means the byte has been placed in the cap-1 channel. The
  startStreamRelay consumer will read it soon, but "soon" is not bounded —
  the consumer may be blocked in `sock.Write` (client slow) or in
  `att.State()` checks. **Handoff to the channel does NOT mean the byte has
  been written to the socket.** It is one step closer than (a) but still not
  the consumption point.

- **(c) Socket `Write` completion:** This is the **only** point at which we
  know the byte has been accepted by the kernel TCP stack on the client
  side. The client's kernel will handle retransmission, ACK, and buffering.
  From the perspective of the tunnel's flow control, the byte is "consumed"
  (in the sense that it is no longer the tunnel's responsibility to hold
  it). **This is the correct release point.**

**DATA bounding.** The sender (DE) maintains a per-stream `outstanding`
counter. `outstanding` is incremented by the number of bytes in each
`WriteFrame` call (the chunk size, up to 65535). `outstanding` is decremented
when a credit frame arrives from the receiver. The sender may issue a
`WriteFrame` only if `outstanding + chunk_size <= creditWindow + unackedAllowance`.
When `outstanding >= creditWindow + unackedAllowance`, the sender parks
(stops reading the target) until a credit frame arrives.

**Failure modes (REV 1).**
- **Credit frame lost:** The sender's `outstanding` is not decremented for
  that chunk; the sender eventually parks. If the loss persists,
  `CreditSafeTimeout` (2 s) fires and the stream degrades to
  **`SAFELY_CAPPED`** (bounded at `CreditSafeWindow` = 64 KiB) — **NOT** to
  unlimited (S2). **Mitigation:** credit frames are small (39 B) and ride the
  same reliable TCP/WS conn; loss is rare and heals on the next credit.
- **Credit frame stale (from a previous carrier generation):** Stale credits
  are **prevented by generation pinning at arrival** (§9.3/S3) — the credit's
  `creditGen` must equal the `h.gen` of the arriving carrier; otherwise it is
  rejected. (REV 0's "structurally impossible" claim is retracted, §9.3.)
- **Dispatcher stall:** The sender parks its relay (stops reading target) but
  the dispatcher on the receiver side is **unaffected** — it does a
  non-blocking `TryPush` and, on a full mailbox, moves on to other streams
  and applies the overflow policy to just this stream
  ([`queue.go:20-26`](../pkg/mux/queue.go:20)) ([`carrier.go:791`](../pkg/mux/carrier.go:791)).
  The mailbox is bounded by `MaxBytesPerStream` (`fullLocked` /
  `rejectAggregate`, [`queue.go:140-143`](../pkg/mux/queue.go:140),
  [`queue.go:187-192`](../pkg/mux/queue.go:187)), so it can't overflow
  silently. **No HOL stall of the shared `writeCh` by the dispatcher.**

**Interaction with integrity invariant.** Credit only ever **parks** the
sender; it never drops a queued byte. The `failUndeliverableData` safety net
([`carrier.go:834`](../pkg/mux/carrier.go:834)) remains armed: if the mailbox
somehow overflows (should not happen under credit), the stream is terminated
cleanly, not silently corrupted.

**Dispatcher can stall?** No. The dispatcher's `TryPush` is bounded by the
mailbox's `MaxBytesPerStream` cap (`fullLocked` / `rejectAggregate`,
[`queue.go:140-143`](../pkg/mux/queue.go:140),
[`queue.go:187-192`](../pkg/mux/queue.go:187)). `TryPush` is
**non-blocking**: on a full mailbox it refuses and the dispatcher moves on
to other streams, applying the overflow policy to just this stream
(`deliver` → `applyPressure`, [`carrier.go:791`](../pkg/mux/carrier.go:791)).
The dispatcher is **never blocked on a slow consumer** (the "dispatcher never
blocks" invariant, [`queue.go:20-26`](../pkg/mux/queue.go:20)).

---

### 2.2 Architecture B: Pause/Resume (Window-Update with Sender-Side Suspend)

**Mechanism.** Instead of byte-granular credits, the receiver sends a **binary
pause/resume** signal. The sender, on receiving `pause`, stops issuing
`WriteFrame` calls for that stream. On receiving `resume`, the sender
resumes. The "window" is implicit: it is the sum of all bytes sent since the
last `pause` that have not yet been `resume`d.

**Credit release point.** The receiver sends `pause` when its mailbox
occupancy exceeds a high-water mark (e.g. `MaxBytesPerStream / 2`), and sends
`resume` when occupancy drops below a low-water mark (e.g.
`MaxBytesPerStream / 4`). The release is **on occupancy threshold**, not on
socket consumption.

**Why this is inferior to A:**
- **Coarse control.** A binary pause/resume cannot express "I can take 512 KiB
  more" vs. "I can take 16 KiB more". The sender either has the full window
  or nothing. On a cross-border conn with high RTT, the sender will either
  burst the full window (filling the mailbox, triggering
  `failUndeliverableData`) or pause entirely (throughput → 0).
- **Hysteresis problem.** The high/low-water marks must be tuned. If the high
  mark is too low, the sender pauses too early (underutilisation). If the low
  mark is too high, the sender resumes too late (mailbox overflow →
  `failUndeliverableData`).
- **No byte accounting.** Without a running `outstanding` counter, the sender
  cannot know how many bytes are in flight. It can only guess. On a lossy or
  high-RTT conn, the guess is unreliable.

**Failure modes.**
- **Pause lost:** Sender keeps sending, mailbox overflows,
  `failUndeliverableData` terminates the stream. **Integrity is preserved**
  (clean termination) but **availability is lost**.
- **Resume lost:** Sender is paused forever (until `CreditEstablishTimeout`
  fires). **Availability is lost** for the duration of the timeout.
- **Hysteresis oscillation:** If the high/low marks are too close, the sender
  oscillates between pause and resume at a rate determined by the consumer's
  drain rate, causing `writeCh` to fill with a high rate of control frames
  (same FIFO contention problem as D4-1).

**Dispatcher can stall?** No (same as A). But the mailbox can overflow if
the pause is lost, triggering `failUndeliverableData`.

---

### 2.3 Architecture C: Hybrid (Credits + Bounded "Unacked-in-Flight" Allowance)

**Mechanism.** Combine A's byte-granular credits with a **bounded unacked
allowance**. The sender may have at most `creditWindow + unackedAllowance`
bytes in flight. `unackedAllowance` is a fixed small value (2 × MaxPayload =
128 KiB) that allows the sender to "get ahead" of the credit signal by up to
2 frames, reducing the stop-and-wait penalty by one RTT.

**Credit release point.** Same as A: on socket `Write` completion (c).

**Why the unacked allowance helps.**
- Without the allowance, the sender is in strict stop-and-wait: send
  `creditWindow` bytes, wait for credit, send `creditWindow` bytes, wait for
  credit. Each cycle is one RTT.
- With the allowance, the sender can send `creditWindow + unackedAllowance`
  bytes before parking. The `unackedAllowance` (128 KiB) covers 2 additional
  64 KiB frames, so the sender can pipeline 2 extra frames ahead of the
  credit signal. This reduces the stop-and-wait penalty by ~2 frames × RTT.
- The allowance is **bounded** (not unlimited), so the mailbox can't
  overflow: `outstanding <= creditWindow + unackedAllowance`. The receiver's
  mailbox cap must be at least `creditWindow + unackedAllowance` to absorb
  the pipelined frames.

**Failure modes.**
- **Allowance too large:** Mailbox overflows. **Mitigation:** the allowance
  is a fixed small constant (2 × MaxPayload), and the mailbox cap is set to
  `creditWindow + unackedAllowance + safety_margin`.
- **Credit lost + allowance exhausted:** Sender parks (same as A).
  `CreditEstablishTimeout` is the safety valve.

**Dispatcher can stall?** No (same as A). The allowance is bounded, so the
mailbox is bounded.

---

## 3. Selected Architecture

**Selected: Architecture C (Hybrid: byte-granular credits + bounded unacked
allowance), with credit release at the socket `Write` completion point
(c).**

### 3.1 Justification tied to constraints and measured ladder

| Constraint | How C satisfies it |
|---|---|
| Do NOT resurrect D4 as-is | C changes the release point from `OnStreamPopped` (a) to socket `Write` completion (c); **credits are batched** (one `FrameCredit` per `MaxPayload` = 64 KiB consumed, not per 32 KiB Pop — D4's per-Pop emission, §1.2); the unacked allowance pipelines 2 frames ahead of the credit signal so the sender is **not** forced into per-chunk stop-and-wait; `outstanding` is tracked on the **sender** side (DE), so there is no receiver-side `addSent`-lag artefact (retracted in §1.2). |
| Do NOT enlarge mailbox | The mailbox cap `MaxBytesPerStream` is **reduced** to `MaxPayload + unackedAllowance + window_max = 704 KiB` (§10.1; REV 0's "enlarge" framing is gone — this is a reduction). `MaxFrames` stays at 16. The effective per-stream `outstanding` ceiling becomes `window_max + unackedAllowance` = 512 + 128 = 640 KiB, **under** the 704 KiB mailbox cap. |
| Do NOT allow DATA drops | Credit only parks the sender. `failUndeliverableData` remains the armed safety net. |
| Do NOT block the dispatcher | The dispatcher is unaffected by credit (it pops from the mailbox at the consumer's rate). The sender parks its relay, not the dispatcher. The `writeCh` FIFO is not starved by credit frames (see §7: separate control queue). |
| Build per-stream flow control with real downstream capacity | Credit is released at socket `Write` completion — the **actual** consumption point. The window is sized to `target_rate × effective_RTT + safety_margin` (§8). |
| Control frames must not get stuck behind DATA | §7: credit frames ride a **separate control queue** with strict priority over DATA. |
| Stale credit must never increase allowance | §9: the `outstanding` counter is per-carrier-generation; the anchor credit **carries `creditGen`** and the receiver pins its expectation to the **`h.gen` of the carrier on which the frame ARRIVED** (directly available, not the rebind payload). Stale credits are **prevented by generation pinning at arrival** — a credit whose `creditGen` ≠ the arriving carrier's `h.gen` is rejected (§9.3). |
| Measured ladder: DE→IR 1 MiB down = 0 bytes | Under C, DE is parked at `outstanding >= window + allowance` (640 KiB), not at the mailbox cap (704 KiB = `MaxBytesPerStream`). The mailbox never overflows. `dropped_data_frames` stays 0. A 1 MiB object **streams through** at the client's drain rate (no longer aborted at the 17th frame, because the mailbox cap is now below the object size, so it must stream). |

### 3.2 Why not A or B

- **A (pure credits, no allowance):** Throughput is bounded by
  `creditWindow / effective_RTT` (the window, not one chunk, fills per RTT).
  At `creditWindow = 512 KiB` and `effective_RTT = 90 ms`:
  **512 KiB / 90 ms ≈ 5.7 MB/s** — a *window-bound* ceiling, not a
  per-chunk stop-and-wait figure (REV 1: the "one RTT per 32 KiB Pop ⇒ 355 KB/s"
  model was retracted in §1.2/§1.4). This 5.7 MB/s ceiling **exceeds the
  1,372 KB/s no-credit baseline** by ≈4.2×, so a 512 KiB window can reach the
  baseline. The unacked allowance in C pipelines 2 extra frames ahead of the
  credit signal, so the sender needs only ≈1 re-gate per
  `creditWindow + unackedAllowance` bytes rather than one per `creditWindow`.
  **Note (B2 reconciliation):** the measured no-credit baseline (1,372 KB/s)
  is **client-rate-bound, not window-bound** — a 512 KiB window is ample.
  §8.4 therefore sets the *starting* window to 512 KiB (not the 1 MiB REV 0
  value, which was only equal to the now-704 KiB mailbox cap as an accident).
- **B (pause/resume):** Coarse, hysteresis-dependent, no byte accounting.
  Inferior to C on all axes.

---

## 4. State Machine

### 4.1 Sender (DE, down direction) — per stream

```
   carrier attach / rebind-attach
                 │
                 ▼
          ┌───────────────┐
          │   UNLATCHED   │  credit disabled, but STILL bounded by
          │ (NOT unlimited)│  MaxBytesPerStream / MaxBytesTotal
          └───────┬───────┘
        first     │      │ CreditEstablishTimeout (CreditSafeTimeout = 2 s)
        valid     │      │ with no valid credit
      FrameCredit │      │
                 ▼      ▼
          ┌───────────┐ ┌────────────────┐
          │  LATCHED   │ │ SAFELY_CAPPED  │  latched to a SAFE SMALL
          │ (window)   │ │ (MaxPayload)   │  window = MaxPayload (64 KiB)
          └─────┬─────┘ └───────┬────────┘  => NEVER unlimited
                │                │ later valid credit (upgrades window)
                │                └──────────▶ LATCHED
                ▼
          ┌───────────┐  outstanding >= window+allow  ┌─────────┐
          │  FLOWING   │──────────────────────────────▶│ PARKED  │
          └───────────┘  FrameCredit lowers           └─────────┘
                ▲                                     │
                └──────────────────────────────────────┘
                        (on credit)
   carrier loss / rebind / session close /
   CreditEstablishTimeout-while-PARKED
                │
                ▼
          ┌───────────────┐
          │  TERMINATED    │  a latched stream NEVER re-opens unlimited
          └───────────────┘  (credit state cleared, gen bumped)
```

| State | Description | Transitions |
|---|---|---|
| `UNLATCHED` | No valid credit frame yet for this carrier generation. Credit is **disabled** but the stream is **NOT unlimited**: it is still bounded by `MaxBytesPerStream` / `MaxBytesTotal` (the mailbox caps), so memory stays closed (§10). | → `LATCHED` on first valid `FrameCredit`; → `SAFELY_CAPPED` on `CreditEstablishTimeout` (`CreditSafeTimeout` = 2 s, no credit in window); → `TERMINATED` on session close / rebind. |
| `LATCHED` | A valid credit frame has been received. Sender tracks `outstanding` bytes and gates at `window + unackedAllowance`. | → `FLOWING` (`outstanding < window+allow`); → `PARKED` (`outstanding >= window+allow`). |
| `SAFELY_CAPPED` | **New (S2):** reached when `CreditEstablishTimeout` fires **before** any credit latched, or when a credit stream stops. Latched to a **safe small window = `MaxPayload` (64 KiB)** — bounded, never unlimited. | → `LATCHED` on a later valid credit (upgrades to the full window); → `TERMINATED` on carrier loss / rebind / session close / `CreditEstablishTimeout`-while-parked. |
| `FLOWING` | Sender is reading target and issuing `WriteFrame` calls. | → `PARKED` when `outstanding >= window+allow`; → `TERMINATED` on carrier loss / rebind / session close. |
| `PARKED` | Sender has stopped reading the target. Waits for a `FrameCredit` that reduces `outstanding` below the threshold. | → `FLOWING` on `FrameCredit`; → `SAFELY_CAPPED` on `CreditEstablishTimeout` (no credit within 2 s while parked — **degrade to the safe small window, never to unlimited**); → `TERMINATED` on carrier loss / rebind / session close. |
| `TERMINATED` | Credit state cleared. Stream is closed or rebinding. | Terminal state for this carrier generation. |

**New constant (S2).** `CreditSafeWindow = mux.MaxPayload` (**64 KiB**). This is the
window a stream latches to on any `CreditEstablishTimeout` (pre-first-credit or
while-parked), replacing the REV 0 "revert to unlimited" fallback. `CreditSafeTimeout`
= 2 s (unchanged). **Invariant: once a stream has latched (`LATCHED` /
`SAFELY_CAPPED`), no transition may re-open the un-latched / unlimited state**
(`§9.5` states this as the guarantee).

### 4.2 Receiver (IR, down direction) — per stream

```
                ┌──────────┐
                │ DRAINING │  streamWorker is popping from mailbox
                └────┬─────┘  and handing off to startStreamRelay
                     │
                     ▼
              ┌──────────────┐   socket Write completes (n bytes > 0)
              │ CREDIT DUE   │──────────────────────────────────┐
              └──────────────┘                                  │
                    ▲                                           ▼
                    │                              ┌─────────────────────┐
                    │                              │ CREDIT EMITTING    │
                    │                              │ (batched, §7)      │
                    │                              └──────────┬──────────┘
                    │                                         │
                    │  credit frame written to ctrlCh         │
                    └─────────────────────────────────────────┘
                                                        │
                                                        ▼
                                                ┌──────────────┐
                                                │  IDLE         │
                                                │ (no credit    │
                                                │  due)         │
                                                └──────────────┘
                                                        │
                                                        │  carrier loss / rebind /
                                                        │  session close
                                                        ▼
                                                ┌──────────────┐
                                                │  TERMINATED  │
                                                └──────────────┘
```

| State | Description | Transitions |
|---|---|---|
| `DRAINING` | The `streamWorker` is actively popping from the mailbox and handing off to `startStreamRelay`. | → `CREDIT_DUE` when a socket `Write` completes (n bytes > 0). |
| `CREDIT_DUE` | Bytes have been consumed by the socket. Credit is owed to the sender. | → `CREDIT_EMITTING` (batched emission, §7). |
| `CREDIT_EMITTING` | The credit frame is being written to the `ctrlCh` (control queue, §7). | → `IDLE` on successful write; → `DRAINING` if more bytes are available. |
| `IDLE` | No credit is due. Awaiting next Pop. | → `DRAINING` on next Pop; → `TERMINATED` on carrier loss / rebind / session close. |
| `TERMINATED` | Credit state cleared. Stream is closed or rebinding. | Terminal state. |

### 4.3 Carrier loss / rebind

On carrier loss (the `readLoop` exits, `Dispatch` returns, `onCarrierLost`
fires):

- **Sender:** The stream's credit state is `TERMINATED`. `outstanding` is
  discarded. On rebind-attach, both sides reset to 0 (§9). The stream enters
  `UNLATCHED` again.
- **Receiver:** The `streamWorker` for the old carrier exits (the mailbox is
  `Close`d). On rebind-attach, a new `streamWorker` is started for the new
  carrier generation. Credit state resets.

### 4.4 Half-close

On a `FrameClose` (peer half-close):

- The stream's mailbox receives a `queueItem{isClose: true}`. The
  `streamWorker` hands off `nil` to `startStreamRelay`, which calls
  `peerEOF` (half-closes the direction). The credit state for that direction
  is cleared. The other direction continues.
- **The credit gate does NOT block the EOF flush path.** Per
  [`relays.go:73-91`](../pkg/node/relays.go:73), the `socketEOF` branch is
  reached **before** the credit gate, and the EOF flush (`flushPending` to
  completion + `sendCloseFrame`) is **never credit-gated**. This is the
  half-close safety invariant (A6 in the D4 doc, preserved).

### 4.5 Remote termination

On `terminateStream` (from `failUndeliverableData` or `applyPressure`):

- The stream's mailbox is `Close`d. The `streamWorker` exits. The
  `streamRec` is removed from `c.streams`. The credit state for that stream
  is cleared on both sides (sender: `clearStream`; receiver: the
  `streamWorker` exits and the credit accumulator is zeroed). The session's
  close reason is recorded (`data_undeliverable` or `overflow`).

---

## 5. Wire Format

### 5.1 New frame type: `FrameCredit = 0x07`

All fields are **big-endian** (the entire repository is big-endian:
[`frame.go:81-83`](../pkg/mux/frame.go:81) `binary.BigEndian.PutUint32/16`,
[`frame.go:100-103`](../pkg/mux/frame.go:100) `binary.BigEndian.Uint32/16`).

**REV 1 (N3):** the REV 0 field list summed to 18 bytes while claiming 25.
The table below **closes to a 32-byte payload / 39-byte frame** with every
byte accounted for. `creditGen` is widened to **`uint64` (8 B)** to match the
in-memory type of the generation token, `carrierHandle.gen uint64`
([`node.go:155`](../pkg/node/node.go:155)) — a 32-bit `creditGen` would
truncation-wrap on long-lived carriers and break the stale check.

| Field | Offset | Size | Type | Endianness | Notes |
|---|---|---|---|---|---|
| `StreamID` | 0 | 4 | uint32 | BigEndian | Stream identifier (same as all frames) |
| `Type` | 4 | 1 | uint8 | — | `0x07` |
| `Length` | 5 | 2 | uint16 | BigEndian | Payload size (**fixed 32 bytes** for v1) |
| **Payload** | **7** | **32** | | | |
| `creditVersion` | 7 | 1 | uint8 | — | `1` for v1; any other value → **reject; degrade to `SAFELY_CAPPED`** (never unlimited, §4.1/§9.5). |
| `creditGen` | 8 | 8 | uint64 | BigEndian | **Arriving-carrier generation**, pinned at arrival (§5.2, S3). Receiver MUST verify `creditGen == h.gen` of the carrier on which the frame arrived. Stale gen → reject. |
| `bytesConsumed` | 16 | 8 | uint64 | BigEndian | **Cumulative bytes consumed** by the socket `Write` on this stream, since the last reset (rebind-attach anchors to 0). Monotonically non-decreasing within a generation. |
| `windowGranted` | 24 | 4 | uint32 | BigEndian | The receiver's current granted window in bytes (≤ `MaxBytesPerStream`). Lets the sender adopt the window in-band; clamped on receipt (§6.5). |
| `flags` | 28 | 1 | uint8 | — | Bit 0: `FINAL` (no more credits expected). Bits 1-7: reserved (0). |
| `reserved` | 29 | 10 | — | — | Zero. Pads the payload to **32 bytes** exactly. |

**Total frame size: 7 (header) + 32 (payload) = 39 bytes.** (The D4 payload was
18 bytes; the v2 payload is 32 bytes — a **wire-format break**, see N4/S4 §5.2.)

### 5.2 Versioning, generation pinning, and the atomic-upgrade requirement

**`creditVersion` (S4).** `creditVersion = 1` is the only valid value. A
receiver that sees `creditVersion != 1` **rejects the frame and degrades the
stream to `SAFELY_CAPPED`** (bounded at `CreditSafeWindow = MaxPayload = 64 KiB`,
§4.1). It **never reverts to unlimited** — that was the constraint-7 hazard
(S2) and is now structurally impossible by state. This is also the monotonic
path for a peer that emits a *future* `creditVersion` we don't understand: we
bound the stream rather than unbinding it.

**`creditGen` — pinned at arrival, not from the rebind payload (S3).**
- The **down** credit flows **IR → DE** on the **down** carrier. `creditGen`
  is stamped with **DE's down-carrier generation** (the DATA-sender's
  `h.gen`, [`node.go:171`](../pkg/node/node.go:171)). IR learns that value when
  DE's down carrier (re-)binds onto IR — i.e. from the **down** carrier's own
  `FrameRebind` (`EncodeRebind(sess.ID, h.gen)`, [`node.go:689`](../pkg/node/node.go:689),
  [`frame.go:54-56`](../pkg/mux/frame.go:54)) — **not** from the up carrier's
  rebind, which carries a different (up-direction) counter. REV 0 conflated
  the two; that is the "unimplementable as written" defect.
- **Hard rule:** when DE receives a down credit on its down carrier, DE
  validates `creditGen` against **its own `h.gen` of the carrier the frame
  ARRIVED on** (directly available in DE's `carrierHandle`) — **NOT** by
  re-parsing any rebind payload. A credit whose `creditGen` ≠ the arriving
  carrier's `h.gen` is **stale** and is rejected. This replaces REV 0's
  "structurally impossible" claim (see §9.3) with: *"stale credits are
  prevented by generation pinning at arrival."*

**Version negotiation + atomic upgrade (S4/N4).** The credit feature is gated
on a **wire-format version bump** (`creditVersion = 1`, 32-byte payload).
Because a v1 build's `Dispatch` hits `default: // unknown frame type: drop`
([`carrier.go:770-771`](../pkg/mux/carrier.go:770)) and **silently drops** any
`FrameCredit`, a **mixed-generation deployment is unsafe**: a v2 peer that
grants credits to a v1 peer that silently drops them will **stall** (its
`outstanding` never advances) or, if it times out, degrade to
`SAFELY_CAPPED` (64 KiB) — a ~8.3 KB/s-class throttle. Therefore:

> **Atomic-upgrade requirement (MANDATORY):** both ends (IR `iran-splitter`
> and DE `germany-splitter`) MUST be upgraded in the **same maintenance
> window**, before the credit feature is enabled. No half-deployed
> up-carrier/down-carrier split is permitted. The capability is signalled by
> the v2 build emitting/accepting `creditVersion = 1` frames; an operator
> confirms both ends report the v2 build before enabling credit, else credit
> stays disabled (streams run mailbox-bounded, §4.1 `UNLATCHED`).

### 5.3 Validation / rejection rules

| Condition | Action |
|---|---|
| `creditVersion != 1` | Reject frame; **degrade to `SAFELY_CAPPED`** (bounded, §4.1). **Never unlimited.** |
| `creditGen != h.gen` of the arriving carrier (stale, §5.2) | Reject frame. Do NOT update `outstanding`. |
| `bytesConsumed < lastSeenBytesConsumed` (went backwards within a generation) | Reject frame (corrupt or replayed). Do NOT update. |
| `bytesConsumed == lastSeenBytesConsumed` (duplicate, e.g. TCP retransmission) | Accept (idempotent: `outstanding` already correct). |
| `windowGranted > MaxBytesPerStream` | Clamp `windowGranted` to `MaxBytesPerStream` (config cap), else accept. |
| `flags & 0x01` (FINAL) | Accept; mark the stream "no more credits expected". |
| Payload length != 32 | Reject (malformed frame; connection-level, logged). |
| `StreamID == 0` (reserved control stream) | Reject (protocol violation, same as all other frame types on stream 0, [`frame.go:29-35`](../pkg/mux/frame.go:29)). |

**Unknown frame types never terminate a stream (S4 — REQUIREMENT).** `Dispatch`
already treats an unrecognised `f.Type` as `default: // unknown frame type:
drop` ([`carrier.go:770-771`](../pkg/mux/carrier.go:770)) — it **drops**, it
does **not** terminate. This is load-bearing: a v2 `FrameCredit` arriving at a
v1 build must be dropped, not turn into a `terminateStream` (which would
violate §0.3's "never a silent drop / explicit terminate only on
`failUndeliverableData`"). **MUST test:** [`TestDispatchUnknownTypeNeverTerminates`](../pkg/mux/carrier_test.go)
feeds `Dispatch` a frame of an unrecognised type and asserts the stream is
**not** terminated and no `dropped_data_frames`/`data_undeliverable` fires.
This guards against a future regression that changes `default:` to terminate.

### 5.4 PHASE A — implemented (decisions only)

Phase A (wire format + parse/validation + protocol-version compatibility +
focused tests) is implemented. This section records the concrete decisions
taken; it does not restructure the design.

**Files touched (Phase A):** [`pkg/mux/frame.go`](../pkg/mux/frame.go)
(`FrameCredit = 0x07`, `CreditPayload`, `EncodeCreditPayload`,
`DecodeCreditPayload`, `ValidateCreditPayload`, `ClampCreditWindow`,
`StaleCreditGeneration`, `ErrCreditMalformedLength`,
`ErrCreditUnknownStream`), [`pkg/mux/auth.go`](../pkg/mux/auth.go)
(`AuthVersion` bump + doc), [`pkg/mux/carrier.go`](../pkg/mux/carrier.go)
(`readLoop` connection-level credit checks + the `Dispatch` `FrameCredit`
case), [`pkg/mux/frame_credit_test.go`](../pkg/mux/frame_credit_test.go)
(new), and this document. `pkg/node/`, `pkg/session/`, `cmd/`, `internal/`
are UNCHANGED.

**Protocol-version mechanism (the operator's preferred fail-closed rule).**
`AuthVersion` is bumped **1 → 2** ([`auth.go`](../pkg/mux/auth.go)). The byte
is baked into all three handshake messages
(`buildChallenge`/`buildResponse`/`buildConfirm`) and verified *before* MAC
in `verifyResponse` and the `CarrierAuth` client path, so a mixed old/new pair
is rejected **during authentication** with `ErrAuthVersion` — never entering a
post-auth silent-drop state. No second mechanism was needed; no existing
golden vector hard-coded the version byte, so no out-of-scope test was
edited.

**Wire layout as implemented (matches §5.1 exactly; 7 + 32 = 39 bytes).**
Payload offsets (relative to payload start, BigEndian):
`creditVersion` u8 @0, `creditGen` u64 @1, `bytesConsumed` u64 @9,
`windowGranted` u32 @17, `flags` u8 @21, `reserved` 10 @22.

**Failure-level mapping (implemented; asserted by tests).**
| Violation | Level | Sentinel / effect |
|---|---|---|
| FrameCredit before authentication | connection (auth) | `ErrAuthProtocol` (auth accepts only FrameAuth on stream 0) |
| FrameCredit on stream 0 | connection | `ErrProtocolViolation` (existing post-auth stream-0 rule) |
| FrameCredit for unregistered stream | connection | `ErrCreditUnknownStream` (`readLoop`) |
| Malformed payload length (≠32) | connection | `ErrCreditMalformedLength` (`readLoop`) |
| creditVersion ≠ 1 | stream | `CreditValidationErr{version}` → `terminateStream` |
| creditGen == 0 (invalid value) | stream | `CreditValidationErr{gen-zero}` → `terminateStream` |
| reserved bytes ≠ 0 / flags bits 1-7 set | stream | `CreditValidationErr{reserved-bytes|reserved-flags}` → `terminateStream` |
| stale creditGen (≠ arriving-carrier h.gen) | stream | `StaleCreditGeneration` (called by the node, Phase B) |
| windowGranted > cap | accept | `ClampCreditWindow` (clamp, never reject, §5.3/§6.5) |

In Phase A there is **no credit ledger / `OnStreamPopped` / credit gate /
`ctrlCh` / relay change**; a *valid* credit is a no-op (parse + validate, no
state stored). Only §5 wire format, parsing/validation, and the version
compatibility rule are in scope here.

**Discrepancy noted (doc vs. code):** §5.3 line "Payload length != 32 →
Reject … connection-level, logged" is implemented at the `readLoop` level
(the only place a carrier signals a connection-level failure); the `Dispatch`
`FrameCredit` case therefore handles the *stream-level* semantic rejects, and
the "unregistered-stream" reject is a Phase-A protocol-context rule enforced
in `readLoop` (connection-level) because a legitimate credit sender only ever
targets an established stream. Both are asserted in
[`frame_credit_test.go`](../pkg/mux/frame_credit_test.go).

---

## 6. Credit Accounting Model

### 6.1 Authoritative release point: (c) — socket `Write` completion

**The authoritative release point is (c): successful socket `Write`
completion by the relay.**

Justification (REV 1 — the refutation of (a)/(b) is **mechanistic**, not
the D4 A/B; see §2.1 where the circular D4-A/B citation is removed):

- **(a) `OnStreamPopped`** measures **mailbox drain**, not consumption. A
  pop leaves the byte in `s.ch` (cap 1) and the startStreamRelay's local
  buffer; the client kernel may not have read it. Granting credit at (a)
  over-acknowledges bytes still in the pipeline (§6.2). **Incorrect release
  point.**
- **(b) `s.ch` handoff** places the byte in the cap-1 channel; the
  consumer may be blocked in `sock.Write` (client recv buffer full).
  **Not the consumption point.**
- **(c) Socket `Write` completion** is the **only** point at which the byte
  has been accepted by the client's kernel TCP stack. From the tunnel's
  perspective the byte is "consumed" (no longer the tunnel's responsibility
  to hold it). **The correct release point.**

### 6.2 `outstanding` — precise definition + pipeline (REV 1, S1; **REV 2 S1-A: per-stream own in-flight bytes**)

**Precise definition (S1; REV 2 S1-A).** On the sender (DE), per stream — counting only the **stream's OWN in-flight bytes** (P4+P5+P6) plus **the share of P1/P2/P3 allocated to this stream**; the shared P1/P3 queues *as wholes* are per-carrier and are NOT inside any single stream's `outstanding` (see the pipeline table below):

```
outstanding = #{ bytes B  :
    B was issued by DE via WriteFrame for this stream since the last reset,
    AND B is NOT yet covered by an accepted credit (bytesConsumed),
    AND B is NOT known-terminated (the stream is not in TERMINATED) }
```

Equivalently, `outstanding = issuedSinceReset − bytesConsumedAccepted`,
clamped to ≥ 0 (the R2-3 underflow guard,
[`architecture-checkpoint-backpressure.md:718`](architecture-checkpoint-backpressure.md:718)).

**The in-flight pipeline (S1 — the REV 0 proof omitted the in-flight window; REV 2 S1-A — per-stream vs per-carrier shared terms).**
`outstanding` is *not* just "bytes in the receiver mailbox." Bytes move
through **six stages** between DE's `WriteFrame` and the client reading
them. **REV 2 S1-A correction:** P1 (`writeCh`) and P3 (`c.frames`) are
**shared per carrier** (one queue/cap for *all* streams on the carrier), so
a single stream's `outstanding` can never account for other streams' P1/P3
bytes — the REV 1 table's "yes" for P1/P3 was **false as stated** (one
carrier can hold ~32 MiB of P1+P3). The per-stream `outstanding` counts the
stream's **own** terms P4+P5+P6 plus the **share allocated to this stream**
of P1+P2+P3; the shared P1/P3 as wholes are bounded **per carrier** by the
§6.3 fixed floor (~16.3 MiB each, *outside* `MaxBytesTotal`, §10.1/§10.2),
and per-stream shares are bounded by the 256 KiB `pending` gate (§10.1):

| Stage | Buffer | Owner | Size | Role in `outstanding` (REV 2 S1-A) |
|---|---|---|---|---|
| P1 | `writeCh` | DE writeLoop | ≤ 256 × 65542, **shared per carrier** (§6.3) | **shared per-carrier term** — NOT a per-stream byte count; only this stream's *share* (bounded by §6.3 floor + `pending` gate) enters `outstanding` |
| P2 | DE `rwc` kernel send buffer | DE kernel | ≤ DE socket send buffer (config, §10.1 row, to be measured) | **shared config term** — only this stream's *share* enters `outstanding` |
| P3 | `c.frames` | IR readLoop→Dispatch | ≤ 256 × 65542, **shared per carrier** (§6.3) | **shared per-carrier term** — only this stream's *share* enters `outstanding` |
| P4 | IR stream **mailbox** | IR streamWorker | ≤ `mailboxCap` | **stream's own** — hard-capped by the queue itself (`queue.go:140-143`) |
| P5 | IR `s.ch` | IR startStreamRelay | ≤ 1 × 65535 | **stream's own** — cap-1 handoff |
| P6 | **client kernel recv buffer** | IR client socket | ≤ client socket recv buffer (config, §10.1 row, to be measured) | **stream's own** — bounded kernel config |

So `outstanding` (per stream) =
(P1_share + P2_share + P3_share) + P4 + P5 + P6, i.e. **the stream's own
in-flight bytes plus its allocated share of the shared P1/P2/P3 terms**.
The shared P1/P3 *wholes* (~32.6 MiB per carrier) are **never inside any
single stream's `outstanding`**; they are accounted for by the §6.3
per-carrier fixed floor. The credit releases at the **P6 boundary** (socket
`Write` completion): a `bytesConsumed = N` credit means N bytes have reached
P6.

**Client-kernel-buffer over-acknowledgement (S1; REV 2 S1-B).** Because we
credit at the P6 boundary, P6 bytes are already *inside* `outstanding`
(they were issued and not yet credited-beyond-P6). This is **not** a leak:
P6 contributes to the sum, it does not push P4 (the mailbox) up. The only
risk is that P6 is unbounded — a TCP recv buffer is bounded by kernel
config. **Configuration requirement (S1):** the IR **client-socket recv
buffer** (kernel `rmem`) and the DE **carrier-socket send buffer** (P2) are
bounded constants, **recorded as explicit §10.1 ledger rows** (S1-B,
"to be measured on first live run"); they do **not** grow the mailbox bound.

**Mailbox-never-exceeds-cap proof (REV 2 S1-A — the enforcement that actually holds).**
The enforcement is **two independent caps**, not a single per-stream sum:

1. **Hard cap (the queue itself, always):** P4 is **hard-capped at
   `MaxBytesPerStream = mailboxCap = 704 KiB`** by `fullLocked`
   ([`queue.go:140-143`](../pkg/mux/queue.go:140)) and, in aggregate, by
   `rejectAggregate` ([`queue.go:187-192`](../pkg/mux/queue.go:187)). This
   holds regardless of the credit path. A persistently full mailbox triggers
   `applyPressure` → `failUndeliverableData` (integrity invariant, §0.3) —
   that is *detection/termination*, not silent overflow.
2. **Credit-gate bound (per-stream OWN terms only, while the gate is
   active):** the gate invariant `outstanding ≤ window + unackedAllowance =
   640 KiB` (enforced by `canSend`, §6.5) bounds the **per-stream own terms**
   (P4 + P5 + P6 + this stream's P1/P2/P3 shares). Since P4 is a subset of
   those per-stream terms: P4 ≤ `outstanding` ≤ **640 KiB < 704 KiB =
   `mailboxCap`**. **The mailbox cannot be driven to persistent-full by the
   credit path.** □

   The shared P1/P3 *wholes* (≤ ~32.6 MiB per carrier) are **outside** this
   per-stream accounting: they are bounded by the §6.3 fixed floor (and
   outside `MaxBytesTotal`, §10.1/§10.2); they can *delay* this stream's
   bytes but can never *grow* P4.

> **Note (REV 2 S1-A):** the shared in-flight terms P1/P3 (~32.6 MiB per
> carrier) are *outside* `outstanding` and *outside* `MaxBytesTotal` —
> §6.3/§10.1–§10.2 bound them as a fixed floor. The per-stream P2/P6 kernel
> buffers are config constants, now recorded as explicit §10.1 rows
> (S1-B, "to be measured on first live run"). This proof shows the
> *per-stream* mailbox (P4) stays under `mailboxCap` while the gate is
> active; the *aggregate* across N streams closes in §10 (B4), with the
> beyond-`N_max` admission policy in §10.3 (S3).

### 6.3 Proof: `writeCh` + `c.frames` in-flight window bounded

`writeCh` (cap 256, [`carrier.go:180`](../pkg/mux/carrier.go:180)) and
`c.frames` (cap 256, [`carrier.go:179`](../pkg/mux/carrier.go:179)) each hold
≤ 256 requests × 65542 bytes ≈ **16.3 MiB** per carrier. These are the
**P1/P3** in-flight window, **shared across all streams on the carrier** and
counted **outside** `MaxBytesTotal` (§10.2, B4). `ctrlCh` (new, cap 64, §7)
holds ≤ 64 × 39 = 2.5 KiB of control frames. Bounded, independent of credit.

### 6.4 Stale / duplicate / out-of-order rejection (restated from §5.3)

| Case | Detection | Action |
|---|---|---|
| **Stale** (previous carrier generation) | `creditGen != h.gen` of the arriving carrier (§5.2, S3) | Reject; do NOT update `outstanding`. |
| **Duplicate** (same credit delivered twice) | `bytesConsumed == lastSeenBytesConsumed` | Accept (idempotent). |
| **Out-of-order** (a later credit arrives first) | `bytesConsumed < lastSeenBytesConsumed` | Reject. Do NOT update. |

**Key invariant:** `bytesConsumed` is a **monotonically non-decreasing**
cumulative counter within a carrier generation; it resets to 0 only on
rebind-attach (§9). Any credit with a lower `bytesConsumed` is rejected.

### 6.5 The `outstanding` ledger (sender side, DE) — REV 1

`gen` is widened to **`uint64`** to match `carrierHandle.gen uint64`
([`node.go:155`](../pkg/node/node.go:155)) — a 32-bit gen truncation-wraps on
long-lived carriers and would corrupt the stale check (N3). **When not
latched the stream is NOT unlimited** (REV 0's `if !latched { return true }`
is **removed**); it is bounded by `MaxBytesPerStream`, and when degraded by
`CreditEstablishTimeout` it is bounded by `CreditSafeWindow` (S2/§4.1).

```go
type creditLedger struct {
    mu          sync.Mutex
    outstanding uint64 // issued − credited, clamped >= 0 (R2-3)
    lastSeen    uint64 // last bytesConsumed accepted
    window      uint32 // windowGranted, clamped to MaxBytesPerStream
    latched     bool   // true after first valid FrameCredit
    safelyCapped bool  // true when degraded by CreditEstablishTimeout
    gen         uint64 // pinned to h.gen of the arriving carrier at latch
}

const (
    unackedAllowance = 2 * mux.MaxPayload // 128 KiB
    creditSafeWindow = mux.MaxPayload      // 64 KiB  (S2)
)

// Gate before each WriteFrame. NEVER returns true for "unlimited":
// un-latched => bounded by MaxBytesPerStream; SAFELY_CAPPED => 64 KiB.
func (l *creditLedger) canSend(chunkSize uint64, maxBytesPerStream uint64) bool {
    l.mu.Lock(); defer l.mu.Unlock()
    limit := maxBytesPerStream                       // pre-latch bound
    if l.latched {
        if l.safelyCapped { limit = creditSafeWindow } // S2: never unlimited
        else { limit = uint64(l.window)+unackedAllowance }
    }
    return l.outstanding+chunkSize <= limit
}

func (l *creditLedger) recordSent(n uint64) {
    l.mu.Lock(); l.outstanding += n; l.mu.Unlock()
}

// gen is uint64 (N3). On a valid, in-order credit, adopt the in-band window.
func (l *creditLedger) onCredit(bytesConsumed, gen uint64, windowGranted uint32, final bool) bool {
    l.mu.Lock(); defer l.mu.Unlock()
    if gen != l.gen { return false }                     // stale: reject (S3)
    if bytesConsumed < l.lastSeen { return false }        // out-of-order: reject
    consumed := bytesConsumed - l.lastSeen
    if consumed > l.outstanding { consumed = l.outstanding } // R2-3 clamp
    l.outstanding -= consumed
    l.lastSeen = bytesConsumed
    if l.latched {
        w := uint64(windowGranted)
        if w > mux.MaxPayload { /* clamp to MaxBytesPerStream via caller */ }
        l.window = uint32(w)
        l.safelyCapped = false                           // a live credit heals it
    }
    l.latched = true                                      // anchor (popped=0) latches too
    if final { l.noMoreCredits = true }
    return true
}
```

**Note:** `onCredit` runs on the **sender's** (DE) ledger. The receiver (IR)
**emits** the frame (`bytesConsumed` = cumulative client-socket bytes written);
DE **consumes** it. The anchor credit (`bytesConsumed = 0`) latches DE to the
safe/small window so the sender is **bounded from the first credit** (matching
D4's INCREMENT 3, [`architecture-checkpoint-backpressure.md:734-750`](architecture-checkpoint-backpressure.md:734),
but with the window seeded to the *granted* window, not `MaxBytesPerStream`).

---

## 7. Control-Plane Priority Model

### 7.1 The problem (restated)

The `writeCh` ([`carrier.go:180`](../pkg/mux/carrier.go:180)) is a single
FIFO channel of cap 256. All frame types (DATA, CREDIT, PING, PONG, CLOSE,
REBIND, HEADER) are enqueued on the same channel and serviced by the single
`writeLoop` ([`carrier.go:272`](../pkg/mux/carrier.go:272)) in FIFO order.
**A credit frame enqueued behind 256 DATA frames will wait for all 256 DATA
frames to be written before it is written.** On a cross-border conn, 256 ×
64 KiB = 16 MiB of DATA at 5 MB/s = 3.2 s of delay before the credit frame
is written. **The credit is 3.2 s stale by the time it reaches the sender.**
The sender's `outstanding` is 3.2 s behind, so the sender is parked for 3.2
s extra. **This is the HOL (head-of-line) stall that D4 suffered and that
the v2 design must eliminate.**

### 7.2 Chosen solution: separate control queue with strict priority (REV 1 — B3)

**Design (REV 1).** Add a **second, smaller channel** `ctrlCh` (cap 64) to
`CarrierConn`. **REV 0's routing was wrong in two ways** and is corrected
here:

1. **Shutdown correctness (B3a):** REV 0's `writeLoop` exited on `<-c.closed`
   with requests still on `ctrlCh`; their `req.done` sends never happened, so
   any producer blocked on `<-req.done` **hung**. REV 0 also had no
   `writeWG`/`drainWrites` accounting for `ctrlCh`. **Fix:** give `ctrlCh`
   the **same `writeWG` + `drainWrites` treatment as `writeCh`**, and make
   **every** enqueue abortable on `c.closed` (a `select` race against
   `<-c.closed`). `Close` calls `ctrlWG.Wait()` then
   `drainCtrl()` (mirror of `drainWrites`,
   [`carrier.go:331-345`](../pkg/mux/carrier.go:331)), so **no producer is
   left waiting on a dead writer** — the invariant asserted by
   [`carrier_shutdown_test.go`](../pkg/mux/carrier_shutdown_test.go)
   (`TestCloseResolvesAllQueuedWrites`, `TestWriterExitsAfterClose`).
2. **Ordering (B3b):** REV 0 routed `FrameRebind` and `FrameHeader` to
   `ctrlCh`. That **breaks the "rebind must be the first frame of the
   stream" invariant** ([`node.go:686-689`](../pkg/node/node.go:686)) and
   reorders `FrameRebind`/`FrameHeader` ahead of the stream's DATA — the peer's
   `OnNewStream` branches on frame type and **drops user data that arrives
   first as malformed**. **Fix: keep `FrameRebind` and `FrameHeader` on
   `writeCh`** (FIFO with DATA). Only **ordering-insensitive** control frames
   ride `ctrlCh`.

**Per-frame-type routing table (REV 1, B3):**

| Frame type | Queue | Ordering-sensitive? | Reason |
|---|---|---|---|
| `FrameData` (0x00) | `writeCh` | **yes** | In-order user data. |
| `FrameHeader` (0x05) | `writeCh` | **yes** | Must be the stream's first frame; FIFO with DATA. |
| `FrameRebind` (0x06) | `writeCh` | **yes** | Must be the stream's first frame on the new carrier ([`node.go:686-689`](../pkg/node/node.go:686)); FIFO with DATA. |
| `FrameClose` (0x04) | `ctrlCh` | no | Terminal control signal; never needs to precede a queued DATA byte. |
| `FrameCredit` (0x07) | `ctrlCh` | no | Cumulative counter; the *next* credit carries the running total, so a late credit is not a byte-order hazard. |
| `FramePing`/`FramePong` (0x02/0x03) | `ctrlCh` | no | Keepalive; ordering-insensitive. _REV 2 S5: this row **moves Ping/Pong off `writeCh`** — today `Dispatch` emits `FramePong` via `c.write(...)` on `writeCh` ([`carrier.go:758-763`](../pkg/mux/carrier.go:758)); in v2 the pong rides `ctrlCh`. This is a **deliberate, benign** change: Ping/Pong carry no in-stream byte-order role, so reordering them relative to DATA is safe. It **does not** affect `liveness_test.go`'s pong-ordering assertions, which the Slice 1 gate MUST re-run (S5)._ |

**`writeLoop` (REV 1 — both channels accounted for shutdown):**

```go
func (c *CarrierConn) writeLoop() {
    for {
        // 1. Priority: if a control frame is ready, service it before DATA.
        select {
        case req := <-c.ctrlCh:
            c.writeOne(req) // rwc.Write + req.done, abortable on c.closed
            continue
        default:
        }
        // 2. No control frame ready: service DATA (or ctrl if one just
        //    landed), or exit on close.
        select {
        case <-c.closed:
            return // Close's drainCtrl()/drainWrites() resolve any in-flight
        case req := <-c.ctrlCh:
            c.writeOne(req)
        case req := <-c.writeCh:
            c.writeOne(req)
        }
    }
}
```

`writeOne` is the single `rwc.Write` + `req.done <- err` helper; on
`<-c.closed` it reports `ErrCarrierClosed`. **Enqueue is abortable:** the
producer path (`c.write` / a new `c.writeCtrl`) does
`c.ctrlWG.Add(1)` under `c.mu`, then
`select { case c.ctrlCh <- req: c.ctrlWG.Done(); ...; case <-c.closed:
c.ctrlWG.Done(); return ErrCarrierClosed }` — the exact mirror of
`write`'s `writeWG` discipline ([`carrier.go:307-329`](../pkg/mux/carrier.go:307)).
`Close` runs `close(c.closed)` → `c.ctrlWG.Wait(); c.drainCtrl()` →
`c.writeWG.Wait(); c.drainWrites()` (mirroring
[`carrier.go:1004-1016`](../pkg/mux/carrier.go:1004)).

**In-order proof for ordering-sensitive types (B3).** `FrameRebind`,
`FrameHeader`, and `FrameData` for a given stream are **all** enqueued on
`writeCh`, which is FIFO and consumed by the single `writeLoop` in enqueue
order. No ordering-sensitive frame is ever on `ctrlCh`, so **none can jump
ahead of the stream's DATA.** For stream `S`: the `FrameRebind`/`FrameHeader`
enqueued before the first `FrameData` is consumed by `writeCh` before that
first `FrameData` (FIFO), so the peer sees `FrameRebind` first — exactly the
invariant [`node.go:686-689`](../pkg/node/node.go:686) and
[`install_reader_test.go:96-98`](../pkg/node/install_reader_test.go:96),
[`node_test.go:667-677`](../pkg/node/node_test.go:667) depend on. `ctrlCh`
frames (CREDIT/CLOSE/PING/PONG) interleave *between* DATA writes but never
between two frames of the same stream that must be ordered; they carry no
stream byte-order. □

**Credit-latency bound (§7.3, REV 1):** a `FrameCredit` on `ctrlCh` is
written **before** the next DATA on `writeCh`, so it is not queued behind up
to 256 DATA frames. Its worst-case delay = (one in-flight `rwc.Write` being
completed) + (≤1 already-queued control frame). Bounded, not 16 MiB of DATA. □

### 7.4 DATA is not starved — derived bound (REV 1 — N2)

REV 0's "10 μs per kernel write ⇒ ~1 ms" estimate is **replaced** by a
worst-case **derived bound** (N2). A control-frame service is one
`rwc.Write`. The **dominant worst case** is a `rwc.Write` that **blocks** on
a saturated kernel send buffer:

```
Worst-case per rwc.Write = max( kernel_write_latency,
                                 frame_bytes / carrier_rate )
```

For a 32 KiB (32768 B) control-adjacent write on a carrier delivering at
5 MB/s: `32768 / 5.0e6 s ≈ 6.5 ms`. That is the **derived worst-case delay
to DATA behind one control-frame service** — **~6.5 ms**, not "~1 ms", and it
is a bound (worst case), not a typical estimate. Against the 90 ms
cross-border RTT this is still small; the bound is stated so an operator can
verify the 5 MB/s figure on the live carrier. In steady state `ctrlCh` is
nearly empty (credit frames are batched, §12 Slice 5, one per 64 KiB
consumed), so control-frame servicing is bursty, not continuous. **DATA is
delayed by at most ~one blocked `rwc.Write` (~6.5 ms at the 5 MB/s
assumption); it is not starved indefinitely.** □
> **Side-by-side bound (REV 2 N4):** this ~6.5 ms figure bounds the delay
> to **control** frames (one blocked `rwc.Write`). The independent
> worst-case delay to **DATA** behind a saturated shared `writeCh` is
> derived in §11.4 item 2: **16.3 MiB ÷ carrier_rate ≈ 3.3 s at 5 MB/s
> (≈ 0.14 s at the 121.4 MiB/s ceiling)** — a pre-existing residual HOL
> risk, not a v2-introduced bound. The two numbers are different quantities
> (control-frame service vs DATA-behind-full-FIFO) and both are stated so
> the operator has the exact magnitudes.

### 7.5 No deadlock (REV 1)

- `ctrlCh` (cap 64) and `writeCh` (cap 256) are **bounded**; `writeLoop` is
  the sole consumer of **both**.
- **Every enqueue is abortable on `c.closed`** (the `select` race in
  §7.2), so no producer blocks on a full channel after close.
- `writeCh` full → the relay **parks** (does not block). `ctrlCh` full → the
  credit-emission path **drops** the credit (non-blocking enqueue; the next
  credit carries the cumulative `bytesConsumed`, so no information is lost —
  but note the drop only *delays* the credit; the next one heals it).
- **REV 2 S2 (two functions):** the **credit-emission** path uses
  `TryWriteControlFrame` — the **non-blocking, drop-on-full** enqueue
  (non-blocking `select` against `c.ctrlCh` / `<-c.closed`; on full it
  *drops* the frame and returns immediately, **never blocking**). The
  **blocking** `WriteControlFrame` (enqueue, then block on `<-req.done`,
  mirroring [`carrier.go:307-329`](../pkg/mux/carrier.go:307)) is used
  **only for `FrameClose`** (a terminal signal that MUST NOT be dropped).
  Call sites: `creditEmitter.emit` (Slice 4/5) and `TestCreditEmitterDropOnFull`
  use `TryWriteControlFrame`; the `FrameClose` write in §11.2 case 3 /
  [`carrier.go:307-329`](../pkg/mux/carrier.go:307)-class paths use
  `WriteControlFrame`. The no-deadlock proof below rests on the
  non-blocking `TryWriteControlFrame` for credits.
- `Close` drains **both** queues via `ctrlWG`/`drainCtrl()` +
  `writeWG`/`drainWrites()`, so no `req.done` is orphaned. **No unbounded
  wait, no deadlock, no hang on close.** □

### 7.6 Why not "priority scheduling on a single queue" or "reserved control capacity"

- **Priority scheduling on a single queue** would require the `writeCh` to
  be a priority queue (e.g. a binary heap). This changes the `writeCh`'s
  type and all the `writeReq` enqueue/dequeue paths. It also introduces a
  priority-inversion risk and changes the concurrency semantics of the
  `writeLoop`. **Too invasive.**
- **Reserved control capacity** is not expressible in a Go channel (FIFO;
  slots can't be reserved). **Not feasible.**
- **Separate control queue** is the cleanest: two channels, one `writeLoop`,
  strict priority via the `select` pattern, **with both channels carrying
  `writeWG`/`drain` shutdown discipline** (B3). **Chosen.**

---

## 8. RTT / Window Sizing Model

### 8.1 Formula (REV 1 — B2)

```
window-bound ceiling ≈ window / effective_RTT
required_window   >= target_rate × effective_RTT + safety_margin
```

Where:
- `target_rate` = desired sustained throughput. The measured no-credit
  **baseline** for a 1 MiB object is **≈1,372 KB/s (≈1.34 MB/s)** (§0.5) —
  that is the cross-border *client-leg* rate, and it is the realistic
  `target_rate` for the down path (the 121.4 MiB/s raw ceiling is the DE
  target→`pending` rate, **not** the client-socket drain rate).
- `effective_RTT` = **measured** credit round-trip (DATA issued → client
  `sock.Write` completes → CREDIT received). **REV 1: this is a *per-credit
  cycle* latency, NOT "one RTT per 32 KiB Pop".** With batching (§12 Slice 5),
  one credit covers `MaxPayload` (64 KiB) of consumed bytes, and the unacked
  allowance (§2.3) lets the sender pipeline 2 further frames. The per-chunk
  latency the REV 0 doc never actually measured (it assumed 90 ms) is left
  **as `effective_RTT` and must be measured** (§8.2); the model no longer
  asserts a 355 KB/s per-Pop stop-and-wait ceiling (retracted in §1.2/§1.4).
- `safety_margin` = `unackedAllowance` = 2 × MaxPayload = 128 KiB.

**B2 reconciliation — can the design's window reach the baseline?**

```
512 KiB / 90 ms ≈ 5.7 MB/s      (window-bound ceiling, IF effective_RTT = 90 ms)
measured baseline            ≈ 1,372 KB/s ≈ 1.34 MB/s  (client-rate-bound)
```

The 5.7 MB/s window ceiling **exceeds the 1.34 MB/s baseline by ≈4.2×**, so a
512 KiB window **can reach** the measured baseline — the baseline is
*client-rate-bound*, not window-bound. The REV 0 inconsistency (asserting the
"one RTT per Pop ⇒ 32 KiB / 90 ms ≈ 355 KB/s" ceiling, which is **44× below**
the 5.7 MB/s window figure and ≈15× below the 1,372 KB/s baseline) comes from
confusing the **per-chunk** Pop rate with the **per-credit-cycle** window rate.
That confusion is resolved here: the binding rate is `window / effective_RTT`,
and with `window = 512 KiB` it comfortably covers the baseline. If
`effective_RTT` is later measured to be much larger than 90 ms, §8.3's
adaptation (raising `window` toward `MaxBytesPerStream`) restores the ceiling.

### 8.2 Measuring `effective_RTT` (not assuming)

The `effective_RTT` is measured **in-band** using the credit frames
themselves:

1. The receiver (IR) tracks, per stream, the **cumulative bytes consumed**
   (`bytesConsumed`). This is the value in the `FrameCredit` payload.
2. The sender (DE) tracks, per stream, the **timestamp** (nanoseconds since
   carrier-attach) of each `WriteFrame` call that issued the bytes being
   acknowledged by the credit.
3. When the sender receives a `FrameCredit` with `bytesConsumed = N`, it
   looks up the timestamp `t_sent` of the `WriteFrame` that issued the
   chunk ending at byte N (or the most recent `WriteFrame` if N spans
   multiple chunks). `effective_RTT_sample = t_credit_recv - t_sent`.
4. The sender maintains an **EWMA** (exponential weighted moving average,
   α = 0.1) of `effective_RTT` over the last 32 samples.

**Simpler proxy (if per-chunk timestamps are too complex):**
- The sender tracks `t_last_data_sent` (timestamp of the last `WriteFrame`
  call) and `t_credit_recv` (timestamp of the last `FrameCredit` received).
- `effective_RTT ≈ t_credit_recv - t_last_data_sent`. This is the
  **one-way** DATA→CREDIT latency, which is approximately half the full
  RTT. For window sizing, use `2 × (t_credit_recv - t_last_data_sent)`.

### 8.3 Window adaptation (REV 1 — B2/B4: clamped to the CLOSED bound)

The window adapts but **never exceeds `window_max`**, where
`window_max = MaxBytesPerStream − unackedAllowance − MaxPayload`
= `704 KiB − 128 KiB − 64 KiB = 512 KiB` (§10). Clamping to
`MaxBytesPerStream` (REV 0) was **wrong**: it let `window_max = 704 KiB`,
giving `outstanding ≤ 704 + 128 = 832 KiB > 704 KiB` = the mailbox cap —
the exact overflow B4 flagged. The clamp must leave the `unackedAllowance`
+ one `MaxPayload` of headroom **inside** the mailbox cap.

- At carrier-attach, the window is initialised to:
  ```
  initial_window = clamp(target_rate × 200 ms, min=window_min, max=window_max)
  ```
  For a target of 5 MB/s: `5 MB/s × 200 ms = 1 MiB` → **clamped to
  `window_max` = 512 KiB**. So `initial_window = 512 KiB`.
- After the first 32 credit samples, the window is **adapted**:
  ```
  target_rate_measured = bytes_consumed_in_window / window_duration
  new_window = target_rate_measured × effective_RTT_ewma + 2×MaxPayload
  new_window = clamp(new_window, min=window_min=256 KiB, max=window_max=512 KiB)
  ```

- The window is updated **at most once per second** (to avoid oscillation).
  The new window takes effect on the next credit frame emission.

### 8.4 Starting window and cap (REV 1)

| Parameter | Value | Rationale |
|---|---|---|
| `initial_window` | **512 KiB** | = `window_max`; starts at the max because the measured baseline (≈1,372 KB/s) is client-rate-bound, not window-bound (§8.1 B2). A 512 KiB window gives a `512 KiB / effective_RTT` ceiling that comfortably covers the baseline. |
| `window_min` | 256 KiB | Floor; below this the re-gate penalty dominates. 256 KiB / 90 ms ≈ 2.8 MB/s, still above the 1,372 KB/s baseline. |
| `window_max` | **512 KiB** = `MaxBytesPerStream − unackedAllowance − MaxPayload` | The CLOSED bound (§10): at `window_max`, the per-stream `outstanding` ≤ 512 + 128 = 640 KiB ≤ MaxBytesPerStream = 704 KiB. _REV 2 S1-A: this 640 KiB limit applies to the stream's **own** in-flight terms (P4+P5+P6 + its P1/P2/P3 share, §6.2) — the shared P1/P3 wholes (~32.6 MiB/carrier) are **outside** it (§6.3 fixed floor). The window may not exceed this or the per-stream mailbox overflows. |
| `MaxBytesPerStream` (mailbox cap) | **704 KiB** | Reduced from 1 MiB (§10, B4); the hard `fullLocked` ceiling. |
| `unackedAllowance` | 128 KiB (2 × MaxPayload) | Fixed. Pipelines 2 frames ahead of the credit signal. |
| `effective_RTT` (measured) | **must be measured** (§8.2); the 90 ms figure is a *placeholder*, not an assumption the model asserts | §8.2 measures it in-band. |
| `safety_margin` | 128 KiB (= `unackedAllowance`) | Absorbs jitter and retransmission. |

**Starting window: 512 KiB. Cap: 512 KiB.** (The window starts at
`window_max` and adapts **downward** toward `window_min` as the measured
`target_rate × effective_RTT` shrinks; it never exceeds `window_max`, so the
mailbox bound in §10 stays closed.)

---

## 9. Reconnect / Rebind Semantics

### 9.1 Generation pinning (REV 1 — S3: pinned at ARRIVAL, not from the rebind payload)

Each carrier connection has a monotonically increasing generation number
(`carrierHandle.gen uint64`, [`node.go:155`](../pkg/node/node.go:155)). On
rebind, a new carrier is installed with `gen = old_gen + 1`
([`node.go:480`](../pkg/node/node.go:480)).

**REV 0's `creditGen` rule was unimplementable-as-written (S3).** REV 0 said
the receiver "compares `creditGen` to its own knowledge of DE's
down-carrier generation (from the `FrameRebind` payload)." That is **wrong
in two ways**:

1. **The `FrameRebind` payload carries the SENDER's generation** — but in
   the *direction the rebind rides*. The rebind that DE installs on the
   **down** carrier carries DE's down-carrier `h.gen`
   ([`node.go:689`](../pkg/node/node.go:689),
   [`frame.go:54-56`](../pkg/mux/frame.go:54)); the rebind that IR installs
   on the **up** carrier carries IR's up-carrier `h.gen` — a **different
   counter**. A down credit (IR→DE) must be checked against **DE's down
   carrier's `h.gen`**, which IR knows only from DE's down-carrier rebind,
   **not** from IR's up-carrier rebind. REV 0 never stated which rebind
   carries which generation, so "check against the rebind payload" is
   ambiguous and the wrong one is easily used.
2. **The check is on the sender's side, not the receiver's.** The
   down-credit is *consumed* by DE. DE already **knows its own down
   carrier's `h.gen`** (it is DE's `carrierHandle`). It does **not** need to
   learn IR's generation to validate IR's credit; it validates the credit's
   `creditGen` field against **the `h.gen` of the carrier the frame ARRIVED
   on** (DE's down carrier). That value is directly available in DE's
   `carrierHandle` — no rebind-payload cross-reference required.

**REV 1 hard rule (S3):**

- The **anchor credit** (the first `FrameCredit` on a new carrier generation,
  `bytesConsumed = 0`) **MUST carry `creditGen`** = the sender's
  down-carrier generation at attach. This is the only field that pins the
  generation; without it, the first credit has no generation to compare and
  the stream cannot latch safely.
- The **receiver-side pin** is against `h.gen` of the carrier the frame
  **arrived on** (directly available in the local `carrierHandle`),
  **NOT** the `FrameRebind` payload. REV 0's "from the `FrameRebind`" is
  **deleted**.
- Stale-credit prevention is therefore **"prevented by generation pinning at
  arrival"**, not "structurally impossible" (§9.3).

**Generation-pinning rule (REV 1):** At latch time (first valid
`FrameCredit`, i.e. the anchor), the sender's `creditLedger.gen` is set to
the `creditGen` **of that frame**, and it equals the arriving carrier's
`h.gen`. All subsequent credits for that stream MUST carry the same
`creditGen`; a credit whose `creditGen` differs is **stale** and is
**rejected** (not accepted, not used to update `outstanding`).

### 9.2 Reset of in-flight state on rebind

On rebind-attach (a new carrier is installed and the stream is re-attached):

1. **Sender (DE):** `creditLedger.clearStream(streamID)` — `outstanding`
   reset to 0, `lastSeen` reset to 0, `latched` set to false, `gen` set to
   the new carrier generation.
2. **Receiver (IR):** The old carrier's `streamWorker` exits (the mailbox
   is `Close`d). The new carrier's `streamWorker` is started. The credit
   accumulator (`bytesConsumed`) is reset to 0 for the new generation.
3. **Both sides:** The first credit frame on the new carrier is an
   **anchor** credit: `bytesConsumed = 0`, `creditGen = new_gen`,
   `flags = 0`. This anchors both sides to 0.

### 9.3 Stale credit handling (REV 1 — S3: "prevented by generation pinning at arrival")

REV 0 claimed a stale credit is "**structurally impossible** on the
receiving side: the previous carrier's `readLoop` has exited." **That claim
is false and is retracted.** A carrier's `readLoop` exiting on `Close`
(`c.readErr`/EOF, [`carrier.go:229-264`](../pkg/mux/carrier.go:229)) only
stops *new* frames from that carrier; it does **not** prevent a credit that
was **already enqueued in `writeCh`/`ctrlCh` on the old carrier** (or in
transit on the TCP conn) from being flushed to the peer before the socket
actually tears down. A replayed or in-flight credit from the old generation
**can** arrive at the new generation. Stale-credit prevention is therefore
**"prevented by generation pinning at arrival" (§9.1)**, not structural.

**A stale credit can NEVER increase a current stream's allowance.**
Proof (REV 1, pinned at arrival):
1. A stale credit has `creditGen = old_gen` (the old carrier's `h.gen`).
2. The current stream's `creditLedger.gen = new_gen`, and `new_gen = h.gen`
   of the **carrier the credit arrived on** (§9.1 pinning rule).
3. `old_gen != new_gen` (generations are monotonically increasing,
   [`node.go:480`](../pkg/node/node.go:480)).
   **`uint64` wrap analysis (REV 2 N6):** `gen` is `uint64`
   ([`node.go:155`](../pkg/node/node.go:155)) and increments by **one per
   reconnect**. At the observed ~10 reconnects/hour that is ~8.7 × 10^4
   generations/year; to wrap the 2^64 generation space (~1.8 × 10^19) would
   take **~5 × 10^13 years**. Wrap is therefore effectively unreachable in
   any deployment lifetime, so `onCredit`'s plain `gen != l.gen` (`!=`)
   check is **safe against wrap** without any modulo/behind-the-3/4-circle
   arithmetic.
4. Therefore `onCredit` (the `gen != l.gen` check, §6.5) **rejects** the
   stale credit and does not update `outstanding`/`lastSeen`.
   **The stale credit cannot increase `outstanding` or the window.** □

### 9.4 Duplicate rebind

If a rebind frame arrives for a stream that is **already attached** to the
current carrier (duplicate rebind, e.g. the sender retransmitted the
rebind), the rebind is **refused** by the existing `handleRebind` logic
([`node.go:826-827`](../pkg/node/node.go:826): `st != AttUnavailable && st
!= AttRebinding` → `drop("attachment not awaiting rebind")`). The credit
state is **not** reset (the stream is already on the current generation).
**No stream becomes unlimited after a duplicate rebind.**

### 9.5 Guarantee: no stream becomes unlimited after a reconnect (REV 1 — S2)

> **REV 1 retraction:** REV 0's §9.5 step 5 said `CreditEstablishTimeout`
> "reverts the stream to unlimited." That is **false as written** and is
> the exact constraint-7 hazard (a reconnect-triggerable unlimited window of
> 2 s × up to 1 MiB per stream). **REV 1: on `CreditEstablishTimeout` the
> stream latches to a SAFE SMALL window (`CreditSafeWindow` = `MaxPayload` =
> 64 KiB) or terminates. It NEVER re-opens the un-latched / unlimited state
> after a latch.** This makes the guarantee hold for the *entire* lifetime of
> the stream, not just "after the anchor credit."

**The guarantee (REV 1):**

1. On reconnect, the stream is in `UNLATCHED`. **`UNLATCHED` is not
   unlimited** — it is still bounded by `MaxBytesPerStream` / `MaxBytesTotal`
   (the mailbox caps, §4.1/§10), so even pre-latch the memory bound stays
   closed (B4).
2. The stream latches to credit-gated on the **first valid** `FrameCredit`
   (the anchor credit, `bytesConsumed = 0`, `creditGen = h.gen` at arrival,
   §9.1). On latch it is bounded by `window + unackedAllowance`.
3. If **no valid credit** arrives within `CreditSafeTimeout` (2 s):
   - **pre-latch** (never latched): the stream moves to **`SAFELY_CAPPED`**
     (§4.1) and is bounded by `CreditSafeWindow` = **64 KiB** — *not*
     unlimited.
   - **while PARKED** (already latched): the stream degrades to
     **`SAFELY_CAPPED`** (64 KiB). **A latched stream is NEVER un-latched to
     unlimited; it only degrades to the safe small window.**
4. **Invariant (S2):** once the stream has latched, no transition (timeout,
   rebind, stall) may set it to unlimited. The only states after a latch are
   `LATCHED` (full window), `SAFELY_CAPPED` (64 KiB), `PARKED`, and
   `TERMINATED`. **The 2 s reconnect-triggerable unlimited window is
   eliminated.**

**Constants (S2):** `CreditSafeWindow = mux.MaxPayload = 64 KiB`
([`frame.go:21`](../pkg/mux/frame.go:21)); `CreditSafeTimeout = 2 s`
(unchanged). These replace REV 0's "revert to unlimited" fallback in §4.1,
§5.3, §6.5, and Slice 3 (§12).

---

## 10. Memory-Bound Proof (REV 1 — B4: the bound now CLOSES)

> **REV 1:** REV 0's §10.2/§10.3 arithmetic was **unbounded in N** and
> mis-attributed `writeCh`+`c.frames` to `MaxBytesTotal`. REV 1 separates
> the **mailbox budget** (`MaxBytesTotal`, which bounds ONLY mailboxes) from
> the **fixed in-flight floor** (`writeCh`+`c.frames`, which is a per-carrier
> constant *outside* `MaxBytesTotal`), picks an explicit `N_max`, and closes
> the inequality with numbers. It also makes `DefaultStreamLimits`,
> `SanitizeLimits`, and the shipped config default change **in the same
> slice**, so no intermediate build ships the 704 KiB / 32 MiB footgun.

### 10.1 What is inside / outside `MaxBytesTotal` (REV 1 — the key distinction)

| Component | Size | Inside `MaxBytesTotal`? | Note |
|---|---|---|---|
| Stream **mailbox** (`StreamQueue` bytes) | ≤ `MaxBytesPerStream` = **704 KiB** per stream | **YES** — the ONLY thing `MaxBytesTotal` aggregates | counted by `TryPush` under `q.mu` ([`queue.go:194-196`](../pkg/mux/queue.go:194)), checked against `budgetLimitLocked` ([`queue.go:187-192`](../pkg/mux/queue.go:187)). |
| `writeCh` (per carrier) | 256 × 65542 ≈ **16.3 MiB** | **NO** — fixed floor, shared, independent of `MaxBytesTotal` | [`carrier.go:180`](../pkg/mux/carrier.go:180). |
| `c.frames` (per carrier) | 256 × 65542 ≈ **16.3 MiB** | **NO** — fixed floor, shared | [`carrier.go:179`](../pkg/mux/carrier.go:179). |
| `ctrlCh` (per carrier) | 64 × 39 ≈ **2.5 KiB** | **NO** — fixed floor | new, §7. |
| `pending` (per stream) | `BufferBytes` = **256 KiB** | **NO** — per-stream, outside the mailbox | [`node.go:127-128`](../pkg/node/node.go:127). |
| `s.ch` (per stream) | 1 × 65535 ≈ **64 KiB** | **NO** — per-stream | cap-1 handoff. |
| socket read chunk | `RelayBufSize` = **32 KiB** | NO | transient. |
| **client-socket kernel recv buffer (P6, IR leg)** | kernel `rmem` — **(to be measured on first live run)** | **NO** — bounded kernel config, per stream | **REV 2 S1-B:** the §6.2 P6 term. Bounded by the kernel `rmem` setting on the IR client socket; **not** a tunnel buffer; does **not** grow the mailbox bound. Recorded here per the §6.2 configuration requirement (S1-B). |
| **carrier-socket kernel send buffer (P2, DE leg)** | kernel `wmem` — **(to be measured on first live run)** | **NO** — bounded kernel config, per stream | **REV 2 S1-B:** the §6.2 P2 term. Bounded by the kernel `wmem` setting on the DE carrier socket; **not** a tunnel buffer; does **not** grow the mailbox bound. |

**Consequence (B4):** raising `MaxBytesTotal` to 48 MiB (REV 0) **bought
nothing** for the dominant term — the 16.3+16.3 MiB `writeCh`+`c.frames`
floor (×2 carriers = **65.2 MiB**) sits **outside** it and is invariant to
`MaxBytesTotal`. The bound must therefore be stated as a sum of a **fixed
floor** (constant, independent of `MaxBytesTotal` and of `N`) and a
**per-stream term** (scales with `N_max`).

### 10.2 Per-node closed bound with explicit `N_max` (REV 1)

Pick **`N_max = 8`** — an **EXPLICIT OPERATIONAL ASSUMPTION** (REV 2 S4): the
observed maximum concurrent down streams in the §0.4/§0.5 measurement campaign
(4/8 MiB up tests; 8 MiB down ceiling) is **8**, and a dedicated relay node is
sized for ≤ 8 concurrent down streams. The operator must confirm this in
Appendix B item 1. _REV 2 S4: the §14.6 cross-reference (the UP-carrier reset
investigation) is **removed** as the basis — it is a diagnostic for a separate
defect and concerns UP streams, not the down-mailbox funding `N_max` governs._

```
FIXED_FLOOR   = 2 carriers × (writeCh + c.frames + ctrlCh)
              = 2 × (16.3 + 16.3 + 0.0025) MiB
              ≈ 65.2 MiB                       [constant; outside MaxBytesTotal]

PER_STREAM    = 2 directions × (mailboxCap + pending + s.ch)
              = 2 × (704 + 256 + 64) KiB
              = 2 × 1,024 KiB = 2 MiB          [mailbox part inside MaxBytesTotal]

node_mem(N)   = FIXED_FLOOR + N × PER_STREAM
              = 65.2 MiB + N × 2 MiB
```

**Closed at `N_max = 8`:** `node_mem = 65.2 + 8 × 2 = 81.2 MiB` per node.
This is the **operator-confirmed memory ceiling** for a dedicated relay node.
(It is independent of `MaxBytesTotal`; the 65.2 MiB floor is the dominant,
unavoidable term.)

### 10.3 `MaxBytesTotal` set to the mailbox budget, not the node total (REV 1)

`MaxBytesTotal` bounds **only mailboxes**. For `N_max = 8` concurrent
down streams to coexist on one carrier without `rejectAggregate`
([`queue.go:187-192`](../pkg/mux/queue.go:187)) firing (which would
`failUndeliverableData` → `dropped_data_frames`, the very integrity
violation this design must eliminate — B4):

```
MaxBytesTotal  >=  N_max × mailboxCap + in_flight_window_margin
                =  8 × 704 KiB + (writeCh/c.frames share allocated to mailboxes)
                ≈  5.63 MiB + 2 MiB headroom
   => MaxBytesTotal = 8 MiB   (was 32 MiB default; see footgun below)
```

**8 MiB** — not REV 0's 48 MiB. The 48 MiB figure was only sensible under the
(mistaken) assumption that `writeCh`+`c.frames` live inside `MaxBytesTotal`.
They do not, so 8 MiB fully funds `N_max = 8` streams.

**Admission policy for streams beyond `N_max` (REV 2 S3).** There is
**no admission control in scope for v2**: streams beyond the funded count
are **ADMITTED** — `MaxBytesTotal` is the **only** enforcement, acting via
`rejectAggregate` ([`queue.go:187-192`](../pkg/mux/queue.go:187)). The
arithmetic: `MaxBytesTotal = 8 MiB` ÷ `mailboxCap = 704 KiB` ≈ **11.6**,
so **~11 full mailboxes** coexist; the **~12th concurrent FULL down
mailbox** trips `rejectAggregate` → `failUndeliverableData`
([`carrier.go:834`](../pkg/mux/carrier.go:834)) → `dropped_data_frames`
([`qstats.go`](../pkg/mux/qstats.go)) + the `data_undeliverable` close
reason — i.e. **the drop threshold is ~12 concurrent FULL mailboxes, not 8**.
**Honest residual hazard:** at ≥12 concurrent full-down-stream mailboxes the
integrity invariant **can terminate a stream** (by design — DATA is never
silently dropped, §0.3). This is the **next thing to instrument**: watch
[`dropped_data_frames`](../pkg/mux/qstats.go) correlated with
[`session_close_reason{data_undeliverable}`](../pkg/node/metrics.go:508) on
the live nodes after the 8-MiB `MaxBytesTotal` ships; a sustained non-zero
rate is the signal that `N_max`/`MaxBytesTotal` must be raised together
(Appendix B item 1).

### 10.4 The 704/32-MiB footgun + the `SanitizeLimits` fix (REV 1 — B4d)

**The footgun:** [`SanitizeLimits`](../pkg/mux/carrier.go:406) silently resets
`MaxBytesTotal` to the default (32 MiB) whenever
`MaxBytesTotal < MaxBytesPerStream`
([`carrier.go:414-415`](../pkg/mux/carrier.go:414)). If Slice 8 ships the
704 KiB `MaxBytesPerStream` **without** also shipping the 8 MiB
`MaxBytesTotal` in the **same build**, `SanitizeLimits` quietly leaves a
32 MiB aggregate over 704 KiB mailboxes ⇒ **45 full mailboxes fit** ⇒
concurrency > 45 on one carrier hits `rejectAggregate` →
`failUndeliverableData` → `dropped_data_frames`. That is an
integrity-adjacent throttle **triggered by concurrency**, contradicting §0.3.

**Required (B4d) — all three change in the SAME slice (Slice 8):**
1. `DefaultStreamLimits` (`MaxBytesPerStream` = 704 KiB, `MaxBytesTotal` =
   8 MiB) — [`carrier.go:393-398`](../pkg/mux/carrier.go:393).
2. The shipped config default (`StreamLimits` set via `SetStreamLimits`,
   [`carrier.go:451`](../pkg/mux/carrier.go:451)) to the same 704/8-MiB pair.
3. **`SanitizeLimits` must FAIL LOUDLY**, not silently reset, when
   `MaxBytesTotal < MaxBytesPerStream`:

   ```go
   // REV 1 proposed: return an error instead of the silent reset at
   // carrier.go:414-415, so a 704-KiB-cap / 32-MiB-default build cannot
   // ship:
   if l.MaxBytesTotal < l.MaxBytesPerStream {
       return StreamLimits{}, fmt.Errorf(
           "mux: MaxBytesTotal (%d) < MaxBytesPerStream (%d); " +
           "raise MaxBytesTotal to >= N_max*MaxBytesPerStream",
           l.MaxBytesTotal, l.MaxBytesPerStream)
   }
   ```
   Failing loud at `SetStreamLimits` means an intermediate build that sets
   only the 704 KiB cap **cannot start** — the operator is forced to set the
   8 MiB aggregate in the same change.

**Closed-bound invariant (the design must maintain; REV 2 N3 — label fixed):**
```
  (a) Without headroom:
      N_max × mailboxCap ≤ MaxBytesTotal
      8 × 704 KiB      = 5.63 MiB  ≤ 8 MiB          ✓

  (b) With headroom:
      N_max × mailboxCap + headroom ≤ MaxBytesTotal
      8 × 704 KiB      + 2.5 MiB   = 8.13 MiB ≈ 8 MiB  ✓
      (headroom = MaxBytesTotal − N_max × mailboxCap = 8 − 5.63 ≈ 2.37 MiB,
       rounded to the 2 MiB design margin)
```
> **REV 2 N3:** REV 1 labeled the "+2 MiB" term "the *per-stream* share of
> the shared `writeCh`/`c.frames`", which **contradicted** §10.1/§10.2's
> statement that the fixed 65.2 MiB floor is **outside** `MaxBytesTotal`
> — both cannot hold in one formula. The term is now simply called
> **"headroom (2.5 MiB available)"** — *slack* reserved between the funded
> mailbox sum and `MaxBytesTotal`; it is **not** a re-labelling of
> `writeCh`/`c.frames`. The `writeCh`/`c.frames` fixed floor (65.2 MiB,
> §10.1/§10.2) remains **outside** `MaxBytesTotal`. Both readings (a) and
> (b) close. □

---

## 11. Deadlock / HOL / Fairness Proof

### 11.1 Lock ordering (REV 2 N1: corrected)

> **REV 2 N1:** REV 1's "the lock order is `c.mu → q.mu`, documented at
> `queue.go:51-56`" was **wrong and the citation pointed at the opposite
> statement**. The [`queue.go:51-56`](../pkg/mux/queue.go:51) comment
> documents the hot path as **`q.mu`-only** and explains that the budget
> limit is deliberately stored as a plain value (`budgetLimitLocked`)
> *precisely so* no second lock is taken under `q.mu`. The real
> invariant is at [`carrier.go:1024-1026`](../pkg/mux/carrier.go:1024):
> *"q.mu is never taken while c.mu is held anywhere else, so the lock
> ordering stays acyclic."*

**Correct statement (REV 2 N1):** there is **no `c.mu → q.mu` nesting
anywhere in the code**. The hot path (TryPush/Pop) takes `q.mu` **only**.
The only place `c.mu` and `q.mu` interact is `Close`, which takes `c.mu`
to snapshot the stream list and **releases `c.mu` before** calling
`q.Close()` — i.e. `q.mu` is **never held while `c.mu` is held**
([`carrier.go:1024-1026`](../pkg/mux/carrier.go:1024)). **No lock
nesting, hence no inversion, acyclic by construction.** □

**v2 does not introduce any new lock.** The `creditLedger` has its own
`mu` (a leaf lock, not held while acquiring `c.mu` or `q.mu`). The `ctrlCh`
and `writeCh` are channels (no explicit lock). **No new lock, no new lock
order, no inversion risk.**

### 11.2 Deadlock proof

**Claim:** The v2 design cannot deadlock.

**Proof by case analysis:**

1. **`writeLoop` (sole consumer of `writeCh` and `ctrlCh`):**
   - `writeLoop` is a single goroutine that reads from `ctrlCh` (priority)
     and `writeCh` (FIFO) and writes to `rwc` (the underlying TCP/WS conn).
   - `rwc.Write` can block (kernel send buffer full), but it **always
     eventually unblocks** (the kernel drains the send buffer, or the conn
     is closed, in which case `rwc.Write` returns an error and the
     `writeLoop` exits via `<-c.closed`).
   - **No deadlock:** the `writeLoop` cannot be permanently blocked.

2. **`streamWorker` (one per stream):**
   - `streamWorker` calls `q.Pop()` (blocks until an item is available or
     the queue is `Close`d). `q.Pop()` unblocks when: (a) a new item is
     `TryPush`ed, (b) the queue is `Close`d (stream terminated or carrier
     closing), or (c) `wake` is signalled. **No deadlock.**
   - `streamWorker` then does `s.ch <- it.payload` (bounded by
     `OverflowWait` = 100 ms). If the consumer (`startStreamRelay`) is
     blocked, the `streamWorker` times out after 100 ms and terminates the
     stream. **No deadlock** (bounded wait).
   - **v2 addition:** `streamWorker` does **not** call `writeCredit`
     (that's in `startStreamRelay`, after `sock.Write`). The
     `streamWorker` is **not** blocked on the credit-emission write.
     **No new deadlock path.**

3. **`startStreamRelay` (one per stream per carrier epoch):**
   - `startStreamRelay` reads from `s.ch` (unbounded wait, but `s.ch` is
     `Close`d on stream termination, which unblocks the read).
   - `startStreamRelay` calls `sock.Write(frame)`. `sock.Write` can block
     (client TCP recv buffer full), but it **always eventually unblocks**
     (the client kernel drains the recv buffer, or the conn is closed, in
     which case `sock.Write` returns an error and the relay exits).
   - **v2 addition (REV 2 S2):** After `sock.Write` completes,
     `startStreamRelay` calls `creditEmitter.emit(streamID, n)` (batched,
     §7). `emit` uses `TryWriteControlFrame` — the **non-blocking,
     drop-on-full** enqueue on `ctrlCh` (cap 64). If `ctrlCh` is full, the
     emit **drops** the credit (the next credit will include the cumulative
     `bytesConsumed`, so no information is lost). **The `creditEmitter.emit`
     never blocks** (`TryWriteControlFrame` is a non-blocking enqueue on a
     bounded channel; drop-on-full). The blocking `WriteControlFrame`
     (which *does* block on `<-req.done`) is reserved for `FrameClose`
     only. **No deadlock.**

4. **`relayShapeA` (one per direction per session):**
   - `relayShapeA` calls `sock.Read(buf)` (blocks until data is available
     or the conn is closed). **No deadlock** (the target socket will
     eventually produce data or be closed).
   - `relayShapeA` calls `flushPending` → `WriteFrame` → `c.write` →
     enqueues on `writeCh` (cap 256) → blocks on `<-req.done`. If
     `writeCh` is full, `c.write` blocks until the `writeLoop` consumes a
     request. The `writeLoop` is always consuming (it's the sole consumer).
     **No deadlock** (the `writeCh` will drain).
   - **v2 addition:** The `creditGate` check (`canSend`) is a
     non-blocking lock acquisition on `creditLedger.mu` (leaf lock, no
     contention with `c.mu` or `q.mu`). **No new deadlock path.**

5. **`Dispatch` (single goroutine per carrier):**
   - `Dispatch` reads from `c.frames` (unbounded wait, but `c.frames` is
     closed when the `readLoop` exits, which unblocks the read).
   - `Dispatch` calls `deliver` → `TryPush` (non-blocking, `q.mu`
     acquired/released atomically). **No deadlock.**
   - **v2 does not change `Dispatch`.** □

**Conclusion:** No combination of the goroutines above can form a
circular wait. **The v2 design cannot deadlock.**

### 11.3 HOL (head-of-line) proof (REV 1 — routing corrected)

**Claim:** The v2 design cannot stall a stream's *ordering-sensitive* frame
(DATA / `FrameRebind` / `FrameHeader`) behind another stream's DATA, and a
credit frame is not FIFO-queued behind 256 DATA frames.

**Proof (REV 1):**
- **Credit not behind DATA (true):** `FrameCredit`, `FrameClose`,
  `FramePing`/`FramePong` ride `ctrlCh` (cap 64), which the `writeLoop`
  checks **before** `writeCh` (§7.2). A credit on `ctrlCh` is written within
  one `writeLoop` iteration regardless of how many DATA frames are on
  `writeCh`. **A credit is never behind 256 DATA frames.** □
- **Rebind/Header stay ordered with DATA (REV 1 correction):** `FrameRebind`
  and `FrameHeader` are **NOT** on `ctrlCh` — they stay on `writeCh` FIFO
  with DATA (§7.2 routing table, B3). A stream's own `FrameRebind`/
  `FrameHeader`/first-DATA therefore preserve in-stream order. **REV 0's
  claim that "all of CREDIT, CLOSE, REBIND, HEADER, PING, PONG ride
  `ctrlCh`" is false and retracted** (it would have broken the
  rebind-must-be-first invariant, §7.2/§node.go:686).
- **Reverse HOL / DATA delay:** bounded by one blocked `rwc.Write`
  (§7.4, N2), **≈6.5 ms at the 5 MB/s assumption** — not the REV 0 "~1 ms
  typical" estimate. DATA is not starved indefinitely. □

### 11.4 Fairness — RESIDUAL HOL RISK, honestly stated (REV 1 — S5)

> **REV 1 (S5):** REV 0's "fairness proof" (claim: "cannot starve one
> stream by another") is **contradicted by its own mechanism and is DELETED**.
> REV 0 cited `MaxBytesTotal` as the fairness bound, but `MaxBytesTotal`
> bounds **mailboxes only** (§10.1) — it does **not** bound `writeCh`
> (256 × 65542 ≈ 16.3 MiB), the actual shared write resource. A burst of DATA
> from stream A can fill `writeCh` and delay stream B's DATA; `MaxBytesTotal`
> does not prevent that. We do **not** assert inter-stream fairness here.

**What is TRUE (honest residual-risk statement):**
1. **Mailboxes are independent and bounded.** Each stream's `StreamQueue` is
   capped at `mailboxCap = 704 KiB`; one stream's full mailbox does not block
   another's `streamWorker` ([`queue.go:140-143`](../pkg/mux/queue.go:140)).
   **No inter-stream HOL on the mailbox side.**
2. **`writeCh` is a shared FIFO (residual HOL risk — unbounded per stream;
   REV 2 N4: magnitude now derived).**
   `writeCh` (cap 256, ~16.3 MiB) is shared by all streams on a carrier.
   **A DATA burst from stream A can fill `writeCh` and delay stream B's DATA
   by up to the full `writeCh` drain time.** Derived (REV 2 N4):
   `16.3 MiB ÷ carrier_rate` ⇒ **≈ 3.3 s** worst-case DATA delay for one
   unlucky stream behind a full `writeCh` **at the doc's 5 MB/s assumption**
   (≈ 0.14 s at the 121.4 MiB/s raw ceiling, §0.4). This is a **pre-existing**
   property of the shared `writeCh` (not introduced by v2), and **v2 does not
   bound it per stream.** We state it as a residual risk, not a solved
   property. It sits side-by-side with §7.4's ~6.5 ms **control-frame**
   bound (one blocked `rwc.Write`); the two are different: §7.4 bounds the
   delay *to control* frames, this §11.4 derivation bounds the delay *to
   DATA* behind a saturated shared FIFO.
3. **`ctrlCh` control-plane (residual, bounded).** A burst of `FrameCredit`
   from stream A can fill `ctrlCh` (cap 64) and delay stream B's credit.
   Credits are **cumulative** (`bytesConsumed`), so a delayed credit only
   *delays* stream B's re-gate; the next credit heals it. **Bounded by the
   `ctrlCh` cap**, not unbounded.
4. **Mitigation plan (NOT added to this design, explicitly out of scope):**
   a **per-stream `writeCh` occupancy budget** would close the residual HOL
   risk. It is **not** part of the 14 deliverables, and **must not** be added
   ad hoc: a per-stream `writeCh` cap can **deadlock with the `pending`
   gate** (`relays.go:106-111`) — if stream A's budget is exhausted AND the
   relay is parked at `pending >= capacity`, and both are coupled to the
   same `writeCh`, a circular wait is possible. Any such budget must first
   prove non-deadlock with `flushPending`/`pending` and with the mailbox
   bound (§6.2) before it is scoped. **This design therefore ships WITHOUT a
   per-stream `writeCh` budget** and carries the residual HOL risk forward as
   a documented, operator-visible open item.

**Decision for the operator:** accept the residual `writeCh` HOL risk
(bounded only by the 256-slot / ~16.3 MiB cap), or scope a **separate** task
to add a per-stream `writeCh` budget that has a deadlock proof against the
`pending` gate. This design does not make that change.

### 11.5 Half-closed / terminated peer proof

**Claim:** The v2 design cannot deadlock with a half-closed or terminated
peer.

**Proof:**
1. **Half-close (peer sends `FrameClose`):** The stream's mailbox receives
   a `queueItem{isClose: true}`. The `streamWorker` hands off `nil` to
   `startStreamRelay`, which calls `peerEOF` (half-closes the direction)
   and exits. The credit state for that direction is cleared. The other
   direction continues. **No deadlock** (the half-close is a clean
   termination of one direction, not a block).
2. **Termination (peer's `terminateStream`):** The stream's mailbox is
   `Close`d. The `streamWorker` exits (`q.Pop()` returns `ok=false`). The
   `s.ch` is `Close`d by the carrier's `Close` path. The
   `startStreamRelay` consumer sees `ok=false` on `s.ch` and exits. **No
   deadlock** (all goroutines for the stream exit cleanly).
3. **Carrier loss (the entire carrier is lost):** All streams on the
   carrier are detached. The grace timer (5 s) starts. If the carrier is
   not re-attached within the grace, the session is closed
   ([`node.go:422`](../pkg/node/node.go:422)). **No deadlock** (bounded
   by the grace timer). □

---

## 12. Implementation Slices (REV 1 — N4/N5/N6)

> **REV 1 gate discipline (N5).** REV 0's per-slice gate was
> `go test -race ./pkg/mux/`. That is **insufficient** after the `writeLoop`
> rewrite, because the rewrite changes the `writeWG`/`drainWrites` shutdown
> contract that the **existing** [`carrier_shutdown_test.go`](../pkg/mux/carrier_shutdown_test.go)
> asserts (`TestCloseResolvesAllQueuedWrites`, `TestWriterExitsAfterClose`).
> **Every slice gate therefore (a) runs the FULL existing `pkg/mux` suite by
> name, and (b) ends with a "main stays green" step (`go build ./... &&
> go test ./...` — the non-race whole-module test).** The exact existing test
> files for `pkg/mux` are:
> `carrier_test.go`, `carrier_shutdown_test.go`, `carrier_reader_test.go`,
> `queue_test.go`, `frame_test.go`, `liveness_test.go`, `security_test.go`,
> `auth_test.go`, `auth_ws_timeout_test.go`, `secret_test.go`,
> **and (REV 2 N5) the 5 files the REV 1 "exact" list omitted**:
> `carrier_close_race_test.go`, `deliver_fail_test.go`, `queue_stats_test.go`,
> `backpressure_test.go`, `consumer_stall_test.go`, plus
> `carrier_stats_test.go`. A gate that skips any of these (especially
> `carrier_shutdown_test.go`) is **not** green.
>
> **Wire-version / atomic upgrade (N4, S4).** The `FrameCredit` payload is
> **32 bytes** (§5.1), a **wire-format break** from D4's 18-byte payload.
> Slice 2's slice ordering **gates on a version bump** (`creditVersion = 1`),
> and because a v1 build's `Dispatch` **silently drops** `FrameCredit`
> ([`carrier.go:770-771`](../pkg/mux/carrier.go:770)), **both ends must be
> upgraded atomically in the same maintenance window** (§5.2). No slice may
> ship credit emission before both binaries are v2.

### Slice 1: Add `ctrlCh` + `ctrlWG`/`drainCtrl`, modify `writeLoop` (mux)

**Files:** `pkg/mux/carrier.go`, `pkg/mux/carrier_test.go` (new tests),
`pkg/mux/carrier_shutdown_test.go` (extend for `ctrlWG`/`drainCtrl`).

**Changes (REV 1 — B3):**
- Add `ctrlCh chan writeReq` (cap 64) **and** `ctrlWG sync.WaitGroup` to
  `CarrierConn` (mirrors `writeWG`,
  [`carrier.go:319`](../pkg/mux/carrier.go:319)).
- Modify `writeLoop` to the strict-priority pattern (§7.2), **with the
  `c.closed` arm exiting cleanly** and every `writeOne` resolving `req.done`.
- Add `drainCtrl()` (mirror of `drainWrites`,
  [`carrier.go:331-345`](../pkg/mux/carrier.go:331)) and call
  `c.ctrlWG.Wait(); c.drainCtrl()` in `Close` **before**
  `c.writeWG.Wait(); c.drainWrites()`
  ([`carrier.go:1004-1016`](../pkg/mux/carrier.go:1004)).
- Add **TWO** control-frame functions (REV 2 S2):
  - `TryWriteControlFrame(streamID uint32, typ uint8, payload []byte)
    (enqueued bool, err error)`: **non-blocking, drop-on-full**. Enqueues on
    `ctrlCh` with abortable `ctrlWG` discipline; on a full `ctrlCh` (or after
    `<-c.closed`) it **drops** the frame and returns immediately — it **never
    blocks**. This is the function the **credit emitter** uses.
  - `WriteControlFrame(streamID uint32, typ uint8, payload []byte) error`:
    **blocking** — enqueues on `ctrlCh` with abortable `ctrlWG` discipline
    (the `select` race against `<-c.closed`), then blocks on `<-req.done`
    (mirroring [`carrier.go:307-329`](../pkg/mux/carrier.go:307)). **Reserved
    for `FrameClose`** (a terminal signal that must not be dropped).
  Emit table (REV 2 S2): `creditEmitter.emit` and `TestCreditEmitterDropOnFull`
  → `TryWriteControlFrame`; `FrameClose` writes → `WriteControlFrame`.
- **Routing (B3):** route `FrameCredit`/`FrameClose`/`FramePing`/
  `FramePong` to `ctrlCh`; **keep `FrameData`, `FrameHeader`, `FrameRebind`
  on `writeCh`** (FIFO, in-order). This is the REV 1 correction — REV 0
  routed Header/Rebind to `ctrlCh`, which broke rebind-must-be-first.
- **No behaviour change for existing DATA tests** (DATA/Rebind/Header still
  FIFO on `writeCh`).
- **REV 2 S5 (scope note):** Ping/Pong **move off `writeCh` onto `ctrlCh`**
  — today `Dispatch` emits `FramePong` via `c.write(...)` on `writeCh`
  ([`carrier.go:758-763`](../pkg/mux/carrier.go:758)). This is a
  **deliberate, benign, non-stream-ordering-sensitive** change: Ping/Pong
  are keepalive and carry no in-stream byte-order role, so reordering them
  relative to DATA is safe. The Slice 1 gate MUST re-run
  `liveness_test.go`'s pong-ordering assertions to prove no keepalive
  behaviour regresses.

**Tests (REV 1 — N5: the existing suite is named, not just the new file):**
- New: `TestControlFramePriority`, `TestCtrlChBounded`,
  `TestWriteLoopDeadlockFree`, `TestCtrlChDrainOnClose` (new: after
  `Close`, every enqueued `ctrlCh` request is resolved — extends
  `carrier_shutdown_test.go`).
- **MUST re-run and stay green (existing):** `carrier_shutdown_test.go`
  (`TestCloseResolvesAllQueuedWrites`, `TestWriterExitsAfterClose` — these
  assert the `writeWG`/`drainWrites` contract we are extending),
  `carrier_reader_test.go`, `queue_test.go`, `frame_test.go`,
  `liveness_test.go` (**incl. the pong-ordering assertions, REV 2 S5**),
  `security_test.go`, `auth_test.go`,
  `auth_ws_timeout_test.go`, `secret_test.go`,
  `carrier_close_race_test.go`, `deliver_fail_test.go`, `queue_stats_test.go`,
  `backpressure_test.go`, `consumer_stall_test.go`, `carrier_stats_test.go`
  (REV 2 N5 — the 5 omitted `pkg/mux` files, now named; `carrier_stats_test.go`
  also present and included).

**Gate:** `go build ./...` + `go vet ./...` +
`go test -race ./pkg/mux/` (full suite, all files named above) +
**main stays green:** `go build ./... && go test ./...`.

---

### Slice 2: Add `FrameCredit` type and payload (mux)

**Files:** `pkg/mux/frame.go`, `pkg/mux/frame_test.go`, `pkg/mux/carrier.go`
(`Dispatch` switch, [`carrier.go:735`](../pkg/mux/carrier.go:735))

**Changes (REV 1 — N3/N4/S4):**
- Add `FrameCredit uint8 = 0x07` to the frame type constants.
- Add `CreditPayload` struct (**32-byte payload**, §5.1): `creditVersion`
  (1), `creditGen` (**uint64**, 8, N3), `bytesConsumed` (8),
  `windowGranted` (4), `flags` (1), `reserved` (10). `EncodeCreditPayload` /
  `DecodeCreditPayload` helpers (BigEndian).
- Add validation: `creditVersion == 1`, `creditGen` == the **arriving
  carrier's `h.gen`** (§5.2/S3, not the rebind payload), `bytesConsumed`
  monotonic, `windowGranted` clamped, `flags` bits, payload length = **32**.
- **Explicit `case FrameCredit:` in `Dispatch`** that decodes + validates
  and routes to the node credit handler — **do NOT let it fall into
  `default: // unknown frame type: drop`** ([`carrier.go:770-771`](../pkg/mux/carrier.go:770)).
- **No behaviour change for existing frame tests.**

**Tests (REV 1 — S4 MUST test + N5):**
- `TestCreditPayloadEncodeDecode`: round-trip the **32-byte** payload.
- `TestCreditPayloadValidation`: reject `creditVersion != 1`, reject
  `bytesConsumed` going backwards, reject wrong payload length (≠ 32).
- `TestCreditFrameOnCtrlCh`: assert `WriteFrame(FrameCredit)` routes to
  `ctrlCh` (Slice 1's `TryWriteControlFrame` for credit; REV 2 S2).
- **`TestDispatchUnknownTypeNeverTerminates` (S4 — MUST):** feed `Dispatch`
  a frame of an unrecognised type; assert the stream is **not** terminated
  and no `dropped_data_frames`/`data_undeliverable` fires. Guards the
  `default:` drop-only behaviour.
- **MUST re-run existing (N5):** `frame_test.go`, `carrier_test.go`,
  `carrier_shutdown_test.go`, `queue_test.go`, `liveness_test.go`,
  `security_test.go`, `auth_test.go`, `auth_ws_timeout_test.go`,
  `secret_test.go`.

**Gate:** `go build ./...` + `go vet ./...` +
`go test -race ./pkg/mux/` (full suite, all files named above) +
**main stays green:** `go build ./... && go test ./...`.

**Ordering (N4/S4):** Slice 2 **gates on the wire-format version bump**
(`creditVersion = 1`, 32-byte payload). It may be built but **must not be
deployed** to only one end: because `Dispatch` on a v1 build **drops**
`FrameCredit`, deploying Slice 2 on IR only (or DE only) silently stalls
the peer. **Both `iran-splitter` and `germany-splitter` must be upgraded to
the v2 build atomically (§5.2 atomic-upgrade requirement) before credit is
enabled on either side.**

---

### Slice 3: Add `creditLedger` (node)

**Files:** `pkg/node/credit.go` (new), `pkg/node/credit_test.go` (new)

**Changes (REV 1 — S2):**
- Add `creditLedger` struct (§6.5): `outstanding`, `lastSeen`, `window`,
  `latched`, **`safelyCapped`**, **`gen uint64`** (N3), `mu`.
- Add `canSend`, `recordSent`, `onCredit`, `clearStream`, `armEstablish`
  methods. `canSend` **never returns "unlimited"** (§6.5): pre-latch it is
  bounded by `MaxBytesPerStream`; `safelyCapped` it is bounded by
  `CreditSafeWindow` (64 KiB).
- Add `CreditSafeTimeout` timer (**2 s** default). On expiry the stream
  latches to **`SAFELY_CAPPED`** (`safelyCapped = true`, window =
  `CreditSafeWindow` = 64 KiB) — **NOT** to unlimited (S2). This is the REV 1
  correction of REV 0's "revert to unlimited (`latched = false`)".

**Tests (REV 1 — S2):**
- `TestCreditLedgerCanSend`: `outstanding + chunk > window + allowance` →
  `canSend` returns false.
- `TestCreditLedgerOnCredit`: valid credit → `outstanding` decreases.
  Stale credit (wrong gen) → rejected. Out-of-order credit → rejected.
  Duplicate credit → no-op.
- `TestCreditSafeTimeoutCapsNotUnlimited` (S2): no credit within 2 s →
  `safelyCapped = true` and `canSend` is bounded by **64 KiB** (never
  unlimited). Assert the un-latched/unlimited state is **never** reachable
  after any latch.
- `TestCreditLedgerClearStream`: `clearStream` resets all fields.

**Gate:** `go build ./...` + `go vet ./...` +
`go test -race ./pkg/node/` + **main stays green:**
`go build ./... && go test ./...`.

---

### Slice 4: Add credit emission in `startStreamRelay` (node)

**Files:** `pkg/node/relays.go`, `pkg/node/node.go`

**Changes:**
- In `startStreamRelay` (the `frame, ok := <-ch` branch), after
  `sock.Write(frame)` succeeds, call `n.creditEmitter.emit(streamID,
  uint64(n))` (the batched credit emitter, Slice 5).
- **Do NOT** call `writeCredit` in the `streamWorker` (this is the key
  difference from D4: credit emission is moved from the `streamWorker` to
  the `startStreamRelay`, after `sock.Write`).
- The credit emitter accumulates bytes and emits a `FrameCredit` when the
  accumulated bytes reach `MaxPayload` (64 KiB) or when the stream is
  half-closing (whichever comes first). **Batching: one credit frame per
  64 KiB consumed, not one per 32 KiB Pop.**

**Tests:**
- `TestCreditEmissionBatching`: consume 128 KiB via `sock.Write`. Assert
  exactly 2 `FrameCredit` frames are emitted (not 4, not 1).
- `TestCreditEmissionOnHalfClose`: consume 32 KiB, then half-close. Assert
  1 `FrameCredit` frame is emitted (the final flush).

**Gate:** `go build ./...` + `go vet ./...` + `go test -race ./pkg/node/`
+ **main stays green:** `go build ./... && go test ./...`.

---

### Slice 5: Add batched credit emitter (node)

**Files:** `pkg/node/credit.go` (extend), `pkg/node/credit_test.go`
(extend)

**Changes:**
- Add `creditEmitter` struct: per-stream accumulator
  (`pendingBytes uint64`, `lastEmit uint64`).
- Add `emit(streamID uint32, n uint64)`: add `n` to `pendingBytes`. If
  `pendingBytes >= MaxPayload`, emit a `FrameCredit` with
  `bytesConsumed = lastSeen + pendingBytes`, reset `pendingBytes`. If
  half-close is pending, emit immediately regardless of size.
- The `FrameCredit` is written via `TryWriteControlFrame` (Slice 1's
  **non-blocking, drop-on-full** `ctrlCh` path; REV 2 S2 — the blocking
  `WriteControlFrame` is reserved for `FrameClose` only). If `ctrlCh` is
  full, **drop** the credit (the next credit will include the cumulative
  `bytesConsumed`).
- **The `creditEmitter.emit` is non-blocking** (`TryWriteControlFrame`:
  non-blocking enqueue on `ctrlCh`).

**Tests:**
- `TestCreditEmitterBatch`: emit 3 × 32 KiB = 96 KiB. Assert 1 credit
  frame (96 KiB < 64 KiB threshold? No: 96 KiB > 64 KiB, so 1 credit for
  64 KiB + 1 credit for 32 KiB = 2 credits).
  **Correction:** the threshold is `MaxPayload` = 64 KiB. 96 KiB → 1
  credit for 64 KiB (at the 64 KiB mark) + 1 credit for 32 KiB (on the
  next emit or half-close). Assert 2 credits.
- `TestCreditEmitterDropOnFull`: fill `ctrlCh` (cap 64). Emit a credit
  via `TryWriteControlFrame`. Assert the credit is dropped (no deadlock,
  no block) — this is the non-blocking drop-on-full path (REV 2 S2).

**Gate:** `go build ./...` + `go vet ./...` + `go test -race ./pkg/node/`
+ **main stays green:** `go build ./... && go test ./...`.

---

### Slice 6: Add credit gate in `relayShapeA` (node)

**Files:** `pkg/node/relays.go`, `pkg/node/node.go`

**Changes:**
- In `relayShapeA` (the `!socketEOF` fall-through, before `sock.Read`),
  add the credit gate:
  ```go
  if l := n.creditLedgerFor(sess, dir); l != nil && !l.canSend(uint64(n.cfg.RelayBufSize)) {
      n.creditPark(sess, dir, att)  // park at the credit gate (not pending-cap)
      continue
  }
  ```
- The `creditPark` call records the park (for metrics:
  `relay_credit_block++`, **unlike D4** this counter now actually
  increments when the credit gate parks the relay).
- **The credit gate is BEFORE the `pending >= capacity` check.** If the
  credit gate passes but `pending >= capacity`, the relay still parks at
  the pending-cap gate (existing behaviour, [`relays.go:106-111`](../pkg/node/relays.go:106)).
  The two gates are **independent** and **both** must pass for the relay
  to read the target.

**Tests:**
- `TestCreditGateParks`: `outstanding >= window + allowance` → relay
  parks. Assert `relay_credit_block` counter increments.
- `TestCreditGateUnparks`: `outstanding < window + allowance` → relay
  reads target. Assert `relay_credit_block` does not increment.

**Gate:** `go build ./...` + `go vet ./...` + `go test -race ./pkg/node/`
+ **main stays green:** `go build ./... && go test ./...`.

---

### Slice 7: Rebind-attach credit reset (node)

**Files:** `pkg/node/node.go`, `pkg/node/credit.go`

**Changes:**
- In `rebindDirection` / `handleRebind` (the rebind-attach path), call
  `n.creditLedgerFor(sess, dir).clearStream()` (reset `outstanding`,
  `lastSeen`, `latched` to 0/false, `safelyCapped` to false, `gen` to the
  new carrier's `h.gen`).
- Emit the **anchor credit** (`bytesConsumed = 0`, **`creditGen = the new
  carrier's `h.gen`** (§9.1, pinned at arrival — NOT the rebind payload),
  `windowGranted` = the current window, `flags = 0`) on the new carrier for
  each re-bound stream. The anchor **latches** the sender to the safe/granted
  window (bounded, never unlimited).
- The anchor credit latches the sender (DE) to the new generation's window.

**Tests:**
- `TestRebindCreditReset`: rebind a stream. Assert `outstanding = 0`,
  `lastSeen = 0`, `latched = false`, `gen = new_gen`.
- `TestAnchorCreditLatches`: emit the anchor credit. Assert `latched =
  true`, `gen = new_gen`.

**Gate:** `go build ./...` + `go vet ./...` + `go test -race ./pkg/node/`
+ **main stays green:** `go build ./... && go test ./...`.

---

### Slice 8: Reduce `MaxBytesPerStream`, set the closed `MaxBytesTotal`, and make `SanitizeLimits` fail loud (mux + config)

**Files:** `pkg/mux/carrier.go`, `internal/config/config.go`

> **REV 1 (B4d):** REV 0 said "raise `MaxBytesTotal` to 48 MiB". That is
> **retracted**: `writeCh`+`c.frames` (the 65.2 MiB dominant floor) are
> **outside** `MaxBytesTotal` (§10.1), so 48 MiB buys nothing and the
> `MaxBytesTotal` only needs to fund the *mailbox* term for `N_max = 8`.
> The value is **8 MiB**, and `DefaultStreamLimits`, the shipped config
> default, and `SanitizeLimits` **all change in this one slice** so no
> intermediate build ships the 704/32-MiB footgun.

**Changes:**
- Reduce `MaxBytesPerStream` from 1 MiB to `MaxPayload + unackedAllowance +
  window_max = 704 KiB` (default). **Reduction** (constraint 2).
- **Set `MaxBytesTotal` to 8 MiB** (from the 32 MiB default) — the closed
  mailbox budget for `N_max = 8` (8 × 704 KiB = 5.6 MiB + 2 MiB headroom,
  §10.3). **Not 48 MiB** (retracted, B4).
- Change `DefaultStreamLimits`
  ([`carrier.go:393-398`](../pkg/mux/carrier.go:393)) to
  `MaxBytesPerStream = 704 KiB`, `MaxBytesTotal = 8 MiB` — **in this slice**.
- Change the shipped config default
  (`SetStreamLimits`, [`carrier.go:451`](../pkg/mux/carrier.go:451)) to the
  same 704/8-MiB pair — **in this slice**.
- **Make `SanitizeLimits` fail LOUDLY**
  ([`carrier.go:406`](../pkg/mux/carrier.go:406)): replace the silent reset
  at [`carrier.go:414-415`](../pkg/mux/carrier.go:414) with an **error
  return** when `MaxBytesTotal < MaxBytesPerStream` (§10.4). This requires
  threading an error through `SetStreamLimits` / `NewNode` callers.

**Tests (REV 1):**
- `TestMaxBytesPerStreamReduced`: default `MaxBytesPerStream` = 704 KiB.
- `TestMaxBytesTotalSetTo8MiB`: default `MaxBytesTotal` = **8 MiB** (not 48).
- `TestSanitizeLimitsFailsLoud`: `SanitizeLimits(MaxBytesPerStream=704 KiB,
  MaxBytesTotal=32 MiB-default)` **returns an error** when
  `MaxBytesTotal < MaxBytesPerStream`; assert the 704/32-MiB footgun **cannot
  silently start**.
- **MUST re-run existing (N5):** `queue_test.go`
  (`fullLocked`/`rejectAggregate` against the new 704/8-MiB bounds),
  `carrier_test.go`, `carrier_shutdown_test.go`, `frame_test.go`,
  `liveness_test.go`, `security_test.go`, `auth_test.go`,
  `auth_ws_timeout_test.go`, `secret_test.go`.

**Gate:** `go build ./...` + `go vet ./...` +
`go test -race ./pkg/mux/` (full suite, all files named above) +
**main stays green:** `go build ./... && go test ./...`.

---

### Slice 9: Integration test (loopback)

**Files:** `pkg/node/credit_test.go` (extend), `e2e-pipe-test/` (new
test case)

**Changes:**
- Loopback test: two `Node` instances (simulated DE and IR) connected via
  in-memory pipes (simulating the down-carrier TCP conn). Transfer a 1 MiB
  object from DE target to IR client. Assert:
  - 0 `dropped_data_frames`.
  - 0 `data_undeliverable` close reasons.
  - The transfer completes in < 5 s (loopback, no cross-border RTT).
  - `relay_credit_block` counter > 0 (the credit gate actually parks the
    relay, unlike D4).
  - The transfer rate is ≥ 50 MB/s (loopback ceiling).

**Gate:** `go build ./...` + `go vet ./...` + `go test -race ./pkg/node/ ./e2e-pipe-test/`
+ **main stays green:** `go build ./... && go test ./...`.

---

### Slice 10: Live A/B test methodology (operator)

**No code changes.** This slice documents the **operator-level** A/B test
procedure (see §13 for the full test matrix). The key requirement:

- **Rate measured, not just pass/fail.** The A/B test MUST measure
  throughput (bytes/sec) for the 1 MiB transfer, not just assert
  `rc==0`. The D4 bug was caught **only** because the rate was measured
  (8.3 KB/s vs 1,372 KB/s), not because the transfer "failed" (it
  technically "succeeded" — the transfer completed, just slowly).
- **Scoring rule:** `rc==0 AND received==expected AND checksum match AND
  rate >= threshold`. HTTP 200 is **NOT** success (curl returns 200 on
  truncated bodies).
- **Rollback criterion:** if the v2 build's rate is **less than 50%** of
  the no-credit baseline rate, **roll back immediately** (the v2 build is
  worse than no credit).

**Gate:** No code gate. Operator sign-off required.

---

## 13. Complete Test Matrix

### 13.1 Unit tests

| Test | File | What it verifies |
|---|---|---|
| `TestControlFramePriority` | `pkg/mux/carrier_test.go` | `FrameCredit`/`Close`/`Ping` on `ctrlCh` are written before DATA on `writeCh`. |
| `TestCtrlChBounded` | `pkg/mux/carrier_test.go` | `ctrlCh` (cap 64) drops the 65th frame (non-blocking; no deadlock). |
| `TestWriteLoopDeadlockFree` | `pkg/mux/carrier_test.go` | `writeLoop` with a slow `rwc.Write` completes within the expected time. |
| `TestCtrlChDrainOnClose` (B3) | `pkg/mux/carrier_shutdown_test.go` | After `Close`, every enqueued `ctrlCh` request is resolved by `drainCtrl()` (no orphaned `req.done`). |
| `TestCreditPayloadEncodeDecode` | `pkg/mux/frame_test.go` | **32-byte** payload round-trips correctly (BigEndian; `creditGen` uint64). |
| `TestCreditPayloadValidation` | `pkg/mux/frame_test.go` | Reject `creditVersion != 1`, reject `bytesConsumed` going backwards, reject wrong payload length (≠ 32). |
| `TestCreditFrameOnCtrlCh` | `pkg/mux/frame_test.go` | `WriteFrame(FrameCredit)` routes to `ctrlCh` via `TryWriteControlFrame` (non-blocking, REV 2 S2). |
| `TestDispatchUnknownTypeNeverTerminates` (S4) | `pkg/mux/carrier_test.go` | An unrecognised frame type is dropped, **never** terminated; no `dropped_data_frames`/`data_undeliverable`. |
| `TestCreditLedgerCanSend` | `pkg/node/credit_test.go` | `outstanding + chunk > window + allowance` → `canSend` false; **never** "unlimited" (pre-latch bounded by `MaxBytesPerStream`). |
| `TestCreditLedgerOnCredit` | `pkg/node/credit_test.go` | Valid credit → `outstanding` decreases. Stale (wrong `gen`) → rejected. Out-of-order → rejected. Duplicate → no-op. |
| `TestCreditSafeTimeoutCapsNotUnlimited` (S2) | `pkg/node/credit_test.go` | No credit within 2 s → `safelyCapped = true`, `canSend` bounded by **64 KiB** (never unlimited). |
| `TestCreditLedgerClearStream` | `pkg/node/credit_test.go` | `clearStream` resets all fields. |
| `TestCreditEmissionBatching` | `pkg/node/credit_test.go` | Consume 128 KiB → 2 credit frames (not 4, not 1). |
| `TestCreditEmitterDropOnFull` | `pkg/node/credit_test.go` | `ctrlCh` full → credit dropped via `TryWriteControlFrame` (non-blocking, no deadlock; REV 2 S2). |
| `TestCreditGateParks` | `pkg/node/credit_test.go` | `outstanding >= threshold` → relay parks. `relay_credit_block` increments. |
| `TestCreditGateUnparks` | `pkg/node/credit_test.go` | `outstanding < threshold` → relay reads. `relay_credit_block` does not increment. |
| `TestRebindCreditReset` | `pkg/node/credit_test.go` | Rebind → `outstanding = 0`, `gen = new h.gen`. |
| `TestAnchorCreditLatches` | `pkg/node/credit_test.go` | Anchor credit (`creditGen = h.gen` at arrival) → `latched = true`. |
| `TestMaxBytesPerStreamReduced` | `pkg/mux/carrier_test.go` | Default `MaxBytesPerStream` = 704 KiB. |
| `TestMaxBytesTotalSetTo8MiB` (B4) | `pkg/mux/carrier_test.go` | Default `MaxBytesTotal` = **8 MiB** (not 48 MiB; the dominant floor is outside it, §10.1). |
| `TestSanitizeLimitsFailsLoud` (B4d) | `pkg/mux/carrier_test.go` | `SanitizeLimits` with `MaxBytesTotal < MaxBytesPerStream` **returns an error** (no silent reset). |

### 13.2 Integration tests (loopback)

| Test | File | What it verifies |
|---|---|---|
| `TestLoopbackTransfer1MiB` | `pkg/node/credit_test.go` | 1 MiB object, DE→IR, loopback. 0 drops, 0 `data_undeliverable`, `relay_credit_block > 0`, rate ≥ 50 MB/s. |
| `TestLoopbackTransfer4MiB` | `pkg/node/credit_test.go` | 4 MiB object, DE→IR, loopback. 0 drops, 0 `data_undeliverable`. |
| `TestLoopbackTransfer8MiB` | `pkg/node/credit_test.go` | 8 MiB object, DE→IR, loopback. 0 drops, 0 `data_undeliverable`. (The UP-carrier reset at 4–8 MiB is a **separate** defect, §14. This test verifies the DOWN path.) |
| `TestRebindMidTransfer` | `pkg/node/credit_test.go` | Kill the down-carrier mid-transfer. Rebind. Assert the transfer resumes (0 drops, 0 `data_undeliverable`). |
| `TestHalfCloseDrain` | `pkg/node/credit_test.go` | DE sends `FrameClose` after the last byte. IR drains the remaining mailbox. 0 drops. |

### 13.3 Race tests (REV 1 — N6: name the host)

**Mandatory:** ≥1 clean `-race` run **under Linux semantics**. The
workspace is **Windows** (`cmd.exe`), so the mandatory run is NOT done on
the developer's Windows box. It is run on the **staging host that hosts the
Iran splitter** (the `iran-splitter` staging box, the same Linux host the
§13.4 live A/B uses for the IR leg — a real Linux machine, not WSL2).

```bash
# On the Iran staging host (Linux), in the source tree:
go test -race ./pkg/mux/
go test -race ./pkg/node/
go test -race ./pkg/session/
go test -race ./e2e-pipe-test/
```

**Why this host (N6):** `-race` on Windows/MSVC is not a reliable race
detector; Go's race detector requires Linux (or macOS) semantics for the
shadow-memory instrumentation. The mandatory run therefore targets the
**Iran staging host** (a Linux box with Go ≥ 1.20 and the module's
dependencies vendored). WSL2 is an acceptable **fallback** if the staging
host is unavailable, but the canonical gate is the Linux staging host.

**Specific race scenarios to exercise:**
- `TestRaceCreditLedgerConcurrent`: 10 goroutines calling `onCredit`
  concurrently on the same `creditLedger`. Assert no data race.
- `TestRaceCtrlChWriteLoop`: `writeLoop` consuming from **`ctrlCh` and
  `writeCh` concurrently** while producers enqueue on **both** (B3). Assert
  no data race on `ctrlWG`/`writeWG`.
- `TestRaceCtrlCloseDrain`: close the carrier while `ctrlCh` requests are in
  flight (B3/N5). Assert no data race, no goroutine leak
  (`TestWriterExitsAfterClose`-class invariant on `ctrlWG`).
- `TestRaceRebindAndCredit`: rebind the carrier while credit frames are in
  flight. Assert no data race, no stale credit accepted.

### 13.4 Operator-level measurement matrix (live)

**MANDATORY scoring rule for any live measurement:**
```
rc==0 AND received_bytes==expected_bytes AND sha256(received)==sha256(expected)
```
**HTTP 200 is NOT success.** curl returns 200 on truncated bodies. The
`received_bytes` and `sha256` checks are the **only** valid success
criteria.

| Test | Object size | Direction | Pass criterion | Rate measured |
|---|---|---|---|---|
| L1 | 1 MiB | DE→IR (down) | `rc==0 AND received==expected AND sha256 match` | `rate = 1 MiB / transfer_time` |
| L2 | 4 MiB | DE→IR (down) | same | same |
| L3 | 8 MiB | DE→IR (down) | same | same |
| L4 | 16 MiB | DE→IR (down) | same | same |
| L5 | 4 MiB | IR→DE (up) | same | same |
| L6 | 8 MiB | IR→DE (up) | same (UP-carrier reset is a separate defect, §14; L6 is expected to fail until §14 is resolved) | same |

**A/B methodology (to catch a D4-like throttle):**

1. **Baseline (no-credit):** Run L1–L5 with the no-credit build. Record
   `rate_baseline = 1 MiB / transfer_time` for L1.
2. **V2 (credit-enabled):** Run L1–L5 with the v2 build. Record
   `rate_v2 = 1 MiB / transfer_time` for L1.
3. **Throttle check:** If `rate_v2 < 0.5 × rate_baseline`, the v2 build
   has a D4-like throttle. **Roll back immediately.**
4. **Scoring:** Each test is scored `PASS` or `FAIL` based on the
   mandatory scoring rule (not just `rc==0`).
5. **Repeat:** Run each test **5 times**. A test passes only if **all 5
   runs** pass the scoring rule. (D4's throttle was intermittent; a single
   run can miss it.)

**Rollback criterion:** If **any** of L1–L5 (5/5 runs) has
`rate < 0.5 × rate_baseline`, or if **any** run has `received_bytes !=
expected_bytes` or `sha256 mismatch`, **roll back to the no-credit
build.**

---

## 14. UP-Carrier Reset Investigation Plan

> **This is a SEPARATE investigation from the flow-control work.** The
> UP-carrier reset (carrier reset between 4 and 8 MiB of clean UP transfer)
> is a distinct defect. This section defines the investigation plan. **The
> upload path data path MUST NOT be modified during this investigation.**

### 14.1 Objective

Identify the **exact byte threshold** at which the UP-carrier (WebSocket,
IR→DE) resets during a clean UP transfer, and attribute the reset to a
specific layer (mux/frame, WebSocket, Xray/REALITY, TCP, liveness/reconnect).

### 14.2 Constraint: no modification to the upload data path

**The upload data path (IR relayShapeA on the client socket → `flushPending`
→ `WriteFrame(FrameData)` on the up-carrier) MUST NOT be modified during
this investigation.** The investigation is **read-only** with respect to
the data path. Instrumentation is added to **observe** the data path, not
to change it.

### 14.3 Byte threshold search (binary search)

1. **Start:** The known-good point is 4 MiB (clean). The known-fail point
   is 8 MiB (carrier reset). The threshold is between 4 and 8 MiB.
2. **Binary search:** Test 6 MiB. If clean, test 7 MiB. If fail, test
   5 MiB. Etc. **Determine the threshold to within ±256 KiB.**
3. **Determinism:** Each threshold test is run **5 times** at the same
   concurrency level. A threshold is "confirmed" only if **all 5 runs**
   fail (or all 5 pass, for the boundary below the threshold).
4. **Record:** For each run, record: `byte_offset_at_reset` (the exact
   byte offset in the transfer where the carrier reset was observed),
   `carrier_loss_count`, `rebind_count`, `dropped_data_frames`,
   `session_close_reason`.

### 14.4 Layer attribution

For each threshold test, attribute the reset to one of these layers:

| Layer | How to identify |
|---|---|
| **mux/frame** | `dropped_data_frames > 0` on the up-carrier. The frame was refused by `TryPush` (mailbox full). **But the up-mailbox is 1 MiB cap; a 4–8 MiB transfer should not overflow it if the client is reading.** Check `overflow_wait_count` and `overflow_terminated_worker`. |
| **WebSocket** | The WebSocket conn (up-carrier) is a TLS conn (REALITY/vless). Check the Xray logs on DE for WebSocket close codes (1006 = abnormal closure, 1011 = internal error). Check the IR Xray logs for the same. |
| **Xray/REALITY** | Check the Xray access logs on both IR and DE for the UP-carrier conn. Look for `connection closed` or `TLS handshake failed` or `REALITY: ...` errors. |
| **TCP** | Check the kernel TCP stats on both IR and DE for the up-carrier port (10802 on IR, 443 on DE). Look for `retransmissions`, `RST`, `zero-window`. |
| **Liveness/reconnect** | Check the `liveness_timeout` counter and the `carrier_reconnect` counter. If the carrier was reset by the liveness mechanism (3 missed pings = 90 s), the reset is a **liveness** reset, not a data-path reset. |

### 14.5 Synthetic local target vs public SOCKS

1. **Synthetic local target:** Replace the public SOCKS client with a
   **local** TCP target (a `net.Pipe` or a local `ListenTCP` + `DialTCP`)
   on the IR side. The up-carrier is still the real WebSocket (IR→DE).
   **If the reset still occurs with a local target, the defect is in the
   up-carrier (WebSocket/Xray/TCP), NOT in the client socket.**
2. **Public SOCKS:** Run the same test through the real public SOCKS
   (188.121.111.122:10900). **If the reset occurs with the public SOCKS
   but NOT with the local target, the defect is in the client socket path
   (Iran's client → IR relayShapeA).**
3. **Both:** If the reset occurs in **both** cases, the defect is in the
   up-carrier itself (WebSocket/Xray/TCP).

### 14.6 Concurrency levels (1/4/8)

Run the threshold search at **3 concurrency levels**: 1, 4, and 8
concurrent UP streams. **If the threshold changes with concurrency, the
defect is in the aggregate budget** (`MaxBytesTotal`, 32 MiB) or the
`writeCh` (256 requests). **If the threshold is the same at all
concurrency levels, the defect is in a per-stream or per-carrier
mechanism** (mailbox, liveness, WebSocket).

### 14.7 Instrumentation (without modifying the data path)

Add **read-only** instrumentation:

1. **Per-byte-offset logging:** Log the byte offset (cumulative bytes
   written) at every `WriteFrame` call on the up-carrier. **Do NOT modify
   the `WriteFrame` call itself** — just log the offset before/after.
   (This is a `log.Printf` call, not a change to the data path.)
2. **Carrier loss timestamp:** Log the exact timestamp and byte offset at
   which the carrier was lost (`onCarrierLost`, [`node.go:585`](../pkg/node/node.go:585)).
3. **Rebind timestamp:** Log the exact timestamp and byte offset at which
   the carrier was re-bound (`onCarrierReady`, [`node.go:625`](../pkg/node/node.go:625)).
4. **Liveness ping/pong count:** Log the number of pings sent and pongs
   received on the up-carrier. **If 3 pings are sent with 0 pongs before
   the reset, the reset is a liveness timeout.**
5. **WebSocket close code:** Log the WebSocket close code (if the up-carrier
   is a WebSocket). **If the close code is 1006 (abnormal), the WebSocket
   conn was dropped by the network (not by the application).**

### 14.8 Deliverable

A **one-page** report:
- The exact byte threshold (±256 KiB).
- The layer attribution (mux/frame, WebSocket, Xray/REALITY, TCP, or
  liveness).
- The concurrency-dependence (threshold changes with concurrency or not).
- The synthetic-vs-public-SOCKS result.
- **No fix is proposed in this report.** The fix is a separate task,
  scoped after the root cause is identified.

---

## Appendix A: Glossary

| Term | Definition |
|---|---|
| `outstanding` | Sender-side counter: bytes issued via `WriteFrame` that are neither acknowledged by a credit nor known-terminated (precise pipeline definition, §6.2). |
| `creditWindow` | The window granted by the receiver (default 512 KiB = `window_max`, §8.4). |
| `unackedAllowance` | Fixed 128 KiB (2 × MaxPayload) allowance for pipelining. |
| `mailboxCap` | `MaxBytesPerStream` = `window_max + unackedAllowance + MaxPayload` = 704 KiB (default). |
| `effective_RTT` | Measured (not assumed) credit-cycle round-trip time. |
| `latched` | Sender state: credit-gated (bounded). **An un-latched stream is NOT unlimited** — it is bounded by `MaxBytesPerStream`; a degraded stream is `SAFELY_CAPPED` (64 KiB). |
| `CreditSafeWindow` | 64 KiB (= `MaxPayload`), the safe small window a stream latches to on `CreditSafeTimeout` (S2). |
| `gen` | Carrier generation number, `uint64` (monotonically increasing per carrier-attach). |
| `anchor credit` | The first credit frame on a new carrier generation (`bytesConsumed = 0`, `creditGen = h.gen` at arrival). |
| `ctrlCh` | The new separate control queue (cap 64) for `FrameCredit`/`Close`/`Ping`/`Pong` (ordering-insensitive only; B3). |
| `writeCh` | The existing FIFO queue (cap 256) for `FrameData`/`FrameHeader`/`FrameRebind` (order-preserving; B3). |

---

## Appendix B: Open Questions for Operator Confirmation

1. **`MaxBytesTotal` set to 8 MiB (REV 1 — B4):** The design (§10) sets
   `MaxBytesTotal` to **8 MiB** (down from the 32 MiB default), because
   `MaxBytesTotal` bounds **only mailboxes**; the dominant ~65.2 MiB
   `writeCh`+`c.frames` floor sits **outside** it (REV 0's 48 MiB was
   retracted as buying nothing for that floor). 8 MiB funds
   `N_max = 8` × 704 KiB mailboxes + headroom. **Confirm `N_max = 8` and
   8 MiB are acceptable for the relay nodes' memory budget.** If a larger
   concurrency is desired, raise both `N_max` and `MaxBytesTotal` together
   (and confirm the 65.2 MiB per-carrier floor on the host).
2. **`CreditEstablishTimeout` = 2 s:** The D4 design used 2 s. **Is 2 s
   sufficient for the cross-border conn to deliver the first credit
   frame?** If the cross-border RTT is 90 ms, 2 s = ~22 RTTs. Should be
   sufficient. **Confirm.**
3. **UP-carrier reset:** This design does **not** address the UP-carrier
   reset (a separate defect, §14). **Confirm that the UP-carrier reset
   investigation is a separate task, scoped after the flow-control v2 is
   deployed and validated.**
4. **Xray/REALITY config:** The flow-control v2 does **not** require any
   Xray/REALITY config changes. **Confirm that the Xray config is stable
   and will not be rotated during the A/B test window.**

---

*End of document.*
