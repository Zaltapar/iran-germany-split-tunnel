# Implementation Status — Production Hardening

Branch: `hardening/production-reliability`
Base commit: `c85ed76` (main, "installer: rewrite install.sh ...")

## Current state

- **All hardening phases (1–8) complete** — see the historical phase
  records below.
- **Phase 5 (reconnect/rebind) production wiring is COMPLETE** — commit
  `881d46d` (phase-5-production-wiring): both production binaries
  (`cmd/iran-splitter`, `cmd/germany-splitter`) run the `pkg/node`
  engine (carrier generations, rebind protocol, grace windows); the
  Phase 5 design/commit records below are historical context for the
  wiring, not pending work.
- **Fix A (authenticated bufio.Reader handoff race) fixed** — commit
  `9d4e2f2`: the reader returned by `CarrierAuth` is bound into the
  carrier before its read loop starts, so pre-buffered frames are never
  orphaned.
- **Follow-up maintenance (this commit)**: the WebSocket carrier auth
  handshake is now bounded even on transports that cannot enforce socket
  deadlines (the production `wsConn` adapter exposes only Read/Write/
  Close); deterministic regression tests; Linux GitHub Actions CI
  (`.github/workflows/go.yml`): `gofmt`, `go vet`, `go test`,
  `go test -race`, `go build` (host + linux/amd64 cross-build); the
  unused historical `hashicorp/yamux` dependency removed via
  `go mod tidy`. No changes to `install.sh`, the v1 protocol, session
  lifecycle, reconnect/rebind, or backpressure.
- Full verification for the follow-up is recorded in the
  "Follow-up — bounded WebSocket auth handshake" section at the bottom.

### Known limitations (current, honest list)

- `go test -race` cannot run on the Windows development host
  (race-instrumented binaries abort at startup with `0xc0000139` — a
  toolchain/environment issue that predates all hardening phases). It is
  now covered by the Linux CI workflow on pushes to `main` and on PRs.
- The Iran `/upload` `CheckOrigin` policy is permissive **by documented
  decision** (machine-to-machine endpoint; the security boundary is the
  v1 authentication plus TLS/Reality in the transport) — Phase 6 record.
- `KeepAliveInterval` is a fixed 30 s default with no env variable on
  purpose — Phase 7 notes.
- Configuration validation is lexical/structural; it does not probe the
  network (e.g. CDN DNS) — Phase 7 notes.
- The up-carrier WebSocket auth handshake bound is 15 s (`mux.AuthTimeout`);
  a peer that upgrades but never sends the challenge now costs at most
  that long per attempt before the connection is closed (before this
  follow-up, the Germany-side dial path could block indefinitely on a
  silent peer because `wsConn` has no `SetDeadline`).

## Historical phase records

The sections below are the phase-by-phase records, kept as written at
the time — including their own "next phase" forward pointers, which are
superseded as the work progressed (each is marked where it has been
superseded).

## Baseline (measured before any change)

Environment: go1.27.0 windows/amd64 (Go cross-build for linux/amd64 verified).

| Check | Result |
|---|---|
| `go test ./...` | PASS (no test files existed in any package) |
| `go vet ./...` | PASS |
| `go build ./cmd/...` | PASS |
| `GOOS=linux GOARCH=amd64 go build ./cmd/...` | PASS |
| `go run ./e2e-pipe-test` | PASS (auth on both carriers, full upload/download round-trip) |
| `go test -race ./...` | **CANNOT RUN on this machine** — race-instrumented binaries crash at startup with `0xc0000139` even for a trivial `1+1==2` test (verified with an unrelated throwaway module, inside and outside OneDrive). Toolchain/environment issue, not code. No WSL or Docker available as a fallback. |

## Phase 1 — baseline + tests (previous commit `81813e7`)

- Added the missing baseline test coverage (required before any refactor):
  - `pkg/mux/frame_test.go` — frame encode/decode: round-trip for all 6 types,
    max-size payload (65535), oversized rejection, truncated header/payload,
    sequence order, closed-stream behavior, exact on-wire header layout.
  - `pkg/mux/secret_test.go` — DeriveSecret determinism, ValidateSecret paths.
  - `pkg/mux/auth_test.go` — full CarrierAuth handshake: success, wrong secret,
    truncated (non-32-byte) auth payload, unexpected frame during auth,
    malformed pong, context timeout against a silent peer.
  - `pkg/mux/carrier_test.go` — Register/Deregister/StreamCount, dispatch
    delivery (data, FrameClose as nil, OnNewStream, unknown-stream drop),
    Close idempotency, Close unblocks stream consumers, write-after-close
    fails, 64 concurrent writes serialized intact, keepalive pings,
    Ready()/ReadErr() after peer close, Close while dispatcher blocked on a
    full stream channel.
  - `pkg/session/session_test.go` — destination buffer encode/decode round
    trips (IPv4/domain/IPv6), long-domain truncation behavior, invalid
    input rejection, stream reader/writer round trips, truncated reads,
    SessionID format, GenerateSessionID uniqueness, SessionStore add/get/
    remove/double-remove, stream indexing, stream-ID collision behavior,
    Wait, CloseAll, context cancellation on Remove.
  - `cmd/iran-splitter/socks_test.go` — SOCKS5 greeting + CONNECT parsing:
    domain/IPv4/IPv6, bad version, no/zero methods, non-CONNECT command,
    truncated greeting, truncated destination.
- `internal/testutil/mempipe.go` (+ test) — in-memory bidirectional byte
  stream pair with per-direction read/write deadlines, used by all tests.
- Minimal behavior-preserving testability change:
  - `cmd/iran-splitter/main.go` — extracted the SOCKS5 greeting/request
    parsing out of `handleSOCKS5Conn` into `socksNegotiate` (new file
    `cmd/iran-splitter/socks.go`). Same bytes, same replies, same log level
    (now one uniform "SOCKS5 negotiation" log line on any rejection).
  - `pkg/mux/frame.go` — `ErrPayloadTooLarge` sentinel (same message, now
    matchable); used by both `WriteFrame` and `CarrierConn.WriteFrame`.
- **Two real bugs found by the new tests and fixed in that commit**
  (both crashes/misbehavior, minimal fixes):
  1. `pkg/session/session.go`: `MaxHeaderSize` was `1+255+2 = 258`, missing
     the 1-byte domain length field. A 255-char destination domain made
     `WriteDestinationBuffer` **panic with index out of range** (max domain
     header is 259 bytes). Fixed to `1+1+255+2 = 259`.
  2. `pkg/mux/carrier.go`: `keepalive()` built the ping with
     `make([]byte, HeaderSize)` (all zeros) = **FrameData on stream 0**, not
     FramePing (0x02). The peer dispatcher drops stream-0 data frames, so no
     pong was ever generated and liveness detection was dead. Now sets
     `ping[4] = FramePing` as the comment always claimed.

## Phase 2 — carrier lifecycle (previous commit `67e291d`)

Made `CarrierConn` shutdown deterministic, race-safe, idempotent and
leak-free. No backpressure or reconnect work mixed in.

- **Cancellation model**: the existing `closed` channel is now the single
  cancellation signal (the context equivalent) — every loop and blocking
  write selects on it; no new public API was forced onto callers.
- **Issue D fixed — writer leak**: `writeLoop` no longer does
  `for req := range c.writeCh` (writeCh is intentionally never closed); it
  selects on `closed` and exits.
- **Pending writes, defined behavior** (`write()` + `writeWG` +
  `drainWrites`):
  - `write()` reserves a slot under the same lock `Close` uses to set
    `closing` (WaitGroup Add/Wait ordering is therefore race-free) and
    rejects immediately with the new `ErrCarrierClosed` sentinel once
    close has started;
  - `Close` waits for in-flight `write()` calls to finish enqueuing, then
    fails every still-queued request with `ErrCarrierClosed`;
  - a request the writer already took is attempted, and if close has
    started by the time it finishes the reported error is normalized to
    `ErrCarrierClosed` (deterministic result regardless of the underlying
    connection error).
  - Net effect: after `Close` returns, no `WriteFrame` caller is blocked.
- **`Close` shutdown sequence** (idempotent via `sync.Once`, safe from
  multiple goroutines): `closing=true` → `close(closed)` → `rwc.Close()`
  (interrupts a read/write stuck in the network layer) → wait for
  in-flight write callers → `drainWrites` → close all stream channels.
  Consequence: readLoop exits (read error or closed channel), writer and
  keepalive exit, a running `Dispatch` returns once the read loop closes
  the frames channel. The old "call Close AFTER the dispatcher returned"
  requirement no longer exists.
- **Keepalive**: exits on close as before, now verified; ticker always
  stopped (no ticker leak).
- **Observability**: new `ShutdownDone() <-chan struct{}` — closed when
  every carrier-owned goroutine (readLoop, writeLoop, keepalive) has
  exited; used by the lifecycle tests to assert leak-free shutdown.
- **Tests** (`pkg/mux/carrier_shutdown_test.go`, 8 new):
  full write queue resolved on Close (no request left waiting), writer
  exits after Close, Close with keepalive actively pinging, 8 concurrent
  Close calls, 8×1024 concurrent writes racing a Close (all resolve with
  nil or ErrCarrierClosed), 100 post-Close writes fail fast with
  ErrCarrierClosed, Close unblocks an idle blocked read loop, and a
  runtime.NumGoroutine settle check over 5 full lifecycles (keepalive +
  stream + Dispatch) proving no goroutine leak.
- All Phase 1 baseline tests still pass unchanged; `e2e-pipe-test` still
  passes; no call-site changes needed (main.go/e2e unchanged).

## Phase 3 — stream backpressure (previous commit `0be3952`)

Fixed Issue B: one stalled stream can no longer stall the whole carrier
dispatcher. The dispatcher only does non-blocking mailbox pushes now, and
the overflow policy terminates the offending STREAM, never the carrier.

- **Bounded per-stream mailbox** (`pkg/mux/queue.go`, new): `StreamQueue`
  with dual limits — at most `MaxFramesPerStream` items AND at most
  `MaxBytesPerStream` payload bytes. Dispatcher side: non-blocking
  `TryPush` (never blocks). Consumer side: single-consumer `Pop` (one
  worker per stream). `Close()` returns the discarded payload bytes so
  the carrier can return them to its aggregate budget.
- **`StreamLimits` / `SanitizeLimits` / `SetStreamLimits`**
  (`pkg/mux/carrier.go`):
  - defaults (`DefaultStreamLimits`): 16 frames / 1 MiB per stream,
    32 MiB aggregate per carrier, 100 ms overflow wait;
  - sanitize: zero/negative → default, frame bound clamped to 16,
    aggregate below per-stream → default aggregate;
  - applied at all four carrier-creation sites in both mains (up + down
    carrier) before `Dispatch`/`Register`.
- **Aggregate budget**: the carrier tracks `queuedBytes` (payload bytes
  across all mailboxes); a push that would exceed `MaxBytesTotal` is
  refused and the pressure policy applies to THAT stream, so many slow
  streams cannot multiply per-stream memory into unbounded RAM.
- **Overflow policy** (`deliver` / `applyPressure` / `terminateStream`):
  - dispatcher never blocks: full mailbox → frame dropped, pressure
    timestamp recorded, every other stream keeps being served;
  - pressure re-evaluates on each later push for the stream; once it has
    persisted for `OverflowWait`, that stream alone is terminated;
  - the consumer receives `nil` (same signal as `FrameClose`) when the
    channel can accept it; the mailbox is closed and its discarded bytes
    are returned to the aggregate budget;
  - a best-effort `FrameClose` goes back to the peer for terminations
    caused by local overflow, so the remote side tears its end down;
  - a terminated stream STAYS registered (`terminated` flag) so later
    frames for its ID are dropped instead of starting a new stream —
    which would re-fire `OnNewStream` and re-dial a dead destination;
  - the per-stream workers count toward Phase 2's `live` set and exit
    via the existing shutdown machinery (`ShutdownDone` unchanged).
- **Config** (both mains): `SPLIT_STREAM_QUEUE_BYTES`,
  `SPLIT_STREAM_QUEUE_FRAMES`, `SPLIT_STREAM_QUEUE_TOTAL_BYTES`,
  `SPLIT_STREAM_OVERFLOW_MS` (milliseconds). Parsed with the existing
  `parseInt`; non-numeric values become 0 and `SanitizeLimits` falls
  back to defaults (documented; the `parseInt` error-swallowing itself
  stays known-failure #4 for Phase 7).
- **Tests**:
  - `pkg/mux/queue_test.go` (new, 6): frame bound, byte bound,
    FIFO + parked-Pop wake, Close byte accounting (discarded bytes
    returned exactly once), Close waking a parked Pop, SanitizeLimits
    contract (defaults, clamp, aggregate-vs-per-stream, pass-through).
  - `pkg/mux/backpressure_test.go` (new, 7): slow stream does not stall
    the dispatcher (stream 2 served while stream 1 is under pressure,
    carrier stays Ready, stream 1 terminated), aggregate budget
    enforcement across streams (fits-mailbox frame refused at the budget,
    boundary-inclusive acceptance), FrameClose under pressure (channel
    goes quiet, no discarded-frame resurfacing, other stream + carrier
    unaffected), terminated stream stays registered (late frames
    dropped, `OnNewStream` does NOT re-fire), per-stream ordering
    preserved under interleaving, Close with data queued (channels
    closed, budget fully reclaimed, `ShutdownDone` closes), terminated
    stream's worker exits (no goroutine leak).
- All Phase 1/2 tests pass unchanged; `e2e-pipe-test` passes; no
  wire-protocol changes (same frame layout, same semantics).

## Phase 4 — session lifecycle (this commit)

Goal: a single, explicit, idempotent session lifecycle — no ambiguous
ownership between client conn, target conn, the two carrier streams, the
session store, contexts, carrier registrations, relay goroutines and
metrics. Scope: make the existing lifecycle correct and deterministic.
NO reconnect/rebind (Phase 5), NO wire-protocol changes.

### State machine

```
Pending → Active → Closing → Closed
            ├── DirUp half-closed   (client EOF / FrameClose)
            └── DirDown half-closed (target EOF / FrameClose)
```

- `NewSession(...)` → Pending. The session EXCLUSIVELY owns its
  `ClientConn`/`TargetConn` (whichever are non-nil) and its context
  (the cancel func is now private); `Close` is the only closer.
- `Activate()` only from Pending; a session that reached Closed can
  never become active again.
- `MarkDirClosed(dir, reason)` half-closes ONE direction; the other
  keeps flowing. When both directions are closed the session transitions
  itself into Closing.
- `Close(reason)` is the single authoritative teardown, callable from
  any goroutine any number of times: ctx cancel → conn closes →
  `OnClose` hooks, exactly once (first reason wins). `Done()` signals
  completion; `Reason()` records why.
- Invalid transitions (activate/half-close after close, half-close from
  Pending, re-marking a direction) are documented no-ops.

### Termination semantics (kept distinct)

- client EOF → best-effort `FrameClose` up + up half-close; the download
  KEEPS FLOWING. (Pre-Phase 4: a client EOF hard-closed the whole session
  on the Iran side and discarded the target's in-flight response — fixed.)
- target EOF → `FrameClose` down (Germany) / `CloseWrite` on the client
  (Iran) + down half-close; already-buffered data is not discarded.
- upload/download carrier failure, carrier replacement, local socket
  read/write failure, peer `FrameClose` on the up stream (dial failure /
  no down-carrier) and explicit cancellation/timeout are hard
  `Close(reason)` calls with distinct reasons; every relay selects on
  `Ctx.Done()` so a close always unblocks the other relays.

### Ownership

- The binaries install carrier deregistration + store unindex +
  `decSession` once via `OnClose` → each runs exactly once (no double
  metric decrements, no double stream removal, no double socket close,
  no use-after-close, no leaked goroutines).
- `SessionStore.Remove` is a pure unindex now (it used to close the
  client conn and cancel the ctx — that moved to `Session.Close`);
  `Add`/`AddStream` refuse already-closing sessions (checked under the
  store lock, atomic with `Remove`) so late registrations cannot leak
  indices; `CloseAll` closes via `Session.Close` outside the lock
  (resolves known failure #8).

### Tests (pkg/session/lifecycle_test.go, new — 18 tests)

normal lifecycle; client-first / target-first / upload / download
half-closes; both directions simultaneously; carrier close while active;
timeout while a relay is blocked; double Close; 12 concurrent Close;
no goroutine leak; Closed-never-reactivates; half-close-from-Pending
no-op; late `OnClose` runs immediately; combined 6-direction termination
(cleanup exactly once); client-FIN keeps the download flowing with
buffered data intact; store cleanup while registering; store cleanup
while deregistering; metrics net-zero after 60 racing close attempts.
`session_test.go` store tests updated to the new ownership.

Both mains (`handleSOCKS5Conn`, `bootstrapUpStream`) rewritten on this
lifecycle; `e2e-pipe-test` is unchanged and passing (protocol untouched).

## Known failures / pre-existing defects (NOT fixed here — planned phases)

Documented so later phases can verify each one is addressed:

1. **Issue A — sessions bound to a CarrierConn**: a carrier disconnect
   kills its streams; no rebind/resume. → Phase 5 (reconnect/rebind).
2. **Issue B — dispatcher head-of-line blocking**: FIXED in Phase 3
   (bounded per-stream mailbox + timed pressure + per-stream termination;
   see Phase 3 notes).
3. **Issue E — no handshake freshness**: symmetric secret echo allows
   replay/reflection; no role/nonces. → Phase 6 (security).
4. **Issue F — `parseInt` swallows errors** (both mains): `fmt.Sscanf(s,
   "%d", &n)` with ignored error → `SPLIT_METRICS_PORT=abc` becomes 0,
   `SPLIT_RELAY_BUF=xyz` becomes 0. → Phase 7 (config validation).
5. **WebSocket origin policy** (`cmd/iran-splitter/main.go`):
   `CheckOrigin: func(...) bool { return true }` — accepts every origin.
   → Phase 6 (security).
6. **Metrics**: mutex-protected counters only (active/total sessions,
   bytes up/down, errors). → Phase 8 (observability).
7. `SessionStore.Wait` polls at 10 ms with `time.Sleep` (fine at current
   scale; noted for later).
8. FIXED in Phase 4: `SessionStore.CloseAll` snapshots under the read
   lock and closes each session via `Session.Close` with no store lock
   held.
9. `WriteDestinationBuffer` silently truncates >255-char domains while
   `WriteDestination` rejects them — inconsistent; pinned by a test.
   (Behavior preserved; revisit in Phase 7.)
10. **Startup race (not shutdown) — RESOLVED**: the read loop started in
    `NewCarrierConn` grabbed its `bufio.Reader` on its first read, racing
    `SetReadBuffer`; if the peer sent bytes in that window (e.g. a
    `FrameRebind` written immediately after the auth handshake), they
    were stranded in the auth reader and the rebind silently vanished,
    closing the session on the grace timer. Fix: `NewCarrierConnWithReader`
    binds the pre-auth reader inside the constructor, before the read
    loop starts; `Node.install` uses it whenever an auth reader is
    handed over. Regression tests: `TestWithReaderBindsReaderBeforeFirstRead`
    / `TestLateSetReadBufferOrphansPrebufferedFrame` (pkg/mux) and
    `TestInstallUpConsumesPrebufferedRebind` (pkg/node).
    **Known boundary (not a bug):** bytes already in flight on a
    direction at the instant that carrier fails are dropped (the dead
    carrier's epoch; no retransmission). Phase 5 guarantees ordered
    lossless delivery only for bytes READ into the bounded reconnect
    buffer DURING the outage (the upload case).

## Tests passed

- `gofmt -l .` — clean
- `go vet ./...` — PASS
- `go build ./...` — PASS (windows/amd64)
- `GOOS=linux GOARCH=amd64 go build ./...` — PASS
- `go test ./... -count=3` — PASS (all packages; 3× to shake out
  timing-sensitive termination races)
- `go run ./e2e-pipe-test` — PASS

`go test -race ./...` — still cannot execute on this Windows host (same
`0xc0000139` toolchain crash as Phases 1–3). The lifecycle is lock-ordered
by construction: all state under `s.mu`, teardown under `sync.Once`;
`-race` should be run in any Linux CI as a final confirmation.

## Next phase (SUPERSEDED — Phase 5 is complete)

The historical Phase 4 record pointed forward to Phase 5, which has
since been completed (design in the Phase 5 section below; production
wiring in commit `881d46d`). Kept for the record:

Phase 5 — reconnect/rebind (Issue A: sessions bound to a CarrierConn):
make sessions survive carrier replacement by rebinding them to a new
`CarrierConn` (reconnect grace, stream re-registration, in-flight stream
policy). Build on the Phase 4 lifecycle: rebind = re-register the streams
of an Active session on the new carrier; the `OnClose` hooks already make
deregistration idempotent, and carrier replacement is today a plain
`Close("carrier replaced")`.

## Files modified (this commit)

- `pkg/session/session.go` (State/Direction state machine, NewSession,
  Activate, MarkDirClosed, Close/teardown, OnClose, Done/Reason/DirClosed;
  store: Add/AddStream closing-guard, pure Remove, CloseAll via
  Session.Close)
- `pkg/session/lifecycle_test.go` (new — 18 lifecycle/termination tests)
- `pkg/session/session_test.go` (store tests updated to the new ownership)
- `cmd/iran-splitter/main.go`, `cmd/germany-splitter/main.go`
  (handleSOCKS5Conn / bootstrapUpStream rewritten on the lifecycle)
- `IMPLEMENTATION_STATUS.md` (phase 4 update)
- `README.md` (session lifecycle section updated)

## Commit

Subject `phase-4-session-lifecycle` on branch
`hardening/production-reliability` (see `git log --oneline -1`).

## Rollback

```
git revert <phase-4-session-lifecycle-commit>
```

Phase 4 touches `pkg/session` plus both mains (lifecycle wiring only);
no wire-protocol changes, so the revert is self-contained.

or to abandon the whole effort:

```
git checkout main && git branch -D hardening/production-reliability
```

## Phase 5 — reconnect/rebind (Issue A) — COMPLETE

Carrier loss no longer kills sessions. Sessions bind to carriers through
`pkg/session.Attachment` (per-direction state + generation):

- `pkg/session/attachment.go` — attachment state machine
  (Unavailable → Attach(gen) → Detach(gen) → Rebinding → Attached),
  exactly-once grace timer, ready signaling, epoch join, and the
  versioned `EncodeRebind`/`ParseRebind` payload.
- `pkg/mux` — new `FrameRebind` frame type (0x06); dispatch is
  frame-type-aware and `OnNewStream` now receives the triggering frame
  type: `func(streamID uint32, firstType uint8, ch chan []byte)`.
  `FrameRebind` opens a stream exactly like `FrameHeader` (its payload
  is the first channel item).
- `pkg/node` (new) — the production node for both roles, with a
  two-node in-memory harness (`internal/testutil.MemPipe`):
  - strict carrier-generation guard: a consumer delivers frames only
    while its attachment is `Attached` AND bound to the consumer's
    exact generation; frames from old/dead/superseded/mid-rebind
    carriers are dropped and never interpreted as a legitimate close;
  - attach ordering: `Attach(newGen)` always runs BEFORE the new
    consumer can observe frames (rebind sweep and peer rebind
    handler alike), so a fresh consumer never drops legitimate data;
  - rebind protocol: the stream-originating node sends `FrameRebind`
    as the FIRST frame of each stream on the replacement carrier; the
    peer resolves the session by the shared `StreamID`
    (`store.GetByStream`) and refuses unknown/stale/post-close
    rebinds without a spurious `FrameClose`;
  - reconnect grace: a session not re-attached within the grace
    window is closed with an explicit reason and is never revived by
    a late carrier;
  - carrier-replacement race: a replacement install waits (bounded)
    for the old carrier's loss sweep to settle before running the
    rebind sweep; reconnect metrics are counted loss-driven (an
    install-snapshot `wasLost` alone misses the
    install-before-sweep interleaving) and the stale lost flag is
    settled after the sweep completes.
- `cmd/germany-splitter` + `e2e-pipe-test` — updated to the
  frame-type-aware `OnNewStream`. `e2e-pipe-test` asserts the opener
  is `FrameHeader`; `cmd/germany-splitter` (pre-Phase-5 standalone
  binary) keeps its bootstrap-only semantics and cleanly refuses
  non-header openers (drain, log, deregister, no `FrameClose`)
  instead of misreading a `FrameRebind` as a destination. Neither
  command was deleted; both compile and work.
- `pkg/node/node_test.go` — 18 scenario tests: single/10-session
  survival, grace timeout + no late revival, fast reconnect, flapping,
  late-frame protection, replacement while the old carrier is shutting
  down, up-only / down-only / both-carrier failure, half-close across
  loss, shutdown during loss, rebind scoping, unknown / stale /
  post-close rebind refusal, bounded-buffer backpressure, and a
  120-session stress test cycling up- and down-carriers.

Test calibration (test-only, NOT production behavior): `readN`
deadline 10 s and stress grace 20 s — under 120 concurrent sessions a
down-direction rebind can exceed 3 s on a loaded host; the assertions
test correctness (no loss, no lost sessions, metric balance, no
goroutine growth), not rebind latency.

## Phase 5 verification (final state)

- Phase 5: complete
- Full repository build: PASS (`go build ./...` and
  `GOOS=linux GOARCH=amd64 go build ./...` from the repo root)
- `go vet ./...` — PASS
- `gofmt -l .` — clean
- `go test ./...` — PASS; `go test ./... -count=3` — PASS
- e2e-pipe-test: PASS (`go run ./e2e-pipe-test`)
- Node stress: PASS (`TestHundredSessionStress` -count=10; full
  `pkg/node` suite -count=5)
- Known environment limitation: `go test -race` still cannot execute
  on this Windows host (race-instrumented binaries abort at startup
  with `0xc0000139`, same toolchain failure as Phases 1–4). Run
  `-race` in any Linux CI as the final confirmation.

## Build-fix follow-up (this commit)

`e2e-pipe-test/main.go` and `cmd/germany-splitter/main.go` were the
only stale `OnNewStream` call sites left from the pre-Phase-5 API;
both were updated to the frame-type-aware signature (see above). No
production semantics in `pkg/node` / `pkg/mux` were altered by this
commit.

## Commits (this phase)

- `phase-5-reconnect-rebind` — Phase 5 design, `pkg/node`, tests
- `phase-5-build-fix` — stale call-site compatibility + this status
  update

## Rollback (this phase)

```
git revert <phase-5-build-fix-commit>
git revert <phase-5-reconnect-rebind-commit>
```
## Phase 6 — security hardening

### Authentication protocol v1 (replaces v0)

The v0 handshake sent the 32-byte derived secret itself on the wire
(`FrameAuth` payload), making any captured handshake replayable forever.
v1 (`pkg/mux/auth.go`, new file) is a three-message **mutual**
HMAC-SHA256 challenge/response on `FrameAuth`/StreamID 0:

1. **Challenge** (responder → initiator), 22 B:
   `version(1) | role | ts_s uint32 BE | nonce_s 16B (crypto/rand)`
2. **Response** (initiator → responder), 74 B:
   `version | role | ts_c | echo(ts_s) | echo(nonce_s) | nonce_c 16B |
   mac_c = HMAC-SHA256(secret, challenge ‖ ts_c ‖ nonce_c)`
3. **Confirmation** (responder → initiator), 50 B:
   `version | role | nonce_s2 16B |
   mac_s = HMAC-SHA256(secret, challenge ‖ response ‖ nonce_s2)`

- **Raw secret never on the wire** — only HMAC tags over fresh data
  (stdlib `crypto/hmac`, `crypto/sha256`, `crypto/rand`,
  `crypto/subtle`; constant-time MAC and echo comparisons).
- **Replay resistance without any nonce store**: every handshake starts
  with a fresh 128-bit server nonce covered by both MACs; the response
  must echo the current challenge (ts_s + nonce_s), so a captured
  response/confirmation from an earlier handshake fails the echo check
  against any new challenge. Nothing to remember → nothing unbounded.
- **Role binding**: `RoleUpload` ('U') / `RoleDownload` ('D') are inside
  both MAC transcripts — a valid secret cannot authenticate the wrong
  carrier direction; a replayed upload handshake cannot become a
  download handshake.
- **Versioning**: `AuthVersion = 1`; unknown versions rejected before MAC
  verification. **Compatibility: v0 ⇄ v1 is NOT interoperable — both
  nodes must be upgraded together** (documented in README).
- **Freshness**: both ends check the peer timestamp within ±60 s
  (`AuthMaxClockSkew`); defense in depth on top of the nonces.
- **Hard timeout**: `AuthTimeout` (15 s, variable for tests) bounds the
  whole handshake and is applied as a socket deadline (`SetDeadline`
  where supported), even with a deadline-less context — a silent/stalling
  attacker cannot hold a connection.
- **Failure handling**: every failure is a connection-level close with NO
  protocol error transmitted (no "correct role but wrong HMAC" leakage);
  the returned error is for local logging only.
- **Auth state machine**: `Unauthenticated → challenge/response →
  Authenticated`. During the handshake only `FrameAuth`/stream 0 in the
  expected phase is accepted; ANY other frame (data/header/rebind/close/
  ping, or a non-zero stream) terminates the connection — no usable
  stream can exist before auth completes.

The old v0 `CarrierAuth` (and its raw-secret wire format) was removed
from `pkg/mux/carrier.go`. `DeriveSecret` remains the shared-secret
derivation (SHA-256 of the operator string); `ValidateSecret`
(constant-time compare) is retained.

### Secret policy (startup)

`pkg/mux/secret.go` + both mains: `ValidateSecretMaterial` fails the
process at startup on empty secrets, the always-enforced blocklist of
known insecure values (password/test/secret/… and the `change-me*`,
`your-secret*` placeholder prefixes — the shipped default
`CHANGE-ME-SECRET-…` no longer boots), and values < 32 chars unless
`SPLIT_ALLOW_WEAK_SECRET=1` (dev/test bypass; blocklist still enforced).
Secrets are never logged.

### Frame-context enforcement (carrier)

`pkg/mux/carrier.go` `readLoop` + `Register`/`createStreamLocked`:

- `FrameAuth` after the handshake → **carrier terminated**
  (`ErrProtocolViolation`, new sentinel in `frame.go`).
- Application frames (`Data`/`Header`/`Rebind`/`Close`) on reserved
  StreamID 0 → **carrier terminated** (previously such frames could
  create a phantom stream 0 via `OnNewStream`).
- `Register(0)` / `createStreamLocked(0)` refuse: StreamID 0 can never
  be a stream.
- `FramePing`/`FramePong` on stream 0 remain valid (keepalive).
- Unknown frame types are dropped (unchanged); oversized/truncated
  frames were already rejected by `WriteFrame`/`ReadFrame` (Phase 1
  tests). Malformed wire data can never panic the process.
### WebSocket / HTTP hardening (Iran `/upload`)

`cmd/iran-splitter/main.go`:

- `http.Server` with `ReadHeaderTimeout=10s` (bounds the
  UNAUTHENTICATED request phase) and `IdleTimeout=60s`; Read/Write
  timeouts stay 0 on purpose (long-lived post-upgrade carrier).
- `/upload` only (other paths → 404), non-GET → 405, non-WebSocket
  requests → 400 (gorilla handshake rejection), upgrade concurrency
  capped at 16 (HTTP 503 when saturated), single-carrier rule → 409
  (unchanged).
- **Auth-failure backoff**: per-process counter — after 10 failures
  within 60 s the endpoint returns HTTP 429 until the window lapses; a
  successful authentication resets it.
- `CheckOrigin` remains permissive **by documented decision**
  (machine-to-machine endpoint; the security boundary is v1 auth +
  TLS/Reality in the transport).

### Rebind security (verification, no change)

Phase 5's `handleRebind` conditions were re-audited and already satisfy
the Phase 6 requirements: v1-authenticated carrier, direction-bound
closure, payload version check, session must exist AND be Active,
direction not half-closed, attachment in rebindable state, sender
generation STRICTLY greater than the last accepted (stale/replay/dup
rebind refused), attach-before-consumer ordering, strict
`AttAttached`-AND-current-generation consumer guard (late/stale
carrier frames can never reach the socket or be read as a half-close).
Covered by Phase 5 tests (TestRebindUnknownSession,
TestStaleRebindRefused, TestRebindAfterSessionClosed,
TestRebindScopedToStreamOwner, TestLateFramesNeverCorruptReboundSession).
A rebind on the wrong-direction carrier is refused structurally
(per-direction `handleRebind` + attachment-state check).

### Metrics / listeners

Metrics already bound `127.0.0.1` on both binaries (verified, no
change); they expose only counters/byte totals — no secrets, tokens or
destination details. No logging of secrets/auth payloads anywhere
(audited: auth-failure logs carry only the local generic error).

### Tests added (Phase 6)

- `pkg/mux/auth_test.go` — REWRITTEN for v1 (13 tests / 16 subtests):
  success (both roles), wrong secret (ErrAuthMAC), wrong role (both
  ends), wrong version (both ends), corrupted response MAC, corrupted
  confirm MAC, truncated challenge, truncated response, freshness
  (stale/future challenge, stale response), replay of a captured
  response against a fresh challenge (echo mismatch), data/rebind
  before auth (stream 0 and stream 5), hard-timeout against a silent
  peer, invalid role.
- `pkg/mux/security_test.go` (new): carrier terminated on stream-0 data
  and on post-auth FrameAuth (ReadErr = ErrProtocolViolation, all
  goroutines shut down), ping-on-0 + data-on-1 still accepted,
  `Register(0)` = nil.
- `pkg/mux/secret_test.go`: `ValidateSecretMaterial` policy matrix
  (9 cases).
- `cmd/iran-splitter/ws_test.go` (new): 404 unknown path, 405 non-GET,
  400 non-WebSocket, 429 during auth-failure backoff, reset on success,
  backoff-window reset logic.
- `e2e-pipe-test/main.go`: the strict "first frame must be FrameHeader"
  assertion now drops a **late FrameClose** opener (documented carrier
  behavior: after Deregister, any frame for the ID starts a new stream;
  production drops non-header openers). This is a harness fix, not a
  protocol change.

### Verification (Phase 6)

- `gofmt -l .` clean
- `go vet ./...` PASS
- `go build ./...` PASS (windows/amd64)
- `GOOS=linux GOARCH=amd64 go build ./...` PASS
- `go test ./... -count=1` PASS (all packages)
- `go run ./e2e-pipe-test` PASS
- `go test -race ./...` — still NOT runnable on this Windows host
  (toolchain startup crash `0xc0000139`, pre-existing, unrelated to
  code). Run on Linux/CI.

### Known limitations / notes

- v0 ⇄ v1 not interoperable — coordinated upgrade of both nodes (by
  design, documented).
- The freshness check trusts host clocks (NTP); the nonce mechanism
  defeats replay independently of clock quality.
- `SPLIT_ALLOW_WEAK_SECRET` is a documented dev/test bypass only; the
  blocklist is still enforced with it set.
- Origin policy intentionally permissive (documented in code + README).

### Rollback

Revert the Phase 6 commit (see git log on this branch). Phase 5 and
earlier remain independently revertible as before.

## Phase 7 — centralized configuration validation

Goal: both binaries load, parse and validate their ENTIRE configuration
through one shared layer before anything runs, and report every problem
at once instead of failing one-at-a-time.

### What changed

- **`internal/config` (new package)** — the single
  load → parse → validate → construct path:
  - `Config`, `Defaults()`, `Load(role)`, `(c *Config) Validate(role)`.
    `Validate` is exported so directly-constructed configs validate
    without environment access (used by tests and future non-env
    callers).
  - `ConfigError` aggregates ALL problems (formatted as a bulleted
    list); a startup failure prints the whole list at once.
  - Env parsing rules: unset OR empty = "use the default"; integers
    parsed with `strconv` and explicit min/max bounds (the legacy
    `fmt.Sscanf` parseInt that silently zeroed bad values is gone);
    `SPLIT_ALLOW_WEAK_SECRET` parsed with `strconv.ParseBool` (any other
    value is a config error).
  - Address validation: `host:port` (bare `:port` for listeners,
    bracketed IPv6, explicit host for dial targets), ports 1..65535,
    no whitespace in hosts.
  - `SPLIT_UP_WS_URL` validation: `ws(s)://` scheme, non-empty host,
    path must be `/upload`; the placeholder
    `wss://cdn.example.com/upload` is explicitly rejected so a fresh
    install fails fast instead of dialing a dead domain forever.
  - Cross-field checks: the app's own listeners may not share an
    endpoint, and the metrics port may not collide with any of them
    (wildcard-aware); the aggregate stream-queue budget must cover at
    least one stream's share.
  - Numeric bounds: relay buffer 1 KiB..8 MiB; queue bytes/frames/
    overflow-wait bounded (64 MiB / 256 MiB / `mux.MaxFrames` / 30 s);
    `0` keeps the documented "library default" sentinel resolved by
    `mux.SanitizeLimits` at runtime.
  - Secret policy delegated to Phase 6's
    `mux.ValidateSecretMaterial` (not re-implemented); errors never
    contain the secret value.
- **`cmd/iran-splitter/main.go`** — local `Config` struct, all
  `os.Getenv`/`parseInt` parsing and the inline secret check are
  removed; `main` now starts with `config.Load(config.RoleIran)` and
  dies before opening any listener when validation fails.
- **`cmd/germany-splitter/main.go`** — same treatment with
  `config.Load(config.RoleGermany)`.
- **`cmd/iran-splitter/ws_test.go`** — test fixture uses
  `config.Defaults()` (no duplicate config type).
- **`internal/config/config_test.go` (new)** — ~30 tests / 50+
  subtests: both valid roles via env and via direct construction;
  unknown role; invalid host:port forms (8 cases); invalid WS URLs
  (5 cases); placeholder URL rejection; placeholder + blocklisted
  secret rejection; weak-secret bypass (`1`/`true`, off); invalid bool;
  8 integer error cases (non-numeric, below min, above max, negative,
  overflow); port collision detection (4 directions); queue
  cross-field + out-of-range; aggregated multi-error output; helper
  units (`envInt`, `envString`, `conflict`); secret-never-leaks check.
- **README** — new "Configuration validation" section under
  Configuration; fixed the stale `SPLIT_WS_LISTEN` default
  (`0.0.0.0:9001` → `127.0.0.1:9001`, matching the code).

### Verification

- `gofmt -l .` clean
- `go vet ./...` PASS
- `go build ./...` PASS (windows/amd64)
- `GOOS=linux GOARCH=amd64 go build ./...` PASS
- `go test ./... -count=1` PASS (all packages, incl. the new config
  suite)
- `go run ./e2e-pipe-test` PASS
- Manual negative-process runs (all exit 1 immediately, before any
  listener): weak secret; three simultaneous bad values reported in
  one aggregated message; placeholder `SPLIT_UP_WS_URL` with the
  weak-secret bypass honored.
- `go test -race ./...` — still NOT runnable on this Windows host
  (toolchain startup crash `0xc0000139`, pre-existing). Run on
  Linux/CI.

### Known limitations / notes

- `KeepAliveInterval` is a fixed default (`30s`) with no env variable
  on purpose; it is validated only via `Defaults()`.
- Validation is lexical/structural; it does not probe the network
  (e.g. whether the CDN domain actually resolves).
- `SPLIT_WS_LISTEN` default is `127.0.0.1:9001`: production deploys
  front it via nginx/CDN and are expected to set an explicit listen
  address.

## Phase 8 — interactive installer

Goal: a robust interactive install/upgrade/uninstall experience that is
BUILT ON `internal/config` instead of duplicating it, keeps the Phase 6
secret policy intact, and never leaks secrets into output or shell
history.

### Pre-existing defects found during inspection (fixed here)

The installer (commit `c85ed76`, pre-hardening) predated Phase 7 and
diverged from the app's own validation:

1. **`is_secret` accepted 8–127 chars** — Phase 6/7 policy requires
   ≥ 32 (`mux.ValidateSecretMaterial`). The old harness (Test 3) even
   installed an 18-char secret that the binary would refuse to boot.
2. **Germany's default `SPLIT_UP_WS_URL` was the placeholder
   `wss://cdn.example.com/upload`**, which `internal/config` explicitly
   rejects — the default path installed a dead service.
3. **No pre-install validation**: config errors surfaced only as
   `service failed` in the journal, after the unit was written.
4. **Secret printed in plaintext** in the summary AND embedded in the
   printed Germany curl command (`--secret ${SECRET}`) — into terminals,
   logs and shell history.
5. **No upgrade path**: a re-run silently overwrote the unit (no
   backup) and could not pre-fill; the operator re-typed everything and
   had to re-supply the old secret.
6. **Stale checked-in units**: `SPLIT_WS_LISTEN=0.0.0.0:9001`
   (vs code default `127.0.0.1:9001`) and no note that the
   placeholder secret/URL is rejected at startup.

### What changed

- **`cmd/iran-splitter/main.go` + `cmd/germany-splitter/main.go`**
  (the ONLY Go change, minimal & additive): a first-argument
  `--validate-config` flag. When present, the binary runs
  `config.Load(role)` and exits with the aggregated `ConfigError` (or
  success) BEFORE any listener is opened or goroutine started. Normal
  startup behavior is byte-for-byte unchanged. `install.sh` uses this
  as its configuration gate; it is also a documented manual dry-run
  (README). This is the installer-compatibility change the Phase 8
  scope allowed: the app stays the SINGLE validation authority — the
  shell never re-implements the full rules.
- **`install.sh` (v1.1.0)**:
  - **Configuration gate** (`validate_config_gate`): after the build,
    the installer runs
    `<binary> --validate-config` with the EXACT env values it is about
    to write into the unit. A rejection aborts the install before any
    unit file is written (asserted by a test).
  - **Early checks aligned to `internal/config`** (fast UX only, never
    stricter than the app): secret ≥ 32 chars + Phase 6 blocklist
    (exact values + `change-me*`/`your-secret*` prefixes);
    `wss://host[:port]/upload` with `ws://` allowed and the
    placeholder `wss://cdn.example.com/upload` explicitly rejected;
    Germany's up-WS-URL prompt has NO default (a real URL is
    required); `host:port` accepts bare `:port` listeners and bracketed
    IPv6 (`[::1]:9001`); `SPLIT_RELAY_BUF` bounds 1024..8 MiB.
  - **Secret hygiene**: generation bumped to `openssl rand -hex 32`
    (256 bits, 64 hex — was `-hex 24`); the secret is persisted to
    `/root/.split-tunnel-secret` (mode 600) for the cross-node
    hand-off; new `--secret-file PATH` flag (whitespace-stripped) so the
    non-interactive Germany command never carries the secret on a
    command line; summary shows the secret MASKED by default
    (`--show-secret` reveals); the printed Iran→Germany next-steps now
    use `scp /root/.split-tunnel-secret` + `--secret-file` instead of
    embedding the value; generated-secret notice replaces the old
    "Generated random shared secret: <value>" line.
  - **Upgrade path** (`load_existing_config`): an existing
    `<role>-splitter.service` is detected; its `SPLIT_*` values
    (including the secret, read via `sed`, never re-printed) pre-fill
    the prompts/flags; the old unit is backed up to
    `<unit>.bak.<ts>` and the previous binary to
    `<role>-splitter.bak` before replacement; the unit is written
    mode 640.
  - **Uninstall** (per role or both, as before): removes the unit +
    binary + managed nginx conf (marker-guarded), and now PRINTS
    rollback hints (kept `.bak` unit/binary files, secret store, and a
    `ufw delete` reminder — ufw rules are intentionally not removed
    automatically).
  - Version string 1.0.0 → 1.1.0 (unit Description follows).
- **`systemd/*.service`** (checked-in manual-deploy units): Iran
  `SPLIT_WS_LISTEN` corrected `0.0.0.0:9001` → `127.0.0.1:9001`
  (matching the code default); comments now state that the shipped
  `YOUR-SECRET-HERE` / placeholder URL are REJECTED at startup and show
  `openssl rand -hex 32`; commented Phase 3 queue variables documented.
- **`test-install.sh`**: extended (9 → 13 scenarios, 90 assertions):
  generated secret is now 64 hex; short (18-char) and blocklisted
  secrets are rejected with a clear message; placeholder and wrong-path
  up-WS-URLs are rejected; bare `:port` and bracketed IPv6 are
  accepted; a failing configuration gate (fake binary via
  `FAKE_GATE_FAIL=1`) aborts BEFORE the unit is written;
  `--secret-file` populates the unit and the value is masked in the
  summary; `--show-secret` reveals it; an upgrade run keeps all
  existing unit values (incl. secret), pre-fills, and backs up the old
  unit; summary no longer contains the plaintext secret (file-based
  hand-off asserted); unit mode 640 asserted on Linux (skipped on
  git-bash where chmod is emulated). Test 1's answer file now uses
  `printf` — heredocs strip trailing blank lines, which silently
  shifted the interactive answers.
- **`README.md`**: installer section rewritten (secret generation,
  file-based cross-node hand-off, masking, upgrade semantics,
  uninstall/rollback hints); new "Pre-install dry-run" note
  documenting `--validate-config`.
- **Repo hygiene**: removed the stray untracked
  `ntent IMPLEMENTATION_STATUS.md` (an accidental `git log` dump).

### Verification

- `gofmt -l .` clean; `go vet ./...` PASS
- `go build ./...` PASS (windows/amd64); `GOOS=linux GOARCH=amd64`
  cross-builds verified by the installer's build step
- `go test ./...` PASS (all packages)
- `go run ./e2e-pipe-test` PASS
- `--validate-config` negative/positive runs verified by hand
  (valid env → `configuration OK`, exit 0; short secret → aggregated
  `ConfigError`, exit 1, no listener opened)
- `bash test-install.sh` — 90/90 PASS (git-bash on Windows; the 640
  mode assertion auto-skips there and runs on Linux)
- `go test -race ./...` — still NOT runnable on this Windows host
  (same pre-existing toolchain crash `0xc0000139`). Run on Linux/CI.

### Notes

- The shell validators in `install.sh` are a deliberately thin
  pre-check; `internal/config` (via `--validate-config`) is the
  authority. They must never be made stricter than the app.
- `deploy.sh` (legacy manual deploy) was left untouched; it still
  copies the checked-in units, which are now corrected and documented.
- The secret file at `/root/.split-tunnel-secret` is created on
  install and kept on uninstall on purpose (documented in the output);
  it is never committed.

### Rollback

```
git revert <phase-8-interactive-installer-commit>
```

Phase 8 touches `install.sh`, `test-install.sh`, both `systemd/*.service`,
the README/this file, and only ADDS the `--validate-config` early-exit in
both mains (reverting the commit removes it cleanly; no protocol,
lifecycle, or queue code was modified).

## Follow-up — bounded WebSocket auth handshake (this commit)

### The gap (audited and confirmed in source)

`mux.CarrierAuth` bounds the handshake by `AuthTimeout` and applied that
bound to the socket only when the transport implemented
`SetDeadline` (a type assertion on the `io.ReadWriteCloser`). The
production WebSocket adapter (`wsConn` in both mains) exposes only
`Read`/`Write`/`Close` — no `SetDeadline` — and the Germany up-carrier
client path (`runUpCarrier`) passed it to `CarrierAuth` with a 15 s
context, but the context was checked only ONCE at the top of the
handshake, so a blocked `Read` was never interrupted by it. A peer that
completed the WebSocket upgrade but never sent the authentication
challenge could therefore hold the Germany-side dial goroutine
indefinitely (the Iran-side server path was covered only by an external
`time.AfterFunc` watchdog in `handleUpWsConn`).

### The fix (minimal, protocol-unchanged)

- `pkg/mux/auth.go` — on a transport WITHOUT `SetDeadline`, each
  handshake read now runs in a short-lived goroutine and is raced
  against `ctx.Done()` and the handshake bound (`min(ctx deadline,
  now+AuthTimeout)`). On expiry/cancellation the connection is closed —
  which interrupts the blocked read (the adapter's `Close` closes the
  underlying TCP conn) — and the read result is handed back through a
  buffered channel so the reader goroutine can always finish (no shared
  state, no goroutine leak). On transports WITH `SetDeadline` (all TCP
  paths) the code path is byte-for-byte the old one. The v1 protocol,
  role binding, replay protection, and post-auth long-lived behavior are
  unchanged; no deadline survives past the handshake.
- `cmd/germany-splitter/main.go` — `runUpCarrier` split into the loop
  plus `runUpCarrierOnce` (behavior-preserving extraction, made the
  production path directly testable; the 15 s auth context is
  unchanged).
- `cmd/iran-splitter/main.go` — the now-redundant `time.AfterFunc`
  watchdog in `handleUpWsConn` removed; `CarrierAuth` itself bounds the
  handshake for the deadline-less `wsConn` (same 15 s `AuthTimeout`).

### Regression tests (deterministic, no real 30 s waits)

- `pkg/mux/auth_ws_timeout_test.go` (new): deadline-less transport
  (mirrors `wsConn`) against a silent peer — (a) `AuthTimeout` bound
  fires (`context.DeadlineExceeded`, conn closed, no goroutine leak),
  (b) a shorter caller context deadline is respected, (c) context
  CANCELLATION interrupts the blocked handshake with
  `context.Canceled` and closes the connection. All use 100–300 ms
  test-specific bounds.
- `cmd/germany-splitter/up_carrier_ws_test.go` (new): the PRODUCTION
  path — real gorilla server that upgrades then goes silent; the
  Germany `runUpCarrierOnce` (dial → `wsConn` → `CarrierAuth`) returns
  in ~0.3 s (test-specific `AuthTimeout`) with the connection closed;
  plus a live-peer success test proving normal authenticated handshakes
  over `wsConn` are unaffected.

### CI (new)

- `.github/workflows/go.yml` (new, first workflow in the repo): Linux
  (`ubuntu-latest`, Go `1.21` per `go.mod`) — `gofmt -l` clean check,
  `go vet ./...`, `go test ./...`, `go test -race ./...`, `go build
  ./...` (host) and `GOOS=linux GOARCH=amd64 go build ./...`. No
  release/build automation. This also gives a permanent home for the
  `-race` suite that cannot run on the Windows dev host.

### Dependency cleanup

- `hashicorp/yamux` was imported by no Go code (historical dependency);
  removed via `go mod tidy` — `go.mod`/`go.sum` now carry only
  `gorilla/websocket`. Full test suite re-run confirms no behavior
  change.

### Verification

- `gofmt -l .` — clean
- `go vet ./...` — PASS
- `go build ./...` — PASS (windows/amd64)
- `GOOS=linux GOARCH=amd64 go build ./...` — PASS
- `go test ./... -count=5` — PASS (all packages)
- New regression tests re-run repeatedly (5× each) — deterministic
- `go run ./e2e-pipe-test` — PASS
- `go test -race ./...` — see Linux CI (Windows-host toolchain crash
  `0xc0000139` unchanged, pre-existing)

### Rollback

```
git revert <this-commit>
```

The commit is self-contained: `pkg/mux/auth.go`, both mains (refactor
+ watchdog removal), two new test files, the new workflow, `go.mod` /
`go.sum`, and this documentation update. No `install.sh` changes, no
wire-protocol changes, no session-lifecycle or backpressure changes.
