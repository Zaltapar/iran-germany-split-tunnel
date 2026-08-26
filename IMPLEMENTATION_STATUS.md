# Implementation Status — Production Hardening

Branch: `hardening/production-reliability`
Base commit: `c85ed76` (main, "installer: rewrite install.sh ...")

## Current phase: Phase 5 (reconnect/rebind) — COMPLETE

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
10. **Startup race (not shutdown)**: the read loop starts in
    `NewCarrierConn` and grabs its `bufio.Reader` at start; if the peer
    sends bytes before `SetReadBuffer` is called, those bytes could be
    left stranded in the auth reader. Works today because every call site
    installs the buffer immediately after construction; making buffer
    installation explicitly ordered is a small follow-up (noted here to
    keep Phase 2's diff scoped to shutdown).

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

## Next phase

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