# Implementation Status — Production Hardening

Branch: `hardening/production-reliability`
Base commit: `c85ed76` (main, "installer: rewrite install.sh ...")

## Current phase: Phase 3 (stream backpressure) — COMPLETE

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

## Phase 3 — stream backpressure (this commit)

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
8. `SessionStore.CloseAll` holds only a `RLock` while calling `Close()` on
   conns (works today because Close does not take the store lock; noted).
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

- `go test ./... -count=1` — PASS (all packages)
- `go test ./pkg/mux/ -count=5` (backpressure subset) — PASS (5× to shake
  out timing-sensitive pressure/termination races)
- `go vet ./...` — PASS
- `go build ./...` — PASS (windows/amd64)
- `GOOS=linux GOARCH=amd64 go build ./...` — PASS
- `go run ./e2e-pipe-test` — PASS
- `gofmt -l .` — clean

`go test -race ./...` — still cannot execute on this Windows host (toolchain
crash at startup, verified in Phase 0 with an unrelated module). The new
shutdown logic is channel/lock-ordered by construction (see Phase 2 notes);
`-race` should be run in any Linux CI as a final confirmation.

## Next phase

Phase 4 is not yet scoped on the roadmap (Phases 5–8 are assigned under
"Known failures"); the next defined item is Phase 5 — reconnect/rebind
(Issue A: sessions bound to a CarrierConn). Scope Phase 4 first
(candidate: soak/load testing of the new mailbox + termination paths).

## Files modified (this commit)

- `pkg/mux/queue.go` (new — bounded StreamQueue mailbox)
- `pkg/mux/carrier.go` (streamRec, StreamLimits/SanitizeLimits/
  SetStreamLimits, aggregate queuedBytes, non-blocking Dispatch/deliver,
  applyPressure, terminateStream, streamWorker, Close reclaims discarded
  bytes from the budget)
- `pkg/mux/queue_test.go` (new — 6 mailbox + SanitizeLimits tests)
- `pkg/mux/backpressure_test.go` (new — 7 backpressure tests)
- `cmd/iran-splitter/main.go`, `cmd/germany-splitter/main.go`
  (SPLIT_STREAM_QUEUE_* / SPLIT_STREAM_OVERFLOW_MS parsing +
  SetStreamLimits on all four carrier-creation sites)
- `IMPLEMENTATION_STATUS.md` (phase 3 update)
- `README.md` (new env vars documented)

## Commit

(see `git log --oneline -1` on branch hardening/production-reliability)

## Rollback

```
git revert <phase-3-stream-backpressure-commit>
```

Phase 3 touches `pkg/mux` plus both mains (config wiring only); no
wire-protocol changes, so the revert is self-contained.

or to abandon the whole effort:

```
git checkout main && git branch -D hardening/production-reliability
```