# Implementation Status — Production Hardening

Branch: `hardening/production-reliability`
Base commit: `c85ed76` (main, "installer: rewrite install.sh ...")

## Current phase: Phase 2 (carrier lifecycle) — COMPLETE

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

## Phase 2 — carrier lifecycle (this commit)

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

## Known failures / pre-existing defects (NOT fixed here — planned phases)

Documented so later phases can verify each one is addressed:

1. **Issue A — sessions bound to a CarrierConn**: a carrier disconnect
   kills its streams; no rebind/resume. → Phase 5 (reconnect/rebind).
2. **Issue B — dispatcher head-of-line blocking**: `Dispatch()` does a
   blocking send into per-stream channels (cap 64); one slow stream stalls
   the whole carrier dispatcher. → Phase 3 (backpressure).
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

- `go test ./... -count=3 -timeout 300s` — PASS (all packages, 3× to shake
  out timing-sensitive shutdown races)
- `go vet ./...` — PASS
- `go build ./cmd/...` — PASS (windows/amd64)
- `GOOS=linux GOARCH=amd64 go build ./cmd/...` — PASS
- `go run ./e2e-pipe-test` — PASS
- `gofmt -l .` — clean

`go test -race ./...` — still cannot execute on this Windows host (toolchain
crash at startup, verified in Phase 0 with an unrelated module). The new
shutdown logic is channel/lock-ordered by construction (see Phase 2 notes);
`-race` should be run in any Linux CI as a final confirmation.

## Next phase

Phase 3 — backpressure (`phase-3-backpressure`):
dispatcher head-of-line blocking (Issue B) — per-stream non-blocking/drop
policy or backpressure to the writer, without touching the lifecycle
behavior pinned by Phase 2 tests.

## Files modified (this commit)

- `pkg/mux/carrier.go` (lifecycle: ErrCarrierClosed, writeWG reservation,
  writeLoop exit on closed, Close shutdown sequence, drainWrites,
  goroutine tracking + ShutdownDone)
- `pkg/mux/carrier_shutdown_test.go` (new — 8 lifecycle tests)
- `IMPLEMENTATION_STATUS.md` (phase 2 update)

## Commit

(see `git log --oneline -1` on branch hardening/production-reliability)

## Rollback

```
git revert <phase-2-carrier-lifecycle-commit>
```

Phase 2 touches only `pkg/mux/carrier.go` plus one new test file, so the
revert is self-contained (no call-site changes were required).

or to abandon the whole effort:

```
git checkout main && git branch -D hardening/production-reliability
```