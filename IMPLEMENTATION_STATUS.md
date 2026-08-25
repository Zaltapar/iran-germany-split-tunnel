# Implementation Status — Production Hardening

Branch: `hardening/production-reliability`
Base commit: `c85ed76` (main, "installer: rewrite install.sh ...")

## Current phase: 0 / Phase 1 (baseline + tests) — COMPLETE

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

## Completed (this commit)

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
- **Two real bugs found by the new tests and fixed in this commit**
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

## Known failures / pre-existing defects (NOT fixed here — planned phases)

Documented so later phases can verify each one is addressed:

1. **Issue D — writer goroutine leak on Close** (`pkg/mux/carrier.go`):
   `writeCh` is never closed, so `writeLoop` blocks forever on
   `for req := range c.writeCh` after `Close()`. Every carrier teardown leaks
   one goroutine. → Phase 2 (carrier lifecycle).
2. **Issue A — sessions bound to a CarrierConn**: a carrier disconnect kills
   its streams; no rebind/resume. → Phase 5 (reconnect/rebind).
3. **Issue B — dispatcher head-of-line blocking**: `Dispatch()` does a
   blocking send into per-stream channels (cap 64); one slow stream stalls
   the whole carrier dispatcher. → Phase 3 (backpressure).
4. **Issue E — no handshake freshness**: symmetric secret echo allows
   replay/reflection; no role/nonces. → Phase 6 (security).
5. **Issue F — `parseInt` swallows errors** (both mains): `fmt.Sscanf(s,
   "%d", &n)` with ignored error → `SPLIT_METRICS_PORT=abc` becomes 0,
   `SPLIT_RELAY_BUF=xyz` becomes 0. → Phase 7 (config validation).
6. **WebSocket origin policy** (`cmd/iran-splitter/main.go`):
   `CheckOrigin: func(...) bool { return true }` — accepts every origin.
   → Phase 6 (security).
7. **Metrics**: mutex-protected counters only (active/total sessions,
   bytes up/down, errors). → Phase 8 (observability).
8. `SessionStore.Wait` polls at 10 ms with `time.Sleep` (fine at current
   scale; noted for later).
9. `SessionStore.CloseAll` holds only a `RLock` while calling `Close()` on
   conns (works today because Close does not take the store lock; noted).
10. `WriteDestinationBuffer` silently truncates >255-char domains while
    `WriteDestination` rejects them — inconsistent; pinned by a test.
    (Behavior preserved; revisit in Phase 7.)

## Tests passed

- `go test -timeout 120s ./...` — PASS (all packages)
- `go vet ./...` — PASS
- `go build ./cmd/...` — PASS (windows/amd64)
- `GOOS=linux GOARCH=amd64 go build ./cmd/...` — PASS
- `go run ./e2e-pipe-test` — PASS
- `gofmt -l .` — clean

`go test -race ./...` — see "Known failures" above (cannot execute on this
machine; re-run in any Linux environment).

## Next phase

Phase 2 — carrier lifecycle (`phase-2-carrier-lifecycle`):
context-based shutdown, close `writeCh` (or equivalent) so the writer exits,
deterministic keepalive/dispatch termination, no goroutine leaks on Close.

## Files modified (this commit)

- `pkg/mux/frame.go` (sentinel error)
- `pkg/mux/carrier.go` (sentinel error; keepalive FramePing fix)
- `pkg/session/session.go` (MaxHeaderSize fix)
- `cmd/iran-splitter/main.go` (SOCKS5 parse extraction)
- `cmd/iran-splitter/socks.go` (new)
- `cmd/iran-splitter/socks_test.go` (new)
- `pkg/mux/frame_test.go` (new)
- `pkg/mux/secret_test.go` (new)
- `pkg/mux/auth_test.go` (new)
- `pkg/mux/carrier_test.go` (new)
- `pkg/session/session_test.go` (new)
- `internal/testutil/mempipe.go` (new)
- `internal/testutil/mempipe_test.go` (new)
- `IMPLEMENTATION_STATUS.md` (new)

## Commit

(see `git log --oneline -1` on branch hardening/production-reliability)

## Rollback

```
git revert <phase-1-baseline-tests-commit>
```

or to abandon the whole effort:

```
git checkout main && git branch -D hardening/production-reliability
```