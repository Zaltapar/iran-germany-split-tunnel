# Tunnel Protocol Frames (mux)

The Iran–Germany split tunnel multiplexes logical streams over each carrier
(up-carrier WebSocket, down-carrier TCP). Every carrier is a byte stream of
frames:

```
Offset  Size  Field
0       4     StreamID (uint32, big-endian)
4       1     Type     (uint8)
5       2     Length   (uint16, big-endian, payload size, max 65535)
7       Len   Payload
```

(`HeaderSize = 7`, `MaxPayload = 65535`.) Frame types are defined in
[`pkg/mux/frame.go`](../../pkg/mux/frame.go#L41-L91); the stream-0 control
plane carries auth/keepalive/liveness. This document covers the full frame
catalog, including the two control frames added in the Phase 2 multi-carrier
work ([`FrameReset`](../../pkg/mux/frame.go#L81) and
[`FrameBootstrapAck`](../../pkg/mux/frame.go#L90)).

## Frame catalog

| Type | Value | Name | Direction (typical) | Kind |
|---|---|---|---|---|
| `0x00` | `FrameData` | user payload | both | stream data |
| `0x01` | `FrameAuth` | shared-secret handshake | both | stream-0 control (handshake only) |
| `0x02` | `FramePing` | keepalive ping | both | stream-0 control |
| `0x03` | `FramePong` | keepalive pong | both | stream-0 control |
| `0x04` | `FrameClose` | stream close / half-close | both | control |
| `0x05` | `FrameHeader` | stream header: encoded target destination | originator | control |
| `0x06` | `FrameRebind` | "this StreamID continues an EXISTING session" | originator | control |
| `0x07` | `FrameCredit` | receiver-side credit (flow control) | receiver → data sender | control (inert unless `SPLIT_CREDITS_ENABLED`) |
| `0x08` | `FrameReset` | stream-level negative acknowledgement (Issue #20) | receiver → originator | control |
| `0x09` | `FrameBootstrapAck` | bootstrap result (Issue #21) | receiver (Germany) → originator (Iran) | control |

### Existing control frames (pre-Phase 2, for reference)

- **`FrameRebind` (0x06)** — sent by the stream-originating node on a freshly
  (re)established carrier as the **first** frame of the stream, before any
  user data. Payload (versioned, `session.EncodeRebind`/`ParseRebindAny`):
  `[0]=version(1 or 2)` `[1:17]=SessionID` `[17:25]=sender carrier generation
  (uint64 BE)`. The generation is monotonically increasing per
  sender+direction, so a replayed/stale rebind is rejected. **Rebinding never
  creates a session** — the receiver resolves the existing session by the frame's
  `StreamID` and re-attaches it; anything it cannot validate is dropped (never a
  `FrameClose` — a refused rebind must not be mistaken for a peer half-close).

- **`FrameCredit` (0x07)** — 32-byte v1 wire format carrying
  cumulative bytes-consumed, a generation token pinned at arrival, and the
  receiver's current window. The mux layer parses/validates; no ledger state is
  kept in `pkg/mux` (Phase B: `pkg/node`). **Inert unless
  `SPLIT_CREDITS_ENABLED`** (default off).

### `FrameReset` (0x08) — stream-level negative ack (Issue #20)

Sent by the receiver (Germany) to the originator (Iran) when a `FrameRebind`
is **refused** (`unknown_peer`, `session_closed`, `rebind_refused`) so the
originator **terminates the stranded session** instead of retrying the rebind
on every subsequent carrier drop. It is a **terminal CONTROL frame** (a
terminal signal, not a half-close like `FrameClose`).

Fixed 10-byte versioned payload (`ResetPayloadSize = 10`,
`ResetVersion = 1`):

```
Offset  Size  Field
0       1     protocol version (must equal 1)
1       1     reason code (ResetReason*)
2:10    8     generation echo (uint64 BE) — the sender's carrier generation
                for the direction, so the receiver verifies the reset
                corresponds to the active stream, not a stale message
```

Reason codes ([`frame.go#L333-L336`](../../pkg/mux/frame.go#L333)):

| Value | Constant | Meaning |
|---|---|---|
| `1` | `ResetReasonUnknownStream` | no session for this stream ID |
| `2` | `ResetReasonSessionClosed` | session exists but is already closed |
| `3` | `ResetReasonRebindRefused` | rebind refused (stale gen / carrier mismatch / attach failed) |
| `4` | `ResetReasonTargetDialFailed` | bootstrap target dial failed (Issue #21 variant) |

Wire behavior:

- **Emitted** by [`handleRebind`](../../pkg/node/node.go#L1443) via
  `h.carrier.WriteControlFrame(id, mux.FrameReset, mux.EncodeResetPayload(resetReason, gen))`
  ([node.go#L1485](../../pkg/node/node.go#L1485)) on the *same* carrier that
  delivered the rebind. Early structural drops (malformed payload, carrier-id
  mismatch) carry no reliable generation and are **not** the stranded-session
  loop, so they `Deregister` *without* a reset.
- **Routed** in [`CarrierConn.Dispatch`](../../pkg/mux/carrier.go#L1079) to the
  `OnStreamReset` callback ([carrier.go#L172](../../pkg/mux/carrier.go#L172)) —
  never delivered to the stream mailbox, so no phantom `OnNewStream` fires and
  no stream record is created.
- **Handled** idempotently by
  [`handleStreamReset`](../../pkg/node/node.go#L1331): no active session →
  no-op; a **stale-generation guard** (`att.LastRebindGen() > gen` → ignore)
  drops retransmissions; otherwise it closes the session (both direction
  attachments), so the rebind sweep can never retry it again. Unknown-stream /
  stale resets are expected in a loss window and must stay idempotent no-ops.

### `FrameBootstrapAck` (0x09) — bootstrap result (Issue #21)

Sent by Germany to Iran on the **up carrier** after
[`bootstrapUpStream`](../../pkg/node/node.go#L2219) completes the target dial +
routing check — on **success OR failure**. The 2-byte versioned payload
(`BootstrapAckPayloadSize = 2`, `BootstrapAckVersion = 1`):

```
Offset  Size  Field
0       1     version (must equal 1)
1       1     status — an RFC 1928 SOCKS5 reply byte
```

The status byte maps **1:1 to the RFC 1928 SOCKS5 reply**, so the Iran SOCKS5
handler forwards it directly:

| Byte | Meaning |
|---|---|
| `0x00` | success (target actually accepted) |
| `0x01` | general SOCKS failure (unrecognized / no-remote-verdict / breaker open / WARP unreachable) |
| `0x02` | connection not allowed by ruleset |
| `0x03` | network unreachable |
| `0x04` | host unreachable / DNS failure |
| `0x05` | connection refused |
| `0x06` | connection timed out / TTL expired |

The pure classifier
[`bootstrapAckStatus(err)`](../../pkg/node/node.go#L2387) produces the status
byte from the target-dial outcome; **`0x00` is returned only for `err == nil`**.

Iran's [`StartSessionAndWait`](../../pkg/node/node.go#L1686) waits (bounded by
the session's own teardown) for this frame **before** replying to the client,
so a premature `0x00` is never sent when the target actually refused / timed
out / was blocked. The **`clientConnGate`** in
[`pkg/session/session.go`](../../pkg/session/session.go#L348) guarantees the
`0x00` reply precedes every downstream payload byte.

Wire behavior:

- **Emitted** by `bootstrapUpStream` — `EncodeBootstrapAckPayload(0x00)` on
  success ([node.go#L2379](../../pkg/node/node.go#L2379)) and
  `EncodeBootstrapAckPayload(0x01)` / `bootstrapAckStatus(...)` on failure
  ([node.go#L2244](../../pkg/node/node.go#L2244),
  [node.go#L2343](../../pkg/node/node.go#L2343)).
- **Routed** in `Dispatch` to the `OnStreamBootstrapAck` callback
  ([carrier.go#L1100-L1112](../../pkg/mux/carrier.go#L1100)); an **unknown-
  stream** ack (its session already closed, or a stale frame for a superseded
  stream) has no waiter and is **dropped silently** — never a protocol
  violation (duplicate/stale control frames are expected and must stay
  idempotent).

## Local sentinel: `BootstrapEndedWithoutResult`

When a session is torn down **locally** (carrier loss, client abort, node
shutdown) *before* a remote `FrameBootstrapAck` arrives, the originator's
`WaitBootstrap` backstop commits the sentinel
`session.BootstrapEndedWithoutResult` (`0xFF`,
[`session.go#L433`](../../pkg/session/session.go#L433)). The Iran SOCKS5
handler normalizes this out-of-range sentinel to the general-failure byte
`0x01` before replying, so the **wire never carries `0xFF`**:

```go
if code == byte(session.BootstrapEndedWithoutResult) {
    code = 0x01
}
```
([cmd/iran-splitter/main.go#L723-L724](../../cmd/iran-splitter/main.go#L723)).

## Observability

`FrameReset` / `FrameBootstrapAck` receive counts are exported in the metrics
snapshot: `stream_resets_received` and `bootstrap_acks_received`
([`pkg/node/metrics.go#L764-L765`](../../pkg/node/metrics.go#L764)); rebind
refusals are bucketed under `rebind_refusal{reason}` (incl.
`stale_generation`).
