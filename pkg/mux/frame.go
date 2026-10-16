package mux

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Frame protocol.
//
// Every carrier (up-carrier WS, down-carrier TCP) is a byte stream of frames:
//
//	Offset  Size  Field
//	0       4     StreamID (uint32, big-endian)
//	4       1     Type     (uint8)
//	5       2     Length   (uint16, big-endian, payload size, max 65535)
//	7       Len   Payload
const (
	HeaderSize = 7
	MaxPayload = 65535
)

// ErrPayloadTooLarge is returned by the frame encoders when the payload
// exceeds the 16-bit Length field.
var ErrPayloadTooLarge = errors.New("mux: frame payload too large")

// ErrProtocolViolation is set as the carrier's ReadErr when a post-auth
// frame violates the protocol's frame-context rules (see
// CarrierConn.readLoop): FrameAuth is only valid during the handshake, and
// application frames (Data/Header/Rebind/Close) are never valid on the
// reserved control stream 0. Such a violation is a connection-level
// failure: the carrier is terminated rather than the frame dropped,
// because a peer producing it is either a v0 peer (incompatible with the
// v1 auth, both ends must be upgraded together) or actively attacking.
var ErrProtocolViolation = errors.New("mux: protocol violation")

// Frame types
const (
	FrameData   uint8 = 0x00 // user data payload
	FrameAuth   uint8 = 0x01 // shared secret authentication
	FramePing   uint8 = 0x02 // keepalive ping
	FramePong   uint8 = 0x03 // keepalive pong
	FrameClose  uint8 = 0x04 // stream close / half-close
	FrameHeader uint8 = 0x05 // stream header: encoded target destination
	// FrameRebind (Phase 5): "this StreamID continues an EXISTING logical
	// session — do not bootstrap a new one". Sent by the stream-originating
	// node on a freshly (re)established carrier as the FIRST frame of the
	// stream, before any user data. Payload (versioned, see
	// session.EncodeRebind/ParseRebind):
	//
	//	[0]     protocol version (1)
	//	[1:17]  SessionID (16 bytes) of the session to re-attach
	//	[17:25] sender's carrier generation for this direction (uint64 BE)
	//
	// The generation is monotonically increasing per sender+direction, so a
	// replayed/stale rebind (old carrier generation) is rejected. Rebinding
	// never creates a session: the receiver resolves the existing session
	// by the frame's StreamID (the identity shared by both nodes — each
	// node keeps its own local SessionID, carried in the payload only as
	// the sender's diagnostic identifier), and re-attaches it; anything
	// it cannot validate is dropped (never a FrameClose — a refused
	// rebind must not be mistaken for a peer half-close).
	FrameRebind uint8 = 0x06
	// FrameCredit (Phase A, design doc §5.1): per-stream receiver-side credit
	// (32-byte payload, v1 wire format). Sent by the receiver to the DATA
	// sender on the down carrier, carrying cumulative bytes-consumed, a
	// generation token pinned at arrival, and the receiver's current window.
	// The mux package parses and validates FrameCredit; no credit ledger
	// state is maintained here (Phase B: pkg/node).
	FrameCredit uint8 = 0x07
	// FrameReset (Issue #20): stream-level negative acknowledgement.
	// Sent by the receiver (Germany) to the originator (Iran) when a
	// FrameRebind is refused (unknown_peer, session_closed, rebind_refused)
	// so the originator terminates the stranded session instead of retrying
	// indefinitely on every subsequent carrier drop. It is a CONTROL frame
	// (terminal signal, not a half-close like FrameClose). Payload is a
	// versioned 10-byte block (see EncodeReset / ParseReset below).
	FrameReset uint8 = 0x08
	// FrameBootstrapAck (Issue #21): bootstrap result from Germany to Iran.
	// Sent on the up carrier after bootstrapUpStream completes the target
	// dial + routing check (success OR failure). The 2-byte payload carries
	// [version=1][status]. Status maps 1:1 to the RFC 1928 SOCKS5 reply
	// byte so the Iran SOCKS5 handler can forward it directly. Iran's
	// StartSession caller waits for this frame before sending the SOCKS5
	// reply, so a premature 0x00 (success) is never sent when the target
	// actually refused / timed out / was blocked.
	FrameBootstrapAck uint8 = 0x09
)

// Frame is a single decoded frame.
type Frame struct {
	StreamID uint32
	Type     uint8
	Length   uint16
	Payload  []byte
}

// WriteFrame encodes one frame (header + payload) into w in a single write.
func WriteFrame(w io.Writer, streamID uint32, typ uint8, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrPayloadTooLarge
	}
	hdr := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(hdr[0:4], streamID)
	hdr[4] = typ
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))
	if len(payload) > 0 {
		_, err := w.Write(append(hdr, payload...))
		return err
	}
	_, err := w.Write(hdr)
	return err
}

// ReadFrame reads one frame from r. The returned payload is valid only
// until the next ReadFrame call on the same reader.
func ReadFrame(r *bufio.Reader) (Frame, error) {
	hdr := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return Frame{}, err
	}
	f := Frame{
		StreamID: binary.BigEndian.Uint32(hdr[0:4]),
		Type:     hdr[4],
	}
	f.Length = binary.BigEndian.Uint16(hdr[5:7])
	if f.Length > 0 {
		f.Payload = make([]byte, f.Length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// ============================================================
// FrameCredit payload — design doc §5.1 (REV 2, 39-byte frame)
// ============================================================
//
// The credit payload is a fixed 32-byte block appended after the 7-byte
// frame header (StreamID 4 + Type 1 + Length 2 = 39 bytes total frame).
// All multi-byte fields use BigEndian to stay consistent with the
// existing frame header and FrameRebind payload.
//
// Offsets (relative to the start of the payload):
//
//	Offset  Size  Field             Notes
//	0       1     creditVersion     must equal 1; any other value → reject
//	1       8     creditGen        uint64 BE, generation token of arriving carrier
//	9       8     bytesConsumed    uint64 BE, cumulative bytes written on this stream
//	17      4     windowGranted    uint32 BE, receiver's current granted window (≤ MaxBytesPerStream, clamped on receipt per §5.3/§6.5)
//	21      1     flags            bit 0 = FINAL; bits 1-7 reserved, MUST be 0
//	22      10    reserved         MUST be all-zero
//	Total:  32 bytes
// A creditGen of 0 is INVALID: the node layer assigns generation >= 1 at
// every carrier install (see node.go genSeq), so gen == 0 has no legitimate
// meaning in the credit payload and is rejected as an invalid value.

// CreditPayloadSize is the fixed 32-byte size of the FrameCredit payload
// (design doc §5.1).
const CreditPayloadSize = 32

// CreditVersion is the credit wire-format version carried in byte 0 of the
// payload (design doc §5.1/§5.2). The only valid value is 1; any other
// value triggers a stream-level rejection (degrade to SAFELY_CAPPED per
// §4.1) — NOT a connection-level one, since it may signal a mixed-version
// deployment handled via §5.2's atomic-upgrade rule, not a protocol
// violation by an attacker.
const CreditVersion byte = 1

// CreditFlagsFinal is bit 0 of the flags field: when set, no further
// credits are expected for this stream (accepted, not an error).
const CreditFlagsFinal byte = 0x01

// CreditFlagsReservedMask isolates the reserved bits (1-7) of the flags
// field; any non-zero value there is a protocol violation.
const CreditFlagsReservedMask byte = 0xFE

// ErrCreditMalformedLength is the connection-level sentinel set as a
// carrier's ReadErr when a FrameCredit's payload length is not exactly
// CreditPayloadSize (design §5.3: "Payload length != 32 → reject;
// connection-level, logged"). Enforced in CarrierConn.readLoop.
var ErrCreditMalformedLength = errors.New("mux: credit: malformed payload length (want " + strconv.Itoa(CreditPayloadSize) + " bytes)")

// ErrCreditUnknownStream is the connection-level sentinel set as a
// carrier's ReadErr when a FrameCredit references a stream this carrier has
// no record of (Phase A protocol-context rule: a credit must target an
// established stream; an unregistered-stream credit is a protocol violation
// that a legitimate credit sender never produces). Enforced in
// CarrierConn.readLoop.
var ErrCreditUnknownStream = errors.New("mux: credit: references an unregistered stream")

// CreditPayload is the decoded 32-byte FrameCredit payload.
type CreditPayload struct {
	Version       byte   // offset 0: must be 1
	Gen           uint64 // offset 1-8:  creditGen
	BytesConsumed uint64 // offset 9-16: bytesConsumed
	WindowGranted uint32 // offset 17-20: windowGranted (clamped to MaxBytesPerStream on receipt, §5.3/§6.5)
	Flags         byte   // offset 21:  bit 0 = FINAL, bits 1-7 reserved
	Reserved      []byte // offset 22-31: 10 bytes, must be all-zero
}

// EncodeCreditPayload encodes a CreditPayload into exactly CreditPayloadSize
// bytes. All multi-byte fields are BigEndian.
func EncodeCreditPayload(p *CreditPayload) []byte {
	out := make([]byte, CreditPayloadSize)
	out[0] = p.Version
	binary.BigEndian.PutUint64(out[1:9], p.Gen)
	binary.BigEndian.PutUint64(out[9:17], p.BytesConsumed)
	binary.BigEndian.PutUint32(out[17:21], p.WindowGranted)
	out[21] = p.Flags
	copy(out[22:32], p.Reserved)
	return out
}

// DecodeCreditPayload decodes exactly CreditPayloadSize bytes into a
// CreditPayload. It returns an error if the slice is not exactly
// CreditPayloadSize bytes long. It does NOT validate semantic content
// (version, generation, reserved bytes, etc.) — that is the caller's
// job (see ValidateCreditPayload).
func DecodeCreditPayload(raw []byte) (CreditPayload, error) {
	if len(raw) != CreditPayloadSize {
		return CreditPayload{}, ErrCreditMalformedLength
	}
	p := CreditPayload{
		Version:       raw[0],
		Gen:           binary.BigEndian.Uint64(raw[1:9]),
		BytesConsumed: binary.BigEndian.Uint64(raw[9:17]),
		WindowGranted: binary.BigEndian.Uint32(raw[17:21]),
		Flags:         raw[21],
		Reserved:      raw[22:32],
	}
	return p, nil
}

// ClampCreditWindow clamps a received windowGranted to the config cap
// (typically the carrier's MaxBytesPerStream). Per §5.3 the rule is
// "windowGranted > MaxBytesPerStream -> Clamp to MaxBytesPerStream, else
// accept": an out-of-bound window is a BENIGN value that is clamped,
// never rejected and never left unlimited (constraint-7). This is the
// only "exceeds the documented bound" case the codec normalizes; it is
// a CLAMP, not a reject.
func ClampCreditWindow(w, cap uint32) uint32 {
	if w > cap {
		return cap
	}
	return w
}

// StaleCreditGeneration reports whether a credit's generation does not
// pin to the arriving carrier's own generation (creditGen != carrierGen),
// per §5.2 (S3). creditGen is stamped with the DATA-sender's down-carrier
// generation; the receiver validates it against the h.gen of the carrier
// on which the frame ARRIVED. A credit with gen != the arriving carrier's
// gen is stale (an older or a future generation) and MUST be rejected
// without updating the outstanding ledger (§5.3). The node layer owns the
// arriving carrier's h.gen, so it calls this helper; gen == 0 is always
// stale here (real carrier generations are >= 1, node.go genSeq).
func StaleCreditGeneration(gen, carrierGen uint64) bool {
	return gen != carrierGen
}

// ValidateCreditPayload enforces the §5.3 structural/semantic rules the mux
// layer can check on a decoded CreditPayload. It returns a
// *CreditValidationErr (inspectable via its Rule field) on rejection and
// nil on accept.
//
// The mux-layer rules (all STREAM-level rejects; in Phase A there is no
// SAFELY_CAPPED degrade state, so a rejected credit terminates the stream
// rather than leaving it unbounded):
//  1. creditVersion must equal CreditVersion (1).
//  2. creditGen must be non-zero (a real carrier generation is >= 1).
//  3. the 10 reserved payload bytes (offsets 22-31) must be all-zero.
//  4. flags bits 1-7 (reserved) must be zero (bit 0 FINAL is allowed).
//
// Two §5.3 rules are handled elsewhere by design, not here:
//
//   - stale creditGen (gen != the ARRIVING carrier's h.gen) is a
//     carrier-relative check that requires the node's carrier handle,
//     so it is the StaleCreditGeneration helper, not ValidateCreditPayload.
//
//   - windowGranted exceeding the cap is a CLAMP (ClampCreditWindow), not a
//     reject, per §5.3/§6.5.
//
//   - The connection-level rejects (payload length != 32, stream 0, and a
//     reference to an unregistered stream) are enforced in
//     CarrierConn.readLoop, not the codec.
type CreditValidationErr struct {
	// Rule is a short identifier: "version", "gen-zero", "reserved-bytes",
	// or "reserved-flags".
	Rule string
}

func (e *CreditValidationErr) Error() string { return "mux: credit: " + e.Rule }

func ValidateCreditPayload(p *CreditPayload) error {
	if p.Version != CreditVersion {
		return &CreditValidationErr{Rule: "version"}
	}
	if p.Gen == 0 {
		return &CreditValidationErr{Rule: "gen-zero"}
	}
	for _, b := range p.Reserved {
		if b != 0 {
			return &CreditValidationErr{Rule: "reserved-bytes"}
		}
	}
	if p.Flags&CreditFlagsReservedMask != 0 {
		return &CreditValidationErr{Rule: "reserved-flags"}
	}
	return nil
}

// ============================================================
// FrameReset payload — Issue #20 (stream-level negative ack)
// ============================================================
//
// Fixed 10-byte block:
//
//	Offset  Size  Field
//	0       1     protocol version (must equal 1)
//	1       1     reason code (ResetReason*)
//	2:10    8     generation echo (uint64 BE) — the sender's carrier
//	                generation for the direction, so the receiver can
//	                verify the reset corresponds to the active stream and
//	                not a stale control message.
//
// Reset reasons:
const (
	ResetReasonUnknownStream    byte = 1 // no session for this stream ID
	ResetReasonSessionClosed    byte = 2 // session exists but is already closed
	ResetReasonRebindRefused    byte = 3 // rebind refused (stale gen, carrier mismatch, attach failed)
	ResetReasonTargetDialFailed byte = 4 // bootstrap target dial failed (Issue #21 variant)
)

// ResetPayloadSize is the fixed 10-byte size of the FrameReset payload.
const ResetPayloadSize = 10

// ResetVersion is the protocol version byte in the FrameReset payload.
const ResetVersion byte = 1

// EncodeResetPayload encodes a FrameReset payload.
func EncodeResetPayload(reason byte, gen uint64) []byte {
	out := make([]byte, ResetPayloadSize)
	out[0] = ResetVersion
	out[1] = reason
	binary.BigEndian.PutUint64(out[2:10], gen)
	return out
}

// ParseResetPayload decodes and validates a FrameReset payload.
// It returns the reason and generation, or an error if malformed.
func ParseResetPayload(payload []byte) (reason byte, gen uint64, err error) {
	if len(payload) != ResetPayloadSize {
		return 0, 0, fmt.Errorf("mux: reset: malformed payload length (want %d, got %d)", ResetPayloadSize, len(payload))
	}
	if payload[0] != ResetVersion {
		return 0, 0, fmt.Errorf("mux: reset: unknown version %d", payload[0])
	}
	reason = payload[1]
	gen = binary.BigEndian.Uint64(payload[2:10])
	return reason, gen, nil
}

// ============================================================
// FrameBootstrapAck payload — Issue #21 (SOCKS5 bootstrap result)
// ============================================================
//
// Fixed 2-byte block:
//
//	Offset  Size  Field
//	0       1     version (must equal 1)
//	1       1     status (RFC 1928 SOCKS5 reply code: 0x00 success, 0x01-0x08 failures)
//
// The status byte maps directly to the SOCKS5 reply that the Iran
// handler writes to the client. Germany sends this on the up carrier
// after bootstrapUpStream completes (success or failure).

// BootstrapAckPayloadSize is the fixed 2-byte size of the FrameBootstrapAck payload.
const BootstrapAckPayloadSize = 2

// BootstrapAckVersion is the protocol version byte in the FrameBootstrapAck payload.
const BootstrapAckVersion byte = 1

// EncodeBootstrapAckPayload encodes a FrameBootstrapAck payload.
func EncodeBootstrapAckPayload(status byte) []byte {
	out := make([]byte, BootstrapAckPayloadSize)
	out[0] = BootstrapAckVersion
	out[1] = status
	return out
}

// ParseBootstrapAckPayload decodes and validates a FrameBootstrapAck payload.
func ParseBootstrapAckPayload(payload []byte) (status byte, err error) {
	if len(payload) != BootstrapAckPayloadSize {
		return 0, fmt.Errorf("mux: bootstrap ack: malformed payload length (want %d, got %d)", BootstrapAckPayloadSize, len(payload))
	}
	if payload[0] != BootstrapAckVersion {
		return 0, fmt.Errorf("mux: bootstrap ack: unknown version %d", payload[0])
	}
	return payload[1], nil
}
