package mux

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
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
	// FrameCredit (D4 hybrid backpressure, receiver half — Increment 1):
	// per-stream credit frame carried on the down carrier (IR→DE), whose
	// payload reports the receiver's cumulative bytes popped from that
	// stream's mailbox. This increment adds the frame type and its
	// payload codec/validation only; no credit state is latched yet
	// (that is Increment 2). A peer that does not know this type simply
	// drops it via the dispatcher's default arm — wire-compatible.
	FrameCredit uint8 = 0x07
)

// CreditVersion1 is the only credit-payload version the receiver accepts.
// Any other value is IGNORED (no state change, no panic, connection stays
// up) so that a peer that has not adopted credit (or that predates this
// frame type) can be mixed-generation on the same wire.
const CreditVersion1 = 1

// creditVersion1 is the private codec alias Increment 1 uses; it is the
// single source of truth for the version byte and stays in lockstep with
// the exported constant above.
const creditVersion1 = CreditVersion1

// creditPayloadSize is the exact byte length of a FrameCredit payload:
// 1 (creditVersion uint8) + 8 (cumulativeBytesPopped uint64, big-endian) +
// 4 (creditWindow uint32 on the wire, big-endian) + 1 (flags uint8, 0) +
// 4 (reserved, 0). All multi-byte fields use binary.BigEndian, matching
// every other wire field in this package (FrameHeader, carrier WriteFrame).
const creditPayloadSize = 18

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

// CreditFrameInfo is the decoded content of one FrameCredit payload.
type CreditFrameInfo struct {
	// CreditVersion is the payload's version byte (must be creditVersion1).
	CreditVersion uint8
	// CumulativeBytesPopped is the receiver's running count of payload
	// bytes popped from the stream's mailbox since (re)bind-attach.
	// Absolute, not a delta — the sender (Increment 2) derives the window
	// as CumulativeBytesPopped - cumulativeSent, clamped at 0.
	CumulativeBytesPopped uint64
	// CreditWindow is the informational uint32 window value carried on the
	// wire (D1-Q6's min(MaxBytesPerStream, creditGranted)); the receiver
	// of Increment 1 does not consume it.
	CreditWindow uint32
}

// WriteCreditFrame encodes a FrameCredit frame (header + 18-byte payload,
// every field binary.BigEndian) for w.
func WriteCreditFrame(w io.Writer, streamID uint32, info CreditFrameInfo) error {
	payload := make([]byte, creditPayloadSize)
	payload[0] = info.CreditVersion
	binary.BigEndian.PutUint64(payload[1:9], info.CumulativeBytesPopped)
	binary.BigEndian.PutUint32(payload[9:13], info.CreditWindow)
	// payload[13] (flags) and payload[14:18] (reserved) stay zero.
	return WriteFrame(w, streamID, FrameCredit, payload)
}

// CreditPayload encodes one FrameCredit payload (the 18-byte body,
// binary.BigEndian; §E.4) for an emitter that writes through the
// carrier's serialized write path (Increment 2). creditWindow is the
// informational D1-Q6 window min(MaxBytesPerStream, creditGranted); the
// flags and reserved bytes stay zero (A6: no FINAL_CREDIT bit).
func CreditPayload(info CreditFrameInfo) []byte {
	payload := make([]byte, creditPayloadSize)
	payload[0] = info.CreditVersion
	binary.BigEndian.PutUint64(payload[1:9], info.CumulativeBytesPopped)
	binary.BigEndian.PutUint32(payload[9:13], info.CreditWindow)
	return payload
}

// parseCreditFrame validates and decodes a FrameCredit payload. It is
// pure: it reports ok=false for any malformed input (wrong length or
// version != 1) and never panics; the caller drops the frame.
func parseCreditFrame(payload []byte) (info CreditFrameInfo, ok bool) {
	if len(payload) != creditPayloadSize {
		return CreditFrameInfo{}, false
	}
	if payload[0] != creditVersion1 {
		return CreditFrameInfo{}, false
	}
	return CreditFrameInfo{
		CreditVersion:         payload[0],
		CumulativeBytesPopped: binary.BigEndian.Uint64(payload[1:9]),
		CreditWindow:          binary.BigEndian.Uint32(payload[9:13]),
	}, true
}
