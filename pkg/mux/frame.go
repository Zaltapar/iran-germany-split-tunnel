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

// Frame types
const (
	FrameData   uint8 = 0x00 // user data payload
	FrameAuth   uint8 = 0x01 // shared secret authentication
	FramePing   uint8 = 0x02 // keepalive ping
	FramePong   uint8 = 0x03 // keepalive pong
	FrameClose  uint8 = 0x04 // stream close / half-close
	FrameHeader uint8 = 0x05 // stream header: encoded target destination
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
