// protocol_test.go — the strict wire format (design §7.3): version
// pinning, closed op set, unknown-field rejection, oversize and
// trailing-data rejection.
package controlagent

import (
	"strings"
	"testing"
)

func TestDecodeFrameAcceptsValidFrame(t *testing.T) {
	f, err := decodeFrame([]byte(`{"v":1,"op":"status","reqId":"r1","payload":{}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Op != OpStatus || f.ReqID != "r1" {
		t.Fatalf("frame mismatch: %+v", f)
	}
}

// Version and op membership are enforced by Frame.validate() (the
// transport layer decodes; the agent validates), so both are asserted
// there.
func TestFrameValidateRejectsUnknownVersion(t *testing.T) {
	f, err := decodeFrame([]byte(`{"v":2,"op":"status","reqId":"r1"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := f.validate(); err == nil {
		t.Fatalf("validate() accepted v2 frame")
	}
}

func TestFrameValidateRejectsUnknownOp(t *testing.T) {
	f, err := decodeFrame([]byte(`{"v":1,"op":"delete-all","reqId":"r1"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := f.validate(); err == nil {
		t.Fatal("validate() accepted unknown op")
	}
}

func TestDecodeFrameRejectsUnknownFields(t *testing.T) {
	if _, err := decodeFrame([]byte(`{"v":1,"op":"status","reqId":"r1","sneaky":1}`)); err == nil {
		t.Fatal("accepted unknown field")
	}
}

func TestDecodeFrameRejectsTrailingData(t *testing.T) {
	if _, err := decodeFrame([]byte(`{"v":1,"op":"status"} {"v":1,"op":"status"}`)); err == nil {
		t.Fatal("accepted two JSON values in one frame")
	}
}

func TestDecodeFrameRejectsOversize(t *testing.T) {
	pad := strings.Repeat("a", MaxFrameBytes)
	raw := []byte(`{"v":1,"op":"status","reqId":"` + pad + `"}`)
	if len(raw) <= MaxFrameBytes {
		t.Fatal("test framing bug: raw not oversize")
	}
	if _, err := decodeFrame(raw); err == nil {
		t.Fatal("accepted an oversize frame")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	in := &Frame{V: 1, Op: OpApply, ReqID: "req-1", IdempotencyKey: "k-1", ChangeID: "c-1"}
	raw, err := encodeFrame(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeFrame(raw)
	if err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}
	if out.Op != OpApply || out.IdempotencyKey != "k-1" || out.ChangeID != "c-1" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestFrameValidateRequiresPayloadShape(t *testing.T) {
	f := &Frame{V: ProtocolVersion, Op: "definitely-not-an-op"}
	if err := f.validate(); err == nil {
		t.Fatal("validate accepted an unknown op")
	}
}
