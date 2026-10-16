package session

// rebind_v2_test.go — Phase 2 (D9) codec tests for the versioned FrameRebind
// payload. Covers v1 byte-identity, v2 round-trip, v1 fallback, malformed /
// unknown-version / over-long-id rejection, and truncation to the id bound.

import (
	"bytes"
	"testing"
)

func testSessionID() SessionID {
	var sid SessionID
	for i := range sid {
		sid[i] = byte(i)
	}
	return sid
}

// TestEncodeRebindV1ByteIdentity: the v1 payload is byte-identical to the
// pre-Phase-2 single-carrier wire (version 1, fixed RebindPayloadSize).
func TestEncodeRebindV1ByteIdentity(t *testing.T) {
	sid := testSessionID()
	got := EncodeRebind(sid, 42)
	if len(got) != RebindPayloadSize {
		t.Fatalf("v1 payload length = %d, want %d", len(got), RebindPayloadSize)
	}
	if got[0] != RebindVersion {
		t.Fatalf("v1 payload[0] = %d, want %d", got[0], RebindVersion)
	}
	// v1 fixed layout: [0]=1, [1:17]=sid, [17:25]=gen(u64 BE).
	want := make([]byte, RebindPayloadSize)
	want[0] = RebindVersion
	copy(want[1:], sid[:])
	_ = putBE(want[1+SessionIDLen:], 42)
	if !bytes.Equal(got, want) {
		t.Fatalf("v1 payload bytes = %v, want %v", got, want)
	}
}

// TestParseRebindAny_V1: a v1 payload decodes with the single-carrier default
// (empty CarrierID) and the version tag preserved.
func TestParseRebindAny_V1(t *testing.T) {
	sid := testSessionID()
	p := EncodeRebind(sid, 7)
	rb, ok := ParseRebindAny(p)
	if !ok {
		t.Fatal("ParseRebindAny(v1) must succeed")
	}
	if rb.Version != RebindVersion {
		t.Fatalf("version = %d, want %d", rb.Version, RebindVersion)
	}
	if !bytes.Equal(rb.SessionID[:], sid[:]) {
		t.Fatal("session id mismatch")
	}
	if rb.Gen != 7 {
		t.Fatalf("gen = %d, want 7", rb.Gen)
	}
	if rb.CarrierID != "" {
		t.Fatalf("v1 carrier id must be empty, got %q", rb.CarrierID)
	}
}

// TestParseRebindAny_V2: a v2 payload round-trips (version, sid, carrierID,
// generation).
func TestParseRebindAny_V2(t *testing.T) {
	sid := testSessionID()
	p := EncodeRebindV2(sid, "down-reality-b", 99)
	rb, ok := ParseRebindAny(p)
	if !ok {
		t.Fatal("ParseRebindAny(v2) must succeed")
	}
	if rb.Version != RebindVersionV2 {
		t.Fatalf("version = %d, want %d", rb.Version, RebindVersionV2)
	}
	if !bytes.Equal(rb.SessionID[:], sid[:]) {
		t.Fatal("session id mismatch")
	}
	if rb.CarrierID != "down-reality-b" {
		t.Fatalf("carrier id = %q, want down-reality-b", rb.CarrierID)
	}
	if rb.Gen != 99 {
		t.Fatalf("gen = %d, want 99", rb.Gen)
	}
}

// TestParseRebindAny_RejectsMalformed: malformed v1/v2 payloads are rejected
// (ok=false), and an unknown version byte is rejected (fail-closed).
func TestParseRebindAny_RejectsMalformed(t *testing.T) {
	sid := testSessionID()

	// Unknown version.
	_, ok := ParseRebindAny(append([]byte{0x7f}, sid[:]...))
	if ok {
		t.Error("unknown version byte: want rejected")
	}

	// Truncated v1.
	v1 := EncodeRebind(sid, 1)
	_, ok = ParseRebindAny(v1[:len(v1)-1])
	if ok {
		t.Error("truncated v1: want rejected")
	}

	// Truncated v2.
	v2 := EncodeRebindV2(sid, "down-reality-b", 1)
	_, ok = ParseRebindAny(v2[:len(v2)-1])
	if ok {
		t.Error("truncated v2: want rejected")
	}

	// v2 with an impossibly large id-length byte.
	bad := make([]byte, 1+SessionIDLen+1+8)
	bad[0] = RebindVersionV2
	copy(bad[1:], sid[:])
	bad[1+SessionIDLen] = 99 // > RebindMaxCarrierIDLen
	_, ok = ParseRebindAny(bad)
	if ok {
		t.Error("v2 with id-length > bound: want rejected")
	}

	// Empty payload.
	if _, ok := ParseRebindAny(nil); ok {
		t.Error("empty payload: want rejected")
	}
}

// TestEncodeRebindV2_TruncatesLongID: a carrier id longer than the bound is
// truncated to RebindMaxCarrierIDLen bytes; the resulting payload still
// round-trips to the truncated id.
func TestEncodeRebindV2_TruncatesLongID(t *testing.T) {
	sid := testSessionID()
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	p := EncodeRebindV2(sid, string(long), 5)
	rb, ok := ParseRebindAny(p)
	if !ok {
		t.Fatal("truncated-id payload must parse")
	}
	if len(rb.CarrierID) != RebindMaxCarrierIDLen {
		t.Fatalf("carrier id length = %d, want %d", len(rb.CarrierID), RebindMaxCarrierIDLen)
	}
	if !bytes.Equal([]byte(rb.CarrierID), long[:RebindMaxCarrierIDLen]) {
		t.Fatal("carrier id was not truncated to the bound")
	}
}

func putBE(b []byte, v uint64) []byte {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	return b
}
