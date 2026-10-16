package mux

// Phase A (design doc §5) — FrameCredit wire format, parsing, validation,
// protocol-version compatibility, and the connection-level vs stream-level
// failure mapping. Concurrency-free: no new mutex, channel, or goroutine is
// introduced by the implementation under test; these tests only exercise the
// existing readLoop/Dispatch/auth machinery.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

// creditTestPayload builds a valid CreditPayload with the given field values.
// Reserved defaults to all-zero (the only valid value).
func creditTestPayload(gen, consumed uint64, window uint32, flags byte) CreditPayload {
	return CreditPayload{
		Version:       CreditVersion,
		Gen:           gen,
		BytesConsumed: consumed,
		WindowGranted: window,
		Flags:         flags,
		Reserved:      make([]byte, 10),
	}
}

// validCreditBytes returns the encoded 32-byte payload of a fully-valid
// credit (version=1, gen=1, reserved zero, flags 0).
func validCreditBytes() []byte {
	return EncodeCreditPayload(&CreditPayload{
		Version: CreditVersion,
		Gen:     1,
		Flags:   0,
	})
}

// waitReadLoopDone polls Ready() until the read loop has exited (readDone
// closed) or the deadline elapses.
func waitReadLoopDone(t *testing.T, c *CarrierConn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for c.Ready() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}

// ---- helpers used by the tests below ----

// isCreditRule reports whether err is a *CreditValidationErr with the given
// rule.
func isCreditRule(err error, rule string) bool {
	var ve *CreditValidationErr
	if errors.As(err, &ve) {
		return ve.Rule == rule
	}
	return false
}

// ============================================================
// Case 1: valid encode/decode round-trip
// ============================================================

// TestCreditEncodeDecodeRoundTrip round-trips a CreditPayload and pins the
// exact on-wire byte layout of §5.1 (offsets, sizes, BigEndian).
func TestCreditEncodeDecodeRoundTrip(t *testing.T) {
	in := CreditPayload{
		Version:       CreditVersion,
		Gen:           0x0102_0304_0506_0708,
		BytesConsumed: 0x090A_0B0C_0D0E_0F10,
		WindowGranted: 0x0001_0002,
		Flags:         CreditFlagsFinal,
		Reserved:      make([]byte, 10),
	}
	raw := EncodeCreditPayload(&in)
	if len(raw) != CreditPayloadSize {
		t.Fatalf("encoded length = %d, want %d", len(raw), CreditPayloadSize)
	}

	// Pin the exact §5.1 field offsets (relative to payload start).
	if raw[0] != CreditVersion {
		t.Errorf("offset 0 (creditVersion) = %#x, want 1", raw[0])
	}
	if got := binary.BigEndian.Uint64(raw[1:9]); got != in.Gen {
		t.Errorf("offsets 1-8 (creditGen) = %#x, want %#x", got, in.Gen)
	}
	if got := binary.BigEndian.Uint64(raw[9:17]); got != in.BytesConsumed {
		t.Errorf("offsets 9-16 (bytesConsumed) = %#x, want %#x", got, in.BytesConsumed)
	}
	if got := binary.BigEndian.Uint32(raw[17:21]); got != in.WindowGranted {
		t.Errorf("offsets 17-20 (windowGranted) = %#x, want %#x", got, in.WindowGranted)
	}
	if raw[21] != CreditFlagsFinal {
		t.Errorf("offset 21 (flags) = %#x, want %#x", raw[21], CreditFlagsFinal)
	}
	for i, b := range raw[22:32] {
		if b != 0 {
			t.Errorf("offset 22+%d (reserved) = %#x, want 0", i, b)
		}
	}

	out, err := DecodeCreditPayload(raw)
	if err != nil {
		t.Fatalf("DecodeCreditPayload: %v", err)
	}
	if out.Version != in.Version || out.Gen != in.Gen || out.BytesConsumed != in.BytesConsumed ||
		out.WindowGranted != in.WindowGranted || out.Flags != in.Flags ||
		!bytes.Equal(out.Reserved, in.Reserved) {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", out, in)
	}
	if err := ValidateCreditPayload(&out); err != nil {
		t.Fatalf("ValidateCreditPayload on valid payload = %v, want nil", err)
	}
}

// ============================================================
// Case 2: boundary values (0 and max credit)
// ============================================================

// TestCreditBoundaryValues checks the boundary field values round-trip and
// pass validation: windowGranted at 0 and at MaxPayload, bytesConsumed at
// its uint64 maximum, and creditGen at its uint64 maximum.
func TestCreditBoundaryValues(t *testing.T) {
	maxGen := ^uint64(0)
	maxConsumed := ^uint64(0)
	cases := map[string]CreditPayload{
		"window-zero":  creditTestPayload(1, 0, 0, 0),
		"window-max":   creditTestPayload(1, 1<<20, MaxPayload, 0),
		"consumed-max": creditTestPayload(1, maxConsumed, 4096, 0),
		"gen-max":      creditTestPayload(maxGen, 1, 4096, CreditFlagsFinal),
	}
	for name, p := range cases {
		raw := EncodeCreditPayload(&p)
		got, err := DecodeCreditPayload(raw)
		if err != nil {
			t.Fatalf("%s: DecodeCreditPayload: %v", name, err)
		}
		if got.WindowGranted != p.WindowGranted || got.BytesConsumed != p.BytesConsumed ||
			got.Gen != p.Gen {
			t.Fatalf("%s: round-trip mismatch: got %+v want %+v", name, got, p)
		}
		if err := ValidateCreditPayload(&got); err != nil {
			t.Fatalf("%s: boundary value rejected by validator: %v", name, err)
		}
	}
}

// ============================================================
// Case 3: zero credit
// ============================================================

// TestCreditZeroCredit checks that a fully-zero credit (zero window, zero
// bytesConsumed) is a VALID bounded value, not a reject: a zero grant means
// "nothing more to send now", which is well within the bounded regime.
func TestCreditZeroCredit(t *testing.T) {
	p := creditTestPayload(1, 0, 0, 0)
	if err := ValidateCreditPayload(&p); err != nil {
		t.Fatalf("zero credit rejected: %v (want valid bounded value)", err)
	}
	if got := ClampCreditWindow(0, MaxPayload); got != 0 {
		t.Fatalf("ClampCreditWindow(0) = %d, want 0", got)
	}
}

// ============================================================
// Case 4: malformed length (connection-level)
// ============================================================

// TestCreditMalformedLengthDecode checks the codec rejects a payload that is
// not exactly CreditPayloadSize bytes.
func TestCreditMalformedLengthDecode(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		if _, err := DecodeCreditPayload(make([]byte, n)); !errors.Is(err, ErrCreditMalformedLength) {
			t.Fatalf("length %d: DecodeCreditPayload err = %v, want ErrCreditMalformedLength", n, err)
		}
	}
}

// TestCreditMalformedLengthConnectionLevel checks that a FrameCredit whose
// payload length is not 32 is a CONNECTION-level failure (readLoop), not a
// stream drop: the carrier's read loop terminates with
// ErrCreditMalformedLength.
func TestCreditMalformedLengthConnectionLevel(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	_ = c.Register(1)
	go c.Dispatch()

	// Correct stream, WRONG payload length (2 bytes, not 32).
	if err := WriteFrame(b, 1, FrameCredit, validCreditBytes()[:2]); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	waitReadLoopDone(t, c)
	if c.Ready() {
		t.Fatal("carrier still Ready after a malformed-length FrameCredit; want connection-level failure")
	}
	if !errors.Is(c.ReadErr(), ErrCreditMalformedLength) {
		t.Fatalf("ReadErr = %v, want ErrCreditMalformedLength", c.ReadErr())
	}
}

// ============================================================
// Case 5: truncated frame
// ============================================================

// TestCreditTruncatedFrame checks that a FrameCredit whose declared Length is
// 32 but whose payload is cut short mid-stream fails at ReadFrame (the
// payload is never assembled, so the stream is not even reached).
func TestCreditTruncatedFrame(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(hdr[0:4], 1)
	hdr[4] = FrameCredit
	binary.BigEndian.PutUint16(hdr[5:7], CreditPayloadSize) // declares 32 payload bytes
	raw := append(hdr, 0, 0, 0, 0, 0)                       // only 5 of the 32 payload bytes

	// Frame-level: ReadFull of the payload fails.
	br := bufio.NewReader(bytes.NewReader(raw))
	if _, err := ReadFrame(br); err == nil {
		t.Fatal("ReadFrame accepted a truncated FrameCredit payload")
	}
}

// ============================================================
// Case 6: invalid reserved bits
// ============================================================

// TestCreditReservedBits checks the two reserved regions: the 10 reserved
// payload bytes and flags bits 1-7. Either non-zero is a stream-level reject;
// the FINAL bit alone (bit 0) is accepted.
func TestCreditReservedBits(t *testing.T) {
	// Reserved payload byte corrupted.
	p := creditTestPayload(1, 0, 4096, 0)
	p.Reserved[3] = 0xFF
	if err := ValidateCreditPayload(&p); !isCreditRule(err, "reserved-bytes") {
		t.Fatalf("reserved byte: ValidateCreditPayload = %v, want rule reserved-bytes", err)
	}

	// Flags reserved bit 1 set.
	p = creditTestPayload(1, 0, 4096, 0x02)
	if err := ValidateCreditPayload(&p); !isCreditRule(err, "reserved-flags") {
		t.Fatalf("flags reserved bit: ValidateCreditPayload = %v, want rule reserved-flags", err)
	}

	// FINAL bit alone is acceptable.
	p = creditTestPayload(1, 0, 4096, CreditFlagsFinal)
	if err := ValidateCreditPayload(&p); err != nil {
		t.Fatalf("FINAL-only flags rejected: %v, want valid", err)
	}
}

// ============================================================
// Case 7: invalid stream / invalid generation value
// ============================================================

// TestCreditInvalidGenerationValue checks that a credit with gen == 0 (no
// pinned generation) is rejected by the codec as an invalid value.
func TestCreditInvalidGenerationValue(t *testing.T) {
	p := creditTestPayload(0, 0, 4096, 0)
	if err := ValidateCreditPayload(&p); !isCreditRule(err, "gen-zero") {
		t.Fatalf("gen=0: ValidateCreditPayload = %v, want rule gen-zero", err)
	}
}

// TestCreditUnregisteredStreamConnectionLevel checks that a FrameCredit for a
// stream the carrier has no record of is a CONNECTION-level failure
// (ErrCreditUnknownStream), not a silent drop.
func TestCreditUnregisteredStreamConnectionLevel(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	_ = c.Register(1) // only stream 1 is known
	go c.Dispatch()

	if err := WriteFrame(b, 99, FrameCredit, validCreditBytes()); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	waitReadLoopDone(t, c)
	if !errors.Is(c.ReadErr(), ErrCreditUnknownStream) {
		t.Fatalf("ReadErr = %v, want ErrCreditUnknownStream", c.ReadErr())
	}
}

// TestCreditOnStreamZeroConnectionLevel checks that a FrameCredit on the
// reserved control stream 0 is rejected connection-level as a protocol
// violation (the generic post-auth stream-0 rule), never silently dropped.
func TestCreditOnStreamZeroConnectionLevel(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	go c.Dispatch()

	if err := WriteFrame(b, 0, FrameCredit, validCreditBytes()); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	waitReadLoopDone(t, c)
	if !errors.Is(c.ReadErr(), ErrProtocolViolation) {
		t.Fatalf("ReadErr = %v, want ErrProtocolViolation (stream-0 credit)", c.ReadErr())
	}
}

// ============================================================
// Case 8: replay / stale generation
// ============================================================

// TestCreditStaleGeneration checks the §5.2 (S3) stale-generation predicate:
// a credit whose creditGen does not pin to the arriving carrier's own gen is
// stale (old or future), and gen==0 is always stale.
func TestCreditStaleGeneration(t *testing.T) {
	cases := []struct {
		name      string
		gen       uint64
		carrier   uint64
		wantStale bool
	}{
		{"fresh", 1, 1, false},
		{"old-replay", 3, 6, true},
		{"future", 9, 6, true},
		{"zero", 0, 6, true},
	}
	for _, c := range cases {
		if got := StaleCreditGeneration(c.gen, c.carrier); got != c.wantStale {
			t.Errorf("%s: StaleCreditGeneration(%d,%d) = %v, want %v",
				c.name, c.gen, c.carrier, got, c.wantStale)
		}
	}
}

// TestCreditStreamLevelReject drives the stream-level reject for a credit
// with invalid semantic content (a corrupted reserved byte here, standing in
// for any §5.3 violation the codec can see): the target stream is terminated
// (nil on its channel) without signalling the peer, and the carrier itself
// stays up.
func TestCreditStreamLevelReject(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	ch := c.Register(1)
	go c.Dispatch()

	// Correct 32-byte length but invalid semantic content (reserved byte).
	p := append([]byte(nil), validCreditBytes()...)
	p[22] = 0xFF
	if err := WriteFrame(b, 1, FrameCredit, p); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case got := <-ch:
		if got != nil {
			t.Fatalf("stream terminated by bad credit delivered %q, want nil", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bad credit did not terminate the stream (stream-level reject missing)")
	}
	// The carrier itself stays up: a stream-level reject must not kill it.
	if !c.Ready() {
		t.Fatal("carrier died on a stream-level credit reject; want only the stream terminated")
	}
}

// ============================================================
// Case 9: wrong protocol version (creditVersion != 1)
// ============================================================

// TestCreditWrongCreditVersion checks that a creditVersion other than 1 is a
// stream-level reject (rule "version"), and that the accepted value is 1.
func TestCreditWrongCreditVersion(t *testing.T) {
	for _, v := range []byte{0, 2, 3, 255} {
		p := creditTestPayload(1, 0, 4096, 0)
		p.Version = v
		if err := ValidateCreditPayload(&p); !isCreditRule(err, "version") {
			t.Fatalf("version=%d: ValidateCreditPayload = %v, want rule version", v, err)
		}
	}
	ok := creditTestPayload(1, 0, 4096, 0)
	if err := ValidateCreditPayload(&ok); err != nil {
		t.Fatalf("version=1 rejected: %v", err)
	}
}

// TestCreditWindowIsClampNotReject checks §5.3: a windowGranted that exceeds
// the cap is CLAMPED, never rejected. The codec's structural validator
// therefore accepts any window value, and ClampCreditWindow folds it to the
// cap.
func TestCreditWindowIsClampNotReject(t *testing.T) {
	p := creditTestPayload(1, 0, MaxPayload, 0)
	if err := ValidateCreditPayload(&p); err != nil {
		t.Fatalf("window=MaxPayload rejected by validator: %v (want accept, clamp elsewhere)", err)
	}
	if got := ClampCreditWindow(2*MaxPayload, MaxPayload); got != MaxPayload {
		t.Fatalf("ClampCreditWindow(2*Max, Max) = %d, want Max", got)
	}
	if got := ClampCreditWindow(1024, MaxPayload); got != 1024 {
		t.Fatalf("ClampCreditWindow(1024, Max) = %d, want 1024 (in-bounds unchanged)", got)
	}
}

// ============================================================
// Case 10: mixed-version peer MUST fail at auth (fail-closed)
// ============================================================

// TestMixedVersionPeerFailsAtAuth proves the operator's hard rule: a new
// (AuthVersion=2) peer paired with an old (AuthVersion=1) peer is rejected
// DURING AUTHENTICATION with an explicit ErrAuthVersion — it never falls
// through to the post-auth silent-drop state. Both directions are covered:
// an old client's version-1 response at a new server, and an old server's
// version-1 challenge at a new client.
func TestMixedVersionPeerFailsAtAuth(t *testing.T) {
	secret := DeriveSecret("mixed-version")

	// (a) new server + old client: client's response carries version byte 1.
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	sErr := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), b, false, RoleUpload, secret)
		sErr <- e
	}()
	ch, err := ReadFrame(bufio.NewReader(a))
	if err != nil || ch.Type != FrameAuth {
		t.Fatalf("did not read the v2 challenge: frame=%+v err=%v", ch, err)
	}
	resp := buildResponse(secret, RoleUpload, ch.Payload, authNow(), authNonce())
	resp[0] = 1 // the OLD peer's version (current AuthVersion is 2)
	if err := WriteFrame(a, 0, FrameAuth, resp); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-sErr:
		if !errors.Is(e, ErrAuthVersion) {
			t.Fatalf("new server vs old client: err = %v, want ErrAuthVersion (fail-closed at auth)", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("new server did not reject the old client's version-1 response")
	}

	// (b) new client + old server: server's challenge carries version byte 1.
	a2, b2 := testutil.NewMemPipe()
	defer a2.Close()
	defer b2.Close()
	cErr := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), a2, true, RoleUpload, secret)
		cErr <- e
	}()
	oldCh := buildChallenge(RoleUpload)
	oldCh[0] = 1 // the OLD server's version (current AuthVersion is 2)
	if err := WriteFrame(b2, 0, FrameAuth, oldCh); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-cErr:
		if !errors.Is(e, ErrAuthVersion) {
			t.Fatalf("new client vs old server: err = %v, want ErrAuthVersion (fail-closed at auth)", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("new client did not reject the old server's version-1 challenge")
	}
}

// TestAuthSameVersionStillSucceeds guards the non-regression side of the
// bump: two v2 (current) peers still complete the handshake.
func TestAuthSameVersionStillSucceeds(t *testing.T) {
	secret := DeriveSecret("same-version-v2")
	cRes, sRes := runAuthPair(t, RoleDownload, secret, secret, 2*time.Second)
	if cRes.err != nil {
		t.Fatalf("client auth (both v2): %v", cRes.err)
	}
	if sRes.err != nil {
		t.Fatalf("server auth (both v2): %v", sRes.err)
	}
}

// ============================================================
// Case 11: pre-auth FrameCredit
// ============================================================

// TestPreAuthFrameCredit checks that a FrameCredit arriving BEFORE the auth
// handshake completes is rejected connection-level (ErrAuthProtocol): the
// handshake accepts ONLY FrameAuth on stream 0, so a credit is out of context
// and can never establish a usable stream.
func TestPreAuthFrameCredit(t *testing.T) {
	secret := DeriveSecret("pre-auth-credit")
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	sErr := make(chan error, 1)
	go func() {
		_, e := CarrierAuth(context.Background(), b, false, RoleUpload, secret)
		sErr <- e
	}()
	// Consume the v2 challenge the server sends first.
	if _, err := ReadFrame(bufio.NewReader(a)); err != nil {
		t.Fatalf("did not read the v2 challenge: %v", err)
	}
	// Now, instead of the expected FrameAuth response, send a FrameCredit.
	if err := WriteFrame(a, 1, FrameCredit, validCreditBytes()); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case e := <-sErr:
		if !errors.Is(e, ErrAuthProtocol) {
			t.Fatalf("pre-auth credit: err = %v, want ErrAuthProtocol (reject before stream)", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pre-auth FrameCredit was not rejected during the handshake")
	}
}

// ============================================================
// Case 12: unknown frame types still dropped; valid credit is a no-op
// ============================================================

// TestDispatchUnknownTypeNeverTerminates is the §5.3 (S4) MUST test: a frame
// of a genuinely unrecognised type (0xFF here) is DROPPED — it does not
// terminate the target stream and no data-frame drop is recorded. This guards
// the `default:` drop-only path so it is never changed to terminate.
func TestDispatchUnknownTypeNeverTerminates(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	c.SetQueueStats(&QueueStats{})
	ch := c.Register(5)
	go c.Dispatch()

	if err := WriteFrame(b, 5, 0xFF, []byte("x")); err != nil {
		t.Fatalf("WriteFrame(unknown type): %v", err)
	}
	// A data frame right after the unknown one MUST still be delivered:
	// the stream was drop-only, not terminated.
	if err := WriteFrame(b, 5, FrameData, []byte("after-unknown")); err != nil {
		t.Fatalf("WriteFrame(data): %v", err)
	}
	select {
	case got := <-ch:
		if got == nil {
			t.Fatal("unknown-type frame terminated the stream (nil delivered); must drop-only")
		}
		if string(got) != "after-unknown" {
			t.Fatalf("payload after unknown frame = %q, want after-unknown", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("data after unknown frame not delivered; stream was terminated")
	}
	if got := c.QueueStats().DroppedDataFrames; got != 0 {
		t.Fatalf("dropped_data_frames = %d after an unknown-type drop, want 0", got)
	}
	if !c.Ready() {
		t.Fatal("carrier died on an unknown-type frame; drop must not tear it down")
	}
}

// TestCreditValidFrameIsNoOp checks Phase A's "no behavior change" contract:
// a fully valid credit is parsed and accepted, does not terminate the stream,
// and does not store any state — the stream keeps delivering data.
func TestCreditValidFrameIsNoOp(t *testing.T) {
	a, b := testutil.NewMemPipe()
	defer a.Close()
	defer b.Close()
	c := NewCarrierConn(a, 0)
	defer c.Close()
	ch := c.Register(7)
	go c.Dispatch()

	if err := WriteFrame(b, 7, FrameCredit, validCreditBytes()); err != nil {
		t.Fatalf("WriteFrame(credit): %v", err)
	}
	if err := WriteFrame(b, 7, FrameData, []byte("still-alive")); err != nil {
		t.Fatalf("WriteFrame(data): %v", err)
	}
	select {
	case got := <-ch:
		if got == nil {
			t.Fatal("a VALID credit terminated the stream; must be a no-op in Phase A")
		}
		if string(got) != "still-alive" {
			t.Fatalf("payload after valid credit = %q, want still-alive", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("valid credit stalled or terminated the stream")
	}
	if !c.Ready() {
		t.Fatal("carrier died after a valid credit; must stay up")
	}
}

// ============================================================
// Case 13: fuzz / property-style parsing
// ============================================================

// TestCreditPropertyRoundTripAndMutations is a table-driven, property-style
// parse check (the repo's convention — no Go fuzz dependency is introduced):
// every generated valid payload round-trips, and each single-byte mutation in
// a checked region is rejected by the validator with the expected rule, while
// mutations in a free field are still accepted.
func TestCreditPropertyRoundTripAndMutations(t *testing.T) {
	// (1) Valid payloads round-trip through encode->decode->validate.
	valids := []CreditPayload{
		creditTestPayload(1, 0, 0, 0),
		creditTestPayload(5, 1<<32, MaxPayload, 0),
		creditTestPayload(^uint64(0), ^uint64(0), MaxPayload, CreditFlagsFinal),
	}
	for _, in := range valids {
		got, err := DecodeCreditPayload(EncodeCreditPayload(&in))
		if err != nil {
			t.Fatalf("valid payload did not decode: %v", err)
		}
		if got.Version != in.Version || got.Gen != in.Gen || got.BytesConsumed != in.BytesConsumed ||
			got.WindowGranted != in.WindowGranted || got.Flags != in.Flags {
			t.Fatalf("valid payload round-trip mismatch: %+v vs %+v", got, in)
		}
		if err := ValidateCreditPayload(&got); err != nil {
			t.Fatalf("valid payload rejected after round-trip: %v", err)
		}
	}

	// (2) Single-byte mutations: encode a clean payload, flip one byte, and
	// assert the exact validation outcome (reject with the named rule, or
	// accept if the byte is in a free field).
	base := validCreditBytes()
	type mutation struct {
		off  int
		val  byte
		want string // "" means "still valid"; else a CreditValidationErr.Rule
		name string
	}
	cases := []mutation{
		{0, 2, "version", "creditVersion -> 2"},
		{0, 0, "version", "creditVersion -> 0"},
		{22, 0xFF, "reserved-bytes", "reserved byte -> 0xFF"},
		{31, 0x01, "reserved-bytes", "last reserved byte -> 1"},
		{21, 0x02, "reserved-flags", "flags reserved bit 1"},
		{21, 0x80, "reserved-flags", "flags reserved bit 7"},
		{21, 0x01, "", "flags FINAL bit only -> still valid"},
		{17, 0xFF, "", "windowGranted most-significant byte -> still valid (clamp, not reject)"},
		{2, 0x01, "", "creditGen high byte -> still valid"},
		{11, 0x5A, "", "bytesConsumed -> still valid (value, not a structural field)"},
	}
	for _, m := range cases {
		raw := append([]byte(nil), base...)
		raw[m.off] = m.val
		got, err := DecodeCreditPayload(raw)
		if err != nil {
			t.Fatalf("%s: decode of a 32-byte buffer failed: %v", m.name, err)
		}
		err = ValidateCreditPayload(&got)
		if m.want == "" {
			if err != nil {
				t.Fatalf("%s: expected valid, got %v", m.name, err)
			}
			continue
		}
		if !isCreditRule(err, m.want) {
			t.Fatalf("%s: expected rule %q, got %v", m.name, m.want, err)
		}
	}
}
