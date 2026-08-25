package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// ============================================================
// Destination buffer encode/decode (the frame FrameHeader payload path)
// ============================================================

func TestDestinationBufferRoundTrip(t *testing.T) {
	cases := []Destination{
		{AddrType: AddrTypeIPv4, Addr: "1.2.3.4", Port: 80},
		{AddrType: AddrTypeIPv4, Addr: "192.168.178.42", Port: 443},
		{AddrType: AddrTypeDomain, Addr: "example.com", Port: 443},
		{AddrType: AddrTypeDomain, Addr: "a", Port: 1},
		{AddrType: AddrTypeDomain, Addr: "", Port: 53},
		{AddrType: AddrTypeIPv6, Addr: "2001:db8::1", Port: 443},
		{AddrType: AddrTypeIPv6, Addr: "::1", Port: 22},
	}
	for _, tc := range cases {
		buf := make([]byte, MaxHeaderSize)
		n := WriteDestinationBuffer(buf, &tc)
		if n == 0 {
			t.Fatalf("WriteDestinationBuffer returned 0 for %+v", tc)
		}
		got := ParseDestinationFromBuf(buf[:n])
		if got == nil {
			t.Fatalf("ParseDestinationFromBuf returned nil for %+v", tc)
		}
		if got.AddrType != tc.AddrType || got.Addr != tc.Addr || got.Port != tc.Port {
			t.Errorf("round trip mismatch: in=%+v out=%+v", tc, got)
		}
	}
}

func TestDestinationBufferTruncatesLongDomain(t *testing.T) {
	// Current behavior: domains longer than 255 chars are silently truncated
	// by WriteDestinationBuffer (WriteDestination, by contrast, returns an
	// error). Pin the current behavior here.
	long := strings.Repeat("x", 300)
	orig := Destination{AddrType: AddrTypeDomain, Addr: long, Port: 80}
	buf := make([]byte, MaxHeaderSize)
	n := WriteDestinationBuffer(buf, &orig)
	if n == 0 {
		t.Fatal("WriteDestinationBuffer rejected the long domain")
	}
	got := ParseDestinationFromBuf(buf[:n])
	if got == nil {
		t.Fatal("ParseDestinationFromBuf returned nil")
	}
	if len(got.Addr) != 255 || got.Addr != long[:255] {
		t.Fatalf("long domain not truncated to 255: len=%d", len(got.Addr))
	}
}

func TestDestinationBufferRejectsInvalid(t *testing.T) {
	cases := []Destination{
		{AddrType: 0x02, Addr: "x", Port: 1},                   // unknown atype
		{AddrType: AddrTypeIPv4, Addr: "999.1.1.1", Port: 1},   // bad IPv4
		{AddrType: AddrTypeIPv4, Addr: "example.com", Port: 1}, // domain as IPv4
		{AddrType: AddrTypeIPv6, Addr: "1.2.3.4", Port: 1},     // IPv4 as IPv6
		{AddrType: AddrTypeIPv6, Addr: "not-an-ip", Port: 1},
	}
	for _, tc := range cases {
		buf := make([]byte, MaxHeaderSize)
		if n := WriteDestinationBuffer(buf, &tc); n != 0 {
			t.Errorf("WriteDestinationBuffer accepted %+v (n=%d)", tc, n)
		}
	}
	// Buffer too small.
	if n := WriteDestinationBuffer(make([]byte, 3), &Destination{AddrType: AddrTypeIPv4, Addr: "1.2.3.4", Port: 1}); n != 0 {
		t.Error("WriteDestinationBuffer accepted a too-small buffer")
	}
}

func TestParseDestinationFromBufRejects(t *testing.T) {
	if ParseDestinationFromBuf(nil) != nil {
		t.Error("nil buffer parsed")
	}
	if ParseDestinationFromBuf([]byte{0x01, 0x00}) != nil {
		t.Error("short buffer parsed")
	}
	// Unknown address type.
	if ParseDestinationFromBuf([]byte{0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) != nil {
		t.Error("unknown address type parsed")
	}
	// Domain whose declared length runs past the buffer end.
	if ParseDestinationFromBuf([]byte{0x03, 0x05, 'a'}) != nil {
		t.Error("truncated domain parsed")
	}
}

// ============================================================
// Destination stream encode/decode (SOCKS5-style reader/writer)
// ============================================================

func TestDestinationStreamRoundTrip(t *testing.T) {
	cases := []Destination{
		{AddrType: AddrTypeIPv4, Addr: "8.8.8.8", Port: 53},
		{AddrType: AddrTypeDomain, Addr: "example.com", Port: 443},
		{AddrType: AddrTypeIPv6, Addr: "fe80::1", Port: 8080},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := WriteDestination(&buf, &tc); err != nil {
			t.Fatalf("WriteDestination(%+v): %v", tc, err)
		}
		got, err := ReadDestination(&buf)
		if err != nil {
			t.Fatalf("ReadDestination(%+v): %v", tc, err)
		}
		if got.AddrType != tc.AddrType || got.Addr != tc.Addr || got.Port != tc.Port {
			t.Errorf("stream round trip mismatch: in=%+v out=%+v", tc, got)
		}
	}
}

func TestReadDestinationRejectsUnknownType(t *testing.T) {
	buf := bytes.NewReader([]byte{0x02, 0x00, 0x00})
	if _, err := ReadDestination(buf); err == nil {
		t.Fatal("unknown address type accepted")
	}
}

func TestReadDestinationTruncated(t *testing.T) {
	// IPv4 with only 2 address bytes, no port.
	buf := bytes.NewReader([]byte{0x01, 0x01, 0x02})
	if _, err := ReadDestination(buf); err == nil {
		t.Fatal("truncated IPv4 destination accepted")
	}
	// Domain: length 5 but only 2 domain bytes.
	buf = bytes.NewReader([]byte{0x03, 0x05, 'a', 'b'})
	if _, err := ReadDestination(buf); err == nil {
		t.Fatal("truncated domain accepted")
	}
	// Empty reader.
	buf = bytes.NewReader(nil)
	if _, err := ReadDestination(buf); err == nil {
		t.Fatal("empty reader accepted")
	}
}

func TestWriteDestinationRejectsInvalid(t *testing.T) {
	bad := []Destination{
		{AddrType: 0x02, Addr: "x", Port: 1},
		{AddrType: AddrTypeIPv4, Addr: "example.com", Port: 1},
		{AddrType: AddrTypeIPv4, Addr: "999.1.1.1", Port: 1},
		{AddrType: AddrTypeIPv6, Addr: "1.2.3.4", Port: 1},
		{AddrType: AddrTypeDomain, Addr: strings.Repeat("y", 300), Port: 1},
	}
	for _, tc := range bad {
		var b bytes.Buffer
		if err := WriteDestination(&b, &tc); err == nil {
			t.Errorf("WriteDestination accepted %+v", tc)
		}
	}
}

// ============================================================
// Session IDs
// ============================================================

func TestSessionIDString(t *testing.T) {
	var sid SessionID
	for i := range sid {
		sid[i] = byte(i)
	}
	s := sid.String()
	if len(s) != 32 {
		t.Fatalf("SessionID.String len = %d, want 32", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Fatalf("SessionID.String is not hex: %v", err)
	}
	if want := "000102030405060708090a0b0c0d0e0f"; s != want {
		t.Errorf("String() = %s, want %s", s, want)
	}
}

func TestGenerateSessionID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		raw, err := GenerateSessionID()
		if err != nil {
			t.Fatalf("GenerateSessionID: %v", err)
		}
		if len(raw) != SessionIDLen {
			t.Fatalf("GenerateSessionID len = %d, want %d", len(raw), SessionIDLen)
		}
		var sid SessionID
		copy(sid[:], raw)
		if seen[sid.String()] {
			t.Fatalf("duplicate session id %s", sid.String())
		}
		seen[sid.String()] = true
	}
}

// ============================================================
// SessionStore
// ============================================================

// fakeConn is a minimal net.Conn whose only observable behavior is Close.
type fakeConn struct{ closed bool }

func (f *fakeConn) Read(p []byte) (int, error)         { return 0, errors.New("fake") }
func (f *fakeConn) Write(p []byte) (int, error)        { return 0, errors.New("fake") }
func (f *fakeConn) Close() error                       { f.closed = true; return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return nil }
func (f *fakeConn) RemoteAddr() net.Addr               { return nil }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func TestSessionStoreAddGetRemove(t *testing.T) {
	ss := NewSessionStore()
	var sid SessionID
	sid[0] = 0x11
	fc := &fakeConn{}
	s := NewSession(sid, nil, fc, nil, context.Background())
	ss.Add(sid, s)
	if n := ss.Count(); n != 1 {
		t.Fatalf("Count = %d, want 1", n)
	}
	got, ok := ss.Get(sid)
	if !ok || got != s {
		t.Fatal("Get did not return the added session")
	}
	got2, ok2 := ss.GetSession(sid)
	if !ok2 || got2 != s {
		t.Fatal("GetSession alias mismatch")
	}
	var missing SessionID
	missing[0] = 0xFF
	if _, ok := ss.Get(missing); ok {
		t.Fatal("Get returned a session that was never added")
	}

	ss.Remove(sid)
	if n := ss.Count(); n != 0 {
		t.Fatalf("Count after Remove = %d, want 0", n)
	}
	// Phase 4 ownership: Remove is a pure unindex — closing the client
	// connection belongs to Session.Close, not to the store.
	if fc.closed {
		t.Error("Remove closed the client connection (must be pure unindex)")
	}
	// Remove must be idempotent: a second Remove must not panic or change state.
	ss.Remove(sid)
	if n := ss.Count(); n != 0 {
		t.Fatalf("Count after double Remove = %d, want 0", n)
	}
}

func TestSessionStoreRemoveDoesNotCancel(t *testing.T) {
	// Phase 4: context cancellation belongs to Session.Close. The store
	// only unindexes.
	ss := NewSessionStore()
	var sid SessionID
	s := NewSession(sid, nil, nil, nil, context.Background())
	ss.Add(sid, s)
	ss.Remove(sid)
	select {
	case <-s.Ctx.Done():
		t.Fatal("Remove cancelled the session context (must be pure unindex)")
	default:
	}
	// ...and Close cancels it.
	s.Close("test")
	select {
	case <-s.Ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the session context")
	}
}

func TestSessionStoreStreamIndexing(t *testing.T) {
	ss := NewSessionStore()
	var sid SessionID
	s := &Session{ID: sid, StreamIDUp: 11, StreamIDDown: 12}
	ss.Add(sid, s)
	ss.AddStream(s)

	if _, ok := ss.GetByStream(11); !ok {
		t.Error("GetByStream(StreamIDUp) failed")
	}
	if _, ok := ss.GetByStream(12); !ok {
		t.Error("GetByStream(StreamIDDown) failed")
	}
	if _, ok := ss.GetByStream(13); ok {
		t.Error("GetByStream returned a session for an unknown stream id")
	}

	ss.RemoveStream(s)
	if _, ok := ss.GetByStream(11); ok {
		t.Error("RemoveStream left StreamIDUp indexed")
	}
	if _, ok := ss.GetByStream(12); ok {
		t.Error("RemoveStream left StreamIDDown indexed")
	}
}

func TestSessionStoreRemoveUnindexesStreams(t *testing.T) {
	ss := NewSessionStore()
	var sid SessionID
	s := &Session{ID: sid, StreamIDUp: 21, StreamIDDown: 22}
	ss.Add(sid, s)
	ss.AddStream(s)
	ss.Remove(sid)
	if _, ok := ss.GetByStream(21); ok {
		t.Error("Remove left StreamIDUp indexed")
	}
	if _, ok := ss.GetByStream(22); ok {
		t.Error("Remove left StreamIDDown indexed")
	}
}

func TestSessionStoreStreamIDCollision(t *testing.T) {
	// Current behavior: adding a second session under the same StreamID
	// silently overwrites the first index. Pin it so any change is explicit.
	ss := NewSessionStore()
	var a, b SessionID
	a[0], b[0] = 0xA1, 0xB1
	sa := &Session{ID: a, StreamIDUp: 7}
	sb := &Session{ID: b, StreamIDUp: 7}
	ss.Add(a, sa)
	ss.Add(b, sb)
	ss.AddStream(sa)
	ss.AddStream(sb)
	if got, _ := ss.GetByStream(7); got != sb {
		t.Fatal("stream index does not point at the most recently added session")
	}
}

func TestSessionStoreWait(t *testing.T) {
	ss := NewSessionStore()
	var sid SessionID
	sid[0] = 0x77
	go func() {
		time.Sleep(20 * time.Millisecond)
		ss.Add(sid, &Session{ID: sid})
	}()
	if _, ok := ss.Wait(sid, 2000); !ok {
		t.Fatal("Wait missed a session added shortly after")
	}

	var missing SessionID
	missing[0] = 0xFF
	start := time.Now()
	if _, ok := ss.Wait(missing, 100); ok {
		t.Fatal("Wait returned a session that never appeared")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("Wait(missing) took %v, want ~100ms", el)
	}
}

func TestSessionStoreCloseAll(t *testing.T) {
	ss := NewSessionStore()
	fc1, fc2 := &fakeConn{}, &fakeConn{}
	var s1, s2 SessionID
	s1[0], s2[0] = 0xC1, 0xC2
	ss.Add(s1, &Session{ID: s1, ClientConn: fc1})
	ss.Add(s2, &Session{ID: s2, ClientConn: fc2})
	ss.CloseAll()
	if !fc1.closed || !fc2.closed {
		t.Error("CloseAll did not close all client connections")
	}
}
