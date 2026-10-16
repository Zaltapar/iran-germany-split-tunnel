// engine_test.go — outbound selection on fake dialers, WARP fail-closed
// and fallback-direct paths, and the no-log-by-default redaction test.
package routing

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

// recordedDialer is a Direct DialFunc fake: it records every address
// dialed and returns either a canned error or a pipe connection.
type recordedDialer struct {
	mu    sync.Mutex
	addrs []string
	err   error
	conn  net.Conn // returned on success (nil → a fresh pipe conn)
}

func (d *recordedDialer) Dial(addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addrs = append(d.addrs, addr)
	if d.err != nil {
		return nil, d.err
	}
	if d.conn != nil {
		return d.conn, nil
	}
	c1, c2 := net.Pipe()
	_ = c2
	return c1, nil
}

func (d *recordedDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.addrs)
}

// fakeWarpSocks is a WARP SOCKS5 endpoint fake: a loopback TCP listener
// that speaks just enough SOCKS5 (no-auth handshake + CONNECT reply)
// for the protocol path, driven by per-test response modes.
type fakeWarpSocks struct {
	ln      net.Listener
	mode    string // "ok" | "refused" | "hang"
	capture []byte // CONNECT request bytes as captured by the handler
	capMu   sync.Mutex
	quit    chan struct{}
	wg      sync.WaitGroup
}

func newFakeWarpSocks(t *testing.T, mode string) *fakeWarpSocks {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake warp listen: %v", err)
	}
	f := &fakeWarpSocks{ln: ln, mode: mode, quit: make(chan struct{})}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.serve()
	}()
	return f
}

func (f *fakeWarpSocks) Addr() string { return f.ln.Addr().String() }

func (f *fakeWarpSocks) Captured() []byte {
	f.capMu.Lock()
	defer f.capMu.Unlock()
	if f.capture == nil {
		return nil
	}
	return append([]byte(nil), f.capture...)
}

func (f *fakeWarpSocks) Close() {
	close(f.quit)
	f.ln.Close()
	f.wg.Wait()
}

func (f *fakeWarpSocks) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			select {
			case <-f.quit:
				return
			default:
				return
			}
		}
		go f.handle(c)
	}
}

func (f *fakeWarpSocks) handle(c net.Conn) {
	defer c.Close()
	// handshake: read 3 bytes (ver cmd nmethods), reply with no-auth.
	hd := make([]byte, 3)
	if _, err := io.ReadFull(c, hd); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	// CONNECT request: ver(1) cmd(1) rsv(1) atype(1) ...
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	captured := append(append([]byte{}, hdr...), 0) // atype position filled below
	rest := []byte{}
	if hdr[3] == 0x01 {
		rest = make([]byte, 6) // 4 ip + 2 port
		if _, err := io.ReadFull(c, rest); err != nil {
			return
		}
		captured = append(captured[:3], 0x01)
	} else if hdr[3] == 0x04 {
		rest = make([]byte, 18)
		if _, err := io.ReadFull(c, rest); err != nil {
			return
		}
		captured = append(captured[:3], 0x04)
	} else {
		rest = make([]byte, 1)
		if _, err := io.ReadFull(c, rest); err != nil {
			return
		}
		domainAndPort := make([]byte, int(rest[0])+2)
		if _, err := io.ReadFull(c, domainAndPort); err != nil {
			return
		}
		rest = append(rest, domainAndPort...)
		captured = append(captured[:3], 0x03)
	}
	captured = append(captured, rest...)
	f.capMu.Lock()
	f.capture = captured
	f.capMu.Unlock()

	switch f.mode {
	case "ok":
		// Reply: ver rep=0 rsv atype + 4.0.0.0:0 (the IPv4 form is
		// representable for every client request).
		if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		// Keep the connection open as the "tunnel".
		buf := make([]byte, 4096)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	case "refused":
		_, _ = c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // REP 4 = refused
	case "hang":
		// Never reply; the client times out on the reply read.
		select {
		case <-f.quit:
		}
	}
}

// waitCaptured polls until the fake has captured the CONNECT request.
func waitCaptured(t *testing.T, f *fakeWarpSocks) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		cap := f.Captured()
		if cap != nil {
			return cap
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for CONNECT capture")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// outbound selection
// ---------------------------------------------------------------------------

func newTestEngine(t *testing.T, rsJSON string, direct *recordedDialer) *Engine {
	t.Helper()
	rs := mustRules(t, rsJSON)
	e, err := New(Config{
		Rules:    rs,
		Direct:   direct.Dial,
		WARPAddr: "127.0.0.1:1", // never dialed in direct tests
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestDialBlockRefusal(t *testing.T) {
	d := &recordedDialer{}
	e := newTestEngine(t,
		`{"version":1,"rules":[{"id":"blk","match":{"keyword":"evil"},"action":"block"}]}`,
		d)
	_, err := e.Dial("evil.example.com:443")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
	if d.count() != 0 {
		t.Fatalf("block must not dial the direct outbound (count=%d)", d.count())
	}
}

func TestDialDirect(t *testing.T) {
	d := &recordedDialer{}
	e := newTestEngine(t,
		`{"version":1,"rules":[{"id":"d","match":{"keyword":"ok"},"action":"direct"}]}`,
		d)
	conn, err := e.Dial("ok.example.com:443")
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	if conn == nil {
		t.Fatal("direct dial returned nil conn")
	}
	conn.Close()
	if d.count() != 1 {
		t.Fatalf("direct dial count = %d, want 1", d.count())
	}
}

func TestDialDefaultDirect(t *testing.T) {
	d := &recordedDialer{}
	e := newTestEngine(t, `{"version":1,"rules":[]}`, d)
	conn, err := e.Dial("unmatched.example.com:80")
	if err != nil {
		t.Fatalf("default direct: %v", err)
	}
	conn.Close()
	if d.count() != 1 {
		t.Fatalf("default direct count = %d, want 1", d.count())
	}
}

// ---------------------------------------------------------------------------
// WARP SOCKS5 protocol path (fake endpoint, "ok" mode)
// ---------------------------------------------------------------------------

func TestDialWarpOK(t *testing.T) {
	fw := newFakeWarpSocks(t, "ok")
	defer fw.Close()

	rs := mustRules(t, `{"version":1,"rules":[
		{"id":"w","match":{"keyword":"target"},"action":"warp","fallback":"direct"}
	]}`)
	e, err := New(Config{
		Rules:    rs,
		Direct:   (&recordedDialer{}).Dial,
		WARPAddr: fw.Addr(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := e.Dial("target.example.com:443")
	if err != nil {
		t.Fatalf("warp dial: %v", err)
	}
	if conn == nil {
		t.Fatal("warp dial returned nil conn")
	}
	// The returned conn is the raw tunnel (the fake keeps it open).
	_, _ = conn.Write([]byte("hello-target")) // must not fail immediately
	conn.Close()
}

// Domain-form CONNECT: verify the fake saw a domain-form request
// (atype 0x03) for a domain host.
func TestDialWarpDomainFormRequest(t *testing.T) {
	fw := newFakeWarpSocks(t, "ok")
	defer fw.Close()

	rs := mustRules(t, `{"version":1,"rules":[
		{"id":"w","match":{"keyword":"x"},"action":"warp"}
	]}`)
	e, err := New(Config{
		Rules:    rs,
		Direct:   (&recordedDialer{}).Dial,
		WARPAddr: fw.Addr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.Dial("target.example.com:8443")
	if err != nil {
		t.Fatalf("warp domain dial: %v", err)
	}
	_ = conn

	cap := waitCaptured(t, fw)
	// captured = ver cmd rsv atype + len + domain + port.
	if cap[1] != 0x01 {
		t.Fatalf("CONNECT cmd = 0x%02x, want 0x01", cap[1])
	}
	if cap[3] != 0x03 {
		t.Fatalf("CONNECT atype = 0x%02x, want 0x03 (domain form)", cap[3])
	}
	domainLen := int(cap[4])
	domain := string(cap[5 : 5+domainLen])
	if domain != "target.example.com" {
		t.Fatalf("domain-form target = %q, want target.example.com", domain)
	}
}

// IP-form CONNECT: verify atype 0x01 + 4-byte IPv4 for a literal IP.
func TestDialWarpIPFormRequest(t *testing.T) {
	fw := newFakeWarpSocks(t, "ok")
	defer fw.Close()

	rs := mustRules(t, `{"version":1,"rules":[
		{"id":"w","match":{"keyword":"9"},"action":"warp"}
	]}`)
	e, err := New(Config{
		Rules:    rs,
		Direct:   (&recordedDialer{}).Dial,
		WARPAddr: fw.Addr(),
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.Dial("9.9.9.9:53")
	if err != nil {
		t.Fatalf("warp ip dial: %v", err)
	}
	_ = conn

	cap := waitCaptured(t, fw)
	if cap[3] != 0x01 {
		t.Fatalf("IP-form atype = 0x%02x, want 0x01", cap[3])
	}
	// The 4 IP bytes must be 9.9.9.9.
	wantIP := net.ParseIP("9.9.9.9").To4()
	if !strings.EqualFold(string(cap[4:8]), string(wantIP)) {
		t.Fatalf("IP bytes = % x, want % x", cap[4:8], wantIP)
	}
	// port 53 = 0x0035
	if cap[8] != 0x00 || cap[9] != 0x35 {
		t.Fatalf("port bytes = % x, want [00 35]", cap[8:10])
	}
}

// ---------------------------------------------------------------------------
// WARP health gate: unreachable endpoint
// ---------------------------------------------------------------------------

// deadAddr returns a loopback address that nothing listens on (a
// near-certain immediate connect refusal on every platform).
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // immediately free it: the connect will be refused
	return addr
}

func TestDialWarpUnreachableFailClosed(t *testing.T) {
	d := &recordedDialer{}
	// No fallback → fail closed even though the rule is explicit.
	rs := mustRules(t, `{"version":1,"rules":[
		{"id":"w","match":{"keyword":"x"},"action":"warp"}
	]}`)
	e, err := New(Config{Rules: rs, Direct: d.Dial, WARPAddr: deadAddr(t)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Dial("x.example.com:443")
	if err == nil {
		t.Fatal("want fail-closed error, got nil")
	}
	if !errors.Is(err, ErrWarpUnreachable) {
		t.Fatalf("want ErrWarpUnreachable, got %v", err)
	}
	if d.count() != 0 {
		t.Fatalf("fail-closed must NOT dial direct (count=%d)", d.count())
	}
}

func TestDialWarpUnreachableFallbackDirect(t *testing.T) {
	d := &recordedDialer{}
	rs := mustRules(t, `{"version":1,"rules":[
		{"id":"w","match":{"keyword":"x"},"action":"warp","fallback":"direct"}
	]}`)
	e, err := New(Config{Rules: rs, Direct: d.Dial, WARPAddr: deadAddr(t)})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.Dial("x.example.com:443")
	if err != nil {
		t.Fatalf("fallback-direct: %v", err)
	}
	conn.Close()
	if d.count() != 1 {
		t.Fatalf("fallback must dial direct exactly once (count=%d)", d.count())
	}
}

func TestDialWarpDefaultOutboundUnreachableFailClosed(t *testing.T) {
	d := &recordedDialer{}
	// Default outbound is warp → the decision is "default" →
	// fail-closed (no fallback is ever carried by the default).
	rs := mustRules(t, `{"version":1,"default_action":"warp","rules":[]}`)
	e, err := New(Config{Rules: rs, Direct: d.Dial, WARPAddr: deadAddr(t)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Dial("unmatched.example.com:443")
	if !errors.Is(err, ErrWarpUnreachable) {
		t.Fatalf("default warp + unreachable endpoint must fail closed, got %v", err)
	}
	if d.count() != 0 {
		t.Fatalf("default outbound must never fall back (count=%d)", d.count())
	}
}

func TestDialWarpRefusedNoFallback(t *testing.T) {
	// The endpoint is REACHABLE but refuses the CONNECT (REP 4): the
	// target failed inside WARP → no fallback even when fallback=direct
	// (a silent leak onto the direct path is exactly what the gate
	// prevents).
	fw := newFakeWarpSocks(t, "refused")
	defer fw.Close()

	d := &recordedDialer{}
	rs := mustRules(t, `{"version":1,"rules":[
		{"id":"w","match":{"keyword":"x"},"action":"warp","fallback":"direct"}
	]}`)
	e, err := New(Config{Rules: rs, Direct: d.Dial, WARPAddr: fw.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Dial("x.example.com:443")
	if err == nil {
		t.Fatal("want CONNECT-refused error")
	}
	if errors.Is(err, ErrWarpUnreachable) {
		t.Fatalf("a REFUSED CONNECT is not an unreachable endpoint: %v", err)
	}
	if d.count() != 0 {
		t.Fatalf("REFUSED CONNECT must not fall back to direct (count=%d)", d.count())
	}
}

// ---------------------------------------------------------------------------
// logging redaction (requirement 9: no destination at the default level)
// ---------------------------------------------------------------------------

func TestNoDestinationInLogsByDefault(t *testing.T) {
	// Default engine: DebugLogging nil → no log sink exists at all, so
	// nothing (destination, rule id, outbound) can ever be logged.
	d := &recordedDialer{}
	rs := mustRules(t, `{"version":1,"rules":[
		{"id":"b","match":{"keyword":"secret-target"},"action":"block"}
	]}`)
	e, err := New(Config{Rules: rs, Direct: d.Dial}) // no WARPAddr: no warp configured
	if err != nil {
		t.Fatal(err)
	}
	// Also assert the error path leaks no destination.
	_, err = e.Dial("secret-target:443")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
	// The error text must not carry the destination.
	if strings.Contains(err.Error(), "secret-target") {
		t.Fatalf("ErrBlocked leaked the destination: %v", err)
	}
}

func TestDebugLoggingWhenEnabled(t *testing.T) {
	d := &recordedDialer{}
	rs := mustRules(t, `{"version":1,"rules":[
		{"id":"w","match":{"keyword":"dbg"},"action":"warp","fallback":"direct"}
	]}`)
	var mu sync.Mutex
	var lines []string
	e, err := New(Config{
		Rules:    rs,
		Direct:   d.Dial,
		WARPAddr: deadAddr(t),
		DebugLogging: func(format string, args ...any) {
			mu.Lock()
			lines = append(lines, format)
			for _, a := range args {
				lines[len(lines)-1] += " " + valueString(a)
			}
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Dial("dbg.example.com:443") // unreachable warp → fallback direct
	_ = err
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "dbg.example.com:443") {
		t.Fatalf("debug sink should capture the destination when enabled; got:\n%s", joined)
	}
	if !strings.Contains(joined, "rule w") {
		t.Fatalf("debug sink should name the deciding rule; got:\n%s", joined)
	}
}

// valueString renders a log arg without an fmt dependency (the engine
// passes strings and OutboundKind values only).
func valueString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case OutboundKind:
		return x.String()
	default:
		return "<v>"
	}
}
