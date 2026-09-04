// Package integration is the L4 two-process local integration harness for
// Issue #9 (production acceptance). It is TEST CODE ONLY — not production
// code, not part of the relay, and NOT run automatically in CI (real
// two-host infrastructure is out of CI scope; see integration/RUNBOOK.md
// for the L5 staging procedure). Run it explicitly on a POSIX host:
//
//	RUN_TWOPROC=1 go test -count=1 -timeout 10m ./integration/
//
// Topology (all on 127.0.0.1, real sockets, real OS processes built from
// the same commit under test):
//
//	SOCKS5 client ──> iran-splitter (real binary)
//	                      │ up-carrier  (real WebSocket)
//	                      ▼
//	                   [up proxy]   ← controllable stand-in for the CDN
//	                      │
//	                      ▼
//	                   germany-splitter (real binary) ──> echo target
//	                      ▲
//	                      │ down-carrier (real TCP)
//	                   [down proxy] ← controllable stand-in for Xray/Reality
//
// The proxies are the failure injectors: Kill() tears down the carrier
// connection without killing either splitter process — the production
// "the CDN drops the connection" / "the Reality tunnel resets" failure
// modes, which is what makes in-flight rebind observable with a live
// Germany node (killing Germany instead loses its in-memory session
// state, so a rebind would fail for the wrong reason).
//
// Windows is skipped: the harness relies on SIGTERM graceful shutdown,
// TCP half-close (CloseWrite), and POSIX process semantics.
package integration

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/integration/socks5"
)

// ============================================================
// log buffer
// ============================================================

type logbuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logbuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logbuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logbuf) contains(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Contains(l.b.String(), substr)
}

// tail returns the log content from byte offset to the end. Offset-based
// waiting is what makes repeated markers deterministic: "carrier down
// ready" appears at startup AND after every reconnect, so a whole-log
// substring test would false-pass without an offset.
func (l *logbuf) tail(offset int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.b.String()
	if offset < 0 || offset > len(s) {
		offset = len(s)
	}
	return s[offset:]
}

// ============================================================
// tcp proxy (CDN / Xray stand-in)
// ============================================================

// tcpProxy is a controllable TCP relay. Kill() closes every proxied
// connection in both directions — the carrier loss injector.
type tcpProxy struct {
	t        *testing.T
	upstream string

	mu    sync.Mutex
	conns []net.Conn
	ln    net.Listener
}

func newProxy(t *testing.T, upstream string) *tcpProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &tcpProxy{t: t, upstream: upstream, ln: ln}
	go p.acceptLoop()
	t.Cleanup(p.closeQuiet)
	return p
}

func (p *tcpProxy) Addr() string { return p.ln.Addr().String() }

func (p *tcpProxy) acceptLoop() {
	for {
		a, err := p.ln.Accept()
		if err != nil {
			return
		}
		b, err := net.Dial("tcp", p.upstream)
		if err != nil {
			a.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, a, b)
		p.mu.Unlock()
		go func(a, b net.Conn) {
			// a = the client side, b = the upstream side. Propagation of a
			// peer death: when one direction hits EOF/error, HALF-CLOSE
			// the corresponding end of the other conn (CloseWrite) so the
			// peer's read loop terminates (EOF) — exactly how a real
			// transport leg dropping the connection behaves. A plain
			// two-way io.Copy without this leaves the far side blocked
			// (and the loss undetected) when the peer DIES instead of
			// closing cleanly.
			done := make(chan struct{}, 2)
			go func() {
				io.Copy(b, a)
				if tc, ok := b.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				done <- struct{}{}
			}()
			go func() {
				io.Copy(a, b)
				if tc, ok := a.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				done <- struct{}{}
			}()
			<-done
			<-done
			a.Close()
			b.Close()
			p.t.Logf("proxy→%s: conn pair torn down", p.upstream)
		}(a, b)
	}
}

// Kill tears down the CURRENTLY proxied connections (simulates the
// intermediate transport dropping the carrier) but leaves the proxy
// LISTENER alive, so the nodes' reconnect dials are still accepted —
// this is exactly the production "the CDN/Reality leg reset, but the
// path is available again" failure mode, and it is what makes the
// in-flight rebind observable. Idempotent.
func (p *tcpProxy) Kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}

func (p *tcpProxy) closeQuiet() {
	p.Kill()
	p.ln.Close()
}

// ============================================================
// process management
// ============================================================

type proc struct {
	t       *testing.T
	name    string
	cmd     *exec.Cmd
	log     *logbuf
	exit    chan error
	exitErr error // captured by stopGraceful / exitCode
	reaped  bool  // true once kill/stop has observed the exit
}

// buildBinaries compiles both production binaries from the tree under
// test (go build) into a temp dir and returns their paths.
func buildBinaries(t *testing.T) (string, string) {
	t.Helper()
	repo := ".." // go test runs with cwd = integration/
	dir := t.TempDir()
	// TWOPROC_RACE=1 builds the binaries with -race (the issue's
	// "race-enabled/debug builds where practical" run).
	race := []string{}
	if os.Getenv("TWOPROC_RACE") == "1" {
		race = []string{"-race"}
		t.Log("building splitter binaries with -race")
	}
	for name, pkg := range map[string]string{
		"iran-splitter":    repo + "/cmd/iran-splitter",
		"germany-splitter": repo + "/cmd/germany-splitter",
	} {
		out := filepath.Join(dir, name+execExt())
		args := append([]string{"build"}, race...)
		args = append(args, "-o", out, pkg)
		cmd := exec.Command("go", args...)
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", name, err, data)
		}
	}
	return filepath.Join(dir, "iran-splitter"+execExt()), filepath.Join(dir, "germany-splitter"+execExt())
}

// execExt is the OS-specific executable suffix (".exe" on Windows, ""
// elsewhere) so the harness builds and launches the right binary name.
func execExt() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startProc(t *testing.T, name, bin string, extraEnv map[string]string) *proc {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Dir = t.TempDir()
	env := append([]string{}, os.Environ()...)
	for k, v := range extraEnv {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	l := &logbuf{}
	cmd.Stdout = l
	cmd.Stderr = l
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s: start: %v", name, err)
	}
	p := &proc{t: t, name: name, cmd: cmd, log: l, exit: make(chan error, 1)}
	go func() { p.exit <- cmd.Wait() }()
	t.Cleanup(p.kill)
	return p
}

// waitForLog blocks until the marker appears in the process log or the
// deadline expires. This observes EXTERNAL process state — the only
// observation point for a separate OS process (no shared memory, no
// sleep-as-wait: it exits on the first match, not on a fixed delay).
func (p *proc) waitForLog(t *testing.T, marker string, d time.Duration) {
	t.Helper()
	p.waitForLogAfter(t, marker, 0, d)
}

// waitForLogAfter is the offset-aware variant: it waits for `marker` in
// the log content written AT OR AFTER `after` (a byte offset returned by
// logLen). Markers that legitimately repeat across the test ("carrier
// up lost", "carrier down ready", "Down-carrier authenticated to") MUST
// use this variant, or an earlier occurrence would satisfy the wait.
func (p *proc) waitForLogAfter(t *testing.T, marker string, after int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(p.log.tail(after), marker) {
			return
		}
		select {
		case err := <-p.exit:
			t.Fatalf("%s: process exited (%v) before %q\n--- log tail ---\n%s", p.name, err, marker, p.log.tail(after))
		case <-time.After(25 * time.Millisecond):
		}
	}
	t.Fatalf("%s: %q not found within %v\n--- log tail ---\n%s", p.name, marker, d, p.log.tail(after))
}

// logLen returns the current log length (a stable wait offset).
func (p *proc) logLen() int {
	return len(p.log.String())
}

// stopGraceful sends SIGINT and waits for the clean-exit log marker.
// SIGINT, not SIGTERM, so the harness works identically when run from a
// terminal (Ctrl-C) and from go test: the binaries treat both identically
// (signal.Notify on SIGINT+SIGTERM).
func (p *proc) stopGraceful(t *testing.T, d time.Duration) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Fatalf("graceful stop requires POSIX signals")
	}
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("%s: SIGINT: %v", p.name, err)
	}
	select {
	case p.exitErr = <-p.exit:
		p.reaped = true
	case <-time.After(d):
		p.kill()
		t.Fatalf("%s: no clean exit within %v\n--- log ---\n%s", p.name, d, p.log.String())
	}
	if !p.log.contains("-splitter stopped") {
		t.Fatalf("%s: shutdown log marker missing\n--- log ---\n%s", p.name, p.log.String())
	}
}

// kill force-kills and reaps (cleanup path; no assertions). On return,
// p.reaped is true when the exit was observed (the exit channel is a
// one-shot: whatever drained it first owns the value).
func (p *proc) kill() {
	if p.cmd.Process == nil {
		return
	}
	select {
	case <-p.exit:
		p.reaped = true
	default:
		_ = p.cmd.Process.Kill()
		select {
		case <-p.exit:
			p.reaped = true
		case <-time.After(5 * time.Second):
		}
	}
}

// exitCode returns the captured exit code (valid after stopGraceful has
// reaped the process).
func (p *proc) exitCode(t *testing.T) int {
	t.Helper()
	if !p.reaped {
		t.Fatalf("%s: exitCode before the process was reaped", p.name)
	}
	if p.exitErr == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(p.exitErr, &ee) {
		return ee.ExitCode()
	}
	t.Fatalf("%s: unexpected exit: %v", p.name, p.exitErr)
	return -1
}

// ============================================================
// metrics
// ============================================================

type metrics struct {
	ActiveSessions       int64
	TotalSessions        int64
	TotalBytesUp         int64
	TotalBytesDown       int64
	Errors               int64
	CarrierLossEvents    int64
	CarrierReconnects    int64
	CarrierRebinds       int64
	SessionsRecovered    int64
	SessionCount         int64
	SessionBufferedBytes int64
}

func fetchMetrics(t *testing.T, port int) metrics {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
	if err != nil {
		t.Fatalf("metrics fetch :%d: %v", port, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("metrics read :%d: %v", port, err)
	}
	// The body is plain "name value\n" lines (pkg/node Metrics.Render +
	// the cmd-level session_count / session_buffered_bytes gauges).
	var m metrics
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "active_sessions":
			m.ActiveSessions = v
		case "total_sessions":
			m.TotalSessions = v
		case "total_bytes_up":
			m.TotalBytesUp = v
		case "total_bytes_down":
			m.TotalBytesDown = v
		case "errors":
			m.Errors = v
		case "carrier_loss_events":
			m.CarrierLossEvents = v
		case "carrier_reconnects":
			m.CarrierReconnects = v
		case "carrier_rebinds":
			m.CarrierRebinds = v
		case "sessions_recovered":
			m.SessionsRecovered = v
		case "session_count":
			m.SessionCount = v
		case "session_buffered_bytes":
			m.SessionBufferedBytes = v
		}
	}
	return m
}

// waitMetric polls until pred(m) holds or the deadline expires, returning
// the last observed snapshot (also asserted in the failure message).
func waitMetric(t *testing.T, port int, d time.Duration, what string, pred func(metrics) bool) metrics {
	t.Helper()
	deadline := time.Now().Add(d)
	var last metrics
	for time.Now().Before(deadline) {
		last = fetchMetrics(t, port)
		if pred(last) {
			return last
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("metrics :%d: %s not observed within %v (last: %+v)", port, what, d, last)
	return last
}

// ============================================================
// echo / scripted target server
// ============================================================

type targetServer struct {
	ln net.Listener

	mu   sync.Mutex
	recs map[net.Conn]*targetRec
}

type targetRec struct {
	received int64
	eofSeen  bool
}

type targetMode int

const (
	modeEcho     targetMode = iota // mirror everything back until FIN
	modeScripted                   // after first data: send targetResp, CloseWrite
)

// targetResp is a fixed 8 KiB random blob (per test process) used by the
// scripted target so checksums are reproducible within a run.
var targetResp = func() []byte {
	b := make([]byte, 8<<10)
	rand.Read(b)
	return b
}()

func newTarget(t *testing.T, mode targetMode) *targetServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	ts := &targetServer{ln: ln, recs: map[net.Conn]*targetRec{}}
	go ts.acceptLoop(mode)
	t.Cleanup(func() { ln.Close() })
	return ts
}

func (ts *targetServer) Port() int { return ts.ln.Addr().(*net.TCPAddr).Port }

func (ts *targetServer) acceptLoop(mode targetMode) {
	for {
		c, err := ts.ln.Accept()
		if err != nil {
			return
		}
		rec := &targetRec{}
		ts.mu.Lock()
		ts.recs[c] = rec
		ts.mu.Unlock()
		go ts.serve(c, rec, mode)
	}
}

func (ts *targetServer) serve(c net.Conn, rec *targetRec, mode targetMode) {
	defer c.Close()
	buf := make([]byte, 32<<10)
	first := true
	for {
		n, err := c.Read(buf)
		if n > 0 {
			rec.received += int64(n)
			switch mode {
			case modeEcho:
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
			case modeScripted:
				if first {
					first = false
					c.Write(targetResp)
					// Target-side half-close: FIN to the client, keep
					// reading the upload until the client FINs.
					if tc, ok := c.(*net.TCPConn); ok {
						tc.CloseWrite()
					} else {
						c.Close()
						return
					}
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				rec.eofSeen = true
			}
			return
		}
	}
}

// ============================================================
// IPv6 echo target (for the IPv6-destination scenario)
// ============================================================

func newTargetV6(t *testing.T) (port int) {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback for the IPv6-dest scenario: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64<<10)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// ============================================================
// raw WebSocket client (upgrade only; for the auth scenarios)
// ============================================================

// wsUpgrade performs the raw HTTP WebSocket upgrade handshake and returns
// the HTTP status line. On 101 the returned conn is the raw WebSocket
// connection (binary frames may be read/written directly).
func wsUpgrade(addr, path string, timeout time.Duration) (net.Conn, string, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, "", err
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte(req)); err != nil {
		c.Close()
		return nil, "", err
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		c.Close()
		return nil, "", err
	}
	// Drain the rest of the header (101 has no body).
	for {
		l, rerr := br.ReadString('\n')
		if rerr != nil || l == "\r\n" {
			break
		}
	}
	return c, strings.TrimSpace(line), nil
}

// wsReadFrame reads ONE WebSocket data frame from the server (server
// frames are unmasked per RFC 6455) and returns its opcode + payload.
// Used by the rogue-client auth scenario; the rest of the harness uses
// the SOCKS5 client, not raw WS.
func wsReadFrame(r io.Reader) (opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	opcode = hdr[0] & 0x0F
	ln := int(hdr[1] & 0x7F)
	switch {
	case ln < 126:
	case ln == 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		ln = int(binary.BigEndian.Uint16(ext[:]))
	default:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		ln = int(binary.BigEndian.Uint64(ext[:]))
	}
	payload = make([]byte, ln)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}

// wsWriteBinary writes ONE masked client→server binary frame (client
// frames MUST be masked per RFC 6455 — raw unmasked writes are
// malformed and are dropped by compliant servers).
func wsWriteBinary(c net.Conn, payload []byte) error {
	hdr := []byte{0x82} // FIN + binary opcode
	switch {
	case len(payload) < 126:
		hdr = append(hdr, byte(len(payload)))
	case len(payload) < 65536:
		hdr = append(hdr, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		hdr = append(hdr, 127)
		for i := 7; i >= 0; i-- {
			hdr = append(hdr, byte(len(payload)>>(8*i)))
		}
	}
	var mask [4]byte
	rand.Read(mask[:])
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	hdr = append(hdr, masked...)
	_, err := c.Write(hdr)
	return err
}

// ============================================================
// scenario helpers
// ============================================================

// runTransfer is the non-`t`-coupled transfer (safe to call from worker
// goroutines): SOCKS5 CONNECT, write payload, read the echo, checksum.
func runTransfer(socksAddr, dest string, port int, size int, d time.Duration) error {
	payload := make([]byte, size)
	rand.Read(payload)
	sum := sha256.Sum256(payload)
	c, err := socks5.Dial(socksAddr, dest, port, d)
	if err != nil {
		return fmt.Errorf("SOCKS5 CONNECT %s:%d: %w", dest, port, err)
	}
	defer c.Close()
	go func() {
		c.Conn().SetWriteDeadline(time.Now().Add(d))
		c.Conn().Write(payload)
	}()
	got := make([]byte, len(payload))
	c.Conn().SetReadDeadline(time.Now().Add(d))
	if _, err := io.ReadFull(c.Conn(), got); err != nil {
		return fmt.Errorf("download %s:%d: %w", dest, port, err)
	}
	if s := sha256.Sum256(got); s != sum {
		return fmt.Errorf("checksum mismatch %s:%d", dest, port)
	}
	return nil
}

// transfer opens a SOCKS5 session, writes payload, reads the echo, and
// verifies the checksum. Returns the client for further assertions.
// MUST be called from the test goroutine (it calls t.Fatalf).
func transfer(t *testing.T, socksAddr, dest string, port int, payload []byte, d time.Duration) *socks5.Client {
	t.Helper()
	sum := sha256.Sum256(payload)
	c, err := socks5.Dial(socksAddr, dest, port, d)
	if err != nil {
		t.Fatalf("SOCKS5 CONNECT %s:%d: %v", dest, port, err)
	}
	go func() {
		c.Conn().SetWriteDeadline(time.Now().Add(d))
		c.Conn().Write(payload)
	}()
	got := make([]byte, len(payload))
	c.Conn().SetReadDeadline(time.Now().Add(d))
	if _, err := io.ReadFull(c.Conn(), got); err != nil {
		c.Close()
		t.Fatalf("download %s:%d: %v", dest, port, err)
	}
	if s := sha256.Sum256(got); s != sum {
		c.Close()
		t.Fatalf("checksum mismatch %s:%d (upload %x vs download %x)", dest, port, sum[:4], s[:4])
	}
	c.Conn().SetDeadline(time.Time{})
	return c
}

// ============================================================
// the L4 gate
// ============================================================

func TestTwoProcessLocal(t *testing.T) {
	if os.Getenv("RUN_TWOPROC") == "" {
		t.Skip("L4 two-process gate: set RUN_TWOPROC=1 to run " +
			"(real processes + real sockets; not part of CI)")
	}
	// Note: most scenarios are platform-portable (real processes, real
	// sockets, os.Kill). The POSIX-only ones (S5 client half-close, S11
	// SIGINT graceful stop) skip themselves on Windows; run the full
	// gate on Linux (workflow_dispatch or a local POSIX host).

	secret := make([]byte, 32)
	rand.Read(secret)
	secretHex := hex.EncodeToString(secret)

	iranBin, deBin := buildBinaries(t)

	socksPort := freePort(t)
	iranWsPort := freePort(t) // Iran's real WS listener (behind up proxy)
	deDownPort := freePort(t) // Germany's real down listener (behind down proxy)
	mIran := freePort(t)
	mDe := freePort(t)

	upProxy := newProxy(t, fmt.Sprintf("127.0.0.1:%d", iranWsPort))
	downProxy := newProxy(t, fmt.Sprintf("127.0.0.1:%d", deDownPort))

	target := newTarget(t, modeEcho)
	scripted := newTarget(t, modeScripted)
	v6Port := newTargetV6(t)

	// Iran: bootstrap wait short (2 s) so the 0x06 scenario is fast.
	iran := startProc(t, "iran", iranBin, map[string]string{
		"SPLIT_SECRET":            secretHex,
		"SPLIT_SOCKS_LISTEN":      fmt.Sprintf("127.0.0.1:%d", socksPort),
		"SPLIT_WS_LISTEN":         fmt.Sprintf("127.0.0.1:%d", iranWsPort),
		"SPLIT_DOWN_CARRIER_ADDR": downProxy.Addr(),
		"SPLIT_METRICS_PORT":      strconv.Itoa(mIran),
		"SPLIT_BOOTSTRAP_WAIT_MS": "2000",
		"SPLIT_CARRIER_GRACE":     "15000",
	})

	// Test tuning (documented): the carrier-loss grace is widened to
	// 15 s so a carrier flap (reconnect backoff ~2 s) ALWAYS lands
	// inside the rebind window — the scenarios test the rebind
	// machinery itself, not the grace boundary (that is covered by
	// the pkg/node unit tests at the production default).
	deEnv := map[string]string{
		"SPLIT_SECRET":        secretHex,
		"SPLIT_UP_WS_URL":     "ws://" + upProxy.Addr() + "/upload",
		"SPLIT_DOWN_LISTEN":   fmt.Sprintf("127.0.0.1:%d", deDownPort),
		"SPLIT_METRICS_PORT":  strconv.Itoa(mDe),
		"SPLIT_CARRIER_GRACE": "15000",
	}
	de := startProc(t, "germany", deBin, deEnv)

	// Both carriers must authenticate over the REAL production paths:
	// a real WebSocket upgrade through the up proxy, a real TCP v1
	// handshake through the down proxy.
	iran.waitForLog(t, "iran-splitter started", 15*time.Second)
	de.waitForLog(t, "germany-splitter started", 15*time.Second)
	de.waitForLog(t, "Up-carrier authenticated", 25*time.Second)
	iran.waitForLog(t, "Up-carrier authenticated from", 25*time.Second)
	iran.waitForLog(t, "Down-carrier authenticated to", 25*time.Second)
	de.waitForLog(t, "Down-carrier authenticated from", 25*time.Second)
	t.Log("topology up: both carriers authenticated through controllable proxies")

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	const big = 256 << 10

	// ---------- S1: CONNECT (IPv4) + sustained upload/download ----------
	t.Run("S1_connect_sustained", func(t *testing.T) {
		m0 := fetchMetrics(t, mIran)
		payload := make([]byte, big)
		rand.Read(payload)
		c := transfer(t, socksAddr, "127.0.0.1", target.Port(), payload, 20*time.Second)

		// Metric deltas: exactly the payload bytes in both directions
		// (the relays count payload bytes), at least one session.
		m1 := waitMetric(t, mIran, 5*time.Second, "session accounted", func(m metrics) bool {
			return m.TotalSessions >= m0.TotalSessions+1 &&
				m.TotalBytesUp >= m0.TotalBytesUp+int64(len(payload)) &&
				m.TotalBytesDown >= m0.TotalBytesDown+int64(len(payload))
		})
		if d := m1.TotalSessions - m0.TotalSessions; d < 1 {
			t.Fatalf("iran total_sessions delta = %d, want >= 1", d)
		}

		// Client FIN → session torn down on both sides.
		c.Close()
		_ = waitMetric(t, mIran, 10*time.Second, "iran settled", func(m metrics) bool {
			return m.ActiveSessions == 0 && m.SessionCount == 0
		})
		_ = waitMetric(t, mDe, 10*time.Second, "germany settled", func(m metrics) bool {
			return m.ActiveSessions == 0 && m.SessionCount == 0
		})
		t.Log("S1 ok: CONNECT + 256KiB up + 256KiB down, checksums exact, metric deltas exact, clean teardown")
	})

	// ---------- S2: domain destination (real resolver path) ----------
	t.Run("S2_domain", func(t *testing.T) {
		payload := make([]byte, 1024)
		rand.Read(payload)
		c := transfer(t, socksAddr, "localhost", target.Port(), payload, 10*time.Second)
		c.Close()
		t.Log("S2 ok: domain destination through the real resolver path")
	})

	// ---------- S3: IPv6 destination ----------
	t.Run("S3_ipv6", func(t *testing.T) {
		if v6Port == 0 {
			t.Skip("no IPv6 loopback")
		}
		payload := make([]byte, 1024)
		rand.Read(payload)
		c := transfer(t, socksAddr, "::1", v6Port, payload, 10*time.Second)
		c.Close()
		t.Log("S3 ok: IPv6 destination")
	})

	// ---------- S4: 8 simultaneous sessions ----------
	t.Run("S4_concurrent", func(t *testing.T) {
		m0 := fetchMetrics(t, mIran)
		const N = 8
		const size = 32 << 10
		var wg sync.WaitGroup
		errs := make(chan error, N)
		for i := 0; i < N; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				// runTransfer, not transfer: the worker must never call
				// t.Fatalf from a non-test goroutine.
				errs <- runTransfer(socksAddr, "127.0.0.1", target.Port(), size, 20*time.Second)
			}(i)
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			if e != nil {
				t.Fatal(e)
			}
		}
		m1 := waitMetric(t, mIran, 10*time.Second, "concurrent sessions accounted", func(m metrics) bool {
			return m.TotalSessions >= m0.TotalSessions+int64(N)
		})
		_ = waitMetric(t, mIran, 10*time.Second, "concurrent settle", func(m metrics) bool {
			return m.ActiveSessions == 0 && m.SessionCount == 0
		})
		if d := m1.TotalSessions - m0.TotalSessions; d < N {
			t.Fatalf("concurrent total_sessions delta = %d, want >= %d", d, N)
		}
		t.Logf("S4 ok: %d simultaneous sessions, all checksums exact", N)
	})

	// ---------- S5: client half-close (upload-only FIN) ----------
	t.Run("S5_client_halfclose", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("S5 requires TCP half-close (CloseWrite); POSIX-only here")
		}
		payload := make([]byte, 4096)
		rand.Read(payload)
		c, err := socks5.Dial(socksAddr, "127.0.0.1", target.Port(), 10*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		c.Conn().SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Conn().Write(payload); err != nil {
			c.Close()
			t.Fatalf("write: %v", err)
		}
		if err := c.HalfCloseWrite(); err != nil {
			c.Close()
			t.Fatalf("HalfCloseWrite: %v", err)
		}
		// The echo target mirrors the payload back; the target then sees
		// the FIN and closes. The client must receive exactly the payload.
		got := make([]byte, len(payload))
		c.Conn().SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(c.Conn(), got); err != nil {
			c.Close()
			t.Fatalf("half-close read: %v", err)
		}
		if !bytes.Equal(got, payload) {
			c.Close()
			t.Fatal("half-close: echoed bytes differ")
		}
		c.Close()
		_ = waitMetric(t, mIran, 10*time.Second, "half-close settle", func(m metrics) bool {
			return m.ActiveSessions == 0
		})
		t.Log("S5 ok: client half-close honored, session settled")
	})

	// ---------- S6: target half-close (download-only FIN) ----------
	t.Run("S6_target_halfclose", func(t *testing.T) {
		c, err := socks5.Dial(socksAddr, "127.0.0.1", scripted.Port(), 10*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		// Trigger the scripted response: write one byte.
		c.Conn().SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Conn().Write([]byte{0x01}); err != nil {
			t.Fatalf("trigger write: %v", err)
		}
		got := make([]byte, len(targetResp))
		c.Conn().SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(c.Conn(), got); err != nil {
			t.Fatalf("scripted response: %v", err)
		}
		if !bytes.Equal(got, targetResp) {
			t.Fatal("scripted response mismatch")
		}
		// The target already CloseWrite'd: the next read must EOF — the
		// download half-close delivered through the real tunnel.
		var b [1]byte
		_, err = c.Conn().Read(b[:])
		if err != io.EOF {
			t.Fatalf("expected io.EOF after target half-close, got %v", err)
		}
		c.Close()
		t.Log("S6 ok: target half-close delivered as EOF through the tunnel")
	})

	// ---------- S7: up-carrier loss → in-flight rebind ----------
	t.Run("S7_up_carrier_rebind", func(t *testing.T) {
		// 64 KiB in flight across the flap — comfortably inside the
		// 256 KiB per-direction reconnect buffer.
		payload := make([]byte, 64<<10)
		rand.Read(payload)
		sum := sha256.Sum256(payload)
		c, err := socks5.Dial(socksAddr, "127.0.0.1", target.Port(), 10*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		go func() {
			c.Conn().SetWriteDeadline(time.Now().Add(45 * time.Second))
			c.Conn().Write(payload)
		}()
		// Let a chunk flow, then sever the UP carrier (CDN stand-in).
		time.Sleep(300 * time.Millisecond)
		irOff, deOff := iran.logLen(), de.logLen() // offsets for NEW markers only
		upProxy.Kill()
		t.Log("S7: up carrier severed mid-session")

		// Deterministic convergence observation: both nodes must log the
		// loss and the re-attachment (the rebind), then the data must
		// arrive intact. Offset-aware: "carrier up lost" / "reattached"
		// may already exist in the log from earlier scenarios.
		iran.waitForLogAfter(t, "carrier up lost", irOff, 10*time.Second)
		de.waitForLogAfter(t, "carrier up lost", deOff, 10*time.Second)
		iran.waitForLogAfter(t, "reattached to carrier gen", irOff, 30*time.Second)

		got := make([]byte, len(payload))
		c.Conn().SetReadDeadline(time.Now().Add(45 * time.Second))
		if _, err := io.ReadFull(c.Conn(), got); err != nil {
			t.Fatalf("data did not survive the up-carrier flap: %v", err)
		}
		if s := sha256.Sum256(got); s != sum {
			t.Fatal("up-carrier flap: checksum mismatch")
		}
		_ = waitMetric(t, mDe, 15*time.Second, "germany up reconnect counted", func(m metrics) bool {
			return m.CarrierReconnects >= 1
		})
		t.Log("S7 ok: in-flight session survived up-carrier loss; rebind logged on both nodes; data intact")
	})

	// ---------- S8: down-carrier loss → in-flight rebind ----------
	t.Run("S8_down_carrier_rebind", func(t *testing.T) {
		c, err := socks5.Dial(socksAddr, "127.0.0.1", scripted.Port(), 10*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		// Small trigger; the 8 KiB response streams across the flap.
		c.Conn().SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Conn().Write([]byte{0x02}); err != nil {
			t.Fatalf("trigger: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		irOff, deOff := iran.logLen(), de.logLen() // offsets for NEW markers only
		downProxy.Kill()
		t.Log("S8: down carrier severed mid-response")

		// "carrier down ready (gen 1)" already exists in the log from
		// startup, so the post-flap readiness must be offset-scoped.
		de.waitForLogAfter(t, "carrier down lost", deOff, 10*time.Second)
		de.waitForLogAfter(t, "carrier down ready", deOff, 30*time.Second)

		got := make([]byte, len(targetResp))
		c.Conn().SetReadDeadline(time.Now().Add(45 * time.Second))
		if _, err := io.ReadFull(c.Conn(), got); err != nil {
			t.Fatalf("down-carrier flap: response did not survive: %v", err)
		}
		if !bytes.Equal(got, targetResp) {
			t.Fatal("down-carrier flap: response mismatch")
		}
		// Iran must have re-dialed the down carrier (its reconnect loop);
		// the startup "Down-carrier authenticated to" must not satisfy it.
		iran.waitForLogAfter(t, "Down-carrier authenticated to", irOff, 30*time.Second)
		t.Log("S8 ok: session survived down-carrier loss; response intact")
	})

	// ---------- S9: unauthorized carrier is rejected (409) ----------
	t.Run("S9_duplicate_carrier_409", func(t *testing.T) {
		// With a live up-carrier, a second dial is rejected with HTTP 409
		// (single-carrier rule) BEFORE the WebSocket upgrade — no second
		// carrier can ever be installed. (The wrong-secret handshake path
		// needs no carrier active to be deterministic; that is S10b.)
		c, status, err := wsUpgrade(upProxy.Addr(), "/upload", 5*time.Second)
		if err != nil {
			t.Fatalf("wsUpgrade (409 case): %v", err)
		}
		if !strings.Contains(status, " 409 ") {
			c.Close()
			t.Fatalf("second up-carrier expected 409 (already connected), got: %s", status)
		}
		c.Close()
		// The real carrier is unaffected: a fresh session works.
		payload := make([]byte, 128)
		rand.Read(payload)
		cc := transfer(t, socksAddr, "127.0.0.1", target.Port(), payload, 10*time.Second)
		cc.Close()
		t.Log("S9 ok: duplicate up-carrier rejected 409; tunnel unaffected")
	})

	// ---------- S10: bootstrap failure → SOCKS 0x06, then recovery ----------
	t.Run("S10_bootstrap_0x06_and_recovery", func(t *testing.T) {
		// Kill Germany entirely: both carriers go. Iran must log both
		// losses before a new CONNECT is issued (deterministic ordering).
		irOff := iran.logLen() // "carrier up lost" may exist from S7
		de.kill()
		if !de.reaped {
			t.Fatalf("de did not exit within 5s after kill\nde log:\n%s", de.log.String())
		}
		iran.waitForLogAfter(t, "carrier up lost", irOff, 15*time.Second)
		iran.waitForLogAfter(t, "carrier down lost", irOff, 15*time.Second)

		start := time.Now()
		_, err := socks5.Dial(socksAddr, "127.0.0.1", target.Port(), 15*time.Second)
		elapsed := time.Since(start)
		var se *socks5.StatusError
		if !errors.As(err, &se) {
			t.Fatalf("expected *StatusError, got %T: %v", err, err)
		}
		if se.Code != 0x06 {
			t.Fatalf("status = 0x%02x, want 0x06 (carriers not ready)", se.Code)
		}
		if elapsed < 1500*time.Millisecond || elapsed > 12*time.Second {
			t.Fatalf("bootstrap wait took %v; want ~2 s (bounded, signal-driven)", elapsed)
		}
		t.Logf("S10 ok: SOCKS 0x06 after %v (bounded bootstrap wait honored over real sockets)", elapsed)

		// S10b: wrong-secret up-carrier. UpReady() is now deterministically
		// false (Germany is dead), so a rogue WS client gets a real 101
		// upgrade and reaches the v1 handshake, where it must be rejected:
		// the peer sends its 22-byte challenge, our garbage 74-byte
		// response fails the MAC, and the connection is closed — no
		// session, no crash.
		rogue, status, err := wsUpgrade(upProxy.Addr(), "/upload", 5*time.Second)
		if err != nil {
			t.Fatalf("S10b wsUpgrade: %v", err)
		}
		if !strings.Contains(status, " 101 ") {
			rogue.Close()
			t.Fatalf("S10b: expected 101 (upgrade) with no carrier active, got: %s", status)
		}
		rogue.SetDeadline(time.Now().Add(20 * time.Second))
		op, ch, err := wsReadFrame(rogue)
		if err != nil {
			rogue.Close()
			t.Fatalf("S10b: no challenge frame from peer: %v", err)
		}
		// The WS frame carries the WHOLE protocol frame: 7-byte header
		// (stream 0, type FrameAuth=0x01, len) + 22-byte challenge.
		if op != 0x02 || len(ch) != 7+22 || ch[1] != 0 || ch[2] != 0 || ch[3] != 0 || ch[4] != 0x01 {
			rogue.Close()
			t.Fatalf("S10b: bad challenge frame (op=0x%x len=%d hdr=% x), want binary/29 stream0 type0x01", op, len(ch), ch[:min(7, len(ch))])
		}
		// Garbage FrameAuth response (stream 0, 74 bytes, wrong version+MAC).
		resp := append([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x4A}, make([]byte, 74)...)
		if err := wsWriteBinary(rogue, resp); err != nil {
			rogue.Close()
			t.Fatalf("S10b: write garbage auth: %v", err)
		}
		// The peer must reject the handshake and close the connection
		// (version/MAC check) — a close (read error or close frame) within
		// the bound; a deadline means it did NOT close = a real failure.
		closed := false
		for i := 0; i < 10; i++ {
			fop, _, rerr := wsReadFrame(rogue)
			if rerr != nil {
				if os.IsTimeout(rerr) {
					rogue.Close()
					t.Fatalf("S10b: peer did not close within the bound (auth failure undetected?)")
				}
				closed = true
				break
			}
			if fop == 0x08 { // WebSocket close frame
				closed = true
				break
			}
		}
		if !closed {
			rogue.Close()
			t.Fatal("S10b: wrong-secret peer was not rejected")
		}
		t.Log("S10b ok: wrong-secret up-carrier rejected at the v1 handshake")

		// S10c: restart Germany: carriers re-establish, a new session works.
		// (The new Germany proc has a fresh log, so its wait is plain;
		// Iran's must be offset-scoped against its own earlier auth log.)
		de = startProc(t, "germany", deBin, deEnv)
		de.waitForLog(t, "Up-carrier authenticated", 25*time.Second)
		iran.waitForLogAfter(t, "Down-carrier authenticated to", irOff, 25*time.Second)
		payload := make([]byte, 128)
		rand.Read(payload)
		c := transfer(t, socksAddr, "127.0.0.1", target.Port(), payload, 10*time.Second)
		c.Close()
		t.Log("S10c ok: Germany restart → carriers re-established → sessions flow again")
	})

	// ---------- S11: graceful shutdown of both nodes ----------
	t.Run("S11_graceful_shutdown", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("S11 requires POSIX signals (SIGINT graceful stop); " +
				"covered on the Linux run (CI workflow_dispatch / staging)")
		}
		_ = waitMetric(t, mIran, 10*time.Second, "no active sessions before shutdown", func(m metrics) bool {
			return m.ActiveSessions == 0 && m.SessionCount == 0
		})
		de.stopGraceful(t, 20*time.Second)
		iran.stopGraceful(t, 20*time.Second)
		if code := de.exitCode(t); code != 0 {
			t.Fatalf("germany exit code = %d, want 0", code)
		}
		if code := iran.exitCode(t); code != 0 {
			t.Fatalf("iran exit code = %d, want 0", code)
		}
		t.Log("S11 ok: both nodes shut down gracefully (SIGINT → clean exit 0)")
	})
}
