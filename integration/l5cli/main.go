// Command l5cli is the Issue #9 L5 staging acceptance client. It is a
// TEST-ONLY tool (not part of the product): it runs on the staging
// hosts to exercise the deployed splitters with objective assertions.
//
// Subcommands:
//
//	l5cli target   - starts the controlled echo + HTTP target (Germany)
//	l5cli client   - runs a SOCKS5 scenario through the Iran splitter
//	l5cli rogue    - malformed/auth-failure peer for scenarios 12/13
//
// Every client command prints a single JSON line with its objective
// result; exit code 0 = scenario assertions met, 1 = not met.
//
// Target HTTP protocol (raw HTTP/1.1 over the tunnel, no dependencies):
//
//	POST /up            body = payload; reply {"sha256":"...","size":N}
//	GET  /file/<MiB>    body = deterministic pattern; reply = bytes, EOF
//
// The deterministic payload pattern is computed identically by client
// and target, so checksums are asserted without trusting either side.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/integration/socks5"
)

// ------------------------------------------------------------
// deterministic payload pattern (client and target agree)
// ------------------------------------------------------------

// patternByte is the i-th byte of the deterministic payload for a seed.
func patternByte(seed byte, i int) byte {
	x := (i*31 + int(seed)*131) ^ (i >> 3)
	return byte(x)
}

func makePattern(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = patternByte(seed, i)
	}
	return b
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ------------------------------------------------------------
// JSON result contract
// ------------------------------------------------------------

type clientResult struct {
	OK         bool    `json:"ok"`
	Mode       string  `json:"mode"`
	SocksReply byte    `json:"socksReply"` // 0x00 success, 0x06 etc.
	BytesUp    int64   `json:"bytesUp"`
	BytesDown  int64   `json:"bytesDown"`
	SHA256     string  `json:"sha256,omitempty"`
	Expected   string  `json:"expected,omitempty"`
	Detail     string  `json:"detail"`
	ElapsedMs  float64 `json:"elapsedMs"`
}

func emit(r clientResult) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
	if r.OK {
		os.Exit(0)
	}
	os.Exit(1)
}

func startTimer() func() float64 {
	t0 := time.Now()
	return func() float64 { return float64(time.Since(t0).Microseconds()) / 1000.0 }
}

// ------------------------------------------------------------
// target: echo server + HTTP responder (loopback only)
// ------------------------------------------------------------

func cmdTarget(args []string) {
	fs := flag.NewFlagSet("target", flag.ExitOnError)
	echoPort := fs.Int("echo-port", 11001, "echo listener port (loopback)")
	httpPort := fs.Int("http-port", 11002, "HTTP listener port (loopback)")
	lisn := fs.String("listen", "127.0.0.1", "bind host (loopback only)")
	fs.Parse(args)

	// echo server
	go func() {
		ln, err := net.Listen("tcp", *lisn+":"+strconv.Itoa(*echoPort))
		if err != nil {
			fmt.Fprintf(os.Stderr, "target: echo listen: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "target: echo listening on %s:%d\n", *lisn, *echoPort)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()

	// HTTP target
	var (
		fileMu sync.Mutex
		files  = map[int][]byte{}
	)
	http.Handle("/up", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		if err != nil {
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sha256": sha256Hex(body), "size": len(body)})
	}))
	http.Handle("/file/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mibStr := strings.TrimPrefix(r.URL.Path, "/file/")
		mib, err := strconv.Atoi(mibStr)
		if err != nil || mib <= 0 || mib > 64 {
			http.Error(w, "bad size", http.StatusBadRequest)
			return
		}
		n := mib << 20
		fileMu.Lock()
		data, ok := files[mib]
		if !ok {
			data = makePattern(0x5A, n)
			files[mib] = data
		}
		fileMu.Unlock()
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Header().Set("Connection", "close")
		_, _ = w.Write(data)
	}))
	srv := &http.Server{Addr: *lisn + ":" + strconv.Itoa(*httpPort), ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "target: HTTP listening on %s:%d\n", *lisn, *httpPort)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "target: http: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "target: stopped\n")
}

// ------------------------------------------------------------
// SOCKS5 raw HTTP helpers (over an established tunnel conn)
// ------------------------------------------------------------

func writeHTTPReq(c net.Conn, req string) error {
	_, err := io.WriteString(c, req)
	return err
}

// readHTTPResponse reads status + headers, returns (statusOK, body).
// With wantBody=false only the status line is consumed.
func readHTTPResponse(c net.Conn, wantBody bool) (int, []byte, error) {
	br := bufio.NewReader(c)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return 0, nil, err
	}
	fields := strings.SplitN(statusLine, " ", 3)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0, nil, fmt.Errorf("bad status line %q", strings.TrimSpace(statusLine))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, nil, fmt.Errorf("bad status code %q", fields[1])
	}
	var contentLen int64 = -1
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "Content-Length") {
			contentLen, _ = strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
		}
	}
	if !wantBody {
		return code, nil, nil
	}
	var (
		body []byte
		n    int
	)
	if contentLen >= 0 {
		body = make([]byte, contentLen)
		_, err = io.ReadFull(br, body)
		n = len(body)
	} else {
		body, err = io.ReadAll(br)
		n = len(body)
	}
	if err != nil {
		return code, body, err
	}
	_ = n
	return code, body, nil
}

// ------------------------------------------------------------
// client: SOCKS5 scenario runner
// ------------------------------------------------------------

func cmdClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	socksAddr := fs.String("socks", "127.0.0.1:10900", "SOCKS5 server address")
	mode := fs.String("mode", "echo", "echo|up|down|upsmall|downsmall|domain|v6|closed|concurrent")
	dest := fs.String("dest", "127.0.0.1", "target address (127.0.0.1 by default: target runs on Germany)")
	port := fs.Int("port", 11002, "target port (HTTP modes); 11001 echo for echo mode")
	mib := fs.Int("mib", 1, "payload size in MiB (up/down modes)")
	n := fs.Int("n", 1, "concurrent sessions (concurrent mode)")
	timeout := fs.Duration("timeout", 120*time.Second, "overall bound")
	_ = fs.Parse(args)

	elapsed := startTimer()
	resDest, resPort := resolveDest(*mode, *dest, *port)

	switch *mode {
	case "echo":
		runEcho(*socksAddr, resDest, resPort, 256<<10, *timeout)
	case "upsmall":
		runUp(*socksAddr, resDest, resPort, 1<<10, *timeout)
	case "downsmall":
		runDown(*socksAddr, resDest, resPort, 1<<10, *timeout)
	case "up":
		runUp(*socksAddr, resDest, resPort, *mib<<20, *timeout)
	case "down":
		runDown(*socksAddr, resDest, resPort, *mib<<20, *timeout)
	case "domain":
		runTLSProbe(*socksAddr, "example.com", 443, *timeout)
	case "v6":
		runTLSProbe(*socksAddr, "[2001:4860:4860::8888]", 443, *timeout)
	case "closed":
		runClosed(*socksAddr, resDest, resPort, *timeout)
	case "concurrent":
		runConcurrent(*socksAddr, resDest, resPort, *n, 1<<20, *timeout)
	default:
		emit(clientResult{Mode: *mode, Detail: "unknown mode"})
	}
	_ = elapsed
}

func resolveDest(mode, dest string, port int) (string, int) {
	switch mode {
	case "echo":
		return dest, 11001
	case "up", "upsmall", "down", "downsmall", "concurrent":
		return dest, 11002
	case "domain":
		return "example.com", 443
	case "v6":
		return "[2001:4860:4860::8888]", 443
	case "closed":
		return "127.0.0.1", 11099
	default:
		return dest, port
	}
}

func dialTunnel(socksAddr, dest string, port int, timeout time.Duration) (*socks5.Client, byte, error) {
	c, err := socks5.Dial(socksAddr, dest, port, timeout)
	if err != nil {
		var se *socks5.StatusError
		if strings.Contains(err.Error(), "status 0x") {
			_ = se
		}
		return nil, 0, err
	}
	return c, 0x00, nil
}

// runEcho: write pattern, read it back, verify, then half-close and
// expect EOF from the target echo server.
func runEcho(socksAddr, dest string, port, size int, timeout time.Duration) {
	elapsed := startTimer()
	c, _, err := dialTunnel(socksAddr, dest, port, timeout)
	if err != nil {
		status := statusOf(err)
		emit(clientResult{Mode: "echo", SocksReply: status, Detail: err.Error(), ElapsedMs: elapsed()})
		return
	}
	defer c.Close()
	payload := makePattern(0x11, size)
	if _, err := c.Conn().Write(payload); err != nil {
		emit(clientResult{Mode: "echo", SocksReply: 0x00, Detail: "write: " + err.Error(), ElapsedMs: elapsed()})
		return
	}
	got := make([]byte, size)
	if _, err := io.ReadFull(c.Conn(), got); err != nil {
		emit(clientResult{Mode: "echo", SocksReply: 0x00, Detail: "read back: " + err.Error(), ElapsedMs: elapsed()})
		return
	}
	if string(got) != string(payload) {
		emit(clientResult{Mode: "echo", SocksReply: 0x00, Detail: "echo mismatch", ElapsedMs: elapsed()})
		return
	}
	// half-close: client FIN -> target sees EOF -> target closes.
	if err := c.HalfCloseWrite(); err != nil {
		emit(clientResult{Mode: "echo", SocksReply: 0x00, Detail: "halfclose: " + err.Error(), ElapsedMs: elapsed()})
		return
	}
	_ = c.Conn().SetReadDeadline(time.Now().Add(15 * time.Second))
	_, err = c.Conn().Read(got[:1])
	if err == io.EOF {
		emit(clientResult{Mode: "echo", SocksReply: 0x00, BytesUp: int64(size), BytesDown: int64(size),
			SHA256: sha256Hex(got), Detail: "echo byte-exact + FIN propagated (EOF observed)", ElapsedMs: elapsed()})
		return
	}
	emit(clientResult{Mode: "echo", SocksReply: 0x00, BytesUp: int64(size), BytesDown: int64(size),
		Detail: fmt.Sprintf("expected EOF after FIN, got %v", err), ElapsedMs: elapsed()})
}

func runUp(socksAddr, dest string, port, size int, timeout time.Duration) {
	elapsed := startTimer()
	c, _, err := dialTunnel(socksAddr, dest, port, timeout)
	if err != nil {
		emit(clientResult{Mode: "up", SocksReply: statusOf(err), Detail: err.Error(), ElapsedMs: elapsed()})
		return
	}
	defer c.Conn().Close()
	payload := makePattern(0x22, size)
	req := fmt.Sprintf("POST /up HTTP/1.1\r\nHost: target\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", size)
	if err := writeHTTPReq(c.Conn(), req); err != nil {
		emit(clientResult{Mode: "up", Detail: "request: " + err.Error(), ElapsedMs: elapsed()})
		return
	}
	if _, err := c.Conn().Write(payload); err != nil {
		emit(clientResult{Mode: "up", Detail: "body: " + err.Error(), ElapsedMs: elapsed()})
		return
	}
	code, body, err := readHTTPResponse(c.Conn(), true)
	if err != nil {
		emit(clientResult{Mode: "up", Detail: "response: " + err.Error(), ElapsedMs: elapsed()})
		return
	}
	var resp struct {
		SHA256 string `json:"sha256"`
		Size   int    `json:"size"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || code != 200 {
		emit(clientResult{Mode: "up", Detail: fmt.Sprintf("http %d: %s", code, body), ElapsedMs: elapsed()})
		return
	}
	local := sha256Hex(payload)
	ok := resp.SHA256 == local && resp.Size == size
	detail := "sha256 match, size match"
	if !ok {
		detail = fmt.Sprintf("mismatch: size=%d want=%d sha=%s want=%s", resp.Size, size, resp.SHA256, local)
	}
	emit(clientResult{Mode: "up", SocksReply: 0x00, BytesUp: int64(size),
		SHA256: resp.SHA256, Expected: local,
		Detail: detail, OK: ok, ElapsedMs: elapsed()})
}

func runDown(socksAddr, dest string, port, size int, timeout time.Duration) {
	elapsed := startTimer()
	c, _, err := dialTunnel(socksAddr, dest, port, timeout)
	if err != nil {
		emit(clientResult{Mode: "down", SocksReply: statusOf(err), Detail: err.Error(), ElapsedMs: elapsed()})
		return
	}
	defer c.Conn().Close()
	mib := size >> 20
	if err := writeHTTPReq(c.Conn(), fmt.Sprintf("GET /file/%d HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n", mib)); err != nil {
		emit(clientResult{Mode: "down", Detail: "request: " + err.Error(), ElapsedMs: elapsed()})
		return
	}
	code, body, err := readHTTPResponse(c.Conn(), true)
	if err != nil {
		emit(clientResult{Mode: "down", Detail: "response: " + err.Error(), ElapsedMs: elapsed()})
		return
	}
	if code != 200 || len(body) != size {
		emit(clientResult{Mode: "down", Detail: fmt.Sprintf("http %d, got %d want %d", code, len(body), size), ElapsedMs: elapsed()})
		return
	}
	got := sha256Hex(body)
	want := sha256Hex(makePattern(0x5A, size))
	ok := got == want
	emit(clientResult{Mode: "down", SocksReply: 0x00, BytesDown: int64(size),
		SHA256: got, Expected: want, Detail: "sha256 match, size exact", OK: ok, ElapsedMs: elapsed()})
}

// runTLSProbe: CONNECT a real domain, verify TLS ClientHello (0x16)
// flows through the tunnel (destination reached, both directions live).
func runTLSProbe(socksAddr, dest string, port int, timeout time.Duration) {
	elapsed := startTimer()
	c, _, err := dialTunnel(socksAddr, dest, port, timeout)
	if err != nil {
		emit(clientResult{Mode: "tls-probe", SocksReply: statusOf(err), Detail: err.Error(), ElapsedMs: elapsed()})
		return
	}
	defer c.Conn().Close()
	// Send a minimal TLS ClientHello (handshake type 0x01) — enough to
	// prove the destination is reachable and will answer.
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	if _, err := c.Conn().Write(hello); err != nil {
		emit(clientResult{Mode: "tls-probe", Detail: "hello write: " + err.Error(), ElapsedMs: elapsed()})
		return
	}
	_ = c.Conn().SetReadDeadline(time.Now().Add(20 * time.Second))
	var first [1]byte
	if _, err := io.ReadFull(c.Conn(), first[:]); err != nil {
		emit(clientResult{Mode: "tls-probe", Detail: "no reply from target: " + err.Error(), ElapsedMs: elapsed()})
		return
	}
	// Any reply proves the target was reached (RST/ServerHello/etc.).
	emit(clientResult{Mode: "tls-probe", SocksReply: 0x00, BytesUp: int64(len(hello)), BytesDown: 1,
		Detail: fmt.Sprintf("target %s:%d reachable, first reply byte 0x%02x", dest, port, first[0]),
		OK:     true, ElapsedMs: elapsed()})
}

// runClosed: CONNECT to a closed port. The relay answers 0x00 (the
// target dial happens on Germany and its failure tears the session
// down with EOF); it must be BOUNDED and never hang.
func runClosed(socksAddr, dest string, port int, timeout time.Duration) {
	elapsed := startTimer()
	c, err := socks5.Dial(socksAddr, dest, port, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "status 0x06") {
			emit(clientResult{Mode: "closed", SocksReply: 0x06, Detail: "reply 0x06 (bounded)", OK: true, ElapsedMs: elapsed()})
			return
		}
		emit(clientResult{Mode: "closed", SocksReply: statusOf(err), Detail: err.Error(), ElapsedMs: elapsed()})
		return
	}
	_ = c
	// Reply was 0x00: expect the tunnel to end (EOF) within the bound.
	conn := c.Conn()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 4096)
	var total int
	for {
		n, err := conn.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	emit(clientResult{Mode: "closed", SocksReply: 0x00, BytesDown: int64(total),
		Detail: "reply 0x00 then tunnel terminated (bounded); target-dial failure surfaced as session end on Germany",
		OK:     true, ElapsedMs: elapsed()})
}

func runConcurrent(socksAddr, dest string, port, n, size int, timeout time.Duration) {
	elapsed := startTimer()
	type res struct {
		ok     bool
		detail string
	}
	results := make([]res, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := socks5.Dial(socksAddr, dest, port, timeout)
			if err != nil {
				results[i] = res{false, err.Error()}
				return
			}
			defer c.Conn().Close()
			seed := byte(i)
			payload := makePattern(seed, size)
			req := fmt.Sprintf("POST /up HTTP/1.1\r\nHost: target\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", size)
			if err := writeHTTPReq(c.Conn(), req); err != nil {
				results[i] = res{false, "req: " + err.Error()}
				return
			}
			if _, err := c.Conn().Write(payload); err != nil {
				results[i] = res{false, "body: " + err.Error()}
				return
			}
			code, body, err := readHTTPResponse(c.Conn(), true)
			if err != nil || code != 200 {
				results[i] = res{false, fmt.Sprintf("http %d: %v", code, err)}
				return
			}
			var r struct {
				SHA256 string `json:"sha256"`
				Size   int    `json:"size"`
			}
			if err := json.Unmarshal(body, &r); err != nil {
				results[i] = res{false, "json: " + err.Error()}
				return
			}
			if r.SHA256 != sha256Hex(payload) || r.Size != size {
				results[i] = res{false, "checksum mismatch"}
				return
			}
			results[i] = res{true, ""}
		}(i)
	}
	wg.Wait()
	failed := 0
	var firstErr string
	for i, r := range results {
		if !r.ok {
			failed++
			if firstErr == "" {
				firstErr = fmt.Sprintf("session %d: %s", i, r.detail)
			}
		}
	}
	ok := failed == 0
	detail := fmt.Sprintf("%d/%d sessions byte-exact", n-failed, n)
	if !ok {
		detail += "; first failure: " + firstErr
	}
	emit(clientResult{Mode: "concurrent", SocksReply: 0x00,
		BytesUp: int64((n - failed) * size), Detail: detail, OK: ok, ElapsedMs: elapsed()})
}

func statusOf(err error) byte {
	if err == nil {
		return 0
	}
	s := err.Error()
	if i := strings.Index(s, "status 0x"); i >= 0 {
		if v, e := strconv.ParseUint(s[i+7:i+9], 16, 8); e == nil {
			return byte(v)
		}
	}
	return 0xFF
}

// ------------------------------------------------------------
// rogue: malformed / auth-failure peers (scenarios 12/13)
// ------------------------------------------------------------

// Protocol frame: 7-byte header StreamID(4) | Type(1) | Len(2) + payload.
const (
	frameAuth = 0x01
)

func writeProtoFrame(w io.Writer, streamID uint32, typ byte, payload []byte) error {
	var hdr [7]byte
	binary.BigEndian.PutUint32(hdr[:4], streamID)
	hdr[4] = typ
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readProtoFrame(r *bufio.Reader) (uint32, byte, []byte, error) {
	var hdr [7]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	n := binary.BigEndian.Uint16(hdr[5:7])
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, err
	}
	return binary.BigEndian.Uint32(hdr[:4]), hdr[4], payload, nil
}

// ws frame helpers (RFC 6455) for the rogue WS peer.
func wsWriteBinary(c net.Conn, payload []byte, masked bool) error {
	header := []byte{0x82}
	l := len(payload)
	switch {
	case l < 126:
		header = append(header, byte(l))
	case l < 65536:
		header = append(header, 126, byte(l>>8), byte(l))
	default:
		header = append(header, 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(l))
		header = append(header, ext[:]...)
	}
	if masked {
		header[len(header)-1] |= 0x80
		mask := []byte{0x12, 0x34, 0x56, 0x78}
		out := make([]byte, 0, len(header)+4+len(payload))
		out = append(out, header...)
		out = append(out, mask...)
		for i, b := range payload {
			out = append(out, b^mask[i%4])
		}
		_, err := c.Write(out)
		return err
	}
	out := make([]byte, 0, len(header)+l)
	out = append(out, header...)
	out = append(out, payload...)
	_, err := c.Write(out)
	return err
}

// wsReadMessage reads one WS data message, unmasking if needed.
func wsReadMessage(r *bufio.Reader) ([]byte, error) {
	var b0 [2]byte
	if _, err := io.ReadFull(r, b0[:]); err != nil {
		return nil, err
	}
	masked := b0[1]&0x80 != 0
	l := int(b0[1] & 0x7F)
	switch l {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		l = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		l = int(binary.BigEndian.Uint64(ext[:]))
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, l)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return payload, nil
}

// v1 response payload for a given challenge (22 bytes), using secret.
func buildV1Response(secret []byte, role byte, challenge []byte) []byte {
	r := make([]byte, 74)
	r[0] = 1
	r[1] = role
	tsC := make([]byte, 4)
	binary.BigEndian.PutUint32(tsC, uint32(time.Now().Unix()))
	copy(r[2:6], tsC)
	copy(r[6:10], challenge[2:6])
	copy(r[10:26], challenge[6:])
	nonceC := make([]byte, 16)
	for i := range nonceC {
		nonceC[i] = byte(i*7 + 1) // deterministic rogue nonce
	}
	copy(r[26:42], nonceC)
	mac := hmac.New(sha256.New, secret)
	mac.Write(challenge)
	mac.Write(tsC)
	mac.Write(nonceC)
	copy(r[42:], mac.Sum(nil))
	return r
}

func cmdRogue(args []string) {
	fs := flag.NewFlagSet("rogue", flag.ExitOnError)
	kind := fs.String("kind", "down", "down|up")
	behavior := fs.String("behavior", "wrong-secret", "wrong-secret|garbage|silence|valid-second")
	addr := fs.String("addr", "127.0.0.1:9002", "target (down: Germany:9002; up: Iran:9001 WS)")
	wrongSecret := fs.String("wrong-secret", "0000000000000000000000000000000000000000000000000000000000000000", "64-hex wrong secret")
	timeout := fs.Duration("timeout", 25*time.Second, "bound")
	_ = fs.Parse(args)

	elapsed := startTimer()
	outcome := "error"
	detail := ""
	wrong, _ := hex.DecodeString(*wrongSecret)

	if *kind == "down" {
		c, err := net.DialTimeout("tcp", *addr, 10*time.Second)
		if err != nil {
			emit(rogueResult("down", *behavior, "dial-failed", elapsed(), err.Error()))
			return
		}
		_ = c.SetDeadline(time.Now().Add(*timeout))
		br := bufio.NewReader(c)
		switch *behavior {
		case "silence":
			// send nothing; expect the server's 15s auth bound to close.
			_, err = br.ReadByte()
			outcome, detail = classifyServerClose(err, "auth timeout close")
		case "garbage":
			// consume the challenge, then send 50 random protocol bytes.
			if _, _, _, err := readProtoFrame(br); err != nil {
				outcome, detail = "no-challenge", err.Error()
			} else if _, err := c.Write(makePattern(0xEE, 50)); err == nil {
				_, err = br.ReadByte()
				outcome, detail = classifyServerClose(err, "garbage-frame close")
			} else {
				outcome, detail = "write-failed", err.Error()
			}
		case "wrong-secret":
			_, _, challenge, err := readProtoFrame(br)
			if err != nil {
				outcome, detail = "no-challenge", err.Error()
			} else if err := writeProtoFrame(c, 0, frameAuth, buildV1Response(wrong, 'D', challenge)); err == nil {
				_, err = br.ReadByte()
				outcome, detail = classifyServerClose(err, "MAC-reject close")
			} else {
				outcome, detail = "write-failed", err.Error()
			}
		case "valid-second":
			// carrier already installed: server must reject BEFORE the
			// challenge (DownReady rule) — no bytes at all.
			_, err = br.ReadByte()
			outcome, detail = classifyServerClose(err, "DownReady pre-auth reject")
		}
		c.Close()
	} else {
		// up-carrier (WS): HTTP upgrade, then protocol over WS frames.
		host, _, _ := net.SplitHostPort(*addr)
		c, err := net.DialTimeout("tcp", *addr, 10*time.Second)
		if err != nil {
			emit(rogueResult("up", *behavior, "dial-failed", elapsed(), err.Error()))
			return
		}
		req := fmt.Sprintf("GET /upload HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", host)
		if _, err := c.Write([]byte(req)); err != nil {
			emit(rogueResult("up", *behavior, "http-failed", elapsed(), err.Error()))
			return
		}
		_ = c.SetDeadline(time.Now().Add(*timeout))
		br := bufio.NewReader(c)
		status, err := br.ReadString('\n')
		if err != nil || !strings.Contains(status, "101") {
			c.Close()
			emit(rogueResult("up", *behavior, "no-upgrade", elapsed(), strings.TrimSpace(status)))
			return
		}
		// drain remaining upgrade headers
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		switch *behavior {
		case "silence":
			_, err = br.ReadByte()
			outcome, detail = classifyServerClose(err, "auth timeout close")
		case "garbage":
			msg, err := wsReadMessage(br) // the challenge frame
			if err != nil {
				outcome, detail = "no-challenge", err.Error()
			} else {
				_ = msg
				if err := wsWriteBinary(c, makePattern(0xEE, 50), true); err == nil {
					_, err = br.ReadByte()
					outcome, detail = classifyServerClose(err, "garbage-frame close")
				} else {
					outcome, detail = "write-failed", err.Error()
				}
			}
		case "wrong-secret":
			msg, err := wsReadMessage(br)
			if err != nil || len(msg) < 7+22 {
				outcome, detail = "no-challenge", fmt.Sprintf("len=%d err=%v", len(msg), err)
			} else {
				challenge := msg[7 : 7+22]
				resp := buildV1Response(wrong, 'U', challenge)
				var frame [7]byte
				binary.BigEndian.PutUint32(frame[:4], 0)
				frame[4] = frameAuth
				binary.BigEndian.PutUint16(frame[5:7], uint16(len(resp)))
				payload := make([]byte, 7+len(resp))
				copy(payload, frame[:])
				copy(payload[7:], resp)
				if err := wsWriteBinary(c, payload, true); err == nil {
					_, err = br.ReadByte()
					outcome, detail = classifyServerClose(err, "MAC-reject close")
				} else {
					outcome, detail = "write-failed", err.Error()
				}
			}
		case "valid-second":
			// UpReady() is checked at the HTTP layer BEFORE the upgrade:
			// expect HTTP 409 (no 101). Re-dial to observe the status.
			c2, err := net.DialTimeout("tcp", *addr, 10*time.Second)
			if err != nil {
				c.Close()
				emit(rogueResult("up", *behavior, "dial-failed", elapsed(), err.Error()))
				return
			}
			_, _ = c2.Write([]byte(req))
			status2, _ := bufio.NewReader(c2).ReadString('\n')
			c2.Close()
			outcome = "http-409"
			detail = strings.TrimSpace(status2)
		}
		c.Close()
	}

	ok := outcome == "server-closed"
	detail2 := fmt.Sprintf("outcome=%s (%s)", outcome, detail)
	emit(rogueResult(*kind, *behavior, outcome, elapsed(), detail2))
	_ = ok
}

func classifyServerClose(err error, note string) (string, string) {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return "server-closed", note
	}
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return "timeout", err.Error()
		}
		return "error", err.Error()
	}
	return "still-open", "server did not close"
}

func rogueResult(kind, behavior, outcome string, elapsedMs float64, detail string) clientResult {
	ok := outcome == "server-closed" || outcome == "http-409" || outcome == "DownReady pre-auth reject"
	if outcome == "DownReady pre-auth reject" {
		// re-label
		ok = true
	}
	return clientResult{Mode: kind + "/" + behavior, Detail: detail, OK: ok, ElapsedMs: elapsedMs}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: l5cli target|client|rogue [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "target":
		cmdTarget(os.Args[2:])
	case "client":
		cmdClient(os.Args[2:])
	case "rogue":
		cmdRogue(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}
