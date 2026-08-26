// Command e2e-pipe-test runs a full in-process end-to-end test of the
// split-tunnel frame protocol over net.Pipe pairs (bypassing the OS TCP
// stack, so it works even on machines where local VPN/xray tooling
// intercepts loopback traffic).
//
// Topology (mirrors production):
//
//	client ↔ Iran ↔[upPipe: up-carrier]↔ Germany ↔ target
//	           ↔[downPipe: down-carrier]↔
//
// Upload:   client → Iran → up-carrier (FrameData) → Germany → target
// Download: target → Germany → down-carrier (FrameData) → Iran → client
//
// Usage: go run ./e2e-pipe-test
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

func fail(format string, args ...any) {
	fmt.Printf("FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	secret := mux.DeriveSecret("e2e-pipe-secret")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	upDe, upIr := net.Pipe()     // up carrier: Germany (client) ↔ Iran (server)
	downIr, downDe := net.Pipe() // down carrier: Iran (client) ↔ Germany (server)
	client, clientPeer := net.Pipe()
	target, targetPeer := net.Pipe()

	// target server (test side): expects "HELLO", answers, closes
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		buf := make([]byte, 64)
		n, err := target.Read(buf)
		if err != nil {
			fail("target read: %v", err)
		}
		fmt.Printf("TARGET received %d bytes: %q\n", n, buf[:n])
		if string(buf[:n]) != "HELLO" {
			fail("target payload mismatch: %q", buf[:n])
		}
		if _, err := target.Write([]byte("WORLD-RESPONSE")); err != nil {
			fail("target write: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
		target.Close()
	}()

	// symmetric FrameAuth handshake on both carriers (4 corners)
	type authRes struct {
		br  *bufio.Reader
		err error
	}
	au := make(chan authRes, 1)
	ad := make(chan authRes, 1)
	gu := make(chan authRes, 1)
	gd := make(chan authRes, 1)
	go func() { br, err := mux.CarrierAuth(ctx, upIr, false, mux.RoleUpload, secret); au <- authRes{br, err} }()
	go func() {
		br, err := mux.CarrierAuth(ctx, downIr, true, mux.RoleDownload, secret)
		ad <- authRes{br, err}
	}()
	go func() { br, err := mux.CarrierAuth(ctx, upDe, true, mux.RoleUpload, secret); gu <- authRes{br, err} }()
	go func() {
		br, err := mux.CarrierAuth(ctx, downDe, false, mux.RoleDownload, secret)
		gd <- authRes{br, err}
	}()
	auths := map[string]chan authRes{"iran-up": au, "iran-down": ad, "germany-up": gu, "germany-down": gd}
	brs := map[string]*bufio.Reader{}
	for name, ch := range auths {
		r := <-ch
		if r.err != nil {
			fail("auth %s: %v", name, r.err)
		}
		brs[name] = r.br
	}
	fmt.Println("AUTH: both carriers authenticated")

	// carriers (keepalive disabled: 0)
	upIrC := mux.NewCarrierConn(upIr, 0)
	upIrC.SetReadBuffer(brs["iran-up"])
	downIrC := mux.NewCarrierConn(downIr, 0)
	downIrC.SetReadBuffer(brs["iran-down"])
	upDeC := mux.NewCarrierConn(upDe, 0)
	upDeC.SetReadBuffer(brs["germany-up"])
	downDeC := mux.NewCarrierConn(downDe, 0)
	downDeC.SetReadBuffer(brs["germany-down"])

	streamID := uint32(1)
	dest := &session.Destination{AddrType: session.AddrTypeDomain, Addr: "example.com", Port: 443}

	// ================= Iran side (mirror of handleSOCKS5Conn) ============
	hdrBuf := make([]byte, session.MaxHeaderSize)
	hdrLen := session.WriteDestinationBuffer(hdrBuf, dest)
	if hdrLen <= 0 {
		fail("destination encode failed")
	}
	upCh := upIrC.Register(streamID)
	downCh := downIrC.Register(streamID)
	if upCh == nil || downCh == nil {
		fail("iran stream registration failed")
	}
	if err := upIrC.WriteFrame(streamID, mux.FrameHeader, hdrBuf[:hdrLen]); err != nil {
		fail("iran header write: %v", err)
	}

	iranDownDone := make(chan struct{})
	go func() { // Iran: down-carrier relay → client
		defer close(iranDownDone)
		defer downIrC.Deregister(streamID)
		for frame := range downCh {
			if frame == nil {
				clientPeer.Close() // teardown of the client conn
				return
			}
			if _, err := clientPeer.Write(frame); err != nil {
				return
			}
		}
	}()

	iranUpDone := make(chan struct{})
	go func() { // Iran: client → up-carrier relay (upload)
		defer close(iranUpDone)
		defer upIrC.Deregister(streamID)
		buf := make([]byte, 64)
		for {
			n, rerr := clientPeer.Read(buf)
			if n > 0 {
				if err := upIrC.WriteFrame(streamID, mux.FrameData, buf[:n]); err != nil {
					fail("iran up write: %v", err)
				}
			}
			if rerr != nil {
				// client gone → Iran sends the up-carrier FrameClose
				_ = upIrC.WriteFrame(streamID, mux.FrameClose, nil)
				return
			}
		}
	}()

	// ================= Germany side (mirror of bootstrapUpStream) ========
	deDone := make(chan struct{})
	deUpDone := make(chan struct{})
	upDeC.OnNewStream = func(id uint32, firstType uint8, ch chan []byte) {
		// Frame-type-aware dispatch (Phase 5): streams are opened only via
		// FrameHeader. A non-header opener is a protocol violation EXCEPT
		// a late FrameClose for an already-deregistered stream: after
		// Deregister, any frame for the ID starts a NEW stream (documented
		// carrier behavior), and production drops such non-header openers
		// rather than treating them as new sessions.
		if firstType != mux.FrameHeader {
			if firstType == mux.FrameClose {
				go func() {
					for range ch { /* discard the late close */
					}
				}()
				return
			}
			fail("germany: stream %d opened by frame type 0x%02x, want FrameHeader (0x%02x)", id, firstType, mux.FrameHeader)
		}
		go func() {
			defer upDeC.Deregister(id)
			hdr := <-ch
			parsed := session.ParseDestinationFromBuf(hdr)
			if parsed == nil {
				fail("germany: invalid destination header")
			}
			fmt.Printf("GERMANY: new stream %d → %s:%d\n", id, parsed.Addr, parsed.Port)
			if parsed.Addr != "example.com" || parsed.Port != 443 {
				fail("germany: wrong destination %s:%d", parsed.Addr, parsed.Port)
			}
			go func() { // up relay: stream → target (ends on Iran's FrameClose)
				defer close(deUpDone)
				for {
					frame, ok := <-ch
					if !ok || frame == nil {
						return
					}
					if _, err := targetPeer.Write(frame); err != nil {
						return
					}
				}
			}()
			buf := make([]byte, 64)
			n, _ := targetPeer.Read(buf)
			if n > 0 {
				if err := downDeC.WriteFrame(id, mux.FrameData, buf[:n]); err != nil {
					fail("germany down write: %v", err)
				}
			}
			_ = downDeC.WriteFrame(id, mux.FrameClose, nil) // target finished
			close(deDone)
			fmt.Println("GERMANY: session done")
		}()
	}

	// ================= dispatchers =======================================
	go upIrC.Dispatch()
	go downIrC.Dispatch()
	go upDeC.Dispatch()
	go downDeC.Dispatch()

	// ================= client (test side) ================================
	if _, err := client.Write([]byte("HELLO")); err != nil {
		fail("client write: %v", err)
	}
	got := make(chan []byte, 1)
	go func() {
		var out []byte
		buf := make([]byte, 64)
		for {
			n, rerr := client.Read(buf)
			if n > 0 {
				out = append(out, buf[:n]...)
			}
			if rerr != nil {
				got <- out
				return
			}
		}
	}()
	select {
	case data := <-got:
		fmt.Printf("CLIENT received %d bytes: %q\n", len(data), data)
		if string(data) != "WORLD-RESPONSE" {
			fail("client payload mismatch: %q", data)
		}
	case <-time.After(5 * time.Second):
		fail("client never received the target response")
	}

	// teardown assertions
	select {
	case <-deDone:
	case <-time.After(5 * time.Second):
		fail("germany session never completed")
	}
	select {
	case <-deUpDone:
	case <-time.After(5 * time.Second):
		fail("germany up relay never saw the Iran FrameClose")
	}
	select {
	case <-iranUpDone:
	case <-time.After(5 * time.Second):
		fail("iran up relay never completed")
	}
	select {
	case <-iranDownDone:
	case <-time.After(5 * time.Second):
		fail("iran down relay never completed")
	}
	select {
	case <-targetDone:
	case <-time.After(5 * time.Second):
		fail("target server never completed")
	}

	fmt.Println("E2E PIPE TEST: PASS")
	os.Exit(0)
}
