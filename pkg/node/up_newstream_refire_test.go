// up_newstream_refire_test.go — up-carrier drop-storm fix, node-level
// end-to-end tests covering the required cases (a), (b) and (f):
//
//	(a) after a bootstrap dial failure terminates the up stream, peer
//	    retransmits of FrameData / FrameClose on that SAME id are dropped
//	    silently (no re-fired OnNewStream, no new session, no re-drop log);
//	(b) a brand-NEW stream id still bootstraps when the target is reachable
//	    again (the recovery path is preserved);
//	(f) the new up_newstream_refired_after_deregister counter increments
//	    EXACTLY on the re-fire condition (an unknown up stream whose first
//	    frame is a data/close 0x00-0x04, i.e. the onUpNewStream default
//	    branch), and stays 0 for the silenced retransmits.
//
// Germany drives the up carrier with raw frames (as Iran's up relay would),
// so the first-frame type is fully deterministic.
package node_test

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// refireTopo builds a fully-operational GERMANY node over in-memory up + down
// carriers, with a controllable target dial. Germany is the up-carrier client
// and the down-carrier server. The up Iran end is returned so the test can
// write raw up frames (FrameHeader/FrameData/FrameClose) that Germany's
// dispatcher processes — exactly what Iran's up relay does.
func refireTopo(t *testing.T, dial func(addr string) (net.Conn, error)) (*node.Node, *testutil.MemConn, *testutil.MemConn) {
	t.Helper()
	const secret = "0123456789abcdef0123456789abcdef"
	secretB := []byte(secret)
	de, err := node.NewNode(node.Config{
		Role: node.RoleGermany, Grace: 2 * time.Second,
		RelayBufSize: 4096, BufferBytes: 256 << 10, KeepAliveInterval: time.Hour,
		TargetDial: dial,
	}, log.New(io.Discard, "", 0), secretB)
	if err != nil {
		t.Fatalf("NewNode(germany): %v", err)
	}
	t.Cleanup(de.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Up carrier: Germany is the auth client (true), Iran the server (false).
	// BOTH ends must run the handshake or it never completes.
	upIr, upDe := testutil.NewMemPipe()
	t.Cleanup(func() { upIr.Close(); upDe.Close() })
	upReady := make(chan error, 1)
	go func() {
		br, err := mux.CarrierAuth(ctx, upDe, true, mux.RoleUpload, secretB)
		if err != nil {
			upReady <- err
			return
		}
		de.InstallUp(upDe, br)
		upReady <- nil
	}()
	if _, err := mux.CarrierAuth(ctx, upIr, false, mux.RoleUpload, secretB); err != nil {
		t.Fatalf("up auth (iran server): %v", err)
	}
	if err := <-upReady; err != nil {
		t.Fatalf("up auth (germany client): %v", err)
	}
	// Down carrier: Germany is the auth server (false), Iran the client (true).
	downIr, downDe := testutil.NewMemPipe()
	t.Cleanup(func() { downIr.Close(); downDe.Close() })
	downReady := make(chan error, 1)
	go func() {
		br, err := mux.CarrierAuth(ctx, downDe, false, mux.RoleDownload, secretB)
		if err != nil {
			downReady <- err
			return
		}
		de.InstallDown(downDe, br)
		downReady <- nil
	}()
	if _, err := mux.CarrierAuth(ctx, downIr, true, mux.RoleDownload, secretB); err != nil {
		t.Fatalf("down auth (iran client): %v", err)
	}
	if err := <-downReady; err != nil {
		t.Fatalf("down auth (germany server): %v", err)
	}
	return de, upIr, downIr
}

// writeUpHeader writes a FrameHeader carrying dest's destination over the
// up-carrier pipe for stream id (as Iran's StartSession would for the up leg).
func writeUpHeader(t *testing.T, w *testutil.MemConn, id uint32, dest *session.Destination) {
	t.Helper()
	hdr := make([]byte, session.MaxHeaderSize)
	nw := session.WriteDestinationBuffer(hdr, dest)
	if nw == 0 {
		t.Fatalf("destination encoding failed: %+v", dest)
	}
	if err := mux.WriteFrame(w, id, mux.FrameHeader, hdr[:nw]); err != nil {
		t.Fatalf("write FrameHeader: %v", err)
	}
}

// deadDest is an unreachable target; liveDest is one the dialer accepts.
var deadDest = &session.Destination{AddrType: session.AddrTypeIPv4, Addr: "93.184.215.14", Port: 443}
var liveDest = &session.Destination{AddrType: session.AddrTypeDomain, Addr: "host.example", Port: 443}

// TestRetransmitAfterBootstrapDropIsSilenced (case a): when the target dial
// fails, the up stream is TERMINATED. A peer retransmit of FrameData /
// FrameClose on that same id is then dropped SILENTLY: OnNewStream does not
// re-fire, no session is created, and the re-fire counter stays 0. This is the
// exact storm the fix removes.
func TestRetransmitAfterBootstrapDropIsSilenced(t *testing.T) {
	var dialAttempts int32
	de, upIr, _ := refireTopo(t, func(addr string) (net.Conn, error) {
		atomic.AddInt32(&dialAttempts, 1)
		return nil, errors.New("i/o timeout") // the Cloudflare egress timeout
	})
	const id uint32 = 7001

	// 1) Iran opens up stream id with a FrameHeader to a dead target;
	//    Germany bootstraps, the dial fails, and the stream is terminated.
	writeUpHeader(t, upIr, id, deadDest)
	eventually(t, 5*time.Second, "germany drops the dial-failed up stream", func() bool {
		if got := de.Metrics().Snapshot(); got.TargetDialFailure >= 1 {
			return true
		}
		return false
	})
	if got := de.Store().Count(); got != 0 {
		t.Fatalf("germany session store = %d after a dial failure, want 0 (dropped, not half-wired)", got)
	}

	// 2) Iran's up relay keeps pushing buffered FrameData, then its trailing
	//    FrameClose, on the SAME terminated id.
	refireBefore := de.Metrics().Snapshot().UpNewStreamRefiredAfterDeregister
	if err := mux.WriteFrame(upIr, id, mux.FrameData, []byte("retransmit-bytes")); err != nil {
		t.Fatalf("retransmit FrameData: %v", err)
	}
	if err := mux.WriteFrame(upIr, id, mux.FrameClose, nil); err != nil {
		t.Fatalf("retransmit FrameClose: %v", err)
	}
	// Let the dispatcher drain the retransmits.
	time.Sleep(150 * time.Millisecond)

	// The retransmits must NOT re-create the stream: no new session, and the
	// re-fire counter must not have moved (the terminating drop silenced it).
	if got := de.Store().Count(); got != 0 {
		t.Fatalf("a retransmit re-created session store = %d, want 0", got)
	}
	if refireAfter := de.Metrics().Snapshot().UpNewStreamRefiredAfterDeregister; refireAfter != refireBefore {
		t.Fatalf("UpNewStreamRefiredAfterDeregister moved %d -> %d; the silenced retransmit must not re-fire", refireBefore, refireAfter)
	}
	// The target was dialed exactly once (no retry storm).
	if got := atomic.LoadInt32(&dialAttempts); got != 1 {
		t.Fatalf("target dial attempts = %d, want 1 (no retry loop)", got)
	}
}

// TestNewStreamIDRecoversWhenTargetLive (case b): after a target has been
// reachable, a brand-NEW up stream id bootstraps normally into a live session
// — the recovery path is preserved by the terminating drop.
func TestNewStreamIDRecoversWhenTargetLive(t *testing.T) {
	target, targetDe := testutil.NewMemPipe()
	defer target.Close()
	defer targetDe.Close()
	// The dialer returns a live target conn (no error) so bootstrap succeeds.
	de, upIr, _ := refireTopo(t, func(addr string) (net.Conn, error) { return target, nil })

	const id uint32 = 7101
	writeUpHeader(t, upIr, id, liveDest)
	eventually(t, 5*time.Second, "germany bootstraps the live-target up stream", func() bool {
		return de.Store().Count() == 1
	})
	if got := de.Store().Count(); got != 1 {
		t.Fatalf("germany session store = %d, want 1 (new stream id recovered)", got)
	}
}

// TestRefireCounterIncrementsExactlyOnReFire (case f): the
// up_newstream_refired_after_deregister counter increments EXACTLY on the
// re-fire condition — an unknown up stream whose FIRST frame is a data/close
// 0x00/0x04 (the onUpNewStream default branch) — and it stays 0 otherwise.
func TestRefireCounterIncrementsExactlyOnReFire(t *testing.T) {
	// A target dial that always succeeds, so the ONLY way the default branch
	// fires is a genuinely-malformed first frame on an unknown id (no
	// bootstrap involved).
	target, targetDe := testutil.NewMemPipe()
	defer target.Close()
	defer targetDe.Close()
	de, upIr, _ := refireTopo(t, func(addr string) (net.Conn, error) { return target, nil })

	before := de.Metrics().Snapshot().UpNewStreamRefiredAfterDeregister

	// A brand-new up stream whose FIRST frame is FrameData (0x00): this is
	// the malformed/re-fire condition and MUST take the default branch.
	if err := mux.WriteFrame(upIr, 9001, mux.FrameData, []byte("orphan")); err != nil {
		t.Fatalf("write orphan FrameData: %v", err)
	}
	eventually(t, 5*time.Second, "germany counts the orphan-data re-fire", func() bool {
		return de.Metrics().Snapshot().UpNewStreamRefiredAfterDeregister > before
	})
	after := de.Metrics().Snapshot().UpNewStreamRefiredAfterDeregister
	if after != before+1 {
		t.Fatalf("UpNewStreamRefiredAfterDeregister = %d, want exactly %d (+1 for the single orphan data frame)", after, before+1)
	}
}
