package node_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// delayedRWC wraps an io.ReadWriteCloser and delays every read by d. It is
// used to make the post-handshake over-read deterministic: while Germany's
// confirm read is delayed, Iran's rebind frame is already in the pipe, so
// the confirm read pulls the rebind into the bufio pre-buffer for sure.
type delayedRWC struct {
	io.ReadWriteCloser
	d time.Duration
}

func (x *delayedRWC) Read(p []byte) (int, error) {
	time.Sleep(x.d)
	return x.ReadWriteCloser.Read(p)
}

// TestInstallUpConsumesPrebufferedRebind is the regression test for the
// auth-reader handoff race: after an up-carrier loss, the peer writes the
// FrameRebind immediately after the replacement handshake; Germany's auth
// bufio.Reader over-reads it (the rebind is in the pipe when the confirm is
// read, so it lands in the reader's buffer, NOT the pipe). If the carrier's
// read loop latches a fresh bufio over the raw transport instead of the auth
// reader, the rebind is orphaned: no "reattached", no "rebind refused", and
// the session later dies on the grace timer.
//
// Before the fix (NewCarrierConn + SetReadBuffer racing the read loop's
// first read) this intermittently lost the rebind and the grace timer
// closed the session. With NewCarrierConnWithReader the rebind is always
// consumed from the auth reader.
func TestInstallUpConsumesPrebufferedRebind(t *testing.T) {
	tp := newTopo(t, 2*time.Second)
	tp.setup()
	sc := tp.startSession(1) // stream 1 up

	// Kill the up carrier and wait until Germany's up attachment is
	// detached and awaiting a rebind (loss sweep settled).
	lossBefore := tp.de.Metrics().Snapshot().CarrierLossEvents
	rebindsBefore := tp.de.Metrics().Snapshot().CarrierRebinds
	tp.killUp()
	eventually(t, 2*time.Second, "germany up attachment detached", func() bool {
		sess := tp.de.Store().Snapshot()
		if len(sess) != 1 {
			return false
		}
		st, _ := sess[0].UpAtt.State()
		return st == session.AttUnavailable
	})
	if got := tp.de.Metrics().Snapshot().CarrierLossEvents; got < lossBefore+1 {
		t.Fatalf("loss events = %d, want >= %d", got, lossBefore+1)
	}

	// Replacement carrier. Germany runs its auth handshake (it is the
	// carrier client on up) while Iran performs only the auth handshake
	// and never installs a carrier, so Iran's own rebind sweep never
	// races. The rebind frame is written to the raw pipe BEFORE Germany
	// runs its handshake: Germany's final auth read (the confirm)
	// therefore over-reads the rebind into its bufio.Reader
	// deterministically — the rebind is guaranteed to sit in
	// br.Buffered(), never in the pipe.
	ir, deRaw := testutil.NewMemPipe()
	// Delay Germany's reads so the rebind (written right after the
	// handshake) is already in the pipe when its confirm read proceeds —
	// the over-read into the bufio pre-buffer becomes deterministic.
	de := &delayedRWC{ReadWriteCloser: deRaw, d: 30 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		br, err := mux.CarrierAuth(ctx, de, true, mux.RoleUpload, tp.secret)
		if err != nil {
			done <- err
			return
		}
		// The rebind must be in the auth reader's buffer, not the pipe —
		// otherwise this test does not exercise the race.
		if br.Buffered() < 7 {
			t.Errorf("precondition: rebind not pre-buffered in auth reader (Buffered=%d); test would not exercise the race", br.Buffered())
		}
		tp.de.InstallUp(de, br)
		done <- nil
	}()
	if _, err := mux.CarrierAuth(ctx, ir, false, mux.RoleUpload, tp.secret); err != nil {
		t.Fatalf("up auth (iran): %v", err)
	}
	// A replacement carrier generation higher than any seen so far.
	if err := mux.WriteFrame(ir, sc.sc.StreamIDUp, mux.FrameRebind,
		session.EncodeRebind(sc.sc.ID, 42)); err != nil {
		t.Fatalf("raw rebind write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("up auth (de): %v", err)
	}

	// The pre-buffered rebind must be consumed by the carrier read loop
	// and re-attach the session on Germany.
	eventually(t, 2*time.Second, "pre-buffered rebind accepted", func() bool {
		return tp.de.Metrics().Snapshot().CarrierRebinds >= rebindsBefore+1
	})
	if got := tp.de.Metrics().Snapshot().CarrierRebindFailures; got != 0 {
		t.Fatalf("rebind failures = %d, want 0", got)
	}
	if sc.sc.State() != session.StateActive {
		t.Fatalf("session state = %v, want Active", sc.sc.State())
	}
	// Germany's up attachment must be re-bound to the replacement carrier.
	eventually(t, 2*time.Second, "germany up attachment re-attached", func() bool {
		sess := tp.de.Store().Snapshot()
		if len(sess) != 1 {
			return false
		}
		st, _ := sess[0].UpAtt.State()
		return st == session.AttAttached
	})
}
