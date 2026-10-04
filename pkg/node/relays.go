package node

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/mux"
	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// This file implements the two relay shapes.
//
// SHAPE A (socket → carrier): relayShapeA. One goroutine per direction
// for the session's lifetime — no epoch swap, hence no reordering. Data
// read from the socket is held in a bounded pending buffer until the
// attached carrier accepts it, so bytes read while the carrier is lost
// survive and are flushed in order on re-attach. When the buffer is full
// the relay stops reading the socket (backpressure all the way to the
// client/target), never growing memory.
//
// SHAPE B (carrier → socket): startStreamRelay / startUpWatcher. A
// fresh per-carrier-epoch consumer; the generation guard drops frames
// from a superseded epoch so a late frame from an old carrier can never
// reach the socket out of order.

type netConn = net.Conn

// relayShapeA pumps sock → carrier for one direction (Iran: client→up;
// Germany: target→down).
//
// Memory is bounded at TWO levels (Issue #6):
//  1. the per-buffer cap (capacity, SPLIT_SESSION_BUFFER_BYTES) — the
//     existing Phase 5 bound;
//  2. the node-level AGGREGATE budget (n.buf,
//     SPLIT_SESSION_BUFFER_TOTAL_BYTES) — the sum over all sessions and
//     directions on this node.
//
// Both apply the same backpressure when full: stop reading the socket,
// park in waitAttach (bounded by the grace timer / shutdown). A read is
// only attempted after the budget grants a reservation for the chunk
// about to be read, so the aggregate can never silently exceed its
// budget (budget.go documents the exact accounting invariant and the
// fair-refusal policy).
func (n *Node) relayShapeA(sess *session.Session, dir session.Direction, sock netConn) {
	att := sess.Att(dir)
	buf := make([]byte, n.cfg.RelayBufSize)
	var pending []byte
	capacity := n.cfg.BufferBytes
	socketEOF := false
	finSent := false

	// Aggregate-budget registration (Issue #6). bufKey{sess,dir} is the
	// relay's identity; begin/end are called from this goroutine only
	// (the single owner of `pending`), and end reclaims any bytes still
	// held so no path can leak reservations.
	bk := bufKey{sess: sess, dir: dir}
	n.buf.begin(bk)
	defer func() {
		if reclaimed := n.buf.end(bk); reclaimed > 0 {
			n.metrics.AddSessionBufferReclaimed(reclaimed)
		}
	}()

	for {
		select {
		case <-sess.Ctx.Done():
			return
		default:
		}

		if socketEOF {
			// Flush the remainder, then half-close the direction.
			if len(pending) == 0 {
				if finSent {
					return
				}
				if n.sendCloseFrame(sess, dir) {
					finSent = true
					n.peerEOF(sess, dir)
					return
				}
				// Carrier unavailable: wait (bounded by the grace
				// timer) for a rebind so the half-close is delivered
				// after all buffered data.
				n.waitAttach(sess, att)
			} else if !n.flushPending(sess, dir, &pending, bk) {
				n.waitAttach(sess, att)
			}
			continue
		}

		// Always attempt to flush buffered bytes BEFORE blocking on the
		// socket: a relay parked in waitAttach during a carrier loss must
		// deliver its pending bytes on rebind even if the peer sends no
		// further data. (A no-op when pending is empty.)
		if len(pending) > 0 {
			if !n.flushPending(sess, dir, &pending, bk) {
				n.waitAttach(sess, att)
				continue
			}
		}

		// Phase B credit gate (design §5, Slice 5): an ADVISORY gate that
		// paces how much target data may be ISSUED against the receiver's
		// granted window, sitting ABOVE the pending >= capacity buffer gate
		// (the two are independent: the credit gate gates issuing, the
		// pending gate gates buffering). Enforced ONLY on the DirDown
		// DATA-sender leg of the Germany role — the exact relayShapeA that
		// fills the downstream mailbox. The clamp limit is the SENDER's
		// CARRIER's live MaxBytesPerStream (S1/SF-4: c.limits, via the
		// lock-correct Limits() accessor), NOT the node config — so it can
		// never silently exceed the mailbox cap that SetStreamLimits moved
		// the carrier to. The hard cap remains fullLocked/rejectAggregate
		// in mux/queue.go; this gate merely paces ahead of it. Inert when
		// credits are disabled (n.creditGate is nil): behaviour is
		// byte-identical to the pending-gate-only path.
		if n.creditGate != nil && dir == session.DirDown && n.cfg.Role == RoleGermany {
			if h := n.current(dir); h != nil {
				capBytes := uint64(h.carrier.Limits().MaxBytesPerStream) // SF-4
				l := n.creditGate.ledger(h.gen, streamIDOf(sess, dir))
				if !l.canSend(uint64(mux.MaxPayload), capBytes) {
					// The CREDIT gate engaged (park here, not the pending
					// gate) — the counter D4's relay_credit_block was blind
					// to. B4: a live credit un-parks within ~µs; the 2 s
					// CreditSafeTimeout is only the fallback.
					n.metrics.CreditGatePark()
					l.creditPark(sess.Ctx, uint64(mux.MaxPayload), capBytes)
					continue
				}
			}
		}

		if len(pending) >= capacity {
			// Backpressure: the bounded reconnect buffer is full; stop
			// reading the socket until the carrier can absorb data.
			n.metrics.RelayBufferFull()
			n.waitAttach(sess, att)
			continue
		}

		nread, rerr := sock.Read(buf)
		if nread > 0 {
			n.metrics.AddRelayBytesRead(int64(nread))
			if sess.Stats.MarkFirstByte() {
				n.metrics.SessionFirstByteSeen()
			}
			if dir == session.DirUp {
				n.metrics.AddUp(int64(nread))
			} else {
				n.metrics.AddDown(int64(nread))
			}
			// Aggregate backpressure (Issue #6): charge the bytes to
			// the node-level budget at the moment they enter the
			// pending slice. If the budget is saturated the charge
			// parks (the bytes sit in the fixed read buffer, NOT in
			// the pending slice, NOT in the gauge) until a refund
			// frees space or the session ends — a relay blocked in a
			// socket Read holds zero budget, so stalled/idle peers
			// can never starve the budget. Parking is bounded: the
			// carrier-loss grace window closes stalled sessions and
			// Node.Close force-reclaims everything (budget.go).
			if !n.buf.chargeWait(bk, nread, sess.Ctx) {
				// Session ended (grace timeout / shutdown): discard
				// this chunk and exit; the pending slice's bytes are
				// reclaimed by the deferred end().
				sess.Close("session-buffer budget: node shutting down")
				return
			}
			pending = append(pending, buf[:nread]...)
			n.metrics.RelayPendingHigh(int64(len(pending)))
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				socketEOF = true
			} else {
				// Non-EOF socket read error.
				//
				// The Iran client leg (DirUp, relayShapeA on the client
				// socket) is special: on a long-haul GET download the up
				// reader is legitimately blocked in sock.Read with nothing
				// left to send, so a single transient non-EOF error there
				// (a RST, a "use of closed network connection" from a
				// concurrent teardown, or a teardown artifact under load)
				// must NOT tear down the whole session — that would kill
				// the in-flight DOWN download. We instead classify it
				// (suppressed benign artifact vs. tolerated up half-close).
				// Every other direction stays fatal below.
				if dir == session.DirUp {
					switch upReadErrorPolicy(sess, rerr) {
					case upReadSuppressed:
						// (a)/(b) Benign teardown artifact (session already
						// Closing/Closed, or os.ErrClosed/net.ErrClosed):
						// not a client abort. No counter, no re-close
						// (teardown already owns it); just log and exit.
						// The line says "suppressed artifact", NOT "closed":
						// this read error is a byproduct of the teardown that
						// ALREADY closed the ClientConn — it is not itself the
						// close event. (A genuine target drop is logged
						// separately as "up stream closed by peer" / "target ...
						// dial failed", so a reader does not mistake this
						// artifact for the cause of a dropped session.)
						n.logger.Printf("session %s: up read error suppressed as benign teardown artifact (session already %s, not a client abort): %v",
							shortID(sess.ID), sess.State().String(), rerr)
						return
					case upReadHalfClose:
						// (c) A genuine non-EOF client-socket error (e.g. a
						// RST): keep the metric truthful but do NOT make it
						// fatal for the whole session. Downgrade to a
						// tolerated up-direction half-close so the pending
						// up bytes flush and the up FrameClose goes out
						// through the existing peerEOF / MarkDirClosed
						// machinery; the DOWN download is allowed to finish
						// (it ends via the down completion + finalizeDrain
						// bound, node.go). Log the underlying error so the
						// live journal records RST-vs-teardown-artifact.
						n.metrics.Error()
						n.metrics.RelaySocketReadError()
						n.logger.Printf("session %s: up read non-EOF error (tolerated as up half-close): %v",
							shortID(sess.ID), rerr)
						socketEOF = true // run the uncapped flush + FrameClose path
						continue
					}
				}
				// Down (target, Germany) and any other direction: a non-EOF
				// read error is fatal — it can never mask a real target
				// failure. Keep the counter and the close.
				n.metrics.Error()
				n.metrics.RelaySocketReadError()
				sess.Close(sockReadErr(dir))
				return
			}
			// EOF may still carry bytes just read; the flush at the top
			// of the next iteration delivers them before the half-close.
			continue
		}
	}
}

// sockReadErr is the close reason for a non-EOF socket read error.
// Shape A reads the client (up direction, Iran) or the target (down
// direction, Germany).
func sockReadErr(dir session.Direction) string {
	if dir == session.DirUp {
		return "client socket read error"
	}
	return "target socket read error"
}

// upReadPolicy is the disposition of a non-EOF read error on the up (client)
// socket of an Iran session.
type upReadPolicy int

const (
	// upReadSuppressed: a benign artifact — the session is already
	// Closing/Closed (a concurrent teardown closed the ClientConn under
	// us) or the error is a closed-connection error. The counter and the
	// close are BOTH suppressed; the relay just exits.
	upReadSuppressed upReadPolicy = iota
	// upReadHalfClose: a genuine non-EOF client error (e.g. a RST). The
	// RelaySocketReadError counter is kept truthful, but the error is
	// downgraded from a fatal session close to a tolerated up-direction
	// half-close so the in-flight DOWN download can finish.
	upReadHalfClose
)

// upReadErrorPolicy classifies a non-EOF up-socket read error for the
// relayShapeA up-direction branch. It is the single decision point so the
// benign-artifact suppression and the half-close downgrade can be tested in
// isolation. It uses only the session's EXISTING state accessors (State,
// never inventing new state) and errors.Is for the closed-connection
// sentinels. It is NOT credited/paced: it only ever suppresses (artifact)
// or half-closes (genuine error); it never drops DATA or force-terminates.
func upReadErrorPolicy(sess *session.Session, rerr error) upReadPolicy {
	// (a) Benign teardown artifact: a concurrent goroutine's teardown
	// already moved the session to Closing/Closed and closed the
	// ClientConn, so our blocked sock.Read returned "use of closed
	// network connection". This is not a client abort.
	if st := sess.State(); st == session.StateClosing || st == session.StateClosed {
		return upReadSuppressed
	}
	// (b) Benign closed-connection error: os.ErrClosed / net.ErrClosed
	// ("use of closed network connection"). Same reasoning as (a).
	if errors.Is(rerr, os.ErrClosed) || errors.Is(rerr, net.ErrClosed) {
		return upReadSuppressed
	}
	// (c) A genuine non-EOF client-socket error (RST, reset, etc.):
	// tolerated as an up-direction half-close, never a fatal session close.
	return upReadHalfClose
}

// flushPending writes all buffered bytes to the attached carrier. It
// returns false — preserving pending — when the carrier is unavailable,
// self-detaching the attachment if the bound carrier died mid-write.
// A byte leaves the buffer only after WriteFrame succeeds, so the
// buffer is the lossless reconnect window.
//
// Aggregate accounting (Issue #6): each successfully written chunk is
// refunded to the node-level budget at the exact moment it leaves the
// pending slice, so the budget invariant (accounted == bytes still in
// the pending slices) holds between calls as well as inside them.
func (n *Node) flushPending(sess *session.Session, dir session.Direction, pending *[]byte, bk bufKey) bool {
	att := sess.Att(dir)
	st, gen := att.State()
	if st != session.AttAttached {
		return false
	}
	h := n.current(dir)
	if h == nil || h.gen != gen {
		return false // being superseded — treat as unavailable
	}
	for len(*pending) > 0 {
		chunk := *pending
		if len(chunk) > mux.MaxPayload {
			chunk = chunk[:mux.MaxPayload]
		}
		if err := h.carrier.WriteFrame(streamIDOf(sess, dir), mux.FrameData, chunk); err != nil {
			n.metrics.RelayWriteFailure()
			if att.Detach(gen) {
				n.logger.Printf("session %s: %s carrier died mid-write; %d buffered bytes, grace %s",
					shortID(sess.ID), dirName(dir), len(*pending), n.cfg.Grace)
			}
			return false
		}
		*pending = (*pending)[len(chunk):]
		n.metrics.AddRelayBytesWritten(int64(len(chunk)))
		// Phase B (Slice 5, S3): charge the credit ledger PER CHUNK
		// (n = len(chunk)), NEVER per flushPending call — a 256 KiB flush
		// would otherwise overshoot the 64 KiB-granular gate by up to 4×.
		// The condition mirrors the gate above exactly (DirDown DATA
		// sender, Germany), so a ledger is only charged on the path the
		// gate paces and credits are wired for. Inert when credits are
		// disabled (n.creditGate is nil).
		if n.creditGate != nil && dir == session.DirDown && n.cfg.Role == RoleGermany {
			if l := n.creditGate.ledger(h.gen, streamIDOf(sess, dir)); l != nil {
				l.recordSent(uint64(len(chunk)))
				n.metrics.AddCreditSentBytes(int64(len(chunk)))
			}
		}
		if r := n.buf.refund(bk, len(chunk)); r > 0 {
			n.metrics.AddSessionBufferReclaimed(r)
		}
	}
	return true
}

// sendCloseFrame writes the direction's FrameClose to the attached
// carrier. Returns false while the carrier is unavailable (self-
// detaches if the bound carrier died mid-write).
func (n *Node) sendCloseFrame(sess *session.Session, dir session.Direction) bool {
	att := sess.Att(dir)
	st, gen := att.State()
	if st != session.AttAttached {
		return false
	}
	h := n.current(dir)
	if h == nil || h.gen != gen {
		return false
	}
	if err := h.carrier.WriteFrame(streamIDOf(sess, dir), mux.FrameClose, nil); err != nil {
		att.Detach(gen)
		return false
	}
	return true
}

// waitAttach parks until the attachment is Attached again (the grace
// timer bounds this), Closed, or the session ends.
func (n *Node) waitAttach(sess *session.Session, att *session.Attachment) {
	for {
		select {
		case <-sess.Ctx.Done():
			return
		default:
		}
		st, _ := att.State()
		if st == session.AttAttached || st == session.AttClosed {
			return
		}
		sig := att.ReadySignal()
		select {
		case <-sess.Ctx.Done():
			return
		case <-sig:
		case <-time.After(50 * time.Millisecond): // re-check after state races
		}
	}
}

// peerEOF half-closes the logical direction after the shape-A socket
// EOF'd (up: client EOF; down: target EOF) and the FrameClose was sent.
func (n *Node) peerEOF(sess *session.Session, dir session.Direction) {
	if sess.DirClosed(dir) {
		return
	}
	if dir == session.DirUp {
		if n.cfg.Role == RoleGermany {
			closeWrite(sess.TargetConn)
		}
	} else {
		if n.cfg.Role == RoleIran {
			closeWrite(sess.ClientConn)
		}
	}
	sess.MarkDirClosed(dir, dirEOFReason(dir))
	if dir == session.DirUp {
		n.finalizeDrain(sess)
	}
}

func dirEOFReason(dir session.Direction) string {
	if dir == session.DirUp {
		return "client EOF"
	}
	return "target EOF"
}

// startChannelConsumer starts the per-carrier-epoch consumer for one
// direction on carrier h: the up watcher (Iran) or the data relay
// (Germany up / Iran down).
func (n *Node) startChannelConsumer(sess *session.Session, dir session.Direction, h *carrierHandle, ch chan []byte) {
	if n.cfg.Role == RoleIran && dir == session.DirUp {
		n.startUpWatcher(sess, h, ch)
		return
	}
	n.startStreamRelay(sess, dir, h, ch)
}

// startUpWatcher (Iran) watches the up stream for the peer's FrameClose
// (e.g. the target dial failed on Germany). Data frames toward Iran do
// not exist on the up stream and are ignored.
func (n *Node) startUpWatcher(sess *session.Session, h *carrierHandle, ch chan []byte) {
	att := sess.UpAtt
	done := make(chan struct{})
	att.SetEpochDone(done)
	go func() {
		defer close(done)
		for {
			select {
			case <-sess.Ctx.Done():
				return
			case frame, ok := <-ch:
				if !ok {
					// Our carrier died. If still bound to this
					// generation, start the grace window (the
					// carrier-loss sweep may have done it already).
					if st, g := att.State(); st == session.AttAttached && g == h.gen {
						att.Detach(h.gen)
					}
					return
				}
				if frame != nil {
					continue // ignore: no data toward us on the up stream
				}
				// Peer FrameClose — honor only while this carrier is the
				// attached epoch (a late FrameClose from a superseded
				// or dead carrier must never close the session).
				if st, g := att.State(); st != session.AttAttached || g != h.gen {
					return
				}
				sess.Close("up stream closed by peer")
				return
			}
		}
	}()
}

// startStreamRelay (shape B) drains the stream channel of carrier h and
// writes frames to the local socket (Germany: up→target; Iran:
// down→client). The generation guard discards data from a superseded
// epoch; a peer FrameClose is honored as a logical half-close.
func (n *Node) startStreamRelay(sess *session.Session, dir session.Direction, h *carrierHandle, ch chan []byte) {
	att := sess.Att(dir)
	var sock netConn
	if dir == session.DirUp {
		sock = sess.TargetConn // Germany
	} else {
		sock = sess.ClientConn // Iran
	}
	done := make(chan struct{})
	att.SetEpochDone(done)
	go func() {
		defer close(done)
		for {
			select {
			case <-sess.Ctx.Done():
				return
			case frame, ok := <-ch:
				if !ok {
					if st, g := att.State(); st == session.AttAttached && g == h.gen {
						att.Detach(h.gen)
					}
					return
				}
				st, g := att.State()
				if st != session.AttAttached || g != h.gen {
					// Not the attached epoch for this carrier: a late
					// data frame or peer close from a superseded or
					// dead carrier must never reach the socket — drop
					// and exit.
					return
				}
				if frame == nil {
					if st, g := att.State(); st == session.AttAttached && g == h.gen {
						sess.Stats.MarkCleanHalfClose()
					}
					// Phase B (Slice 4): on half-close, force-flush any
					// remaining pending credit bytes with CreditFlagsFinal.
					// A dropped finalize is safe (cumulative-absolute): the
					// last credit carries the running total. Inert when
					// credits are disabled (n.creditEmitter is nil).
					if n.creditEmitter != nil && dir == session.DirDown {
						n.creditEmitter.finalize(carrierKey{carrier: h.carrier, streamID: streamIDOf(sess, dir)})
					}
					n.peerEOF(sess, dir)
					return
				}
				if dir == session.DirUp {
					n.metrics.AddUp(int64(len(frame)))
				} else {
					n.metrics.AddDown(int64(len(frame)))
				}
				// Phase B (Slice 4, B1): enforce the exact write/credit
				// shape. Credit ONLY the bytes the socket actually accepted
				// (nw), and ONLY on a full, error-free write. A partial
				// write (nw < len(frame), err == nil) or a full failure
				// credits NOTHING and terminates the stream — a half-
				// written frame must never continue (the session is
				// closing). This is the invariant that forbids over-ack:
				// Sigma(bytesConsumed) <= Sigma(bytes actually written).
				nw, werr := sock.Write(frame)
				if werr == nil && nw == len(frame) {
					// Authoritative release point: the byte is accepted by
					// the client kernel TCP stack, so it is "consumed" and
					// the receiver may tell the sender more may be issued.
					// Scoped to the down receiver path; inert when credits
					// are disabled (n.creditEmitter is nil).
					if n.creditEmitter != nil && dir == session.DirDown {
						key := carrierKey{carrier: h.carrier, streamID: streamIDOf(sess, dir)}
						if n.creditEmitter.recordConsumed(key, uint64(nw)) {
							n.metrics.AddCreditConsumedBytes(int64(nw))
							if n.creditEmitter.emit(key, false) {
								n.metrics.CreditEmitted()
							} else {
								n.metrics.CreditDropped()
							}
						}
					}
				} else {
					// failed OR partial write: no credit; the session is
					// closing (never continue with a half-written frame).
					n.metrics.Error()
					n.metrics.RelaySocketWriteError()
					sess.Close(sockWriteErr(dir))
					return
				}
			}
		}
	}()
}

// sockWriteErr is the close reason for a shape-B socket write failure
// (Germany: target; Iran: client).
func sockWriteErr(dir session.Direction) string {
	if dir == session.DirUp {
		return "target socket write error"
	}
	return "client socket write error"
}
