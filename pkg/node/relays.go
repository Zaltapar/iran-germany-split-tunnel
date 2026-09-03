package node

import (
	"errors"
	"io"
	"net"
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

		if len(pending) >= capacity {
			// Backpressure: the bounded reconnect buffer is full; stop
			// reading the socket until the carrier can absorb data.
			n.waitAttach(sess, att)
			continue
		}

		nread, rerr := sock.Read(buf)
		if nread > 0 {
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
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				socketEOF = true
			} else {
				n.metrics.Error()
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
		return "client read error"
	}
	return "target read error"
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
			if att.Detach(gen) {
				n.logger.Printf("session %s: %s carrier died mid-write; %d buffered bytes, grace %s",
					shortID(sess.ID), dirName(dir), len(*pending), n.cfg.Grace)
			}
			return false
		}
		*pending = (*pending)[len(chunk):]
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
					n.peerEOF(sess, dir)
					return
				}
				if dir == session.DirUp {
					n.metrics.AddUp(int64(len(frame)))
				} else {
					n.metrics.AddDown(int64(len(frame)))
				}
				if _, err := sock.Write(frame); err != nil {
					n.metrics.Error()
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
		return "target write failed"
	}
	return "client write failed"
}
