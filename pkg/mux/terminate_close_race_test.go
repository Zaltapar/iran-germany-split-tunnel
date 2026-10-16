// terminate_close_race_test.go — regression test for the -race failure in
// TestHandleSOCKS5TargetRefused / TestStartSessionAndWaitTargetRefused:
//
//	Node.Close -> upReg.CloseAll -> CarrierConn.Close closes s.ch (step c)
//	while a node-spawned goroutine (bootstrapUpStream's dial-drop path) is
//	inside Terminate -> terminateStream -> s.ch <- nil.
//
// Close's close-safety proof covers two sender classes: the stream workers
// (workerWait, step b) and the dispatcher's own terminate handoffs
// (dispatchDone, step b2). The public Terminate is a THIRD sender class —
// it runs in node-spawned goroutines that the dispatcher fires and returns
// from without waiting (go n.bootstrapUpStream). The fix adds a termWG
// wait (step b3) between b2 and c so no Terminate-originated send can be
// in flight when s.ch closes.
//
// This test drives the same shape at the mux level: many concurrent
// Terminate calls (registered and unregistered ids) racing a Close, across
// repeated iterations so the race detector has a high hit probability.
package mux

import (
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/testutil"
)

func TestTerminateRacesCloseWithoutSendOnClosedChannel(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		a, b := testutil.NewMemPipe()
		c := NewCarrierConn(a, 0)
		go c.Dispatch()
		ids := []uint32{1, 2, 3}
		chs := map[uint32]chan []byte{}
		for _, id := range ids {
			chs[id] = c.Register(id)
		}
		// Fire a burst of concurrent Terminates (mixed registered /
		// unregistered ids so the tombstone path is exercised too), then
		// race Close against the in-flight handoffs.
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for _, id := range ids {
					c.Terminate(id)
				}
			}()
		}
		close(start)
		// Close must be safe against ANY in-flight Terminate: it latches
		// closing=true, aborts the handoff selects via c.closed, and
		// waits on termWG before closing the consumer channels.
		c.Close()
		// Post-fix, every Terminate's handoff is released by c.closed, so
		// the burst is bounded and must complete (and MUST complete, since
		// Close already waited for them).
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: concurrent Terminates still running 5s after Close", iter)
		}
		// Full post-Close contract: every consumer channel closed, all
		// carrier-owned goroutines exited.
		for id, ch := range chs {
			if ch == nil {
				t.Fatalf("iteration %d: stream %d not registered", iter, id)
			}
			gone := make(chan struct{})
			go func() {
				for range ch {
				}
				close(gone)
			}()
			select {
			case <-gone:
			case <-time.After(3 * time.Second):
				t.Fatalf("iteration %d: stream %d consumer channel was not closed by Close", iter, id)
			}
		}
		select {
		case <-c.ShutdownDone():
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: carrier-owned goroutines did not all exit after Close", iter)
		}
		a.Close()
		b.Close()
	}
}
