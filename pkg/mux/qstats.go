package mux

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// rejectReason identifies the mutually-exclusive reason a mailbox push was
// refused. The values are intentionally private so callers cannot introduce
// another exported metric bucket.
type rejectReason uint8

const (
	rejectStreamFrames rejectReason = iota
	rejectStreamBytes
	rejectAggregate
	rejectClosed
)

// QueueStats is the fixed-cardinality, carrier-wide queue telemetry surface.
// Every field is a cumulative counter, a current gauge, or an atomic-max
// gauge. Fields must be accessed atomically after the carrier has started.
type QueueStats struct {
	// Mailbox accounting.
	PushAccepted       int64
	PushRejectedStream int64
	PushRejectedTotal  int64
	PushRejectedClosed int64

	// Per-stream mailbox high-water marks.
	StreamQueuedBytesHigh  int64
	StreamQueuedFramesHigh int64

	// Carrier aggregate queue gauges and high-water marks.
	QueuedBytesNow   int64
	QueuedFramesNow  int64
	QueuedBytesHigh  int64
	QueuedFramesHigh int64

	// Overflow termination accounting.
	OverflowTerminations       int64
	OverflowTerminationsWorker int64
	OverflowWaitSumNanos       int64
	OverflowWaitCount          int64
	OverflowWaitMaxNanos       int64

	// Carrier transport and liveness failures.
	WriteFailures   int64
	ReadFailures    int64
	ReadEOF         int64
	BlackholeDeaths int64
}

func (s *QueueStats) push(n int) {
	if s == nil {
		return
	}
	atomic.AddInt64(&s.PushAccepted, 1)
	_ = n // The payload length is already reflected by the queue occupancy fold.
}

func (s *QueueStats) reject(reason rejectReason) {
	if s == nil {
		return
	}
	switch reason {
	case rejectStreamFrames, rejectStreamBytes:
		atomic.AddInt64(&s.PushRejectedStream, 1)
	case rejectAggregate:
		atomic.AddInt64(&s.PushRejectedTotal, 1)
	case rejectClosed:
		atomic.AddInt64(&s.PushRejectedClosed, 1)
	}
}

func atomicMax(dst *int64, value int64) {
	for {
		old := atomic.LoadInt64(dst)
		if value <= old || atomic.CompareAndSwapInt64(dst, old, value) {
			return
		}
	}
}

func (s *QueueStats) observeHighStream(nBytes, nItems int64) {
	if s == nil {
		return
	}
	atomicMax(&s.StreamQueuedBytesHigh, nBytes)
	atomicMax(&s.StreamQueuedFramesHigh, nItems)
}

func (s *QueueStats) observeHighQueued(nBytes, nItems int64) {
	if s == nil {
		return
	}
	atomicMax(&s.QueuedBytesHigh, nBytes)
	atomicMax(&s.QueuedFramesHigh, nItems)
}

// addQueued updates the current aggregate gauges and folds the same snapshot
// into their high-water marks. The atomic adds are the only synchronization;
// no queue or carrier lock is taken here.
func (s *QueueStats) addQueued(bytesDelta, itemsDelta int64) {
	if s == nil {
		return
	}
	nBytes := atomic.AddInt64(&s.QueuedBytesNow, bytesDelta)
	nItems := atomic.AddInt64(&s.QueuedFramesNow, itemsDelta)
	s.observeHighQueued(nBytes, nItems)
}

// observeQueued is an absolute occupancy fold for callers that already have
// an aggregate snapshot. The queue hot path uses addQueued so concurrent
// carriers cannot overwrite the current gauge with a stale snapshot.
func (s *QueueStats) observeQueued(nBytes, nItems int64) {
	if s == nil {
		return
	}
	atomic.StoreInt64(&s.QueuedBytesNow, nBytes)
	atomic.StoreInt64(&s.QueuedFramesNow, nItems)
	s.observeHighQueued(nBytes, nItems)
}

func (s *QueueStats) discard(nBytes, nItems int64) {
	if s == nil {
		return
	}
	// Close supplies the pre-close mailbox occupancy. Folding it here keeps
	// the high-water invariant independent of which operation created it.
	s.observeHighStream(nBytes, nItems)
}

func (s *QueueStats) overflowTerminated(wait time.Duration) {
	if s == nil {
		return
	}
	atomic.AddInt64(&s.OverflowTerminations, 1)
	n := wait.Nanoseconds()
	atomic.AddInt64(&s.OverflowWaitSumNanos, n)
	atomic.AddInt64(&s.OverflowWaitCount, 1)
	atomicMax(&s.OverflowWaitMaxNanos, n)
}

func (s *QueueStats) overflowTerminatedWorker() {
	if s == nil {
		return
	}
	atomic.AddInt64(&s.OverflowTerminationsWorker, 1)
}

func (s *QueueStats) writeFailure() {
	if s == nil {
		return
	}
	atomic.AddInt64(&s.WriteFailures, 1)
}

func (s *QueueStats) readFailure(isEOF bool) {
	if s == nil {
		return
	}
	if isEOF {
		atomic.AddInt64(&s.ReadEOF, 1)
		return
	}
	atomic.AddInt64(&s.ReadFailures, 1)
}

func (s *QueueStats) blackholeDeath() {
	if s == nil {
		return
	}
	atomic.AddInt64(&s.BlackholeDeaths, 1)
}

// Render returns the fixed queue metric line list for one carrier direction.
// Only the two compile-time direction prefixes are accepted; rejecting other
// prefixes keeps this renderer from becoming a variable-label surface.
func (s *QueueStats) Render(prefix string) string {
	return s.render(prefix)
}

func (s *QueueStats) render(prefix string) string {
	if prefix != "mux_up_" && prefix != "mux_down_" {
		return ""
	}
	if s == nil {
		return (&QueueStats{}).render(prefix)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%spush_accepted %d\n", prefix, atomicLoad(&s.PushAccepted))
	fmt.Fprintf(&b, "%spush_rejected_stream %d\n", prefix, atomicLoad(&s.PushRejectedStream))
	fmt.Fprintf(&b, "%spush_rejected_total %d\n", prefix, atomicLoad(&s.PushRejectedTotal))
	fmt.Fprintf(&b, "%spush_rejected_closed %d\n", prefix, atomicLoad(&s.PushRejectedClosed))
	fmt.Fprintf(&b, "%sstream_queued_bytes_high %d\n", prefix, atomicLoad(&s.StreamQueuedBytesHigh))
	fmt.Fprintf(&b, "%sstream_queued_frames_high %d\n", prefix, atomicLoad(&s.StreamQueuedFramesHigh))
	fmt.Fprintf(&b, "%squeued_bytes %d\n", prefix, atomicLoad(&s.QueuedBytesNow))
	fmt.Fprintf(&b, "%squeued_frames %d\n", prefix, atomicLoad(&s.QueuedFramesNow))
	fmt.Fprintf(&b, "%squeued_bytes_high %d\n", prefix, atomicLoad(&s.QueuedBytesHigh))
	fmt.Fprintf(&b, "%squeued_frames_high %d\n", prefix, atomicLoad(&s.QueuedFramesHigh))
	fmt.Fprintf(&b, "%soverflow_terminations %d\n", prefix, atomicLoad(&s.OverflowTerminations))
	fmt.Fprintf(&b, "%soverflow_terminations_worker %d\n", prefix, atomicLoad(&s.OverflowTerminationsWorker))
	fmt.Fprintf(&b, "%soverflow_wait_count %d\n", prefix, atomicLoad(&s.OverflowWaitCount))
	fmt.Fprintf(&b, "%soverflow_wait_sum_seconds %.6f\n", prefix, float64(atomicLoad(&s.OverflowWaitSumNanos))/float64(time.Second))
	fmt.Fprintf(&b, "%soverflow_wait_max_seconds %.6f\n", prefix, float64(atomicLoad(&s.OverflowWaitMaxNanos))/float64(time.Second))
	fmt.Fprintf(&b, "%scarrier_write_failures %d\n", prefix, atomicLoad(&s.WriteFailures))
	fmt.Fprintf(&b, "%scarrier_read_failures %d\n", prefix, atomicLoad(&s.ReadFailures))
	fmt.Fprintf(&b, "%scarrier_read_eof %d\n", prefix, atomicLoad(&s.ReadEOF))
	fmt.Fprintf(&b, "%sblackhole_deaths %d\n", prefix, atomicLoad(&s.BlackholeDeaths))
	return b.String()
}

func atomicLoad(p *int64) int64 {
	if p == nil {
		return 0
	}
	return atomic.LoadInt64(p)
}
