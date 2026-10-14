package connect

import (
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// The cost of closing a nat flow's upstream socket, bounded per buffer.
//
// On Windows a closesocket can block in the kernel for seconds, and a Go
// syscall that blocks keeps its OS thread: the scheduler hands the flow's P to
// a new thread and the blocked one stays parked until the kernel returns. A
// flow cap evicts by canceling, so every eviction leaves a socket that is
// still closing while the replacement flow opens a new one. Under sustained
// churn a device's local nat had 9,992 evicted flows closing at once (9,990
// inside closesocket) against its ipv6 buffer's 2,048-flow cap, and the Go
// runtime stopped at its 10,000-thread limit ("fatal error: thread
// exhaustion").
//
// Two bounds keep that from recurring, whatever the kernel's close latency:
//   - `flowSocketCloseLimiter` lets at most a fixed number of a buffer's flows
//     be inside the close of their upstream socket at once. A net.Conn close
//     waits until the descriptor is destroyed, even when the last reference
//     is dropped by the flow's reader goroutine, so holding a slot across the
//     first `Close` bounds the threads those closes can hold.
//   - `flowSocketOccupancy` counts a buffer's flows from admission until their
//     flow goroutine has finished, socket close included, so admission sees
//     the flows that left the index but still hold a socket. While that
//     closing backlog is at its limit, new flows are refused, so eviction
//     cannot open sockets faster than they close.
//
// A socket whose dial fails after it exists is closed by Go inside the dial,
// on the flow goroutine, outside the limiter. Such a flow is counted while it
// dials, so those closes are bounded by the cap and the backlog limit. Icmp
// flows hold IcmpCreateFile handles on Windows, not sockets, and have small
// caps; they are not covered.
//
// Both are owned by one buffer and safe for concurrent use. A nil limiter or
// occupancy (a buffer or sequence built directly, in tests) is inert.

// The default concurrent socket closes per buffer. Windows is strict because
// a close can hold a thread for seconds; elsewhere a udp or tcp close(2) does
// not block, and the bound is a backstop that never waits in practice.
func defaultFlowSocketCloseConcurrency() int {
	if runtime.GOOS == "windows" {
		return 16
	}
	return 256
}

// A close that takes at least this long is logged, so a slow kernel close is
// visible before it becomes a backlog.
const flowSocketSlowCloseThreshold = time.Second

// the rate limit of the slow-close and refusal log lines
const flowSocketCloseLogInterval = 5 * time.Second

// A buffer's close slots.
type flowSocketCloseLimiter struct {
	log   Logger
	tag   string
	slots chan struct{}
	// closes waiting for a slot
	waitingCount atomic.Int64
	slowThrottle *logThrottle
}

// concurrency <= 0 selects the platform default.
func newFlowSocketCloseLimiter(concurrency int, log Logger, tag string) *flowSocketCloseLimiter {
	if concurrency <= 0 {
		concurrency = defaultFlowSocketCloseConcurrency()
	}
	return &flowSocketCloseLimiter{
		log:          loggerOrDefault(log),
		tag:          tag,
		slots:        make(chan struct{}, concurrency),
		slowThrottle: newLogThrottle(flowSocketCloseLogInterval),
	}
}

// Closes `socket` holding one slot for the whole close. A nil limiter closes
// inline, for sequences built outside a buffer.
func (self *flowSocketCloseLimiter) close(socket io.Closer) error {
	if self == nil {
		return socket.Close()
	}
	select {
	case self.slots <- struct{}{}:
	default:
		self.waitingCount.Add(1)
		self.slots <- struct{}{}
		self.waitingCount.Add(-1)
	}
	defer func() {
		<-self.slots
	}()
	closeStart := time.Now()
	err := socket.Close()
	if closeDuration := time.Since(closeStart); flowSocketSlowCloseThreshold <= closeDuration {
		if ok, suppressed := self.slowThrottle.Allow(time.Now()); ok {
			self.log.Infof(
				"[lnr]%s socket close took %s (%d closing, %d waiting to close)%s\n",
				self.tag,
				closeDuration.Round(time.Millisecond),
				len(self.slots),
				self.waitingCount.Load(),
				suppressedSuffix(suppressed),
			)
		}
	}
	return err
}

// closes waiting for a slot
func (self *flowSocketCloseLimiter) waiting() int {
	if self == nil {
		return 0
	}
	return int(self.waitingCount.Load())
}

// The minimum closing backlog a capped buffer tolerates before it refuses new
// flows. A quarter of the cap above this keeps ordinary churn admitted while a
// close is merely slow.
const minFlowSocketCloseBacklogLimit = 64

// 0 disables the backlog check. An explicit `configured` wins; otherwise a
// capped buffer gets a quarter of its cap, at least the minimum.
func flowSocketCloseBacklogLimit(configured int, globalLimit int) int {
	if configured != 0 {
		return max(0, configured)
	}
	if globalLimit <= 0 {
		return 0
	}
	return max(minFlowSocketCloseBacklogLimit, globalLimit/4)
}

// A buffer's flows from admission until their flow goroutine has finished.
type flowSocketOccupancy struct {
	log   Logger
	tag   string
	count atomic.Int64
	// rate limits the refusal log line
	refusedThrottle *logThrottle
}

func newFlowSocketOccupancy(log Logger, tag string) *flowSocketOccupancy {
	return &flowSocketOccupancy{
		log:             loggerOrDefault(log),
		tag:             tag,
		refusedThrottle: newLogThrottle(flowSocketCloseLogInterval),
	}
}

// Counts one admitted flow, and returns the release its owner calls once the
// flow goroutine has finished, socket close included. The release is
// idempotent.
func (self *flowSocketOccupancy) occupy() func() {
	if self == nil {
		return func() {}
	}
	self.count.Add(1)
	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			self.count.Add(-1)
		})
	}
}

// admitted flows whose socket has not finished closing
func (self *flowSocketOccupancy) occupied() int {
	if self == nil {
		return 0
	}
	return int(self.count.Load())
}

// Whether a new flow may open while `indexedCount` flows are live. The
// flows past the index are the ones still closing; at `backlogLimit` or more
// new flows are refused (and the refusal logged, rate limited).
func (self *flowSocketOccupancy) admit(indexedCount int, backlogLimit int) bool {
	if self == nil || backlogLimit <= 0 {
		return true
	}
	closingCount := self.occupied() - indexedCount
	if closingCount < backlogLimit {
		return true
	}
	if ok, suppressed := self.refusedThrottle.Allow(time.Now()); ok {
		self.log.Infof(
			"[lnr]%s new flow refused: %d flows are still closing their sockets (limit %d, %d live)%s\n",
			self.tag,
			closingCount,
			backlogLimit,
			indexedCount,
			suppressedSuffix(suppressed),
		)
	}
	return false
}
