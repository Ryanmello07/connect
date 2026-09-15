package connect

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// H1 path re-roll: the monitor of one live H1 websocket.
//
// runH1 builds an `h1PathConnection` after each dial, before it registers the
// connection's routes, and ticks it from the connection's watcher goroutine
// every TickInterval. There is no connection, and no per-frame, timer or
// syscall cost, when:
//   - the mode is Off;
//   - the transport carries only control (a TransportGenerator is set);
//   - the dial round trip, a third of the dial duration, is below MinPathRtt.
//     A TCP connect, a TLS handshake and the upgrade take at least three round
//     trips, so a same-datacenter connection is dormant from registration and
//     counted as such.
//
// A far connection publishes an `h1RouteObserver` on its receive route. Each
// tick in which a message moved takes the observer's tick and one kernel
// reading of the websocket's socket, adds the reader's counters, and hands the
// sample to the `h1PathMonitor`. A tick in which nothing moved reads nothing.
// When the monitor goes dormant (a kernel or ack round trip below MinPathRtt)
// the observer stops sampling and the watcher stops the ticker.
//
// A connection through an extender or a proxy is observe-only: its kernel
// socket describes another leg, or nothing, and a re-dial does not choose the
// platform leg's 4-tuple.
//
// In Observe a conviction is counted and logged, at most once per
// ConvictionLogInterval per connection.
//
// The connection is owned by the watcher goroutine, which runH1 joins before
// close. Every method is nil-safe, so runH1 needs no check for an unmonitored
// connection. The connection counts ConnectionsMonitored, ConnectionsDormant at
// the dial gate, KernelUnavailable (once per connection: no kernel socket, or
// its first read failed) and SuppressedObserve.

// The per-connection counters runH1 keeps for the monitor. The reader and the
// writer update them; the watcher reads them.
type h1PathCounters struct {
	readMessageCount  *atomic.Uint64
	writeMessageCount *atomic.Uint64
	readByteCount     *atomic.Uint64
	receiveFullCount  *atomic.Uint64
	speedTestActive   *atomic.Bool
}

// Package test seams for the H1 path connections of one transport. Every
// field is optional. Connections are numbered from zero in dial order.
type h1PathTestHooks struct {
	// replaces the dial round trip measured for the connection
	dialRtt func(connectionOrdinal int, dialRtt time.Duration) time.Duration
	// edits each sample, after the connection filled it and before the monitor
	// reads it
	sample func(connectionOrdinal int, sample *h1PathSample)
	// borrows each decision after the connection chose its action; must not
	// block
	decision func(connectionOrdinal int, decision h1PathDecision)
	// replaces the process counters for the connection and its monitor
	stats *h1PathStats
}

type h1PathConnection struct {
	transport   *PlatformTransport
	settings    *H1PathRerollSettings
	stats       *h1PathStats
	hooks       *h1PathTestHooks
	ordinal     int
	mode        H1PathRerollMode
	observeOnly bool

	monitor  *h1PathMonitor
	observer *h1RouteObserver
	counters h1PathCounters

	// nil when the socket is not a direct TCP socket to the platform, or its
	// first read failed
	rawConn        syscall.RawConn
	localPort      int
	kernelReadOk   bool
	lowestRtt      time.Duration
	sampled        bool
	lastReadCount  uint64
	lastWriteCount uint64

	lastLogTime time.Time
}

// The connection's mode, and whether it may only observe. Off when the settings
// are Off or the transport carries only control. A provider without
// AllowProviderAct is clamped to Observe.
func h1PathConnectionMode(
	settings *PlatformTransportSettings,
	proxied bool,
	extenderIp netip.Addr,
) (mode H1PathRerollMode, observeOnly bool) {
	if settings.TransportGenerator != nil {
		return H1PathRerollModeOff, false
	}
	reroll := &settings.H1PathReroll
	mode = reroll.Mode
	switch mode {
	case H1PathRerollModeObserve, H1PathRerollModeAct:
	default:
		return H1PathRerollModeOff, false
	}
	if mode == H1PathRerollModeAct &&
		reroll.Role == H1PathRerollRoleProvider &&
		!reroll.AllowProviderAct {
		mode = H1PathRerollModeObserve
	}
	return mode, proxied || extenderIp.IsValid()
}

// Returns nil when the connection is not monitored (see the file header).
func (self *PlatformTransport) newH1PathConnection(
	ws *websocket.Conn,
	extenderIp netip.Addr,
	dialDuration time.Duration,
	connectionOrdinal int,
	counters h1PathCounters,
) *h1PathConnection {
	proxied := self.clientStrategy != nil &&
		self.clientStrategy.settings != nil &&
		self.clientStrategy.settings.ProxySettings != nil
	mode, observeOnly := h1PathConnectionMode(self.settings, proxied, extenderIp)
	if mode == H1PathRerollModeOff {
		return nil
	}
	settings := &self.settings.H1PathReroll
	hooks := self.settings.h1PathTestHooks
	stats := &h1PathProcessStats
	if hooks != nil && hooks.stats != nil {
		stats = hooks.stats
	}

	dialRtt := dialDuration / 3
	if hooks != nil && hooks.dialRtt != nil {
		dialRtt = hooks.dialRtt(connectionOrdinal, dialRtt)
	}
	monitor := newH1PathMonitor(settings, time.Now(), dialRtt)
	if monitor == nil {
		stats.ConnectionsDormant.Add(1)
		return nil
	}
	monitor.stats = stats

	connection := &h1PathConnection{
		transport:   self,
		settings:    settings,
		stats:       stats,
		hooks:       hooks,
		ordinal:     connectionOrdinal,
		mode:        mode,
		observeOnly: observeOnly,
		monitor:     monitor,
		observer:    newH1RouteObserver(self.h1PathBaseline, settings.PackSampleEvery),
		counters:    counters,
	}
	if rawConn, localPort, ok := h1PathKernelSocket(ws, self.platformUrl); ok {
		connection.rawConn = rawConn
		connection.localPort = localPort
	} else {
		stats.KernelUnavailable.Add(1)
	}
	stats.ConnectionsMonitored.Add(1)
	if self.log.V(1).Enabled() {
		self.log.Infof(
			"[t]h1 path monitor dial_rtt=%s kernel=%t port=%d mode=%s observe_only=%t\n",
			dialRtt,
			connection.rawConn != nil,
			connection.localPort,
			mode,
			observeOnly,
		)
	}
	return connection
}

// the receive observer to publish on the connection's route; nil when not
// monitored
func (self *h1PathConnection) observerOrNil() *h1RouteObserver {
	if self == nil {
		return nil
	}
	return self.observer
}

func (self *h1PathConnection) tickInterval() time.Duration {
	if self == nil {
		return time.Second
	}
	return max(self.settings.TickInterval, time.Millisecond)
}

// Stops the observer sampling. Safe to call while a route snapshot still
// carries it.
func (self *h1PathConnection) close() {
	if self == nil {
		return
	}
	self.observer.setActive(false)
}

// Takes one sample and returns the monitor's decision with the connection's
// action. A dormant decision means the connection will never tick again.
func (self *h1PathConnection) tick(now time.Time) h1PathDecision {
	if self == nil {
		return h1PathDecision{dormant: true}
	}
	sample := h1PathSample{
		now:               now,
		readMessageCount:  self.counters.readMessageCount.Load(),
		writeMessageCount: self.counters.writeMessageCount.Load(),
		readByteCount:     self.counters.readByteCount.Load(),
		receiveFullCount:  self.counters.receiveFullCount.Load(),
		speedTestActive:   self.counters.speedTestActive.Load(),
	}
	sample.standingDown, _ = self.transport.standDown(TransportModeH1)

	moved := !self.sampled ||
		sample.readMessageCount != self.lastReadCount ||
		sample.writeMessageCount != self.lastWriteCount
	self.sampled = true
	self.lastReadCount = sample.readMessageCount
	self.lastWriteCount = sample.writeMessageCount
	kernelRead := false
	if moved {
		observerTick := self.observer.takeTick(now)
		if observerTick.known {
			sample.queueDelay = observerTick.queueDelay
			sample.queueDelaySamples = observerTick.samples
		}
		sample.ackRttMin = observerTick.ackRttMin
		if self.rawConn != nil {
			var kernelSample h1PathKernelSample
			if h1PathReadKernel(self.rawConn, &kernelSample) {
				kernelRead = true
				self.kernelReadOk = true
				kernelSample.copyTo(&sample, &self.lowestRtt)
			} else {
				if !self.kernelReadOk {
					// this socket's counters cannot be read here at all
					self.stats.KernelUnavailable.Add(1)
				}
				// a closed socket or a refused read; stop paying for it
				self.rawConn = nil
			}
		}
	}
	if !kernelRead {
		// an idle tick keeps the round trip the kernel already reported; the
		// monitor ignores its other fields, since nothing moved
		sample.minRtt = max(self.lowestRtt, 0)
	}
	if self.hooks != nil && self.hooks.sample != nil {
		self.hooks.sample(self.ordinal, &sample)
	}

	decision := self.monitor.tick(sample)
	if decision.dormant {
		self.observer.setActive(false)
	} else {
		self.decide(now, &decision)
	}
	if self.settings.LogTicks {
		self.logTick(&sample, &decision)
	}
	if self.hooks != nil && self.hooks.decision != nil {
		self.hooks.decision(self.ordinal, decision)
	}
	return decision
}

// Chooses the action for a verdict: a conviction is observed, and a loss
// denial (counted by the monitor) is suppressed.
func (self *h1PathConnection) decide(now time.Time, decision *h1PathDecision) {
	switch {
	case decision.convicted:
		decision.action = h1PathActionObserve
		decision.reason = h1PathReasonObserve
		self.stats.recordSuppression(h1PathReasonObserve)
		self.logVerdict(now, decision)
	case decision.reason != h1PathReasonNone:
		decision.action = h1PathActionSuppressed
		self.logVerdict(now, decision)
	}
}

// at most one line per ConvictionLogInterval per connection
func (self *h1PathConnection) logVerdict(now time.Time, decision *h1PathDecision) {
	if !self.lastLogTime.IsZero() && now.Sub(self.lastLogTime) < self.settings.ConvictionLogInterval {
		return
	}
	self.lastLogTime = now
	verdict := "conviction"
	if !decision.convicted {
		verdict = "loss denied"
	}
	queueDelay := "unknown"
	if decision.queueDelayKnown {
		queueDelay = decision.queueDelay.String()
	}
	self.transport.log.Infof(
		"[t]h1 path %s dir=%s confidence=%s ticks=%d/%d qd=%s rate=%s thin=%s rtt=%s loss=%d/%d kernel=%t port=%d mode=%s observe_only=%t action=%s reason=%s\n",
		verdict,
		decision.direction,
		decision.confidence,
		decision.collapsedTicks,
		self.settings.WindowTicks,
		queueDelay,
		h1PathBitRateString(decision.byteRate),
		h1PathBitRateString(decision.thinByteRate),
		decision.pathRtt,
		decision.lossTicks,
		decision.lossKnownTicks,
		self.rawConn != nil,
		self.localPort,
		self.mode,
		self.observeOnly,
		decision.action,
		decision.reason,
	)
}

func (self *h1PathConnection) logTick(sample *h1PathSample, decision *h1PathDecision) {
	self.transport.log.Infof(
		"[t]h1path tick connection=%d read=%d write=%d read_bytes=%d receive_full=%d speed_test=%t standing_down=%t qd=%s qd_samples=%d ack_rtt=%s rx_bytes=%t/%d rx_ooo=%t/%d tx=%t acked=%d retrans=%d not_sent=%d min_rtt=%s mss=%d/%d dormant=%t clean=%t convicted=%t dir=%s confidence=%s action=%s reason=%s collapsed=%d rate=%s thin=%s rtt=%s\n",
		self.ordinal,
		sample.readMessageCount,
		sample.writeMessageCount,
		sample.readByteCount,
		sample.receiveFullCount,
		sample.speedTestActive,
		sample.standingDown,
		sample.queueDelay,
		sample.queueDelaySamples,
		sample.ackRttMin,
		sample.rxBytesKnown,
		sample.rxBytes,
		sample.rxOooKnown,
		sample.rxOoo,
		sample.txKnown,
		sample.txAckedBytes,
		sample.txRetrans,
		sample.txNotSent,
		sample.minRtt,
		sample.rcvMss,
		sample.sndMss,
		decision.dormant,
		decision.clean,
		decision.convicted,
		decision.direction,
		decision.confidence,
		decision.action,
		decision.reason,
		decision.collapsedTicks,
		h1PathBitRateString(decision.byteRate),
		h1PathBitRateString(decision.thinByteRate),
		decision.pathRtt,
	)
}

func h1PathBitRateString(byteRate float64) string {
	return fmt.Sprintf("%.2fMb/s", byteRate*8/(1000*1000))
}
