package connect

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// H1 path re-roll: the monitor of one live H1 websocket.
//
// runH1 builds an `h1PathConnection` after each dial, before it registers the
// connection's routes, and ticks it from the connection's watcher goroutine
// every TickInterval. Each connection resolves its own mode, in precedence
// order: the process override (SetH1PathRerollModeOverride), the environment
// (CONNECT_H1_PATH_REROLL), then the transport's settings. A later dial
// therefore picks up a mode the host changed, without a settings change of its
// own. Its role -- which selects the provider gates and the provider clamp --
// is resolved the same way, from SetH1PathRerollRoleOverride,
// CONNECT_H1_PATH_REROLL_ROLE and the settings, because a provider process is
// the only thing that knows its websocket to the platform is a provider's. There is no connection, and no per-frame, timer or syscall cost, when:
//   - the effective mode is Off;
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
// The dial that replaces a re-rolled connection carries a source port plan
// when the policy is FarRandom: its sockets bind a random ephemeral port far
// from the local ports the ledger convicted this network epoch
// (h1_source_port.go).
//
// In Observe a conviction is counted and logged, at most once per
// ConvictionLogInterval per connection. In Act, a conviction goes through the
// process ledger, keyed by the transport's route manager:
//   - noteConviction first, which counts an earlier re-roll on the same route
//     manager as unimproved when this conviction lands in its improvement
//     window;
//   - an observe-only connection stops there and is observed;
//   - allow, which may refuse (latched, daily budget, device spacing,
//     unconfirmed budget, provider gate), counted by reason;
//   - noteReroll, then the stale-tag mark on the shared baseline, and the
//     decision's action is reroll. runH1's watcher closes the connection and
//     the loop re-dials without the reconnect backoff.
// Clean ticks after a re-roll resolve it as improved (noteClean).
//
// A transport whose receive channel is unbuffered (TransportBufferSize 0) is
// not monitored either: our own consumer paces every delivery there, so no tick
// describes the path.
//
// The connection is owned by the watcher goroutine, which runH1 joins before
// close. Every method is nil-safe, so runH1 needs no check for an unmonitored
// connection. The connection counts ConnectionsMonitored, ConnectionsDormant at
// the dial gate, ConnectionsUnbuffered, KernelUnavailable (once per connection: no kernel socket, or
// its first read failed), SuppressedObserve and the ledger's refusals,
// Rerolls, Improved and Unimproved; runH1 counts RerollDials, and a re-roll
// dial's source port plan counts SourcePortBinds and SourcePortFallbacks, one
// per socket it plans.

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
	// replaces the process counters for the connection, its monitor and
	// runH1's re-roll dials
	stats *h1PathStats
	// replaces the process ledger
	ledger *h1PathLedger
	// replaces the random draw of re-roll dials' source port plans; must be
	// safe for concurrent use
	sourcePortRandom func(n int) int
}

type h1PathConnection struct {
	transport   *PlatformTransport
	settings    *H1PathRerollSettings
	stats       *h1PathStats
	hooks       *h1PathTestHooks
	ordinal     int
	mode        H1PathRerollMode
	modeSource  h1PathModeSource
	role        H1PathRerollRole
	logTicks    bool
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
	// clean ticks since the connection started or last convicted
	cleanTicks int
}

// Whether the connection's effective mode applies, and whether it may only
// observe. A transport that carries only control is Off whatever the mode is:
// its websocket carries no bulk traffic to classify.
func h1PathConnectionMode(
	settings *PlatformTransportSettings,
	effectiveMode H1PathRerollMode,
	proxied bool,
	extenderIp netip.Addr,
) (mode H1PathRerollMode, observeOnly bool) {
	if settings.TransportGenerator != nil {
		return H1PathRerollModeOff, false
	}
	mode = h1PathNormalizeMode(effectiveMode)
	if mode == H1PathRerollModeOff {
		return H1PathRerollModeOff, false
	}
	return mode, proxied || extenderIp.IsValid()
}

// the last bad CONNECT_H1_PATH_REROLL value logged by this process
var h1PathBadModeEnvValue atomic.Pointer[string]

// the last bad CONNECT_H1_PATH_REROLL_ROLE value logged by this process
var h1PathBadRoleEnvValue atomic.Pointer[string]

// True the first time this process sees the value, so a bad environment value
// is logged once rather than at every dial. Two connections racing here can
// both log.
func h1PathNoteBadEnv(logged *atomic.Pointer[string], envValue string) bool {
	if previous := logged.Load(); previous != nil && *previous == envValue {
		return false
	}
	logged.Store(&envValue)
	return true
}

// The role of a connection of this transport, reading the process override and
// the environment at each dial. A provider process declares itself through one
// of those two or through its settings; nothing here can tell a provider's
// websocket from a client's.
func (self *PlatformTransport) h1PathEffectiveRole() H1PathRerollRole {
	overrideRole, overrideSet := H1PathRerollRoleOverride()
	envValue := strings.TrimSpace(os.Getenv(H1PathRerollRoleEnv))
	role, envValid := h1PathEffectiveRole(
		&self.settings.H1PathReroll,
		overrideRole,
		overrideSet,
		envValue,
	)
	if !envValid && h1PathNoteBadEnv(&h1PathBadRoleEnvValue, envValue) {
		self.log.Infof(
			"[t]h1 path: ignoring %s=%q, want client or provider\n",
			H1PathRerollRoleEnv,
			envValue,
		)
	}
	return role
}

// The mode of a connection of this transport and where it came from, reading
// the process override and the environment at each dial, with the role the
// clamp applies.
func (self *PlatformTransport) h1PathEffectiveMode(role H1PathRerollRole) (H1PathRerollMode, h1PathModeSource) {
	overrideMode, overrideSet := H1PathRerollModeOverride()
	envValue := strings.TrimSpace(os.Getenv(H1PathRerollModeEnv))
	mode, source, envValid := h1PathEffectiveMode(
		&self.settings.H1PathReroll,
		role,
		overrideMode,
		overrideSet,
		envValue,
	)
	if !envValid && h1PathNoteBadEnv(&h1PathBadModeEnvValue, envValue) {
		self.log.Infof(
			"[t]h1 path: ignoring %s=%q, want off, observe or act\n",
			H1PathRerollModeEnv,
			envValue,
		)
	}
	return mode, source
}

// Logs the mode and its source the first time a connection of this transport
// resolves them, and again whenever they change. A mode from the settings is a
// key event; a mode a host or an operator set is logged unconditionally,
// because it explains behavior the settings do not.
func (self *PlatformTransport) noteH1PathMode(mode H1PathRerollMode, source h1PathModeSource) {
	noted := int32(mode)*8 + int32(source) + 1
	if self.h1PathModeNoted.Swap(noted) == noted {
		return
	}
	if source == h1PathModeSourceSettings {
		if v := self.log.V(1); v.Enabled() {
			v.Infof("[t]h1 path mode=%s source=%s\n", mode, source)
		}
		return
	}
	self.log.Infof("[t]h1 path mode=%s source=%s\n", mode, source)
}

// Whether every tick of a monitored connection is logged: the settings, or the
// environment.
func h1PathLogTicks(settings *H1PathRerollSettings) bool {
	return settings.LogTicks ||
		strings.TrimSpace(os.Getenv(H1PathRerollLogTicksEnv)) == "1"
}

// the H1 path counters of this transport: the process counters, or a test's
func (self *PlatformTransport) h1PathStats() *h1PathStats {
	if hooks := self.settings.h1PathTestHooks; hooks != nil && hooks.stats != nil {
		return hooks.stats
	}
	return &h1PathProcessStats
}

// the ledger of this transport's connections: the process ledger, or a test's
func (self *PlatformTransport) h1PathLedger() *h1PathLedger {
	if hooks := self.settings.h1PathTestHooks; hooks != nil && hooks.ledger != nil {
		return hooks.ledger
	}
	return h1PathDefaultLedger()
}

// The context of the dial that replaces a re-rolled connection. With policy
// FarRandom it carries a source port plan that excludes the ports the ledger
// convicted this network epoch; with policy Kernel it is ctx.
func (self *PlatformTransport) h1PathRerollDialContext(ctx context.Context) context.Context {
	settings := &self.settings.H1PathReroll
	if settings.SourcePortPolicy != H1SourcePortFarRandom {
		return ctx
	}
	var random func(n int) int
	if hooks := self.settings.h1PathTestHooks; hooks != nil {
		random = hooks.sourcePortRandom
	}
	plan := newH1SourcePortPlan(settings, self.h1PathLedger().excluded(), random, self.h1PathStats())
	return withH1SourcePortPlan(ctx, plan)
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
	role := self.h1PathEffectiveRole()
	effectiveMode, modeSource := self.h1PathEffectiveMode(role)
	mode, observeOnly := h1PathConnectionMode(self.settings, effectiveMode, proxied, extenderIp)
	if self.settings.TransportGenerator == nil {
		// a control-only transport is never monitored, whatever the mode says,
		// so its mode is not worth a line
		self.noteH1PathMode(mode, modeSource)
	}
	if mode == H1PathRerollModeOff {
		return nil
	}
	settings := &self.settings.H1PathReroll
	hooks := self.settings.h1PathTestHooks
	stats := self.h1PathStats()

	if self.settings.TransportBufferSize <= 0 {
		// An unbuffered receive channel makes our own consumer the pacer of
		// every delivery: the reader's full test, cap <= len, holds for every
		// message, so every tick is excluded and none can be read as the
		// path's. The monitor would be inert for the connection's life and
		// still pay for its ticks, its kernel reads and the per-frame
		// sampling, so there is no connection to tick at all.
		stats.ConnectionsUnbuffered.Add(1)
		return nil
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
		modeSource:  modeSource,
		role:        role,
		logTicks:    h1PathLogTicks(settings),
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
			"[t]h1 path monitor dial_rtt=%s kernel=%t port=%d mode=%s source=%s role=%s observe_only=%t\n",
			dialRtt,
			connection.rawConn != nil,
			connection.localPort,
			mode,
			modeSource,
			role,
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

// The monitor failed and this connection will not tick again: the observer
// stops sampling and the failure is counted, so an Observe rollout can tell a
// detector that died from one that saw nothing. The connection is left alone --
// the watcher that calls this is also what closes the websocket for a network
// change, so it keeps running with the monitor switched off.
func (self *h1PathConnection) monitorStopped(err any) {
	if self == nil {
		return
	}
	self.observer.setActive(false)
	self.stats.MonitorStopped.Add(1)
	self.transport.log.Infof("[t]h1 path monitor stopped: %s\n", err)
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
		sample.ackRtt = observerTick.ackRtt
		sample.ackRttSamples = observerTick.ackSamples
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
	if self.logTicks {
		self.logTick(&sample, &decision)
	}
	if self.hooks != nil && self.hooks.decision != nil {
		self.hooks.decision(self.ordinal, decision)
	}
	return decision
}

// the ledger of an Act connection: the process ledger, or a test's
func (self *h1PathConnection) ledger() *h1PathLedger {
	if self.hooks != nil && self.hooks.ledger != nil {
		return self.hooks.ledger
	}
	return h1PathDefaultLedger()
}

// Chooses the action for a verdict (see the file header). A loss denial,
// counted by the monitor, is suppressed. Observe never touches the ledger.
func (self *h1PathConnection) decide(now time.Time, decision *h1PathDecision) {
	act := self.mode == H1PathRerollModeAct
	key := self.transport.routeManager
	switch {
	case decision.convicted:
		self.cleanTicks = 0
		if !act {
			self.observe(decision)
			break
		}
		ledger := self.ledger()
		if ledger.noteConviction(key, self.settings, now) {
			self.stats.Unimproved.Add(1)
		}
		if self.observeOnly {
			self.observe(decision)
			break
		}
		allowed, reason := ledger.allow(
			self.settings,
			now,
			self.role,
			decision.confidence,
			now.Sub(self.monitor.start),
		)
		if !allowed {
			decision.action = h1PathActionSuppressed
			decision.reason = reason
			self.stats.recordSuppression(reason)
			break
		}
		ledger.noteReroll(key, self.settings, now, self.role, decision.confidence, self.localPort)
		// packs built for this connection, and their resends, carry old tags
		// that must not convict the next one
		self.transport.h1PathBaseline.markReroll(now, decision.pathRtt)
		self.stats.Rerolls.Add(1)
		decision.action = h1PathActionReroll
	case decision.reason != h1PathReasonNone:
		decision.action = h1PathActionSuppressed
	case decision.clean && act:
		self.cleanTicks += 1
		if self.settings.CleanTicks <= self.cleanTicks &&
			self.ledger().noteClean(key, self.settings, now, self.cleanTicks) {
			self.stats.Improved.Add(1)
		}
	}
	if decision.convicted || decision.reason != h1PathReasonNone {
		self.logVerdict(now, decision)
	}
}

func (self *h1PathConnection) observe(decision *h1PathDecision) {
	decision.action = h1PathActionObserve
	decision.reason = h1PathReasonObserve
	self.stats.recordSuppression(h1PathReasonObserve)
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
	ackQueue := "unknown"
	if decision.ackQueueKnown {
		ackQueue = decision.ackQueue.String()
	}
	self.transport.log.Infof(
		"[t]h1 path %s dir=%s confidence=%s ticks=%d/%d qd=%s ack_queue=%s rate=%s thin=%s rtt=%s loss=%d/%d kernel=%t port=%d mode=%s source=%s role=%s observe_only=%t action=%s reason=%s\n",
		verdict,
		decision.direction,
		decision.confidence,
		decision.collapsedTicks,
		self.settings.WindowTicks,
		queueDelay,
		ackQueue,
		h1PathBitRateString(decision.byteRate),
		h1PathBitRateString(decision.thinByteRate),
		decision.pathRtt,
		decision.lossTicks,
		decision.lossKnownTicks,
		self.rawConn != nil,
		self.localPort,
		self.mode,
		self.modeSource,
		self.role,
		self.observeOnly,
		decision.action,
		decision.reason,
	)
}

func (self *h1PathConnection) logTick(sample *h1PathSample, decision *h1PathDecision) {
	self.transport.log.Infof(
		"[t]h1path tick connection=%d read=%d write=%d read_bytes=%d receive_full=%d speed_test=%t standing_down=%t qd=%s qd_samples=%d ack_rtt_min=%s ack_rtt=%s/%d rx_bytes=%t/%d rx_ooo=%t/%d tx=%t acked=%d retrans=%d not_sent=%d min_rtt=%s mss=%d/%d dormant=%t clean=%t convicted=%t dir=%s confidence=%s action=%s reason=%s collapsed=%d rate=%s thin=%s rtt=%s\n",
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
		sample.ackRtt,
		sample.ackRttSamples,
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
