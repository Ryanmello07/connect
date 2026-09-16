package connect

import (
	"math/bits"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// H1 path re-roll: detection and budgeting for an H1 websocket whose TCP
// 4-tuple was hashed onto a lossy network path.
//
// A relay path can hash each TCP 4-tuple onto one of several members, and a
// lossy member holds a websocket at a few Mb/s for its whole life while the
// same client on another source port runs at full rate. Transfer cannot see
// this: the carrier is reliable, so it shows no resends, only an ack round trip
// that climbs to seconds while the window sits queued in the far socket.
//
// This file holds the pure parts, with no call sites of their own:
//   - the settings and their defaults (library default Observe), the
//     environment variables and the process mode override, and the precedence
//     between them;
//   - `h1PathMonitor`, one per connection, which classifies ticks from a
//     sampled queue delay, the delivered rate and optional kernel TCP counters,
//     and convicts a direction after a sustained collapse with loss evidence;
//   - `h1PathLedger`, one per process, which decides whether a conviction may
//     re-roll the connection: an unimproved latch, a daily budget, device
//     spacing, an unconfirmed budget per network epoch and the provider gate;
//   - `h1PathStats`, process counters with an exported snapshot.
//
// A monitor is owned by one goroutine. The ledger and the stats are safe for
// concurrent use.

// How far the H1 path monitor may go. The zero value is Off, so settings built
// by hand stay inert.
type H1PathRerollMode int

const (
	H1PathRerollModeOff     H1PathRerollMode = 0
	H1PathRerollModeObserve H1PathRerollMode = 1
	H1PathRerollModeAct     H1PathRerollMode = 2
)

// Accepts off, observe and act, case-insensitive, with surrounding space
// ignored.
func ParseH1PathRerollMode(s string) (H1PathRerollMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off":
		return H1PathRerollModeOff, true
	case "observe":
		return H1PathRerollModeObserve, true
	case "act":
		return H1PathRerollModeAct, true
	default:
		return H1PathRerollModeOff, false
	}
}

// The environment variable that sets the mode of every H1 connection dialed
// after it is read: off, observe or act. It wins over the settings, and the
// process override wins over it. A value that does not parse is ignored and
// logged once.
const H1PathRerollModeEnv = "CONNECT_H1_PATH_REROLL"

// "1" logs one line per monitor tick, whatever the settings say.
const H1PathRerollLogTicksEnv = "CONNECT_H1_PATH_REROLL_LOG_TICKS"

// Anything but Off, Observe and Act is Off, so a value from outside the
// package cannot act by accident.
func h1PathNormalizeMode(mode H1PathRerollMode) H1PathRerollMode {
	switch mode {
	case H1PathRerollModeObserve, H1PathRerollModeAct:
		return mode
	default:
		return H1PathRerollModeOff
	}
}

// Where a connection's mode came from, for its log lines.
type h1PathModeSource int

const (
	h1PathModeSourceSettings h1PathModeSource = 0
	h1PathModeSourceEnv      h1PathModeSource = 1
	h1PathModeSourceOverride h1PathModeSource = 2
)

func (self h1PathModeSource) String() string {
	switch self {
	case h1PathModeSourceEnv:
		return "env"
	case h1PathModeSourceOverride:
		return "override"
	default:
		return "settings"
	}
}

// the process override as mode + 1; zero is no override
var h1PathModeOverrideValue atomic.Int32

// SetH1PathRerollModeOverride sets the H1 path re-roll mode of every
// connection dialed after it, over the environment and over each transport's
// settings. It is the host's kill switch: SetH1PathRerollModeOverride(Off)
// stops the monitor everywhere without a settings change or a reconnect of its
// own. An unknown mode is stored as Off.
func SetH1PathRerollModeOverride(mode H1PathRerollMode) {
	h1PathModeOverrideValue.Store(int32(h1PathNormalizeMode(mode)) + 1)
}

// ClearH1PathRerollModeOverride returns to the environment and the settings.
func ClearH1PathRerollModeOverride() {
	h1PathModeOverrideValue.Store(0)
}

// H1PathRerollModeOverride is the process override, and whether one is set.
func H1PathRerollModeOverride() (H1PathRerollMode, bool) {
	value := h1PathModeOverrideValue.Load()
	if value == 0 {
		return H1PathRerollModeOff, false
	}
	return H1PathRerollMode(value - 1), true
}

// The mode of a connection and where it came from, in precedence order: the
// process override, then the environment, then the settings. An empty
// environment value, or one that does not parse, falls through; envValid is
// false only for a value that was set and did not parse, so the caller can log
// it once. A provider is then clamped to Observe unless AllowProviderAct,
// whichever level chose Act: a provider's re-dial counts against its
// reliability.
func h1PathEffectiveMode(
	settings *H1PathRerollSettings,
	overrideMode H1PathRerollMode,
	overrideSet bool,
	envValue string,
) (mode H1PathRerollMode, source h1PathModeSource, envValid bool) {
	mode = h1PathNormalizeMode(settings.Mode)
	source = h1PathModeSourceSettings
	envValid = true
	if envValue != "" {
		if envMode, ok := ParseH1PathRerollMode(envValue); ok {
			mode = envMode
			source = h1PathModeSourceEnv
		} else {
			envValid = false
		}
	}
	if overrideSet {
		mode = h1PathNormalizeMode(overrideMode)
		source = h1PathModeSourceOverride
	}
	if mode == H1PathRerollModeAct &&
		settings.Role == H1PathRerollRoleProvider &&
		!settings.AllowProviderAct {
		mode = H1PathRerollModeObserve
	}
	return mode, source, envValid
}

func (self H1PathRerollMode) String() string {
	switch self {
	case H1PathRerollModeOff:
		return "off"
	case H1PathRerollModeObserve:
		return "observe"
	case H1PathRerollModeAct:
		return "act"
	default:
		return "unknown"
	}
}

// Selects the gates that apply. A provider's re-dial is counted against its
// reliability, so it acts only when explicitly allowed and then through its own
// age and spacing gates.
type H1PathRerollRole int

const (
	H1PathRerollRoleClient   H1PathRerollRole = 0
	H1PathRerollRoleProvider H1PathRerollRole = 1
)

func (self H1PathRerollRole) String() string {
	switch self {
	case H1PathRerollRoleClient:
		return "client"
	case H1PathRerollRoleProvider:
		return "provider"
	default:
		return "unknown"
	}
}

// How a re-roll dial chooses its local port. Kernel leaves it to connect(),
// which on linux moves only a few ports from the last one to the same
// destination.
type H1SourcePortPolicy int

const (
	H1SourcePortKernel    H1SourcePortPolicy = 0
	H1SourcePortFarRandom H1SourcePortPolicy = 1
)

// Configures the H1 path monitor and ledger. Durations and counts are read on
// every tick and must not be mutated after the owning transport is
// constructed.
type H1PathRerollSettings struct {
	Mode H1PathRerollMode
	Role H1PathRerollRole
	// lets Role Provider reach Act; without it a provider is clamped to Observe
	AllowProviderAct bool
	// logs one line per tick with every input
	LogTicks bool

	TickInterval time.Duration
	// collapsed ticks are counted over the last WindowTicks (at most 16)
	WindowTicks  int
	ConvictTicks int
	// no verdict before the connection is this old
	MinConnectionAge time.Duration
	// a path round trip below this makes the connection dormant
	MinPathRtt time.Duration
	// the round trip used for the thin rate is at least this
	RttFloor time.Duration
	// the queue delay threshold is max(QueueDelayFloor, QueueDelayRttMultiple x path rtt)
	QueueDelayFloor       time.Duration
	QueueDelayRttMultiple int
	// demand per tick, below which a tick is neither collapsed nor clean
	MinTickByteCount ByteCount
	// pack samples needed in a tick for its queue delay to be known
	MinTickPackSamples int
	// the receive observer samples one frame in this many, rounded up to a power of two
	PackSampleEvery int
	// the thin rate is ThinSegmentsPerRtt x mss per round trip
	ThinSegmentsPerRtt int
	// mss when the kernel does not report one
	DefaultMss int
	// loss evidence is counted over the last LossWindowTicks (at most 16)
	LossWindowTicks int
	RxLossMinTicks  int
	TxLossMinTicks  int
	// the floor on kernel unsent bytes for a backlogged send-side tick; the
	// backlog must also take at least the queue delay threshold to drain
	SendBacklogByteCount ByteCount
	// the queue delay baseline is the minimum over BaselineBucketCount buckets
	// (at most 16)
	BaselineBucketDuration time.Duration
	BaselineBucketCount    int
	// the ack echo round trip is the minimum over this window
	AckRttWindow time.Duration

	// clean ticks after a re-roll that count it as improved
	CleanTicks int
	// a conviction on the same route manager this soon after a re-roll counts it as unimproved
	ImprovementWindow time.Duration
	// minimum time between any two re-rolls on the device
	DeviceRerollSpacing time.Duration
	// unimproved re-rolls in one network epoch that set the latch
	MaxUnimprovedRerolls int
	// re-rolls on an unconfirmed conviction allowed in one network epoch
	MaxUnconfirmedRerolls int
	// unimproved re-rolls in a rolling 24 hours that stop re-rolls (at most 32)
	MaxUnimprovedRerollsPerDay int
	LatchDuration              time.Duration
	// a network change clears a latch only once it is at least this old
	LatchMinAgeForNetworkReset time.Duration
	// provider connections re-roll only once at least this old
	ProviderMinConnectionAge time.Duration
	// minimum time between two provider re-rolls
	ProviderRerollSpacing time.Duration

	SourcePortPolicy H1SourcePortPolicy
	// a far-random port is at least this far from every port convicted this epoch
	SourcePortExcludeRadius int

	// at most one conviction log line per connection per interval
	ConvictionLogInterval time.Duration
}

func DefaultH1PathRerollSettings() H1PathRerollSettings {
	return H1PathRerollSettings{
		Mode:                       H1PathRerollModeObserve,
		Role:                       H1PathRerollRoleClient,
		AllowProviderAct:           false,
		LogTicks:                   false,
		TickInterval:               500 * time.Millisecond,
		WindowTicks:                5,
		ConvictTicks:               4,
		MinConnectionAge:           3 * time.Second,
		MinPathRtt:                 20 * time.Millisecond,
		RttFloor:                   25 * time.Millisecond,
		QueueDelayFloor:            1 * time.Second,
		QueueDelayRttMultiple:      10,
		MinTickByteCount:           kib(32),
		MinTickPackSamples:         2,
		PackSampleEvery:            16,
		ThinSegmentsPerRtt:         256,
		DefaultMss:                 1448,
		LossWindowTicks:            10,
		RxLossMinTicks:             2,
		TxLossMinTicks:             2,
		SendBacklogByteCount:       kib(256),
		BaselineBucketDuration:     10 * time.Second,
		BaselineBucketCount:        12,
		AckRttWindow:               10 * time.Minute,
		CleanTicks:                 20,
		ImprovementWindow:          120 * time.Second,
		DeviceRerollSpacing:        2 * time.Second,
		MaxUnimprovedRerolls:       2,
		MaxUnconfirmedRerolls:      1,
		MaxUnimprovedRerollsPerDay: 6,
		LatchDuration:              30 * time.Minute,
		LatchMinAgeForNetworkReset: 5 * time.Minute,
		ProviderMinConnectionAge:   120 * time.Second,
		ProviderRerollSpacing:      10 * time.Minute,
		SourcePortPolicy:           H1SourcePortFarRandom,
		SourcePortExcludeRadius:    256,
		ConvictionLogInterval:      30 * time.Second,
	}
}

// the rings are 16-bit maps, newest tick in bit zero
const h1PathRingTickCount = 16

func h1PathRingMask(tickCount int) uint16 {
	tickCount = min(h1PathRingTickCount, max(1, tickCount))
	return uint16((1 << tickCount) - 1)
}

func h1PathRingPush(ring uint16, set bool) uint16 {
	ring <<= 1
	if set {
		ring |= 1
	}
	return ring
}

// One observation of one connection. Counters are cumulative since the
// connection started; the monitor takes deltas between the ticks it accepts.
// A kernel field is read only when its known flag is set on both ends of a
// delta.
type h1PathSample struct {
	now time.Time

	// websocket messages delivered by the reader and written by the writer
	readMessageCount  uint64
	writeMessageCount uint64
	// websocket payload bytes delivered by the reader
	readByteCount uint64
	// offers that found the receive channel full
	receiveFullCount uint64
	speedTestActive  bool
	standingDown     bool

	// from the receive observer's tick; the delay is known when there are at
	// least MinTickPackSamples samples
	queueDelay        time.Duration
	queueDelaySamples int
	// the minimum ack echo round trip over AckRttWindow; zero is unknown
	ackRttMin time.Duration

	rxBytesKnown bool
	rxBytes      uint64
	// linux counts out-of-order packets, darwin out-of-order bytes; only
	// advancement is read
	rxOooKnown   bool
	rxOoo        uint64
	txKnown      bool
	txAckedBytes uint64
	txRetrans    uint64
	txNotSent    uint64
	// the kernel minimum round trip, or the minimum smoothed round trip seen
	// where the kernel keeps no minimum; zero is unknown
	minRtt time.Duration
	// zero is unknown
	rcvMss int
	sndMss int
}

type h1PathDirection int

const (
	h1PathDirectionNone h1PathDirection = 0
	h1PathDirectionRx   h1PathDirection = 1
	h1PathDirectionTx   h1PathDirection = 2
)

func (self h1PathDirection) String() string {
	switch self {
	case h1PathDirectionRx:
		return "rx"
	case h1PathDirectionTx:
		return "tx"
	default:
		return "none"
	}
}

type h1PathConfidence int

const (
	h1PathConfidenceNone        h1PathConfidence = 0
	h1PathConfidenceConfirmed   h1PathConfidence = 1
	h1PathConfidenceUnconfirmed h1PathConfidence = 2
)

func (self h1PathConfidence) String() string {
	switch self {
	case h1PathConfidenceConfirmed:
		return "confirmed"
	case h1PathConfidenceUnconfirmed:
		return "unconfirmed"
	default:
		return "none"
	}
}

type h1PathAction int

const (
	h1PathActionNone       h1PathAction = 0
	h1PathActionObserve    h1PathAction = 1
	h1PathActionReroll     h1PathAction = 2
	h1PathActionSuppressed h1PathAction = 3
)

func (self h1PathAction) String() string {
	switch self {
	case h1PathActionObserve:
		return "observe"
	case h1PathActionReroll:
		return "reroll"
	case h1PathActionSuppressed:
		return "suppressed"
	default:
		return "none"
	}
}

// Why a conviction did not re-roll, in the order the checks run.
type h1PathReason string

const (
	h1PathReasonNone              h1PathReason = ""
	h1PathReasonLossDenied        h1PathReason = "lossDenied"
	h1PathReasonObserve           h1PathReason = "observe"
	h1PathReasonRole              h1PathReason = "role"
	h1PathReasonLatched           h1PathReason = "latched"
	h1PathReasonDailyBudget       h1PathReason = "dailyBudget"
	h1PathReasonSpacing           h1PathReason = "spacing"
	h1PathReasonUnconfirmedBudget h1PathReason = "unconfirmedBudget"
	h1PathReasonProviderGate      h1PathReason = "providerGate"
)

// The monitor's verdict for one sample. The monitor sets action none; the
// connection that owns it decides observe, reroll or suppressed. The
// remaining fields are the inputs of the verdict, for the log line.
type h1PathDecision struct {
	dormant    bool
	convicted  bool
	direction  h1PathDirection
	confidence h1PathConfidence
	clean      bool
	action     h1PathAction
	reason     h1PathReason

	// collapsed ticks in the window of the direction evaluated
	collapsedTicks int
	// ticks with loss evidence, and ticks where the evidence was known, in the loss window
	lossTicks       int
	lossKnownTicks  int
	queueDelay      time.Duration
	queueDelayKnown bool
	// delivered bytes per second in the direction evaluated
	byteRate     float64
	thinByteRate float64
	pathRtt      time.Duration
}

// Classifies the ticks of one H1 connection and convicts a direction whose
// delivery collapsed:
//   - thr = max(QueueDelayFloor, QueueDelayRttMultiple x pathRtt), and
//     thin = ThinSegmentsPerRtt x mss / max(pathRtt, RttFloor);
//   - rx collapsed: not excluded, demand, queue delay known and at least thr,
//     rate below thin;
//   - tx collapsed: not excluded, kernel tx known, unsent at least
//     SendBacklogByteCount, acked bytes advancing below thin;
//   - clean: not excluded, demand, and a direction at or above thin;
//   - excluded, for both directions: the receive channel was full, the speed
//     test echo is active, or the transport is standing down H1;
//   - a direction convicts with ConvictTicks of the last WindowTicks collapsed,
//     the connection at least MinConnectionAge old, and loss evidence over the
//     last LossWindowTicks: rx is confirmed by out-of-order data in
//     RxLossMinTicks ticks, denied when the kernel reports the field and fewer
//     ticks show it, and unconfirmed when the field is unknown; tx needs
//     retransmits in TxLossMinTicks ticks.
//
// A conviction resets every ring. A denial resets only that direction's
// collapsed ring, so it is evaluated again after ConvictTicks more collapsed
// ticks against a loss window that kept its history.
//
// The monitor counts Ticks, the conviction counters, SuppressedLossDenied and
// ConnectionsDormant when a tick makes it dormant. Not safe for concurrent use.
type h1PathMonitor struct {
	settings *H1PathRerollSettings
	stats    *h1PathStats
	start    time.Time
	dialRtt  time.Duration

	primed  bool
	dormant bool
	prev    h1PathSample

	rxCollapsedRing uint16
	txCollapsedRing uint16
	rxOooRing       uint16
	rxOooKnownRing  uint16
	txRetransRing   uint16
}

// Returns nil when the dial round trip is below MinPathRtt: such a path never
// gets a monitor, and the caller counts it dormant.
func newH1PathMonitor(
	settings *H1PathRerollSettings,
	start time.Time,
	dialRtt time.Duration,
) *h1PathMonitor {
	if dialRtt < settings.MinPathRtt {
		return nil
	}
	return &h1PathMonitor{
		settings: settings,
		stats:    &h1PathProcessStats,
		start:    start,
		dialRtt:  dialRtt,
	}
}

// the minimum known round trip; the dial round trip is always known
func (self *h1PathMonitor) pathRtt(sample *h1PathSample) time.Duration {
	pathRtt := self.dialRtt
	if 0 < sample.minRtt {
		pathRtt = min(pathRtt, sample.minRtt)
	}
	if 0 < sample.ackRttMin {
		pathRtt = min(pathRtt, sample.ackRttMin)
	}
	return pathRtt
}

func (self *h1PathMonitor) thinByteRate(pathRtt time.Duration, mss int) float64 {
	if mss <= 0 {
		mss = self.settings.DefaultMss
	}
	rtt := max(pathRtt, self.settings.RttFloor, time.Millisecond)
	return float64(self.settings.ThinSegmentsPerRtt) * float64(mss) / rtt.Seconds()
}

func (self *h1PathMonitor) resetRings() {
	self.rxCollapsedRing = 0
	self.txCollapsedRing = 0
	self.rxOooRing = 0
	self.rxOooKnownRing = 0
	self.txRetransRing = 0
}

func (self *h1PathMonitor) tick(sample h1PathSample) h1PathDecision {
	settings := self.settings
	if self.dormant {
		return h1PathDecision{dormant: true}
	}
	pathRtt := self.pathRtt(&sample)
	if pathRtt < settings.MinPathRtt {
		// a short path never re-rolls, and stops costing ticks
		self.dormant = true
		self.stats.ConnectionsDormant.Add(1)
		return h1PathDecision{dormant: true, pathRtt: pathRtt}
	}
	if !self.primed {
		self.primed = true
		self.prev = sample
		return h1PathDecision{pathRtt: pathRtt}
	}
	tickInterval := max(settings.TickInterval, time.Millisecond)
	elapsed := sample.now.Sub(self.prev.now)
	if elapsed < tickInterval/2 ||
		(sample.readMessageCount == self.prev.readMessageCount &&
			sample.writeMessageCount == self.prev.writeMessageCount) {
		// nothing moved, or too soon: the next accepted tick takes the delta
		return h1PathDecision{pathRtt: pathRtt}
	}
	prev := self.prev
	self.prev = sample
	self.stats.Ticks.Add(1)

	seconds := elapsed.Seconds()
	// demand scales with the tick's length, so a tick after an idle gap does
	// not pass on bytes that trickled in over the whole gap
	demandByteCount := float64(settings.MinTickByteCount) * seconds / tickInterval.Seconds()
	excluded := prev.receiveFullCount != sample.receiveFullCount ||
		sample.speedTestActive ||
		sample.standingDown

	rxByteCount := h1PathCounterDelta(prev.readByteCount, sample.readByteCount)
	if prev.rxBytesKnown && sample.rxBytesKnown {
		rxByteCount = h1PathCounterDelta(prev.rxBytes, sample.rxBytes)
	}
	rxByteRate := float64(rxByteCount) / seconds
	rxThinByteRate := self.thinByteRate(pathRtt, sample.rcvMss)
	rxDemand := demandByteCount <= float64(rxByteCount)
	queueDelayThreshold := max(
		settings.QueueDelayFloor,
		time.Duration(settings.QueueDelayRttMultiple)*pathRtt,
	)
	queueDelayKnown := 0 < sample.queueDelaySamples &&
		settings.MinTickPackSamples <= sample.queueDelaySamples
	rxCollapsed := !excluded &&
		rxDemand &&
		queueDelayKnown &&
		queueDelayThreshold <= sample.queueDelay &&
		rxByteRate < rxThinByteRate
	rxClean := !excluded && rxDemand && rxThinByteRate <= rxByteRate

	txKnown := prev.txKnown && sample.txKnown
	txAckedByteCount := uint64(0)
	if txKnown {
		txAckedByteCount = h1PathCounterDelta(prev.txAckedBytes, sample.txAckedBytes)
	}
	txByteRate := float64(txAckedByteCount) / seconds
	txThinByteRate := self.thinByteRate(pathRtt, sample.sndMss)
	// the backlog bar is a duration, the same one the receive side applies to
	// its queue delay: a saturated uplink is always backlogged, slower than
	// thin and retransmitting, and only the time its own send queue takes to
	// drain separates it from a collapse. The byte floor keeps a slow but
	// healthy upload, whose whole queue is small, off the rule.
	txCollapsed := !excluded &&
		txKnown &&
		uint64(settings.SendBacklogByteCount) <= sample.txNotSent &&
		txByteRate*queueDelayThreshold.Seconds() <= float64(sample.txNotSent) &&
		0 < txAckedByteCount &&
		txByteRate < txThinByteRate
	txClean := !excluded &&
		txKnown &&
		demandByteCount <= float64(txAckedByteCount) &&
		txThinByteRate <= txByteRate

	rxOooKnown := prev.rxOooKnown && sample.rxOooKnown
	self.rxCollapsedRing = h1PathRingPush(self.rxCollapsedRing, rxCollapsed)
	self.txCollapsedRing = h1PathRingPush(self.txCollapsedRing, txCollapsed)
	self.rxOooKnownRing = h1PathRingPush(self.rxOooKnownRing, rxOooKnown)
	self.rxOooRing = h1PathRingPush(self.rxOooRing, rxOooKnown && prev.rxOoo < sample.rxOoo)
	self.txRetransRing = h1PathRingPush(self.txRetransRing, txKnown && prev.txRetrans < sample.txRetrans)

	decision := h1PathDecision{
		clean:           rxClean || txClean,
		queueDelay:      sample.queueDelay,
		queueDelayKnown: queueDelayKnown,
		byteRate:        rxByteRate,
		thinByteRate:    rxThinByteRate,
		pathRtt:         pathRtt,
	}
	if sample.now.Sub(self.start) < settings.MinConnectionAge {
		return decision
	}
	windowMask := h1PathRingMask(settings.WindowTicks)
	lossMask := h1PathRingMask(settings.LossWindowTicks)

	if rxCollapsedTicks := bits.OnesCount16(self.rxCollapsedRing & windowMask); settings.ConvictTicks <= rxCollapsedTicks {
		lossTicks := bits.OnesCount16(self.rxOooRing & lossMask)
		lossKnownTicks := bits.OnesCount16(self.rxOooKnownRing & lossMask)
		decision.direction = h1PathDirectionRx
		decision.collapsedTicks = rxCollapsedTicks
		decision.lossTicks = lossTicks
		decision.lossKnownTicks = lossKnownTicks
		switch {
		case settings.RxLossMinTicks <= lossTicks:
			decision.confidence = h1PathConfidenceConfirmed
		case 0 < lossKnownTicks:
			// the kernel speaks for this socket and saw too little loss: a
			// queue beyond it (the provider's leg) or an access link. Both
			// rings restart together, so the next verdict reads the loss of
			// the window it judges; a loss window that kept its older ticks
			// would let one out-of-order tick every few seconds accumulate
			// across denials until the bar is met.
			self.rxCollapsedRing = 0
			self.rxOooRing = 0
			self.stats.recordSuppression(h1PathReasonLossDenied)
			decision.reason = h1PathReasonLossDenied
		default:
			decision.confidence = h1PathConfidenceUnconfirmed
		}
		if decision.confidence != h1PathConfidenceNone {
			decision.convicted = true
			self.resetRings()
			self.stats.RxConvictions.Add(1)
			self.stats.recordConfidence(decision.confidence)
			return decision
		}
	}

	if txCollapsedTicks := bits.OnesCount16(self.txCollapsedRing & windowMask); settings.ConvictTicks <= txCollapsedTicks {
		lossTicks := bits.OnesCount16(self.txRetransRing & lossMask)
		decision.direction = h1PathDirectionTx
		decision.collapsedTicks = txCollapsedTicks
		decision.lossTicks = lossTicks
		// a collapsed tx tick already required the kernel counters
		decision.lossKnownTicks = txCollapsedTicks
		decision.byteRate = txByteRate
		decision.thinByteRate = txThinByteRate
		if settings.TxLossMinTicks <= lossTicks {
			decision.convicted = true
			decision.confidence = h1PathConfidenceConfirmed
			decision.reason = h1PathReasonNone
			self.resetRings()
			self.stats.TxConvictions.Add(1)
			self.stats.recordConfidence(decision.confidence)
			return decision
		}
		// both rings restart together, as on the receive side
		self.txCollapsedRing = 0
		self.txRetransRing = 0
		self.stats.recordSuppression(h1PathReasonLossDenied)
		decision.reason = h1PathReasonLossDenied
	}
	return decision
}

// a counter that went backwards (a reset) reads as no movement
func h1PathCounterDelta(prev uint64, next uint64) uint64 {
	if next < prev {
		return 0
	}
	return next - prev
}

// the daily budget is counted in a ring of the latest unimproved re-rolls
const h1PathDayRingSize = 32

// at most this many route managers wait for an improvement verdict
const h1PathPendingLimit = 64

// at most this many convicted local ports are excluded per network epoch
const h1PathExcludedPortLimit = 16

// The process-wide budget for re-rolls. Every method takes the current time so
// the ledger can be driven by a test clock.
//
// A re-roll leaves its route manager pending for ImprovementWindow. A
// conviction on that route manager inside the window is unimproved; clean
// ticks are an improvement; an entry that ages out, is evicted, or is dropped
// by a network change is unresolved. MaxUnimprovedRerolls unimproved re-rolls
// in one network epoch set the latch for LatchDuration.
//
// The ledger counts Unresolved; callers count Unimproved and Improved from the
// returns of noteConviction and noteClean, and the suppression reasons from
// allow. Safe for concurrent use.
type h1PathLedger struct {
	stats *h1PathStats

	stateLock          sync.Mutex
	lastReroll         time.Time
	lastProviderReroll time.Time
	epochUnimproved    int
	epochUnconfirmed   int
	latchStart         time.Time
	latchUntil         time.Time
	// the settings that set the latch decide when a network change may clear it
	latchNetworkResetAge           time.Duration
	dayUnimprovedTimes             [h1PathDayRingSize]time.Time
	dayUnimprovedNext              int
	pendingRouteManagerRerollTimes map[*RouteManager]time.Time
	excludedPorts                  []int
}

func newH1PathLedger() *h1PathLedger {
	return &h1PathLedger{
		stats:                          &h1PathProcessStats,
		pendingRouteManagerRerollTimes: map[*RouteManager]time.Time{},
	}
}

var h1PathDefaultLedgerOnce sync.Once
var h1PathDefaultLedgerValue *h1PathLedger

// The process ledger. Its network change listener is registered once and lives
// for the process lifetime.
func h1PathDefaultLedger() *h1PathLedger {
	h1PathDefaultLedgerOnce.Do(func() {
		ledger := newH1PathLedger()
		AddNetworkChangeListener(func() {
			ledger.networkChanged(time.Now())
		})
		h1PathDefaultLedgerValue = ledger
	})
	return h1PathDefaultLedgerValue
}

func (self *h1PathLedger) expirePendingWithLock(settings *H1PathRerollSettings, now time.Time) {
	for key, rerollTime := range self.pendingRouteManagerRerollTimes {
		if settings.ImprovementWindow < now.Sub(rerollTime) {
			delete(self.pendingRouteManagerRerollTimes, key)
			self.stats.Unresolved.Add(1)
		}
	}
}

// Returns true when the conviction lands inside the improvement window of a
// re-roll on the same route manager. That re-roll is unimproved: it counts
// toward the epoch latch and the daily budget.
func (self *h1PathLedger) noteConviction(
	key *RouteManager,
	settings *H1PathRerollSettings,
	now time.Time,
) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	self.expirePendingWithLock(settings, now)
	if _, ok := self.pendingRouteManagerRerollTimes[key]; !ok {
		return false
	}
	delete(self.pendingRouteManagerRerollTimes, key)
	self.epochUnimproved += 1
	self.dayUnimprovedTimes[self.dayUnimprovedNext] = now
	self.dayUnimprovedNext = (self.dayUnimprovedNext + 1) % h1PathDayRingSize
	if settings.MaxUnimprovedRerolls <= self.epochUnimproved {
		self.latchStart = now
		self.latchUntil = now.Add(settings.LatchDuration)
		self.latchNetworkResetAge = settings.LatchMinAgeForNetworkReset
	}
	return true
}

// Decides whether a conviction may re-roll. It refuses, in order, when latched,
// over the daily budget, inside device spacing, over the unconfirmed budget, or
// for a provider outside its gate. A provider without AllowProviderAct is
// refused by role; the connection clamps such a provider to Observe before it
// gets here, so that refusal is only a guard.
func (self *h1PathLedger) allow(
	settings *H1PathRerollSettings,
	now time.Time,
	role H1PathRerollRole,
	confidence h1PathConfidence,
	connectionAge time.Duration,
) (bool, h1PathReason) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	self.expirePendingWithLock(settings, now)
	if now.Before(self.latchUntil) {
		return false, h1PathReasonLatched
	}
	dayUnimproved := 0
	for _, unimprovedTime := range self.dayUnimprovedTimes {
		if !unimprovedTime.IsZero() && now.Sub(unimprovedTime) < 24*time.Hour {
			dayUnimproved += 1
		}
	}
	if min(settings.MaxUnimprovedRerollsPerDay, h1PathDayRingSize) <= dayUnimproved {
		return false, h1PathReasonDailyBudget
	}
	if !self.lastReroll.IsZero() && now.Sub(self.lastReroll) < settings.DeviceRerollSpacing {
		return false, h1PathReasonSpacing
	}
	if confidence != h1PathConfidenceConfirmed && settings.MaxUnconfirmedRerolls <= self.epochUnconfirmed {
		return false, h1PathReasonUnconfirmedBudget
	}
	if role == H1PathRerollRoleProvider {
		if !settings.AllowProviderAct {
			return false, h1PathReasonRole
		}
		if connectionAge < settings.ProviderMinConnectionAge {
			return false, h1PathReasonProviderGate
		}
		if !self.lastProviderReroll.IsZero() && now.Sub(self.lastProviderReroll) < settings.ProviderRerollSpacing {
			return false, h1PathReasonProviderGate
		}
	}
	return true, h1PathReasonNone
}

// Records an allowed re-roll: device and provider spacing, the unconfirmed
// budget, the pending improvement entry and the convicted local port. A
// non-positive port is not recorded.
func (self *h1PathLedger) noteReroll(
	key *RouteManager,
	settings *H1PathRerollSettings,
	now time.Time,
	role H1PathRerollRole,
	confidence h1PathConfidence,
	localPort int,
) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	self.expirePendingWithLock(settings, now)
	self.lastReroll = now
	if role == H1PathRerollRoleProvider {
		self.lastProviderReroll = now
	}
	if confidence != h1PathConfidenceConfirmed {
		self.epochUnconfirmed += 1
	}
	if _, ok := self.pendingRouteManagerRerollTimes[key]; !ok && h1PathPendingLimit <= len(self.pendingRouteManagerRerollTimes) {
		var oldestKey *RouteManager
		var oldestTime time.Time
		for pendingKey, rerollTime := range self.pendingRouteManagerRerollTimes {
			if oldestKey == nil || rerollTime.Before(oldestTime) {
				oldestKey = pendingKey
				oldestTime = rerollTime
			}
		}
		delete(self.pendingRouteManagerRerollTimes, oldestKey)
		self.stats.Unresolved.Add(1)
	}
	self.pendingRouteManagerRerollTimes[key] = now
	if 0 < localPort {
		self.excludedPorts = append(self.excludedPorts, localPort)
		if h1PathExcludedPortLimit < len(self.excludedPorts) {
			// keep the latest
			self.excludedPorts = append(
				[]int{},
				self.excludedPorts[len(self.excludedPorts)-h1PathExcludedPortLimit:]...,
			)
		}
	}
}

// Returns true when a pending re-roll on the route manager has reached
// CleanTicks clean ticks. The re-roll is improved, and the epoch's unimproved
// count is reset.
func (self *h1PathLedger) noteClean(
	key *RouteManager,
	settings *H1PathRerollSettings,
	now time.Time,
	cleanTicks int,
) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	self.expirePendingWithLock(settings, now)
	if _, ok := self.pendingRouteManagerRerollTimes[key]; !ok {
		return false
	}
	if cleanTicks < settings.CleanTicks {
		return false
	}
	delete(self.pendingRouteManagerRerollTimes, key)
	self.epochUnimproved = 0
	return true
}

// Starts a new network epoch: the epoch counters, the pending entries and the
// excluded ports clear. A latch clears only once it is at least as old as the
// reset age recorded when it was set. The daily budget and the device spacing
// span epochs.
func (self *h1PathLedger) networkChanged(now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	if now.Before(self.latchUntil) && self.latchNetworkResetAge <= now.Sub(self.latchStart) {
		self.latchStart = time.Time{}
		self.latchUntil = time.Time{}
	}
	self.epochUnimproved = 0
	self.epochUnconfirmed = 0
	self.excludedPorts = nil
	// a connection on the new network says nothing about a re-roll on the old one
	for key := range self.pendingRouteManagerRerollTimes {
		delete(self.pendingRouteManagerRerollTimes, key)
		self.stats.Unresolved.Add(1)
	}
}

// A copy of the local ports convicted this epoch, oldest first.
func (self *h1PathLedger) excluded() []int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]int{}, self.excludedPorts...)
}

// Counts the H1 path monitor across the process. The monitor, the ledger and
// the connection each count the fields their doc comments name. Safe for
// concurrent use.
type h1PathStats struct {
	ConnectionsMonitored        atomic.Uint64
	ConnectionsDormant          atomic.Uint64
	KernelUnavailable           atomic.Uint64
	Ticks                       atomic.Uint64
	RxConvictions               atomic.Uint64
	TxConvictions               atomic.Uint64
	ConfirmedConvictions        atomic.Uint64
	UnconfirmedConvictions      atomic.Uint64
	Rerolls                     atomic.Uint64
	RerollDials                 atomic.Uint64
	SuppressedObserve           atomic.Uint64
	SuppressedRole              atomic.Uint64
	SuppressedLossDenied        atomic.Uint64
	SuppressedLatched           atomic.Uint64
	SuppressedSpacing           atomic.Uint64
	SuppressedUnconfirmedBudget atomic.Uint64
	SuppressedDailyBudget       atomic.Uint64
	SuppressedProviderGate      atomic.Uint64
	Improved                    atomic.Uint64
	Unimproved                  atomic.Uint64
	Unresolved                  atomic.Uint64
	SourcePortBinds             atomic.Uint64
	SourcePortFallbacks         atomic.Uint64
}

var h1PathProcessStats h1PathStats

func (self *h1PathStats) recordSuppression(reason h1PathReason) {
	switch reason {
	case h1PathReasonObserve:
		self.SuppressedObserve.Add(1)
	case h1PathReasonRole:
		self.SuppressedRole.Add(1)
	case h1PathReasonLossDenied:
		self.SuppressedLossDenied.Add(1)
	case h1PathReasonLatched:
		self.SuppressedLatched.Add(1)
	case h1PathReasonSpacing:
		self.SuppressedSpacing.Add(1)
	case h1PathReasonUnconfirmedBudget:
		self.SuppressedUnconfirmedBudget.Add(1)
	case h1PathReasonDailyBudget:
		self.SuppressedDailyBudget.Add(1)
	case h1PathReasonProviderGate:
		self.SuppressedProviderGate.Add(1)
	}
}

func (self *h1PathStats) recordConfidence(confidence h1PathConfidence) {
	switch confidence {
	case h1PathConfidenceConfirmed:
		self.ConfirmedConvictions.Add(1)
	case h1PathConfidenceUnconfirmed:
		self.UnconfirmedConvictions.Add(1)
	}
}

// A point-in-time copy of the process H1 path counters. Fields are read
// independently, so a snapshot taken while connections tick may be off by the
// events in flight.
type H1PathRerollStatsSnapshot struct {
	ConnectionsMonitored        uint64
	ConnectionsDormant          uint64
	KernelUnavailable           uint64
	Ticks                       uint64
	RxConvictions               uint64
	TxConvictions               uint64
	ConfirmedConvictions        uint64
	UnconfirmedConvictions      uint64
	Rerolls                     uint64
	RerollDials                 uint64
	SuppressedObserve           uint64
	SuppressedRole              uint64
	SuppressedLossDenied        uint64
	SuppressedLatched           uint64
	SuppressedSpacing           uint64
	SuppressedUnconfirmedBudget uint64
	SuppressedDailyBudget       uint64
	SuppressedProviderGate      uint64
	Improved                    uint64
	Unimproved                  uint64
	Unresolved                  uint64
	SourcePortBinds             uint64
	SourcePortFallbacks         uint64
}

func (self *h1PathStats) snapshot() H1PathRerollStatsSnapshot {
	return H1PathRerollStatsSnapshot{
		ConnectionsMonitored:        self.ConnectionsMonitored.Load(),
		ConnectionsDormant:          self.ConnectionsDormant.Load(),
		KernelUnavailable:           self.KernelUnavailable.Load(),
		Ticks:                       self.Ticks.Load(),
		RxConvictions:               self.RxConvictions.Load(),
		TxConvictions:               self.TxConvictions.Load(),
		ConfirmedConvictions:        self.ConfirmedConvictions.Load(),
		UnconfirmedConvictions:      self.UnconfirmedConvictions.Load(),
		Rerolls:                     self.Rerolls.Load(),
		RerollDials:                 self.RerollDials.Load(),
		SuppressedObserve:           self.SuppressedObserve.Load(),
		SuppressedRole:              self.SuppressedRole.Load(),
		SuppressedLossDenied:        self.SuppressedLossDenied.Load(),
		SuppressedLatched:           self.SuppressedLatched.Load(),
		SuppressedSpacing:           self.SuppressedSpacing.Load(),
		SuppressedUnconfirmedBudget: self.SuppressedUnconfirmedBudget.Load(),
		SuppressedDailyBudget:       self.SuppressedDailyBudget.Load(),
		SuppressedProviderGate:      self.SuppressedProviderGate.Load(),
		Improved:                    self.Improved.Load(),
		Unimproved:                  self.Unimproved.Load(),
		Unresolved:                  self.Unresolved.Load(),
		SourcePortBinds:             self.SourcePortBinds.Load(),
		SourcePortFallbacks:         self.SourcePortFallbacks.Load(),
	}
}

// The process H1 path re-roll counters.
func H1PathRerollStats() H1PathRerollStatsSnapshot {
	return h1PathProcessStats.snapshot()
}
