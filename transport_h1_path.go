package connect

import (
	"math/bits"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"weak"
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
// What each evidence is worth, and what it costs when it is wrong. The queue
// delay is read from pack tags against the sender's clock and against a
// baseline built from what that source has shown, so a sender clock step and a
// queue that was already standing when the source was first read are both
// invisible to it in opposite directions. The ack echo is this client's own
// send time read against the dial round trip, so it needs neither clock nor
// baseline, and it is the only queue evidence a conviction can be checked
// against here. The four shapes the rollout is sized against, at the library
// defaults and pinned by TestH1PathEvidencePolicyOnTheMeasuredShapes:
//
//   - the same datacenter: a dial round trip under MinPathRtt gets no monitor
//     at all, and a connection whose kernel later reports a shorter path goes
//     dormant at its first tick. No ticks, no cost, no false positive.
//   - a healthy 101 ms path at 200 Mb/s: the rate alone excludes it, 25 MB/s
//     against a thin rate of 3.5 MB/s, and its 4 ms queue is three orders
//     below the threshold. No collapsed tick in ten minutes.
//   - a saturated 20 Mb/s access link with bufferbloat: a real false positive
//     and the residual cost of the feature. 2.5 MB/s is under thin, the bloat
//     is a real queue that the acks carry too, so nothing denies it and the
//     conviction is confirmed. It convicts 1.5 s after the queue stands, and
//     what bounds the device is the ledger: two unimproved re-rolls latch the
//     epoch for LatchDuration and MaxUnimprovedRerollsPerDay stop them
//     altogether. BaselineRisePerMinute bounds how long one connection goes on
//     seeing the queue -- a reference that cannot rise is a queue that never
//     lifts and a conviction that never stops, which is how one bloated link
//     spent a whole daily budget while the pack side was decaying on schedule
//     -- and it has to bound both measures or it bounds nothing. What it
//     cannot bound is the device, because the ack reference's floor and rise
//     live on the monitor and every dial builds a new one: the queue survives
//     the re-roll and the reference does not, while the pack baseline and the
//     rolling ack minimum, which belong to the path, do survive it. Measured on
//     one epoch through the re-dialling harness, which is what production does
//     (TestH1PathEvidencePolicyOnTheMeasuredShapes): a 1.5 s bloat costs two
//     break-before-make disconnects and stops convicting at 10m09 with the
//     daily budget untouched, and a 6 s bloat spends the whole daily budget of
//     six inside four hours -- 5102 convictions, the last at 2h50m, and 596
//     refusals after it. A queue that clears and comes back is not bounded by
//     the rise at all, since the reference drops back to its floor while the
//     queue is gone: two minutes of 6 s bloat in every ten costs the same six.
//     Visibility is (q - thr) / rise on each measure and never less than one
//     AckRttWindow on the ack side, where the rolling minimum holds the
//     reference at the smallest round trip still inside that window, so 1.5 s
//     and 6 s of bloat are the same reading for the first ten minutes. The
//     levers if the field disagrees are that rise and the daily budget, not the
//     threshold, which is what keeps the measured collapse in.
//   - the measured collapse, 0.5 MB/s behind a 6-10 s queue on a 101 ms path:
//     convicted 2 s after the queue reaches the threshold, confirmed by the
//     kernel's out-of-order counter and by an ack round trip that carries the
//     same queue.
//
// And the shape with no ack to read at all -- a peer that answers over another
// transport, and the sender clock step that is then indistinguishable from a
// queue: the conviction stands on the pack tags, because the alternative is to
// go blind on a route whose peer talks elsewhere, but it is unconfirmed. One
// unconfirmed re-roll is allowed per network epoch and an improvement gives it
// back, so a clock step costs one disconnect and then nothing, with no latch,
// while a real collapse the re-roll fixes costs nothing at all.
//
// A route with no ack is also outside the reach of one of the two fixes, and
// the boundary is worth naming because it is the ground truth's own shape. The
// queue delay is measured against what the source has already shown, so a queue
// already standing when that source's floor was set is inside the floor and
// reads as zero for the connection's life -- and the ground truth is a session
// that starts bad and stays bad. The ack echo is the only evidence that needs
// no floor of the sender's, so where one rides the route the collapse is
// convicted in 3 s and where none does the connection is invisible, in Observe
// and in Act alike. An uploading client joins that invisible population for as
// long as its own send queue holds the queue delay threshold's worth of data,
// because the ack guard reads that queue's drain time and withdraws the
// evidence (the rule, and TicksAckBacklogged against Ticks). That is a backlog
// and not a band of uplink rates -- max(AckBacklogFloorByteCount, rate x
// threshold), which is 16 KiB up to 0.13 Mb/s and 63 KB at 0.5 Mb/s on a 101
// ms path, and three times each on a 300 ms one. Neither of the independent
// floors that
// suggest themselves closes it: neither the dial round trip nor the kernel's
// minimum round trip bounds the offset between the two clocks that every pack
// tag carries, and neither one times the far socket's send queue, which sits
// upstream of everything our kernel measures -- our own segments never wait
// behind it. A round trip on our own clock is the only thing that does, which
// is what the ack echo is, so this is the shape of the evidence and not a gap
// in the rule.
//
// That last shape is not a corner, and treating it as unconfirmed is a choice
// about most clients, not about a few. A route carries an ack to read only
// while the peer answers over it, so the platform rig and seven of the eight
// S9 arms read none: a pack queue and the kernel's out-of-order counter, and
// nothing measured on a clock this device owns. The reading kept here is that
// such a client re-rolls once per network epoch instead of twice, and the trade
// is cheap for the shape the rollout is sized against. The ground truth is 11
// in 100 four-tuples on a slow member, stable for hours, so one re-roll lands
// healthy 89 times in 100, and a re-roll that lands healthy returns the budget
// (noteClean), which leaves the cap binding on about one session in a hundred:
// the one that re-rolls from one slow member onto another. That last session is
// also the one the cap has to hold, so the budget comes back only when the
// measure that convicted reads its own queue gone (h1PathConvicted). A
// replacement read on any other measure is credited for what that measure could
// not see: on a queue standing at birth the pack tags read zero before the
// re-roll and zero after it, and twenty such ticks would clear the latch and
// the budget together and let one bad member cost a disconnect every time the
// acks went quiet. What the other reading would buy is the ten points between
// 89 and 99, and what it would cost is every sender clock step two disconnects
// and a 30 minute latch, on evidence no clock here can check. A rollout that
// wants to re-price this reads TicksAckUnknown against Ticks for the size of
// the population it applies to.
//
// The same cadence decides what the ledger is able to bound, and that is why
// its two budgets read different things. A re-roll is judged by the connection
// that replaced it, so the verdict arrives when the route next carries
// evidence, and on this population that is the ack echo: an echo slower than
// ImprovementWindow convicts the replacement after the window has closed, so
// the re-roll before it is answered by nothing. A verdict of nothing cost
// nothing, which is one break-before-make disconnect per ack cadence for ever
// -- no latch, because nothing was ever unimproved, and no daily budget,
// because only an unimproved re-roll reached it. So the latch reads verdicts
// and the daily budget reads disconnects: a re-roll that ages out unresolved is
// charged to the budget and not to the latch, which leaves the latch meaning
// what it says while MaxUnimprovedRerollsPerDay bounds the device whatever its
// route can judge. Measured over one simulated hour behind a 6 s queue that
// only the ack echo reads
// (TestH1PathRerollIsChargedWhateverTheRouteCanJudge): an echo every 30 s or
// every 100 s falls inside the window and costs three re-rolls with the epoch
// latched, and every 150 s and every 240 s fall outside it and cost 23 and 14
// unbounded disconnects, or the budget's six once the age-out is charged. What
// the charge costs is a re-roll that did work and could not be read, which is
// charged too, because nothing here can tell that one from a re-roll that
// changed nothing.
//
// That cost starts at half the window and not at it, because a credit needs
// two echoes where an age-out needs one. CleanTicks clean ticks at
// AckEvidenceWindow of freshness per echo is two echoes, and the re-roll lands
// a tick or two after the echo that convicted, so the twentieth fresh tick
// arrives about 2C + AckEvidenceWindow after it against the window's 120 s.
// Measured a second at a time on a replacement that is healthy from its first
// tick, at 16 Mb/s, which is under the thin bar and is most of the population
// (TestH1PathImprovementCreditNeedsTwoEchoesInsideTheWindow): an echo every 58
// s is credited, every 59 s is charged, and every cadence above that is
// charged as well. So from about a minute up, a re-roll that worked costs a
// day's charge, and it is only past 120 s that nothing can be judged at all.
// The same reading in the counter a rollout has is TicksAckUnknown against
// Ticks, which is about 1 - AckEvidenceWindow / C: measured 0.911 at a 60 s
// echo and 0.967 at 150 s, so above about 0.91 a fleet's successful re-rolls
// are being charged, and above about 0.96 its re-rolls are not being judged.
//
// A network change is the other way a route stops being able to answer, and it
// is charged on the same reading: the epoch that ended cannot judge the
// re-roll, so it reaches the budget and not the latch, exactly as an age-out
// does. Left uncharged it handed the whole pre-fix rate back, because the
// change clears the epoch counters as well and the budget was the only bound
// still standing: on the same 150 s echo, a change every two minutes cost 47
// disconnects in two hours and charged none of them, against six and then
// refusals once they are charged
// (TestH1PathNetworkChangeChargesTheDisconnect). What that costs is a device
// that roams faster than the window -- it spends its six a day on re-rolls no
// network lived long enough to judge -- and the lever is the same
// MaxUnimprovedRerollsPerDay.
//
// The last disconnect loop neither budget bounded was a route that recovers
// and collapses again, because the improvement credit used to be permanent.
// CleanTicks is twenty ticks, ten seconds at the defaults: evidence that a
// replacement started well and none that it lasts. A replacement clean for ten
// seconds and collapsed a minute later was credited, its entry dropped, its
// epoch counts returned and the day charged nothing, so the device paid one
// disconnect per cycle for ever -- 109 in two hours on a route good for a
// minute at a time, 39 at three minutes, 12 at ten. The credit is now taken
// back by the next conviction on the same route manager, counted Recollapsed
// and charged to the day, and each of those arms costs the budget's six and
// then refusals
// (TestH1PathImprovementCreditIsTakenBackWhenTheRouteRecollapses). What stops
// such a loop is the day and not the latch: a re-collapse is not the latch's
// reading, and the credit returned the epoch's counts before it anyway, so the
// budget is what bounds it -- the budget reading disconnects, which is what it
// is for. What stays free is a re-roll whose route is never convicted again,
// which is the population the credit was written for: one re-roll off a slow
// member onto a good one, on a connection that then runs for hours.
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

// The environment variable that sets the role of every H1 connection dialed
// after it is read: client or provider. It wins over the settings, and the
// process override wins over it. A value that does not parse is ignored and
// logged once.
//
// The role is what selects the provider gates, and a process that serves
// clients has to say so: nothing in this package can tell a provider's
// websocket to the platform from a client's. Without it, a provider process
// asking for the act mode re-rolls under the client gates -- no minimum
// connection age and no provider spacing -- because the settings of a
// host-built transport carry the zero role, which is client.
const H1PathRerollRoleEnv = "CONNECT_H1_PATH_REROLL_ROLE"

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
// it once. The role is resolved the same way (h1PathEffectiveRole) and passed
// in; a provider is then clamped to Observe unless AllowProviderAct, whichever
// level chose Act: a provider's re-dial counts against its reliability.
func h1PathEffectiveMode(
	settings *H1PathRerollSettings,
	role H1PathRerollRole,
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
		role == H1PathRerollRoleProvider &&
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

// Accepts client and provider, case-insensitive, with surrounding space
// ignored.
func ParseH1PathRerollRole(s string) (H1PathRerollRole, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "client":
		return H1PathRerollRoleClient, true
	case "provider":
		return H1PathRerollRoleProvider, true
	default:
		return H1PathRerollRoleClient, false
	}
}

// Anything but Client and Provider is Provider, the role with the tighter
// gates, so a value from outside the package cannot act by accident.
func h1PathNormalizeRole(role H1PathRerollRole) H1PathRerollRole {
	switch role {
	case H1PathRerollRoleClient, H1PathRerollRoleProvider:
		return role
	default:
		return H1PathRerollRoleProvider
	}
}

// the process override as role + 1; zero is no override
var h1PathRoleOverrideValue atomic.Int32

// SetH1PathRerollRoleOverride sets the H1 path re-roll role of every connection
// dialed after it, over the environment and over each transport's settings. A
// provider process declares itself with this, or with the role environment
// variable above, so that its connections are clamped to Observe unless
// AllowProviderAct, and go through the provider age and spacing gates when they
// are allowed to act. An unknown role is stored as Provider.
func SetH1PathRerollRoleOverride(role H1PathRerollRole) {
	h1PathRoleOverrideValue.Store(int32(h1PathNormalizeRole(role)) + 1)
}

// ClearH1PathRerollRoleOverride returns to the environment and the settings.
func ClearH1PathRerollRoleOverride() {
	h1PathRoleOverrideValue.Store(0)
}

// H1PathRerollRoleOverride is the process override, and whether one is set.
func H1PathRerollRoleOverride() (H1PathRerollRole, bool) {
	value := h1PathRoleOverrideValue.Load()
	if value == 0 {
		return H1PathRerollRoleClient, false
	}
	return H1PathRerollRole(value - 1), true
}

// The role of a connection, in the same precedence order as the mode: the
// process override, then the environment, then the settings. envValid is false
// only for a value that was set and did not parse, so the caller can log it
// once.
func h1PathEffectiveRole(
	settings *H1PathRerollSettings,
	overrideRole H1PathRerollRole,
	overrideSet bool,
	envValue string,
) (role H1PathRerollRole, envValid bool) {
	role = h1PathNormalizeRole(settings.Role)
	envValid = true
	if envValue != "" {
		if envRole, ok := ParseH1PathRerollRole(envValue); ok {
			role = envRole
		} else {
			envValid = false
		}
	}
	if overrideSet {
		role = h1PathNormalizeRole(overrideRole)
	}
	return role, envValid
}

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
	// The bytes our kernel has accepted and not yet put on the wire, read by
	// two rules that ask different questions of them. Both require the backlog
	// to take at least the queue delay threshold to drain at the rate the wire
	// is acking, which is the whole of what the receive direction asks -- could
	// our own uplink have put a threshold-sized queue into the ack round trip
	// -- and AckBacklogFloorByteCount is only the floor that keeps a socket
	// with a few bytes pending and nothing acked in the tick from answering
	// yes for ever. It cannot keep an ordinary uploading client's queue out of
	// the guard at any rate, and what that costs is at the rule. A send
	// conviction asks a second question, whether there is
	// enough backlog to call the direction collapsed, and
	// SendBacklogByteCount is that bar. Every platform reports the same
	// quantity here (transport_h1_path_socket_darwin.go)
	SendBacklogByteCount     ByteCount
	AckBacklogFloorByteCount ByteCount
	// the queue delay baseline is the minimum over BaselineBucketCount buckets
	// (at most 16), and may rise above the smallest delay a source ever showed
	// by at most BaselineRisePerMinute for each minute since it showed it, so a
	// collapse that outlives the buckets does not become its own baseline.
	// Non-positive leaves the buckets alone
	BaselineBucketDuration time.Duration
	BaselineBucketCount    int
	BaselineRisePerMinute  time.Duration
	// the ack echo round trip is the minimum over this window
	AckRttWindow time.Duration
	// an ack round trip is evidence about the receive queue for this long
	// after it was read; a receive collapse whose fresh ack round trip holds
	// no queue is denied. Non-positive turns the check off
	AckEvidenceWindow time.Duration

	// clean ticks after a re-roll that count it as improved
	CleanTicks int
	// a conviction on the same route manager this soon after a re-roll counts it as unimproved
	ImprovementWindow time.Duration
	// minimum time between any two re-rolls on the device
	DeviceRerollSpacing time.Duration
	// unimproved re-rolls in one network epoch that set the latch
	MaxUnimprovedRerolls int
	// re-rolls on an unconfirmed conviction allowed in one network epoch; an
	// improvement gives the budget back
	MaxUnconfirmedRerolls int
	// re-rolls in a rolling 24 hours that were not resolved as improved --
	// convicted again inside ImprovementWindow, or judged by nothing before it
	// ran out -- that stop re-rolls (at most 32)
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
		AckBacklogFloorByteCount:   kib(16),
		BaselineBucketDuration:     10 * time.Second,
		BaselineBucketCount:        12,
		BaselineRisePerMinute:      100 * time.Millisecond,
		AckRttWindow:               10 * time.Minute,
		AckEvidenceWindow:          5 * time.Second,
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
	// when the source the delay was read from took its baseline slot, which is
	// when the floor behind that delay started being built. Zero where nothing
	// supplied it, which the observer only does with no delay to read
	queueDelaySlotTime time.Time
	// sampled packs the observer could not read a queue from: a tag older than
	// the route's latest re-roll mark, and a source the baseline holds no slot
	// for
	stalePacks     int
	unslottedPacks int
	// the minimum ack echo round trip over AckRttWindow; zero is unknown
	ackRttMin time.Duration
	// the ack echo round trip of this tick, valid when ackRttSamples is
	// positive
	ackRtt        time.Duration
	ackRttSamples int

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

// Why a conviction did not re-roll, in the order the checks run. sourcePort is
// the connection's own: its dial kept a port inside the excluded window.
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
	h1PathReasonSourcePort        h1PathReason = "sourcePort"
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

	// The readings that can credit a re-roll as improved, one per measure a
	// conviction can be read from, because the ledger judges a replacement
	// against the conviction it answers and not against whatever the
	// replacement happens to be able to read. clean is any of the three.
	cleanRxAck  bool
	cleanRxPack bool
	cleanTx     bool

	// collapsed ticks in the window of the direction evaluated
	collapsedTicks int
	// ticks with loss evidence, and ticks where the evidence was known, in the loss window
	lossTicks      int
	lossKnownTicks int
	// ticks of the loss window whose own ack round trip held the queue
	ackQueuedTicks  int
	queueDelay      time.Duration
	queueDelayKnown bool
	// the latest ack round trip over its own risen reference, and whether one
	// was fresh enough to read
	ackQueue      time.Duration
	ackQueueKnown bool
	// delivered bytes per second in the direction evaluated
	byteRate     float64
	thinByteRate float64
	pathRtt      time.Duration
}

// Classifies the ticks of one H1 connection and convicts a direction whose
// delivery collapsed:
//   - thr = max(QueueDelayFloor, QueueDelayRttMultiple x pathRtt), and
//     thin = ThinSegmentsPerRtt x mss / max(pathRtt, RttFloor);
//   - our own send queue takes at least thr to drain when the kernel's unsent
//     bytes are over AckBacklogFloorByteCount and take at least thr to drain at
//     the rate the wire is acking, which is what withdraws the ack evidence;
//     it is backlogged for a send conviction when those bytes also reach
//     SendBacklogByteCount;
//   - rx collapsed: not excluded, demand, rate below thin, and a queue of at
//     least thr -- a fresh ack round trip that holds one over its own risen
//     reference (ackBaseline), or, with no fresh ack to read, a queue delay
//     that holds one over the pack baseline, which rises the same way. A
//     fresh ack round trip below thr denies the tick whatever the queue delay
//     says, and a backlogged send queue, which would inflate that round trip
//     by our own uplink, makes it no evidence either way;
//   - tx collapsed: not excluded, a backlogged send queue, acked bytes
//     advancing below thin;
//   - clean, which is what resolves a re-roll as improved, read once per
//     measure a conviction can stand on: demand and a direction at or above
//     thin, or, on a tick our own consumer did not pace, demand and a queue
//     that measure read and found under thr -- a fresh ack round trip, or a
//     queue delay against a baseline floor older than the connection. The
//     cheap readings are what make the credit reachable at the rates sessions
//     actually run at; none of them counts a tick whose bytes were not counted
//     (the speed test echo, a stand down);
//   - excluded from collapsing, for both directions: the receive channel was
//     full, the speed test echo is active, or the transport is standing down
//     H1;
//   - a direction convicts with ConvictTicks of the last WindowTicks collapsed,
//     the connection at least MinConnectionAge old, and loss evidence over the
//     last LossWindowTicks: rx is denied when the kernel reports out-of-order
//     data and fewer than RxLossMinTicks ticks show it, confirmed when
//     RxLossMinTicks ticks show it and an ack round trip held the queue in at
//     least one tick of that window, and unconfirmed otherwise -- the kernel
//     field unknown, or a queue that stood on the sender's clock alone; tx
//     needs retransmits in TxLossMinTicks ticks and is measured entirely on
//     this device's own clock, so it is confirmed.
//
// A conviction resets every ring. A denial resets only that direction's
// collapsed ring, so it is evaluated again after ConvictTicks more collapsed
// ticks against a loss window that kept its history.
//
// The monitor counts Ticks and, of those, how each was read: TicksUnread and
// TicksReceiveFull for the ticks nothing could be judged from,
// TicksQueueDelayUnknown for the ones with no queue delay to judge,
// TicksAckUnknown for the ones with no fresh ack round trip to judge,
// TicksAckBacklogged for the ones whose ack our own send queue took away, and
// TicksCollapsed for the ones a direction collapsed in. It also counts
// PacksStale and PacksUnslotted, the sampled packs of an accepted tick that
// read nothing, RxAckDeniedTicks, the conviction counters,
// SuppressedLossDenied and ConnectionsDormant when a tick makes it dormant.
// Not safe for concurrent use.
type h1PathMonitor struct {
	settings *H1PathRerollSettings
	stats    *h1PathStats
	start    time.Time
	dialRtt  time.Duration

	primed  bool
	dormant bool
	prev    h1PathSample
	// the latest ack round trip and when it was read
	ackRtt     time.Duration
	ackRttTime time.Time
	// the ack round trip's own floor and when it was last reached
	ackFloor     time.Duration
	ackFloorTime time.Time

	rxCollapsedRing uint16
	txCollapsedRing uint16
	rxOooRing       uint16
	rxOooKnownRing  uint16
	rxAckQueuedRing uint16
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
		// the dial measured the path before this connection carried a byte, so
		// it is a queue-free reference for an ack round trip whatever the
		// connection does afterwards
		ackFloor:     dialRtt,
		ackFloorTime: start,
	}
}

// The reference an ack round trip's queue is read against, and the floor
// behind it: the ack side of the rule the pack baseline already follows
// (transport_h1_observer.go). The floor starts at the dial round trip, which is
// what lets an ack read a queue that was already standing when the connection
// opened, and is lowered by any shorter path the kernel or an ack reports. The
// reference may rise above the floor by BaselineRisePerMinute for each minute
// since the acks last came back to it, and the rolling minimum over
// AckRttWindow caps that rise, so a link whose new normal is a standing queue
// settles on it instead of climbing past it.
//
// Without the rise the reference is a lifetime minimum, and a queue that never
// lifts is a conviction that never stops: a bloated access link convicted for
// as long as it stayed bloated, at 1.5 s exactly as at 6 s, which spent the
// device's whole daily budget instead of an epoch's two or three re-rolls. With
// it, a queue of q is visible for (q - thr) / rise, the same lever and the same
// arithmetic the pack side has always had, now on both measures -- with a floor
// of one AckRttWindow under it, because the rolling minimum caps the reference
// at the smallest round trip still in that window and the pre-queue readings
// take the whole window to age out. Any ack-carried queue is therefore visible
// for at least ten minutes whatever its depth, which is what the cap costs and
// why a 1.5 s bloat and a 6 s one read the same for that long.
//
// The rise restarts when the acks come back within the threshold of the floor,
// not within the threshold of the risen reference. The second test is the
// oscillation it looks like a shorthand for: the reference rises until it
// hides the queue, the hidden queue reads as an unqueued route, the reference
// drops back to the floor and the same queue convicts again, for ever, in
// cycles of (q - thr) / rise.
func (self *h1PathMonitor) ackBaseline(
	sample *h1PathSample,
	pathRtt time.Duration,
	queueDelayThreshold time.Duration,
) time.Duration {
	if pathRtt < self.ackFloor {
		self.ackFloor = pathRtt
		self.ackFloorTime = sample.now
	}
	if 0 < sample.ackRttSamples {
		if sample.ackRtt < self.ackFloor {
			self.ackFloor = sample.ackRtt
		}
		if sample.ackRtt-self.ackFloor < queueDelayThreshold {
			self.ackFloorTime = sample.now
		}
	}
	rise := max(self.settings.BaselineRisePerMinute, 0)
	base := self.ackFloor + time.Duration(
		float64(rise)*sample.now.Sub(self.ackFloorTime).Minutes(),
	)
	if 0 < sample.ackRttMin {
		base = min(base, sample.ackRttMin)
	}
	return base
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
	self.rxAckQueuedRing = 0
	self.txRetransRing = 0
}

func (self *h1PathMonitor) tick(sample h1PathSample) h1PathDecision {
	settings := self.settings
	if self.dormant {
		return h1PathDecision{dormant: true}
	}
	if 0 < sample.ackRttSamples {
		self.ackRtt = sample.ackRtt
		self.ackRttTime = sample.now
	}
	pathRtt := self.pathRtt(&sample)
	if pathRtt < settings.MinPathRtt {
		// a short path never re-rolls, and stops costing ticks
		self.dormant = true
		self.stats.ConnectionsDormant.Add(1)
		return h1PathDecision{dormant: true, pathRtt: pathRtt}
	}
	queueDelayThreshold := max(
		settings.QueueDelayFloor,
		time.Duration(settings.QueueDelayRttMultiple)*pathRtt,
	)
	// maintained on every tick the connection is alive for, accepted or not: it
	// measures how long the route has gone without showing itself unqueued, and
	// an idle tick is part of that
	ackBase := self.ackBaseline(&sample, pathRtt, queueDelayThreshold)
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
	// A full receive route means our own consumer set this tick's rate: the
	// reader stalls, the window closes and the far socket queues, so the tick
	// cannot convict. It can still be clean, because back pressure only lowers
	// the delivered rate -- a tick that cleared the thin rate cleared it in
	// spite of us -- and a re-roll needs clean ticks to resolve as improved. A
	// speed test and a stand down are different: their bytes are not counted at
	// all, so neither verdict can read the tick.
	unread := sample.speedTestActive || sample.standingDown
	receiveFull := prev.receiveFullCount != sample.receiveFullCount
	excluded := receiveFull || unread
	rxByteCount := h1PathCounterDelta(prev.readByteCount, sample.readByteCount)
	if prev.rxBytesKnown && sample.rxBytesKnown {
		rxByteCount = h1PathCounterDelta(prev.rxBytes, sample.rxBytes)
	}
	rxByteRate := float64(rxByteCount) / seconds
	rxThinByteRate := self.thinByteRate(pathRtt, sample.rcvMss)
	rxDemand := demandByteCount <= float64(rxByteCount)
	queueDelayKnown := 0 < sample.queueDelaySamples &&
		settings.MinTickPackSamples <= sample.queueDelaySamples
	// Deliberately not one of the three disjoint readings above: the receive
	// rule can still convict on the ack round trip alone, so a tick that
	// collapsed may also be one whose pack tags could not be read. An Observe
	// rollout needs to see that the primary signal was unavailable whether or
	// not the tick collapsed, so this one counts across the others.
	if !queueDelayKnown {
		self.stats.TicksQueueDelayUnknown.Add(1)
	}
	// The two ways a sampled pack reaches the observer and reads nothing. The
	// sticky slot rule leaves one blind spot -- a source that goes quiet for a
	// whole baseline window loses its slot, and the source that takes it reads
	// its own standing queue as its floor -- and unslotted packs are the only
	// sign of it from outside. Stale packs say the same about a re-roll whose
	// replacement is still being handed the retired connection's tags.
	if 0 < sample.stalePacks {
		self.stats.PacksStale.Add(uint64(sample.stalePacks))
	}
	if 0 < sample.unslottedPacks {
		self.stats.PacksUnslotted.Add(uint64(sample.unslottedPacks))
	}
	txKnown := prev.txKnown && sample.txKnown
	txAckedByteCount := uint64(0)
	if txKnown {
		txAckedByteCount = h1PathCounterDelta(prev.txAckedBytes, sample.txAckedBytes)
	}
	txByteRate := float64(txAckedByteCount) / seconds
	// Our own send queue, read as the time it takes to drain: bytes the kernel
	// has not put on the wire, over a small floor, taking at least the queue
	// delay threshold to drain at the rate the wire is acking. The drain time
	// is the whole of what the receive side asks -- could our own uplink have
	// put a threshold-sized queue into what we sent -- and it has to be able to
	// answer yes on its own, because the queue it is asking about is a duration
	// and not a byte count: 60 KB unsent on a 0.25 Mb/s uplink is two seconds
	// in every ack round trip and no byte bar that also excludes a fast uplink
	// holding a full batch is low enough to see it. The floor is only there for
	// the one case the drain time alone gets wrong, a socket with a few bytes
	// pending and nothing acked in the tick, whose drain time is unbounded for
	// as long as it stays quiet; below about 0.13 Mb/s up, where 16 KiB is
	// itself a threshold-sized queue, the guard is the floor's and the residual
	// stands -- 8 KiB leaving a 0.05 Mb/s uplink takes 1.3 s, and a socket with
	// no receive queue at all is convicted for it
	// (TestH1PathAckGuardCostsASlowUplinkItsEvidence).
	//
	// What the floor cannot do is keep an uploading client's ordinary queue out
	// of the guard, and that is this rule's cost rather than a corner of it.
	// The backlog it takes is the uplink's rate times the threshold: 32 KB on a
	// 0.25 Mb/s uplink and 63 KB on a 0.5 Mb/s one, under one send buffer and
	// about a second of that link's data, which a client that is uploading
	// holds all the time. Its ack evidence is then withdrawn on every tick for
	// as long as it uploads, and on the population this feature exists for --
	// a queue already standing when the source was first read, so the pack tags
	// read zero -- the ack is the only measure that reads the queue, so the
	// collapse is invisible there rather than unconfirmed. Measured on that
	// collapse, 0.5 MB/s behind a 7 s queue
	// (TestH1PathAckGuardCostsASlowUplinkItsEvidence): 14 convictions in 60
	// ticks become none, with every accepted tick counted, where the old shared
	// bar at SendBacklogByteCount convicted all 14. TicksAckBacklogged against
	// Ticks is what shows it, which is why it is kept apart from
	// TicksAckUnknown: this population is an uplink to be read against, not a
	// peer that answers elsewhere.
	//
	// Which uplinks that is, measured rather than assumed, is two byte bars
	// over one drain time and not a band of rates
	// (TestH1PathAckGuardBandIsTwoByteBarsOverTheThreshold). The evidence goes
	// at every rate once the backlog reaches max(AckBacklogFloorByteCount, rate
	// x threshold) -- 16 KiB from 0.05 to 0.13 Mb/s, then 31.6 KB at 0.25 Mb/s,
	// 63.1 KB at 0.5, 126 KB at 1 and 253 KB at 2, on a 101 ms path. The top of
	// the band is SendBacklogByteCount over the same threshold, 2.076 Mb/s
	// here:
	// above it the same backlog is enough to convict the send direction, so a
	// client whose uplink also shows retransmits gets a verdict instead of
	// going invisible, and one whose uplink shows none is invisible as before.
	// Both bars are divided by the threshold, so the whole band moves with the
	// path: on a 300 ms path every backlog triples and the top falls to 0.699
	// Mb/s, which is inside the rates quoted above.
	//
	// The send rule asks a second question of the same bytes -- is there enough
	// backlog to call the direction collapsed -- and SendBacklogByteCount is
	// that bar, which is why one reading cannot serve both: a conjunction can
	// only deny evidence in fewer cases than either half of it, so the byte bar
	// that keeps a send conviction honest is the byte bar that hides the
	// uplink the ack guard exists for. Unknown on either end of the delta reads
	// as not backlogged, which leaves the ack evidence on, as it is on every
	// platform with no kernel counters at all.
	ackBacklogged := txKnown &&
		uint64(settings.AckBacklogFloorByteCount) <= sample.txNotSent &&
		txByteRate*queueDelayThreshold.Seconds() <= float64(sample.txNotSent)
	sendBacklogged := ackBacklogged &&
		uint64(settings.SendBacklogByteCount) <= sample.txNotSent

	// The queue delay is read against the sender's clock, so a backward step of
	// that clock reads exactly like a standing queue and nothing in the pack
	// tags can tell the two apart. The ack echo carries our own send time, and
	// an ack rides the same route as the packs, so a queue that holds the packs
	// holds the acks with it: the measured collapse runs an ack round trip of
	// 6-10 s against a 101 ms path.
	//
	// Our own send path is in that round trip too -- the tag is stamped at pack
	// build, so the Transfer send queue, the batch writer and the kernel send
	// buffer are all inside it -- and the time our uplink takes to drain says
	// nothing about the receive path. A tick whose own send queue is backlogged
	// by the bar above therefore has no ack evidence either way.
	ackFresh := 0 < settings.AckEvidenceWindow &&
		!self.ackRttTime.IsZero() &&
		sample.now.Sub(self.ackRttTime) <= settings.AckEvidenceWindow
	ackQueueKnown := ackFresh && !ackBacklogged
	// the uplink's share of the no-ack population: these ticks had an ack to
	// read and our own send queue took it away
	if ackFresh && ackBacklogged {
		self.stats.TicksAckBacklogged.Add(1)
	}
	// A route whose peer answers elsewhere never carries one, and its
	// convictions are therefore unconfirmed for the connection's life (the file
	// header). Counting the ticks is what sizes that population, so a rollout
	// can read how many clients the confidence rule applies to instead of
	// assuming. Like TicksQueueDelayUnknown this crosses the three disjoint
	// readings rather than joining them.
	if !ackFresh {
		self.stats.TicksAckUnknown.Add(1)
	}
	ackQueue := self.ackRtt - ackBase
	ackQueued := ackQueueKnown && queueDelayThreshold <= ackQueue
	packQueued := queueDelayKnown && queueDelayThreshold <= sample.queueDelay
	// The two measures of the same queue disagree in both directions, and the
	// ack wins each time, because it is the one this client can check. A fresh
	// ack round trip with no queue in it denies the tick. An ack round trip
	// that holds a queue collapses the tick whatever the pack tags say, which
	// is what reaches the session that was already deep in the far socket's
	// queue when its source was first read: that queue is inside the source's
	// baseline, so the queue delay reads zero for the connection's life, while
	// the ack is measured against a dial round trip taken before any of it.
	// The same reading covers a tick with too few pack samples, a source the
	// baseline holds no slot for, and the window after a re-roll in which every
	// arriving pack was built before the mark.
	rxQueued := ackQueued || (packQueued && !ackQueueKnown)
	if packQueued && ackQueueKnown && !ackQueued {
		self.stats.RxAckDeniedTicks.Add(1)
	}
	rxCollapsed := !excluded &&
		rxDemand &&
		rxQueued &&
		rxByteRate < rxThinByteRate
	rxCleanRate := !unread && rxDemand && rxThinByteRate <= rxByteRate

	txThinByteRate := self.thinByteRate(pathRtt, sample.sndMss)
	// a saturated uplink is always backlogged, slower than thin and
	// retransmitting, and only the time its own send queue takes to drain
	// separates it from a collapse; the byte bar is what keeps a small queue
	// on a slow uplink -- enough to withdraw the ack evidence -- from
	// convicting the direction as well
	txCollapsed := !excluded &&
		sendBacklogged &&
		0 < txAckedByteCount &&
		txByteRate < txThinByteRate
	txDemand := txKnown && demandByteCount <= float64(txAckedByteCount)
	txCleanRate := !unread && txDemand && txThinByteRate <= txByteRate
	// What resolves a re-roll as improved, kept apart by the measure that read
	// it, because the ledger judges a replacement against the conviction it
	// answers: the same direction, read from the same measure, found healthy
	// (h1PathLedger). A credit from anywhere else credits the replacement for
	// what it could not see.
	//
	// A direction at or above thin is the strong reading, and it survives our
	// own back pressure, which only lowers the delivered rate: a tick that
	// cleared thin cleared it in spite of us. It credits both measures of the
	// receive direction, since a collapse is a rate under thin whatever read
	// its queue. Thin is 3.53 MB/s on a 101 ms path, so on its own it puts the
	// credit, and the unconfirmed budget an improvement returns, out of reach
	// of every session running under 29 Mb/s: most of them, and all of the
	// 5-140 Mb/s bad population below its own thin rate, which is the
	// population the feature exists for.
	//
	// The cheap readings are what put the credit in reach of those, and each
	// one is a queue this tick read and found absent rather than a queue it
	// could not read. A tick with no fresh ack is not an ack round trip with no
	// queue in it. A queue delay read against a floor this connection watched
	// being set is not a queue that lifted either: the floor of a source first
	// read under a standing queue is inside that queue, and its delay then
	// reads zero for the connection's life -- which is the ground truth's own
	// shape, a session that starts bad and stays bad. What that guard reads is
	// the age of the reference and not which source convicted, so one gap is
	// left: a source whose floor was set inside the queue while the convicted
	// connection was running is older than the replacement and reads zero for
	// it too. It takes a socket whose talkers changed under a standing queue,
	// and closing it means carrying the convicting source through the ledger,
	// which is a heavier reading than the counters it protects. Crediting
	// either reading would resolve a re-roll as improved while the replacement
	// sat on the same bad member, and hand back the unimproved latch and the
	// unconfirmed budget, which are the only things bounding the next one. Both
	// also drop the ticks our own consumer paced, because a tick we slowed
	// ourselves says nothing about the path.
	//
	// The send reading needs no such guard: a send conviction is read from our
	// own kernel's send queue, and a tick that moved acked bytes without that
	// queue standing is that queue drained.
	packFloorHeld := !sample.queueDelaySlotTime.After(self.start)
	rxAckClean := !excluded && rxDemand && ackQueueKnown && !ackQueued && !rxCollapsed
	rxPackClean := !excluded && rxDemand && queueDelayKnown && packFloorHeld &&
		!packQueued && !rxCollapsed
	cleanRxAck := rxCleanRate || rxAckClean
	cleanRxPack := rxCleanRate || rxPackClean
	cleanTx := txCleanRate || (!excluded && txDemand && !txCollapsed)
	clean := cleanRxAck || cleanRxPack || cleanTx
	// An accepted tick that reached no verdict is not the same reading as a
	// healthy one, and nothing said which it was: an Observe rollout could not
	// tell a fleet with no collapse from one that was never able to classify a
	// tick. The sharpest case is a speed test whose SpeedStop is never
	// delivered, which leaves speedTestActive set and the connection blind for
	// the rest of its life with no signal at all. A tick falls in exactly one
	// of these three, by the first thing that decided it, so they can be summed
	// against Ticks and what they leave is the ticks read that found nothing.
	switch {
	case unread:
		self.stats.TicksUnread.Add(1)
	case receiveFull:
		self.stats.TicksReceiveFull.Add(1)
	case rxCollapsed || txCollapsed:
		self.stats.TicksCollapsed.Add(1)
	}

	rxOooKnown := prev.rxOooKnown && sample.rxOooKnown
	self.rxCollapsedRing = h1PathRingPush(self.rxCollapsedRing, rxCollapsed)
	self.txCollapsedRing = h1PathRingPush(self.txCollapsedRing, txCollapsed)
	self.rxAckQueuedRing = h1PathRingPush(self.rxAckQueuedRing, ackQueued)
	self.rxOooKnownRing = h1PathRingPush(self.rxOooKnownRing, rxOooKnown)
	self.rxOooRing = h1PathRingPush(self.rxOooRing, rxOooKnown && prev.rxOoo < sample.rxOoo)
	self.txRetransRing = h1PathRingPush(self.txRetransRing, txKnown && prev.txRetrans < sample.txRetrans)

	decision := h1PathDecision{
		clean:           clean,
		cleanRxAck:      cleanRxAck,
		cleanRxPack:     cleanRxPack,
		cleanTx:         cleanTx,
		queueDelay:      sample.queueDelay,
		queueDelayKnown: queueDelayKnown,
		ackQueue:        ackQueue,
		ackQueueKnown:   ackQueueKnown,
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
		ackQueuedTicks := bits.OnesCount16(self.rxAckQueuedRing & lossMask)
		decision.direction = h1PathDirectionRx
		decision.collapsedTicks = rxCollapsedTicks
		decision.lossTicks = lossTicks
		decision.lossKnownTicks = lossKnownTicks
		decision.ackQueuedTicks = ackQueuedTicks
		switch {
		case settings.RxLossMinTicks <= lossTicks && 0 < ackQueuedTicks:
			decision.confidence = h1PathConfidenceConfirmed
		case settings.RxLossMinTicks <= lossTicks:
			// loss the kernel saw, and a queue that stood on the sender's clock
			// alone: nothing here was measured on a clock this device controls,
			// so the re-roll draws on the unconfirmed budget
			decision.confidence = h1PathConfidenceUnconfirmed
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

// What a re-roll has to beat. The monitor that convicted does not survive the
// dial that answers it -- every dial builds a new one (newH1PathConnection) --
// so the conviction it read is kept here for as long as the re-roll is pending,
// and the improvement is judged against it.
type h1PathConvicted struct {
	direction h1PathDirection
	// the queue was read from the ack echo, so only an ack echo saying the
	// queue is gone answers it: the pack tags never saw this queue, and their
	// silence about it after the re-roll is the same silence as before
	ackCarried bool
}

// The clean ticks a connection has counted since it last convicted, one count
// per reading that can credit a re-roll (h1PathMonitor.tick).
type h1PathCleanTicks struct {
	rxAck  int
	rxPack int
	tx     int
}

// whether any reading has reached the bar, which is the cheap test before the
// ledger's lock
func (self h1PathCleanTicks) reached(cleanTicks int) bool {
	return cleanTicks <= max(self.rxAck, self.rxPack, self.tx)
}

// the count that can resolve a re-roll answering this conviction
func (self h1PathConvicted) cleanTicks(cleanTicks h1PathCleanTicks) int {
	switch {
	case self.direction == h1PathDirectionTx:
		return cleanTicks.tx
	case self.ackCarried:
		return cleanTicks.rxAck
	default:
		return cleanTicks.rxPack
	}
}

// One re-roll waiting for a verdict.
type h1PathPendingReroll struct {
	rerollTime time.Time
	convicted  h1PathConvicted
	// clean ticks of the convicted measure credited this re-roll as improved
	// (noteClean). The entry stays after that, so a route that re-collapses
	// can take the credit back; it no longer ages out, since an improvement
	// is a verdict and the window is only how long one is waited for
	credited bool
}

// The process-wide budget for re-rolls. Every method takes the current time so
// the ledger can be driven by a test clock.
//
// A re-roll leaves its route manager pending for ImprovementWindow. A
// conviction on that route manager inside the window is unimproved; clean ticks
// of the measure that convicted are an improvement; an entry that ages out, is
// evicted, or is dropped by a network change is unresolved.
// MaxUnimprovedRerolls unimproved re-rolls in one network epoch set the latch
// for LatchDuration.
//
// The improvement is a credit and not a discharge, so the entry stays for as
// long as its route manager lives. CleanTicks ticks is ten seconds at the
// defaults: evidence that the replacement started well, and none at all that
// it kept working. A conviction on a credited route manager takes the credit
// back as a re-collapse, which reaches the budget and not the latch: the latch
// reads a replacement that was never better, and this one was, for as long as
// CleanTicks ticks can see. What stays free is a re-roll whose route is never
// convicted again, which is what "a re-roll that keeps working is free" says.
//
// The two budgets read different things. The latch reads verdicts, so only a
// conviction inside the window sets it: that is the reading that says the
// replacement is as bad as what it replaced. The daily budget reads
// disconnects, so everything that spent one and was not resolved as improved is
// charged to it -- unimproved (noteConviction), aged out
// (expirePendingWithLock), evicted at the pending limit or overwritten by a
// second re-roll on the same route manager (noteReroll), dropped by a network
// change (networkChanged), or credited and convicted again
// (noteConviction) -- and it is what bounds a device whose route cannot
// produce a verdict inside the window at all, whose network does not stand
// still long enough to give one, or that recovers for a few seconds at a
// time.
//
// An unconfirmed conviction is one nothing on this device could check: no
// kernel loss counter, or a queue that stood on the sender's clock alone.
// MaxUnconfirmedRerolls of those are allowed per network epoch, and an
// improvement returns the budget, so a re-roll that keeps working is free and
// one that changes nothing is spent once. Taking a credit back does not take
// the returned budget back with it -- the epoch's counts have moved on by then
// and there is nothing to restore them to -- so a route that recovers and
// re-collapses can spend the epoch's unconfirmed budget more than once. The
// day is what bounds that one, as it bounds the rest of that loop.
//
// The ledger counts Unresolved and Recollapsed; callers count Unimproved and
// Improved from the returns of noteConviction and noteClean, and the
// suppression reasons from allow. Safe for concurrent use.
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
	latchNetworkResetAge time.Duration
	dayChargedTimes      [h1PathDayRingSize]time.Time
	dayChargedNext       int
	// Keyed weakly: the ledger outlives every transport in the process, and an
	// entry waits out the improvement window whether or not anything still
	// reads it -- a credited one waits for a conviction that may never come --
	// so a strong key would pin a route manager, its match states, its pending
	// writer snapshots and its alias scopes, for as long as the process runs. A
	// weak key keeps the identity (a pointer that has been collected never
	// equals a live one, whatever the allocator does with the address) and
	// drops the object, which is also what bounds this map. A collected route
	// manager's re-roll is unresolved, which is what it is: nothing is left to
	// judge it.
	pendingRouteManagerRerolls map[weak.Pointer[RouteManager]]h1PathPendingReroll
	excludedPorts              []int
}

func newH1PathLedger() *h1PathLedger {
	return &h1PathLedger{
		stats:                      &h1PathProcessStats,
		pendingRouteManagerRerolls: map[weak.Pointer[RouteManager]]h1PathPendingReroll{},
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

// Charges one re-roll to the rolling daily budget, at the moment it stopped
// being judgeable rather than the moment the ledger noticed. Everything that
// spends a break-before-make disconnect and is not resolved as improved passes
// through here, so the budget counts disconnects and not verdicts. The ring is
// a set of times with no order, so the charges need not arrive in order.
func (self *h1PathLedger) chargeDayWithLock(chargeTime time.Time) {
	self.dayChargedTimes[self.dayChargedNext] = chargeTime
	self.dayChargedNext = (self.dayChargedNext + 1) % h1PathDayRingSize
}

// Drops the pending entries that can no longer be judged, and charges the ones
// whose improvement window simply ran out.
//
// An age-out is the case the window was too short for: a re-roll is judged by
// the connection that replaced it, and that verdict arrives at the cadence of
// whatever evidence the route carries, so on a route whose ack echo comes back
// slower than ImprovementWindow the replacement is convicted after the window
// has closed and the re-roll before it is answered by nothing. Charged to
// nothing it costs a disconnect per ack cadence for ever, with neither the
// latch nor the budget binding because nothing was ever unimproved -- measured
// at the library defaults, 23 disconnects an hour at a 150 s echo and 14 at a
// 240 s one (TestH1PathRerollIsChargedWhateverTheRouteCanJudge). It is charged
// to the daily budget and not to the epoch latch because it is not the same
// reading: a conviction inside the window says the replacement is as bad as
// what it replaced, and an age-out says only that a disconnect was spent. The
// cost of the charge is that a re-roll that did work and could not be read is
// charged too, and that starts at half the window rather than at it, since the
// credit needs two ack echoes where the age-out needs one: an echo every 59 s
// already charges a re-roll that worked
// (TestH1PathImprovementCreditNeedsTwoEchoesInsideTheWindow). The levers are
// ImprovementWindow and MaxUnimprovedRerollsPerDay.
//
// A route manager collected under the weak key is not charged: its transport is
// gone, so nothing is looping and no disconnect follows. An epoch that ended
// (networkChanged) is charged, though it is not judged: the new network says
// nothing about the re-roll, but the disconnect was spent all the same.
//
// A credited entry does not age out. The window is how long a verdict is
// waited for, and that one arrived; what it waits for now is a conviction that
// would take the credit back, which can come at any age (noteConviction).
func (self *h1PathLedger) expirePendingWithLock(settings *H1PathRerollSettings, now time.Time) {
	for key, pending := range self.pendingRouteManagerRerolls {
		collected := key.Value() == nil
		if !collected &&
			(pending.credited || now.Sub(pending.rerollTime) <= settings.ImprovementWindow) {
			continue
		}
		delete(self.pendingRouteManagerRerolls, key)
		if pending.credited {
			// already resolved as improved, and its route manager is gone, so
			// there is nothing left to take the credit back
			continue
		}
		self.stats.Unresolved.Add(1)
		if !collected {
			// charged when the window closed and not when the ledger was next
			// touched: nothing sweeps these entries on a timer, and on a device
			// whose only connection stops convicting the next touch can be
			// hours away, which would hold the budget for a day from then
			self.chargeDayWithLock(pending.rerollTime.Add(settings.ImprovementWindow))
		}
	}
}

// Returns true when the conviction lands inside the improvement window of a
// re-roll on the same route manager. That re-roll is unimproved: it counts
// toward the epoch latch and the daily budget.
//
// A conviction on a credited entry takes the credit back instead: the re-roll
// is charged to the daily budget, counted Recollapsed and dropped, and the
// latch is left alone, since a replacement that was read as working is not the
// reading the latch is for -- that one says the replacement was as bad as what
// it replaced, and this one says it stopped being better. Without the
// revocation a replacement clean for CleanTicks ticks and collapsed again
// bought its own next re-roll for ever: measured on a route that clears for a
// minute at a time, 109 disconnects in two hours against six here
// (TestH1PathImprovementCreditIsTakenBackWhenTheRouteRecollapses).
func (self *h1PathLedger) noteConviction(
	key *RouteManager,
	settings *H1PathRerollSettings,
	now time.Time,
) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	self.expirePendingWithLock(settings, now)
	pendingKey := weak.Make(key)
	pending, ok := self.pendingRouteManagerRerolls[pendingKey]
	if !ok {
		return false
	}
	delete(self.pendingRouteManagerRerolls, pendingKey)
	self.chargeDayWithLock(now)
	if pending.credited {
		self.stats.Recollapsed.Add(1)
		return false
	}
	self.epochUnimproved += 1
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
	dayCharged := 0
	for _, chargedTime := range self.dayChargedTimes {
		if !chargedTime.IsZero() && now.Sub(chargedTime) < 24*time.Hour {
			dayCharged += 1
		}
	}
	if min(settings.MaxUnimprovedRerollsPerDay, h1PathDayRingSize) <= dayCharged {
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
	convicted h1PathConvicted,
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
	pendingKey := weak.Make(key)
	if replaced, ok := self.pendingRouteManagerRerolls[pendingKey]; ok {
		// The route manager is the client's, not the connection's, so two
		// connections of one client can pass allow in the same instant and the
		// second arrives here on an entry the first is still waiting on. The
		// entry it overwrites spent a disconnect and nothing judged it, so it
		// is charged like any other drop -- sequentially this cannot happen,
		// since the conviction that led here took the entry first
		// (noteConviction), and DeviceRerollSpacing closes the window to the
		// width of these two calls.
		if !replaced.credited {
			self.stats.Unresolved.Add(1)
			self.chargeDayWithLock(now)
		}
	} else if h1PathPendingLimit <= len(self.pendingRouteManagerRerolls) {
		// a credited entry goes first and costs nothing: it is the memory of a
		// verdict already given, kept only so a re-collapse can take it back.
		// An uncredited one stops being tracked before anything judged it, and
		// it spent a disconnect like any other, so it is charged here rather
		// than dropped for free
		var oldestKey weak.Pointer[RouteManager]
		var oldestTime time.Time
		oldestCredited := false
		oldestSet := false
		for candidateKey, pending := range self.pendingRouteManagerRerolls {
			replaces := !oldestSet ||
				(pending.credited && !oldestCredited) ||
				(pending.credited == oldestCredited && pending.rerollTime.Before(oldestTime))
			if !replaces {
				continue
			}
			oldestKey = candidateKey
			oldestTime = pending.rerollTime
			oldestCredited = pending.credited
			oldestSet = true
		}
		delete(self.pendingRouteManagerRerolls, oldestKey)
		if !oldestCredited {
			self.stats.Unresolved.Add(1)
			self.chargeDayWithLock(now)
		}
	}
	self.pendingRouteManagerRerolls[pendingKey] = h1PathPendingReroll{
		rerollTime: now,
		convicted:  convicted,
	}
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

// Returns true, once, when a pending re-roll on the route manager has reached
// CleanTicks clean ticks of the measure that convicted. The re-roll is
// improved, and the epoch's unimproved and unconfirmed counts are both reset: a
// re-roll that demonstrably fixed the connection is the evidence its conviction
// lacked, so it costs the epoch nothing and the next unconfirmed conviction is
// judged on its own.
//
// The entry is kept and marked rather than dropped, so the credit can be taken
// back by any later conviction on the same route manager (noteConviction). Ten
// seconds of clean ticks say the replacement started well and nothing about
// whether it lasts, and the caller reads clean ticks on every tick once the
// bar is reached, so the mark is also what keeps Improved counting one per
// re-roll.
//
// Only the convicted measure counts, because these two counters are the only
// bound on a client that keeps re-rolling, and every other reading a
// replacement can offer is a reading of something we did not convict: a send
// direction that was never the complaint, or a receive queue on the measure
// that was blind to this one. A replacement that cannot be read on the
// convicted measure resolves nothing and its re-roll ages out unresolved,
// which is what it is.
func (self *h1PathLedger) noteClean(
	key *RouteManager,
	settings *H1PathRerollSettings,
	now time.Time,
	cleanTicks h1PathCleanTicks,
) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	self.expirePendingWithLock(settings, now)
	pendingKey := weak.Make(key)
	pending, ok := self.pendingRouteManagerRerolls[pendingKey]
	if !ok || pending.credited {
		return false
	}
	if pending.convicted.cleanTicks(cleanTicks) < settings.CleanTicks {
		return false
	}
	pending.credited = true
	self.pendingRouteManagerRerolls[pendingKey] = pending
	self.epochUnimproved = 0
	self.epochUnconfirmed = 0
	return true
}

// Starts a new network epoch: the epoch counters, the pending entries and the
// excluded ports clear. A latch clears only once it is at least as old as the
// reset age recorded when it was set. The daily budget and the device spacing
// span epochs.
//
// A pending re-roll is dropped here and charged on the way out. Dropped,
// because a connection on the new network is no evidence about a re-roll on
// the old one, and the latch reads evidence. Charged, because the daily budget
// reads disconnects and that one was spent: the change is what stopped anyone
// judging it, not proof that nothing was owed. Left uncharged it gave the
// whole pre-fix rate back to a device that changes network faster than
// ImprovementWindow, since the change clears the epoch counters too and the
// budget was the only bound left -- measured over two hours on a route whose
// ack echo comes every 150 s (TestH1PathNetworkChangeChargesTheDisconnect):
// with a change every two minutes, 47 re-rolls and nothing charged, against
// the budget's six and then refusals once they are.
//
// What the charge costs is a device that roams faster than the window and
// convicts on each network: it spends its six a day on re-rolls no network
// lived long enough to judge, and MaxUnimprovedRerollsPerDay is the lever, the
// same one an ack cadence slower than the window already leans on. A route
// manager collected under the weak key is not charged, as everywhere else: its
// transport is gone, so no disconnect follows. Neither is a credited entry:
// that re-roll was resolved as improved before the change, and the credit ends
// with the epoch rather than being charged to it.
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
	for key, pending := range self.pendingRouteManagerRerolls {
		collected := key.Value() == nil
		delete(self.pendingRouteManagerRerolls, key)
		if pending.credited {
			// resolved as improved before the change: the disconnect it spent
			// bought a connection that worked, and the credit ends with the
			// epoch rather than being charged to it
			continue
		}
		self.stats.Unresolved.Add(1)
		if !collected {
			self.chargeDayWithLock(now)
		}
	}
}

// Whether the port is inside the window of a port convicted this network epoch,
// which is what a far-random plan is required to avoid.
func (self *h1PathLedger) excludesPort(port int, radius int) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return h1SourcePortExcluded(port, self.excludedPorts, radius)
}

// Whether a connection's local port means its planned dial did not move the
// 4-tuple: the dial carried a source port plan, and the port it ended up with
// is still inside the window the ledger excluded. Only a planned dial is judged
// this way -- the kernel's port after an ordinary reconnect sits next to the
// previous one too, and that connection is a fresh 4-tuple nobody asked to
// move.
func h1PathSourcePortUnmoved(
	settings *H1PathRerollSettings,
	ledger *h1PathLedger,
	mode H1PathRerollMode,
	plannedDial bool,
	localPort int,
) bool {
	if !plannedDial ||
		mode != H1PathRerollModeAct ||
		settings.SourcePortPolicy != H1SourcePortFarRandom ||
		localPort <= 0 {
		return false
	}
	return ledger.excludesPort(localPort, max(0, settings.SourcePortExcludeRadius))
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
	ConnectionsMonitored atomic.Uint64
	ConnectionsDormant   atomic.Uint64
	// connections whose transport buffers nothing, so every tick would be
	// excluded by our own back pressure
	ConnectionsUnbuffered atomic.Uint64
	KernelUnavailable     atomic.Uint64
	// connections whose monitor failed and was stopped, leaving the connection
	// itself running
	MonitorStopped atomic.Uint64
	// connections that convicted at least once, counted once each. RxConvictions
	// counts verdicts, and one stuck connection produces one every two seconds
	// for as long as it stays stuck, so only this one reads against
	// ConnectionsMonitored as a share of sessions
	ConnectionsConvicted atomic.Uint64
	Ticks                atomic.Uint64
	// How each accepted tick was read. These three are disjoint -- a tick is
	// counted by the first thing that decided it -- so they sum to at most
	// Ticks and what they leave is the ticks that were read and found nothing.
	// With Ticks they separate a connection that saw no collapse from one that
	// never looked.
	//
	// The speed test echo or a stand down kept the tick out of both verdicts,
	// and our own back pressure kept it out of a conviction
	TicksUnread      atomic.Uint64
	TicksReceiveFull atomic.Uint64
	// a direction collapsed in the tick, whether or not the window ever
	// reached a conviction
	TicksCollapsed atomic.Uint64
	// accepted ticks with too few pack samples to read a queue delay. This one
	// crosses the three above rather than joining them: the receive rule can
	// convict on the ack round trip alone, so a tick can both collapse and
	// carry no readable pack tags, and a rollout needs to see both
	TicksQueueDelayUnknown atomic.Uint64
	// accepted ticks with no fresh ack round trip to read, which is every tick
	// of a route whose peer answers over another transport. Against Ticks this
	// is the size of the population whose convictions can only be unconfirmed;
	// it crosses the three disjoint readings in the same way
	TicksAckUnknown atomic.Uint64
	// accepted ticks that had an ack round trip to read and lost it to our own
	// send backlog. Disjoint from TicksAckUnknown, which counts the ticks with
	// no ack to read at all; the two together are the ticks whose conviction
	// could only be unconfirmed, and they are kept apart because a busy uplink
	// and a peer that answers over another transport are different problems
	// with different fixes
	TicksAckBacklogged atomic.Uint64
	// sampled packs of an accepted tick that read nothing: a tag older than the
	// route's latest re-roll mark, and a source the baseline holds no slot for.
	// The second is the only reading of the sticky slot rule's blind spot, a
	// source that went quiet long enough to lose its slot and came back into a
	// queue it now takes for its own floor
	PacksStale     atomic.Uint64
	PacksUnslotted atomic.Uint64
	// ticks whose queue delay reached the threshold and whose fresh ack round
	// trip did not: the sender's clock and ours disagree about the queue
	RxAckDeniedTicks            atomic.Uint64
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
	SuppressedSourcePort        atomic.Uint64
	// A re-roll is Improved only when the measure that convicted reads its own
	// queue gone (h1PathConvicted), so a replacement nothing could read on that
	// measure is Unresolved and not Improved: a rollout reading Improved against
	// Rerolls is reading how often a re-roll was seen to work, and Unresolved is
	// how often nothing could tell either way. Unimproved and Unresolved are
	// both charged to the daily budget, since both spent a disconnect; only
	// Unimproved reaches the latch, and SuppressedDailyBudget against these two
	// is where a route that cannot be judged inside the window shows up.
	//
	// Recollapsed counts the credits taken back: a re-roll counted Improved
	// whose route was convicted again afterwards, charged to the budget and
	// not to the latch. Improved less Recollapsed is how often a
	// re-roll was seen to work and was never seen to stop, and Recollapsed
	// against Improved is how much of the credit a fleet's routes hand back
	Improved            atomic.Uint64
	Unimproved          atomic.Uint64
	Unresolved          atomic.Uint64
	Recollapsed         atomic.Uint64
	SourcePortBinds     atomic.Uint64
	SourcePortFallbacks atomic.Uint64
	// connections whose local port is inside the window the ledger excluded,
	// so a planned re-roll dial did not move the 4-tuple
	SourcePortUnmoved atomic.Uint64
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
	case h1PathReasonSourcePort:
		self.SuppressedSourcePort.Add(1)
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
	ConnectionsUnbuffered       uint64
	KernelUnavailable           uint64
	MonitorStopped              uint64
	ConnectionsConvicted        uint64
	Ticks                       uint64
	TicksUnread                 uint64
	TicksReceiveFull            uint64
	TicksQueueDelayUnknown      uint64
	TicksAckUnknown             uint64
	TicksAckBacklogged          uint64
	TicksCollapsed              uint64
	PacksStale                  uint64
	PacksUnslotted              uint64
	RxAckDeniedTicks            uint64
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
	SuppressedSourcePort        uint64
	Improved                    uint64
	Unimproved                  uint64
	Unresolved                  uint64
	Recollapsed                 uint64
	SourcePortBinds             uint64
	SourcePortFallbacks         uint64
	SourcePortUnmoved           uint64
}

func (self *h1PathStats) snapshot() H1PathRerollStatsSnapshot {
	return H1PathRerollStatsSnapshot{
		ConnectionsMonitored:        self.ConnectionsMonitored.Load(),
		ConnectionsDormant:          self.ConnectionsDormant.Load(),
		ConnectionsUnbuffered:       self.ConnectionsUnbuffered.Load(),
		KernelUnavailable:           self.KernelUnavailable.Load(),
		MonitorStopped:              self.MonitorStopped.Load(),
		ConnectionsConvicted:        self.ConnectionsConvicted.Load(),
		Ticks:                       self.Ticks.Load(),
		TicksUnread:                 self.TicksUnread.Load(),
		TicksReceiveFull:            self.TicksReceiveFull.Load(),
		TicksQueueDelayUnknown:      self.TicksQueueDelayUnknown.Load(),
		TicksAckUnknown:             self.TicksAckUnknown.Load(),
		TicksAckBacklogged:          self.TicksAckBacklogged.Load(),
		TicksCollapsed:              self.TicksCollapsed.Load(),
		PacksStale:                  self.PacksStale.Load(),
		PacksUnslotted:              self.PacksUnslotted.Load(),
		RxAckDeniedTicks:            self.RxAckDeniedTicks.Load(),
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
		SuppressedSourcePort:        self.SuppressedSourcePort.Load(),
		Improved:                    self.Improved.Load(),
		Unimproved:                  self.Unimproved.Load(),
		Unresolved:                  self.Unresolved.Load(),
		Recollapsed:                 self.Recollapsed.Load(),
		SourcePortBinds:             self.SourcePortBinds.Load(),
		SourcePortFallbacks:         self.SourcePortFallbacks.Load(),
		SourcePortUnmoved:           self.SourcePortUnmoved.Load(),
	}
}

// The process H1 path re-roll counters.
func H1PathRerollStats() H1PathRerollStatsSnapshot {
	return h1PathProcessStats.snapshot()
}
