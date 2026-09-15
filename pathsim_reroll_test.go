package connect

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// S9, the lossy-connection re-roll, on the path simulator of pathsim_test.go.
//
// What it models. A relay datacenter hashes each TCP 4-tuple onto one of
// several members of the path to a client about 100 ms away, and one member in
// eight is lossy. A client whose websocket lands there runs at a few Mb/s for
// the connection's whole life while the same client on another source port runs
// at line rate. Transfer cannot see it: the carrier is reliable, so the sender
// records no resends at all, and the only visible symptom is the whole window
// sitting queued in the far socket while the receiver's read-to-send delay
// climbs to seconds.
//
// The scenario models the member assignment (a hash of the connection's
// synthetic source port), the lossy member's shape (a slow, deep, blocking
// socket queue) and the switch (break before make: the old leg is torn down,
// its queued bytes are lost, and a new leg for a new port starts after a dial
// gap). Everything that decides is production code: `h1PathMonitor`,
// `h1PathLedger`, `h1RouteObserver` (fed by the real `Client.run` sampling on
// the receiver's route) and `newH1SourcePortPlan`.
//
// What it does not model. There is no kernel TCP here, so the out-of-order
// counter the monitor reads as loss evidence is scripted per arm rather than
// measured, and the send-side counters are never known. There is no websocket
// and no dial: a re-roll is a leg swap plus a fixed gap, and `RerollDials`,
// `SourcePortBinds` and the platform transport's own reconnect path are not
// exercised (they have their own tests in transport_h1_path_platform_test.go
// and h1_source_port_unix_test.go). The drain handoff of the design's commit 10
// is not implemented, so every arm here switches break before make.
//
// One detector setting is not the default. At 16 KiB payloads a connection
// collapsed to 5 Mb/s carries about 39 frames a second, so the production 1-in-16
// sampling yields about one pack sample per 500 ms tick, below the default
// MinTickPackSamples of 2, and the queue delay would read unknown on every
// tick. A real client's frames are mostly MTU-sized, where 39 frames a second
// is 5 Mb/s of 1448-byte frames times eleven and the default is met with room
// to spare. The arms therefore set MinTickPackSamples 1 and keep
// PackSampleEvery at the production 16; the frame size, not the detector, is
// what the simulator cannot reproduce. This is recorded as an open question for
// the rig protocol.

// How the path assigns a connection to a member.
type pathHashModel int

const (
	// fnv1a over the seed and the port: neighbouring ports land on unrelated
	// members, the friendly case for a kernel re-roll
	pathHashIndependent pathHashModel = 0
	// contiguous blocks of 64 ports share a member, as the rig's bad ports
	// 40004-40012 did: a kernel re-roll of a few ports stays in the bad block
	pathHashBlock64 pathHashModel = 1
)

// Whether a connection on this source port lands on the lossy member.
func pathConnectionLossy(hash pathHashModel, seed uint64, port int, members int, lossyMember int) bool {
	members = max(1, members)
	switch hash {
	case pathHashBlock64:
		return (port/64)%members == lossyMember
	default:
		var key [10]byte
		binary.LittleEndian.PutUint64(key[0:8], seed)
		binary.LittleEndian.PutUint16(key[8:10], uint16(port))
		digest := fnv.New64a()
		digest.Write(key[:])
		return int(digest.Sum64()%uint64(members)) == lossyMember
	}
}

// The re-roll half of an arm: the detector settings, the member model, and how
// a leg is built for a port.
type pathRerollScenario struct {
	Settings H1PathRerollSettings
	// the source port of the first connection
	FirstPort  int
	PortPolicy H1SourcePortPolicy
	Hash       pathHashModel
	// members of the path, and the one that is lossy
	Members     int
	LossyMember int
	// the client leg for a healthy or a lossy connection
	Leg func(lossy bool) pathHop
	// the kernel's out-of-order counter for one tick: whether the field is
	// known at all, and whether it advanced since the tick before
	KernelOoo func(tick int, lossy bool) (known bool, advanced bool)
	// the time the replacement connection takes to dial
	DialGap time.Duration
	// the rate a healthy connection reads, for the recovery window; zero
	// leaves recovery unmeasured
	HealthyRate float64
}

// What one arm's re-roll produced.
type pathRerollResult struct {
	convictions                 int
	confirmedConvictions        int
	unconfirmedConvictions      int
	switches                    int
	improved                    int
	suppressedLatched           int
	suppressedUnconfirmedBudget int
	// messages the switch threw away: the retired leg's queue, what it was
	// serialising, what was propagating, and what its routes still held
	switchDrops int64
	// connections the arm monitored, and connections too close to monitor
	monitored int
	dormant   int
	// the source ports the connections used, in order
	ports []int
	// from the offer start
	firstConvictionAfter time.Duration
	firstSwitchAfter     time.Duration
	// from the switch to the first second at 0.8 x HealthyRate; zero when the
	// arm never switched or never recovered
	recoveryAfterSwitch time.Duration
}

func (self *pathRerollResult) flag() string {
	return fmt.Sprintf(
		"reroll=c%d/s%d/i%d",
		self.convictions, self.switches, self.improved,
	)
}

// The offset of the first tick from the offer start. It is not a round number
// of anything, so a tick never shares a virtual instant with a delivery, a
// compression interval or a source push.
const pathRerollTickOffset = 37 * time.Microsecond

// The mss the scenario reports to the monitor, an ethernet segment.
const pathRerollMss = 1448

// Drives the production H1 path monitor over one arm's connection, and swaps
// the arm's last hop for a new leg when the monitor and the ledger call for a
// re-roll. One goroutine in the arm's bubble owns all of it.
type pathReroll struct {
	arm      pathArm
	scenario *pathRerollScenario
	carrier  *pathCarrier
	receiver *Client
	meter    *pathMeter

	settings H1PathRerollSettings
	stats    *h1PathStats
	ledger   *h1PathLedger
	baseline *h1QueueDelayBaseline
	// the kernel port model, and the far-random plan's draws
	random *rand.Rand

	// the live connection
	port             int
	lossy            bool
	leg              *pathHopRuntime
	observer         *h1RouteObserver
	receiveTransport Transport
	sendTransport    Transport
	receiveRoute     Route
	sendRoute        Route
	monitor          *h1PathMonitor
	rxOoo            uint64
	cleanTicks       int
	tickOrdinal      int

	started  time.Time
	switchAt time.Time
	stopped  chan struct{}
	done     chan struct{}
	result   pathRerollResult
}

func newPathReroll(arm pathArm, carrier *pathCarrier, receiver *Client) *pathReroll {
	scenario := arm.Reroll
	stats := &h1PathStats{}
	ledger := newH1PathLedger()
	ledger.stats = stats
	reroll := &pathReroll{
		arm:      arm,
		scenario: scenario,
		carrier:  carrier,
		receiver: receiver,
		settings: scenario.Settings,
		stats:    stats,
		ledger:   ledger,
		baseline: newH1QueueDelayBaseline(&scenario.Settings),
		// a stream of its own, so the loss draws of the hops are untouched
		random:  rand.New(rand.NewPCG(arm.Seed, 99)),
		port:    scenario.FirstPort,
		stopped: make(chan struct{}),
		done:    make(chan struct{}),
	}
	reroll.result.ports = []int{scenario.FirstPort}
	reroll.lossy = pathConnectionLossy(
		scenario.Hash, arm.Seed, scenario.FirstPort, scenario.Members, scenario.LossyMember)
	if scenario.Settings.Mode != H1PathRerollModeOff {
		reroll.startMonitor(time.Now())
	}
	return reroll
}

// A new connection's monitor and observer. Nil when the path is too short to
// monitor, exactly as `newH1PathMonitor` refuses one below MinPathRtt.
func (self *pathReroll) startMonitor(now time.Time) {
	monitor := newH1PathMonitor(&self.settings, now, self.pathRtt())
	if monitor == nil {
		self.stats.ConnectionsDormant.Add(1)
		return
	}
	monitor.stats = self.stats
	self.monitor = monitor
	self.observer = newH1RouteObserver(self.baseline, self.settings.PackSampleEvery)
	self.rxOoo = 0
	self.cleanTicks = 0
	self.stats.ConnectionsMonitored.Add(1)
}

// The round trip of the live path: every hop of the arm, the client leg
// included. A re-roll keeps the delays, so it does not move.
func (self *pathReroll) pathRtt() time.Duration {
	return pathRoundTrip(self.arm.Hops)
}

// nil for an arm whose connection is not monitored, which is what an Off arm
// and a dormant same-datacenter arm publish
func (self *pathReroll) observerOrNil() *h1RouteObserver {
	if self == nil {
		return nil
	}
	return self.observer
}

// Records the transports and routes of the connection the caller published, so
// a re-roll can retire them.
func (self *pathReroll) adoptLeg(
	receiveTransport Transport,
	sendTransport Transport,
	receiveRoute Route,
	sendRoute Route,
) {
	self.receiveTransport = receiveTransport
	self.sendTransport = sendTransport
	self.receiveRoute = receiveRoute
	self.sendRoute = sendRoute
	self.leg = self.carrier.hops[len(self.carrier.hops)-1]
}

// Starts the tick goroutine. Nil-safe, so an arm without a re-roll scenario
// needs no branch.
func (self *pathReroll) start(ctx context.Context, started time.Time) {
	if self == nil {
		return
	}
	self.started = started
	go self.run(ctx)
}

// Stops the tick goroutine, joins it, and returns the arm's result. Nil-safe.
func (self *pathReroll) finish() *pathRerollResult {
	if self == nil {
		return nil
	}
	close(self.stopped)
	<-self.done
	if 0 < self.switches() && 0 < self.scenario.HealthyRate {
		self.result.recoveryAfterSwitch = pathRecoveryAfter(
			self.meter,
			self.arm.PayloadByteCount,
			self.switchAt,
			0.8*self.scenario.HealthyRate,
		)
	}
	self.result.confirmedConvictions = int(self.stats.ConfirmedConvictions.Load())
	self.result.unconfirmedConvictions = int(self.stats.UnconfirmedConvictions.Load())
	self.result.monitored = int(self.stats.ConnectionsMonitored.Load())
	self.result.dormant = int(self.stats.ConnectionsDormant.Load())
	self.result.suppressedLatched = int(self.stats.SuppressedLatched.Load())
	self.result.suppressedUnconfirmedBudget = int(self.stats.SuppressedUnconfirmedBudget.Load())
	self.result.improved = int(self.stats.Improved.Load())
	return &self.result
}

func (self *pathReroll) switches() int {
	return self.result.switches
}

func (self *pathReroll) run(ctx context.Context) {
	defer close(self.done)
	if self.monitor == nil {
		// an Off arm, or a path short enough to be dormant: no ticks at all,
		// which is the production cost of an unmonitored connection
		return
	}
	select {
	case <-time.After(pathRerollTickOffset):
	case <-self.stopped:
		return
	case <-ctx.Done():
		return
	}
	ticker := time.NewTicker(max(self.settings.TickInterval, time.Millisecond))
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			self.tick(ctx, now)
		case <-self.stopped:
			return
		case <-ctx.Done():
			return
		}
	}
}

// One monitor tick: the sample the platform transport would build from its
// reader counters, its observer and the kernel, then the verdict, then the Act
// steps in the order transport_h1_path_connection.go runs them.
func (self *pathReroll) tick(ctx context.Context, now time.Time) {
	if self.monitor == nil {
		return
	}
	self.tickOrdinal += 1
	forward := self.leg.forwardControl
	reverse := self.leg.reverseControl
	sample := h1PathSample{
		now: now,
		// the leg is the connection: its counters start at zero, exactly as a
		// fresh socket's do
		readMessageCount:  uint64(forward.deliveredMessages.Load()),
		writeMessageCount: uint64(reverse.deliveredMessages.Load()),
		readByteCount:     uint64(forward.deliveredBytes.Load()),
		rxBytesKnown:      true,
		rxBytes:           uint64(forward.deliveredBytes.Load()),
		minRtt:            self.pathRtt(),
		rcvMss:            pathRerollMss,
		sndMss:            pathRerollMss,
	}
	observerTick := self.observer.takeTick(now)
	if observerTick.known {
		sample.queueDelay = observerTick.queueDelay
		sample.queueDelaySamples = observerTick.samples
	}
	sample.ackRttMin = observerTick.ackRttMin
	if self.scenario.KernelOoo != nil {
		known, advanced := self.scenario.KernelOoo(self.tickOrdinal, self.lossy)
		if advanced {
			self.rxOoo += 1
		}
		sample.rxOooKnown = known
		sample.rxOoo = self.rxOoo
	}

	decision := self.monitor.tick(sample)
	if decision.dormant {
		self.observer.setActive(false)
		self.monitor = nil
		return
	}
	self.decide(ctx, now, &decision)
}

// The Act steps of transport_h1_path_connection.go's decide, on this arm's own
// ledger and stats.
func (self *pathReroll) decide(ctx context.Context, now time.Time, decision *h1PathDecision) {
	act := self.settings.Mode == H1PathRerollModeAct
	key := self.receiver.RouteManager()
	switch {
	case decision.convicted:
		self.cleanTicks = 0
		self.result.convictions += 1
		if self.result.firstConvictionAfter == 0 {
			self.result.firstConvictionAfter = now.Sub(self.started)
		}
		if !act {
			self.stats.recordSuppression(h1PathReasonObserve)
			return
		}
		if self.ledger.noteConviction(key, &self.settings, now) {
			self.stats.Unimproved.Add(1)
		}
		allowed, reason := self.ledger.allow(
			&self.settings,
			now,
			self.settings.Role,
			decision.confidence,
			now.Sub(self.monitor.start),
		)
		if !allowed {
			self.stats.recordSuppression(reason)
			return
		}
		self.ledger.noteReroll(
			key, &self.settings, now, self.settings.Role, decision.confidence, self.port)
		// packs built for this connection, and their resends, carry old tags
		// that must not convict the next one
		self.baseline.markReroll(now, decision.pathRtt)
		self.stats.Rerolls.Add(1)
		self.switchLeg(ctx, now)
	case decision.clean && act:
		self.cleanTicks += 1
		if self.settings.CleanTicks <= self.cleanTicks &&
			self.ledger.noteClean(key, &self.settings, now, self.cleanTicks) {
			self.stats.Improved.Add(1)
		}
	}
}

// Break before make: the connection is closed, everything it held is lost, and
// the replacement dials DialGap later onto whatever member its new source port
// hashes to. The design's commit 10 replaces this with a drain handoff that
// keeps the old leg's receive route registered while the new one carries new
// traffic; it is out of scope here, so this scenario has no drain arm and no
// handoff setting.
func (self *pathReroll) switchLeg(ctx context.Context, now time.Time) {
	routeManager := self.receiver.RouteManager()
	// The trim runs first, while the receiver is still reading: a link blocked
	// writing to a route nobody reads answers nothing until it is cancelled.
	close(self.leg.forwardControl.stopIngress)
	self.result.switchDrops += self.leg.forwardControl.trimNow(ctx, 0, true)
	routeManager.RemoveTransport(self.receiveTransport)
	routeManager.RemoveTransport(self.sendTransport)
	self.observer.setActive(false)
	self.leg.forwardCancel()
	self.leg.reverseCancel()

	self.result.switches += 1
	if self.result.firstSwitchAfter == 0 {
		self.result.firstSwitchAfter = now.Sub(self.started)
	}
	self.switchAt = now

	// the dial. The retired leg's goroutines finish inside it, so what its
	// routes still hold can be counted once they are done.
	select {
	case <-time.After(self.scenario.DialGap):
	case <-ctx.Done():
		return
	}
	self.result.switchDrops += drainPathRoutes(self.receiveRoute, self.sendRoute)

	self.port = self.nextPort()
	self.result.ports = append(self.result.ports, self.port)
	self.lossy = pathConnectionLossy(
		self.scenario.Hash, self.arm.Seed, self.port, self.scenario.Members, self.scenario.LossyMember)
	hop := self.scenario.Leg(self.lossy)
	self.arm.Hops[len(self.arm.Hops)-1] = hop

	receiveRoute := make(Route, self.arm.RouteCapacity)
	sendRoute := make(Route, self.arm.RouteCapacity)
	self.carrier.extraRoutes = append(self.carrier.extraRoutes, receiveRoute, sendRoute)
	// the inter-hop channels are the relay's side of the connection and do not
	// move; only the client's socket does
	forwardIn := self.carrier.channels[len(self.carrier.channels)-2]
	reverseOut := self.carrier.channels[len(self.carrier.channels)-1]
	self.leg = self.carrier.startHop(
		ctx, hop, self.arm.Seed, 2*len(self.carrier.hops),
		forwardIn, receiveRoute, sendRoute, reverseOut,
		self.arm.PayloadByteCount, true, true,
	)
	self.receiveRoute = receiveRoute
	self.sendRoute = sendRoute

	self.startMonitor(time.Now())
	self.receiveTransport = NewReceiveGatewayTransportWithType(TransportTypeH1)
	self.sendTransport = NewSendGatewayTransportWithType(TransportTypeH1)
	routeManager.UpdateTransportWithProperties(
		self.receiveTransport,
		[]Route{receiveRoute},
		TransferCarrierProperties{
			ReceiveReliability: CarrierReliabilityReliable,
			receiveObserver:    self.observer,
		},
	)
	routeManager.UpdateTransport(self.sendTransport, []Route{sendRoute})
}

// The source port of the replacement connection.
func (self *pathReroll) nextPort() int {
	if self.scenario.PortPolicy == H1SourcePortFarRandom {
		plan := newH1SourcePortPlan(
			&self.settings, self.ledger.excluded(), self.random.IntN, self.stats)
		if port, ok := plan.pick(); ok {
			return port
		}
		return self.port
	}
	// the kernel's own choice: the next ports of its rotor, a few above the
	// one just closed
	return self.port + 2 + 2*self.random.IntN(8)
}

// The time from `after` to the start of the first one-second window of the
// meter's delivery trace that carried at least `targetByteRate` bytes. Zero
// when no window did.
func pathRecoveryAfter(
	meter *pathMeter,
	payloadByteCount int,
	after time.Time,
	targetByteRate float64,
) time.Duration {
	meter.stateLock.Lock()
	defer meter.stateLock.Unlock()

	target := int64(targetByteRate)
	end := 0
	windowFrames := int64(0)
	for start := 0; start < len(meter.deliveries); start += 1 {
		if meter.deliveries[start].Before(after) {
			continue
		}
		windowEnd := meter.deliveries[start].Add(time.Second)
		end = max(end, start)
		for end < len(meter.deliveries) && meter.deliveries[end].Before(windowEnd) {
			windowFrames += int64(meter.deliveryFrames[end])
			end += 1
		}
		if target <= windowFrames*int64(payloadByteCount) {
			return meter.deliveries[start].Sub(after)
		}
		windowFrames -= int64(meter.deliveryFrames[start])
	}
	return 0
}

// The relay's leg to the client: 50 ms each way, and a socket queue rather
// than the relay's drop-on-full forward queue.
const pathRerollLegDelay = 50 * time.Millisecond

// The lossy member's shape, from the rig: a websocket that ran at 3-6 Mb/s
// with 178-408 retransmits and up to 3.2 MB unsent in the relay's socket.
const pathRerollLossyRate = ByteCount(640 * 1000)
const pathRerollLossyQueueMessages = 200

// The healthy member, and the reverse direction of both.
const pathRerollHealthyQueueMessages = 4096

// One client leg, healthy or lossy.
func pathRerollLeg(lossy bool) pathHop {
	forward := pathLink{
		Delay:          pathRerollLegDelay,
		BytesPerSecond: pathGigabit,
		QueueMessages:  pathRerollHealthyQueueMessages,
	}
	if lossy {
		forward.BytesPerSecond = pathRerollLossyRate
		forward.QueueMessages = pathRerollLossyQueueMessages
	}
	return pathHop{
		Name:    "client-leg",
		Forward: forward,
		Reverse: pathLink{
			Delay:          pathRerollLegDelay,
			BytesPerSecond: pathGigabit,
			QueueMessages:  pathRerollHealthyQueueMessages,
		},
	}
}

// The same-datacenter leg: half a millisecond each way, so the whole path is
// under the monitor's MinPathRtt and no connection on it is ever monitored.
func pathRerollShortLeg(lossy bool) pathHop {
	hop := pathRerollLeg(lossy)
	hop.Forward.Delay = 250 * time.Microsecond
	hop.Reverse.Delay = 250 * time.Microsecond
	return hop
}

// The detector settings every arm starts from: the library defaults, the arm's
// mode, and the one sampling change the file header explains.
func pathRerollSettings(mode H1PathRerollMode) H1PathRerollSettings {
	settings := DefaultH1PathRerollSettings()
	settings.Mode = mode
	settings.MinTickPackSamples = 1
	return settings
}

// The kernel out-of-order counter of a lossy member: known, and advancing on
// every tick, which is the rig's picture of a member that drops.
func pathRerollOooEveryTick(_ int, lossy bool) (bool, bool) {
	return true, lossy
}

// A member that drops rarely: the counter advances on one tick in three, which
// is still the RxLossMinTicks of 2 in the last 10.
func pathRerollOooEveryThirdTick(tick int, lossy bool) (bool, bool) {
	return true, lossy && tick%3 == 0
}

// A kernel that reports no out-of-order counter at all: every conviction is
// unconfirmed, as on Windows and on linux before 5.4.
func pathRerollOooUnknown(_ int, _ bool) (bool, bool) {
	return false, false
}

func pathRerollArm(
	name string,
	relayRoundTrip time.Duration,
	leg func(lossy bool) pathHop,
	offer time.Duration,
	scenario *pathRerollScenario,
) pathArm {
	scenario.Leg = leg
	if scenario.Members <= 0 {
		scenario.Members = 8
	}
	if scenario.KernelOoo == nil {
		scenario.KernelOoo = pathRerollOooEveryTick
	}
	if scenario.DialGap <= 0 {
		scenario.DialGap = 400 * time.Millisecond
	}
	lossy := pathConnectionLossy(
		scenario.Hash, pathRerollSeed, scenario.FirstPort, scenario.Members, scenario.LossyMember)
	arm := pathScenarioArm(
		name,
		[]pathHop{
			pathRelayHop("provider-relay", relayRoundTrip, pathGigabit, pathRelayQueueMessages, 0),
			leg(lossy),
		},
		1,
		offer,
		WindowSizingConstant,
		func(sender *ClientSettings, receiver *ClientSettings) {
			sender.SendBufferSettings.ResendQueueMaxByteCount = mib(4)
			receiver.ReceiveBufferSettings.ReceiveQueueMaxByteCount = mib(16)
		},
	)
	arm.Drain = 60 * time.Second
	arm.StallAfter = 30 * time.Second
	arm.Reroll = scenario
	return arm
}

// The seed of every S9 arm. It fixes the hops' loss draws, the source port
// model and the far-random plan's draws, so the ports below are the ports
// every run picks.
const pathRerollSeed = uint64(7)

// The source ports the connections start on.
//
// Under the independent model with this seed, 49154 is on the lossy member and
// 49152 is not. The far-random replacement is the production plan's first pick
// with 49154 excluded: 42171 where the ephemeral range is linux's 32768-60999
// and 60160 where it is 49152-65535, both healthy, so the arm reads the same on
// either kind of host even though the port does not travel.
//
// Under the block64 model 40960 is the first port of a lossy block of 64
// (40960/64 = 640, and 640 mod 8 is 0), which is where the kernel's own re-roll
// stays and the far-random plan does not.
const pathRerollLossyPort = 49154
const pathRerollHealthyPort = 49152
const pathRerollBlockLossyPort = 40960

// S9. A connection on a lossy path member is detected, re-rolled onto a new
// source port, and rescued; a healthy connection and a same-datacenter one pay
// nothing for the monitor.
//
// The fast tier read this when it was written (linux; darwin reads the same
// except for the far-random port, see pathRerollLossyPort):
//
//	arm                                              Mb/s  steady  writes  resend  dup
//	S9/mode=off/leg=healthy                         300.8   303.0   18473       0    0
//	S9/mode=act/leg=healthy                         300.8   303.0   18473       0    0
//	S9/mode=off/leg=lossy                             5.0     4.9     856      14   14
//	S9/mode=observe/leg=lossy                         5.0     4.9     856      14   14
//	S9/mode=act/leg=lossy/hash=independent/port=far  227.0   302.5   27723     204    2
//	S9/mode=off/path=same-dc                        993.2   993.5   15338       0    0
//	S9/mode=act/path=same-dc                        993.2   993.5   15338       0    0
//
// The lossy member holds the connection at 5.0 Mb/s, one sixtieth of the
// healthy 303, and Transfer sees 14 resends in 856 writes: the collapse is
// almost invisible to it, exactly as the rig read it. Observe convicts first at
// 3.50 s and changes not one integer of the run. Act convicts once at 3.50 s,
// re-rolls 49154 -> 42171 (60160 on darwin), loses 203 messages in the break,
// recovers a full second's delivery at the healthy rate 552 ms later, and reads
// 302.5 Mb/s steady, 1.00 of the healthy arm. The 200 gap resends of that arm
// are the break's own cost: the window the retired leg was holding.
//
// R_break, the recovery time the design's commit 10 has to beat with a drain
// handoff, is 552 ms on this path. There is no drain arm to compare it against
// here: the handoff is out of scope until that commit lands.
//
// The full tier (CONNECT_PATHSIM_FULL=1) adds four arms, which read:
//
//	S9/mode=act/leg=lossy/hash=block64/port=kernel     4.4     4.9    2259     686  282
//	S9/mode=act/leg=lossy/hash=block64/port=far      281.6   301.8  128923     204    2
//	S9/mode=act/leg=lossy/ooo=third                  281.6   301.8  128923     204    2
//	S9/mode=act/leg=lossy/ooo=unknown                  4.6     5.1    2352     409  207
//
// The kernel's own re-roll walks 40960 -> 40962 -> 40968, never leaving the bad
// block of 64, so both re-rolls are unimproved, the latch stops the third, and
// the arm stays at 4.9 Mb/s. The far-random port leaves the block on its first
// pick and reads the healthy rate, which is what commit 6 is for. Out-of-order
// data on one tick in three still confirms the conviction. With no kernel
// counter at all every conviction is unconfirmed, and the epoch's unconfirmed
// budget of one allows exactly one re-roll, after which the arm is stuck: the
// budget is the price of acting on evidence the kernel did not give.
func TestPathsimS9LossyConnectionReroll(t *testing.T) {
	// Long enough that the re-roll arm reaches its twenty clean ticks (ten
	// seconds past a switch at about 3.5 s) with room to spare, and short
	// enough that the whole fast tier stays a few wall seconds.
	offer := pathOffer(16*time.Second, 60*time.Second)
	// The healthy control pair only has to read its steady rate and convict
	// nothing, and at 300 Mb/s every virtual second it runs is frames the
	// fast tier pays for, so it runs half as long.
	healthyOffer := pathOffer(8*time.Second, 30*time.Second)
	// A same-datacenter arm only has to show that nothing is monitored.
	shortOffer := pathOffer(2*time.Second, 8*time.Second)

	results := map[string]pathResult{}
	order := []string{}
	run := func(arm pathArm) pathResult {
		result := runPathArm(t, arm)
		results[arm.Name] = result
		order = append(order, arm.Name)
		return result
	}

	const off = "S9/mode=off/leg=lossy"
	const observe = "S9/mode=observe/leg=lossy"
	const act = "S9/mode=act/leg=lossy/hash=independent/port=far"
	const healthyOff = "S9/mode=off/leg=healthy"
	const healthyAct = "S9/mode=act/leg=healthy"
	const shortOff = "S9/mode=off/path=same-dc"
	const shortAct = "S9/mode=act/path=same-dc"

	// the healthy control first: its steady rate is the recovery target of the
	// re-roll arm
	healthyOffResult := run(pathRerollArm(healthyOff, pathShortRoundTrip, pathRerollLeg, healthyOffer,
		&pathRerollScenario{
			Settings:  pathRerollSettings(H1PathRerollModeOff),
			FirstPort: pathRerollHealthyPort,
		}))
	healthyActResult := run(pathRerollArm(healthyAct, pathShortRoundTrip, pathRerollLeg, healthyOffer,
		&pathRerollScenario{
			Settings:   pathRerollSettings(H1PathRerollModeAct),
			FirstPort:  pathRerollHealthyPort,
			PortPolicy: H1SourcePortFarRandom,
		}))
	healthyRate := healthyActResult.steadyGoodput()

	offResult := run(pathRerollArm(off, pathShortRoundTrip, pathRerollLeg, offer,
		&pathRerollScenario{
			Settings:  pathRerollSettings(H1PathRerollModeOff),
			FirstPort: pathRerollLossyPort,
		}))
	observeResult := run(pathRerollArm(observe, pathShortRoundTrip, pathRerollLeg, offer,
		&pathRerollScenario{
			Settings:  pathRerollSettings(H1PathRerollModeObserve),
			FirstPort: pathRerollLossyPort,
		}))
	actResult := run(pathRerollArm(act, pathShortRoundTrip, pathRerollLeg, offer,
		&pathRerollScenario{
			Settings:    pathRerollSettings(H1PathRerollModeAct),
			FirstPort:   pathRerollLossyPort,
			PortPolicy:  H1SourcePortFarRandom,
			HealthyRate: healthyRate,
		}))

	shortOffResult := run(pathRerollArm(shortOff, 500*time.Microsecond, pathRerollShortLeg, shortOffer,
		&pathRerollScenario{
			Settings:  pathRerollSettings(H1PathRerollModeOff),
			FirstPort: pathRerollHealthyPort,
		}))
	shortActResult := run(pathRerollArm(shortAct, 500*time.Microsecond, pathRerollShortLeg, shortOffer,
		&pathRerollScenario{
			Settings:   pathRerollSettings(H1PathRerollModeAct),
			FirstPort:  pathRerollHealthyPort,
			PortPolicy: H1SourcePortFarRandom,
		}))

	// The full tier adds the arms that pin the ledger and the loss rule, and
	// the arm that shows what the far-random source port is for.
	const blockKernel = "S9/mode=act/leg=lossy/hash=block64/port=kernel"
	const blockFar = "S9/mode=act/leg=lossy/hash=block64/port=far"
	const thirdTickOoo = "S9/mode=act/leg=lossy/ooo=third"
	const unknownOoo = "S9/mode=act/leg=lossy/ooo=unknown"
	if pathsimFull() {
		run(pathRerollArm(blockKernel, pathShortRoundTrip, pathRerollLeg, offer,
			&pathRerollScenario{
				Settings:   pathRerollSettings(H1PathRerollModeAct),
				FirstPort:  pathRerollBlockLossyPort,
				PortPolicy: H1SourcePortKernel,
				Hash:       pathHashBlock64,
			}))
		run(pathRerollArm(blockFar, pathShortRoundTrip, pathRerollLeg, offer,
			&pathRerollScenario{
				Settings:    pathRerollSettings(H1PathRerollModeAct),
				FirstPort:   pathRerollBlockLossyPort,
				PortPolicy:  H1SourcePortFarRandom,
				Hash:        pathHashBlock64,
				HealthyRate: healthyRate,
			}))
		run(pathRerollArm(thirdTickOoo, pathShortRoundTrip, pathRerollLeg, offer,
			&pathRerollScenario{
				Settings:    pathRerollSettings(H1PathRerollModeAct),
				FirstPort:   pathRerollLossyPort,
				PortPolicy:  H1SourcePortFarRandom,
				KernelOoo:   pathRerollOooEveryThirdTick,
				HealthyRate: healthyRate,
			}))
		run(pathRerollArm(unknownOoo, pathShortRoundTrip, pathRerollLeg, offer,
			&pathRerollScenario{
				Settings:   pathRerollSettings(H1PathRerollModeAct),
				FirstPort:  pathRerollBlockLossyPort,
				PortPolicy: H1SourcePortKernel,
				Hash:       pathHashBlock64,
				KernelOoo:  pathRerollOooUnknown,
			}))
	}

	ordered := []pathResult{}
	for _, name := range order {
		ordered = append(ordered, results[name])
	}
	reportPathScenario(t, "S9 lossy connection re-roll", ordered)
	for _, name := range order {
		result := results[name]
		if result.reroll == nil {
			continue
		}
		t.Logf(
			"S9: %s ports=%v convictions=%d(first %s) switches=%d(first %s) improved=%d recovery=%s switchdrops=%d",
			name, result.reroll.ports,
			result.reroll.convictions, formatPathDuration(result.reroll.firstConvictionAfter),
			result.reroll.switches, formatPathDuration(result.reroll.firstSwitchAfter),
			result.reroll.improved, formatPathDuration(result.reroll.recoveryAfterSwitch),
			result.reroll.switchDrops,
		)
	}

	// The collapse signature: a few Mb/s with no resends to explain it.
	if pathRerollCollapsedRate < offResult.steadyGoodput() {
		t.Errorf(
			"S9: %s read %.1f Mb/s, not the collapse the lossy member is supposed to be",
			off, offResult.steadyGoodput()*8/1e6,
		)
	}
	// The rig read no resends at all. Here the ack round trip climbing past the
	// resend timeout costs a few: 14 of 1011 writes, 1.4%, all of them timeout
	// resends of packs the far socket had not yet serialised.
	if float64(offResult.writeCount)*pathRerollCollapseResendShare < float64(offResult.resendCount) {
		t.Errorf(
			"S9: %s resent %d of %d writes; the collapse is supposed to be nearly invisible to Transfer",
			off, offResult.resendCount, offResult.writeCount,
		)
	}

	// Observe convicts and does nothing else, and costs the run nothing.
	if observeResult.reroll.convictions < 1 {
		t.Errorf("S9: %s convicted %d times", observe, observeResult.reroll.convictions)
	}
	if first := observeResult.reroll.firstConvictionAfter; first < 2500*time.Millisecond || 4500*time.Millisecond < first {
		t.Errorf(
			"S9: %s convicted first at %s, outside the design's ~3.5 s",
			observe, formatPathDuration(first),
		)
	}
	if observeResult.reroll.switches != 0 {
		t.Errorf("S9: %s switched %d times", observe, observeResult.reroll.switches)
	}
	assertPathRerollEqual(t, "S9", offResult, observeResult, "publishing the observer")

	// Act rescues the connection.
	if actResult.reroll.switches != 1 {
		t.Errorf("S9: %s switched %d times, want exactly one", act, actResult.reroll.switches)
	}
	if first := actResult.reroll.firstSwitchAfter; first < 2500*time.Millisecond || 5*time.Second < first {
		t.Errorf("S9: %s switched first at %s", act, formatPathDuration(first))
	}
	if actResult.reroll.convictions != 1 {
		t.Errorf(
			"S9: %s convicted %d times; the replacement connection is supposed to be healthy",
			act, actResult.reroll.convictions,
		)
	}
	if actResult.reroll.improved != 1 {
		t.Errorf("S9: %s resolved %d re-rolls as improved", act, actResult.reroll.improved)
	}
	if !actResult.drained || actResult.duplicates < 0 {
		t.Errorf(
			"S9: %s did not drain, so its duplicate count is not a reading (%d)",
			act, actResult.duplicates,
		)
	}
	if rescued := pathRatio(actResult, healthyActResult); rescued < 0.6 {
		t.Errorf(
			"S9: %s read %.1f Mb/s steady, %.2f of the healthy %.1f Mb/s; the re-roll did not rescue it",
			act, actResult.steadyGoodput()*8/1e6, rescued, healthyActResult.steadyGoodput()*8/1e6,
		)
	}

	// A healthy connection is never convicted, and Act costs it nothing.
	if 0 < healthyActResult.reroll.convictions || 0 < healthyActResult.reroll.switches {
		t.Errorf(
			"S9: %s convicted %d times and switched %d times on a healthy member",
			healthyAct, healthyActResult.reroll.convictions, healthyActResult.reroll.switches,
		)
	}
	assertPathRerollEqual(t, "S9", healthyOffResult, healthyActResult, "monitoring a healthy connection")

	// A same-datacenter path is dormant: no monitor, no observer, no ticks.
	if shortActResult.reroll.dormant != 1 || shortActResult.reroll.monitored != 0 {
		t.Errorf(
			"S9: %s monitored %d connections and made %d dormant on a %s path",
			shortAct, shortActResult.reroll.monitored, shortActResult.reroll.dormant,
			pathRoundTrip(pathRerollShortHops()),
		)
	}
	if 0 < shortActResult.reroll.convictions {
		t.Errorf("S9: %s convicted %d times", shortAct, shortActResult.reroll.convictions)
	}
	assertPathRerollEqual(t, "S9", shortOffResult, shortActResult, "Act on a same-datacenter path")

	if !pathsimFull() {
		return
	}

	// The kernel's own re-roll of a few ports stays inside the bad block, so
	// the second re-roll is unimproved as well and the latch stops the third.
	blockKernelResult := results[blockKernel]
	if blockKernelResult.reroll.switches != 2 {
		t.Errorf(
			"S9: %s switched %d times, want the two the unimproved latch allows",
			blockKernel, blockKernelResult.reroll.switches,
		)
	}
	if blockKernelResult.reroll.suppressedLatched < 1 {
		t.Errorf("S9: %s never refused a conviction for the latch", blockKernel)
	}
	if latched := pathRatio(blockKernelResult, healthyActResult); 0.2 < latched {
		t.Errorf(
			"S9: %s read %.2f of the healthy rate; it is supposed to stay on the bad block",
			blockKernel, latched,
		)
	}

	// The far-random port leaves the block on the first try.
	blockFarResult := results[blockFar]
	if blockFarResult.reroll.switches != 1 {
		t.Errorf("S9: %s switched %d times, want exactly one", blockFar, blockFarResult.reroll.switches)
	}
	if rescued := pathRatio(blockFarResult, healthyActResult); rescued < 0.6 {
		t.Errorf(
			"S9: %s read %.2f of the healthy rate; the far-random port did not leave the block",
			blockFar, rescued,
		)
	}

	// Out-of-order data on one tick in three is still loss evidence.
	thirdResult := results[thirdTickOoo]
	if thirdResult.reroll.switches != 1 || thirdResult.reroll.confirmedConvictions < 1 {
		t.Errorf(
			"S9: %s switched %d times with %d confirmed convictions",
			thirdTickOoo, thirdResult.reroll.switches, thirdResult.reroll.confirmedConvictions,
		)
	}
	if 0 < thirdResult.reroll.unconfirmedConvictions {
		t.Errorf(
			"S9: %s convicted %d times without loss evidence the kernel reported",
			thirdTickOoo, thirdResult.reroll.unconfirmedConvictions,
		)
	}

	// Without the kernel's counter every conviction is unconfirmed, and the
	// epoch's unconfirmed budget allows exactly one re-roll.
	unknownResult := results[unknownOoo]
	if unknownResult.reroll.switches != 1 {
		t.Errorf(
			"S9: %s switched %d times, want the one the unconfirmed budget allows",
			unknownOoo, unknownResult.reroll.switches,
		)
	}
	if unknownResult.reroll.confirmedConvictions != 0 {
		t.Errorf(
			"S9: %s confirmed %d convictions with no kernel counter to confirm them",
			unknownOoo, unknownResult.reroll.confirmedConvictions,
		)
	}
	if unknownResult.reroll.suppressedUnconfirmedBudget < 1 {
		t.Errorf("S9: %s never refused a conviction for the unconfirmed budget", unknownOoo)
	}
}

// The rate the lossy member is supposed to hold the connection at, in bytes a
// second: the link's own rate with a little headroom.
const pathRerollCollapsedRate = float64(8 * 1e6 / 8)

// What a collapse with no loss under it may cost in resends. Measured 1.4%.
const pathRerollCollapseResendShare = 0.02

// A connection is integer-identical to its control when the monitor changed
// nothing about what the transfer layer did.
func assertPathRerollEqual(t *testing.T, scenario string, control pathResult, monitored pathResult, what string) {
	t.Helper()
	type field struct {
		name    string
		control int64
		other   int64
	}
	for _, f := range []field{
		{"delivered bytes", control.deliveredByteCount, monitored.deliveredByteCount},
		{"frames", control.frameCount, monitored.frameCount},
		{"admitted", control.admitted, monitored.admitted},
		{"forward arrivals", control.forwardArrivals, monitored.forwardArrivals},
		{"writes", int64(control.writeCount), int64(monitored.writeCount)},
		{"resends", int64(control.resendCount), int64(monitored.resendCount)},
	} {
		if f.control != f.other {
			t.Errorf(
				"%s: %s read %d %s against %s's %d: %s changed the run",
				scenario, monitored.arm, f.other, f.name, control.arm, f.control, what,
			)
		}
	}
}

func pathRerollShortHops() []pathHop {
	return []pathHop{
		pathRelayHop("provider-relay", 500*time.Microsecond, pathGigabit, pathRelayQueueMessages, 0),
		pathRerollShortLeg(false),
	}
}

// The link control, on one link, without the rest of the simulator.

// One message per second, so the link is still serialising the head when the
// trim arrives.
const pathTrimTestRate = ByteCount(pathPayloadByteCount)

// Offers `count` messages and returns once the link has taken them all. The
// link takes each buffer as it reads it and is what returns it to the pool,
// whether it delivers it, drops it or is cancelled holding it.
func offerPathTrimMessages(t *testing.T, in Route, count int) {
	t.Helper()
	for range count {
		message := MessagePoolGet(pathPayloadByteCount)
		in <- message
	}
	synctest.Wait()
}

func startPathTrimLink(
	t *testing.T,
	ctx context.Context,
	control *pathLinkControl,
) (Route, Route, *pathLinkStats, chan struct{}) {
	t.Helper()
	in := make(Route, 16)
	out := make(Route, 64)
	stats := &pathLinkStats{}
	frozen := &atomic.Bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPathLink(
			ctx,
			pathLink{BytesPerSecond: pathTrimTestRate, QueueMessages: 64},
			rand.New(rand.NewPCG(1, 2)),
			in,
			out,
			pathPayloadByteCount,
			frozen,
			stats,
			control,
		)
	}()
	return in, out, stats, done
}

func TestPathLinkControlTrimKeepsTheQueueHead(t *testing.T) {
	// the pool's lazy initialiser starts a stats goroutine; born outside the
	// bubble, as runPathArm does
	MessagePoolReturn(MessagePoolGet(64))
	synctest.Test(t, func(t *testing.T) {
		assertMessagePoolOwnership(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		control := newPathLinkControl()
		in, out, _, done := startPathTrimLink(t, ctx, control)
		offerPathTrimMessages(t, in, 10)
		// one message is in the serialiser and nine are queued
		if outstanding := control.outstanding.Load(); outstanding != 10 {
			t.Fatalf("the link holds %d messages, want 10", outstanding)
		}

		// four of the nine queued fit in 64 KiB of head
		if dropped := control.trimNow(ctx, int64(kib(64)), false); dropped != 5 {
			t.Errorf("the trim dropped %d messages, want the 5 past the kept head", dropped)
		}
		if outstanding := control.outstanding.Load(); outstanding != 5 {
			t.Errorf("the link holds %d messages after the trim, want 5", outstanding)
		}

		close(control.stopIngress)
		// the message in the serialiser and the kept head still arrive
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if delivered := control.deliveredMessages.Load(); delivered != 5 {
			t.Errorf("the link delivered %d messages, want the 5 it kept", delivered)
		}
		cancel()
		<-done
		drainPathRoutes(in, out)
	})
}

func TestPathLinkControlTrimDropsTheMessageInFlight(t *testing.T) {
	MessagePoolReturn(MessagePoolGet(64))
	synctest.Test(t, func(t *testing.T) {
		assertMessagePoolOwnership(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		control := newPathLinkControl()
		in, out, _, done := startPathTrimLink(t, ctx, control)
		offerPathTrimMessages(t, in, 10)

		// nine queued and the one in the serialiser
		if dropped := control.trimNow(ctx, 0, true); dropped != 10 {
			t.Errorf("the trim dropped %d messages, want every one the link held", dropped)
		}
		if outstanding := control.outstanding.Load(); outstanding != 0 {
			t.Errorf("the link still holds %d messages", outstanding)
		}
		close(control.stopIngress)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if delivered := control.deliveredMessages.Load(); delivered != 0 {
			t.Errorf("the link delivered %d messages after a trim that dropped every one", delivered)
		}
		cancel()
		<-done
		drainPathRoutes(in, out)
	})
}

// Attaching a control to every link of a carrier — the extra select cases, the
// delivered counters and the outstanding count — must not move a single
// integer of a run. Every scenario but S9 runs without controls, so this is
// what says the two code paths are one.
func TestPathLinkControlDoesNotChangeTheRun(t *testing.T) {
	hops := func() []pathHop {
		return []pathHop{
			pathRelayHop("provider-relay", 500*time.Microsecond, pathGigabit, pathRelayQueueMessages, 0),
			pathRerollShortLeg(false),
		}
	}
	arm := func(name string) pathArm {
		return pathScenarioArm(name, hops(), 1, 500*time.Millisecond, WindowSizingConstant, nil)
	}
	plain := runPathArm(t, arm("control/off"))
	controlledArm := arm("control/on")
	// Mode Off publishes no observer and runs no tick, so the controls are the
	// only difference between the two arms.
	controlledArm.Reroll = &pathRerollScenario{
		Settings:  pathRerollSettings(H1PathRerollModeOff),
		FirstPort: pathRerollHealthyPort,
		Leg:       pathRerollShortLeg,
		Members:   8,
	}
	controlled := runPathArm(t, controlledArm)

	if controlled.reroll == nil || controlled.reroll.monitored != 0 {
		t.Fatalf("the controlled arm monitored a connection, so it is not the control's own cost")
	}
	// the arm name and the re-roll integers are the only parts of the result
	// that are supposed to differ
	controlled.arm = plain.arm
	controlled.reroll = nil
	if plain.digest() != controlled.digest() {
		t.Errorf(
			"a carrier with link controls read %s against %s without them:\n%s\n%s",
			controlled.digest(), plain.digest(), plain.row(), controlled.row(),
		)
	}
}
