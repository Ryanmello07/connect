package connect

import (
	"container/heap"
	"context"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urnetwork/connect/protocol"
)

// A deterministic path simulator for the transfer layer: two real Clients, a
// sender and a receiver, joined by a carrier made of one or more hops, run
// inside a `testing/synctest` bubble so that every delay is virtual, every
// random decision comes from a seeded generator, and a run costs the CPU of
// the frames it carries rather than the seconds it models.
//
// What is real here is the whole of the transfer layer on both ends: the send
// window and its sizing rule, the resend queue and every recovery kind, the
// receive hold and its policy, the acknowledgement compression worker and its
// gap wake, the round-trip estimator, and logical lanes. What is modelled is
// everything below the route channel: each hop direction is a bounded
// message queue in front of a serialiser at an optional byte rate, followed
// by a propagation delay. The queue is the relay's non-blocking forward queue
// (`ForwardTimeout` 0, drop on full) or a socket buffer that blocks its
// writer; the serialiser is the link or the relay's per-message work; the
// delay is the wire. Loss is drawn per message at the serialiser, iid or in
// bursts, and a scripted drop list removes exact offered messages so a cell
// can plant one hole. Hops chain, so a client-relay-relay-provider path is
// three hops with their own queues and losses.
//
// What it does not contain, and what no reading here can be read as having
// measured: a kernel TCP stack on either end, the provider's NAT, websocket
// framing, encryption (off, so the handshake and its CPU are absent), or any
// CPU cost at all. In virtual time a frame costs nothing to build, so the
// simulator's own ceiling is set by the transfer layer's timers alone — the
// acknowledgement compression interval against the window — and every
// scenario must read well below it (`pathsimCeiling`, the instrument rule of
// transfer_throughput_chain_test.go carried over). Rates in scenarios are
// therefore bounded by the link rates the scenario sets, never by the host,
// and ratios between arms are the result.
//
// Determinism. Time only advances when every goroutine in the bubble is
// durably blocked, so the order of events at distinct virtual instants is
// fixed. Two independent events at the same instant would still race on the
// real scheduler, so every delivery carries a sub-microsecond seeded jitter
// that takes the timeline off any lattice the fixed delays and the 10 ms
// compression timer would put it on. Each scenario prints a digest of its
// integer results; three runs must print the same digests.
//
// Tiers. The fast tier runs by default and keeps every arm to a few virtual
// seconds. `CONNECT_PATHSIM_FULL=1` runs the long offers and the whole grids.

const pathsimFullEnv = "CONNECT_PATHSIM_FULL"

func pathsimFull() bool {
	return os.Getenv(pathsimFullEnv) != ""
}

// One direction of one hop.
type pathLink struct {
	// one-way propagation
	Delay time.Duration
	// serialisation rate; zero is unpaced
	BytesPerSecond ByteCount
	// forward queue depth in messages; zero is unbounded
	QueueMessages int
	// what a full queue does: drop the arrival (the relay's forward queue) or
	// stop reading so the writer blocks (a socket buffer)
	DropOnFull bool
	// iid loss per message, drawn at the serialiser
	Loss float64
	// probability per message that a burst of BurstLength consecutive drops
	// starts
	BurstLoss   float64
	BurstLength int
	// extra random delay per message, up to this; with Reorder false the
	// delivery order is kept and the jitter only spreads arrivals
	Jitter  time.Duration
	Reorder bool
	// offered-message ordinals (1-based, counted at the ingress) dropped once
	// each, before the queue
	DropOffered []int64
	// observes every message at the ingress, for a cell that needs the wire
	// order; called on the link goroutine
	Trace func(ordinal int64, message []byte, at time.Time)
}

type pathHop struct {
	Name    string
	Forward pathLink
	Reverse pathLink
}

// A live handle on one hop direction, for a scenario that retires a link while
// the run continues (the H1 re-roll of S9). A link built without one takes the
// identical code path, so every other scenario is unaffected.
type pathLinkControl struct {
	// closed to stop the link reading its ingress, as a closed socket stops
	// reading the wire
	stopIngress chan struct{}
	// the trim requests the link serves, one at a time
	trim chan pathTrimRequest
	// bytes and messages the link handed to its egress, counted whether or not
	// the run is frozen: this is a socket counter, not a measurement
	deliveredBytes    atomic.Int64
	deliveredMessages atomic.Int64
	// queued plus serialising plus in flight, as of the link's last state change
	outstanding atomic.Int64
}

// Drops everything the link holds past keepByteCount of queue head, and with
// dropInFlight the message in the serialiser and everything propagating too.
// The link replies with the number of messages it dropped.
type pathTrimRequest struct {
	keepByteCount int64
	dropInFlight  bool
	dropped       chan int64
}

func newPathLinkControl() *pathLinkControl {
	return &pathLinkControl{
		stopIngress: make(chan struct{}),
		trim:        make(chan pathTrimRequest),
	}
}

// Asks the link to trim and returns what it dropped. The link owns every
// buffer it drops and returns them to the pool itself. Call it while the link
// is still able to reach its select: a link blocked writing to a route nobody
// reads answers only when its context is cancelled.
func (self *pathLinkControl) trimNow(ctx context.Context, keepByteCount int64, dropInFlight bool) int64 {
	request := pathTrimRequest{
		keepByteCount: keepByteCount,
		dropInFlight:  dropInFlight,
		dropped:       make(chan int64, 1),
	}
	select {
	case self.trim <- request:
	case <-ctx.Done():
		return 0
	}
	select {
	case dropped := <-request.dropped:
		return dropped
	case <-ctx.Done():
		return 0
	}
}

// Written only by the link goroutine and read after it has been joined.
type pathLinkStats struct {
	offered       int64
	queueDrops    int64
	lossDrops     int64
	scriptedDrops int64
	delivered     int64
	// delivered messages at least the payload long: the data packs, as
	// against acks, probes and the client key publication
	dataDelivered int64
	maxQueue      int
}

func (self pathLinkStats) drops() int64 {
	return self.queueDrops + self.lossDrops + self.scriptedDrops
}

type pathInFlight struct {
	deliverAt time.Time
	seq       int64
	message   []byte
}

type pathInFlightHeap []pathInFlight

func (self pathInFlightHeap) Len() int { return len(self) }
func (self pathInFlightHeap) Less(i int, j int) bool {
	if !self[i].deliverAt.Equal(self[j].deliverAt) {
		return self[i].deliverAt.Before(self[j].deliverAt)
	}
	return self[i].seq < self[j].seq
}
func (self pathInFlightHeap) Swap(i int, j int) { self[i], self[j] = self[j], self[i] }
func (self *pathInFlightHeap) Push(x any)       { *self = append(*self, x.(pathInFlight)) }
func (self *pathInFlightHeap) Pop() any {
	old := *self
	item := old[len(old)-1]
	*self = old[:len(old)-1]
	return item
}

// The tie-break every delivery carries, so that no two independent events
// share a virtual instant by construction of the delays. Deliveries on one
// in-order link are also kept strictly increasing, so a link never hands
// two messages to a client in the same instant.
const pathTieBreakJitter = time.Microsecond

// The virtual time the clients are given before the offer starts.
const pathSettle = 5 * time.Millisecond

// The offset between consecutive lanes' first packs.
const pathLaneStagger = 100 * time.Microsecond

// The virtual time a source waits after a release before it pushes.
const pathSourceSettle = time.Microsecond

// One hop direction. Reads `in`, applies the queue policy, serialises,
// applies loss, delays, and writes `out` in delivery order. Every pooled
// buffer it holds when cancelled is returned.
func runPathLink(
	ctx context.Context,
	link pathLink,
	random *rand.Rand,
	in Route,
	out Route,
	dataByteCount int,
	frozen *atomic.Bool,
	stats *pathLinkStats,
	control *pathLinkControl,
) {
	queue := [][]byte{}
	inFlight := &pathInFlightHeap{}
	serviceTimer := time.NewTimer(time.Hour)
	serviceTimer.Stop()
	deliverTimer := time.NewTimer(time.Hour)
	deliverTimer.Stop()
	defer serviceTimer.Stop()
	defer deliverTimer.Stop()

	serving := false
	var servingMessage []byte
	var serviceDoneAt time.Time
	var lastDeliverAt time.Time
	seq := int64(0)
	burstRemaining := 0
	scriptedDrops := map[int64]bool{}
	for _, ordinal := range link.DropOffered {
		scriptedDrops[ordinal] = true
	}
	// nil channels without a control, so the select is the same select
	var stopIngress chan struct{}
	var trims chan pathTrimRequest
	if control != nil {
		stopIngress = control.stopIngress
		trims = control.trim
	}
	ingressStopped := false

	noteOutstanding := func() {
		if control == nil {
			return
		}
		outstanding := int64(len(queue)) + int64(inFlight.Len())
		if serving {
			outstanding += 1
		}
		control.outstanding.Store(outstanding)
	}

	returnHeld := func() {
		for _, message := range queue {
			MessagePoolReturn(message)
		}
		queue = nil
		if serving {
			MessagePoolReturn(servingMessage)
			serving = false
		}
		for _, item := range *inFlight {
			MessagePoolReturn(item.message)
		}
		*inFlight = (*inFlight)[:0]
	}

	armDelivery := func(now time.Time) {
		if inFlight.Len() == 0 {
			return
		}
		deliverTimer.Reset(max(0, (*inFlight)[0].deliverAt.Sub(now)))
	}

	// the serialiser has finished one message: loss, then propagation
	completeService := func(now time.Time) {
		message := servingMessage
		serving = false
		servingMessage = nil

		dropped := false
		if 0 < burstRemaining {
			burstRemaining--
			dropped = true
		} else {
			if 0 < link.Loss && random.Float64() < link.Loss {
				dropped = true
			}
			if !dropped && 0 < link.BurstLoss && random.Float64() < link.BurstLoss {
				dropped = true
				burstRemaining = max(0, link.BurstLength-1)
			}
		}
		if dropped {
			if !frozen.Load() {
				stats.lossDrops++
			}
			MessagePoolReturn(message)
			return
		}

		deliverAt := now.Add(link.Delay)
		if 0 < link.Jitter {
			deliverAt = deliverAt.Add(time.Duration(random.Int64N(int64(link.Jitter))))
		}
		deliverAt = deliverAt.Add(time.Duration(random.Int64N(int64(pathTieBreakJitter))))
		// In order, and never at the same instant as the message before:
		// two acks delivered together are coalesced into one snapshot that
		// the sender applies in map order, which is the one place the
		// transfer layer's own order is not a function of the wire's.
		if !link.Reorder && !deliverAt.After(lastDeliverAt) {
			deliverAt = lastDeliverAt.Add(time.Nanosecond)
		}
		lastDeliverAt = deliverAt
		seq++
		heap.Push(inFlight, pathInFlight{deliverAt: deliverAt, seq: seq, message: message})
		if (*inFlight)[0].seq == seq {
			armDelivery(now)
		}
	}

	// take the head of the queue into the serialiser; unpaced links complete
	// at once and keep going until the queue is empty
	startService := func(now time.Time) {
		for !serving && 0 < len(queue) {
			servingMessage = queue[0]
			queue[0] = nil
			queue = queue[1:]
			serving = true
			if link.BytesPerSecond <= 0 {
				completeService(now)
				continue
			}
			serviceTime := time.Duration(
				int64(len(servingMessage)) * int64(time.Second) / int64(link.BytesPerSecond),
			)
			serviceDoneAt = now.Add(serviceTime)
			serviceTimer.Reset(serviceTime)
		}
	}

	deliverDue := func(now time.Time) bool {
		for 0 < inFlight.Len() && !(*inFlight)[0].deliverAt.After(now) {
			item := heap.Pop(inFlight).(pathInFlight)
			select {
			case out <- item.message:
				if control != nil {
					control.deliveredBytes.Add(int64(len(item.message)))
					control.deliveredMessages.Add(1)
				}
				if !frozen.Load() {
					stats.delivered++
					if dataByteCount <= len(item.message) {
						stats.dataDelivered++
					}
				}
			case <-ctx.Done():
				MessagePoolReturn(item.message)
				return false
			}
		}
		armDelivery(now)
		return true
	}

	// keeps the queue head up to keepByteCount and drops the rest; the
	// serialiser and everything propagating go too when the caller asks
	trim := func(request pathTrimRequest) int64 {
		dropped := int64(0)
		keptByteCount := int64(0)
		kept := 0
		full := false
		for _, message := range queue {
			if !full && keptByteCount+int64(len(message)) <= request.keepByteCount {
				keptByteCount += int64(len(message))
				queue[kept] = message
				kept++
				continue
			}
			full = true
			MessagePoolReturn(message)
			dropped++
		}
		for i := kept; i < len(queue); i++ {
			queue[i] = nil
		}
		queue = queue[:kept]
		if request.dropInFlight {
			if serving {
				serviceTimer.Stop()
				MessagePoolReturn(servingMessage)
				servingMessage = nil
				serving = false
				dropped++
			}
			for _, item := range *inFlight {
				MessagePoolReturn(item.message)
				dropped++
			}
			*inFlight = (*inFlight)[:0]
			deliverTimer.Stop()
		}
		// the kept head still has to be served
		startService(time.Now())
		return dropped
	}

	for {
		inCase := in
		if ingressStopped {
			// the socket is closed: nothing more arrives
			inCase = nil
		} else if 0 < link.QueueMessages && !link.DropOnFull && link.QueueMessages <= len(queue) {
			// block the writer by not reading
			inCase = nil
		}
		select {
		case message := <-inCase:
			counting := !frozen.Load()
			if counting {
				stats.offered++
			}
			if link.Trace != nil {
				link.Trace(stats.offered, message, time.Now())
			}
			switch {
			case counting && scriptedDrops[stats.offered]:
				stats.scriptedDrops++
				MessagePoolReturn(message)
			case 0 < link.QueueMessages && link.DropOnFull && link.QueueMessages <= len(queue):
				if counting {
					stats.queueDrops++
				}
				MessagePoolReturn(message)
			default:
				queue = append(queue, message)
				if counting {
					stats.maxQueue = max(stats.maxQueue, len(queue))
				}
				startService(time.Now())
			}
			noteOutstanding()
		case <-serviceTimer.C:
			completeService(serviceDoneAt)
			startService(serviceDoneAt)
			noteOutstanding()
		case <-deliverTimer.C:
			if !deliverDue(time.Now()) {
				returnHeld()
				return
			}
			noteOutstanding()
		case <-stopIngress:
			ingressStopped = true
			// a closed channel stays ready; take the case once
			stopIngress = nil
		case request := <-trims:
			dropped := trim(request)
			noteOutstanding()
			select {
			case request.dropped <- dropped:
			default:
			}
		case <-ctx.Done():
			returnHeld()
			return
		}
	}
}

type pathHopStats struct {
	name    string
	forward pathLinkStats
	reverse pathLinkStats
	// the hop whose forward deliveries reach the receiver: the last hop, and
	// every replacement leg a re-roll scenario starts in its place
	terminal bool
}

// A running hop: its statistics, a control per direction, and a cancel per
// direction. A scenario that retires a leg cancels its two directions; the
// carrier joins them in drain().
type pathHopRuntime struct {
	stats          *pathHopStats
	forwardControl *pathLinkControl
	reverseControl *pathLinkControl
	forwardCancel  context.CancelFunc
	reverseCancel  context.CancelFunc
}

// The hops joined into a carrier between the sender's and the receiver's
// gateway routes. Forward runs sender to receiver through the hops in order;
// reverse runs receiver to sender through them in reverse order.
type pathCarrier struct {
	senderOut   Route
	senderIn    Route
	receiverIn  Route
	receiverOut Route
	channels    []Route
	stats       []*pathHopStats
	// one per hop in start order, including the legs a re-roll scenario starts
	hops []*pathHopRuntime
	// the routes a re-roll scenario created, drained with the carrier's own
	extraRoutes []Route
	// Set when the measurement ends, before the clients close: what the
	// clients write while closing is carried but not counted, since the
	// close races the carrier's cancellation and the count would move.
	frozen atomic.Bool
	done   sync.WaitGroup
}

// `controlled` gives every hop direction a `pathLinkControl`. Without it the
// links run with a nil control, which is the code path every scenario but S9
// takes: the same select over the same channels, so the same digests.
func startPathCarrier(
	ctx context.Context,
	hops []pathHop,
	seed uint64,
	routeCapacity int,
	dataByteCount int,
	controlled bool,
) *pathCarrier {
	carrier := &pathCarrier{
		senderOut:   make(Route, routeCapacity),
		senderIn:    make(Route, routeCapacity),
		receiverIn:  make(Route, routeCapacity),
		receiverOut: make(Route, routeCapacity),
	}
	forwardIn := carrier.senderOut
	reverseOut := carrier.senderIn
	for i, hop := range hops {
		forwardOut := carrier.receiverIn
		reverseIn := carrier.receiverOut
		if i+1 < len(hops) {
			forwardOut = make(Route, routeCapacity)
			reverseIn = make(Route, routeCapacity)
			carrier.channels = append(carrier.channels, forwardOut, reverseIn)
		}
		carrier.startHop(
			ctx, hop, seed, 2*i,
			forwardIn, forwardOut, reverseIn, reverseOut,
			dataByteCount, i+1 == len(hops), controlled,
		)
		forwardIn = forwardOut
		reverseOut = reverseIn
	}
	return carrier
}

// Starts one hop's two directions, each under its own cancellable context and
// with its own control. `randomOrdinal` picks the two loss streams, so a leg
// started later in a run draws from streams no other hop uses.
func (self *pathCarrier) startHop(
	ctx context.Context,
	hop pathHop,
	seed uint64,
	randomOrdinal int,
	forwardIn Route,
	forwardOut Route,
	reverseIn Route,
	reverseOut Route,
	dataByteCount int,
	terminal bool,
	controlled bool,
) *pathHopRuntime {
	stats := &pathHopStats{name: hop.Name, terminal: terminal}
	self.stats = append(self.stats, stats)
	forwardCtx, forwardCancel := context.WithCancel(ctx)
	reverseCtx, reverseCancel := context.WithCancel(ctx)
	runtime := &pathHopRuntime{
		stats:         stats,
		forwardCancel: forwardCancel,
		reverseCancel: reverseCancel,
	}
	if controlled {
		runtime.forwardControl = newPathLinkControl()
		runtime.reverseControl = newPathLinkControl()
	}
	self.hops = append(self.hops, runtime)
	forwardRandom := rand.New(rand.NewPCG(seed, uint64(randomOrdinal)))
	reverseRandom := rand.New(rand.NewPCG(seed, uint64(randomOrdinal+1)))
	self.done.Add(2)
	go func() {
		defer self.done.Done()
		runPathLink(
			forwardCtx, hop.Forward, forwardRandom, forwardIn, forwardOut,
			dataByteCount, &self.frozen, &stats.forward, runtime.forwardControl,
		)
	}()
	go func() {
		defer self.done.Done()
		runPathLink(
			reverseCtx, hop.Reverse, reverseRandom, reverseIn, reverseOut,
			dataByteCount, &self.frozen, &stats.reverse, runtime.reverseControl,
		)
	}()
	return runtime
}

// Returns every message a route still holds to the pool, and how many there
// were. Call it once the links on both ends of the route have stopped.
func drainPathRoutes(routes ...Route) int64 {
	drained := int64(0)
	for _, route := range routes {
		draining := true
		for draining {
			select {
			case message := <-route:
				MessagePoolReturn(message)
				drained++
			default:
				draining = false
			}
		}
	}
	return drained
}

// Joins the hops and returns every buffer left on a route. Call after the
// context is cancelled and the clients are closed.
func (self *pathCarrier) drain() {
	self.done.Wait()
	routes := []Route{self.senderOut, self.senderIn, self.receiverIn, self.receiverOut}
	routes = append(routes, self.channels...)
	routes = append(routes, self.extraRoutes...)
	drainPathRoutes(routes...)
}

// The delivery meter at the receiver's callback. Gaps are measured between
// consecutive deliveries and from the start to the first one.
type pathMeter struct {
	stateLock    sync.Mutex
	byteCount    int64
	frameCount   int64
	started      time.Time
	lastAt       time.Time
	maxGap       time.Duration
	holBlocked   time.Duration
	holThreshold time.Duration
	// the first delivery instants, capped
	deliveries []time.Time
	// the frames of each recorded delivery, for a scenario that measures the
	// rate over a window of the trace rather than over the whole offer
	deliveryFrames []int32
}

const pathMeterTraceCap = 1 << 16

func (self *pathMeter) deliver(frames []*protocol.Frame, payloadByteCount int) {
	now := time.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.deliveries) < pathMeterTraceCap {
		self.deliveries = append(self.deliveries, now)
		self.deliveryFrames = append(self.deliveryFrames, int32(len(frames)))
	}
	gap := now.Sub(self.lastAt)
	if self.maxGap < gap {
		self.maxGap = gap
	}
	if self.holThreshold < gap {
		self.holBlocked += gap
	}
	self.lastAt = now
	self.byteCount += int64(len(frames)) * int64(payloadByteCount)
	self.frameCount += int64(len(frames))
}

func (self *pathMeter) snapshot() (int64, int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.byteCount, self.frameCount
}

// Closes the trailing gap at `now` so a run that stalled at its end reads as
// stalled.
func (self *pathMeter) finish(now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	gap := now.Sub(self.lastAt)
	if self.maxGap < gap {
		self.maxGap = gap
	}
	if self.holThreshold < gap {
		self.holBlocked += gap
	}
	self.lastAt = now
}

// One arm of a scenario: the path, the offered load, and the two clients'
// configuration.
type pathArm struct {
	Name string
	Hops []pathHop
	// flows, as explicit logical lanes 1..Lanes on one client pair
	Lanes            int
	PayloadByteCount int
	Offer            time.Duration
	// how long after the offer to wait for everything admitted to be
	// delivered exactly once, which is what makes the duplicate count exact
	Drain time.Duration
	// a gap between deliveries longer than this is a stall
	StallAfter time.Duration
	// a gap longer than this counts as head-of-line blocked time; zero
	// derives twice the round trip plus two compression intervals
	HolAfter time.Duration
	Seed     uint64
	// the gateway route depth on each side of a hop; zero is 16
	RouteCapacity int
	// process-wide policy the clients are built under
	WindowSizing WindowSizingPolicyKind
	MemoryBudget ByteCount
	Configure    func(sender *ClientSettings, receiver *ClientSettings)
	// when set, the last hop is one H1 connection of S9: the production path
	// monitor watches it and may re-roll it onto a new leg mid-run
	Reroll *pathRerollScenario
}

func pathRoundTrip(hops []pathHop) time.Duration {
	rtt := time.Duration(0)
	for _, hop := range hops {
		rtt += hop.Forward.Delay + hop.Reverse.Delay
	}
	return rtt
}

// Everything one arm produced, in virtual time.
type pathResult struct {
	arm                string
	offer              time.Duration
	deliveredByteCount int64
	steadyByteCount    int64
	frameCount         int64
	admitted           int64
	forwardArrivals    int64
	// forward arrivals less admitted, exact once drained; -1 when not
	duplicates       int64
	writeCount       uint64
	resendCount      uint64
	timeoutResends   uint64
	gapResends       uint64
	tailProbes       uint64
	cumulativeProbes uint64
	deferredResends  uint64
	evictionResends  uint64
	// packs and acks the receive pump could not hand to a sequence, which on
	// a reliable lane must be zero: a nonzero count is an instrument fault
	handoffDrops uint64
	// packs the sender discarded past the caller's budget; the offer sets no
	// budget, so a nonzero count is an instrument fault as well
	deadlineDrops uint64
	// the first delivery instants, for locating where two runs diverge
	deliveries                 []time.Time
	receiverDrops              uint64
	receiverEvictions          uint64
	receiverTentativeEvictions uint64
	hops                       []pathHopStats
	maxGap                     time.Duration
	holBlocked                 time.Duration
	stalled                    bool
	drained                    bool
	drainTime                  time.Duration
	window                     SendWindowEstimate
	sequenceCount              int
	// nil unless the arm carried a re-roll scenario
	reroll *pathRerollResult
}

// bytes per second over the whole offer
func (self pathResult) goodput() float64 {
	return float64(self.deliveredByteCount) / self.offer.Seconds()
}

// bytes per second over the second half of the offer, past any ramp
func (self pathResult) steadyGoodput() float64 {
	return float64(self.steadyByteCount) / (self.offer / 2).Seconds()
}

func (self pathResult) forwardDrops() int64 {
	drops := int64(0)
	for _, hop := range self.hops {
		drops += hop.forward.drops()
	}
	return drops
}

func (self pathResult) reverseDrops() int64 {
	drops := int64(0)
	for _, hop := range self.hops {
		drops += hop.reverse.drops()
	}
	return drops
}

// The integer facts of a run, hashed. Equal digests across runs is the
// determinism claim.
func (self pathResult) digest() string {
	hash := fnv.New64a()
	fmt.Fprintf(hash, "%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%v|%d|%d",
		self.deliveredByteCount, self.steadyByteCount, self.frameCount, self.admitted,
		self.forwardArrivals, self.writeCount, self.resendCount, self.timeoutResends,
		self.gapResends, self.tailProbes, self.cumulativeProbes, self.deferredResends,
		self.evictionResends, self.receiverDrops, self.receiverEvictions,
		self.maxGap, self.holBlocked, self.drained, self.drainTime, self.window.Window,
	)
	fmt.Fprintf(hash, "|%d|%d", self.handoffDrops, self.deadlineDrops)
	if self.reroll != nil {
		// only a re-roll arm hashes these, so every other scenario's digest
		// is the digest it printed before S9 existed
		fmt.Fprintf(hash, "|%d|%d|%d|%d|%d|%d|%d|%d|%v|%v|%v|%v",
			self.reroll.convictions, self.reroll.switches, self.reroll.improved,
			self.reroll.suppressedLatched, self.reroll.suppressedUnconfirmedBudget,
			self.reroll.monitored, self.reroll.dormant,
			self.reroll.switchDrops, self.reroll.ports,
			self.reroll.firstConvictionAfter, self.reroll.firstSwitchAfter,
			self.reroll.recoveryAfterSwitch,
		)
	}
	for _, hop := range self.hops {
		fmt.Fprintf(hash, "|%d|%d|%d|%d|%d|%d",
			hop.forward.offered, hop.forward.drops(), hop.forward.delivered,
			hop.reverse.offered, hop.reverse.drops(), hop.reverse.delivered,
		)
	}
	return fmt.Sprintf("%016x", hash.Sum64())
}

const pathTableHeader = "%-34s %9s %9s %7s %7s %6s %6s %6s %6s %5s %8s %8s %8s %6s %s"

func pathTableHeaderRow() string {
	return fmt.Sprintf(pathTableHeader,
		"arm", "Mb/s", "steady", "writes", "resend", "rto", "gap", "probe", "dup",
		"drops", "maxgap", "hol", "drain", "win", "flags")
}

func (self pathResult) row() string {
	flags := []string{}
	if self.stalled {
		flags = append(flags, "STALLED")
	}
	if !self.drained {
		flags = append(flags, "UNDRAINED")
	}
	if self.window.Sized {
		flags = append(flags, "sized")
	}
	if 0 < self.receiverEvictions {
		flags = append(flags, fmt.Sprintf("evict=%d", self.receiverEvictions))
	}
	if 0 < self.evictionResends {
		flags = append(flags, fmt.Sprintf("evresend=%d", self.evictionResends))
	}
	if 0 < self.receiverTentativeEvictions {
		flags = append(flags, fmt.Sprintf("tentative=%d", self.receiverTentativeEvictions))
	}
	if 0 < self.receiverDrops {
		flags = append(flags, fmt.Sprintf("rdrop=%d", self.receiverDrops))
	}
	if 0 < self.handoffDrops {
		flags = append(flags, fmt.Sprintf("HANDOFF=%d", self.handoffDrops))
	}
	if 0 < self.deadlineDrops {
		flags = append(flags, fmt.Sprintf("DEADLINE=%d", self.deadlineDrops))
	}
	if 0 < self.reverseDrops() {
		flags = append(flags, fmt.Sprintf("ackdrop=%d", self.reverseDrops()))
	}
	if self.reroll != nil {
		flags = append(flags, self.reroll.flag())
	}
	duplicates := "-"
	if 0 <= self.duplicates {
		duplicates = fmt.Sprintf("%d", self.duplicates)
	}
	return fmt.Sprintf(pathTableHeader,
		self.arm,
		fmt.Sprintf("%.1f", self.goodput()*8/1e6),
		fmt.Sprintf("%.1f", self.steadyGoodput()*8/1e6),
		fmt.Sprintf("%d", self.writeCount),
		fmt.Sprintf("%d", self.resendCount),
		fmt.Sprintf("%d", self.timeoutResends),
		fmt.Sprintf("%d", self.gapResends),
		fmt.Sprintf("%d", self.tailProbes+self.cumulativeProbes),
		duplicates,
		fmt.Sprintf("%d", self.forwardDrops()),
		formatPathDuration(self.maxGap),
		formatPathDuration(self.holBlocked),
		formatPathDuration(self.drainTime),
		formatPathWindow(self.window.Window),
		strings.Join(flags, " "),
	)
}

func formatPathDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "0"
	case d < time.Millisecond:
		return fmt.Sprintf("%dus", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

func formatPathWindow(byteCount ByteCount) string {
	if byteCount <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fM", float64(byteCount)/float64(mib(1)))
}

// The offered load: a source per lane that keeps exactly what the sender
// admits outstanding, and never more.
//
// A source that blocks on admission — the natural shape, and the one the
// transfer harness uses — races the sequence goroutine at every
// acknowledgement: the sequence clears its capacity flag and drains its
// pre-write queue while the caller's `awaitResendCapacity` fast path reads
// that flag, and which of them runs first decides how many packs leave in
// that instant and how many wait for the caller's 2 ms capacity poll
// (`resendCapacityPollInterval`). That count differs from run to run on the
// real scheduler, and it is the one source of nondeterminism this simulator
// found in the transfer layer. So the source does the sender's admission
// arithmetic itself, from the two facts the sequence goroutine reports on
// its own goroutine — what it released (the per-item ack seam) and its live
// window estimate — and the sequence never finds its window full.
//
// The arithmetic is the resend queue's (`transferQueue.CanAdd`): an item is
// charged its encoded frame length against both the lane's window and, above
// the lane's floor, the shared pool. Under the constant policy the pool for
// lanes 1..8 is one `ResendQueueMaxByteCount`, which is why eight flows carry
// the same total window as one; under the sizing rule it is the process
// share. Each lane here is given an equal floor of the constant window, so
// the constant arms are equal static shares and the rule's arms borrow from
// the pool in event order. The item size is a conservative constant, so a
// lane runs one item under the exact window.
type pathSourceSet struct {
	stateLock sync.Mutex
	itemBytes ByteCount
	// items the pool lends above the floors, over all lanes, less one
	poolItems int64
	// items above their lane's floor, over all lanes
	borrowed int64
	lanes    map[uint32]*pathSource
}

type pathSource struct {
	lane       uint32
	floorItems int64
	pushed     int64
	released   int64
	wake       chan struct{}
}

// On the sequence goroutine, once per item the sender released.
func (self *pathSourceSet) release(lane uint32) {
	self.stateLock.Lock()
	source := self.lanes[lane]
	if source != nil {
		source.released++
		if source.floorItems <= source.pushed-source.released {
			self.borrowed--
		}
	}
	self.stateLock.Unlock()
	if source != nil {
		select {
		case source.wake <- struct{}{}:
		default:
		}
	}
}

// Whether one more item fits the lane's window and the pool; counts it if so.
func (self *pathSourceSet) admit(source *pathSource, window ByteCount) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	windowItems := int64((window - 1) / self.itemBytes)
	outstanding := source.pushed - source.released
	if windowItems <= outstanding {
		return false
	}
	if source.floorItems <= outstanding {
		if self.poolItems <= self.borrowed {
			return false
		}
		self.borrowed++
	}
	source.pushed++
	return true
}

// Runs one arm in its own bubble and returns what it produced. The
// process-wide window policy and memory budget are set for the arm and
// restored after it; the clients are built from `DefaultClientSettings` under
// them, exactly as a deployment builds its own, with encryption off.
func runPathArm(t *testing.T, arm pathArm) pathResult {
	t.Helper()

	// the pool's lazy initialiser starts a stats goroutine; touched here so
	// it is born outside the bubble
	MessagePoolReturn(MessagePoolGet(64))

	// One P for the arm. Virtual time fixes the order of events at distinct
	// instants, and the link never hands two messages over in one instant,
	// but a goroutine readied by another in the same instant still runs
	// concurrently with it on more than one P. The receiver has one such
	// pair: its ack worker, woken by the gap wake while the sequence
	// goroutine is still advancing the head through a run of held items,
	// snapshots either an intermediate head or the final one and writes an
	// extra head ack accordingly. On one P a readied goroutine runs when the
	// one that readied it blocks, which is after the instant's work is done.
	restoreProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(restoreProcs)

	restoreBudget := MemoryBudget()
	restoreSizing := DefaultWindowSizing()
	defer func() {
		SetMemoryBudget(restoreBudget)
		SetWindowSizing(restoreSizing)
	}()
	SetMemoryBudget(arm.MemoryBudget)
	SetWindowSizing(arm.WindowSizing)

	if arm.Lanes <= 0 {
		arm.Lanes = 1
	}
	if arm.RouteCapacity <= 0 {
		arm.RouteCapacity = 16
	}
	if arm.StallAfter <= 0 {
		arm.StallAfter = 2 * time.Second
	}
	if arm.HolAfter <= 0 {
		arm.HolAfter = 2*pathRoundTrip(arm.Hops) + 20*time.Millisecond
	}
	if arm.Drain <= 0 {
		arm.Drain = 10 * time.Second
	}

	result := pathResult{arm: arm.Name, offer: arm.Offer, duplicates: -1}
	synctest.Test(t, func(t *testing.T) {
		assertMessagePoolOwnership(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		carrier := startPathCarrier(
			ctx, arm.Hops, arm.Seed, arm.RouteCapacity, arm.PayloadByteCount, arm.Reroll != nil)

		newSettings := func() *ClientSettings {
			settings := DefaultClientSettings()
			settings.EncryptionSettings.Mode = EncryptionModeOff
			return settings
		}
		senderSettings := newSettings()
		receiverSettings := newSettings()
		if arm.Configure != nil {
			arm.Configure(senderSettings, receiverSettings)
		}

		// One flow runs on lane zero, the shape every transfer fixture
		// measures; several run on lanes 1..N with equal floors of the
		// constant window (see pathSourceSet).
		lanes := []uint32{0}
		if 1 < arm.Lanes {
			lanes = lanes[:0]
			for lane := 1; lane <= arm.Lanes; lane++ {
				lanes = append(lanes, uint32(lane))
			}
			senderSettings.SendBufferSettings.LaneFloorByteCount =
				senderSettings.SendBufferSettings.ResendQueueMaxByteCount / ByteCount(arm.Lanes)
		}
		payload := string(make([]byte, arm.PayloadByteCount))
		sample := RequireToFrameWithDefaultProtocolVersion(&protocol.SimpleMessage{Content: payload})
		// the encoded frame is the message plus a pack header of tens of
		// bytes; the allowance keeps the arithmetic conservative
		itemBytes := MessageByteCount([]*protocol.Frame{sample}) + 128
		MessagePoolReturn(sample.MessageBytes)
		sources := &pathSourceSet{itemBytes: itemBytes, lanes: map[uint32]*pathSource{}}
		floorTotal := ByteCount(0)
		for _, lane := range lanes {
			floor := senderSettings.SendBufferSettings.ResendQueueMinByteCount
			if lane != 0 {
				floor = senderSettings.SendBufferSettings.LaneFloorByteCount
			}
			floorTotal += floor
			sources.lanes[lane] = &pathSource{
				lane:       lane,
				floorItems: int64(floor / itemBytes),
				wake:       make(chan struct{}, 1),
			}
		}
		// The pool: the process share under the rule; one constant window
		// for lanes under the constant policy; and none for lane zero under
		// the constant policy, whose queue then has only its window.
		poolTotal := ByteCount(0)
		hasPool := false
		if budget := senderSettings.SendBufferSettings.ResendQueueBudget; budget != nil {
			poolTotal, hasPool = budget.TotalByteCount(), true
		} else if lanes[0] != 0 {
			poolTotal, hasPool = senderSettings.SendBufferSettings.ResendQueueMaxByteCount, true
		}
		if hasPool {
			sources.poolItems = max(0, int64(max(0, poolTotal-floorTotal)/itemBytes)-1)
		} else {
			sources.poolItems = int64(senderSettings.SendBufferSettings.ResendQueueMaxByteCount / itemBytes)
		}
		senderSettings.SendBufferSettings.afterAckSendItemForTest = func(id sendSequenceId, _ uint64) {
			sources.release(id.LogicalLane)
		}

		senderId := NewId()
		receiverId := NewId()
		sender := NewClient(ctx, senderId, NewNoContractClientOob(), senderSettings)
		receiver := NewClient(ctx, receiverId, NewNoContractClientOob(), receiverSettings)
		sender.ContractManager().AddNoContractPeer(receiverId)
		receiver.ContractManager().AddNoContractPeer(senderId)
		// The routes are published exactly as the H1 platform transport
		// publishes its own: typed H1 and, on the receive side, with a
		// reliable carrier property. That is what makes the receive pump
		// apply the reliable-lane handoff contract — wait for sequence
		// capacity rather than drop a Pack it has already read — which on an
		// unknown lane would manufacture loss above the carrier and pin every
		// later Pack behind an artificial hole (CODESTYLE, receive callbacks
		// and reliable-carrier backpressure). The first ceiling cell of this
		// simulator read exactly that fault: gap resends and a stall at zero
		// delay with no loss configured.
		reliable := TransferCarrierProperties{ReceiveReliability: CarrierReliabilityReliable}
		sender.RouteManager().UpdateTransport(
			NewSendGatewayTransportWithType(TransportTypeH1), []Route{carrier.senderOut})
		sender.RouteManager().UpdateTransportWithProperties(
			NewReceiveGatewayTransportWithType(TransportTypeH1), []Route{carrier.senderIn}, reliable)
		// The receiver is the re-roll scenario's client: its receive route is
		// the one the queue delay observer is published on, and the pair is
		// retired and replaced when the connection re-rolls.
		var reroll *pathReroll
		receiverProperties := reliable
		if arm.Reroll != nil {
			reroll = newPathReroll(arm, carrier, receiver)
			receiverProperties.receiveObserver = reroll.observerOrNil()
		}
		receiverReceiveTransport := NewReceiveGatewayTransportWithType(TransportTypeH1)
		receiverSendTransport := NewSendGatewayTransportWithType(TransportTypeH1)
		receiver.RouteManager().UpdateTransportWithProperties(
			receiverReceiveTransport, []Route{carrier.receiverIn}, receiverProperties)
		receiver.RouteManager().UpdateTransport(
			receiverSendTransport, []Route{carrier.receiverOut})
		if reroll != nil {
			reroll.adoptLeg(
				receiverReceiveTransport, receiverSendTransport,
				carrier.receiverIn, carrier.receiverOut,
			)
		}

		meter := &pathMeter{holThreshold: arm.HolAfter}
		receiver.AddReceiveCallback(func(_ TransferPath, frames []*protocol.Frame, _ Peer) {
			meter.deliver(frames, arm.PayloadByteCount)
		})
		if reroll != nil {
			reroll.meter = meter
		}

		stop := &atomic.Bool{}
		stopped := make(chan struct{})
		admitted := &atomic.Int64{}
		var offers sync.WaitGroup
		// the lane's live window, followed as the sizing rule moves it
		laneWindow := func(lane uint32) ByteCount {
			sender.sendBuffer.mutex.Lock()
			sequence := sender.sendBuffer.sendSequences[sendSequenceId{
				Destination: receiverId,
				LogicalLane: lane,
			}]
			sender.sendBuffer.mutex.Unlock()
			if sequence == nil {
				return senderSettings.SendBufferSettings.ResendQueueMaxByteCount
			}
			return sequence.sendWindowEstimate(time.Now()).Window
		}
		// Both clients publish their client key on construction, as a lane
		// zero pack written by their own goroutines; the settle puts those
		// alone at the origin so the data burst does not race them for wire
		// order.
		time.Sleep(pathSettle)
		started := time.Now()
		meter.started = started
		meter.lastAt = started
		for i, lane := range lanes {
			offers.Add(1)
			go func(lane uint32, stagger time.Duration) {
				defer offers.Done()
				source := sources.lanes[lane]
				// lanes start at distinct instants, so their first packs do
				// not race each other for wire order
				select {
				case <-time.After(stagger):
				case <-stopped:
					return
				}
				for !stop.Load() {
					// The sequence goroutine reads its capacity at the top of
					// every iteration and stores the flag the caller's fast
					// path reads; a push in the same instant as a release
					// races that store. Pushing one settle later, once every
					// goroutine has blocked, reads a settled flag.
					select {
					case <-time.After(pathSourceSettle):
					case <-stopped:
						return
					}
					for !stop.Load() && sources.admit(source, laneWindow(lane)) {
						frame := RequireToFrameWithDefaultProtocolVersion(
							&protocol.SimpleMessage{Content: payload},
						)
						ok, err := sender.SendWithTimeoutDetailed(
							frame,
							receiverId,
							nil,
							-1,
							TransferKey{LogicalLane: lane},
							sendPackRecoveryOption{upstreamRecoverable: true, retainAfterAckTimeout: true},
						)
						if !ok || err != nil {
							MessagePoolReturn(frame.MessageBytes)
							return
						}
						admitted.Add(1)
					}
					select {
					case <-source.wake:
					case <-stopped:
					}
				}
			}(lane, time.Duration(i)*pathLaneStagger)
		}
		reroll.start(ctx, started)

		time.Sleep(arm.Offer / 2)
		midByteCount, _ := meter.snapshot()
		time.Sleep(arm.Offer - arm.Offer/2)
		endByteCount, _ := meter.snapshot()
		// An offer goroutine blocked in admission on a stalled path returns
		// only when the client closes, so the offers are joined after that.
		stop.Store(true)
		close(stopped)
		result.deliveredByteCount = endByteCount
		result.steadyByteCount = endByteCount - midByteCount

		// the drain: everything admitted arrives exactly once, or the run is
		// undrained and its duplicate count is not a reading
		drainStart := time.Now()
		drainDeadline := drainStart.Add(arm.Drain)
		for {
			_, frameCount := meter.snapshot()
			if admitted.Load() <= frameCount {
				result.drained = true
				break
			}
			if !time.Now().Before(drainDeadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		result.drainTime = time.Since(drainStart)
		meter.finish(time.Now())

		result.frameCount = meter.frameCount
		result.deliveries = meter.deliveries
		result.maxGap = meter.maxGap
		result.holBlocked = meter.holBlocked
		result.stalled = arm.StallAfter < meter.maxGap

		sendStats := sender.DestinationSendStats(receiverId)
		result.writeCount = sendStats.WriteCount
		result.resendCount = sendStats.ResendWriteCount
		result.window = sendStats.SendWindow
		result.sequenceCount = sendStats.SequenceCount
		recovery := sender.SendRecoveryStats()
		result.timeoutResends = recovery.TimeoutResendWriteCount
		result.gapResends = recovery.SelectiveGapWriteCount
		result.tailProbes = recovery.AckTailProbeWriteCount
		result.cumulativeProbes = recovery.CumulativeProbeWriteCount
		result.deferredResends = recovery.TimeoutResendDeferCount
		result.evictionResends = recovery.SendEvictionResendCount
		receiveStats := receiver.ReceiveStats()
		result.deadlineDrops = sender.ReceiveStats().SendPackDeadlineDropCount
		result.handoffDrops = receiveStats.PackHandoffDropCount + receiveStats.AckHandoffDropCount
		result.receiverDrops = receiveStats.ReceiveQueueDropCount
		result.receiverEvictions = receiveStats.ReceiveQueueEvictionCount
		result.receiverTentativeEvictions = receiveStats.ReceiveQueueTentativeEvictionCount

		result.reroll = reroll.finish()

		// the measurement ends here; what closing writes is not counted
		carrier.frozen.Store(true)
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer closeCancel()
		if err := sender.CloseAndWait(closeCtx); err != nil {
			t.Errorf("close the sender: %v", err)
		}
		if err := receiver.CloseAndWait(closeCtx); err != nil {
			t.Errorf("close the receiver: %v", err)
		}
		cancel()
		offers.Wait()
		result.admitted = admitted.Load()
		carrier.drain()

		for _, stats := range carrier.stats {
			result.hops = append(result.hops, *stats)
		}
		for _, hop := range result.hops {
			// one terminal hop unless a re-roll replaced it, when every leg
			// that carried traffic to the receiver counts
			if hop.terminal {
				result.forwardArrivals += hop.forward.dataDelivered
			}
		}
		if result.drained {
			result.duplicates = result.forwardArrivals - result.admitted
		}
	})
	return result
}

// The instrument's own ceiling: the window seeded past any bound, one hop at
// zero delay, unpaced, lossless. In virtual time nothing costs CPU, so what
// binds is the transfer layer's own clocking — one window per acknowledgement
// compression interval — and it is measured rather than derived so a change
// to that clocking shows up here before it is misread in a scenario.
//
// Measured once per process; every scenario arm asserts its rate is below
// `pathCensorFraction` of it, as the chain fixture does with its own ceiling.
var pathsimCeilingOnce sync.Once
var pathsimCeilingRate float64

const pathCensorFraction = 0.7
const pathCeilingWindow = ByteCount(16 * 1024 * 1024)

func pathsimCeiling(t *testing.T) float64 {
	t.Helper()
	pathsimCeilingOnce.Do(func() {
		result := runPathArm(t, pathArm{
			Name:             "ceiling",
			Hops:             []pathHop{{Name: "wire"}},
			Lanes:            1,
			PayloadByteCount: pathPayloadByteCount,
			Offer:            200 * time.Millisecond,
			Drain:            5 * time.Second,
			Seed:             1,
			WindowSizing:     WindowSizingConstant,
			MemoryBudget:     pathReferenceBudget,
			Configure: func(sender *ClientSettings, receiver *ClientSettings) {
				sender.SendBufferSettings.ResendQueueMaxByteCount = pathCeilingWindow
				receiver.ReceiveBufferSettings.ReceiveQueueMaxByteCount = 4 * pathCeilingWindow
			},
		})
		pathsimCeilingRate = result.steadyGoodput()
		t.Logf("ceiling: %.0f Mb/s steady (%.0f frames/s) with a %s window at zero delay; %s",
			pathsimCeilingRate*8/1e6, pathsimCeilingRate/float64(pathPayloadByteCount),
			formatBytes(pathCeilingWindow), result.row())
	})
	if pathsimCeilingRate <= 0 {
		t.Fatalf("the ceiling cell delivered nothing; no scenario has an instrument to be read against")
	}
	return pathsimCeilingRate
}

// Prints a scenario's table and digests, and refuses any arm that read
// within the censor margin of the ceiling. Returns the results for the
// scenario's own assertions.
func reportPathScenario(t *testing.T, scenario string, results []pathResult) {
	t.Helper()
	ceiling := pathsimCeiling(t)
	lines := []string{fmt.Sprintf("%s (ceiling %.0f Mb/s)", scenario, ceiling*8/1e6), pathTableHeaderRow()}
	digests := []string{}
	for _, result := range results {
		lines = append(lines, result.row())
		digests = append(digests, fmt.Sprintf("%s=%s", result.arm, result.digest()))
		if pathCensorFraction*ceiling <= result.steadyGoodput() {
			t.Errorf(
				"%s: %s read %.0f Mb/s against the instrument's %.0f Mb/s ceiling, inside the %.0f%% censor margin; the reading is the instrument's and no assertion on it is meaningful",
				scenario, result.arm, result.steadyGoodput()*8/1e6, ceiling*8/1e6, pathCensorFraction*100,
			)
		}
	}
	lines = append(lines, "digest "+strings.Join(digests, " "))
	t.Logf("\n%s", strings.Join(lines, "\n"))
}

// The payload every scenario carries. 16 KiB keeps the frame count, which is
// the wall cost of a virtual second, low enough for the fast tier.
const pathPayloadByteCount = 16 * 1024

// The reference budget, where `memoryTargetScale` returns one and the
// constant window is its full 2 MiB, so the two window policies are compared
// without crediting the rule with the scaling of the constant it replaces.
var pathReferenceBudget = mib(64)

// The offer length of the tier.
func pathOffer(fast time.Duration, full time.Duration) time.Duration {
	if pathsimFull() {
		return full
	}
	return fast
}

// A symmetric one-hop path: the round trip split evenly, both directions
// paced at the rate, a relay-shaped forward queue that drops on full.
func pathRelayHop(name string, roundTrip time.Duration, bytesPerSecond ByteCount, queueMessages int, loss float64) pathHop {
	return pathHop{
		Name: name,
		Forward: pathLink{
			Delay:          roundTrip / 2,
			BytesPerSecond: bytesPerSecond,
			QueueMessages:  queueMessages,
			DropOnFull:     true,
			Loss:           loss,
		},
		Reverse: pathLink{
			Delay:          roundTrip - roundTrip/2,
			BytesPerSecond: bytesPerSecond,
			QueueMessages:  queueMessages,
			DropOnFull:     true,
		},
	}
}

// Ratios and orderings the scenarios assert on.
func pathRatio(numerator pathResult, denominator pathResult) float64 {
	below := denominator.steadyGoodput()
	if below <= 0 {
		return 0
	}
	return numerator.steadyGoodput() / below
}
