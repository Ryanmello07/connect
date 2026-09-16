package connect

import (
	"math"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"
)

// H1 path re-roll: the sampled receive queue delay of one route.
//
// A pack's tag is the sender's clock at pack build, and a resend keeps it. For
// a pack read at readMs, rel = readMs - tag is the path's transit, plus any
// standing queue, plus the offset between the two clocks. The minimum rel of
// a source over about two minutes is its baseline of transit and offset, so a
// tick's minimum rel over the baseline is the queue every frame of that tick
// waited behind. A per-tick minimum ignores resends, whose old tags read late.
//
// An ack's tag echoes our own send time, so readMs - tag is an ack round trip
// on our clock alone. Its minimum over AckRttWindow is a path round trip that
// needs no kernel counters, and a tick's own minimum is that tick's round trip:
// the acks share the route with the packs, so the same queue is in both, and
// the ack side of it is measured without the sender's clock.
//
// `h1RouteObserver` is published on one receive route through
// TransferCarrierProperties and fed by Client.run, which samples one frame in
// PackSampleEvery. The per-frame cost is an atomic load and add; a sampled frame
// costs one clock read and two short locks, and neither allocates.
//
// `h1QueueDelayBaseline` is shared by every route and generation of one
// transport, so a new connection is judged against the history of the path
// and not against its own first, possibly already queued, frames. A wall clock
// step resets it.
//
// The baseline holds a slot per source and there are fewer slots than a
// provider's websocket has clients. A slot is therefore sticky: a source that
// keeps sending holds its slot for the connection's life, and a new source
// takes only a free slot or one whose source has been silent for the whole
// baseline window. Rotating the slots instead would give a source that came
// back neither buckets nor floor, so the rel it showed at that moment -- under
// a standing queue, the queue itself -- became its floor and the queue delay
// read zero for every source, forever. Which sources hold the slots does not
// matter: every source behind one socket waits in the same queue, so any
// stable few of them measure it. The observer follows the same rule, so its
// tick is spent on the sources whose baseline can read a queue.
//
// The baseline is a rolling minimum, and a rolling minimum cannot see a queue
// that outlives its window: a connection stuck on a lossy path for its whole
// life delivers no unqueued frame after the first minutes, the standing queue
// becomes the baseline and the queue delay reads zero. Each source therefore
// also keeps the smallest rel it ever saw, and the baseline may rise above
// that floor only by BaselineRisePerMinute for each minute since it was set.
// The floor absorbs the two clocks' relative drift many times over (100 ms a
// minute is 1667 ppm against the tens of ppm two disciplined clocks reach), and
// a real queue of q stays visible for (q - threshold) / rise rather than for
// one window. What the floor cannot absorb is a backward clock step on the
// sender, which reads exactly like a queue for as long: the receive rule
// answers that with the ack round trip, measured on this client's own clock
// (transport_h1_path.go).
//
// Both types are safe for concurrent use.

// sources tracked per baseline and per observer tick
const h1QueueDelaySourceCount = 4

// the queue delay baseline keeps at most this many buckets
const h1QueueDelayBucketLimit = 16

// the ack round trip minimum is kept in this many buckets over AckRttWindow
const h1AckRttBucketCount = 6

// a disagreement between the wall and monotonic clocks above this, between two
// ticks, is a wall clock step
const h1QueueDelayClockStepThreshold = 100 * time.Millisecond

// A ring of bucket minimums indexed by the bucket's epoch modulo the bucket
// count. Epochs are counted in bucket durations on the monotonic clock from the
// baseline's origin. The zero value is unset and holds nothing.
type h1MinBuckets struct {
	minMs [h1QueueDelayBucketLimit]int64
	epoch int64
	set   bool
}

func (self *h1MinBuckets) resetWithLock(bucketCount int, epoch int64) {
	for i := 0; i < bucketCount; i++ {
		self.minMs[i] = math.MaxInt64
	}
	self.epoch = epoch
	self.set = true
}

// clears the buckets the ring moved past; an epoch older than the newest one
// (which a monotonic clock does not produce) reads as the newest
func (self *h1MinBuckets) advanceWithLock(bucketCount int, epoch int64) {
	if !self.set {
		self.resetWithLock(bucketCount, epoch)
		return
	}
	if epoch <= self.epoch {
		return
	}
	if int64(bucketCount) <= epoch-self.epoch {
		self.resetWithLock(bucketCount, epoch)
		return
	}
	for e := self.epoch + 1; e <= epoch; e++ {
		self.minMs[e%int64(bucketCount)] = math.MaxInt64
	}
	self.epoch = epoch
}

func (self *h1MinBuckets) addWithLock(bucketCount int, valueMs int64) {
	i := self.epoch % int64(bucketCount)
	self.minMs[i] = min(self.minMs[i], valueMs)
}

// math.MaxInt64 when every bucket is empty
func (self *h1MinBuckets) minWithLock(bucketCount int) int64 {
	m := int64(math.MaxInt64)
	if !self.set {
		return m
	}
	for i := 0; i < bucketCount; i++ {
		m = min(m, self.minMs[i])
	}
	return m
}

type h1QueueDelaySource struct {
	sourceId Id
	used     bool
	buckets  h1MinBuckets
	lastUse  time.Time
	// the smallest rel ever seen for the source, and when it was seen; the
	// buckets may rise above it only at the rise rate. math.MaxInt64 is unset
	floorMs   int64
	floorTime time.Time
	// tags at or below this are from before the latest re-roll
	freshAfterTagMs uint64
}

// The per-source minimum rel over BaselineBucketCount buckets of
// BaselineBucketDuration, and the minimum ack round trip over AckRttWindow.
// A value is kept for between count-1 and count bucket durations, depending on
// where in its bucket it landed.
type h1QueueDelayBaseline struct {
	bucketDuration    time.Duration
	bucketCount       int
	ackBucketDuration time.Duration
	// how far the baseline may rise above a source's floor in a minute;
	// non-positive keeps the buckets alone
	risePerMinute time.Duration

	stateLock sync.Mutex
	// set by the first observation; bucket epochs count from here
	origin     time.Time
	originSet  bool
	sources    [h1QueueDelaySourceCount]h1QueueDelaySource
	ackBuckets h1MinBuckets
	clockSet   bool
	lastWall   time.Time
	lastMono   time.Time
	// counts wall clock steps; an observer whose tick spans a step discards it
	clockStepCount uint64
	// replaces the wall clock reading of the step check
	nowWallForTest func() time.Time
}

func newH1QueueDelayBaseline(settings *H1PathRerollSettings) *h1QueueDelayBaseline {
	bucketCount := min(h1QueueDelayBucketLimit, max(1, settings.BaselineBucketCount))
	return &h1QueueDelayBaseline{
		bucketDuration:    max(time.Millisecond, settings.BaselineBucketDuration),
		bucketCount:       bucketCount,
		ackBucketDuration: max(time.Millisecond, settings.AckRttWindow/h1AckRttBucketCount),
		risePerMinute:     max(0, settings.BaselineRisePerMinute),
	}
}

func (self *h1QueueDelayBaseline) epochWithLock(now time.Time, bucketDuration time.Duration) int64 {
	if !self.originSet {
		self.origin = now
		self.originSet = true
	}
	elapsed := now.Sub(self.origin)
	if elapsed < 0 {
		return 0
	}
	return int64(elapsed / bucketDuration)
}

// The source's baseline: the minimum of its buckets, held down by the floor,
// which the buckets may rise above only at the rise rate. math.MaxInt64 when
// the source has observed nothing.
func (self *h1QueueDelayBaseline) baselineWithLock(source *h1QueueDelaySource, now time.Time) int64 {
	baseMs := source.buckets.minWithLock(self.bucketCount)
	if self.risePerMinute <= 0 || source.floorMs == math.MaxInt64 {
		return baseMs
	}
	elapsed := max(0, now.Sub(source.floorTime))
	riseMs := self.risePerMinute.Milliseconds() * int64(elapsed) / int64(time.Minute)
	return min(baseMs, source.floorMs+riseMs)
}

func (self *h1QueueDelayBaseline) sourceWithLock(sourceId Id) *h1QueueDelaySource {
	for i := range self.sources {
		if self.sources[i].used && self.sources[i].sourceId == sourceId {
			return &self.sources[i]
		}
	}
	return nil
}

// Takes a slot for a source the baseline does not hold: a free one, else the
// slot of the source that has been silent longest, once that silence has run a
// whole bucket. Returns nil when every slot is held by a source that is still
// sending, and the source is then not measured at all. The silence bar is what
// bounds how long a socket whose talkers have changed reads no queue delay,
// and it is a whole bucket because a slot given away is a floor thrown away.
func (self *h1QueueDelayBaseline) admitWithLock(sourceId Id, now time.Time) *h1QueueDelaySource {
	var source *h1QueueDelaySource
	for i := range self.sources {
		if !self.sources[i].used {
			source = &self.sources[i]
			break
		}
		if self.bucketDuration <= now.Sub(self.sources[i].lastUse) &&
			(source == nil || self.sources[i].lastUse.Before(source.lastUse)) {
			source = &self.sources[i]
		}
	}
	if source == nil {
		return nil
	}
	*source = h1QueueDelaySource{
		sourceId: sourceId,
		used:     true,
		floorMs:  math.MaxInt64,
	}
	return source
}

// Folds one tick's minimum rel for the source into its buckets and returns the
// baseline, which includes that minimum. math.MaxInt64 when every slot is held
// by another live source.
func (self *h1QueueDelayBaseline) observe(sourceId Id, minRelMs int64, now time.Time) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	epoch := self.epochWithLock(now, self.bucketDuration)
	source := self.sourceWithLock(sourceId)
	if source == nil {
		source = self.admitWithLock(sourceId, now)
		if source == nil {
			return math.MaxInt64
		}
	}
	source.buckets.advanceWithLock(self.bucketCount, epoch)
	source.buckets.addWithLock(self.bucketCount, minRelMs)
	source.lastUse = now
	if minRelMs < source.floorMs {
		// a lower rel is the path with less queue than we have ever seen, so it
		// replaces the floor and restarts the rise from here
		source.floorMs = minRelMs
		source.floorTime = now
	}
	return self.baselineWithLock(source, now)
}

// For every source with a baseline, marks tags up to 2 x pathRtt past the
// sender clock's reading of now as stale: those packs were built for the
// retired connection, and a resend keeps its tag.
func (self *h1QueueDelayBaseline) markReroll(now time.Time, pathRtt time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	epoch := self.epochWithLock(now, self.bucketDuration)
	nowMs := now.UnixMilli()
	for i := range self.sources {
		source := &self.sources[i]
		if !source.used {
			continue
		}
		source.buckets.advanceWithLock(self.bucketCount, epoch)
		baseMs := self.baselineWithLock(source, now)
		if baseMs == math.MaxInt64 {
			continue
		}
		freshAfterTagMs := nowMs - baseMs + 2*pathRtt.Milliseconds()
		if 0 < freshAfterTagMs {
			source.freshAfterTagMs = max(source.freshAfterTagMs, uint64(freshAfterTagMs))
		}
	}
}

// zero when the source has no mark
func (self *h1QueueDelayBaseline) freshAfter(sourceId Id) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	if source := self.sourceWithLock(sourceId); source != nil {
		return source.freshAfterTagMs
	}
	return 0
}

func (self *h1QueueDelayBaseline) observeAck(rttMs int64, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	self.ackBuckets.advanceWithLock(h1AckRttBucketCount, self.epochWithLock(now, self.ackBucketDuration))
	self.ackBuckets.addWithLock(h1AckRttBucketCount, rttMs)
}

// zero when no ack round trip is in the window
func (self *h1QueueDelayBaseline) ackRttMin(now time.Time) time.Duration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	if !self.ackBuckets.set {
		return 0
	}
	self.ackBuckets.advanceWithLock(h1AckRttBucketCount, self.epochWithLock(now, self.ackBucketDuration))
	minMs := self.ackBuckets.minWithLock(h1AckRttBucketCount)
	if minMs == math.MaxInt64 {
		return 0
	}
	return time.Duration(minMs) * time.Millisecond
}

// Compares the wall and monotonic clocks since the previous check. When they
// disagree by more than 100 ms every bucket resets, the step count advances,
// and it returns true. Returns the step count after the check.
func (self *h1QueueDelayBaseline) checkClockStep(now time.Time) (bool, uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	wall := now.Round(0)
	if self.nowWallForTest != nil {
		wall = self.nowWallForTest().Round(0)
	}
	if !self.clockSet {
		self.clockSet = true
		self.lastWall = wall
		self.lastMono = now
		return false, self.clockStepCount
	}
	// Sub uses the monotonic readings when both times carry one
	disagreement := wall.Sub(self.lastWall) - now.Sub(self.lastMono)
	self.lastWall = wall
	self.lastMono = now
	if disagreement < 0 {
		disagreement = -disagreement
	}
	if disagreement <= h1QueueDelayClockStepThreshold {
		return false, self.clockStepCount
	}
	for i := range self.sources {
		if self.sources[i].used {
			self.sources[i].buckets.resetWithLock(self.bucketCount, self.sources[i].buckets.epoch)
			self.sources[i].floorMs = math.MaxInt64
			self.sources[i].floorTime = time.Time{}
		}
	}
	if self.ackBuckets.set {
		self.ackBuckets.resetWithLock(h1AckRttBucketCount, self.ackBuckets.epoch)
	}
	self.clockStepCount += 1
	return true, self.clockStepCount
}

func (self *h1QueueDelayBaseline) clockSteps() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.clockStepCount
}

type h1ObserverSlot struct {
	sourceId Id
	used     bool
	// the baseline holds a slot for the source, so its samples can read a queue
	tracked  bool
	minRelMs int64
	count    int
}

// One tick of one route's observer.
type h1ObserverTick struct {
	// the queue delay of the source with the most samples; valid when known
	queueDelay time.Duration
	// that source's pack samples in the tick
	samples int
	// packs ignored because their tag predates the latest re-roll
	stale int
	// packs of a source the baseline does not hold, read while every slot was
	// held by one it does
	unslotted int
	// the minimum ack round trip over AckRttWindow; zero is unknown
	ackRttMin time.Duration
	// the minimum ack round trip of this tick's own acks, valid when
	// ackSamples is positive: the same queue as the packs, on our own clock
	ackRtt     time.Duration
	ackSamples int
	// at least one fresh sample, and no wall clock step during the tick
	known bool
}

// The receive-route observer. Client.run calls sampleNext for every frame it
// reads on the route and observePack or observeAck for a sampled one; the
// connection that published it calls takeTick.
type h1RouteObserver struct {
	baseline   *h1QueueDelayBaseline
	sampleMask uint32
	frameCount atomic.Uint32
	active     atomic.Bool

	stateLock      sync.Mutex
	slots          [h1QueueDelaySourceCount]h1ObserverSlot
	ackMinMs       int64
	ackCount       int
	staleCount     int
	unslottedCount int
	// the sources the baseline held a slot for when it last read one of their
	// ticks; their samples are the only ones a queue can be read from
	trackedSourceIds [h1QueueDelaySourceCount]Id
	trackedCount     int
	// the baseline's clock step count at this observer's previous tick
	clockStepCount uint64
}

// Samples one frame in sampleEvery, rounded up to a power of two. The observer
// starts active.
func newH1RouteObserver(baseline *h1QueueDelayBaseline, sampleEvery int) *h1RouteObserver {
	sampleMask := uint32(0)
	if 1 < sampleEvery {
		sampleMask = uint32(1)<<bits.Len32(uint32(min(sampleEvery, 1<<30)-1)) - 1
	}
	clockStepCount := baseline.clockSteps()
	observer := &h1RouteObserver{
		baseline:       baseline,
		sampleMask:     sampleMask,
		ackMinMs:       math.MaxInt64,
		clockStepCount: clockStepCount,
	}
	observer.active.Store(true)
	return observer
}

// Counts one frame read on the route and returns true when it is sampled.
// Lock free, and false while the observer is inactive.
func (self *h1RouteObserver) sampleNext() bool {
	if !self.active.Load() {
		return false
	}
	return self.frameCount.Add(1)&self.sampleMask == 0
}

func (self *h1RouteObserver) setActive(active bool) {
	self.active.Store(active)
}

func (self *h1RouteObserver) trackedWithLock(sourceId Id) bool {
	for i := 0; i < self.trackedCount; i += 1 {
		if self.trackedSourceIds[i] == sourceId {
			return true
		}
	}
	return false
}

// Records whether the baseline held a slot for the source when it read the
// source's latest tick. A source that stops appearing keeps its place: it is
// the baseline that holds the slot, and only the baseline's refusal says the
// source lost it. The list is as long as the baseline's, so a refused source
// leaving room for an admitted one keeps it true even when a source is dropped
// without ever being read again.
func (self *h1RouteObserver) noteTrackedWithLock(sourceId Id, tracked bool) {
	for i := 0; i < self.trackedCount; i += 1 {
		if self.trackedSourceIds[i] != sourceId {
			continue
		}
		if tracked {
			return
		}
		copy(self.trackedSourceIds[i:], self.trackedSourceIds[i+1:self.trackedCount])
		self.trackedCount -= 1
		return
	}
	if !tracked {
		return
	}
	if self.trackedCount < h1QueueDelaySourceCount {
		self.trackedSourceIds[self.trackedCount] = sourceId
		self.trackedCount += 1
		return
	}
	copy(self.trackedSourceIds[0:], self.trackedSourceIds[1:])
	self.trackedSourceIds[h1QueueDelaySourceCount-1] = sourceId
}

// Folds one sampled pack into the tick's minimum rel for its source. A tag at or
// before the source's latest re-roll mark counts as stale and nothing else. A
// source the baseline holds takes a free slot, else the slot of one it does not
// hold, so the tick is spent on the sources whose baseline can read a queue; a
// source the baseline does not hold takes only a free slot.
func (self *h1RouteObserver) observePack(sourceId Id, tagSendTimeMs uint64, readTime time.Time) {
	if tagSendTimeMs == 0 || math.MaxInt64 < tagSendTimeMs {
		// no tag
		return
	}
	freshAfterTagMs := self.baseline.freshAfter(sourceId)
	relMs := readTime.UnixMilli() - int64(tagSendTimeMs)

	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	if tagSendTimeMs <= freshAfterTagMs {
		self.staleCount += 1
		return
	}
	tracked := self.trackedWithLock(sourceId)
	var slot *h1ObserverSlot
	for i := range self.slots {
		if self.slots[i].used && self.slots[i].sourceId == sourceId {
			slot = &self.slots[i]
			break
		}
	}
	if slot == nil {
		for i := range self.slots {
			if !self.slots[i].used {
				slot = &self.slots[i]
				break
			}
		}
	}
	if slot == nil && tracked {
		for i := range self.slots {
			if self.slots[i].tracked {
				continue
			}
			if slot == nil || self.slots[i].count < slot.count {
				slot = &self.slots[i]
			}
		}
	}
	if slot == nil {
		self.unslottedCount += 1
		return
	}
	if !slot.used || slot.sourceId != sourceId {
		*slot = h1ObserverSlot{
			sourceId: sourceId,
			used:     true,
			minRelMs: math.MaxInt64,
		}
	}
	slot.tracked = tracked
	slot.minRelMs = min(slot.minRelMs, relMs)
	slot.count += 1
}

// Folds one sampled ack's round trip into the tick's minimum. The tag was
// stamped by this client, so a negative round trip is a local clock step and is
// ignored.
func (self *h1RouteObserver) observeAck(tagSendTimeMs uint64, readTime time.Time) {
	if tagSendTimeMs == 0 || math.MaxInt64 < tagSendTimeMs {
		return
	}
	rttMs := readTime.UnixMilli() - int64(tagSendTimeMs)
	if rttMs < 0 {
		return
	}

	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	self.ackMinMs = min(self.ackMinMs, rttMs)
	self.ackCount += 1
}

// Closes the tick: folds each source's minimum into the baseline and reports
// the queue delay of the source with the most samples. A tick that spans a
// wall clock step is unknown. The slots reset either way.
func (self *h1RouteObserver) takeTick(now time.Time) h1ObserverTick {
	var slots [h1QueueDelaySourceCount]h1ObserverSlot
	var ackMinMs int64
	var ackCount int
	var staleCount int
	var unslottedCount int
	var previousClockStepCount uint64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()

		slots = self.slots
		ackMinMs = self.ackMinMs
		ackCount = self.ackCount
		staleCount = self.staleCount
		unslottedCount = self.unslottedCount
		previousClockStepCount = self.clockStepCount
		self.slots = [h1QueueDelaySourceCount]h1ObserverSlot{}
		self.ackMinMs = math.MaxInt64
		self.ackCount = 0
		self.staleCount = 0
		self.unslottedCount = 0
	}()

	_, clockStepCount := self.baseline.checkClockStep(now)
	if clockStepCount != previousClockStepCount {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.clockStepCount = clockStepCount
		}()
		return h1ObserverTick{
			stale:     staleCount,
			unslotted: unslottedCount,
			ackRttMin: self.baseline.ackRttMin(now),
		}
	}

	if 0 < ackCount {
		self.baseline.observeAck(ackMinMs, now)
	}
	tick := h1ObserverTick{
		stale:     staleCount,
		unslotted: unslottedCount,
		ackRttMin: self.baseline.ackRttMin(now),
	}
	if 0 < ackCount {
		tick.ackRtt = time.Duration(ackMinMs) * time.Millisecond
		tick.ackSamples = ackCount
	}
	for i := range slots {
		slot := &slots[i]
		if !slot.used || slot.count == 0 {
			continue
		}
		baseMs := self.baseline.observe(slot.sourceId, slot.minRelMs, now)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.noteTrackedWithLock(slot.sourceId, baseMs != math.MaxInt64)
		}()
		if baseMs == math.MaxInt64 {
			// no slot in the baseline, so nothing to read the minimum against
			tick.unslotted += slot.count
			continue
		}
		if tick.known && slot.count <= tick.samples {
			continue
		}
		tick.known = true
		tick.samples = slot.count
		tick.queueDelay = time.Duration(max(0, slot.minRelMs-baseMs)) * time.Millisecond
	}
	return tick
}
