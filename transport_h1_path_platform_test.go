package connect

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"
)

// These tests drive the H1 path monitor through the real runH1 against a real
// loopback websocket platform. Loopback has no far path, so the hooks script
// each connection's dial round trip and the path half of its samples, while
// the reader's flags (speed test, receive backpressure) and the connection
// lifecycle stay real. Every count is read from a per-test stats value, so a
// transport left running by another test cannot move it.
//
// Waits are counted: a test waits for a number of monitor decisions on a
// connection, not for time to pass. A connection still ticking after a
// conviction was not closed by it, because its watcher returns on a close.
// Connections are counted by the dial round trip hook, which runs once for
// each connection runH1 runs; the platform's own count also includes the
// strategy's losing parallel dials.

// the scripted path round trip
const testingH1PathRtt = 105 * time.Millisecond

// the thin rate at testingH1PathRtt is 256 x 1448 / 105 ms, about 3.5 MB/s
const testingH1PathCollapsedByteRate = 256 * 1000
const testingH1PathHealthyByteRate = 8 * 1000 * 1000

type testingH1PathClass int

const (
	// the connection's own counters and flags, on the scripted far round trip
	testingH1PathReal testingH1PathClass = 0
	// thin delivery behind a 5 s queue that holds the acks too, with
	// out-of-order data every tick: the measured collapse, confirmed
	testingH1PathCollapsed testingH1PathClass = 1
	// full rate, no queue
	testingH1PathHealthy testingH1PathClass = 2
	// the same collapse on a route whose peer answers over another transport,
	// so the queue stands on the sender's clock alone: unconfirmed
	testingH1PathCollapsedNoAck testingH1PathClass = 3
	// no queue at a rate under thin, which is what most sessions run at
	testingH1PathHealthyThin testingH1PathClass = 4
)

// A rate with no queue under it that is still an order below thin: 5.6 Mb/s
// against a thin rate of 28 Mb/s on the rig's 105 ms path.
const testingH1PathHealthyThinByteRate = 700 * 1000

type testingH1PathRig struct {
	stats  *h1PathStats
	ledger *h1PathLedger
	// the class of each sample, by connection ordinal and tick index
	class func(connectionOrdinal int, tickIndex int) testingH1PathClass
	// when it returns true the sample hook fails, standing in for any error
	// under the monitor tick; nil never fails
	samplePanic func(connectionOrdinal int, tickIndex int) bool
	// the dial round trip of each connection
	dialRtt time.Duration

	stateLock    sync.Mutex
	dialOrdinals []int
	tickCounts   map[int]int
	startTimes   map[int]time.Time
	// the connection's own sample, before the script edits it
	realSamples map[int][]h1PathSample
	decisions   map[int][]h1PathDecision
}

func newTestingH1PathRig(class func(connectionOrdinal int, tickIndex int) testingH1PathClass) *testingH1PathRig {
	stats := &h1PathStats{}
	ledger := newH1PathLedger()
	ledger.stats = stats
	return &testingH1PathRig{
		stats:       stats,
		ledger:      ledger,
		class:       class,
		dialRtt:     testingH1PathRtt,
		tickCounts:  map[int]int{},
		startTimes:  map[int]time.Time{},
		realSamples: map[int][]h1PathSample{},
		decisions:   map[int][]h1PathDecision{},
	}
}

func (self *testingH1PathRig) hooks() *h1PathTestHooks {
	return &h1PathTestHooks{
		dialRtt: func(connectionOrdinal int, dialRtt time.Duration) time.Duration {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.dialOrdinals = append(self.dialOrdinals, connectionOrdinal)
			return self.dialRtt
		},
		sample: func(connectionOrdinal int, sample *h1PathSample) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.realSamples[connectionOrdinal] = append(self.realSamples[connectionOrdinal], *sample)
			tickIndex := self.tickCounts[connectionOrdinal]
			self.tickCounts[connectionOrdinal] = tickIndex + 1
			startTime, ok := self.startTimes[connectionOrdinal]
			if !ok {
				startTime = sample.now
				self.startTimes[connectionOrdinal] = startTime
			}
			if self.samplePanic != nil && self.samplePanic(connectionOrdinal, tickIndex) {
				panic("h1 path monitor tick")
			}
			// a loopback kernel or ack round trip would make every connection
			// dormant, and a loopback ack carries none of the queue the class
			// scripts, so it would deny every collapsed tick; each class below
			// writes the ack round trip its own shape has
			sample.ackRttMin = 0
			sample.ackRtt = 0
			sample.ackRttSamples = 0
			sample.minRtt = testingH1PathRtt
			class := self.class(connectionOrdinal, tickIndex)
			if class == testingH1PathReal {
				return
			}
			seconds := sample.now.Sub(startTime).Seconds()
			sample.readMessageCount = uint64(tickIndex+1) * 8
			sample.writeMessageCount = uint64(tickIndex+1) * 8
			sample.receiveFullCount = 0
			sample.rcvMss = 1448
			sample.sndMss = 1448
			sample.txKnown = false
			sample.rxBytesKnown = true
			sample.rxOooKnown = true
			sample.queueDelaySamples = 4
			switch class {
			case testingH1PathCollapsed, testingH1PathCollapsedNoAck:
				sample.rxBytes = uint64(seconds * testingH1PathCollapsedByteRate)
				sample.queueDelay = 5 * time.Second
				sample.rxOoo = uint64(tickIndex)
				if class == testingH1PathCollapsed {
					// the acks ride the collapsed route and carry the same
					// queue, measured against the dial round trip
					sample.ackRttMin = testingH1PathRtt
					sample.ackRtt = testingH1PathRtt + 5*time.Second
					sample.ackRttSamples = 4
				}
			case testingH1PathHealthy, testingH1PathHealthyThin:
				byteRate := float64(testingH1PathHealthyByteRate)
				if class == testingH1PathHealthyThin {
					byteRate = testingH1PathHealthyThinByteRate
				}
				sample.rxBytes = uint64(seconds * byteRate)
				sample.queueDelay = 0
				sample.rxOoo = 0
				sample.ackRttMin = testingH1PathRtt
				sample.ackRtt = testingH1PathRtt
				sample.ackRttSamples = 4
			}
		},
		decision: func(connectionOrdinal int, decision h1PathDecision) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.decisions[connectionOrdinal] = append(self.decisions[connectionOrdinal], decision)
		},
		stats:  self.stats,
		ledger: self.ledger,
	}
}

// decisions of the connection, oldest first
func (self *testingH1PathRig) connectionDecisions(connectionOrdinal int) []h1PathDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]h1PathDecision{}, self.decisions[connectionOrdinal]...)
}

func (self *testingH1PathRig) connectionRealSamples(connectionOrdinal int) []h1PathSample {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]h1PathSample{}, self.realSamples[connectionOrdinal]...)
}

func (self *testingH1PathRig) dials() []int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]int{}, self.dialOrdinals...)
}

// the number of the connection's convictions, and of its decisions after the
// latest conviction
func (self *testingH1PathRig) convictions(connectionOrdinal int) (convictionCount int, decisionCountAfter int) {
	for _, decision := range self.connectionDecisions(connectionOrdinal) {
		if decision.convicted {
			convictionCount += 1
			decisionCountAfter = 0
		} else {
			decisionCountAfter += 1
		}
	}
	return
}

func testingH1PathTransportSettings(mode H1PathRerollMode, rig *testingH1PathRig) *PlatformTransportSettings {
	settings := testingPlatformTransportSettings()
	reroll := &settings.H1PathReroll
	reroll.Mode = mode
	reroll.TickInterval = 20 * time.Millisecond
	reroll.MinConnectionAge = 100 * time.Millisecond
	// demand scales with the tick, so 1 KiB per 20 ms tick is 51 KB/s
	reroll.MinTickByteCount = kib(1)
	settings.h1PathTestHooks = rig.hooks()
	return settings
}

func testingH1PathCollapsedAlways(connectionOrdinal int, tickIndex int) testingH1PathClass {
	return testingH1PathCollapsed
}

// the receive observer published on the transport's receive route, and
// whether a receive route is published at all
func testingH1PathPublishedObserver(transport *PlatformTransport) (observer *h1RouteObserver, published bool) {
	routeManager := transport.routeManager
	routeManager.mutex.Lock()
	defer routeManager.mutex.Unlock()
	for _, properties := range routeManager.readerMatchState.transportProperties {
		published = true
		if properties.receiveObserver != nil {
			observer = properties.receiveObserver
		}
	}
	return
}

// A far connection in Observe convicts a collapsed path and keeps running:
// the monitor counts the conviction, the connection counts it as observed, and
// the same connection goes on ticking into a second conviction.
func TestPlatformTransportH1PathObserveCountsConvictionWithoutRedial(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
		transport := testingPlatformTransport(t, ctx, platform.url, testingH1PathTransportSettings(H1PathRerollModeObserve, rig))

		if !waitForCondition(15*time.Second, func() bool {
			convictionCount, decisionCountAfter := rig.convictions(0)
			return 2 <= convictionCount && 0 < decisionCountAfter
		}) {
			convictionCount, _ := rig.convictions(0)
			t.Fatalf("convictions on the first connection = %d, want at least 2 followed by another tick", convictionCount)
		}
		if dials := rig.dials(); len(dials) != 1 {
			t.Fatalf("connections %v, want [0]: an observed conviction re-dialed", dials)
		}
		if !transport.IsConnected() {
			t.Fatal("the transport lost its connection")
		}
		stats := rig.stats.snapshot()
		if stats.ConnectionsMonitored != 1 || stats.ConnectionsDormant != 0 {
			t.Fatalf("stats = %+v, want one monitored connection", stats)
		}
		// the connection is still ticking, so the two counters may be a tick apart
		if stats.RxConvictions < 2 || stats.SuppressedObserve < 2 || stats.TxConvictions != 0 || stats.Rerolls != 0 {
			t.Fatalf("stats = %+v, want the rx convictions observed", stats)
		}
		for _, decision := range rig.connectionDecisions(0) {
			if decision.convicted &&
				(decision.action != h1PathActionObserve ||
					decision.direction != h1PathDirectionRx ||
					decision.confidence != h1PathConfidenceConfirmed) {
				t.Fatalf("conviction = %+v, want a confirmed rx conviction observed", decision)
			}
		}
	})
}

// A route whose peer answers over another transport carries no ack, so the
// queue stands on the sender's clock alone and nothing here can check it: the
// conviction is unconfirmed, and the epoch's unconfirmed budget of one allows
// exactly one re-roll however long the collapse lasts. This is what the
// confidence rule decides for every client whose peer talks elsewhere (see the
// no-ack paragraph of transport_h1_path.go), and the cost it is accepted at.
func TestPlatformTransportH1PathNoAckRouteRerollsOncePerEpoch(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			return testingH1PathCollapsedNoAck
		})
		settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
		settings.H1PathReroll.DeviceRerollSpacing = 50 * time.Millisecond
		testingPlatformTransport(t, ctx, platform.url, settings)

		testingH1PathWaitForConvictions(t, rig, 1, 2)
		if dials := rig.dials(); len(dials) != 2 {
			t.Fatalf("connections %v, want 2: one re-roll, then the unconfirmed budget", dials)
		}
		testingH1PathRequireRerolled(t, rig, 0)
		testingH1PathRequireSuppressed(t, rig, 1, h1PathReasonUnconfirmedBudget)
		for _, decision := range rig.connectionDecisions(0) {
			if decision.convicted && decision.confidence != h1PathConfidenceUnconfirmed {
				t.Fatalf("conviction = %+v, want it unconfirmed with no ack on the route", decision)
			}
		}
		stats := rig.stats.snapshot()
		if stats.Rerolls != 1 || stats.ConfirmedConvictions != 0 ||
			stats.UnconfirmedConvictions < 2 || stats.SuppressedUnconfirmedBudget < 1 {
			t.Fatalf("stats = %+v, want one unconfirmed re-roll and the budget refusing", stats)
		}
		// every tick of both connections read no ack, which is what sizes the
		// population the rule applies to
		if stats.TicksAckUnknown != stats.Ticks {
			t.Fatalf("stats = %+v, want every tick counted with no ack to read", stats)
		}
	})
}

// A same-datacenter dial is dormant from registration: no observer is
// published, no connection exists to tick, and the dormancy is counted once.
func TestPlatformTransportH1PathDormantOnShortPath(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
		rig.dialRtt = 300 * time.Microsecond
		transport := testingPlatformTransport(t, ctx, platform.url, testingH1PathTransportSettings(H1PathRerollModeObserve, rig))

		if !waitForCondition(15*time.Second, transport.IsConnected) {
			t.Fatal("the transport never connected")
		}
		// routes are published before the transport reports connected
		observer, published := testingH1PathPublishedObserver(transport)
		if !published || observer != nil {
			t.Fatalf("published = %t, observer = %p: want the receive route without an observer", published, observer)
		}
		if dials := rig.dials(); len(dials) != 1 || dials[0] != 0 {
			t.Fatalf("dial round trips read for connections %v, want [0]", dials)
		}
		stats := rig.stats.snapshot()
		if stats.ConnectionsDormant != 1 || stats.ConnectionsMonitored != 0 || stats.KernelUnavailable != 0 {
			t.Fatalf("stats = %+v, want exactly one dormant connection", stats)
		}
		// a dormant connection has no ticker; ten tick intervals show none
		time.Sleep(10 * transport.settings.H1PathReroll.TickInterval)
		if stats := rig.stats.snapshot(); stats.Ticks != 0 {
			t.Fatalf("ticks = %d on a dormant connection", stats.Ticks)
		}
		if decisions := rig.connectionDecisions(0); len(decisions) != 0 {
			t.Fatalf("a dormant connection decided %d times", len(decisions))
		}
	})
}

// A transport that buffers nothing paces every delivery from our own consumer,
// so the reader's full test holds for every message and no tick could ever be
// read as the path's. Such a connection is not monitored at all rather than
// monitored inertly: no observer, no ticker, no kernel read.
func TestPlatformTransportH1PathUnbufferedTransportIsNotMonitored(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	platform := newTestingPlatformServer(t)
	rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
	settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
	settings.TransportBufferSize = 0
	transport := testingPlatformTransport(t, ctx, platform.url, settings)

	if !waitForCondition(15*time.Second, transport.IsConnected) {
		t.Fatal("the transport never connected")
	}
	observer, published := testingH1PathPublishedObserver(transport)
	if !published || observer != nil {
		t.Fatalf("published = %t, observer = %p: want the receive route without an observer", published, observer)
	}
	time.Sleep(10 * settings.H1PathReroll.TickInterval)
	stats := rig.stats.snapshot()
	if stats.ConnectionsUnbuffered != 1 || stats.ConnectionsMonitored != 0 || stats.ConnectionsDormant != 0 {
		t.Fatalf("stats = %+v, want exactly one unbuffered connection", stats)
	}
	if stats.Ticks != 0 || 0 < len(rig.connectionDecisions(0)) {
		t.Fatalf("stats = %+v with %d decisions: an unbuffered connection is still ticking", stats, len(rig.connectionDecisions(0)))
	}
}

// A far dial publishes its observer on the receive route for exactly the
// connection's lifetime, and the observer stops sampling at close.
func TestPlatformTransportH1PathObserverPublishedOnFarPath(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			return testingH1PathHealthy
		})
		transport := testingPlatformTransport(t, ctx, platform.url, testingH1PathTransportSettings(H1PathRerollModeObserve, rig))

		if !waitForCondition(15*time.Second, transport.IsConnected) {
			t.Fatal("the transport never connected")
		}
		observer, published := testingH1PathPublishedObserver(transport)
		if !published || observer == nil {
			t.Fatalf("published = %t, observer = %p: want the far connection's observer", published, observer)
		}
		if observer.baseline != transport.h1PathBaseline {
			t.Fatal("the observer does not use the transport's baseline")
		}
		if !observer.active.Load() {
			t.Fatal("the published observer is not sampling")
		}
		if stats := rig.stats.snapshot(); stats.ConnectionsMonitored != 1 || stats.ConnectionsDormant != 0 {
			t.Fatalf("stats = %+v, want one monitored connection", stats)
		}
		// the loopback socket is a direct TCP socket to the platform port, which
		// these kernels read
		switch runtime.GOOS {
		case "linux", "android", "darwin", "ios":
			if stats := rig.stats.snapshot(); stats.KernelUnavailable != 0 {
				t.Fatalf("kernel unavailable = %d for a direct loopback dial", stats.KernelUnavailable)
			}
		}

		transport.Close()
		select {
		case <-transport.Done():
		case <-time.After(15 * time.Second):
			t.Fatal("the transport did not finish closing")
		}
		if _, published := testingH1PathPublishedObserver(transport); published {
			t.Fatal("the receive route outlived the transport")
		}
		if observer.active.Load() {
			t.Fatal("the observer still samples after its connection closed")
		}
	})
}

// Speed-test echo ticks are excluded: a script that is collapsed only while
// the speed test runs convicts nothing until the test stops.
func TestPlatformTransportH1PathSpeedTestExcludesTicks(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		var phaseLock sync.Mutex
		// 0 healthy, 1 collapsed during the speed test, 2 collapsed after it
		phase := 0
		// the first tick index of phase 1
		collapsedTickIndex := -1
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			phaseLock.Lock()
			defer phaseLock.Unlock()
			if phase == 0 {
				return testingH1PathHealthy
			}
			if collapsedTickIndex < 0 {
				collapsedTickIndex = tickIndex
			}
			return testingH1PathCollapsed
		})
		settings := testingH1PathTransportSettings(H1PathRerollModeObserve, rig)
		transport := testingPlatformTransport(t, ctx, platform.url, settings)

		if !testingWaitForActiveMode(transport, TransportModeH1, 15*time.Second) {
			t.Fatal("the transport was never elected")
		}
		speedControl := func(control byte) {
			dataMessageCount := platform.dataMessages.Load()
			platform.sendBinary([]byte{control, 0, 0, 0, 0})
			// the echo proves the reader handled the control message
			if !waitForCondition(15*time.Second, func() bool {
				return dataMessageCount < platform.dataMessages.Load()
			}) {
				t.Fatalf("the speed control %d was not echoed", control)
			}
		}

		speedControl(TransportControlSpeedStart)
		func() {
			phaseLock.Lock()
			defer phaseLock.Unlock()
			phase = 1
		}()
		// twice the conviction window of collapsed samples, all excluded
		excludedTickCount := 2 * settings.H1PathReroll.WindowTicks
		if !waitForCondition(15*time.Second, func() bool {
			phaseLock.Lock()
			startIndex := collapsedTickIndex
			phaseLock.Unlock()
			return 0 <= startIndex && startIndex+excludedTickCount <= len(rig.connectionDecisions(0))
		}) {
			t.Fatal("the connection stopped ticking during the speed test")
		}
		phaseLock.Lock()
		startIndex := collapsedTickIndex
		phaseLock.Unlock()
		// a sample is recorded before its decision, so samples read second
		// cover every decision
		decisions := rig.connectionDecisions(0)
		samples := rig.connectionRealSamples(0)
		for i, decision := range decisions[startIndex:] {
			if decision.convicted {
				t.Fatalf("tick %d convicted during the speed test: %+v", startIndex+i, decision)
			}
			if !samples[startIndex+i].speedTestActive {
				t.Fatalf("tick %d did not see the speed test", startIndex+i)
			}
		}

		speedControl(TransportControlSpeedStop)
		func() {
			phaseLock.Lock()
			defer phaseLock.Unlock()
			phase = 2
		}()
		if !waitForCondition(15*time.Second, func() bool {
			convictionCount, _ := rig.convictions(0)
			return 1 <= convictionCount
		}) {
			t.Fatal("the collapsed path was not convicted after the speed test stopped")
		}
	})
}

// A reader that finds the receive route full counts it, so the monitor can
// exclude a tick whose delivery was limited by the consumer.
func TestPlatformTransportH1PathCountsReceiveBackpressure(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			return testingH1PathReal
		})
		settings := testingH1PathTransportSettings(H1PathRerollModeObserve, rig)
		settings.TransportBufferSize = 4
		transport := testingPlatformTransport(t, ctx, platform.url, settings)

		if !waitForCondition(15*time.Second, transport.IsConnected) {
			t.Fatal("the transport never connected")
		}
		lastSample := func() (h1PathSample, bool) {
			samples := rig.connectionRealSamples(0)
			if len(samples) == 0 {
				return h1PathSample{}, false
			}
			return samples[len(samples)-1], true
		}
		message := make([]byte, 64)
		// nothing reads the route, so it holds exactly its buffer
		for i := 0; i < settings.TransportBufferSize; i += 1 {
			platform.sendBinary(message)
		}
		if !waitForCondition(15*time.Second, func() bool {
			sample, ok := lastSample()
			return ok && sample.readMessageCount == uint64(settings.TransportBufferSize)
		}) {
			t.Fatal("the reader did not deliver the buffered messages")
		}
		if sample, _ := lastSample(); sample.receiveFullCount != 0 ||
			sample.readByteCount != uint64(settings.TransportBufferSize*len(message)) {
			t.Fatalf("sample = %+v, want no backpressure and every payload byte counted", sample)
		}

		platform.sendBinary(message)
		if !waitForCondition(15*time.Second, func() bool {
			sample, ok := lastSample()
			return ok && sample.receiveFullCount == 1
		}) {
			t.Fatal("the reader did not count the full receive route")
		}
		if sample, _ := lastSample(); sample.readMessageCount != uint64(settings.TransportBufferSize) {
			t.Fatalf("read message count = %d while the route is full", sample.readMessageCount)
		}
	})
}

// The effective mode is resolved before this (see
// TestH1PathEffectiveModePrecedence); eligibility is what the connection's own
// shape allows.
func TestH1PathEligibility(t *testing.T) {
	extenderIp := netip.MustParseAddr("192.0.2.7")
	for _, c := range []struct {
		name            string
		mode            H1PathRerollMode
		generator       bool
		proxied         bool
		extenderIp      netip.Addr
		wantMode        H1PathRerollMode
		wantObserveOnly bool
	}{
		{name: "act", mode: H1PathRerollModeAct, wantMode: H1PathRerollModeAct},
		{name: "observe", mode: H1PathRerollModeObserve, wantMode: H1PathRerollModeObserve},
		{name: "off", mode: H1PathRerollModeOff, wantMode: H1PathRerollModeOff},
		{name: "unknown mode", mode: H1PathRerollMode(7), wantMode: H1PathRerollModeOff},
		{name: "control only", mode: H1PathRerollModeAct, generator: true, wantMode: H1PathRerollModeOff},
		{name: "extender", mode: H1PathRerollModeAct, extenderIp: extenderIp, wantMode: H1PathRerollModeAct, wantObserveOnly: true},
		{name: "proxy", mode: H1PathRerollModeAct, proxied: true, wantMode: H1PathRerollModeAct, wantObserveOnly: true},
	} {
		settings := DefaultPlatformTransportSettings()
		// the settings mode is not read here: the effective mode is the input
		settings.H1PathReroll.Mode = H1PathRerollModeOff
		if c.generator {
			settings.TransportGenerator = func() (Transport, Transport) {
				return NewSendClientTransport(DestinationId(ControlId)), NewReceiveGatewayTransport()
			}
		}
		mode, observeOnly := h1PathConnectionMode(settings, c.mode, c.proxied, c.extenderIp)
		if mode != c.wantMode || (mode != H1PathRerollModeOff && observeOnly != c.wantObserveOnly) {
			t.Errorf("%s: mode = %s, observe only = %t; want %s, %t", c.name, mode, observeOnly, c.wantMode, c.wantObserveOnly)
		}
	}
}

// A window client's transports share one baseline across migration
// generations: the generator installs it on the window's own settings copy,
// never on the generated settings another window may share.
func TestApiMultiClientGeneratorWindowSharesOneH1PathBaseline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	generatedSettings := DefaultPlatformTransportSettings()
	generatorSettings := DefaultApiMultiClientGeneratorSettings()
	generatorSettings.PlatformTransportSettingsGenerator = func() *PlatformTransportSettings {
		return generatedSettings
	}
	generatorSettings.PlatformTransportMode = TransportModeH1
	createdTransports := make(chan *PlatformTransport, 1)
	generatorSettings.PlatformTransportCreated = func(client *Client, transport *PlatformTransport) {
		createdTransports <- transport
	}
	generator := NewApiMultiClientGenerator(
		ctx,
		nil,
		NewClientStrategyWithDefaults(ctx),
		nil,
		"http://127.0.0.1:1",
		"test-jwt",
		"http://127.0.0.1:1",
		"test-device",
		"test-spec",
		"0.0.0-test",
		nil,
		DefaultClientSettings,
		generatorSettings,
	)
	callCtx, callCancel := context.WithCancel(ctx)
	callCancel()
	clientSettings := DefaultClientSettings()
	clientSettings.ControlPingTimeout = time.Second
	_, err := generator.NewClientContext(
		ctx,
		callCtx,
		&MultiClientGeneratorClientArgs{
			ClientId: NewId(),
			ClientAuth: &ClientAuth{
				ByJwt:      "test-jwt",
				InstanceId: NewId(),
				AppVersion: "0.0.0-test",
			},
		},
		clientSettings,
	)
	if err == nil {
		t.Fatal("canceled setup unexpectedly created a client")
	}
	var transport *PlatformTransport
	select {
	case transport = <-createdTransports:
	default:
		t.Fatal("transport observer was not called")
	}
	windowBaseline := transport.settings.h1PathBaseline
	if windowBaseline == nil || transport.h1PathBaseline != windowBaseline {
		t.Fatal("the window transport does not use its settings' baseline")
	}
	if generatedSettings.h1PathBaseline != nil {
		t.Fatal("the window baseline was installed on the generated settings")
	}
	// a migration replacement is built from the same window settings
	replacementSettings := *transport.settings
	replacementSettings.StartDisabled = true
	replacement := NewPlatformTransportWithTargetMode(
		ctx,
		NewClientStrategyWithDefaults(ctx),
		NewRouteManager(ctx, "h1-path-baseline-replacement"),
		"http://127.0.0.1:1",
		&ClientAuth{InstanceId: NewId()},
		TransportModeH1,
		&replacementSettings,
	)
	defer replacement.Close()
	if replacement.h1PathBaseline != windowBaseline {
		t.Fatal("the replacement generation has a baseline of its own")
	}
}

type testingH1PathLedgerState struct {
	pendingCount    int
	lastReroll      time.Time
	epochUnimproved int
	latchUntil      time.Time
	excludedPorts   []int
}

func testingH1PathLedgerSnapshot(ledger *h1PathLedger) testingH1PathLedgerState {
	ledger.stateLock.Lock()
	defer ledger.stateLock.Unlock()
	return testingH1PathLedgerState{
		pendingCount:    len(ledger.pendingRouteManagerRerollTimes),
		lastReroll:      ledger.lastReroll,
		epochUnimproved: ledger.epochUnimproved,
		latchUntil:      ledger.latchUntil,
		excludedPorts:   append([]int{}, ledger.excludedPorts...),
	}
}

// Requires that the connection convicted exactly once and was re-rolled by
// that conviction: its watcher returned, so nothing followed.
func testingH1PathRequireRerolled(t *testing.T, rig *testingH1PathRig, connectionOrdinal int) {
	t.Helper()
	decisions := rig.connectionDecisions(connectionOrdinal)
	convictionCount, _ := rig.convictions(connectionOrdinal)
	if convictionCount != 1 || len(decisions) == 0 {
		t.Fatalf("connection %d convicted %d times in %d decisions, want once", connectionOrdinal, convictionCount, len(decisions))
	}
	last := decisions[len(decisions)-1]
	if !last.convicted || last.action != h1PathActionReroll {
		t.Fatalf("connection %d ended with %+v, want its conviction re-rolled", connectionOrdinal, last)
	}
}

// Requires that every conviction of the connection was refused for reason.
func testingH1PathRequireSuppressed(t *testing.T, rig *testingH1PathRig, connectionOrdinal int, reason h1PathReason) {
	t.Helper()
	for _, decision := range rig.connectionDecisions(connectionOrdinal) {
		if decision.convicted && (decision.action != h1PathActionSuppressed || decision.reason != reason) {
			t.Fatalf("connection %d conviction %+v, want it suppressed by %s", connectionOrdinal, decision, reason)
		}
	}
}

func testingH1PathWaitForConvictions(t *testing.T, rig *testingH1PathRig, connectionOrdinal int, convictionCount int) {
	t.Helper()
	if !waitForCondition(15*time.Second, func() bool {
		count, decisionCountAfter := rig.convictions(connectionOrdinal)
		return convictionCount <= count && 0 < decisionCountAfter
	}) {
		count, _ := rig.convictions(connectionOrdinal)
		t.Fatalf("connection %d convicted %d times, want %d followed by another tick (connections %v)", connectionOrdinal, count, convictionCount, rig.dials())
	}
}

// Restores the process override when the test ends. Registered before the
// transport, so it runs after the transport is closed.
func testingH1PathRestoreModeOverride(t *testing.T) {
	t.Helper()
	previousMode, previousSet := H1PathRerollModeOverride()
	t.Cleanup(func() {
		if previousSet {
			SetH1PathRerollModeOverride(previousMode)
		} else {
			ClearH1PathRerollModeOverride()
		}
	})
}

// The environment turns on Act for a transport whose settings say Observe, so
// a collapsed connection is re-rolled. The mode does not depend on the address
// family, so these tests run on one.
func TestPlatformTransportH1PathEnvironmentActOverridesSettings(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := newRecordingLogger()
	t.Setenv(H1PathRerollModeEnv, "act")
	platform := newTestingPlatformServer(t)
	rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
		if connectionOrdinal == 0 {
			return testingH1PathCollapsed
		}
		return testingH1PathHealthy
	})
	settings := testingH1PathTransportSettings(H1PathRerollModeObserve, rig)
	settings.Log = log
	transport := testingPlatformTransport(t, ctx, platform.url, settings)

	if !waitForCondition(15*time.Second, func() bool {
		return settings.H1PathReroll.CleanTicks <= len(rig.connectionDecisions(1))
	}) {
		t.Fatalf("connections %v, want the convicted connection re-rolled by the environment", rig.dials())
	}
	testingH1PathRequireRerolled(t, rig, 0)
	if stats := rig.stats.snapshot(); stats.Rerolls != 1 || stats.RerollDials != 1 {
		t.Fatalf("stats = %+v, want one re-roll", stats)
	}
	if !transport.IsConnected() {
		t.Fatal("the transport is not connected after the re-roll")
	}
	// one line per transport, however many connections resolved the mode
	if lines := log.linesWith("[t]h1 path mode=act source=env"); len(lines) != 1 {
		t.Fatalf("mode lines = %v, want exactly one", lines)
	}
}

// The process override wins over the environment: with the environment asking
// for Act and the override for Observe, convictions are observed and the
// connection stays.
func TestPlatformTransportH1PathOverrideBeatsEnvironment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := newRecordingLogger()
	t.Setenv(H1PathRerollModeEnv, "act")
	testingH1PathRestoreModeOverride(t)
	SetH1PathRerollModeOverride(H1PathRerollModeObserve)

	platform := newTestingPlatformServer(t)
	rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
	settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
	settings.Log = log
	transport := testingPlatformTransport(t, ctx, platform.url, settings)

	testingH1PathWaitForConvictions(t, rig, 0, 2)
	if dials := rig.dials(); len(dials) != 1 {
		t.Fatalf("connections %v, want [0]: the override observed the convictions", dials)
	}
	stats := rig.stats.snapshot()
	if stats.Rerolls != 0 || stats.RerollDials != 0 || stats.SuppressedObserve < 2 {
		t.Fatalf("stats = %+v, want every conviction observed", stats)
	}
	if !transport.IsConnected() {
		t.Fatal("the transport lost its connection")
	}
	if lines := log.linesWith("[t]h1 path mode=observe source=override"); len(lines) != 1 {
		t.Fatalf("mode lines = %v, want exactly one", lines)
	}
}

// An override set to Off after a connection is running stops the monitor at
// the next dial: the replacement publishes no observer and is not counted.
func TestPlatformTransportH1PathOverrideOffStopsTheNextConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testingH1PathRestoreModeOverride(t)
	ClearH1PathRerollModeOverride()

	platform := newTestingPlatformServer(t)
	rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
	settings := testingH1PathTransportSettings(H1PathRerollModeObserve, rig)
	transport := testingPlatformTransport(t, ctx, platform.url, settings)

	if !waitForCondition(15*time.Second, func() bool {
		observer, published := testingH1PathPublishedObserver(transport)
		return published && observer != nil
	}) {
		t.Fatal("the first connection published no observer")
	}
	if stats := rig.stats.snapshot(); stats.ConnectionsMonitored != 1 {
		t.Fatalf("stats = %+v, want the first connection monitored", stats)
	}

	SetH1PathRerollModeOverride(H1PathRerollModeOff)
	transport.Kick()
	if !waitForCondition(15*time.Second, func() bool {
		observer, published := testingH1PathPublishedObserver(transport)
		return published && observer == nil
	}) {
		t.Fatal("the connection after the override still publishes an observer")
	}
	if dials := rig.dials(); len(dials) != 1 {
		t.Fatalf("connections %v, want [0]: the second connection is not monitored", dials)
	}
	stats := rig.stats.snapshot()
	if stats.ConnectionsMonitored != 1 || stats.ConnectionsDormant != 0 || stats.Rerolls != 0 {
		t.Fatalf("stats = %+v, want only the first connection monitored", stats)
	}
}

// The watcher that ticks the monitor is also what closes the connection for a
// kick, so an error under the tick stops the monitor and nothing else: the
// connection carries on, its ticker stops, and a later kick still closes it and
// re-dials. Without the containment the whole watcher unwinds and the
// connection rides on with nothing left to close it.
func TestPlatformTransportH1PathMonitorErrorLeavesTheConnectionKickable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	platform := newTestingPlatformServer(t)
	rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
	// every tick of the first connection fails inside the monitor
	rig.samplePanic = func(connectionOrdinal int, tickIndex int) bool {
		return connectionOrdinal == 0
	}
	settings := testingH1PathTransportSettings(H1PathRerollModeObserve, rig)
	transport := testingPlatformTransport(t, ctx, platform.url, settings)

	if !waitForCondition(15*time.Second, func() bool {
		return 1 <= rig.stats.snapshot().MonitorStopped
	}) {
		t.Errorf("stats = %+v, want the monitor error counted once", rig.stats.snapshot())
	}
	if !transport.IsConnected() {
		t.Error("the connection went down with its monitor")
	}
	// the ticker is stopped for good, so no further sample is taken
	sampleCount := len(rig.connectionRealSamples(0))
	time.Sleep(10 * settings.H1PathReroll.TickInterval)
	if after := len(rig.connectionRealSamples(0)); after != sampleCount {
		t.Errorf("the monitor took %d more samples after it failed", after-sampleCount)
	}
	if dials := rig.dials(); len(dials) != 1 {
		t.Fatalf("connections %v, want [0]: the failure re-dialed on its own", dials)
	}

	// the kick the watcher owes: it closes this connection and the loop
	// re-dials, which is exactly what a dead watcher can no longer do
	transport.Kick()
	if !waitForCondition(15*time.Second, func() bool {
		return 2 <= len(rig.dials())
	}) {
		t.Fatalf("connections %v after a kick, want the connection with the failed monitor closed and re-dialed", rig.dials())
	}
	if !waitForCondition(15*time.Second, transport.IsConnected) {
		t.Fatal("the transport never reconnected after the kick")
	}
	if stats := rig.stats.snapshot(); stats.MonitorStopped != 1 {
		t.Errorf("stats = %+v, want exactly one stopped monitor", stats)
	}
}

// The environment forces the per-tick log of a monitored connection.
func TestPlatformTransportH1PathLogTicksEnvironment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := newRecordingLogger()
	t.Setenv(H1PathRerollLogTicksEnv, "1")
	platform := newTestingPlatformServer(t)
	rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
	settings := testingH1PathTransportSettings(H1PathRerollModeObserve, rig)
	settings.Log = log
	if settings.H1PathReroll.LogTicks {
		t.Fatal("the test settings already log every tick")
	}
	testingPlatformTransport(t, ctx, platform.url, settings)

	if !waitForCondition(15*time.Second, func() bool {
		return 5 <= len(rig.connectionDecisions(0))
	}) {
		t.Fatal("the connection did not tick")
	}
	decisionCount := len(rig.connectionDecisions(0))
	// each tick logs before the decision reaches the rig
	if lines := log.linesWith("[t]h1path tick connection=0"); len(lines) < decisionCount {
		t.Fatalf("tick lines = %d for %d decisions", len(lines), decisionCount)
	}
}

// A convicted connection is closed and re-dialed at once, without the
// reconnect backoff: with an hour of ReconnectTimeout, the backoff on a young
// connection would draw a wait of up to an hour.
func TestPlatformTransportH1PathRerollRedialsWithoutBackoff(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			if connectionOrdinal == 0 {
				return testingH1PathCollapsed
			}
			return testingH1PathHealthy
		})
		settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
		settings.ReconnectTimeout = time.Hour
		transport := testingPlatformTransport(t, ctx, platform.url, settings)

		if !waitForCondition(15*time.Second, func() bool {
			return 2 <= len(rig.dials())
		}) {
			t.Fatalf("connections %v, want the convicted connection re-dialed", rig.dials())
		}
		// the replacement runs healthy for twice its clean window
		if !waitForCondition(15*time.Second, func() bool {
			return 2*settings.H1PathReroll.CleanTicks <= len(rig.connectionDecisions(1))
		}) {
			t.Fatal("the replacement connection stopped ticking")
		}
		if dials := rig.dials(); len(dials) != 2 || dials[0] != 0 || dials[1] != 1 {
			t.Fatalf("connections %v, want [0 1]", dials)
		}
		testingH1PathRequireRerolled(t, rig, 0)
		if convictionCount, _ := rig.convictions(1); convictionCount != 0 {
			t.Fatalf("the healthy replacement convicted %d times", convictionCount)
		}
		stats := rig.stats.snapshot()
		if stats.RxConvictions != 1 || stats.Rerolls != 1 || stats.RerollDials != 1 || stats.ConnectionsMonitored != 2 {
			t.Fatalf("stats = %+v, want one conviction, one re-roll and one re-roll dial", stats)
		}
		if !transport.IsConnected() {
			t.Fatal("the transport is not connected after the re-roll")
		}
		if !testingWaitForActiveMode(transport, TransportModeH1, 15*time.Second) {
			mode, _ := transport.activeMode()
			t.Fatalf("active mode = %q after the re-roll, want h1", mode)
		}
	})
}

// With the Kernel source port policy a re-roll dial carries no plan: the
// kernel chooses the local port and nothing is bound or counted.
func TestPlatformTransportH1PathKernelSourcePortPolicyDoesNotBind(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			if connectionOrdinal == 0 {
				return testingH1PathCollapsed
			}
			return testingH1PathHealthy
		})
		settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
		settings.H1PathReroll.SourcePortPolicy = H1SourcePortKernel
		randomCount := 0
		settings.h1PathTestHooks.sourcePortRandom = func(n int) int {
			randomCount += 1
			return 0
		}
		testingPlatformTransport(t, ctx, platform.url, settings)

		if !waitForCondition(15*time.Second, func() bool {
			return settings.H1PathReroll.CleanTicks <= len(rig.connectionDecisions(1))
		}) {
			t.Fatalf("connections %v, want the convicted connection re-dialed", rig.dials())
		}
		testingH1PathRequireRerolled(t, rig, 0)
		stats := rig.stats.snapshot()
		if stats.RerollDials != 1 || stats.SourcePortBinds != 0 || stats.SourcePortFallbacks != 0 || randomCount != 0 {
			t.Fatalf("stats = %+v with %d draws, want an unplanned re-roll dial", stats, randomCount)
		}
	})
}

// Two re-rolls whose replacements convict again latch the ledger: the third
// connection's convictions are refused and it stays. A network change starts a
// new epoch but leaves a latch younger than LatchMinAgeForNetworkReset.
func TestPlatformTransportH1PathRerollLatchesAfterUnimproved(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
		settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
		settings.H1PathReroll.DeviceRerollSpacing = 50 * time.Millisecond
		settings.H1PathReroll.LatchMinAgeForNetworkReset = time.Hour
		transport := testingPlatformTransport(t, ctx, platform.url, settings)

		testingH1PathWaitForConvictions(t, rig, 2, 2)
		if dials := rig.dials(); len(dials) != 3 {
			t.Fatalf("connections %v, want 3: two re-rolls, then the latch", dials)
		}
		testingH1PathRequireRerolled(t, rig, 0)
		testingH1PathRequireRerolled(t, rig, 1)
		testingH1PathRequireSuppressed(t, rig, 2, h1PathReasonLatched)
		stats := rig.stats.snapshot()
		if stats.Rerolls != 2 || stats.Unimproved != 2 || stats.SuppressedLatched < 2 || stats.Improved != 0 {
			t.Fatalf("stats = %+v, want two unimproved re-rolls and the latch refusing", stats)
		}
		if state := testingH1PathLedgerSnapshot(rig.ledger); !time.Now().Before(state.latchUntil) {
			t.Fatalf("ledger = %+v, want latched", state)
		}

		// the host's network change: the process ledger and the transport both
		// subscribe to it; this test's ledger is private, so both are called
		rig.ledger.networkChanged(time.Now())
		transport.Kick()
		testingH1PathWaitForConvictions(t, rig, 3, 2)
		if dials := rig.dials(); len(dials) != 4 {
			t.Fatalf("connections %v, want 4: the kick's re-dial only", dials)
		}
		testingH1PathRequireSuppressed(t, rig, 3, h1PathReasonLatched)
		if stats := rig.stats.snapshot(); stats.Rerolls != 2 {
			t.Fatalf("re-rolls = %d after a network change under a young latch", stats.Rerolls)
		}
	})
}

// A network change clears a latch at least LatchMinAgeForNetworkReset old:
// re-rolls resume, and two more unimproved ones latch again.
func TestPlatformTransportH1PathRerollLatchClearsOnNetworkChangeOnceOld(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		var armedLock sync.Mutex
		// connections from the network change on are healthy until armed, so
		// none can convict between the ledger's epoch change and the kick
		armed := false
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			armedLock.Lock()
			defer armedLock.Unlock()
			if 3 <= connectionOrdinal && !armed {
				return testingH1PathHealthy
			}
			return testingH1PathCollapsed
		})
		settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
		settings.H1PathReroll.DeviceRerollSpacing = 50 * time.Millisecond
		settings.H1PathReroll.LatchMinAgeForNetworkReset = 0
		transport := testingPlatformTransport(t, ctx, platform.url, settings)

		testingH1PathWaitForConvictions(t, rig, 2, 1)
		testingH1PathRequireSuppressed(t, rig, 2, h1PathReasonLatched)

		transport.Kick()
		if !waitForCondition(15*time.Second, func() bool {
			return 4 <= len(rig.dials())
		}) {
			t.Fatalf("connections %v, want the kick's re-dial", rig.dials())
		}
		rig.ledger.networkChanged(time.Now())
		func() {
			armedLock.Lock()
			defer armedLock.Unlock()
			armed = true
		}()

		testingH1PathWaitForConvictions(t, rig, 5, 1)
		if dials := rig.dials(); len(dials) != 6 {
			t.Fatalf("connections %v, want 6: two more re-rolls, then the latch again", dials)
		}
		testingH1PathRequireRerolled(t, rig, 3)
		testingH1PathRequireRerolled(t, rig, 4)
		testingH1PathRequireSuppressed(t, rig, 5, h1PathReasonLatched)
		// connections 0, 1, 3 and 4 re-rolled, and each replacement's conviction
		// resolved its predecessor's re-roll as unimproved
		if stats := rig.stats.snapshot(); stats.Rerolls != 4 || stats.Unimproved != 4 {
			t.Fatalf("stats = %+v, want four re-rolls, all unimproved", stats)
		}
	})
}

// Observe convicts without touching the ledger.
func TestPlatformTransportH1PathObserveModeNeverRedials(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
		settings := testingH1PathTransportSettings(H1PathRerollModeObserve, rig)
		testingPlatformTransport(t, ctx, platform.url, settings)

		testingH1PathWaitForConvictions(t, rig, 0, 2)
		if dials := rig.dials(); len(dials) != 1 {
			t.Fatalf("connections %v, want [0]", dials)
		}
		if stats := rig.stats.snapshot(); stats.Rerolls != 0 || stats.RerollDials != 0 || stats.SuppressedObserve < 2 {
			t.Fatalf("stats = %+v, want observed convictions only", stats)
		}
		if state := testingH1PathLedgerSnapshot(rig.ledger); state.pendingCount != 0 ||
			!state.lastReroll.IsZero() || len(state.excludedPorts) != 0 {
			t.Fatalf("ledger = %+v, want untouched", state)
		}
	})
}

// A planned re-roll dial whose bind falls back keeps the kernel's port, which
// on linux is a few ports from the one just convicted -- inside the window the
// plan exists to avoid, so the 4-tuple never moved. The replacement is
// suppressed by its source port, because spending another re-roll would draw
// from the same broken plan. The re-roll that produced it is charged
// unimproved all the same: it spent a break-before-make disconnect and moved
// nothing, and a device that can never move its source port would otherwise
// pay one disconnect an epoch for ever against no budget at all.
//
// The fallback is forced the way a full ephemeral range would: an exclude
// radius that covers the range leaves the plan no port to pick, so the dial
// gets the kernel's.
func TestPlatformTransportH1PathUnmovedSourcePortChargesButDoesNotReroll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	platform := newTestingPlatformServer(t)
	rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
	settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
	// wide enough that every ephemeral port is inside the window of the
	// convicted one
	settings.H1PathReroll.SourcePortExcludeRadius = 65535
	testingPlatformTransport(t, ctx, platform.url, settings)

	// the first connection re-rolls, and the replacement cannot leave the
	// window
	if !waitForCondition(15*time.Second, func() bool {
		return 2 <= len(rig.dials()) && 1 <= rig.stats.snapshot().SourcePortUnmoved
	}) {
		t.Fatalf("connections %v, stats = %+v; want a replacement inside the excluded window", rig.dials(), rig.stats.snapshot())
	}
	testingH1PathRequireRerolled(t, rig, 0)
	testingH1PathWaitForConvictions(t, rig, 1, 2)
	testingH1PathRequireSuppressed(t, rig, 1, h1PathReasonSourcePort)

	// no second re-roll, whatever the replacement reads
	if dials := rig.dials(); len(dials) != 2 {
		t.Fatalf("connections %v, want [0 1]: the unmoved replacement re-rolled again", dials)
	}
	stats := rig.stats.snapshot()
	if stats.Rerolls != 1 || stats.SourcePortFallbacks == 0 || stats.SourcePortBinds != 0 {
		t.Fatalf("stats = %+v, want one re-roll whose plan fell back", stats)
	}
	if stats.SuppressedSourcePort < 2 || stats.Unimproved != 1 || stats.Improved != 0 {
		t.Fatalf("stats = %+v, want the unmoved re-roll charged unimproved once", stats)
	}
	if stats.ConnectionsConvicted != 2 {
		t.Fatalf("stats = %+v, want both connections counted convicted once each", stats)
	}
	// the re-roll is resolved rather than left to age out, and one unimproved
	// re-roll is under the latch
	if state := testingH1PathLedgerSnapshot(rig.ledger); state.pendingCount != 0 ||
		state.epochUnimproved != 1 || !state.latchUntil.IsZero() {
		t.Fatalf("ledger = %+v, want the re-roll resolved and the epoch under the latch", state)
	}
}

// A provider asking for Act without AllowProviderAct is observed: its re-dial
// would count against its reliability.
func TestPlatformTransportH1PathProviderRoleClampsToObserve(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
		settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
		settings.H1PathReroll.Role = H1PathRerollRoleProvider
		testingPlatformTransport(t, ctx, platform.url, settings)

		testingH1PathWaitForConvictions(t, rig, 0, 2)
		if dials := rig.dials(); len(dials) != 1 {
			t.Fatalf("connections %v, want [0]", dials)
		}
		for _, decision := range rig.connectionDecisions(0) {
			if decision.convicted && decision.action != h1PathActionObserve {
				t.Fatalf("provider conviction %+v, want it observed", decision)
			}
		}
		if stats := rig.stats.snapshot(); stats.Rerolls != 0 || stats.SuppressedObserve < 2 || stats.SuppressedRole != 0 {
			t.Fatalf("stats = %+v, want the provider clamped to Observe", stats)
		}
		if state := testingH1PathLedgerSnapshot(rig.ledger); state.pendingCount != 0 || !state.lastReroll.IsZero() {
			t.Fatalf("ledger = %+v, want untouched", state)
		}
	})
}

// A provider process declares its role in the environment, which is the only
// way the clamp can reach a transport whose settings a host built: an operator
// who sets the mode to act in a provider process gets Observe, not a re-roll
// under the client gates.
func TestPlatformTransportH1PathProviderEnvironmentClampsToObserve(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testingH1PathRestoreModeOverride(t)
	ClearH1PathRerollModeOverride()
	t.Setenv(H1PathRerollModeEnv, "act")
	t.Setenv(H1PathRerollRoleEnv, "provider")

	platform := newTestingPlatformServer(t)
	rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
	// the settings say what a host's settings say: a client that may act
	settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)

	testingPlatformTransport(t, ctx, platform.url, settings)

	testingH1PathWaitForConvictions(t, rig, 0, 2)
	if dials := rig.dials(); len(dials) != 1 {
		t.Fatalf("connections %v, want [0]: the provider re-rolled", dials)
	}
	for _, decision := range rig.connectionDecisions(0) {
		if decision.convicted && decision.action != h1PathActionObserve {
			t.Fatalf("provider conviction %+v, want it observed", decision)
		}
	}
	if stats := rig.stats.snapshot(); stats.Rerolls != 0 || stats.SuppressedObserve < 2 {
		t.Fatalf("stats = %+v, want the provider clamped to Observe", stats)
	}
	if state := testingH1PathLedgerSnapshot(rig.ledger); state.pendingCount != 0 || !state.lastReroll.IsZero() {
		t.Fatalf("ledger = %+v, want untouched", state)
	}
}

// An allowed provider that acts goes through the provider gates, which the
// client gates do not have: a connection younger than ProviderMinConnectionAge
// is refused however convincing its collapse.
func TestPlatformTransportH1PathProviderEnvironmentAppliesTheProviderGates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testingH1PathRestoreModeOverride(t)
	ClearH1PathRerollModeOverride()
	t.Setenv(H1PathRerollRoleEnv, "provider")

	platform := newTestingPlatformServer(t)
	rig := newTestingH1PathRig(testingH1PathCollapsedAlways)
	settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
	settings.H1PathReroll.AllowProviderAct = true

	testingPlatformTransport(t, ctx, platform.url, settings)

	testingH1PathWaitForConvictions(t, rig, 0, 2)
	if dials := rig.dials(); len(dials) != 1 {
		t.Fatalf("connections %v, want [0]: a young provider connection re-rolled", dials)
	}
	testingH1PathRequireSuppressed(t, rig, 0, h1PathReasonProviderGate)
	if stats := rig.stats.snapshot(); stats.Rerolls != 0 || stats.SuppressedProviderGate < 2 {
		t.Fatalf("stats = %+v, want the provider gate refusing", stats)
	}
}

// A re-roll closes only the H1 connection. It does not kick the transport,
// which would also close H3, reset the pinned backoff and re-evaluate the
// family hold; a kick still re-dials H1 as before.
func TestPlatformTransportH1PathRerollDoesNotTouchH3Carrier(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		var armedLock sync.Mutex
		armed := false
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			armedLock.Lock()
			defer armedLock.Unlock()
			if connectionOrdinal == 0 && armed {
				return testingH1PathCollapsed
			}
			return testingH1PathHealthy
		})
		settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
		settings.PlatformTransportBudget = NewPlatformTransportBudget(mib(64), 8)
		settings.H1BudgetByteCount = kib(64)
		settings.H3BudgetByteCount = kib(64)
		settings.ModePreferences = map[TransportMode]int{
			TransportModeH1: 1,
			TransportModeH3: 2,
		}
		h3Ctxs := make(chan context.Context, 1)
		settings.runH3ModeForTest = func(ctx context.Context, mode TransportMode, _ time.Duration) {
			select {
			case h3Ctxs <- ctx:
			default:
			}
			<-ctx.Done()
		}
		transport := NewPlatformTransportWithTargetMode(
			ctx,
			NewClientStrategyWithDefaults(ctx),
			NewRouteManager(ctx, "h1-path-h3"),
			platform.url,
			&ClientAuth{
				ByJwt:      "testing",
				InstanceId: NewId(),
				AppVersion: "testing",
			},
			TransportModeAuto,
			settings,
		)
		t.Cleanup(transport.Close)

		var h3Ctx context.Context
		select {
		case h3Ctx = <-h3Ctxs:
		case <-time.After(15 * time.Second):
			t.Fatal("the H3 carrier never started")
		}
		if !testingWaitForActiveMode(transport, TransportModeH1, 15*time.Second) {
			t.Fatal("h1 was never elected")
		}
		kick := transport.kickMonitor.NotifyChannel()
		func() {
			armedLock.Lock()
			defer armedLock.Unlock()
			armed = true
		}()

		if !waitForCondition(15*time.Second, func() bool {
			return 2 <= len(rig.dials()) && 0 < len(rig.connectionDecisions(1))
		}) {
			t.Fatalf("connections %v, want the H1 connection re-rolled", rig.dials())
		}
		testingH1PathRequireRerolled(t, rig, 0)
		select {
		case <-kick:
			t.Fatal("the re-roll kicked the transport")
		default:
		}
		if h3Ctx.Err() != nil {
			t.Fatal("the re-roll closed the H3 carrier")
		}

		transport.Kick()
		select {
		case <-kick:
		default:
			t.Fatal("the control kick did not notify")
		}
		if !waitForCondition(15*time.Second, func() bool {
			return 3 <= len(rig.dials())
		}) {
			t.Fatalf("connections %v, want the kick to re-dial H1", rig.dials())
		}
		if stats := rig.stats.snapshot(); stats.Rerolls != 1 || stats.RerollDials != 1 {
			t.Fatalf("stats = %+v, want one re-roll dial; the kick's dial is not one", stats)
		}
	})
}

// A replacement that runs clean for CleanTicks resolves its re-roll as
// improved and clears the pending entry.
func TestPlatformTransportH1PathImprovementClearsPending(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			if connectionOrdinal == 0 {
				return testingH1PathCollapsed
			}
			return testingH1PathHealthy
		})
		settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
		transport := testingPlatformTransport(t, ctx, platform.url, settings)

		if !waitForCondition(15*time.Second, func() bool {
			return rig.stats.Improved.Load() == 1
		}) {
			t.Fatalf("stats = %+v, want the re-roll improved", rig.stats.snapshot())
		}
		testingH1PathRequireRerolled(t, rig, 0)
		cleanTickCount := 0
		for _, decision := range rig.connectionDecisions(1) {
			if decision.clean {
				cleanTickCount += 1
			}
		}
		if cleanTickCount < settings.H1PathReroll.CleanTicks {
			t.Fatalf("improved after %d clean ticks, want at least %d", cleanTickCount, settings.H1PathReroll.CleanTicks)
		}
		if stats := rig.stats.snapshot(); stats.Rerolls != 1 || stats.Unimproved != 0 || stats.Unresolved != 0 {
			t.Fatalf("stats = %+v, want one re-roll resolved as improved", stats)
		}
		if state := testingH1PathLedgerSnapshot(rig.ledger); state.pendingCount != 0 || state.epochUnimproved != 0 {
			t.Fatalf("ledger = %+v, want no pending re-roll", state)
		}
		if !transport.IsConnected() {
			t.Fatal("the improved replacement is not connected")
		}
	})
}

// A re-roll resolves as improved when the replacement stops collapsing, not
// when it reaches the thin rate. Thin is 28 Mb/s on this path, so a rate bar
// would leave the credit -- and the unconfirmed budget an improvement returns
// -- unreachable for a session running at 5.6 Mb/s, which is the rate most
// sessions run at and the whole bottom of the population the feature is for.
func TestPlatformTransportH1PathImprovementAtARealUserRate(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			if connectionOrdinal == 0 {
				return testingH1PathCollapsed
			}
			return testingH1PathHealthyThin
		})
		settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
		testingPlatformTransport(t, ctx, platform.url, settings)

		if !waitForCondition(15*time.Second, func() bool {
			return rig.stats.Improved.Load() == 1
		}) {
			t.Fatalf("stats = %+v, want the re-roll improved at a rate under thin", rig.stats.snapshot())
		}
		testingH1PathRequireRerolled(t, rig, 0)
		for _, decision := range rig.connectionDecisions(1) {
			if decision.convicted {
				t.Fatalf("the replacement convicted: %+v", decision)
			}
			if decision.clean && decision.thinByteRate <= decision.byteRate {
				t.Fatalf("the replacement cleared the thin rate, so this test proves nothing: %+v", decision)
			}
		}
		if state := testingH1PathLedgerSnapshot(rig.ledger); state.pendingCount != 0 || state.epochUnimproved != 0 {
			t.Fatalf("ledger = %+v, want no pending re-roll", state)
		}
	})
}

func testingH1PathDecideConnection(mode H1PathRerollMode, observeOnly bool) (*h1PathConnection, *h1PathLedger) {
	settings := DefaultH1PathRerollSettings()
	settings.Mode = mode
	stats := &h1PathStats{}
	ledger := newH1PathLedger()
	ledger.stats = stats
	transport := &PlatformTransport{
		log:            loggerOrDefault(nil),
		routeManager:   NewRouteManager(context.Background(), "h1-path-decide"),
		h1PathBaseline: newH1QueueDelayBaseline(&settings),
	}
	connection := &h1PathConnection{
		transport:   transport,
		settings:    &settings,
		stats:       stats,
		hooks:       &h1PathTestHooks{stats: stats, ledger: ledger},
		mode:        mode,
		observeOnly: observeOnly,
		monitor:     &h1PathMonitor{start: time.Now().Add(-time.Minute)},
		localPort:   50000,
	}
	return connection, ledger
}

func testingH1PathConviction() h1PathDecision {
	return h1PathDecision{
		convicted:  true,
		direction:  h1PathDirectionRx,
		confidence: h1PathConfidenceConfirmed,
		pathRtt:    testingH1PathRtt,
	}
}

// An observe-only connection (an extender or a proxy leg) never re-rolls in
// Act, but its conviction still resolves a pending re-roll as unimproved.
func TestH1PathConnectionObserveOnlyNeverRerolls(t *testing.T) {
	connection, ledger := testingH1PathDecideConnection(H1PathRerollModeAct, true)
	now := time.Now()
	ledger.noteReroll(connection.transport.routeManager, connection.settings, now.Add(-time.Minute), H1PathRerollRoleClient, h1PathConfidenceConfirmed, 0)

	decision := testingH1PathConviction()
	connection.decide(now, &decision)
	if decision.action != h1PathActionObserve {
		t.Fatalf("decision = %+v, want observed", decision)
	}
	stats := connection.stats.snapshot()
	if stats.Rerolls != 0 || stats.SuppressedObserve != 1 || stats.Unimproved != 1 {
		t.Fatalf("stats = %+v, want one observed conviction and the earlier re-roll unimproved", stats)
	}
	if state := testingH1PathLedgerSnapshot(ledger); state.pendingCount != 0 || len(state.excludedPorts) != 0 {
		t.Fatalf("ledger = %+v, want the pending re-roll resolved and no port recorded", state)
	}
}

// Act goes through the ledger in order: a conviction re-rolls and records the
// port and the stale-tag mark, clean ticks resolve it as improved, and the
// device spacing refuses a conviction right after.
func TestH1PathConnectionActRerollsThroughTheLedger(t *testing.T) {
	connection, ledger := testingH1PathDecideConnection(H1PathRerollModeAct, false)
	settings := connection.settings
	// long enough to outlast the clean window below
	settings.DeviceRerollSpacing = time.Minute
	baseline := connection.transport.h1PathBaseline
	sourceId := NewId()
	start := time.Now()
	baseline.observe(sourceId, 50, start)

	decision := testingH1PathConviction()
	connection.decide(start, &decision)
	if decision.action != h1PathActionReroll {
		t.Fatalf("decision = %+v, want a re-roll", decision)
	}
	state := testingH1PathLedgerSnapshot(ledger)
	if state.pendingCount != 1 || !state.lastReroll.Equal(start) || len(state.excludedPorts) != 1 || state.excludedPorts[0] != 50000 {
		t.Fatalf("ledger = %+v, want the re-roll pending with its port", state)
	}
	if baseline.freshAfter(sourceId) == 0 {
		t.Fatal("the re-roll did not mark the baseline's stale tags")
	}

	for i := 1; i <= settings.CleanTicks; i += 1 {
		clean := h1PathDecision{clean: true, pathRtt: testingH1PathRtt}
		connection.decide(start.Add(time.Duration(i)*settings.TickInterval), &clean)
	}
	if stats := connection.stats.snapshot(); stats.Improved != 1 || stats.Rerolls != 1 {
		t.Fatalf("stats = %+v, want the re-roll improved after %d clean ticks", stats, settings.CleanTicks)
	}

	soon := start.Add(time.Duration(settings.CleanTicks+1) * settings.TickInterval)
	refused := testingH1PathConviction()
	connection.decide(soon, &refused)
	if refused.action != h1PathActionSuppressed || refused.reason != h1PathReasonSpacing {
		t.Fatalf("decision = %+v, want refused by device spacing", refused)
	}
	if stats := connection.stats.snapshot(); stats.SuppressedSpacing != 1 || stats.Rerolls != 1 || stats.Unimproved != 0 {
		t.Fatalf("stats = %+v, want one spacing refusal", stats)
	}
}
