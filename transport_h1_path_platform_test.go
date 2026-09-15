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
	// thin delivery behind a 5 s queue, with out-of-order data every tick
	testingH1PathCollapsed testingH1PathClass = 1
	// full rate, no queue
	testingH1PathHealthy testingH1PathClass = 2
)

type testingH1PathRig struct {
	stats *h1PathStats
	// the class of each sample, by connection ordinal and tick index
	class func(connectionOrdinal int, tickIndex int) testingH1PathClass
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
	return &testingH1PathRig{
		stats:       &h1PathStats{},
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
			// a loopback kernel or ack round trip would make every connection dormant
			sample.ackRttMin = 0
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
			case testingH1PathCollapsed:
				sample.rxBytes = uint64(seconds * testingH1PathCollapsedByteRate)
				sample.queueDelay = 5 * time.Second
				sample.rxOoo = uint64(tickIndex)
			case testingH1PathHealthy:
				sample.rxBytes = uint64(seconds * testingH1PathHealthyByteRate)
				sample.queueDelay = 0
				sample.rxOoo = 0
			}
		},
		decision: func(connectionOrdinal int, decision h1PathDecision) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.decisions[connectionOrdinal] = append(self.decisions[connectionOrdinal], decision)
		},
		stats: self.stats,
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

func TestH1PathEligibility(t *testing.T) {
	extenderIp := netip.MustParseAddr("192.0.2.7")
	for _, c := range []struct {
		name            string
		mode            H1PathRerollMode
		role            H1PathRerollRole
		allowProvider   bool
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
		{name: "provider", mode: H1PathRerollModeAct, role: H1PathRerollRoleProvider, wantMode: H1PathRerollModeObserve},
		{name: "provider allowed", mode: H1PathRerollModeAct, role: H1PathRerollRoleProvider, allowProvider: true, wantMode: H1PathRerollModeAct},
		{name: "provider observe", mode: H1PathRerollModeObserve, role: H1PathRerollRoleProvider, wantMode: H1PathRerollModeObserve},
	} {
		settings := DefaultPlatformTransportSettings()
		settings.H1PathReroll.Mode = c.mode
		settings.H1PathReroll.Role = c.role
		settings.H1PathReroll.AllowProviderAct = c.allowProvider
		if c.generator {
			settings.TransportGenerator = func() (Transport, Transport) {
				return NewSendClientTransport(DestinationId(ControlId)), NewReceiveGatewayTransport()
			}
		}
		mode, observeOnly := h1PathConnectionMode(settings, c.proxied, c.extenderIp)
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
