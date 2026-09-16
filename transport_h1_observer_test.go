package connect

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect/protocol"
)

// A one-way H1 route that holds every message for a fixed delay, in order,
// and counts the Transfer packs addressed to destinationId that it delivers.
// Every buffer it holds when cancelled is returned.
func runH1ObserverTestDelayLine(
	ctx context.Context,
	delay time.Duration,
	in Route,
	out Route,
	destinationId Id,
	packCount *atomic.Int64,
) {
	type heldMessage struct {
		message   []byte
		deliverAt time.Time
	}
	queue := []heldMessage{}
	defer func() {
		for _, held := range queue {
			MessagePoolReturn(held.message)
		}
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		if 0 < len(queue) {
			timer.Reset(max(0, time.Until(queue[0].deliverAt)))
		}
		select {
		case <-ctx.Done():
			return
		case message := <-in:
			queue = append(queue, heldMessage{message: message, deliverAt: time.Now().Add(delay)})
		case <-timer.C:
			for 0 < len(queue) && !time.Now().Before(queue[0].deliverAt) {
				held := queue[0]
				// decoded before the send, which hands the buffer to the reader
				pack := h1ObserverTestIsPackFor(held.message, destinationId)
				select {
				case out <- held.message:
					queue = queue[1:]
					if pack {
						packCount.Add(1)
					}
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func h1ObserverTestIsPackFor(message []byte, destinationId Id) bool {
	path, err := FilteredTransferPath(message)
	if err != nil || path.DestinationId != destinationId {
		return false
	}
	transferFrame := &protocol.TransferFrame{}
	if err := proto.Unmarshal(message, transferFrame); err != nil {
		return false
	}
	if transferFrame.Pack != nil {
		return true
	}
	if frame := transferFrame.GetFrame(); frame != nil {
		return frame.GetMessageType() == protocol.MessageType_TransferPack
	}
	return false
}

func h1ObserverTestTagMs(t time.Time) uint64 {
	return uint64(t.UnixMilli())
}

func TestH1RouteObserverQueueDelayAttributionAcrossRoutes(t *testing.T) {
	// the pool's lazy initialiser starts a stats goroutine; touched here so it
	// is born outside the bubble
	MessagePoolReturn(MessagePoolGet(64))

	const messageCount = 64
	synctest.Test(t, func(t *testing.T) {
		assertMessagePoolOwnership(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		newSettings := func() *ClientSettings {
			settings := DefaultClientSettings()
			settings.EncryptionSettings.Mode = EncryptionModeOff
			return settings
		}
		senderId := NewId()
		receiverId := NewId()
		sender := NewClient(ctx, senderId, NewNoContractClientOob(), newSettings())
		receiver := NewClient(ctx, receiverId, NewNoContractClientOob(), newSettings())
		sender.ContractManager().AddNoContractPeer(receiverId)
		receiver.ContractManager().AddNoContractPeer(senderId)

		// the sender writes to two H1 routes, one 200 ms and one 2000 ms from
		// the receiver; acks return on an undelayed route
		sendA := make(Route, messageCount)
		sendB := make(Route, messageCount)
		receiveA := make(Route, messageCount)
		receiveB := make(Route, messageCount)
		returnRoute := make(Route, messageCount)
		packCountA := &atomic.Int64{}
		packCountB := &atomic.Int64{}
		var lines sync.WaitGroup
		lines.Add(2)
		go func() {
			defer lines.Done()
			runH1ObserverTestDelayLine(ctx, 200*time.Millisecond, sendA, receiveA, receiverId, packCountA)
		}()
		go func() {
			defer lines.Done()
			runH1ObserverTestDelayLine(ctx, 2000*time.Millisecond, sendB, receiveB, receiverId, packCountB)
		}()

		// sampled on every frame, sharing one baseline, as the routes of one
		// transport do
		pathSettings := DefaultH1PathRerollSettings()
		baseline := newH1QueueDelayBaseline(&pathSettings)
		observerA := newH1RouteObserver(baseline, 1)
		observerB := newH1RouteObserver(baseline, 1)

		sender.RouteManager().UpdateTransport(NewSendGatewayTransportWithType(TransportTypeH1), []Route{sendA})
		sender.RouteManager().UpdateTransport(NewSendGatewayTransportWithType(TransportTypeH1), []Route{sendB})
		sender.RouteManager().UpdateTransportWithProperties(
			NewReceiveGatewayTransportWithType(TransportTypeH1),
			[]Route{returnRoute},
			TransferCarrierProperties{ReceiveReliability: CarrierReliabilityReliable},
		)
		receiver.RouteManager().UpdateTransportWithProperties(
			NewReceiveGatewayTransportWithType(TransportTypeH1),
			[]Route{receiveA},
			TransferCarrierProperties{ReceiveReliability: CarrierReliabilityReliable, receiveObserver: observerA},
		)
		receiver.RouteManager().UpdateTransportWithProperties(
			NewReceiveGatewayTransportWithType(TransportTypeH1),
			[]Route{receiveB},
			TransferCarrierProperties{ReceiveReliability: CarrierReliabilityReliable, receiveObserver: observerB},
		)
		receiver.RouteManager().UpdateTransport(NewSendGatewayTransportWithType(TransportTypeH1), []Route{returnRoute})

		// application frames are counted by content
		deliveredLock := sync.Mutex{}
		delivered := map[string]bool{}
		receiver.AddReceiveCallback(func(_ TransferPath, frames []*protocol.Frame, _ Peer) {
			for _, frame := range frames {
				message, err := FromFrame(frame)
				if err != nil {
					continue
				}
				if simpleMessage, ok := message.(*protocol.SimpleMessage); ok {
					func() {
						deliveredLock.Lock()
						defer deliveredLock.Unlock()
						delivered[simpleMessage.Content] = true
					}()
				}
			}
		})
		deliveredCount := func() int {
			deliveredLock.Lock()
			defer deliveredLock.Unlock()
			return len(delivered)
		}

		time.Sleep(5 * time.Millisecond)
		// 10 ms apart, so each message is its own pack and the writer's random
		// route choice spreads the packs across both routes
		for i := 0; i < messageCount; i++ {
			frame := RequireToFrameWithDefaultProtocolVersion(
				&protocol.SimpleMessage{Content: fmt.Sprintf("h1-observer-%02d", i)},
			)
			if !sender.SendWithTimeout(frame, receiverId, nil, -1) {
				MessagePoolReturn(frame.MessageBytes)
				t.Fatalf("send %d refused", i)
			}
			time.Sleep(10 * time.Millisecond)
		}
		deadline := time.Now().Add(60 * time.Second)
		for deliveredCount() < messageCount {
			if !time.Now().Before(deadline) {
				t.Fatalf("delivered %d of %d", deliveredCount(), messageCount)
			}
			time.Sleep(10 * time.Millisecond)
		}
		// one tick over the whole exchange, taken with nothing left to read
		synctest.Wait()
		if 0 < len(receiveA) || 0 < len(receiveB) {
			t.Fatalf("the receiver left %d and %d frames unread", len(receiveA), len(receiveB))
		}
		now := time.Now()
		tickA := observerA.takeTick(now)
		tickB := observerB.takeTick(now)

		t.Logf("route A: %d packs, tick %+v; route B: %d packs, tick %+v", packCountA.Load(), tickA, packCountB.Load(), tickB)
		if packCountA.Load() == 0 || packCountB.Load() == 0 || packCountA.Load()+packCountB.Load() < messageCount {
			t.Fatalf("packs per route = %d and %d; want at least %d across both routes", packCountA.Load(), packCountB.Load(), messageCount)
		}
		if !tickA.known || tickA.queueDelay < 0 || 2*time.Millisecond < tickA.queueDelay {
			t.Errorf("route A tick = %+v, want a queue delay of 0-2 ms", tickA)
		}
		if !tickB.known || tickB.queueDelay < 1799*time.Millisecond || 1801*time.Millisecond < tickB.queueDelay {
			t.Errorf("route B tick = %+v, want a queue delay of 1799-1801 ms", tickB)
		}
		if int64(tickA.samples) != packCountA.Load() || int64(tickB.samples) != packCountB.Load() {
			t.Errorf("samples = %d and %d, packs delivered = %d and %d", tickA.samples, tickB.samples, packCountA.Load(), packCountB.Load())
		}
		if tickA.stale != 0 || tickB.stale != 0 {
			t.Errorf("stale = %d and %d with no re-roll", tickA.stale, tickB.stale)
		}

		// the reverse direction: the sender's acks come back on the delayed
		// routes and echo the receiver's own send time
		ackedCount := &atomic.Int64{}
		for i := 0; i < messageCount; i++ {
			frame := RequireToFrameWithDefaultProtocolVersion(
				&protocol.SimpleMessage{Content: fmt.Sprintf("h1-observer-reply-%02d", i)},
			)
			ackCallback := func(err error) {
				if err == nil {
					ackedCount.Add(1)
				}
			}
			if !receiver.SendWithTimeout(frame, senderId, ackCallback, -1) {
				MessagePoolReturn(frame.MessageBytes)
				t.Fatalf("reply %d refused", i)
			}
			time.Sleep(10 * time.Millisecond)
		}
		for ackedCount.Load() < messageCount {
			if !time.Now().Before(deadline) {
				t.Fatalf("acked %d of %d replies", ackedCount.Load(), messageCount)
			}
			time.Sleep(10 * time.Millisecond)
		}
		synctest.Wait()
		now = time.Now()
		// An ack write carries the Pack's inbound carrier as a transport
		// affinity, and a route generation's affinity set is a fixed order, so
		// the ack route is drawn once by the snapshot's shuffle and every ack
		// of this phase takes it. Which route wins says nothing about the
		// observer, but it does decide the order: takeTick folds its own acks
		// into the shared window before reading the minimum back, so the route
		// that carried them goes first and the other route then reports a
		// window it contributed nothing to, which is the sharing under test.
		ackSampleCount := func(observer *h1RouteObserver) int {
			observer.stateLock.Lock()
			defer observer.stateLock.Unlock()
			return observer.ackCount
		}
		type replyRoute struct {
			name     string
			delay    time.Duration
			observer *h1RouteObserver
			tick     h1ObserverTick
		}
		replyRoutes := []*replyRoute{
			{name: "A", delay: 200 * time.Millisecond, observer: observerA},
			{name: "B", delay: 2000 * time.Millisecond, observer: observerB},
		}
		if ackSampleCount(observerA) < ackSampleCount(observerB) {
			replyRoutes[0], replyRoutes[1] = replyRoutes[1], replyRoutes[0]
		}
		ackSamples := 0
		ownAckRttMin := time.Duration(0)
		for _, route := range replyRoutes {
			route.tick = route.observer.takeTick(now)
			t.Logf("replies: route %s (%s) tick %+v", route.name, route.delay, route.tick)
			if route.tick.ackSamples == 0 {
				continue
			}
			ackSamples += route.tick.ackSamples
			if ownAckRttMin == 0 || route.tick.ackRtt < ownAckRttMin {
				ownAckRttMin = route.tick.ackRtt
			}
			// the replies take the undelayed return route, so the round trip
			// is this route's delay plus the two clients' own work
			if route.tick.ackRtt < route.delay || route.delay+50*time.Millisecond < route.tick.ackRtt {
				t.Errorf("route %s ack round trip = %s, want %s and its own work", route.name, route.tick.ackRtt, route.delay)
			}
		}
		// every reply is acked at least once; a repeat ack is allowed
		if ackSamples < messageCount {
			t.Errorf("ack samples = %d across both routes, want at least %d", ackSamples, messageCount)
		}
		// the window is shared by the transport's routes: the tick taken last
		// reports the minimum over every route, whether or not it read an ack
		// of its own
		if replyRoutes[1].tick.ackRttMin != ownAckRttMin {
			t.Errorf("route %s read %s of a shared minimum of %s", replyRoutes[1].name, replyRoutes[1].tick.ackRttMin, ownAckRttMin)
		}

		closeCtx, closeCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer closeCancel()
		if err := sender.CloseAndWait(closeCtx); err != nil {
			t.Errorf("close the sender: %v", err)
		}
		if err := receiver.CloseAndWait(closeCtx); err != nil {
			t.Errorf("close the receiver: %v", err)
		}
		cancel()
		lines.Wait()
		for _, route := range []Route{sendA, sendB, receiveA, receiveB, returnRoute} {
			draining := true
			for draining {
				select {
				case message := <-route:
					MessagePoolReturn(message)
				default:
					draining = false
				}
			}
		}
	})
}

func TestH1RouteObserverSamplesEverySixteenthFrame(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	now := h1PathTestOrigin
	sourceId := NewId()
	cases := []struct {
		sampleEvery int
		inactive    bool
		samples     int
	}{
		{sampleEvery: settings.PackSampleEvery, samples: 10},
		// rounded up to 32
		{sampleEvery: 17, samples: 5},
		{sampleEvery: 1, samples: 160},
		{sampleEvery: 0, samples: 160},
		{sampleEvery: settings.PackSampleEvery, inactive: true, samples: 0},
	}
	for _, c := range cases {
		observer := newH1RouteObserver(newH1QueueDelayBaseline(&settings), c.sampleEvery)
		observer.setActive(!c.inactive)
		sampled := 0
		for i := 0; i < 160; i++ {
			if observer.sampleNext() {
				sampled += 1
				observer.observePack(sourceId, h1ObserverTestTagMs(now.Add(-200*time.Millisecond)), now)
			}
		}
		tick := observer.takeTick(now)
		if sampled != c.samples || tick.samples != c.samples || tick.known != (0 < c.samples) {
			t.Errorf("sample every %d (inactive %t): sampled %d, tick %+v; want %d samples",
				c.sampleEvery, c.inactive, sampled, tick, c.samples)
		}
	}
}

func TestH1RouteObserverExcludesPreRerollTags(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	sourceId := NewId()
	now := h1PathTestOrigin
	rerollTime := now.Add(time.Second)
	afterReroll := rerollTime.Add(500 * time.Millisecond)

	// packs of the retired window: built before the re-roll and resent after
	// it with their old tags, the newest 2 s old when read
	observeRetiredWindow := func(observer *h1RouteObserver) {
		for i := 0; i < 8; i++ {
			tag := rerollTime.Add(-1500*time.Millisecond - time.Duration(i)*10*time.Millisecond)
			observer.observePack(sourceId, h1ObserverTestTagMs(tag), afterReroll)
		}
	}
	establishBaseline := func(observer *h1RouteObserver) {
		for i := 0; i < 4; i++ {
			observer.observePack(sourceId, h1ObserverTestTagMs(now.Add(-200*time.Millisecond)), now)
		}
		if tick := observer.takeTick(now); !tick.known || tick.queueDelay != 0 {
			t.Fatalf("baseline tick = %+v, want a known zero queue delay", tick)
		}
	}

	// control: without the mark the retired window reads as a standing queue
	control := newH1RouteObserver(newH1QueueDelayBaseline(&settings), 1)
	establishBaseline(control)
	observeRetiredWindow(control)
	if tick := control.takeTick(afterReroll); !tick.known || tick.queueDelay != 1800*time.Millisecond || tick.stale != 0 {
		t.Fatalf("unmarked tick = %+v, want a known 1800 ms queue delay", tick)
	}

	baseline := newH1QueueDelayBaseline(&settings)
	observer := newH1RouteObserver(baseline, 1)
	establishBaseline(observer)
	// fresh after the sender clock's reading of the re-roll plus 2 x 100 ms:
	// rerollTime - 200 ms + 200 ms
	baseline.markReroll(rerollTime, 100*time.Millisecond)
	if freshAfter := baseline.freshAfter(sourceId); freshAfter != h1ObserverTestTagMs(rerollTime) {
		t.Fatalf("fresh after tag %d, want %d", freshAfter, h1ObserverTestTagMs(rerollTime))
	}
	observeRetiredWindow(observer)
	// the boundary tag is stale too
	observer.observePack(sourceId, h1ObserverTestTagMs(rerollTime), afterReroll)
	if tick := observer.takeTick(afterReroll); tick.known || tick.samples != 0 || tick.stale != 9 {
		t.Fatalf("marked tick = %+v, want unknown with 9 stale packs", tick)
	}

	// fresh tags count, against the same baseline
	nextTick := afterReroll.Add(500 * time.Millisecond)
	for i := 0; i < 3; i++ {
		observer.observePack(sourceId, h1ObserverTestTagMs(nextTick.Add(-300*time.Millisecond)), nextTick)
	}
	observer.observePack(sourceId, h1ObserverTestTagMs(rerollTime.Add(-time.Second)), nextTick)
	if tick := observer.takeTick(nextTick); !tick.known || tick.samples != 3 || tick.stale != 1 ||
		tick.queueDelay != 100*time.Millisecond {
		t.Fatalf("fresh tick = %+v, want 3 samples, 1 stale and a 100 ms queue delay", tick)
	}
}

// The baseline may rise above a source's floor only at BaselineRisePerMinute.
// The rate is the whole trade: a queue of q stays visible for
// (q - threshold) / rate, and a backward clock step of s on the sender holds a
// queue delay that is not there for s / rate.
func TestH1QueueDelayBaselineRisesAtTheSettingsRate(t *testing.T) {
	// 200 ms of transit on the first tick, then a 6 s standing queue
	queueDelayAt := func(settings *H1PathRerollSettings, elapsed time.Duration) time.Duration {
		baseline := newH1QueueDelayBaseline(settings)
		observer := newH1RouteObserver(baseline, 1)
		sourceId := NewId()
		delay := time.Duration(0)
		for k := 1; k <= int(elapsed/h1PathTestStep); k += 1 {
			now := h1PathTestOrigin.Add(time.Duration(k) * h1PathTestStep)
			rel := 200 * time.Millisecond
			if 1 < k {
				rel += 6 * time.Second
			}
			for i := 0; i < 4; i += 1 {
				observer.observePack(sourceId, h1ObserverTestTagMs(now.Add(-rel)), now)
			}
			tick := observer.takeTick(now)
			if !tick.known {
				t.Fatalf("the tick at %s is unknown", now.Sub(h1PathTestOrigin))
			}
			delay = tick.queueDelay
		}
		return delay
	}

	settings := DefaultH1PathRerollSettings()
	for _, c := range []struct {
		elapsed    time.Duration
		queueDelay time.Duration
	}{
		// inside the bucket window the floor is not the binding half
		{elapsed: time.Minute, queueDelay: 6 * time.Second},
		{elapsed: 10*time.Minute + h1PathTestStep, queueDelay: 5 * time.Second},
		{elapsed: 30*time.Minute + h1PathTestStep, queueDelay: 3 * time.Second},
	} {
		if delay := queueDelayAt(&settings, c.elapsed); delay != c.queueDelay {
			t.Errorf("the queue delay at %s = %s, want %s", c.elapsed, delay, c.queueDelay)
		}
	}

	// without a rate the buckets are the whole baseline, and a queue that
	// outlives them reads as none at all
	settings.BaselineRisePerMinute = 0
	if delay := queueDelayAt(&settings, 5*time.Minute); delay != 0 {
		t.Errorf("without a rise rate the queue delay at 5m = %s, want the buckets to have followed the queue", delay)
	}
}

func TestH1QueueDelayBaselineWallClockStepResets(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	sourceId := NewId()
	baseline := newH1QueueDelayBaseline(&settings)
	wallOffset := time.Duration(0)
	var monotonicNow time.Time
	baseline.nowWallForTest = func() time.Time {
		return monotonicNow.Add(wallOffset)
	}
	observer := newH1RouteObserver(baseline, 1)
	// a second route of the same transport, ticking just after the first
	other := newH1RouteObserver(baseline, 1)

	tick := func(k int, relMs int64) (h1ObserverTick, h1ObserverTick) {
		monotonicNow = h1PathTestOrigin.Add(time.Duration(k) * 500 * time.Millisecond)
		tag := h1ObserverTestTagMs(monotonicNow) - uint64(relMs)
		for i := 0; i < 4; i++ {
			observer.observePack(sourceId, tag, monotonicNow)
			other.observePack(sourceId, tag, monotonicNow)
		}
		return observer.takeTick(monotonicNow), other.takeTick(monotonicNow)
	}

	if first, _ := tick(0, 200); !first.known || first.queueDelay != 0 {
		t.Fatalf("tick 0 = %+v, want a known zero queue delay", first)
	}
	// a 50 ms slew is not a step
	wallOffset = 50 * time.Millisecond
	if first, second := tick(1, 700); !first.known || first.queueDelay != 500*time.Millisecond ||
		!second.known || second.queueDelay != 500*time.Millisecond {
		t.Fatalf("tick 1 = %+v and %+v, want known 500 ms queue delays", first, second)
	}
	// a 5 s step: both routes' ticks span it and are unknown
	wallOffset += 5 * time.Second
	if first, second := tick(2, 700); first.known || second.known || first.samples != 0 {
		t.Fatalf("tick 2 = %+v and %+v, want both unknown", first, second)
	}
	// the baseline restarted from the next tick's minimum
	if first, second := tick(3, 700); !first.known || first.queueDelay != 0 || !second.known || second.queueDelay != 0 {
		t.Fatalf("tick 3 = %+v and %+v, want known zero queue delays after the reset", first, second)
	}
}

func TestH1RouteObserverAckRttUsesOwnClock(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	observer := newH1RouteObserver(newH1QueueDelayBaseline(&settings), 1)
	now := h1PathTestOrigin

	observer.observeAck(h1ObserverTestTagMs(now.Add(-105*time.Millisecond)), now)
	if tick := observer.takeTick(now); tick.ackRttMin != 105*time.Millisecond ||
		tick.ackRtt != 105*time.Millisecond || tick.ackSamples != 1 || tick.known {
		t.Fatalf("tick = %+v, want an ack round trip of 105 ms and no queue delay", tick)
	}
	// a tick with no ack of its own reports none, and the window minimum stands
	if tick := observer.takeTick(now); tick.ackRttMin != 105*time.Millisecond ||
		tick.ackRtt != 0 || tick.ackSamples != 0 {
		t.Fatalf("tick without an ack = %+v, want the window minimum alone", tick)
	}
	// 300 ms acks every 10 s: the 105 ms minimum holds for the 10 min window,
	// while each tick reports its own 300 ms, which is where the receive rule
	// reads the queue the acks are sitting behind
	for elapsed := 10 * time.Second; elapsed <= 10*time.Minute; elapsed += 10 * time.Second {
		at := now.Add(elapsed)
		observer.observeAck(h1ObserverTestTagMs(at.Add(-300*time.Millisecond)), at)
		want := 105 * time.Millisecond
		if settings.AckRttWindow <= elapsed {
			want = 300 * time.Millisecond
		}
		tick := observer.takeTick(at)
		if tick.ackRttMin != want {
			t.Fatalf("at %s the ack round trip = %s, want %s", elapsed, tick.ackRttMin, want)
		}
		if tick.ackRtt != 300*time.Millisecond || tick.ackSamples != 1 {
			t.Fatalf("at %s the tick's own ack round trip = %s over %d acks, want 300 ms over 1", elapsed, tick.ackRtt, tick.ackSamples)
		}
	}
}

func TestH1RouteObserverObservePackDoesNotAllocate(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	baseline := newH1QueueDelayBaseline(&settings)
	baseline.markReroll(time.Now(), 100*time.Millisecond)
	observer := newH1RouteObserver(baseline, settings.PackSampleEvery)
	// more sources than slots, so a slot is replaced
	sourceIds := []Id{NewId(), NewId(), NewId(), NewId(), NewId()}
	i := 0
	// each run reads 16 frames, of which one is sampled
	allocs := testing.AllocsPerRun(1000, func() {
		for frame := 0; frame < settings.PackSampleEvery; frame++ {
			if observer.sampleNext() {
				readTime := time.Now()
				observer.observePack(sourceIds[i%len(sourceIds)], uint64(readTime.UnixMilli()-105), readTime)
				observer.observeAck(uint64(readTime.UnixMilli()-105), readTime)
				i += 1
			}
		}
	})
	if allocs != 0 {
		t.Fatalf("sampling allocates %.1f times per 16 frames", allocs)
	}
	// the warm-up run is not measured
	if i != 1001 {
		t.Fatalf("sampled %d times in 1001 runs of 16 frames", i)
	}
	if tick := observer.takeTick(time.Now()); !tick.known || tick.samples == 0 {
		t.Fatalf("tick after sampling = %+v", tick)
	}
}

func BenchmarkH1RouteObserverSampledFrames(b *testing.B) {
	settings := DefaultH1PathRerollSettings()
	observer := newH1RouteObserver(newH1QueueDelayBaseline(&settings), settings.PackSampleEvery)
	sourceId := NewId()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if observer.sampleNext() {
			readTime := time.Now()
			observer.observePack(sourceId, uint64(readTime.UnixMilli()-105), readTime)
		}
	}
}

func TestReceiveDispositionCarriesObserverOnlyForPublishingRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	selector := NewMultiRouteSelector(
		ctx,
		"h1-observer-receive",
		nil,
		DestinationId(NewId()),
		true,
	)
	defer selector.Close()
	settings := DefaultH1PathRerollSettings()
	observer := newH1RouteObserver(newH1QueueDelayBaseline(&settings), 1)
	observedRoute := make(Route, 1)
	plainRoute := make(Route, 1)
	selector.updateTransportWithProperties(
		NewReceiveGatewayTransportWithType(TransportTypeH1),
		[]Route{observedRoute},
		TransferCarrierProperties{ReceiveReliability: CarrierReliabilityReliable, receiveObserver: observer},
	)
	selector.updateTransportWithProperties(
		NewReceiveGatewayTransportWithType(TransportTypeH1),
		[]Route{plainRoute},
		TransferCarrierProperties{ReceiveReliability: CarrierReliabilityReliable},
	)

	for _, c := range []struct {
		name     string
		route    Route
		observer *h1RouteObserver
	}{
		{name: "publishing route", route: observedRoute, observer: observer},
		{name: "other route", route: plainRoute, observer: nil},
	} {
		c.route <- MessagePoolGet(23)
		message, disposition, err := selector.readWithCarrier(ctx, time.Second)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		MessagePoolReturn(message)
		if disposition.observer != c.observer ||
			disposition.transportType != TransportTypeH1 ||
			disposition.reliability != CarrierReliabilityReliable {
			t.Fatalf("%s disposition = %+v", c.name, disposition)
		}
	}
}
