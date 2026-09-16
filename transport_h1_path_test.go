package connect

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// Samples are synthesized at 500 ms steps from a fixed origin. Tick index k
// ends at k x 500 ms; index 0 primes the monitor. The kernel minimum round
// trip is 105 ms unless a shape says otherwise, which gives a queue delay
// threshold of 1.05 s and a thin rate of 3.53 MB/s.

const h1PathTestStep = 500 * time.Millisecond

var h1PathTestOrigin = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// One tick's movement. Rates are bytes per second over the step.
type h1PathTickShape struct {
	idle bool

	rxByteRate        float64
	kernelUnknown     bool
	queueDelay        time.Duration
	queueDelaySamples int
	rxOooUnknown      bool
	rxOooAdvance      bool

	txKnown         bool
	txAckedByteRate float64
	txNotSent       uint64
	txRetrans       bool

	receiveFull     bool
	speedTestActive bool
	standingDown    bool

	// zero keeps the 105 ms default; negative leaves the kernel value unknown
	minRtt    time.Duration
	ackRttMin time.Duration
	// the tick's own ack echo round trip; zero leaves the tick without an ack
	ackRtt time.Duration
	mss    int
}

// One run of a shape: the cumulative sample the monitor reads deltas from, and
// the rolling minimum ack round trip that goes with it. That minimum is the
// one production's observer keeps over AckRttWindow and hands to every
// connection of the path (h1QueueDelayBaseline.ackRttMin), so it is kept here
// and not in the monitor: it outlives a re-dial the way the pack baseline
// does, while the monitor's own ack floor does not. A shape that sets its own
// minimum is left alone.
type h1PathShapeRun struct {
	sample      h1PathSample
	ackRttTimes []time.Time
	ackRtts     []time.Duration
}

// Fills the run's sample for one tick and returns it.
func (self *h1PathShapeRun) tickSample(
	settings *H1PathRerollSettings,
	k int,
	tickShape h1PathTickShape,
) *h1PathSample {
	sample := &self.sample
	sample.now = h1PathTestOrigin.Add(time.Duration(k) * h1PathTestStep)
	if 0 < k && !tickShape.idle {
		rxByteCount := uint64(tickShape.rxByteRate * h1PathTestStep.Seconds())
		sample.readMessageCount += 1 + rxByteCount/(16*1024)
		sample.writeMessageCount += 1
		sample.readByteCount += rxByteCount
		sample.rxBytes += rxByteCount
		if tickShape.rxOooAdvance {
			sample.rxOoo += 3
		}
		if tickShape.txKnown {
			sample.txAckedBytes += uint64(tickShape.txAckedByteRate * h1PathTestStep.Seconds())
			if tickShape.txRetrans {
				sample.txRetrans += 2
			}
		}
		if tickShape.receiveFull {
			sample.receiveFullCount += 1
		}
	}
	sample.rxBytesKnown = !tickShape.kernelUnknown
	sample.rxOooKnown = !tickShape.kernelUnknown && !tickShape.rxOooUnknown
	sample.txKnown = tickShape.txKnown
	sample.txNotSent = tickShape.txNotSent
	sample.queueDelay = tickShape.queueDelay
	sample.queueDelaySamples = tickShape.queueDelaySamples
	sample.speedTestActive = tickShape.speedTestActive
	sample.standingDown = tickShape.standingDown
	sample.ackRtt = tickShape.ackRtt
	sample.ackRttSamples = 0
	if 0 < tickShape.ackRtt {
		sample.ackRttSamples = 1
		self.ackRttTimes = append(self.ackRttTimes, sample.now)
		self.ackRtts = append(self.ackRtts, tickShape.ackRtt)
	}
	sample.ackRttMin = tickShape.ackRttMin
	if tickShape.ackRttMin == 0 {
		window := max(settings.AckRttWindow, 0)
		kept := 0
		ackRttMin := time.Duration(0)
		for i, ackRttTime := range self.ackRttTimes {
			if window < sample.now.Sub(ackRttTime) {
				continue
			}
			self.ackRttTimes[kept] = ackRttTime
			self.ackRtts[kept] = self.ackRtts[i]
			kept += 1
			if ackRttMin == 0 {
				ackRttMin = self.ackRtts[i]
			}
			ackRttMin = min(ackRttMin, self.ackRtts[i])
		}
		self.ackRttTimes = self.ackRttTimes[:kept]
		self.ackRtts = self.ackRtts[:kept]
		sample.ackRttMin = ackRttMin
	}
	switch {
	case tickShape.minRtt < 0 || tickShape.kernelUnknown:
		sample.minRtt = 0
	case tickShape.minRtt == 0:
		sample.minRtt = 105 * time.Millisecond
	default:
		sample.minRtt = tickShape.minRtt
	}
	sample.rcvMss = 1448
	sample.sndMss = 1448
	if tickShape.mss != 0 {
		sample.rcvMss = tickShape.mss
		sample.sndMss = tickShape.mss
	}
	if tickShape.kernelUnknown {
		sample.rcvMss = 0
		sample.sndMss = 0
	}
	return sample
}

// Feeds the monitor the shape at each tick index and returns every decision.
func runH1PathMonitorShape(
	monitor *h1PathMonitor,
	tickCount int,
	shape func(k int) h1PathTickShape,
) []h1PathDecision {
	run := &h1PathShapeRun{}
	decisions := make([]h1PathDecision, 0, tickCount)
	for k := 0; k < tickCount; k++ {
		decisions = append(decisions, monitor.tick(*run.tickSample(monitor.settings, k, shape(k))))
	}
	return decisions
}

func newH1PathTestMonitor(t *testing.T, settings *H1PathRerollSettings, dialRtt time.Duration) (*h1PathMonitor, *h1PathStats) {
	t.Helper()
	monitor := newH1PathMonitor(settings, h1PathTestOrigin, dialRtt)
	if monitor == nil {
		t.Fatalf("no monitor for dial rtt %s", dialRtt)
	}
	stats := &h1PathStats{}
	monitor.stats = stats
	return monitor, stats
}

func h1PathConvictionTicks(decisions []h1PathDecision) []int {
	ticks := []int{}
	for k, decision := range decisions {
		if decision.convicted {
			ticks = append(ticks, k)
		}
	}
	return ticks
}

// The measured collapse: 0.5 MB/s delivered while the queue grows from the
// start of the bulk at 0.5 s. The acks ride the same route as the packs and
// carry the same queue, which is what the rig read -- an ack round trip
// climbing to 6-10 s against a 101 ms path -- and what makes the conviction
// confirmed rather than a queue on the sender's clock alone.
func h1PathCollapseShape(k int) h1PathTickShape {
	elapsed := time.Duration(k) * h1PathTestStep
	queue := max(0, elapsed-500*time.Millisecond)
	return h1PathTickShape{
		rxByteRate:        500_000,
		queueDelay:        queue,
		queueDelaySamples: 4,
		rxOooAdvance:      true,
		ackRtt:            105*time.Millisecond + queue,
	}
}

// The collapse shape with the queue at its full depth from the first tick, in
// the pack tags and in the acks alike.
func h1PathHeldCollapseShape(k int) h1PathTickShape {
	shape := h1PathCollapseShape(k)
	shape.queueDelay = 6 * time.Second
	shape.ackRtt = 6105 * time.Millisecond
	return shape
}

// Ticks alone cannot tell a connection that saw no collapse from one that
// could never read a tick, which is what an Observe rollout has to know before
// it believes a quiet fleet. Every accepted tick is now counted by how it was
// read: unread (the speed test echo or a stand down), our own back pressure,
// no queue delay to judge, or a collapse in a direction.
func TestH1PathMonitorCountsHowEachTickWasRead(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	const tickCount = 21

	// a speed test that never stops: every tick is accepted and none is read
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, tickCount, func(k int) h1PathTickShape {
		shape := h1PathCollapseShape(k)
		shape.speedTestActive = true
		return shape
	})
	if ticks := h1PathConvictionTicks(decisions); 0 < len(ticks) {
		t.Fatalf("a speed test convicted at %v", ticks)
	}
	snapshot := stats.snapshot()
	if snapshot.Ticks != tickCount-1 || snapshot.TicksUnread != tickCount-1 ||
		snapshot.TicksCollapsed != 0 || snapshot.TicksReceiveFull != 0 {
		t.Fatalf("stats = %+v, want every tick of a stuck speed test unread", snapshot)
	}

	// our own back pressure: read, but no conviction can come of it
	monitor, stats = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	runH1PathMonitorShape(monitor, tickCount, func(k int) h1PathTickShape {
		shape := h1PathCollapseShape(k)
		shape.receiveFull = true
		return shape
	})
	snapshot = stats.snapshot()
	if snapshot.TicksReceiveFull != tickCount-1 || snapshot.TicksUnread != 0 ||
		snapshot.TicksCollapsed != 0 {
		t.Fatalf("stats = %+v, want every tick behind our own back pressure", snapshot)
	}

	// no pack sample and no ack to read: the tick says nothing about a queue
	// either way
	monitor, stats = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	runH1PathMonitorShape(monitor, tickCount, func(k int) h1PathTickShape {
		shape := h1PathCollapseShape(k)
		shape.queueDelaySamples = 0
		shape.ackRtt = 0
		return shape
	})
	snapshot = stats.snapshot()
	if snapshot.TicksQueueDelayUnknown != tickCount-1 || snapshot.TicksCollapsed != 0 {
		t.Fatalf("stats = %+v, want every tick without a queue delay counted", snapshot)
	}

	// no pack sample, but an ack round trip that holds the queue: the pack
	// tags are still unread and the tick collapses on the ack alone
	monitor, stats = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	runH1PathMonitorShape(monitor, tickCount, func(k int) h1PathTickShape {
		shape := h1PathCollapseShape(k)
		shape.queueDelaySamples = 0
		return shape
	})
	snapshot = stats.snapshot()
	if snapshot.TicksQueueDelayUnknown != tickCount-1 || snapshot.TicksCollapsed < 15 {
		t.Fatalf("stats = %+v, want the ack collapsing ticks the pack tags could not read", snapshot)
	}

	// a tick that collapses on the ack alone is read as collapsed and also
	// carries no readable pack tags: the first three counters are disjoint and
	// summable against Ticks, the fourth crosses them
	monitor, stats = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	runH1PathMonitorShape(monitor, tickCount, func(k int) h1PathTickShape {
		shape := h1PathHeldCollapseShape(k)
		shape.queueDelaySamples = 0
		if k%5 == 0 {
			// both at once: a stuck speed test on a tick our own back
			// pressure also closed
			shape.receiveFull = true
			shape.speedTestActive = true
		}
		return shape
	})
	snapshot = stats.snapshot()
	read := snapshot.TicksUnread + snapshot.TicksReceiveFull + snapshot.TicksCollapsed
	if snapshot.Ticks < read {
		t.Fatalf("stats = %+v, want the three readings to sum within Ticks", snapshot)
	}
	if snapshot.TicksUnread == 0 || snapshot.TicksCollapsed == 0 {
		t.Fatalf("stats = %+v, want both unread ticks and collapses in the run", snapshot)
	}
	if snapshot.TicksReceiveFull != 0 {
		t.Fatalf(
			"stats = %+v, want a tick that was unread and back pressured counted once",
			snapshot,
		)
	}
	if snapshot.TicksQueueDelayUnknown != tickCount-1 {
		t.Fatalf(
			"stats = %+v, want every tick counted unreadable whatever else decided it",
			snapshot,
		)
	}

	// the measured collapse: every tick past the queue threshold is collapsed,
	// and the convictions are a small part of them
	monitor, stats = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, tickCount, h1PathCollapseShape)
	convictions := len(h1PathConvictionTicks(decisions))
	snapshot = stats.snapshot()
	if snapshot.Ticks != tickCount-1 || snapshot.TicksUnread != 0 ||
		snapshot.TicksReceiveFull != 0 || snapshot.TicksQueueDelayUnknown != 0 {
		t.Fatalf("stats = %+v, want every tick of the collapse read", snapshot)
	}
	if snapshot.TicksCollapsed < 15 || uint64(convictions) == snapshot.TicksCollapsed {
		t.Fatalf(
			"stats = %+v with %d convictions, want the collapsed ticks counted apart from them",
			snapshot, convictions,
		)
	}

	// a healthy connection: read on every tick, and nothing collapsed
	monitor, stats = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	runH1PathMonitorShape(monitor, tickCount, func(k int) h1PathTickShape {
		return h1PathTickShape{rxByteRate: 25_000_000, queueDelay: 4 * time.Millisecond, queueDelaySamples: 4}
	})
	snapshot = stats.snapshot()
	if snapshot.Ticks != tickCount-1 || snapshot.TicksCollapsed != 0 ||
		snapshot.TicksUnread != 0 || snapshot.TicksReceiveFull != 0 ||
		snapshot.TicksQueueDelayUnknown != 0 {
		t.Fatalf("stats = %+v, want a healthy connection read on every tick", snapshot)
	}
}

func TestH1PathRerollSettingsDefaultToObserve(t *testing.T) {
	if mode := (H1PathRerollSettings{}).Mode; mode != H1PathRerollModeOff {
		t.Fatalf("zero settings mode = %s, want off", mode)
	}
	if mode := DefaultH1PathRerollSettings().Mode; mode != H1PathRerollModeObserve {
		t.Fatalf("default mode = %s, want observe", mode)
	}
	if mode := DefaultPlatformTransportSettings().H1PathReroll.Mode; mode != H1PathRerollModeObserve {
		t.Fatalf("platform transport default mode = %s, want observe", mode)
	}
	if policy := DefaultH1PathRerollSettings().SourcePortPolicy; policy != H1SourcePortFarRandom {
		t.Fatalf("default source port policy = %d, want far random", policy)
	}
}

func TestParseH1PathRerollMode(t *testing.T) {
	cases := []struct {
		input string
		mode  H1PathRerollMode
		ok    bool
	}{
		{input: "off", mode: H1PathRerollModeOff, ok: true},
		{input: "Observe", mode: H1PathRerollModeObserve, ok: true},
		{input: " ACT ", mode: H1PathRerollModeAct, ok: true},
		{input: "", mode: H1PathRerollModeOff, ok: false},
		{input: "bogus", mode: H1PathRerollModeOff, ok: false},
	}
	for _, c := range cases {
		mode, ok := ParseH1PathRerollMode(c.input)
		if mode != c.mode || ok != c.ok {
			t.Errorf("ParseH1PathRerollMode(%q) = %s, %t; want %s, %t", c.input, mode, ok, c.mode, c.ok)
		}
		if ok && mode.String() != c.mode.String() {
			t.Errorf("mode %d prints %q", mode, mode.String())
		}
	}
}

func TestH1PathMonitorConvictsMeasuredCollapse(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 8, h1PathCollapseShape)

	// the tick ending 2.0 s is the first with a queue delay of at least
	// 1.05 s; four collapsed ticks convict at the tick ending 3.5 s
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 1 || ticks[0] != 7 {
		t.Fatalf("conviction ticks = %v, want [7]", ticks)
	}
	decision := decisions[7]
	if decision.direction != h1PathDirectionRx || decision.confidence != h1PathConfidenceConfirmed {
		t.Fatalf("conviction = %s %s, want rx confirmed", decision.direction, decision.confidence)
	}
	if decision.action != h1PathActionNone {
		t.Fatalf("monitor chose action %s; the connection owns the action", decision.action)
	}
	if decision.collapsedTicks != 4 || decision.pathRtt != 105*time.Millisecond {
		t.Fatalf("conviction inputs collapsed=%d rtt=%s, want 4 and 105ms", decision.collapsedTicks, decision.pathRtt)
	}
	if thin := decision.thinByteRate; thin < 3_530_000 || 3_531_000 < thin {
		t.Fatalf("thin rate = %.0f, want 3.53 MB/s", thin)
	}
	snapshot := stats.snapshot()
	if snapshot.Ticks != 7 || snapshot.RxConvictions != 1 || snapshot.ConfirmedConvictions != 1 ||
		snapshot.TxConvictions != 0 || snapshot.UnconfirmedConvictions != 0 {
		t.Fatalf("stats = %+v", snapshot)
	}
}

func TestH1PathMonitorLossEvidenceConfirmsInTwoTicks(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 8, func(k int) h1PathTickShape {
		shape := h1PathCollapseShape(k)
		shape.rxOooAdvance = k == 2 || k == 5
		return shape
	})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 1 || ticks[0] != 7 {
		t.Fatalf("conviction ticks = %v, want [7]", ticks)
	}
	if decision := decisions[7]; decision.confidence != h1PathConfidenceConfirmed || decision.lossTicks != 2 {
		t.Fatalf("conviction confidence=%s loss=%d, want confirmed on 2 ticks", decision.confidence, decision.lossTicks)
	}
	if denied := stats.SuppressedLossDenied.Load(); denied != 0 {
		t.Fatalf("loss denied %d times", denied)
	}
}

func TestH1PathMonitorLossEvidenceDeniesOneTickInTen(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	shape := func(k int) h1PathTickShape {
		collapse := h1PathCollapseShape(k)
		collapse.rxOooAdvance = k%10 == 3
		return collapse
	}
	decisions := runH1PathMonitorShape(monitor, 8, shape)
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
		t.Fatalf("conviction ticks = %v, want none", ticks)
	}
	if decision := decisions[7]; decision.reason != h1PathReasonLossDenied ||
		decision.direction != h1PathDirectionRx || decision.lossTicks != 1 {
		t.Fatalf("tick 7 = %+v, want an rx loss denial on 1 tick", decision)
	}
	if denied := stats.SuppressedLossDenied.Load(); denied != 1 {
		t.Fatalf("loss denied %d times by the tick ending 3.5 s, want 1", denied)
	}

	// the same collapse held for 30 s never finds a second tick in any window
	monitor, _ = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, shape)
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
		t.Fatalf("conviction ticks over 60 = %v, want none", ticks)
	}
}

func TestH1PathMonitorLossEvidenceUnknownIsUnconfirmed(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 8, func(k int) h1PathTickShape {
		shape := h1PathCollapseShape(k)
		shape.rxOooUnknown = true
		shape.rxOooAdvance = false
		return shape
	})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 1 || ticks[0] != 7 {
		t.Fatalf("conviction ticks = %v, want [7]", ticks)
	}
	if decision := decisions[7]; decision.confidence != h1PathConfidenceUnconfirmed {
		t.Fatalf("conviction confidence = %s, want unconfirmed", decision.confidence)
	}
	if snapshot := stats.snapshot(); snapshot.UnconfirmedConvictions != 1 || snapshot.SuppressedLossDenied != 0 {
		t.Fatalf("stats = %+v", snapshot)
	}
}

func TestH1PathMonitorNeverConvictsHealthyShapes(t *testing.T) {
	collapseHeld := func(k int) h1PathTickShape {
		return h1PathTickShape{
			rxByteRate:        500_000,
			queueDelay:        6 * time.Second,
			queueDelaySamples: 4,
			rxOooAdvance:      true,
		}
	}
	cases := []struct {
		name  string
		shape func(k int) h1PathTickShape
	}{
		{
			name: "healthy 101 ms at 25 MB/s with out-of-order data in 26 of 30 ticks",
			shape: func(k int) h1PathTickShape {
				return h1PathTickShape{
					rxByteRate:        25_000_000,
					queueDelay:        4 * time.Millisecond,
					queueDelaySamples: 400,
					rxOooAdvance:      k%30 < 26,
					minRtt:            101 * time.Millisecond,
				}
			},
		},
		{
			name: "app-limited lossy wi-fi at 0.2 MB/s",
			shape: func(k int) h1PathTickShape {
				return h1PathTickShape{
					rxByteRate:        200_000,
					queueDelay:        20 * time.Millisecond,
					queueDelaySamples: 4,
					rxOooAdvance:      true,
				}
			},
		},
		{
			name: "slow-start transient",
			shape: func(k int) h1PathTickShape {
				queueDelays := []time.Duration{0, 830 * time.Millisecond, 100 * time.Millisecond}
				queueDelay := 4 * time.Millisecond
				if phase := k % 20; phase < len(queueDelays) {
					queueDelay = queueDelays[phase]
				}
				return h1PathTickShape{
					rxByteRate:        1_000_000,
					queueDelay:        queueDelay,
					queueDelaySamples: 8,
					rxOooAdvance:      true,
				}
			},
		},
		{
			name: "receive channel full under a collapse shape",
			shape: func(k int) h1PathTickShape {
				shape := collapseHeld(k)
				shape.receiveFull = true
				return shape
			},
		},
		{
			name: "speed test active under a collapse shape",
			shape: func(k int) h1PathTickShape {
				shape := collapseHeld(k)
				shape.speedTestActive = true
				return shape
			},
		},
		{
			name: "standing down under a collapse shape",
			shape: func(k int) h1PathTickShape {
				shape := collapseHeld(k)
				shape.standingDown = true
				return shape
			},
		},
		{
			name: "idle counters under a collapse shape",
			shape: func(k int) h1PathTickShape {
				shape := collapseHeld(k)
				shape.idle = true
				return shape
			},
		},
		{
			name: "kernel unknown but healthy",
			shape: func(k int) h1PathTickShape {
				return h1PathTickShape{
					rxByteRate:        25_000_000,
					kernelUnknown:     true,
					queueDelay:        4 * time.Millisecond,
					queueDelaySamples: 400,
				}
			},
		},
		{
			name: "tx healthy with a 2 MiB backlog",
			shape: func(k int) h1PathTickShape {
				return h1PathTickShape{
					rxByteRate:      10_000,
					txKnown:         true,
					txAckedByteRate: 25_000_000,
					txNotSent:       2 * 1024 * 1024,
					txRetrans:       true,
				}
			},
		},
	}
	for _, c := range cases {
		settings := DefaultH1PathRerollSettings()
		monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
		decisions := runH1PathMonitorShape(monitor, 60, c.shape)
		if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
			t.Errorf("%s: conviction ticks = %v, want none", c.name, ticks)
		}
		snapshot := stats.snapshot()
		if snapshot.RxConvictions != 0 || snapshot.TxConvictions != 0 {
			t.Errorf("%s: stats = %+v", c.name, snapshot)
		}
		if c.name == "idle counters under a collapse shape" && snapshot.Ticks != 0 {
			t.Errorf("%s: %d ticks taken with no counter movement", c.name, snapshot.Ticks)
		}
	}
}

func TestH1PathMonitorSlowAccessResidualClass(t *testing.T) {
	// 20 Mb/s is under the thin rate at 105 ms, and a large window holds a
	// 1.5 s queue in the access link
	slowAccess := func(ooo func(k int) bool) func(k int) h1PathTickShape {
		return func(k int) h1PathTickShape {
			return h1PathTickShape{
				rxByteRate:        2_500_000,
				queueDelay:        1500 * time.Millisecond,
				queueDelaySamples: 16,
				rxOooAdvance:      ooo(k),
			}
		}
	}
	settings := DefaultH1PathRerollSettings()

	monitor, _ := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 60, slowAccess(func(k int) bool { return k%10 == 3 }))
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
		t.Fatalf("one tick of loss in ten convicted at ticks %v", ticks)
	}

	// the known residual false positive: a lossy policer on a slow access
	// link convicts once loss shows in 3 ticks of 10
	monitor, _ = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, slowAccess(func(k int) bool {
		phase := k % 10
		return phase == 1 || phase == 4 || phase == 7
	}))
	ticks := h1PathConvictionTicks(decisions)
	if len(ticks) == 0 || ticks[0] != 6 {
		t.Fatalf("three ticks of loss in ten convicted at ticks %v, want the first at 6", ticks)
	}
}

func TestH1PathMonitorDormantOnShortPath(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	if monitor := newH1PathMonitor(&settings, h1PathTestOrigin, time.Millisecond); monitor != nil {
		t.Fatal("a 1 ms dial round trip built a monitor")
	}

	monitor, stats := newH1PathTestMonitor(t, &settings, 50*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 60, func(k int) h1PathTickShape {
		shape := h1PathHeldCollapseShape(k)
		shape.minRtt = 300 * time.Microsecond
		return shape
	})
	for k, decision := range decisions {
		if !decision.dormant || decision.convicted {
			t.Fatalf("tick %d = %+v, want dormant from the first tick", k, decision)
		}
	}
	if snapshot := stats.snapshot(); snapshot.ConnectionsDormant != 1 || snapshot.Ticks != 0 {
		t.Fatalf("stats = %+v, want one dormant connection and no ticks", snapshot)
	}

	// an ack echo under the floor is a short path too, and dormancy sticks
	// after it is gone
	monitor, _ = newH1PathTestMonitor(t, &settings, 50*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, func(k int) h1PathTickShape {
		shape := h1PathHeldCollapseShape(k)
		if k == 3 {
			shape.ackRttMin = 2 * time.Millisecond
		}
		return shape
	})
	for k, decision := range decisions {
		if decision.convicted || decision.dormant != (3 <= k) {
			t.Fatalf("tick %d = %+v, want dormant from tick 3", k, decision)
		}
	}
}

func TestH1PathMonitorAgeGateAndRingReset(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	monitor, _ := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 12, h1PathHeldCollapseShape)
	// four collapsed ticks by 2.0 s wait for the 3 s age gate; the reset then
	// needs four more collapsed ticks
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 2 || ticks[0] != 6 || ticks[1] != 10 {
		t.Fatalf("conviction ticks = %v, want [6 10]", ticks)
	}
}

func TestH1PathMonitorSendSideCollapse(t *testing.T) {
	cases := []struct {
		name        string
		shape       func(k int) h1PathTickShape
		convictions []int
	}{
		{
			name: "linux: unsent 1 MiB, acked 0.5 MB/s, retransmits every tick",
			shape: func(k int) h1PathTickShape {
				return h1PathTickShape{
					rxByteRate:      20_000,
					txKnown:         true,
					txAckedByteRate: 500_000,
					txNotSent:       1024 * 1024,
					txRetrans:       true,
				}
			},
			convictions: []int{6, 10},
		},
		{
			name: "darwin: send buffer 1 MiB, sent bytes 0.5 MB/s, maxseg 1400, smoothed rtt minimum",
			shape: func(k int) h1PathTickShape {
				return h1PathTickShape{
					rxByteRate:      20_000,
					txKnown:         true,
					txAckedByteRate: 500_000,
					txNotSent:       1024 * 1024,
					txRetrans:       true,
					mss:             1400,
					minRtt:          104 * time.Millisecond,
				}
			},
			convictions: []int{6, 10},
		},
		{
			name: "no retransmits",
			shape: func(k int) h1PathTickShape {
				return h1PathTickShape{
					rxByteRate:      20_000,
					txKnown:         true,
					txAckedByteRate: 500_000,
					txNotSent:       1024 * 1024,
				}
			},
			convictions: []int{},
		},
	}
	for _, c := range cases {
		settings := DefaultH1PathRerollSettings()
		monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
		tickCount := 12
		if len(c.convictions) == 0 {
			tickCount = 60
		}
		decisions := runH1PathMonitorShape(monitor, tickCount, c.shape)
		ticks := h1PathConvictionTicks(decisions)
		if len(ticks) != len(c.convictions) {
			t.Errorf("%s: conviction ticks = %v, want %v", c.name, ticks, c.convictions)
			continue
		}
		for i := range ticks {
			if ticks[i] != c.convictions[i] {
				t.Errorf("%s: conviction ticks = %v, want %v", c.name, ticks, c.convictions)
				break
			}
		}
		for _, k := range ticks {
			if decision := decisions[k]; decision.direction != h1PathDirectionTx ||
				decision.confidence != h1PathConfidenceConfirmed {
				t.Errorf("%s: tick %d = %s %s, want tx confirmed", c.name, k, decision.direction, decision.confidence)
			}
		}
		if len(c.convictions) == 0 && stats.SuppressedLossDenied.Load() == 0 {
			t.Errorf("%s: a collapsed send side without retransmits was not counted as loss denied", c.name)
		}
	}
}

func newH1PathTestLedger() (*h1PathLedger, *h1PathStats) {
	ledger := newH1PathLedger()
	stats := &h1PathStats{}
	ledger.stats = stats
	return ledger, stats
}

// A pending re-roll waits out its improvement window whether or not anything
// still reads the route manager it names, so the ledger holds the key weakly: a
// route manager nothing else references is collected, and its re-roll resolves
// as unresolved at the next call rather than pinning the route manager -- its
// match states, its writer snapshots and its alias scopes -- for the process's
// life. A route manager that is still live keeps its entry through any number
// of collections.
func TestH1PathLedgerDoesNotPinARouteManager(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	ledger, stats := newH1PathTestLedger()
	now := h1PathTestOrigin

	live := &RouteManager{}
	ledger.noteReroll(live, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 40004)
	func() {
		// the ledger is the only thing that will know this one
		dead := &RouteManager{}
		ledger.noteReroll(dead, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 40012)
		if state := testingH1PathLedgerSnapshot(ledger); state.pendingCount != 2 {
			t.Fatalf("ledger = %+v, want both re-rolls pending", state)
		}
		runtime.KeepAlive(dead)
	}()

	// the sweep runs from any call, and only a collection can drop the entry
	// inside the improvement window
	pendingCount := 2
	for range 10 {
		runtime.GC()
		ledger.allow(&settings, now.Add(time.Second), H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute)
		pendingCount = testingH1PathLedgerSnapshot(ledger).pendingCount
		if pendingCount <= 1 {
			break
		}
	}
	if pendingCount != 1 {
		t.Fatalf("pending re-rolls = %d, want the collected route manager's dropped", pendingCount)
	}
	if unresolved := stats.Unresolved.Load(); unresolved != 1 {
		t.Fatalf("unresolved = %d, want the collected route manager's re-roll", unresolved)
	}
	// the live one is untouched, and still resolves the way it always did
	if !ledger.noteConviction(live, &settings, now.Add(2*time.Second)) {
		t.Fatal("the live route manager's re-roll was dropped by a collection")
	}
	if state := testingH1PathLedgerSnapshot(ledger); state.pendingCount != 0 || state.epochUnimproved != 1 {
		t.Fatalf("ledger = %+v, want the live re-roll resolved as unimproved", state)
	}
	runtime.KeepAlive(live)
}

func TestH1PathLedgerDeviceSpacing(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	ledger, _ := newH1PathTestLedger()
	key := &RouteManager{}
	now := h1PathTestOrigin

	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); !ok {
		t.Fatalf("first re-roll refused: %s", reason)
	}
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 40004)
	// spacing is per device: any connection's re-roll 1 s later is refused
	if ok, reason := ledger.allow(&settings, now.Add(time.Second), H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); ok || reason != h1PathReasonSpacing {
		t.Fatalf("re-roll 1 s later = %t %s, want spacing", ok, reason)
	}
	if ok, reason := ledger.allow(&settings, now.Add(2*time.Second), H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); !ok {
		t.Fatalf("re-roll 2 s later refused: %s", reason)
	}
}

func TestH1PathLedgerUnimprovedLatch(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	ledger, _ := newH1PathTestLedger()
	key := &RouteManager{}
	now := h1PathTestOrigin

	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 40004)
	now = now.Add(30 * time.Second)
	if !ledger.noteConviction(key, &settings, now) {
		t.Fatal("a conviction 30 s after a re-roll was not unimproved")
	}
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); !ok {
		t.Fatalf("one unimproved re-roll refused the next: %s", reason)
	}
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 40012)
	now = now.Add(30 * time.Second)
	if !ledger.noteConviction(key, &settings, now) {
		t.Fatal("the second conviction inside the window was not unimproved")
	}
	if ok, reason := ledger.allow(&settings, now.Add(10*time.Second), H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); ok || reason != h1PathReasonLatched {
		t.Fatalf("after two unimproved re-rolls allow = %t %s, want latched", ok, reason)
	}
	if ok, reason := ledger.allow(&settings, now.Add(29*time.Minute), H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); ok || reason != h1PathReasonLatched {
		t.Fatalf("29 min into the latch allow = %t %s, want latched", ok, reason)
	}
	if ok, reason := ledger.allow(&settings, now.Add(30*time.Minute), H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); !ok {
		t.Fatalf("the latch outlived its 30 min: %s", reason)
	}
}

func TestH1PathLedgerCleanTicksResolveImprovement(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	ledger, stats := newH1PathTestLedger()
	key := &RouteManager{}
	now := h1PathTestOrigin

	// one unimproved re-roll, then a second re-roll that turns out clean
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 40004)
	now = now.Add(10 * time.Second)
	if !ledger.noteConviction(key, &settings, now) {
		t.Fatal("conviction was not unimproved")
	}
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 40012)
	now = now.Add(10 * time.Second)
	if ledger.noteClean(key, &settings, now, h1PathCleanTicks{rxAck: 19}) {
		t.Fatal("19 clean ticks counted as improved")
	}
	// the re-roll answers a receive queue the ack echo read, so a send
	// direction that never stopped working and a pack baseline that never saw
	// that queue are not what it has to beat
	if ledger.noteClean(key, &settings, now, h1PathCleanTicks{tx: 400, rxPack: 400}) {
		t.Fatal("clean ticks of the directions that did not convict counted as improved")
	}
	if ledger.noteClean(key, &settings, now, h1PathCleanTicks{rxAck: 20}) != true {
		t.Fatal("20 clean ticks did not count as improved")
	}
	if ledger.epochUnimproved != 0 {
		t.Fatalf("improvement left the epoch's unimproved count at %d", ledger.epochUnimproved)
	}
	if ledger.noteConviction(key, &settings, now.Add(time.Second)) {
		t.Fatal("a conviction after an improvement was unimproved")
	}

	// a conviction after the improvement window is not unimproved, and the
	// aged-out entry is unresolved
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 0)
	if ledger.noteConviction(key, &settings, now.Add(121*time.Second)) {
		t.Fatal("a conviction 121 s after the re-roll was unimproved")
	}
	if unresolved := stats.Unresolved.Load(); unresolved != 1 {
		t.Fatalf("unresolved = %d, want 1", unresolved)
	}
}

func TestH1PathLedgerUnconfirmedBudget(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	ledger, _ := newH1PathTestLedger()
	now := h1PathTestOrigin

	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceUnconfirmed, time.Minute); !ok {
		t.Fatalf("first unconfirmed re-roll refused: %s", reason)
	}
	ledger.noteReroll(&RouteManager{}, &settings, now, H1PathRerollRoleClient, h1PathConfidenceUnconfirmed, h1PathConvicted{direction: h1PathDirectionRx}, 0)
	now = now.Add(time.Minute)
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceUnconfirmed, time.Minute); ok || reason != h1PathReasonUnconfirmedBudget {
		t.Fatalf("second unconfirmed re-roll = %t %s, want unconfirmedBudget", ok, reason)
	}
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); !ok {
		t.Fatalf("a confirmed re-roll was refused by the unconfirmed budget: %s", reason)
	}
	ledger.networkChanged(now)
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceUnconfirmed, time.Minute); !ok {
		t.Fatalf("a network change did not reset the unconfirmed budget: %s", reason)
	}

	// An improvement gives the budget back. A re-roll that fixed the
	// connection is the evidence its conviction lacked, so the epoch is no
	// worse off for having spent it, and a device whose peer answers over
	// another transport keeps re-rolling for as long as re-rolling works.
	ledger, _ = newH1PathTestLedger()
	key := &RouteManager{}
	now = h1PathTestOrigin
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceUnconfirmed, h1PathConvicted{direction: h1PathDirectionRx}, 0)
	now = now.Add(time.Minute)
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceUnconfirmed, time.Minute); ok {
		t.Fatalf("the unconfirmed budget was not spent: %t %s", ok, reason)
	}
	if ledger.noteClean(key, &settings, now, h1PathCleanTicks{rxAck: settings.CleanTicks}) {
		t.Fatal("an ack the conviction never read resolved a re-roll the pack tags convicted")
	}
	if !ledger.noteClean(key, &settings, now, h1PathCleanTicks{rxPack: settings.CleanTicks}) {
		t.Fatal("the clean ticks did not resolve the re-roll as improved")
	}
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceUnconfirmed, time.Minute); !ok {
		t.Fatalf("an improvement did not give the unconfirmed budget back: %s", reason)
	}
}

func TestH1PathLedgerNetworkChangeLatchAge(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	ledger, stats := newH1PathTestLedger()
	key := &RouteManager{}
	now := h1PathTestOrigin

	for i := 0; i < 2; i++ {
		ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 0)
		now = now.Add(10 * time.Second)
		ledger.noteConviction(key, &settings, now)
	}
	latchStart := now
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); ok || reason != h1PathReasonLatched {
		t.Fatalf("allow = %t %s, want latched", ok, reason)
	}
	// a pending entry is dropped as unresolved by a network change
	ledger.noteReroll(&RouteManager{}, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 0)

	ledger.networkChanged(latchStart.Add(4 * time.Minute))
	if ok, reason := ledger.allow(&settings, latchStart.Add(4*time.Minute), H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); ok || reason != h1PathReasonLatched {
		t.Fatalf("a network change 4 min into the latch cleared it: %t %s", ok, reason)
	}
	if unresolved := stats.Unresolved.Load(); unresolved != 1 {
		t.Fatalf("unresolved after network change = %d, want 1", unresolved)
	}
	ledger.networkChanged(latchStart.Add(6 * time.Minute))
	if ok, reason := ledger.allow(&settings, latchStart.Add(6*time.Minute), H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); !ok {
		t.Fatalf("a network change 6 min into the latch kept it: %s", reason)
	}
	dayUnimproved := 0
	for _, unimprovedTime := range ledger.dayUnimprovedTimes {
		if !unimprovedTime.IsZero() {
			dayUnimproved += 1
		}
	}
	if dayUnimproved != 2 {
		t.Fatalf("the daily count after two network changes = %d, want 2", dayUnimproved)
	}
}

func TestH1PathLedgerDailyBudget(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	ledger, _ := newH1PathTestLedger()
	key := &RouteManager{}
	now := h1PathTestOrigin
	firstUnimproved := time.Time{}

	// six unimproved re-rolls across three network epochs; each epoch's
	// second sets the latch, and the network change 6 min later clears it
	for epoch := 0; epoch < 3; epoch++ {
		for i := 0; i < 2; i++ {
			if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); !ok {
				t.Fatalf("epoch %d re-roll %d refused: %s", epoch, i, reason)
			}
			ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 0)
			now = now.Add(10 * time.Second)
			if !ledger.noteConviction(key, &settings, now) {
				t.Fatalf("epoch %d conviction %d was not unimproved", epoch, i)
			}
			if firstUnimproved.IsZero() {
				firstUnimproved = now
			}
			if i == 0 {
				now = now.Add(time.Minute)
			}
		}
		now = now.Add(6 * time.Minute)
		ledger.networkChanged(now)
	}
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); ok || reason != h1PathReasonDailyBudget {
		t.Fatalf("after six unimproved re-rolls allow = %t %s, want dailyBudget", ok, reason)
	}
	justBefore := firstUnimproved.Add(24*time.Hour - time.Second)
	if ok, reason := ledger.allow(&settings, justBefore, H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); ok || reason != h1PathReasonDailyBudget {
		t.Fatalf("a second before the oldest ages out allow = %t %s, want dailyBudget", ok, reason)
	}
	if ok, reason := ledger.allow(&settings, firstUnimproved.Add(24*time.Hour), H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); !ok {
		t.Fatalf("the oldest unimproved re-roll aged out and allow still refused: %s", reason)
	}
}

func TestH1PathLedgerProviderGate(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	ledger, _ := newH1PathTestLedger()
	now := h1PathTestOrigin

	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleProvider, h1PathConfidenceConfirmed, 10*time.Minute); ok || reason != h1PathReasonRole {
		t.Fatalf("provider without AllowProviderAct = %t %s, want role", ok, reason)
	}
	settings.AllowProviderAct = true
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleProvider, h1PathConfidenceConfirmed, 119*time.Second); ok || reason != h1PathReasonProviderGate {
		t.Fatalf("provider at age 119 s = %t %s, want providerGate", ok, reason)
	}
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleProvider, h1PathConfidenceConfirmed, 121*time.Second); !ok {
		t.Fatalf("provider at age 121 s refused: %s", reason)
	}
	ledger.noteReroll(&RouteManager{}, &settings, now, H1PathRerollRoleProvider, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 0)
	if ok, reason := ledger.allow(&settings, now.Add(9*time.Minute), H1PathRerollRoleProvider, h1PathConfidenceConfirmed, 5*time.Minute); ok || reason != h1PathReasonProviderGate {
		t.Fatalf("provider 9 min after its re-roll = %t %s, want providerGate", ok, reason)
	}
	if ok, reason := ledger.allow(&settings, now.Add(9*time.Minute), H1PathRerollRoleClient, h1PathConfidenceConfirmed, 5*time.Minute); !ok {
		t.Fatalf("the provider spacing refused a client: %s", reason)
	}
	if ok, reason := ledger.allow(&settings, now.Add(10*time.Minute), H1PathRerollRoleProvider, h1PathConfidenceConfirmed, 5*time.Minute); !ok {
		t.Fatalf("provider 10 min after its re-roll refused: %s", reason)
	}
}

func TestH1PathLedgerExcludedPorts(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	settings.DeviceRerollSpacing = 0
	ledger, _ := newH1PathTestLedger()
	now := h1PathTestOrigin

	for i := 0; i < 20; i++ {
		ledger.noteReroll(&RouteManager{}, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 40000+i)
	}
	excluded := ledger.excluded()
	if len(excluded) != 16 || excluded[0] != 40004 || excluded[15] != 40019 {
		t.Fatalf("excluded = %v, want the latest 16 ports", excluded)
	}
	excluded[0] = 1
	if ledger.excluded()[0] != 40004 {
		t.Fatal("excluded returned the ledger's own slice")
	}
	ledger.networkChanged(now)
	if excluded := ledger.excluded(); len(excluded) != 0 {
		t.Fatalf("excluded after a network change = %v", excluded)
	}
}

func TestH1PathDefaultLedgerFollowsNetworkChange(t *testing.T) {
	ledger := h1PathDefaultLedger()
	if ledger != h1PathDefaultLedger() {
		t.Fatal("the default ledger is not one per process")
	}
	settings := DefaultH1PathRerollSettings()
	// an hour in the past, so the process ledger's device spacing and pending
	// entry cannot refuse or judge another test's re-roll
	ledger.noteReroll(&RouteManager{}, &settings, time.Now().Add(-time.Hour), H1PathRerollRoleClient, h1PathConfidenceConfirmed, h1PathConvicted{direction: h1PathDirectionRx, ackCarried: true}, 40004)
	NetworkChanged()
	if excluded := ledger.excluded(); len(excluded) != 0 {
		t.Fatalf("NetworkChanged left the default ledger's excluded ports %v", excluded)
	}
}

// The mode of a connection, in precedence order. The relay-advertised level of
// the design is not implemented here, so the levels are the process override,
// the environment and the settings.
func TestH1PathEffectiveModePrecedence(t *testing.T) {
	for _, c := range []struct {
		name             string
		settingsMode     H1PathRerollMode
		role             H1PathRerollRole
		allowProviderAct bool
		envValue         string
		overrideMode     H1PathRerollMode
		overrideSet      bool
		wantMode         H1PathRerollMode
		wantSource       h1PathModeSource
		wantEnvValid     bool
	}{
		{
			name: "settings only", settingsMode: H1PathRerollModeObserve,
			wantMode: H1PathRerollModeObserve, wantSource: h1PathModeSourceSettings, wantEnvValid: true,
		},
		{
			name: "unknown settings mode", settingsMode: H1PathRerollMode(7),
			wantMode: H1PathRerollModeOff, wantSource: h1PathModeSourceSettings, wantEnvValid: true,
		},
		{
			name: "env act over settings observe", settingsMode: H1PathRerollModeObserve, envValue: "act",
			wantMode: H1PathRerollModeAct, wantSource: h1PathModeSourceEnv, wantEnvValid: true,
		},
		{
			name: "env off over settings act", settingsMode: H1PathRerollModeAct, envValue: "OFF ",
			wantMode: H1PathRerollModeOff, wantSource: h1PathModeSourceEnv, wantEnvValid: true,
		},
		{
			name: "empty env keeps the settings", settingsMode: H1PathRerollModeAct, envValue: "",
			wantMode: H1PathRerollModeAct, wantSource: h1PathModeSourceSettings, wantEnvValid: true,
		},
		{
			name: "bad env keeps the settings", settingsMode: H1PathRerollModeObserve, envValue: "bogus",
			wantMode: H1PathRerollModeObserve, wantSource: h1PathModeSourceSettings, wantEnvValid: false,
		},
		{
			name: "override observe over env act and settings act", settingsMode: H1PathRerollModeAct, envValue: "act",
			overrideMode: H1PathRerollModeObserve, overrideSet: true,
			wantMode: H1PathRerollModeObserve, wantSource: h1PathModeSourceOverride, wantEnvValid: true,
		},
		{
			name: "override off over env act", settingsMode: H1PathRerollModeObserve, envValue: "act",
			overrideMode: H1PathRerollModeOff, overrideSet: true,
			wantMode: H1PathRerollModeOff, wantSource: h1PathModeSourceOverride, wantEnvValid: true,
		},
		{
			name: "override act over settings off", settingsMode: H1PathRerollModeOff,
			overrideMode: H1PathRerollModeAct, overrideSet: true,
			wantMode: H1PathRerollModeAct, wantSource: h1PathModeSourceOverride, wantEnvValid: true,
		},
		{
			name: "unknown override", settingsMode: H1PathRerollModeAct,
			overrideMode: H1PathRerollMode(7), overrideSet: true,
			wantMode: H1PathRerollModeOff, wantSource: h1PathModeSourceOverride, wantEnvValid: true,
		},
		{
			name: "provider clamps the settings", settingsMode: H1PathRerollModeAct, role: H1PathRerollRoleProvider,
			wantMode: H1PathRerollModeObserve, wantSource: h1PathModeSourceSettings, wantEnvValid: true,
		},
		{
			name: "provider clamps the env", settingsMode: H1PathRerollModeObserve, role: H1PathRerollRoleProvider, envValue: "act",
			wantMode: H1PathRerollModeObserve, wantSource: h1PathModeSourceEnv, wantEnvValid: true,
		},
		{
			name: "provider clamps the override", settingsMode: H1PathRerollModeObserve, role: H1PathRerollRoleProvider,
			overrideMode: H1PathRerollModeAct, overrideSet: true,
			wantMode: H1PathRerollModeObserve, wantSource: h1PathModeSourceOverride, wantEnvValid: true,
		},
		{
			name: "allowed provider acts", settingsMode: H1PathRerollModeObserve, role: H1PathRerollRoleProvider,
			allowProviderAct: true, envValue: "act",
			wantMode: H1PathRerollModeAct, wantSource: h1PathModeSourceEnv, wantEnvValid: true,
		},
		{
			name: "provider off stays off", settingsMode: H1PathRerollModeAct, role: H1PathRerollRoleProvider,
			allowProviderAct: true, envValue: "off",
			wantMode: H1PathRerollModeOff, wantSource: h1PathModeSourceEnv, wantEnvValid: true,
		},
	} {
		settings := DefaultH1PathRerollSettings()
		settings.Mode = c.settingsMode
		settings.Role = c.role
		settings.AllowProviderAct = c.allowProviderAct
		// the role the clamp reads comes from its own resolution, which with
		// no override and no environment is the settings
		role, _ := h1PathEffectiveRole(&settings, H1PathRerollRoleClient, false, "")
		mode, source, envValid := h1PathEffectiveMode(&settings, role, c.overrideMode, c.overrideSet, c.envValue)
		if mode != c.wantMode || source != c.wantSource || envValid != c.wantEnvValid {
			t.Errorf(
				"%s: mode = %s from %s (env valid %t); want %s from %s (env valid %t)",
				c.name, mode, source, envValid, c.wantMode, c.wantSource, c.wantEnvValid,
			)
		}
	}
}

// The role follows the same precedence as the mode, and an unknown role is the
// provider, whose gates are the tighter ones.
func TestH1PathRerollRolePrecedence(t *testing.T) {
	for _, c := range []struct {
		name         string
		settingsRole H1PathRerollRole
		envValue     string
		overrideRole H1PathRerollRole
		overrideSet  bool
		wantRole     H1PathRerollRole
		wantEnvValid bool
	}{
		{
			name: "settings client", settingsRole: H1PathRerollRoleClient,
			wantRole: H1PathRerollRoleClient, wantEnvValid: true,
		},
		{
			name: "settings provider", settingsRole: H1PathRerollRoleProvider,
			wantRole: H1PathRerollRoleProvider, wantEnvValid: true,
		},
		{
			name: "env provider over settings client", envValue: " PROVIDER ",
			wantRole: H1PathRerollRoleProvider, wantEnvValid: true,
		},
		{
			name: "env client over settings provider", settingsRole: H1PathRerollRoleProvider, envValue: "client",
			wantRole: H1PathRerollRoleClient, wantEnvValid: true,
		},
		{
			name: "bad env keeps the settings", settingsRole: H1PathRerollRoleProvider, envValue: "bogus",
			wantRole: H1PathRerollRoleProvider, wantEnvValid: false,
		},
		{
			name: "override client over env provider", envValue: "provider",
			overrideRole: H1PathRerollRoleClient, overrideSet: true,
			wantRole: H1PathRerollRoleClient, wantEnvValid: true,
		},
		{
			name:         "override provider over settings client",
			overrideRole: H1PathRerollRoleProvider, overrideSet: true,
			wantRole: H1PathRerollRoleProvider, wantEnvValid: true,
		},
		{
			name:         "unknown override is the provider",
			overrideRole: H1PathRerollRole(7), overrideSet: true,
			wantRole: H1PathRerollRoleProvider, wantEnvValid: true,
		},
		{
			name: "unknown settings role is the provider", settingsRole: H1PathRerollRole(7),
			wantRole: H1PathRerollRoleProvider, wantEnvValid: true,
		},
	} {
		settings := DefaultH1PathRerollSettings()
		settings.Role = c.settingsRole
		role, envValid := h1PathEffectiveRole(&settings, c.overrideRole, c.overrideSet, c.envValue)
		if role != c.wantRole || envValid != c.wantEnvValid {
			t.Errorf(
				"%s: role = %s (env valid %t); want %s (env valid %t)",
				c.name, role, envValid, c.wantRole, c.wantEnvValid,
			)
		}
	}
}

// The role a transport resolves reaches the clamp, so an operator who sets act
// in a provider process gets Observe. The two environment values are logged
// independently, once per value.
func TestH1PathRerollRoleEnvironmentClampsTheMode(t *testing.T) {
	log := newRecordingLogger()
	settings := DefaultPlatformTransportSettings()
	settings.H1PathReroll.Mode = H1PathRerollModeAct
	transport := &PlatformTransport{log: log, settings: settings}

	if role := transport.h1PathEffectiveRole(); role != H1PathRerollRoleClient {
		t.Fatalf("role = %s with no environment, want the settings client", role)
	}
	if mode, _ := transport.h1PathEffectiveMode(transport.h1PathEffectiveRole()); mode != H1PathRerollModeAct {
		t.Fatalf("mode = %s for a client, want act", mode)
	}

	t.Setenv(H1PathRerollRoleEnv, "provider")
	if role := transport.h1PathEffectiveRole(); role != H1PathRerollRoleProvider {
		t.Fatalf("role = %s with the environment provider", role)
	}
	if mode, source := transport.h1PathEffectiveMode(transport.h1PathEffectiveRole()); mode != H1PathRerollModeObserve {
		t.Fatalf("mode = %s from %s for a provider, want the clamp to observe", mode, source)
	}
	settings.H1PathReroll.AllowProviderAct = true
	if mode, _ := transport.h1PathEffectiveMode(transport.h1PathEffectiveRole()); mode != H1PathRerollModeAct {
		t.Fatalf("mode = %s for an allowed provider, want act", mode)
	}

	// each distinct bad value is logged once, and the mode's own bad value is
	// counted apart from the role's
	badRole := fmt.Sprintf("bogus-%s", NewId())
	t.Setenv(H1PathRerollRoleEnv, badRole)
	badMode := fmt.Sprintf("bogus-%s", NewId())
	t.Setenv(H1PathRerollModeEnv, badMode)
	for range 3 {
		role := transport.h1PathEffectiveRole()
		if role != H1PathRerollRoleClient {
			t.Fatalf("role = %s for a bad environment value, want the settings client", role)
		}
		if mode, source := transport.h1PathEffectiveMode(role); mode != H1PathRerollModeAct || source != h1PathModeSourceSettings {
			t.Fatalf("mode = %s from %s for a bad environment value", mode, source)
		}
	}
	if lines := log.linesWith(badRole); len(lines) != 1 {
		t.Fatalf("log lines for the bad role %s = %v, want one", badRole, lines)
	}
	if lines := log.linesWith(badMode); len(lines) != 1 {
		t.Fatalf("log lines for the bad mode %s = %v, want one", badMode, lines)
	}
}

// The process role override is set, read and cleared, and an unknown role is
// stored as the provider rather than reaching the client gates.
func TestH1PathRerollRoleOverrideApi(t *testing.T) {
	previousRole, previousSet := H1PathRerollRoleOverride()
	t.Cleanup(func() {
		if previousSet {
			SetH1PathRerollRoleOverride(previousRole)
		} else {
			ClearH1PathRerollRoleOverride()
		}
	})

	ClearH1PathRerollRoleOverride()
	if role, ok := H1PathRerollRoleOverride(); ok || role != H1PathRerollRoleClient {
		t.Fatalf("override = %s, %t after clear", role, ok)
	}
	for _, wantRole := range []H1PathRerollRole{H1PathRerollRoleClient, H1PathRerollRoleProvider} {
		SetH1PathRerollRoleOverride(wantRole)
		if role, ok := H1PathRerollRoleOverride(); !ok || role != wantRole {
			t.Errorf("override = %s, %t; want %s, true", role, ok, wantRole)
		}
	}
	SetH1PathRerollRoleOverride(H1PathRerollRole(7))
	if role, ok := H1PathRerollRoleOverride(); !ok || role != H1PathRerollRoleProvider {
		t.Fatalf("override = %s, %t after an unknown role; want provider, true", role, ok)
	}
	ClearH1PathRerollRoleOverride()
	if _, ok := H1PathRerollRoleOverride(); ok {
		t.Fatal("the override survived a clear")
	}
}

// The process override is set, read and cleared, and an unknown mode is stored
// as Off rather than reaching Act.
func TestH1PathRerollModeOverrideApi(t *testing.T) {
	previousMode, previousSet := H1PathRerollModeOverride()
	t.Cleanup(func() {
		if previousSet {
			SetH1PathRerollModeOverride(previousMode)
		} else {
			ClearH1PathRerollModeOverride()
		}
	})

	ClearH1PathRerollModeOverride()
	if mode, ok := H1PathRerollModeOverride(); ok || mode != H1PathRerollModeOff {
		t.Fatalf("override = %s, %t after clear", mode, ok)
	}
	for _, wantMode := range []H1PathRerollMode{
		H1PathRerollModeOff,
		H1PathRerollModeObserve,
		H1PathRerollModeAct,
	} {
		SetH1PathRerollModeOverride(wantMode)
		if mode, ok := H1PathRerollModeOverride(); !ok || mode != wantMode {
			t.Errorf("override = %s, %t; want %s, true", mode, ok, wantMode)
		}
	}
	SetH1PathRerollModeOverride(H1PathRerollMode(7))
	if mode, ok := H1PathRerollModeOverride(); !ok || mode != H1PathRerollModeOff {
		t.Fatalf("override = %s, %t after an unknown mode; want off, true", mode, ok)
	}
	ClearH1PathRerollModeOverride()
	if _, ok := H1PathRerollModeOverride(); ok {
		t.Fatal("the override survived a clear")
	}
}

// A transport reads the environment at each connection. A value that does not
// parse leaves the settings mode in force and is logged once per value.
func TestH1PathRerollModeEnvironmentBadValueLogsOnce(t *testing.T) {
	log := newRecordingLogger()
	settings := DefaultPlatformTransportSettings()
	settings.H1PathReroll.Mode = H1PathRerollModeObserve
	transport := &PlatformTransport{log: log, settings: settings}

	t.Setenv(H1PathRerollModeEnv, "act")
	if mode, source := transport.h1PathEffectiveMode(H1PathRerollRoleClient); mode != H1PathRerollModeAct || source != h1PathModeSourceEnv {
		t.Fatalf("mode = %s from %s, want act from env", mode, source)
	}

	// each distinct bad value is logged once, however many connections read it
	badValue := fmt.Sprintf("bogus-%s", NewId())
	t.Setenv(H1PathRerollModeEnv, badValue)
	for range 3 {
		if mode, source := transport.h1PathEffectiveMode(H1PathRerollRoleClient); mode != H1PathRerollModeObserve || source != h1PathModeSourceSettings {
			t.Fatalf("mode = %s from %s, want the settings observe", mode, source)
		}
	}
	if lines := log.linesWith(badValue); len(lines) != 1 {
		t.Fatalf("log lines for %s = %v, want one", badValue, lines)
	}

	otherBadValue := fmt.Sprintf("bogus-%s", NewId())
	t.Setenv(H1PathRerollModeEnv, otherBadValue)
	transport.h1PathEffectiveMode(H1PathRerollRoleClient)
	if lines := log.linesWith(otherBadValue); len(lines) != 1 {
		t.Fatalf("log lines for %s = %v, want one", otherBadValue, lines)
	}
}

// The tick log is forced by the environment whatever the settings say.
func TestH1PathLogTicksEnvironment(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	if h1PathLogTicks(&settings) {
		t.Fatal("the default settings log every tick")
	}
	t.Setenv(H1PathRerollLogTicksEnv, "1")
	if !h1PathLogTicks(&settings) {
		t.Fatal("the environment did not force the tick log")
	}
	t.Setenv(H1PathRerollLogTicksEnv, "0")
	if h1PathLogTicks(&settings) {
		t.Fatal("a zero environment value forced the tick log")
	}
	settings.LogTicks = true
	if !h1PathLogTicks(&settings) {
		t.Fatal("the settings did not turn on the tick log")
	}
}

// A saturated uplink is backlogged, slower than thin and retransmitting, which
// is every property the send-side rule reads. What separates it from a
// collapse is how long the backlog takes to drain: the same queue-delay
// threshold the receive side applies, measured on the socket's own send queue.
func TestH1PathMonitorNeverConvictsASaturatedUplink(t *testing.T) {
	// the websocket writer keeps the send buffer full; the uplink is saturated
	// so the kernel retransmits, and every rate is under the thin rate
	uplink := func(ackedByteRate float64, notSent uint64, rtt time.Duration) func(k int) h1PathTickShape {
		return func(k int) h1PathTickShape {
			return h1PathTickShape{
				rxByteRate:      20_000,
				txKnown:         true,
				txAckedByteRate: ackedByteRate,
				txNotSent:       notSent,
				txRetrans:       true,
				minRtt:          rtt,
			}
		}
	}
	cases := []struct {
		name     string
		shape    func(k int) h1PathTickShape
		convicts bool
	}{
		{
			// 2.5 MB/s against a thin rate of 3.67 MB/s at 101 ms
			name:  "20 Mb/s uplink, 400 KiB unsent",
			shape: uplink(2_500_000, 400*1024, 101*time.Millisecond),
		},
		{
			name:  "20 Mb/s uplink, exactly the backlog floor unsent",
			shape: uplink(2_500_000, 256*1024, 101*time.Millisecond),
		},
		{
			name:  "10 Mb/s uplink, 300 KiB unsent",
			shape: uplink(1_250_000, 300*1024, 101*time.Millisecond),
		},
		{
			// a thin rate of 9.27 MB/s at 40 ms is above the whole uplink
			name:  "25 Mb/s uplink at 40 ms, 400 KiB unsent",
			shape: uplink(3_125_000, 400*1024, 40*time.Millisecond),
		},
		{
			// darwin counts in-flight data in the send buffer, so two round
			// trips of a 20 Mb/s uplink read as 493 KiB unsent
			name:  "darwin send buffer holding two round trips at 20 Mb/s",
			shape: uplink(2_500_000, 505_000, 101*time.Millisecond),
		},
		{
			// the floor: a trickle upload's whole send queue is small, however
			// long that queue takes to drain
			name:  "80 kb/s upload, 30 kB unsent",
			shape: uplink(10_000, 30_000, 101*time.Millisecond),
		},
		{
			// 4 MiB takes 1.68 s to drain, past the 1.01 s threshold
			name:     "20 Mb/s uplink, 4 MiB unsent",
			shape:    uplink(2_500_000, 4*1024*1024, 101*time.Millisecond),
			convicts: true,
		},
	}
	for _, c := range cases {
		settings := DefaultH1PathRerollSettings()
		monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
		decisions := runH1PathMonitorShape(monitor, 60, c.shape)
		ticks := h1PathConvictionTicks(decisions)
		snapshot := stats.snapshot()
		if c.convicts {
			if len(ticks) == 0 {
				t.Errorf("%s: no conviction, want the drain time past the threshold to convict", c.name)
			}
			continue
		}
		if len(ticks) != 0 {
			t.Errorf("%s: conviction ticks = %v, want none", c.name, ticks)
		}
		if snapshot.TxConvictions != 0 || snapshot.RxConvictions != 0 {
			t.Errorf("%s: stats = %+v", c.name, snapshot)
		}
	}
}

// A loss denial re-arms the collapsed ring, so the direction is judged again
// four ticks later. The loss evidence has to be re-armed with it: a loss
// window that keeps its older ticks lets one out-of-order tick every few
// seconds accumulate across denials until the bar is met, and the denial then
// holds only for a path with almost no reordering at all. That denial is what
// keeps a provider-leg queue, which inflates the queue delay while the client
// socket is clean, from re-rolling the client's socket.
func TestH1PathMonitorLossDenialRestartsTheReceiveLossWindow(t *testing.T) {
	collapse := func(ooo func(k int) bool) func(k int) h1PathTickShape {
		return func(k int) h1PathTickShape {
			return h1PathTickShape{
				rxByteRate:        500_000,
				queueDelay:        6 * time.Second,
				queueDelaySamples: 4,
				rxOooAdvance:      ooo(k),
			}
		}
	}
	settings := DefaultH1PathRerollSettings()

	// one out-of-order tick every five, a reordering rate a healthy client
	// link reaches on its own
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 60, collapse(func(k int) bool { return k%5 == 0 }))
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
		t.Fatalf("conviction ticks = %v, want none: one tick in five is not loss evidence", ticks)
	}
	if denied := stats.SuppressedLossDenied.Load(); denied < 2 {
		t.Fatalf("loss denied %d times over 30 s, want a denial for each re-armed window", denied)
	}

	// loss that is really there still confirms: from 10 s on every tick
	// carries out-of-order data
	monitor, _ = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, collapse(func(k int) bool { return k%5 == 0 || 20 <= k }))
	ticks := h1PathConvictionTicks(decisions)
	if len(ticks) == 0 || ticks[0] < 20 {
		t.Fatalf("conviction ticks = %v, want the first once loss arrives at tick 20", ticks)
	}
}

// The send side denies a collapse without retransmits the same way, and its
// retransmit window is re-armed with its collapsed ring for the same reason.
func TestH1PathMonitorLossDenialRestartsTheSendLossWindow(t *testing.T) {
	collapse := func(retrans func(k int) bool) func(k int) h1PathTickShape {
		return func(k int) h1PathTickShape {
			return h1PathTickShape{
				rxByteRate:      20_000,
				txKnown:         true,
				txAckedByteRate: 500_000,
				txNotSent:       1024 * 1024,
				txRetrans:       retrans(k),
			}
		}
	}
	settings := DefaultH1PathRerollSettings()

	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 60, collapse(func(k int) bool { return k%5 == 0 }))
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
		t.Fatalf("conviction ticks = %v, want none: one retransmitting tick in five is not loss evidence", ticks)
	}
	if denied := stats.SuppressedLossDenied.Load(); denied < 2 {
		t.Fatalf("loss denied %d times over 30 s, want a denial for each re-armed window", denied)
	}

	monitor, _ = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, collapse(func(k int) bool { return k%5 == 0 || 20 <= k }))
	ticks := h1PathConvictionTicks(decisions)
	if len(ticks) == 0 || ticks[0] < 20 {
		t.Fatalf("conviction ticks = %v, want the first once retransmits arrive at tick 20", ticks)
	}
}

// A connection stuck on the lossy member for its whole life is the case this
// work targets, and it is the hardest one for a queue delay measured against a
// rolling minimum: once the uncongested minima age out of the baseline window
// the standing queue becomes its own baseline and the delay reads zero. The
// connection is then classified healthy for the rest of its life, which in
// Observe truncates the fleet measurement at one baseline window and in Act
// means a conviction the ledger refused once can never be made again.
func TestH1PathSessionLongCollapseStaysVisible(t *testing.T) {
	const sessionDuration = 20 * time.Minute
	const standingQueue = 6 * time.Second
	// the queue appears when the session's first bulk flow fills the far socket
	const queueStart = 5 * time.Second
	const transit = 200 * time.Millisecond

	settings := DefaultH1PathRerollSettings()
	baseline := newH1QueueDelayBaseline(&settings)
	observer := newH1RouteObserver(baseline, 1)
	monitor, _ := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	sourceId := NewId()

	sample := h1PathSample{
		rxBytesKnown: true,
		rxOooKnown:   true,
		minRtt:       105 * time.Millisecond,
		rcvMss:       1448,
		sndMss:       1448,
	}
	convictions := 0
	lastConviction := time.Duration(0)
	lastQueueDelay := time.Duration(0)
	for k := 1; k <= int(sessionDuration/h1PathTestStep); k += 1 {
		now := h1PathTestOrigin.Add(time.Duration(k) * h1PathTestStep)
		elapsed := now.Sub(h1PathTestOrigin)
		rel := transit
		if queueStart <= elapsed {
			rel += standingQueue
		}
		for i := 0; i < 4; i += 1 {
			observer.observePack(sourceId, h1ObserverTestTagMs(now.Add(-rel)), now)
		}
		tick := observer.takeTick(now)

		// 0.5 MB/s against a thin rate of 3.53 MB/s, out-of-order every tick
		sample.now = now
		sample.readMessageCount += 16
		sample.writeMessageCount += 1
		sample.readByteCount += uint64(500_000 * h1PathTestStep.Seconds())
		sample.rxBytes = sample.readByteCount
		sample.rxOoo += 3
		sample.queueDelay = 0
		sample.queueDelaySamples = 0
		if tick.known {
			sample.queueDelay = tick.queueDelay
			sample.queueDelaySamples = tick.samples
		}
		sample.ackRttMin = tick.ackRttMin
		if queueStart <= elapsed {
			lastQueueDelay = sample.queueDelay
		}
		if decision := monitor.tick(sample); decision.convicted {
			convictions += 1
			lastConviction = elapsed
		}
	}
	if lastQueueDelay < 3*time.Second {
		t.Errorf(
			"the queue delay after %s of a standing %s queue = %s, want the baseline to still hold it",
			sessionDuration, standingQueue, lastQueueDelay,
		)
	}
	if lastConviction < 15*time.Minute {
		t.Errorf(
			"the last of %d convictions was %s into a %s collapse, want one in the last quarter of the session",
			convictions, lastConviction, sessionDuration,
		)
	}
}

// The queue delay is read against the sender's clock, and nothing in a pack
// tag separates a standing queue from a sender whose clock stepped back: both
// add a constant to every rel. The ack echo carries our own send time and
// rides the same route as the packs, so a queue that holds the packs holds the
// acks with it. A fresh ack round trip with no queue in it is therefore the
// receive rule's only defence against a clock step, and the rule falls back to
// the queue delay alone when no ack was read.
func TestH1PathMonitorRequiresTheAckRoundTripToCorroborateAQueue(t *testing.T) {
	// 18 Mb/s under a thin rate of 3.53 MB/s, ordinary wi-fi reordering, and a
	// 2 s queue delay: every other input of a receive conviction
	slowLink := func(ackRtt time.Duration) func(k int) h1PathTickShape {
		return func(k int) h1PathTickShape {
			return h1PathTickShape{
				rxByteRate:        2_250_000,
				queueDelay:        2 * time.Second,
				queueDelaySamples: 4,
				rxOooAdvance:      true,
				ackRtt:            ackRtt,
			}
		}
	}
	for _, c := range []struct {
		name     string
		ackRtt   time.Duration
		convicts bool
	}{
		{name: "the ack round trip holds no queue", ackRtt: 110 * time.Millisecond},
		{name: "the ack round trip holds the same queue", ackRtt: 2100 * time.Millisecond, convicts: true},
		{name: "no ack was read on the route", convicts: true},
	} {
		settings := DefaultH1PathRerollSettings()
		monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
		decisions := runH1PathMonitorShape(monitor, 60, slowLink(c.ackRtt))
		ticks := h1PathConvictionTicks(decisions)
		if c.convicts != (0 < len(ticks)) {
			t.Errorf("%s: conviction ticks = %v, want convictions %t", c.name, ticks, c.convicts)
		}
		if denied := stats.RxAckDeniedTicks.Load(); c.convicts == (0 < denied) {
			t.Errorf("%s: %d ticks denied by the ack round trip", c.name, denied)
		}
	}

	// the window: an ack is evidence for AckEvidenceWindow, so a route that
	// carries one every 3 s never escapes it, and one that carries an ack every
	// 15 s leaves whole windows with nothing to read
	for _, c := range []struct {
		name     string
		ackEvery int
		convicts bool
	}{
		{name: "an ack every 3 s", ackEvery: 6},
		{name: "an ack every 15 s", ackEvery: 30, convicts: true},
	} {
		settings := DefaultH1PathRerollSettings()
		monitor, _ := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
		decisions := runH1PathMonitorShape(monitor, 60, func(k int) h1PathTickShape {
			shape := slowLink(0)(k)
			if k%c.ackEvery == 0 {
				shape.ackRtt = 110 * time.Millisecond
			}
			return shape
		})
		if ticks := h1PathConvictionTicks(decisions); c.convicts != (0 < len(ticks)) {
			t.Errorf("%s: conviction ticks = %v, want convictions %t", c.name, ticks, c.convicts)
		}
	}
}

// One tick of a connection driven through the real observer into the real
// monitor: packs whose tags sit rel behind the read, an ack whose echo sits
// ackRtt behind it, and the bytes the connection delivered.
type h1PathObserverTickShape struct {
	rel        time.Duration
	ackRtt     time.Duration
	rxByteRate float64
}

// Feeds the shape at each 500 ms tick from the test origin. Out-of-order data
// advances every tick, so the loss evidence is never what decides.
func runH1PathObserverMonitorShape(
	t *testing.T,
	settings *H1PathRerollSettings,
	duration time.Duration,
	shape func(elapsed time.Duration) h1PathObserverTickShape,
) ([]h1PathDecision, *h1PathStats) {
	t.Helper()
	baseline := newH1QueueDelayBaseline(settings)
	observer := newH1RouteObserver(baseline, 1)
	monitor, stats := newH1PathTestMonitor(t, settings, 105*time.Millisecond)
	sourceId := NewId()
	sample := h1PathSample{
		rxBytesKnown: true,
		rxOooKnown:   true,
		minRtt:       105 * time.Millisecond,
		rcvMss:       1448,
		sndMss:       1448,
	}
	decisions := []h1PathDecision{}
	for k := 1; k <= int(duration/h1PathTestStep); k += 1 {
		now := h1PathTestOrigin.Add(time.Duration(k) * h1PathTestStep)
		tickShape := shape(now.Sub(h1PathTestOrigin))
		for i := 0; i < 4; i += 1 {
			observer.observePack(sourceId, h1ObserverTestTagMs(now.Add(-tickShape.rel)), now)
		}
		if 0 < tickShape.ackRtt {
			observer.observeAck(h1ObserverTestTagMs(now.Add(-tickShape.ackRtt)), now)
		}
		tick := observer.takeTick(now)

		byteCount := uint64(tickShape.rxByteRate * h1PathTestStep.Seconds())
		sample.now = now
		sample.readMessageCount += 1 + byteCount/(16*1024)
		sample.writeMessageCount += 1
		sample.readByteCount += byteCount
		sample.rxBytes = sample.readByteCount
		sample.rxOoo += 3
		sample.queueDelay = 0
		sample.queueDelaySamples = 0
		if tick.known {
			sample.queueDelay = tick.queueDelay
			sample.queueDelaySamples = tick.samples
		}
		sample.ackRttMin = tick.ackRttMin
		sample.ackRtt = tick.ackRtt
		sample.ackRttSamples = tick.ackSamples
		decisions = append(decisions, monitor.tick(sample))
	}
	return decisions, stats
}

// A provider phone that acquires network time can step its clock back by
// seconds. Every pack it sends then reads that much late, for as long as the
// baseline holds the pre-step floor, which with the floor's rise rate is
// minutes. The client's own clock never moved, so nothing in checkClockStep
// fires; the ack round trip is what keeps the healthy link it is sharing off
// the rule, and it still lets the real collapse through.
func TestH1PathSenderClockStepDoesNotConvictASlowLink(t *testing.T) {
	const transit = 200 * time.Millisecond
	settings := DefaultH1PathRerollSettings()

	// 18 Mb/s of wi-fi, no queue of its own, and a 2 s backward step at 60 s
	decisions, stats := runH1PathObserverMonitorShape(t, &settings, 5*time.Minute,
		func(elapsed time.Duration) h1PathObserverTickShape {
			rel := transit
			if time.Minute <= elapsed {
				rel += 2 * time.Second
			}
			return h1PathObserverTickShape{
				rel:        rel,
				ackRtt:     110 * time.Millisecond,
				rxByteRate: 2_250_000,
			}
		})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
		t.Errorf("a 2 s backward clock step on the sender convicted at ticks %v", ticks)
	}
	if denied := stats.RxAckDeniedTicks.Load(); denied < 400 {
		t.Errorf("%d ticks denied by the ack round trip, want the step's ticks denied there", denied)
	}

	// without the check, which is where this rule stood before, the same step
	// convicts a healthy link and in Act re-dials it
	unchecked := settings
	unchecked.AckEvidenceWindow = 0
	decisions, _ = runH1PathObserverMonitorShape(t, &unchecked, 5*time.Minute,
		func(elapsed time.Duration) h1PathObserverTickShape {
			rel := transit
			if time.Minute <= elapsed {
				rel += 2 * time.Second
			}
			return h1PathObserverTickShape{
				rel:        rel,
				ackRtt:     110 * time.Millisecond,
				rxByteRate: 2_250_000,
			}
		})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) == 0 {
		t.Error("with the ack check off the clock step did not convict, so the arms above prove nothing")
	}

	// the measured collapse: 0.5 MB/s behind a 6 s queue that the ack round
	// trip carries too
	decisions, _ = runH1PathObserverMonitorShape(t, &settings, 5*time.Minute,
		func(elapsed time.Duration) h1PathObserverTickShape {
			shape := h1PathObserverTickShape{
				rel:        transit,
				ackRtt:     105 * time.Millisecond,
				rxByteRate: 500_000,
			}
			if 5*time.Second <= elapsed {
				shape.rel += 6 * time.Second
				shape.ackRtt = 6100 * time.Millisecond
			}
			return shape
		})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) == 0 {
		t.Error("the measured collapse was not convicted")
	}
}

// A full receive route means our own consumer set the tick's rate, so the tick
// cannot convict. It can still be clean: back pressure only ever lowers the
// delivered rate, so a tick that cleared the thin rate cleared it in spite of
// us. The cost of voiding it instead is paid after a re-roll, where CleanTicks
// clean ticks are what resolves the re-roll as improved: at 200 Mb/s a 32-slot
// receive route drains a frame every 140 us, so one 4.5 ms pause in the
// client's own receive loop fills it, and on a busy client almost every tick
// carries one.
func TestH1PathMonitorCleanTicksSurviveReceiveBackpressure(t *testing.T) {
	cleanTicks := func(decisions []h1PathDecision) int {
		clean := 0
		for _, decision := range decisions {
			if decision.clean {
				clean += 1
			}
		}
		return clean
	}
	settings := DefaultH1PathRerollSettings()

	// 200 Mb/s with the receive route full in every tick
	monitor, _ := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 60, func(k int) h1PathTickShape {
		return h1PathTickShape{
			rxByteRate:        25_000_000,
			queueDelay:        4 * time.Millisecond,
			queueDelaySamples: 400,
			receiveFull:       true,
		}
	})
	if clean := cleanTicks(decisions); clean != 59 {
		t.Errorf("%d of 59 ticks clean with the receive route full, want every one", clean)
	}

	// the same back pressure still holds a collapse shape off the rule, and a
	// tick under the thin rate is not clean either way
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, func(k int) h1PathTickShape {
		shape := h1PathHeldCollapseShape(k)
		shape.receiveFull = true
		return shape
	})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
		t.Errorf("a collapse shape behind our own back pressure convicted at ticks %v", ticks)
	}
	if clean := cleanTicks(decisions); clean != 0 {
		t.Errorf("%d ticks under the thin rate were clean", clean)
	}
	if snapshot := stats.snapshot(); snapshot.RxConvictions != 0 || snapshot.TxConvictions != 0 {
		t.Errorf("stats = %+v", snapshot)
	}

	// a speed test and a stand down are different: their bytes are not counted
	// at all, so no verdict can read the tick
	for _, c := range []struct {
		name  string
		shape func(k int) h1PathTickShape
	}{
		{
			name: "speed test",
			shape: func(k int) h1PathTickShape {
				return h1PathTickShape{rxByteRate: 25_000_000, speedTestActive: true}
			},
		},
		{
			name: "standing down",
			shape: func(k int) h1PathTickShape {
				return h1PathTickShape{rxByteRate: 25_000_000, standingDown: true}
			},
		},
	} {
		monitor, _ := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
		decisions := runH1PathMonitorShape(monitor, 60, c.shape)
		if clean := cleanTicks(decisions); clean != 0 {
			t.Errorf("%s: %d ticks clean, want none", c.name, clean)
		}
	}
}

// The demand floor is what keeps an application-limited connection off the
// receive rule, and it is the only thing that does: a session delivering
// 40 KB/s behind a 3 s queue, with out-of-order data and an ack round trip that
// carries the queue too, has every other input of a receive conviction. In Act
// that conviction is a real disconnect of a connection that is merely idle-ish.
func TestH1PathMonitorRequiresReceiveDemand(t *testing.T) {
	// the floor is MinTickByteCount over a tick, so the rate that meets it is
	// 32 KiB per 500 ms
	appLimited := func(byteRate float64) func(k int) h1PathTickShape {
		return func(k int) h1PathTickShape {
			return h1PathTickShape{
				rxByteRate:        byteRate,
				queueDelay:        3 * time.Second,
				queueDelaySamples: 4,
				rxOooAdvance:      true,
				ackRtt:            3100 * time.Millisecond,
			}
		}
	}
	for _, c := range []struct {
		name     string
		byteRate float64
		convicts bool
	}{
		{name: "40 KB/s of an idle-ish session", byteRate: 40_000},
		{name: "one byte under the demand floor", byteRate: 2 * (32*1024 - 1)},
		{name: "exactly the demand floor", byteRate: 2 * 32 * 1024, convicts: true},
	} {
		settings := DefaultH1PathRerollSettings()
		monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
		decisions := runH1PathMonitorShape(monitor, 60, appLimited(c.byteRate))
		ticks := h1PathConvictionTicks(decisions)
		if c.convicts != (0 < len(ticks)) {
			t.Errorf("%s: conviction ticks = %v, want convictions %t", c.name, ticks, c.convicts)
		}
		if snapshot := stats.snapshot(); c.convicts != (0 < snapshot.RxConvictions) {
			t.Errorf("%s: stats = %+v", c.name, snapshot)
		}
	}

	// a tick after an idle gap does not pass on bytes that trickled in over the
	// whole gap: the floor scales with the tick
	settings := DefaultH1PathRerollSettings()
	monitor, _ := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	sample := h1PathSample{
		rxBytesKnown: true,
		rxOooKnown:   true,
		minRtt:       105 * time.Millisecond,
		rcvMss:       1448,
		sndMss:       1448,
		queueDelay:   3 * time.Second,
		// samples enough for the delay to be known, and no ack to read
		queueDelaySamples: 4,
	}
	// ten-second ticks carrying 40 KB each: over the floor for a 500 ms tick,
	// well under it for the tick that actually elapsed
	for k := 0; k < 12; k += 1 {
		sample.now = h1PathTestOrigin.Add(time.Duration(k) * 10 * time.Second)
		sample.readMessageCount += 3
		sample.writeMessageCount += 1
		sample.readByteCount += 40_000
		sample.rxBytes = sample.readByteCount
		sample.rxOoo += 3
		if decision := monitor.tick(sample); decision.convicted {
			t.Fatalf("a 40 kB tick over 10 s convicted at %s", sample.now.Sub(h1PathTestOrigin))
		}
	}
}

// The pack-sample floor is what keeps a queue delay resting on a single frame
// from convicting on the pack tags alone. At its default of 2 nothing
// exercised it: the unit shapes feed 4 to 400 samples, the platform rig
// hard-codes 4, and pathsim S9 lowers it to 1 because at 16 KiB payloads a
// collapsed connection yields about one sample a tick -- the one scenario that
// would have covered the default turns it off.
//
// The floor governs the pack tags and nothing else. A tick with a fresh ack
// round trip that holds the queue collapses however few packs it sampled,
// because that reading needs no baseline and no sender clock.
func TestH1PathMonitorRequiresTwoPackSamples(t *testing.T) {
	if samples := DefaultH1PathRerollSettings().MinTickPackSamples; samples != 2 {
		t.Fatalf("the default pack sample floor = %d, want 2", samples)
	}
	collapse := func(samples int, ackRtt time.Duration) func(k int) h1PathTickShape {
		return func(k int) h1PathTickShape {
			shape := h1PathCollapseShape(k)
			shape.queueDelay = 6 * time.Second
			shape.queueDelaySamples = samples
			shape.ackRtt = ackRtt
			return shape
		}
	}
	for _, c := range []struct {
		name     string
		samples  int
		floor    int
		ackRtt   time.Duration
		convicts bool
	}{
		{name: "one sample in the tick", samples: 1, floor: 2},
		{name: "two samples in the tick", samples: 2, floor: 2, convicts: true},
		// what pathsim S9 sets, where the frame size and not the detector is
		// what the simulator cannot reproduce
		{name: "one sample against a floor of one", samples: 1, floor: 1, convicts: true},
		// the ack carries the tick whatever the floor keeps out
		{
			name:     "one sample and an ack round trip that holds the queue",
			samples:  1,
			floor:    2,
			ackRtt:   6100 * time.Millisecond,
			convicts: true,
		},
		{
			name:     "no sample at all and an ack round trip that holds the queue",
			samples:  0,
			floor:    2,
			ackRtt:   6100 * time.Millisecond,
			convicts: true,
		},
	} {
		settings := DefaultH1PathRerollSettings()
		settings.MinTickPackSamples = c.floor
		monitor, _ := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
		decisions := runH1PathMonitorShape(monitor, 60, collapse(c.samples, c.ackRtt))
		ticks := h1PathConvictionTicks(decisions)
		if c.convicts != (0 < len(ticks)) {
			t.Errorf("%s: conviction ticks = %v, want convictions %t", c.name, ticks, c.convicts)
		}
		if known := decisions[59].queueDelayKnown; known != (0 < c.samples && c.floor <= c.samples) {
			t.Errorf("%s: queue delay known = %t", c.name, known)
		}
	}
}

// The population this detector exists for is a session that starts on the bad
// member: the ground truth is a 4-tuple that rides a slow path for hours, so
// the far socket is already deep when the transport reads its first frame. The
// pack baseline is the smallest rel a source has ever shown and it only moves
// down, so a queue standing at the first sample is inside the baseline and the
// queue delay reads zero for the connection's whole life -- the connection the
// feature was built for was the one it could not see.
//
// The ack echo needs no baseline and no sender clock: it is this client's own
// send time, read against a dial round trip taken before any of the queue
// existed. It therefore carries the queue whatever the pack tags hold, and a
// collapse that was standing at birth is convicted on the same schedule as one
// that arrives later.
func TestH1PathMonitorConvictsACollapseStandingAtTheFirstSample(t *testing.T) {
	const transit = 200 * time.Millisecond
	const queue = 6 * time.Second
	const pathRtt = 105 * time.Millisecond
	settings := DefaultH1PathRerollSettings()
	queueDelayThreshold := max(
		settings.QueueDelayFloor,
		time.Duration(settings.QueueDelayRttMultiple)*pathRtt,
	)

	for _, c := range []struct {
		name       string
		queueAfter time.Duration
	}{
		{name: "standing before the first frame", queueAfter: 0},
		{name: "standing at 500 ms", queueAfter: 500 * time.Millisecond},
		{name: "arriving at 10 s", queueAfter: 10 * time.Second},
	} {
		decisions, _ := runH1PathObserverMonitorShape(t, &settings, 3*time.Minute,
			func(elapsed time.Duration) h1PathObserverTickShape {
				shape := h1PathObserverTickShape{
					rel:        transit,
					ackRtt:     pathRtt,
					rxByteRate: 700_000,
				}
				if c.queueAfter <= elapsed {
					shape.rel += queue
					shape.ackRtt += queue
				}
				return shape
			})
		ticks := h1PathConvictionTicks(decisions)
		if len(ticks) == 0 {
			t.Errorf("%s: a %s queue was never convicted", c.name, queue)
			continue
		}
		// four collapsed ticks past MinConnectionAge, from the tick the queue
		// is first read in
		first := time.Duration(ticks[0]+1) * h1PathTestStep
		if want := c.queueAfter + settings.MinConnectionAge + 2*time.Second; want < first {
			t.Errorf("%s: first conviction at %s, want one by %s", c.name, first, want)
		}
	}

	// the mechanism: with the queue standing at the first sample the pack tags
	// never show it, so the conviction above is the ack's alone
	decisions, stats := runH1PathObserverMonitorShape(t, &settings, time.Minute,
		func(elapsed time.Duration) h1PathObserverTickShape {
			return h1PathObserverTickShape{
				rel:        transit + queue,
				ackRtt:     pathRtt + queue,
				rxByteRate: 700_000,
			}
		})
	for k, decision := range decisions {
		if queueDelayThreshold <= decision.queueDelay {
			t.Fatalf(
				"tick %d read a queue delay of %s from the pack tags, so this arm proves nothing",
				k, decision.queueDelay,
			)
		}
	}
	if denied := stats.RxAckDeniedTicks.Load(); 0 < denied {
		t.Errorf("%d ticks denied by the ack round trip, want the ack to carry the queue", denied)
	}
}

// The observer's two discard counts reach the process counters. Without them
// the sticky slot rule's one blind spot -- a source that goes quiet for a whole
// baseline window, loses its slot, and comes back to take its own standing
// queue for a floor -- cannot be seen from an Observe rollout at all, and
// neither can a re-roll whose replacement is still being handed the retired
// connection's tags.
func TestH1PathMonitorCountsThePacksTheObserverCouldNotRead(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	baseline := newH1QueueDelayBaseline(&settings)
	observer := newH1RouteObserver(baseline, 1)
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	sample := h1PathSample{
		rxBytesKnown: true,
		rxOooKnown:   true,
		minRtt:       105 * time.Millisecond,
		rcvMss:       1448,
		sndMss:       1448,
	}
	feed := func(k int, tick h1ObserverTick) {
		sample.now = h1PathTestOrigin.Add(time.Duration(k) * h1PathTestStep)
		sample.readMessageCount += 16
		sample.writeMessageCount += 1
		sample.readByteCount += uint64(700_000 * h1PathTestStep.Seconds())
		sample.rxBytes = sample.readByteCount
		sample.queueDelay = tick.queueDelay
		sample.queueDelaySamples = 0
		if tick.known {
			sample.queueDelaySamples = tick.samples
		}
		sample.stalePacks = tick.stale
		sample.unslottedPacks = tick.unslotted
		monitor.tick(sample)
	}

	// one source establishes a baseline, then a re-roll mark makes its older
	// tags stale
	sourceId := NewId()
	start := h1PathTestOrigin
	for i := 0; i < 4; i += 1 {
		observer.observePack(sourceId, h1ObserverTestTagMs(start.Add(-200*time.Millisecond)), start)
	}
	feed(0, observer.takeTick(start))

	rerollTime := start.Add(h1PathTestStep)
	baseline.markReroll(rerollTime, 105*time.Millisecond)
	afterReroll := rerollTime.Add(h1PathTestStep)
	for i := 0; i < 3; i += 1 {
		observer.observePack(sourceId, h1ObserverTestTagMs(rerollTime.Add(-time.Second)), afterReroll)
	}
	staleTick := observer.takeTick(afterReroll)
	if staleTick.stale != 3 {
		t.Fatalf("observer tick = %+v, want 3 stale packs", staleTick)
	}
	feed(2, staleTick)

	// and more sources than the baseline holds slots for: the ones it refuses
	// read nothing
	unslottedTime := afterReroll.Add(h1PathTestStep)
	for i := 0; i < 2*h1QueueDelaySourceCount; i += 1 {
		other := NewId()
		observer.observePack(other, h1ObserverTestTagMs(unslottedTime.Add(-200*time.Millisecond)), unslottedTime)
		observer.observePack(other, h1ObserverTestTagMs(unslottedTime.Add(-200*time.Millisecond)), unslottedTime)
	}
	unslottedTick := observer.takeTick(unslottedTime)
	if unslottedTick.unslotted == 0 {
		t.Fatalf("observer tick = %+v, want packs of sources with no slot", unslottedTick)
	}
	feed(3, unslottedTick)

	snapshot := stats.snapshot()
	if snapshot.PacksStale != 3 {
		t.Errorf("stats = %+v, want the 3 stale packs counted", snapshot)
	}
	if snapshot.PacksUnslotted != uint64(unslottedTick.unslotted) {
		t.Errorf("stats = %+v, want %d unslotted packs counted", snapshot, unslottedTick.unslotted)
	}
}

// The scope limit behind the test above, stated where it can fail. The pack
// tags measure a queue against what the source has already shown, so a queue
// that was standing when the source's floor was set is inside the floor and
// reads as zero for the connection's life. The ack echo is the only evidence
// that needs no floor of the sender's, so a route carrying no ack does not read
// a queue standing at birth at all, in Observe or in Act.
//
// Neither candidate for an independent floor closes it. Neither the dial round
// trip nor the kernel's minimum round trip bounds the offset between the two
// clocks that every rel carries, and neither one times the far socket's send
// queue, which sits upstream of everything our kernel measures: our own
// segments never wait behind it. A round trip on our own clock is the only
// thing that does, which is what the ack echo is. The limit is therefore the
// shape of the evidence and not a gap in the rule, and what it costs is read
// from TicksAckUnknown against Ticks.
func TestH1PathMonitorCannotReadABirthQueueOnARouteWithNoAck(t *testing.T) {
	const transit = 200 * time.Millisecond
	const queue = 6 * time.Second
	settings := DefaultH1PathRerollSettings()
	noAckShape := func(queueAfter time.Duration) func(elapsed time.Duration) h1PathObserverTickShape {
		return func(elapsed time.Duration) h1PathObserverTickShape {
			shape := h1PathObserverTickShape{rel: transit, rxByteRate: 700_000}
			if queueAfter <= elapsed {
				shape.rel += queue
			}
			return shape
		}
	}

	decisions, stats := runH1PathObserverMonitorShape(t, &settings, 3*time.Minute, noAckShape(0))
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
		t.Errorf("a queue standing at the first sample convicted at ticks %v with no ack to read", ticks)
	}
	snapshot := stats.snapshot()
	if snapshot.TicksCollapsed != 0 {
		t.Errorf("stats = %+v, want the connection invisible for its whole life", snapshot)
	}
	if snapshot.Ticks == 0 || snapshot.TicksAckUnknown != snapshot.Ticks {
		t.Errorf("stats = %+v, want every tick counted with no ack to read", snapshot)
	}

	// and the boundary: the same route reads a queue that arrives after the
	// floor is set, so what is lost is the queue standing at birth and not the
	// pack rule
	decisions, _ = runH1PathObserverMonitorShape(t, &settings, 3*time.Minute, noAckShape(10*time.Second))
	if ticks := h1PathConvictionTicks(decisions); len(ticks) == 0 {
		t.Error("a queue arriving at 10 s was never convicted from the pack tags alone")
	}
}

// A tick that could read no queue at all is not a tick with no queue in it, so
// it cannot resolve a re-roll as improved. The window right after a re-roll is
// exactly that tick: every arriving pack was built before the mark and reads
// stale, and a route with no ack has nothing else, so twenty of them in a row
// would credit the replacement with an improvement while it sat on the same bad
// member -- and hand back the unconfirmed budget that is the only thing
// stopping the next re-roll.
func TestH1PathMonitorDoesNotCreditABlindTickAsClean(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	// 700 KB/s under a thin rate of 3.53 MB/s, so the rate reading cannot
	// carry these ticks either way
	blind := func(k int) h1PathTickShape {
		return h1PathTickShape{rxByteRate: 700_000}
	}
	monitor, _ := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	for k, decision := range runH1PathMonitorShape(monitor, 30, blind) {
		if decision.clean {
			t.Fatalf("tick %d with no pack samples and no ack was credited clean: %+v", k, decision)
		}
	}

	// the same rate with pack samples that read no queue is clean, so what the
	// arm above shows is the blindness and not the rate
	monitor, _ = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	cleanTicks := 0
	for _, decision := range runH1PathMonitorShape(monitor, 30, func(k int) h1PathTickShape {
		shape := blind(k)
		shape.queueDelaySamples = 4
		return shape
	}) {
		if decision.clean {
			cleanTicks += 1
		}
	}
	if cleanTicks < settings.CleanTicks {
		t.Errorf("%d clean ticks with a readable queue, want at least %d", cleanTicks, settings.CleanTicks)
	}
}

// A queue the ack round trip reads is bounded by BaselineRisePerMinute exactly
// as a queue the pack tags read is: visible for (q - thr) / rise and then gone,
// rather than convicting for as long as it stands. The hour this runs for is
// the check that it is gone and stays gone -- a reference that restarts against
// itself hides the queue, reads the hidden queue as a healthy route, drops back
// and convicts again on the same cycle for ever.
func TestH1PathMonitorAckQueueDecaysAtTheBaselineRise(t *testing.T) {
	const pathRtt = 101 * time.Millisecond
	const queue = 3 * time.Second
	// 700 KB/s under thin, a queue only the acks carry from 10 s on, and
	// out-of-order data every tick
	settings := DefaultH1PathRerollSettings()
	monitor, stats := newH1PathTestMonitor(t, &settings, pathRtt)
	decisions := runH1PathMonitorShape(monitor, int(time.Hour/h1PathTestStep), func(k int) h1PathTickShape {
		shape := h1PathTickShape{
			rxByteRate:        700_000,
			queueDelaySamples: 4,
			rxOooAdvance:      true,
			minRtt:            pathRtt,
			ackRtt:            pathRtt,
		}
		if 20 <= k {
			shape.ackRtt = pathRtt + queue
		}
		return shape
	})
	ticks := h1PathConvictionTicks(decisions)
	if len(ticks) == 0 {
		t.Fatal("a 3 s ack queue never convicted")
	}
	first := time.Duration(ticks[0]) * h1PathTestStep
	last := time.Duration(ticks[len(ticks)-1]) * h1PathTestStep
	if want := 12 * time.Second; first > want {
		t.Errorf("first conviction at %s, want it inside %s of the queue standing", first, want)
	}
	// (3 s - 1.01 s of threshold) / 100 ms a minute, from the 10 s the queue
	// starts at
	if lower, upper := 19*time.Minute, 21*time.Minute; last < lower || upper < last {
		t.Errorf(
			"last of %d convictions at %s, want the rise to end them between %s and %s",
			len(ticks), last, lower, upper,
		)
	}
	t.Logf("3 s ack queue: %d convictions from %s to %s in an hour, %d collapsed ticks",
		len(ticks), first, last, stats.snapshot().TicksCollapsed)
}

// The ack round trip carries our own uplink's standing queue as well as the
// receive path's, and the time our send buffer takes to drain says nothing
// about what is arriving. A device uploading hard while it downloads therefore
// reads an ack round trip of seconds on a receive path that has no queue at
// all, and without the send backlog guard that alone would collapse every
// receive tick.
//
// The guard is the time that backlog takes to drain at the rate the wire is
// acking, floored by a byte count small enough to be no more than a moment of
// any uplink this rule applies to. The drain time is what has to decide,
// because the queue it is asking about is a duration and not a byte count: the
// arms below are a 400 KiB backlog that is a real queue on a 1.6 Mb/s uplink
// and no queue at all on a 200 Mb/s one, and 60 KB that is two seconds of a
// 0.25 Mb/s uplink and nowhere near the byte bar a send conviction needs.
func TestH1PathMonitorDoesNotReadOurOwnSendQueueAsTheReceiveQueue(t *testing.T) {
	// 700 KB/s down, no receive queue, and an uplink holding 400 KiB it takes
	// 2 s to drain, which is what can put 7 s into every ack round trip
	uploader := func(k int) h1PathTickShape {
		return h1PathTickShape{
			rxByteRate:        700_000,
			queueDelay:        20 * time.Millisecond,
			queueDelaySamples: 4,
			rxOooAdvance:      true,
			ackRtt:            7 * time.Second,
			txKnown:           true,
			txAckedByteRate:   200_000,
			txNotSent:         400 * 1024,
		}
	}
	settings := DefaultH1PathRerollSettings()
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 60, uploader)
	for k, decision := range decisions {
		if decision.convicted && decision.direction == h1PathDirectionRx {
			t.Fatalf("tick %d convicted the receive path behind our own send queue: %+v", k, decision)
		}
		if decision.ackQueueKnown {
			t.Fatalf("tick %d read our own send queue as ack evidence: %+v", k, decision)
		}
	}
	if snapshot := stats.snapshot(); snapshot.RxConvictions != 0 || snapshot.TicksAckBacklogged == 0 {
		t.Errorf("stats = %+v, want no receive conviction and the ack withdrawn", snapshot)
	}

	// the same shape with a send queue that clears in 150 ms: the ack round
	// trip is then the receive path's and it convicts, so the arm above is the
	// guard and not the rest of the rule
	monitor, _ = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, func(k int) h1PathTickShape {
		shape := uploader(k)
		shape.txNotSent = 30 * 1024
		return shape
	})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) == 0 {
		t.Error("a send queue that clears in 150 ms withdrew the ack evidence")
	}

	// A slow uplink puts the same seconds into the round trip with a backlog
	// nowhere near the byte bar a send conviction needs: 60 KB at 0.25 Mb/s is
	// two seconds. This is the case the byte bar hid while it was ANDed with
	// the drain time, and the receive path here has no queue at all.
	slow := func(k int) h1PathTickShape {
		shape := uploader(k)
		shape.ackRtt = 2 * time.Second
		shape.txAckedByteRate = 31_250
		shape.txNotSent = 60_000
		return shape
	}
	monitor, stats = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, slow)
	for k, decision := range decisions {
		if decision.convicted || decision.ackQueueKnown {
			t.Fatalf("tick %d read a 0.25 Mb/s uplink's own two seconds as the receive path's: %+v", k, decision)
		}
	}
	if snapshot := stats.snapshot(); snapshot.TicksAckBacklogged == 0 {
		t.Errorf("stats = %+v, want the slow uplink's ticks counted as our own backlog", snapshot)
	}
	// and its send direction is not convicted for it either: 60 KB is a queue
	// in time and not a backlog, so only the ack evidence is withdrawn
	if snapshot := stats.snapshot(); snapshot.TxConvictions != 0 {
		t.Errorf("stats = %+v, want no send conviction from a 60 KB backlog", snapshot)
	}

	// The floor is the one thing the drain time alone gets wrong: a socket
	// with a few bytes pending and nothing acked in the tick drains in no time
	// at all, for ever. Its ack round trip is still the receive path's.
	monitor, stats = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, func(k int) h1PathTickShape {
		shape := uploader(k)
		shape.txAckedByteRate = 0
		shape.txNotSent = 8 * 1024
		return shape
	})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) == 0 {
		t.Error("a quiet socket with 8 KiB pending withdrew the ack evidence")
	}
	if snapshot := stats.snapshot(); snapshot.TicksAckBacklogged != 0 {
		t.Errorf("stats = %+v, want nothing read as our own backlog under the floor", snapshot)
	}

	// and with the same 400 KiB on an uplink that clears it in 16 ms: our own
	// send queue cannot be what put 7 s into the round trip, so the evidence
	// stands and the receive path is convicted
	monitor, stats = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, func(k int) h1PathTickShape {
		shape := uploader(k)
		shape.txAckedByteRate = 25_000_000
		return shape
	})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) == 0 {
		t.Error("a backlog that drains in 16 ms withdrew the ack evidence")
	}
	if snapshot := stats.snapshot(); snapshot.TicksAckBacklogged != 0 {
		t.Errorf("stats = %+v, want no tick read as our own backlog", snapshot)
	}
}

// What one arm of the evidence policy produced: the monitor's verdicts and
// what the process ledger did with them.
type h1PathPolicyOutcome struct {
	collapsedTicks  uint64
	ackDeniedTicks  uint64
	convictions     int
	confirmed       int
	unconfirmed     int
	rerolls         int
	suppressed      map[h1PathReason]int
	firstConviction time.Duration
	lastConviction  time.Duration
}

func (self h1PathPolicyOutcome) String() string {
	return fmt.Sprintf(
		"collapsed=%d ackdenied=%d convictions=%d(%dc/%du) rerolls=%d suppressed=%v first=%s last=%s",
		self.collapsedTicks, self.ackDeniedTicks,
		self.convictions, self.confirmed, self.unconfirmed, self.rerolls,
		self.suppressed, self.firstConviction, self.lastConviction,
	)
}

// Runs the shape through the real monitor and the real connection decision
// against a real process ledger, so an arm reads the whole cost of a shape and
// not only its verdicts. The shape keeps producing whatever it produced, which
// is the pessimistic reading: a re-roll here never lands anywhere better.
//
// A re-roll rebuilds the monitor and resets the connection's own state, which
// is what production does -- every dial builds both (newH1PathConnection) --
// and it is what decides how long a shape stays visible, because the ack
// round trip's floor and rise live on the monitor and start again with it
// while the pack baseline and the rolling ack minimum do not. A harness that
// kept one monitor for a whole run measured a bufferbloated link as costing
// three re-rolls where it costs six.
func runH1PathPolicyShape(
	t *testing.T,
	settings *H1PathRerollSettings,
	dialRtt time.Duration,
	tickCount int,
	shape func(k int) h1PathTickShape,
) h1PathPolicyOutcome {
	t.Helper()
	connection, _ := testingH1PathDecideConnection(H1PathRerollModeAct, false)
	*connection.settings = *settings
	settings = connection.settings
	dial := func(now time.Time) {
		monitor := newH1PathMonitor(settings, now, dialRtt)
		if monitor == nil {
			t.Fatalf("no monitor for dial rtt %s", dialRtt)
		}
		monitor.stats = connection.stats
		connection.monitor = monitor
		connection.cleanTicks = h1PathCleanTicks{}
		connection.convicted = false
	}
	dial(h1PathTestOrigin)

	outcome := h1PathPolicyOutcome{suppressed: map[h1PathReason]int{}}
	run := &h1PathShapeRun{}
	for k := 0; k < tickCount; k += 1 {
		elapsed := time.Duration(k) * h1PathTestStep
		now := h1PathTestOrigin.Add(elapsed)
		decision := connection.monitor.tick(*run.tickSample(settings, k, shape(k)))
		connection.decide(now, &decision)
		if decision.convicted {
			outcome.convictions += 1
			if outcome.firstConviction == 0 {
				outcome.firstConviction = elapsed
			}
			outcome.lastConviction = elapsed
			switch decision.confidence {
			case h1PathConfidenceConfirmed:
				outcome.confirmed += 1
			case h1PathConfidenceUnconfirmed:
				outcome.unconfirmed += 1
			}
		}
		switch decision.action {
		case h1PathActionReroll:
			outcome.rerolls += 1
			dial(now)
		case h1PathActionSuppressed:
			outcome.suppressed[decision.reason] += 1
		}
	}
	snapshot := connection.stats.snapshot()
	outcome.collapsedTicks = snapshot.TicksCollapsed
	outcome.ackDeniedTicks = snapshot.RxAckDeniedTicks
	return outcome
}

// One tick of a probe that re-dials: what the receive route carries, on the
// sender's clock and on ours.
type h1PathRerollProbeShape struct {
	// the pack tags' transit -- the path, plus whatever queue stands in front
	// of the far socket -- read against the sender's clock
	rel time.Duration
	// this tick's ack echo round trip; zero leaves the tick with no ack to
	// read, which is every tick of a route whose peer answers elsewhere and
	// most ticks of a download-heavy client, whose acks are echoes of its own
	// sparse sends
	ackRtt     time.Duration
	rxByteRate float64
	// the source the packs come from; the zero Id keeps the previous one
	sourceId Id
}

// What a probe run cost the device.
type h1PathRerollProbeOutcome struct {
	convictions int
	rerolls     int
	rerollTimes []time.Duration
	improved    uint64
	suppressed  map[h1PathReason]int
}

func (self h1PathRerollProbeOutcome) String() string {
	return fmt.Sprintf(
		"convictions=%d rerolls=%d at=%v improved=%d suppressed=%v",
		self.convictions, self.rerolls, self.rerollTimes, self.improved, self.suppressed,
	)
}

// Drives the real observer, the real shared baseline, the real monitor, the
// connection's own decide and a real ledger, and re-dials the way production
// does: an allowed re-roll builds a new monitor and a new observer on the
// transport's shared baseline, so the ack floor and the connection's age start
// again with the connection while the pack baseline does not
// (PlatformTransport.newH1PathConnection). That is what runH1PathPolicyShape
// cannot read -- it keeps one monitor for a whole run, which answers what one
// connection costs -- and it is the only way to see what a replacement is
// credited for.
func runH1PathRerollProbe(
	t *testing.T,
	settings *H1PathRerollSettings,
	dialRtt time.Duration,
	duration time.Duration,
	shape func(elapsed time.Duration, connectionOrdinal int) h1PathRerollProbeShape,
) (h1PathRerollProbeOutcome, *h1PathStats, *h1PathLedger) {
	t.Helper()
	connection, ledger := testingH1PathDecideConnection(H1PathRerollModeAct, false)
	*connection.settings = *settings
	settings = connection.settings
	baseline := newH1QueueDelayBaseline(settings)
	connection.transport.h1PathBaseline = baseline

	start := h1PathTestOrigin
	newConnection := func(now time.Time) (*h1RouteObserver, h1PathSample) {
		monitor := newH1PathMonitor(settings, now, dialRtt)
		if monitor == nil {
			t.Fatalf("no monitor for dial rtt %s", dialRtt)
		}
		monitor.stats = connection.stats
		connection.monitor = monitor
		// the dial builds a connection as well as a monitor, and its clean
		// ticks and its first-conviction mark start again with it
		connection.cleanTicks = h1PathCleanTicks{}
		connection.convicted = false
		// every frame is sampled, so a tick reads what the shape says
		return newH1RouteObserver(baseline, 1), h1PathSample{
			rxBytesKnown: true,
			rxOooKnown:   true,
			minRtt:       dialRtt,
			rcvMss:       1448,
			sndMss:       1448,
		}
	}
	observer, sample := newConnection(start)

	outcome := h1PathRerollProbeOutcome{suppressed: map[h1PathReason]int{}}
	sourceId := NewId()
	connectionOrdinal := 0
	for k := 1; k <= int(duration/h1PathTestStep); k += 1 {
		now := start.Add(time.Duration(k) * h1PathTestStep)
		elapsed := now.Sub(start)
		tickShape := shape(elapsed, connectionOrdinal)
		if tickShape.sourceId != (Id{}) {
			sourceId = tickShape.sourceId
		}
		for i := 0; i < 4; i += 1 {
			observer.observePack(sourceId, h1ObserverTestTagMs(now.Add(-tickShape.rel)), now)
		}
		if 0 < tickShape.ackRtt {
			observer.observeAck(h1ObserverTestTagMs(now.Add(-tickShape.ackRtt)), now)
		}
		observerTick := observer.takeTick(now)

		byteCount := uint64(tickShape.rxByteRate * h1PathTestStep.Seconds())
		sample.now = now
		sample.readMessageCount += 1 + byteCount/(16*1024)
		sample.writeMessageCount += 1
		sample.readByteCount += byteCount
		sample.rxBytes += byteCount
		// out-of-order data every tick, so the loss evidence is never what
		// decides
		sample.rxOoo += 3
		sample.queueDelay = 0
		sample.queueDelaySamples = 0
		sample.queueDelaySlotTime = time.Time{}
		if observerTick.known {
			sample.queueDelay = observerTick.queueDelay
			sample.queueDelaySamples = observerTick.samples
			sample.queueDelaySlotTime = observerTick.queueDelaySlotTime
		}
		sample.ackRttMin = observerTick.ackRttMin
		sample.ackRtt = observerTick.ackRtt
		sample.ackRttSamples = observerTick.ackSamples

		decision := connection.monitor.tick(sample)
		connection.decide(now, &decision)
		if decision.convicted {
			outcome.convictions += 1
		}
		switch decision.action {
		case h1PathActionReroll:
			outcome.rerolls += 1
			outcome.rerollTimes = append(outcome.rerollTimes, elapsed)
			connectionOrdinal += 1
			observer, sample = newConnection(now)
		case h1PathActionSuppressed:
			outcome.suppressed[decision.reason] += 1
		}
	}
	outcome.improved = connection.stats.snapshot().Improved
	return outcome, connection.stats, ledger
}

// The improvement credit on the population the feature exists for: a session
// that starts bad and stays bad, and a client whose re-roll lands on a member
// as slow as the one it left.
//
// Such a session's pack baseline is built under the standing queue -- the
// source was first read inside it -- so the queue delay reads zero for the
// connection's life, on the replacement exactly as on the connection that was
// convicted. The ack echo is the only measure that reads the queue, and a
// download-heavy client's acks are echoes of its own sparse sends, so most
// ticks have none. Crediting the ticks in between credits a replacement for
// being invisible, and because an improvement resets the epoch's unimproved
// count and its unconfirmed budget together, it turns off both of the things
// bounding a client that keeps re-rolling: the device pays a break-before-make
// disconnect every time the acks go quiet long enough. What has to happen here
// is the design's own number -- two re-rolls, then the latch.
func TestH1PathRerollOntoAnotherSlowMemberStillLatches(t *testing.T) {
	const transit = 101 * time.Millisecond
	const queue = 6 * time.Second
	settings := DefaultH1PathRerollSettings()

	// 700 KB/s behind a 6 s queue standing from the first frame, and an ack
	// echo that comes back every twenty seconds and carries the same queue.
	// The queue is read for the five seconds an ack is evidence for
	// (AckEvidenceWindow) and nothing reads it for the fifteen after that,
	// which is the ordinary shape of a download: the acks a client reads on
	// this route are echoes of its own sends.
	outcome, stats, ledger := runH1PathRerollProbe(t, &settings, transit, 20*time.Minute,
		func(elapsed time.Duration, connectionOrdinal int) h1PathRerollProbeShape {
			shape := h1PathRerollProbeShape{rel: transit + queue, rxByteRate: 700_000}
			if elapsed%(20*time.Second) == 0 {
				shape.ackRtt = transit + queue
			}
			return shape
		})
	t.Logf("every member as slow as the last: %s", outcome)
	if outcome.rerolls != settings.MaxUnimprovedRerolls {
		t.Errorf(
			"%s, want the %d re-rolls the unimproved latch allows",
			outcome, settings.MaxUnimprovedRerolls,
		)
	}
	if outcome.improved != 0 {
		t.Errorf("%s, want no replacement credited while every one of them stayed collapsed", outcome)
	}
	if outcome.suppressed[h1PathReasonLatched] == 0 {
		t.Errorf("%s, want the epoch latched", outcome)
	}
	if snapshot := stats.snapshot(); snapshot.TicksAckUnknown == 0 || snapshot.TicksAckUnknown == snapshot.Ticks {
		t.Errorf(
			"stats = %+v, want the blind ticks this reads to be some of the ticks and not all of them",
			snapshot,
		)
	}
	if state := testingH1PathLedgerSnapshot(ledger); state.epochUnimproved < settings.MaxUnimprovedRerolls {
		t.Errorf("ledger = %+v, want both re-rolls charged", state)
	}

	// The same reading from the other measure. A route with no ack at all
	// convicts on the pack tags, and after the re-roll its traffic comes from a
	// source the shared baseline has never held a slot for: that source's floor
	// is set inside the queue still standing, so its queue delay reads zero
	// from the first tick. A floor this connection watched being set is not
	// evidence that a queue lifted, and crediting it here would hand back the
	// unconfirmed budget that is the only thing stopping the next re-roll.
	replacementSource := NewId()
	outcome, _, ledger = runH1PathRerollProbe(t, &settings, transit, 3*time.Minute,
		func(elapsed time.Duration, connectionOrdinal int) h1PathRerollProbeShape {
			shape := h1PathRerollProbeShape{rel: transit, rxByteRate: 700_000}
			if 30*time.Second <= elapsed {
				shape.rel += queue
			}
			if 0 < connectionOrdinal {
				shape.sourceId = replacementSource
			}
			return shape
		})
	t.Logf("a replacement read from a source the baseline has never seen: %s", outcome)
	if outcome.rerolls != 1 || outcome.convictions == 0 {
		t.Errorf("%s, want the one re-roll the unconfirmed budget allows", outcome)
	}
	if outcome.improved != 0 {
		t.Errorf("%s, want no credit from a floor set inside the queue being judged", outcome)
	}
	if state := testingH1PathLedgerSnapshot(ledger); state.epochUnconfirmed != 1 {
		t.Errorf("ledger = %+v, want the unconfirmed budget still spent", state)
	}
}

// The evidence policy on the shapes the rollout has to be sized against, each
// driven through the real monitor and the real ledger. The file header states
// the same four readings in words; this is where they are measured.
//
// The queue delay and the ack round trip are two measures of one queue. The
// queue delay is read on the sender's clock against a baseline built from what
// that source has shown, so it is wrong in both directions: a backward clock
// step on the sender adds a queue that is not there, and a queue already
// standing when the source was first read is inside the baseline and never
// appears. The ack round trip is this client's own send time against the dial
// round trip, so a conviction it backs is one this device checked. A
// conviction with no ack to read stands -- going blind on every route whose
// peer answers over another transport would cost more than it saves -- but it
// is unconfirmed, and the epoch's unconfirmed budget of one is what bounds it.
func TestH1PathEvidencePolicyOnTheMeasuredShapes(t *testing.T) {
	const pathRtt = 101 * time.Millisecond
	settings := DefaultH1PathRerollSettings()

	// the same datacenter: no monitor at all, and a connection whose kernel
	// later reports a shorter path is dormant from its first tick
	if monitor := newH1PathMonitor(&settings, h1PathTestOrigin, time.Millisecond); monitor != nil {
		t.Error("a 1 ms dial round trip built a monitor")
	}
	sameDatacenter := runH1PathPolicyShape(t, &settings, 40*time.Millisecond, 1200,
		func(k int) h1PathTickShape {
			shape := h1PathHeldCollapseShape(k)
			shape.minRtt = time.Millisecond
			return shape
		})
	t.Logf("same datacenter: %s", sameDatacenter)
	if sameDatacenter.convictions != 0 || sameDatacenter.collapsedTicks != 0 {
		t.Errorf("same datacenter: %s, want a dormant connection", sameDatacenter)
	}

	// a healthy 101 ms path at 200 Mb/s, with ordinary reordering and a 4 ms
	// standing queue that the acks carry
	healthy := runH1PathPolicyShape(t, &settings, pathRtt, 1200, func(k int) h1PathTickShape {
		return h1PathTickShape{
			rxByteRate:        25_000_000,
			queueDelay:        4 * time.Millisecond,
			queueDelaySamples: 400,
			rxOooAdvance:      k%30 < 26,
			minRtt:            pathRtt,
			ackRtt:            pathRtt + 4*time.Millisecond,
		}
	})
	t.Logf("healthy 101 ms at 200 Mb/s: %s", healthy)
	if healthy.convictions != 0 || healthy.collapsedTicks != 0 {
		t.Errorf("healthy 101 ms at 200 Mb/s: %s, want nothing collapsed in ten minutes", healthy)
	}

	// A saturated 20 Mb/s access link whose large window holds bufferbloat from
	// 10 s on. The bloat is a real queue and the acks carry it, so nothing
	// denies it: this is the residual false positive, and it is bounded by the
	// ledger and by BaselineRisePerMinute together. Two hours is long enough
	// for the epoch's latch to expire twice, so an arm that never decayed would
	// keep re-rolling here until the daily budget was gone.
	bloatShape := func(depth time.Duration) func(k int) h1PathTickShape {
		return func(k int) h1PathTickShape {
			queue := time.Duration(0)
			if 20 <= k {
				queue = depth
			}
			return h1PathTickShape{
				rxByteRate:        2_500_000,
				queueDelay:        queue,
				queueDelaySamples: 16,
				rxOooAdvance:      true,
				minRtt:            pathRtt,
				ackRtt:            pathRtt + queue,
			}
		}
	}
	const bloatTicks = int(2 * time.Hour / h1PathTestStep)
	bloat := runH1PathPolicyShape(t, &settings, pathRtt, bloatTicks, bloatShape(1500*time.Millisecond))
	t.Logf("bufferbloated 20 Mb/s access link, 1.5 s over two hours: %s", bloat)
	if bloat.unconfirmed != 0 || bloat.confirmed == 0 {
		t.Errorf("bufferbloated 20 Mb/s access link: %s, want confirmed convictions", bloat)
	}
	if bloat.rerolls != 2 || bloat.suppressed[h1PathReasonLatched] == 0 {
		t.Errorf(
			"bufferbloated 20 Mb/s access link: %s, want two re-rolls and then the epoch latched",
			bloat,
		)
	}
	if want := 11500 * time.Millisecond; bloat.firstConviction != want {
		t.Errorf("bufferbloated 20 Mb/s access link convicted at %s, want %s", bloat.firstConviction, want)
	}
	// (1.5 s - 1.01 s of threshold) / 100 ms a minute predicts five minutes,
	// and the rolling ack minimum puts a floor of one AckRttWindow under every
	// ack-carried queue whatever its depth: the reference cannot rise past the
	// smallest round trip still in that window, so nothing shallower than
	// (thr + AckRttWindow x rise) is bounded by the rise at all
	if want := settings.AckRttWindow; bloat.lastConviction < want ||
		bloat.lastConviction > want+time.Minute {
		t.Errorf(
			"bufferbloated 20 Mb/s access link convicted last at %s, want the rolling minimum to end it near %s",
			bloat.lastConviction, want,
		)
	}
	if 0 < bloat.suppressed[h1PathReasonDailyBudget] {
		t.Errorf("bufferbloated 20 Mb/s access link: %s, want the epoch bounded before the day", bloat)
	}

	// Four times the bloat is not four times the cost, because each re-roll
	// rebuilds the monitor and the ack reference starts again from the dial
	// round trip while the queue does not: the rise bounds one connection and
	// the re-roll hands it a new one. What bounds the device here is the daily
	// budget, and a 6 s queue spends all six of it. Four hours is long enough
	// for the sixth, which is the whole of what this shape can cost in a day.
	const deepBloatTicks = int(4 * time.Hour / h1PathTestStep)
	deepBloat := runH1PathPolicyShape(t, &settings, pathRtt, deepBloatTicks, bloatShape(6*time.Second))
	t.Logf("bufferbloated 20 Mb/s access link, 6 s over four hours: %s", deepBloat)
	if deepBloat.rerolls != settings.MaxUnimprovedRerollsPerDay {
		t.Errorf(
			"bufferbloated 20 Mb/s access link at 6 s: %s, want the %d re-rolls of the daily budget",
			deepBloat, settings.MaxUnimprovedRerollsPerDay,
		)
	}
	if deepBloat.suppressed[h1PathReasonDailyBudget] == 0 {
		t.Errorf("bufferbloated 20 Mb/s access link at 6 s: %s, want the daily budget to end it", deepBloat)
	}
	if deepBloat.lastConviction <= bloat.lastConviction {
		t.Errorf(
			"a 6 s queue stayed visible for %s and a 1.5 s queue for %s; nothing bounds either",
			deepBloat.lastConviction, bloat.lastConviction,
		)
	}
	// the last conviction is the last one a connection in the budget's own
	// epoch can reach, which is about the sixth latch out
	if lower, upper := 2*time.Hour, 3*time.Hour+30*time.Minute; deepBloat.lastConviction < lower ||
		upper < deepBloat.lastConviction {
		t.Errorf(
			"bufferbloated 20 Mb/s access link at 6 s convicted last at %s, want it between %s and %s",
			deepBloat.lastConviction, lower, upper,
		)
	}

	// A queue that clears and comes back is not bounded by the rise at all:
	// the reference drops back to the floor while the queue is gone, so every
	// return is the first one again. Two minutes of bloat in every ten costs
	// the same daily budget as a queue that never lifts, and this is the shape
	// an evening access link actually has.
	recurringBloat := runH1PathPolicyShape(t, &settings, pathRtt, deepBloatTicks, func(k int) h1PathTickShape {
		shape := bloatShape(6 * time.Second)(k)
		if 2*time.Minute <= time.Duration(k)*h1PathTestStep%(10*time.Minute) {
			shape.queueDelay = 0
			shape.ackRtt = pathRtt
		}
		return shape
	})
	t.Logf("20 Mb/s access link bloated two minutes in every ten, over four hours: %s", recurringBloat)
	if recurringBloat.rerolls != settings.MaxUnimprovedRerollsPerDay {
		t.Errorf(
			"recurring bloat: %s, want the same %d re-rolls a standing queue costs",
			recurringBloat, settings.MaxUnimprovedRerollsPerDay,
		)
	}

	// the measured collapse: 0.5 MB/s behind a queue that grows from the start
	// of the bulk, with an ack round trip that carries the same queue
	collapse := runH1PathPolicyShape(t, &settings, pathRtt, 1200, h1PathCollapseShape)
	t.Logf("measured collapse: %s", collapse)
	if collapse.unconfirmed != 0 || collapse.confirmed == 0 {
		t.Errorf("measured collapse: %s, want confirmed convictions", collapse)
	}
	if want := 3500 * time.Millisecond; collapse.firstConviction != want {
		t.Errorf("measured collapse convicted at %s, want %s", collapse.firstConviction, want)
	}

	// a route that carries no ack at all, and a sender that steps its clock
	// back 2 s at 60 s: the pack tags cannot tell that from a queue, and
	// nothing here can. The conviction stands and is unconfirmed, so the epoch
	// pays one re-roll and refuses every later one
	step := runH1PathPolicyShape(t, &settings, pathRtt, 1200, func(k int) h1PathTickShape {
		queue := time.Duration(0)
		if 120 <= k {
			queue = 2 * time.Second
		}
		return h1PathTickShape{
			rxByteRate:        2_250_000,
			queueDelay:        queue,
			queueDelaySamples: 4,
			rxOooAdvance:      true,
			minRtt:            pathRtt,
		}
	})
	t.Logf("sender clock step on a route with no ack: %s", step)
	if step.confirmed != 0 || step.unconfirmed == 0 {
		t.Errorf("sender clock step on a route with no ack: %s, want unconfirmed convictions", step)
	}
	if step.rerolls != 1 || step.suppressed[h1PathReasonUnconfirmedBudget] == 0 ||
		0 < step.suppressed[h1PathReasonLatched] {
		t.Errorf(
			"sender clock step on a route with no ack: %s, want one re-roll, the rest refused by the budget and no latch",
			step,
		)
	}
	if step.ackDeniedTicks != 0 {
		t.Errorf("sender clock step on a route with no ack: %s, want no tick denied by an ack", step)
	}
}
