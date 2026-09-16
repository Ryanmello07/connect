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

// Feeds the monitor the shape at each tick index and returns every decision.
func runH1PathMonitorShape(
	monitor *h1PathMonitor,
	tickCount int,
	shape func(k int) h1PathTickShape,
) []h1PathDecision {
	sample := h1PathSample{}
	decisions := make([]h1PathDecision, 0, tickCount)
	for k := 0; k < tickCount; k++ {
		tickShape := shape(k)
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
		sample.ackRttMin = tickShape.ackRttMin
		sample.ackRtt = tickShape.ackRtt
		sample.ackRttSamples = 0
		if 0 < tickShape.ackRtt {
			sample.ackRttSamples = 1
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
		decisions = append(decisions, monitor.tick(sample))
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
	ledger.noteReroll(live, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 40004)
	func() {
		// the ledger is the only thing that will know this one
		dead := &RouteManager{}
		ledger.noteReroll(dead, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 40012)
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
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 40004)
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

	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 40004)
	now = now.Add(30 * time.Second)
	if !ledger.noteConviction(key, &settings, now) {
		t.Fatal("a conviction 30 s after a re-roll was not unimproved")
	}
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); !ok {
		t.Fatalf("one unimproved re-roll refused the next: %s", reason)
	}
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 40012)
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
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 40004)
	now = now.Add(10 * time.Second)
	if !ledger.noteConviction(key, &settings, now) {
		t.Fatal("conviction was not unimproved")
	}
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 40012)
	now = now.Add(10 * time.Second)
	if ledger.noteClean(key, &settings, now, 19) {
		t.Fatal("19 clean ticks counted as improved")
	}
	if ledger.noteClean(key, &settings, now, 20) != true {
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
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 0)
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
	ledger.noteReroll(&RouteManager{}, &settings, now, H1PathRerollRoleClient, h1PathConfidenceUnconfirmed, 0)
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
	ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceUnconfirmed, 0)
	now = now.Add(time.Minute)
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceUnconfirmed, time.Minute); ok {
		t.Fatalf("the unconfirmed budget was not spent: %t %s", ok, reason)
	}
	if !ledger.noteClean(key, &settings, now, settings.CleanTicks) {
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
		ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 0)
		now = now.Add(10 * time.Second)
		ledger.noteConviction(key, &settings, now)
	}
	latchStart := now
	if ok, reason := ledger.allow(&settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, time.Minute); ok || reason != h1PathReasonLatched {
		t.Fatalf("allow = %t %s, want latched", ok, reason)
	}
	// a pending entry is dropped as unresolved by a network change
	ledger.noteReroll(&RouteManager{}, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 0)

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
			ledger.noteReroll(key, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 0)
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
	ledger.noteReroll(&RouteManager{}, &settings, now, H1PathRerollRoleProvider, h1PathConfidenceConfirmed, 0)
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
		ledger.noteReroll(&RouteManager{}, &settings, now, H1PathRerollRoleClient, h1PathConfidenceConfirmed, 40000+i)
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
	ledger.noteReroll(&RouteManager{}, &settings, time.Now().Add(-time.Hour), H1PathRerollRoleClient, h1PathConfidenceConfirmed, 40004)
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

// The ack round trip carries our own uplink's standing queue as well as the
// receive path's, and the time our send buffer takes to drain says nothing
// about what is arriving. A device uploading hard while it downloads therefore
// reads an ack round trip of seconds on a receive path that has no queue at
// all, and without the send backlog guard that alone would collapse every
// receive tick.
func TestH1PathMonitorDoesNotReadOurOwnSendQueueAsTheReceiveQueue(t *testing.T) {
	// 700 KB/s down, no receive queue, and an uplink holding 400 KiB that puts
	// 7 s into every ack round trip
	uploader := func(k int) h1PathTickShape {
		return h1PathTickShape{
			rxByteRate:        700_000,
			queueDelay:        20 * time.Millisecond,
			queueDelaySamples: 4,
			rxOooAdvance:      true,
			ackRtt:            7 * time.Second,
			txKnown:           true,
			txAckedByteRate:   25_000_000,
			txNotSent:         400 * 1024,
		}
	}
	settings := DefaultH1PathRerollSettings()
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 60, uploader)
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
		t.Errorf("a saturated uplink convicted the receive path at ticks %v", ticks)
	}
	if snapshot := stats.snapshot(); snapshot.TicksCollapsed != 0 {
		t.Errorf("stats = %+v, want no collapsed tick behind our own send queue", snapshot)
	}

	// the same shape with the send queue under the floor: the ack round trip
	// is then the receive path's and it convicts, so the arm above is the
	// guard and not the rest of the rule
	monitor, _ = newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions = runH1PathMonitorShape(monitor, 60, func(k int) h1PathTickShape {
		shape := uploader(k)
		shape.txNotSent = 30 * 1024
		return shape
	})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) == 0 {
		t.Error("with the send queue under the floor the ack round trip did not convict")
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
// not only its verdicts. The connection is never replaced, which is the
// pessimistic reading: the shape keeps producing whatever it produced.
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
	monitor := newH1PathMonitor(connection.settings, h1PathTestOrigin, dialRtt)
	if monitor == nil {
		t.Fatalf("no monitor for dial rtt %s", dialRtt)
	}
	monitor.stats = connection.stats
	connection.monitor = monitor

	outcome := h1PathPolicyOutcome{suppressed: map[h1PathReason]int{}}
	decisions := runH1PathMonitorShape(monitor, tickCount, shape)
	for k := range decisions {
		decision := decisions[k]
		elapsed := time.Duration(k) * h1PathTestStep
		connection.decide(h1PathTestOrigin.Add(elapsed), &decision)
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
		case h1PathActionSuppressed:
			outcome.suppressed[decision.reason] += 1
		}
	}
	snapshot := connection.stats.snapshot()
	outcome.collapsedTicks = snapshot.TicksCollapsed
	outcome.ackDeniedTicks = snapshot.RxAckDeniedTicks
	return outcome
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

	// a saturated 20 Mb/s access link whose large window holds 1.5 s of
	// bufferbloat from 10 s on. The bloat is a real queue and the acks carry
	// it, so nothing denies it: this is the residual false positive, and the
	// ledger is the whole of what bounds it
	bloat := runH1PathPolicyShape(t, &settings, pathRtt, 1200, func(k int) h1PathTickShape {
		queue := time.Duration(0)
		if 20 <= k {
			queue = 1500 * time.Millisecond
		}
		return h1PathTickShape{
			rxByteRate:        2_500_000,
			queueDelay:        queue,
			queueDelaySamples: 16,
			rxOooAdvance:      true,
			minRtt:            pathRtt,
			ackRtt:            pathRtt + queue,
		}
	})
	t.Logf("bufferbloated 20 Mb/s access link: %s", bloat)
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
