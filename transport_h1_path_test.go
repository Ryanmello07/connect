package connect

import (
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
	mss       int
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

// the measured collapse: 0.5 MB/s delivered while the queue grows from the
// start of the bulk at 0.5 s
func h1PathCollapseShape(k int) h1PathTickShape {
	elapsed := time.Duration(k) * h1PathTestStep
	return h1PathTickShape{
		rxByteRate:        500_000,
		queueDelay:        max(0, elapsed-500*time.Millisecond),
		queueDelaySamples: 4,
		rxOooAdvance:      true,
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
		shape := h1PathCollapseShape(k)
		shape.queueDelay = 6 * time.Second
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
		shape := h1PathCollapseShape(k)
		shape.queueDelay = 6 * time.Second
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
	decisions := runH1PathMonitorShape(monitor, 12, func(k int) h1PathTickShape {
		shape := h1PathCollapseShape(k)
		shape.queueDelay = 6 * time.Second
		return shape
	})
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
