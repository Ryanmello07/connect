// Bounded retransmission of the inner TCP segments the user NAT sends toward
// the source on the return path (the provider-terminated download direction).
// Transfer delivers those segments losslessly to the source device, but the
// device kernel can still drop one on its receive socket after the tunnel has
// written it, and with nothing retained here that drop was a permanent hole.
// See tcpReturnRetransmitState for the design; the hooks are in TcpSequence.
package connect

import (
	"math"
	"sync/atomic"
	"time"
)

const (
	// duplicate acknowledgements of one cumulative ack that mean loss rather
	// than reordering (RFC 5681)
	returnRetransmitDupAckThreshold = 3
	// the timer floor, which is TCP's own minimum, and the timer before the
	// first round-trip sample exists (RFC 6298 §2.1)
	returnRetransmitMinRto     = 200 * time.Millisecond
	returnRetransmitInitialRto = 1 * time.Second
	// the backoff ceiling. With the no-progress bound this fixes how many
	// timer retransmissions a silent source costs before it is reset.
	returnRetransmitMaxRto = 8 * time.Second
	// the ceiling on a loss-recovery burst, in consecutive segments from the
	// cumulative acknowledgement. The burst doubles from one per partial
	// acknowledgement and reaches this on the eighth; from then on recovery
	// runs at this many segments a round trip. Without SACK nothing says what
	// the source holds past a hole, so this is also the most one
	// acknowledgement can resend that it already had: about 190 KB of
	// full-size segments. At this ceiling the default cap's worst case at the
	// 16 MiB maximum window, a purged span of about 11,600 segments of 1,448
	// bytes, recovers in about 100 round trips, 3 s at 30 ms, where one
	// segment a round trip took nearly 6 minutes.
	returnRetransmitMaxBurstSegmentCount = 128
	// the most blocks one SACK option carries beside a timestamp option
	tcpMaxSackBlockCount = 4
	// what one retained segment's ring record costs, checked against the
	// compiler's size in TestTcpReturnRetainedSegmentRecordByteCount
	tcpReturnRetainedSegmentByteCount = 96
	// the memory bound as a multiple of the retention cap. A retained
	// segment holds the whole pool root its packet came from, which is one
	// size class: about 2 KiB for any packet above 256 bytes, and 256 bytes
	// below that. Full segments at the default mtu therefore cost about twice
	// their sequence bytes, and this leaves room for the ring and for the
	// short segment that ends each socket read. A segment of a few bytes,
	// which a source can force with small window openings, costs hundreds of
	// times its own sequence bytes, and this is what bounds it.
	returnRetransmitRetainMemoryFactor = 3
	// the no-progress bound used when the settings leave it zero: the
	// provider's bound on a source that acknowledges none of its returns
	// (RemoteUserNatProviderSettings.ReturnSendAbandonTimeout). At 60 s, a
	// 60 to 120 s gap in the source's connectivity, which the provider waits
	// out, reset download flows that would have completed when the gap
	// closed; a source silent for longer with a return parked is released by
	// the provider anyway. The flow's idle timeout, 300 s, is longer still.
	defaultReturnRetransmitTimeout = defaultReturnSendAbandonTimeout
)

// One selective acknowledgement block, [start, end) in sequence space.
type tcpSackBlock struct {
	start uint32
	end   uint32
}

// Why a retained segment was sent again.
type tcpReturnRetransmitReason int

const (
	tcpReturnRetransmitReasonDupAck tcpReturnRetransmitReason = iota
	tcpReturnRetransmitReasonSackHole
	tcpReturnRetransmitReasonPartialAck
	tcpReturnRetransmitReasonTimeout
	tcpReturnRetransmitReasonCount
)

func (self tcpReturnRetransmitReason) String() string {
	switch self {
	case tcpReturnRetransmitReasonDupAck:
		return "dupack"
	case tcpReturnRetransmitReasonSackHole:
		return "sack"
	case tcpReturnRetransmitReasonPartialAck:
		return "partial"
	case tcpReturnRetransmitReasonTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// Where a sequence stands in repairing its return path (see
// tcpReturnRetransmitState).
type tcpReturnRecoveryPhase int

const (
	tcpReturnRecoveryPhaseNone tcpReturnRecoveryPhase = iota
	// a timer expiry sent the head again, and no acknowledgement has
	// advanced or repeated since; the expiry may be spurious
	tcpReturnRecoveryPhaseTimeoutProbe
	// acknowledgements since the expiry advanced, but no further than the
	// head it sent again; the next advance past the head, or a duplicate,
	// decides
	tcpReturnRecoveryPhaseTimeoutProbeAdvanced
	// loss recovery: after the third duplicate acknowledgement, or after an
	// expiry the acknowledgements showed real
	tcpReturnRecoveryPhaseLoss
)

// One sent segment, retained until the source's cumulative acknowledgement
// covers it. The ring owns `packet`, a read-only share of the delivered pool
// buffer, and returns it exactly once: on acknowledgement, on reset, or at the
// sequence's end. A bare FIN retains no packet.
type tcpReturnRetainedSegment struct {
	seq uint32
	// sequence-space length: the payload bytes, plus one for a FIN
	byteCount        uint32
	fin              bool
	packet           []byte
	payloadOffset    uint16
	payloadByteCount uint16
	// handed to the return path; only a delivered segment can be lost
	delivered       bool
	sentNanos       int64
	retransmitNanos int64
	retransmitCount int
	sacked          bool
	// decided for retransmission, waiting for the worker to build and send it
	due       bool
	dueReason tcpReturnRetransmitReason
	// a burst's guess past the hole rather than a segment the
	// acknowledgements showed missing: the source may hold it and answer the
	// retransmission with a duplicate acknowledgement
	guessed bool
}

// Cumulative counts of return-path retransmission across a NAT's TCP flows.
// Read with `LocalUserNat.ReturnRetransmitStats` or the provider's.
type ReturnRetransmitStats struct {
	// packets sent again, each piece of a segment cut for a smaller path mtu
	// counted, and the sequence bytes of the segments they carried
	PacketCount int64
	ByteCount   ByteCount
	// retransmission timer expiries
	TimeoutCount int64
	// flows reset because the source acknowledged nothing for the bound
	AbandonCount int64
}

// Atomic counters shared by every sequence of a NAT, safe on the sequence
// goroutines without a NAT-wide lock.
type returnRetransmitCounters struct {
	packetCount  atomic.Int64
	byteCount    atomic.Int64
	timeoutCount atomic.Int64
	abandonCount atomic.Int64
}

// Returns one stable-enough snapshot of independent atomics.
func (self *returnRetransmitCounters) snapshot() ReturnRetransmitStats {
	return ReturnRetransmitStats{
		PacketCount:  self.packetCount.Load(),
		ByteCount:    ByteCount(self.byteCount.Load()),
		TimeoutCount: self.timeoutCount.Load(),
		AbandonCount: self.abandonCount.Load(),
	}
}

// The return-path retransmission state of one TcpSequence: a TCP sender's
// loss-recovery core, reduced to what the path needs.
//
// Why it exists. The user NAT terminates the source's TCP flow: it reads the
// origin's bytes from the upstream socket, packetizes them into inner TCP
// segments toward the source, and hands each segment to Transfer, which
// delivers it losslessly to the source device and writes it to the device's
// TUN. Transfer's reliability ends at that write. The device kernel can still
// drop the segment on the flow's receive socket, which a real sender repairs
// from its send buffer and which nothing here repaired: the source answered
// with duplicate acknowledgements for ever, the NAT never sent the segment
// again, and the download stopped. On physical hosts at about 800 Mb/s on a
// single flow the kernel drops a segment in roughly one run in five, with the
// receive buffer at its ceiling and megabytes queued out of order behind one
// missing segment. THROUGHPUTFIX §38 described this mechanism and declined it
// as a relocation of Transfer's reliability; the loss here is below Transfer's
// delivery boundary, which that verdict did not cover.
//
// What is retained. Every data segment the socket reader packetizes, as a
// read-only share of the very pool buffer that is delivered, with its sequence
// number and length, and the FIN, as a sequence number alone. A segment is
// released when the source's cumulative acknowledgement covers its end. A
// segment a SACK block covers is marked and skipped by hole selection but is
// released only by the cumulative acknowledgement, since a receiver may renege
// on selective acknowledgements (RFC 2018 §8); a source whose cumulative
// acknowledgement stops short of a segment it reported is treated as having
// reneged, and every mark is dropped. A retransmission is not the retained
// buffer: it is fresh packets built from the retained payload with the
// current acknowledgement, window and timestamps, exactly as the handshake
// retransmits its SYN-ACK, cut by the segment size packetization would use at
// that moment.
//
// Selective acknowledgement is negotiated or ignored. Every rule below that
// reads a block runs only on a sequence whose handshake negotiated
// sack-permitted: the source's SYN offered it and the SYN-ACK offered it
// back, which it does only where EnableReturnRetransmitSack turns it on, and
// that is off. So on every flow today the cumulative acknowledgement and the
// timer alone decide what is repaired, and a source that sends blocks unasked
// is reporting what it likes to a path that does not read them. The option
// parsing and the hole rules stay behind that gate for the day the handshake
// does negotiate it, and they are written to hold for whoever sends the
// blocks then, since a source that negotiated them is no more trusted than
// one that did not: what a run of crafted blocks costs is bounded per hole
// interval in markSackHolesWithLock. The gate is the reason to hold it shut
// for now: the selective path is where a few dozen bytes of acknowledgement
// ask for a burst of full-size segments, per flow, with nothing bounding the
// sum across flows, and the repair this exists for is one the cumulative
// acknowledgement already makes.
//
// Pieces. After the source reports a smaller path mtu (fragmentation needed,
// packet too big), a segment packetized before the report is larger than the
// path carries, and sent again whole it would be dropped again on every
// trigger until the bound; so a retained segment above the current size goes
// as consecutive pieces, each within it. The ring still holds one record per
// packetized segment and never splits one: its share, its counts and every
// rule below stay per record, and the path that repairs loss never shifts the
// ring or takes another share. The cost is granularity. An acknowledgement
// that ends inside a record releases and samples nothing, a SACK block that
// covers only some of its pieces marks none of them, and a record goes again
// whole, so a piece the source already holds can go again, at most one
// packetized segment's bytes per retransmission.
//
// Sent means delivered. A segment is retained when it is packetized, for the
// cap, but it counts as sent only once the delivery drain has handed it to
// the return path: retransmissions leave on their own goroutine and can
// overtake segments still queued for delivery, and a decision about a segment
// the source cannot have seen yet would be a spurious retransmission. Every
// trigger below considers delivered segments only, the round trip is measured
// from delivery, and the delivered set is always a prefix of the ring, since
// the drain delivers in sequence order. The drain marks a batch only when
// its callback returns, and the source can answer the batch before that, so a
// duplicate acknowledgement that arrives while nothing is marked still counts,
// and fast retransmit follows the marking; a recovery that began while a batch
// was being delivered takes its recovery point over that batch, which was on
// its way before the recovery's first retransmission.
//
// Bounds. Retained sequence bytes never exceed the source's advertised window,
// because the packetizer already stops at the greatest advertised edge and
// every emitted byte is retained, and never exceed the cap,
// ReturnRetransmitRetainByteCount, which the packetizer applies beside the
// window: a burst larger than the cap waits for acknowledgements to free
// space, as it waits for the window. The window is the source's to choose, up
// to about a gigabyte at the largest scale, so it cannot bound the provider's
// memory alone. Retained bytes are exactly the bytes in flight, so the cap is
// also a rate ceiling of the cap over the inner round trip wherever it binds
// before the window: 4 MiB at 100 ms is about 335 Mb/s. The cap therefore
// defaults to the flow's own maximum window, MaxWindowSize, which the settings
// already hold as the most packet data one sequence keeps in memory, and binds
// only where a source advertises more than that, or where the memory bound
// below binds first.
//
// Memory. Without retention a delivered buffer goes back to the pool when
// Transfer acknowledges it; with it, when the source's kernel does. In steady
// flow the extra is what is sent between those two acknowledgements. While a
// hole stands the kernel acknowledges nothing past it, and the extra grows to
// everything sent since, up to the window and the cap, until the repair.
//
// Sequence bytes do not measure that memory. A share holds the whole pool
// root its packet came from, one size class: about 2 KiB for any packet above
// 256 bytes and 256 bytes below that, plus a ring record. Full segments at the
// default mtu cost about twice their sequence bytes; a segment of a few bytes
// costs hundreds of times its own, and a source can force those without the
// origin's help, by opening its window a few bytes at a time. So the pool
// roots and the ring are bounded beside the sequence bytes, at
// returnRetransmitRetainMemoryFactor times the cap, which is what the cap's
// worth of full-size segments costs with room to spare for the ring and the
// short segment that ends each socket read. The bound is read as a ceiling on
// the next chunk's sequence bytes, so retention passes it by at most one
// socket read and the ring's last doubling; a flow whose path mtu has been
// cut far below the packet pool's class binds on memory before the cap. The
// ring gives its records back when the retained set empties, rather than
// keeping the peak for the life of the flow. Across flows nothing but the
// flow count bounds the sum.
//
// Constrained providers. MaxWindowSize scales with the process memory budget
// (DefaultTcpBufferSettingsWithBufferSize): 16 MiB unbudgeted, 8 MiB at the
// phone network extension's 32 MiB, never below 256 KiB. The provider profile
// with a memory target (DefaultProviderLocalUserNatSettingsWithMemoryTarget)
// sizes flow counts by a per-flow cost that leaves out window-sized data,
// treats every window as a demand-driven ceiling, and changes neither the
// window nor the cap, so no constructor lowers the cap. A per-flow value small
// enough for a phone's provider share would impose the rate ceiling above on
// every flow and still not bound the sum across flows, which only an
// aggregate bound charged to that share could. A host that must keep less per
// flow sets the cap, or MaxWindowSize with it; both the sequence bytes and the
// memory follow it.
//
// Time is bounded by ReturnRetransmitTimeout: when the cumulative
// acknowledgement has not advanced for that long with delivered segments
// outstanding, the flow is reset toward the source and closed, never left
// idle. It defaults to the provider's ReturnSendAbandonTimeout, 120 s, so a
// gap in the source's acknowledgements shorter than the provider's own bound
// on that source resets nothing. That is the acceptance contract: a transient
// loss completes the exact byte stream; an unrecoverable one is an explicit,
// bounded failure.
//
// Triggers. Fast retransmit: the third duplicate acknowledgement of one
// cumulative ack retransmits the first unacknowledged segment and starts loss
// recovery (RFC 5681 §3.2). A duplicate repeats the cumulative ack and the
// window and carries no payload, SYN or FIN (RFC 5681 §2): a window update is
// not one, however many the source sends while its application reads. Nor are
// the duplicates this flow's own retransmissions draw from the source, which
// it answers one for one; a run of duplicates within reach of a recent
// retransmission starts nothing unless it is longer than the retransmissions
// that explain it (see fastRetransmitWithLock). Where the handshake
// negotiated SACK, blocks retransmit every unmarked segment below the highest
// selectively acknowledged byte instead, and further duplicate
// acknowledgements that extend the marked range retransmit the holes they
// newly reveal. A partial acknowledgement inside loss recovery, one that
// advances but not to the recovery's end, retransmits the next hole at once
// (NewReno, RFC 6582), and not only the hole: a burst of consecutive segments
// from the cumulative acknowledgement: the run recovery may have in flight
// past it, which starts at the head alone, grows by one for each
// retransmission an acknowledgement covers, so that it doubles every round
// trip to a ceiling of 128, and starts again at the head alone as soon as an
// acknowledgement covers data the source held past the hole. Never past the
// recovery point, and never a segment this recovery already sent again. An
// advance that ends inside a segment this recovery already sent again sends
// nothing: it acknowledges one of the pieces the segment went in, the rest are
// in flight, and the next hole is not known until they land. An advance an
// earlier copy of the head explains, because the head was never sent again or
// its retransmission is younger than half the shortest round trip this flow
// has measured, ends the recovery instead: the head was never missing, so the
// recovery was spurious. Path reordering, which three duplicates cannot tell
// from loss, is one cause; going on from it, every ordinary acknowledgement of
// data in flight would read as a partial one and its bursts would send that
// data again, a whole window for one reordered segment. The failure this
// path exists for is a receive socket out of memory, and the kernel then
// prunes its out-of-order queue when the hole fills, so the source holds
// nothing past it; one segment per partial acknowledgement would take a round
// trip per purged segment where a real sender slow-starts the go-back-N.
// Without SACK a burst may resend a segment the source held: at most the run,
// which is what the acknowledgements have shown lost, and each at most once
// per recovery.
// The timer: max(200 ms, 2 x srtt, srtt + 4 rttvar) from the inner round
// trip, one second before a sample exists, doubling on each expiry to an 8 s
// ceiling and reset by acknowledgement progress, which wakes the worker when
// it brings the deadline in by more than a quarter of the timer, as the first
// sample and a dropped backoff do; expiry retransmits the first
// unacknowledged segment only, and an expiry during loss recovery presumes
// what it already sent again lost and starts the bursts over from one.
//
// An expiry is not by itself loss. The round trip includes Transfer's
// queueing, so a tunnel stall holds acknowledgements past the timer, and if
// the expiry began loss recovery every late acknowledgement would read as a
// partial one and send the window again. So an expiry probes, in the spirit
// of F-RTO (RFC 5682), and sends nothing beyond the head until the
// acknowledgements decide. The first to advance past the retransmitted head,
// whether or not others advanced to it before, acknowledges bytes never sent
// again: the originals arrived, the expiry was spurious, and the probe ends
// with the timer back at its base, the value the expiry doubled, updated by
// whatever round trips the late acknowledgements sampled. An advance that
// ends no further than the head decides nothing, since the source may hold
// the original head or its retransmission; a head sent in pieces for a
// smaller path mtu draws one such advance per piece. A duplicate
// acknowledgement shows a segment missing and turns the probe into loss
// recovery, retransmitting at once when the head had already advanced.
// Silence decides nothing, so expiries with no answer at all only back off
// and send the head again; an expiry after the source has answered is loss
// (RFC 5682 §2.1 step 1), which is how a source that lost everything past the
// head recovers when no later segment exists to draw a duplicate. Until the
// probe decides, advances keep the doubled timer, so a stall that lets one
// acknowledgement through must outlast twice the timer to read as loss.
//
// The round trip is sampled by the time from a segment's delivery to the
// acknowledgement that covers it, and only from an acknowledgement that
// covers no retransmitted segment at all. A retransmission's own
// acknowledgement does not say which copy it answers (Karn, RFC 6298 §3), and
// the segments behind the hole it filled are no better: their acknowledgement
// was held back by that hole, so their time from delivery measures the
// repair, not the path. Linux draws the same line with
// FLAG_RETRANS_DATA_ACKED. Sampling them set srtt to the repair time on the
// first loss of a flow - 1.05 s on a 50 ms path, a timer of 3.15 s - and the
// timer stayed seconds wide for the rest of the flow, over every later tail
// loss.
//
// A flow whose source offered timestamps could sample a recovery after all,
// and deliberately does not. The echo says which copy the acknowledgement
// answers, which is the one exemption from Karn's rule RFC 6298 §3 names, and
// the receiver takes its TS.Recent from whichever copy filled the hole
// (RFC 7323 §4.3), so the time from that echo would be the path rather than
// the repair. What it would buy is a flow under continuous loss, which keeps
// the timer its last acknowledgement of unretransmitted data left, bounded
// either way by the floor and the 8 s ceiling and re-sampled by the first
// clean acknowledgement after the loss; what it costs is that the echo is the
// source's to choose, so the value has to be checked against this flow's own
// clock before it may set srtt, and a source could otherwise write the timer
// it prefers. That check is a rule with its own tests and it belongs with the
// spurious-recovery detection this leaves open, not beside the rule above.
//
// Every hole is sent at most once per max(srtt, 200 ms), whatever triggers
// it, so a run of duplicate acknowledgements costs one segment; the timer
// bypasses that limit, being a limit itself. Nothing is ever retransmitted
// above the window: the retained set is inside the greatest advertised edge,
// which never moves back. Duplicate suppression on the source is its
// kernel's job.
//
// Lifecycle. When the upstream closes, the FIN is retained like data and the
// sequence stays open until the source acknowledges everything, or the bound
// expires; before this it closed as soon as the FIN left. When the upstream
// fails, the reset that follows discards the retained set, since a reset is
// never repaired. Disabled, nothing is retained and every path is byte for
// byte the earlier behaviour.
//
// Every method is called with the sequence's ConnectionState mutex held; the
// worker that builds and sends retransmissions runs on its own goroutine and
// takes that mutex only to select and build.
type tcpReturnRetransmitState struct {
	enabled bool
	// whether the handshake negotiated selective acknowledgement, which the
	// sequence sets from ConnectionState.enableSack. False, every selective
	// block is ignored and the cumulative acknowledgement alone decides what
	// is repaired.
	sackPermitted         bool
	retainByteCount       int64
	retainMemoryByteCount int64
	timeout               time.Duration
	// shared with the owning NAT, nil when nothing counts
	counters *returnRetransmitCounters

	// circular, in sequence order from head; the delivered prefix first
	segments       []tcpReturnRetainedSegment
	head           int
	count          int
	deliveredCount int
	// the sequence bytes retained, and the pool roots and ring records that
	// hold them, each against its own bound
	retainedByteCount       int64
	retainedMemoryByteCount int64
	sackedCount             int
	highestSackedEnd        uint32
	appliedSackBlocks       [tcpMaxSackBlockCount]tcpSackBlock
	appliedSackBlockCount   int
	finRetained             bool
	dueCount                int
	// the selective holes newly marked in the current hole interval, and
	// when that interval ends; the ceiling is carried over the interval
	// rather than over one acknowledgement (see markSackHolesWithLock)
	sackBurstSegmentCount int
	sackBurstEndNanos     int64

	dupAckCount int
	// the duplicate acknowledgements this flow's own retransmissions can
	// explain: how many packets went again while the guard stood, the
	// retained end when the last of them went, and when the guard lapses,
	// one timer after that
	explainedDupAckCount int
	explainedDupAckEnd   uint32
	explainedDupAckNanos int64
	// the scaled window of the last acceptable acknowledgement, which a
	// duplicate must repeat
	ackWindowByteCount uint32
	recoveryPhase      tcpReturnRecoveryPhase
	// the end of the highest delivered segment when the recovery or the
	// probe last began; an acknowledgement that reaches it ends either
	recoveryEnd uint32
	// the end of the head the probe's expiry sent again
	probeHeadEnd uint32
	// when loss recovery began, or an expiry last restarted it; a segment
	// sent again since then is in flight and no burst sends it again
	recoveryStartNanos int64
	// the consecutive segments from the cumulative acknowledgement that
	// recovery may have in flight, one when it begins and one more for each
	// retransmission an acknowledgement covers
	burstSegmentCount int

	rttKnown  bool
	srttNanos int64
	// the shortest round trip this flow ever measured, which bounds how soon
	// a retransmission of its own can be acknowledged
	minRttNanos      int64
	rttvarNanos      int64
	rtoNanos         int64
	rtoDeadlineNanos int64
	// when the worker next wakes by itself, as the clock last told it; an
	// acknowledgement that brings the deadline in before this wakes it
	timerWakeNanos int64
	// when the cumulative acknowledgement last advanced, or the first segment
	// was delivered with nothing outstanding
	progressNanos int64

	// per flow, for the summary line
	retransmitPacketCount int64
	retransmitByteCount   int64
	reasonCounts          [tcpReturnRetransmitReasonCount]int64
}

func newTcpReturnRetransmitState(tcpBufferSettings *TcpBufferSettings) tcpReturnRetransmitState {
	state := tcpReturnRetransmitState{
		enabled:         tcpBufferSettings.EnableReturnRetransmit,
		retainByteCount: int64(tcpBufferSettings.ReturnRetransmitRetainByteCount),
		timeout:         tcpBufferSettings.ReturnRetransmitTimeout,
		rtoNanos:        int64(returnRetransmitInitialRto),
	}
	if state.retainByteCount <= 0 {
		// the flow's maximum window, so the cap never binds below it
		state.retainByteCount = int64(tcpBufferSettings.MaxWindowSize)
	}
	state.retainMemoryByteCount = returnRetransmitRetainMemoryFactor * state.retainByteCount
	if state.timeout <= 0 {
		state.timeout = defaultReturnRetransmitTimeout
	}
	return state
}

func (self *tcpReturnRetransmitState) segmentAtWithLock(index int) *tcpReturnRetainedSegment {
	return &self.segments[(self.head+index)%len(self.segments)]
}

func (self *tcpReturnRetransmitState) appendWithLock(segment tcpReturnRetainedSegment) {
	if self.count == len(self.segments) {
		self.resizeWithLock(max(16, 2*len(self.segments)))
	}
	self.segments[(self.head+self.count)%len(self.segments)] = segment
	self.count += 1
}

// Moves the ring to a backing array of `byteCount` records, which must hold
// what it carries, and charges the change against the memory bound.
func (self *tcpReturnRetransmitState) resizeWithLock(segmentCount int) {
	resized := make([]tcpReturnRetainedSegment, segmentCount)
	for index := 0; index < self.count; index += 1 {
		resized[index] = *self.segmentAtWithLock(index)
	}
	self.retainedMemoryByteCount += int64(segmentCount-len(self.segments)) * tcpReturnRetainedSegmentByteCount
	self.segments = resized
	self.head = 0
}

// Returns the ring's backing array to what it carries, so a flow that held a
// window of segments through one loss episode does not keep the records for
// the rest of its life. Halving at a quarter full leaves room to grow again
// without copying on every append.
func (self *tcpReturnRetransmitState) shrinkWithLock() {
	segmentCount := len(self.segments)
	for 16 < segmentCount && self.count <= segmentCount/4 {
		segmentCount /= 2
	}
	if segmentCount < len(self.segments) {
		self.resizeWithLock(segmentCount)
	}
}

// Removes the head and returns the pool share it held, so the caller decides
// when the share goes back.
func (self *tcpReturnRetransmitState) popWithLock() (segment tcpReturnRetainedSegment) {
	segment = self.segments[self.head]
	self.segments[self.head] = tcpReturnRetainedSegment{}
	self.head = (self.head + 1) % len(self.segments)
	self.count -= 1
	if self.count == 0 {
		self.head = 0
	}
	self.retainedByteCount -= int64(segment.byteCount)
	self.retainedMemoryByteCount -= int64(cap(segment.packet))
	if segment.delivered {
		self.deliveredCount -= 1
	}
	if segment.sacked {
		self.sackedCount -= 1
	}
	if segment.due {
		self.dueCount -= 1
	}
	return
}

// Sequence bytes the cap still allows; unbounded when disabled, or when
// neither the settings nor a maximum window give a cap and the window alone
// bounds retention. The memory the retained set holds is bounded beside the
// sequence bytes, in memory bytes read as a ceiling on the next chunk's
// sequence bytes: one chunk is at most one socket read, so retention passes
// its memory bound by at most that read's segments and the ring's last
// doubling.
func (self *tcpReturnRetransmitState) roomWithLock() int64 {
	if !self.enabled || self.retainByteCount <= 0 {
		return int64(1) << 62
	}
	return min(
		self.retainByteCount-self.retainedByteCount,
		self.retainMemoryByteCount-self.retainedMemoryByteCount,
	)
}

// The end of the newest delivered segment, which is the highest sequence the
// source can have seen.
func (self *tcpReturnRetransmitState) highestDeliveredWithLock() uint32 {
	tail := self.segmentAtWithLock(self.deliveredCount - 1)
	return tail.seq + tail.byteCount
}

// Retains one packetized segment until the source acknowledges it. Borrows the
// packet: a read-only share is kept, and the caller still owns and returns its
// original. A bare FIN passes a nil packet. The segment counts as sent only
// when markDeliveredWithLock sees it.
func (self *tcpReturnRetransmitState) retainWithLock(
	packet []byte,
	seq uint32,
	payloadOffset int,
	payloadByteCount int,
	fin bool,
) {
	if !self.enabled {
		return
	}
	segment := tcpReturnRetainedSegment{
		seq:              seq,
		byteCount:        uint32(payloadByteCount),
		fin:              fin,
		payloadOffset:    uint16(payloadOffset),
		payloadByteCount: uint16(payloadByteCount),
	}
	if fin {
		segment.byteCount += 1
		self.finRetained = true
	}
	if packet != nil && 0 < payloadByteCount {
		segment.packet = MessagePoolShareReadOnly(packet)
	}
	self.appendWithLock(segment)
	self.retainedByteCount += int64(segment.byteCount)
	// the whole pool root the share holds, whatever part of it the payload
	// fills
	self.retainedMemoryByteCount += int64(cap(segment.packet))
}

// Marks retained segments as handed to the return path, by the sequences the
// drain delivered, in order. A delivered sequence the ring no longer holds
// was acknowledged before the batch's callback returned, which the fast
// acknowledgement path allows, and is skipped; a packet that was never
// retained (a teardown reset) matches nothing and shifts nothing. Reports
// whether the worker must run: the first delivered segment with nothing
// outstanding just went out, which starts the timer and the no-progress
// clock, and fast retransmit may have followed it. The source answers a
// batch while the drain is still inside its callback, so the duplicates of a
// hole at the batch's head can all arrive before this marks the head; they
// were counted (see ackWithLock), and the head is sent again here.
//
// `startNanos` is when the batch's delivery began. A batch that began before
// the recovery under way was on its way to the source before that recovery's
// first retransmission, so the recovery point covers it: a hole inside it is
// one the acknowledgement of that retransmission stops at. Without this the
// hole lay past the point, that acknowledgement read as a full recovery, and
// the hole waited for the timer, its duplicates already spent. A batch that
// began after the recovery is data sent during it, and stays past the point.
func (self *tcpReturnRetransmitState) markDeliveredWithLock(
	seqs []uint32,
	startNanos int64,
	nowNanos int64,
) (wake bool) {
	if !self.enabled {
		return false
	}
	for _, seq := range seqs {
		for self.deliveredCount < self.count {
			segment := self.segmentAtWithLock(self.deliveredCount)
			if 0 < int32(segment.seq-seq) {
				// the delivered sequence is already acknowledged and gone
				break
			}
			// this one, or an older one that in-order delivery put out
			// before it
			if self.deliveredCount == 0 {
				wake = true
				self.progressNanos = nowNanos
				self.rtoDeadlineNanos = nowNanos + self.rtoNanos
			}
			segment.delivered = true
			segment.sentNanos = nowNanos
			self.deliveredCount += 1
			if segment.seq == seq {
				break
			}
		}
	}
	if self.recoveryPhase != tcpReturnRecoveryPhaseNone && 0 < self.deliveredCount &&
		startNanos < self.recoveryStartNanos {
		if end := self.highestDeliveredWithLock(); 0 < int32(end-self.recoveryEnd) {
			self.recoveryEnd = end
		}
	}
	if wake && self.recoveryPhase == tcpReturnRecoveryPhaseNone && returnRetransmitDupAckThreshold <= self.dupAckCount {
		// the duplicates repeat the head's own sequence, which the source is
		// missing
		self.fastRetransmitWithLock(self.segmentAtWithLock(0).seq, nowNanos)
	}
	return
}

// Returns every retained share. Used by a reset, which nothing repairs, and at
// the sequence's end.
func (self *tcpReturnRetransmitState) releaseAllWithLock() {
	for 0 < self.count {
		segment := self.popWithLock()
		if segment.packet != nil {
			MessagePoolReturn(segment.packet)
		}
	}
	self.shrinkWithLock()
	self.recoveryPhase = tcpReturnRecoveryPhaseNone
	self.dupAckCount = 0
	self.appliedSackBlockCount = 0
	// beside the rest of the recovery bookkeeping, so nothing retained after
	// this is held back by an interval that belonged to what was discarded
	self.sackBurstSegmentCount = 0
}

// The timer before backoff (RFC 6298 §2, with the 2 x srtt floor).
func (self *tcpReturnRetransmitState) baseRtoNanos() int64 {
	if !self.rttKnown {
		return int64(returnRetransmitInitialRto)
	}
	return max(
		int64(returnRetransmitMinRto),
		2*self.srttNanos,
		self.srttNanos+4*self.rttvarNanos,
	)
}

// How long one hole waits between retransmissions that acknowledgements ask
// for: one round trip, floored so a loopback path cannot resend per ack.
func (self *tcpReturnRetransmitState) holeIntervalNanos() int64 {
	return max(self.srttNanos, int64(returnRetransmitMinRto))
}

func (self *tcpReturnRetransmitState) updateRttWithLock(sampleNanos int64) {
	if !self.rttKnown {
		self.rttKnown = true
		self.srttNanos = sampleNanos
		self.minRttNanos = sampleNanos
		self.rttvarNanos = sampleNanos / 2
		return
	}
	self.minRttNanos = min(self.minRttNanos, sampleNanos)
	deviationNanos := self.srttNanos - sampleNanos
	if deviationNanos < 0 {
		deviationNanos = -deviationNanos
	}
	self.rttvarNanos = (3*self.rttvarNanos + deviationNanos) / 4
	self.srttNanos = (7*self.srttNanos + sampleNanos) / 8
}

// Whether this flow's own retransmission of a segment, sent at
// `retransmitNanos`, can be what the acknowledgement covering it answers,
// rather than a copy sent before it. An acknowledgement cannot answer a
// retransmission sooner than the shortest round trip the flow ever measured,
// and half of that leaves room for a path that became faster. Before any
// sample nothing can be told, and the retransmission is taken as the answer.
func (self *tcpReturnRetransmitState) retransmissionExplainsWithLock(
	segmentResent bool,
	retransmitNanos int64,
	nowNanos int64,
) bool {
	if !segmentResent {
		return false
	}
	if !self.rttKnown {
		return true
	}
	return self.minRttNanos/2 <= nowNanos-retransmitNanos
}

func (self *tcpReturnRetransmitState) markDueWithLock(
	segment *tcpReturnRetainedSegment,
	reason tcpReturnRetransmitReason,
	nowNanos int64,
) {
	if !segment.delivered || segment.due || segment.sacked {
		return
	}
	if reason != tcpReturnRetransmitReasonTimeout &&
		0 < segment.retransmitCount &&
		nowNanos-segment.retransmitNanos < self.holeIntervalNanos() {
		// one retransmission per hole per round trip; the timer is its own
		// limit and is not held back by it
		return
	}
	segment.due = true
	segment.dueReason = reason
	segment.guessed = false
	self.dueCount += 1
}

// Starts loss recovery from the first burst, the head alone. `startNanos` is
// when the retransmissions that belong to it began.
func (self *tcpReturnRetransmitState) beginLossRecoveryWithLock(startNanos int64) {
	self.recoveryPhase = tcpReturnRecoveryPhaseLoss
	self.recoveryStartNanos = startNanos
	self.burstSegmentCount = 1
}

// Fast retransmit, on the duplicates of the head reaching the threshold with
// no recovery under way: loss recovery to the highest delivered segment, and
// the holes below the selectively acknowledged range, or the head.
//
// A segment sent again that the source already held answers with a duplicate
// acknowledgement of its own, and the source's stack sends one for every
// duplicate segment it receives. Only a burst's guesses past the hole can be
// such segments; what the acknowledgements showed missing draws no duplicate.
// Their acknowledgements repeat whatever the source holds in order, which is
// at most everything retained when the retransmission went, since the path
// delivers in order. So while a guess's own duplicates can still be arriving,
// a run of duplicates at or below that end is evidence of nothing unless it is
// longer than the guesses that explain it. Without this, one recovery's
// needless retransmissions started the next recovery, whose bursts sent the
// window again, whose duplicates started the next: a storm that lasted the
// rest of the flow. A real loss in that range costs the extra duplicates, or
// the guard's lapse one timer after the last retransmission, and the timer
// itself is the backstop.
func (self *tcpReturnRetransmitState) fastRetransmitWithLock(ackNumber uint32, nowNanos int64) {
	if nowNanos < self.explainedDupAckNanos &&
		int32(ackNumber-self.explainedDupAckEnd) <= 0 &&
		self.dupAckCount < returnRetransmitDupAckThreshold+self.explainedDupAckCount {
		return
	}
	self.beginLossRecoveryWithLock(nowNanos)
	self.recoveryEnd = self.highestDeliveredWithLock()
	if 0 < self.sackedCount {
		self.markSackHolesWithLock(nowNanos)
	} else {
		self.markDueWithLock(self.segmentAtWithLock(0), tcpReturnRetransmitReasonDupAck, nowNanos)
	}
}

// Sends the burst of one partial acknowledgement in loss recovery: the
// consecutive delivered segments from the cumulative acknowledgement that the
// run allows. The run grows by one for each retransmission this
// acknowledgement covered, `ackedResentCount`, so recovery sends two segments
// for each one that arrives and doubles every round trip, from the head alone,
// up to the ceiling. A source that pruned its out-of-order queue on the hole
// fill holds nothing past it, and one segment a round trip would take a round
// trip per segment of the purged span; a real sender slow-starts that
// go-back-N instead. The run is what recovery may have in flight past the
// acknowledgement, so it is also what a run of losses can cost in segments the
// source held past it. The burst stops at the recovery point and at the window
// edge `windowEnd`, which retention already implies, and skips segments
// already sent again in this recovery, which are in flight: the
// acknowledgements for one burst arrive together, and the hole interval, one
// round trip, would let the later of them resend the burst's tail.
func (self *tcpReturnRetransmitState) markBurstWithLock(windowEnd uint32, nowNanos int64, ackedResentCount int) {
	self.burstSegmentCount = min(
		max(1, self.burstSegmentCount+ackedResentCount),
		returnRetransmitMaxBurstSegmentCount,
	)
	for index := 0; index < min(self.burstSegmentCount, self.deliveredCount); index += 1 {
		segment := self.segmentAtWithLock(index)
		end := segment.seq + segment.byteCount
		if 0 < int32(end-self.recoveryEnd) || 0 < int32(end-windowEnd) {
			break
		}
		if 0 < segment.retransmitCount && self.recoveryStartNanos <= segment.retransmitNanos {
			continue
		}
		self.markDueWithLock(segment, tcpReturnRetransmitReasonPartialAck, nowNanos)
		if 0 < index && segment.due {
			// past the hole at the cumulative acknowledgement, so it is the
			// burst's guess
			segment.guessed = true
		}
	}
}

// Retransmits every unmarked delivered segment below the highest selectively
// acknowledged byte, each at most once per round trip, and at most a burst's
// worth newly marked per hole interval. Nothing reaches this without the
// handshake negotiating sack-permitted (applySackWithLock), and a source that
// negotiated it still reports what it likes: one acknowledgement whose single
// block covers only the newest retained segment would otherwise mark every
// delivered segment below it, and takeDueWithLock builds all of them in one
// hold of the sequence mutex, which the shared send shard's acknowledgement
// path waits on, and the worker holds every packet until the first is
// delivered.
//
// The bound is carried over the hole interval rather than over one
// acknowledgement, because one acknowledgement is not what an interval costs:
// this runs again for every acknowledgement whose blocks are new, any number
// of which can arrive inside one interval, and the segments the last run sent
// are skipped by the one-per-hole-interval rule rather than counted against
// the ceiling, so the walk goes on past them to the next unsent ones. A
// source that moves its single block down the flight drew the whole retained
// set per interval that way, one burst per acknowledgement. Over the interval
// the rate is the one the partial-acknowledgement bursts keep, which have one
// partial acknowledgement per round trip to grow on, and the same period one
// hole waits between its own retransmissions; the holes a burst leaves are
// marked by the next trigger, so a purged span still recovers in a burst per
// interval rather than a segment per round trip.
func (self *tcpReturnRetransmitState) markSackHolesWithLock(nowNanos int64) {
	if self.sackedCount == 0 {
		return
	}
	if self.sackBurstSegmentCount == 0 || self.sackBurstEndNanos <= nowNanos {
		// the interval runs from its first mark, rather than from a zero
		// deadline the monotonic clock can be either side of
		self.sackBurstSegmentCount = 0
		self.sackBurstEndNanos = nowNanos + self.holeIntervalNanos()
	}
	for index := 0; index < self.deliveredCount &&
		self.sackBurstSegmentCount < returnRetransmitMaxBurstSegmentCount; index += 1 {
		segment := self.segmentAtWithLock(index)
		if 0 <= int32(segment.seq-self.highestSackedEnd) {
			break
		}
		previousDueCount := self.dueCount
		self.markDueWithLock(segment, tcpReturnRetransmitReasonSackHole, nowNanos)
		if previousDueCount < self.dueCount {
			self.sackBurstSegmentCount += 1
		}
	}
}

// The first retained index whose segment starts at or after `seq`, or count.
// Segments are in sequence order, so this is a binary search on the offset
// from the head.
func (self *tcpReturnRetransmitState) indexAtOrAfterWithLock(seq uint32) int {
	headSeq := self.segmentAtWithLock(0).seq
	target := int64(int32(seq - headSeq))
	low, high := 0, self.count
	for low < high {
		middle := (low + high) / 2
		offset := int64(int32(self.segmentAtWithLock(middle).seq - headSeq))
		if offset < target {
			low = middle + 1
		} else {
			high = middle
		}
	}
	return low
}

// Marks the segments the acknowledgement's SACK blocks cover. Each duplicate
// acknowledgement repeats the whole out-of-order range, so a block inside one
// already applied costs four compares rather than a walk; a block that extends
// or adds one walks only its own segments. Reports whether anything new was
// marked.
func (self *tcpReturnRetransmitState) applySackWithLock(tcp *parsedTcp) (changed bool) {
	if !self.sackPermitted {
		// the handshake negotiated none, so these blocks report what their
		// sender likes and nothing here is decided by them
		return false
	}
	for blockIndex := 0; blockIndex < tcp.sackBlockCount; blockIndex += 1 {
		block := tcp.sackBlocks[blockIndex]
		if int32(block.end-block.start) <= 0 {
			continue
		}
		applied := false
		for appliedIndex := 0; appliedIndex < self.appliedSackBlockCount; appliedIndex += 1 {
			appliedBlock := self.appliedSackBlocks[appliedIndex]
			if 0 <= int32(block.start-appliedBlock.start) && 0 <= int32(appliedBlock.end-block.end) {
				applied = true
				break
			}
		}
		if applied {
			continue
		}
		for index := self.indexAtOrAfterWithLock(block.start); index < self.count; index += 1 {
			segment := self.segmentAtWithLock(index)
			end := segment.seq + segment.byteCount
			if 0 < int32(end-block.end) {
				break
			}
			if !segment.sacked {
				segment.sacked = true
				self.sackedCount += 1
				changed = true
				if segment.due {
					// the source has it after all
					segment.due = false
					self.dueCount -= 1
				}
				if self.sackedCount == 1 || 0 < int32(end-self.highestSackedEnd) {
					self.highestSackedEnd = end
				}
			}
		}
		// remember the block, replacing one it extends, else the oldest
		replaceIndex := -1
		for appliedIndex := 0; appliedIndex < self.appliedSackBlockCount; appliedIndex += 1 {
			appliedBlock := self.appliedSackBlocks[appliedIndex]
			if 0 <= int32(appliedBlock.start-block.start) && 0 <= int32(block.end-appliedBlock.end) {
				replaceIndex = appliedIndex
				break
			}
		}
		if replaceIndex < 0 {
			if self.appliedSackBlockCount < tcpMaxSackBlockCount {
				replaceIndex = self.appliedSackBlockCount
				self.appliedSackBlockCount += 1
			} else {
				replaceIndex = tcpMaxSackBlockCount - 1
				copy(self.appliedSackBlocks[0:], self.appliedSackBlocks[1:])
			}
		}
		self.appliedSackBlocks[replaceIndex] = block
	}
	return
}

// Releases every segment the cumulative acknowledgement covers and samples the
// round trip from the newest released segment, unless the acknowledgement
// covers a retransmitted segment, when it samples nothing (see the type
// header). Reports what it released, which the partial-acknowledgement rule
// reads: how many of the released segments this recovery had sent again, and
// how many it had not, which are segments the source held past the hole.
func (self *tcpReturnRetransmitState) releaseAckedWithLock(
	ackNumber uint32,
	nowNanos int64,
) (resentCount int, heldCount int) {
	sampleNanos := int64(-1)
	resentAcked := false
	for 0 < self.count {
		segment := self.segmentAtWithLock(0)
		if 0 < int32(segment.seq+segment.byteCount-ackNumber) {
			break
		}
		if 0 < segment.retransmitCount {
			// nothing this acknowledgement covers measures the path
			resentAcked = true
		} else if segment.delivered {
			sampleNanos = nowNanos - segment.sentNanos
		}
		if 0 < segment.retransmitCount && self.recoveryStartNanos <= segment.retransmitNanos {
			resentCount += 1
		} else {
			heldCount += 1
		}
		released := self.popWithLock()
		if released.packet != nil {
			MessagePoolReturn(released.packet)
		}
	}
	if 0 <= sampleNanos && !resentAcked {
		self.updateRttWithLock(sampleNanos)
	}
	if 0 < self.count && self.segmentAtWithLock(0).sacked {
		// the source reported holding the head and then acknowledged
		// short of it: it reneged (RFC 2018 §8), so every mark is stale and
		// the head is a hole the partial-acknowledgement rule may fill
		for index := 0; index < self.count; index += 1 {
			self.segmentAtWithLock(index).sacked = false
		}
		self.sackedCount = 0
		self.appliedSackBlockCount = 0
	}
	// applied blocks below the acknowledgement no longer cover anything
	keptCount := 0
	for appliedIndex := 0; appliedIndex < self.appliedSackBlockCount; appliedIndex += 1 {
		appliedBlock := self.appliedSackBlocks[appliedIndex]
		if 0 < int32(appliedBlock.end-ackNumber) {
			self.appliedSackBlocks[keptCount] = appliedBlock
			keptCount += 1
		}
	}
	self.appliedSackBlockCount = keptCount
	self.shrinkWithLock()
	return
}

// Applies one acknowledgement the sequence has already validated against its
// emitted range. `previousAckNumber` is the cumulative acknowledgement before
// it, `windowByteCount` its window after scaling, and `windowEnd` the
// greatest window edge the source has advertised. Reports whether the worker
// must run now: a retransmission is due, or progress brought the timer's
// deadline in well before the wake the worker is sleeping toward, as the first
// round-trip sample does to the initial second and as progress does to a
// backed-off timer; the worker sleeps past a deadline by at most a quarter of
// the timer.
func (self *tcpReturnRetransmitState) ackWithLock(
	tcp *parsedTcp,
	previousAckNumber uint32,
	windowByteCount uint32,
	windowEnd uint32,
	nowNanos int64,
) (wake bool) {
	previousWindowByteCount := self.ackWindowByteCount
	self.ackWindowByteCount = windowByteCount
	if !self.enabled || self.count == 0 {
		self.dupAckCount = 0
		return false
	}
	ackNumber := tcp.ackNumber
	if ackNumber != previousAckNumber {
		// the head the acknowledgement advanced over, before it is released
		previousHead := *self.segmentAtWithLock(0)
		ackedResentCount, ackedHeldCount := self.releaseAckedWithLock(ackNumber, nowNanos)
		self.dupAckCount = 0
		self.progressNanos = nowNanos
		recovered := self.count == 0 || 0 <= int32(ackNumber-self.recoveryEnd)
		// progress re-arms the timer from its base, which drops the backoff,
		// except while a probe is undecided
		keepBackoff := false
		switch self.recoveryPhase {
		case tcpReturnRecoveryPhaseTimeoutProbe, tcpReturnRecoveryPhaseTimeoutProbeAdvanced:
			if recovered {
				self.recoveryPhase = tcpReturnRecoveryPhaseNone
			} else if int32(ackNumber-self.probeHeadEnd) <= 0 {
				// no further than the head the expiry sent again, which
				// after a smaller path mtu went in pieces that are
				// acknowledged one by one: the source may hold its original
				// or the retransmission, and nothing yet says which
				self.recoveryPhase = tcpReturnRecoveryPhaseTimeoutProbeAdvanced
				keepBackoff = true
			} else {
				// past the retransmitted head, whatever advanced to it
				// before: the source holds bytes that were never sent again,
				// so the originals arrived and only their acknowledgements
				// were late (RFC 5682 §2.1 step 3b). The expiry was spurious:
				// nothing more is sent, and the base below is the timer it
				// doubled
				self.recoveryPhase = tcpReturnRecoveryPhaseNone
			}
		case tcpReturnRecoveryPhaseLoss:
			if recovered {
				self.recoveryPhase = tcpReturnRecoveryPhaseNone
			} else if head := self.segmentAtWithLock(0); 0 < int32(ackNumber-head.seq) &&
				0 < head.retransmitCount && self.recoveryStartNanos <= head.retransmitNanos {
				// it ends inside a segment this recovery already sent
				// again, as the acknowledgement of one of its pieces does:
				// the rest are in flight, and a burst here would grow on
				// each piece and resend what lies past them, which the
				// source may hold
			} else if !self.retransmissionExplainsWithLock(
				0 < previousHead.retransmitCount,
				previousHead.retransmitNanos,
				nowNanos,
			) {
				// the head was never sent again, or came too soon after the
				// retransmission to be its answer: a copy sent before it
				// arrived, so the head was never missing and this recovery
				// is spurious. Its cause is reordering on the path, which
				// three duplicates cannot tell from loss, or duplicates this
				// flow's own retransmissions drew. Recovery ends here: going
				// on, every ordinary acknowledgement of data in flight would
				// read as a partial one and its bursts would send that data
				// again
				self.recoveryPhase = tcpReturnRecoveryPhaseNone
			} else {
				// a partial acknowledgement: the next hole starts at the
				// new head, and waiting three more duplicates for it would
				// wait for data that may never be sent (RFC 6582 §3.2)
				if 0 < ackedHeldCount {
					// it covered data the source held past the hole, so
					// nothing was purged here and the next hole is one
					// segment: the run starts again at the head alone
					self.burstSegmentCount = 1
					ackedResentCount = 0
				}
				self.markBurstWithLock(windowEnd, nowNanos, ackedResentCount)
			}
		}
		if !keepBackoff {
			self.rtoNanos = self.baseRtoNanos()
		}
		self.rtoDeadlineNanos = nowNanos + self.rtoNanos
		if self.count == 0 {
			return false
		}
		if self.applySackWithLock(tcp) && self.recoveryPhase == tcpReturnRecoveryPhaseLoss {
			self.markSackHolesWithLock(nowNanos)
		}
		// by more than a quarter of the timer: a sample's jitter moves the
		// deadline in by less on many acknowledgements, and a wake for each
		// would take the mutex from the acknowledgement path at its rate
		return 0 < self.dueCount ||
			(0 < self.deliveredCount && self.rtoDeadlineNanos+self.rtoNanos/4 < self.timerWakeNanos)
	}
	if 0 < len(tcp.payload) || tcp.syn || tcp.fin || tcp.rst || windowByteCount != previousWindowByteCount {
		// not a duplicate acknowledgement: it carries something of its own,
		// if only a window update, which a receiver sends as its application
		// reads and which says nothing about loss (RFC 5681 §2)
		return false
	}
	self.dupAckCount += 1
	sackChanged := self.applySackWithLock(tcp)
	if self.deliveredCount == 0 {
		// the hole's batch is still being delivered, and this duplicate still
		// counts: markDeliveredWithLock retransmits when it marks the head
		return false
	}
	switch self.recoveryPhase {
	case tcpReturnRecoveryPhaseTimeoutProbe:
		// the source is missing the head: the expiry was real (RFC 5682
		// §2.1 step 2a), and the head it sent again, at the start the
		// expiry recorded, is already out
		self.beginLossRecoveryWithLock(self.recoveryStartNanos)
	case tcpReturnRecoveryPhaseTimeoutProbeAdvanced:
		// the acknowledgement that covered exactly the head was a partial
		// one, and the segment after it is missing too (step 3a): its burst
		// goes now
		self.beginLossRecoveryWithLock(self.recoveryStartNanos)
		self.markBurstWithLock(windowEnd, nowNanos, 0)
	}
	if self.dupAckCount < returnRetransmitDupAckThreshold {
		return 0 < self.dueCount
	}
	switch {
	case self.recoveryPhase == tcpReturnRecoveryPhaseNone:
		// at the threshold, or past it when the duplicates before it came
		// while nothing was delivered, or when this flow's own retransmissions
		// explained the ones before it
		self.fastRetransmitWithLock(ackNumber, nowNanos)
	case 0 < self.sackedCount && (sackChanged || self.dupAckCount == returnRetransmitDupAckThreshold):
		self.markSackHolesWithLock(nowNanos)
	case self.dupAckCount == returnRetransmitDupAckThreshold:
		self.markDueWithLock(self.segmentAtWithLock(0), tcpReturnRetransmitReasonDupAck, nowNanos)
	}
	return 0 < self.dueCount
}

// The worker's clock. Reports an expired no-progress bound as `abandon`, marks
// the head due on timer expiry with backoff, and returns how long the worker
// waits for the next of either, negative when nothing delivered is
// outstanding. An expiry with no answer from the source since the last one
// probes; an expiry after the probe saw an answer, or during loss recovery,
// is loss (RFC 5682 §2.1 step 1). The wake it returns is remembered, so an
// acknowledgement that brings the deadline in before it wakes the worker.
func (self *tcpReturnRetransmitState) timerWithLock(nowNanos int64) (abandon bool, waitNanos int64) {
	self.timerWakeNanos = math.MaxInt64
	if !self.enabled || self.deliveredCount == 0 {
		return false, -1
	}
	abandonNanos := self.progressNanos + int64(self.timeout)
	if abandonNanos <= nowNanos {
		return true, -1
	}
	if self.rtoDeadlineNanos <= nowNanos {
		head := self.segmentAtWithLock(0)
		self.markDueWithLock(head, tcpReturnRetransmitReasonTimeout, nowNanos)
		self.rtoNanos = min(2*self.rtoNanos, int64(returnRetransmitMaxRto))
		self.rtoDeadlineNanos = nowNanos + self.rtoNanos
		switch self.recoveryPhase {
		case tcpReturnRecoveryPhaseNone, tcpReturnRecoveryPhaseTimeoutProbe:
			// silence is no evidence of loss: a stall that holds the
			// acknowledgements back looks the same, so only the head goes
			self.recoveryPhase = tcpReturnRecoveryPhaseTimeoutProbe
			self.probeHeadEnd = head.seq + head.byteCount
			self.recoveryStartNanos = nowNanos
		default:
			// what was sent again before the expiry is presumed lost with
			// the rest, and the bursts start over from one
			self.beginLossRecoveryWithLock(nowNanos)
		}
		self.recoveryEnd = self.highestDeliveredWithLock()
		if self.counters != nil {
			self.counters.timeoutCount.Add(1)
		}
	}
	self.timerWakeNanos = min(self.rtoDeadlineNanos, abandonNanos)
	return false, self.timerWakeNanos - nowNanos
}

// Builds every due segment through `build`, which appends its packets, one or
// more pieces, and records the send. The packets are the caller's to deliver
// outside the lock.
func (self *tcpReturnRetransmitState) takeDueWithLock(
	packets [][]byte,
	nowNanos int64,
	build func(packets [][]byte, segment *tcpReturnRetainedSegment) [][]byte,
) [][]byte {
	guessedPacketCount := 0
	defer func() {
		if guessedPacketCount == 0 {
			return
		}
		// the duplicates the guesses can draw, for the guard in
		// fastRetransmitWithLock. A segment the acknowledgements showed
		// missing draws none: the source is missing it
		if self.explainedDupAckNanos <= nowNanos {
			self.explainedDupAckCount = 0
		}
		self.explainedDupAckCount += guessedPacketCount
		tail := self.segmentAtWithLock(self.count - 1)
		self.explainedDupAckEnd = tail.seq + tail.byteCount
		self.explainedDupAckNanos = nowNanos + self.baseRtoNanos()
	}()
	for index := 0; 0 < self.dueCount && index < self.count; index += 1 {
		segment := self.segmentAtWithLock(index)
		if !segment.due {
			continue
		}
		segment.due = false
		self.dueCount -= 1
		segment.retransmitNanos = nowNanos
		segment.retransmitCount += 1
		builtCount := len(packets)
		packets = build(packets, segment)
		builtCount = len(packets) - builtCount
		if segment.guessed {
			guessedPacketCount += builtCount
		}
		self.retransmitPacketCount += int64(builtCount)
		self.retransmitByteCount += int64(segment.byteCount)
		self.reasonCounts[segment.dueReason] += 1
		if self.counters != nil {
			self.counters.packetCount.Add(int64(builtCount))
			self.counters.byteCount.Add(int64(segment.byteCount))
		}
	}
	return packets
}
