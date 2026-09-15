// Bounded retransmission of the inner TCP segments the user NAT sends toward
// the source on the return path (the provider-terminated download direction).
// Transfer delivers those segments losslessly to the source device, but the
// device kernel can still drop one on its receive socket after the tunnel has
// written it, and with nothing retained here that drop was a permanent hole.
// See tcpReturnRetransmitState for the design; the hooks are in TcpSequence.
package connect

import (
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
	// the most blocks one SACK option carries beside a timestamp option
	tcpMaxSackBlockCount = 4
	// the bounds used when the settings leave them zero
	defaultReturnRetransmitRetainByteCount = ByteCount(4 * 1024 * 1024)
	defaultReturnRetransmitTimeout         = 60 * time.Second
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
	// one acknowledgement since the expiry covered exactly the head it sent
	// again, and the next acknowledgement decides
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
}

// Cumulative counts of return-path retransmission across a NAT's TCP flows.
// Read with `LocalUserNat.ReturnRetransmitStats` or the provider's.
type ReturnRetransmitStats struct {
	// segments sent again, and their sequence bytes
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
// buffer: it is a fresh packet built from the retained payload with the
// current acknowledgement, window and timestamps, exactly as the handshake
// retransmits its SYN-ACK.
//
// Sent means delivered. A segment is retained when it is packetized, for the
// cap, but it counts as sent only once the delivery drain has handed it to
// the return path: retransmissions leave on their own goroutine and can
// overtake segments still queued for delivery, and a decision about a segment
// the source cannot have seen yet would be a spurious retransmission. Every
// trigger below considers delivered segments only, the round trip is measured
// from delivery, and the delivered set is always a prefix of the ring, since
// the drain delivers in sequence order.
//
// Bounds. Retained sequence bytes never exceed the source's advertised window,
// because the packetizer already stops at the window edge and every emitted
// byte is retained, and never exceed ReturnRetransmitRetainByteCount, which
// the packetizer applies beside the window: a burst larger than the cap waits
// for acknowledgements to free space, as it waits for the window. Pool size
// classes round each share up, so the memory is at most about 1.4 times the
// cap. Time is bounded by ReturnRetransmitTimeout: when the cumulative
// acknowledgement has not advanced for that long with delivered segments
// outstanding, the flow is reset toward the source and closed, never left
// idle. That is the acceptance contract: a transient loss completes the exact
// byte stream; an unrecoverable one is an explicit, bounded failure.
//
// Triggers. Fast retransmit: the third duplicate acknowledgement of one
// cumulative ack retransmits the first unacknowledged segment and starts loss
// recovery (RFC 5681 §3.2). A duplicate repeats the cumulative ack and the
// window and carries no payload, SYN or FIN (RFC 5681 §2): a window update is
// not one, however many the source sends while its application reads. With
// SACK blocks it retransmits every unmarked segment below the highest
// selectively acknowledged byte instead, and further duplicate
// acknowledgements that extend the marked range retransmit the holes they
// newly reveal. A partial acknowledgement inside loss recovery, one that
// advances but not to the recovery's end, retransmits the next hole at once
// (NewReno, RFC 6582). The timer: max(200 ms, 2 x srtt, srtt + 4 rttvar) from
// the inner round trip, one second before a sample exists, doubling on each
// expiry to an 8 s ceiling and reset by acknowledgement progress; expiry
// retransmits the first unacknowledged segment only.
//
// An expiry is not by itself loss. The round trip includes Transfer's
// queueing, so a tunnel stall holds acknowledgements past the timer, and if
// the expiry began loss recovery every late acknowledgement would read as a
// partial one and send the window again. So an expiry probes, in the spirit
// of F-RTO (RFC 5682), and sends nothing beyond the head until the
// acknowledgements decide. The first to advance past the retransmitted head,
// or a second to advance with no duplicate between, acknowledges a segment
// never sent again: the originals arrived, the expiry was spurious, and the
// probe ends with the timer back at its base, the value the expiry doubled,
// updated by whatever round trips the late acknowledgements sampled. A
// duplicate acknowledgement shows a segment missing and turns the probe into
// loss recovery, retransmitting at once when the head had already advanced.
// Silence decides nothing, so expiries with no answer at all only back off
// and send the head again; an expiry after the source has answered is loss
// (RFC 5682 §2.1 step 1), which is how a source that lost everything past the
// head recovers when no later segment exists to draw a duplicate. Until the
// probe decides, advances keep the doubled timer, so a stall that lets one
// acknowledgement through must outlast twice the timer to read as loss.
//
// The round trip is sampled by the time from a segment's delivery to the
// acknowledgement that covers it, from segments never retransmitted (Karn).
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
	enabled         bool
	retainByteCount int64
	timeout         time.Duration
	// shared with the owning NAT, nil when nothing counts
	counters *returnRetransmitCounters

	// circular, in sequence order from head; the delivered prefix first
	segments              []tcpReturnRetainedSegment
	head                  int
	count                 int
	deliveredCount        int
	retainedByteCount     int64
	sackedCount           int
	highestSackedEnd      uint32
	appliedSackBlocks     [tcpMaxSackBlockCount]tcpSackBlock
	appliedSackBlockCount int
	finRetained           bool
	dueCount              int

	dupAckCount int
	// the scaled window of the last acceptable acknowledgement, which a
	// duplicate must repeat
	ackWindowByteCount uint32
	recoveryPhase      tcpReturnRecoveryPhase
	// the end of the highest delivered segment when the recovery or the
	// probe last began; an acknowledgement that reaches it ends either
	recoveryEnd uint32
	// the end of the head the probe's expiry sent again
	probeHeadEnd uint32

	rttKnown         bool
	srttNanos        int64
	rttvarNanos      int64
	rtoNanos         int64
	rtoDeadlineNanos int64
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
		state.retainByteCount = int64(defaultReturnRetransmitRetainByteCount)
	}
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
		grown := make([]tcpReturnRetainedSegment, max(16, 2*len(self.segments)))
		for index := 0; index < self.count; index += 1 {
			grown[index] = *self.segmentAtWithLock(index)
		}
		self.segments = grown
		self.head = 0
	}
	self.segments[(self.head+self.count)%len(self.segments)] = segment
	self.count += 1
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

// Sequence bytes the cap still allows; unbounded when disabled.
func (self *tcpReturnRetransmitState) roomWithLock() int64 {
	if !self.enabled {
		return int64(1) << 62
	}
	return self.retainByteCount - self.retainedByteCount
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
}

// Marks retained segments as handed to the return path, by the sequences the
// drain delivered, in order. A delivered sequence the ring no longer holds
// was acknowledged before the batch's callback returned, which the fast
// acknowledgement path allows, and is skipped; a packet that was never
// retained (a teardown reset) matches nothing and shifts nothing. Reports
// whether the first delivered segment with nothing outstanding just went out,
// which starts the timer and the no-progress clock.
func (self *tcpReturnRetransmitState) markDeliveredWithLock(seqs []uint32, nowNanos int64) (armed bool) {
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
				armed = true
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
	self.recoveryPhase = tcpReturnRecoveryPhaseNone
	self.dupAckCount = 0
	self.appliedSackBlockCount = 0
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
		self.rttvarNanos = sampleNanos / 2
		return
	}
	deviationNanos := self.srttNanos - sampleNanos
	if deviationNanos < 0 {
		deviationNanos = -deviationNanos
	}
	self.rttvarNanos = (3*self.rttvarNanos + deviationNanos) / 4
	self.srttNanos = (7*self.srttNanos + sampleNanos) / 8
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
	self.dueCount += 1
}

// Retransmits every unmarked delivered segment below the highest selectively
// acknowledged byte, each at most once per round trip.
func (self *tcpReturnRetransmitState) markSackHolesWithLock(nowNanos int64) {
	if self.sackedCount == 0 {
		return
	}
	for index := 0; index < self.deliveredCount; index += 1 {
		segment := self.segmentAtWithLock(index)
		if 0 <= int32(segment.seq-self.highestSackedEnd) {
			break
		}
		self.markDueWithLock(segment, tcpReturnRetransmitReasonSackHole, nowNanos)
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
// round trip from the newest released segment that was never retransmitted.
func (self *tcpReturnRetransmitState) releaseAckedWithLock(ackNumber uint32, nowNanos int64) {
	sampleNanos := int64(-1)
	for 0 < self.count {
		segment := self.segmentAtWithLock(0)
		if 0 < int32(segment.seq+segment.byteCount-ackNumber) {
			break
		}
		if segment.delivered && segment.retransmitCount == 0 {
			sampleNanos = nowNanos - segment.sentNanos
		}
		released := self.popWithLock()
		if released.packet != nil {
			MessagePoolReturn(released.packet)
		}
	}
	if 0 <= sampleNanos {
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
}

// Applies one acknowledgement the sequence has already validated against its
// emitted range. `previousAckNumber` is the cumulative acknowledgement before
// it and `windowByteCount` its window after scaling. Reports whether a
// retransmission is now due, which wakes the worker.
func (self *tcpReturnRetransmitState) ackWithLock(
	tcp *parsedTcp,
	previousAckNumber uint32,
	windowByteCount uint32,
	nowNanos int64,
) (due bool) {
	previousWindowByteCount := self.ackWindowByteCount
	self.ackWindowByteCount = windowByteCount
	if !self.enabled || self.count == 0 {
		self.dupAckCount = 0
		return false
	}
	ackNumber := tcp.ackNumber
	if ackNumber != previousAckNumber {
		self.releaseAckedWithLock(ackNumber, nowNanos)
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
			} else if self.recoveryPhase == tcpReturnRecoveryPhaseTimeoutProbe &&
				int32(ackNumber-self.probeHeadEnd) <= 0 {
				// exactly the head the expiry sent again: the source may
				// hold its original or the retransmission, and nothing yet
				// says which
				self.recoveryPhase = tcpReturnRecoveryPhaseTimeoutProbeAdvanced
				keepBackoff = true
			} else {
				// past the retransmitted head, or a second advance with no
				// duplicate between: the source holds segments that were
				// never sent again, so the originals arrived and only their
				// acknowledgements were late (RFC 5682 §2.1 step 3b). The
				// expiry was spurious: nothing more is sent, and the base
				// below is the timer it doubled
				self.recoveryPhase = tcpReturnRecoveryPhaseNone
			}
		case tcpReturnRecoveryPhaseLoss:
			if recovered {
				self.recoveryPhase = tcpReturnRecoveryPhaseNone
			} else {
				// a partial acknowledgement: the next hole starts at the
				// new head, and waiting three more duplicates for it would
				// wait for data that may never be sent (RFC 6582 §3.2)
				self.markDueWithLock(self.segmentAtWithLock(0), tcpReturnRetransmitReasonPartialAck, nowNanos)
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
		return 0 < self.dueCount
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
		return false
	}
	switch self.recoveryPhase {
	case tcpReturnRecoveryPhaseTimeoutProbe:
		// the source is missing the head: the expiry was real (RFC 5682
		// §2.1 step 2a), and the head it sent again is already out
		self.recoveryPhase = tcpReturnRecoveryPhaseLoss
	case tcpReturnRecoveryPhaseTimeoutProbeAdvanced:
		// the acknowledgement that covered exactly the head was a partial
		// one, and the segment after it is missing too (step 3a)
		self.recoveryPhase = tcpReturnRecoveryPhaseLoss
		self.markDueWithLock(self.segmentAtWithLock(0), tcpReturnRetransmitReasonPartialAck, nowNanos)
	}
	if self.dupAckCount < returnRetransmitDupAckThreshold {
		return 0 < self.dueCount
	}
	if self.dupAckCount == returnRetransmitDupAckThreshold || sackChanged {
		if self.recoveryPhase == tcpReturnRecoveryPhaseNone {
			self.recoveryPhase = tcpReturnRecoveryPhaseLoss
			self.recoveryEnd = self.highestDeliveredWithLock()
		}
		if 0 < self.sackedCount {
			self.markSackHolesWithLock(nowNanos)
		} else if self.dupAckCount == returnRetransmitDupAckThreshold {
			self.markDueWithLock(self.segmentAtWithLock(0), tcpReturnRetransmitReasonDupAck, nowNanos)
		}
	}
	return 0 < self.dueCount
}

// The worker's clock. Reports an expired no-progress bound as `abandon`, marks
// the head due on timer expiry with backoff, and returns how long the worker
// waits for the next of either, negative when nothing delivered is
// outstanding. An expiry with no answer from the source since the last one
// probes; an expiry after the probe saw an answer, or during loss recovery,
// is loss (RFC 5682 §2.1 step 1).
func (self *tcpReturnRetransmitState) timerWithLock(nowNanos int64) (abandon bool, waitNanos int64) {
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
		default:
			self.recoveryPhase = tcpReturnRecoveryPhaseLoss
		}
		self.recoveryEnd = self.highestDeliveredWithLock()
		if self.counters != nil {
			self.counters.timeoutCount.Add(1)
		}
	}
	return false, min(self.rtoDeadlineNanos, abandonNanos) - nowNanos
}

// Builds every due segment through `build` and records the send. The packets
// are the caller's to deliver outside the lock.
func (self *tcpReturnRetransmitState) takeDueWithLock(
	packets [][]byte,
	nowNanos int64,
	build func(segment *tcpReturnRetainedSegment) []byte,
) [][]byte {
	for index := 0; 0 < self.dueCount && index < self.count; index += 1 {
		segment := self.segmentAtWithLock(index)
		if !segment.due {
			continue
		}
		segment.due = false
		self.dueCount -= 1
		segment.retransmitNanos = nowNanos
		segment.retransmitCount += 1
		self.retransmitPacketCount += 1
		self.retransmitByteCount += int64(segment.byteCount)
		self.reasonCounts[segment.dueReason] += 1
		if self.counters != nil {
			self.counters.packetCount.Add(1)
			self.counters.byteCount.Add(int64(segment.byteCount))
		}
		packets = append(packets, build(segment))
	}
	return packets
}
