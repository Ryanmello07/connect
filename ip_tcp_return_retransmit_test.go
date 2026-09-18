// Deterministic tests of the return path's inner TCP retransmission
// (ip_tcp_return_retransmit.go): a source model that reassembles like a
// kernel, drops chosen segments as a kernel does at its receive socket, and
// answers with cumulative and selective acknowledgements, all in virtual time.
//
// The model acknowledges synchronously, inside the delivery callback, so a
// segment acknowledged in order is released before its batch is marked
// delivered and yields no round-trip sample; the timer then runs at its
// initial value, which the schedules below state. Held acknowledgements
// released later do sample the round trip.
//
// Every rule compares sequence numbers modulo 2^32, and a flow that starts
// well inside the sequence space orders them the same way a plain unsigned
// comparison does. So the tests whose decisions compare sequences run again
// as rows whose sequence space wraps partway through the flight
// (tcpReturnTestInitialSynSeqs), usually halfway through a segment next to the
// loss, so that segment starts numerically above its own end and above every
// later sequence. A plain comparison anywhere a rule decides what is sent
// fails at least one row.
package connect

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/urnetwork/connect/protocol"
)

const (
	tcpReturnTestDefaultInitialSynSeq = uint32(1000)
	tcpReturnTestMtu                  = 1500
	// one segment: the mtu less the IPv4 and option-free TCP headers; a
	// timestamp-negotiated flow carries twelve fewer payload bytes
	tcpReturnTestSegmentByteCount = tcpReturnTestMtu - Ipv4HeaderSizeWithoutExtensions - TcpHeaderSizeWithoutExtensions
	tcpReturnTestWindowScale      = uint32(4)
	// the largest window the literal field can carry at that scale
	tcpReturnTestWindowByteCount = uint32(0xffff) << tcpReturnTestWindowScale
)

// Runs one test in a synctest bubble. The message pool starts its stats
// goroutine lazily on first use, and a goroutine started inside a bubble
// belongs to it and would hold the bubble open for ever, so the pool is
// touched once outside first.
func runTcpReturnRetransmitTest(t *testing.T, test func(t *testing.T)) {
	MessagePoolReturn(MessagePoolGet(1))
	synctest.Test(t, test)
}

// A deterministic payload of whole segments whose bytes identify their offset.
func tcpReturnTestPayload(segmentCount int, segmentByteCount int) []byte {
	payload := make([]byte, segmentCount*segmentByteCount)
	for index := range payload {
		payload[index] = byte(index*7 + index/segmentByteCount)
	}
	return payload
}

// Payload bytes per full segment on a flow built with `options`: the
// configured mtu less the flow's IP header, the TCP header and the timestamp
// option when negotiated.
func tcpReturnTestSegmentByteCountFor(options tcpReturnTestOptions) int {
	segmentByteCount := tcpReturnTestSegmentByteCount
	if options.ipVersion == 6 {
		segmentByteCount -= Ipv6HeaderSize - Ipv4HeaderSizeWithoutExtensions
	}
	if options.timestamps {
		segmentByteCount -= tcpTimestampOptionByteCount
	}
	return segmentByteCount
}

// The initial sequence of a flow whose sequence space wraps `byteCount`
// sequence bytes after its first data byte: from there on every sequence is
// numerically below every one before it, which only modular comparisons
// order correctly.
func tcpReturnTestInitialSynSeqWrappingAfter(byteCount int) uint32 {
	return ^uint32(byteCount)
}

// The initial sequences a test runs its rows at: the default, and for each of
// `segmentIndexes` one that wraps halfway through that full segment, so the
// segment starts numerically above its own end and above every later
// sequence.
func tcpReturnTestInitialSynSeqs(options tcpReturnTestOptions, segmentIndexes ...int) []uint32 {
	segmentByteCount := tcpReturnTestSegmentByteCountFor(options)
	initialSynSeqs := []uint32{0}
	for _, segmentIndex := range segmentIndexes {
		initialSynSeqs = append(
			initialSynSeqs,
			tcpReturnTestInitialSynSeqWrappingAfter(segmentIndex*segmentByteCount+segmentByteCount/2),
		)
	}
	return initialSynSeqs
}

// The source's timestamp clock (RFC 7323), in milliseconds of virtual time.
// The bubble's clock starts before the process's epoch, so the value is far
// from zero, and only its progress means anything.
func tcpReturnTestSourceTimestampValue() uint32 {
	return uint32(time.Since(tcpTimestampEpoch)/time.Millisecond) + 1
}

// One acknowledgement on its way to the sequence, with the out-of-order runs
// the source held when the arrival caused it: a path a round trip away
// delivers what was true when it left, not what the source holds on arrival.
type tcpReturnTestDelayedAck struct {
	ackNumber  uint32
	sackBlocks []tcpSackBlock
	at         time.Time
}

// A segment the sequence sent toward the source, as the source model saw it.
type tcpReturnTestSegment struct {
	seq     uint32
	payload []byte
	fin     bool
	rst     bool
	// the timestamp option, when the segment carried one
	timestampValue uint32
	timestampEcho  uint32
	// the whole IP packet's length
	packetByteCount int
	at              time.Time
}

// The source device's TCP receiver, reduced to what the sequence can observe:
// in-order reassembly, out-of-order queueing, cumulative acknowledgements
// with optional SACK blocks and timestamps, and a drop policy standing in for
// the kernel's receive-socket drop, which produces no acknowledgement at all.
type tcpReturnTestSource struct {
	harness    *tcpReturnRetransmitTestHarness
	sack       bool
	timestamps bool

	// when positive, each acknowledgement an arrival causes reaches the
	// sequence this long after it, in order, as over a path with this delay;
	// the harness's pump sends them from `delayedAcks`, or the test steps
	// them from `steppedAcks`
	ackDelay    time.Duration
	delayedAcks chan tcpReturnTestDelayedAck
	stepAcks    bool

	stateLock sync.Mutex
	// while held, nothing is acknowledged; released by ackNow
	holdAcks bool
	rcvNxt   uint32
	// the source's own send sequence, which its upload advances and every
	// segment it sends carries
	sndNxt uint32
	// when the in-order frontier last advanced
	frontierAt time.Time
	stream     []byte
	// out of order, by sequence, without overlap
	ooo []tcpReturnTestSegment
	// when positive, the path toward the source drops every packet longer
	// than this before the kernel sees it, as a link whose mtu is below the
	// sequence's does; the path mtu report is the test's to give
	pathMtu int
	// how many more deliveries of each sequence the kernel drops
	dropCounts map[uint32]int
	// how long the tunnel write of the next delivery of each sequence holds
	// the goroutine delivering it before the kernel sees it, as a stalled
	// return path holds the flow's delivery drain
	stallDurations map[uint32]time.Duration
	// how many deliveries of each sequence arrived, drops included
	seenCounts map[uint32]int
	// every data, FIN or RST segment delivered, in delivery order
	segments    []tcpReturnTestSegment
	finReceived bool
	rstReceived bool
	rstAt       time.Time
	// the last cumulative acknowledgement sent, and how many were sent
	lastAckNumber uint32
	ackCount      int
	// the most sequence bytes the source ever held past its last
	// acknowledgement, which is what the retention cap bounds
	maxOutstandingByteCount int64
	// a receiver that discards its out-of-order queue on the next in-order
	// arrival, to renege on what it selectively acknowledged, or as a kernel
	// prunes its queue on the hole fill
	renegeOnce bool
	// RFC 7323 TS.Recent: the value echoed in acknowledgements
	timestampRecent uint32
	// the timestamp value of the last acknowledgement sent
	lastAckTimestampValue uint32
	// scaled units the advertised window has grown by since the handshake;
	// every acknowledgement carries it
	windowGrowth uint16
	// the acknowledgements waiting for the test's stepAcks, in the order the
	// arrivals caused them
	steppedAcks []tcpReturnTestDelayedAck
	// the first delivery of `reorderSeq` reaches the source only after
	// `reorderAfter` later segments have, as a route crossover delivers it;
	// zero holds nothing back
	reorderSeq     uint32
	reorderAfter   int
	reordered      *tcpReturnTestSegment
	reorderPending int
	reorderDone    bool
}

func (self *tcpReturnTestSource) receive(segment tcpReturnTestSegment) {
	var ackPacket []byte
	var ackTcp parsedTcp
	held := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if 0 < self.reorderAfter && segment.seq == self.reorderSeq &&
			!self.reorderDone && 0 < len(segment.payload) {
			// the path holds it back; the segments behind it pass it
			self.reorderDone = true
			reordered := segment
			self.reordered = &reordered
			self.reorderPending = self.reorderAfter
			return true
		}
		return false
	}()
	if held {
		return
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()

		self.segments = append(self.segments, segment)
		if segment.rst {
			self.rstReceived = true
			self.rstAt = segment.at
			return
		}
		self.seenCounts[segment.seq] += 1
		if 0 < self.pathMtu && self.pathMtu < segment.packetByteCount {
			// too big for the path, so nothing answers it either
			return
		}
		if 0 < self.dropCounts[segment.seq] {
			// the kernel drop: TCP never sees it, so nothing answers it
			self.dropCounts[segment.seq] -= 1
			return
		}
		if self.timestamps && int32(segment.seq-self.rcvNxt) <= 0 &&
			0 <= int32(segment.timestampValue-self.timestampRecent) {
			// RFC 7323 §4.3: an in-order or older segment with a newer
			// value updates the echo
			self.timestampRecent = segment.timestampValue
		}
		if self.renegeOnce && 0 < len(self.ooo) && 0 <= int32(self.rcvNxt-segment.seq) {
			// the hole is filled and what was queued beyond it is gone
			self.renegeOnce = false
			self.ooo = nil
		}
		previousRcvNxt := self.rcvNxt
		self.accept(segment)
		if self.rcvNxt != previousRcvNxt {
			self.frontierAt = segment.at
		}
		end := segment.seq + uint32(len(segment.payload))
		if segment.fin {
			end += 1
		}
		if outstanding := int64(int32(end - self.lastAckNumber)); self.maxOutstandingByteCount < outstanding {
			self.maxOutstandingByteCount = outstanding
		}
		if self.holdAcks {
			return
		}
		if 0 < self.ackDelay {
			delayed := tcpReturnTestDelayedAck{
				ackNumber:  self.rcvNxt,
				sackBlocks: self.sackBlocksWithLock(),
				at:         segment.at.Add(self.ackDelay),
			}
			if self.stepAcks {
				self.steppedAcks = append(self.steppedAcks, delayed)
				return
			}
			select {
			case self.delayedAcks <- delayed:
			default:
				self.harness.t.Errorf("delayed acknowledgement queue full")
			}
			return
		}
		ackPacket, ackTcp = self.buildAckWithLock(self.rcvNxt, self.sackBlocksWithLock())
	}()
	if ackPacket != nil {
		self.harness.sendFromSource(&ackTcp, ackPacket)
	}
	var reordered *tcpReturnTestSegment
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.reordered != nil && 0 < self.reorderPending {
			self.reorderPending -= 1
			if self.reorderPending == 0 {
				reordered = self.reordered
				self.reordered = nil
			}
		}
	}()
	if reordered != nil {
		// the segments it was held behind have arrived; it arrives now
		reordered.at = time.Now()
		self.receive(*reordered)
	}
}

// Reassembles one accepted segment. The lock must be held.
func (self *tcpReturnTestSource) accept(segment tcpReturnTestSegment) {
	end := segment.seq + uint32(len(segment.payload))
	if segment.fin {
		end += 1
	}
	if 0 < int32(segment.seq-self.rcvNxt) {
		for _, queued := range self.ooo {
			if queued.seq == segment.seq {
				return
			}
		}
		insertIndex := len(self.ooo)
		for index, queued := range self.ooo {
			if 0 < int32(queued.seq-segment.seq) {
				insertIndex = index
				break
			}
		}
		self.ooo = append(self.ooo, tcpReturnTestSegment{})
		copy(self.ooo[insertIndex+1:], self.ooo[insertIndex:])
		self.ooo[insertIndex] = segment
		return
	}
	if int32(end-self.rcvNxt) <= 0 {
		// wholly old
		return
	}
	trimByteCount := self.rcvNxt - segment.seq
	payload := segment.payload[min(int(trimByteCount), len(segment.payload)):]
	self.stream = append(self.stream, payload...)
	self.rcvNxt += uint32(len(payload))
	if segment.fin {
		self.finReceived = true
		self.rcvNxt += 1
	}
	for 0 < len(self.ooo) && int32(self.ooo[0].seq-self.rcvNxt) <= 0 {
		queued := self.ooo[0]
		self.ooo = self.ooo[1:]
		self.accept(queued)
	}
}

// The window every segment the source sends advertises, in the units the
// field carries at the negotiated scale. The lock must be held.
func (self *tcpReturnTestSource) windowSizeWithLock() uint16 {
	return uint16(tcpReturnTestWindowByteCount>>tcpReturnTestWindowScale) - 64 + self.windowGrowth
}

// The out-of-order runs the source holds now, as selective acknowledgement
// blocks, when it negotiated them. The lock must be held.
func (self *tcpReturnTestSource) sackBlocksWithLock() []tcpSackBlock {
	if !self.sack {
		return nil
	}
	var blocks []tcpSackBlock
	for _, queued := range self.ooo {
		end := queued.seq + uint32(len(queued.payload))
		if queued.fin {
			end += 1
		}
		if 0 < len(blocks) && blocks[len(blocks)-1].end == queued.seq {
			blocks[len(blocks)-1].end = end
		} else {
			blocks = append(blocks, tcpSackBlock{start: queued.seq, end: end})
		}
	}
	if tcpMaxSackBlockCount < len(blocks) {
		blocks = blocks[:tcpMaxSackBlockCount]
	}
	return blocks
}

// Builds one pure acknowledgement at `ackNumber` carrying `blocks`, a
// timestamp when negotiated, and the current window. The lock must be held.
func (self *tcpReturnTestSource) buildAckWithLock(ackNumber uint32, blocks []tcpSackBlock) ([]byte, parsedTcp) {
	optionByteCount := 0
	if self.timestamps {
		optionByteCount += tcpTimestampOptionByteCount
	}
	if 0 < len(blocks) {
		// two NOPs then the SACK option, a multiple of four
		optionByteCount += 2 + 2 + 8*len(blocks)
	}
	tcpHeaderByteCount := TcpHeaderSizeWithoutExtensions + optionByteCount
	packet, tcp := self.harness.sourcePacket(tcpHeaderByteCount)
	tcp[12] = byte(tcpHeaderByteCount/4) << 4
	options := tcp[TcpHeaderSizeWithoutExtensions:tcpHeaderByteCount]
	optionIndex := 0
	if self.timestamps {
		options[0] = 1
		options[1] = 1
		options[2] = 8
		options[3] = 10
		self.lastAckTimestampValue = tcpReturnTestSourceTimestampValue()
		binary.BigEndian.PutUint32(options[4:8], self.lastAckTimestampValue)
		binary.BigEndian.PutUint32(options[8:12], self.timestampRecent)
		optionIndex = tcpTimestampOptionByteCount
	}
	if 0 < len(blocks) {
		options[optionIndex] = 1
		options[optionIndex+1] = 1
		options[optionIndex+2] = 5
		options[optionIndex+3] = byte(2 + 8*len(blocks))
		for blockIndex, block := range blocks {
			binary.BigEndian.PutUint32(options[optionIndex+4+8*blockIndex:], block.start)
			binary.BigEndian.PutUint32(options[optionIndex+8+8*blockIndex:], block.end)
		}
	}
	self.lastAckNumber = ackNumber
	self.ackCount += 1
	parsed := parsedTcp{
		seq:        self.sndNxt,
		ack:        true,
		ackNumber:  ackNumber,
		windowSize: self.windowSizeWithLock(),
		options:    options,
	}
	parseTcpOptions(&parsed)
	return packet, parsed
}

// Releases held acknowledgements and acknowledges the current frontier.
func (self *tcpReturnTestSource) ackNow() {
	var ackPacket []byte
	var ackTcp parsedTcp
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.holdAcks = false
		ackPacket, ackTcp = self.buildAckWithLock(self.rcvNxt, self.sackBlocksWithLock())
	}()
	self.harness.sendFromSource(&ackTcp, ackPacket)
}

// Sends one pure acknowledgement at `ackNumber`, which must not pass what
// the source holds in order, whether or not acknowledgements are held; a
// receiver whose acknowledgements were merely late sends these one by one.
func (self *tcpReturnTestSource) sendAck(ackNumber uint32) {
	var ackPacket []byte
	var ackTcp parsedTcp
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if 0 < int32(ackNumber-self.rcvNxt) {
			self.harness.t.Errorf("acknowledgement at %d past the source's frontier %d", ackNumber, self.rcvNxt)
		}
		ackPacket, ackTcp = self.buildAckWithLock(ackNumber, self.sackBlocksWithLock())
	}()
	self.harness.sendFromSource(&ackTcp, ackPacket)
}

// Sends one delayed acknowledgement: the number and the selective blocks the
// arrival that caused it left, whatever the source holds now.
func (self *tcpReturnTestSource) sendDelayedAck(delayed tcpReturnTestDelayedAck) {
	var ackPacket []byte
	var ackTcp parsedTcp
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ackPacket, ackTcp = self.buildAckWithLock(delayed.ackNumber, delayed.sackBlocks)
	}()
	self.harness.sendFromSource(&ackTcp, ackPacket)
}

// Sends one pure acknowledgement that repeats the last cumulative
// acknowledgement and whose only news is a window grown by `growth` scaled
// units, as a receiver sends when its application reads.
func (self *tcpReturnTestSource) sendWindowUpdate(growth uint16) {
	var ackPacket []byte
	var ackTcp parsedTcp
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.windowGrowth += growth
		ackPacket, ackTcp = self.buildAckWithLock(self.lastAckNumber, self.sackBlocksWithLock())
	}()
	self.harness.sendFromSource(&ackTcp, ackPacket)
}

// Sends one duplicate of the last acknowledgement, window included.
func (self *tcpReturnTestSource) sendDuplicateAck() {
	var ackPacket []byte
	var ackTcp parsedTcp
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ackPacket, ackTcp = self.buildAckWithLock(self.lastAckNumber, self.sackBlocksWithLock())
	}()
	self.harness.sendFromSource(&ackTcp, ackPacket)
}

// Sends one acknowledgement whose selective blocks are the test's own rather
// than the runs the source holds, as a source that never negotiated selective
// acknowledgement and reports what it likes.
func (self *tcpReturnTestSource) sendCraftedSackAck(ackNumber uint32, blocks []tcpSackBlock) {
	var ackPacket []byte
	var ackTcp parsedTcp
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ackPacket, ackTcp = self.buildAckWithLock(ackNumber, blocks)
	}()
	self.harness.sendFromSource(&ackTcp, ackPacket)
}

// Sends one data segment of the source's own upload, as a client sends while
// the download runs. It repeats the last cumulative acknowledgement and the
// current window, having nothing new to report, and carries the payload the
// sequence forwards to the origin.
func (self *tcpReturnTestSource) sendData(payload []byte) {
	var packet []byte
	var tcp parsedTcp
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		var tcpHeader []byte
		packet, tcpHeader = self.harness.sourcePacket(TcpHeaderSizeWithoutExtensions + len(payload))
		tcpHeader[12] = byte(TcpHeaderSizeWithoutExtensions/4) << 4
		copy(tcpHeader[TcpHeaderSizeWithoutExtensions:], payload)
		tcp = parsedTcp{
			seq:        self.sndNxt,
			ack:        true,
			ackNumber:  self.lastAckNumber,
			windowSize: self.windowSizeWithLock(),
			payload:    tcpHeader[TcpHeaderSizeWithoutExtensions:],
		}
		self.sndNxt += uint32(len(payload))
	}()
	self.harness.sendFromSource(&tcp, packet)
}

// Takes the stall set for the next delivery at `seq`, zero when none is.
func (self *tcpReturnTestSource) takeStall(seq uint32) time.Duration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	stall := self.stallDurations[seq]
	delete(self.stallDurations, seq)
	return stall
}

func (self *tcpReturnTestSource) seenCount(seq uint32) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.seenCounts[seq]
}

// Every delivery at one sequence, in order.
func (self *tcpReturnTestSource) deliveries(seq uint32) []tcpReturnTestSegment {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var deliveries []tcpReturnTestSegment
	for _, segment := range self.segments {
		if segment.seq == seq && !segment.rst {
			deliveries = append(deliveries, segment)
		}
	}
	return deliveries
}

// Delivery times of every segment at one sequence, in order.
func (self *tcpReturnTestSource) deliveryTimes(seq uint32) []time.Time {
	var times []time.Time
	for _, segment := range self.deliveries(seq) {
		times = append(times, segment.at)
	}
	return times
}

func (self *tcpReturnTestSource) streamCopy() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]byte(nil), self.stream...)
}

func (self *tcpReturnTestSource) sentAckCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ackCount
}

// An upstream whose Close takes time, as a real socket's can, so the
// goroutine closing it yields to whatever its earlier defers woke.
type tcpReturnTestSlowCloseConn struct {
	net.Conn
	closeDelay time.Duration
}

func (self *tcpReturnTestSlowCloseConn) Close() error {
	time.Sleep(self.closeDelay)
	return self.Conn.Close()
}

// How one harness is built.
type tcpReturnTestOptions struct {
	// zero is 4
	ipVersion int
	// the flow negotiates selective acknowledgement: the SYN offers
	// sack-permitted and the settings let the SYN-ACK offer it back, which is
	// what the sequence requires before it reads a block (RFC 2018 §2).
	// Without it no block from this source is read at all, however the source
	// sends it
	sack bool
	// one half of that negotiation alone, for the rows that pin it: the SYN
	// offers sack-permitted where the settings do not allow it, and the
	// settings allow it where the SYN is silent. Neither negotiates anything,
	// and the SYN-ACK offers nothing either way
	sourceOffersSack  bool
	settingsAllowSack bool
	timestamps        bool
	// zero is the default well inside the sequence space; see
	// tcpReturnTestInitialSynSeqWrappingAfter for a flow that wraps
	initialSynSeq uint32
	// the scale the source's SYN negotiates; zero is tcpReturnTestWindowScale,
	// and every acknowledgement advertises almost the whole field at it
	windowScale uint32
	// how long the sequence's Close of its upstream takes
	upstreamCloseDelay time.Duration
	// how long each acknowledgement the source sends takes to arrive; zero
	// acknowledges inside the delivery callback
	ackDelay time.Duration
	// with ackDelay, the delayed acknowledgements wait for the test's
	// stepAcks instead of a pump goroutine, so each is applied with the
	// sequence's goroutines run to rest, as they run between real arrivals
	stepAcks  bool
	configure func(*TcpBufferSettings)
}

// Runs one TCP user-NAT sequence against an in-memory upstream, with the
// source model answering on the sequence's own delivery goroutines. Every
// harness reconciles the pool at close, in both directions.
type tcpReturnRetransmitTestHarness struct {
	t              *testing.T
	cancel         context.CancelFunc
	settings       *TcpBufferSettings
	sequence       *TcpSequence
	upstream       net.Conn
	source         *tcpReturnTestSource
	transferSource TransferPath
	counters       returnRetransmitCounters
	ipVersion      int
	initialSynSeq  uint32
	// data starts after the SYN's sequence byte
	dataSeq uint32
	// payload bytes per full segment on this flow
	segmentByteCount int
	synAckReceived   chan struct{}
	// whether the SYN-ACK offered sack-permitted, read after the handshake
	synAckSackPermitted bool
	runDone             chan struct{}
	// closed when the delayed acknowledgement pump ends; nil without one
	ackPumpDone  chan struct{}
	poolTaken    uint64
	poolReturned uint64
	violations   uint64
	closeOnce    sync.Once
}

func newTcpReturnRetransmitTestHarness(t *testing.T, options tcpReturnTestOptions) *tcpReturnRetransmitTestHarness {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	sequenceSocket, upstreamSocket := net.Pipe()
	var sequenceConn net.Conn = sequenceSocket
	if 0 < options.upstreamCloseDelay {
		sequenceConn = &tcpReturnTestSlowCloseConn{Conn: sequenceSocket, closeDelay: options.upstreamCloseDelay}
	}
	settings := DefaultTcpBufferSettingsWithBufferSize(8)
	// far beyond every virtual clock the tests run, so only the bound under
	// test can end a flow
	settings.ReadTimeout = 10 * time.Minute
	settings.WriteTimeout = 10 * time.Minute
	settings.IdleTimeout = 10 * time.Minute
	settings.AckCompressTimeout = 0
	settings.WriteBatchSize = 4
	settings.Mtu = tcpReturnTestMtu
	settings.DialContextSettings = &DialContextSettings{
		DialContext: func(dialCtx context.Context, network string, addr string) (net.Conn, error) {
			return sequenceConn, nil
		},
	}
	ipVersion := options.ipVersion
	if ipVersion == 0 {
		ipVersion = 4
	}
	segmentByteCount := tcpReturnTestSegmentByteCountFor(options)
	// one socket read is eight segments
	settings.ReadBufferByteCount = 8 * segmentByteCount
	// off by default, as production has it, so only a row that asks for the
	// negotiation reaches the selective paths
	settings.EnableReturnRetransmitSack = options.sack || options.settingsAllowSack
	if options.configure != nil {
		options.configure(settings)
	}
	initialSynSeq := options.initialSynSeq
	if initialSynSeq == 0 {
		initialSynSeq = tcpReturnTestDefaultInitialSynSeq
	}

	poolTaken, poolReturned, _ := MessagePoolCounts()
	harness := &tcpReturnRetransmitTestHarness{
		t:                t,
		cancel:           cancel,
		settings:         settings,
		upstream:         upstreamSocket,
		transferSource:   SourceId(NewId()),
		ipVersion:        ipVersion,
		initialSynSeq:    initialSynSeq,
		dataSeq:          initialSynSeq + 1,
		segmentByteCount: segmentByteCount,
		synAckReceived:   make(chan struct{}, 1),
		runDone:          make(chan struct{}),
		poolTaken:        poolTaken,
		poolReturned:     poolReturned,
		violations:       MessagePoolViolationCount(),
	}
	harness.source = &tcpReturnTestSource{
		harness:        harness,
		sack:           options.sack || options.sourceOffersSack,
		timestamps:     options.timestamps,
		ackDelay:       options.ackDelay,
		stepAcks:       options.stepAcks,
		rcvNxt:         harness.dataSeq,
		sndNxt:         harness.dataSeq,
		lastAckNumber:  harness.dataSeq,
		dropCounts:     map[uint32]int{},
		stallDurations: map[uint32]time.Duration{},
		seenCounts:     map[uint32]int{},
	}
	if 0 < options.ackDelay && !options.stepAcks {
		// far more than any test's arrivals, so the delivery callback never
		// waits on it
		harness.source.delayedAcks = make(chan tcpReturnTestDelayedAck, 64*1024)
		harness.ackPumpDone = make(chan struct{})
		go func() {
			defer close(harness.ackPumpDone)
			for {
				select {
				case <-ctx.Done():
					return
				case delayed := <-harness.source.delayedAcks:
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Until(delayed.at)):
					}
					harness.source.sendDelayedAck(delayed)
				}
			}
		}()
	}

	sourceIp := net.IPv4(192, 0, 2, 10).To4()
	destinationIp := net.IPv4(203, 0, 113, 7).To4()
	if ipVersion == 6 {
		sourceIp = net.ParseIP("2001:db8::10")
		destinationIp = net.ParseIP("2001:db8::7")
	}
	harness.sequence = NewTcpSequence(
		ctx,
		func(
			source TransferPath,
			provideMode protocol.ProvideMode,
			ipPath *IpPath,
			packet []byte,
		) {
			parse := parseIpv4
			if ipVersion == 6 {
				parse = parseIpv6
			}
			_, packetSourceIp, packetDestinationIp, transport, ok := parse(packet)
			if !ok {
				return
			}
			tcp := &parsedTcp{}
			if !parseTcpPacket(packetSourceIp, packetDestinationIp, transport, tcp) {
				return
			}
			if tcp.syn {
				// what the SYN-ACK offered back, which decides whether this
				// flow reads a selective block at all
				harness.synAckSackPermitted = tcp.enableSackPermitted
				select {
				case harness.synAckReceived <- struct{}{}:
				default:
				}
				return
			}
			if len(tcp.payload) == 0 && !tcp.fin && !tcp.rst {
				// a pure acknowledgement of the source's own data
				return
			}
			if stall := harness.source.takeStall(tcp.seq); 0 < stall {
				time.Sleep(stall)
			}
			harness.source.receive(tcpReturnTestSegment{
				seq:             tcp.seq,
				payload:         append([]byte(nil), tcp.payload...),
				fin:             tcp.fin,
				rst:             tcp.rst,
				timestampValue:  tcp.timestampValue,
				timestampEcho:   tcp.timestampEcho,
				packetByteCount: len(packet),
				at:              time.Now(),
			})
		},
		harness.transferSource,
		protocol.ProvideMode_Network,
		ipVersion,
		sourceIp,
		40001,
		destinationIp,
		443,
		initialSynSeq,
		settings,
	)
	harness.sequence.returnRetransmit.counters = &harness.counters
	go func() {
		defer close(harness.runDone)
		harness.sequence.Run()
	}()

	// the SYN negotiates a window scale so the source can advertise a window
	// larger than the retention cap under test, and timestamps when asked
	windowScale := options.windowScale
	if windowScale == 0 {
		windowScale = tcpReturnTestWindowScale
	}
	synOptions := []byte{3, 3, byte(windowScale), 1}
	if options.timestamps {
		synOptions = append(synOptions, 1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0)
		// from the clock the acknowledgements use: a fixed 1 reads as newer
		// than that clock's values modulo 2^32, so the sequence never moved
		// its echo past the SYN's and no row could tell a current echo
		binary.BigEndian.PutUint32(synOptions[8:12], tcpReturnTestSourceTimestampValue())
	}
	if options.sack || options.sourceOffersSack {
		// sack-permitted, which the SYN-ACK answers only where the settings
		// let it, and two NOPs so the options stay a whole header word
		synOptions = append(synOptions, 4, 2, 1, 1)
	}
	synPacket, synTcpHeader := harness.sourcePacket(TcpHeaderSizeWithoutExtensions + len(synOptions))
	copy(synTcpHeader[TcpHeaderSizeWithoutExtensions:], synOptions)
	synTcp := parsedTcp{
		syn:        true,
		seq:        initialSynSeq,
		windowSize: 0xffff,
		options:    synTcpHeader[TcpHeaderSizeWithoutExtensions:],
	}
	parseTcpOptions(&synTcp)
	harness.sendFromSource(&synTcp, synPacket)
	select {
	case <-harness.synAckReceived:
	case <-time.After(2 * time.Second):
		harness.close()
		t.Fatal("TCP return retransmit harness did not establish")
	}
	// the negotiation the row asked for, on the wire: a source reads the
	// SYN-ACK's sack-permitted to decide whether to report its out-of-order
	// runs at all
	if harness.synAckSackPermitted != options.sack {
		harness.close()
		t.Fatalf("syn-ack offered sack-permitted=%t, want %t", harness.synAckSackPermitted, options.sack)
	}
	if returnSackPermitted := harness.returnSackPermitted(); returnSackPermitted != options.sack {
		harness.close()
		t.Fatalf("the return path took sack-permitted=%t from the handshake, want %t", returnSackPermitted, options.sack)
	}
	// the handshake's acknowledgement, which established flows apply directly
	harness.source.ackNow()

	t.Cleanup(harness.close)
	return harness
}

// Sends the next acknowledgement the source queued, at its own time, with the
// sequence's goroutines run to rest afterwards, as they run between real
// arrivals. Reports how many packets the sequence sent again in answer to it,
// which for a flow inside its path mtu is the segments of one burst, and
// whether there was one to send. Retransmissions sent during the step arrive
// and queue their own acknowledgements behind those already waiting, as an
// in-order path delivers them.
func (self *tcpReturnRetransmitTestHarness) stepOneAck() (packetCount int64, stepped bool) {
	self.t.Helper()
	var next tcpReturnTestDelayedAck
	stepped = func() bool {
		self.source.stateLock.Lock()
		defer self.source.stateLock.Unlock()
		if len(self.source.steppedAcks) == 0 {
			return false
		}
		next = self.source.steppedAcks[0]
		self.source.steppedAcks = self.source.steppedAcks[1:]
		return true
	}()
	if !stepped {
		return 0, false
	}
	if wait := time.Until(next.at); 0 < wait {
		time.Sleep(wait)
	}
	_, _, before, _ := self.retransmitState()
	self.source.sendDelayedAck(next)
	synctest.Wait()
	_, _, after, _ := self.retransmitState()
	return after - before, true
}

// The time of the next acknowledgement the source queued, and whether there
// is one.
func (self *tcpReturnRetransmitTestHarness) nextAckAt() (at time.Time, queued bool) {
	self.source.stateLock.Lock()
	defer self.source.stateLock.Unlock()
	if len(self.source.steppedAcks) == 0 {
		return time.Time{}, false
	}
	return self.source.steppedAcks[0].at, true
}

// Advances `duration` of virtual time, sending each acknowledgement the source
// queued whose time falls inside it, in the order its arrivals caused them and
// at that time.
func (self *tcpReturnRetransmitTestHarness) stepAcks(duration time.Duration) {
	self.t.Helper()
	end := time.Now().Add(duration)
	for {
		at, queued := self.nextAckAt()
		if !queued || end.Before(at) {
			break
		}
		self.stepOneAck()
	}
	if wait := time.Until(end); 0 < wait {
		time.Sleep(wait)
	}
	synctest.Wait()
}

// A zeroed pooled packet from the source with room for `tcpByteCount` bytes of
// TCP after this flow's IP header, and that TCP part. The sequence reads the
// parsed fields beside it, so only the version and the length are real.
func (self *tcpReturnRetransmitTestHarness) sourcePacket(tcpByteCount int) (packet []byte, tcp []byte) {
	ipHeaderByteCount := Ipv4HeaderSizeWithoutExtensions
	versionByte := byte(0x45)
	if self.ipVersion == 6 {
		ipHeaderByteCount = Ipv6HeaderSize
		versionByte = 0x60
	}
	packet = MessagePoolGet(ipHeaderByteCount + tcpByteCount)
	clear(packet)
	packet[0] = versionByte
	return packet, packet[ipHeaderByteCount:]
}

// The sequence number of the k-th full data segment, from zero.
func (self *tcpReturnRetransmitTestHarness) segmentSeq(segmentIndex int) uint32 {
	return self.dataSeq + uint32(segmentIndex*self.segmentByteCount)
}

func (self *tcpReturnRetransmitTestHarness) payload(segmentCount int) []byte {
	return tcpReturnTestPayload(segmentCount, self.segmentByteCount)
}

// Hands one source packet to the sequence as the TCP buffer does: an
// established pure acknowledgement applies directly, anything else queues.
// Either entry takes the packet on success; a refusal after the sequence has
// ended is teardown, not a failure.
func (self *tcpReturnRetransmitTestHarness) sendFromSource(tcp *parsedTcp, packet []byte) {
	if tcp.ack && !tcp.syn && !tcp.fin && !tcp.rst && len(tcp.payload) == 0 &&
		self.sequence.applyEstablishedPureAck(self.transferSource, TransferKey{}, tcp, packet) {
		return
	}
	success, err := self.sequence.send(&TcpSendItem{
		source:      self.transferSource,
		provideMode: protocol.ProvideMode_Network,
		tcp:         *tcp,
		ipPacket:    packet,
	}, -1)
	if err != nil || !success {
		MessagePoolReturn(packet)
	}
}

// Sends the source's reset.
func (self *tcpReturnRetransmitTestHarness) sendRstFromSource() {
	packet, _ := self.sourcePacket(TcpHeaderSizeWithoutExtensions)
	self.sendFromSource(&parsedTcp{
		seq:       self.dataSeq,
		ack:       true,
		ackNumber: self.source.lastAckNumber,
		rst:       true,
	}, packet)
}

// Writes origin bytes into the upstream; returns when the sequence's socket
// reader has consumed them, which the window and the cap can hold back.
func (self *tcpReturnRetransmitTestHarness) write(payload []byte) {
	self.t.Helper()
	if _, err := self.upstream.Write(payload); err != nil {
		self.t.Errorf("upstream write: %v", err)
	}
}

// Closes the upstream, which the socket reader sees as its FIN.
func (self *tcpReturnRetransmitTestHarness) closeUpstream() {
	self.upstream.Close()
}

func (self *tcpReturnRetransmitTestHarness) runIsDone() bool {
	select {
	case <-self.runDone:
		return true
	default:
		return false
	}
}

func (self *tcpReturnRetransmitTestHarness) waitRunDone(timeout time.Duration) {
	self.t.Helper()
	select {
	case <-self.runDone:
	case <-time.After(timeout):
		self.t.Fatalf("sequence did not end within %s", timeout)
	}
}

// The per-flow state, read under the sequence mutex.
func (self *tcpReturnRetransmitTestHarness) retransmitState() (
	retainedByteCount int64,
	retainedCount int,
	packetCount int64,
	reasonCounts [tcpReturnRetransmitReasonCount]int64,
) {
	self.sequence.mutex.Lock()
	defer self.sequence.mutex.Unlock()
	state := &self.sequence.returnRetransmit
	return state.retainedByteCount, state.count, state.retransmitPacketCount, state.reasonCounts
}

// The retransmission timer and its base before backoff, read under the
// sequence mutex.
func (self *tcpReturnRetransmitTestHarness) retransmitTimer() (rto time.Duration, baseRto time.Duration) {
	self.sequence.mutex.Lock()
	defer self.sequence.mutex.Unlock()
	state := &self.sequence.returnRetransmit
	return time.Duration(state.rtoNanos), time.Duration(state.baseRtoNanos())
}

// The loss-recovery run, read under the sequence mutex: the consecutive
// segments from the cumulative acknowledgement that recovery may have in
// flight.
func (self *tcpReturnRetransmitTestHarness) burstRunSegmentCount() int {
	self.sequence.mutex.Lock()
	defer self.sequence.mutex.Unlock()
	return self.sequence.returnRetransmit.burstSegmentCount
}

// Where the flow stands in repairing its return path, read under the sequence
// mutex.
// The duplicate acknowledgements this flow's own guesses can explain, read
// under the sequence mutex (see fastRetransmitWithLock).
func (self *tcpReturnRetransmitTestHarness) explainedDupAckCount() int {
	self.sequence.mutex.Lock()
	defer self.sequence.mutex.Unlock()
	return self.sequence.returnRetransmit.explainedDupAckCount
}

// Whether the handshake left the return path reading selective blocks, read
// under the sequence mutex.
func (self *tcpReturnRetransmitTestHarness) returnSackPermitted() bool {
	self.sequence.mutex.Lock()
	defer self.sequence.mutex.Unlock()
	return self.sequence.returnRetransmit.sackPermitted
}

func (self *tcpReturnRetransmitTestHarness) recoveryPhase() tcpReturnRecoveryPhase {
	self.sequence.mutex.Lock()
	defer self.sequence.mutex.Unlock()
	return self.sequence.returnRetransmit.recoveryPhase
}

// Requires the source's reassembled stream to be exactly `want`, the bytes
// from the first data byte, and every delivery to carry them at its offset.
func (self *tcpReturnRetransmitTestHarness) requireStream(want []byte) {
	self.t.Helper()
	if stream := self.source.streamCopy(); !bytes.Equal(stream, want) {
		self.t.Fatalf("stream has %d bytes, want %d exact", len(stream), len(want))
	}
	self.requireDeliveriesAtTheirOffsets(want)
}

// Requires every data segment the source was handed, originals, pieces and
// retransmissions alike, to carry exactly the bytes of `payload` at its
// sequence's offset from the first data byte, whatever the wrap.
func (self *tcpReturnRetransmitTestHarness) requireDeliveriesAtTheirOffsets(payload []byte) {
	self.t.Helper()
	self.source.stateLock.Lock()
	defer self.source.stateLock.Unlock()
	for deliveryIndex, segment := range self.source.segments {
		if len(segment.payload) == 0 {
			continue
		}
		offset := int(segment.seq - self.dataSeq)
		if len(payload) < offset+len(segment.payload) {
			self.t.Fatalf("delivery %d at %d carries %d bytes from offset %d, past the %d byte payload", deliveryIndex, segment.seq, len(segment.payload), offset, len(payload))
		}
		if !bytes.Equal(segment.payload, payload[offset:offset+len(segment.payload)]) {
			self.t.Fatalf("delivery %d at %d carries %d bytes that are not the payload's at offset %d", deliveryIndex, segment.seq, len(segment.payload), offset)
		}
	}
}

// The delivery at `seq` numbered `deliveryIndex` from zero, failing the test
// rather than panicking the package's test binary when there are fewer.
func (self *tcpReturnRetransmitTestHarness) requireDelivery(seq uint32, deliveryIndex int) tcpReturnTestSegment {
	self.t.Helper()
	deliveries := self.source.deliveries(seq)
	if len(deliveries) <= deliveryIndex {
		self.t.Fatalf("%d deliveries at %d, want at least %d", len(deliveries), seq, deliveryIndex+1)
	}
	return deliveries[deliveryIndex]
}

func (self *tcpReturnRetransmitTestHarness) requireSeenCount(segmentIndex int, want int) {
	self.t.Helper()
	if got := self.source.seenCount(self.segmentSeq(segmentIndex)); got != want {
		self.t.Fatalf("segment %d delivered %d times, want %d", segmentIndex, got, want)
	}
}

// Ends the sequence and reconciles the pool: every root taken since the
// harness began must be back, and none twice.
func (self *tcpReturnRetransmitTestHarness) close() {
	self.closeOnce.Do(func() {
		self.sequence.Cancel()
		self.cancel()
		self.upstream.Close()
		select {
		case <-self.runDone:
		case <-time.After(2 * time.Second):
			self.t.Errorf("TCP return retransmit harness did not stop")
		}
		if self.ackPumpDone != nil {
			// a pending acknowledgement owns no pool buffer, but one being
			// built does until the sequence refuses it
			<-self.ackPumpDone
		}
		taken, returned, _ := MessagePoolCounts()
		if outstanding := int64(taken-returned) - int64(self.poolTaken-self.poolReturned); outstanding != 0 {
			self.t.Errorf("pool roots outstanding after the sequence ended: %d, want 0", outstanding)
		}
		if violations := MessagePoolViolationCount() - self.violations; violations != 0 {
			self.t.Errorf("pool ownership violations during the sequence: %d, want 0", violations)
		}
	})
}

// Proves the parser keeps SACK blocks, in order, without allocating for them,
// stops at the fixed capacity, and treats a malformed length as opaque.
func TestParseTcpOptionsExtractsSackBlocks(t *testing.T) {
	options := []byte{1, 1, 5, 18}
	for _, block := range []tcpSackBlock{{start: 100, end: 200}, {start: 300, end: 400}} {
		options = binary.BigEndian.AppendUint32(options, block.start)
		options = binary.BigEndian.AppendUint32(options, block.end)
	}
	tcp := &parsedTcp{options: options}
	parseTcpOptions(tcp)
	if tcp.sackBlockCount != 2 ||
		tcp.sackBlocks[0] != (tcpSackBlock{start: 100, end: 200}) ||
		tcp.sackBlocks[1] != (tcpSackBlock{start: 300, end: 400}) {
		t.Fatalf("sack blocks=%d %v", tcp.sackBlockCount, tcp.sackBlocks)
	}

	// five blocks: the fixed capacity keeps the first four
	options = []byte{5, 42}
	for blockIndex := 0; blockIndex < 5; blockIndex += 1 {
		options = binary.BigEndian.AppendUint32(options, uint32(1000*blockIndex))
		options = binary.BigEndian.AppendUint32(options, uint32(1000*blockIndex+500))
	}
	tcp = &parsedTcp{options: options}
	parseTcpOptions(tcp)
	if tcp.sackBlockCount != tcpMaxSackBlockCount || tcp.sackBlocks[3].start != 3000 {
		t.Fatalf("sack blocks over capacity=%d %v", tcp.sackBlockCount, tcp.sackBlocks)
	}

	// a length that is not 2+8n carries no blocks but does not end the parse
	tcp = &parsedTcp{options: []byte{5, 6, 0, 0, 0, 0, 2, 4, 0x05, 0xb4}}
	parseTcpOptions(tcp)
	if tcp.sackBlockCount != 0 || !tcp.enableMss || tcp.mss != 0x05b4 {
		t.Fatalf("malformed sack: blocks=%d mss=%t/%d", tcp.sackBlockCount, tcp.enableMss, tcp.mss)
	}

	// a reused struct forgets the previous packet's blocks
	tcp.sackBlockCount = 3
	tcp.options = nil
	parseTcpOptions(tcp)
	if tcp.sackBlockCount != 0 {
		t.Fatalf("stale sack blocks=%d", tcp.sackBlockCount)
	}
}

// (a) One segment dropped at the source's kernel and three duplicate
// acknowledgements: exactly that segment is sent again, once, at once, and
// the stream completes byte for byte. With the setting off this is the
// permanent hole (see TestTcpReturnRetransmitDisabledNeverRetransmits).
func TestTcpReturnRetransmitRecoversOneDroppedSegmentOnDuplicateAcks(t *testing.T) {
	for _, initialSynSeq := range tcpReturnTestInitialSynSeqs(tcpReturnTestOptions{}, 1, 3) {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq})
			droppedSeq := harness.segmentSeq(1)
			harness.source.dropCounts[droppedSeq] = 1
			start := time.Now()

			payload := harness.payload(8)
			harness.write(payload)
			synctest.Wait()

			harness.requireStream(payload)
			for segmentIndex := 0; segmentIndex < 8; segmentIndex += 1 {
				want := 1
				if harness.segmentSeq(segmentIndex) == droppedSeq {
					want = 2
				}
				harness.requireSeenCount(segmentIndex, want)
			}
			// fast, not by the timer: no virtual time passed
			for _, at := range harness.source.deliveryTimes(droppedSeq) {
				if !at.Equal(start) {
					t.Fatalf("retransmission at +%s, want at once", at.Sub(start))
				}
			}
			retainedByteCount, retainedCount, packetCount, reasonCounts := harness.retransmitState()
			if retainedByteCount != 0 || retainedCount != 0 {
				t.Fatalf("retained after full acknowledgement: %d bytes in %d segments", retainedByteCount, retainedCount)
			}
			if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 {
				t.Fatalf("retransmissions=%d reasons=%v, want one on duplicate acks", packetCount, reasonCounts)
			}
			if stats := harness.counters.snapshot(); stats.PacketCount != 1 || stats.ByteCount != ByteCount(harness.segmentByteCount) {
				t.Fatalf("stats=%+v", stats)
			}
		})
	}
}

// A batch whose first segment the source's kernel drops draws its duplicate
// acknowledgements while the rest of the batch is still inside the delivery
// callback, before the drain marks any of it delivered, as a provider's
// return callback does while it waits for Transfer admission. Every one of
// those duplicates counts, and fast retransmit follows the moment the batch is
// marked, not the timer. A first segment held by a stalled tunnel write lets
// the whole batch queue behind it, so all seven duplicates come before the
// marking. They were counted and then ignored while nothing was delivered, and
// only the third could trigger, so the hole waited a second for the timer,
// with SACK or without.
func TestTcpReturnRetransmitDuplicatesBeforeTheirBatchIsMarkedFastRetransmit(t *testing.T) {
	const batchSegmentCount = 8
	const stall = 10 * time.Millisecond
	for _, sack := range []bool{false, true} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
				sack: sack,
				configure: func(settings *TcpBufferSettings) {
					// the batch and the read queue both hold the whole write
					settings.WriteBatchSize = 2 * batchSegmentCount
				},
			})
			payload := harness.payload(1 + batchSegmentCount)
			harness.source.stallDurations[harness.segmentSeq(0)] = stall
			start := time.Now()
			harness.write(payload[:harness.segmentByteCount])
			synctest.Wait()
			// the drain is held in the first segment's write, so the next read
			// queues whole and goes as one batch
			harness.source.stateLock.Lock()
			harness.source.dropCounts[harness.segmentSeq(1)] = 1
			harness.source.stateLock.Unlock()
			harness.write(payload[harness.segmentByteCount:])
			synctest.Wait()

			time.Sleep(stall)
			synctest.Wait()
			// far past the timer
			time.Sleep(2 * returnRetransmitInitialRto)
			synctest.Wait()

			harness.requireStream(payload)
			for segmentIndex := 0; segmentIndex <= batchSegmentCount; segmentIndex += 1 {
				want := 1
				if segmentIndex == 1 {
					want = 2
				}
				harness.requireSeenCount(segmentIndex, want)
				if got := harness.requireDelivery(harness.segmentSeq(segmentIndex), want-1).at.Sub(start); got != stall {
					t.Fatalf("sack=%t: segment %d delivered at +%s, want +%s after the stall", sack, segmentIndex, got, stall)
				}
			}
			wantReason := tcpReturnRetransmitReasonDupAck
			if sack {
				wantReason = tcpReturnRetransmitReasonSackHole
			}
			_, _, packetCount, reasonCounts := harness.retransmitState()
			if packetCount != 1 || reasonCounts[wantReason] != 1 {
				t.Fatalf("sack=%t: retransmissions=%d reasons=%v, want one on %s", sack, packetCount, reasonCounts, wantReason)
			}
			if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
				t.Fatalf("sack=%t: stats=%+v, want no timer expiry", sack, stats)
			}
		})
	}
}

// (b) Two separated segments dropped, with SACK: the third duplicate
// acknowledgement's blocks reveal both holes and only the holes are sent, at
// once, with no cumulative-progress round between them and nothing
// retransmitted on the duplicate acknowledgements that follow. The
// acknowledgements are held and sent by hand, in the order the source's
// arrivals cause them, for the reason
// TestTcpReturnRetransmitPartialAckFillsTheNextHole gives.
func TestTcpReturnRetransmitSackRetransmitsOnlyTheHoles(t *testing.T) {
	for _, initialSynSeq := range tcpReturnTestInitialSynSeqs(tcpReturnTestOptions{}, 1, 2, 3, 5) {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq, sack: true})
			harness.source.holdAcks = true
			harness.source.dropCounts[harness.segmentSeq(1)] = 1
			harness.source.dropCounts[harness.segmentSeq(3)] = 1

			payload := harness.payload(8)
			harness.write(payload)
			synctest.Wait()

			// the first segment, then the five that arrived out of order
			harness.source.sendAck(harness.segmentSeq(1))
			for range 5 {
				harness.source.sendDuplicateAck()
			}
			synctest.Wait()
			harness.requireSeenCount(1, 2)
			harness.requireSeenCount(3, 2)
			// the holes are filled, so the acknowledgement covers the flight
			harness.source.ackNow()
			synctest.Wait()

			harness.requireStream(payload)
			for segmentIndex := 0; segmentIndex < 8; segmentIndex += 1 {
				want := 1
				if segmentIndex == 1 || segmentIndex == 3 {
					want = 2
				}
				harness.requireSeenCount(segmentIndex, want)
			}
			_, _, packetCount, reasonCounts := harness.retransmitState()
			if packetCount != 2 ||
				reasonCounts[tcpReturnRetransmitReasonSackHole] != 2 ||
				reasonCounts[tcpReturnRetransmitReasonDupAck] != 0 ||
				reasonCounts[tcpReturnRetransmitReasonPartialAck] != 0 {
				t.Fatalf("retransmissions=%d reasons=%v, want two on sack holes", packetCount, reasonCounts)
			}
		})
	}
}

// A SACK block that grows down over a hole the source got from a
// retransmission marks that segment held while a lower hole is still missing.
// When a block past a new hole then asks for the holes again, past the hole
// interval, the lower hole and the new one go again and the repaired segment,
// which the source holds, does not. The wrapped row starts the grown block
// numerically above the block it grew from, where a plain comparison reads it
// as one already applied and never marks the repaired segment.
func TestTcpReturnRetransmitSackBlockGrownOverARepairedHoleMarksIt(t *testing.T) {
	const segmentCount = 8
	const lowerHoleIndex = 1
	const repairedHoleIndex = 3
	// in the two segments written later
	const newHoleIndex = segmentCount
	for _, initialSynSeq := range tcpReturnTestInitialSynSeqs(tcpReturnTestOptions{sack: true}, repairedHoleIndex) {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{sack: true, initialSynSeq: initialSynSeq})
			// the lower hole's first retransmission is lost as well
			harness.source.dropCounts[harness.segmentSeq(lowerHoleIndex)] = 2
			harness.source.dropCounts[harness.segmentSeq(repairedHoleIndex)] = 1
			harness.source.dropCounts[harness.segmentSeq(newHoleIndex)] = 1
			// acknowledgements go one at a time below, with the worker run
			// between them as it runs between arrivals
			harness.source.holdAcks = true
			payload := harness.payload(segmentCount + 2)
			harness.write(payload[:segmentCount*harness.segmentByteCount])
			synctest.Wait()

			// one round trip, sampled, puts the timer past every step below
			time.Sleep(100 * time.Millisecond)
			harness.source.sendAck(harness.segmentSeq(lowerHoleIndex))
			for range returnRetransmitDupAckThreshold {
				harness.source.sendDuplicateAck()
			}
			synctest.Wait()
			harness.requireSeenCount(lowerHoleIndex, 2)
			harness.requireSeenCount(repairedHoleIndex, 2)
			// the repaired segment joins the blocks on either side of it
			harness.source.sendDuplicateAck()
			synctest.Wait()

			// past the hole interval and inside the timer
			time.Sleep(250 * time.Millisecond)
			harness.write(payload[segmentCount*harness.segmentByteCount:])
			synctest.Wait()
			harness.source.sendDuplicateAck()
			synctest.Wait()
			harness.source.ackNow()
			synctest.Wait()

			harness.requireStream(payload)
			for segmentIndex := 0; segmentIndex < segmentCount+2; segmentIndex += 1 {
				want := 1
				switch segmentIndex {
				case lowerHoleIndex:
					want = 3
				case repairedHoleIndex, newHoleIndex:
					want = 2
				}
				harness.requireSeenCount(segmentIndex, want)
			}
			_, _, packetCount, reasonCounts := harness.retransmitState()
			if packetCount != 4 || reasonCounts[tcpReturnRetransmitReasonSackHole] != 4 {
				t.Fatalf("retransmissions=%d reasons=%v, want both holes, then the lower hole and the new one, on sack holes", packetCount, reasonCounts)
			}
			if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
				t.Fatalf("stats=%+v, want no timer expiry", stats)
			}
		})
	}
}

// A selective acknowledgement that arrives on an advancing acknowledgement,
// outside loss recovery, retransmits nothing by itself: the three duplicates
// are what tell loss from reordering, and a source reports its out-of-order
// range on every acknowledgement it sends, the first of a reordered run
// included. Marking those holes as they are reported sends a reordered
// segment again for every crossover on the path, and does it before the
// duplicates that would have shown the recovery spurious.
func TestTcpReturnRetransmitSackOnAnAdvancingAckRetransmitsNothing(t *testing.T) {
	const segmentCount = 8
	const holeIndex = 1
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{sack: true})
		harness.source.holdAcks = true
		harness.source.dropCounts[harness.segmentSeq(holeIndex)] = 1
		payload := harness.payload(segmentCount)
		harness.write(payload)
		synctest.Wait()

		// the acknowledgement of the first segment, which also reports every
		// segment the source holds past the hole
		harness.source.sendAck(harness.segmentSeq(holeIndex))
		synctest.Wait()
		if _, _, packetCount, reasonCounts := harness.retransmitState(); packetCount != 0 {
			t.Fatalf("retransmissions=%d reasons=%v on an advancing acknowledgement with selective blocks, want none", packetCount, reasonCounts)
		}
		harness.requireSeenCount(holeIndex, 1)

		// three duplicates of it decide
		for range returnRetransmitDupAckThreshold {
			harness.source.sendDuplicateAck()
		}
		synctest.Wait()
		harness.requireSeenCount(holeIndex, 2)
		harness.source.ackNow()
		synctest.Wait()

		harness.requireStream(payload)
		for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex += 1 {
			want := 1
			if segmentIndex == holeIndex {
				want = 2
			}
			harness.requireSeenCount(segmentIndex, want)
		}
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonSackHole] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v, want the hole once on its sack hole", packetCount, reasonCounts)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
			t.Fatalf("stats=%+v, want no timer expiry", stats)
		}
	})
}

// Inside loss recovery an acknowledgement that advances and reports a new
// out-of-order run marks the holes that run reveals. This is the ordinary
// shape of a partial acknowledgement from a source that reports its runs: it
// covers the hole it was waiting for and says what it now holds above, and
// the holes between are known from the blocks alone. The burst that partial
// acknowledgements otherwise send is no help here, because every segment it
// would reach was already sent again in this recovery and is in flight, so
// without this the acknowledgement marks nothing and the next hole waits for
// a duplicate that a source with blocks to send need never send.
func TestTcpReturnRetransmitAnAdvancingAcknowledgementMarksTheHolesItsBlocksReveal(t *testing.T) {
	const segmentCount = 40
	// what the duplicates report holding, which puts the holes below it
	const reportedIndex = 5
	// what the advancing acknowledgement reports holding, well above it
	const advancedIndex = 30
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{sack: true})
		// nothing is acknowledged, so the whole flight is retained
		harness.source.holdAcks = true
		payload := harness.payload(segmentCount)
		harness.write(payload)
		synctest.Wait()
		// one segment of the flight, as a block that claims it alone
		block := func(segmentIndex int) []tcpSackBlock {
			return []tcpSackBlock{{
				start: harness.segmentSeq(segmentIndex),
				end:   harness.segmentSeq(segmentIndex + 1),
			}}
		}

		// three duplicates reporting one segment start the recovery, which
		// marks the holes below what they report
		for range returnRetransmitDupAckThreshold {
			harness.source.sendCraftedSackAck(harness.dataSeq, block(reportedIndex))
		}
		synctest.Wait()
		_, _, recoveryPacketCount, _ := harness.retransmitState()
		if recoveryPacketCount != reportedIndex {
			t.Fatalf("retransmissions=%d on the third duplicate, want the %d holes below what it reported",
				recoveryPacketCount, reportedIndex)
		}

		// one acknowledgement that both advances over the repaired head and
		// reports a run far above it
		harness.source.sendCraftedSackAck(harness.segmentSeq(1), block(advancedIndex))
		synctest.Wait()
		_, _, packetCount, reasonCounts := harness.retransmitState()
		// everything below the newly reported run that is not the segment it
		// reports and was not already sent again in this recovery
		wantPacketCount := int64(advancedIndex - 1)
		if packetCount != wantPacketCount || reasonCounts[tcpReturnRetransmitReasonSackHole] != packetCount {
			t.Fatalf("retransmissions=%d reasons=%v after the advancing acknowledgement, want %d on selective holes",
				packetCount, reasonCounts, wantPacketCount)
		}
		for segmentIndex := 1; segmentIndex < advancedIndex; segmentIndex += 1 {
			want := 2
			if segmentIndex == reportedIndex {
				// reported held, so never a hole
				want = 1
			}
			harness.requireSeenCount(segmentIndex, want)
		}
		harness.requireSeenCount(advancedIndex, 1)

		// the flow is unharmed: the source acknowledges the flight it had all
		// along and the ring empties
		harness.source.ackNow()
		synctest.Wait()
		harness.requireStream(payload)
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the acknowledgement: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
	})
}

// Hole selection stops at the highest selectively acknowledged byte: the
// segment that starts exactly there is past everything the acknowledgement
// reported and may be in flight, so it is not a hole. A source a round trip
// away reports what it held when the acknowledgement left, and the segments
// sent since are exactly the ones at and above that edge. Here the flight is
// delivered in one instant and its acknowledgements arrive one by one a round
// trip later, so the third duplicate reports the three segments the source
// held when it left while nine have been delivered: the segment at the edge
// of what it reported must not go again with the hole.
func TestTcpReturnRetransmitSackHolesStopAtTheHighestSelectiveByte(t *testing.T) {
	const segmentCount = 9
	const holeIndex = 1
	// the segment at the edge the third duplicate's blocks reach
	const edgeIndex = 5
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			sack:     true,
			ackDelay: tcpReturnTestStepRoundTrip,
			stepAcks: true,
		})
		harness.source.dropCounts[harness.segmentSeq(holeIndex)] = 1
		payload := harness.payload(segmentCount)
		harness.writeSegments(payload, 0, segmentCount)

		// the acknowledgement of the first segment and the three duplicates
		// the next three arrivals caused
		for step := 0; step < 1+returnRetransmitDupAckThreshold; step += 1 {
			if _, stepped := harness.stepOneAck(); !stepped {
				t.Fatalf("only %d acknowledgements were queued", step)
			}
		}
		harness.requireSeenCount(holeIndex, 2)
		harness.requireSeenCount(edgeIndex, 1)
		if _, _, packetCount, reasonCounts := harness.retransmitState(); packetCount != 1 {
			t.Fatalf("retransmissions=%d reasons=%v on the third duplicate, want the hole alone", packetCount, reasonCounts)
		}

		harness.stepAcks(4 * tcpReturnTestStepRoundTrip)
		harness.requireStream(payload)
		for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex += 1 {
			want := 1
			if segmentIndex == holeIndex {
				want = 2
			}
			harness.requireSeenCount(segmentIndex, want)
		}
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonSackHole] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v, want the hole once on its sack hole", packetCount, reasonCounts)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
			t.Fatalf("stats=%+v, want no timer expiry", stats)
		}
	})
}

// What one hole interval of partial-acknowledgement bursts costs, on the path
// every flow runs: no block, no negotiation, and a source that moves its
// cumulative acknowledgement a segment at a time so that every burst grows.
// The walk covers the run from the head of the ring, the head moves only as
// acknowledgements release segments, and a hole goes again at most once an
// interval, so an interval's bursts send again at most the segments its
// acknowledgements released and one run beyond them. That is the bound the
// selective walk needs a budget of its own to have (markSackHolesWithLock):
// there a block costs the source nothing and redraws the same retained set
// every interval, here each segment of it costs the source a cumulative
// acknowledgement, and what that acknowledgement releases never comes back.
func TestTcpReturnRetransmitPartialAckBurstsStayWithinTheSegmentsTheyRelease(t *testing.T) {
	// the flight of the crafted rows, and no sleeps anywhere below, so every
	// acknowledgement of a row falls in one hole interval
	const segmentCount = 600
	for _, row := range []struct {
		advanceCount    int
		wantPacketCount int64
	}{
		// two segments an acknowledgement while the run is doubling: the one
		// the acknowledgement uncovered and the one the run grew by
		{50, 101},
		{100, 201},
		// the run reaches the ceiling, and the bound is exactly the released
		// segments and one of them
		{299, 427},
		// and it never passes the retained set, whatever is released
		{500, 600},
	} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
			// nothing is acknowledged until the loop below, so the whole
			// flight is retained
			harness.source.holdAcks = true
			payload := harness.payload(segmentCount)
			harness.write(payload)
			synctest.Wait()
			for range returnRetransmitDupAckThreshold {
				harness.source.sendCraftedSackAck(harness.dataSeq, nil)
			}
			synctest.Wait()
			for segmentIndex := 1; segmentIndex <= row.advanceCount; segmentIndex += 1 {
				harness.source.sendCraftedSackAck(harness.segmentSeq(segmentIndex), nil)
				synctest.Wait()
			}

			_, retainedCount, packetCount, reasonCounts := harness.retransmitState()
			if bound := int64(row.advanceCount + returnRetransmitMaxBurstSegmentCount); bound < packetCount {
				t.Fatalf("%d acknowledgements drew %d retransmissions in one interval, want at most the %d they released and one burst",
					row.advanceCount, packetCount, bound)
			}
			if packetCount != row.wantPacketCount ||
				reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 ||
				reasonCounts[tcpReturnRetransmitReasonPartialAck] != row.wantPacketCount-1 {
				t.Fatalf("%d acknowledgements drew %d retransmissions %v, want %d on the hole and the bursts",
					row.advanceCount, packetCount, reasonCounts, row.wantPacketCount)
			}
			// what the bursts cost the source: each acknowledgement it sent
			// released a segment, and the ring never grows back
			if wantRetainedCount := segmentCount - row.advanceCount; retainedCount != wantRetainedCount {
				t.Fatalf("%d segments retained after %d acknowledgements, want %d released",
					retainedCount, row.advanceCount, wantRetainedCount)
			}
		})
	}
}

// Half a negotiation is none of one, in both directions, and this is what
// holds the selective path off a default build. The setting is off in
// production, and every ordinary source - Linux, macOS, Windows - offers
// sack-permitted in its SYN, so the first row is what the feature does today
// on every flow: the SYN-ACK must offer nothing back, the return path must not
// take the option, and the blocks such a source sends must draw the head
// alone. The second row is the source's half missing, where offering
// sack-permitted to a source that never asked for it would be the violation
// (RFC 2018 §2).
//
// The two are separate fields here for the same reason: with one field driving
// both halves, the whole of the settings half could be dropped from the
// sequence and no row could tell.
func TestTcpReturnRetransmitHalfANegotiationReadsNoBlock(t *testing.T) {
	// as many segments as the crafted rows, so an unbounded mark would be
	// plain
	const segmentCount = 300
	for _, half := range []struct {
		name    string
		options tcpReturnTestOptions
	}{
		{"the setting off and a source that offers sack-permitted", tcpReturnTestOptions{sourceOffersSack: true}},
		{"the setting on and a source that does not", tcpReturnTestOptions{settingsAllowSack: true}},
	} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			// the harness checks the SYN-ACK and the return path's own flag
			// against the whole negotiation, which neither half is
			harness := newTcpReturnRetransmitTestHarness(t, half.options)
			harness.source.holdAcks = true
			payload := harness.payload(segmentCount)
			harness.write(payload)
			synctest.Wait()

			// the same crafted acknowledgements the negotiated rows answer
			// with a burst of holes: one block over the newest retained
			// segment, which would mark every delivered segment below it
			crafted := []tcpSackBlock{{
				start: harness.segmentSeq(segmentCount - 1),
				end:   harness.segmentSeq(segmentCount),
			}}
			for range returnRetransmitDupAckThreshold {
				harness.source.sendCraftedSackAck(harness.dataSeq, crafted)
			}
			synctest.Wait()
			_, _, packetCount, reasonCounts := harness.retransmitState()
			if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 {
				t.Fatalf("%s: retransmissions=%d reasons=%v, want the head alone on its duplicate acknowledgements",
					half.name, packetCount, reasonCounts)
			}

			// and the flow is unharmed: the source acknowledges the flight it
			// had all along and the ring empties
			harness.source.ackNow()
			synctest.Wait()
			harness.requireStream(payload)
			if retainedByteCount, retainedCount, _, _ := harness.retransmitState(); retainedByteCount != 0 || retainedCount != 0 {
				t.Fatalf("%s: retained after the acknowledgement: %d bytes in %d segments", half.name, retainedByteCount, retainedCount)
			}
		})
	}
}

// Selective blocks are read only where the handshake negotiated
// sack-permitted, and nothing here negotiates it: the option parser reads the
// blocks, and every rule that would act on them is behind that gate, so a
// source that reports what it likes to a flow that never offered the option
// changes nothing at all. The same crafted acknowledgements that draw a
// burst of holes on the negotiated flow below draw the head alone here, which
// is what three duplicate acknowledgements mean without blocks, and the flow
// reaches the same place segment for segment as one whose acknowledgements
// carried no blocks.
func TestTcpReturnRetransmitSackBlocksWithoutTheNegotiationChangeNothing(t *testing.T) {
	// as many segments as the crafted rows below, so an unbounded mark would
	// be plain
	const segmentCount = 300
	var packetCounts [2]int64
	var reasonCounts [2][tcpReturnRetransmitReasonCount]int64
	for arm, blocks := range []bool{true, false} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
			// nothing is acknowledged, so the whole flight is retained
			harness.source.holdAcks = true
			payload := harness.payload(segmentCount)
			harness.write(payload)
			synctest.Wait()
			if _, retainedCount, _, _ := harness.retransmitState(); retainedCount != segmentCount {
				t.Fatalf("%d segments retained, want the whole flight of %d", retainedCount, segmentCount)
			}

			// three duplicates of the handshake's acknowledgement, each
			// claiming the newest segment alone where the arm sends blocks
			var crafted []tcpSackBlock
			if blocks {
				crafted = []tcpSackBlock{{
					start: harness.segmentSeq(segmentCount - 1),
					end:   harness.segmentSeq(segmentCount),
				}}
			}
			for range returnRetransmitDupAckThreshold {
				harness.source.sendCraftedSackAck(harness.dataSeq, crafted)
			}
			synctest.Wait()
			packetCounts[arm], reasonCounts[arm] = func() (int64, [tcpReturnRetransmitReasonCount]int64) {
				_, _, packetCount, reasons := harness.retransmitState()
				return packetCount, reasons
			}()
			if packetCounts[arm] != 1 || reasonCounts[arm][tcpReturnRetransmitReasonDupAck] != 1 {
				t.Fatalf("blocks=%t: retransmissions=%d reasons=%v, want the head alone on its duplicate acknowledgements",
					blocks, packetCounts[arm], reasonCounts[arm])
			}

			// the flow is unharmed either way: the source acknowledges the
			// flight it had all along and the ring empties
			harness.source.ackNow()
			synctest.Wait()
			harness.requireStream(payload)
			retainedByteCount, retainedCount, _, _ := harness.retransmitState()
			if retainedByteCount != 0 || retainedCount != 0 {
				t.Fatalf("blocks=%t: retained after the acknowledgement: %d bytes in %d segments", blocks, retainedByteCount, retainedCount)
			}
		})
	}
	if packetCounts[0] != packetCounts[1] || reasonCounts[0] != reasonCounts[1] {
		t.Fatalf("crafted blocks drew %d retransmissions %v, acknowledgements without blocks %d %v: the blocks changed the flow",
			packetCounts[0], reasonCounts[0], packetCounts[1], reasonCounts[1])
	}
}

// A source that negotiated sack-permitted still reports what it likes, and
// one acknowledgement's blocks mark at most a burst's worth of holes. The
// flow here negotiates the option and then sends blocks no out-of-order run
// of its own supports, which is the shape the bound has to hold for: the
// handshake decides whether blocks are read at all, and nothing after it can
// tell a crafted block from a true one. What must not follow
// is that one 40-byte acknowledgement, whose single block covers only the
// newest retained segment, marks every delivered segment below it as a hole:
// the worker then builds a window of packets in one hold of the sequence
// mutex, which the shared send shard's acknowledgement path waits on, and
// holds every one of them until the first is delivered. The ceiling is the
// one the partial-acknowledgement bursts keep, and what is left over waits
// for the next trigger.
func TestTcpReturnRetransmitCraftedSackBlocksMarkAtMostOneBurst(t *testing.T) {
	// more than twice the ceiling, so a run that is not bounded is plain
	const segmentCount = 300
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{sack: true})
		// nothing is acknowledged, so the whole flight is retained
		harness.source.holdAcks = true
		payload := harness.payload(segmentCount)
		harness.write(payload)
		synctest.Wait()
		if _, retainedCount, _, _ := harness.retransmitState(); retainedCount != segmentCount {
			t.Fatalf("%d segments retained, want the whole flight of %d", retainedCount, segmentCount)
		}

		// three duplicates of the handshake's acknowledgement, each claiming
		// the newest segment alone
		newest := tcpSackBlock{
			start: harness.segmentSeq(segmentCount - 1),
			end:   harness.segmentSeq(segmentCount),
		}
		for range returnRetransmitDupAckThreshold {
			harness.source.sendCraftedSackAck(harness.dataSeq, []tcpSackBlock{newest})
		}
		synctest.Wait()

		_, _, packetCount, reasonCounts := harness.retransmitState()
		t.Logf("one crafted acknowledgement drew %d packets, reasons=%v", packetCount, reasonCounts)
		if returnRetransmitMaxBurstSegmentCount < packetCount {
			t.Fatalf("retransmissions=%d reasons=%v on one acknowledgement, above the ceiling of %d", packetCount, reasonCounts, returnRetransmitMaxBurstSegmentCount)
		}
		if packetCount == 0 || reasonCounts[tcpReturnRetransmitReasonSackHole] != packetCount {
			t.Fatalf("retransmissions=%d reasons=%v, want the holes the blocks reported, up to the ceiling", packetCount, reasonCounts)
		}

		// the flow is unharmed: the source acknowledges the flight it had all
		// along and the ring empties
		harness.source.ackNow()
		synctest.Wait()
		harness.requireStream(payload)
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the acknowledgement: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
	})
}

// The ceiling above bounds one acknowledgement, and one acknowledgement is
// not what a hole interval costs. `markSackHolesWithLock` runs again for
// every acknowledgement whose blocks are new, any number of which can arrive
// inside one interval, and the segments the last run sent are skipped by the
// one-per-hole-interval rule rather than counted against the ceiling, so the
// walk goes on past them. A crafted source that moves its single 40-byte
// block down the flight therefore drew the whole retained set per interval,
// one burst per acknowledgement, which is the amplification the ceiling was
// added to stop: at the default cap that is a window of full-size segments
// per interval per flow, built and held by the worker, for a few dozen bytes
// of acknowledgement. The bound is carried over the hole interval instead:
// at most a burst's worth of holes are newly marked in one, whatever the
// acknowledgements report, which is the rate the partial-acknowledgement
// bursts already keep and the same period one hole waits between its own
// retransmissions.
func TestTcpReturnRetransmitCraftedSackBlocksMarkAtMostOneBurstARoundTrip(t *testing.T) {
	// more than twice the ceiling, so a run that is not bounded is plain
	const segmentCount = 300
	// blocks after the three that start the recovery, each new to the
	// applied set, and each of which drew its own burst
	const laterAckCount = 4
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{sack: true})
		// nothing is acknowledged, so the whole flight is retained
		harness.source.holdAcks = true
		payload := harness.payload(segmentCount)
		harness.write(payload)
		synctest.Wait()
		if _, retainedCount, _, _ := harness.retransmitState(); retainedCount != segmentCount {
			t.Fatalf("%d segments retained, want the whole flight of %d", retainedCount, segmentCount)
		}
		// one segment of the flight, as a block that claims it alone
		block := func(segmentIndex int) []tcpSackBlock {
			return []tcpSackBlock{{
				start: harness.segmentSeq(segmentIndex),
				end:   harness.segmentSeq(segmentIndex + 1),
			}}
		}

		// the three duplicates that start the recovery, claiming the newest
		// segment alone
		for range returnRetransmitDupAckThreshold {
			harness.source.sendCraftedSackAck(harness.dataSeq, block(segmentCount-1))
		}
		synctest.Wait()
		_, _, firstPacketCount, _ := harness.retransmitState()

		// and more inside the same hole interval, each claiming a segment
		// the applied blocks do not cover, so each is news
		for ackIndex := 1; ackIndex <= laterAckCount; ackIndex += 1 {
			harness.source.sendCraftedSackAck(harness.dataSeq, block(segmentCount-1-ackIndex))
			synctest.Wait()
		}
		_, _, packetCount, reasonCounts := harness.retransmitState()
		t.Logf("%d crafted acknowledgements in one hole interval drew %d packets, reasons=%v",
			returnRetransmitDupAckThreshold+laterAckCount, packetCount, reasonCounts)
		if firstPacketCount == 0 || reasonCounts[tcpReturnRetransmitReasonSackHole] != packetCount {
			t.Fatalf("retransmissions=%d reasons=%v, want the holes the blocks reported, up to the ceiling", packetCount, reasonCounts)
		}
		if returnRetransmitMaxBurstSegmentCount < packetCount {
			t.Fatalf("retransmissions=%d reasons=%v on %d acknowledgements inside one hole interval, above the ceiling of %d",
				packetCount, reasonCounts, returnRetransmitDupAckThreshold+laterAckCount, returnRetransmitMaxBurstSegmentCount)
		}

		// the bound is a rate, not a stop: the next interval carries the next
		// burst, so a source that really did report those holes recovers a
		// burst's worth of them per round trip
		time.Sleep(returnRetransmitMinRto)
		harness.source.sendCraftedSackAck(harness.dataSeq, block(segmentCount-2-laterAckCount))
		synctest.Wait()
		_, _, nextPacketCount, _ := harness.retransmitState()
		if nextPacketCount <= packetCount || 2*returnRetransmitMaxBurstSegmentCount < nextPacketCount {
			t.Fatalf("retransmissions=%d after the interval, want one more burst above the %d of the first", nextPacketCount, packetCount)
		}

		// the flow is unharmed: the source acknowledges the flight it had all
		// along and the ring empties
		harness.source.ackNow()
		synctest.Wait()
		harness.requireStream(payload)
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the acknowledgement: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
	})
}

// The interval's budget bounds what the blocks of one interval ask for, and a
// loss recovery that begins inside a spent interval is not one of those asks:
// it costs the source a cumulative acknowledgement, and it is the
// acknowledgements saying a new segment is missing. Its first hole therefore
// goes at once. Without that reserve the second recovery here was repaired
// not at all, not even at its head, because the head is left to the selective
// walk whenever anything is selectively acknowledged: the three duplicates
// were spent, no later trigger was owed, and the repair waited for the timer.
// What the reserve is not is the whole budget back, which would let a source
// that reports the next two heads end each recovery as spurious and start
// another for every segment it acknowledges.
func TestTcpReturnRetransmitANewRecoveryMarksItsFirstHoleInASpentInterval(t *testing.T) {
	// each flight is longer than the ceiling, so the first spends the whole
	// interval budget and the second has holes of its own to spare
	const flightSegmentCount = 200
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{sack: true})
		// nothing is acknowledged, so the whole flight is retained
		harness.source.holdAcks = true
		payload := harness.payload(2 * flightSegmentCount)
		flightByteCount := flightSegmentCount * harness.segmentByteCount
		harness.write(payload[:flightByteCount])
		synctest.Wait()
		// one segment of the flight, as a block that claims it alone
		block := func(segmentIndex int) []tcpSackBlock {
			return []tcpSackBlock{{
				start: harness.segmentSeq(segmentIndex),
				end:   harness.segmentSeq(segmentIndex + 1),
			}}
		}

		// a first recovery that spends the interval's whole budget
		for range returnRetransmitDupAckThreshold {
			harness.source.sendCraftedSackAck(harness.dataSeq, block(flightSegmentCount-1))
		}
		synctest.Wait()
		_, _, firstPacketCount, _ := harness.retransmitState()
		if firstPacketCount != returnRetransmitMaxBurstSegmentCount {
			t.Fatalf("the first recovery drew %d, want the interval's whole budget of %d",
				firstPacketCount, returnRetransmitMaxBurstSegmentCount)
		}

		// the source acknowledges everything, which ends that recovery and
		// empties the ring, and the origin sends a second flight: all inside
		// the same hole interval
		harness.source.ackNow()
		synctest.Wait()
		if _, retainedCount, _, _ := harness.retransmitState(); retainedCount != 0 {
			t.Fatalf("%d segments retained after the acknowledgement of the whole flight", retainedCount)
		}
		harness.source.holdAcks = true
		harness.write(payload[flightByteCount:])
		synctest.Wait()

		// a new loss episode, still inside that interval: its first hole is
		// the one the cumulative acknowledgement is stuck on
		for range returnRetransmitDupAckThreshold {
			harness.source.sendCraftedSackAck(harness.source.lastAckNumber, block(2*flightSegmentCount-1))
		}
		synctest.Wait()
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != firstPacketCount+1 || reasonCounts[tcpReturnRetransmitReasonSackHole] != packetCount {
			t.Fatalf("retransmissions=%d reasons=%v, want the new recovery's first hole above the %d of the first",
				packetCount, reasonCounts, firstPacketCount)
		}
		harness.requireSeenCount(flightSegmentCount, 2)

		// and the rest of its holes at the next interval, as a burst
		time.Sleep(returnRetransmitMinRto)
		harness.source.sendCraftedSackAck(harness.source.lastAckNumber, block(2*flightSegmentCount-2))
		synctest.Wait()
		_, _, nextPacketCount, _ := harness.retransmitState()
		if wantNextPacketCount := packetCount + returnRetransmitMaxBurstSegmentCount; nextPacketCount != wantNextPacketCount {
			t.Fatalf("retransmissions=%d after the interval, want the whole burst the new interval allows, %d, above the %d the reserve drew",
				nextPacketCount, wantNextPacketCount, packetCount)
		}

		// the flow is unharmed: the source acknowledges both flights and the
		// ring empties
		harness.source.ackNow()
		synctest.Wait()
		harness.requireStream(payload)
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the acknowledgement: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
	})
}

// The interval's budget counts the holes it marks, not the segments it walks
// past. A source reports holding a run and a segment far above it, so every
// hole between them lies past a burst's worth of segments the walk skips
// because they are marked, and a budget spent on those would mark nothing at
// all: recovery of a sparse loss would then wait for the cumulative
// acknowledgement to bring the holes within a burst of the head, one interval
// per burst of segments the source already has.
func TestTcpReturnRetransmitSackHolesPastWhatTheSourceHoldsAreStillMarked(t *testing.T) {
	// the holes start above a whole burst of reported segments
	const heldCount = returnRetransmitMaxBurstSegmentCount
	const segmentCount = 2*heldCount + 44
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{sack: true})
		// nothing is acknowledged, so the whole flight is retained
		harness.source.holdAcks = true
		payload := harness.payload(segmentCount)
		harness.write(payload)
		synctest.Wait()
		if _, retainedCount, _, _ := harness.retransmitState(); retainedCount != segmentCount {
			t.Fatalf("%d segments retained, want the whole flight of %d", retainedCount, segmentCount)
		}

		// the run from the head, and the newest segment alone, which puts
		// every hole above the run
		blocks := []tcpSackBlock{
			{start: harness.dataSeq, end: harness.segmentSeq(heldCount)},
			{start: harness.segmentSeq(segmentCount - 1), end: harness.segmentSeq(segmentCount)},
		}
		for range returnRetransmitDupAckThreshold {
			harness.source.sendCraftedSackAck(harness.dataSeq, blocks)
		}
		synctest.Wait()

		_, _, packetCount, reasonCounts := harness.retransmitState()
		t.Logf("%d holes above a reported run of %d drew %d packets, reasons=%v",
			segmentCount-heldCount-1, heldCount, packetCount, reasonCounts)
		if packetCount != returnRetransmitMaxBurstSegmentCount ||
			reasonCounts[tcpReturnRetransmitReasonSackHole] != packetCount {
			t.Fatalf("retransmissions=%d reasons=%v, want a burst of %d from the first hole above the run",
				packetCount, reasonCounts, returnRetransmitMaxBurstSegmentCount)
		}
		// from the first hole above the run, and nothing the source reported
		for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex += 1 {
			want := 1
			if heldCount <= segmentIndex && segmentIndex < heldCount+returnRetransmitMaxBurstSegmentCount {
				want = 2
			}
			harness.requireSeenCount(segmentIndex, want)
		}

		// the flow is unharmed: the source acknowledges the flight it had all
		// along and the ring empties
		harness.source.ackNow()
		synctest.Wait()
		harness.requireStream(payload)
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the acknowledgement: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
	})
}

// Two separated segments dropped, without SACK: the third duplicate
// acknowledgement fills the first hole, and the partial acknowledgement that
// answers it fills the second at once rather than waiting for three more
// duplicates that no new data would produce. The acknowledgements are held and
// sent by hand, in the order the source's arrivals cause them, because a
// source that answers inside the delivery callback can acknowledge the
// retransmission before the drain has marked the batch that carries the second
// hole, which a real path a round trip away cannot; that ordering left the
// second hole to the timer in about one run in a hundred.
func TestTcpReturnRetransmitPartialAckFillsTheNextHole(t *testing.T) {
	for _, initialSynSeq := range tcpReturnTestInitialSynSeqs(tcpReturnTestOptions{}, 1, 2, 3) {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq})
			harness.source.holdAcks = true
			harness.source.dropCounts[harness.segmentSeq(1)] = 1
			harness.source.dropCounts[harness.segmentSeq(3)] = 1

			payload := harness.payload(8)
			harness.write(payload)
			synctest.Wait()

			// the first segment, then the five that arrived out of order
			harness.source.sendAck(harness.segmentSeq(1))
			for range 5 {
				harness.source.sendDuplicateAck()
			}
			synctest.Wait()
			harness.requireSeenCount(1, 2)
			// the acknowledgement of the first hole's retransmission, which
			// stops at the second
			harness.source.sendAck(harness.segmentSeq(3))
			synctest.Wait()
			harness.source.ackNow()
			synctest.Wait()

			harness.requireStream(payload)
			harness.requireSeenCount(1, 2)
			harness.requireSeenCount(3, 2)
			_, _, packetCount, reasonCounts := harness.retransmitState()
			if packetCount != 2 ||
				reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 ||
				reasonCounts[tcpReturnRetransmitReasonPartialAck] != 1 {
				t.Fatalf("retransmissions=%d reasons=%v, want one on duplicate acks and one on the partial ack", packetCount, reasonCounts)
			}
		})
	}
}

// Pure acknowledgements that repeat the cumulative acknowledgement but open
// the window are window updates, which a receiver sends as its application
// reads, not duplicates (RFC 5681 §2): three of them with data outstanding
// retransmit nothing, and three true duplicates after them retransmit the
// head once. Counting the updates sent a segment the source already held.
func TestTcpReturnRetransmitWindowUpdatesAreNotDuplicateAcks(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		harness.source.holdAcks = true

		harness.write(harness.payload(2))
		synctest.Wait()

		for range 3 {
			harness.source.sendWindowUpdate(16)
		}
		synctest.Wait()
		if _, _, packetCount, reasonCounts := harness.retransmitState(); packetCount != 0 {
			t.Fatalf("retransmissions=%d reasons=%v after three window updates, want none", packetCount, reasonCounts)
		}
		harness.requireSeenCount(0, 1)

		for range 3 {
			harness.source.sendDuplicateAck()
		}
		synctest.Wait()
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v after three duplicates, want the head once", packetCount, reasonCounts)
		}
		harness.requireSeenCount(0, 2)
		harness.requireSeenCount(1, 1)
	})
}

// The window an acknowledgement carries while nothing is retained is still
// the window the next duplicate must repeat. Those acknowledgements take the
// idle early return, which records the window and nothing else: without the
// record the first duplicate of the next loss is compared with a window
// older than the update and reads as a window update of its own, so one of
// the three duplicates is spent and a three-duplicate loss waits a second for
// the timer.
func TestTcpReturnRetransmitWindowUpdateWhileIdleIsRecorded(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		// nothing is retained, so this takes the idle path
		harness.source.sendWindowUpdate(16)
		synctest.Wait()
		if _, retainedCount, _, _ := harness.retransmitState(); retainedCount != 0 {
			t.Fatalf("%d segments retained before the flight, want the idle path", retainedCount)
		}

		start := time.Now()
		// the head is lost, so exactly the three segments behind it answer,
		// each with a duplicate carrying the window the update left
		harness.source.dropCounts[harness.segmentSeq(0)] = 1
		payload := harness.payload(1 + returnRetransmitDupAckThreshold)
		harness.write(payload)
		synctest.Wait()

		harness.requireSeenCount(0, 2)
		if got := harness.requireDelivery(harness.segmentSeq(0), 1).at; !got.Equal(start) {
			t.Fatalf("the head was sent again at +%s, want at once on the third duplicate", got.Sub(start))
		}
		harness.requireStream(payload)
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v, want the head once on duplicate acks", packetCount, reasonCounts)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
			t.Fatalf("stats=%+v, want no timer expiry", stats)
		}
	})
}

// A data segment from the source repeats the cumulative acknowledgement when
// it has nothing new to report, and is news of the upload rather than
// evidence of a hole: a duplicate carries no payload (RFC 5681 §2). Three of
// them with a download in flight retransmit nothing, and three true
// duplicates after them still recover the head. Counting upload segments
// started a spurious recovery on every bidirectional flow, a request body
// under a streaming response as much as a websocket, and the partial
// acknowledgements of that recovery then sent bursts of data the source
// already held.
func TestTcpReturnRetransmitSourceDataIsNotADuplicateAck(t *testing.T) {
	const downloadSegmentCount = 4
	const uploadSegmentCount = 3
	const uploadSegmentByteCount = 64
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		// the download stays unacknowledged under the upload
		harness.source.holdAcks = true

		payload := harness.payload(downloadSegmentCount)
		harness.write(payload)
		synctest.Wait()

		upload := tcpReturnTestPayload(uploadSegmentCount, uploadSegmentByteCount)
		for segmentIndex := 0; segmentIndex < uploadSegmentCount; segmentIndex += 1 {
			harness.source.sendData(upload[segmentIndex*uploadSegmentByteCount : (segmentIndex+1)*uploadSegmentByteCount])
			synctest.Wait()
		}
		// the origin takes the upload, which is what those segments were
		received := make([]byte, len(upload))
		for readByteCount := 0; readByteCount < len(received); {
			n, err := harness.upstream.Read(received[readByteCount:])
			if err != nil {
				t.Fatalf("upstream read: %v", err)
			}
			readByteCount += n
		}
		synctest.Wait()
		if !bytes.Equal(received, upload) {
			t.Fatal("the origin did not receive the source's upload")
		}
		if _, _, packetCount, reasonCounts := harness.retransmitState(); packetCount != 0 {
			t.Fatalf("retransmissions=%d reasons=%v after %d upload segments, want none", packetCount, reasonCounts, uploadSegmentCount)
		}
		for segmentIndex := 0; segmentIndex < downloadSegmentCount; segmentIndex += 1 {
			harness.requireSeenCount(segmentIndex, 1)
		}

		for range returnRetransmitDupAckThreshold {
			harness.source.sendDuplicateAck()
		}
		synctest.Wait()
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v after three duplicates, want the head once", packetCount, reasonCounts)
		}
		harness.requireSeenCount(0, 2)
		harness.requireSeenCount(1, 1)
	})
}

// One hole waits a whole round trip between retransmissions, not the floor:
// on a path slower than the floor the duplicates of segments that left before
// the repair keep arriving for a round trip after it, and each carries a
// selective range the repair has not answered yet. With the interval fixed at
// the floor the hole goes again 200 ms after its repair, inside the round
// trip that would have acknowledged it, and every following duplicate costs
// another copy. The flow's round trip is 300 ms, the repair goes at +300 ms,
// and the last duplicate built before it arrives at +550 ms, 250 ms later.
func TestTcpReturnRetransmitHoleWaitsARoundTripNotTheFloor(t *testing.T) {
	const roundTrip = 300 * time.Millisecond
	const lateWriteAt = 250 * time.Millisecond
	const flightCount = 5
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			sack:     true,
			ackDelay: roundTrip,
		})
		harness.source.dropCounts[harness.segmentSeq(1)] = 1
		start := time.Now()
		payload := harness.payload(flightCount + 1)
		harness.writeSegments(payload, 0, flightCount)

		// one more segment, whose duplicate is built before the repair and
		// arrives a quarter round trip short of the interval
		time.Sleep(lateWriteAt)
		harness.writeSegments(payload, flightCount, 1)
		// the acknowledgements of the flight, the repair, and its own
		// acknowledgement a round trip later
		time.Sleep(3 * roundTrip)
		synctest.Wait()

		harness.requireStream(payload)
		harness.requireSeenCount(1, 2)
		if got := harness.requireDelivery(harness.segmentSeq(1), 1).at.Sub(start); got != roundTrip {
			t.Fatalf("the hole was repaired at +%s, want +%s on the third duplicate", got, roundTrip)
		}
		if rto, _ := harness.retransmitTimer(); rto < 2*roundTrip {
			t.Fatalf("timer %s, want the flow's round trip sampled so the interval is above the floor", rto)
		}
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonSackHole] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v, want the hole exactly once", packetCount, reasonCounts)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
			t.Fatalf("stats=%+v, want no timer expiry", stats)
		}
	})
}

// Sent means delivered: a segment still queued behind a stalled tunnel write
// has not reached the source, so it counts for nothing. With the first
// segments acknowledged inside their own delivery and the rest each holding
// the drain for longer than the timer, nothing is outstanding while the drain
// is stalled, no timer runs, and every segment reaches the source exactly
// once. A segment counted as sent before its delivery is sent again by the
// timer while its original waits, overtaking it. The wrapped row puts the
// segments acknowledged first numerically above the queued ones, which is
// where a plain comparison in the delivery marking counts the queued
// segments as sent. The IPv6 rows run the same stall because the marking
// reads each delivered packet's sequence from its own header, whose offset is
// the version's: read at the IPv4 offset an IPv6 packet yields its
// destination address, which by its value either marks every queued segment
// as sent, as the documentation range here does, or marks nothing ever.
func TestTcpReturnRetransmitNeverSendsAgainASegmentStillQueuedForDelivery(t *testing.T) {
	const segmentCount = 8
	const stalledIndex = 4
	// longer than the timer before a round-trip sample
	const stall = 2 * returnRetransmitInitialRto
	for _, ipVersion := range []int{4, 6} {
		for _, initialSynSeq := range tcpReturnTestInitialSynSeqs(tcpReturnTestOptions{ipVersion: ipVersion}, stalledIndex-1) {
			runTcpReturnRetransmitTest(t, func(t *testing.T) {
				t.Logf("IPv%d initial sequence %d", ipVersion, initialSynSeq)
				harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
					ipVersion:     ipVersion,
					initialSynSeq: initialSynSeq,
				})
				for segmentIndex := stalledIndex; segmentIndex < segmentCount; segmentIndex += 1 {
					harness.source.stallDurations[harness.segmentSeq(segmentIndex)] = stall
				}
				start := time.Now()
				payload := harness.payload(segmentCount)
				harness.write(payload)
				synctest.Wait()
				// every stall, and a timer's ceiling past them
				time.Sleep(time.Duration(segmentCount-stalledIndex)*stall + returnRetransmitMaxRto)
				synctest.Wait()

				harness.requireStream(payload)
				for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex += 1 {
					harness.requireSeenCount(segmentIndex, 1)
				}
				if got, want := harness.requireDelivery(harness.segmentSeq(segmentCount-1), 0).at.Sub(start), time.Duration(segmentCount-stalledIndex)*stall; got != want {
					t.Fatalf("IPv%d: last segment delivered at +%s, want +%s after every stall", ipVersion, got, want)
				}
				retainedByteCount, retainedCount, packetCount, reasonCounts := harness.retransmitState()
				if retainedByteCount != 0 || retainedCount != 0 {
					t.Fatalf("IPv%d: retained after full acknowledgement: %d bytes in %d segments", ipVersion, retainedByteCount, retainedCount)
				}
				if packetCount != 0 {
					t.Fatalf("IPv%d: retransmissions=%d reasons=%v with nothing lost, want none", ipVersion, packetCount, reasonCounts)
				}
				if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
					t.Fatalf("IPv%d: stats=%+v, want no timer expiry while nothing delivered was outstanding", ipVersion, stats)
				}
			})
		}
	}
}

// (c) A source that acknowledges nothing: the timer sends the first
// unacknowledged segment again at one second, doubling to the ceiling, and
// the no-progress bound ends the flow with a reset rather than leaving it
// idle. The schedule is exact in virtual time and derived from the constants.
func TestTcpReturnRetransmitTimesOutWithBackoffThenResets(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		harness.source.holdAcks = true
		start := time.Now()

		harness.write(harness.payload(2))
		synctest.Wait()

		harness.waitRunDone(defaultReturnRetransmitTimeout + time.Minute)

		wantOffsets := []time.Duration{0}
		rto := returnRetransmitInitialRto
		for at := rto; at < defaultReturnRetransmitTimeout; at += rto {
			wantOffsets = append(wantOffsets, at)
			rto = min(2*rto, returnRetransmitMaxRto)
		}
		times := harness.source.deliveryTimes(harness.segmentSeq(0))
		if len(times) != len(wantOffsets) {
			t.Fatalf("first segment delivered %d times, want %d", len(times), len(wantOffsets))
		}
		for index, at := range times {
			if got := at.Sub(start); got != wantOffsets[index] {
				t.Fatalf("delivery %d at +%s, want +%s", index, got, wantOffsets[index])
			}
		}
		// only the head is sent on the timer
		harness.requireSeenCount(1, 1)
		harness.source.stateLock.Lock()
		rstReceived, rstAt := harness.source.rstReceived, harness.source.rstAt
		harness.source.stateLock.Unlock()
		if !rstReceived {
			t.Fatal("no reset reached the source at the bound")
		}
		if got := rstAt.Sub(start); got != defaultReturnRetransmitTimeout {
			t.Fatalf("reset at +%s, want +%s", got, defaultReturnRetransmitTimeout)
		}
		wantTimeoutCount := int64(len(wantOffsets) - 1)
		if stats := harness.counters.snapshot(); stats.TimeoutCount != wantTimeoutCount || stats.AbandonCount != 1 || stats.PacketCount != wantTimeoutCount {
			t.Fatalf("stats=%+v, want %d timeouts and one abandon", stats, wantTimeoutCount)
		}
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the reset: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
	})
}

// The no-progress bound defaults to the provider's bound on a source that
// acknowledges none of its returns, and a source whose acknowledgements stop
// for just under it, as over a connectivity gap the provider waits out, keeps
// its flow: the acknowledgements resume, the stream completes, and nothing is
// reset. At 60 s the flow was reset halfway through the same gap.
func TestTcpReturnRetransmitSurvivesAnAcknowledgementGapTheProviderWaitsOut(t *testing.T) {
	abandonTimeout := DefaultRemoteUserNatProviderSettings().ReturnSendAbandonTimeout
	if got := DefaultTcpBufferSettings().ReturnRetransmitTimeout; got != abandonTimeout {
		t.Fatalf("no-progress bound %s, want the provider's return abandon bound %s", got, abandonTimeout)
	}
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		if harness.settings.ReturnRetransmitTimeout != abandonTimeout {
			t.Fatalf("harness bound %s, want the default %s", harness.settings.ReturnRetransmitTimeout, abandonTimeout)
		}
		harness.source.holdAcks = true
		payload := harness.payload(2)
		harness.write(payload)
		synctest.Wait()

		time.Sleep(abandonTimeout - time.Second)
		synctest.Wait()
		harness.source.ackNow()
		synctest.Wait()

		harness.requireStream(payload)
		harness.source.stateLock.Lock()
		rstReceived := harness.source.rstReceived
		harness.source.stateLock.Unlock()
		if rstReceived || harness.runIsDone() {
			t.Fatalf("the flow ended within the provider's abandon bound: rst=%t", rstReceived)
		}
		if stats := harness.counters.snapshot(); stats.AbandonCount != 0 || stats.TimeoutCount == 0 {
			t.Fatalf("stats=%+v, want the timer's retransmissions through the gap and no abandon", stats)
		}
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the acknowledgements resumed: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
	})
}

// The no-progress bound runs from the last acknowledgement progress, not from
// the first delivery: a source whose cumulative acknowledgement advances
// partway through a gap, with a segment still outstanding, keeps its flow past
// the bound measured from the first delivery, and is reset exactly one bound
// after that progress once nothing advances again. A clock that restarted only
// when a segment went out with nothing outstanding reset every download whose
// ring never emptied for the bound, however its acknowledgements advanced.
func TestTcpReturnRetransmitNoProgressBoundRunsFromTheLastAcknowledgementProgress(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		harness.source.holdAcks = true
		start := time.Now()
		harness.write(harness.payload(2))
		synctest.Wait()

		// progress inside the bound, with the second segment still outstanding
		const progressAfter = defaultReturnRetransmitTimeout * 5 / 6
		time.Sleep(progressAfter)
		harness.source.sendAck(harness.segmentSeq(1))
		synctest.Wait()

		// past the bound from the first delivery, inside it from the progress
		time.Sleep(defaultReturnRetransmitTimeout - progressAfter + time.Second)
		synctest.Wait()
		harness.source.stateLock.Lock()
		rstReceived := harness.source.rstReceived
		harness.source.stateLock.Unlock()
		if rstReceived || harness.runIsDone() {
			t.Fatalf("flow reset at +%s with acknowledgement progress at +%s: rst=%t", time.Since(start), progressAfter, rstReceived)
		}
		if _, retainedCount, _, _ := harness.retransmitState(); retainedCount != 1 {
			t.Fatalf("%d segments retained, want the second still outstanding", retainedCount)
		}

		harness.waitRunDone(defaultReturnRetransmitTimeout)
		harness.source.stateLock.Lock()
		rstReceived, rstAt := harness.source.rstReceived, harness.source.rstAt
		harness.source.stateLock.Unlock()
		if !rstReceived {
			t.Fatal("no reset reached the source one bound after the last progress")
		}
		if got, want := rstAt.Sub(start), progressAfter+defaultReturnRetransmitTimeout; got != want {
			t.Fatalf("reset at +%s, want +%s, one bound after the progress", got, want)
		}
		if stats := harness.counters.snapshot(); stats.AbandonCount != 1 {
			t.Fatalf("stats=%+v, want one abandon", stats)
		}
	})
}

// The deadline of the timer, read under the sequence mutex, from now.
func (self *tcpReturnRetransmitTestHarness) retransmitDeadline() time.Duration {
	self.sequence.mutex.Lock()
	defer self.sequence.mutex.Unlock()
	return time.Duration(self.sequence.returnRetransmit.rtoDeadlineNanos - monotonicNanos())
}

// Requires the second delivery of the segment at `segmentIndex`, the timer's
// retransmission, at exactly `want`.
func (self *tcpReturnRetransmitTestHarness) requireTimerRetransmissionAt(segmentIndex int, want time.Time) {
	self.t.Helper()
	if got := self.requireDelivery(self.segmentSeq(segmentIndex), 1).at; !got.Equal(want) {
		self.t.Fatalf("segment %d sent again by the timer %s after its deadline", segmentIndex, got.Sub(want))
	}
	if _, _, _, reasonCounts := self.retransmitState(); reasonCounts[tcpReturnRetransmitReasonTimeout] == 0 {
		self.t.Fatalf("reasons=%v, want the timer", reasonCounts)
	}
}

// The first round-trip sample brings the timer's deadline in from the initial
// second to the sampled timer, and a lost tail that only the timer repairs is
// sent again at that deadline. The worker computed its wait from the initial
// second and was never woken by the acknowledgement, so it slept out the
// second and sent the tail 600 ms late.
func TestTcpReturnRetransmitTimerExpiresAtTheDeadlineTheFirstSampleBringsIn(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		const segmentCount = 8
		const roundTrip = 100 * time.Millisecond
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		harness.source.holdAcks = true
		// the tail, with nothing after it to draw a duplicate
		harness.source.dropCounts[harness.segmentSeq(segmentCount-2)] = 1
		harness.source.dropCounts[harness.segmentSeq(segmentCount-1)] = 1
		harness.write(harness.payload(segmentCount))
		synctest.Wait()

		time.Sleep(roundTrip)
		harness.source.sendAck(harness.segmentSeq(segmentCount - 2))
		synctest.Wait()
		// one sample of 100 ms: max(200 ms, 2 x 100 ms, 100 ms + 4 x 50 ms)
		rto, baseRto := harness.retransmitTimer()
		if rto != 3*roundTrip || baseRto != rto {
			t.Fatalf("timer %s base %s after the first sample, want %s", rto, baseRto, 3*roundTrip)
		}
		deadline := time.Now().Add(harness.retransmitDeadline())
		if want := time.Now().Add(rto); !deadline.Equal(want) {
			t.Fatalf("deadline %s after the acknowledgement, want %s", time.Until(deadline), rto)
		}

		time.Sleep(returnRetransmitMaxRto)
		synctest.Wait()
		harness.requireTimerRetransmissionAt(segmentCount-2, deadline)
	})
}

// Acknowledgement progress drops a backed-off timer to its base, and a lost
// tail that only the timer repairs is sent again at that base. A stall backs
// the timer off to 4.8 s; the late acknowledgements of the stalled flight and
// of a new one decide its probe spurious and sample a round trip, and the new
// flight's last segments are lost. The worker was sleeping out the 4.8 s wait
// it computed at the last expiry, and sent the tail more than four seconds
// late.
func TestTcpReturnRetransmitTimerExpiresAtTheBaseAfterProgressDropsItsBackoff(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		const flightCount = 8
		const roundTrip = 100 * time.Millisecond
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		harness.source.holdAcks = true
		payload := harness.payload(3 * flightCount)
		harness.write(payload[:flightCount*harness.segmentByteCount])
		synctest.Wait()
		time.Sleep(roundTrip)
		harness.source.sendAck(harness.segmentSeq(flightCount))
		synctest.Wait()

		// the second flight stalls through four expiries
		harness.write(payload[flightCount*harness.segmentByteCount : 2*flightCount*harness.segmentByteCount])
		synctest.Wait()
		time.Sleep((1+2+4+8)*3*roundTrip + roundTrip)
		synctest.Wait()
		if rto, baseRto := harness.retransmitTimer(); rto != 16*baseRto {
			t.Fatalf("timer %s base %s after four expiries, want 16 times the base", rto, baseRto)
		}

		// the third flight, whose tail is lost
		for segmentIndex := 3*flightCount - 3; segmentIndex < 3*flightCount; segmentIndex += 1 {
			harness.source.dropCounts[harness.segmentSeq(segmentIndex)] = 1
		}
		harness.write(payload[2*flightCount*harness.segmentByteCount:])
		synctest.Wait()
		time.Sleep(roundTrip / 2)
		harness.source.sendAck(harness.segmentSeq(3*flightCount - 3))
		synctest.Wait()
		rto, baseRto := harness.retransmitTimer()
		if rto != baseRto || returnRetransmitInitialRto <= rto {
			t.Fatalf("timer %s base %s after the progress, want the base", rto, baseRto)
		}
		deadline := time.Now().Add(harness.retransmitDeadline())

		time.Sleep(2 * returnRetransmitMaxRto)
		synctest.Wait()
		harness.requireTimerRetransmissionAt(3*flightCount-3, deadline)
		if _, _, _, reasonCounts := harness.retransmitState(); reasonCounts[tcpReturnRetransmitReasonPartialAck] != 0 {
			t.Fatalf("reasons=%v, want the stalled flight's probe decided spurious, with no loss recovery", reasonCounts)
		}
	})
}

// The timer and the no-progress clock are armed by a delivery with nothing
// outstanding, and the deliveries behind it leave both alone. An upstream
// that keeps producing while the source acknowledges nothing does not hold
// the head's expiry off: the head goes again one timer after its own
// delivery, however much followed it, and the bound still runs from there. A
// clock re-armed by every delivery left the head unrepaired for as long as
// the upstream trickled, and pushed the bound back with it.
func TestTcpReturnRetransmitLaterDeliveriesLeaveTheHeadsTimerAlone(t *testing.T) {
	const trickleCount = 8
	// so the trickle outlasts the timer before a round-trip sample
	const trickleInterval = returnRetransmitInitialRto / 4
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		harness.source.holdAcks = true
		start := time.Now()
		payload := harness.payload(trickleCount)
		for segmentIndex := 0; segmentIndex < trickleCount; segmentIndex += 1 {
			harness.writeSegments(payload, segmentIndex, 1)
			time.Sleep(trickleInterval)
		}
		synctest.Wait()

		// one initial timer after the head's own delivery, in the middle of
		// the trickle
		harness.requireTimerRetransmissionAt(0, start.Add(returnRetransmitInitialRto))
		harness.requireSeenCount(1, 1)

		// and the bound runs from that delivery too, not from the last one
		harness.waitRunDone(defaultReturnRetransmitTimeout)
		harness.source.stateLock.Lock()
		rstReceived, rstAt := harness.source.rstReceived, harness.source.rstAt
		harness.source.stateLock.Unlock()
		if !rstReceived {
			t.Fatal("no reset reached the source at the bound")
		}
		if got := rstAt.Sub(start); got != defaultReturnRetransmitTimeout {
			t.Fatalf("reset at +%s, want +%s, one bound after the first delivery", got, defaultReturnRetransmitTimeout)
		}
		if stats := harness.counters.snapshot(); stats.AbandonCount != 1 {
			t.Fatalf("stats=%+v, want one abandon", stats)
		}
	})
}

// The timer's smoothing and its floor in exact values (RFC 6298 §2.3): a
// 100 ms sample leaves srtt 100 ms and rttvar 50 ms, and a 200 ms one after
// it leaves srtt 112.5 ms and rttvar 62.5 ms, so the timer is
// srtt + 4 rttvar = 362.5 ms; a path far below the floor keeps the floor
// itself, which is TCP's own minimum and what stops a fast path from sending
// a hole again on every acknowledgement. Only the first sample of a flow was
// pinned anywhere, so the smoothing constants and the floor's value were
// free. Each sample is shorter than the timer standing when it is taken, so
// no expiry falls in the same instant as the acknowledgement that carries
// it.
func TestTcpReturnRetransmitTimerSmoothsItsSamplesAboveTheFloor(t *testing.T) {
	for _, c := range []struct {
		name     string
		samples  []time.Duration
		wantBase time.Duration
	}{
		{
			name:     "a hundred then two hundred",
			samples:  []time.Duration{100 * time.Millisecond, 200 * time.Millisecond},
			wantBase: 362500 * time.Microsecond,
		},
		{
			// the floor's own value, not the constant, which a test that
			// read it could not pin
			name:     "a path below the floor",
			samples:  []time.Duration{20 * time.Millisecond, 20 * time.Millisecond},
			wantBase: 200 * time.Millisecond,
		},
	} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("%s", c.name)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
			// each segment is acknowledged by hand its own sample later
			harness.source.holdAcks = true
			payload := harness.payload(len(c.samples))
			for index, sample := range c.samples {
				harness.writeSegments(payload, index, 1)
				time.Sleep(sample)
				harness.source.sendAck(harness.segmentSeq(index + 1))
				synctest.Wait()
			}

			harness.requireStream(payload)
			rto, baseRto := harness.retransmitTimer()
			if baseRto != c.wantBase || rto != baseRto {
				t.Fatalf("%s: timer %s base %s after samples %v, want %s", c.name, rto, baseRto, c.samples, c.wantBase)
			}
		})
	}
}

// An acknowledgement that covers a retransmitted segment measures the repair,
// not the path, so it samples no round trip at all (RFC 6298 §3, and Linux's
// FLAG_RETRANS_DATA_ACKED). The retransmission's own acknowledgement does not
// say which copy it answers, which is Karn's rule, and the segments behind it
// are no better: their acknowledgement was held back by the hole in front of
// them, so the time from their delivery is the hole's repair time. Here a
// 50 ms flow loses its head, the timer repairs it a second later, and the
// acknowledgement that follows covers the repair and the segment that waited
// behind it. Sampled, that one acknowledgement set srtt to 1.05 s and the
// timer to 3.15 s, and the timer was still seconds wide after the next
// exchanges: every later tail loss on the flow waited that long.
func TestTcpReturnRetransmitTakesNoRoundTripSampleAcrossARepairedHole(t *testing.T) {
	const roundTrip = 50 * time.Millisecond
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{ackDelay: roundTrip})
		// the head is lost with one segment behind it, too few duplicates to
		// repair it, so the timer does
		harness.source.dropCounts[harness.segmentSeq(0)] = 1
		payload := harness.payload(4)
		harness.writeSegments(payload, 0, 2)

		time.Sleep(returnRetransmitInitialRto + roundTrip)
		synctest.Wait()
		harness.requireSeenCount(0, 2)
		if rto, baseRto := harness.retransmitTimer(); baseRto != returnRetransmitInitialRto || rto != baseRto {
			t.Fatalf("timer %s base %s after the repair was acknowledged, want the initial %s, from no sample at all", rto, baseRto, returnRetransmitInitialRto)
		}

		// the first acknowledgement that measures the path alone
		harness.writeSegments(payload, 2, 2)
		time.Sleep(roundTrip)
		synctest.Wait()
		harness.requireStream(payload)
		rto, baseRto := harness.retransmitTimer()
		// the floor, and not a rule read from the round trip: two 50 ms
		// samples give srtt 50 ms and rttvar 18.75 ms, so both 2 x srtt and
		// srtt + 4 rttvar are below it. The floor's own value, not the
		// constant, which a test that read it could not pin
		if want := 200 * time.Millisecond; baseRto != want || rto != baseRto {
			t.Fatalf("timer %s base %s after two %s samples, want %s, the floor on a path this fast", rto, baseRto, roundTrip, want)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 1 {
			t.Fatalf("stats=%+v, want the one expiry that repaired the head", stats)
		}
	})
}

// A source that received every segment but whose acknowledgements a stall
// held past the timer, and then arrive late: the expiry sends the head once
// and nothing else follows, whether the late acknowledgements come one per
// segment, so that the first covers exactly the retransmitted head and the
// second decides, or one per two segments, so that the first already passes
// it. Until the probe decides the timer keeps its backoff; once it does the
// timer is back at its base, the value the expiry doubled. Before the probe
// the expiry began loss recovery and every late acknowledgement read as a
// partial one: eight segments cost the timeout and seven more retransmissions
// one per segment, or three more two per segment.
func TestTcpReturnRetransmitSpuriousTimeoutSendsOnlyTheHead(t *testing.T) {
	const segmentCount = 8
	// segments covered by each late acknowledgement
	for _, stride := range []int{1, 2} {
		for _, initialSynSeq := range tcpReturnTestInitialSynSeqs(tcpReturnTestOptions{}, 1, 4) {
			runTcpReturnRetransmitTest(t, func(t *testing.T) {
				t.Logf("stride %d initial sequence %d", stride, initialSynSeq)
				harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq})
				harness.source.holdAcks = true
				start := time.Now()
				payload := harness.payload(segmentCount)
				harness.write(payload)
				synctest.Wait()

				time.Sleep(returnRetransmitInitialRto)
				synctest.Wait()
				// no round trip was sampled, so the expiry doubled the initial timer
				backedOffRto := 2 * returnRetransmitInitialRto
				if rto, _ := harness.retransmitTimer(); rto != backedOffRto {
					t.Fatalf("stride %d: timer %s after the expiry, want %s", stride, rto, backedOffRto)
				}
				harness.requireSeenCount(0, 2)

				requireOnlyTheHead := func(when string) {
					t.Helper()
					if _, _, packetCount, reasonCounts := harness.retransmitState(); packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonTimeout] != 1 {
						t.Fatalf("stride %d: retransmissions=%d reasons=%v %s, want the head once on the timer", stride, packetCount, reasonCounts, when)
					}
				}

				harness.source.sendAck(harness.segmentSeq(stride))
				synctest.Wait()
				requireOnlyTheHead("after the first late acknowledgement")
				rto, baseRto := harness.retransmitTimer()
				if stride == 1 && rto != backedOffRto {
					t.Fatalf("stride 1: timer %s with the probe undecided, want the backoff kept at %s", rto, backedOffRto)
				}
				if stride == 2 && rto != baseRto {
					t.Fatalf("stride 2: timer %s after the spurious expiry, want the base %s", rto, baseRto)
				}

				harness.source.sendAck(harness.segmentSeq(2 * stride))
				synctest.Wait()
				requireOnlyTheHead("after the second late acknowledgement")
				if rto, baseRto := harness.retransmitTimer(); rto != baseRto {
					t.Fatalf("stride %d: timer %s after the spurious expiry, want the base %s", stride, rto, baseRto)
				}

				for segmentIndex := 3 * stride; segmentIndex <= segmentCount; segmentIndex += stride {
					// the worker runs between acknowledgements, as it does
					// between arrivals; back to back, a later acknowledgement
					// would release what an earlier one marked before it went
					harness.source.sendAck(harness.segmentSeq(segmentIndex))
					synctest.Wait()
				}
				// every later timer and the bound would have fired by now
				time.Sleep(defaultReturnRetransmitTimeout)
				synctest.Wait()

				harness.requireStream(payload)
				requireOnlyTheHead("after every acknowledgement")
				for segmentIndex := 1; segmentIndex < segmentCount; segmentIndex += 1 {
					harness.requireSeenCount(segmentIndex, 1)
				}
				if got := harness.requireDelivery(harness.segmentSeq(0), 1).at.Sub(start); got != returnRetransmitInitialRto {
					t.Fatalf("stride %d: head retransmitted at +%s, want +%s", stride, got, returnRetransmitInitialRto)
				}
				if stats := harness.counters.snapshot(); stats.TimeoutCount != 1 || stats.AbandonCount != 0 {
					t.Fatalf("stride %d: stats=%+v, want one timeout and no abandon", stride, stats)
				}
				retainedByteCount, retainedCount, _, _ := harness.retransmitState()
				if retainedByteCount != 0 || retainedCount != 0 {
					t.Fatalf("stride %d: retained after full acknowledgement: %d bytes in %d segments", stride, retainedByteCount, retainedCount)
				}
			})
		}
	}
}

// A real expiry: the source's kernel dropped the whole flight, so the timer's
// head is the first segment it gets and its acknowledgement covers exactly
// that head. A segment sent after it arrives out of order and draws a
// duplicate, which shows the probe the loss is real: the remaining holes go
// on that duplicate and the partial acknowledgements that follow, at once,
// with no second expiry and each hole sent again exactly once.
func TestTcpReturnRetransmitRealTimeoutRecoversOnTheDuplicateAck(t *testing.T) {
	for _, initialSynSeq := range tcpReturnTestInitialSynSeqs(tcpReturnTestOptions{}, 1, 3) {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			const flightCount = 4
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq})
			for segmentIndex := 0; segmentIndex < flightCount; segmentIndex += 1 {
				harness.source.dropCounts[harness.segmentSeq(segmentIndex)] = 1
			}
			start := time.Now()
			payload := harness.payload(flightCount)
			harness.write(payload)
			synctest.Wait()

			time.Sleep(returnRetransmitInitialRto)
			synctest.Wait()
			harness.requireSeenCount(0, 2)
			harness.requireSeenCount(1, 1)

			later := tcpReturnTestPayload(1, harness.segmentByteCount)
			later[0] ^= 0xff
			harness.write(later)
			synctest.Wait()

			harness.requireStream(append(append([]byte(nil), payload...), later...))
			for segmentIndex := 0; segmentIndex < flightCount; segmentIndex += 1 {
				harness.requireSeenCount(segmentIndex, 2)
				if got := harness.requireDelivery(harness.segmentSeq(segmentIndex), 1).at.Sub(start); got != returnRetransmitInitialRto {
					t.Fatalf("segment %d retransmitted at +%s, want at the one expiry +%s", segmentIndex, got, returnRetransmitInitialRto)
				}
			}
			harness.requireSeenCount(flightCount, 1)
			_, _, packetCount, reasonCounts := harness.retransmitState()
			if packetCount != flightCount ||
				reasonCounts[tcpReturnRetransmitReasonTimeout] != 1 ||
				reasonCounts[tcpReturnRetransmitReasonPartialAck] != flightCount-1 {
				t.Fatalf("retransmissions=%d reasons=%v, want the head on the timer and the rest on partial acknowledgements", packetCount, reasonCounts)
			}
			if stats := harness.counters.snapshot(); stats.TimeoutCount != 1 {
				t.Fatalf("stats=%+v, want one timeout", stats)
			}
		})
	}
}

// A duplicate acknowledgement while a timer probe is still undecided shows
// the expiry was real (RFC 5682 §2.1 step 2a), so the probe becomes loss
// recovery there and then: the acknowledgement that follows reads as the
// partial one it is and fills the next hole at once. A probe left undecided
// by the duplicate reads that same acknowledgement as an advance past the
// head it sent again, calls the expiry spurious, and leaves the next hole to
// another expiry a second or more away. Two segments are lost, so the
// acknowledgement after the probe's own repair stops at the second, with no
// duplicate of its own left to come: exactly the shape whose only evidence
// is the duplicate the probe already saw.
func TestTcpReturnRetransmitDuplicateDuringAnUndecidedProbeIsLoss(t *testing.T) {
	// long enough after the expiry that the acknowledgement can be the
	// retransmission's own answer (see retransmissionExplainsWithLock)
	const ackAfterExpiry = 3 * returnRetransmitInitialRto / 2
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		harness.source.holdAcks = true
		harness.source.dropCounts[harness.segmentSeq(0)] = 1
		harness.source.dropCounts[harness.segmentSeq(2)] = 1
		start := time.Now()
		payload := harness.payload(4)
		harness.write(payload)
		synctest.Wait()

		// nothing has been acknowledged, so the expiry probes with the head
		time.Sleep(returnRetransmitInitialRto)
		synctest.Wait()
		harness.requireSeenCount(0, 2)
		harness.requireSeenCount(2, 1)

		// the probe's head arrived, but the source is still missing the
		// third segment and says so with a duplicate before its own
		// acknowledgement of the head
		time.Sleep(ackAfterExpiry)
		harness.source.sendDuplicateAck()
		synctest.Wait()
		harness.source.sendAck(harness.segmentSeq(2))
		synctest.Wait()

		at := time.Now()
		harness.requireSeenCount(2, 2)
		if got := harness.requireDelivery(harness.segmentSeq(2), 1).at; !got.Equal(at) {
			t.Fatalf("the second hole went again %s after the partial acknowledgement, want at once", got.Sub(at))
		}
		harness.source.ackNow()
		synctest.Wait()
		harness.requireStream(payload)
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 2 ||
			reasonCounts[tcpReturnRetransmitReasonTimeout] != 1 ||
			reasonCounts[tcpReturnRetransmitReasonPartialAck] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v, want the head on the timer and the second hole on the partial acknowledgement", packetCount, reasonCounts)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 1 {
			t.Fatalf("stats=%+v, want one timer expiry, at +%s", stats, time.Since(start))
		}
	})
}

// The recovery point is the highest delivered segment, and the drain marks a
// batch only when its callback returns, so a second hole inside the batch that
// was being delivered when recovery began lay past the point. The
// acknowledgement of the first hole's retransmission then stopped at the
// second hole, read as a full recovery, and the hole waited for the timer:
// the duplicates that would have shown it had already arrived, during the
// recovery. Here the drain is held inside the batch that carries the second
// hole while the first hole's duplicates arrive, and the batch is marked
// before the acknowledgement of the retransmission comes back, as a real path
// a round trip away always does.
func TestTcpReturnRetransmitRecoveryCoversTheBatchItBeganInside(t *testing.T) {
	const segmentCount = 7
	const firstHoleIndex = 1
	const secondHoleIndex = 4
	const stalledIndex = 6
	const stall = 20 * time.Millisecond
	const roundTrip = 10 * time.Millisecond
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			configure: func(settings *TcpBufferSettings) {
				// the whole read goes as one batch
				settings.WriteBatchSize = 16
			},
		})
		harness.source.holdAcks = true
		harness.source.dropCounts[harness.segmentSeq(firstHoleIndex)] = 1
		harness.source.dropCounts[harness.segmentSeq(secondHoleIndex)] = 1
		payload := harness.payload(segmentCount)
		written := harness.writeSegments(payload, 0, secondHoleIndex-1)
		// the drain is held by the last segment's write, so the batch that
		// carries the second hole is delivered and not yet marked
		harness.source.stateLock.Lock()
		harness.source.stallDurations[harness.segmentSeq(stalledIndex)] = stall
		harness.source.stateLock.Unlock()
		harness.writeSegments(payload, written, segmentCount-written)

		// the acknowledgements the arrivals before the stall caused
		time.Sleep(roundTrip)
		harness.source.sendAck(harness.segmentSeq(firstHoleIndex))
		for range returnRetransmitDupAckThreshold {
			harness.source.sendDuplicateAck()
		}
		synctest.Wait()
		harness.requireSeenCount(firstHoleIndex, 2)

		// the stall ends, the batch is marked, and the acknowledgement of the
		// retransmission comes back and stops at the second hole
		time.Sleep(stall)
		synctest.Wait()
		harness.source.sendAck(harness.segmentSeq(secondHoleIndex))
		synctest.Wait()

		harness.requireSeenCount(secondHoleIndex, 2)
		harness.source.ackNow()
		synctest.Wait()
		harness.requireStream(payload)
		for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex += 1 {
			want := 1
			if segmentIndex == firstHoleIndex || segmentIndex == secondHoleIndex {
				want = 2
			}
			harness.requireSeenCount(segmentIndex, want)
		}
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 2 ||
			reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 ||
			reasonCounts[tcpReturnRetransmitReasonPartialAck] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v, want the first hole on duplicates and the second on the partial acknowledgement", packetCount, reasonCounts)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
			t.Fatalf("stats=%+v, want no timer expiry", stats)
		}
	})
}

// A recovery ends on the acknowledgement that reaches its point exactly, not
// one byte past it. The point is the end of the highest segment delivered
// when the recovery began, and the acknowledgement of the repair reaches
// exactly that end whenever the loss was the head of the flight, which is the
// common shape. A recovery left standing on it costs twice: the same
// acknowledgement reads as a partial one and its burst sends a segment the
// source holds, and the next episode's own partial acknowledgement, being
// past the stale point, reads as a full recovery, so its second hole waits
// for the timer with its duplicates already spent. Here the flight's head is
// lost, a later flight is delivered inside the recovery so the ring is not
// emptied by the boundary acknowledgement, and that flight loses two segments
// of its own.
func TestTcpReturnRetransmitRecoveryEndsOnAnAcknowledgementThatReachesItsPoint(t *testing.T) {
	// the hand-driven path delay: long enough that an acknowledgement can be
	// the answer to a retransmission a step before it
	const step = 100 * time.Millisecond
	const firstCount = 4
	const secondCount = 6
	// the second flight loses its own first segment, so the boundary
	// acknowledgement is also the source's frontier and nothing advances past
	// the point before the new episode's duplicates
	const firstHoleIndex = firstCount
	const secondHoleIndex = firstCount + 2
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		harness.source.holdAcks = true
		harness.source.dropCounts[harness.segmentSeq(0)] = 1
		payload := harness.payload(firstCount + secondCount)
		harness.writeSegments(payload, 0, firstCount)

		// the head of the flight is lost and the three segments behind it
		// draw the duplicates that repair it; the recovery's point is the end
		// of the flight
		time.Sleep(step)
		for range returnRetransmitDupAckThreshold {
			harness.source.sendDuplicateAck()
		}
		synctest.Wait()
		harness.requireSeenCount(0, 2)

		// a second flight, delivered inside the recovery, so it lies past the
		// point and holds the ring open past the boundary acknowledgement
		time.Sleep(step)
		harness.source.dropCounts[harness.segmentSeq(firstHoleIndex)] = 1
		harness.source.dropCounts[harness.segmentSeq(secondHoleIndex)] = 1
		harness.writeSegments(payload, firstCount, secondCount)

		// exactly the recovery's point, with the second flight outstanding
		time.Sleep(step)
		harness.source.sendAck(harness.segmentSeq(firstCount))
		synctest.Wait()
		harness.requireSeenCount(firstCount, 1)

		// the second flight's own loss: its first hole on the duplicates, its
		// second on the partial acknowledgement that follows
		time.Sleep(step)
		for range returnRetransmitDupAckThreshold {
			harness.source.sendDuplicateAck()
		}
		synctest.Wait()
		harness.requireSeenCount(firstHoleIndex, 2)

		time.Sleep(2 * step)
		harness.source.sendAck(harness.segmentSeq(secondHoleIndex))
		synctest.Wait()
		at := time.Now()
		harness.requireSeenCount(secondHoleIndex, 2)
		if got := harness.requireDelivery(harness.segmentSeq(secondHoleIndex), 1).at; !got.Equal(at) {
			t.Fatalf("the second hole went again %s after the partial acknowledgement, want at once", got.Sub(at))
		}

		harness.source.ackNow()
		synctest.Wait()
		harness.requireStream(payload)
		for segmentIndex := 1; segmentIndex < firstCount+secondCount; segmentIndex += 1 {
			want := 1
			if segmentIndex == firstHoleIndex || segmentIndex == secondHoleIndex {
				want = 2
			}
			harness.requireSeenCount(segmentIndex, want)
		}
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 3 ||
			reasonCounts[tcpReturnRetransmitReasonDupAck] != 2 ||
			reasonCounts[tcpReturnRetransmitReasonPartialAck] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v, want two heads on duplicates and one hole on the partial acknowledgement", packetCount, reasonCounts)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
			t.Fatalf("stats=%+v, want no timer expiry", stats)
		}
	})
}

// The round trip of the tests that step the source's acknowledgements through
// a download.
const tcpReturnTestStepRoundTrip = 50 * time.Millisecond

// Writes `segmentCount` segments of `payload` from where `written` stands, and
// returns the new position.
func (self *tcpReturnRetransmitTestHarness) writeSegments(payload []byte, written int, segmentCount int) int {
	self.t.Helper()
	self.write(payload[written*self.segmentByteCount : (written+segmentCount)*self.segmentByteCount])
	synctest.Wait()
	return written + segmentCount
}

// Segments the source was handed more than once, counted apart from the ones
// its kernel dropped, which is what a needless retransmission costs the return
// path.
func (self *tcpReturnRetransmitTestHarness) requireSegmentsSentAgain(
	segmentCount int,
	lost map[int]bool,
) (lostSentAgain int, heldSentAgain int) {
	self.t.Helper()
	for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex += 1 {
		seenCount := self.source.seenCount(self.segmentSeq(segmentIndex))
		if lost[segmentIndex] {
			lostSentAgain += seenCount - 2
			if seenCount < 2 {
				self.t.Fatalf("lost segment %d delivered %d times, want the original and one retransmission", segmentIndex, seenCount)
			}
		} else {
			heldSentAgain += seenCount - 1
		}
	}
	return
}

// Recovery without SACK cannot see what the source holds past a hole, so its
// bursts are bounded by what the acknowledgements have shown lost: the run
// from the cumulative acknowledgement grows by one segment for each
// retransmission an acknowledgement covers, which doubles it every round trip,
// and starts again at the head alone as soon as an acknowledgement covers data
// the source held. Holes spread through a flight then cost exactly one
// retransmission each, and a run of losses costs at most the run again in
// segments the source held past it. Bursts that doubled on every partial
// acknowledgement reached the ceiling within two round trips and sent back
// whatever lay past the loss, which the source answered with duplicate
// acknowledgements of its own.
func TestTcpReturnRetransmitBurstsStopAtDataTheSourceHeld(t *testing.T) {
	const segmentCount = 40
	for _, c := range []struct {
		name  string
		drops []int
		// segments the source held that recovery may send again
		maxHeldSentAgain int
	}{
		{name: "holes spread through the flight", drops: []int{1, 10, 20, 30}, maxHeldSentAgain: 0},
		{name: "a run of losses", drops: []int{1, 2, 3, 4, 5, 6, 7, 8}, maxHeldSentAgain: 8},
	} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("%s", c.name)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
				ackDelay: tcpReturnTestStepRoundTrip,
				stepAcks: true,
			})
			lost := map[int]bool{}
			for _, segmentIndex := range c.drops {
				harness.source.dropCounts[harness.segmentSeq(segmentIndex)] = 1
				lost[segmentIndex] = true
			}
			payload := harness.payload(segmentCount)
			harness.writeSegments(payload, 0, segmentCount)
			// every acknowledgement of the flight, and the recovery after it
			for range 16 {
				harness.stepAcks(tcpReturnTestStepRoundTrip)
			}

			harness.requireStream(payload)
			lostSentAgain, heldSentAgain := harness.requireSegmentsSentAgain(segmentCount, lost)
			_, _, packetCount, reasonCounts := harness.retransmitState()
			t.Logf("%s: retransmissions=%d reasons=%v, %d of them segments the source held", c.name, packetCount, reasonCounts, heldSentAgain)
			if lostSentAgain != 0 {
				t.Fatalf("%s: %d lost segments were sent again more than once", c.name, lostSentAgain)
			}
			if c.maxHeldSentAgain < heldSentAgain {
				t.Fatalf("%s: %d segments the source held were sent again, for %d lost", c.name, heldSentAgain, len(c.drops))
			}
			if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
				t.Fatalf("%s: stats=%+v, want every repair on duplicate or partial acknowledgements", c.name, stats)
			}
		})
	}
}

// One segment reaching the source behind three later ones, as a route
// crossover delivers it, with nothing lost. Three duplicate acknowledgements
// cannot tell that from loss, so the reordered segment is sent again once, and
// that is the whole cost: the acknowledgement that follows covers a head whose
// retransmission is far too young to be what answered it, so the recovery ends
// there. Going on, every ordinary acknowledgement of the data in flight read
// as a partial acknowledgement and its burst sent that data again, whose
// duplicates drew more: the flight and every round after it, for one segment
// that was never lost.
func TestTcpReturnRetransmitAReorderedSegmentIsSentAgainOnlyOnce(t *testing.T) {
	const firstCount = 40
	const roundCount = 20
	const roundCountPerFlow = 6
	const reorderedIndex = 10
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			ackDelay: tcpReturnTestStepRoundTrip,
			stepAcks: true,
		})
		harness.source.reorderSeq = harness.segmentSeq(reorderedIndex)
		harness.source.reorderAfter = returnRetransmitDupAckThreshold

		segmentCount := firstCount + roundCountPerFlow*roundCount
		payload := harness.payload(segmentCount)
		written := harness.writeSegments(payload, 0, firstCount)
		for round := 0; round < roundCountPerFlow; round += 1 {
			written = harness.writeSegments(payload, written, roundCount)
			harness.stepAcks(tcpReturnTestStepRoundTrip)
		}
		for range 8 {
			harness.stepAcks(tcpReturnTestStepRoundTrip)
		}

		harness.requireStream(payload)
		_, heldSentAgain := harness.requireSegmentsSentAgain(segmentCount, nil)
		_, _, packetCount, reasonCounts := harness.retransmitState()
		t.Logf("retransmissions=%d reasons=%v", packetCount, reasonCounts)
		if 1 < packetCount || heldSentAgain != int(packetCount) {
			t.Fatalf("retransmissions=%d reasons=%v with nothing lost, want at most the reordered segment once", packetCount, reasonCounts)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
			t.Fatalf("stats=%+v, want no timer expiry", stats)
		}
	})
}

// A recovery whose head is a segment this recovery never sent again, ended as
// spurious. A source that reports holding the head and a segment well above
// it, and reports nothing between, leaves the holes below its highest
// selective byte to be sent again and the head itself alone: it is marked,
// which is what stops it. When the source then acknowledges the head, the
// recovery is answered by bytes that were never sent again, so the head was
// never missing and the recovery was spurious, and it ends there rather than
// reading every later acknowledgement of data in flight as a partial one and
// sending that data again. This is the arm of that rule where the head has no
// retransmission at all rather than one too young to be the answer, which is
// the reordering the sibling above covers.
func TestTcpReturnRetransmitAHeadNeverSentAgainEndsTheRecovery(t *testing.T) {
	const segmentCount = 8
	// what the source reports holding: the head, and one segment well above
	// it that puts the holes between them below its highest selective byte
	const highestHeldIndex = 4
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{sack: true})
		// nothing is acknowledged, so the whole flight is retained
		harness.source.holdAcks = true
		payload := harness.payload(segmentCount)
		harness.write(payload)
		synctest.Wait()

		blocks := []tcpSackBlock{
			{start: harness.dataSeq, end: harness.segmentSeq(1)},
			{start: harness.segmentSeq(highestHeldIndex), end: harness.segmentSeq(highestHeldIndex + 1)},
		}
		for range returnRetransmitDupAckThreshold {
			harness.source.sendCraftedSackAck(harness.dataSeq, blocks)
		}
		synctest.Wait()
		if _, _, packetCount, _ := harness.retransmitState(); packetCount != highestHeldIndex-1 {
			t.Fatalf("retransmissions=%d on the third duplicate, want the %d holes between the two reported segments", packetCount, highestHeldIndex-1)
		}
		if phase := harness.recoveryPhase(); phase != tcpReturnRecoveryPhaseLoss {
			t.Fatalf("recovery phase %d after the third duplicate, want loss recovery", phase)
		}

		// the source acknowledges the head it reported holding, which this
		// recovery never sent again
		harness.source.sendAck(harness.segmentSeq(1))
		synctest.Wait()
		if phase := harness.recoveryPhase(); phase != tcpReturnRecoveryPhaseNone {
			t.Fatalf("recovery phase %d after an acknowledgement of a head that was never sent again, want the recovery ended as spurious", phase)
		}

		// and the rest of the flight, which is data in flight rather than a
		// recovery's partial acknowledgements, costs nothing more
		harness.source.ackNow()
		synctest.Wait()
		harness.requireStream(payload)
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != highestHeldIndex-1 || reasonCounts[tcpReturnRetransmitReasonSackHole] != packetCount {
			t.Fatalf("retransmissions=%d reasons=%v over the flow, want the %d holes once each", packetCount, reasonCounts, highestHeldIndex-1)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
			t.Fatalf("stats=%+v, want no timer expiry", stats)
		}
	})
}

// A run of segments the source's kernel drops with data still flowing behind
// it. Recovery sends a few segments the source held past the run, and the
// source's kernel answers every one of them with a duplicate acknowledgement.
// Those duplicates are not evidence of loss: they repeat what the source holds
// in order, which is at most what was retained when the retransmissions went.
// Before this they reached the threshold and began another recovery, whose
// partial acknowledgements were the ordinary acknowledgements of data in
// flight, whose bursts sent that data again, whose duplicates began the next
// recovery: about a window sent again every round trip for the rest of the
// flow. A real loss after them is still repaired by duplicate acknowledgements
// once the guard has lapsed, never by the timer here.
func TestTcpReturnRetransmitDuplicatesOfItsOwnRetransmissionsDoNotStartARecovery(t *testing.T) {
	const firstCount = 40
	const roundCount = 20
	const roundCountPerFlow = 12
	const lostStart = 1
	const lostEnd = 9
	// well past the recovery, so the guard on the duplicates it drew has
	// lapsed and the duplicates of this one are the only ones that count
	const laterLostIndex = firstCount + 6*roundCount + 3
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			ackDelay: tcpReturnTestStepRoundTrip,
			stepAcks: true,
		})
		lost := map[int]bool{}
		for segmentIndex := lostStart; segmentIndex < lostEnd; segmentIndex += 1 {
			lost[segmentIndex] = true
		}
		lost[laterLostIndex] = true
		for segmentIndex := range lost {
			harness.source.dropCounts[harness.segmentSeq(segmentIndex)] = 1
		}

		segmentCount := firstCount + roundCountPerFlow*roundCount
		payload := harness.payload(segmentCount)
		written := harness.writeSegments(payload, 0, firstCount)
		for round := 0; round < roundCountPerFlow; round += 1 {
			written = harness.writeSegments(payload, written, roundCount)
			harness.stepAcks(tcpReturnTestStepRoundTrip)
		}
		// every acknowledgement of the last round, and a recovery after it
		for range 8 {
			harness.stepAcks(tcpReturnTestStepRoundTrip)
		}

		harness.requireStream(payload)
		lostSentAgain, heldSentAgain := harness.requireSegmentsSentAgain(segmentCount, lost)
		_, _, packetCount, reasonCounts := harness.retransmitState()
		t.Logf("retransmissions=%d reasons=%v, %d of them segments the source held", packetCount, reasonCounts, heldSentAgain)
		if reasonCounts[tcpReturnRetransmitReasonDupAck] != 2 {
			t.Fatalf("reasons=%v, want one fast retransmit for the run and one for the later loss", reasonCounts)
		}
		if lostSentAgain != 0 {
			t.Fatalf("%d lost segments were sent again more than once", lostSentAgain)
		}
		if maxHeldSentAgain := 4 * (lostEnd - lostStart); maxHeldSentAgain < heldSentAgain {
			t.Fatalf("%d segments the source held were sent again, for %d lost", heldSentAgain, lostEnd-lostStart)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
			t.Fatalf("stats=%+v, want every repair on duplicate or partial acknowledgements", stats)
		}
	})
}

// The round trip of the loss-recovery burst tests, above the 200 ms hole
// interval floor so the interval is one round trip and would let the late
// acknowledgements of one burst resend its tail.
const tcpReturnTestBurstRoundTrip = 250 * time.Millisecond

// The source's view of a recovery that ran in bursts: the stream is exact,
// every segment in `lost` came again exactly once, and the in-order frontier
// reached the end within `maxRoundTripCount` round trips of `recoveryAt`.
// Both spans below recover in exactly 11.000 round trips of virtual time, so
// the bound is the produced value: the doubling run is what makes it a
// handful rather than one round trip per segment, and a bound with room to
// spare would let a third of that speed back.
func requireTcpReturnTestBurstRecovery(
	t *testing.T,
	harness *tcpReturnRetransmitTestHarness,
	payload []byte,
	lostStartIndex int,
	lostEndIndex int,
	recoveryAt time.Time,
	maxRoundTripCount int,
) {
	t.Helper()
	harness.requireStream(payload)
	for segmentIndex := lostStartIndex; segmentIndex < lostEndIndex; segmentIndex += 1 {
		harness.requireSeenCount(segmentIndex, 2)
	}
	harness.source.stateLock.Lock()
	frontierAt := harness.source.frontierAt
	harness.source.stateLock.Unlock()
	recovery := frontierAt.Sub(recoveryAt)
	if time.Duration(maxRoundTripCount)*tcpReturnTestBurstRoundTrip < recovery {
		t.Fatalf("%d lost segments recovered in %s, %.1f round trips, want at most %d", lostEndIndex-lostStartIndex, recovery, float64(recovery)/float64(tcpReturnTestBurstRoundTrip), maxRoundTripCount)
	}
	t.Logf("%d lost segments recovered in %s, %.3f round trips", lostEndIndex-lostStartIndex, recovery, float64(recovery)/float64(tcpReturnTestBurstRoundTrip))
}

// A source whose kernel drops one segment and then, when fast retransmit
// fills that hole, prunes everything it held out of order beyond it, as
// tcp_prune_ofo_queue does under receive-memory pressure, and whose
// acknowledgements take a round trip each. Nothing but the retained copies
// can fill the pruned span, and without SACK nothing but the partial
// acknowledgements says it is missing. Each partial acknowledgement sends a
// burst from the cumulative acknowledgement, doubling to the ceiling, so 702
// segments recover in a handful of round trips, each sent again exactly once:
// twice the span would be the bound, and nothing is sent twice. Segments sent
// after the recovery began lie past its point, arrive, and are never part of
// a burst. One segment per partial acknowledgement took one round trip per
// pruned segment.
func TestTcpReturnRetransmitPrunedSpanRecoversInBursts(t *testing.T) {
	for _, initialSynSeq := range tcpReturnTestInitialSynSeqs(tcpReturnTestOptions{}, 2, 300) {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			// with the later segments, inside one window of the source (see the
			// window constants)
			const segmentCount = 704
			const laterSegmentCount = 8
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq, ackDelay: tcpReturnTestBurstRoundTrip})
			harness.source.dropCounts[harness.segmentSeq(1)] = 1
			harness.source.renegeOnce = true

			payload := harness.payload(segmentCount + laterSegmentCount)
			harness.write(payload[:segmentCount*harness.segmentByteCount])
			synctest.Wait()
			// the duplicates arrive a round trip later, fast retransmit fills the
			// hole, and the source prunes
			time.Sleep(tcpReturnTestBurstRoundTrip)
			synctest.Wait()
			harness.requireSeenCount(1, 2)
			harness.write(payload[segmentCount*harness.segmentByteCount:])
			synctest.Wait()
			// far past any recovery here, and inside the no-progress bound of a
			// flow that stalled
			time.Sleep(defaultReturnRetransmitTimeout / 2)
			synctest.Wait()

			fastRetransmitAt := harness.requireDelivery(harness.segmentSeq(1), 1).at
			requireTcpReturnTestBurstRecovery(t, harness, payload, 2, segmentCount, fastRetransmitAt, 11)
			harness.requireSeenCount(0, 1)
			harness.requireSeenCount(1, 2)
			for segmentIndex := segmentCount; segmentIndex < segmentCount+laterSegmentCount; segmentIndex += 1 {
				harness.requireSeenCount(segmentIndex, 1)
			}
			_, _, packetCount, reasonCounts := harness.retransmitState()
			if packetCount != segmentCount-1 ||
				reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 ||
				reasonCounts[tcpReturnRetransmitReasonPartialAck] != segmentCount-2 {
				t.Fatalf("retransmissions=%d reasons=%v, want the hole on duplicates and the pruned span once on partial acknowledgements", packetCount, reasonCounts)
			}
			if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 || stats.ByteCount != ByteCount((segmentCount-1)*harness.segmentByteCount) {
				t.Fatalf("stats=%+v, want no timeout and each lost segment once", stats)
			}
		})
	}
}

// The guard credits this flow's own retransmissions with at most two bursts
// of duplicate acknowledgements. Each take of due segments pushes the guard's
// window out by a timer, so the window never lapsed during a recovery and the
// count grew with every burst: the 702-segment recovery below left it at 701,
// and a real loss after that would have needed 704 duplicates before fast
// retransmit believed it, which is the timer's job and not the guard's. What
// can still be drawing duplicates is the bursts in flight, which is one per
// round trip over a window of at least two round trips, so the count stops at
// two of them and the recovery it bounds is unchanged.
func TestTcpReturnRetransmitTheGuardCreditsAtMostTwoBurstsOfItsOwn(t *testing.T) {
	// the pruned span of the burst rows, whose bursts double to the ceiling
	// and whose guesses are what the guard counts
	const segmentCount = 704
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{ackDelay: tcpReturnTestBurstRoundTrip})
		harness.source.dropCounts[harness.segmentSeq(1)] = 1
		harness.source.renegeOnce = true
		payload := harness.payload(segmentCount)
		harness.write(payload)
		synctest.Wait()

		// twice a round trip apart over the whole recovery, so every burst is
		// read
		peakCount := 0
		for range 24 {
			time.Sleep(tcpReturnTestBurstRoundTrip / 2)
			synctest.Wait()
			peakCount = max(peakCount, harness.explainedDupAckCount())
		}
		if peakCount != returnRetransmitMaxExplainedDupAckCount {
			t.Fatalf("the guard credited %d duplicates to its own guesses over the recovery, want the cap of %d reached and held",
				peakCount, returnRetransmitMaxExplainedDupAckCount)
		}

		// and the recovery the guard rides on is unchanged: the pruned span
		// comes back, each segment exactly once
		fastRetransmitAt := harness.requireDelivery(harness.segmentSeq(1), 1).at
		requireTcpReturnTestBurstRecovery(t, harness, payload, 2, segmentCount, fastRetransmitAt, 11)
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != segmentCount-1 ||
			reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 ||
			reasonCounts[tcpReturnRetransmitReasonPartialAck] != segmentCount-2 {
			t.Fatalf("retransmissions=%d reasons=%v, want the hole on duplicates and the pruned span once on partial acknowledgements", packetCount, reasonCounts)
		}
	})
}

// What the credit buys and what it costs, read as behaviour rather than as
// the constant: after a recovery whose guesses are more than two bursts, the
// run of duplicate acknowledgements the guard absorbs at a standing
// cumulative acknowledgement is exactly two bursts, and the threshold's own
// three on top of them; the next duplicate is believed and the repair goes.
// A credit of one burst would start the repair at half this run, and a credit
// of four bursts, or the uncapped count this recovery would otherwise leave
// at 398, would not start it inside twice the run: each of those reads as its
// own number here rather than as never.
//
// A burst goes only on an acknowledgement that advances, so a run at a
// standing one can only be answering guesses that went before the advances
// stopped; two bursts at the ceiling is the bound taken for that (see
// returnRetransmitMaxExplainedDupAckCount). The source below repeats an
// acknowledgement it has long passed, which is what makes a run this long
// reach the credit at all: no receiver of the flight it was sent has that
// many duplicates to give, and the rows that measure a compliant one never
// pass 140.
func TestTcpReturnRetransmitTheGuardAbsorbsTwoBurstsOfDuplicatesAndNoMore(t *testing.T) {
	const recoverySegmentCount = 400
	const laterSegmentCount = 100
	// the run the guard is expected to absorb, and twice it, so a credit
	// larger than the cap reads as its own number rather than as never
	const wantRun = returnRetransmitDupAckThreshold + 2*returnRetransmitMaxBurstSegmentCount
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		harness.source.holdAcks = true
		payload := harness.payload(recoverySegmentCount + laterSegmentCount)
		recoveryByteCount := recoverySegmentCount * harness.segmentByteCount
		harness.write(payload[:recoveryByteCount])
		synctest.Wait()

		// a recovery whose bursts guess far past the hole: the source
		// acknowledges one segment at a time, so every burst grows
		for range returnRetransmitDupAckThreshold {
			harness.source.sendAck(harness.dataSeq)
		}
		synctest.Wait()
		for segmentIndex := 1; segmentIndex < recoverySegmentCount-100; segmentIndex += 1 {
			harness.source.sendAck(harness.segmentSeq(segmentIndex))
			synctest.Wait()
		}

		// data behind the recovery point, so the ring still holds a head
		// when the recovery ends and the run below has something to repair
		harness.write(payload[recoveryByteCount:])
		synctest.Wait()
		harness.source.sendAck(harness.segmentSeq(recoverySegmentCount))
		synctest.Wait()
		if phase := harness.recoveryPhase(); phase != tcpReturnRecoveryPhaseNone {
			t.Fatalf("recovery phase %d after the acknowledgement that ends it, want none", phase)
		}
		_, _, recoveryPacketCount, _ := harness.retransmitState()
		if recoveryPacketCount <= 2*returnRetransmitMaxBurstSegmentCount {
			t.Fatalf("the recovery sent %d segments again, want more than the two bursts the run below is read against", recoveryPacketCount)
		}
		t.Logf("the recovery sent %d segments again and left the guard crediting %d duplicates",
			recoveryPacketCount, harness.explainedDupAckCount())

		// the run at the standing acknowledgement, one duplicate at a time
		run := 0
		for index := 1; index <= 2*wantRun; index += 1 {
			harness.source.sendDuplicateAck()
			synctest.Wait()
			if _, _, packetCount, _ := harness.retransmitState(); recoveryPacketCount < packetCount {
				run = index
				break
			}
		}
		if run != wantRun {
			t.Fatalf("the guard absorbed %d duplicates before the repair went (0 = more than %d), want the threshold above two bursts, %d",
				run, 2*wantRun, wantRun)
		}
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != recoveryPacketCount+1 ||
			reasonCounts[tcpReturnRetransmitReasonDupAck] != 2 {
			t.Fatalf("retransmissions=%d reasons=%v, want the run to have sent the head once", packetCount, reasonCounts)
		}
	})
}

// The same recovery after a real expiry: the source's kernel drops the whole
// flight after its first segment, so no duplicate acknowledgement ever comes.
// The expiry probes with the head, the source acknowledges exactly that head,
// and with nothing later to draw a duplicate the second expiry shows the loss
// real; from there the partial acknowledgements recover the rest in bursts,
// not one segment per acknowledgement.
func TestTcpReturnRetransmitLostFlightRecoversInBurstsAfterTheProbe(t *testing.T) {
	for _, initialSynSeq := range tcpReturnTestInitialSynSeqs(tcpReturnTestOptions{}, 1, 300) {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			const segmentCount = 704
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq, ackDelay: tcpReturnTestBurstRoundTrip})
			for segmentIndex := 1; segmentIndex < segmentCount; segmentIndex += 1 {
				harness.source.dropCounts[harness.segmentSeq(segmentIndex)] = 1
			}

			payload := harness.payload(segmentCount)
			harness.write(payload)
			synctest.Wait()
			time.Sleep(defaultReturnRetransmitTimeout / 2)
			synctest.Wait()

			// the first segment's acknowledgement sampled the round trip, so the
			// timer is max(2 x srtt, srtt + 4 rttvar) = 3 round trips from it;
			// the probe's head goes at its expiry, and the loss shows real at
			// the second, twice that timer after the head's acknowledgement
			rto := 3 * tcpReturnTestBurstRoundTrip
			start := harness.requireDelivery(harness.segmentSeq(0), 0).at
			probeAt := harness.requireDelivery(harness.segmentSeq(1), 1).at
			if got, want := probeAt.Sub(start), tcpReturnTestBurstRoundTrip+rto; got != want {
				t.Fatalf("probe at +%s, want +%s", got, want)
			}
			lossAt := harness.requireDelivery(harness.segmentSeq(2), 1).at
			if got, want := lossAt.Sub(probeAt), tcpReturnTestBurstRoundTrip+2*rto; got != want {
				t.Fatalf("second expiry %s after the probe, want %s", got, want)
			}
			requireTcpReturnTestBurstRecovery(t, harness, payload, 1, segmentCount, lossAt, 11)
			harness.requireSeenCount(0, 1)
			_, _, packetCount, reasonCounts := harness.retransmitState()
			if packetCount != segmentCount-1 ||
				reasonCounts[tcpReturnRetransmitReasonTimeout] != 2 ||
				reasonCounts[tcpReturnRetransmitReasonPartialAck] != segmentCount-3 {
				t.Fatalf("retransmissions=%d reasons=%v, want two heads on the timer and the rest once on partial acknowledgements", packetCount, reasonCounts)
			}
			if stats := harness.counters.snapshot(); stats.TimeoutCount != 2 || stats.AbandonCount != 0 {
				t.Fatalf("stats=%+v, want two timeouts and no abandon", stats)
			}
		})
	}
}

// The loss-recovery run has a ceiling, and a new recovery starts again at the
// head alone. Two pruned spans in one flow, each stepped acknowledgement by
// acknowledgement: the first is large enough for the run to reach the
// ceiling, and the second begins after it. Without the ceiling the run grows
// to the whole span, and one acknowledgement that covers a burst can then ask
// for a window of retransmissions at once; without the restart the next
// recovery's first partial acknowledgement sends the previous run in one go,
// and without selective acknowledgement those are segments the source may
// hold.
//
// Produced: the first recovery's run reads 1, 2, 3 ... 128 and stays there,
// every acknowledgement drawing two segments; the second's reads 1, 2 ...
// 20. Without the ceiling the first run reaches 399; with the run kept the
// second recovery reads 128 at its first acknowledgement and sends 38
// segments on the next.
func TestTcpReturnRetransmitBurstRunHasACeilingAndRestartsAtOne(t *testing.T) {
	// the ceiling's own value, in consecutive segments from the cumulative
	// acknowledgement: about 190 KB of full-size segments, which is the most
	// one acknowledgement asks for and, without selective acknowledgement,
	// the most it can send again that the source already held
	const maxBurstSegmentCount = 128
	const firstSpanCount = 400
	const secondSpanCount = 40
	const firstHoleIndex = 1
	const secondHoleIndex = firstSpanCount + 1
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		if returnRetransmitMaxBurstSegmentCount != maxBurstSegmentCount {
			t.Fatalf("the burst ceiling is %d segments, want %d", returnRetransmitMaxBurstSegmentCount, maxBurstSegmentCount)
		}
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			ackDelay: tcpReturnTestStepRoundTrip,
			stepAcks: true,
		})
		payload := harness.payload(firstSpanCount + secondSpanCount)

		// Steps every acknowledgement the source has queued, and reports the
		// run at each one that drew retransmissions: the first, which is the
		// recovery's own start, the largest, and the most packets any one
		// acknowledgement drew.
		stepRecovery := func() (firstRun int, maxRun int, maxPacketCount int64) {
			for {
				packetCount, stepped := harness.stepOneAck()
				if !stepped {
					return
				}
				if packetCount <= 0 {
					continue
				}
				run := harness.burstRunSegmentCount()
				if maxPacketCount == 0 {
					firstRun = run
				}
				maxRun = max(maxRun, run)
				maxPacketCount = max(maxPacketCount, packetCount)
			}
		}

		// a source whose kernel drops one segment and prunes what it held
		// past the hole when the repair fills it, so the whole span behind it
		// is recovered by the partial acknowledgements
		harness.source.dropCounts[harness.segmentSeq(firstHoleIndex)] = 1
		harness.source.renegeOnce = true
		harness.writeSegments(payload, 0, firstSpanCount)
		firstRun, maxRun, maxPacketCount := stepRecovery()
		t.Logf("the first recovery: run from %d to %d, at most %d packets on one acknowledgement", firstRun, maxRun, maxPacketCount)
		if firstRun != 1 {
			t.Fatalf("the first recovery began with a run of %d, want the head alone", firstRun)
		}
		if maxRun != maxBurstSegmentCount {
			t.Fatalf("the run reached %d over a span of %d segments, want the ceiling %d", maxRun, firstSpanCount, maxBurstSegmentCount)
		}
		if maxBurstSegmentCount < maxPacketCount {
			t.Fatalf("one acknowledgement drew %d packets, above the ceiling %d", maxPacketCount, maxBurstSegmentCount)
		}

		// the second span, with the run left at the ceiling by the first
		harness.source.stateLock.Lock()
		harness.source.renegeOnce = true
		harness.source.stateLock.Unlock()
		harness.source.dropCounts[harness.segmentSeq(secondHoleIndex)] = 1
		harness.writeSegments(payload, firstSpanCount, secondSpanCount)
		firstRun, maxRun, maxPacketCount = stepRecovery()
		t.Logf("the second recovery: run from %d to %d, at most %d packets on one acknowledgement", firstRun, maxRun, maxPacketCount)
		if firstRun != 1 {
			t.Fatalf("the second recovery began with a run of %d, want the head alone", firstRun)
		}
		// its acknowledgements each cover one retransmission and grow the run
		// by one, so two segments go on each
		if 2 < maxPacketCount {
			t.Fatalf("an acknowledgement of the second recovery drew %d packets, want at most two from a run that starts again", maxPacketCount)
		}

		harness.stepAcks(4 * tcpReturnTestStepRoundTrip)
		harness.requireStream(payload)
		for segmentIndex := 0; segmentIndex < firstSpanCount+secondSpanCount; segmentIndex += 1 {
			want := 1
			if firstHoleIndex <= segmentIndex && segmentIndex < firstSpanCount ||
				secondHoleIndex <= segmentIndex && segmentIndex < firstSpanCount+secondSpanCount {
				// the hole and the span the source pruned behind it
				want = 2
			}
			harness.requireSeenCount(segmentIndex, want)
		}
		_, _, packetCount, reasonCounts := harness.retransmitState()
		wantPacketCount := int64(firstSpanCount - firstHoleIndex + secondSpanCount - (secondHoleIndex - firstSpanCount))
		if packetCount != wantPacketCount || reasonCounts[tcpReturnRetransmitReasonDupAck] != 2 {
			t.Fatalf("retransmissions=%d reasons=%v, want %d, each span once, on two fast retransmits and their partial acknowledgements", packetCount, reasonCounts, wantPacketCount)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
			t.Fatalf("stats=%+v, want every repair on duplicate or partial acknowledgements", stats)
		}
	})
}

// The burst stops at the window edge it is given, as well as at the recovery
// point. No sequence supplies an edge that binds: the packetizer emits only
// what fits inside the greatest edge the source has advertised, which never
// moves back (ip.go, receiveWindowEnd), every emitted byte is retained, and
// the edge the acknowledgement path hands the burst is that same greatest
// edge, so every retained segment ends at or below it and the recovery point
// is reached first. The stop is therefore unreachable through a sequence and
// is pinned here on the state alone, against the day a caller passes an edge
// of its own.
func TestTcpReturnRetransmitBurstStopsAtTheWindowEdge(t *testing.T) {
	const segmentCount = 8
	const segmentByteCount = 1000
	const initialSeq = uint32(1000)
	segmentSeq := func(segmentIndex int) uint32 {
		return initialSeq + uint32(segmentIndex*segmentByteCount)
	}
	for _, c := range []struct {
		name         string
		windowEnd    uint32
		wantDueCount int
	}{
		{
			name: "an edge inside the retained set",
			// the end of the third segment, which is where the burst stops
			windowEnd:    segmentSeq(3),
			wantDueCount: 3,
		},
		{
			name:         "an edge past it, which is the only edge a sequence gives",
			windowEnd:    segmentSeq(segmentCount),
			wantDueCount: segmentCount,
		},
	} {
		settings := DefaultTcpBufferSettingsWithBufferSize(8)
		state := newTcpReturnRetransmitState(settings)
		seqs := []uint32{}
		for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex += 1 {
			// no packet: nothing here builds one, so nothing is retained of
			// the pool either
			state.retainWithLock(nil, segmentSeq(segmentIndex), 0, segmentByteCount, false)
			seqs = append(seqs, segmentSeq(segmentIndex))
		}
		state.markDeliveredWithLock(seqs, 0, 0)
		state.beginLossRecoveryWithLock(0)
		state.recoveryEnd = segmentSeq(segmentCount)
		state.burstSegmentCount = segmentCount
		state.markBurstWithLock(c.windowEnd, 1, 0)

		if state.dueCount != c.wantDueCount {
			t.Fatalf("%s: %d segments due of %d retained, want %d", c.name, state.dueCount, state.count, c.wantDueCount)
		}
		for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex += 1 {
			if due := state.segmentAtWithLock(segmentIndex).due; due != (segmentIndex < c.wantDueCount) {
				t.Fatalf("%s: segment %d due=%v, want the burst to stop at %d", c.name, segmentIndex, due, c.wantDueCount)
			}
		}
	}
}

// The pool roots and ring records the retained set holds, read under the
// sequence mutex: what the ring can be seen to hold, beside what the state
// charges against the memory bound.
func (self *tcpReturnRetransmitTestHarness) retainedMemory() (
	measuredByteCount int64,
	chargedByteCount int64,
	ringSegmentCount int,
) {
	self.sequence.mutex.Lock()
	defer self.sequence.mutex.Unlock()
	state := &self.sequence.returnRetransmit
	for index := 0; index < state.count; index += 1 {
		measuredByteCount += int64(cap(state.segmentAtWithLock(index).packet))
	}
	measuredByteCount += int64(len(state.segments)) * int64(unsafe.Sizeof(tcpReturnRetainedSegment{}))
	return measuredByteCount, state.retainedMemoryByteCount, len(state.segments)
}

// The record size the memory bound is charged in is the compiler's.
func TestTcpReturnRetainedSegmentRecordByteCount(t *testing.T) {
	if got, want := unsafe.Sizeof(tcpReturnRetainedSegment{}), uintptr(tcpReturnRetainedSegmentByteCount); got != want {
		t.Fatalf("a retained segment is %d bytes, and the memory bound charges %d", got, want)
	}
}

// Retention holds whole pool roots, one per packetized segment, so the cap in
// sequence bytes says nothing about the memory a flow keeps: a segment of a
// few bytes, which a source can force with small window openings or an origin
// that trickles, holds a 268-byte root and a ring record for one byte of
// sequence space. The memory bound holds whatever the segment size: the flow
// stops packetizing at three times the cap in pool roots and ring records,
// where before a 4 KiB cap held 1.4 MB, 356 times it. The ring also returns
// its records when the retained set empties, instead of keeping the peak for
// the life of the flow.
func TestTcpReturnRetransmitRetainedMemoryStaysWithinTheCap(t *testing.T) {
	const capByteCount = 16 * 1024
	for _, chunkByteCount := range []int{1, 64, tcpReturnTestSegmentByteCount} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("chunks of %d bytes", chunkByteCount)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
				configure: func(settings *TcpBufferSettings) {
					settings.ReturnRetransmitRetainByteCount = capByteCount
				},
			})
			harness.source.holdAcks = true
			payload := harness.payload(64)
			writeDone := make(chan struct{})
			go func() {
				defer close(writeDone)
				for offset := 0; offset+chunkByteCount <= len(payload); offset += chunkByteCount {
					// written directly, so that a failed test's teardown
					// closing the pipe ends this goroutine quietly
					if _, err := harness.upstream.Write(payload[offset : offset+chunkByteCount]); err != nil {
						return
					}
				}
			}()
			synctest.Wait()

			select {
			case <-writeDone:
				t.Fatalf("chunks of %d bytes: the whole payload was consumed with nothing acknowledged", chunkByteCount)
			default:
			}
			measuredByteCount, chargedByteCount, ringSegmentCount := harness.retainedMemory()
			retainedByteCount, retainedCount, _, _ := harness.retransmitState()
			t.Logf("chunks of %d bytes: %d segments holding %d sequence bytes in %d bytes of memory, ring %d",
				chunkByteCount, retainedCount, retainedByteCount, measuredByteCount, ringSegmentCount)
			if measuredByteCount != chargedByteCount {
				t.Fatalf("chunks of %d bytes: the ring holds %d bytes and the bound is charged %d", chunkByteCount, measuredByteCount, chargedByteCount)
			}
			// the bound, passed by at most the ring's last doubling
			maxByteCount := int64(returnRetransmitRetainMemoryFactor*capByteCount) +
				int64(ringSegmentCount/2)*int64(unsafe.Sizeof(tcpReturnRetainedSegment{}))
			if maxByteCount < measuredByteCount {
				t.Fatalf("chunks of %d bytes: retention holds %d bytes of memory for %d sequence bytes, above the bound %d", chunkByteCount, measuredByteCount, retainedByteCount, maxByteCount)
			}
			if capByteCount < retainedByteCount {
				t.Fatalf("chunks of %d bytes: retained %d sequence bytes, above the cap", chunkByteCount, retainedByteCount)
			}

			harness.source.ackNow()
			select {
			case <-writeDone:
			case <-time.After(2 * time.Second):
				t.Fatalf("chunks of %d bytes: the writes did not complete after acknowledgements freed space", chunkByteCount)
			}
			synctest.Wait()
			harness.requireStream(payload[:len(payload)/chunkByteCount*chunkByteCount])
			retainedByteCount, retainedCount, _, _ = harness.retransmitState()
			if retainedByteCount != 0 || retainedCount != 0 {
				t.Fatalf("chunks of %d bytes: retained after full acknowledgement: %d bytes in %d segments", chunkByteCount, retainedByteCount, retainedCount)
			}
			measuredByteCount, chargedByteCount, ringSegmentCount = harness.retainedMemory()
			if 16 < ringSegmentCount || measuredByteCount != chargedByteCount {
				t.Fatalf("chunks of %d bytes: the emptied ring keeps %d records holding %d bytes", chunkByteCount, ringSegmentCount, measuredByteCount)
			}
		})
	}
}

// (d) An explicit retention cap, as a provider short of memory sets below the
// flow's maximum window: with the source's window far larger than the cap and
// no acknowledgements, packetizing stops at the cap and the upstream write
// waits; acknowledgements free space and the burst completes, with the bytes
// past the last acknowledgement never above the cap.
func TestTcpReturnRetransmitRetainedBytesStayWithinTheCap(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		const capSegmentCount = 4
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			configure: func(settings *TcpBufferSettings) {
				settings.ReturnRetransmitRetainByteCount = capSegmentCount * tcpReturnTestSegmentByteCount
			},
		})
		harness.source.holdAcks = true

		payload := harness.payload(16)
		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			harness.write(payload)
		}()
		synctest.Wait()

		select {
		case <-writeDone:
			t.Fatal("the burst was consumed past the cap with nothing acknowledged")
		default:
		}
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != capSegmentCount*tcpReturnTestSegmentByteCount || retainedCount != capSegmentCount {
			t.Fatalf("retained %d bytes in %d segments, want exactly the cap of %d segments", retainedByteCount, retainedCount, capSegmentCount)
		}
		if got := len(harness.source.streamCopy()); got != capSegmentCount*tcpReturnTestSegmentByteCount {
			t.Fatalf("source received %d bytes, want the cap", got)
		}

		harness.source.ackNow()
		select {
		case <-writeDone:
		case <-time.After(2 * time.Second):
			t.Fatal("the burst did not complete after acknowledgements freed space")
		}
		synctest.Wait()

		harness.requireStream(payload)
		harness.source.stateLock.Lock()
		maxOutstandingByteCount := harness.source.maxOutstandingByteCount
		harness.source.stateLock.Unlock()
		if capSegmentCount*tcpReturnTestSegmentByteCount < maxOutstandingByteCount {
			t.Fatalf("bytes past the last acknowledgement reached %d, above the cap", maxOutstandingByteCount)
		}
		_, _, packetCount, _ := harness.retransmitState()
		if packetCount != 0 {
			t.Fatalf("retransmissions=%d with no loss", packetCount)
		}
		// the held segments were acknowledged after delivery, which is the
		// only shape this model samples the round trip from
		harness.sequence.mutex.Lock()
		rttKnown := harness.sequence.returnRetransmit.rttKnown
		harness.sequence.mutex.Unlock()
		if !rttKnown {
			t.Fatal("no round trip was sampled from the released acknowledgements")
		}
	})
}

// What the shared pool holds and the roots the ring holds that it is charged
// for, read under the sequence mutex: the pool's account and the ring's own
// account of the same bytes.
func (self *tcpReturnRetransmitTestHarness) retainedPool() (
	poolByteCount ByteCount,
	rootByteCount int64,
	memoryByteCount int64,
) {
	self.sequence.mutex.Lock()
	defer self.sequence.mutex.Unlock()
	state := &self.sequence.returnRetransmit
	return state.budget.UsedByteCount(), state.retainedRootByteCountWithLock(), state.retainedMemoryByteCount
}

// (e) The retained pool roots are charged to the pool this NAT's flows share,
// TcpBufferSettings.ReturnQueueBudget. A pool smaller than the flow's own cap
// binds first: packetizing stops at the pool exactly as it stops at a closed
// window, the upstream write waits, and the pool holds exactly the roots the
// ring holds - not the ring's records, which are per flow. Acknowledgements
// return both, and the pool's reserve and release counts balance, so no
// chunk's reservation is left behind. Uncharged, the pool stands at zero
// however much is retained and nothing throttles the return producer, which
// is what lets a full NAT budget refuse the acknowledgement that would
// release it (TestNatProviderMemoryTcpAckProgressAtFullDataBudget).
func TestTcpReturnRetransmitChargesRetainedRootsToTheSharedPool(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		const poolSegmentCount = 4
		var pool *TransferMemoryBudget
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			configure: func(settings *TcpBufferSettings) {
				// whole segment roots, well below this flow's own cap
				pool = NewTransferMemoryBudget(
					ByteCount(poolSegmentCount) * retainedMessageCapacity(ByteCount(settings.Mtu)))
				settings.ReturnQueueBudget = pool
			},
		})
		harness.source.holdAcks = true

		payload := harness.payload(16)
		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			harness.write(payload)
		}()
		synctest.Wait()

		select {
		case <-writeDone:
			t.Fatal("the burst was consumed past the shared pool with nothing acknowledged")
		default:
		}
		poolByteCount, rootByteCount, memoryByteCount := harness.retainedPool()
		_, retainedCount, _, _ := harness.retransmitState()
		t.Logf("%d segments retained, %d bytes of roots and ring, pool %d of %d",
			retainedCount, memoryByteCount, poolByteCount, pool.TotalByteCount())
		if retainedCount != poolSegmentCount {
			t.Fatalf("retained %d segments, want the %d the pool has room for", retainedCount, poolSegmentCount)
		}
		if poolByteCount != ByteCount(rootByteCount) || poolByteCount != pool.TotalByteCount() {
			t.Fatalf("the pool holds %d for %d bytes of roots, want the whole pool of %d",
				poolByteCount, rootByteCount, pool.TotalByteCount())
		}
		if memoryByteCount <= rootByteCount {
			t.Fatalf("the ring's records are %d bytes beside its roots, want the per-flow bound to carry them",
				memoryByteCount-rootByteCount)
		}

		harness.source.ackNow()
		select {
		case <-writeDone:
		case <-time.After(2 * time.Second):
			t.Fatal("the burst did not complete after acknowledgements freed the pool")
		}
		synctest.Wait()
		harness.requireStream(payload)
		poolByteCount, rootByteCount, _ = harness.retainedPool()
		if poolByteCount != 0 || rootByteCount != 0 {
			t.Fatalf("the pool holds %d for %d bytes of roots after full acknowledgement", poolByteCount, rootByteCount)
		}
		if stats := pool.Stats(); stats.ReservedByteCount != stats.ReleasedByteCount {
			t.Fatalf("the pool's claims do not balance: %+v", stats)
		}
	})
}

// (f) The pool is shared, so one flow's retention can park another's
// packetizer - and the parked flow's own acknowledgements, which are the only
// thing that signals its window, cannot free what a sibling holds. The
// sibling's acknowledgement does, through the pool's capacity edge. Without
// that wake the parked flow sends nothing until its idle timeout, which is
// why upstream's own return cache waited on this pool's notification. The
// sibling's no-progress bound is the other end of it: nothing can hold the
// pool for ever.
func TestTcpReturnRetentionWakesAFlowParkedOnASiblingsPool(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		const poolSegmentCount = 4
		var pool *TransferMemoryBudget
		configure := func(settings *TcpBufferSettings) {
			if pool == nil {
				pool = NewTransferMemoryBudget(
					ByteCount(poolSegmentCount) * retainedMessageCapacity(ByteCount(settings.Mtu)))
			}
			settings.ReturnQueueBudget = pool
		}
		sibling := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{configure: configure})
		parked := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{configure: configure})
		sibling.source.holdAcks = true
		parked.source.holdAcks = true

		siblingPayload := sibling.payload(16)
		siblingWriteDone := make(chan struct{})
		go func() {
			defer close(siblingWriteDone)
			sibling.write(siblingPayload)
		}()
		synctest.Wait()
		if poolByteCount, _, _ := sibling.retainedPool(); poolByteCount != pool.TotalByteCount() {
			t.Fatalf("the sibling holds %d of the pool, want the whole %d", poolByteCount, pool.TotalByteCount())
		}

		// more than one socket read, so the write itself cannot complete
		// while the packetizer is parked
		parkedPayload := parked.payload(16)
		parkedWriteDone := make(chan struct{})
		go func() {
			defer close(parkedWriteDone)
			parked.write(parkedPayload)
		}()
		synctest.Wait()
		requireParked := func(when string) {
			t.Helper()
			select {
			case <-parkedWriteDone:
				t.Fatalf("a flow packetized on a pool a sibling had filled: %s", when)
			default:
			}
			if _, retainedCount, _, _ := parked.retransmitState(); retainedCount != 0 {
				t.Fatalf("the parked flow retained %d segments the pool never admitted: %s", retainedCount, when)
			}
			if got := len(parked.source.streamCopy()); got != 0 {
				t.Fatalf("the parked flow's source received %d bytes the pool never admitted: %s", got, when)
			}
		}
		requireParked("with the sibling holding the pool")

		// its own source acknowledges everything it can, which is nothing it
		// retained, so its own acknowledgements cannot free this pool
		parked.source.ackNow()
		synctest.Wait()
		requireParked("after its own acknowledgements")

		sibling.source.ackNow()
		select {
		case <-parkedWriteDone:
		case <-time.After(2 * time.Second):
			t.Fatal("a flow parked on a sibling's pool was not woken when the sibling released it")
		}
		synctest.Wait()
		parked.requireStream(parkedPayload)
		select {
		case <-siblingWriteDone:
		case <-time.After(2 * time.Second):
			t.Fatal("the sibling's burst did not complete")
		}
		synctest.Wait()
		sibling.requireStream(siblingPayload)
		if poolByteCount := pool.UsedByteCount(); poolByteCount != 0 {
			t.Fatalf("the pool holds %d after both flows were acknowledged", poolByteCount)
		}
	})
}

// The cap a flow gets when the settings leave it zero is its own maximum
// window. With the source advertising more than that window and acknowledging
// nothing, packetizing stops at exactly MaxWindowSize, below the earlier fixed
// 4 MiB or above it, and the acknowledgements then free the rest. The fixed
// cap held a flow whose window and maximum window both allowed 8 MiB at half
// of that, a rate ceiling of 4 MiB over the inner round trip, and let a flow
// with a 256 KiB maximum window retain four times it.
func TestTcpReturnRetransmitDefaultCapIsTheFlowsMaximumWindow(t *testing.T) {
	for _, c := range []struct {
		maxWindowSize uint32
		// the source's window is almost 65,536 units at this scale: about
		// 1 MiB at 4 and 16 MiB at 8, above the maximum window either way
		windowScale uint32
	}{
		{maxWindowSize: uint32(kib(256)), windowScale: 4},
		{maxWindowSize: uint32(mib(8)), windowScale: 8},
	} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
				windowScale: c.windowScale,
				configure: func(settings *TcpBufferSettings) {
					settings.MaxWindowSize = c.maxWindowSize
				},
			})
			if harness.settings.ReturnRetransmitRetainByteCount != 0 {
				t.Fatalf("default cap setting %d, want zero", harness.settings.ReturnRetransmitRetainByteCount)
			}
			harness.source.holdAcks = true
			capByteCount := int(c.maxWindowSize)
			// past the cap by more than one socket read
			payload := harness.payload(capByteCount/harness.segmentByteCount + 16)

			writeDone := make(chan struct{})
			go func() {
				defer close(writeDone)
				harness.write(payload)
			}()
			synctest.Wait()
			select {
			case <-writeDone:
				t.Fatalf("maximum window %d: the burst was consumed past it with nothing acknowledged", capByteCount)
			default:
			}
			retainedByteCount, _, _, _ := harness.retransmitState()
			if retainedByteCount != int64(capByteCount) {
				t.Fatalf("maximum window %d: retained %d bytes, want exactly the maximum window", capByteCount, retainedByteCount)
			}
			if got := len(harness.source.streamCopy()); got != capByteCount {
				t.Fatalf("maximum window %d: source received %d bytes, want the maximum window", capByteCount, got)
			}

			harness.source.ackNow()
			select {
			case <-writeDone:
			case <-time.After(2 * time.Second):
				t.Fatalf("maximum window %d: the burst did not complete after acknowledgements freed space", capByteCount)
			}
			synctest.Wait()
			harness.requireStream(payload)
			harness.source.stateLock.Lock()
			maxOutstandingByteCount := harness.source.maxOutstandingByteCount
			harness.source.stateLock.Unlock()
			if int64(capByteCount) < maxOutstandingByteCount {
				t.Fatalf("maximum window %d: bytes past the last acknowledgement reached %d", capByteCount, maxOutstandingByteCount)
			}
			if _, _, packetCount, _ := harness.retransmitState(); packetCount != 0 {
				t.Fatalf("maximum window %d: retransmissions=%d with no loss", capByteCount, packetCount)
			}
		})
	}
}

// (e) With the setting off nothing is retained and nothing is ever sent
// again: the dropped segment stays a hole through the timer's and the
// bound's whole schedule, and no reset follows, which is the earlier
// behaviour and the failure this change exists for.
func TestTcpReturnRetransmitDisabledNeverRetransmits(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			configure: func(settings *TcpBufferSettings) {
				settings.EnableReturnRetransmit = false
			},
		})
		harness.source.dropCounts[harness.segmentSeq(1)] = 1

		payload := harness.payload(8)
		harness.write(payload)
		synctest.Wait()
		time.Sleep(defaultReturnRetransmitTimeout + returnRetransmitMaxRto)
		synctest.Wait()

		harness.requireSeenCount(1, 1)
		if stream := harness.source.streamCopy(); len(stream) != harness.segmentByteCount {
			t.Fatalf("stream has %d bytes, want the one segment before the hole", len(stream))
		}
		retainedByteCount, retainedCount, packetCount, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 || packetCount != 0 {
			t.Fatalf("retained %d bytes in %d segments, retransmissions=%d with the setting off", retainedByteCount, retainedCount, packetCount)
		}
		harness.source.stateLock.Lock()
		rstReceived := harness.source.rstReceived
		harness.source.stateLock.Unlock()
		if rstReceived || harness.runIsDone() {
			t.Fatal("the flow ended with retransmission off; the earlier behaviour is silent idle")
		}
	})
}

// (f) The FIN is retained like data: dropped once, it is sent again on the
// timer, and the sequence stays open until the source acknowledges it, then
// ends without a reset. The wrapped rows wrap halfway through the second
// segment, and right after the data, so the FIN's sequence byte is the last in
// the space and its end is zero.
func TestTcpReturnRetransmitRetainsAndRetransmitsFin(t *testing.T) {
	for _, initialSynSeq := range []uint32{
		0,
		tcpReturnTestInitialSynSeqWrappingAfter(tcpReturnTestSegmentByteCount + tcpReturnTestSegmentByteCount/2),
		tcpReturnTestInitialSynSeqWrappingAfter(2*tcpReturnTestSegmentByteCount + 1),
	} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq})
			payload := harness.payload(2)
			harness.write(payload)
			synctest.Wait()

			finSeq := harness.segmentSeq(2)
			harness.source.dropCounts[finSeq] = 1
			closeAt := time.Now()
			harness.closeUpstream()
			synctest.Wait()

			if harness.runIsDone() {
				t.Fatal("the sequence ended before the source acknowledged the FIN")
			}
			if got := harness.source.seenCount(finSeq); got != 1 {
				t.Fatalf("FIN delivered %d times before the timer, want 1", got)
			}

			// no round trip was sampled (see the file header), so the timer
			// runs at its initial value
			harness.waitRunDone(2 * returnRetransmitInitialRto)

			times := harness.source.deliveryTimes(finSeq)
			if len(times) != 2 {
				t.Fatalf("FIN delivered %d times, want 2", len(times))
			}
			if got := times[1].Sub(closeAt); got != returnRetransmitInitialRto {
				t.Fatalf("FIN retransmitted at +%s, want +%s", got, returnRetransmitInitialRto)
			}
			harness.source.stateLock.Lock()
			finReceived, rstReceived := harness.source.finReceived, harness.source.rstReceived
			harness.source.stateLock.Unlock()
			if !finReceived || rstReceived {
				t.Fatalf("fin=%t rst=%t, want the FIN accepted and no reset", finReceived, rstReceived)
			}
			harness.requireStream(payload)
			_, _, packetCount, reasonCounts := harness.retransmitState()
			if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonTimeout] != 1 {
				t.Fatalf("retransmissions=%d reasons=%v, want the FIN once on the timer", packetCount, reasonCounts)
			}
		})
	}
}

// The FIN's own sequence byte is retained with it. With data still
// unacknowledged, the source's acknowledgement of exactly that data ends at
// the FIN's sequence, one byte short of the FIN's end, and releases the data
// alone. A FIN whose record ended at its sequence would go with that
// acknowledgement: a FIN the source's kernel dropped would never be sent
// again, the ring would empty under the parked drain, and the flow would end
// with neither FIN nor reset, so a download that ends by closing never reaches
// its end of stream. The wrapped rows wrap halfway through the second segment,
// and right after the data, where the FIN's sequence byte is the last in the
// space and its end is zero.
func TestTcpReturnRetransmitKeepsTheFinUntilItsOwnSequenceByteIsAcknowledged(t *testing.T) {
	for _, initialSynSeq := range []uint32{
		0,
		tcpReturnTestInitialSynSeqWrappingAfter(tcpReturnTestSegmentByteCount + tcpReturnTestSegmentByteCount/2),
		tcpReturnTestInitialSynSeqWrappingAfter(2*tcpReturnTestSegmentByteCount + 1),
	} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq})
			// the data is still outstanding when the FIN goes
			harness.source.holdAcks = true
			payload := harness.payload(2)
			harness.write(payload)
			synctest.Wait()

			finSeq := harness.segmentSeq(2)
			harness.source.dropCounts[finSeq] = 1
			harness.closeUpstream()
			synctest.Wait()
			retainedByteCount, retainedCount, _, _ := harness.retransmitState()
			if retainedByteCount != int64(len(payload))+1 || retainedCount != 3 {
				// not fatal: what follows shows what the missing byte costs
				t.Errorf("retained %d bytes in %d segments, want the two segments and the FIN's sequence byte", retainedByteCount, retainedCount)
			}

			// the data alone, which is the whole frontier of a source whose
			// kernel dropped the FIN
			ackAt := time.Now()
			harness.source.stateLock.Lock()
			harness.source.holdAcks = false
			harness.source.stateLock.Unlock()
			harness.source.sendAck(finSeq)
			synctest.Wait()
			retainedByteCount, retainedCount, _, _ = harness.retransmitState()
			if retainedByteCount != 1 || retainedCount != 1 {
				t.Errorf("retained %d bytes in %d segments after the data was acknowledged, want the FIN's sequence byte alone", retainedByteCount, retainedCount)
			}
			if harness.runIsDone() {
				t.Fatal("the sequence ended on the data acknowledgement, with the FIN never sent again")
			}
			if got := harness.source.seenCount(finSeq); got != 1 {
				t.Fatalf("FIN delivered %d times before the timer, want 1", got)
			}

			// that acknowledgement sampled the round trip, which is nothing in
			// virtual time, so the timer stands at its floor
			harness.waitRunDone(2 * returnRetransmitMinRto)

			times := harness.source.deliveryTimes(finSeq)
			if len(times) != 2 {
				t.Fatalf("FIN delivered %d times, want 2", len(times))
			}
			if got := times[1].Sub(ackAt); got != returnRetransmitMinRto {
				t.Fatalf("FIN retransmitted at +%s after the data was acknowledged, want +%s", got, returnRetransmitMinRto)
			}
			harness.source.stateLock.Lock()
			finReceived, rstReceived := harness.source.finReceived, harness.source.rstReceived
			harness.source.stateLock.Unlock()
			if !finReceived || rstReceived {
				t.Fatalf("fin=%t rst=%t, want the FIN accepted and no reset", finReceived, rstReceived)
			}
			harness.requireStream(payload)
			retainedByteCount, retainedCount, packetCount, reasonCounts := harness.retransmitState()
			if retainedByteCount != 0 || retainedCount != 0 {
				t.Fatalf("retained after the FIN was acknowledged: %d bytes in %d segments", retainedByteCount, retainedCount)
			}
			if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonTimeout] != 1 {
				t.Fatalf("retransmissions=%d reasons=%v, want the FIN once on the timer", packetCount, reasonCounts)
			}
		})
	}
}

// Establishes a flow whose upstream has sent its FIN, unacknowledged and
// held in retention, with the delivery drain parked waiting for that
// acknowledgement, on an upstream whose Close takes time.
// The drain waits for the retained ring at both of its ends. Its loop reads
// the socket reader's queue from two places — the outer wait for the next
// packet and the inner drain that fills a batch — and either can be the one
// that finds the queue closed. The tests above always end on the inner one,
// because the reader closes the queue while the drain is still inside the
// batch that carries the FIN. The outer one is reached when the batch is
// finished from the queue instead: here the first segment's tunnel write holds
// the drain while the reader queues the rest of the flight, adds its FIN and
// closes, so the next batch fills to its size from the queue and the close is
// found by the outer read. Without the wait there the sequence cancels behind
// a delivered FIN with a hole still retained, and the source's download ends
// one segment short.
func TestTcpReturnRetransmitDrainWaitsForTheRingWhenTheReaderClosesFirst(t *testing.T) {
	// the flight after the stalled first segment, one short of the batch, so
	// the FIN fills it
	const flightCount = 3
	const holeIndex = 2
	const stall = 10 * time.Millisecond
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		if harness.settings.WriteBatchSize != 1+flightCount {
			t.Fatalf("batch size %d, want %d so the FIN fills the second batch", harness.settings.WriteBatchSize, 1+flightCount)
		}
		harness.source.stallDurations[harness.segmentSeq(0)] = stall
		harness.source.dropCounts[harness.segmentSeq(holeIndex)] = 1
		start := time.Now()
		payload := harness.payload(1 + flightCount)
		// the first segment alone, whose write holds the drain
		harness.writeSegments(payload, 0, 1)

		// everything else, and the reader's close, while the drain is held:
		// the queue takes the flight and the FIN, and the batch that carries
		// them is full without the closed queue being read
		harness.write(payload[harness.segmentByteCount:])
		harness.closeUpstream()
		synctest.Wait()

		time.Sleep(stall)
		synctest.Wait()
		if harness.runIsDone() {
			t.Fatal("the sequence ended with a hole still retained behind the delivered FIN")
		}
		finSeq := harness.segmentSeq(1 + flightCount)
		if got := harness.source.seenCount(finSeq); got != 1 {
			t.Fatalf("the FIN at %d was delivered %d times with the flight, want once", finSeq, got)
		}
		harness.requireSeenCount(holeIndex, 1)

		// only one segment and the FIN came behind the hole, so the
		// duplicates never reach the threshold and the timer repairs it (see
		// the file header for the initial timer)
		harness.waitRunDone(2 * returnRetransmitInitialRto)
		harness.requireSeenCount(holeIndex, 2)
		if got, want := harness.requireDelivery(harness.segmentSeq(holeIndex), 1).at.Sub(start), stall+returnRetransmitInitialRto; got != want {
			t.Fatalf("the hole was repaired at +%s, want +%s, one timer after the batch", got, want)
		}
		harness.source.stateLock.Lock()
		finReceived, rstReceived := harness.source.finReceived, harness.source.rstReceived
		harness.source.stateLock.Unlock()
		if !finReceived || rstReceived {
			t.Fatalf("fin=%t rst=%t, want the FIN accepted behind the repaired hole and no reset", finReceived, rstReceived)
		}
		harness.requireStream(payload)
		retainedByteCount, retainedCount, packetCount, reasonCounts := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the drain: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
		if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonTimeout] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v, want the hole once on the timer", packetCount, reasonCounts)
		}
	})
}

func newTcpReturnRetransmitTestHarnessWithParkedDrain(t *testing.T, configure func(*TcpBufferSettings)) *tcpReturnRetransmitTestHarness {
	t.Helper()
	harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
		upstreamCloseDelay: 20 * time.Millisecond,
		configure:          configure,
	})
	payload := harness.payload(2)
	harness.write(payload)
	synctest.Wait()
	harness.source.holdAcks = true
	harness.closeUpstream()
	synctest.Wait()
	if harness.runIsDone() {
		t.Fatal("the sequence ended with the FIN unacknowledged")
	}
	return harness
}

// The flow ends while the drain is parked on the retained FIN, by the
// source's reset: the sequence must end, every worker with it, and every
// share must come back. Before the fix the drain was woken once, before the
// cancel, waited again, and nothing ever woke it, so Run never returned and
// the flow's slot and shares were held for ever.
func TestTcpReturnRetransmitParkedDrainEndsOnSourceReset(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarnessWithParkedDrain(t, nil)
		harness.sendRstFromSource()
		harness.waitRunDone(time.Second)
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the end: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
		harness.close()
	})
}

// The same with the flow ended by the idle timer rather than the source.
func TestTcpReturnRetransmitParkedDrainEndsOnIdleTimeout(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		const idleTimeout = 2 * time.Second
		harness := newTcpReturnRetransmitTestHarnessWithParkedDrain(t, func(settings *TcpBufferSettings) {
			settings.IdleTimeout = idleTimeout
			// the idle timer must be the thing that ends this flow
			settings.ReturnRetransmitTimeout = time.Minute
		})
		// the idle condition closes on the first interval with no update
		// since its checkpoint, which is the second interval here: the
		// handshake and data acknowledgements moved it during the first
		harness.waitRunDone(2*idleTimeout + time.Second)
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the end: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
		harness.close()
	})
}

// An upstream that fails rather than closing resets the flow toward the
// source, and a reset is never repaired: the retained ring goes with it,
// while the source is still acknowledging nothing. Without that release the
// drain parks on a ring no acknowledgement will ever empty, the worker goes
// on retransmitting data behind a reset the source has already seen, and the
// flow holds its pool shares and its slot until the no-progress bound two
// minutes later. The upstream fails here by a read timeout, which is the
// socket reader's ordinary non-EOF exit, shared with its socket errors.
func TestTcpReturnRetransmitUpstreamFailureReleasesTheRetainedRing(t *testing.T) {
	const segmentCount = 2
	// well inside the timer before a round-trip sample, so nothing is due
	const readTimeout = 100 * time.Millisecond
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			configure: func(settings *TcpBufferSettings) {
				settings.ReadTimeout = readTimeout
			},
		})
		// the ring is full of segments the source has not acknowledged when
		// the upstream fails
		harness.source.holdAcks = true
		start := time.Now()
		payload := harness.payload(segmentCount)
		harness.write(payload)
		synctest.Wait()
		if _, retainedCount, _, _ := harness.retransmitState(); retainedCount != segmentCount {
			t.Fatalf("%d segments retained before the upstream failed, want %d", retainedCount, segmentCount)
		}

		// the upstream's read times out here and the reset follows it
		time.Sleep(readTimeout)
		synctest.Wait()

		harness.source.stateLock.Lock()
		rstReceived, rstAt := harness.source.rstReceived, harness.source.rstAt
		harness.source.stateLock.Unlock()
		if !rstReceived {
			t.Fatal("the source was never reset when the upstream failed")
		}
		if got := rstAt.Sub(start); got != readTimeout {
			t.Fatalf("reset at +%s, want +%s when the upstream read timed out", got, readTimeout)
		}
		retainedByteCount, retainedCount, packetCount, reasonCounts := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			// not fatal: the flow's end below is what the retained ring costs
			t.Errorf("retained behind the reset: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
		if packetCount != 0 {
			t.Fatalf("retransmissions=%d reasons=%v behind the reset, want none", packetCount, reasonCounts)
		}
		// nothing is left waiting for an acknowledgement that cannot come:
		// well before the timer's first expiry, and far inside the
		// no-progress bound that is the only other way out
		harness.waitRunDone(returnRetransmitInitialRto / 2)
		for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex += 1 {
			harness.requireSeenCount(segmentIndex, 1)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 || stats.AbandonCount != 0 {
			t.Fatalf("stats=%+v, want the reset to end the flow, not the timer or the bound", stats)
		}
	})
}

// A selectively acknowledged segment stays retained until the cumulative
// acknowledgement covers it: a source that reports segments and then
// discards them gets every one of them again from retention. Forgetting on
// selective acknowledgement would leave the discarded segments unrecoverable.
// Every segment reaches the source before the hole's retransmission does, so
// the discard takes all of them; with acknowledgements sent inside delivery,
// the last original could arrive after the discard, and about one run in
// 1,500 it did and was never needed again.
func TestTcpReturnRetransmitSackedSegmentsStayRetainedUntilCumulativeAck(t *testing.T) {
	const segmentCount = 6
	for _, initialSynSeq := range tcpReturnTestInitialSynSeqs(tcpReturnTestOptions{}, 2, 4) {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq, sack: true})
			harness.source.dropCounts[harness.segmentSeq(1)] = 1
			// the hole's retransmission is the next in-order arrival, and the
			// source drops its whole out-of-order queue when it comes
			harness.source.renegeOnce = true
			harness.source.holdAcks = true

			payload := harness.payload(segmentCount)
			harness.write(payload)
			synctest.Wait()
			// the source reports every segment past the hole, and the third
			// duplicate sends the hole
			harness.source.sendAck(harness.segmentSeq(1))
			for range returnRetransmitDupAckThreshold {
				harness.source.sendDuplicateAck()
			}
			synctest.Wait()
			harness.requireSeenCount(1, 2)
			// the acknowledgement of the hole stops short of the segments the
			// source reported, and the partial acknowledgements that follow
			// send each of them again at once
			harness.source.ackNow()
			synctest.Wait()

			harness.requireStream(payload)
			harness.requireSeenCount(0, 1)
			for segmentIndex := 1; segmentIndex < segmentCount; segmentIndex += 1 {
				harness.requireSeenCount(segmentIndex, 2)
			}
			retainedByteCount, retainedCount, packetCount, reasonCounts := harness.retransmitState()
			if retainedByteCount != 0 || retainedCount != 0 {
				t.Fatalf("retained after full acknowledgement: %d bytes in %d segments", retainedByteCount, retainedCount)
			}
			if packetCount != segmentCount-1 ||
				reasonCounts[tcpReturnRetransmitReasonSackHole] != 1 ||
				reasonCounts[tcpReturnRetransmitReasonPartialAck] != segmentCount-2 {
				t.Fatalf("retransmissions=%d reasons=%v, want the hole on sack and each discarded segment once on partial acknowledgements", packetCount, reasonCounts)
			}
			if stats := harness.counters.snapshot(); stats.TimeoutCount != 0 {
				t.Fatalf("stats=%+v, want no timer expiry", stats)
			}
		})
	}
}

// The retransmitted pieces of one retained segment, as the source saw them:
// every delivery after the first `originalCount`, which must all lie inside
// the segment at `segmentIndex`.
func tcpReturnTestRetransmittedPieces(
	t *testing.T,
	harness *tcpReturnRetransmitTestHarness,
	originalCount int,
	segmentIndex int,
) []tcpReturnTestSegment {
	t.Helper()
	harness.source.stateLock.Lock()
	defer harness.source.stateLock.Unlock()
	start := harness.segmentSeq(segmentIndex)
	if len(harness.source.segments) < originalCount {
		t.Fatalf("%d deliveries, fewer than the %d originals", len(harness.source.segments), originalCount)
	}
	pieces := append([]tcpReturnTestSegment(nil), harness.source.segments[originalCount:]...)
	for _, piece := range pieces {
		if offset := int(int32(piece.seq - start)); offset < 0 || harness.segmentByteCount <= offset {
			t.Fatalf("a retransmission at %d lies outside segment %d at %d", piece.seq, segmentIndex, start)
		}
	}
	return pieces
}

// Requires `pieces` to be the segment at `segmentIndex` cut as packetization
// cuts at `pathMtu`: consecutive from its start, every piece but the last
// exactly filling the path mtu, and together its exact bytes.
func requireTcpReturnTestPiecesAtPathMtu(
	t *testing.T,
	harness *tcpReturnRetransmitTestHarness,
	pieces []tcpReturnTestSegment,
	payload []byte,
	segmentIndex int,
	pathMtu int,
	timestamps bool,
) {
	t.Helper()
	headerByteCount := Ipv4HeaderSizeWithoutExtensions + TcpHeaderSizeWithoutExtensions
	if harness.ipVersion == 6 {
		headerByteCount = Ipv6HeaderSize + TcpHeaderSizeWithoutExtensions
	}
	if timestamps {
		headerByteCount += tcpTimestampOptionByteCount
	}
	pieceByteCount := pathMtu - headerByteCount
	wantPieceCount := (harness.segmentByteCount + pieceByteCount - 1) / pieceByteCount
	if len(pieces) != wantPieceCount {
		t.Fatalf("segment %d sent again in %d packets, want %d pieces of at most %d bytes", segmentIndex, len(pieces), wantPieceCount, pieceByteCount)
	}
	var reassembled []byte
	for pieceIndex, piece := range pieces {
		if pathMtu < piece.packetByteCount {
			t.Fatalf("piece %d is a %d byte packet, above the path mtu %d", pieceIndex, piece.packetByteCount, pathMtu)
		}
		if pieceIndex < len(pieces)-1 && piece.packetByteCount != pathMtu {
			t.Fatalf("piece %d is a %d byte packet, want the path mtu %d exactly", pieceIndex, piece.packetByteCount, pathMtu)
		}
		if wantSeq := harness.segmentSeq(segmentIndex) + uint32(len(reassembled)); piece.seq != wantSeq {
			t.Fatalf("piece %d at %d, want %d", pieceIndex, piece.seq, wantSeq)
		}
		if timestamps && piece.timestampValue == 0 {
			t.Fatalf("piece %d carries no timestamp", pieceIndex)
		}
		reassembled = append(reassembled, piece.payload...)
	}
	segmentStart := segmentIndex * harness.segmentByteCount
	if !bytes.Equal(reassembled, payload[segmentStart:segmentStart+harness.segmentByteCount]) {
		t.Fatalf("pieces carry %d bytes, want segment %d's %d exact", len(reassembled), segmentIndex, harness.segmentByteCount)
	}
}

// The source reports a smaller path mtu after a burst was packetized at the
// configured one, and then drops a segment of that burst: the path drops
// anything larger than it reported, so fast retransmit sends the segment as
// consecutive pieces cut as packetization cuts now, for either address family
// and with or without the timestamp option, and the source reassembles the
// exact bytes. The acknowledgements of the first pieces end inside the
// segment and send nothing more, since the rest are in flight. Sent whole, the
// retransmission was dropped on every trigger until the bound reset the flow.
// The wrapped rows wrap inside the first piece, so the acknowledgements of
// the pieces end numerically below where the segment starts, and still end
// inside it.
func TestTcpReturnRetransmitCutsARetransmissionToTheReportedPathMtu(t *testing.T) {
	const segmentCount = 4
	// 100 bytes into the dropped segment, inside its first piece
	wrapInFirstPiece := func(options tcpReturnTestOptions) uint32 {
		return tcpReturnTestInitialSynSeqWrappingAfter(tcpReturnTestSegmentByteCountFor(options) + 100)
	}
	for _, c := range []struct {
		ipVersion     int
		timestamps    bool
		pathMtu       int
		initialSynSeq uint32
	}{
		// the family floors: three pieces for IPv4, the last short, and two
		// for IPv6
		{ipVersion: 4, timestamps: false, pathMtu: ipv4MinimumPathMtu},
		{ipVersion: 4, timestamps: true, pathMtu: ipv4MinimumPathMtu},
		{ipVersion: 6, timestamps: false, pathMtu: ipv6MinimumPathMtu},
		{ipVersion: 6, timestamps: true, pathMtu: ipv6MinimumPathMtu},
		{
			ipVersion:     4,
			timestamps:    false,
			pathMtu:       ipv4MinimumPathMtu,
			initialSynSeq: wrapInFirstPiece(tcpReturnTestOptions{}),
		},
		{
			ipVersion:     4,
			timestamps:    true,
			pathMtu:       ipv4MinimumPathMtu,
			initialSynSeq: wrapInFirstPiece(tcpReturnTestOptions{timestamps: true}),
		},
		{
			ipVersion:     6,
			timestamps:    true,
			pathMtu:       ipv6MinimumPathMtu,
			initialSynSeq: wrapInFirstPiece(tcpReturnTestOptions{ipVersion: 6, timestamps: true}),
		},
	} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("IPv%d timestamps=%t path mtu %d initial sequence %d", c.ipVersion, c.timestamps, c.pathMtu, c.initialSynSeq)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
				ipVersion:     c.ipVersion,
				timestamps:    c.timestamps,
				initialSynSeq: c.initialSynSeq,
			})
			harness.source.dropCounts[harness.segmentSeq(1)] = 1
			// acknowledgements go one at a time below, with the worker run
			// between them as it runs between arrivals
			harness.source.holdAcks = true
			start := time.Now()
			payload := harness.payload(segmentCount)
			harness.write(payload)
			synctest.Wait()
			if original := harness.requireDelivery(harness.segmentSeq(1), 0); original.packetByteCount != tcpReturnTestMtu {
				t.Fatalf("IPv%d: the original is a %d byte packet, want the configured mtu %d", c.ipVersion, original.packetByteCount, tcpReturnTestMtu)
			}

			harness.source.stateLock.Lock()
			harness.source.pathMtu = c.pathMtu
			harness.source.stateLock.Unlock()
			harness.sequence.applyPathMtu(c.pathMtu)

			harness.source.sendAck(harness.segmentSeq(1))
			for range returnRetransmitDupAckThreshold {
				harness.source.sendDuplicateAck()
			}
			synctest.Wait()

			pieces := tcpReturnTestRetransmittedPieces(t, harness, segmentCount, 1)
			requireTcpReturnTestPiecesAtPathMtu(t, harness, pieces, payload, 1, c.pathMtu, c.timestamps)
			for _, piece := range pieces {
				if !piece.at.Equal(start) {
					t.Fatalf("IPv%d: piece at +%s, want at once on the duplicates", c.ipVersion, piece.at.Sub(start))
				}
			}
			ackNumber := harness.segmentSeq(1)
			for _, piece := range pieces[:len(pieces)-1] {
				ackNumber += uint32(len(piece.payload))
				harness.source.sendAck(ackNumber)
				synctest.Wait()
			}
			// the last piece fills the hole, and the source held the rest
			harness.source.sendAck(harness.segmentSeq(segmentCount))
			synctest.Wait()

			harness.requireStream(payload)
			if got := tcpReturnTestRetransmittedPieces(t, harness, segmentCount, 1); len(got) != len(pieces) {
				t.Fatalf("IPv%d: %d packets sent again after the pieces were acknowledged, want none", c.ipVersion, len(got)-len(pieces))
			}
			retainedByteCount, retainedCount, packetCount, reasonCounts := harness.retransmitState()
			if retainedByteCount != 0 || retainedCount != 0 {
				t.Fatalf("IPv%d: retained after full acknowledgement: %d bytes in %d segments", c.ipVersion, retainedByteCount, retainedCount)
			}
			if packetCount != int64(len(pieces)) || reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 ||
				reasonCounts[tcpReturnRetransmitReasonPartialAck] != 0 {
				t.Fatalf("IPv%d: retransmissions=%d reasons=%v, want the segment once on duplicates, in %d pieces", c.ipVersion, packetCount, reasonCounts, len(pieces))
			}
			if stats := harness.counters.snapshot(); stats.PacketCount != int64(len(pieces)) || stats.ByteCount != ByteCount(harness.segmentByteCount) {
				t.Fatalf("IPv%d: stats=%+v, want %d packets carrying one segment", c.ipVersion, stats, len(pieces))
			}
		})
	}
}

// A path that stopped carrying the configured mtu before a flight left, and
// the source's report of it after the flight was packetized: the source holds
// nothing, and no later segment exists to draw a duplicate. The timer's probe
// sends the head in pieces, and the acknowledgement of each ends no further
// than the head, so the probe stays undecided with its timer doubled instead
// of calling the expiry spurious; the second expiry shows the loss real and
// the rest of the flight recovers in bursts at once, each segment sent again
// once, in pieces. Read as spurious on the second piece's acknowledgement,
// each expiry recovered one segment. The wrapped row wraps between the end of
// the head's first piece and the end of its second, so the first piece's
// acknowledgement ends numerically above the head's end, and still short of
// it.
func TestTcpReturnRetransmitProbeHeadAcknowledgedInPiecesDecidesNothing(t *testing.T) {
	for _, initialSynSeq := range []uint32{0, tcpReturnTestInitialSynSeqWrappingAfter(1000)} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("initial sequence %d", initialSynSeq)
			const segmentCount = 8
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{initialSynSeq: initialSynSeq})
			harness.source.stateLock.Lock()
			harness.source.pathMtu = ipv4MinimumPathMtu
			harness.source.stateLock.Unlock()
			start := time.Now()
			payload := harness.payload(segmentCount)
			harness.write(payload)
			synctest.Wait()
			harness.sequence.applyPathMtu(ipv4MinimumPathMtu)

			time.Sleep(returnRetransmitInitialRto)
			synctest.Wait()
			pieces := tcpReturnTestRetransmittedPieces(t, harness, segmentCount, 0)
			requireTcpReturnTestPiecesAtPathMtu(t, harness, pieces, payload, 0, ipv4MinimumPathMtu, false)
			if rto, _ := harness.retransmitTimer(); rto != 2*returnRetransmitInitialRto {
				t.Fatalf("timer %s after the pieces of the head were acknowledged, want the backoff kept at %s", rto, 2*returnRetransmitInitialRto)
			}

			time.Sleep(2 * returnRetransmitInitialRto)
			synctest.Wait()
			harness.requireStream(payload)
			harness.source.stateLock.Lock()
			frontierAt := harness.source.frontierAt
			retransmitted := append([]tcpReturnTestSegment(nil), harness.source.segments[segmentCount:]...)
			harness.source.stateLock.Unlock()
			if got, want := frontierAt.Sub(start), 3*returnRetransmitInitialRto; got != want {
				t.Fatalf("flight recovered at +%s, want +%s at the second expiry", got, want)
			}
			for _, piece := range retransmitted {
				if ipv4MinimumPathMtu < piece.packetByteCount {
					t.Fatalf("a %d byte packet at %d sent again, above the path mtu", piece.packetByteCount, piece.seq)
				}
			}
			for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex += 1 {
				harness.requireSeenCount(segmentIndex, 2)
			}
			_, _, packetCount, reasonCounts := harness.retransmitState()
			if packetCount != int64(segmentCount*len(pieces)) ||
				reasonCounts[tcpReturnRetransmitReasonTimeout] != 2 ||
				reasonCounts[tcpReturnRetransmitReasonPartialAck] != segmentCount-2 {
				t.Fatalf("retransmissions=%d reasons=%v, want two heads on the timer and the rest once on partial acknowledgements, %d pieces each", packetCount, reasonCounts, len(pieces))
			}
			if stats := harness.counters.snapshot(); stats.TimeoutCount != 2 || stats.AbandonCount != 0 {
				t.Fatalf("stats=%+v, want two timeouts and no abandon", stats)
			}
		})
	}
}

// A source that negotiates timestamps, as Linux does by default: every packet
// toward it carries the twelve-byte option ahead of the payload, and every
// segment twelve fewer payload bytes. A segment its kernel drops, with or
// without SACK, and repaired by duplicate acknowledgements, by the timer, or
// in pieces after a smaller path mtu, reaches the source as exactly the
// payload's bytes at the segment's offset. Every packet sent again carries a
// timestamp value advanced by exactly the virtual time since the original and
// echoes the newest timestamp the source sent, which an acknowledgement or a
// window update after the original moved, never the original's options. A
// retained payload located as if the option were absent, or packets sized
// without it, put the option's bytes into the stream. Before the path mtu
// rows no test negotiated timestamps, and none has checked what a
// retransmission's option carries.
func TestTcpReturnRetransmitWithTimestampsSendsExactBytesAndCurrentTimestamps(t *testing.T) {
	const segmentCount = 4
	// how long after the originals the acknowledgement-driven rows repair the
	// loss, and the timer row's window update comes: inside the timer
	const repairDelay = 300 * time.Millisecond
	for _, c := range []struct {
		ipVersion int
		sack      bool
		// "duplicates", "timer" or "pieces"
		recovery string
	}{
		{ipVersion: 4, sack: false, recovery: "duplicates"},
		{ipVersion: 4, sack: true, recovery: "duplicates"},
		{ipVersion: 4, sack: false, recovery: "timer"},
		{ipVersion: 4, sack: true, recovery: "timer"},
		{ipVersion: 4, sack: false, recovery: "pieces"},
		{ipVersion: 4, sack: true, recovery: "pieces"},
		{ipVersion: 6, sack: true, recovery: "pieces"},
	} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			t.Logf("IPv%d sack=%t recovery by %s", c.ipVersion, c.sack, c.recovery)
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
				ipVersion:  c.ipVersion,
				sack:       c.sack,
				timestamps: true,
			})
			// the timer's head is the first segment; the acknowledgements
			// repair the second
			lostIndex := 1
			if c.recovery == "timer" {
				lostIndex = 0
			}
			lostSeq := harness.segmentSeq(lostIndex)
			harness.source.dropCounts[lostSeq] = 1
			harness.source.holdAcks = true
			payload := harness.payload(segmentCount)
			harness.write(payload)
			synctest.Wait()
			first := harness.requireDelivery(harness.segmentSeq(0), 0)
			withoutTimestampsByteCount := tcpReturnTestSegmentByteCountFor(tcpReturnTestOptions{ipVersion: c.ipVersion})
			if first.packetByteCount != tcpReturnTestMtu || len(first.payload) != withoutTimestampsByteCount-tcpTimestampOptionByteCount {
				t.Fatalf("the first segment is a %d byte packet carrying %d bytes, want the %d byte mtu carrying twelve fewer than %d", first.packetByteCount, len(first.payload), tcpReturnTestMtu, withoutTimestampsByteCount)
			}
			original := harness.requireDelivery(lostSeq, 0)
			if original.timestampValue == 0 {
				t.Fatal("the original carries no timestamp")
			}
			pathMtu := ipv4MinimumPathMtu
			if c.ipVersion == 6 {
				pathMtu = ipv6MinimumPathMtu
			}
			if c.recovery == "pieces" {
				harness.source.stateLock.Lock()
				harness.source.pathMtu = pathMtu
				harness.source.stateLock.Unlock()
				harness.sequence.applyPathMtu(pathMtu)
			}

			time.Sleep(repairDelay)
			switch c.recovery {
			case "timer":
				harness.source.sendWindowUpdate(16)
				time.Sleep(returnRetransmitInitialRto - repairDelay)
			default:
				harness.source.sendAck(lostSeq)
				for range returnRetransmitDupAckThreshold {
					harness.source.sendDuplicateAck()
				}
			}
			repairAt := time.Now()
			harness.source.stateLock.Lock()
			wantEcho := harness.source.lastAckTimestampValue
			harness.source.stateLock.Unlock()
			if wantEcho == original.timestampEcho {
				t.Fatalf("the source's newest timestamp %d is the original's echo, so this row cannot tell them apart", wantEcho)
			}
			synctest.Wait()

			retransmitted := tcpReturnTestRetransmittedPieces(t, harness, segmentCount, lostIndex)
			if c.recovery == "pieces" {
				requireTcpReturnTestPiecesAtPathMtu(t, harness, retransmitted, payload, lostIndex, pathMtu, true)
			} else if len(retransmitted) != 1 || len(retransmitted[0].payload) != harness.segmentByteCount {
				t.Fatalf("segment %d sent again in %d packets, want once whole", lostIndex, len(retransmitted))
			}
			wantValue := original.timestampValue + uint32(repairAt.Sub(original.at)/time.Millisecond)
			for index, packet := range retransmitted {
				if !packet.at.Equal(repairAt) {
					t.Fatalf("packet %d sent again at +%s, want +%s", index, packet.at.Sub(original.at), repairAt.Sub(original.at))
				}
				if packet.timestampValue != wantValue {
					t.Fatalf("packet %d sent again with timestamp %d, want %d, the original's %d advanced by %s", index, packet.timestampValue, wantValue, original.timestampValue, repairAt.Sub(original.at))
				}
				if packet.timestampEcho != wantEcho {
					t.Fatalf("packet %d sent again echoing %d, want the source's newest %d (the original echoed %d)", index, packet.timestampEcho, wantEcho, original.timestampEcho)
				}
			}

			harness.source.ackNow()
			synctest.Wait()
			harness.requireStream(payload)
			retainedByteCount, retainedCount, packetCount, reasonCounts := harness.retransmitState()
			if retainedByteCount != 0 || retainedCount != 0 {
				t.Fatalf("retained after full acknowledgement: %d bytes in %d segments", retainedByteCount, retainedCount)
			}
			wantReason := tcpReturnRetransmitReasonDupAck
			switch {
			case c.recovery == "timer":
				wantReason = tcpReturnRetransmitReasonTimeout
			case c.sack:
				wantReason = tcpReturnRetransmitReasonSackHole
			}
			if packetCount != int64(len(retransmitted)) || reasonCounts[wantReason] != 1 {
				t.Fatalf("retransmissions=%d reasons=%v, want segment %d once on %s in %d packets", packetCount, reasonCounts, lostIndex, wantReason, len(retransmitted))
			}
			if stats := harness.counters.snapshot(); stats.ByteCount != ByteCount(harness.segmentByteCount) {
				t.Fatalf("stats=%+v, want one segment of %d bytes sent again", stats, harness.segmentByteCount)
			}
		})
	}
}

// (g) Ownership across loss, selective acknowledgement, the FIN and the
// bound's reset: every pooled buffer the sequence took or shared is back
// exactly once. The harness reconciles at close; this test says so
// explicitly and drives the paths that hold shares longest.
func TestTcpReturnRetransmitReturnsEveryPooledBufferOnce(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
			sack: true,
			configure: func(settings *TcpBufferSettings) {
				settings.ReturnRetransmitTimeout = 5 * time.Second
			},
		})
		harness.source.dropCounts[harness.segmentSeq(2)] = 1
		harness.write(harness.payload(6))
		synctest.Wait()

		// the tail is never acknowledged: the FIN and the last segments are
		// held in retention until the bound resets the flow
		harness.source.holdAcks = true
		harness.write(harness.payload(3))
		synctest.Wait()
		harness.closeUpstream()
		harness.waitRunDone(time.Minute)

		harness.source.stateLock.Lock()
		rstReceived := harness.source.rstReceived
		harness.source.stateLock.Unlock()
		if !rstReceived {
			t.Fatal("the bound did not reset the flow")
		}
		harness.close()

		taken, returned, _ := MessagePoolCounts()
		if outstanding := int64(taken-returned) - int64(harness.poolTaken-harness.poolReturned); outstanding != 0 {
			t.Fatalf("pool roots outstanding: %d, want 0", outstanding)
		}
		if violations := MessagePoolViolationCount() - harness.violations; violations != 0 {
			t.Fatalf("pool ownership violations: %d, want 0", violations)
		}
	})
}
