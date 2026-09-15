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

// One acknowledgement on its way to the sequence.
type tcpReturnTestDelayedAck struct {
	ackNumber uint32
	at        time.Time
}

// A segment the sequence sent toward the source, as the source model saw it.
type tcpReturnTestSegment struct {
	seq     uint32
	payload []byte
	fin     bool
	rst     bool
	// the timestamp option, when the segment carried one
	timestampValue uint32
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
	// the harness's pump sends them from `delayedAcks`
	ackDelay    time.Duration
	delayedAcks chan tcpReturnTestDelayedAck

	stateLock sync.Mutex
	// while held, nothing is acknowledged; released by ackNow
	holdAcks bool
	rcvNxt   uint32
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
	// scaled units the advertised window has grown by since the handshake;
	// every acknowledgement carries it
	windowGrowth uint16
}

func (self *tcpReturnTestSource) receive(segment tcpReturnTestSegment) {
	var ackPacket []byte
	var ackTcp parsedTcp
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
			select {
			case self.delayedAcks <- tcpReturnTestDelayedAck{ackNumber: self.rcvNxt, at: segment.at.Add(self.ackDelay)}:
			default:
				self.harness.t.Errorf("delayed acknowledgement queue full")
			}
			return
		}
		ackPacket, ackTcp = self.buildAckWithLock(self.rcvNxt)
	}()
	if ackPacket != nil {
		self.harness.sendFromSource(&ackTcp, ackPacket)
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

// Builds one pure acknowledgement at `ackNumber`, with SACK blocks for the
// out-of-order runs when negotiated, a timestamp when negotiated, and the
// current window. The lock must be held.
func (self *tcpReturnTestSource) buildAckWithLock(ackNumber uint32) ([]byte, parsedTcp) {
	var blocks []tcpSackBlock
	if self.sack {
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
	}
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
		binary.BigEndian.PutUint32(options[4:8], uint32(time.Since(tcpTimestampEpoch)/time.Millisecond)+1)
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
		seq:        self.harness.dataSeq,
		ack:        true,
		ackNumber:  ackNumber,
		windowSize: uint16(tcpReturnTestWindowByteCount>>tcpReturnTestWindowScale) - 64 + self.windowGrowth,
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
		ackPacket, ackTcp = self.buildAckWithLock(self.rcvNxt)
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
		ackPacket, ackTcp = self.buildAckWithLock(ackNumber)
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
		ackPacket, ackTcp = self.buildAckWithLock(self.lastAckNumber)
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
		ackPacket, ackTcp = self.buildAckWithLock(self.lastAckNumber)
	}()
	self.harness.sendFromSource(&ackTcp, ackPacket)
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
	ipVersion  int
	sack       bool
	timestamps bool
	// zero is the default well inside the sequence space
	initialSynSeq uint32
	// the scale the source's SYN negotiates; zero is tcpReturnTestWindowScale,
	// and every acknowledgement advertises almost the whole field at it
	windowScale uint32
	// how long the sequence's Close of its upstream takes
	upstreamCloseDelay time.Duration
	// how long each acknowledgement the source sends takes to arrive; zero
	// acknowledges inside the delivery callback
	ackDelay  time.Duration
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
	runDone          chan struct{}
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
	segmentByteCount := tcpReturnTestSegmentByteCount
	if ipVersion == 6 {
		segmentByteCount -= Ipv6HeaderSize - Ipv4HeaderSizeWithoutExtensions
	}
	if options.timestamps {
		segmentByteCount -= tcpTimestampOptionByteCount
	}
	// one socket read is eight segments
	settings.ReadBufferByteCount = 8 * segmentByteCount
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
		harness:       harness,
		sack:          options.sack,
		timestamps:    options.timestamps,
		ackDelay:      options.ackDelay,
		rcvNxt:        harness.dataSeq,
		lastAckNumber: harness.dataSeq,
		dropCounts:    map[uint32]int{},
		seenCounts:    map[uint32]int{},
	}
	if 0 < options.ackDelay {
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
					harness.source.sendAck(delayed.ackNumber)
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
			harness.source.receive(tcpReturnTestSegment{
				seq:             tcp.seq,
				payload:         append([]byte(nil), tcp.payload...),
				fin:             tcp.fin,
				rst:             tcp.rst,
				timestampValue:  tcp.timestampValue,
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
		binary.BigEndian.PutUint32(synOptions[8:12], 1)
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
	// the handshake's acknowledgement, which established flows apply directly
	harness.source.ackNow()

	t.Cleanup(harness.close)
	return harness
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

func (self *tcpReturnRetransmitTestHarness) requireStream(want []byte) {
	self.t.Helper()
	if stream := self.source.streamCopy(); !bytes.Equal(stream, want) {
		self.t.Fatalf("stream has %d bytes, want %d exact", len(stream), len(want))
	}
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
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
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

// (b) Two separated segments dropped, with SACK: the third duplicate
// acknowledgement's blocks reveal both holes and only the holes are sent, at
// once, with no cumulative-progress round between them and nothing
// retransmitted on the duplicate acknowledgements that follow.
func TestTcpReturnRetransmitSackRetransmitsOnlyTheHoles(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{sack: true})
		harness.source.dropCounts[harness.segmentSeq(1)] = 1
		harness.source.dropCounts[harness.segmentSeq(3)] = 1

		payload := harness.payload(8)
		harness.write(payload)
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

// Two separated segments dropped, without SACK: the third duplicate
// acknowledgement fills the first hole, and the partial acknowledgement that
// answers it fills the second at once rather than waiting for three more
// duplicates that no new data would produce.
func TestTcpReturnRetransmitPartialAckFillsTheNextHole(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
		harness.source.dropCounts[harness.segmentSeq(1)] = 1
		harness.source.dropCounts[harness.segmentSeq(3)] = 1

		payload := harness.payload(8)
		harness.write(payload)
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
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
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
			if got := harness.source.deliveryTimes(harness.segmentSeq(0))[1].Sub(start); got != returnRetransmitInitialRto {
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

// A real expiry: the source's kernel dropped the whole flight, so the timer's
// head is the first segment it gets and its acknowledgement covers exactly
// that head. A segment sent after it arrives out of order and draws a
// duplicate, which shows the probe the loss is real: the remaining holes go
// on that duplicate and the partial acknowledgements that follow, at once,
// with no second expiry and each hole sent again exactly once.
func TestTcpReturnRetransmitRealTimeoutRecoversOnTheDuplicateAck(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		const flightCount = 4
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
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
			if got := harness.source.deliveryTimes(harness.segmentSeq(segmentIndex))[1].Sub(start); got != returnRetransmitInitialRto {
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

// The round trip of the loss-recovery burst tests, above the 200 ms hole
// interval floor so the interval is one round trip and would let the late
// acknowledgements of one burst resend its tail.
const tcpReturnTestBurstRoundTrip = 250 * time.Millisecond

// The source's view of a recovery that ran in bursts: the stream is exact,
// every segment in `lost` came again exactly once, and the in-order frontier
// reached the end within `maxRoundTripCount` round trips of `recoveryAt`.
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
	t.Logf("%d lost segments recovered in %.1f round trips", lostEndIndex-lostStartIndex, float64(recovery)/float64(tcpReturnTestBurstRoundTrip))
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
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		// with the later segments, inside one window of the source (see the
		// window constants)
		const segmentCount = 704
		const laterSegmentCount = 8
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{ackDelay: tcpReturnTestBurstRoundTrip})
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

		fastRetransmitAt := harness.source.deliveryTimes(harness.segmentSeq(1))[1]
		requireTcpReturnTestBurstRecovery(t, harness, payload, 2, segmentCount, fastRetransmitAt, 12)
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

// The same recovery after a real expiry: the source's kernel drops the whole
// flight after its first segment, so no duplicate acknowledgement ever comes.
// The expiry probes with the head, the source acknowledges exactly that head,
// and with nothing later to draw a duplicate the second expiry shows the loss
// real; from there the partial acknowledgements recover the rest in bursts,
// not one segment per acknowledgement.
func TestTcpReturnRetransmitLostFlightRecoversInBurstsAfterTheProbe(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		const segmentCount = 704
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{ackDelay: tcpReturnTestBurstRoundTrip})
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
		start := harness.source.deliveryTimes(harness.segmentSeq(0))[0]
		probeAt := harness.source.deliveryTimes(harness.segmentSeq(1))[1]
		if got, want := probeAt.Sub(start), tcpReturnTestBurstRoundTrip+rto; got != want {
			t.Fatalf("probe at +%s, want +%s", got, want)
		}
		lossAt := harness.source.deliveryTimes(harness.segmentSeq(2))[1]
		if got, want := lossAt.Sub(probeAt), tcpReturnTestBurstRoundTrip+2*rto; got != want {
			t.Fatalf("second expiry %s after the probe, want %s", got, want)
		}
		requireTcpReturnTestBurstRecovery(t, harness, payload, 1, segmentCount, lossAt, 12)
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
// ends without a reset.
func TestTcpReturnRetransmitRetainsAndRetransmitsFin(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
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

// Establishes a flow whose upstream has sent its FIN, unacknowledged and
// held in retention, with the delivery drain parked waiting for that
// acknowledgement, on an upstream whose Close takes time.
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

// A selectively acknowledged segment stays retained until the cumulative
// acknowledgement covers it: a source that reports segments and then
// discards them gets every one of them again from retention. Forgetting on
// selective acknowledgement would leave the discarded segments unrecoverable.
func TestTcpReturnRetransmitSackedSegmentsStayRetainedUntilCumulativeAck(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{sack: true})
		harness.source.dropCounts[harness.segmentSeq(1)] = 1
		// the hole's retransmission is the next in-order arrival, and the
		// source drops its whole out-of-order queue when it comes
		harness.source.renegeOnce = true

		payload := harness.payload(6)
		harness.write(payload)
		synctest.Wait()
		// the reneged segments inside the recovery come back on partial
		// acknowledgements at once; those past its end wait for the timer,
		// whose first expiry probes with the first of them, and with no
		// later segment to draw a duplicate the second expiry, twice the
		// timer after the answer, shows the loss real and sends the last
		time.Sleep(3 * returnRetransmitInitialRto)
		synctest.Wait()

		harness.requireStream(payload)
		for segmentIndex := 1; segmentIndex < 6; segmentIndex += 1 {
			harness.requireSeenCount(segmentIndex, 2)
		}
		harness.requireSeenCount(0, 1)
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after full acknowledgement: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
	})
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
func TestTcpReturnRetransmitCutsARetransmissionToTheReportedPathMtu(t *testing.T) {
	const segmentCount = 4
	for _, c := range []struct {
		ipVersion  int
		timestamps bool
		pathMtu    int
	}{
		// the family floors: three pieces for IPv4, the last short, and two
		// for IPv6
		{ipVersion: 4, timestamps: false, pathMtu: ipv4MinimumPathMtu},
		{ipVersion: 4, timestamps: true, pathMtu: ipv4MinimumPathMtu},
		{ipVersion: 6, timestamps: false, pathMtu: ipv6MinimumPathMtu},
		{ipVersion: 6, timestamps: true, pathMtu: ipv6MinimumPathMtu},
	} {
		runTcpReturnRetransmitTest(t, func(t *testing.T) {
			harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{
				ipVersion:  c.ipVersion,
				timestamps: c.timestamps,
			})
			harness.source.dropCounts[harness.segmentSeq(1)] = 1
			// acknowledgements go one at a time below, with the worker run
			// between them as it runs between arrivals
			harness.source.holdAcks = true
			start := time.Now()
			payload := harness.payload(segmentCount)
			harness.write(payload)
			synctest.Wait()
			if original := harness.source.deliveries(harness.segmentSeq(1))[0]; original.packetByteCount != tcpReturnTestMtu {
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
// each expiry recovered one segment.
func TestTcpReturnRetransmitProbeHeadAcknowledgedInPiecesDecidesNothing(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		const segmentCount = 8
		harness := newTcpReturnRetransmitTestHarness(t, tcpReturnTestOptions{})
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
