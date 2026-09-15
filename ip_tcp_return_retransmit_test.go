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
	tcpReturnTestInitialSynSeq = uint32(1000)
	// data starts after the SYN's sequence byte
	tcpReturnTestDataSeq = tcpReturnTestInitialSynSeq + 1
	tcpReturnTestMtu     = 1500
	// one segment: the mtu less the IPv4 and option-free TCP headers
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

// The sequence number of the k-th data segment, from zero.
func tcpReturnTestSegmentSeq(segmentIndex int) uint32 {
	return tcpReturnTestDataSeq + uint32(segmentIndex*tcpReturnTestSegmentByteCount)
}

// A deterministic payload of whole segments whose bytes identify their offset.
func tcpReturnTestPayload(segmentCount int) []byte {
	payload := make([]byte, segmentCount*tcpReturnTestSegmentByteCount)
	for index := range payload {
		payload[index] = byte(index*7 + index/tcpReturnTestSegmentByteCount)
	}
	return payload
}

// A segment the sequence sent toward the source, as the source model saw it.
type tcpReturnTestSegment struct {
	seq     uint32
	payload []byte
	fin     bool
	rst     bool
	at      time.Time
}

// The source device's TCP receiver, reduced to what the sequence can observe:
// in-order reassembly, out-of-order queueing, cumulative acknowledgements
// with optional SACK blocks, and a drop policy standing in for the kernel's
// receive-socket drop, which produces no acknowledgement at all.
type tcpReturnTestSource struct {
	harness *tcpReturnRetransmitTestHarness
	sack    bool

	stateLock sync.Mutex
	// while held, nothing is acknowledged; released by ackNow
	holdAcks bool
	rcvNxt   uint32
	stream   []byte
	// out of order, by sequence, without overlap
	ooo []tcpReturnTestSegment
	// how many more deliveries of each sequence the kernel drops
	dropCounts map[uint32]int
	// how many deliveries of each sequence arrived, drops included
	seenCounts map[uint32]int
	// every data, FIN or RST segment delivered, in delivery order
	segments    []tcpReturnTestSegment
	finReceived bool
	rstReceived bool
	rstAt       time.Time
	// the last cumulative acknowledgement sent
	lastAckNumber uint32
	// the most sequence bytes the source ever held past its last
	// acknowledgement, which is what the retention cap bounds
	maxOutstandingByteCount int64
	// a receiver that discards its out-of-order queue on the next in-order
	// arrival, to renege on what it selectively acknowledged
	renegeOnce bool
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
		if 0 < self.dropCounts[segment.seq] {
			// the kernel drop: TCP never sees it, so nothing answers it
			self.dropCounts[segment.seq] -= 1
			return
		}
		if self.renegeOnce && 0 < len(self.ooo) && 0 <= int32(self.rcvNxt-segment.seq) {
			// the hole is filled and what was reported beyond it is gone
			self.renegeOnce = false
			self.ooo = nil
		}
		self.accept(segment)
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
		ackPacket, ackTcp = self.buildAckWithLock()
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

// Builds one pure acknowledgement at the current frontier, with SACK blocks
// for the out-of-order runs when negotiated. The lock must be held.
func (self *tcpReturnTestSource) buildAckWithLock() ([]byte, parsedTcp) {
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
	if 0 < len(blocks) {
		// two NOPs then the SACK option, a multiple of four
		optionByteCount = 2 + 2 + 8*len(blocks)
	}
	tcpHeaderByteCount := TcpHeaderSizeWithoutExtensions + optionByteCount
	packet := MessagePoolGet(Ipv4HeaderSizeWithoutExtensions + tcpHeaderByteCount)
	clear(packet)
	packet[0] = 0x45
	tcp := packet[Ipv4HeaderSizeWithoutExtensions:]
	tcp[12] = byte(tcpHeaderByteCount/4) << 4
	options := tcp[TcpHeaderSizeWithoutExtensions:tcpHeaderByteCount]
	if 0 < len(blocks) {
		options[0] = 1
		options[1] = 1
		options[2] = 5
		options[3] = byte(2 + 8*len(blocks))
		for blockIndex, block := range blocks {
			binary.BigEndian.PutUint32(options[4+8*blockIndex:], block.start)
			binary.BigEndian.PutUint32(options[8+8*blockIndex:], block.end)
		}
	}
	self.lastAckNumber = self.rcvNxt
	parsed := parsedTcp{
		seq:        tcpReturnTestDataSeq,
		ack:        true,
		ackNumber:  self.rcvNxt,
		windowSize: uint16(tcpReturnTestWindowByteCount >> tcpReturnTestWindowScale),
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
		ackPacket, ackTcp = self.buildAckWithLock()
	}()
	self.harness.sendFromSource(&ackTcp, ackPacket)
}

func (self *tcpReturnTestSource) seenCount(seq uint32) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.seenCounts[seq]
}

// Delivery times of every segment at one sequence, in order.
func (self *tcpReturnTestSource) deliveryTimes(seq uint32) []time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var times []time.Time
	for _, segment := range self.segments {
		if segment.seq == seq && !segment.rst {
			times = append(times, segment.at)
		}
	}
	return times
}

func (self *tcpReturnTestSource) streamCopy() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]byte(nil), self.stream...)
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
	synAckReceived chan struct{}
	runDone        chan struct{}
	poolTaken      uint64
	poolReturned   uint64
	violations     uint64
	closeOnce      sync.Once
}

func newTcpReturnRetransmitTestHarness(
	t *testing.T,
	sack bool,
	configure func(*TcpBufferSettings),
) *tcpReturnRetransmitTestHarness {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	sequenceSocket, upstreamSocket := net.Pipe()
	settings := DefaultTcpBufferSettingsWithBufferSize(8)
	// far beyond every virtual clock the tests run, so only the bound under
	// test can end a flow
	settings.ReadTimeout = 10 * time.Minute
	settings.WriteTimeout = 10 * time.Minute
	settings.IdleTimeout = 10 * time.Minute
	settings.AckCompressTimeout = 0
	settings.WriteBatchSize = 4
	settings.Mtu = tcpReturnTestMtu
	// one socket read is eight segments
	settings.ReadBufferByteCount = 8 * tcpReturnTestSegmentByteCount
	settings.DialContextSettings = &DialContextSettings{
		DialContext: func(dialCtx context.Context, network string, addr string) (net.Conn, error) {
			return sequenceSocket, nil
		},
	}
	if configure != nil {
		configure(settings)
	}

	poolTaken, poolReturned, _ := MessagePoolCounts()
	harness := &tcpReturnRetransmitTestHarness{
		t:              t,
		cancel:         cancel,
		settings:       settings,
		upstream:       upstreamSocket,
		transferSource: SourceId(NewId()),
		synAckReceived: make(chan struct{}, 1),
		runDone:        make(chan struct{}),
		poolTaken:      poolTaken,
		poolReturned:   poolReturned,
		violations:     MessagePoolViolationCount(),
	}
	harness.source = &tcpReturnTestSource{
		harness:    harness,
		sack:       sack,
		rcvNxt:     tcpReturnTestDataSeq,
		dropCounts: map[uint32]int{},
		seenCounts: map[uint32]int{},
	}
	harness.source.lastAckNumber = tcpReturnTestDataSeq

	sourceIp := net.IPv4(192, 0, 2, 10).To4()
	destinationIp := net.IPv4(203, 0, 113, 7).To4()
	harness.sequence = NewTcpSequence(
		ctx,
		func(
			source TransferPath,
			provideMode protocol.ProvideMode,
			ipPath *IpPath,
			packet []byte,
		) {
			_, packetSourceIp, packetDestinationIp, transport, ok := parseIpv4(packet)
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
				seq:     tcp.seq,
				payload: append([]byte(nil), tcp.payload...),
				fin:     tcp.fin,
				rst:     tcp.rst,
				at:      time.Now(),
			})
		},
		harness.transferSource,
		protocol.ProvideMode_Network,
		4,
		sourceIp,
		40001,
		destinationIp,
		443,
		tcpReturnTestInitialSynSeq,
		settings,
	)
	harness.sequence.returnRetransmit.counters = &harness.counters
	go func() {
		defer close(harness.runDone)
		harness.sequence.Run()
	}()

	// the SYN negotiates a window scale so the source can advertise a window
	// larger than the retention cap under test
	synOptions := []byte{3, 3, byte(tcpReturnTestWindowScale), 1}
	synPacket := MessagePoolGet(Ipv4HeaderSizeWithoutExtensions + TcpHeaderSizeWithoutExtensions + len(synOptions))
	clear(synPacket)
	synPacket[0] = 0x45
	copy(synPacket[Ipv4HeaderSizeWithoutExtensions+TcpHeaderSizeWithoutExtensions:], synOptions)
	synTcp := parsedTcp{
		syn:        true,
		seq:        tcpReturnTestInitialSynSeq,
		windowSize: 0xffff,
		options:    synPacket[Ipv4HeaderSizeWithoutExtensions+TcpHeaderSizeWithoutExtensions:],
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
		harness := newTcpReturnRetransmitTestHarness(t, false, nil)
		droppedSeq := tcpReturnTestSegmentSeq(1)
		harness.source.dropCounts[droppedSeq] = 1
		start := time.Now()

		payload := tcpReturnTestPayload(8)
		harness.write(payload)
		synctest.Wait()

		if stream := harness.source.streamCopy(); !bytes.Equal(stream, payload) {
			t.Fatalf("stream has %d bytes, want %d exact", len(stream), len(payload))
		}
		for segmentIndex := 0; segmentIndex < 8; segmentIndex += 1 {
			seq := tcpReturnTestSegmentSeq(segmentIndex)
			want := 1
			if seq == droppedSeq {
				want = 2
			}
			if got := harness.source.seenCount(seq); got != want {
				t.Fatalf("segment %d delivered %d times, want %d", segmentIndex, got, want)
			}
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
		if stats := harness.counters.snapshot(); stats.PacketCount != 1 || stats.ByteCount != tcpReturnTestSegmentByteCount {
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
		harness := newTcpReturnRetransmitTestHarness(t, true, nil)
		firstHoleSeq := tcpReturnTestSegmentSeq(1)
		secondHoleSeq := tcpReturnTestSegmentSeq(3)
		harness.source.dropCounts[firstHoleSeq] = 1
		harness.source.dropCounts[secondHoleSeq] = 1

		payload := tcpReturnTestPayload(8)
		harness.write(payload)
		synctest.Wait()

		if stream := harness.source.streamCopy(); !bytes.Equal(stream, payload) {
			t.Fatalf("stream has %d bytes, want %d exact", len(stream), len(payload))
		}
		for segmentIndex := 0; segmentIndex < 8; segmentIndex += 1 {
			seq := tcpReturnTestSegmentSeq(segmentIndex)
			want := 1
			if seq == firstHoleSeq || seq == secondHoleSeq {
				want = 2
			}
			if got := harness.source.seenCount(seq); got != want {
				t.Fatalf("segment %d delivered %d times, want %d", segmentIndex, got, want)
			}
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
		harness := newTcpReturnRetransmitTestHarness(t, false, nil)
		firstHoleSeq := tcpReturnTestSegmentSeq(1)
		secondHoleSeq := tcpReturnTestSegmentSeq(3)
		harness.source.dropCounts[firstHoleSeq] = 1
		harness.source.dropCounts[secondHoleSeq] = 1

		payload := tcpReturnTestPayload(8)
		harness.write(payload)
		synctest.Wait()

		if stream := harness.source.streamCopy(); !bytes.Equal(stream, payload) {
			t.Fatalf("stream has %d bytes, want %d exact", len(stream), len(payload))
		}
		if got := harness.source.seenCount(firstHoleSeq); got != 2 {
			t.Fatalf("first hole delivered %d times, want 2", got)
		}
		if got := harness.source.seenCount(secondHoleSeq); got != 2 {
			t.Fatalf("second hole delivered %d times, want 2", got)
		}
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 2 ||
			reasonCounts[tcpReturnRetransmitReasonDupAck] != 1 ||
			reasonCounts[tcpReturnRetransmitReasonPartialAck] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v, want one on duplicate acks and one on the partial ack", packetCount, reasonCounts)
		}
	})
}

// (c) A source that acknowledges nothing: the timer sends the first
// unacknowledged segment again at one second, doubling to the ceiling, and
// the no-progress bound ends the flow with a reset rather than leaving it
// idle. The schedule is exact in virtual time.
func TestTcpReturnRetransmitTimesOutWithBackoffThenResets(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, false, nil)
		harness.source.holdAcks = true
		start := time.Now()

		harness.write(tcpReturnTestPayload(2))
		synctest.Wait()

		harness.waitRunDone(2 * time.Minute)

		// 1, 2, 4, then 8 s steps: 1, 3, 7, 15, 23, 31, 39, 47, 55, and 63
		// would pass the 60 s bound
		wantOffsets := []time.Duration{
			0,
			1 * time.Second,
			3 * time.Second,
			7 * time.Second,
			15 * time.Second,
			23 * time.Second,
			31 * time.Second,
			39 * time.Second,
			47 * time.Second,
			55 * time.Second,
		}
		times := harness.source.deliveryTimes(tcpReturnTestSegmentSeq(0))
		if len(times) != len(wantOffsets) {
			t.Fatalf("first segment delivered %d times, want %d", len(times), len(wantOffsets))
		}
		for index, at := range times {
			if got := at.Sub(start); got != wantOffsets[index] {
				t.Fatalf("delivery %d at +%s, want +%s", index, got, wantOffsets[index])
			}
		}
		// only the head is sent on the timer
		if got := harness.source.seenCount(tcpReturnTestSegmentSeq(1)); got != 1 {
			t.Fatalf("second segment delivered %d times, want 1", got)
		}
		harness.source.stateLock.Lock()
		rstReceived, rstAt := harness.source.rstReceived, harness.source.rstAt
		harness.source.stateLock.Unlock()
		if !rstReceived {
			t.Fatal("no reset reached the source at the bound")
		}
		if got := rstAt.Sub(start); got != defaultReturnRetransmitTimeout {
			t.Fatalf("reset at +%s, want +%s", got, defaultReturnRetransmitTimeout)
		}
		if stats := harness.counters.snapshot(); stats.TimeoutCount != 9 || stats.AbandonCount != 1 || stats.PacketCount != 9 {
			t.Fatalf("stats=%+v", stats)
		}
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after the reset: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
	})
}

// (d) The retention cap: with the source's window far larger than the cap
// and no acknowledgements, packetizing stops at the cap and the upstream
// write waits; acknowledgements free space and the burst completes, with the
// bytes past the last acknowledgement never above the cap.
func TestTcpReturnRetransmitRetainedBytesStayWithinTheCap(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		const capSegmentCount = 4
		harness := newTcpReturnRetransmitTestHarness(t, false, func(settings *TcpBufferSettings) {
			settings.ReturnRetransmitRetainByteCount = capSegmentCount * tcpReturnTestSegmentByteCount
		})
		harness.source.holdAcks = true

		payload := tcpReturnTestPayload(16)
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

		if stream := harness.source.streamCopy(); !bytes.Equal(stream, payload) {
			t.Fatalf("stream has %d bytes, want %d exact", len(stream), len(payload))
		}
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

// (e) With the setting off nothing is retained and nothing is ever sent
// again: the dropped segment stays a hole through the timer's and the
// bound's whole schedule, and no reset follows, which is the earlier
// behaviour and the failure this change exists for.
func TestTcpReturnRetransmitDisabledNeverRetransmits(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, false, func(settings *TcpBufferSettings) {
			settings.EnableReturnRetransmit = false
		})
		droppedSeq := tcpReturnTestSegmentSeq(1)
		harness.source.dropCounts[droppedSeq] = 1

		payload := tcpReturnTestPayload(8)
		harness.write(payload)
		synctest.Wait()
		time.Sleep(defaultReturnRetransmitTimeout + returnRetransmitMaxRto)
		synctest.Wait()

		if got := harness.source.seenCount(droppedSeq); got != 1 {
			t.Fatalf("dropped segment delivered %d times with retransmission off, want 1", got)
		}
		if stream := harness.source.streamCopy(); len(stream) != tcpReturnTestSegmentByteCount {
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
		harness := newTcpReturnRetransmitTestHarness(t, false, nil)
		payload := tcpReturnTestPayload(2)
		harness.write(payload)
		synctest.Wait()

		finSeq := tcpReturnTestSegmentSeq(2)
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
		if stream := harness.source.streamCopy(); !bytes.Equal(stream, payload) {
			t.Fatalf("stream has %d bytes, want %d exact", len(stream), len(payload))
		}
		_, _, packetCount, reasonCounts := harness.retransmitState()
		if packetCount != 1 || reasonCounts[tcpReturnRetransmitReasonTimeout] != 1 {
			t.Fatalf("retransmissions=%d reasons=%v, want the FIN once on the timer", packetCount, reasonCounts)
		}
	})
}

// A selectively acknowledged segment stays retained until the cumulative
// acknowledgement covers it: a source that reports segments and then
// discards them gets every one of them again from retention. Forgetting on
// selective acknowledgement would leave the discarded segments unrecoverable.
func TestTcpReturnRetransmitSackedSegmentsStayRetainedUntilCumulativeAck(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, true, nil)
		holeSeq := tcpReturnTestSegmentSeq(1)
		harness.source.dropCounts[holeSeq] = 1
		// the hole's retransmission is the next in-order arrival, and the
		// source drops its whole out-of-order queue when it comes
		harness.source.renegeOnce = true

		payload := tcpReturnTestPayload(6)
		harness.write(payload)
		synctest.Wait()
		// the reneged segments inside the recovery come back on partial
		// acknowledgements at once; those past its end wait for the timer
		time.Sleep(2 * returnRetransmitInitialRto)
		synctest.Wait()

		if stream := harness.source.streamCopy(); !bytes.Equal(stream, payload) {
			t.Fatalf("stream has %d bytes, want %d exact", len(stream), len(payload))
		}
		for segmentIndex := 1; segmentIndex < 6; segmentIndex += 1 {
			if got := harness.source.seenCount(tcpReturnTestSegmentSeq(segmentIndex)); got != 2 {
				t.Fatalf("segment %d delivered %d times, want 2 (dropped or reneged, then retained)", segmentIndex, got)
			}
		}
		if got := harness.source.seenCount(tcpReturnTestSegmentSeq(0)); got != 1 {
			t.Fatalf("first segment delivered %d times, want 1", got)
		}
		retainedByteCount, retainedCount, _, _ := harness.retransmitState()
		if retainedByteCount != 0 || retainedCount != 0 {
			t.Fatalf("retained after full acknowledgement: %d bytes in %d segments", retainedByteCount, retainedCount)
		}
	})
}

// (g) Ownership across loss, selective acknowledgement, the FIN and the
// bound's reset: every pooled buffer the sequence took or shared is back
// exactly once. The harness reconciles at close; this test says so
// explicitly and drives the paths that hold shares longest.
func TestTcpReturnRetransmitReturnsEveryPooledBufferOnce(t *testing.T) {
	runTcpReturnRetransmitTest(t, func(t *testing.T) {
		harness := newTcpReturnRetransmitTestHarness(t, true, func(settings *TcpBufferSettings) {
			settings.ReturnRetransmitTimeout = 5 * time.Second
		})
		harness.source.dropCounts[tcpReturnTestSegmentSeq(2)] = 1
		harness.write(tcpReturnTestPayload(6))
		synctest.Wait()

		// the tail is never acknowledged: the FIN and the last segments are
		// held in retention until the bound resets the flow
		harness.source.holdAcks = true
		harness.write(tcpReturnTestPayload(3))
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
