package connect

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/urnetwork/connect/protocol"
)

// S6. With the provider's inner repair off, a segment lost after the transfer
// layer has delivered it is never retransmitted.
//
// THROUGHPUT-RIG-REVIEW §6, the open single-flow wedge: the provider
// terminates TCP and relies on Transfer for delivery, so its TCP does not
// retransmit data segments (ip.go, "Packet flow from the user-NAT to the
// source is assumed to never require user-NAT retransmission"). Any inner
// segment lost between the client's transfer receive and its kernel TCP —
// the client's backlog, its pruning under bursts, a tun write refused — is a
// permanent hole: the kernel holds megabytes out of order, its window
// collapses, and the download stops for the rest of the run.
//
// What is in process here is the provider's half exactly: a `TcpSequence`
// against an in-memory origin, with this test as the client's stack and the
// sequence built with `EnableReturnRetransmit` off. The origin offers 256 KiB;
// the client acknowledges every segment except the third, which it drops, and
// answers everything after it with the duplicate acknowledgement a kernel
// would send. The provider then sends until the client's 64 KiB window closes
// and stops. Over sixty virtual seconds the dropped segment's sequence number
// is emitted exactly once: no retransmission timer fires on this side and
// duplicate acknowledgements trigger nothing, which is the mechanism by which
// the rig's flow wedged.
//
// The repair is on by default now (`tcpReturnRetransmitState`), so this cell
// asks for the old shape explicitly. It is worth keeping as the narrow one:
// one sequence, no transfer layer, and the pre-fix behaviour the rig review's
// §6 describes, so that what the repair changed stays legible. S9 below is
// the same loss over the whole path — the provider's nat, a transfer client
// on each side, and a modelled device kernel — with the repair off and on.
//
// What is still not in process, here or in S9: the device's real stack behind
// the tun. That needs the gVisor tun of tun.go driven inside a virtual-time
// bubble, and its own goroutines and clocks are not known to run under
// synctest; S9's kernel is a model of it, and the rig pins the rest.
//
// Produced: 65 segments of 1040 bytes emitted, all at the origin's first
// instant since nothing in this cell has a delay, up to the hole plus
// 65535 bytes where the window closed; the third segment emitted once;
// nothing emitted in the sixty seconds after the window closed.
func TestPathsimS6InnerSegmentLossIsNotRetransmittedByTheProvider(t *testing.T) {
	// the pool's lazy initialiser, born outside the bubble
	MessagePoolReturn(MessagePoolGet(64))

	synctest.Test(t, func(t *testing.T) {
		assertMessagePoolOwnership(t)

		const initialSynSeq = uint32(1000)
		const originByteCount = 256 * 1024
		const lostSegment = 3
		const clientWindow = uint16(65535)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sequenceSocket, originSocket := net.Pipe()
		settings := DefaultTcpBufferSettingsWithBufferSize(64)
		// the shape before the inner repair, which is what §6 measured
		settings.EnableReturnRetransmit = false
		settings.ReadTimeout = 120 * time.Second
		settings.WriteTimeout = 120 * time.Second
		settings.IdleTimeout = 120 * time.Second
		settings.DialContextSettings = &DialContextSettings{
			DialContext: func(dialCtx context.Context, network string, addr string) (net.Conn, error) {
				return sequenceSocket, nil
			},
		}

		type segment struct {
			ordinal   int
			seq       uint32
			byteCount int
			at        time.Time
		}
		var stateLock sync.Mutex
		segments := []segment{}
		synAck := make(chan uint32, 1)
		arrivals := make(chan segment, 1024)
		source := SourceId(NewId())
		sourceIp := net.IPv4(192, 0, 2, 1).To4()
		destinationIp := net.IPv4(203, 0, 113, 7).To4()

		receive := func(_ TransferPath, _ protocol.ProvideMode, _ *IpPath, packet []byte) {
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
				case synAck <- tcp.seq:
				default:
				}
				return
			}
			if len(tcp.payload) == 0 {
				return
			}
			stateLock.Lock()
			s := segment{ordinal: len(segments) + 1, seq: tcp.seq, byteCount: len(tcp.payload), at: time.Now()}
			segments = append(segments, s)
			stateLock.Unlock()
			select {
			case arrivals <- s:
			default:
				t.Errorf("S6: the arrival queue overflowed")
			}
		}
		sequence := NewTcpSequence(
			ctx,
			receive,
			source,
			protocol.ProvideMode_Network,
			4,
			sourceIp,
			40001,
			destinationIp,
			443,
			initialSynSeq,
			settings,
		)
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			sequence.Run()
		}()
		defer func() {
			sequence.Cancel()
			cancel()
			originSocket.Close()
			<-runDone
		}()

		// the client's packets: a pool-owned IPv4/TCP header with no payload
		clientSeq := initialSynSeq + 1
		send := func(syn bool, ackNumber uint32) {
			headerByteCount := Ipv4HeaderSizeWithoutExtensions + TcpHeaderSizeWithoutExtensions
			packet := MessagePoolGet(headerByteCount)
			clear(packet)
			packet[0] = 0x45
			item := &TcpSendItem{
				source:      source,
				provideMode: protocol.ProvideMode_Network,
				tcp: parsedTcp{
					seq:        clientSeq,
					syn:        syn,
					ack:        !syn,
					ackNumber:  ackNumber,
					windowSize: clientWindow,
					payload:    packet[headerByteCount:],
				},
				ipPacket: packet,
			}
			if syn {
				item.tcp.seq = initialSynSeq
			}
			ok, err := sequence.send(item, -1)
			if err != nil || !ok {
				MessagePoolReturn(packet)
				t.Fatalf("S6: the client's packet was not accepted: %v", err)
			}
		}

		send(true, 0)
		var providerIsn uint32
		select {
		case providerIsn = <-synAck:
		case <-time.After(5 * time.Second):
			t.Fatal("S6: no SYN-ACK from the provider")
		}
		expected := providerIsn + 1
		send(false, expected)

		// the origin: a fast server writing everything it has
		origin := make([]byte, originByteCount)
		for i := range origin {
			origin[i] = byte(i)
		}
		writeDone := make(chan error, 1)
		go func() {
			_, err := originSocket.Write(origin)
			writeDone <- err
		}()

		// The client's stack: acknowledge in order, drop one segment, and
		// answer everything past it with the duplicate acknowledgement.
		hole := uint32(0)
		dropped := false
		windowClosedAt := time.Time{}
		deadline := time.After(60 * time.Second)
		receiving := true
		for receiving {
			select {
			case s := <-arrivals:
				if !dropped && s.ordinal == lostSegment {
					hole = s.seq
					dropped = true
					// dropped: no acknowledgement advances past it
					continue
				}
				if !dropped && s.seq == expected {
					expected += uint32(s.byteCount)
					send(false, expected)
					continue
				}
				// past the hole: a duplicate acknowledgement of the hole
				send(false, hole)
				if uint32(int64(hole)+int64(clientWindow)) <= s.seq+uint32(s.byteCount) {
					windowClosedAt = time.Now()
				}
			case <-deadline:
				receiving = false
			}
		}

		stateLock.Lock()
		defer stateLock.Unlock()
		if !dropped {
			t.Fatalf("S6: only %d segments arrived, so no segment was dropped", len(segments))
		}
		emissions := 0
		lastAt := time.Time{}
		for _, s := range segments {
			if s.seq == hole {
				emissions++
			}
			if lastAt.Before(s.at) {
				lastAt = s.at
			}
		}
		if emissions != 1 {
			t.Errorf("S6: the dropped segment at %d was emitted %d times over sixty seconds; with the inner repair off the provider does not retransmit, and if it now does the wedge of the rig review's §6 has a different shape", hole, emissions)
		}
		if windowClosedAt.IsZero() {
			t.Errorf("S6: the client's window never closed behind the hole; %d segments arrived", len(segments))
		} else if windowClosedAt.Add(time.Second).Before(lastAt) {
			t.Errorf("S6: the provider emitted a segment %s after the client's window closed", lastAt.Sub(windowClosedAt))
		}
		if len(segments) == 0 || segments[len(segments)-1].seq+uint32(segments[len(segments)-1].byteCount) == providerIsn+1+originByteCount {
			t.Errorf("S6: the whole origin was delivered, so the window did not bind; %d segments", len(segments))
		}
		t.Logf("S6: %d segments emitted, the hole at %d emitted %d time(s), window closed after %s of virtual time, last emission at %s",
			len(segments), hole-providerIsn-1, emissions, windowClosedAt.Sub(segments[0].at), lastAt.Sub(segments[0].at))
	})
}

// S9. The client's kernel drops one inner segment after the tunnel write, and
// the provider repairs it or does not.
//
// THROUGHPUT-RIG-REVIEW §6, the wedge S6 above pins half of. The whole of it
// is here: the provider's `LocalUserNat` and its TCP sequence, a real transfer
// client on each side joined by the path simulator's carrier, and the client
// device's kernel modelled in this file. The loss is applied inside the
// device's receive callback, which is the tun write: Transfer has delivered
// the packet and acknowledged it to the provider by the time the packet is
// dropped, so the drop is below Transfer's reliability boundary and nothing in
// the transfer layer can see it. That is the rig's measurement — on physical
// hosts at about 800 Mb/s one run in five loses a segment on the device's
// receive socket — and every arm below asserts the transfer layer resent
// nothing of its own and filled no gap of its own, and that the arms the
// repair keeps moving leave no route unacknowledged either, which is what
// makes the inner repair the only repair there is.
//
// The arms are the fix off and on over the same path and the same drops, plus
// a control with no drop at all. The device's kernel is Linux-like: it
// acknowledges every second segment in order, with a 40 ms delayed
// acknowledgement for the tail, and acknowledges at once whenever its
// out-of-order queue is not empty; nothing here negotiates selective
// acknowledgement, on either side, so the duplicate acknowledgements are all
// the provider has to go on. Its window is its free receive buffer behind a
// right edge that never moves left, which is what makes those
// acknowledgements duplicates and what stops the download; the last paragraph
// below is why that rule matters here.
//
// Produced (fast tier, a 50 ms round trip over one 1 Gb/s relay hop, a 64 KiB
// device buffer, a 1 MiB origin in 1,005 segments of 1,060 bytes):
//
//	arm                delivered  exact   repair     done  retx  loss   maxooo      ooo  trto
//	off/one loss            7KiB     no        —        —     0     1    63415    63415     1
//	on/one loss          1024KiB    yes   50.0ms  866.1ms     1     1    63415        0     0
//	on/four losses       1024KiB    yes   50.0ms    1.06s     5     4    64475        0     0
//	on/no loss           1024KiB    yes        —  825.5ms     0     0        0        0     0
//
// With the repair off the flow wedges exactly as the rig's did: the device
// answers every later segment with a duplicate acknowledgement, the provider
// sends up to the window edge the stuck acknowledgement froze and then sends
// nothing at all, and the download stops 7 KiB in with 62 KiB of the device's
// buffer held out of order behind one missing segment for the rest of the run.
// Nothing repairs it: the device is never handed a segment twice. The transfer
// layer's one timeout resend in that arm, after two seconds of silence on a
// route with a retained item, is not a repair — the receive sequence already
// holds that item, and the device's kernel is handed nothing by it. It is the
// `trto` column above, asserted per arm and carried in the digest, so that the
// one number this paragraph is about cannot change unseen.
//
// With the repair on the same drop costs one retransmission and exactly one
// round trip, the queue behind the hole drains, and the origin's bytes arrive
// exactly. Four drops, two of them consecutive, cost five retransmissions:
// one for each loss and one the burst guesses past the pair, asserted as that
// number rather than as a ceiling with a dozen spurious segments of room in
// it. Without the guard on the duplicates its own retransmissions draw, the
// verifier's probe measured thousands of retransmissions for four losses on a
// flow of this shape, and with the doubling burst unbounded it resent most of
// the window every round trip. The lossless arm pays nothing at all, which is
// also what it would pay with the repair off, so each arm reads the repair
// back from the settings its flow was built with and carries it in the
// digest: three arms fail when the flag is flipped, and that is what holds
// the fourth to its name.
//
// The device's window is the reason the wedge looks the way it does. Its
// receiver never moves its right edge left (RFC 1122 §4.2.2.16), so while the
// frontier is stuck every acknowledgement repeats the same number and the same
// window — true duplicates, which is what fast retransmit needs — and the
// provider stops at that frozen edge rather than at any decision of its own.
// A model that shrank the advertised window as the queue filled made every
// duplicate a window update instead, and the hole then waited for the
// provider's timer: 250 ms rather than 50 ms here, and one RTO on a real path.

const (
	// the tunnel these arms run over: one relay hop, the rig's far client
	pathInnerRoundTrip = 50 * time.Millisecond
	// the device's receive buffer, which is also the window it advertises as
	// its out-of-order queue fills: the largest the unscaled field carries,
	// since nothing here negotiates a window scale
	pathInnerClientWindow = 65535
	// what the origin serves, in segments of about a kilobyte
	pathInnerOriginByteCount = 1024 * 1024
	pathInnerInitialSynSeq   = uint32(1000)
	// Linux's delayed acknowledgement timer, and the segments in order it
	// acknowledges without waiting for it
	pathInnerDelayedAck       = 40 * time.Millisecond
	pathInnerAckEverySegments = 2
	// how long an arm watches a flow that is making no progress
	pathInnerObserve = 5 * time.Second
)

// One data segment the device's kernel holds out of order.
type pathInnerSegment struct {
	seq     uint32
	payload []byte
}

// The client device's kernel TCP, reduced to what the provider can observe:
// in-order reassembly, an out-of-order queue behind a window whose right edge
// never moves left, Linux-like delayed acknowledgements with an immediate one
// whenever that queue is not empty, and a drop policy standing in for the
// receive-socket drop the rig measured. The drop is applied inside the
// device's receive callback, which is the tun write: Transfer has delivered
// the packet and acknowledged it by then, so nothing below the drop can
// repair it.
//
// Every acknowledgement it decides on is handed to one sender goroutine
// rather than sent from the callback, which is the receive-callback contract
// (CODESTYLE) and also the shape of a kernel: the tun write returns and the
// stack's answer follows it.
type pathInnerKernel struct {
	stateLock sync.Mutex
	acks      chan []byte
	sourceIp  net.IP
	destIp    net.IP

	rcvNxt uint32
	// the right edge of the window it has advertised, which never moves left
	rcvRightEdge    uint32
	stream          []byte
	ooo             []pathInnerSegment
	oooByteCount    int
	maxOooByteCount int
	established     chan struct{}
	inOrderPending  int
	delayedAckTimer *time.Timer

	// deliveries per sequence, which counts the provider's retransmissions
	seenCounts map[uint32]int
	// the ordinals among first-seen segments whose delivery is dropped
	dropOrdinals map[int]bool
	newSegmentUp int
	lossCount    int
	firstLossAt  time.Time
	// the end of the first segment dropped, and when the in-order frontier
	// first passed it, which is the repair
	firstHoleEnd   uint32
	firstHoleFixed time.Time
	segmentCount   int
	retransmitted  int
	// acknowledgements it could not hand to its sender, which would be loss
	// on the return path, and there is none here
	ackDropCount   int
	completeAt     time.Time
	completeTarget int
}

func newPathInnerKernel(
	acks chan []byte,
	sourceIp net.IP,
	destIp net.IP,
	dropOrdinals []int,
	completeTarget int,
) *pathInnerKernel {
	drops := map[int]bool{}
	for _, ordinal := range dropOrdinals {
		drops[ordinal] = true
	}
	return &pathInnerKernel{
		acks:           acks,
		sourceIp:       sourceIp,
		destIp:         destIp,
		established:    make(chan struct{}, 1),
		seenCounts:     map[uint32]int{},
		dropOrdinals:   drops,
		completeTarget: completeTarget,
	}
}

// The window the device advertises: its free receive buffer, except that the
// right edge never moves left (RFC 1122 §4.2.2.16). That rule is why the
// acknowledgements behind a hole are true duplicates rather than window
// updates: the frontier is stuck and the edge is fixed, so every one of them
// repeats the same window. It is also what stops the download — the provider
// sends up to the edge and no further — and what the rig saw as the client's
// window collapsing, which is the free buffer behind the hole, not the field.
// The lock must be held.
func (self *pathInnerKernel) windowWithLock() int {
	free := max(0, pathInnerClientWindow-self.oooByteCount)
	if edge := self.rcvNxt + uint32(free); 0 < int32(edge-self.rcvRightEdge) {
		self.rcvRightEdge = edge
	}
	return int(self.rcvRightEdge - self.rcvNxt)
}

// The same window, read without moving the edge, for a reading taken between
// acknowledgements. The lock must be held.
func (self *pathInnerKernel) advertisedWindowWithLock() int {
	return max(int(self.rcvRightEdge-self.rcvNxt), max(0, pathInnerClientWindow-self.oooByteCount))
}

// Builds one packet toward the provider. The lock must be held.
func (self *pathInnerKernel) buildWithLock(syn bool, ackNumber uint32) []byte {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    self.sourceIp,
		DstIP:    self.destIp,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(40001),
		DstPort: layers.TCPPort(443),
		SYN:     syn,
		ACK:     !syn,
		Seq:     pathInnerInitialSynSeq,
		Ack:     ackNumber,
		Window:  uint16(self.windowWithLock()),
	}
	if !syn {
		tcp.Seq = pathInnerInitialSynSeq + 1
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip, tcp,
	); err != nil {
		return nil
	}
	return append([]byte(nil), buffer.Bytes()...)
}

// Queues one acknowledgement of the current frontier and cancels a delayed
// one. The lock must be held.
func (self *pathInnerKernel) ackNowWithLock() {
	self.inOrderPending = 0
	if self.delayedAckTimer != nil {
		self.delayedAckTimer.Stop()
		self.delayedAckTimer = nil
	}
	packet := self.buildWithLock(false, self.rcvNxt)
	if packet == nil {
		self.ackDropCount += 1
		return
	}
	select {
	case self.acks <- packet:
	default:
		self.ackDropCount += 1
	}
}

// Takes one packet from the tunnel, after the write that delivered it.
func (self *pathInnerKernel) receive(tcp *parsedTcp, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if tcp.syn {
		self.rcvNxt = tcp.seq + 1
		self.rcvRightEdge = self.rcvNxt
		self.ackNowWithLock()
		select {
		case self.established <- struct{}{}:
		default:
		}
		return
	}
	if len(tcp.payload) == 0 {
		return
	}
	self.segmentCount += 1
	self.seenCounts[tcp.seq] += 1
	if 1 < self.seenCounts[tcp.seq] {
		self.retransmitted += 1
	} else {
		self.newSegmentUp += 1
		if self.dropOrdinals[self.newSegmentUp] {
			// the receive-socket drop: the kernel never sees it, so nothing
			// answers it
			self.lossCount += 1
			if self.firstLossAt.IsZero() {
				self.firstLossAt = now
				self.firstHoleEnd = tcp.seq + uint32(len(tcp.payload))
			}
			return
		}
	}
	outOfOrder := false
	switch {
	case tcp.seq == self.rcvNxt:
		self.stream = append(self.stream, tcp.payload...)
		self.rcvNxt += uint32(len(tcp.payload))
		for 0 < len(self.ooo) && self.ooo[0].seq == self.rcvNxt {
			queued := self.ooo[0]
			self.ooo = self.ooo[1:]
			self.oooByteCount -= len(queued.payload)
			self.stream = append(self.stream, queued.payload...)
			self.rcvNxt += uint32(len(queued.payload))
		}
	case 0 < int32(tcp.seq-self.rcvNxt):
		outOfOrder = true
		insertIndex := len(self.ooo)
		held := false
		for index, queued := range self.ooo {
			if queued.seq == tcp.seq {
				held = true
				break
			}
			if 0 < int32(queued.seq-tcp.seq) {
				insertIndex = index
				break
			}
		}
		if !held {
			self.ooo = append(self.ooo, pathInnerSegment{})
			copy(self.ooo[insertIndex+1:], self.ooo[insertIndex:])
			self.ooo[insertIndex] = pathInnerSegment{
				seq:     tcp.seq,
				payload: append([]byte(nil), tcp.payload...),
			}
			self.oooByteCount += len(tcp.payload)
			self.maxOooByteCount = max(self.maxOooByteCount, self.oooByteCount)
		}
	default:
		// wholly old, from a retransmission of something already in order
		outOfOrder = true
	}
	if self.firstHoleFixed.IsZero() && !self.firstLossAt.IsZero() &&
		0 <= int32(self.rcvNxt-self.firstHoleEnd) {
		self.firstHoleFixed = now
	}
	if self.completeAt.IsZero() && self.completeTarget <= len(self.stream) {
		self.completeAt = now
	}
	// RFC 5681 §4.2: an immediate acknowledgement while anything is out of
	// order, and otherwise one for every second segment with the delayed
	// timer behind it
	if outOfOrder || 0 < len(self.ooo) {
		self.ackNowWithLock()
		return
	}
	self.inOrderPending += 1
	if pathInnerAckEverySegments <= self.inOrderPending {
		self.ackNowWithLock()
		return
	}
	if self.delayedAckTimer == nil {
		self.delayedAckTimer = time.AfterFunc(pathInnerDelayedAck, func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if 0 < self.inOrderPending {
				self.ackNowWithLock()
			}
		})
	}
}

// What the arm reads from the kernel, under its lock.
type pathInnerKernelSnapshot struct {
	streamByteCount int
	segmentCount    int
	retransmitted   int
	lossCount       int
	// the most bytes it ever held out of order, and what it still holds
	maxOooByteCount int
	oooByteCount    int
	window          int
	ackDropCount    int
	firstLossAt     time.Time
	firstHoleFixed  time.Time
	completeAt      time.Time
}

// Stops the delayed acknowledgement timer, so nothing is armed when the arm
// tears down.
func (self *pathInnerKernel) stop() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.delayedAckTimer != nil {
		self.delayedAckTimer.Stop()
		self.delayedAckTimer = nil
	}
	self.inOrderPending = 0
}

func (self *pathInnerKernel) snapshot() pathInnerKernelSnapshot {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return pathInnerKernelSnapshot{
		streamByteCount: len(self.stream),
		segmentCount:    self.segmentCount,
		retransmitted:   self.retransmitted,
		lossCount:       self.lossCount,
		maxOooByteCount: self.maxOooByteCount,
		oooByteCount:    self.oooByteCount,
		// read, not advanced: the edge moves when an acknowledgement carries
		// it
		window:         self.advertisedWindowWithLock(),
		ackDropCount:   self.ackDropCount,
		firstLossAt:    self.firstLossAt,
		firstHoleFixed: self.firstHoleFixed,
		completeAt:     self.completeAt,
	}
}

// One arm of S9.
type pathInnerArm struct {
	name string
	// the provider's inner retransmission
	returnRetransmit bool
	// ordinals among the segments the device sees for the first time, whose
	// delivery its kernel drops
	dropOrdinals []int
}

// What one arm produced, in virtual time.
type pathInnerResult struct {
	arm string
	// the provider's inner repair as the flow was actually built, read back
	// from the settings the nat took rather than from the arm that asked
	repairEnabled      bool
	deliveredByteCount int
	exact              bool
	// from the kernel's drop to the in-order frontier passing it
	repairTime    time.Duration
	completeTime  time.Duration
	segmentCount  int
	retransmitted int
	lossCount     int
	// the most the device ever held out of order, what it still held, and
	// the window it last advertised
	maxOooByteCount int
	oooByteCount    int
	window          int
	providerStats   ReturnRetransmitStats
	transferWrites  uint64
	transferResends uint64
	// items the transfer layer sent again to fill a gap in its own sequence,
	// which is how it repairs a loss it can see
	transferGapResends uint64
	// items it sent again because a route went unacknowledged, which repairs
	// nothing the device is missing
	transferTimeoutResends uint64
	carrierDrops           int64
}

// The integer facts of an arm, hashed; three runs must print the same.
func (self pathInnerResult) digest() string {
	hash := fnv.New64a()
	fmt.Fprintf(hash, "%v|%d|%v|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d",
		self.repairEnabled,
		self.deliveredByteCount, self.exact, self.repairTime, self.completeTime,
		self.segmentCount, self.retransmitted, self.lossCount, self.maxOooByteCount,
		self.oooByteCount, self.providerStats.PacketCount, self.providerStats.ByteCount,
		self.providerStats.TimeoutCount, self.transferWrites, self.transferResends,
		self.transferGapResends, self.transferTimeoutResends, self.carrierDrops,
	)
	return fmt.Sprintf("%016x", hash.Sum64())
}

func (self pathInnerResult) row() string {
	complete := "no"
	if self.exact {
		complete = "yes"
	}
	repair := "-"
	if 0 < self.repairTime {
		repair = formatPathDuration(self.repairTime)
	}
	return fmt.Sprintf("%-24s %9s %6s %8s %8s %5d %5d %8d %8d %6d %5d %8d",
		self.arm,
		fmt.Sprintf("%dKiB", self.deliveredByteCount/1024),
		complete,
		repair,
		formatPathDuration(self.completeTime),
		self.retransmitted,
		self.lossCount,
		self.maxOooByteCount,
		self.oooByteCount,
		self.transferResends,
		self.transferTimeoutResends,
		self.segmentCount,
	)
}

// Runs one arm in its own bubble: a provider with its local nat and a device
// with its kernel, joined by one relay hop of the path simulator's carrier,
// with the origin's bytes offered as fast as the provider's socket reader
// takes them.
func runPathInnerArm(t *testing.T, arm pathInnerArm) pathInnerResult {
	t.Helper()
	// the pool's lazy initialiser starts a stats goroutine; touched here so
	// it is born outside the bubble
	MessagePoolReturn(MessagePoolGet(64))
	restoreProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(restoreProcs)

	result := pathInnerResult{arm: arm.name}
	synctest.Test(t, func(t *testing.T) {
		assertMessagePoolOwnership(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		hops := []pathHop{pathRelayHop("tunnel", pathInnerRoundTrip, pathGigabit, pathRelayQueueMessages, 0)}
		carrier := startPathCarrier(ctx, hops, 9, 16, 1500)

		newSettings := func() *ClientSettings {
			settings := DefaultClientSettings()
			settings.EncryptionSettings.Mode = EncryptionModeOff
			return settings
		}
		providerId := NewId()
		deviceId := NewId()
		providerClient := NewClient(ctx, providerId, NewNoContractClientOob(), newSettings())
		deviceClient := NewClient(ctx, deviceId, NewNoContractClientOob(), newSettings())
		providerClient.ContractManager().AddNoContractPeer(deviceId)
		deviceClient.ContractManager().AddNoContractPeer(providerId)
		providerClient.ContractManager().SetProvideModesWithReturnTraffic(map[protocol.ProvideMode]bool{
			protocol.ProvideMode_Network: true,
			protocol.ProvideMode_Public:  true,
		})
		// published exactly as the H1 platform transport publishes its own,
		// so the receive pump applies the reliable-carrier handoff contract
		reliable := TransferCarrierProperties{ReceiveReliability: CarrierReliabilityReliable}
		providerClient.RouteManager().UpdateTransport(
			NewSendGatewayTransportWithType(TransportTypeH1), []Route{carrier.senderOut})
		providerClient.RouteManager().UpdateTransportWithProperties(
			NewReceiveGatewayTransportWithType(TransportTypeH1), []Route{carrier.senderIn}, reliable)
		deviceClient.RouteManager().UpdateTransportWithProperties(
			NewReceiveGatewayTransportWithType(TransportTypeH1), []Route{carrier.receiverIn}, reliable)
		deviceClient.RouteManager().UpdateTransport(
			NewSendGatewayTransportWithType(TransportTypeH1), []Route{carrier.receiverOut})

		// the origin, on the provider's own side of the tunnel
		natSocket, originSocket := net.Pipe()
		natSettings := DefaultProviderLocalUserNatSettings()
		natSettings.TcpBufferSettings.EnableReturnRetransmit = arm.returnRetransmit
		result.repairEnabled = natSettings.TcpBufferSettings.EnableReturnRetransmit
		natSettings.TcpBufferSettings.DialContextSettings = &DialContextSettings{
			DialContext: func(dialCtx context.Context, network string, addr string) (net.Conn, error) {
				return natSocket, nil
			},
		}
		nat := NewLocalUserNat(ctx, "pathsim-exit", natSettings)
		provider := NewRemoteUserNatProvider(providerClient, nat, DefaultRemoteUserNatProviderSettings())

		sourceIp := net.IPv4(198, 51, 100, 10).To4()
		destinationIp := net.IPv4(203, 0, 113, 7).To4()
		acks := make(chan []byte, 4096)
		kernel := newPathInnerKernel(acks, sourceIp, destinationIp, arm.dropOrdinals, pathInnerOriginByteCount)

		// the device's one sender: a receive callback never sends
		sendDone := make(chan struct{})
		go func() {
			defer close(sendDone)
			for {
				select {
				case <-ctx.Done():
					return
				case packet := <-acks:
					frame, err := ToFrame(&protocol.IpPacketToProvider{
						IpPacket: &protocol.IpPacket{PacketBytes: packet},
					}, DefaultProtocolVersion)
					if err != nil {
						t.Errorf("S9: %s: to frame: %v", arm.name, err)
						return
					}
					if !deviceClient.SendWithTimeout(frame, providerId, func(error) {}, -1) {
						MessagePoolReturn(frame.MessageBytes)
						return
					}
				}
			}
		}()

		deviceClient.AddReceiveCallback(func(_ TransferPath, frames []*protocol.Frame, _ Peer) {
			now := time.Now()
			for _, frame := range frames {
				message, err := FromFrame(frame)
				if err != nil {
					continue
				}
				fromProvider, ok := message.(*protocol.IpPacketFromProvider)
				if !ok {
					continue
				}
				packet := fromProvider.IpPacket.PacketBytes
				_, packetSourceIp, packetDestinationIp, transport, ok := parseIpv4(packet)
				if !ok {
					continue
				}
				tcp := &parsedTcp{}
				if !parseTcpPacket(packetSourceIp, packetDestinationIp, transport, tcp) {
					continue
				}
				kernel.receive(tcp, now)
			}
		})

		// the clients settle, then the handshake
		time.Sleep(pathSettle)
		func() {
			kernel.stateLock.Lock()
			defer kernel.stateLock.Unlock()
			packet := kernel.buildWithLock(true, 0)
			select {
			case acks <- packet:
			default:
				t.Fatalf("S9: %s: the device could not send its SYN", arm.name)
			}
		}()
		select {
		case <-kernel.established:
		case <-time.After(10 * time.Second):
			t.Fatalf("S9: %s: no SYN-ACK reached the device", arm.name)
		}

		origin := make([]byte, pathInnerOriginByteCount)
		for index := range origin {
			origin[index] = byte(index*7 + index/1024)
		}
		originDone := make(chan struct{})
		go func() {
			defer close(originDone)
			// a wedged flow leaves this write parked; the close below ends it
			originSocket.Write(origin)
		}()

		// watch until the download completes or stops making progress
		started := time.Now()
		deadline := started.Add(pathInnerObserve)
		lastByteCount := 0
		stalledSince := started
		for time.Now().Before(deadline) {
			watched := kernel.snapshot()
			if !watched.completeAt.IsZero() {
				break
			}
			if lastByteCount < watched.streamByteCount {
				lastByteCount = watched.streamByteCount
				stalledSince = time.Now()
			} else if 2*pathInnerObserve/5 < time.Since(stalledSince) {
				// no progress for two fifths of the watch: wedged
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		synctest.Wait()

		snapshot := kernel.snapshot()
		result.deliveredByteCount = snapshot.streamByteCount
		result.segmentCount = snapshot.segmentCount
		result.retransmitted = snapshot.retransmitted
		result.lossCount = snapshot.lossCount
		result.maxOooByteCount = snapshot.maxOooByteCount
		result.oooByteCount = snapshot.oooByteCount
		result.window = snapshot.window
		if 0 < snapshot.ackDropCount {
			t.Errorf("S9: %s: the device could not send %d acknowledgements; the return path in this cell loses nothing",
				arm.name, snapshot.ackDropCount)
		}
		kernel.stateLock.Lock()
		result.exact = bytes.Equal(kernel.stream, origin)
		kernel.stateLock.Unlock()
		if !snapshot.firstHoleFixed.IsZero() {
			result.repairTime = snapshot.firstHoleFixed.Sub(snapshot.firstLossAt)
		}
		if !snapshot.completeAt.IsZero() {
			result.completeTime = snapshot.completeAt.Sub(started)
		}
		result.providerStats = nat.ReturnRetransmitStats()
		sendStats := providerClient.DestinationSendStats(deviceId)
		result.transferWrites = sendStats.WriteCount
		result.transferResends = sendStats.ResendWriteCount
		recovery := providerClient.SendRecoveryStats()
		result.transferGapResends = recovery.SelectiveGapWriteCount +
			recovery.AckTailProbeWriteCount +
			recovery.CumulativeProbeWriteCount
		result.transferTimeoutResends = recovery.TimeoutResendWriteCount

		// the measurement ends here; what the teardown writes is not counted
		kernel.stop()
		carrier.frozen.Store(true)
		originSocket.Close()
		<-originDone
		provider.Close()
		nat.Close()
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer closeCancel()
		if err := providerClient.CloseAndWait(closeCtx); err != nil {
			t.Errorf("S9: %s: close the provider: %v", arm.name, err)
		}
		if err := deviceClient.CloseAndWait(closeCtx); err != nil {
			t.Errorf("S9: %s: close the device: %v", arm.name, err)
		}
		cancel()
		<-sendDone
		carrier.drain()
		for _, stats := range carrier.stats {
			result.carrierDrops += stats.forward.drops() + stats.reverse.drops()
		}
	})
	return result
}

// Prints one scenario's table and digests. There is no rate here and so no
// reading against the simulator's ceiling: what these arms measure is what
// reached the device and what it cost, in bytes and counts.
func reportPathInnerScenario(t *testing.T, scenario string, results []pathInnerResult) {
	t.Helper()
	header := fmt.Sprintf("%-24s %9s %6s %8s %8s %5s %5s %8s %8s %6s %5s %8s",
		"arm", "delivered", "exact", "repair", "done", "retx", "loss", "maxooo", "ooo", "tresend", "trto", "segments")
	lines := []string{scenario, header}
	digests := []string{}
	for _, result := range results {
		lines = append(lines, result.row())
		digests = append(digests, fmt.Sprintf("%s=%s", result.arm, result.digest()))
	}
	lines = append(lines, "digest "+strings.Join(digests, " "))
	t.Logf("\n%s", strings.Join(lines, "\n"))
}

func TestPathsimS9InnerSegmentLossRepairedByTheProvider(t *testing.T) {
	arms := []pathInnerArm{
		{name: "S9/off/one loss", dropOrdinals: []int{8}},
		{name: "S9/on/one loss", returnRetransmit: true, dropOrdinals: []int{8}},
		{name: "S9/on/four losses", returnRetransmit: true, dropOrdinals: []int{8, 200, 201, 500}},
		{name: "S9/on/no loss", returnRetransmit: true},
	}
	results := []pathInnerResult{}
	for _, arm := range arms {
		results = append(results, runPathInnerArm(t, arm))
	}
	reportPathInnerScenario(t, "S9 an inner segment lost after the tunnel write", results)
	off, on, four, clean := results[0], results[1], results[2], results[3]

	// The loss is below Transfer's delivery boundary in every arm: the
	// carrier drops nothing, the provider's transfer client resends nothing
	// and recovers nothing, and each arm lost exactly what its kernel
	// dropped. This is the rig's finding and the reason an inner repair is
	// the only repair there can be.
	for index, result := range results {
		if 0 < result.transferResends || 0 < result.transferGapResends {
			t.Errorf("S9: %s: the transfer layer resent %d items and filled %d gaps of its own; a loss above its delivery cannot be visible to it",
				result.arm, result.transferResends, result.transferGapResends)
		}
		if arms[index].returnRetransmit && 0 < result.transferTimeoutResends {
			t.Errorf("S9: %s: the transfer layer sent %d items again on an unacknowledged route; a flow the inner repair keeps moving leaves no route unanswered for its timeout",
				result.arm, result.transferTimeoutResends)
		}
		if 0 < result.carrierDrops {
			t.Errorf("S9: %s: the carrier dropped %d messages; the only loss in this cell is the device's kernel drop",
				result.arm, result.carrierDrops)
		}
		if want := len(arms[index].dropOrdinals); result.lossCount != want {
			t.Errorf("S9: %s: the device's kernel dropped %d segments, want %d", result.arm, result.lossCount, want)
		}
	}

	// Each arm ran with the repair its name says, read back from the settings
	// its flow was built with rather than from the arm that asked for them.
	// Three of the four fail outright when the flag is flipped; the lossless
	// one cannot, because a repair with nothing to repair is silent in every
	// number the device can see, so this and the digest are what hold its
	// name to what it ran.
	if off.repairEnabled || !on.repairEnabled || !four.repairEnabled || !clean.repairEnabled {
		t.Errorf("S9: the arms ran with the repair off=%t, on=%t, four losses=%t, no loss=%t; want it off in the first and on in the other three",
			off.repairEnabled, on.repairEnabled, four.repairEnabled, clean.repairEnabled)
	}

	// Off: the wedge the rig measured. The device answers every later segment
	// with a duplicate acknowledgement, the provider sends up to the window
	// edge that stuck acknowledgement froze and then sends nothing, and the
	// download stops where it stopped.
	if off.exact || pathInnerOriginByteCount <= off.deliveredByteCount {
		t.Errorf("S9: the disabled arm delivered %d of %d bytes; with no inner repair the hole is permanent",
			off.deliveredByteCount, pathInnerOriginByteCount)
	}
	if 0 < off.retransmitted || 0 < off.providerStats.PacketCount {
		t.Errorf("S9: the disabled arm sent %d segments again (%d by the flow's own count), want none",
			off.retransmitted, off.providerStats.PacketCount)
	}
	if off.oooByteCount < pathInnerClientWindow/2 || off.oooByteCount != off.maxOooByteCount {
		t.Errorf("S9: the disabled arm left %d bytes queued out of order behind the hole, of %d at its peak; the queue is supposed to fill the device's buffer and stay there",
			off.oooByteCount, off.maxOooByteCount)
	}
	// its one timeout resend is the wedge seen from below Transfer, not a
	// repair: the route carrying the last delivered item goes unacknowledged
	// for two seconds because the device answers nothing new, and the receive
	// sequence already holds the item it sends again, so the device's kernel
	// is handed nothing by it - which is what the arm's own retransmitted
	// count of zero above says from the device's side
	if off.transferTimeoutResends != 1 {
		t.Errorf("S9: the disabled arm's transfer layer sent %d items again on an unacknowledged route, want the one the wedged route costs",
			off.transferTimeoutResends)
	}

	// On: the same drop over the same path costs one retransmission and a
	// couple of round trips, the window reopens, and the origin's bytes
	// arrive exactly.
	if !on.exact {
		t.Errorf("S9: the enabled arm delivered %d of %d bytes, and not the origin's bytes exactly",
			on.deliveredByteCount, pathInnerOriginByteCount)
	}
	if on.retransmitted != on.lossCount {
		t.Errorf("S9: the enabled arm sent %d segments again for %d lost, want one for one",
			on.retransmitted, on.lossCount)
	}
	if maxRepairTime := 6 * pathInnerRoundTrip; maxRepairTime < on.repairTime {
		t.Errorf("S9: the enabled arm passed the hole %s after the loss, above %s", on.repairTime, maxRepairTime)
	}
	if on.oooByteCount != 0 || on.maxOooByteCount < pathInnerClientWindow/2 {
		t.Errorf("S9: the enabled arm left %d bytes queued out of order, of %d at its peak; the repair is supposed to drain the queue the hole filled",
			on.oooByteCount, on.maxOooByteCount)
	}
	if on.window != pathInnerClientWindow {
		t.Errorf("S9: the enabled arm left the device advertising %d bytes, want its whole buffer of %d back",
			on.window, pathInnerClientWindow)
	}
	if off.deliveredByteCount >= on.deliveredByteCount {
		t.Errorf("S9: the disabled arm delivered %d bytes and the enabled one %d; the repair is supposed to be what completes the download",
			off.deliveredByteCount, on.deliveredByteCount)
	}

	// Four losses with a delayed-acknowledgement device and no selective
	// acknowledgement anywhere: the retransmissions stay at the loss count
	// rather than running away. Without the guard on the duplicates its own
	// retransmissions draw, the verifier's probe measured thousands of
	// retransmissions for four losses.
	if !four.exact {
		t.Errorf("S9: the four-loss arm delivered %d of %d bytes, and not the origin's bytes exactly",
			four.deliveredByteCount, pathInnerOriginByteCount)
	}
	// Five segments exactly: one for each loss, and one the burst guesses
	// past the consecutive pair, which is how the run grows from the head
	// alone. A bound with slack in it would have let a dozen spurious
	// segments through as a repair.
	if want := four.lossCount + 1; four.retransmitted != want {
		t.Errorf("S9: the four-loss arm sent %d segments again for %d lost, want %d: one for each loss and one guess past the pair",
			four.retransmitted, four.lossCount, want)
	}

	// And the repair costs nothing when nothing is lost. Nothing here tells
	// this arm from the same flow with the repair off, which is why the arm
	// reads its flow's own setting above: what it pins is that a flow with
	// the repair on and no loss to repair sends not one segment twice.
	if !clean.exact || 0 < clean.retransmitted || 0 < clean.providerStats.PacketCount {
		t.Errorf("S9: the lossless arm delivered %d bytes and sent %d segments again (%d by the flow's own count), want the whole origin and none",
			clean.deliveredByteCount, clean.retransmitted, clean.providerStats.PacketCount)
	}
}
