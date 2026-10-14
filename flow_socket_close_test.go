package connect

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect/protocol"
)

// Flow socket closes bounded per buffer (flow_socket_close.go). A Windows
// device's local nat evicted ~10,000 udp flows whose closesocket each held an
// OS thread, until the Go runtime stopped at its thread limit. These tests
// hold every upstream close at a barrier, the way a slow kernel close does,
// and check that a buffer neither runs more closes at once than its limiter
// allows nor keeps evicting live flows while its closing backlog is full.

// Holds every Close at `release`, counting the closes inside at once.
type testCloseBarrier struct {
	entered   chan struct{}
	release   chan struct{}
	inside    atomic.Int64
	maxInside atomic.Int64
	closed    atomic.Int64
	once      sync.Once
	// while set, every write of a held socket fails
	failWrites atomic.Bool
}

var errTestWrite = errors.New("test write refused")

func newTestCloseBarrier() *testCloseBarrier {
	return &testCloseBarrier{
		entered: make(chan struct{}, 1024),
		release: make(chan struct{}),
	}
}

func (self *testCloseBarrier) hold(closeSocket func() error) error {
	inside := self.inside.Add(1)
	for {
		maxInside := self.maxInside.Load()
		if inside <= maxInside || self.maxInside.CompareAndSwap(maxInside, inside) {
			break
		}
	}
	self.entered <- struct{}{}
	<-self.release
	self.inside.Add(-1)
	self.closed.Add(1)
	return closeSocket()
}

func (self *testCloseBarrier) open() {
	self.once.Do(func() {
		close(self.release)
	})
}

type testHeldUdpConn struct {
	*net.UDPConn
	barrier *testCloseBarrier
}

func (self *testHeldUdpConn) Close() error {
	return self.barrier.hold(self.UDPConn.Close)
}

func (self *testHeldUdpConn) Write(b []byte) (int, error) {
	if self.barrier.failWrites.Load() {
		return 0, errTestWrite
	}
	return self.UDPConn.Write(b)
}

type testHeldTcpConn struct {
	*net.TCPConn
	barrier *testCloseBarrier
}

func (self *testHeldTcpConn) Close() error {
	return self.barrier.hold(self.TCPConn.Close)
}

// A dial whose sockets close at `barrier`, signaling `opened` once a socket is
// connected so a test can order each eviction after its flow has a socket.
func testHeldCloseDial(barrier *testCloseBarrier, opened chan<- struct{}) *DialContextSettings {
	return &DialContextSettings{
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			defer func() {
				opened <- struct{}{}
			}()
			switch v := conn.(type) {
			case *net.UDPConn:
				return &testHeldUdpConn{UDPConn: v, barrier: barrier}, nil
			case *net.TCPConn:
				return &testHeldTcpConn{TCPConn: v, barrier: barrier}, nil
			default:
				return conn, nil
			}
		},
	}
}

func waitTestSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(10 * time.Second):
		t.Fatalf("timeout waiting for %s", description)
	}
}

// What a capped buffer of either family exposes to these tests.
type testClosingBuffer struct {
	send          func(sourcePort uint16) bool
	sequenceCount func() int
	occupied      func() int
	closeWaiting  func() int
	// the indexed flow of the source port, nil when there is none
	sequenceFor func(sourcePort uint16) any
}

// The buffer runs until the test ends; cleanup opens the barrier, cancels and
// joins the buffer's lifecycle, then reconciles the message pool.
func newTestClosingUdpBuffer(t *testing.T, ipVersion int, settings *UdpBufferSettings, barrier *testCloseBarrier) testClosingBuffer {
	assertMessagePoolOwnership(t)
	sinkPort, closeSink := startUdpSink(t, ipVersion)
	t.Cleanup(closeSink)
	ctx, cancel := context.WithCancel(context.Background())
	receive := func(source TransferPath, provideMode protocol.ProvideMode, ipPath *IpPath, packet []byte) {}
	var buffer *UdpBuffer[BufferId4]
	var buffer6 *UdpBuffer[BufferId6]
	var send testUdpSendFunction
	if ipVersion == 6 {
		b := NewUdp6Buffer(ctx, receive, settings)
		buffer6 = &b.UdpBuffer
		send = b.send
	} else {
		b := NewUdp4Buffer(ctx, receive, settings)
		buffer = &b.UdpBuffer
		send = b.send
	}
	sourceIp, destinationIp := testFlowIps(ipVersion, 1)
	source := SourceId(NewId())
	closing := testClosingBuffer{
		send: func(sourcePort uint16) bool {
			packet := MessagePoolGet(32)
			parsed := &parsedUdp{
				sourceIp:        sourceIp,
				destinationIp:   destinationIp,
				sourcePort:      sourcePort,
				destinationPort: sinkPort,
				payload:         packet[:4],
			}
			success, err := send(source, protocol.ProvideMode_Network, parsed, -1, packet)
			if err != nil {
				t.Fatalf("udp send %d: %v", sourcePort, err)
			}
			if !success {
				MessagePoolReturn(packet)
			}
			return success
		},
	}
	if buffer6 != nil {
		closing.sequenceCount = udpFlowBufferState(buffer6).sequenceCount
		closing.occupied = buffer6.socketOccupancy.occupied
		closing.closeWaiting = buffer6.socketCloseLimiter.waiting
		closing.sequenceFor = udpSequenceForTest(buffer6)
	} else {
		closing.sequenceCount = udpFlowBufferState(buffer).sequenceCount
		closing.occupied = buffer.socketOccupancy.occupied
		closing.closeWaiting = buffer.socketCloseLimiter.waiting
		closing.sequenceFor = udpSequenceForTest(buffer)
	}
	t.Cleanup(func() {
		barrier.open()
		cancel()
		if buffer6 != nil {
			buffer6.waitForLifecycle()
		} else {
			buffer.waitForLifecycle()
		}
	})
	return closing
}

func udpSequenceForTest[BufferId comparable](buffer *UdpBuffer[BufferId]) func(sourcePort uint16) any {
	return func(sourcePort uint16) any {
		buffer.mutex.Lock()
		defer buffer.mutex.Unlock()
		for _, sequence := range buffer.sequences {
			if sequence.sourcePort == sourcePort {
				return sequence
			}
		}
		return nil
	}
}

func tcpSequenceForTest[BufferId comparable](buffer *TcpBuffer[BufferId]) func(sourcePort uint16) any {
	return func(sourcePort uint16) any {
		buffer.mutex.Lock()
		defer buffer.mutex.Unlock()
		for _, sequence := range buffer.sequences {
			if sequence.sourcePort == sourcePort {
				return sequence
			}
		}
		return nil
	}
}

func newTestClosingTcpBuffer(t *testing.T, ipVersion int, settings *TcpBufferSettings, barrier *testCloseBarrier) testClosingBuffer {
	assertMessagePoolOwnership(t)
	listenerPort, closeListener := startTcpHoldListener(t, ipVersion)
	t.Cleanup(closeListener)
	ctx, cancel := context.WithCancel(context.Background())
	receive := func(source TransferPath, provideMode protocol.ProvideMode, ipPath *IpPath, packet []byte) {}
	var buffer *TcpBuffer[BufferId4]
	var buffer6 *TcpBuffer[BufferId6]
	var send testTcpSendFunction
	if ipVersion == 6 {
		b := NewTcp6Buffer(ctx, receive, settings)
		buffer6 = &b.TcpBuffer
		send = b.send
	} else {
		b := NewTcp4Buffer(ctx, receive, settings)
		buffer = &b.TcpBuffer
		send = b.send
	}
	sourceIp, destinationIp := testFlowIps(ipVersion, 1)
	source := SourceId(NewId())
	closing := testClosingBuffer{
		send: func(sourcePort uint16) bool {
			packet := MessagePoolGet(32)
			parsed := &parsedTcp{
				sourceIp:        sourceIp,
				destinationIp:   destinationIp,
				sourcePort:      sourcePort,
				destinationPort: listenerPort,
				syn:             true,
				seq:             1000,
				windowSize:      65535,
			}
			success, err := send(source, protocol.ProvideMode_Network, parsed, -1, packet)
			if err != nil {
				t.Fatalf("tcp syn %d: %v", sourcePort, err)
			}
			if !success {
				MessagePoolReturn(packet)
			}
			return success
		},
	}
	if buffer6 != nil {
		closing.sequenceCount = tcpFlowBufferState(buffer6).sequenceCount
		closing.occupied = buffer6.socketOccupancy.occupied
		closing.closeWaiting = buffer6.socketCloseLimiter.waiting
		closing.sequenceFor = tcpSequenceForTest(buffer6)
	} else {
		closing.sequenceCount = tcpFlowBufferState(buffer).sequenceCount
		closing.occupied = buffer.socketOccupancy.occupied
		closing.closeWaiting = buffer.socketCloseLimiter.waiting
		closing.sequenceFor = tcpSequenceForTest(buffer)
	}
	t.Cleanup(func() {
		barrier.open()
		cancel()
		if buffer6 != nil {
			buffer6.waitForLifecycle()
		} else {
			buffer.waitForLifecycle()
		}
	})
	return closing
}

// Evicts three flows from a one-flow cap while every close is held: one close
// runs and two wait for its slot, and none runs beside it.
func testEvictionWaitsForCloseSlots(t *testing.T, buffer testClosingBuffer, barrier *testCloseBarrier, opened <-chan struct{}) {
	for _, sourcePort := range []uint16{40001, 40002, 40003, 40004} {
		if !buffer.send(sourcePort) {
			t.Fatalf("flow %d was not admitted", sourcePort)
		}
		waitTestSignal(t, opened, "the flow's socket to open")
	}
	waitTestSignal(t, barrier.entered, "the first eviction's close")
	// a second close entering while the first holds the only slot fails at
	// once
	deadline := time.After(10 * time.Second)
	for buffer.closeWaiting() != 2 {
		select {
		case <-barrier.entered:
			t.Fatal("a second close ran beside the first with one close slot")
		case <-deadline:
			t.Fatal("timeout waiting for two evicted flows to wait for a close slot")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if inside := barrier.inside.Load(); inside != 1 {
		t.Fatalf("%d closes ran at once with one close slot", inside)
	}
	barrier.open()
	pollUntil(t, 10*time.Second, "the evicted flows to finish closing", func() bool {
		return barrier.closed.Load() == 3 && buffer.occupied() == 1
	})
	if maxInside := barrier.maxInside.Load(); maxInside != 1 {
		t.Fatalf("at most %d closes ran at once with one close slot", maxInside)
	}
}

func TestUdpBufferEvictionWaitsForCloseSlots(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		barrier := newTestCloseBarrier()
		opened := make(chan struct{}, 16)
		settings := DefaultUdpBufferSettingsWithBufferSize(8)
		settings.GlobalLimit = 1
		settings.SocketCloseConcurrency = 1
		settings.SocketCloseBacklogLimit = -1
		settings.DialContextSettings = testHeldCloseDial(barrier, opened)
		buffer := newTestClosingUdpBuffer(t, ipVersion, settings, barrier)
		testEvictionWaitsForCloseSlots(t, buffer, barrier, opened)
	})
}

func TestTcpBufferEvictionWaitsForCloseSlots(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		barrier := newTestCloseBarrier()
		opened := make(chan struct{}, 16)
		settings := DefaultTcpBufferSettingsWithBufferSize(8)
		settings.GlobalLimit = 1
		settings.SocketCloseConcurrency = 1
		settings.SocketCloseBacklogLimit = -1
		settings.DialContextSettings = testHeldCloseDial(barrier, opened)
		buffer := newTestClosingTcpBuffer(t, ipVersion, settings, barrier)
		testEvictionWaitsForCloseSlots(t, buffer, barrier, opened)
	})
}

// With a two-flow cap and a backlog limit of two, two evictions whose closes
// are held fill the backlog: the next new flow is refused and evicts nothing,
// and once the closes finish a new flow is admitted again.
func testFullCloseBacklogRefusesNewFlows(t *testing.T, buffer testClosingBuffer, barrier *testCloseBarrier, opened <-chan struct{}) {
	for _, sourcePort := range []uint16{40001, 40002, 40003, 40004} {
		if !buffer.send(sourcePort) {
			t.Fatalf("flow %d was not admitted", sourcePort)
		}
		waitTestSignal(t, opened, "the flow's socket to open")
	}
	if occupied, live := buffer.occupied(), buffer.sequenceCount(); occupied != 4 || live != 2 {
		t.Fatalf("occupied=%d live=%d, want two live flows and two closing", occupied, live)
	}
	if buffer.send(40005) {
		t.Fatal("a new flow was admitted while the closing backlog was full")
	}
	if occupied, live := buffer.occupied(), buffer.sequenceCount(); occupied != 4 || live != 2 {
		t.Fatalf("the refusal evicted a flow: occupied=%d live=%d", occupied, live)
	}
	barrier.open()
	pollUntil(t, 10*time.Second, "the evicted flows to finish closing", func() bool {
		return buffer.occupied() == 2
	})
	if !buffer.send(40005) {
		t.Fatal("a new flow was refused after the backlog drained")
	}
	waitTestSignal(t, opened, "the admitted flow's socket to open")
}

func TestUdpBufferFullCloseBacklogRefusesNewFlows(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		barrier := newTestCloseBarrier()
		opened := make(chan struct{}, 16)
		settings := DefaultUdpBufferSettingsWithBufferSize(8)
		settings.GlobalLimit = 2
		settings.SocketCloseBacklogLimit = 2
		settings.DialContextSettings = testHeldCloseDial(barrier, opened)
		buffer := newTestClosingUdpBuffer(t, ipVersion, settings, barrier)
		testFullCloseBacklogRefusesNewFlows(t, buffer, barrier, opened)
	})
}

func TestTcpBufferFullCloseBacklogRefusesNewFlows(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		barrier := newTestCloseBarrier()
		opened := make(chan struct{}, 16)
		settings := DefaultTcpBufferSettingsWithBufferSize(8)
		settings.GlobalLimit = 2
		settings.SocketCloseBacklogLimit = 2
		settings.DialContextSettings = testHeldCloseDial(barrier, opened)
		buffer := newTestClosingTcpBuffer(t, ipVersion, settings, barrier)
		testFullCloseBacklogRefusesNewFlows(t, buffer, barrier, opened)
	})
}

// A flow that ends on its own (here a failed write) while the only close slot
// is held must stop taking packets before it waits for a slot: the next
// packet on its tuple replaces it instead of queueing behind a flow that will
// never write again.
func TestUdpBufferFlowThatEndsIsReplacedWhileItWaitsForACloseSlot(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		barrier := newTestCloseBarrier()
		barrier.failWrites.Store(true)
		opened := make(chan struct{}, 16)
		settings := DefaultUdpBufferSettingsWithBufferSize(8)
		settings.SocketCloseConcurrency = 1
		settings.SocketCloseBacklogLimit = -1
		settings.DialContextSettings = testHeldCloseDial(barrier, opened)
		buffer := newTestClosingUdpBuffer(t, ipVersion, settings, barrier)
		testFlowThatEndsIsReplaced(t, buffer, barrier, opened)
	})
}

func testFlowThatEndsIsReplaced(t *testing.T, buffer testClosingBuffer, barrier *testCloseBarrier, opened <-chan struct{}) {
	// the first flow ends and its close takes the only slot
	if !buffer.send(40001) {
		t.Fatal("the first flow was not admitted")
	}
	waitTestSignal(t, opened, "the first flow's socket to open")
	waitTestSignal(t, barrier.entered, "the first flow's close")
	// the second flow ends and its close waits for the slot
	if !buffer.send(40002) {
		t.Fatal("the second flow was not admitted")
	}
	waitTestSignal(t, opened, "the second flow's socket to open")
	pollUntil(t, 10*time.Second, "the second flow to wait for a close slot", func() bool {
		return buffer.closeWaiting() == 1
	})
	ended := buffer.sequenceFor(40002)
	if ended == nil {
		t.Fatal("the ended flow left the index before its close")
	}
	if !buffer.send(40002) {
		t.Fatal("a packet on the ended flow's tuple was not taken")
	}
	if buffer.sequenceFor(40002) == ended {
		t.Fatal("a packet on the ended flow's tuple went to the flow that is waiting to close")
	}
}

type testHeldCloser struct {
	barrier *testCloseBarrier
}

func (self testHeldCloser) Close() error {
	return self.barrier.hold(func() error { return nil })
}

// The limiter alone: six closes with two slots run two at a time.
func TestFlowSocketCloseLimiterBoundsConcurrentCloses(t *testing.T) {
	limiter := newFlowSocketCloseLimiter(2, nil, "test")
	barrier := newTestCloseBarrier()
	defer barrier.open()
	var closes sync.WaitGroup
	for range 6 {
		closes.Add(1)
		go func() {
			defer closes.Done()
			_ = limiter.close(testHeldCloser{barrier: barrier})
		}()
	}
	waitTestSignal(t, barrier.entered, "the first close")
	waitTestSignal(t, barrier.entered, "the second close")
	pollUntil(t, 10*time.Second, "four closes waiting for a slot", func() bool {
		return limiter.waiting() == 4
	})
	if inside := barrier.inside.Load(); inside != 2 {
		t.Fatalf("%d closes ran at once with two slots", inside)
	}
	barrier.open()
	closes.Wait()
	if maxInside := barrier.maxInside.Load(); maxInside != 2 {
		t.Fatalf("at most %d closes ran at once with two slots", maxInside)
	}
	if waiting := limiter.waiting(); waiting != 0 {
		t.Fatalf("%d closes still counted as waiting", waiting)
	}
}

// A nil limiter and a nil occupancy are inert, for buffers and sequences
// built directly.
func TestFlowSocketCloseNilIsInert(t *testing.T) {
	var limiter *flowSocketCloseLimiter
	barrier := newTestCloseBarrier()
	barrier.open()
	if err := limiter.close(testHeldCloser{barrier: barrier}); err != nil {
		t.Fatal(err)
	}
	if barrier.closed.Load() != 1 {
		t.Fatal("a nil limiter did not close")
	}
	var occupancy *flowSocketOccupancy
	occupancy.occupy()()
	if !occupancy.admit(0, 1) || occupancy.occupied() != 0 {
		t.Fatal("a nil occupancy is not inert")
	}
}

func TestFlowSocketCloseBacklogLimit(t *testing.T) {
	cases := []struct {
		configured  int
		globalLimit int
		want        int
	}{
		{configured: 0, globalLimit: 0, want: 0},
		{configured: 0, globalLimit: 100, want: minFlowSocketCloseBacklogLimit},
		{configured: 0, globalLimit: 2048, want: 512},
		{configured: 3, globalLimit: 2048, want: 3},
		{configured: 3, globalLimit: 0, want: 3},
		{configured: -1, globalLimit: 2048, want: 0},
	}
	for _, c := range cases {
		if got := flowSocketCloseBacklogLimit(c.configured, c.globalLimit); got != c.want {
			t.Errorf("flowSocketCloseBacklogLimit(%d, %d) = %d, want %d", c.configured, c.globalLimit, got, c.want)
		}
	}
}
