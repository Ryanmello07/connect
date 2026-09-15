//go:build linux || darwin

package connect

import (
	"context"
	mathrandv2 "math/rand/v2"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These tests bind real loopback sockets. A planned port can be taken by
// another socket of the machine between the draw and the bind, so a random
// hands out a fresh port on each draw and records it: the bound port is the
// last port handed out, and never one the kernel chose.

// A random for a plan that hands out distinct ports of the ephemeral range and
// records them. Safe for concurrent use.
type testingH1SourcePortRandom struct {
	stateLock sync.Mutex
	random    *mathrandv2.Rand
	// replaces the draw when set; returns a port
	nextPort     func(drawIndex int) int
	offeredPorts []int
}

func newTestingH1SourcePortRandom(seed uint64) *testingH1SourcePortRandom {
	return &testingH1SourcePortRandom{
		random: mathrandv2.New(mathrandv2.NewPCG(seed, 11)),
	}
}

func (self *testingH1SourcePortRandom) intN(n int) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lowPort, _ := h1EphemeralPortRange()
	port := lowPort + self.random.IntN(n)
	if self.nextPort != nil {
		port = self.nextPort(len(self.offeredPorts))
	}
	self.offeredPorts = append(self.offeredPorts, port)
	return port - lowPort
}

func (self *testingH1SourcePortRandom) offered() []int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]int{}, self.offeredPorts...)
}

func testingTcpAddrPort(t *testing.T, addr net.Addr) int {
	t.Helper()
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("address %v is not tcp", addr)
	}
	return tcpAddr.Port
}

// the local port of the socket, zero while it is unbound
func testingRawConnLocalPort(rawConn syscall.RawConn) (port int, err error) {
	controlErr := rawConn.Control(func(fd uintptr) {
		var sockaddr syscall.Sockaddr
		sockaddr, err = syscall.Getsockname(int(fd))
		switch v := sockaddr.(type) {
		case *syscall.SockaddrInet4:
			port = v.Port
		case *syscall.SockaddrInet6:
			port = v.Port
		}
	})
	if controlErr != nil {
		return 0, controlErr
	}
	return port, err
}

// accepts one connection and returns its remote port
func testingAcceptRemotePort(t *testing.T, listener net.Listener) <-chan int {
	remotePorts := make(chan int, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(remotePorts)
			return
		}
		defer conn.Close()
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			remotePorts <- tcpAddr.Port
		}
		close(remotePorts)
	}()
	return remotePorts
}

// A planned dial binds the drawn port after DialControl, which runs once on
// the still unbound socket.
func TestH1SourcePortDialerBindsPlannedPort(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		listener, err := net.Listen(testTcpNetwork(ipVersion), testLoopbackHostPort(ipVersion, 0))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		remotePorts := testingAcceptRemotePort(t, listener)

		settings := DefaultH1PathRerollSettings()
		stats := &h1PathStats{}
		random := newTestingH1SourcePortRandom(uint64(ipVersion))
		plan := newH1SourcePortPlan(&settings, nil, random.intN, stats)
		ctx := withH1SourcePortPlan(context.Background(), plan)

		connectSettings := DefaultConnectSettings()
		var controlNetworks []string
		var controlLocalPorts []int
		connectSettings.DialControl = func(network string, address string, rawConn syscall.RawConn) error {
			localPort, err := testingRawConnLocalPort(rawConn)
			if err != nil {
				return err
			}
			controlNetworks = append(controlNetworks, network)
			controlLocalPorts = append(controlLocalPorts, localPort)
			return nil
		}
		conn, err := connectSettings.DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		offeredPorts := random.offered()
		if len(offeredPorts) == 0 {
			t.Fatal("the dial drew no port")
		}
		plannedPort := offeredPorts[len(offeredPorts)-1]
		if localPort := testingTcpAddrPort(t, conn.LocalAddr()); localPort != plannedPort {
			t.Fatalf("local port %d, want the planned port %d (offered %v)", localPort, plannedPort, offeredPorts)
		}
		select {
		case remotePort := <-remotePorts:
			if remotePort != plannedPort {
				t.Fatalf("the listener saw port %d, want the planned port %d", remotePort, plannedPort)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("the listener accepted nothing")
		}
		if len(controlNetworks) != 1 || controlNetworks[0] != testTcpNetwork(ipVersion) || controlLocalPorts[0] != 0 {
			t.Fatalf("DialControl saw networks %v with local ports %v, want one unbound %s socket", controlNetworks, controlLocalPorts, testTcpNetwork(ipVersion))
		}
		if snapshot := stats.snapshot(); snapshot.SourcePortBinds != 1 || snapshot.SourcePortFallbacks != 0 {
			t.Fatalf("stats = %+v, want one bind", snapshot)
		}
	})
}

// A listener already holds the only port the plan draws: every bind attempt
// finds it in use, and the dial still succeeds on the kernel's port.
func TestH1SourcePortDialerFallsBackWhenPortBusy(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		listener, err := net.Listen(testTcpNetwork(ipVersion), testLoopbackHostPort(ipVersion, 0))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		remotePorts := testingAcceptRemotePort(t, listener)

		// a port of the ephemeral range, held for the whole dial
		lowPort, highPort := h1EphemeralPortRange()
		portRandom := mathrandv2.New(mathrandv2.NewPCG(uint64(ipVersion), 13))
		var busyListener net.Listener
		for range 64 {
			port := lowPort + portRandom.IntN(highPort-lowPort+1)
			busyListener, err = net.Listen(testTcpNetwork(ipVersion), testLoopbackHostPort(ipVersion, port))
			if err == nil {
				break
			}
		}
		if busyListener == nil {
			t.Fatal("no free port of the ephemeral range to hold")
		}
		defer busyListener.Close()
		busyPort := testingTcpAddrPort(t, busyListener.Addr())

		settings := DefaultH1PathRerollSettings()
		stats := &h1PathStats{}
		random := newTestingH1SourcePortRandom(uint64(ipVersion))
		random.nextPort = func(drawIndex int) int {
			return busyPort
		}
		plan := newH1SourcePortPlan(&settings, nil, random.intN, stats)
		ctx := withH1SourcePortPlan(context.Background(), plan)

		conn, err := DefaultConnectSettings().DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("the dial failed with its planned port busy: %v", err)
		}
		defer conn.Close()
		if localPort := testingTcpAddrPort(t, conn.LocalAddr()); localPort == busyPort {
			t.Fatalf("local port %d is the busy port", localPort)
		}
		select {
		case <-remotePorts:
		case <-time.After(15 * time.Second):
			t.Fatal("the listener accepted nothing")
		}
		if offeredPorts := random.offered(); len(offeredPorts) != h1SourcePortBindAttempts {
			t.Fatalf("the plan drew %d ports, want one per bind attempt (%d)", len(offeredPorts), h1SourcePortBindAttempts)
		}
		if snapshot := stats.snapshot(); snapshot.SourcePortBinds != 0 || snapshot.SourcePortFallbacks != 1 {
			t.Fatalf("stats = %+v, want one fallback", snapshot)
		}
	})
}

// A family-pinned strategy's inner dial applies the plan.
func TestPinnedDirectStrategyAppliesSourcePortPlan(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		listener, err := net.Listen(testTcpNetwork(ipVersion), testLoopbackHostPort(ipVersion, 0))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		remotePorts := testingAcceptRemotePort(t, listener)

		strategy := NewDirectClientStrategy(ctx, DefaultClientStrategySettings(), ipVersion)
		dialContextSettings := strategy.settings.ConnectSettings.DialContextSettings
		if dialContextSettings == nil || dialContextSettings.DialContext == nil {
			t.Fatal("the pinned strategy has no inner dial")
		}

		settings := DefaultH1PathRerollSettings()
		stats := &h1PathStats{}
		random := newTestingH1SourcePortRandom(uint64(ipVersion))
		plan := newH1SourcePortPlan(&settings, nil, random.intN, stats)
		conn, err := dialContextSettings.DialContext(withH1SourcePortPlan(ctx, plan), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		offeredPorts := random.offered()
		if len(offeredPorts) == 0 {
			t.Fatal("the pinned dial drew no port")
		}
		plannedPort := offeredPorts[len(offeredPorts)-1]
		select {
		case remotePort := <-remotePorts:
			if remotePort != plannedPort {
				t.Fatalf("the listener saw port %d, want the planned port %d", remotePort, plannedPort)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("the listener accepted nothing")
		}
		if snapshot := stats.snapshot(); snapshot.SourcePortBinds != 1 || snapshot.SourcePortFallbacks != 0 {
			t.Fatalf("stats = %+v, want one bind", snapshot)
		}
	})
}

// A re-roll dial binds a planned port away from the convicted one. Connections
// 0 and 1 collapse and are re-rolled; connection 2 is healthy. For each re-roll
// dial the random first offers ports just above the latest convicted port,
// inside its excluded window, so a plan that did not exclude it would bind one
// of them; after that it offers far ports. The first dial is not planned.
func TestPlatformTransportH1PathRerollDialUsesPlannedSourcePort(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		platform := newTestingPlatformServerIpVersion(t, ipVersion)
		rig := newTestingH1PathRig(func(connectionOrdinal int, tickIndex int) testingH1PathClass {
			if connectionOrdinal < 2 {
				return testingH1PathCollapsed
			}
			return testingH1PathHealthy
		})
		settings := testingH1PathTransportSettings(H1PathRerollModeAct, rig)
		settings.H1PathReroll.DeviceRerollSpacing = 50 * time.Millisecond
		radius := settings.H1PathReroll.SourcePortExcludeRadius
		lowPort, highPort := h1EphemeralPortRange()

		random := newTestingH1SourcePortRandom(uint64(ipVersion))
		var planLock sync.Mutex
		unplannedDraws := 0
		nearDraws := map[int]int{}
		farPort := lowPort
		random.nextPort = func(drawIndex int) int {
			excludedPorts := rig.ledger.excluded()
			planLock.Lock()
			defer planLock.Unlock()
			if len(excludedPorts) == 0 {
				unplannedDraws += 1
				return lowPort
			}
			latestPort := excludedPorts[len(excludedPorts)-1]
			if nearDraws[len(excludedPorts)] < h1SourcePortPickDraws {
				nearDraws[len(excludedPorts)] += 1
				return latestPort + 1 + nearDraws[len(excludedPorts)]%radius
			}
			// distinct ports spread over the range
			farPort = lowPort + (farPort-lowPort+7919)%(highPort-lowPort+1)
			return farPort
		}
		settings.h1PathTestHooks.sourcePortRandom = random.intN
		transport := testingPlatformTransport(t, ctx, platform.url, settings)

		if !waitForCondition(15*time.Second, func() bool {
			return 2*settings.H1PathReroll.CleanTicks <= len(rig.connectionDecisions(2))
		}) {
			t.Fatalf("connections %v, want two re-rolls and a healthy third connection", rig.dials())
		}
		testingH1PathRequireRerolled(t, rig, 0)
		testingH1PathRequireRerolled(t, rig, 1)
		if convictionCount, _ := rig.convictions(2); convictionCount != 0 {
			t.Fatalf("the healthy connection convicted %d times", convictionCount)
		}

		excludedPorts := rig.ledger.excluded()
		if len(excludedPorts) != 2 || excludedPorts[0] <= 0 || excludedPorts[1] <= 0 {
			t.Fatalf("convicted ports %v, want the ports of connections 0 and 1", excludedPorts)
		}
		convictedPort, rerolledPort := excludedPorts[0], excludedPorts[1]
		offeredPorts := random.offered()
		offered := false
		for _, port := range offeredPorts {
			if port == rerolledPort {
				offered = true
			}
		}
		if !offered {
			t.Fatalf("connection 1 used port %d, which the plan never drew (convicted %d): the kernel chose it", rerolledPort, convictedPort)
		}
		if distance := rerolledPort - convictedPort; -radius <= distance && distance <= radius {
			t.Fatalf("connection 1 used port %d, within %d of the convicted port %d", rerolledPort, radius, convictedPort)
		}
		planLock.Lock()
		if unplannedDraws != 0 || nearDraws[1] == 0 || nearDraws[2] == 0 {
			t.Errorf("draws without a convicted port %d, near draws %v: want only planned re-roll dials, each offered its window", unplannedDraws, nearDraws)
		}
		planLock.Unlock()
		stats := rig.stats.snapshot()
		if stats.Rerolls != 2 || stats.RerollDials != 2 || stats.SourcePortBinds < 2 {
			t.Fatalf("stats = %+v, want two re-roll dials with bound ports", stats)
		}
		if !transport.IsConnected() {
			t.Fatal("the transport is not connected after the re-rolls")
		}
	})
}
