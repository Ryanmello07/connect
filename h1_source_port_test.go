package connect

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

// The plan's pick is driven by a random that walks every index of the range in
// order, so the picks cover the whole range and reach both edges of each
// excluded window.
func TestH1SourcePortPlanPickExcludesConvictedWindows(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	radius := settings.SourcePortExcludeRadius
	excludedPorts := []int{40004, 50000}
	nextIndex := 0
	plan := newH1SourcePortPlan(&settings, excludedPorts, func(n int) int {
		index := nextIndex % n
		nextIndex += 1
		return index
	}, &h1PathStats{})
	lowPort, highPort := h1EphemeralPortRange()
	if plan.lowPort != lowPort || plan.highPort != highPort || plan.excludeRadius != radius {
		t.Fatalf("plan range %d-%d radius %d, want %d-%d radius %d", plan.lowPort, plan.highPort, plan.excludeRadius, lowPort, highPort, radius)
	}
	excludedPorts[0] = 0
	if plan.excludedPorts[0] != 40004 {
		t.Fatal("the plan shares the caller's excluded ports")
	}

	pickedPorts := map[int]bool{}
	for range max(10000, highPort-lowPort+1) {
		port, ok := plan.pick()
		if !ok {
			t.Fatal("no port picked from a mostly free range")
		}
		if port < lowPort || highPort < port {
			t.Fatalf("picked port %d outside %d-%d", port, lowPort, highPort)
		}
		for _, excludedPort := range []int{40004, 50000} {
			if distance := port - excludedPort; -radius <= distance && distance <= radius {
				t.Fatalf("picked port %d within %d of convicted port %d", port, radius, excludedPort)
			}
		}
		pickedPorts[port] = true
	}
	for _, excludedPort := range []int{40004, 50000} {
		for _, edgePort := range []int{excludedPort - radius - 1, excludedPort + radius + 1} {
			if lowPort <= edgePort && edgePort <= highPort && !pickedPorts[edgePort] {
				t.Errorf("port %d, just outside the window of %d, was never picked", edgePort, excludedPort)
			}
		}
	}

	// a random that strays outside [0, n) still picks inside the range
	plan.random = func(n int) int {
		return -3*n - 1
	}
	if port, ok := plan.pick(); !ok || port < lowPort || highPort < port {
		t.Fatalf("stray random picked %d, %t", port, ok)
	}
}

// With every port inside an excluded window, the pick fails after its scan.
func TestH1SourcePortPlanExhausted(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	lowPort, highPort := h1EphemeralPortRange()
	settings.SourcePortExcludeRadius = highPort - lowPort
	stats := &h1PathStats{}
	plan := newH1SourcePortPlan(&settings, []int{lowPort}, nil, stats)
	if port, ok := plan.pick(); ok {
		t.Fatalf("picked port %d from an exhausted range", port)
	}
	// an exhausted plan leaves the port to the kernel
	plan.bind("tcp4", nil)
	if snapshot := stats.snapshot(); snapshot.SourcePortBinds != 0 || snapshot.SourcePortFallbacks != 1 {
		t.Fatalf("stats = %+v, want one fallback", snapshot)
	}
}

// Without a plan the dialer is the same pointer, and so is a dialer with an
// explicit local address.
func TestH1SourcePortDialerIsInertWithoutPlan(t *testing.T) {
	dialer := DefaultConnectSettings().NetDialer()
	if h1SourcePortDialer(context.Background(), dialer) != dialer {
		t.Fatal("a dial without a plan got another dialer")
	}
	if h1SourcePortPlanFromContext(context.Background()) != nil {
		t.Fatal("a plain context carries a plan")
	}

	settings := DefaultH1PathRerollSettings()
	plan := newH1SourcePortPlan(&settings, nil, nil, &h1PathStats{})
	ctx := withH1SourcePortPlan(context.Background(), plan)
	if h1SourcePortPlanFromContext(ctx) != plan {
		t.Fatal("the context does not carry the plan")
	}
	localDialer := DefaultConnectSettings().NetDialer()
	localDialer.LocalAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	if h1SourcePortDialer(ctx, localDialer) != localDialer {
		t.Fatal("a dialer with a local address got another dialer")
	}
}

// A planned dialer is a copy. Its control runs the dialer's own control first
// and returns that control's error without binding, and it leaves networks
// other than tcp4 and tcp6 alone.
func TestH1SourcePortDialerChainsTheDialersControl(t *testing.T) {
	settings := DefaultH1PathRerollSettings()
	stats := &h1PathStats{}
	plan := newH1SourcePortPlan(&settings, nil, nil, stats)
	ctx := withH1SourcePortPlan(context.Background(), plan)

	controlErr := errors.New("control refused")
	controlCount := 0
	dialer := &net.Dialer{
		Control: func(network string, address string, rawConn syscall.RawConn) error {
			controlCount += 1
			return controlErr
		},
	}
	planned := h1SourcePortDialer(ctx, dialer)
	if planned == dialer || dialer.Control == nil || dialer.ControlContext != nil {
		t.Fatal("the planned dialer is not a copy that leaves the original alone")
	}
	if planned.Control != nil || planned.ControlContext == nil {
		t.Fatal("the planned dialer did not move its control into ControlContext")
	}
	if err := planned.ControlContext(ctx, "tcp4", "192.0.2.1:443", nil); !errors.Is(err, controlErr) {
		t.Fatalf("control error = %v, want the dialer's own", err)
	}
	if controlCount != 1 {
		t.Fatalf("the dialer's control ran %d times, want once", controlCount)
	}

	controlErr = nil
	if err := planned.ControlContext(ctx, "udp4", "192.0.2.1:443", nil); err != nil {
		t.Fatalf("udp control error = %v", err)
	}
	if controlCount != 2 {
		t.Fatalf("the dialer's control ran %d times, want twice", controlCount)
	}
	if snapshot := stats.snapshot(); snapshot.SourcePortBinds != 0 || snapshot.SourcePortFallbacks != 0 {
		t.Fatalf("stats = %+v, want no bind attempt", snapshot)
	}

	// a ControlContext of the dialer's own wins over its Control, as in net.Dialer
	contextControlCount := 0
	dialer.ControlContext = func(ctx context.Context, network string, address string, rawConn syscall.RawConn) error {
		contextControlCount += 1
		return controlErr
	}
	controlErr = errors.New("context control refused")
	planned = h1SourcePortDialer(ctx, dialer)
	if err := planned.ControlContext(ctx, "tcp6", "[2001:db8::1]:443", nil); !errors.Is(err, controlErr) {
		t.Fatalf("control error = %v, want the dialer's own context control", err)
	}
	if contextControlCount != 1 || controlCount != 2 {
		t.Fatalf("context control ran %d times and control %d times, want 1 and 2", contextControlCount, controlCount)
	}
}

// A host's injected dial keeps its own source identity: a plan in the context
// binds nothing.
func TestH1SourcePortPlanLeavesInjectedDialAlone(t *testing.T) {
	forEachIpVersion(t, func(t *testing.T, ipVersion int) {
		listener, err := net.Listen(testTcpNetwork(ipVersion), testLoopbackHostPort(ipVersion, 0))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()

		settings := DefaultH1PathRerollSettings()
		stats := &h1PathStats{}
		randomCount := 0
		plan := newH1SourcePortPlan(&settings, nil, func(n int) int {
			randomCount += 1
			return 0
		}, stats)
		ctx := withH1SourcePortPlan(context.Background(), plan)

		connectSettings := DefaultConnectSettings()
		injectedCount := 0
		connectSettings.DialContextSettings = &DialContextSettings{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				injectedCount += 1
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, network, addr)
			},
		}
		conn, err := connectSettings.DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		if injectedCount != 1 || randomCount != 0 {
			t.Fatalf("injected dials %d, plan draws %d; want 1 and 0", injectedCount, randomCount)
		}
		if snapshot := stats.snapshot(); snapshot.SourcePortBinds != 0 || snapshot.SourcePortFallbacks != 0 {
			t.Fatalf("stats = %+v, want the injected dial unplanned", snapshot)
		}
	})
}
