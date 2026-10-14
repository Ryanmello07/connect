package connect

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
)

// The egress pin follows the socket's own family (egress.go). On Windows the
// ipv4 option succeeds on a dual-stack AF_INET6 socket, so taking the first
// option that succeeded reported such an ipv6 socket pinned while its native
// ipv6 followed the route table into the tunnel. A device whose host had no
// physical ipv6 most likely looped its local-route ipv6 flows through its own
// tunnel this way.

// One fake socket's two options, recording what was set.
type testEgressSockopts struct {
	ipv4Err error
	ipv6Err error
	ipv4Set int
	ipv6Set int
}

// `destination` is a peer as Control hands it ("" for none), parsed the way
// egressControl parses it.
func (self *testEgressSockopts) apply(family int, destination string, index4 uint32, index6 uint32) error {
	destinationAddr := netip.Addr{}
	if destination != "" {
		destinationAddr = egressDestination(net.JoinHostPort(destination, "53"))
	}
	return applyEgressPin(
		family,
		destinationAddr,
		index4,
		index6,
		func() error {
			self.ipv4Set += 1
			return self.ipv4Err
		},
		func() error {
			self.ipv6Set += 1
			return self.ipv6Err
		},
	)
}

var errTestSockopt = errors.New("test sockopt refused")

// The regression: the host has no physical ipv6 (index6 0) and the ipv4
// option succeeds on the ipv6 socket dialing a global peer. The socket is
// refused, not reported pinned.
func TestEgressPinRefusesAnIpv6SocketWithoutAnIpv6Interface(t *testing.T) {
	sockopts := &testEgressSockopts{}
	if err := sockopts.apply(6, "2001:db8::1", 7, 0); err == nil {
		t.Fatal("an ipv6 socket with no ipv6 egress interface was reported pinned")
	}
	if sockopts.ipv4Set != 1 || sockopts.ipv6Set != 0 {
		t.Fatalf("ipv4Set=%d ipv6Set=%d, want the ipv4-mapped option tried and no ipv6 option", sockopts.ipv4Set, sockopts.ipv6Set)
	}
	// a unique local peer is routed like any other
	if err := (&testEgressSockopts{}).apply(6, "fd00::1", 7, 0); err == nil {
		t.Fatal("an ipv6 dial to a unique local peer with no ipv6 egress interface was reported pinned")
	}
	// an already-created ipv6 socket, with no known peer, says so too
	listener := &testEgressSockopts{}
	if err := listener.apply(6, "", 7, 0); err == nil || listener.ipv4Set != 1 {
		t.Fatalf("an ipv6 socket with no known peer: err=%v ipv4Set=%d, want the ipv4 option tried and an error", err, listener.ipv4Set)
	}
}

// With an ipv6 interface, the ipv6 option is what pins the socket, and the
// ipv4-mapped option is best effort.
func TestEgressPinSetsTheIpv6OptionOnAnIpv6Socket(t *testing.T) {
	sockopts := &testEgressSockopts{ipv4Err: errTestSockopt}
	if err := sockopts.apply(6, "2001:db8::1", 7, 9); err != nil {
		t.Fatalf("an ipv6 socket with an ipv6 interface: %v", err)
	}
	if sockopts.ipv4Set != 1 || sockopts.ipv6Set != 1 {
		t.Fatalf("ipv4Set=%d ipv6Set=%d, want both options set", sockopts.ipv4Set, sockopts.ipv6Set)
	}
	failing := &testEgressSockopts{ipv6Err: errTestSockopt}
	if err := failing.apply(6, "2001:db8::1", 7, 9); !errors.Is(err, errTestSockopt) {
		t.Fatalf("a refused ipv6 option on an ipv6 socket: err=%v, want it reported", err)
	}
	ipv6Only := &testEgressSockopts{}
	if err := ipv6Only.apply(6, "2001:db8::1", 0, 9); err != nil || ipv6Only.ipv4Set != 0 {
		t.Fatalf("ipv6-only egress: err=%v ipv4Set=%d", err, ipv6Only.ipv4Set)
	}
	// a zoneless link-local peer, as the egress resolver and the nat hand it,
	// is pinned to the ipv6 egress interface
	zoneless := &testEgressSockopts{}
	if err := zoneless.apply(6, "fe80::1", 7, 9); err != nil || zoneless.ipv6Set != 1 {
		t.Fatalf("a zoneless link-local peer with an ipv6 interface: err=%v ipv6Set=%d", err, zoneless.ipv6Set)
	}
}

func TestEgressPinSetsTheIpv4OptionOnAnIpv4Socket(t *testing.T) {
	sockopts := &testEgressSockopts{}
	if err := sockopts.apply(4, "192.0.2.1", 7, 9); err != nil {
		t.Fatalf("an ipv4 socket with an ipv4 interface: %v", err)
	}
	if sockopts.ipv4Set != 1 || sockopts.ipv6Set != 0 {
		t.Fatalf("ipv4Set=%d ipv6Set=%d, want only the ipv4 option", sockopts.ipv4Set, sockopts.ipv6Set)
	}
	if err := (&testEgressSockopts{}).apply(4, "192.0.2.1", 0, 9); err == nil {
		t.Fatal("an ipv4 socket with no ipv4 egress interface was reported pinned")
	}
	if err := (&testEgressSockopts{ipv4Err: errTestSockopt}).apply(4, "192.0.2.1", 7, 9); !errors.Is(err, errTestSockopt) {
		t.Fatalf("a refused ipv4 option on an ipv4 socket: err=%v, want it reported", err)
	}
}

// Ipv6 peers that need no pin: loopback, a zoned link-local or link-scoped
// multicast peer (its zone sends it), and a zoneless one on a host with no
// ipv6 egress interface (Windows places it on a link; the tunnel's routes
// never carry it). An ipv4 peer on an ipv6 socket needs the ipv4 option.
func TestEgressPinIpv6PeersTheTunnelNeverCarries(t *testing.T) {
	for _, c := range []struct {
		destination string
		index6      uint32
	}{
		{destination: "::1", index6: 0},
		{destination: "::1", index6: 9},
		{destination: "fe80::1%eth0", index6: 0},
		{destination: "fe80::1%eth0", index6: 9},
		{destination: "ff02::1%eth0", index6: 9},
		{destination: "fe80::1", index6: 0},
		{destination: "ff02::1", index6: 0},
	} {
		sockopts := &testEgressSockopts{}
		if err := sockopts.apply(6, c.destination, 7, c.index6); err != nil {
			t.Errorf("an ipv6 dial to %s (index6 %d): %v", c.destination, c.index6, err)
		}
		if sockopts.ipv4Set != 0 || sockopts.ipv6Set != 0 {
			t.Errorf("an ipv6 dial to %s (index6 %d) set ipv4=%d ipv6=%d options", c.destination, c.index6, sockopts.ipv4Set, sockopts.ipv6Set)
		}
	}
	// Go hands Control an ipv4-mapped peer in its ipv4 form
	mappedAddress := (&net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 53}).String()
	mappedDestination := egressDestination(mappedAddress)
	mapped := &testEgressSockopts{}
	err := applyEgressPin(6, mappedDestination, 7, 0, func() error {
		mapped.ipv4Set += 1
		return nil
	}, func() error {
		mapped.ipv6Set += 1
		return nil
	})
	if err != nil || mapped.ipv4Set != 1 || mapped.ipv6Set != 0 {
		t.Errorf("an ipv6 socket dialing %s: err=%v ipv4Set=%d ipv6Set=%d", mappedAddress, err, mapped.ipv4Set, mapped.ipv6Set)
	}
	noop := func() error {
		return nil
	}
	if err := applyEgressPin(6, mappedDestination, 0, 9, noop, noop); err == nil {
		t.Error("an ipv6 socket dialing an ipv4 peer with no ipv4 egress interface was reported pinned")
	}
}

// An already-created socket whose family the platform could not read keeps
// the attempt over both options, where one success is enough.
func TestEgressPinUnknownFamilyTakesEitherOption(t *testing.T) {
	if err := (&testEgressSockopts{ipv4Err: errTestSockopt}).apply(0, "", 7, 9); err != nil {
		t.Fatalf("one option set: %v", err)
	}
	if err := (&testEgressSockopts{ipv4Err: errTestSockopt, ipv6Err: errTestSockopt}).apply(0, "", 7, 9); !errors.Is(err, errTestSockopt) {
		t.Fatalf("both options refused: err=%v, want it reported", err)
	}
	if err := (&testEgressSockopts{}).apply(0, "", 0, 0); err != nil {
		t.Fatalf("no egress interface: %v", err)
	}
}

func TestEgressDestination(t *testing.T) {
	cases := []struct {
		address string
		want    string
	}{
		{address: "192.0.2.1:53", want: "192.0.2.1"},
		{address: "[2001:db8::1]:443", want: "2001:db8::1"},
		{address: "[fe80::1%eth0]:53", want: "fe80::1%eth0"},
		{address: "[::]:0", want: ""},
		{address: "0.0.0.0:0", want: ""},
		{address: "", want: ""},
		{address: "example.invalid:53", want: ""},
	}
	for _, c := range cases {
		got := egressDestination(c.address)
		if c.want == "" {
			if got.IsValid() {
				t.Errorf("egressDestination(%q) = %s, want none", c.address, got)
			}
			continue
		}
		if got != netip.MustParseAddr(c.want) {
			t.Errorf("egressDestination(%q) = %s, want %s", c.address, got, c.want)
		}
	}
}

func TestEgressSocketFamily(t *testing.T) {
	cases := []struct {
		network string
		want    int
	}{
		{network: "udp4", want: 4},
		{network: "tcp4", want: 4},
		{network: "udp6", want: 6},
		{network: "tcp6", want: 6},
		{network: "udp", want: 0},
		{network: "", want: 0},
	}
	for _, c := range cases {
		if got := egressSocketFamily(c.network); got != c.want {
			t.Errorf("egressSocketFamily(%q) = %d, want %d", c.network, got, c.want)
		}
	}
}

// What egressControl hands the platform pin for a real dial.
type testEgressPinCall struct {
	family      int
	destination netip.Addr
	index4      uint32
	index6      uint32
}

// Records every pin egressControl applies, with egress bound to (index4,
// index6), until the test ends.
func recordEgressPins(t *testing.T, index4 uint32, index6 uint32) *[]testEgressPinCall {
	t.Helper()
	calls := &[]testEgressPinCall{}
	previous := egressInterfaceApply
	egressInterfaceApply = func(fd uintptr, family int, destination netip.Addr, index4 uint32, index6 uint32) error {
		*calls = append(*calls, testEgressPinCall{
			family:      family,
			destination: destination,
			index4:      index4,
			index6:      index6,
		})
		return nil
	}
	SetEgressInterfaceIndex(index4, index6)
	t.Cleanup(func() {
		SetEgressInterfaceIndex(0, 0)
		egressInterfaceApply = previous
	})
	return calls
}

// The wiring the Windows fix rests on: Control runs before the socket is
// bound, so the platform cannot read its family there, and egressControl
// must hand it the family and peer from what Go passes Control. A "udp" dial
// to an ipv4 peer, written either way, reaches the pin as family 4 and that
// peer.
func TestEgressControlHandsThePinTheSocketFamilyAndPeer(t *testing.T) {
	calls := recordEgressPins(t, 7, 0)
	for _, address := range []string{"127.0.0.1:9", "[::ffff:127.0.0.1]:9"} {
		*calls = nil
		conn, err := egressDialer(&net.Dialer{}).Dial("udp", address)
		if err != nil {
			t.Fatalf("dial %s: %v", address, err)
		}
		conn.Close()
		want := testEgressPinCall{family: 4, destination: netip.MustParseAddr("127.0.0.1"), index4: 7, index6: 0}
		if len(*calls) != 1 || (*calls)[0] != want {
			t.Errorf("a udp dial to %s handed the pin %+v, want [%+v]", address, *calls, want)
		}
	}
}

// The same for an ipv6 peer: family 6 and the peer. Needs an ipv6 loopback.
func TestEgressControlHandsThePinAnIpv6Socket(t *testing.T) {
	requireIpv6Loopback(t)
	calls := recordEgressPins(t, 7, 9)
	conn, err := egressDialer(&net.Dialer{}).Dial("udp", "[::1]:9")
	if err != nil {
		t.Fatalf("dial [::1]:9: %v", err)
	}
	conn.Close()
	want := testEgressPinCall{family: 6, destination: netip.MustParseAddr("::1"), index4: 7, index6: 9}
	if len(*calls) != 1 || (*calls)[0] != want {
		t.Errorf("a udp dial to [::1]:9 handed the pin %+v, want [%+v]", *calls, want)
	}
}

// A dial the pin would refuse is refused before a socket exists, so Go never
// creates one only to close it inline on the dialing goroutine. Stands in
// for a platform that pins.
func TestEgressDialRefusesAnUnpinnableIpv6PeerBeforeASocketExists(t *testing.T) {
	previous := egressInterfacePinning
	egressInterfacePinning = true
	t.Cleanup(func() {
		egressInterfacePinning = previous
	})
	recordEgressPins(t, 7, 0)
	socketCount := 0
	settings := &ConnectSettings{
		DialControl: func(network string, address string, _ syscall.RawConn) error {
			socketCount += 1
			return nil
		},
	}
	_, err := settings.DialContext(context.Background(), "udp", "[2001:db8::1]:9")
	if err == nil || !strings.Contains(err.Error(), "no ipv6 egress interface") {
		t.Fatalf("an ipv6 dial with no ipv6 egress interface: err=%v, want the pin's refusal", err)
	}
	if socketCount != 0 {
		t.Fatalf("%d sockets were created for a dial the pin refuses", socketCount)
	}
	conn, err := settings.DialContext(context.Background(), "udp", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("an ipv4 dial: %v", err)
	}
	conn.Close()
	if socketCount != 1 {
		t.Fatalf("an ipv4 dial created %d sockets, want 1", socketCount)
	}
	if err := egressDialRefusal("[fe80::1]:53"); err != nil {
		t.Fatalf("a link-local peer: %v", err)
	}
}
