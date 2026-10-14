//go:build windows

package connect

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The Windows pin on real sockets: an ipv6 socket is pinned through
// IPV6_UNICAST_IF, and with no ipv6 egress interface it is refused. The ipv4
// option succeeds on a dual-stack AF_INET6 socket, which is how the
// first-success pin reported ipv6 sockets pinned.
func TestApplyEgressInterfacePinsAnIpv6SocketThroughTheIpv6Option(t *testing.T) {
	loIndex := loopbackInterfaceIndex(t)
	fd, err := windows.Socket(windows.AF_INET6, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.Closesocket(fd)
	peer := netip.MustParseAddr("2001:db8::1")
	if err := applyEgressInterface(uintptr(fd), 6, peer, loIndex, loIndex); err != nil {
		t.Fatalf("pin an ipv6 socket: %v", err)
	}
	index, err := windows.GetsockoptInt(fd, windows.IPPROTO_IPV6, ipv6UnicastIf)
	if err != nil {
		t.Fatal(err)
	}
	if uint32(index) != loIndex {
		t.Fatalf("IPV6_UNICAST_IF is %d, want %d", index, loIndex)
	}
	if err := applyEgressInterface(uintptr(fd), 6, peer, loIndex, 0); err == nil {
		t.Fatal("an ipv6 socket with no ipv6 egress interface was reported pinned")
	}
}

// Through the dialer, as the nat dials: Control is handed "udp6" and the peer,
// so a dial the route table would send into the tunnel fails.
func TestEgressDialerRefusesAnIpv6DialWithoutAnIpv6Interface(t *testing.T) {
	loIndex := loopbackInterfaceIndex(t)
	SetEgressInterfaceIndex(loIndex, 0)
	t.Cleanup(func() {
		SetEgressInterfaceIndex(0, 0)
	})
	conn, err := egressDialer(&net.Dialer{}).Dial("udp", "[2001:db8::1]:9")
	if err == nil {
		conn.Close()
		t.Fatal("an ipv6 dial with no ipv6 egress interface succeeded")
	}
	if !strings.Contains(err.Error(), "no ipv6 egress interface") {
		t.Fatalf("an ipv6 dial with no ipv6 egress interface: %v, want the pin's refusal", err)
	}
}
