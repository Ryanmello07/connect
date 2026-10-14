//go:build windows

package connect

import (
	"net/netip"

	"golang.org/x/sys/windows"
)

// IP_UNICAST_IF (IPPROTO_IP, option 31) forces the outgoing interface for
// unicast, overriding the route table. The interface index must be passed in
// NETWORK byte order. IPV6_UNICAST_IF (IPPROTO_IPV6, option 31) does the same
// for IPv6 but takes the index in HOST byte order. This asymmetry matches
// wireguard-windows' bindSocketRoute.
const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

func htonl(x uint32) uint32 {
	return (x&0x000000ff)<<24 | (x&0x0000ff00)<<8 | (x&0x00ff0000)>>8 | (x&0xff000000)>>24
}

// Whether the forced egress interface binds a socket here (IP_UNICAST_IF / IPV6_UNICAST_IF pin the socket); a
// variable so tests can stand in for a platform that pins.
var egressInterfacePinning = true

// Sets the forced egress interface on the socket, through its own family's
// option (applyEgressPin). A socket of unknown family takes its family from
// its bound address.
func applyEgressInterface(fd uintptr, family int, destination netip.Addr, index4 uint32, index6 uint32) error {
	h := windows.Handle(fd)
	if family == 0 {
		family = windowsSocketFamily(h)
	}
	return applyEgressPin(
		family,
		destination,
		index4,
		index6,
		func() error {
			return windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(htonl(index4)))
		},
		func() error {
			return windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIf, int(index6))
		},
	)
}

// 4 or 6 from the socket's bound address; 0 when it has none yet
func windowsSocketFamily(h windows.Handle) int {
	sockaddr, err := windows.Getsockname(h)
	if err != nil {
		return 0
	}
	switch sockaddr.(type) {
	case *windows.SockaddrInet4:
		return 4
	case *windows.SockaddrInet6:
		return 6
	default:
		return 0
	}
}
