//go:build darwin

// macOS socket binding keeps controlled provider traffic outside a packet tunnel.
package connect

import (
	"net/netip"

	"golang.org/x/sys/unix"
)

// Whether the forced egress interface binds a socket here (IP_BOUND_IF / IPV6_BOUND_IF pin the socket); a
// variable so tests can stand in for a platform that pins.
var egressInterfacePinning = true

// Pins a macOS socket to the physical interface selected by the caller,
// through its own family's option (applyEgressPin). The
// acceptance peer provider uses this to remain independent of the product
// packet tunnel running on the same host. A socket of unknown family takes
// its family from its bound address.
func applyEgressInterface(fd uintptr, family int, destination netip.Addr, index4 uint32, index6 uint32) error {
	if family == 0 {
		family = darwinSocketFamily(int(fd))
	}
	return applyEgressPin(
		family,
		destination,
		index4,
		index6,
		func() error {
			return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(index4))
		},
		func() error {
			return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(index6))
		},
	)
}

// 4 or 6 from the socket's bound address; 0 when it has none yet
func darwinSocketFamily(fd int) int {
	sockaddr, err := unix.Getsockname(fd)
	if err != nil {
		return 0
	}
	switch sockaddr.(type) {
	case *unix.SockaddrInet4:
		return 4
	case *unix.SockaddrInet6:
		return 6
	default:
		return 0
	}
}
