package connect

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
)

// Socket self-exclusion for Windows VPN services and controlled macOS peers.
//
// When this process itself provides a VPN tunnel (a DeviceLocal writing a tun
// adapter), its own outbound sockets must not route back into that tunnel, or
// the platform/provider connections loop. Windows has no per-application
// exclusion, so connect binds its outbound sockets to the physical interface
// via IP_UNICAST_IF / IPV6_UNICAST_IF (the wireguard-windows pattern). A
// controlled same-host macOS acceptance provider uses IP_BOUND_IF /
// IPV6_BOUND_IF so its traffic stays outside the app's packet tunnel. A socket
// with a forced egress interface ignores the tun's default route.
//
// The binding is a no-op unless an egress index is set, and a no-op on every
// platform except Windows and macOS, so ordinary mobile and app builds remain
// inert.

var egressInterfaceIndex4 atomic.Uint32
var egressInterfaceIndex6 atomic.Uint32

// SetEgressInterfaceIndex binds connect's outbound sockets to the given
// physical interface indices (IPv4 and IPv6). Pass 0 for a family to leave that
// family unbound. Safe to call repeatedly, e.g. from a network-change handler.
// Only takes effect on Windows and macOS.
func SetEgressInterfaceIndex(index4 uint32, index6 uint32) {
	egressInterfaceIndex4.Store(index4)
	egressInterfaceIndex6.Store(index6)
}

// EgressInterfaceIndex returns the current (index4, index6). Zero means unset.
func EgressInterfaceIndex() (uint32, uint32) {
	return egressInterfaceIndex4.Load(), egressInterfaceIndex6.Load()
}

// The platform pin egressControl applies; tests replace it to see what it is
// handed.
var egressInterfaceApply = applyEgressInterface

// egressControl is a net.Dialer / net.ListenConfig Control callback that applies
// the egress interface binding to a socket at creation time.
func egressControl(network string, address string, c syscall.RawConn) error {
	index4, index6 := EgressInterfaceIndex()
	if index4 == 0 && index6 == 0 {
		return nil
	}
	family := egressSocketFamily(network)
	destination := egressDestination(address)
	var innerErr error
	err := c.Control(func(fd uintptr) {
		innerErr = egressInterfaceApply(fd, family, destination, index4, index6)
	})
	if err != nil {
		return err
	}
	return innerErr
}

// egressDialer installs the egress control on d, chaining any existing Control.
func egressDialer(d *net.Dialer) *net.Dialer {
	prev := d.Control
	d.Control = func(network string, address string, c syscall.RawConn) error {
		if prev != nil {
			if err := prev(network, address, c); err != nil {
				return err
			}
		}
		return egressControl(network, address, c)
	}
	return d
}

// applyEgress binds an already-created socket-backed conn (e.g. *net.UDPConn) to
// the egress interface. A no-op when no egress index is set or off Windows and
// macOS.
func applyEgress(conn syscall.Conn) error {
	index4, index6 := EgressInterfaceIndex()
	if index4 == 0 && index6 == 0 {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return egressControl("", "", raw)
}

// The address family of the socket a Control callback is given, from the
// network Go names it with: 4 for "udp4"/"tcp4", 6 for "udp6"/"tcp6". Go
// names every AF_INET6 socket with the 6, a dual-stack one included
// (net.netFD.ctrlNetwork). 0 is unknown, as for an already-created socket,
// which the platform pin then resolves from the socket itself.
func egressSocketFamily(network string) int {
	switch {
	case strings.HasSuffix(network, "4"):
		return 4
	case strings.HasSuffix(network, "6"):
		return 6
	default:
		return 0
	}
}

// The peer a dial's Control callback is given; invalid when there is none
// (an already-created socket, or an unspecified listen address).
func egressDestination(address string) netip.Addr {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}
	}
	destination, err := netip.ParseAddr(host)
	if err != nil || destination.IsUnspecified() {
		return netip.Addr{}
	}
	return destination
}

// The refusal the egress pin would give a dial to `address`, decided before a
// socket exists. A dial the pin refuses in Control still creates a socket,
// which Go then closes inline on the dialing goroutine, outside any nat close
// limiter (flow_socket_close.go); refusing here creates none. Only an ipv6
// peer on a host with no ipv6 egress interface is refused, the case the pin
// itself refuses.
func egressDialRefusal(address string) error {
	if !egressInterfacePinning {
		return nil
	}
	index4, index6 := EgressInterfaceIndex()
	if index4 == 0 && index6 == 0 || index6 != 0 {
		return nil
	}
	destination := egressDestination(address)
	if !destination.IsValid() || destination.Unmap().Is4() {
		return nil
	}
	noop := func() error {
		return nil
	}
	return applyEgressPin(6, destination, index4, index6, noop, noop)
}

// Pins a socket of `family` (4, 6, or 0 when unknown) to the egress
// interface through the platform's two options, `setIpv4` and `setIpv6`.
// `destination` is the dialed peer, invalid when unknown.
//
// A socket is pinned through its own family's option. Go creates an AF_INET6
// socket, dual-stack included, for an ipv6 destination, and the ipv4 option
// succeeds on a dual-stack one (it applies to ipv4-mapped traffic) while the
// socket's native ipv6 traffic stays unpinned and follows the route table:
// on a host with tunnel ipv6 routes, into the tunnel this process provides.
// Taking the first option that succeeded therefore reported such a socket
// pinned. A device whose host had no physical ipv6 most likely looped its
// local-route ipv6 flows through its own tunnel this way, and the flow churn
// exhausted the Go runtime's threads (flow_socket_close.go).
//
// So an ipv4 socket, or an ipv6 socket dialing an ipv4 peer, needs the ipv4
// option. An ipv6 socket needs the ipv6 option, and also gets the ipv4
// option, best effort, for ipv4-mapped traffic; with no ipv6 egress interface
// it is refused (a dial fails; an already-created socket's owner logs it).
// Some ipv6 peers need no pin: loopback never routes into the tunnel, and a
// link-local or link-scoped multicast peer is on a link, never behind the
// tunnel's routes. A zoned one is sent by its zone; a zoneless one is pinned
// to the ipv6 egress interface when there is one, and otherwise left for
// Windows to place on a link. Only a socket of unknown family keeps the
// attempt over both options in which one success is enough, and a
// per-option failure stays harmless there: setting the other family's
// option on a single-family socket fails.
func applyEgressPin(
	family int,
	destination netip.Addr,
	index4 uint32,
	index6 uint32,
	setIpv4 func() error,
	setIpv6 func() error,
) error {
	unpinned := func(family int) error {
		return fmt.Errorf(
			"connect: no ipv%d egress interface (v4=%d v6=%d); "+
				"the socket would follow the route table and loop into the tunnel",
			family,
			index4,
			index6,
		)
	}
	failed := func(err error) error {
		return fmt.Errorf(
			"connect: could not pin the socket to the egress interface (v4=%d v6=%d): %w; "+
				"the socket would follow the route table and loop into the tunnel",
			index4,
			index6,
			err,
		)
	}
	pinIpv4 := func() error {
		if index4 == 0 {
			return unpinned(4)
		}
		if err := setIpv4(); err != nil {
			return failed(err)
		}
		return nil
	}
	switch family {
	case 4:
		return pinIpv4()
	case 6:
		if destination.IsValid() && destination.Unmap().Is4() {
			return pinIpv4()
		}
		onLink := destination.IsLinkLocalUnicast() ||
			destination.IsLinkLocalMulticast() ||
			destination.IsInterfaceLocalMulticast()
		if destination.IsLoopback() || onLink && (destination.Zone() != "" || index6 == 0) {
			return nil
		}
		if index4 != 0 {
			// ipv4-mapped traffic; refused on an ipv6-only socket
			_ = setIpv4()
		}
		if index6 == 0 {
			return unpinned(6)
		}
		if err := setIpv6(); err != nil {
			return failed(err)
		}
		return nil
	default:
		attempted := 0
		var lastErr error
		if index4 != 0 {
			attempted += 1
			if err := setIpv4(); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		if index6 != 0 {
			attempted += 1
			if err := setIpv6(); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		if attempted == 0 || lastErr == nil {
			return nil
		}
		return failed(lastErr)
	}
}
