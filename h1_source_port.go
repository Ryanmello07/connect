package connect

import (
	"context"
	mathrandv2 "math/rand/v2"
	"net"
	"runtime"
	"syscall"
)

// H1 path re-roll: the local port of a re-roll dial.
//
// A relay path hashes each TCP 4-tuple onto one of its members, and a re-roll
// must land the replacement connection on another member. connect() does not
// help: on linux and android it moves the local port to the same destination
// only a few ports forward, so a path that hashes blocks of adjacent ports
// keeps the replacement on the lossy member. A re-roll dial with policy
// FarRandom therefore carries an `h1SourcePortPlan` in its context, and every
// TCP socket the direct dialer creates for that dial binds a uniform random
// port of the platform's ephemeral range, more than SourcePortExcludeRadius
// away from every local port convicted in this network epoch.
//
// The plan applies below the client strategy, in ConnectSettings' direct dial
// (the address race) and in a family-pinned strategy's inner dial. Every
// dialer the strategy races gets it, and each socket draws its own port. It
// does not apply to:
//   - a proxy dial, whose local port does not reach the platform;
//   - a host's injected DialContextSettings, which keeps its own source
//     identity;
//   - a dialer with an explicit LocalAddr;
//   - a network other than tcp4 and tcp6.
//
// The dialer's own control (DialControl, then the egress interface binding)
// runs first. The bind never fails the dial: a port in use moves on to the
// next pick, up to h1SourcePortBindAttempts, and any other failure leaves the
// port to the kernel. Each planned socket counts SourcePortBinds or
// SourcePortFallbacks. Binding is implemented on linux and darwin (android and
// ios included); elsewhere every planned socket falls back.
//
// A plan is immutable after construction and safe for concurrent use, since
// the sockets of one dial bind in parallel.

// uniform draws before a pick scans the range
const h1SourcePortPickDraws = 64

// Picks tried per socket while the picked port is in use. Each pick is an
// independent uniform draw over the allowed ports, so this many consecutive
// EADDRINUSE means the range is essentially full; below that the surrender is
// the expensive outcome, because the kernel's own port is a few above the one
// just convicted and so inside the window the plan exists to avoid.
const h1SourcePortBindAttempts = 16

// The kernel's default ephemeral range: ip_local_port_range on linux and
// android, the dynamic range on darwin, ios and everything else. Both bounds
// are inclusive.
func h1EphemeralPortRange() (lowPort int, highPort int) {
	switch runtime.GOOS {
	case "linux", "android":
		return 32768, 60999
	default:
		return 49152, 65535
	}
}

type h1SourcePortPlan struct {
	lowPort       int
	highPort      int
	excludedPorts []int
	excludeRadius int
	// returns a value in [0, n); must be safe for concurrent use
	random func(n int) int
	stats  *h1PathStats
}

// excludedPorts is copied. A nil random draws from math/rand/v2.
func newH1SourcePortPlan(
	settings *H1PathRerollSettings,
	excludedPorts []int,
	random func(n int) int,
	stats *h1PathStats,
) *h1SourcePortPlan {
	lowPort, highPort := h1EphemeralPortRange()
	if random == nil {
		random = mathrandv2.IntN
	}
	return &h1SourcePortPlan{
		lowPort:       lowPort,
		highPort:      highPort,
		excludedPorts: append([]int{}, excludedPorts...),
		excludeRadius: max(0, settings.SourcePortExcludeRadius),
		random:        random,
		stats:         stats,
	}
}

// A port of the range outside every excluded window: uniform draws first, then
// a scan from a random offset, so a range that is mostly excluded still yields
// a port. False when every port is excluded.
func (self *h1SourcePortPlan) pick() (int, bool) {
	portCount := self.highPort - self.lowPort + 1
	for range h1SourcePortPickDraws {
		port := self.lowPort + self.randomIndex(portCount)
		if self.allowed(port) {
			return port, true
		}
	}
	offset := self.randomIndex(portCount)
	for i := range portCount {
		port := self.lowPort + (offset+i)%portCount
		if self.allowed(port) {
			return port, true
		}
	}
	return 0, false
}

func (self *h1SourcePortPlan) randomIndex(n int) int {
	// a random that strays outside [0, n) still lands in the range
	index := self.random(n) % n
	if index < 0 {
		index += n
	}
	return index
}

func (self *h1SourcePortPlan) allowed(port int) bool {
	return !h1SourcePortExcluded(port, self.excludedPorts, self.excludeRadius)
}

// Whether the port is within radius of any of the ports, which is the window a
// planned dial must land outside of. A connection inside it shares the
// convicted 4-tuple's neighbourhood and, on a path that hashes blocks of
// adjacent ports, its member.
func h1SourcePortExcluded(port int, excludedPorts []int, radius int) bool {
	for _, excludedPort := range excludedPorts {
		distance := port - excludedPort
		if distance < 0 {
			distance = -distance
		}
		if distance <= radius {
			return true
		}
	}
	return false
}

type h1SourcePortPlanContextKey struct{}

func withH1SourcePortPlan(ctx context.Context, plan *h1SourcePortPlan) context.Context {
	return context.WithValue(ctx, h1SourcePortPlanContextKey{}, plan)
}

// nil when the dial is not planned
func h1SourcePortPlanFromContext(ctx context.Context) *h1SourcePortPlan {
	if ctx == nil {
		return nil
	}
	plan, _ := ctx.Value(h1SourcePortPlanContextKey{}).(*h1SourcePortPlan)
	return plan
}

// The dialer for one dial. Without a plan in ctx, or with a LocalAddr, it is
// the same dialer. Otherwise it is a copy whose control runs the dialer's own
// control and then binds the planned port. The copy moves Control into
// ControlContext, because a dialer ignores Control when ControlContext is set.
func h1SourcePortDialer(ctx context.Context, dialer *net.Dialer) *net.Dialer {
	plan := h1SourcePortPlanFromContext(ctx)
	if plan == nil || dialer.LocalAddr != nil {
		return dialer
	}
	planned := *dialer
	control := planned.Control
	controlContext := planned.ControlContext
	planned.Control = nil
	planned.ControlContext = func(
		ctx context.Context,
		network string,
		address string,
		rawConn syscall.RawConn,
	) error {
		if controlContext != nil {
			if err := controlContext(ctx, network, address, rawConn); err != nil {
				return err
			}
		} else if control != nil {
			if err := control(network, address, rawConn); err != nil {
				return err
			}
		}
		// the dialer passes the socket's family in the network
		switch network {
		case "tcp4", "tcp6":
			plan.bind(network, rawConn)
		}
		return nil
	}
	return &planned
}
