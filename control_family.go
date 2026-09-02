package connect

import (
	"fmt"
	"sync/atomic"
)

// Address-family policy for this process's CONTROL-PLANE dials: the api
// https client, the platform control websocket, and the h3/quic transport's
// name path. The tunnelled user data plane is not affected and is IPv4-only by
// its own design (see Tun.dialContext).
//
// Two independent pieces of state live here. The POLICY is what a developer
// set and is never changed by anything else. The DEMOTION LEDGER (below) is
// what this process has learned about a family that connects and then fails.
// Keeping them apart is what lets the ui round-trip "Auto" as "Auto" while a
// demotion is quietly in force.
//
// Process-global, like the egress interface binding in egress.go, and read
// INSIDE each dial rather than captured when a dialer is built -- a client
// strategy memoizes its http client and its tls dialer for the life of the
// process, so a value read at construction could never be changed at runtime.
type IpFamilyPolicy int32

const (
	// Happy Eyeballs as the platform provides it, plus reactive demotion.
	IpFamilyAuto IpFamilyPolicy = 0
	// Control dials use IPv4 only, whatever the ledger has learned.
	IpFamilyForce4 IpFamilyPolicy = 1
	// Control dials use IPv6 only, whatever the ledger has learned.
	IpFamilyForce6 IpFamilyPolicy = 2
)

var controlIpFamilyPolicy atomic.Int32

// SetControlIpFamilyPolicy sets the control-plane family policy for this
// process. An unrecognised value is Auto rather than an error: this is fed
// from a persisted file and across a gomobile boundary where an older or
// newer peer may carry a value this build does not know, and the safe
// interpretation of "something I do not understand" is "do what you would
// have done anyway".
func SetControlIpFamilyPolicy(policy IpFamilyPolicy) {
	switch policy {
	case IpFamilyForce4, IpFamilyForce6:
	default:
		policy = IpFamilyAuto
	}
	controlIpFamilyPolicy.Store(int32(policy))
}

// ControlIpFamilyPolicy returns the policy alone. It never reflects a learned
// demotion -- see controlFamilyStatus for that.
func ControlIpFamilyPolicy() IpFamilyPolicy {
	return IpFamilyPolicy(controlIpFamilyPolicy.Load())
}

// controlDialNetwork narrows a family-agnostic network string ("tcp", "udp")
// to a family-specific one when a policy or a demotion says so, and returns it
// unchanged otherwise.
//
// A FORCE conflicting with an explicitly requested family is an error, which
// preserves the semantics the dead DisableIpv4/DisableIpv6 pair had: a caller
// that asked for tcp6 by name must not silently be given tcp4. A DEMOTION
// never errors -- it is a heuristic, and a heuristic must not fail a caller's
// explicit request.
func controlDialNetwork(network string) (string, error) {
	policy := ControlIpFamilyPolicy()

	switch network {
	case "tcp4", "udp4":
		if policy == IpFamilyForce6 {
			return "", fmt.Errorf("ipv4 is disabled by the control family policy")
		}
		return network, nil
	case "tcp6", "udp6":
		if policy == IpFamilyForce4 {
			return "", fmt.Errorf("ipv6 is disabled by the control family policy")
		}
		return network, nil
	case "tcp", "udp":
		// narrowed below
	default:
		// unix sockets and anything else are not ours to reinterpret
		return network, nil
	}

	switch policy {
	case IpFamilyForce4:
		return network + "4", nil
	case IpFamilyForce6:
		return network + "6", nil
	}
	return network, nil
}
