//go:build !windows && !darwin

package connect

import (
	"net/netip"
)

// Whether the forced egress interface binds a socket here (the pin is a no-op here); a
// variable so tests can stand in for a platform that pins.
var egressInterfacePinning = false

// On other platforms self-exclusion is handled at the OS layer. Android uses
// VpnService.protect / addDisallowedApplication. The forced-egress binding is a
// no-op so the egress control is inert in those builds.
func applyEgressInterface(_ uintptr, _ int, _ netip.Addr, _ uint32, _ uint32) error {
	return nil
}
