package connect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	// auto: a live demotion narrows to the family that is not demoted
	switch controlFamilyDemotedFamily() {
	case 6:
		return network + "4", nil
	case 4:
		return network + "6", nil
	}
	return network, nil
}

const (
	// A demotion has to outlast the reconnect storm that follows a failure,
	// and a persistent path problem has to stop costing the user anything
	// within a couple of strikes. Five minutes doubling to six hours does
	// both: the second strike already covers a ten-minute session, and a
	// genuinely broken tunnel settles at the cap.
	controlFamilyDemotionBase = 5 * time.Minute
	controlFamilyDemotionMax  = 6 * time.Hour
)

type controlFamilyDemotion struct {
	until   time.Time
	strikes int
}

// the learned half of the policy. Guarded by its own mutex rather than folded
// into an atomic: an entry is three fields and every read is off the hot path
// of an already-blocking dial.
var controlFamilyLedger = struct {
	mu      sync.Mutex
	demoted map[int]controlFamilyDemotion
	now     func() time.Time
	probe   func(family int) bool
}{
	demoted: map[int]controlFamilyDemotion{},
	now:     time.Now,
	probe:   probeFamilySupport,
}

func init() {
	// a path change invalidates everything learned about the old path
	AddNetworkChangeListener(controlFamilyClear)
}

// controlFamilyDemote records that `family` connected and then failed. It
// reports whether the demotion took.
//
// It is REFUSED when the other family is not usable on this device. On an
// IPv6-only network with no CLAT there is no IPv4 to fall back to, and
// demoting IPv6 there would take the user from a slow control plane to no
// control plane at all.
func controlFamilyDemote(family int) bool {
	other := 4
	if family == 4 {
		other = 6
	}

	controlFamilyLedger.mu.Lock()

	if !controlFamilyLedger.probe(other) {
		controlFamilyLedger.mu.Unlock()
		return false
	}

	now := controlFamilyLedger.now()
	entry := controlFamilyLedger.demoted[family]
	entry.strikes += 1
	backoff := controlFamilyDemotionBase << (entry.strikes - 1)
	if backoff > controlFamilyDemotionMax || backoff <= 0 {
		backoff = controlFamilyDemotionMax
	}
	entry.until = now.Add(backoff)
	controlFamilyLedger.demoted[family] = entry
	strikes := entry.strikes
	controlFamilyLedger.mu.Unlock()

	loggerOrDefault(nil).Infof(
		"[family]demote family=%d strikes=%d for=%s\n", family, strikes, backoff)
	return true
}

// controlFamilyClear drops everything learned. Wired to NetworkChanged.
func controlFamilyClear() {
	controlFamilyLedger.mu.Lock()
	hadEntries := 0 < len(controlFamilyLedger.demoted)
	clear(controlFamilyLedger.demoted)
	controlFamilyLedger.mu.Unlock()

	if hadEntries {
		loggerOrDefault(nil).Infof("[family]clear (network changed)\n")
	}
}

// controlFamilyDemotedFamily returns the family currently demoted, or 0.
// A demotion of BOTH families is impossible by construction -- demoting one
// requires the other to be usable -- but if it somehow occurred, neither is
// reported, because narrowing to a family we also believe is broken is worse
// than letting the platform race them.
func controlFamilyDemotedFamily() int {
	controlFamilyLedger.mu.Lock()
	defer controlFamilyLedger.mu.Unlock()
	now := controlFamilyLedger.now()
	live := 0
	for family, entry := range controlFamilyLedger.demoted {
		if now.Before(entry.until) {
			if live != 0 {
				return 0
			}
			live = family
		}
	}
	return live
}

// controlFamilyDemotedUntil is the expiry for a family, zero when not demoted.
// Exists for the tests and for the status line.
func controlFamilyDemotedUntil(family int) time.Time {
	controlFamilyLedger.mu.Lock()
	defer controlFamilyLedger.mu.Unlock()
	return controlFamilyLedger.demoted[family].until
}

// controlFamilyStatus describes any live demotion for the developer ui, and is
// empty when there is none. The ui shows this BESIDE the policy, never in
// place of it: a row that read "Force IPv4" because the heuristic fired could
// not be set back to Auto.
func controlFamilyStatus() string {
	controlFamilyLedger.mu.Lock()
	defer controlFamilyLedger.mu.Unlock()
	now := controlFamilyLedger.now()
	parts := []string{}
	for _, family := range []int{4, 6} {
		entry, ok := controlFamilyLedger.demoted[family]
		if !ok || !now.Before(entry.until) {
			continue
		}
		parts = append(parts, fmt.Sprintf(
			"IPv%d demoted for %s (%d strikes)",
			family,
			entry.until.Sub(now).Round(time.Minute),
			entry.strikes,
		))
	}
	return strings.Join(parts, ", ")
}

// probeFamilySupport reports whether this device has a usable global address
// of the family.
//
// NOT nettest.SupportsIPv4/SupportsIPv6: those memoize inside x/net behind a
// sync.Once, so they answer for whatever network the process started on and
// never re-evaluate across a wifi/cellular switch. A stale "yes, IPv4 works"
// is exactly the wrong answer for the guard that keeps a demotion from taking
// an IPv6-only user offline.
func probeFamilySupport(family int) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		// unknown: assume the family is available rather than blocking a
		// demotion that may be the user's only way onto a working path
		return true
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || !ipNet.IP.IsGlobalUnicast() {
			continue
		}
		if (ipNet.IP.To4() != nil) == (family == 4) {
			return true
		}
	}
	return false
}

// controlDialFamilyLine formats the per-dial family evidence.
//
// `family=4` / `family=6` is a LITERAL token, deliberately not derived from an
// address in the rendered line. The sdk's log redactor rewrites both IPv4 and
// IPv6 literals to the same opaque <addr:hex> shape, including the brackets
// that would otherwise give an IPv6 address away -- so in a REDACTED bundle,
// which is the mode a user is asked to send, an address cannot tell a support
// engineer which family was dialed. This token can.
func controlDialFamilyLine(
	tag string,
	network string,
	addr string,
	conn net.Conn,
	err error,
) string {
	family := "?"
	if f := connFamily(conn); f != 0 {
		family = fmt.Sprintf("%d", f)
	}
	policy := "auto"
	switch ControlIpFamilyPolicy() {
	case IpFamilyForce4:
		policy = "force4"
	case IpFamilyForce6:
		policy = "force6"
	}
	demoted := controlFamilyStatus()
	if demoted == "" {
		demoted = "none"
	}
	if err != nil {
		return fmt.Sprintf(
			"[family]dial tag=%s net=%s family=%s policy=%s demoted=%s err=%s",
			tag, network, family, policy, demoted, err)
	}
	return fmt.Sprintf(
		"[family]dial tag=%s net=%s family=%s policy=%s demoted=%s",
		tag, network, family, policy, demoted)
}

// isPathTimeout reports whether err is the post-connect timeout that proves a
// path is blackholed.
//
// Deliberately narrow. A certificate failure, an ALPN mismatch, a refusal or a
// reset all mean the packets ARRIVED and something at the far end objected --
// which says nothing about the family. Demoting on those would blame IPv6 for
// a server misconfiguration and steer every user off a healthy path, which is
// worse than the bug this exists to fix.
func isPathTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// connFamily is 4, 6, or 0 when the connection has no usable remote address.
func connFamily(conn net.Conn) int {
	if conn == nil {
		return 0
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return 0
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// test seams. Package-private and restored by the caller.
func swapControlFamilyClock(now func() time.Time) func() {
	controlFamilyLedger.mu.Lock()
	defer controlFamilyLedger.mu.Unlock()
	prev := controlFamilyLedger.now
	controlFamilyLedger.now = now
	return func() {
		controlFamilyLedger.mu.Lock()
		defer controlFamilyLedger.mu.Unlock()
		controlFamilyLedger.now = prev
	}
}

// pickControlIPAddr chooses which resolved address a single-address control
// dial should use, honoring a force and then a demotion.
//
// Falls back to the first address when nothing matches the preference: a
// forced family the name does not publish must degrade to "dial what exists"
// rather than make the transport unusable.
func pickControlIPAddr(addrs []net.IPAddr) net.IPAddr {
	if len(addrs) == 0 {
		return net.IPAddr{}
	}
	want := 0
	switch ControlIpFamilyPolicy() {
	case IpFamilyForce4:
		want = 4
	case IpFamilyForce6:
		want = 6
	default:
		switch controlFamilyDemotedFamily() {
		case 6:
			want = 4
		case 4:
			want = 6
		}
	}
	if want == 0 {
		return addrs[0]
	}
	for _, addr := range addrs {
		if (addr.IP.To4() != nil) == (want == 4) {
			return addr
		}
	}
	return addrs[0]
}

func swapControlFamilyProbe(probe func(family int) bool) func() {
	controlFamilyLedger.mu.Lock()
	defer controlFamilyLedger.mu.Unlock()
	prev := controlFamilyLedger.probe
	controlFamilyLedger.probe = probe
	return func() {
		controlFamilyLedger.mu.Lock()
		defer controlFamilyLedger.mu.Unlock()
		controlFamilyLedger.probe = prev
	}
}
