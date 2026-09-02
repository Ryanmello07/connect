package connect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestControlDialNetworkForce(t *testing.T) {
	tests := []struct {
		name    string
		policy  IpFamilyPolicy
		network string
		want    string
		wantErr bool
	}{
		{"auto leaves tcp alone", IpFamilyAuto, "tcp", "tcp", false},
		{"auto leaves udp alone", IpFamilyAuto, "udp", "udp", false},
		{"force4 narrows tcp", IpFamilyForce4, "tcp", "tcp4", false},
		{"force6 narrows tcp", IpFamilyForce6, "tcp", "tcp6", false},
		{"force4 narrows udp", IpFamilyForce4, "udp", "udp4", false},
		{"force6 narrows udp", IpFamilyForce6, "udp", "udp6", false},
		{"force4 passes matching explicit", IpFamilyForce4, "tcp4", "tcp4", false},
		{"force4 rejects conflicting explicit", IpFamilyForce4, "tcp6", "", true},
		{"force6 rejects conflicting explicit", IpFamilyForce6, "udp4", "", true},
		{"auto passes explicit through", IpFamilyAuto, "tcp6", "tcp6", false},
		{"unknown network is untouched", IpFamilyForce4, "unix", "unix", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetControlIpFamilyPolicy(test.policy)
			defer SetControlIpFamilyPolicy(IpFamilyAuto)
			got, err := controlDialNetwork(test.network)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %s under %d", test.network, test.policy)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestSetControlIpFamilyPolicyClampsUnknown(t *testing.T) {
	defer SetControlIpFamilyPolicy(IpFamilyAuto)
	SetControlIpFamilyPolicy(IpFamilyPolicy(99))
	if got := ControlIpFamilyPolicy(); got != IpFamilyAuto {
		t.Fatalf("got %d, want IpFamilyAuto", got)
	}
	SetControlIpFamilyPolicy(IpFamilyPolicy(-3))
	if got := ControlIpFamilyPolicy(); got != IpFamilyAuto {
		t.Fatalf("got %d, want IpFamilyAuto", got)
	}
}

// Only a post-connect TIMEOUT proves a path is blackholed. Everything else is
// a server or configuration fault, and demoting a family for one would steer
// every user off a healthy path.
func TestIsPathTimeoutIsNarrow(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"context deadline", context.DeadlineExceeded, true},
		{"os deadline", os.ErrDeadlineExceeded, true},
		{"wrapped deadline", fmt.Errorf("tls: %w", context.DeadlineExceeded), true},
		{"net timeout", &net.OpError{Err: &timeoutError{}}, true},
		{"certificate", &tls.CertificateVerificationError{}, false},
		{"connection refused", &net.OpError{Err: errors.New("connection refused")}, false},
		{"reset", errors.New("read: connection reset by peer"), false},
		{"alpn", errors.New("tls: no application protocol"), false},
		{"nil", nil, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isPathTimeout(test.err); got != test.want {
				t.Fatalf("isPathTimeout(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}

type timeoutError struct{}

func (self *timeoutError) Error() string   { return "i/o timeout" }
func (self *timeoutError) Timeout() bool   { return true }
func (self *timeoutError) Temporary() bool { return true }

// A demotion must never take the user offline. With no IPv4 on the device,
// demoting IPv6 is refused.
func TestControlFamilyDemoteRefusedWhenOtherFamilyUnusable(t *testing.T) {
	restore := swapControlFamilyProbe(func(family int) bool { return family == 6 })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	if controlFamilyDemote(6) {
		t.Fatal("demoted ipv6 with no ipv4 available")
	}
	network, err := controlDialNetwork("tcp")
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp" {
		t.Fatalf("got %q, want tcp -- a refused demotion must not narrow", network)
	}
}

// The POLICY accessor must never reflect a learned demotion. A ui row that
// read back "Force IPv4" because the heuristic fired could not be set back to
// Auto -- it would already appear not to be Auto. The demotion is visible
// through controlFamilyStatus instead, which is what the ui shows beside the
// policy. This is asserted HERE rather than in the sdk because
// controlFamilyDemote is only reachable from this package.
func TestControlIpFamilyPolicyIgnoresDemotion(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()
	SetControlIpFamilyPolicy(IpFamilyAuto)
	defer SetControlIpFamilyPolicy(IpFamilyAuto)

	if !controlFamilyDemote(6) {
		t.Fatal("expected the demotion to take")
	}
	if got := ControlIpFamilyPolicy(); got != IpFamilyAuto {
		t.Fatalf("policy reads %d after a demotion, want IpFamilyAuto -- "+
			"a demotion must never be reported as a policy the user set", got)
	}
	if controlFamilyStatus() == "" {
		t.Fatal("expected a non-empty status while a demotion is live -- " +
			"the ui has no other way to tell auto-with-a-demotion from plain auto")
	}
}

func TestControlFamilyDemoteNarrowsToTheOtherFamily(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	if !controlFamilyDemote(6) {
		t.Fatal("expected the demotion to take")
	}
	network, err := controlDialNetwork("tcp")
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp4" {
		t.Fatalf("got %q, want tcp4", network)
	}
	if controlFamilyStatus() == "" {
		t.Fatal("expected a non-empty status while a demotion is live")
	}
}

// A force beats the ledger in both directions -- it is an explicit override,
// which is the whole point of the setting.
func TestForceBeatsDemotion(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()
	controlFamilyDemote(6)

	SetControlIpFamilyPolicy(IpFamilyForce6)
	defer SetControlIpFamilyPolicy(IpFamilyAuto)
	network, err := controlDialNetwork("tcp")
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp6" {
		t.Fatalf("got %q, want tcp6 -- an explicit force outranks a demotion", network)
	}
}

func TestControlFamilyBackoffDoublesAndCaps(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	base := time.Unix(1750000000, 0)
	now := base
	restoreClock := swapControlFamilyClock(func() time.Time { return now })
	defer restoreClock()
	controlFamilyClear()
	defer controlFamilyClear()

	controlFamilyDemote(6)
	if got := controlFamilyDemotedUntil(6).Sub(base); got != controlFamilyDemotionBase {
		t.Fatalf("first demotion lasts %s, want %s", got, controlFamilyDemotionBase)
	}
	controlFamilyDemote(6)
	if got := controlFamilyDemotedUntil(6).Sub(base); got != 2*controlFamilyDemotionBase {
		t.Fatalf("second demotion lasts %s, want %s", got, 2*controlFamilyDemotionBase)
	}
	for i := 0; i < 20; i += 1 {
		controlFamilyDemote(6)
	}
	if got := controlFamilyDemotedUntil(6).Sub(base); got != controlFamilyDemotionMax {
		t.Fatalf("demotion lasts %s, want the %s cap", got, controlFamilyDemotionMax)
	}
}

func TestControlFamilyDemotionExpires(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	now := time.Unix(1750000000, 0)
	restoreClock := swapControlFamilyClock(func() time.Time { return now })
	defer restoreClock()
	controlFamilyClear()
	defer controlFamilyClear()

	controlFamilyDemote(6)
	now = now.Add(controlFamilyDemotionBase + time.Second)
	network, err := controlDialNetwork("tcp")
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp" {
		t.Fatalf("got %q, want tcp once the demotion expired", network)
	}
	if controlFamilyStatus() != "" {
		t.Fatal("expected an empty status once the demotion expired")
	}
}

// A network change invalidates everything learned about the old path.
func TestNetworkChangedClearsTheLedger(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	controlFamilyDemote(6)
	NetworkChanged()
	network, err := controlDialNetwork("tcp")
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp" {
		t.Fatalf("got %q, want tcp after a network change", network)
	}
}

func TestConnFamily(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want int
	}{
		{"ipv4", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, 4},
		{"ipv4 in ipv6 form", &net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 443}, 4},
		{"ipv6", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}, 6},
		{"nil", nil, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := connFamily(&stubConn{remote: test.addr}); got != test.want {
				t.Fatalf("got %d, want %d", got, test.want)
			}
		})
	}
}

type stubConn struct {
	net.Conn
	remote net.Addr
}

func (self *stubConn) RemoteAddr() net.Addr { return self.remote }
