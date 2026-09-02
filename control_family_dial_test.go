package connect

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The shape of the reported bug: the tcp connect succeeds over IPv6 (small
// packets pass an HE tunnel), then the tls handshake times out (the large
// ServerHello is dropped). The caller must still get a working connection.
func TestFamilyFallbackRecoversFromAPostConnectTimeout(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	var mutex sync.Mutex
	var dialed []string
	dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		mutex.Lock()
		dialed = append(dialed, network)
		mutex.Unlock()
		remote := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}
		if network == "tcp4" {
			remote = &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
		}
		return &stubConn{remote: remote}, nil
	}
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		if connFamily(conn) == 6 {
			return nil, &timeoutError{}
		}
		return conn, nil
	}

	conn, err := dialControlTlsWithFamilyFallback(
		context.Background(), "tcp", "api.example:443", dial, handshake)
	if err != nil {
		t.Fatal(err)
	}
	if got := connFamily(conn); got != 4 {
		t.Fatalf("returned an IPv%d connection, want IPv4", got)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(dialed) != 2 || dialed[0] != "tcp" || dialed[1] != "tcp4" {
		t.Fatalf("dialed %v, want [tcp tcp4]", dialed)
	}
	if controlFamilyDemotedFamily() != 6 {
		t.Fatal("expected ipv6 to be demoted by the failure")
	}
}

// Exactly one retry. The dial already sits inside the strategy's own dialer
// evaluation under a 15s request budget, so a helper that retried repeatedly
// could consume the whole budget alone and starve the other dialers.
func TestFamilyFallbackRetriesOnlyOnce(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	var mutex sync.Mutex
	attempts := 0
	dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		mutex.Lock()
		attempts += 1
		mutex.Unlock()
		return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}, nil
	}
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		return nil, &timeoutError{}
	}

	_, err := dialControlTlsWithFamilyFallback(
		context.Background(), "tcp", "api.example:443", dial, handshake)
	if err == nil {
		t.Fatal("expected the second failure to be returned")
	}
	mutex.Lock()
	defer mutex.Unlock()
	if attempts != 2 {
		t.Fatalf("dialed %d times, want exactly 2", attempts)
	}
}

// A non-timeout failure is not a path problem and must not demote or retry.
func TestFamilyFallbackDoesNotRetryANonTimeout(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	attempts := 0
	dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		attempts += 1
		return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}, nil
	}
	certErr := errors.New("x509: certificate signed by unknown authority")
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		return nil, certErr
	}

	_, err := dialControlTlsWithFamilyFallback(
		context.Background(), "tcp", "api.example:443", dial, handshake)
	if !errors.Is(err, certErr) {
		t.Fatalf("got %v, want the certificate error unwrapped", err)
	}
	if attempts != 1 {
		t.Fatalf("dialed %d times, want 1 -- a certificate failure is not a path failure", attempts)
	}
	if controlFamilyDemotedFamily() != 0 {
		t.Fatal("a certificate failure must not demote a family")
	}
}

// An explicitly family-specific dial has nowhere to fall back to.
func TestFamilyFallbackDoesNotRetryAnExplicitFamily(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	attempts := 0
	dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		attempts += 1
		return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}, nil
	}
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		return nil, &timeoutError{}
	}

	_, _ = dialControlTlsWithFamilyFallback(
		context.Background(), "tcp6", "api.example:443", dial, handshake)
	if attempts != 1 {
		t.Fatalf("dialed %d times, want 1 for an explicit tcp6", attempts)
	}
}

// The family has to be read off the connection BEFORE the handshake runs and
// before any Close. A real tls.Conn closes the underlying connection on a
// failed handshake -- newNormalDialTlsContext's callback does exactly that --
// and a closed net.TCPConn is not required to keep answering RemoteAddr. Read
// it late and `failed` is 0, so nothing is demoted and nothing is retried:
// the fallback silently stops existing on the one path it was written for.
//
// forgetfulConn reproduces that: it answers RemoteAddr until it is closed and
// nil afterwards. The brief's other tests cannot catch the ordering, because
// stubConn's Close is a no-op that leaves RemoteAddr working forever.
func TestFamilyFallbackReadsTheFamilyBeforeTheConnectionIsClosed(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	var mutex sync.Mutex
	var dialed []string
	dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		mutex.Lock()
		dialed = append(dialed, network)
		mutex.Unlock()
		if network == "tcp4" {
			return &forgetfulConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}}, nil
		}
		return &forgetfulConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}, nil
	}
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		if connFamily(conn) == 6 {
			// what tls.Conn.Close() does to the connection it wraps
			conn.Close()
			return nil, &timeoutError{}
		}
		return conn, nil
	}

	conn, err := dialControlTlsWithFamilyFallback(
		context.Background(), "tcp", "api.example:443", dial, handshake)
	if err != nil {
		t.Fatal(err)
	}
	if got := connFamily(conn); got != 4 {
		t.Fatalf("returned an IPv%d connection, want IPv4", got)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(dialed) != 2 || dialed[1] != "tcp4" {
		t.Fatalf("dialed %v, want [tcp tcp4] -- the family was read too late to fall back", dialed)
	}
}

// answers RemoteAddr until closed, then forgets, like a real net.TCPConn may.
type forgetfulConn struct {
	net.Conn
	remote net.Addr
	closed atomic.Bool
}

func (self *forgetfulConn) RemoteAddr() net.Addr {
	if self.closed.Load() {
		return nil
	}
	return self.remote
}

func (self *forgetfulConn) Close() error {
	self.closed.Store(true)
	return nil
}

// The retry is only reachable if the FIRST handshake is bounded to part of the
// caller's budget. The failure this helper exists to catch is a handshake that
// stalls until its deadline, so a first attempt allowed to spend the whole
// request budget hands the retry a context that is already dead.
func TestFamilyFallbackBoundsTheFirstHandshakeToPartOfTheBudget(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	callerCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	callerDeadline, _ := callerCtx.Deadline()

	dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		if network == "tcp4" {
			return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}}, nil
		}
		return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}, nil
	}
	var mutex sync.Mutex
	deadlines := []time.Time{}
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("the handshake was given a context with no deadline")
		}
		mutex.Lock()
		deadlines = append(deadlines, deadline)
		mutex.Unlock()
		if connFamily(conn) == 6 {
			return nil, &timeoutError{}
		}
		return conn, nil
	}

	conn, err := dialControlTlsWithFamilyFallback(
		callerCtx, "tcp", "api.example:443", dial, handshake)
	if err != nil {
		t.Fatal(err)
	}
	if got := connFamily(conn); got != 4 {
		t.Fatalf("returned an IPv%d connection, want IPv4", got)
	}

	mutex.Lock()
	defer mutex.Unlock()
	if len(deadlines) != 2 {
		t.Fatalf("handshaked %d times, want 2", len(deadlines))
	}
	// half of a 10s budget: the first attempt has to give up with most of the
	// second half still available to the retry
	if !deadlines[0].Before(callerDeadline.Add(-4 * time.Second)) {
		t.Fatalf(
			"the first handshake was given until %s of the caller's %s -- no budget is left to retry with",
			deadlines[0].Format(time.RFC3339Nano),
			callerDeadline.Format(time.RFC3339Nano),
		)
	}
	if deadlines[1].Before(deadlines[0]) {
		t.Fatal("the retry was given less budget than the first attempt")
	}
}

// The real failure is a handshake that STALLS to its deadline -- a blackholed
// path gives up only when the context does, because the kernel retransmits for
// minutes. The caller must still receive a working connection, which is only
// possible if the first attempt left some budget behind.
func TestFamilyFallbackRecoversFromAHandshakeThatStallsToItsDeadline(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	callerCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		// a real dial on a dead context fails at once
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if network == "tcp4" {
			return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}}, nil
		}
		return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}, nil
	}
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if connFamily(conn) == 6 {
			// the ServerHello never arrives; the handshake ends at the deadline
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return conn, nil
	}

	conn, err := dialControlTlsWithFamilyFallback(
		callerCtx, "tcp", "api.example:443", dial, handshake)
	if err != nil {
		t.Fatalf("%v -- the stalled first attempt left the retry no budget", err)
	}
	if got := connFamily(conn); got != 4 {
		t.Fatalf("returned an IPv%d connection, want IPv4", got)
	}
	if controlFamilyDemotedFamily() != 6 {
		t.Fatal("expected ipv6 to be demoted by the stall")
	}
}

// A request that simply runs out of budget mid-handshake proves nothing about
// the path. Demoting there would take a user on a merely slow link off a
// healthy family for five minutes, which is the false positive the design
// refused to accept when it declined to shorten TlsTimeout.
func TestFamilyFallbackDoesNotDemoteWhenTheCallersBudgetRanOut(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()

	// far too little left to bound a first attempt and still have a retry, so
	// whatever the handshake reports is the caller's deadline, not the path's
	callerCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	attempts := 0
	dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		attempts += 1
		return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}, nil
	}
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	_, err := dialControlTlsWithFamilyFallback(
		callerCtx, "tcp", "api.example:443", dial, handshake)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want the caller's deadline error", err)
	}
	if attempts != 1 {
		t.Fatalf("dialed %d times, want 1 -- there was no budget to retry with", attempts)
	}
	if controlFamilyDemotedFamily() != 0 {
		t.Fatal("the caller's own budget expiring must not demote a family")
	}
}

// The route back from a demotion that took the user offline.
//
// The ledger is only ever written after a connect SUCCEEDED and the handshake
// then timed out, so a demotion can be confirmed but never refuted. When the
// family we demoted onto cannot connect at all, the dial returns at the
// connect step and nothing is recorded -- so every control dial in the process
// stays narrowed onto the family that just proved it does not work, for five
// minutes and, as strikes accumulate, up to six hours.
//
// The dial stub resolves the network through controlDialNetwork exactly as
// ConnectSettings.DialContext does, so the narrowing under test is the real
// one and not a value the test handed itself.
func TestFamilyFallbackUndoesADemotionThatCannotConnect(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()
	SetControlIpFamilyPolicy(IpFamilyAuto)

	if !controlFamilyDemote(6) {
		t.Fatal("expected the demotion to take")
	}
	if got, _ := controlDialNetwork("tcp", "api.example:443"); got != "tcp4" {
		t.Fatalf("precondition: controlDialNetwork = %q, want tcp4", got)
	}

	var mutex sync.Mutex
	var dialed []string
	dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		resolved, err := controlDialNetwork(network, addr)
		if err != nil {
			return nil, err
		}
		mutex.Lock()
		dialed = append(dialed, resolved)
		mutex.Unlock()
		if resolved == "tcp4" {
			// the device has no ipv4 route at all
			return nil, &net.OpError{
				Op: "dial", Net: "tcp4", Err: errors.New("connect: network is unreachable"),
			}
		}
		return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}, nil
	}
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		return conn, nil
	}

	conn, err := dialControlTlsWithFamilyFallback(
		context.Background(), "tcp", "api.example:443", dial, handshake)
	if err != nil {
		t.Fatalf("%v -- the demotion steered the dial onto a family with no route "+
			"and nothing could undo it", err)
	}
	if got := connFamily(conn); got != 6 {
		t.Fatalf("returned an IPv%d connection, want IPv6", got)
	}
	mutex.Lock()
	dialedCopy := append([]string{}, dialed...)
	mutex.Unlock()
	if len(dialedCopy) != 2 || dialedCopy[0] != "tcp4" || dialedCopy[1] != "tcp" {
		t.Fatalf("dialed %v, want [tcp4 tcp] -- the redial must be family-agnostic "+
			"so happy eyeballs runs again", dialedCopy)
	}
	if controlFamilyDemotedFamily() != 0 {
		t.Fatal("the demotion still stands after the family it demoted onto failed to connect")
	}
}

// A force is a developer override and is never undone by a dial failure.
func TestFamilyFallbackDoesNotUndoAForce(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()
	controlFamilyClear()
	defer controlFamilyClear()
	SetControlIpFamilyPolicy(IpFamilyForce4)
	defer SetControlIpFamilyPolicy(IpFamilyAuto)

	attempts := 0
	dialErr := errors.New("connect: network is unreachable")
	dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		attempts += 1
		return nil, dialErr
	}
	handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		return conn, nil
	}

	_, err := dialControlTlsWithFamilyFallback(
		context.Background(), "tcp", "api.example:443", dial, handshake)
	if !errors.Is(err, dialErr) {
		t.Fatalf("got %v, want the dial error", err)
	}
	if attempts != 1 {
		t.Fatalf("dialed %d times, want 1 -- a force must not be re-dialed around", attempts)
	}
	if ControlIpFamilyPolicy() != IpFamilyForce4 {
		t.Fatal("the force was cleared by a dial failure")
	}
}

// The spec: "a second failure over the second family is also not a family
// problem." A strike that the retry could not confirm must not be left
// standing -- it narrows every control dial in the process, including the
// extender and h3/quic paths, on evidence the helper itself just contradicted.
func TestFamilyFallbackRollsBackTheStrikeWhenTheRetryAlsoFails(t *testing.T) {
	restore := swapControlFamilyProbe(func(int) bool { return true })
	defer restore()

	tests := []struct {
		name         string
		retryDialErr bool
	}{
		{"the retry cannot connect", true},
		{"the retry connects and its handshake fails", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controlFamilyClear()
			defer controlFamilyClear()

			dial := func(ctx context.Context, network string, addr string) (net.Conn, error) {
				if network == "tcp4" {
					if test.retryDialErr {
						return nil, errors.New("connect: network is unreachable")
					}
					return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}}, nil
				}
				return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}, nil
			}
			handshake := func(ctx context.Context, conn net.Conn) (net.Conn, error) {
				return nil, &timeoutError{}
			}

			_, err := dialControlTlsWithFamilyFallback(
				context.Background(), "tcp", "api.example:443", dial, handshake)
			if err == nil {
				t.Fatal("expected the original error back")
			}
			if got := controlFamilyDemotedFamily(); got != 0 {
				t.Fatalf("ipv%d is still demoted after the other family failed too", got)
			}
			if controlFamilyStatus() != "" {
				t.Fatalf("status %q -- a strike the retry contradicted must not survive",
					controlFamilyStatus())
			}
		})
	}
}
