package connect

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
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
