package connect

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// A busy gateway's socks refusal is a retryable transport fault; rejected
// credentials and protocol violations stay hard.
func TestProxyDialErrorClassifiesSocksRefusals(t *testing.T) {
	refusal := func(reason string) error {
		return &net.OpError{Op: "socks connect", Net: "tcp", Err: errors.New(reason)}
	}
	for reason, retryable := range map[string]bool{
		"no acceptable authentication methods":            true,
		"unknown error general SOCKS server failure":      true,
		"unknown error host unreachable":                  true,
		"unknown error TTL expired":                       true,
		"username/password authentication failed":         false,
		"unknown error connection not allowed by ruleset": false,
		"unexpected protocol version 4":                   false,
	} {
		err := proxyDialError(refusal(reason))
		var unavailable *ProxyUnavailableError
		if errors.As(err, &unavailable) != retryable {
			t.Fatalf("%q: retryable = %t, want %t", reason, !retryable, retryable)
		}
		if cause := classifyHttpRequestCause(unavailable); retryable && cause.kind == 0 {
			t.Fatalf("%q: the request exhaustion counts the refusal as hard", reason)
		}
	}

	// already typed transport faults and non-socks errors are left alone
	reset := &net.OpError{Op: "socks connect", Net: "tcp", Err: io.EOF}
	if proxyDialError(reset) != error(reset) {
		t.Fatal("a socks handshake eof was rewrapped")
	}
	timeout := &net.OpError{Op: "socks connect", Net: "tcp", Err: &net.DNSError{IsTimeout: true}}
	if proxyDialError(timeout) != error(timeout) {
		t.Fatal("a socks net.Error was rewrapped")
	}
	plain := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("no acceptable authentication methods")}
	if proxyDialError(plain) != error(plain) {
		t.Fatal("a non-socks error was rewrapped")
	}
}

// The proxy dial path returns the classified refusal from a real socks
// server that refuses every authentication method.
func TestProxyDialContextReportsGatewayRefusalAsUnavailable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				header := make([]byte, 2)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				io.ReadFull(conn, make([]byte, header[1]))
				conn.Write([]byte{5, 0xff})
			}()
		}
	}()

	settings := DefaultConnectSettings()
	settings.ProxySettings = &ProxySettings{Network: "tcp", Address: listener.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = settings.DialContext(ctx, "tcp", "api.example:443")
	var unavailable *ProxyUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want a ProxyUnavailableError", err)
	}
}

// A proxied strategy dials one route at a time and never leaves the proxy:
// no resilient variants and no alt dialers. An injected dial context wins
// over the proxy, so it keeps both.
func TestProxiedClientStrategyKeepsOneProxiedDialer(t *testing.T) {
	descriptions := func(settings *ClientStrategySettings) map[string]bool {
		strategy := NewClientStrategy(context.Background(), settings)
		defer strategy.Close()
		out := map[string]bool{}
		for dialer := range strategy.dialers {
			out[dialer.description] = true
		}
		return out
	}

	base := DefaultClientStrategySettings()
	base.AltUrl = "https://alt.space.example"
	direct := descriptions(base)
	for _, want := range []string{"normal", "fragment", "alt h3", "alt whodis"} {
		if !direct[want] {
			t.Fatalf("a direct strategy lacks %q (%v), so the test proves nothing", want, direct)
		}
	}

	proxied := DefaultClientStrategySettings()
	proxied.AltUrl = base.AltUrl
	proxied.ProxySettings = &ProxySettings{Network: "tcp", Address: "192.0.2.1:1080"}
	if got := descriptions(proxied); len(got) != 1 || !got["normal"] {
		t.Fatalf("a proxied strategy has dialers %v, want only normal", got)
	}

	injected := DefaultClientStrategySettings()
	injected.AltUrl = base.AltUrl
	injected.ProxySettings = proxied.ProxySettings
	injected.DialContextSettings = &DialContextSettings{DialContext: (&net.Dialer{}).DialContext}
	if got := descriptions(injected); !got["fragment"] || !got["alt h3"] {
		t.Fatalf("an injected dial context lost its dialers: %v", got)
	}
}

// Socks dials to one proxy host wait for one of ProxyHostDialConcurrency
// slots, across ports; a waiting dial gives up with its context.
func TestProxyHostDialsAreBounded(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var stateLock sync.Mutex
	inFlight, maxInFlight := 0, 0
	hold := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				stateLock.Lock()
				inFlight++
				maxInFlight = max(maxInFlight, inFlight)
				stateLock.Unlock()
				<-hold
				stateLock.Lock()
				inFlight--
				stateLock.Unlock()
			}()
		}
	}()

	// one gateway host, two port spellings: the host is the key
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	addresses := []string{"127.0.0.1:" + port, "127.0.0.1:" + port}

	n := ProxyHostDialConcurrency + 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := range n {
		settings := DefaultConnectSettings()
		settings.ProxySettings = &ProxySettings{Network: "tcp", Address: addresses[i%2]}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := settings.DialContext(ctx, "tcp", "api.example:443")
			errs <- err
		}()
	}
	wg.Wait()
	close(hold)
	close(errs)

	stateLock.Lock()
	defer stateLock.Unlock()
	if maxInFlight != ProxyHostDialConcurrency {
		t.Fatalf("%d socks dials reached the proxy host at once, want %d", maxInFlight, ProxyHostDialConcurrency)
	}
	waited := 0
	for err := range errs {
		if errors.Is(err, context.DeadlineExceeded) {
			waited++
		}
	}
	if waited < n-ProxyHostDialConcurrency {
		t.Fatalf("%d dials ended with their context, want at least %d", waited, n-ProxyHostDialConcurrency)
	}
}

// A proxied strategy draws no extenders from its directory; the same
// directory gives a direct strategy its extender dialers.
func TestProxiedClientStrategyExpandsNoDirectoryExtenders(t *testing.T) {
	clock := newTestClock()
	directory, rootPrivateKey := newTestExtenderDirectory(t, clock, nil)
	t.Cleanup(setSpoofDomainsForTest([]string{"spoof.example"}))
	t.Cleanup(swapControlFamilyProbe(func(family int) bool { return true }))
	ip := netip.MustParseAddr("192.0.2.111")
	record := signTestRecord(
		t,
		rootPrivateKey,
		newTestExtenderKey(t),
		clock.Now(),
		clock.Now().Add(14*24*time.Hour),
		testExtenderAddress(ip.String(), ExtenderCarrierTcp),
	)
	if _, err := directory.ApplyRecord(record, ExtenderSourceFeed); err != nil {
		t.Fatal(err)
	}
	expand := func(proxied bool) int {
		settings := DefaultClientStrategySettings()
		settings.ExtenderDirectory = directory
		if proxied {
			settings.ProxySettings = &ProxySettings{Network: "tcp", Address: "192.0.2.1:1080"}
		}
		strategy := NewClientStrategy(context.Background(), settings)
		defer strategy.Close()
		return len(strategy.expandExtenderDialers())
	}
	if expand(false) == 0 {
		t.Fatal("a direct strategy expanded no extenders, so the test proves nothing")
	}
	if n := expand(true); n != 0 {
		t.Fatalf("a proxied strategy expanded %d extender dialers", n)
	}
}
