package connect

import (
	"context"
	"errors"
	"io"
	"net"
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
