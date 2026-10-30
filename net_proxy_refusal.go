package connect

import (
	"context"
	"net"
	"strings"
	"sync"
)

// ProxyUnavailableError is a socks refusal that a busy or briefly failing
// proxy gives. A shared gateway answers a burst of handshakes this way, so the
// refusal is a transport availability fault the caller may retry, the same as
// a reset or a timeout. Refusals that retrying cannot change, such as rejected
// credentials or a ruleset, keep their original error.
type ProxyUnavailableError struct {
	reason string
}

func (self *ProxyUnavailableError) Error() string {
	return "proxy unavailable: " + self.reason
}

func (self *ProxyUnavailableError) Timeout() bool   { return false }
func (self *ProxyUnavailableError) Temporary() bool { return true }

// the x/net socks client reports these as plain strings, so they are matched
// exactly. Anything else, including a protocol violation, stays a hard error.
var proxyUnavailableReasons = map[string]bool{
	"no acceptable authentication methods":       true,
	"unknown error general SOCKS server failure": true,
	"unknown error network unreachable":          true,
	"unknown error host unreachable":             true,
	"unknown error connection refused":           true,
	"unknown error TTL expired":                  true,
}

// proxyDialError keeps the socks client's net.OpError, and so its proxy and
// destination addresses, and only replaces a retryable refusal leaf.
func proxyDialError(err error) error {
	opErr, ok := err.(*net.OpError)
	if !ok || opErr.Err == nil || !strings.HasPrefix(opErr.Op, "socks") {
		return err
	}
	if _, ok := opErr.Err.(net.Error); ok {
		return err
	}
	reason := opErr.Err.Error()
	if !proxyUnavailableReasons[reason] {
		return err
	}
	copied := *opErr
	copied.Err = &ProxyUnavailableError{reason: reason}
	return &copied
}

// ProxyHostDialConcurrency bounds the socks dials, connect and handshake, in
// flight at once to one proxy host across the process. Many proxies are often
// ports of one shared gateway, and a gateway refuses a burst of new
// connections: with 1000 proxy providers on one host, 1000 requests at once
// through such a gateway failed 43% of the time and 50 at once failed 2.5%.
// Established connections do not count; only the setup does. A dial waits for
// a slot within its own context.
const ProxyHostDialConcurrency = 32

var proxyHostDials = struct {
	mutex sync.Mutex
	slots map[string]chan struct{}
}{
	slots: map[string]chan struct{}{},
}

// the proxy host, without its port, keys the slots: the gateway is the host
func proxyHostDialSlots(address string) chan struct{} {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	proxyHostDials.mutex.Lock()
	defer proxyHostDials.mutex.Unlock()
	slots, ok := proxyHostDials.slots[host]
	if !ok {
		slots = make(chan struct{}, ProxyHostDialConcurrency)
		proxyHostDials.slots[host] = slots
	}
	return slots
}

func acquireProxyHostDial(ctx context.Context, address string) (func(), error) {
	slots := proxyHostDialSlots(address)
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
