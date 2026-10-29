package connect

import (
	"net"
	"strings"
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
