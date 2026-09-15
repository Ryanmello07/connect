//go:build linux || darwin

package connect

import (
	"errors"
	"syscall"
)

// Binds a picked port before connect. The wildcard address keeps the kernel's
// choice of source address. Counts one bind or one fallback.
func (self *h1SourcePortPlan) bind(network string, rawConn syscall.RawConn) {
	for range h1SourcePortBindAttempts {
		port, ok := self.pick()
		if !ok {
			break
		}
		var sockaddr syscall.Sockaddr
		if network == "tcp6" {
			sockaddr = &syscall.SockaddrInet6{Port: port}
		} else {
			sockaddr = &syscall.SockaddrInet4{Port: port}
		}
		var bindErr error
		if err := rawConn.Control(func(fd uintptr) {
			bindErr = syscall.Bind(int(fd), sockaddr)
		}); err != nil {
			break
		}
		if bindErr == nil {
			self.stats.SourcePortBinds.Add(1)
			return
		}
		if !errors.Is(bindErr, syscall.EADDRINUSE) {
			break
		}
	}
	self.stats.SourcePortFallbacks.Add(1)
}
