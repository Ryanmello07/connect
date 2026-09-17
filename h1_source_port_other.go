//go:build !linux && !darwin

package connect

import (
	"syscall"
)

// No bind on this platform: the kernel chooses the port. Counts one fallback.
func (self *h1SourcePortPlan) bind(network string, rawConn syscall.RawConn) {
	self.stats.SourcePortFallbacks.Add(1)
}
