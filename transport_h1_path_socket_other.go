//go:build !linux && !darwin

package connect

import "syscall"

// Only Linux, Android, darwin and iOS expose per-socket TCP counters that the
// H1 path monitor reads; elsewhere every kernel field stays unknown and the
// monitor judges from the queue delay and the delivered rate.
func h1PathReadKernel(rawConn syscall.RawConn, out *h1PathKernelSample) bool {
	*out = h1PathKernelSample{}
	return false
}
