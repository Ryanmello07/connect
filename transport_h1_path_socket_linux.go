//go:build linux

package connect

import (
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux and Android: TCP_INFO through a raw getsockopt, the same shape as
// udpSocketReceiveDropCount.
//
// x/sys GetsockoptTCPInfo discards the length the kernel writes back, and the
// kernel copies only its own struct's length, so a field past an older
// kernel's struct would read as a real zero. The raw call keeps the length,
// and a field is read only when that length reaches its end. The layout is
// unix.TCPInfo, generated from include/uapi/linux/tcp.h; the ends used, with
// the kernel that added each field:
//   - snd_mss 20, rcv_mss 24 and total_retrans 104: every kernel with TCP_INFO
//   - bytes_acked 128 and bytes_received 136: 4.1
//   - notsent_bytes 148 and min_rtt 152: 4.6
//   - rcv_ooopack 228: 5.4, so older Android kernels read no receive loss

// Reads the socket's TCP_INFO into out. False, with every field unknown, when
// the descriptor or the call fails.
func h1PathReadKernel(rawConn syscall.RawConn, out *h1PathKernelSample) bool {
	*out = h1PathKernelSample{}
	var info unix.TCPInfo
	length := uint32(unsafe.Sizeof(info))
	var errno syscall.Errno
	controlErr := rawConn.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.IPPROTO_TCP,
			unix.TCP_INFO,
			uintptr(unsafe.Pointer(&info)),
			uintptr(unsafe.Pointer(&length)),
			0,
		)
	})
	if controlErr != nil || errno != 0 {
		return false
	}
	h1PathKernelSampleFromTcpInfo(&info, length, out)
	return true
}

// Fills out from a TCP_INFO of which the kernel wrote length bytes. Fields
// past length stay unknown.
func h1PathKernelSampleFromTcpInfo(info *unix.TCPInfo, length uint32, out *h1PathKernelSample) {
	*out = h1PathKernelSample{}
	reaches := func(end uintptr) bool {
		return end <= uintptr(length)
	}

	if reaches(unsafe.Offsetof(info.Snd_mss) + unsafe.Sizeof(info.Snd_mss)) {
		out.sndMss = int(info.Snd_mss)
	}
	if reaches(unsafe.Offsetof(info.Rcv_mss) + unsafe.Sizeof(info.Rcv_mss)) {
		out.rcvMss = int(info.Rcv_mss)
	}
	if reaches(unsafe.Offsetof(info.Bytes_received) + unsafe.Sizeof(info.Bytes_received)) {
		out.rxBytesKnown = true
		out.rxBytes = info.Bytes_received
	}
	if reaches(unsafe.Offsetof(info.Rcv_ooopack) + unsafe.Sizeof(info.Rcv_ooopack)) {
		out.rxOooKnown = true
		out.rxOoo = uint64(info.Rcv_ooopack)
	}
	if reaches(unsafe.Offsetof(info.Total_retrans)+unsafe.Sizeof(info.Total_retrans)) &&
		reaches(unsafe.Offsetof(info.Bytes_acked)+unsafe.Sizeof(info.Bytes_acked)) &&
		reaches(unsafe.Offsetof(info.Notsent_bytes)+unsafe.Sizeof(info.Notsent_bytes)) {
		out.txKnown = true
		out.txAckedBytes = info.Bytes_acked
		out.txRetrans = uint64(info.Total_retrans)
		out.txNotSent = uint64(info.Notsent_bytes)
	}
	// microseconds; the kernel reports ~0 until the first round trip sample
	if reaches(unsafe.Offsetof(info.Min_rtt)+unsafe.Sizeof(info.Min_rtt)) &&
		0 < info.Min_rtt && info.Min_rtt < ^uint32(0) {
		out.minRtt = time.Duration(info.Min_rtt) * time.Microsecond
	}
}
