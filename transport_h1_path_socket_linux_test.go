//go:build linux

package connect

import (
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Whether this kernel's TCP_INFO reaches rcv_ooopack (5.4 and later). Logs the
// kernel release when it does not.
func h1PathKernelReportsOutOfOrder(t *testing.T, rawConn syscall.RawConn) bool {
	t.Helper()
	var info unix.TCPInfo
	length := uint32(unsafe.Sizeof(info))
	var errno syscall.Errno
	if err := rawConn.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.IPPROTO_TCP,
			unix.TCP_INFO,
			uintptr(unsafe.Pointer(&info)),
			uintptr(unsafe.Pointer(&length)),
			0,
		)
	}); err != nil || errno != 0 {
		t.Fatalf("getsockopt: %v %v", err, errno)
	}
	reports := unsafe.Offsetof(info.Rcv_ooopack)+unsafe.Sizeof(info.Rcv_ooopack) <= uintptr(length)
	if !reports {
		var uname unix.Utsname
		_ = unix.Uname(&uname)
		t.Logf("kernel %s reports %d bytes of TCP_INFO, without rcv_ooopack", unix.ByteSliceToString(uname.Release[:]), length)
	}
	return reports
}

// The ends of the fields read, from include/uapi/linux/tcp.h: a layout change
// in x/sys would misread the kernel and move every length gate.
func TestH1PathTcpInfoLayoutMatchesTheKernel(t *testing.T) {
	var info unix.TCPInfo
	ends := []struct {
		name string
		end  uintptr
		want uintptr
	}{
		{name: "tcpi_snd_mss", end: unsafe.Offsetof(info.Snd_mss) + unsafe.Sizeof(info.Snd_mss), want: 20},
		{name: "tcpi_rcv_mss", end: unsafe.Offsetof(info.Rcv_mss) + unsafe.Sizeof(info.Rcv_mss), want: 24},
		{name: "tcpi_total_retrans", end: unsafe.Offsetof(info.Total_retrans) + unsafe.Sizeof(info.Total_retrans), want: 104},
		{name: "tcpi_bytes_acked", end: unsafe.Offsetof(info.Bytes_acked) + unsafe.Sizeof(info.Bytes_acked), want: 128},
		{name: "tcpi_bytes_received", end: unsafe.Offsetof(info.Bytes_received) + unsafe.Sizeof(info.Bytes_received), want: 136},
		{name: "tcpi_notsent_bytes", end: unsafe.Offsetof(info.Notsent_bytes) + unsafe.Sizeof(info.Notsent_bytes), want: 148},
		{name: "tcpi_min_rtt", end: unsafe.Offsetof(info.Min_rtt) + unsafe.Sizeof(info.Min_rtt), want: 152},
		{name: "tcpi_rcv_ooopack", end: unsafe.Offsetof(info.Rcv_ooopack) + unsafe.Sizeof(info.Rcv_ooopack), want: 228},
	}
	for _, e := range ends {
		if e.end != e.want {
			t.Errorf("%s ends at %d, want %d", e.name, e.end, e.want)
		}
	}
}

// The kernel copies only its own struct; a field past the copied length reads
// as unknown, never as a real zero.
func TestH1PathTcpInfoShortLengthLeavesLaterFieldsUnknown(t *testing.T) {
	info := unix.TCPInfo{
		Snd_mss:        1448,
		Rcv_mss:        1440,
		Total_retrans:  7,
		Bytes_acked:    8 * 1024 * 1024,
		Bytes_received: 9 * 1024 * 1024,
		Notsent_bytes:  300 * 1024,
		Min_rtt:        101000,
		Rcv_ooopack:    3,
	}
	full := h1PathKernelSample{
		rxBytesKnown: true,
		rxBytes:      9 * 1024 * 1024,
		rxOooKnown:   true,
		rxOoo:        3,
		txKnown:      true,
		txAckedBytes: 8 * 1024 * 1024,
		txRetrans:    7,
		txNotSent:    300 * 1024,
		minRtt:       101 * time.Millisecond,
		rcvMss:       1440,
		sndMss:       1448,
	}
	mssOnly := h1PathKernelSample{rcvMss: 1440, sndMss: 1448}
	rxBytes := mssOnly
	rxBytes.rxBytesKnown = true
	rxBytes.rxBytes = 9 * 1024 * 1024
	withTx := rxBytes
	withTx.txKnown = true
	withTx.txAckedBytes = 8 * 1024 * 1024
	withTx.txRetrans = 7
	withTx.txNotSent = 300 * 1024
	withMinRtt := withTx
	withMinRtt.minRtt = 101 * time.Millisecond

	cases := []struct {
		length uint32
		want   h1PathKernelSample
	}{
		{length: 0, want: h1PathKernelSample{}},
		{length: 20, want: h1PathKernelSample{sndMss: 1448}},
		// every kernel with TCP_INFO: before 4.1
		{length: 104, want: mssOnly},
		{length: 135, want: mssOnly},
		// 4.1 to 4.5
		{length: 136, want: rxBytes},
		{length: 147, want: rxBytes},
		{length: 148, want: withTx},
		// 4.6 to 5.3
		{length: 160, want: withMinRtt},
		{length: 227, want: withMinRtt},
		// 5.4 and later
		{length: 232, want: full},
		{length: uint32(unsafe.Sizeof(info)), want: full},
	}
	var kernel h1PathKernelSample
	for _, c := range cases {
		// a previous full reading must not leak into a shorter one
		kernel = full
		h1PathKernelSampleFromTcpInfo(&info, c.length, &kernel)
		if kernel != c.want {
			t.Errorf("length %d: %+v, want %+v", c.length, kernel, c.want)
		}
	}

	// no round trip sample yet reads ~0, and zero is unknown too
	for _, minRtt := range []uint32{^uint32(0), 0} {
		noRtt := info
		noRtt.Min_rtt = minRtt
		h1PathKernelSampleFromTcpInfo(&noRtt, uint32(unsafe.Sizeof(noRtt)), &kernel)
		if kernel.minRtt != 0 {
			t.Errorf("min_rtt %d: round trip %v, want unknown", minRtt, kernel.minRtt)
		}
	}
}
