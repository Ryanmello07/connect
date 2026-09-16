//go:build darwin

package connect

import (
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Darwin and iOS: TCP_CONNECTION_INFO through x/sys.
//
// The layout is unix.TCPConnectionInfo, 112 bytes, which matches struct
// tcp_connection_info in the SDK's netinet/tcp.h. XNU copies at most its own
// struct. The last field, tcpi_txretransmitpackets, arrived in xnu-4570 (macOS
// 10.13, iOS 11), well before macOS 12, the oldest release Go supports; on an
// older kernel it would read zero, which only denies a send conviction. x/sys
// does not return the copied length, so a struct the kernel did not fill is
// recognized by a zero maximum segment, which no connected socket reports.
//
// Mapping, with its approximations:
//   - Rxbytes and Rxoutoforderbytes: received and out-of-order bytes
//   - Txbytes: bytes sent, a proxy for acked bytes
//   - Txretransmitpackets: retransmitted segments
//   - Snd_sbbytes less the in-flight bound: the bytes the kernel has accepted
//     and not yet put on the wire, which is what linux reports directly as
//     Notsent_bytes. Darwin has no unsent field; Snd_sbbytes is the whole send
//     buffer, unacked and unsent together, and in-flight data is at most the
//     congestion window and at most the peer's advertised window, so taking
//     the smaller of those off leaves a lower bound on the unsent bytes. It
//     has to be the same quantity on both platforms, because one constant
//     (SendBacklogByteCount) reads it: on the whole buffer the constant is
//     reached by any client with a busy uplink, which convicts its send
//     direction early and turns the receive side's ack evidence off
//     altogether, and darwin and iOS are most of the fleet. Erring low is the
//     safe direction for both rules: a backlog under-reported denies no
//     evidence and convicts nothing
//   - Srtt: the smoothed round trip in milliseconds; darwin keeps no minimum,
//     so the caller keeps the lowest (h1PathKernelSample.copyTo)
//   - Maxseg: both segment sizes

// Reads the socket's TCP_CONNECTION_INFO into out. False, with every field
// unknown, when the descriptor or the call fails or the kernel filled nothing.
func h1PathReadKernel(rawConn syscall.RawConn, out *h1PathKernelSample) bool {
	*out = h1PathKernelSample{}
	var info *unix.TCPConnectionInfo
	var err error
	controlErr := rawConn.Control(func(fd uintptr) {
		info, err = unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
	})
	if controlErr != nil || err != nil || info == nil {
		return false
	}
	return h1PathKernelSampleFromConnectionInfo(info, out)
}

// Fills out from a TCP_CONNECTION_INFO. False, with every field unknown, when
// the maximum segment is zero.
func h1PathKernelSampleFromConnectionInfo(info *unix.TCPConnectionInfo, out *h1PathKernelSample) bool {
	*out = h1PathKernelSample{}
	if info.Maxseg == 0 {
		return false
	}
	out.rxBytesKnown = true
	out.rxBytes = info.Rxbytes
	out.rxOooKnown = true
	out.rxOoo = info.Rxoutoforderbytes
	out.txKnown = true
	out.txAckedBytes = info.Txbytes
	out.txRetrans = info.Txretransmitpackets
	// the window fields are zero on a socket that has not sent, where the whole
	// buffer is unsent anyway
	inFlight := uint64(min(info.Snd_cwnd, info.Snd_wnd))
	sendBuffer := uint64(info.Snd_sbbytes)
	out.txNotSent = sendBuffer - min(sendBuffer, inFlight)
	out.minRtt = time.Duration(info.Srtt) * time.Millisecond
	out.rcvMss = int(info.Maxseg)
	out.sndMss = int(info.Maxseg)
	return true
}
