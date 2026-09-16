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
//     Notsent_bytes. Darwin has no unsent field and no snd_una either;
//     Snd_sbbytes is the whole send buffer, unacked and unsent together, and
//     in-flight data is at most the congestion window and at most the peer's
//     advertised window, so taking the smaller of those off leaves a lower
//     bound on the unsent bytes. It has to be the same quantity on both
//     platforms, because the same two bars read it (transport_h1_path.go): on
//     the whole buffer they are reached by any client with a busy uplink,
//     which convicts its send direction early and turns the receive side's ack
//     evidence off altogether, and darwin and iOS are most of the fleet.
//
//     Where the two platforms agree and where they do not, measured through
//     this function against a real linux socket's Notsent_bytes. A socket with
//     more in its buffer than the window allows is window-limited: in-flight
//     is the window, the subtraction is exact, and darwin reports what linux
//     reports (400 KiB unsent behind 128 KiB in flight reads 400 KiB on both).
//     That is every saturated and every slow uplink, which is the whole of
//     what either bar is for. A socket with less in its buffer than the window
//     allows reads zero here where linux can report a real Notsent_bytes -- an
//     application-limited burst the kernel has not transmitted yet (400 KiB
//     behind a cwnd grown to 512 KiB, 300 KiB behind a scaled 1 MiB peer
//     window). Those bytes are not waiting on an ack, so they leave at line
//     rate and cannot be the seconds the ack guard is looking for, while the
//     guard's own drain term reads the acked rate of the tick and on an
//     application-limited socket that is the application's rate: the zero is
//     the better answer to the question being asked, not a worse one. What
//     darwin cannot see at all is a kernel holding bytes back for a reason
//     other than the window -- its own pacing, or a full interface queue --
//     and that is the scope limit.
//
//     The direction of the error is not symmetric between the two rules that
//     read it, which is worth naming because darwin and iOS are most of the
//     fleet. Under-reporting a backlog convicts nothing and denies no ack
//     evidence, which is the safe direction for the birth queue the ack rule
//     exists to read, and the unsafe one for the uplink guard, whose whole job
//     is to deny evidence: where darwin reads zero and linux does not, darwin
//     keeps evidence linux withdraws
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
