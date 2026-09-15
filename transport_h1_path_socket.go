package connect

import (
	"crypto/tls"
	"net"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// H1 path re-roll: kernel TCP counters for the socket under an H1 websocket.
//
// The platform dial wraps its TCP socket in the websocket batch writer and
// TLS, with a resilient TLS writer under the TLS on the resilient dial (which
// fragments or reorders the handshake). Only those layers are unwrapped.
// Anything else has no kernel socket that describes the path to the platform,
// so its kernel fields stay unknown:
//   - an extender carries the platform TLS inside another TLS, QUIC or DNS
//     stream, so a second TLS layer or an unknown wrapper stops the unwrap;
//   - a proxy terminates the TCP connection on its own port, so a socket whose
//     remote port is not the platform url's port is refused;
//   - an injected dial context returns its own connection type.
//
// Counters are read through RawConn.Control only, never File().Fd(), which
// clears O_NONBLOCK on the shared descriptor (see duplicateSocketHandle).
// Linux and Android read TCP_INFO, darwin and iOS read TCP_CONNECTION_INFO,
// and other platforms read nothing (h1PathReadKernel in the platform files).
// A field the kernel does not report stays unknown, and the monitor reads an
// unknown field as neither loss nor its absence.

// the platform dial nests at most three layers; the bound only stops a cycle
const h1PathUnwrapLimit = 6

// Unwraps the platform dial's layers down to its TCP socket. Refuses a second
// TLS layer, which is a tunnel to something other than the platform.
func h1PathTcpConn(conn net.Conn) (*net.TCPConn, bool) {
	tlsLayerCount := 0
	for i := 0; i <= h1PathUnwrapLimit; i += 1 {
		switch v := conn.(type) {
		case *net.TCPConn:
			return v, v != nil
		case *WebSocketWriteBatchConn:
			if v == nil {
				return nil, false
			}
			conn = v.conn
		case *tls.Conn:
			if v == nil {
				return nil, false
			}
			tlsLayerCount += 1
			if 1 < tlsLayerCount {
				return nil, false
			}
			conn = v.NetConn()
		case *ResilientTlsConn:
			if v == nil {
				return nil, false
			}
			conn = v.conn
		default:
			return nil, false
		}
	}
	return nil, false
}

// The port a direct dial to the platform url connects to: the explicit port,
// or 443 for wss and https and 80 for ws and http. Zero when the url has
// neither.
func h1PathPlatformPort(platformUrl string) int {
	u, err := url.Parse(platformUrl)
	if err != nil {
		return 0
	}
	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || 65535 < port {
			return 0
		}
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "wss", "https":
		return 443
	case "ws", "http":
		return 80
	default:
		return 0
	}
}

// The kernel socket of an H1 websocket dialed directly to the platform url, and
// its local port. Not ok when the connection is not a known wrapping of a TCP
// socket or its remote port is not the platform port.
func h1PathKernelSocket(
	ws *websocket.Conn,
	platformUrl string,
) (rawConn syscall.RawConn, localPort int, ok bool) {
	if ws == nil {
		return nil, 0, false
	}
	tcpConn, ok := h1PathTcpConn(ws.UnderlyingConn())
	if !ok {
		return nil, 0, false
	}
	platformPort := h1PathPlatformPort(platformUrl)
	remoteAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr)
	if !ok || remoteAddr == nil || platformPort == 0 || remoteAddr.Port != platformPort {
		return nil, 0, false
	}
	localAddr, ok := tcpConn.LocalAddr().(*net.TCPAddr)
	if !ok || localAddr == nil {
		return nil, 0, false
	}
	rawConn, ok = socketRawConn(tcpConn)
	if !ok {
		return nil, 0, false
	}
	return rawConn, localAddr.Port, true
}

// One read of a socket's kernel counters. Every counter is cumulative over the
// socket's life. The zero value is all unknown.
type h1PathKernelSample struct {
	rxBytesKnown bool
	rxBytes      uint64
	// linux counts out-of-order packets, darwin out-of-order bytes; only
	// advancement is read
	rxOooKnown bool
	rxOoo      uint64
	// acked bytes, retransmits and the send backlog are known together.
	// Darwin reports bytes sent for acked bytes, and a send buffer that
	// includes in-flight data for the backlog.
	txKnown      bool
	txAckedBytes uint64
	txRetrans    uint64
	txNotSent    uint64
	// linux reports the kernel minimum round trip, darwin only a smoothed
	// round trip; zero is unknown
	minRtt time.Duration
	// zero is unknown
	rcvMss int
	sndMss int
}

// Copies the reading into a monitor sample. lowestRtt is the caller's lowest
// kernel round trip for this socket, lowered by the reading and carried into
// the sample, so darwin's smoothed round trip becomes the lowest seen and a
// reading with no round trip keeps the last known one.
func (self *h1PathKernelSample) copyTo(sample *h1PathSample, lowestRtt *time.Duration) {
	sample.rxBytesKnown = self.rxBytesKnown
	sample.rxBytes = self.rxBytes
	sample.rxOooKnown = self.rxOooKnown
	sample.rxOoo = self.rxOoo
	sample.txKnown = self.txKnown
	sample.txAckedBytes = self.txAckedBytes
	sample.txRetrans = self.txRetrans
	sample.txNotSent = self.txNotSent
	sample.rcvMss = self.rcvMss
	sample.sndMss = self.sndMss
	if 0 < self.minRtt && (*lowestRtt <= 0 || self.minRtt < *lowestRtt) {
		*lowestRtt = self.minRtt
	}
	sample.minRtt = max(*lowestRtt, 0)
}
