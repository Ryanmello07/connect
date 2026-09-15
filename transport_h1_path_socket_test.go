package connect

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A connected loopback TCP pair, closed at cleanup.
func h1PathLoopbackTcpPair(t *testing.T) (client *net.TCPConn, server *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { clientConn.Close() })
	serverConn, ok := <-accepted
	if !ok {
		t.Fatalf("accept failed")
	}
	t.Cleanup(func() { serverConn.Close() })
	return clientConn.(*net.TCPConn), serverConn.(*net.TCPConn)
}

func TestH1PathTcpConnUnwrapsDialWrappers(t *testing.T) {
	tcpConn, _ := h1PathLoopbackTcpPair(t)
	tlsConfig := &tls.Config{ServerName: "platform.example"}

	chains := []struct {
		name string
		conn net.Conn
	}{
		{name: "tcp", conn: tcpConn},
		{name: "batch(tcp)", conn: NewWebSocketWriteBatchConn(tcpConn)},
		{name: "batch(tls(tcp))", conn: NewWebSocketWriteBatchConn(tls.Client(tcpConn, tlsConfig))},
		{
			name: "batch(tls(resilient(tcp)))",
			conn: NewWebSocketWriteBatchConn(tls.Client(NewResilientTlsConn(tcpConn, true, false), tlsConfig)),
		},
	}
	for _, chain := range chains {
		unwrapped, ok := h1PathTcpConn(chain.conn)
		if !ok || unwrapped != tcpConn {
			t.Errorf("%s: unwrapped to (%p, %t), want (%p, true)", chain.name, unwrapped, ok, tcpConn)
		}
	}

	pipeConn, pipePeer := net.Pipe()
	defer pipeConn.Close()
	defer pipePeer.Close()
	refused := []struct {
		name string
		conn net.Conn
	}{
		{name: "pipe", conn: pipeConn},
		{name: "batch(pipe)", conn: NewWebSocketWriteBatchConn(pipeConn)},
		// an extender carries the platform tls inside its own tls
		{name: "batch(tls(tls(tcp)))", conn: NewWebSocketWriteBatchConn(tls.Client(tls.Client(tcpConn, tlsConfig), tlsConfig))},
		// an unknown wrapper, such as an extender's buffered stream
		{name: "batch(tls(buffered(tcp)))", conn: NewWebSocketWriteBatchConn(tls.Client(newBufferedConn(tcpConn, bufio.NewReader(tcpConn)), tlsConfig))},
		{name: "nil", conn: nil},
		{name: "typed nil", conn: (*net.TCPConn)(nil)},
	}
	for _, chain := range refused {
		if unwrapped, ok := h1PathTcpConn(chain.conn); ok {
			t.Errorf("%s: unwrapped to %p, want refused", chain.name, unwrapped)
		}
	}
}

func TestH1PathPlatformPort(t *testing.T) {
	cases := []struct {
		platformUrl string
		port        int
	}{
		{platformUrl: "wss://platform.example/", port: 443},
		{platformUrl: "ws://platform.example:8080/", port: 8080},
		{platformUrl: "https://platform.example", port: 443},
		{platformUrl: "http://platform.example", port: 80},
		{platformUrl: "ws://platform.example/", port: 80},
		{platformUrl: "WSS://platform.example/", port: 443},
		{platformUrl: "wss://[2001:db8::1]:8443/", port: 8443},
		{platformUrl: "ftp://platform.example/", port: 0},
		{platformUrl: "wss://platform.example:99999/", port: 0},
		{platformUrl: "://platform.example", port: 0},
		{platformUrl: "", port: 0},
	}
	for _, c := range cases {
		if port := h1PathPlatformPort(c.platformUrl); port != c.port {
			t.Errorf("%q: port %d, want %d", c.platformUrl, port, c.port)
		}
	}
}

// A real websocket dialed the way the platform dialer wraps it: only the
// platform port yields the kernel socket, and the local port is the socket's.
func TestH1PathKernelSocketRequiresThePlatformPort(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	dialer := &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			var netDialer net.Dialer
			conn, err := netDialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return NewWebSocketWriteBatchConn(conn), nil
		},
		HandshakeTimeout: 30 * time.Second,
	}
	platformUrl := "ws" + strings.TrimPrefix(server.URL, "http") + "/"
	ws, _, err := dialer.Dial(platformUrl, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	rawConn, localPort, ok := h1PathKernelSocket(ws, platformUrl)
	if !ok || rawConn == nil {
		t.Fatalf("kernel socket not found for the platform port")
	}
	if wantPort := ws.LocalAddr().(*net.TCPAddr).Port; localPort != wantPort {
		t.Errorf("local port %d, want %d", localPort, wantPort)
	}

	serverPort := ws.RemoteAddr().(*net.TCPAddr).Port
	otherPortUrl := "ws://127.0.0.1:" + strconv.Itoa(serverPort%65535+1) + "/"
	for _, otherUrl := range []string{otherPortUrl, "wss://127.0.0.1/", "not a url"} {
		if _, _, ok := h1PathKernelSocket(ws, otherUrl); ok {
			t.Errorf("%q: kernel socket returned for a remote port %d that is not the platform port", otherUrl, serverPort)
		}
	}
	if _, _, ok := h1PathKernelSocket(nil, platformUrl); ok {
		t.Errorf("kernel socket returned for a nil websocket")
	}
}

func TestH1PathKernelSampleCopyKeepsLowestRoundTrip(t *testing.T) {
	readings := []struct {
		minRtt       time.Duration
		wantLowest   time.Duration
		rxBytesKnown bool
	}{
		{minRtt: 0, wantLowest: 0},
		{minRtt: 120 * time.Millisecond, wantLowest: 120 * time.Millisecond, rxBytesKnown: true},
		{minRtt: 101 * time.Millisecond, wantLowest: 101 * time.Millisecond},
		{minRtt: 150 * time.Millisecond, wantLowest: 101 * time.Millisecond, rxBytesKnown: true},
		// a reading with no round trip keeps the last known one
		{minRtt: 0, wantLowest: 101 * time.Millisecond},
	}
	var lowestRtt time.Duration
	for i, reading := range readings {
		kernel := h1PathKernelSample{
			rxBytesKnown: reading.rxBytesKnown,
			rxBytes:      uint64(1000 + i),
			rxOooKnown:   true,
			rxOoo:        uint64(2000 + i),
			txKnown:      true,
			txAckedBytes: uint64(3000 + i),
			txRetrans:    uint64(4000 + i),
			txNotSent:    uint64(5000 + i),
			minRtt:       reading.minRtt,
			rcvMss:       1400 + i,
			sndMss:       1300 + i,
		}
		sample := h1PathSample{readByteCount: 77}
		kernel.copyTo(&sample, &lowestRtt)
		want := h1PathSample{
			readByteCount: 77,
			rxBytesKnown:  reading.rxBytesKnown,
			rxBytes:       uint64(1000 + i),
			rxOooKnown:    true,
			rxOoo:         uint64(2000 + i),
			txKnown:       true,
			txAckedBytes:  uint64(3000 + i),
			txRetrans:     uint64(4000 + i),
			txNotSent:     uint64(5000 + i),
			minRtt:        reading.wantLowest,
			rcvMss:        1400 + i,
			sndMss:        1300 + i,
		}
		if sample != want {
			t.Errorf("reading %d: sample %+v, want %+v", i, sample, want)
		}
		if lowestRtt != reading.wantLowest {
			t.Errorf("reading %d: lowest round trip %v, want %v", i, lowestRtt, reading.wantLowest)
		}
	}
}
