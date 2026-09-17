//go:build linux || darwin

package connect

import (
	"io"
	"testing"
)

// Kernel counters on a loopback socket after bulk transfer in each direction.
// The receiver of each phase replies with one byte and the sender reads it:
// that segment acknowledges the whole phase, so the sender's kernel has
// counted every acked byte before the read.
func TestH1PathKernelSampleCountsLoopbackTraffic(t *testing.T) {
	const bulkByteCount = 4 * 1024 * 1024
	clientConn, serverConn := h1PathLoopbackTcpPair(t)
	rawConn, ok := socketRawConn(clientConn)
	if !ok {
		t.Fatalf("no raw conn")
	}

	transfer := func(from io.Writer, to io.Reader, fromReply io.Reader, toReply io.Writer) {
		t.Helper()
		writeErr := make(chan error, 1)
		go func() {
			_, err := from.Write(make([]byte, bulkByteCount))
			writeErr <- err
		}()
		if _, err := io.ReadFull(to, make([]byte, bulkByteCount)); err != nil {
			t.Fatalf("bulk read: %v", err)
		}
		if err := <-writeErr; err != nil {
			t.Fatalf("bulk write: %v", err)
		}
		if _, err := toReply.Write([]byte{1}); err != nil {
			t.Fatalf("reply write: %v", err)
		}
		if _, err := io.ReadFull(fromReply, make([]byte, 1)); err != nil {
			t.Fatalf("reply read: %v", err)
		}
	}

	// the server sends: the client's socket receives
	transfer(serverConn, clientConn, serverConn, clientConn)
	var kernel h1PathKernelSample
	if !h1PathReadKernel(rawConn, &kernel) {
		t.Fatalf("kernel read failed")
	}
	if !kernel.rxBytesKnown || kernel.rxBytes < bulkByteCount {
		t.Errorf("receive: rxBytes (%t, %d), want known and at least %d", kernel.rxBytesKnown, kernel.rxBytes, bulkByteCount)
	}
	if kernel.rxOooKnown != h1PathKernelReportsOutOfOrder(t, rawConn) {
		t.Errorf("receive: rxOooKnown %t, not what this kernel reports", kernel.rxOooKnown)
	}
	receivedByteCount := kernel.rxBytes

	// the client sends
	transfer(clientConn, serverConn, clientConn, serverConn)
	if !h1PathReadKernel(rawConn, &kernel) {
		t.Fatalf("kernel read failed")
	}
	if !kernel.txKnown || kernel.txAckedBytes < bulkByteCount {
		t.Errorf("send: txAckedBytes (%t, %d), want known and at least %d", kernel.txKnown, kernel.txAckedBytes, bulkByteCount)
	}
	if kernel.sndMss <= 0 || kernel.rcvMss <= 0 {
		t.Errorf("send: mss (%d, %d), want both known", kernel.sndMss, kernel.rcvMss)
	}
	// the client received only the one-byte reply since
	if !kernel.rxBytesKnown || kernel.rxBytes != receivedByteCount+1 {
		t.Errorf("send: rxBytes %d, want %d", kernel.rxBytes, receivedByteCount+1)
	}
	t.Logf(
		"rxBytes=%d rxOoo=(%t, %d) txAckedBytes=%d txRetrans=%d txNotSent=%d minRtt=%v mss=(%d, %d)",
		kernel.rxBytes, kernel.rxOooKnown, kernel.rxOoo, kernel.txAckedBytes, kernel.txRetrans,
		kernel.txNotSent, kernel.minRtt, kernel.rcvMss, kernel.sndMss,
	)

	// a closed socket reads nothing
	clientConn.Close()
	if h1PathReadKernel(rawConn, &kernel) || kernel != (h1PathKernelSample{}) {
		t.Errorf("closed socket: read %+v, want all unknown", kernel)
	}
}
