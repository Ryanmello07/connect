//go:build darwin

package connect

import (
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Darwin reports out-of-order bytes on every supported release.
func h1PathKernelReportsOutOfOrder(t *testing.T, rawConn syscall.RawConn) bool {
	return true
}

// The offsets of struct tcp_connection_info in the SDK's netinet/tcp.h, read
// with offsetof: a layout change in x/sys would misread the kernel.
func TestH1PathTcpConnectionInfoLayoutMatchesXnu(t *testing.T) {
	var info unix.TCPConnectionInfo
	offsets := []struct {
		name   string
		offset uintptr
		size   uintptr
		want   uintptr
	}{
		{name: "tcpi_maxseg", offset: unsafe.Offsetof(info.Maxseg), size: unsafe.Sizeof(info.Maxseg), want: 16},
		{name: "tcpi_snd_cwnd", offset: unsafe.Offsetof(info.Snd_cwnd), size: unsafe.Sizeof(info.Snd_cwnd), want: 24},
		{name: "tcpi_snd_wnd", offset: unsafe.Offsetof(info.Snd_wnd), size: unsafe.Sizeof(info.Snd_wnd), want: 28},
		{name: "tcpi_snd_sbbytes", offset: unsafe.Offsetof(info.Snd_sbbytes), size: unsafe.Sizeof(info.Snd_sbbytes), want: 32},
		{name: "tcpi_srtt", offset: unsafe.Offsetof(info.Srtt), size: unsafe.Sizeof(info.Srtt), want: 44},
		{name: "tcpi_txbytes", offset: unsafe.Offsetof(info.Txbytes), size: unsafe.Sizeof(info.Txbytes), want: 64},
		{name: "tcpi_rxbytes", offset: unsafe.Offsetof(info.Rxbytes), size: unsafe.Sizeof(info.Rxbytes), want: 88},
		{name: "tcpi_rxoutoforderbytes", offset: unsafe.Offsetof(info.Rxoutoforderbytes), size: unsafe.Sizeof(info.Rxoutoforderbytes), want: 96},
		{name: "tcpi_txretransmitpackets", offset: unsafe.Offsetof(info.Txretransmitpackets), size: unsafe.Sizeof(info.Txretransmitpackets), want: 104},
	}
	for _, o := range offsets {
		if o.offset != o.want {
			t.Errorf("%s at %d, want %d", o.name, o.offset, o.want)
		}
	}
	if size := unsafe.Sizeof(info); size != 112 || unix.SizeofTCPConnectionInfo != 112 {
		t.Errorf("struct size %d (x/sys %d), want 112", size, unix.SizeofTCPConnectionInfo)
	}
	if unix.TCP_CONNECTION_INFO != 0x106 {
		t.Errorf("TCP_CONNECTION_INFO 0x%x, want 0x106", unix.TCP_CONNECTION_INFO)
	}
}

// The send buffer holds unacked and unsent bytes together, and only the unsent
// part is what linux reports and what one constant reads on both platforms, so
// the in-flight bound comes off it.
func TestH1PathTcpConnectionInfoMapsFields(t *testing.T) {
	info := unix.TCPConnectionInfo{
		Maxseg:              16344,
		Snd_cwnd:            120 * 1024,
		Snd_wnd:             44 * 1024,
		Snd_sbbytes:         300 * 1024,
		Srtt:                101,
		Txbytes:             11,
		Txretransmitpackets: 12,
		Rxbytes:             13,
		Rxoutoforderbytes:   14,
		Rxpackets:           99,
		Txpackets:           98,
		Txretransmitbytes:   97,
	}
	var kernel h1PathKernelSample
	if !h1PathKernelSampleFromConnectionInfo(&info, &kernel) {
		t.Fatalf("a filled struct read as unknown")
	}
	want := h1PathKernelSample{
		rxBytesKnown: true,
		rxBytes:      13,
		rxOooKnown:   true,
		rxOoo:        14,
		txKnown:      true,
		txAckedBytes: 11,
		txRetrans:    12,
		// the peer's window is the smaller bound, so 300 - 44 KiB is unsent
		txNotSent: 256 * 1024,
		minRtt:    101 * time.Millisecond,
		rcvMss:    16344,
		sndMss:    16344,
	}
	if kernel != want {
		t.Errorf("sample %+v, want %+v", kernel, want)
	}

	// a whole buffer in flight is nothing unsent, and never a negative count
	inFlight := info
	inFlight.Snd_cwnd = 1024 * 1024
	inFlight.Snd_wnd = 1024 * 1024
	if h1PathKernelSampleFromConnectionInfo(&inFlight, &kernel); kernel.txNotSent != 0 {
		t.Errorf("unsent = %d with the whole buffer in flight, want 0", kernel.txNotSent)
	}
	// a socket that has not sent reports no windows, and its buffer is unsent
	unsent := info
	unsent.Snd_cwnd = 0
	unsent.Snd_wnd = 0
	if h1PathKernelSampleFromConnectionInfo(&unsent, &kernel); kernel.txNotSent != 300*1024 {
		t.Errorf("unsent = %d with no window reported, want the whole buffer", kernel.txNotSent)
	}

	// a struct the kernel did not fill, over a previous reading
	unfilled := unix.TCPConnectionInfo{Rxbytes: 5}
	if h1PathKernelSampleFromConnectionInfo(&unfilled, &kernel) || kernel != (h1PathKernelSample{}) {
		t.Errorf("unfilled struct: %+v, want all unknown", kernel)
	}
}

// The window states the unsent count is read across, and what each one means
// for the two rules that read it (transport_h1_path_socket_darwin.go). The
// numbers are the ones a linux socket reports directly as Notsent_bytes for
// the same shapes, so this is where the two platforms are pinned against each
// other.
func TestH1PathTcpConnectionInfoUnsentBytesAcrossWindowStates(t *testing.T) {
	unsentByteCount := func(sendBuffer uint32, cwnd uint32, wnd uint32) uint64 {
		t.Helper()
		info := unix.TCPConnectionInfo{
			Maxseg:      1448,
			Snd_cwnd:    cwnd,
			Snd_wnd:     wnd,
			Snd_sbbytes: sendBuffer,
			Srtt:        101,
		}
		var kernel h1PathKernelSample
		if !h1PathKernelSampleFromConnectionInfo(&info, &kernel) {
			t.Fatalf("a filled struct read as unknown")
		}
		return kernel.txNotSent
	}
	states := []struct {
		name       string
		sendBuffer uint32
		cwnd       uint32
		wnd        uint32
		want       uint64
	}{
		{
			// window-limited, which is every saturated uplink: in-flight is
			// the window and the subtraction is exact
			name:       "400 KiB behind 128 KiB in flight",
			sendBuffer: 528 * 1024, cwnd: 128 * 1024, wnd: 1024 * 1024,
			want: 400 * 1024,
		},
		{
			// a slow uplink's window is a handful of segments, so its own
			// queue is visible here: 60 KB is two seconds at 0.25 Mb/s, which
			// is what withdraws the ack evidence
			name:       "60 KB behind a 14 KB congestion window",
			sendBuffer: 60*1024 + 14*1024, cwnd: 14 * 1024, wnd: 256 * 1024,
			want: 60 * 1024,
		},
		{
			// not window-limited: the bound is loose and eats the whole
			// buffer, where linux reports 400 KiB of an application-limited
			// burst that leaves at line rate
			name:       "400 KiB with the congestion window grown past it",
			sendBuffer: 400 * 1024, cwnd: 512 * 1024, wnd: 1024 * 1024,
			want: 0,
		},
		{
			name:       "300 KiB behind a scaled 1 MiB peer window",
			sendBuffer: 300 * 1024, cwnd: 2048 * 1024, wnd: 1024 * 1024,
			want: 0,
		},
	}
	for _, state := range states {
		if unsent := unsentByteCount(state.sendBuffer, state.cwnd, state.wnd); unsent != state.want {
			t.Errorf("%s: unsent = %d, want %d", state.name, unsent, state.want)
		}
	}

	// and the slow uplink's reading fed to the rule it is for: a healthy
	// receive path whose ack round trip carries two seconds of our own queue
	// is not convicted for it
	settings := DefaultH1PathRerollSettings()
	monitor, stats := newH1PathTestMonitor(t, &settings, 105*time.Millisecond)
	decisions := runH1PathMonitorShape(monitor, 60, func(k int) h1PathTickShape {
		return h1PathTickShape{
			rxByteRate:        700_000,
			queueDelay:        20 * time.Millisecond,
			queueDelaySamples: 4,
			rxOooAdvance:      true,
			ackRtt:            2 * time.Second,
			txKnown:           true,
			txAckedByteRate:   31_250,
			txNotSent:         unsentByteCount(60*1024+14*1024, 14*1024, 256*1024),
		}
	})
	if ticks := h1PathConvictionTicks(decisions); len(ticks) != 0 {
		t.Errorf("a 0.25 Mb/s uplink's own queue convicted the receive path at ticks %v", ticks)
	}
	if snapshot := stats.snapshot(); snapshot.TicksAckBacklogged == 0 {
		t.Errorf("stats = %+v, want the uplink's ticks counted as our own backlog", snapshot)
	}
}
