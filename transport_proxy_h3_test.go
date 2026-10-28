package connect

import (
	"context"
	"net"
	"testing"
)

// Every h3 mode sends udp from a host socket, so a transport whose strategy
// dials through a proxy offers none of them and an explicit h3 target falls
// back to h1; without a proxy, or with a packet conn factory that supplies the
// h3 endpoints, the modes stay.
func TestProxiedPlatformTransportRunsH1Only(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h3Modes := []TransportMode{TransportModeH3, TransportModeH3Dns, TransportModeH3DnsPump}
	for _, c := range []struct {
		name    string
		proxied bool
		factory bool
		target  TransportMode
	}{
		{"proxied auto", true, false, TransportModeAuto},
		{"proxied h3", true, false, TransportModeH3},
		{"proxied h3dnspump", true, false, TransportModeH3DnsPump},
		{"direct auto", false, false, TransportModeAuto},
		{"proxied with factory", true, true, TransportModeH3},
	} {
		strategySettings := DefaultClientStrategySettings()
		if c.proxied {
			strategySettings.ProxySettings = &ProxySettings{Network: "tcp", Address: "192.0.2.1:1080"}
		}
		strategy := NewClientStrategy(ctx, strategySettings)
		settings := testingFamilyTransportSettings()
		// held: the mode shape is decided at construction, no dial is needed
		settings.StartDisabled = true
		if c.factory {
			settings.H3PacketConnFactory = func(context.Context) (net.PacketConn, error) {
				return net.ListenPacket("udp4", "127.0.0.1:0")
			}
		}
		transport := NewPlatformTransportWithTargetMode(
			ctx,
			strategy,
			NewRouteManager(ctx, "proxy-h3"),
			"https://localhost",
			testingFamilyAuth(),
			c.target,
			settings,
		)
		h3Off := c.proxied && !c.factory
		for _, mode := range h3Modes {
			if offered := transport.modePreference(mode) != modePreferenceNone; offered == h3Off && c.target == TransportModeAuto {
				t.Fatalf("%s: offers %s = %t", c.name, mode, offered)
			}
		}
		wantTarget := c.target
		if h3Off && isH3TransportMode(c.target) {
			wantTarget = TransportModeH1
		}
		if transport.targetMode != wantTarget {
			t.Fatalf("%s: target mode = %s, want %s", c.name, transport.targetMode, wantTarget)
		}
		if transport.modePreference(TransportModeH1) == modePreferenceNone && c.target == TransportModeAuto {
			t.Fatalf("%s: h1 is not offered", c.name)
		}
		// the caller's preferences are not edited
		if settings.ModePreferences[TransportModeH3] == 0 {
			t.Fatalf("%s: edited the caller's mode preferences", c.name)
		}
		transport.Close()
		strategy.Close()
	}
}
