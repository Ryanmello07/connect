package connect

import "testing"

func TestControlDialNetworkForce(t *testing.T) {
	tests := []struct {
		name    string
		policy  IpFamilyPolicy
		network string
		want    string
		wantErr bool
	}{
		{"auto leaves tcp alone", IpFamilyAuto, "tcp", "tcp", false},
		{"auto leaves udp alone", IpFamilyAuto, "udp", "udp", false},
		{"force4 narrows tcp", IpFamilyForce4, "tcp", "tcp4", false},
		{"force6 narrows tcp", IpFamilyForce6, "tcp", "tcp6", false},
		{"force4 narrows udp", IpFamilyForce4, "udp", "udp4", false},
		{"force6 narrows udp", IpFamilyForce6, "udp", "udp6", false},
		{"force4 passes matching explicit", IpFamilyForce4, "tcp4", "tcp4", false},
		{"force4 rejects conflicting explicit", IpFamilyForce4, "tcp6", "", true},
		{"force6 rejects conflicting explicit", IpFamilyForce6, "udp4", "", true},
		{"auto passes explicit through", IpFamilyAuto, "tcp6", "tcp6", false},
		{"unknown network is untouched", IpFamilyForce4, "unix", "unix", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetControlIpFamilyPolicy(test.policy)
			defer SetControlIpFamilyPolicy(IpFamilyAuto)
			got, err := controlDialNetwork(test.network)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %s under %d", test.network, test.policy)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestSetControlIpFamilyPolicyClampsUnknown(t *testing.T) {
	defer SetControlIpFamilyPolicy(IpFamilyAuto)
	SetControlIpFamilyPolicy(IpFamilyPolicy(99))
	if got := ControlIpFamilyPolicy(); got != IpFamilyAuto {
		t.Fatalf("got %d, want IpFamilyAuto", got)
	}
	SetControlIpFamilyPolicy(IpFamilyPolicy(-3))
	if got := ControlIpFamilyPolicy(); got != IpFamilyAuto {
		t.Fatalf("got %d, want IpFamilyAuto", got)
	}
}
