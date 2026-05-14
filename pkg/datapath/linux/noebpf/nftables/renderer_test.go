// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRenderDualStackServiceAndPolicySpike(t *testing.T) {
	script, err := Render(DesiredState{
		Services: []ServiceDNAT{
			{
				FrontendAddr: netip.MustParseAddr("10.245.0.10"),
				FrontendPort: 53,
				Protocol:     ProtocolUDP,
				BackendAddr:  netip.MustParseAddr("10.244.1.20"),
				BackendPort:  53,
			},
			{
				FrontendAddr: netip.MustParseAddr("fd00:10:96::a"),
				FrontendPort: 53,
				Protocol:     ProtocolUDP,
				BackendAddr:  netip.MustParseAddr("fd00:10:244::20"),
				BackendPort:  53,
			},
		},
		Policies: []EndpointPolicy{
			{
				EndpointIP:  netip.MustParseAddr("10.244.1.20"),
				IngressDeny: true,
				IngressAllow: []PolicyAllow{{
					Source:      netip.MustParsePrefix("10.244.0.0/16"),
					Destination: netip.MustParseAddr("10.244.1.20"),
					Port:        80,
					Protocol:    ProtocolTCP,
				}},
			},
			{
				EndpointIP:  netip.MustParseAddr("fd00:10:244::20"),
				IngressDeny: true,
				IngressAllow: []PolicyAllow{{
					Source:      netip.MustParsePrefix("fd00:10:244::/48"),
					Destination: netip.MustParseAddr("fd00:10:244::20"),
					Port:        80,
					Protocol:    ProtocolTCP,
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"table inet cilium_noebpf",
		"type nat hook prerouting priority dstnat; policy accept;",
		"type nat hook output priority -100; policy accept;",
		"ip daddr 10.245.0.10 udp dport 53 dnat to 10.244.1.20:53",
		"ip6 daddr fd00:10:96::a udp dport 53 dnat to [fd00:10:244::20]:53",
		"ct state established,related accept",
		"ip saddr 10.244.0.0/16 ip daddr 10.244.1.20 tcp dport 80 accept",
		"ip daddr 10.244.1.20 drop",
		"ip6 saddr fd00:10:244::/48 ip6 daddr fd00:10:244::20 tcp dport 80 accept",
		"ip6 daddr fd00:10:244::20 drop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("rendered script missing %q:\n%s", want, script)
		}
	}
}

func TestRenderRejectsNat46(t *testing.T) {
	_, err := Render(DesiredState{Services: []ServiceDNAT{{
		FrontendAddr: netip.MustParseAddr("10.245.0.10"),
		FrontendPort: 80,
		Protocol:     ProtocolTCP,
		BackendAddr:  netip.MustParseAddr("fd00:10:244::20"),
		BackendPort:  80,
	}}})
	if err == nil || !strings.Contains(err.Error(), "NAT46") {
		t.Fatalf("expected NAT46/NAT64 rejection, got %v", err)
	}
}
