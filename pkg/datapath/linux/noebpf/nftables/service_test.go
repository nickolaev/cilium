// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

func TestServicesFromFrontends(t *testing.T) {
	frontends := []*loadbalancer.Frontend{
		frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.TCP, "10.245.0.10", 80,
			backend(loadbalancer.TCP, "10.244.1.10", 8080)),
		frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.UDP, "fd00:10:96::a", 53,
			backend(loadbalancer.UDP, "fd00:10:244:1::10", 5353)),
		frontend(loadbalancer.SVCTypeLoadBalancer, loadbalancer.TCP, "10.245.0.11", 80,
			backend(loadbalancer.TCP, "10.244.1.11", 8080)),
		frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.SCTP, "10.245.0.12", 80,
			backend(loadbalancer.SCTP, "10.244.1.12", 8080)),
	}

	svcs, err := ServicesFromFrontends(frontends)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 2 {
		t.Fatalf("expected two supported DNAT entries, got %#v", svcs)
	}
	if !slices.Contains(svcs, ServiceDNAT{FrontendAddr: netip.MustParseAddr("10.245.0.10"), FrontendPort: 80, Protocol: ProtocolTCP, BackendAddr: netip.MustParseAddr("10.244.1.10"), BackendPort: 8080}) {
		t.Fatalf("missing IPv4 service DNAT: %#v", svcs)
	}
	if !slices.Contains(svcs, ServiceDNAT{FrontendAddr: netip.MustParseAddr("fd00:10:96::a"), FrontendPort: 53, Protocol: ProtocolUDP, BackendAddr: netip.MustParseAddr("fd00:10:244:1::10"), BackendPort: 5353}) {
		t.Fatalf("missing IPv6 service DNAT: %#v", svcs)
	}
}

func frontend(t loadbalancer.SVCType, proto loadbalancer.L4Type, ip string, port uint16, bes ...*loadbalancer.Backend) *loadbalancer.Frontend {
	return &loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			Address:     loadbalancer.NewL3n4Addr(proto, cmtypes.AddrClusterFrom(netip.MustParseAddr(ip), 0), port, loadbalancer.ScopeExternal),
			Type:        t,
			ServiceName: loadbalancer.NewServiceName("default", "echo"),
		},
		Service: &loadbalancer.Service{Name: loadbalancer.NewServiceName("default", "echo"), Source: source.Kubernetes},
		Backends: loadbalancer.BackendsSeq2(func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {
			for _, be := range bes {
				if !yield(be, 1) {
					return
				}
			}
		}),
	}
}

func backend(proto loadbalancer.L4Type, ip string, port uint16) *loadbalancer.Backend {
	return &loadbalancer.Backend{
		Address: loadbalancer.NewL3n4Addr(proto, cmtypes.AddrClusterFrom(netip.MustParseAddr(ip), 0), port, loadbalancer.ScopeExternal),
		State:   loadbalancer.BackendStateActive,
		Source:  source.Kubernetes,
	}
}
