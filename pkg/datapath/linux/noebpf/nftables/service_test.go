// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

func TestServicesFromFrontends(t *testing.T) {
	frontends := []*loadbalancer.Frontend{
		frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.TCP, "10.245.0.10", 80,
			backend(loadbalancer.TCP, "10.244.1.10", 8080)),
		frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.UDP, "fd00:10:96::a", 53,
			backend(loadbalancer.UDP, "fd00:10:244:1::10", 5353)),
		frontend(loadbalancer.SVCTypeNodePort, loadbalancer.TCP, "0.0.0.0", 30080,
			backend(loadbalancer.TCP, "10.244.1.12", 8080)),
		frontend(loadbalancer.SVCTypeNodePort, loadbalancer.UDP, "::", 30053,
			backend(loadbalancer.UDP, "fd00:10:244:1::12", 5353)),
		frontend(loadbalancer.SVCTypeLoadBalancer, loadbalancer.TCP, "10.245.0.11", 80,
			backend(loadbalancer.TCP, "10.244.1.11", 8080)),
		frontend(loadbalancer.SVCTypeLocalRedirect, loadbalancer.TCP, "169.254.169.254", 8080,
			backend(loadbalancer.TCP, "10.244.1.15", 8080)),
		frontend(loadbalancer.SVCTypeExternalIPs, loadbalancer.UDP, "10.245.0.12", 53,
			backend(loadbalancer.UDP, "10.244.1.12", 5353)),
		frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.SCTP, "10.245.0.13", 80,
			backend(loadbalancer.SCTP, "10.244.1.13", 8080)),
		frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.TCP, "10.245.0.14", 80,
			backendWithState(loadbalancer.TCP, "10.244.1.14", 8080, loadbalancer.BackendStateTerminating)),
	}

	svcs, err := ServicesFromFrontends(frontends)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 8 {
		t.Fatalf("expected eight supported DNAT entries, got %#v", svcs)
	}
	if !containsServiceDNAT(svcs, ServiceDNAT{FrontendAddr: netip.MustParseAddr("10.245.0.10"), FrontendPort: 80, Protocol: ProtocolTCP, BackendAddr: netip.MustParseAddr("10.244.1.10"), BackendPort: 8080}) {
		t.Fatalf("missing IPv4 service DNAT: %#v", svcs)
	}
	if !containsServiceDNAT(svcs, ServiceDNAT{FrontendAddr: netip.MustParseAddr("fd00:10:96::a"), FrontendPort: 53, Protocol: ProtocolUDP, BackendAddr: netip.MustParseAddr("fd00:10:244:1::10"), BackendPort: 5353}) {
		t.Fatalf("missing IPv6 service DNAT: %#v", svcs)
	}
	if !containsServiceDNAT(svcs, ServiceDNAT{FrontendAddr: netip.MustParseAddr("0.0.0.0"), FrontendPort: 30080, Protocol: ProtocolTCP, BackendAddr: netip.MustParseAddr("10.244.1.12"), BackendPort: 8080, NodePort: true}) {
		t.Fatalf("missing NodePort service DNAT: %#v", svcs)
	}
	if !containsServiceDNAT(svcs, ServiceDNAT{FrontendAddr: netip.MustParseAddr("::"), FrontendPort: 30053, Protocol: ProtocolUDP, BackendAddr: netip.MustParseAddr("fd00:10:244:1::12"), BackendPort: 5353, NodePort: true}) {
		t.Fatalf("missing IPv6 NodePort service DNAT: %#v", svcs)
	}
	if !containsServiceDNAT(svcs, ServiceDNAT{FrontendAddr: netip.MustParseAddr("10.245.0.11"), FrontendPort: 80, Protocol: ProtocolTCP, BackendAddr: netip.MustParseAddr("10.244.1.11"), BackendPort: 8080}) {
		t.Fatalf("missing LoadBalancer service DNAT: %#v", svcs)
	}
	if !containsServiceDNAT(svcs, ServiceDNAT{FrontendAddr: netip.MustParseAddr("10.245.0.12"), FrontendPort: 53, Protocol: ProtocolUDP, BackendAddr: netip.MustParseAddr("10.244.1.12"), BackendPort: 5353}) {
		t.Fatalf("missing ExternalIPs service DNAT: %#v", svcs)
	}
	if !containsServiceDNAT(svcs, ServiceDNAT{FrontendAddr: netip.MustParseAddr("169.254.169.254"), FrontendPort: 8080, Protocol: ProtocolTCP, BackendAddr: netip.MustParseAddr("10.244.1.15"), BackendPort: 8080}) {
		t.Fatalf("missing LocalRedirect service DNAT: %#v", svcs)
	}
	if !containsServiceDNAT(svcs, ServiceDNAT{FrontendAddr: netip.MustParseAddr("10.245.0.13"), FrontendPort: 80, Protocol: ProtocolSCTP, BackendAddr: netip.MustParseAddr("10.244.1.13"), BackendPort: 8080}) {
		t.Fatalf("missing SCTP service DNAT: %#v", svcs)
	}
}

func TestServicesFromFrontendsRenderSourceRanges(t *testing.T) {
	frontends := []*loadbalancer.Frontend{
		frontendWithService(loadbalancer.SVCTypeLoadBalancer, loadbalancer.TCP, "10.245.0.21", 80,
			serviceWithSourceRanges("default", "echo", "10.0.0.0/8", "fd00:10:10::/64"),
			backend(loadbalancer.TCP, "10.244.1.21", 8080)),
		frontendWithService(loadbalancer.SVCTypeLoadBalancer, loadbalancer.TCP, "fd00:10:96::21", 80,
			serviceWithSourceRanges("default", "echo", "10.0.0.0/8", "fd00:10:10::/64"),
			backend(loadbalancer.TCP, "fd00:10:244:1::21", 8080)),
	}

	svcs, err := ServicesFromFrontends(frontends)
	if err != nil {
		t.Fatal(err)
	}
	script, err := Render(DesiredState{Services: svcs})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "ip saddr 10.0.0.0/8 ip daddr 10.245.0.21 tcp dport 80 counter dnat to 10.244.1.21:8080") {
		t.Fatalf("missing IPv4 source-range DNAT rule:\n%s", script)
	}
	if !strings.Contains(script, "ip6 saddr fd00:10:10::/64 ip6 daddr fd00:10:96::21 tcp dport 80 counter dnat to [fd00:10:244:1::21]:8080") {
		t.Fatalf("missing IPv6 source-range DNAT rule:\n%s", script)
	}
}

func TestServicesFromFrontendsSessionAffinity(t *testing.T) {
	frontends := []*loadbalancer.Frontend{
		frontendWithService(loadbalancer.SVCTypeClusterIP, loadbalancer.TCP, "10.245.0.31", 80,
			sessionAffinityService("default", "echo"),
			backend(loadbalancer.TCP, "10.244.1.31", 8080),
			backend(loadbalancer.TCP, "10.244.1.32", 8080)),
	}

	svcs, err := ServicesFromFrontends(frontends)
	if err != nil {
		t.Fatal(err)
	}
	script, err := Render(DesiredState{Services: svcs})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "jhash ip saddr mod 2 == 0 counter dnat to") {
		t.Fatalf("missing session-affinity hashing in nft script:\n%s", script)
	}
	if strings.Contains(script, "numgen random") {
		t.Fatalf("session affinity should not use random selection:\n%s", script)
	}
}

func TestServicesFromFrontendsRespectsTrafficPolicyLocal(t *testing.T) {
	nodetypes.SetName("node-a")
	t.Cleanup(func() { nodetypes.SetName("localhost") })

	frontends := []*loadbalancer.Frontend{
		frontendWithService(loadbalancer.SVCTypeClusterIP, loadbalancer.TCP, "10.245.0.41", 80,
			&loadbalancer.Service{
				Name:             loadbalancer.NewServiceName("default", "echo"),
				Source:           source.Kubernetes,
				IntTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
			},
			backendOnNode("node-a", loadbalancer.TCP, "10.244.1.41", 8080),
			backendOnNode("node-b", loadbalancer.TCP, "10.244.1.42", 8080)),
		frontendWithService(loadbalancer.SVCTypeLoadBalancer, loadbalancer.TCP, "10.245.0.42", 80,
			&loadbalancer.Service{
				Name:             loadbalancer.NewServiceName("default", "echo"),
				Source:           source.Kubernetes,
				ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
			},
			backendOnNode("node-a", loadbalancer.TCP, "10.244.1.43", 8080),
			backendOnNode("node-b", loadbalancer.TCP, "10.244.1.44", 8080)),
	}

	svcs, err := ServicesFromFrontends(frontends)
	if err != nil {
		t.Fatal(err)
	}
	script, err := Render(DesiredState{Services: svcs})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "10.245.0.41 tcp dport 80 counter dnat to 10.244.1.41:8080") {
		t.Fatalf("missing local ClusterIP backend:\n%s", script)
	}
	if strings.Contains(script, "10.244.1.42:8080") {
		t.Fatalf("unexpected remote ClusterIP backend in local policy:\n%s", script)
	}
	if !strings.Contains(script, "10.245.0.42 tcp dport 80 counter dnat to 10.244.1.43:8080") {
		t.Fatalf("missing local LoadBalancer backend:\n%s", script)
	}
	if strings.Contains(script, "10.244.1.44:8080") {
		t.Fatalf("unexpected remote LoadBalancer backend in local policy:\n%s", script)
	}
}

func TestServicesFromFrontendsSkipsTerminatingBackends(t *testing.T) {
	frontends := []*loadbalancer.Frontend{
		frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.TCP, "10.245.0.14", 80,
			backendWithState(loadbalancer.TCP, "10.244.1.14", 8080, loadbalancer.BackendStateTerminating)),
	}

	svcs, err := ServicesFromFrontends(frontends)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 0 {
		t.Fatalf("expected terminating backend to be skipped, got %#v", svcs)
	}

	script, err := Render(DesiredState{Services: svcs})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "10.244.1.14") {
		t.Fatalf("terminating backend rendered in nft script:\n%s", script)
	}
}

func TestServicesFromFrontendsRejectsMixedFamilies(t *testing.T) {
	frontends := []*loadbalancer.Frontend{
		frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.TCP, "10.245.0.10", 80,
			backend(loadbalancer.TCP, "fd00:10:244:1::10", 8080)),
	}

	_, err := ServicesFromFrontends(frontends)
	if err == nil {
		t.Fatal("expected mixed frontend/backend IP families to be rejected")
	}
	if !strings.Contains(err.Error(), "different IP families") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func frontend(t loadbalancer.SVCType, proto loadbalancer.L4Type, ip string, port uint16, bes ...*loadbalancer.Backend) *loadbalancer.Frontend {
	return frontendWithService(t, proto, ip, port, &loadbalancer.Service{Name: loadbalancer.NewServiceName("default", "echo"), Source: source.Kubernetes}, bes...)
}

func frontendWithService(t loadbalancer.SVCType, proto loadbalancer.L4Type, ip string, port uint16, svc *loadbalancer.Service, bes ...*loadbalancer.Backend) *loadbalancer.Frontend {
	return &loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			Address:     loadbalancer.NewL3n4Addr(proto, cmtypes.AddrClusterFrom(netip.MustParseAddr(ip), 0), port, loadbalancer.ScopeExternal),
			Type:        t,
			ServiceName: loadbalancer.NewServiceName("default", "echo"),
		},
		Service: svc,
		Backends: loadbalancer.BackendsSeq2(func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {
			for _, be := range bes {
				if !yield(be, 1) {
					return
				}
			}
		}),
	}
}

func serviceWithSourceRanges(namespace, name string, prefixes ...string) *loadbalancer.Service {
	svc := &loadbalancer.Service{Name: loadbalancer.NewServiceName(namespace, name), Source: source.Kubernetes}
	for _, prefix := range prefixes {
		svc.SourceRanges = append(svc.SourceRanges, netip.MustParsePrefix(prefix))
	}
	return svc
}

func sessionAffinityService(namespace, name string) *loadbalancer.Service {
	return &loadbalancer.Service{
		Name:                   loadbalancer.NewServiceName(namespace, name),
		Source:                 source.Kubernetes,
		SessionAffinity:        true,
		SessionAffinityTimeout: 0,
	}
}

func containsServiceDNAT(in []ServiceDNAT, want ServiceDNAT) bool {
	for _, got := range in {
		if got.FrontendAddr == want.FrontendAddr &&
			got.FrontendPort == want.FrontendPort &&
			got.Protocol == want.Protocol &&
			got.BackendAddr == want.BackendAddr &&
			got.BackendPort == want.BackendPort &&
			got.NodePort == want.NodePort {
			return true
		}
	}
	return false
}

func backend(proto loadbalancer.L4Type, ip string, port uint16) *loadbalancer.Backend {
	return backendWithState(proto, ip, port, loadbalancer.BackendStateActive)
}

func backendWithState(proto loadbalancer.L4Type, ip string, port uint16, state loadbalancer.BackendState) *loadbalancer.Backend {
	return &loadbalancer.Backend{
		Address: loadbalancer.NewL3n4Addr(proto, cmtypes.AddrClusterFrom(netip.MustParseAddr(ip), 0), port, loadbalancer.ScopeExternal),
		State:   state,
		Source:  source.Kubernetes,
	}
}

func backendOnNode(node string, proto loadbalancer.L4Type, ip string, port uint16) *loadbalancer.Backend {
	be := backend(proto, ip, port)
	be.NodeName = node
	return be
}
