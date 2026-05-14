// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// ServicesFromFrontends converts Cilium load-balancer frontends into the narrow
// no-eBPF M1 Service DNAT representation. Unsupported Service semantics are
// skipped deliberately; Helm/status/docs must advertise the same support matrix.
func ServicesFromFrontends(frontends []*loadbalancer.Frontend) ([]ServiceDNAT, error) {
	var out []ServiceDNAT
	for _, fe := range frontends {
		if fe == nil || fe.Service == nil {
			continue
		}
		if !isM1ServiceType(fe.Type) {
			continue
		}
		proto, ok := protocolFromLB(fe.Address.Protocol())
		if !ok {
			continue
		}
		for be := range fe.Backends {
			if be == nil || be.State != loadbalancer.BackendStateActive {
				continue
			}
			if be.Address.Addr().Is6() != fe.Address.Addr().Is6() {
				return nil, fmt.Errorf("frontend %s and backend %s use different IP families", fe.Address, be.Address)
			}
			out = append(out, ServiceDNAT{
				FrontendAddr: fe.Address.Addr(),
				FrontendPort: fe.Address.Port(),
				Protocol:     proto,
				BackendAddr:  be.Address.Addr(),
				BackendPort:  backendPort(fe, be.Address),
				NodePort:     fe.Type == loadbalancer.SVCTypeNodePort,
			})
		}
	}
	return out, nil
}

func isM1ServiceType(t loadbalancer.SVCType) bool {
	switch t {
	case loadbalancer.SVCTypeClusterIP, loadbalancer.SVCTypeNodePort:
		return true
	default:
		return false
	}
}

func protocolFromLB(proto loadbalancer.L4Type) (Protocol, bool) {
	switch proto {
	case loadbalancer.TCP:
		return ProtocolTCP, true
	case loadbalancer.UDP:
		return ProtocolUDP, true
	default:
		return "", false
	}
}

func backendPort(fe *loadbalancer.Frontend, be loadbalancer.L3n4Addr) uint16 {
	if be.Port() != 0 {
		return be.Port()
	}
	return fe.Address.Port()
}

// Frontend returns the frontend address as a netip.AddrPort for tests and
// future controller bookkeeping.
func (s ServiceDNAT) Frontend() netip.AddrPort {
	return netip.AddrPortFrom(s.FrontendAddr, s.FrontendPort)
}
