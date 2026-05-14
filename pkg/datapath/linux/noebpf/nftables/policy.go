// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import "net/netip"

// PolicyProtocol is the L4 protocol supported by the M1 no-eBPF KNP renderer.
type PolicyProtocol = Protocol

// Pod describes the small amount of pod state needed by the no-eBPF policy
// renderer. A future controller will build this from Kubernetes Pods,
// Namespaces, and local Cilium endpoints.
type Pod struct {
	Name      string
	Namespace string
	IPs       []netip.Addr
	Labels    map[string]string
	Local     bool
}

// Peer selects allowed peer IPs for a rule. Empty selectors match all peers.
type Peer struct {
	PodSelector       map[string]string
	NamespaceSelector map[string]string
	IPBlock           *netip.Prefix
	Except            []netip.Prefix
}

// Port selects an allowed L4 port. Protocol defaults to TCP when empty.
type Port struct {
	Protocol PolicyProtocol
	Port     uint16
}

// PolicyRule is a minimal K8s NetworkPolicy-like allow rule.
type PolicyRule struct {
	Peers []Peer
	Ports []Port
}

// EndpointPolicySpec is the per-local-endpoint policy shape consumed by the
// nftables renderer.
type EndpointPolicySpec struct {
	Pod          Pod
	IngressDeny  bool
	EgressDeny   bool
	IngressRules []PolicyRule
	EgressRules  []PolicyRule
}

// CompileEndpointPolicy converts a minimal KNP-like endpoint policy into the
// renderer's allow/drop tuples for every IP family assigned to the local pod.
func CompileEndpointPolicy(spec EndpointPolicySpec, pods []Pod) []EndpointPolicy {
	var out []EndpointPolicy
	for _, ip := range spec.Pod.IPs {
		if !ip.IsValid() {
			continue
		}
		pol := EndpointPolicy{EndpointIP: ip, IngressDeny: spec.IngressDeny, EgressDeny: spec.EgressDeny}
		for _, rule := range spec.IngressRules {
			pol.IngressAllow = append(pol.IngressAllow, compileAllows(ip, rule, pods)...)
		}
		for _, rule := range spec.EgressRules {
			pol.EgressAllow = append(pol.EgressAllow, compileAllows(ip, rule, pods)...)
		}
		out = append(out, pol)
	}
	return out
}

func compileAllows(dst netip.Addr, rule PolicyRule, pods []Pod) []PolicyAllow {
	ports := rule.Ports
	if len(ports) == 0 {
		ports = []Port{{Protocol: ProtocolTCP, Port: 0}}
	}
	peers := rule.Peers
	if len(peers) == 0 {
		peers = []Peer{{IPBlock: ptr(netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0))}}
		if dst.Is6() {
			peers = []Peer{{IPBlock: ptr(netip.PrefixFrom(netip.IPv6Unspecified(), 0))}}
		}
	}

	var out []PolicyAllow
	for _, peer := range peers {
		prefixes := peerPrefixes(peer, pods)
		for _, prefix := range prefixes {
			if prefix.Addr().Is6() != dst.Is6() {
				continue
			}
			for _, port := range ports {
				proto := port.Protocol
				if proto == "" {
					proto = ProtocolTCP
				}
				out = append(out, PolicyAllow{Source: prefix, Destination: dst, Port: port.Port, Protocol: proto})
			}
		}
	}
	return out
}

func peerPrefixes(peer Peer, pods []Pod) []netip.Prefix {
	if peer.IPBlock != nil {
		return subtractExcept(*peer.IPBlock, peer.Except)
	}
	var out []netip.Prefix
	for _, pod := range pods {
		if !labelsMatch(pod.Labels, peer.PodSelector) {
			continue
		}
		// Namespace labels are represented with the reserved key
		// "io.kubernetes.pod.namespace" for this Phase 3 renderer core. The
		// future controller can pre-expand namespace selectors into pod lists.
		if len(peer.NamespaceSelector) > 0 && !labelsMatch(pod.Labels, peer.NamespaceSelector) {
			continue
		}
		for _, ip := range pod.IPs {
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	return out
}

func labelsMatch(labels, selector map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func subtractExcept(block netip.Prefix, except []netip.Prefix) []netip.Prefix {
	// Phase 3 core records except prefixes by omitting exact matches. A follow-up
	// controller can lower partial except ranges into multiple nftables intervals.
	for _, ex := range except {
		if ex == block {
			return nil
		}
	}
	return []netip.Prefix{block}
}

func ptr[T any](v T) *T { return &v }
