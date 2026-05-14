// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"net/netip"
	"sort"
)

// PolicyProtocol is the L4 protocol supported by the M1 no-eBPF KNP renderer.
type PolicyProtocol = Protocol

// Pod describes the small amount of pod state needed by the no-eBPF policy
// renderer. A future controller will build this from Kubernetes Pods,
// Namespaces, and local Cilium endpoints.
type Pod struct {
	Name            string
	Namespace       string
	IPs             []netip.Addr
	Labels          map[string]string
	NamespaceLabels map[string]string
	Local           bool
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
			pol.IngressAllow = append(pol.IngressAllow, compileIngressAllows(ip, rule, pods)...)
		}
		for _, rule := range spec.EgressRules {
			pol.EgressAllow = append(pol.EgressAllow, compileEgressAllows(ip, rule, pods)...)
		}
		out = append(out, pol)
	}
	return out
}

func compileIngressAllows(endpointIP netip.Addr, rule PolicyRule, pods []Pod) []PolicyAllow {
	var out []PolicyAllow
	endpointPrefix := netip.PrefixFrom(endpointIP, endpointIP.BitLen())
	for _, peerPrefix := range policyPeerPrefixes(endpointIP, rule, pods) {
		for _, port := range policyPorts(rule) {
			out = append(out, PolicyAllow{
				Source:      peerPrefix,
				Destination: endpointPrefix,
				Port:        port.Port,
				Protocol:    port.Protocol,
			})
		}
	}
	return out
}

func compileEgressAllows(endpointIP netip.Addr, rule PolicyRule, pods []Pod) []PolicyAllow {
	var out []PolicyAllow
	endpointPrefix := netip.PrefixFrom(endpointIP, endpointIP.BitLen())
	for _, peerPrefix := range policyPeerPrefixes(endpointIP, rule, pods) {
		for _, port := range policyPorts(rule) {
			out = append(out, PolicyAllow{
				Source:      endpointPrefix,
				Destination: peerPrefix,
				Port:        port.Port,
				Protocol:    port.Protocol,
			})
		}
	}
	return out
}

func policyPorts(rule PolicyRule) []Port {
	ports := rule.Ports
	if len(ports) == 0 {
		ports = []Port{{Protocol: ProtocolTCP, Port: 0}}
	}
	for i := range ports {
		if ports[i].Protocol == "" {
			ports[i].Protocol = ProtocolTCP
		}
	}
	return ports
}

func policyPeerPrefixes(endpointIP netip.Addr, rule PolicyRule, pods []Pod) []netip.Prefix {
	peers := rule.Peers
	if len(peers) == 0 {
		peers = []Peer{{IPBlock: ptr(netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0))}}
		if endpointIP.Is6() {
			peers = []Peer{{IPBlock: ptr(netip.PrefixFrom(netip.IPv6Unspecified(), 0))}}
		}
	}

	var out []netip.Prefix
	for _, peer := range peers {
		prefixes := peerPrefixes(peer, pods)
		for _, prefix := range prefixes {
			if prefix.Addr().Is6() != endpointIP.Is6() {
				continue
			}
			out = append(out, prefix)
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
		if len(peer.NamespaceSelector) > 0 && !labelsMatch(pod.NamespaceLabels, peer.NamespaceSelector) {
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
	out := []netip.Prefix{block.Masked()}
	for _, ex := range except {
		next := out[:0]
		for _, prefix := range out {
			next = append(next, subtractPrefix(prefix, ex.Masked())...)
		}
		out = append([]netip.Prefix(nil), next...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() == out[j].Addr() {
			return out[i].Bits() < out[j].Bits()
		}
		return out[i].Addr().Less(out[j].Addr())
	})
	return out
}

func subtractPrefix(block, except netip.Prefix) []netip.Prefix {
	if block.Addr().Is4() != except.Addr().Is4() || !prefixContainsPrefix(block, except) {
		return []netip.Prefix{block}
	}
	if except.Bits() <= block.Bits() {
		return nil
	}
	var out []netip.Prefix
	cur := []netip.Prefix{block}
	for bits := block.Bits() + 1; bits <= except.Bits(); bits++ {
		var next []netip.Prefix
		for _, prefix := range cur {
			left, right := splitPrefix(prefix)
			if prefixContainsPrefix(left, except) {
				out = append(out, right)
				next = append(next, left)
			} else if prefixContainsPrefix(right, except) {
				out = append(out, left)
				next = append(next, right)
			} else {
				out = append(out, left, right)
			}
		}
		cur = next
	}
	return out
}

func prefixContainsPrefix(outer, inner netip.Prefix) bool {
	return outer.Contains(inner.Addr()) && outer.Bits() <= inner.Bits()
}

func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := prefix.Bits() + 1
	left := netip.PrefixFrom(prefix.Addr(), bits).Masked()
	rightAddr := setPrefixBit(prefix.Addr(), bits-1)
	right := netip.PrefixFrom(rightAddr, bits).Masked()
	return left, right
}

func setPrefixBit(addr netip.Addr, bit int) netip.Addr {
	bytes := addr.As16()
	if addr.Is4() {
		i := 12 + bit/8
		bytes[i] |= 1 << (7 - uint(bit%8))
		return netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]})
	}
	i := bit / 8
	bytes[i] |= 1 << (7 - uint(bit%8))
	return netip.AddrFrom16(bytes)
}

func ptr[T any](v T) *T { return &v }
