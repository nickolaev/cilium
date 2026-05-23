// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"net/netip"
	"sort"
	"strings"

	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	cidrGroupLabelSource = "cidrgroup"
)

// PolicyProtocol is the L4 protocol supported by the no-eBPF KNP renderer.
type PolicyProtocol = Protocol

// LabelSelector is the minimal selector representation used by the no-eBPF
// policy compiler. It supports standard matchLabels and matchExpressions
// semantics.
type LabelSelector struct {
	MatchLabels      map[string]string
	MatchExpressions []metav1.LabelSelectorRequirement
}

// Pod describes the small amount of pod state needed by the no-eBPF policy
// renderer. A future controller will build this from Kubernetes Pods,
// Namespaces, and local Cilium endpoints.
type Pod struct {
	Name            string
	Namespace       string
	IPs             []netip.Addr
	Labels          map[string]string
	NamespaceLabels map[string]string
	NamedPorts      map[string][]Port
	Local           bool
}

// Peer selects allowed peer IPs for a rule. Empty selectors match all peers.
type Peer struct {
	PodSelector       *LabelSelector
	NamespaceSelector *LabelSelector
	IPBlock           *netip.Prefix
	Except            []netip.Prefix
}

func (p Peer) String() string {
	switch {
	case p.IPBlock != nil:
		excepts := make([]string, 0, len(p.Except))
		for _, ex := range p.Except {
			excepts = append(excepts, ex.String())
		}
		sort.Strings(excepts)
		if len(excepts) == 0 {
			return p.IPBlock.String()
		}
		return p.IPBlock.String() + "-" + strings.Join(excepts, ",")
	case p.PodSelector != nil || p.NamespaceSelector != nil:
		return selectorString(p.PodSelector) + "|" + selectorString(p.NamespaceSelector)
	default:
		return "*"
	}
}

// Port selects an allowed L4 port. Protocol defaults to TCP when empty.
type Port struct {
	Protocol PolicyProtocol
	Port     uint16
	EndPort  uint16
}

// PolicyRule is a minimal K8s NetworkPolicy-like allow rule.
type PolicyRule struct {
	Peers         []Peer
	Ports         []Port
	MatchAllPorts bool
}

// PolicyDeny is the rendered deny tuple used by explicit deny rules.
type PolicyDeny struct {
	Source      netip.Prefix
	Destination netip.Prefix
	Port        uint16
	EndPort     uint16
	Protocol    Protocol
}

// EndpointPolicySpec is the per-local-endpoint policy shape consumed by the
// nftables renderer.
type EndpointPolicySpec struct {
	Pod              Pod
	IngressDeny      bool
	EgressDeny       bool
	IngressRules     []PolicyRule
	EgressRules      []PolicyRule
	IngressDenyRules []PolicyRule
	EgressDenyRules  []PolicyRule
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
		for _, rule := range spec.IngressDenyRules {
			pol.IngressDenyRules = append(pol.IngressDenyRules, compileIngressDenies(ip, rule, pods)...)
		}
		for _, rule := range spec.EgressDenyRules {
			pol.EgressDenyRules = append(pol.EgressDenyRules, compileEgressDenies(ip, rule, pods)...)
		}
		out = append(out, pol)
	}
	return out
}

func compileIngressAllows(endpointIP netip.Addr, rule PolicyRule, pods []Pod) []PolicyAllow {
	var out []PolicyAllow
	endpointPrefix := netip.PrefixFrom(endpointIP, endpointIP.BitLen())
	ports := policyPorts(rule)
	if len(ports) == 0 {
		return nil
	}
	for _, peerPrefix := range policyPeerPrefixes(endpointIP, rule, pods) {
		for _, port := range ports {
			out = append(out, PolicyAllow{
				Source:      peerPrefix,
				Destination: endpointPrefix,
				Port:        port.Port,
				EndPort:     port.EndPort,
				Protocol:    port.Protocol,
			})
		}
	}
	return out
}

func compileEgressAllows(endpointIP netip.Addr, rule PolicyRule, pods []Pod) []PolicyAllow {
	var out []PolicyAllow
	endpointPrefix := netip.PrefixFrom(endpointIP, endpointIP.BitLen())
	ports := policyPorts(rule)
	if len(ports) == 0 {
		return nil
	}
	for _, peerPrefix := range policyPeerPrefixes(endpointIP, rule, pods) {
		for _, port := range ports {
			out = append(out, PolicyAllow{
				Source:      endpointPrefix,
				Destination: peerPrefix,
				Port:        port.Port,
				EndPort:     port.EndPort,
				Protocol:    port.Protocol,
			})
		}
	}
	return out
}

func compileIngressDenies(endpointIP netip.Addr, rule PolicyRule, pods []Pod) []PolicyDeny {
	var out []PolicyDeny
	endpointPrefix := netip.PrefixFrom(endpointIP, endpointIP.BitLen())
	ports := policyPorts(rule)
	if len(ports) == 0 {
		return nil
	}
	for _, peerPrefix := range policyPeerPrefixes(endpointIP, rule, pods) {
		for _, port := range ports {
			out = append(out, PolicyDeny{
				Source:      peerPrefix,
				Destination: endpointPrefix,
				Port:        port.Port,
				EndPort:     port.EndPort,
				Protocol:    port.Protocol,
			})
		}
	}
	return out
}

func compileEgressDenies(endpointIP netip.Addr, rule PolicyRule, pods []Pod) []PolicyDeny {
	var out []PolicyDeny
	endpointPrefix := netip.PrefixFrom(endpointIP, endpointIP.BitLen())
	ports := policyPorts(rule)
	if len(ports) == 0 {
		return nil
	}
	for _, peerPrefix := range policyPeerPrefixes(endpointIP, rule, pods) {
		for _, port := range ports {
			out = append(out, PolicyDeny{
				Source:      endpointPrefix,
				Destination: peerPrefix,
				Port:        port.Port,
				EndPort:     port.EndPort,
				Protocol:    port.Protocol,
			})
		}
	}
	return out
}

func policyPorts(rule PolicyRule) []Port {
	if rule.MatchAllPorts {
		return []Port{{Protocol: ProtocolTCP}}
	}
	if len(rule.Ports) == 0 {
		return nil
	}
	ports := append([]Port(nil), rule.Ports...)
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
		combined := combinedPodLabels(pod)
		if !selectorMatches(combined, peer.PodSelector) {
			continue
		}
		if !selectorMatches(combined, peer.NamespaceSelector) {
			continue
		}
		for _, ip := range pod.IPs {
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	return out
}

func selectorMatches(labels map[string]string, selector *LabelSelector) bool {
	if selector == nil {
		return true
	}
	for k, v := range selector.MatchLabels {
		if labelValue(labels, k) != v {
			return false
		}
	}
	for _, expr := range selector.MatchExpressions {
		value, ok := labelValueOK(labels, expr.Key)
		switch expr.Operator {
		case metav1.LabelSelectorOpIn:
			if !ok || !containsString(expr.Values, value) {
				return false
			}
		case metav1.LabelSelectorOpNotIn:
			if ok && containsString(expr.Values, value) {
				return false
			}
		case metav1.LabelSelectorOpExists:
			if !ok {
				return false
			}
		case metav1.LabelSelectorOpDoesNotExist:
			if ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func labelValue(labels map[string]string, key string) string {
	value, _ := labelValueOK(labels, key)
	return value
}

func labelValueOK(labels map[string]string, key string) (string, bool) {
	if labels == nil {
		return "", false
	}
	if value, ok := labels[key]; ok {
		return value, true
	}
	if stripped, ok := stripLabelSourcePrefix(key); ok {
		value, ok := labels[stripped]
		return value, ok
	}
	return "", false
}

func stripLabelSourcePrefix(key string) (string, bool) {
	source, remainder, ok := strings.Cut(key, ":")
	if !ok {
		return "", false
	}
	switch source {
	case "k8s", "any", "reserved", cidrGroupLabelSource:
		return remainder, true
	default:
		return "", false
	}
}

func combinedPodLabels(pod Pod) map[string]string {
	combined := make(map[string]string, len(pod.Labels)+len(pod.NamespaceLabels))
	for k, v := range pod.Labels {
		combined[k] = v
	}
	for k, v := range pod.NamespaceLabels {
		combined[k] = v
	}
	return combined
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func selectorString(selector *LabelSelector) string {
	if selector == nil {
		return ""
	}
	keys := make([]string, 0, len(selector.MatchLabels)+len(selector.MatchExpressions))
	for k, v := range selector.MatchLabels {
		keys = append(keys, k+"="+v)
	}
	for _, expr := range selector.MatchExpressions {
		keys = append(keys, expr.Key+":"+string(expr.Operator))
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
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
