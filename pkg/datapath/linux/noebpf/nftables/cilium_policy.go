// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/option"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
)

var noebpfPolicyLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// PoliciesFromCiliumNetworkPolicies compiles the supported no-eBPF subset of
// namespaced CiliumNetworkPolicy objects into nftables endpoint policy.
func PoliciesFromCiliumNetworkPolicies(localPods []k8sTables.LocalPod, allPods []*corev1.Pod, namespaces []k8sTables.Namespace, cnps []*ciliumv2.CiliumNetworkPolicy) ([]EndpointPolicy, error) {
	parsed := make([]parsedCiliumPolicy, 0, len(cnps))
	for _, cnp := range cnps {
		if cnp == nil {
			continue
		}
		rules, err := cnp.Parse(noebpfPolicyLogger, option.Config.ClusterName)
		if err != nil {
			return nil, fmt.Errorf("ciliumnetworkpolicy %s/%s: %w", cnp.Namespace, cnp.Name, err)
		}
		parsed = append(parsed, parsedCiliumPolicy{namespace: cnp.Namespace, name: cnp.Name, rules: rules})
	}
	return policiesFromParsedCiliumRules(localPods, allPods, namespaces, parsed)
}

// PoliciesFromCiliumClusterwideNetworkPolicies compiles the supported no-eBPF
// subset of clusterwide CiliumClusterwideNetworkPolicy objects into endpoint policy.
func PoliciesFromCiliumClusterwideNetworkPolicies(localPods []k8sTables.LocalPod, allPods []*corev1.Pod, namespaces []k8sTables.Namespace, ccnps []*ciliumv2.CiliumClusterwideNetworkPolicy) ([]EndpointPolicy, error) {
	parsed := make([]parsedCiliumPolicy, 0, len(ccnps))
	for _, ccnp := range ccnps {
		if ccnp == nil {
			continue
		}
		rules, err := ccnp.Parse(noebpfPolicyLogger, option.Config.ClusterName)
		if err != nil {
			return nil, fmt.Errorf("ciliumclusterwidenetworkpolicy %s: %w", ccnp.Name, err)
		}
		parsed = append(parsed, parsedCiliumPolicy{namespace: "", name: ccnp.Name, rules: rules})
	}
	return policiesFromParsedCiliumRules(localPods, allPods, namespaces, parsed)
}

type parsedCiliumPolicy struct {
	namespace string
	name      string
	rules     policyapi.Rules
}

func policiesFromParsedCiliumRules(localPods []k8sTables.LocalPod, allPods []*corev1.Pod, namespaces []k8sTables.Namespace, policies []parsedCiliumPolicy) ([]EndpointPolicy, error) {
	pods := podsFromK8sPods(localPods, allPods, namespaces)
	byPod := map[string]*EndpointPolicySpec{}

	for _, policy := range policies {
		for _, rule := range policy.rules {
			if err := addCiliumRule(rule, pods, byPod, policy.namespace, policy.name); err != nil {
				return nil, fmt.Errorf("cilium policy %s/%s: %w", policy.namespace, policy.name, err)
			}
		}
	}

	var out []EndpointPolicy
	for _, spec := range byPod {
		out = append(out, CompileEndpointPolicy(*spec, pods)...)
	}
	return out, nil
}

func addCiliumRule(rule *policyapi.Rule, pods []Pod, byPod map[string]*EndpointPolicySpec, policyNamespace, policyName string) error {
	if rule == nil {
		return nil
	}
	if rule.NodeSelector.LabelSelector != nil {
		return fmt.Errorf("node selector is not supported in no-eBPF mode")
	}
	if rule.EndpointSelector.LabelSelector == nil {
		return fmt.Errorf("rule must have an endpoint selector")
	}
	endpointSelector := selectorFromAPI(rule.EndpointSelector)
	defaultDenyIngress := rule.EnableDefaultDeny.Ingress != nil && *rule.EnableDefaultDeny.Ingress
	defaultDenyEgress := rule.EnableDefaultDeny.Egress != nil && *rule.EnableDefaultDeny.Egress
	// If the policy hasn't been sanitized, keep the legacy default-deny posture.
	if rule.EnableDefaultDeny.Ingress == nil {
		defaultDenyIngress = len(rule.Ingress) > 0 || len(rule.IngressDeny) > 0
	}
	if rule.EnableDefaultDeny.Egress == nil {
		defaultDenyEgress = len(rule.Egress) > 0 || len(rule.EgressDeny) > 0
	}

	for i := range pods {
		pod := pods[i]
		if !pod.Local {
			continue
		}
		if !selectorMatches(combinedPodLabels(pod), endpointSelector) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		spec := byPod[key]
		if spec == nil {
			spec = &EndpointPolicySpec{Pod: pod}
			byPod[key] = spec
		}
		spec.IngressDeny = spec.IngressDeny || defaultDenyIngress
		spec.EgressDeny = spec.EgressDeny || defaultDenyEgress

		for _, ingress := range rule.Ingress {
			allow, err := ciliumIngressRule(pod, ingress)
			if err != nil {
				return fmt.Errorf("%s/%s ingress: %w", policyNamespace, policyName, err)
			}
			spec.IngressRules = append(spec.IngressRules, allow)
		}
		for _, ingressDeny := range rule.IngressDeny {
			deny, err := ciliumIngressDenyRule(pod, ingressDeny)
			if err != nil {
				return fmt.Errorf("%s/%s ingressDeny: %w", policyNamespace, policyName, err)
			}
			spec.IngressDenyRules = append(spec.IngressDenyRules, deny)
		}
		for _, egress := range rule.Egress {
			allow, err := ciliumEgressRule(pod, egress)
			if err != nil {
				return fmt.Errorf("%s/%s egress: %w", policyNamespace, policyName, err)
			}
			spec.EgressRules = append(spec.EgressRules, allow)
		}
		for _, egressDeny := range rule.EgressDeny {
			deny, err := ciliumEgressDenyRule(pod, egressDeny)
			if err != nil {
				return fmt.Errorf("%s/%s egressDeny: %w", policyNamespace, policyName, err)
			}
			spec.EgressDenyRules = append(spec.EgressDenyRules, deny)
		}
	}

	return nil
}

func ciliumIngressRule(endpoint Pod, rule policyapi.IngressRule) (PolicyRule, error) {
	if rule.Authentication != nil {
		return PolicyRule{}, fmt.Errorf("authentication is not supported in no-eBPF mode")
	}
	peers, err := ciliumIngressPeers(rule.IngressCommonRule)
	if err != nil {
		return PolicyRule{}, err
	}
	ports, matchAll, err := ciliumAllowPorts(endpoint, rule.ToPorts)
	if err != nil {
		return PolicyRule{}, err
	}
	return PolicyRule{Peers: peers, Ports: ports, MatchAllPorts: matchAll}, nil
}

func ciliumEgressRule(endpoint Pod, rule policyapi.EgressRule) (PolicyRule, error) {
	if len(rule.ToFQDNs) > 0 {
		return PolicyRule{}, fmt.Errorf("toFQDNs are not supported in no-eBPF mode")
	}
	if rule.Authentication != nil {
		return PolicyRule{}, fmt.Errorf("authentication is not supported in no-eBPF mode")
	}
	peers, err := ciliumEgressPeers(rule.EgressCommonRule)
	if err != nil {
		return PolicyRule{}, err
	}
	ports, matchAll, err := ciliumAllowPorts(endpoint, rule.ToPorts)
	if err != nil {
		return PolicyRule{}, err
	}
	return PolicyRule{Peers: peers, Ports: ports, MatchAllPorts: matchAll}, nil
}

func ciliumIngressDenyRule(endpoint Pod, rule policyapi.IngressDenyRule) (PolicyRule, error) {
	peers, err := ciliumIngressPeers(rule.IngressCommonRule)
	if err != nil {
		return PolicyRule{}, err
	}
	ports, matchAll, err := ciliumDenyPorts(endpoint, rule.ToPorts)
	if err != nil {
		return PolicyRule{}, err
	}
	return PolicyRule{Peers: peers, Ports: ports, MatchAllPorts: matchAll}, nil
}

func ciliumEgressDenyRule(endpoint Pod, rule policyapi.EgressDenyRule) (PolicyRule, error) {
	peers, err := ciliumEgressPeers(rule.EgressCommonRule)
	if err != nil {
		return PolicyRule{}, err
	}
	ports, matchAll, err := ciliumDenyPorts(endpoint, rule.ToPorts)
	if err != nil {
		return PolicyRule{}, err
	}
	return PolicyRule{Peers: peers, Ports: ports, MatchAllPorts: matchAll}, nil
}

func ciliumIngressPeers(rule policyapi.IngressCommonRule) ([]Peer, error) {
	if len(rule.FromEntities) > 0 {
		return nil, fmt.Errorf("fromEntities are not supported in no-eBPF mode")
	}
	if len(rule.FromGroups) > 0 {
		return nil, fmt.Errorf("fromGroups are not supported in no-eBPF mode")
	}
	if len(rule.FromRequires) > 0 {
		return nil, fmt.Errorf("fromRequires are not supported in no-eBPF mode")
	}
	if len(rule.FromNodes) > 0 {
		return nil, fmt.Errorf("fromNodes are not supported in no-eBPF mode")
	}
	return ciliumPeers(rule.FromEndpoints, rule.FromCIDR, rule.FromCIDRSet)
}

func ciliumEgressPeers(rule policyapi.EgressCommonRule) ([]Peer, error) {
	if len(rule.ToEntities) > 0 {
		return nil, fmt.Errorf("toEntities are not supported in no-eBPF mode")
	}
	if len(rule.ToGroups) > 0 {
		return nil, fmt.Errorf("toGroups are not supported in no-eBPF mode")
	}
	if len(rule.ToRequires) > 0 {
		return nil, fmt.Errorf("toRequires are not supported in no-eBPF mode")
	}
	if len(rule.ToNodes) > 0 {
		return nil, fmt.Errorf("toNodes are not supported in no-eBPF mode")
	}
	return ciliumPeers(rule.ToEndpoints, rule.ToCIDR, rule.ToCIDRSet)
}

func ciliumPeers(endpointSelectors []policyapi.EndpointSelector, cidrs []policyapi.CIDR, cidrRules []policyapi.CIDRRule) ([]Peer, error) {
	peers := make([]Peer, 0, len(endpointSelectors)+len(cidrs)+len(cidrRules))
	for _, sel := range endpointSelectors {
		if sel.LabelSelector == nil {
			peers = append(peers, Peer{})
			continue
		}
		peers = append(peers, Peer{PodSelector: selectorFromAPI(sel)})
	}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(string(cidr))
		if err != nil {
			return nil, err
		}
		peers = append(peers, Peer{IPBlock: &prefix})
	}
	for _, rule := range cidrRules {
		if rule.CIDRGroupRef != "" || rule.CIDRGroupSelector.LabelSelector != nil {
			return nil, fmt.Errorf("CIDR group selectors are not supported in no-eBPF mode")
		}
		prefix, err := netip.ParsePrefix(string(rule.Cidr))
		if err != nil {
			return nil, err
		}
		peer := Peer{IPBlock: &prefix}
		for _, except := range rule.ExceptCIDRs {
			ex, err := netip.ParsePrefix(string(except))
			if err != nil {
				return nil, err
			}
			peer.Except = append(peer.Except, ex)
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

func ciliumAllowPorts(endpoint Pod, portRules []policyapi.PortRule) ([]Port, bool, error) {
	if len(portRules) == 0 {
		return nil, true, nil
	}
	var out []Port
	for _, portRule := range portRules {
		if !portRule.Rules.IsEmpty() {
			return nil, false, fmt.Errorf("L7 policy is not supported in no-eBPF mode")
		}
		if len(portRule.Ports) == 0 {
			return nil, true, nil
		}
		for _, pp := range portRule.Ports {
			ports, err := ciliumPortsFromPortProtocol(endpoint, pp)
			if err != nil {
				return nil, false, err
			}
			out = append(out, ports...)
		}
	}
	if len(out) == 0 {
		return nil, false, nil
	}
	return out, false, nil
}

func ciliumDenyPorts(endpoint Pod, portRules []policyapi.PortDenyRule) ([]Port, bool, error) {
	if len(portRules) == 0 {
		return nil, true, nil
	}
	var out []Port
	for _, portRule := range portRules {
		if len(portRule.Ports) == 0 {
			return nil, true, nil
		}
		for _, pp := range portRule.Ports {
			ports, err := ciliumPortsFromPortProtocol(endpoint, pp)
			if err != nil {
				return nil, false, err
			}
			out = append(out, ports...)
		}
	}
	if len(out) == 0 {
		return nil, false, nil
	}
	return out, false, nil
}

func ciliumPortsFromPortProtocol(endpoint Pod, pp policyapi.PortProtocol) ([]Port, error) {
	protocols, err := ciliumProtocols(pp.Protocol)
	if err != nil {
		return nil, err
	}
	if pp.EndPort != 0 && pp.Port != "" && !isNumericPort(pp.Port) {
		return nil, fmt.Errorf("endPort is not supported with named ports")
	}
	if pp.Port == "" {
		return []Port{{Protocol: protocols[0]}}, nil
	}
	if portNum, err := strconv.ParseUint(pp.Port, 10, 16); err == nil {
		if pp.EndPort != 0 && pp.EndPort < int32(portNum) {
			return nil, fmt.Errorf("endPort must be greater than or equal to port")
		}
		out := make([]Port, 0, len(protocols))
		for _, proto := range protocols {
			out = append(out, Port{Protocol: proto, Port: uint16(portNum), EndPort: uint16(pp.EndPort)})
		}
		return out, nil
	}
	return resolveCiliumNamedPorts(endpoint, pp.Port, protocols), nil
}

func ciliumProtocols(proto policyapi.L4Proto) ([]Protocol, error) {
	switch proto {
	case "", policyapi.ProtoAny:
		return []Protocol{ProtocolTCP, ProtocolUDP, ProtocolSCTP}, nil
	case policyapi.ProtoTCP:
		return []Protocol{ProtocolTCP}, nil
	case policyapi.ProtoUDP:
		return []Protocol{ProtocolUDP}, nil
	case policyapi.ProtoSCTP:
		return []Protocol{ProtocolSCTP}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", proto)
	}
}

func resolveCiliumNamedPorts(endpoint Pod, name string, protocols []Protocol) []Port {
	if endpoint.NamedPorts == nil {
		return nil
	}
	var out []Port
	for _, candidate := range endpoint.NamedPorts[name] {
		if len(protocols) == 1 && candidate.Protocol != "" && candidate.Protocol != protocols[0] {
			continue
		}
		if candidate.Protocol == "" {
			candidate.Protocol = protocols[0]
		}
		out = append(out, candidate)
	}
	return out
}

func selectorFromAPI(sel policyapi.EndpointSelector) *LabelSelector {
	if sel.LabelSelector == nil {
		return nil
	}
	copySel := &LabelSelector{
		MatchLabels:      map[string]string{},
		MatchExpressions: append([]metav1.LabelSelectorRequirement(nil), sel.MatchExpressions...),
	}
	for k, v := range sel.MatchLabels {
		copySel.MatchLabels[k] = v
	}
	return copySel
}

func isNumericPort(port string) bool {
	_, err := strconv.ParseUint(port, 10, 16)
	return err == nil
}
