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
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
)

var noebpfPolicyLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// PoliciesFromCiliumNetworkPolicies compiles the supported no-eBPF subset of
// namespaced CiliumNetworkPolicy objects into nftables endpoint policy.
func PoliciesFromCiliumNetworkPolicies(localPods []k8sTables.LocalPod, allPods []*corev1.Pod, namespaces []k8sTables.Namespace, frontends []*loadbalancer.Frontend, cidrGroups []*ciliumv2.CiliumCIDRGroup, cnps []*ciliumv2.CiliumNetworkPolicy) ([]EndpointPolicy, error) {
	groups := newCIDRGroupIndex(cidrGroups)
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
	return policiesFromParsedCiliumRules(localPods, allPods, namespaces, frontends, groups, parsed)
}

// PoliciesFromCiliumClusterwideNetworkPolicies compiles the supported no-eBPF
// subset of clusterwide CiliumClusterwideNetworkPolicy objects into endpoint policy.
func PoliciesFromCiliumClusterwideNetworkPolicies(localPods []k8sTables.LocalPod, allPods []*corev1.Pod, namespaces []k8sTables.Namespace, frontends []*loadbalancer.Frontend, cidrGroups []*ciliumv2.CiliumCIDRGroup, ccnps []*ciliumv2.CiliumClusterwideNetworkPolicy) ([]EndpointPolicy, error) {
	groups := newCIDRGroupIndex(cidrGroups)
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
	return policiesFromParsedCiliumRules(localPods, allPods, namespaces, frontends, groups, parsed)
}

type parsedCiliumPolicy struct {
	namespace string
	name      string
	rules     policyapi.Rules
}

func policiesFromParsedCiliumRules(localPods []k8sTables.LocalPod, allPods []*corev1.Pod, namespaces []k8sTables.Namespace, frontends []*loadbalancer.Frontend, groups cidrGroupIndex, policies []parsedCiliumPolicy) ([]EndpointPolicy, error) {
	pods := podsFromK8sPods(localPods, allPods, namespaces)
	byPod := map[string]*EndpointPolicySpec{}

	for _, policy := range policies {
		for _, rule := range policy.rules {
			if err := addCiliumRule(rule, pods, frontends, groups, byPod, policy.namespace, policy.name); err != nil {
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

func addCiliumRule(rule *policyapi.Rule, pods []Pod, frontends []*loadbalancer.Frontend, groups cidrGroupIndex, byPod map[string]*EndpointPolicySpec, policyNamespace, policyName string) error {
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
			allow, ok, err := ciliumIngressRule(pod, ingress, groups)
			if err != nil {
				return fmt.Errorf("%s/%s ingress: %w", policyNamespace, policyName, err)
			}
			if ok {
				spec.IngressRules = append(spec.IngressRules, allow)
			}
		}
		for _, ingressDeny := range rule.IngressDeny {
			deny, ok, err := ciliumIngressDenyRule(pod, ingressDeny, groups)
			if err != nil {
				return fmt.Errorf("%s/%s ingressDeny: %w", policyNamespace, policyName, err)
			}
			if ok {
				spec.IngressDenyRules = append(spec.IngressDenyRules, deny)
			}
		}
		for _, egress := range rule.Egress {
			allow, ok, err := ciliumEgressRule(pod, egress, frontends, groups)
			if err != nil {
				return fmt.Errorf("%s/%s egress: %w", policyNamespace, policyName, err)
			}
			if ok {
				spec.EgressRules = append(spec.EgressRules, allow)
			}
		}
		for _, egressDeny := range rule.EgressDeny {
			deny, ok, err := ciliumEgressDenyRule(pod, egressDeny, groups)
			if err != nil {
				return fmt.Errorf("%s/%s egressDeny: %w", policyNamespace, policyName, err)
			}
			if ok {
				spec.EgressDenyRules = append(spec.EgressDenyRules, deny)
			}
		}
	}

	return nil
}

func ciliumIngressRule(endpoint Pod, rule policyapi.IngressRule, groups cidrGroupIndex) (PolicyRule, bool, error) {
	if rule.Authentication != nil {
		return PolicyRule{}, false, fmt.Errorf("authentication is not supported in no-eBPF mode")
	}
	peers, hasSource, err := ciliumIngressPeers(rule.IngressCommonRule, groups)
	if err != nil {
		return PolicyRule{}, false, err
	}
	if hasSource && len(peers) == 0 {
		return PolicyRule{}, false, nil
	}
	var ports []Port
	var matchAll bool
	switch {
	case len(rule.ICMPs) > 0:
		ports, err = ciliumICMPPorts(endpoint, rule.ICMPs)
	case len(rule.ToPorts) > 0:
		ports, matchAll, err = ciliumAllowPorts(endpoint, rule.ToPorts)
	default:
		matchAll = true
	}
	if err != nil {
		return PolicyRule{}, false, err
	}
	return PolicyRule{Peers: peers, Ports: ports, MatchAllPorts: matchAll}, true, nil
}

func ciliumEgressRule(endpoint Pod, rule policyapi.EgressRule, frontends []*loadbalancer.Frontend, groups cidrGroupIndex) (PolicyRule, bool, error) {
	if len(rule.ToFQDNs) > 0 {
		return PolicyRule{}, true, fmt.Errorf("toFQDNs are not supported in no-eBPF mode")
	}
	if rule.Authentication != nil {
		return PolicyRule{}, true, fmt.Errorf("authentication is not supported in no-eBPF mode")
	}
	var peers []Peer
	var hasSource bool
	var err error
	if len(rule.ToServices) > 0 {
		peers, err = ciliumServicePeers(rule.ToServices, frontends)
	} else {
		peers, hasSource, err = ciliumEgressPeers(rule.EgressCommonRule, groups)
	}
	if err != nil {
		return PolicyRule{}, true, err
	}
	if hasSource && len(peers) == 0 {
		return PolicyRule{}, false, nil
	}
	if len(rule.ToServices) > 0 && len(peers) == 0 {
		return PolicyRule{}, false, nil
	}
	var ports []Port
	var matchAll bool
	switch {
	case len(rule.ICMPs) > 0:
		ports, err = ciliumICMPPorts(endpoint, rule.ICMPs)
	case len(rule.ToPorts) > 0:
		ports, matchAll, err = ciliumAllowPorts(endpoint, rule.ToPorts)
	default:
		matchAll = true
	}
	if err != nil {
		return PolicyRule{}, true, err
	}
	return PolicyRule{Peers: peers, Ports: ports, MatchAllPorts: matchAll}, true, nil
}

func ciliumIngressDenyRule(endpoint Pod, rule policyapi.IngressDenyRule, groups cidrGroupIndex) (PolicyRule, bool, error) {
	peers, hasSource, err := ciliumIngressPeers(rule.IngressCommonRule, groups)
	if err != nil {
		return PolicyRule{}, false, err
	}
	if hasSource && len(peers) == 0 {
		return PolicyRule{}, false, nil
	}
	var ports []Port
	var matchAll bool
	switch {
	case len(rule.ICMPs) > 0:
		ports, err = ciliumICMPPorts(endpoint, rule.ICMPs)
	case len(rule.ToPorts) > 0:
		ports, matchAll, err = ciliumDenyPorts(endpoint, rule.ToPorts)
	default:
		matchAll = true
	}
	if err != nil {
		return PolicyRule{}, false, err
	}
	return PolicyRule{Peers: peers, Ports: ports, MatchAllPorts: matchAll}, true, nil
}

func ciliumEgressDenyRule(endpoint Pod, rule policyapi.EgressDenyRule, groups cidrGroupIndex) (PolicyRule, bool, error) {
	peers, hasSource, err := ciliumEgressPeers(rule.EgressCommonRule, groups)
	if err != nil {
		return PolicyRule{}, false, err
	}
	if hasSource && len(peers) == 0 {
		return PolicyRule{}, false, nil
	}
	var ports []Port
	var matchAll bool
	switch {
	case len(rule.ICMPs) > 0:
		ports, err = ciliumICMPPorts(endpoint, rule.ICMPs)
	case len(rule.ToPorts) > 0:
		ports, matchAll, err = ciliumDenyPorts(endpoint, rule.ToPorts)
	default:
		matchAll = true
	}
	if err != nil {
		return PolicyRule{}, false, err
	}
	return PolicyRule{Peers: peers, Ports: ports, MatchAllPorts: matchAll}, true, nil
}

func ciliumIngressPeers(rule policyapi.IngressCommonRule, groups cidrGroupIndex) ([]Peer, bool, error) {
	if len(rule.FromEntities) > 0 {
		return nil, false, fmt.Errorf("fromEntities are not supported in no-eBPF mode")
	}
	if len(rule.FromRequires) > 0 {
		return nil, false, fmt.Errorf("fromRequires are not supported in no-eBPF mode")
	}
	if len(rule.FromNodes) > 0 {
		return nil, false, fmt.Errorf("fromNodes are not supported in no-eBPF mode")
	}
	return ciliumPeers(rule.FromEndpoints, rule.FromCIDR, rule.FromCIDRSet, rule.FromGroups, groups)
}

func ciliumEgressPeers(rule policyapi.EgressCommonRule, groups cidrGroupIndex) ([]Peer, bool, error) {
	if len(rule.ToEntities) > 0 {
		return nil, false, fmt.Errorf("toEntities are not supported in no-eBPF mode")
	}
	if len(rule.ToRequires) > 0 {
		return nil, false, fmt.Errorf("toRequires are not supported in no-eBPF mode")
	}
	if len(rule.ToNodes) > 0 {
		return nil, false, fmt.Errorf("toNodes are not supported in no-eBPF mode")
	}
	return ciliumPeers(rule.ToEndpoints, rule.ToCIDR, rule.ToCIDRSet, rule.ToGroups, groups)
}

func ciliumPeers(endpointSelectors []policyapi.EndpointSelector, cidrs []policyapi.CIDR, cidrRules []policyapi.CIDRRule, externalGroups []policyapi.Groups, groups cidrGroupIndex) ([]Peer, bool, error) {
	hasSource := endpointSelectors != nil || cidrs != nil || cidrRules != nil || externalGroups != nil
	peers := make([]Peer, 0, len(endpointSelectors)+len(cidrs)+len(cidrRules)+len(externalGroups))
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
			return nil, false, err
		}
		peers = append(peers, Peer{IPBlock: &prefix})
	}
	for _, rule := range cidrRules {
		excepts, err := cidrRuleExcepts(rule.ExceptCIDRs)
		if err != nil {
			return nil, false, err
		}
		switch {
		case rule.CIDRGroupRef != "":
			for _, prefix := range groups.prefixesForRef(string(rule.CIDRGroupRef)) {
				peer := Peer{IPBlock: &prefix, Except: excepts}
				peers = append(peers, peer)
			}
		case rule.CIDRGroupSelector.LabelSelector != nil:
			for _, prefix := range groups.prefixesForSelector(selectorFromAPI(rule.CIDRGroupSelector)) {
				peer := Peer{IPBlock: &prefix, Except: excepts}
				peers = append(peers, peer)
			}
		default:
			prefix, err := netip.ParsePrefix(string(rule.Cidr))
			if err != nil {
				return nil, false, err
			}
			peers = append(peers, Peer{IPBlock: &prefix, Except: excepts})
		}
	}
	for _, group := range externalGroups {
		prefixes, err := ciliumGroupPrefixes(group, groups)
		if err != nil {
			return nil, false, err
		}
		for _, prefix := range prefixes {
			peers = append(peers, Peer{IPBlock: &prefix})
		}
	}
	return uniquePeers(peers), hasSource, nil
}

func ciliumGroupPrefixes(group policyapi.Groups, groups cidrGroupIndex) ([]netip.Prefix, error) {
	selector := selectorFromAPI(group.GetAsEndpointSelector())
	if selector == nil {
		return nil, nil
	}
	return groups.prefixesForSelector(selector), nil
}

func cidrRuleExcepts(excepts []policyapi.CIDR) ([]netip.Prefix, error) {
	if len(excepts) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(excepts))
	for _, except := range excepts {
		prefix, err := netip.ParsePrefix(string(except))
		if err != nil {
			return nil, err
		}
		out = append(out, prefix)
	}
	return out, nil
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

func ciliumICMPPorts(endpoint Pod, rules policyapi.ICMPRules) ([]Port, error) {
	var out []Port
	for _, rule := range rules {
		for _, field := range rule.Fields {
			pp := field.PortProtocol()
			ports, err := ciliumPortsFromPortProtocol(endpoint, *pp)
			if err != nil {
				return nil, err
			}
			out = append(out, ports...)
		}
	}
	return out, nil
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
	case policyapi.ProtoICMP:
		return []Protocol{ProtocolICMP}, nil
	case policyapi.ProtoICMPv6:
		return []Protocol{ProtocolICMPv6}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", proto)
	}
}

func ciliumServicePeers(services []policyapi.Service, frontends []*loadbalancer.Frontend) ([]Peer, error) {
	if len(services) > 0 && frontends == nil {
		return nil, fmt.Errorf("toServices requires the no-eBPF service backend")
	}
	var peers []Peer
	for _, service := range services {
		for _, frontend := range matchingFrontendsForService(service, frontends) {
			for backend := range frontend.Backends {
				if backend == nil || backend.State != loadbalancer.BackendStateActive {
					continue
				}
				addr := backend.Address.Addr()
				prefix := netip.PrefixFrom(addr, addr.BitLen())
				peers = append(peers, Peer{IPBlock: &prefix})
			}
		}
	}
	return uniquePeers(peers), nil
}

func matchingFrontendsForService(service policyapi.Service, frontends []*loadbalancer.Frontend) []*loadbalancer.Frontend {
	var out []*loadbalancer.Frontend
	for _, frontend := range frontends {
		if frontend == nil || frontend.Service == nil {
			continue
		}
		switch {
		case service.K8sService != nil:
			if service.K8sService.ServiceName != frontend.Service.Name.Name() {
				continue
			}
			if service.K8sService.Namespace != "" && service.K8sService.Namespace != frontend.Service.Name.Namespace() {
				continue
			}
			out = append(out, frontend)
		case service.K8sServiceSelector != nil:
			if service.K8sServiceSelector.Namespace != "" && service.K8sServiceSelector.Namespace != frontend.Service.Name.Namespace() {
				continue
			}
			if !selectorMatches(serviceLabels(frontend.Service), selectorFromAPI(policyapi.EndpointSelector(service.K8sServiceSelector.Selector))) {
				continue
			}
			out = append(out, frontend)
		}
	}
	return out
}

func serviceLabels(svc *loadbalancer.Service) map[string]string {
	if svc == nil || len(svc.Labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(svc.Labels))
	for k, v := range svc.Labels {
		out[k] = v.Value
	}
	return out
}

func uniquePeers(in []Peer) []Peer {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]Peer, 0, len(in))
	for _, peer := range in {
		key := peer.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, peer)
	}
	return out
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
