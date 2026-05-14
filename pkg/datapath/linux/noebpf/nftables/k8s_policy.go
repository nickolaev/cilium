// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"fmt"
	"net/netip"

	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
)

const namespaceLabel = "io.kubernetes.pod.namespace"

// PoliciesFromK8sNetworkPolicies compiles the small M1 subset of Kubernetes
// NetworkPolicy into nftables endpoint policy. It intentionally handles the
// certification-critical 80/20 subset first: local pods, numeric TCP/UDP ports,
// pod selectors, all-namespace selectors, same-namespace defaults, and ipBlock.
func PoliciesFromK8sNetworkPolicies(localPods []k8sTables.LocalPod, networkPolicies []*networkingv1.NetworkPolicy) ([]EndpointPolicy, error) {
	pods := podsFromLocalPods(localPods)
	byPod := map[string]*EndpointPolicySpec{}

	for _, np := range networkPolicies {
		if np == nil {
			continue
		}
		for i := range pods {
			pod := pods[i]
			if pod.Namespace != np.Namespace || !labelSelectorMatches(np.Spec.PodSelector, pod.Labels) {
				continue
			}

			key := pod.Namespace + "/" + pod.Name
			spec := byPod[key]
			if spec == nil {
				spec = &EndpointPolicySpec{Pod: pod}
				byPod[key] = spec
			}

			if policyHasIngress(np) {
				spec.IngressDeny = true
				for _, rule := range np.Spec.Ingress {
					r, err := knpIngressRule(np.Namespace, rule)
					if err != nil {
						return nil, fmt.Errorf("networkpolicy %s/%s ingress: %w", np.Namespace, np.Name, err)
					}
					spec.IngressRules = append(spec.IngressRules, r)
				}
			}
			if policyHasEgress(np) {
				spec.EgressDeny = true
				for _, rule := range np.Spec.Egress {
					r, err := knpEgressRule(np.Namespace, rule)
					if err != nil {
						return nil, fmt.Errorf("networkpolicy %s/%s egress: %w", np.Namespace, np.Name, err)
					}
					spec.EgressRules = append(spec.EgressRules, r)
				}
			}
		}
	}

	var out []EndpointPolicy
	for _, spec := range byPod {
		out = append(out, CompileEndpointPolicy(*spec, pods)...)
	}
	return out, nil
}

func podsFromLocalPods(localPods []k8sTables.LocalPod) []Pod {
	var pods []Pod
	for _, lp := range localPods {
		if lp.Pod == nil || lp.Spec.HostNetwork {
			continue
		}
		pod := Pod{
			Name:      lp.Name,
			Namespace: lp.Namespace,
			Labels:    map[string]string{namespaceLabel: lp.Namespace},
			Local:     true,
		}
		for k, v := range lp.Labels {
			pod.Labels[k] = v
		}
		for _, podIP := range lp.Status.PodIPs {
			ip, err := netip.ParseAddr(podIP.IP)
			if err == nil {
				pod.IPs = append(pod.IPs, ip)
			}
		}
		if len(pod.IPs) > 0 {
			pods = append(pods, pod)
		}
	}
	return pods
}

func policyHasIngress(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return true
	}
	for _, t := range np.Spec.PolicyTypes {
		if t == networkingv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}

func policyHasEgress(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return len(np.Spec.Egress) > 0
	}
	for _, t := range np.Spec.PolicyTypes {
		if t == networkingv1.PolicyTypeEgress {
			return true
		}
	}
	return false
}

func knpIngressRule(policyNamespace string, rule networkingv1.NetworkPolicyIngressRule) (PolicyRule, error) {
	peers, err := knpPeers(policyNamespace, rule.From)
	if err != nil {
		return PolicyRule{}, err
	}
	ports, err := knpPorts(rule.Ports)
	if err != nil {
		return PolicyRule{}, err
	}
	return PolicyRule{Peers: peers, Ports: ports}, nil
}

func knpEgressRule(policyNamespace string, rule networkingv1.NetworkPolicyEgressRule) (PolicyRule, error) {
	peers, err := knpPeers(policyNamespace, rule.To)
	if err != nil {
		return PolicyRule{}, err
	}
	ports, err := knpPorts(rule.Ports)
	if err != nil {
		return PolicyRule{}, err
	}
	return PolicyRule{Peers: peers, Ports: ports}, nil
}

func knpPeers(policyNamespace string, peers []networkingv1.NetworkPolicyPeer) ([]Peer, error) {
	if len(peers) == 0 {
		return nil, nil
	}
	out := make([]Peer, 0, len(peers))
	for _, peer := range peers {
		p := Peer{}
		if peer.IPBlock != nil {
			prefix, err := netip.ParsePrefix(peer.IPBlock.CIDR)
			if err != nil {
				return nil, err
			}
			p.IPBlock = &prefix
			for _, except := range peer.IPBlock.Except {
				ex, err := netip.ParsePrefix(except)
				if err != nil {
					return nil, err
				}
				p.Except = append(p.Except, ex)
			}
			out = append(out, p)
			continue
		}

		p.PodSelector = selectorMatchLabels(peer.PodSelector)
		if peer.NamespaceSelector == nil {
			if p.PodSelector == nil {
				p.PodSelector = map[string]string{}
			}
			p.PodSelector[namespaceLabel] = policyNamespace
		} else {
			p.NamespaceSelector = selectorMatchLabels(peer.NamespaceSelector)
		}
		out = append(out, p)
	}
	return out, nil
}

func knpPorts(ports []networkingv1.NetworkPolicyPort) ([]Port, error) {
	if len(ports) == 0 {
		return nil, nil
	}
	out := make([]Port, 0, len(ports))
	for _, port := range ports {
		proto := ProtocolTCP
		if port.Protocol != nil {
			switch *port.Protocol {
			case corev1.ProtocolTCP:
				proto = ProtocolTCP
			case corev1.ProtocolUDP:
				proto = ProtocolUDP
			default:
				continue
			}
		}
		if port.Port == nil {
			out = append(out, Port{Protocol: proto})
			continue
		}
		if port.Port.Type != 0 { // named ports are not in the M1 subset.
			continue
		}
		out = append(out, Port{Protocol: proto, Port: uint16(port.Port.IntVal)})
	}
	return out, nil
}

func selectorMatchLabels(sel *metav1.LabelSelector) map[string]string {
	if sel == nil {
		return nil
	}
	out := make(map[string]string, len(sel.MatchLabels))
	for k, v := range sel.MatchLabels {
		out[k] = string(v)
	}
	return out
}

func labelSelectorMatches(sel metav1.LabelSelector, labels map[string]string) bool {
	for k, v := range sel.MatchLabels {
		if labels[k] != string(v) {
			return false
		}
	}
	// M1 keeps matchExpressions out of the datapath compiler. Treat them as not
	// matching rather than accidentally over-selecting endpoints.
	return len(sel.MatchExpressions) == 0
}
