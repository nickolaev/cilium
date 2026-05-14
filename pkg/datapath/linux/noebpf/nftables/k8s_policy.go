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
func PoliciesFromK8sNetworkPolicies(localPods []k8sTables.LocalPod, allPods []*corev1.Pod, namespaces []k8sTables.Namespace, networkPolicies []*networkingv1.NetworkPolicy) ([]EndpointPolicy, error) {
	pods := podsFromK8sPods(localPods, allPods, namespaces)
	byPod := map[string]*EndpointPolicySpec{}

	for _, np := range networkPolicies {
		if np == nil {
			continue
		}
		for i := range pods {
			pod := pods[i]
			if !pod.Local || pod.Namespace != np.Namespace || !labelSelectorMatches(np.Spec.PodSelector, pod.Labels) {
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

func podsFromK8sPods(localPods []k8sTables.LocalPod, allPods []*corev1.Pod, namespaces []k8sTables.Namespace) []Pod {
	namespaceLabels := map[string]map[string]string{}
	for _, ns := range namespaces {
		labels := map[string]string{namespaceLabel: ns.Name}
		for k, v := range ns.Labels {
			labels[k] = v
		}
		namespaceLabels[ns.Name] = labels
	}

	localKeys := map[string]struct{}{}
	for _, lp := range localPods {
		localKeys[lp.Namespace+"/"+lp.Name] = struct{}{}
	}

	var pods []Pod
	seen := map[string]struct{}{}
	for _, kp := range allPods {
		pod, ok := podFromK8sPod(kp, namespaceLabels)
		if !ok {
			continue
		}
		if _, ok := localKeys[pod.Namespace+"/"+pod.Name]; ok {
			pod.Local = true
		}
		pods = append(pods, pod)
		seen[pod.Namespace+"/"+pod.Name] = struct{}{}
	}

	// Fall back to the local-pod table for tests or startup races before the all-pod
	// informer has replayed. Remote peers still come from allPods once available.
	for _, lp := range localPods {
		if _, ok := seen[lp.Namespace+"/"+lp.Name]; ok {
			continue
		}
		pod, ok := podFromK8sPod(lp.Pod, namespaceLabels)
		if !ok {
			continue
		}
		pod.Local = true
		pods = append(pods, pod)
	}
	return pods
}

func podFromK8sPod(kp *corev1.Pod, namespaceLabels map[string]map[string]string) (Pod, bool) {
	if kp == nil || kp.Spec.HostNetwork || kp.DeletionTimestamp != nil {
		return Pod{}, false
	}
	pod := Pod{
		Name:            kp.Name,
		Namespace:       kp.Namespace,
		Labels:          map[string]string{namespaceLabel: kp.Namespace},
		NamespaceLabels: map[string]string{namespaceLabel: kp.Namespace},
	}
	if labels, ok := namespaceLabels[kp.Namespace]; ok {
		pod.NamespaceLabels = labels
	}
	for k, v := range kp.Labels {
		pod.Labels[k] = v
	}
	for _, podIP := range kp.Status.PodIPs {
		ip, err := netip.ParseAddr(podIP.IP)
		if err == nil {
			pod.IPs = append(pod.IPs, ip)
		}
	}
	return pod, len(pod.IPs) > 0
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

		var err error
		p.PodSelector, err = selectorMatchLabels(peer.PodSelector)
		if err != nil {
			return nil, err
		}
		if peer.NamespaceSelector == nil {
			if p.PodSelector == nil {
				p.PodSelector = map[string]string{}
			}
			p.PodSelector[namespaceLabel] = policyNamespace
		} else {
			p.NamespaceSelector, err = selectorMatchLabels(peer.NamespaceSelector)
			if err != nil {
				return nil, err
			}
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
				return nil, fmt.Errorf("unsupported protocol %s", *port.Protocol)
			}
		}
		if port.Port == nil {
			out = append(out, Port{Protocol: proto})
			continue
		}
		if port.EndPort != nil {
			return nil, fmt.Errorf("endPort is not supported")
		}
		if port.Port.Type != 0 { // named ports are not in the M1 subset.
			return nil, fmt.Errorf("named ports are not supported")
		}
		out = append(out, Port{Protocol: proto, Port: uint16(port.Port.IntVal)})
	}
	return out, nil
}

func selectorMatchLabels(sel *metav1.LabelSelector) (map[string]string, error) {
	if sel == nil {
		return nil, nil
	}
	if len(sel.MatchExpressions) > 0 {
		return nil, fmt.Errorf("matchExpressions are not supported")
	}
	out := make(map[string]string, len(sel.MatchLabels))
	for k, v := range sel.MatchLabels {
		out[k] = string(v)
	}
	return out, nil
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
