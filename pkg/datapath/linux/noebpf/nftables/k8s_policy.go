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

// PoliciesFromK8sNetworkPolicies compiles the supported no-eBPF subset of
// Kubernetes NetworkPolicy into nftables endpoint policy. It intentionally
// handles the certification-relevant 80/20 subset first: local pods, TCP/UDP/
// SCTP ports, pod selectors, namespace selectors, same-namespace defaults,
// named ports, endPort, matchExpressions, and ipBlock.
func PoliciesFromK8sNetworkPolicies(localPods []k8sTables.LocalPod, allPods []*corev1.Pod, namespaces []k8sTables.Namespace, networkPolicies []*networkingv1.NetworkPolicy) ([]EndpointPolicy, error) {
	pods := podsFromK8sPods(localPods, allPods, namespaces)
	byPod := map[string]*EndpointPolicySpec{}

	for _, np := range networkPolicies {
		if np == nil {
			continue
		}
		for i := range pods {
			pod := pods[i]
			if !pod.Local || pod.Namespace != np.Namespace || !selectorMatches(pod.Labels, selectorFromK8s(&np.Spec.PodSelector)) {
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
					r, err := knpIngressRule(np.Namespace, pod, rule)
					if err != nil {
						return nil, fmt.Errorf("networkpolicy %s/%s ingress: %w", np.Namespace, np.Name, err)
					}
					if r.MatchAllPorts || len(r.Ports) > 0 {
						spec.IngressRules = append(spec.IngressRules, r)
					}
				}
			}
			if policyHasEgress(np) {
				spec.EgressDeny = true
				for _, rule := range np.Spec.Egress {
					r, err := knpEgressRule(np.Namespace, pod, rule)
					if err != nil {
						return nil, fmt.Errorf("networkpolicy %s/%s egress: %w", np.Namespace, np.Name, err)
					}
					if r.MatchAllPorts || len(r.Ports) > 0 {
						spec.EgressRules = append(spec.EgressRules, r)
					}
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
	for _, container := range kp.Spec.Containers {
		for _, cp := range container.Ports {
			if cp.Name == "" || cp.ContainerPort <= 0 {
				continue
			}
			proto := protocolFromCore(cp.Protocol)
			pod.NamedPorts = appendNamedPort(pod.NamedPorts, cp.Name, Port{Protocol: proto, Port: uint16(cp.ContainerPort)})
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

func knpIngressRule(policyNamespace string, endpoint Pod, rule networkingv1.NetworkPolicyIngressRule) (PolicyRule, error) {
	peers, err := knpPeers(policyNamespace, rule.From)
	if err != nil {
		return PolicyRule{}, err
	}
	ports, matchAll, err := knpPorts(endpoint, rule.Ports)
	if err != nil {
		return PolicyRule{}, err
	}
	return PolicyRule{Peers: peers, Ports: ports, MatchAllPorts: matchAll}, nil
}

func knpEgressRule(policyNamespace string, endpoint Pod, rule networkingv1.NetworkPolicyEgressRule) (PolicyRule, error) {
	peers, err := knpPeers(policyNamespace, rule.To)
	if err != nil {
		return PolicyRule{}, err
	}
	ports, matchAll, err := knpPorts(endpoint, rule.Ports)
	if err != nil {
		return PolicyRule{}, err
	}
	return PolicyRule{Peers: peers, Ports: ports, MatchAllPorts: matchAll}, nil
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

		p.PodSelector = selectorFromK8s(peer.PodSelector)
		if peer.NamespaceSelector == nil {
			p.NamespaceSelector = &LabelSelector{MatchLabels: map[string]string{namespaceLabel: policyNamespace}}
		} else {
			p.NamespaceSelector = selectorFromK8s(peer.NamespaceSelector)
		}
		out = append(out, p)
	}
	return out, nil
}

func knpPorts(endpoint Pod, ports []networkingv1.NetworkPolicyPort) ([]Port, bool, error) {
	if len(ports) == 0 {
		return nil, true, nil
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
			case corev1.ProtocolSCTP:
				proto = ProtocolSCTP
			default:
				return nil, false, fmt.Errorf("unsupported protocol %s", *port.Protocol)
			}
		}
		if port.Port == nil {
			out = append(out, Port{Protocol: proto})
			continue
		}
		if port.EndPort != nil && port.Port.Type != 0 {
			return nil, false, fmt.Errorf("endPort is not supported with named ports")
		}
		if port.Port.Type != 0 {
			out = append(out, resolveNamedPorts(endpoint, port.Port.StrVal, proto)...)
			continue
		}
		if port.EndPort != nil {
			if *port.EndPort < port.Port.IntVal {
				return nil, false, fmt.Errorf("endPort must be greater than or equal to port")
			}
			out = append(out, Port{Protocol: proto, Port: uint16(port.Port.IntVal), EndPort: uint16(*port.EndPort)})
			continue
		}
		out = append(out, Port{Protocol: proto, Port: uint16(port.Port.IntVal)})
	}
	if len(out) == 0 {
		return nil, false, nil
	}
	return out, false, nil
}

func selectorFromK8s(sel *metav1.LabelSelector) *LabelSelector {
	if sel == nil {
		return nil
	}
	out := &LabelSelector{MatchLabels: make(map[string]string, len(sel.MatchLabels)), MatchExpressions: append([]metav1.LabelSelectorRequirement(nil), sel.MatchExpressions...)}
	for k, v := range sel.MatchLabels {
		out.MatchLabels[k] = string(v)
	}
	return out
}

func protocolFromCore(proto corev1.Protocol) Protocol {
	switch proto {
	case corev1.ProtocolUDP:
		return ProtocolUDP
	case corev1.ProtocolSCTP:
		return ProtocolSCTP
	default:
		return ProtocolTCP
	}
}

func appendNamedPort(existing map[string][]Port, name string, port Port) map[string][]Port {
	if existing == nil {
		existing = map[string][]Port{}
	}
	existing[name] = append(existing[name], port)
	return existing
}

func resolveNamedPorts(endpoint Pod, name string, proto Protocol) []Port {
	if endpoint.NamedPorts == nil {
		return nil
	}
	var out []Port
	for _, candidate := range endpoint.NamedPorts[name] {
		if candidate.Protocol != "" && candidate.Protocol != proto {
			continue
		}
		candidate.Protocol = proto
		out = append(out, candidate)
	}
	return out
}
