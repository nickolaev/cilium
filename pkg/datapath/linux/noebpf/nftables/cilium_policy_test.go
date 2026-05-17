// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	policyapi "github.com/cilium/cilium/pkg/policy/api"

	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPoliciesFromCiliumNetworkPoliciesAllowAndDenyPrecedence(t *testing.T) {
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "server", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}}}}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.1.10"}}},
	}
	client := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.1.20"}}},
	}

	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "allow-client", Namespace: "backend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{
						MatchLabels:      map[string]string{"app": "client"},
						MatchExpressions: []slimmetav1.LabelSelectorRequirement{{Key: "io.cilium.k8s.namespace.labels.team", Operator: slimmetav1.LabelSelectorOpIn, Values: []string{"blue"}}},
					}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "http", Protocol: policyapi.ProtoTCP}}}},
			}},
			IngressDeny: []policyapi.IngressDenyRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{
						MatchLabels:      map[string]string{"app": "client"},
						MatchExpressions: []slimmetav1.LabelSelectorRequirement{{Key: "io.cilium.k8s.namespace.labels.team", Operator: slimmetav1.LabelSelectorOpIn, Values: []string{"blue"}}},
					}}},
				},
				ToPorts: []policyapi.PortDenyRule{{Ports: []policyapi.PortProtocol{{Port: "http", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}

	policies, err := PoliciesFromCiliumNetworkPolicies(
		[]k8sTables.LocalPod{{Pod: server}},
		[]*corev1.Pod{server, client},
		[]k8sTables.Namespace{{Name: "backend", Labels: map[string]string{"team": "green"}}, {Name: "frontend", Labels: map[string]string{"team": "blue"}}},
		[]*ciliumv2.CiliumNetworkPolicy{cnp},
	)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	allowIdx := strings.Index(script, "tcp dport 8080 counter accept")
	denyIdx := strings.Index(script, "tcp dport 8080 counter drop")
	require.NotEqual(t, -1, allowIdx, script)
	require.NotEqual(t, -1, denyIdx, script)
	require.Less(t, denyIdx, allowIdx, script)
}

func TestPoliciesFromCiliumNetworkPoliciesNamedPortsAndEndPort(t *testing.T) {
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "server", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}}}}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.1.11"}}},
	}
	client := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.1.21"}}},
	}

	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "named-port-and-range", Namespace: "backend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"k8s:app": "server"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{
						MatchLabels:      map[string]string{"k8s:app": "client"},
						MatchExpressions: []slimmetav1.LabelSelectorRequirement{{Key: "io.cilium.k8s.namespace.labels.team", Operator: slimmetav1.LabelSelectorOpIn, Values: []string{"blue"}}},
					}}},
				},
				ToPorts: []policyapi.PortRule{
					{Ports: []policyapi.PortProtocol{{Port: "http", Protocol: policyapi.ProtoTCP}}},
					{Ports: []policyapi.PortProtocol{{Port: "8080", EndPort: 8082, Protocol: policyapi.ProtoTCP}}},
				},
			}},
		},
	}

	policies, err := PoliciesFromCiliumNetworkPolicies(
		[]k8sTables.LocalPod{{Pod: server}},
		[]*corev1.Pod{server, client},
		[]k8sTables.Namespace{{Name: "backend", Labels: map[string]string{"team": "green"}}, {Name: "frontend", Labels: map[string]string{"team": "blue"}}},
		[]*ciliumv2.CiliumNetworkPolicy{cnp},
	)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	require.Contains(t, script, "ip saddr 10.244.1.21/32 ip daddr 10.244.1.11/32 tcp dport 8080 counter accept")
	require.Contains(t, script, "ip saddr 10.244.1.21/32 ip daddr 10.244.1.11/32 tcp dport 8080-8082 counter accept")
}

func TestPoliciesFromCiliumClusterwideNetworkPolicies(t *testing.T) {
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "server", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}}}}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.2.10"}}},
	}
	backendClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "backend-client", Namespace: "backend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.2.30"}}},
	}
	client := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.2.20"}}},
	}

	ccnp := &ciliumv2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "allow-client"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{
						MatchLabels:      map[string]string{"app": "client"},
						MatchExpressions: []slimmetav1.LabelSelectorRequirement{{Key: "io.cilium.k8s.namespace.labels.team", Operator: slimmetav1.LabelSelectorOpIn, Values: []string{"blue"}}},
					}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "http", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}

	policies, err := PoliciesFromCiliumClusterwideNetworkPolicies(
		[]k8sTables.LocalPod{{Pod: server}},
		[]*corev1.Pod{server, backendClient, client},
		[]k8sTables.Namespace{{Name: "backend", Labels: map[string]string{"team": "green"}}, {Name: "frontend", Labels: map[string]string{"team": "blue"}}},
		[]*ciliumv2.CiliumClusterwideNetworkPolicy{ccnp},
	)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	require.Contains(t, script, "ip saddr 10.244.2.20/32 ip daddr 10.244.2.10/32 tcp dport 8080 counter accept")
	require.NotContains(t, script, "ip saddr 10.244.2.30/32 ip daddr 10.244.2.10/32 tcp dport 8080 counter accept")
}

func TestPoliciesFromCiliumNetworkPoliciesNamespaceBoundary(t *testing.T) {
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.3.10"}}},
	}
	backendClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client-a", Namespace: "backend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.3.20"}}},
	}
	frontendClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client-b", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.3.30"}}},
	}
	tcp := policyapi.ProtoTCP
	port := policyapi.PortProtocol{Port: "8080", Protocol: tcp}

	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "allow-client", Namespace: "backend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{port}}},
			}},
		},
	}

	policies, err := PoliciesFromCiliumNetworkPolicies(
		[]k8sTables.LocalPod{{Pod: server}},
		[]*corev1.Pod{server, backendClient, frontendClient},
		[]k8sTables.Namespace{{Name: "backend"}, {Name: "frontend"}},
		[]*ciliumv2.CiliumNetworkPolicy{cnp},
	)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	require.Contains(t, script, "10.244.3.20/32")
	require.NotContains(t, script, "10.244.3.30/32")
}

func TestPoliciesFromCiliumNetworkPoliciesCIDRSetExcept(t *testing.T) {
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.4.10"}}},
	}
	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "cidr-except", Namespace: "backend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromCIDRSet: []policyapi.CIDRRule{{
						Cidr:        policyapi.CIDR("10.0.0.0/8"),
						ExceptCIDRs: []policyapi.CIDR{"10.1.0.0/16"},
					}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "53", Protocol: policyapi.ProtoUDP}}}},
			}},
		},
	}

	policies, err := PoliciesFromCiliumNetworkPolicies(
		[]k8sTables.LocalPod{{Pod: server}},
		[]*corev1.Pod{server},
		[]k8sTables.Namespace{{Name: "backend"}},
		[]*ciliumv2.CiliumNetworkPolicy{cnp},
	)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotEmpty(t, policies[0].IngressAllow)

	except := netip.MustParseAddr("10.1.0.1")
	for _, allow := range policies[0].IngressAllow {
		require.False(t, allow.Source.Contains(except), "excepted source still present in %#v", allow.Source)
	}
}

func TestControllerCNPReconciliationOnDelete(t *testing.T) {
	c := &controller{
		cnpCache: map[resource.Key]*ciliumv2.CiliumNetworkPolicy{},
	}
	cnp := &ciliumv2.CiliumNetworkPolicy{ObjectMeta: k8smetav1.ObjectMeta{Name: "p", Namespace: "default"}}
	key := resource.Key{Namespace: "default", Name: "p"}
	c.handleCNPEvent(resource.Event[*ciliumv2.CiliumNetworkPolicy]{Kind: resource.Upsert, Key: key, Object: cnp, Done: func(error) {}})
	require.Len(t, c.cachedCNPs(), 1)
	c.handleCNPEvent(resource.Event[*ciliumv2.CiliumNetworkPolicy]{Kind: resource.Delete, Key: key, Done: func(error) {}})
	require.Empty(t, c.cachedCNPs())
}
