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

func TestPoliciesFromCiliumNetworkPoliciesAllowAndDenyAcrossPolicies(t *testing.T) {
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "server", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}}}}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.6.10"}}},
	}
	client := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client", Namespace: "backend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.6.20"}}},
	}
	allow := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "allow", Namespace: "backend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "8080", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}
	deny := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "deny", Namespace: "backend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}},
			IngressDeny: []policyapi.IngressDenyRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
				},
				ToPorts: []policyapi.PortDenyRule{{Ports: []policyapi.PortProtocol{{Port: "8080", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}

	policies, err := PoliciesFromCiliumNetworkPolicies(
		[]k8sTables.LocalPod{{Pod: server}},
		[]*corev1.Pod{server, client},
		[]k8sTables.Namespace{{Name: "backend"}},
		[]*ciliumv2.CiliumNetworkPolicy{allow, deny},
	)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	denyIdx := strings.Index(script, "ip saddr 10.244.6.20/32 ip daddr 10.244.6.10/32 tcp dport 8080 counter drop")
	allowIdx := strings.Index(script, "ip saddr 10.244.6.20/32 ip daddr 10.244.6.10/32 tcp dport 8080 counter accept")
	require.NotEqual(t, -1, denyIdx, script)
	require.NotEqual(t, -1, allowIdx, script)
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

func TestPoliciesFromCiliumNetworkPoliciesEgressAllowAndDeny(t *testing.T) {
	client := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.1.21"}}},
	}
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "frontend", Labels: map[string]string{"app": "server"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.1.11"}}},
	}

	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "egress-allow-deny", Namespace: "frontend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}},
			Egress: []policyapi.EgressRule{{
				EgressCommonRule: policyapi.EgressCommonRule{
					ToEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "80", Protocol: policyapi.ProtoTCP}}}},
			}},
			EgressDeny: []policyapi.EgressDenyRule{{
				EgressCommonRule: policyapi.EgressCommonRule{
					ToEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}}},
				},
				ToPorts: []policyapi.PortDenyRule{{Ports: []policyapi.PortProtocol{{Port: "80", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}

	policies, err := PoliciesFromCiliumNetworkPolicies(
		[]k8sTables.LocalPod{{Pod: client}},
		[]*corev1.Pod{client, server},
		[]k8sTables.Namespace{{Name: "frontend"}},
		[]*ciliumv2.CiliumNetworkPolicy{cnp},
	)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	denyIdx := strings.Index(script, "ip saddr 10.244.1.21/32 ip daddr 10.244.1.11/32 tcp dport 80 counter drop")
	allowIdx := strings.Index(script, "ip saddr 10.244.1.21/32 ip daddr 10.244.1.11/32 tcp dport 80 counter accept")
	require.NotEqual(t, -1, denyIdx, script)
	require.NotEqual(t, -1, allowIdx, script)
	require.Less(t, denyIdx, allowIdx, script)
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

func TestPoliciesFromCiliumClusterwideNetworkPoliciesEgressAllowAndDeny(t *testing.T) {
	client := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.2.21"}}},
	}
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.2.11"}}},
	}

	ccnp := &ciliumv2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "egress-allow-deny"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}},
			Egress: []policyapi.EgressRule{{
				EgressCommonRule: policyapi.EgressCommonRule{
					ToEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{
						MatchLabels:      map[string]string{"app": "server"},
						MatchExpressions: []slimmetav1.LabelSelectorRequirement{{Key: "io.cilium.k8s.namespace.labels.team", Operator: slimmetav1.LabelSelectorOpIn, Values: []string{"blue"}}},
					}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "443", Protocol: policyapi.ProtoTCP}}}},
			}},
			EgressDeny: []policyapi.EgressDenyRule{{
				EgressCommonRule: policyapi.EgressCommonRule{
					ToEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{
						MatchLabels:      map[string]string{"app": "server"},
						MatchExpressions: []slimmetav1.LabelSelectorRequirement{{Key: "io.cilium.k8s.namespace.labels.team", Operator: slimmetav1.LabelSelectorOpIn, Values: []string{"blue"}}},
					}}},
				},
				ToPorts: []policyapi.PortDenyRule{{Ports: []policyapi.PortProtocol{{Port: "443", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}

	policies, err := PoliciesFromCiliumClusterwideNetworkPolicies(
		[]k8sTables.LocalPod{{Pod: client}},
		[]*corev1.Pod{client, server},
		[]k8sTables.Namespace{{Name: "frontend", Labels: map[string]string{"team": "green"}}, {Name: "backend", Labels: map[string]string{"team": "blue"}}},
		[]*ciliumv2.CiliumClusterwideNetworkPolicy{ccnp},
	)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	denyIdx := strings.Index(script, "ip saddr 10.244.2.21/32 ip daddr 10.244.2.11/32 tcp dport 443 counter drop")
	allowIdx := strings.Index(script, "ip saddr 10.244.2.21/32 ip daddr 10.244.2.11/32 tcp dport 443 counter accept")
	require.NotEqual(t, -1, denyIdx, script)
	require.NotEqual(t, -1, allowIdx, script)
	require.Less(t, denyIdx, allowIdx, script)
}

func TestPoliciesFromCiliumNetworkPoliciesRejectUnsupportedFeatures(t *testing.T) {
	client := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.3.21"}}},
	}

	testCases := []struct {
		name string
		cnp  *ciliumv2.CiliumNetworkPolicy
		want string
	}{
		{
			name: "l7 http",
			cnp: &ciliumv2.CiliumNetworkPolicy{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "l7", Namespace: "frontend"},
				Spec: &policyapi.Rule{
					EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}},
					Ingress: []policyapi.IngressRule{{
						IngressCommonRule: policyapi.IngressCommonRule{
							FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
						},
						ToPorts: []policyapi.PortRule{{
							Ports: []policyapi.PortProtocol{{Port: "80", Protocol: policyapi.ProtoTCP}},
							Rules: &policyapi.L7Rules{HTTP: []policyapi.PortRuleHTTP{{Method: "GET"}}},
						}},
					}},
				},
			},
			want: "L7 policy is not supported in no-eBPF mode",
		},
		{
			name: "tofqdn",
			cnp: &ciliumv2.CiliumNetworkPolicy{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "fqdn", Namespace: "frontend"},
				Spec: &policyapi.Rule{
					EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}},
					Egress: []policyapi.EgressRule{{
						ToFQDNs: []policyapi.FQDNSelector{{MatchName: "example.com"}},
					}},
				},
			},
			want: "toFQDNs are not supported in no-eBPF mode",
		},
		{
			name: "icmp ingress",
			cnp: &ciliumv2.CiliumNetworkPolicy{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "icmp-ingress", Namespace: "frontend"},
				Spec: &policyapi.Rule{
					EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}},
					Ingress: []policyapi.IngressRule{{
						IngressCommonRule: policyapi.IngressCommonRule{
							FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
						},
						ICMPs: policyapi.ICMPRules{{Fields: []policyapi.ICMPField{{}}}},
					}},
				},
			},
			want: "ICMP policy is not supported in no-eBPF mode",
		},
		{
			name: "icmp egress deny",
			cnp: &ciliumv2.CiliumNetworkPolicy{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "icmp-egress", Namespace: "frontend"},
				Spec: &policyapi.Rule{
					EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}},
					EgressDeny: []policyapi.EgressDenyRule{{
						EgressCommonRule: policyapi.EgressCommonRule{
							ToEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}}},
						},
						ICMPs: policyapi.ICMPRules{{Fields: []policyapi.ICMPField{{}}}},
					}},
				},
			},
			want: "ICMP policy is not supported in no-eBPF mode",
		},
		{
			name: "from entities",
			cnp: &ciliumv2.CiliumNetworkPolicy{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "entities", Namespace: "frontend"},
				Spec: &policyapi.Rule{
					EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}},
					Ingress: []policyapi.IngressRule{{
						IngressCommonRule: policyapi.IngressCommonRule{
							FromEntities: []policyapi.Entity{policyapi.EntityWorld},
						},
						ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "80", Protocol: policyapi.ProtoTCP}}}},
					}},
				},
			},
			want: "fromEntities are not supported in no-eBPF mode",
		},
		{
			name: "from groups",
			cnp: &ciliumv2.CiliumNetworkPolicy{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "groups", Namespace: "frontend"},
				Spec: &policyapi.Rule{
					EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}},
					Ingress: []policyapi.IngressRule{{
						IngressCommonRule: policyapi.IngressCommonRule{
							FromGroups: []policyapi.Groups{{AWS: &policyapi.AWSGroup{Labels: map[string]string{"team": "blue"}}}},
						},
						ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "80", Protocol: policyapi.ProtoTCP}}}},
					}},
				},
			},
			want: "fromGroups are not supported in no-eBPF mode",
		},
		{
			name: "to groups",
			cnp: &ciliumv2.CiliumNetworkPolicy{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "egress-groups", Namespace: "frontend"},
				Spec: &policyapi.Rule{
					EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}},
					Egress: []policyapi.EgressRule{{
						EgressCommonRule: policyapi.EgressCommonRule{
							ToGroups: []policyapi.Groups{{AWS: &policyapi.AWSGroup{SecurityGroupsIds: []string{"sg-12345678"}}}},
						},
						ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "80", Protocol: policyapi.ProtoTCP}}}},
					}},
				},
			},
			want: "toGroups are not supported in no-eBPF mode",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PoliciesFromCiliumNetworkPolicies(
				[]k8sTables.LocalPod{{Pod: client}},
				[]*corev1.Pod{client},
				[]k8sTables.Namespace{{Name: "frontend"}},
				[]*ciliumv2.CiliumNetworkPolicy{tc.cnp},
			)
			require.ErrorContains(t, err, tc.want)
		})
	}
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

func TestPoliciesFromCiliumNetworkPoliciesMatchExpressionsNotIn(t *testing.T) {
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.5.10"}}},
	}
	backendClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client-a", Namespace: "backend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.5.20"}}},
	}
	frontendClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client-b", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.5.30"}}},
	}

	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "not-in", Namespace: "backend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{
						MatchLabels: map[string]string{"app": "client"},
						MatchExpressions: []slimmetav1.LabelSelectorRequirement{{
							Key:      "io.cilium.k8s.namespace.labels.team",
							Operator: slimmetav1.LabelSelectorOpNotIn,
							Values:   []string{"green"},
						}},
					}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "8080", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}

	policies, err := PoliciesFromCiliumNetworkPolicies(
		[]k8sTables.LocalPod{{Pod: server}},
		[]*corev1.Pod{server, backendClient, frontendClient},
		[]k8sTables.Namespace{{Name: "backend", Labels: map[string]string{"team": "green"}}, {Name: "frontend", Labels: map[string]string{"team": "blue"}}},
		[]*ciliumv2.CiliumNetworkPolicy{cnp},
	)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	require.NotContains(t, script, "10.244.5.20/32 ip daddr 10.244.5.10/32 tcp dport 8080 counter accept")
	require.Contains(t, script, "10.244.5.30/32 ip daddr 10.244.5.10/32 tcp dport 8080 counter accept")
}

func TestPoliciesFromCiliumNetworkPoliciesMatchExpressionsExistsAndDoesNotExist(t *testing.T) {
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.7.10"}}},
	}
	existsClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client-a", Namespace: "backend", Labels: map[string]string{"app": "client", "team": "blue"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.7.20"}}},
	}
	doesNotExistClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client-b", Namespace: "backend", Labels: map[string]string{"app": "client", "debug": "true"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.7.30"}}},
	}

	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "exists-does-not-exist", Namespace: "backend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}},
			Ingress: []policyapi.IngressRule{
				{
					IngressCommonRule: policyapi.IngressCommonRule{
						FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{
							MatchLabels: map[string]string{"app": "client"},
							MatchExpressions: []slimmetav1.LabelSelectorRequirement{{
								Key:      "team",
								Operator: slimmetav1.LabelSelectorOpExists,
							}},
						}}},
					},
					ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "8080", Protocol: policyapi.ProtoTCP}}}},
				},
				{
					IngressCommonRule: policyapi.IngressCommonRule{
						FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{
							MatchLabels: map[string]string{"app": "client"},
							MatchExpressions: []slimmetav1.LabelSelectorRequirement{{
								Key:      "debug",
								Operator: slimmetav1.LabelSelectorOpDoesNotExist,
							}},
						}}},
					},
					ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "8080", Protocol: policyapi.ProtoTCP}}}},
				},
			},
		},
	}

	policies, err := PoliciesFromCiliumNetworkPolicies(
		[]k8sTables.LocalPod{{Pod: server}},
		[]*corev1.Pod{server, existsClient, doesNotExistClient},
		[]k8sTables.Namespace{{Name: "backend"}},
		[]*ciliumv2.CiliumNetworkPolicy{cnp},
	)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	require.Contains(t, script, "ip saddr 10.244.7.20/32 ip daddr 10.244.7.10/32 tcp dport 8080 counter accept")
	require.NotContains(t, script, "ip saddr 10.244.7.30/32 ip daddr 10.244.7.10/32 tcp dport 8080 counter accept")
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

func TestControllerCNPReconciliationOnUpdateAndDelete(t *testing.T) {
	c := &controller{
		cnpCache: map[resource.Key]*ciliumv2.CiliumNetworkPolicy{},
	}
	key := resource.Key{Namespace: "default", Name: "p"}
	initial := &ciliumv2.CiliumNetworkPolicy{ObjectMeta: k8smetav1.ObjectMeta{Name: "p", Namespace: "default"}}
	updated := &ciliumv2.CiliumNetworkPolicy{ObjectMeta: k8smetav1.ObjectMeta{Name: "p", Namespace: "default", Labels: map[string]string{"version": "updated"}}}

	c.handleCNPEvent(resource.Event[*ciliumv2.CiliumNetworkPolicy]{Kind: resource.Upsert, Key: key, Object: initial, Done: func(error) {}})
	require.Len(t, c.cachedCNPs(), 1)
	require.Equal(t, "p", c.cachedCNPs()[0].Name)

	c.handleCNPEvent(resource.Event[*ciliumv2.CiliumNetworkPolicy]{Kind: resource.Upsert, Key: key, Object: updated, Done: func(error) {}})
	require.Len(t, c.cachedCNPs(), 1)
	require.Equal(t, "updated", c.cachedCNPs()[0].Labels["version"])

	c.handleCNPEvent(resource.Event[*ciliumv2.CiliumNetworkPolicy]{Kind: resource.Delete, Key: key, Done: func(error) {}})
	require.Empty(t, c.cachedCNPs())
}

func TestControllerCCNPReconciliationOnUpdateAndDelete(t *testing.T) {
	c := &controller{
		ccnpCache: map[resource.Key]*ciliumv2.CiliumClusterwideNetworkPolicy{},
	}
	key := resource.Key{Name: "p"}
	initial := &ciliumv2.CiliumClusterwideNetworkPolicy{ObjectMeta: k8smetav1.ObjectMeta{Name: "p"}}
	updated := &ciliumv2.CiliumClusterwideNetworkPolicy{ObjectMeta: k8smetav1.ObjectMeta{Name: "p", Labels: map[string]string{"version": "updated"}}}

	c.handleCCNPEvent(resource.Event[*ciliumv2.CiliumClusterwideNetworkPolicy]{Kind: resource.Upsert, Key: key, Object: initial, Done: func(error) {}})
	require.Len(t, c.cachedCCNPs(), 1)
	require.Equal(t, "p", c.cachedCCNPs()[0].Name)

	c.handleCCNPEvent(resource.Event[*ciliumv2.CiliumClusterwideNetworkPolicy]{Kind: resource.Upsert, Key: key, Object: updated, Done: func(error) {}})
	require.Len(t, c.cachedCCNPs(), 1)
	require.Equal(t, "updated", c.cachedCCNPs()[0].Labels["version"])

	c.handleCCNPEvent(resource.Event[*ciliumv2.CiliumClusterwideNetworkPolicy]{Kind: resource.Delete, Key: key, Done: func(error) {}})
	require.Empty(t, c.cachedCCNPs())
}
