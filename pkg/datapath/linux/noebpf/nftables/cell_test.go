// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"strings"
	"testing"

	intstr "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr"
	"github.com/stretchr/testify/require"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	policyapi "github.com/cilium/cilium/pkg/policy/api"

	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDesiredStateHonorsBackendGates(t *testing.T) {
	mixedFamilyFrontend := frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.TCP, "10.245.0.10", 80,
		backend(loadbalancer.TCP, "fd00:10:244:1::10", 8080))

	state, err := desiredState([]*loadbalancer.Frontend{mixedFamilyFrontend}, nil, nil, nil, nil, nil, nil, nil, false, false)
	require.NoError(t, err)
	require.Empty(t, state.Services)
	require.Empty(t, state.Policies)

	_, err = desiredState([]*loadbalancer.Frontend{mixedFamilyFrontend}, nil, nil, nil, nil, nil, nil, nil, true, false)
	require.Error(t, err)
}

func TestDesiredStateIncludesCiliumPolicies(t *testing.T) {
	serverA := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server-a", Namespace: "backend", Labels: map[string]string{"app": "server-a"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.10.10"}}},
	}
	serverB := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server-b", Namespace: "frontend", Labels: map[string]string{"app": "server-b"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.10.20"}}},
	}
	backendClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client-a", Namespace: "backend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.10.25"}}},
	}
	frontendClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.10.30"}}},
	}

	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "backend-allow", Namespace: "backend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server-a"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "8080", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}
	ccnp := &ciliumv2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "frontend-allow"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server-b"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "9090", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}

	state, err := desiredState(
		nil,
		[]k8sTables.LocalPod{{Pod: serverA}, {Pod: serverB}},
		[]*corev1.Pod{serverA, serverB, backendClient, frontendClient},
		[]k8sTables.Namespace{{Name: "backend"}, {Name: "frontend"}},
		nil,
		[]*ciliumv2.CiliumNetworkPolicy{cnp},
		[]*ciliumv2.CiliumClusterwideNetworkPolicy{ccnp},
		nil,
		false,
		true,
	)
	require.NoError(t, err)
	require.Len(t, state.Policies, 2)

	script, err := Render(state)
	require.NoError(t, err)
	require.Contains(t, script, "ip saddr 10.244.10.25/32 ip daddr 10.244.10.10/32 tcp dport 8080 counter accept")
	require.Contains(t, script, "ip saddr 10.244.10.30/32 ip daddr 10.244.10.20/32 tcp dport 9090 counter accept")
}

func TestDesiredStateMixesKNPAndCiliumPolicies(t *testing.T) {
	backendServer := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "backend-server", Namespace: "backend", Labels: map[string]string{"app": "backend-server"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.11.10"}}},
	}
	frontendServer := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "frontend-server", Namespace: "frontend", Labels: map[string]string{"app": "frontend-server"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.11.20"}}},
	}
	crossServer := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "cross-server", Namespace: "other", Labels: map[string]string{"app": "cross-server"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.11.30"}}},
	}
	backendClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "backend-client", Namespace: "backend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.11.40"}}},
	}
	frontendClient := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "frontend-client", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.11.50"}}},
	}
	port8080 := intstr.FromInt32(8080)
	tcp := corev1.ProtocolTCP

	knp := &networkingv1.NetworkPolicy{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "backend-allow", Namespace: "backend"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "backend-server"}},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{{PodSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
				Ports: []networkingv1.NetworkPolicyPort{{Port: &port8080, Protocol: &tcp}},
			}},
		},
	}
	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "frontend-allow", Namespace: "frontend"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend-server"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "9090", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}
	ccnp := &ciliumv2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "cross-allow"},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "cross-server"}}},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{{LabelSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
				},
				ToPorts: []policyapi.PortRule{{Ports: []policyapi.PortProtocol{{Port: "7070", Protocol: policyapi.ProtoTCP}}}},
			}},
		},
	}

	state, err := desiredState(
		nil,
		[]k8sTables.LocalPod{{Pod: backendServer}, {Pod: frontendServer}, {Pod: crossServer}},
		[]*corev1.Pod{backendServer, frontendServer, crossServer, backendClient, frontendClient},
		[]k8sTables.Namespace{{Name: "backend"}, {Name: "frontend"}, {Name: "other"}},
		[]*networkingv1.NetworkPolicy{knp},
		[]*ciliumv2.CiliumNetworkPolicy{cnp},
		[]*ciliumv2.CiliumClusterwideNetworkPolicy{ccnp},
		nil,
		false,
		true,
	)
	require.NoError(t, err)
	require.Len(t, state.Policies, 3)

	script, err := Render(state)
	require.NoError(t, err)
	require.Contains(t, script, "ip saddr 10.244.11.40/32 ip daddr 10.244.11.10/32 tcp dport 8080 counter accept")
	require.Contains(t, script, "ip saddr 10.244.11.50/32 ip daddr 10.244.11.20/32 tcp dport 9090 counter accept")
	require.Contains(t, script, "ip saddr 10.244.11.50/32 ip daddr 10.244.11.30/32 tcp dport 7070 counter accept")
}

func TestDesiredStatePrefersCiliumDenyOverKNPAllow(t *testing.T) {
	server := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.12.10"}}},
	}
	client := &corev1.Pod{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "client", Namespace: "backend", Labels: map[string]string{"app": "client"}},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.12.20"}}},
	}
	port8080 := intstr.FromInt32(8080)
	tcp := corev1.ProtocolTCP

	knp := &networkingv1.NetworkPolicy{
		ObjectMeta: slimmetav1.ObjectMeta{Name: "allow-client", Namespace: "backend"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{{PodSelector: &slimmetav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
				Ports: []networkingv1.NetworkPolicyPort{{Port: &port8080, Protocol: &tcp}},
			}},
		},
	}
	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "deny-client", Namespace: "backend"},
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

	state, err := desiredState(
		nil,
		[]k8sTables.LocalPod{{Pod: server}},
		[]*corev1.Pod{server, client},
		[]k8sTables.Namespace{{Name: "backend"}},
		[]*networkingv1.NetworkPolicy{knp},
		[]*ciliumv2.CiliumNetworkPolicy{cnp},
		nil,
		nil,
		false,
		true,
	)
	require.NoError(t, err)
	require.Len(t, state.Policies, 2)

	script, err := Render(state)
	require.NoError(t, err)
	denyIdx := strings.Index(script, "ip saddr 10.244.12.20/32 ip daddr 10.244.12.10/32 tcp dport 8080 counter drop")
	allowIdx := strings.Index(script, "ip saddr 10.244.12.20/32 ip daddr 10.244.12.10/32 tcp dport 8080 counter accept")
	require.NotEqual(t, -1, denyIdx, script)
	require.NotEqual(t, -1, allowIdx, script)
	require.Less(t, denyIdx, allowIdx, script)
}
