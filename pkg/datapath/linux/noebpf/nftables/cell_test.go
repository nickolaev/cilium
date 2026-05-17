// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"testing"

	"github.com/stretchr/testify/require"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	policyapi "github.com/cilium/cilium/pkg/policy/api"

	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDesiredStateHonorsBackendGates(t *testing.T) {
	mixedFamilyFrontend := frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.TCP, "10.245.0.10", 80,
		backend(loadbalancer.TCP, "fd00:10:244:1::10", 8080))

	state, err := desiredState([]*loadbalancer.Frontend{mixedFamilyFrontend}, nil, nil, nil, nil, nil, nil, false, false)
	require.NoError(t, err)
	require.Empty(t, state.Services)
	require.Empty(t, state.Policies)

	_, err = desiredState([]*loadbalancer.Frontend{mixedFamilyFrontend}, nil, nil, nil, nil, nil, nil, true, false)
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
