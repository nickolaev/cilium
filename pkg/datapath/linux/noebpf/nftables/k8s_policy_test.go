// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"testing"

	intstr "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr"
	"github.com/stretchr/testify/require"

	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
)

func TestPoliciesFromK8sNetworkPolicies(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port80 := intstr.FromInt32(80)
	policies, err := PoliciesFromK8sNetworkPolicies([]k8sTables.LocalPod{
		{Pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "default", Labels: map[string]string{"app": "server"}},
			Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.0.10"}, {IP: "fd00:10:244::10"}}},
		}},
		{Pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "default", Labels: map[string]string{"app": "client"}},
			Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.0.20"}}},
		}},
	}, nil, nil, []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-client", Namespace: "default"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port80}},
			}},
		},
	}})
	require.NoError(t, err)
	require.Len(t, policies, 2)
	require.True(t, policies[0].IngressDeny)
	require.Len(t, policies[0].IngressAllow, 1)
	require.Equal(t, uint16(80), policies[0].IngressAllow[0].Port)

	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	require.Contains(t, script, "ip daddr 10.244.0.10 drop")
	require.Contains(t, script, "ip6 daddr fd00:10:244::10 drop")
	require.Contains(t, script, "tcp dport 80 accept")
}

func TestPoliciesFromK8sNetworkPoliciesNamespaceSelector(t *testing.T) {
	policies, err := PoliciesFromK8sNetworkPolicies([]k8sTables.LocalPod{
		{Pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "backend", Labels: map[string]string{"app": "server"}},
			Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.0.10"}}},
		}},
		{Pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "frontend", Labels: map[string]string{"app": "client"}},
			Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.0.20"}}},
		}},
	}, nil, []k8sTables.Namespace{
		{Name: "frontend", Labels: map[string]string{"team": "blue"}},
		{Name: "backend", Labels: map[string]string{"team": "green"}},
	}, []*networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-frontend", Namespace: "backend"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "blue"}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				}},
			}},
		},
	}})
	require.NoError(t, err)
	script, err := Render(DesiredState{Policies: policies})
	require.NoError(t, err)
	require.Contains(t, script, "ip saddr 10.244.0.20/32 ip daddr 10.244.0.10/32 accept")
}
