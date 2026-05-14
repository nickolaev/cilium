// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCompileEndpointPolicyDualStack(t *testing.T) {
	server := Pod{Name: "server", Namespace: "default", Local: true, Labels: map[string]string{"app": "server"}, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.10"), netip.MustParseAddr("fd00:10:244:1::10")}}
	client := Pod{Name: "client", Namespace: "default", Labels: map[string]string{"role": "client", "team": "blue"}, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.20"), netip.MustParseAddr("fd00:10:244:1::20")}}

	policies := CompileEndpointPolicy(EndpointPolicySpec{
		Pod:         server,
		IngressDeny: true,
		IngressRules: []PolicyRule{{
			Peers: []Peer{{PodSelector: map[string]string{"role": "client"}}},
			Ports: []Port{{Protocol: ProtocolTCP, Port: 8080}},
		}},
	}, []Pod{client})

	if len(policies) != 2 {
		t.Fatalf("expected one policy per server IP, got %#v", policies)
	}
	script, err := Render(DesiredState{Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip saddr 10.244.1.20/32 ip daddr 10.244.1.10/32 tcp dport 8080 accept",
		"ip daddr 10.244.1.10 drop",
		"ip6 saddr fd00:10:244:1::20/128 ip6 daddr fd00:10:244:1::10/128 tcp dport 8080 accept",
		"ip6 daddr fd00:10:244:1::10 drop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in:\n%s", want, script)
		}
	}
}

func TestCompileEndpointPolicyIPBlockExceptExact(t *testing.T) {
	server := Pod{Name: "server", IPs: []netip.Addr{netip.MustParseAddr("10.244.1.10")}}
	policies := CompileEndpointPolicy(EndpointPolicySpec{
		Pod:         server,
		IngressDeny: true,
		IngressRules: []PolicyRule{{
			Peers: []Peer{{IPBlock: ptr(netip.MustParsePrefix("10.0.0.0/8")), Except: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}},
			Ports: []Port{{Protocol: ProtocolUDP, Port: 53}},
		}},
	}, nil)
	if len(policies) != 1 || len(policies[0].IngressAllow) != 0 {
		t.Fatalf("expected exact except to remove allow, got %#v", policies)
	}
}

func TestCompileEndpointPolicyEgressUsesEndpointAsSource(t *testing.T) {
	client := Pod{Name: "client", Namespace: "default", Local: true, Labels: map[string]string{"app": "client"}, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.20")}}
	server := Pod{Name: "server", Namespace: "default", Labels: map[string]string{"app": "server"}, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.10")}}

	policies := CompileEndpointPolicy(EndpointPolicySpec{
		Pod:        client,
		EgressDeny: true,
		EgressRules: []PolicyRule{{
			Peers: []Peer{{PodSelector: map[string]string{"app": "server"}}},
			Ports: []Port{{Protocol: ProtocolTCP, Port: 8080}},
		}},
	}, []Pod{server})

	script, err := Render(DesiredState{Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip saddr 10.244.1.20/32 ip daddr 10.244.1.10/32 tcp dport 8080 accept",
		"ip saddr 10.244.1.20 drop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in:\n%s", want, script)
		}
	}
}

func TestCompileEndpointPolicyNamespaceSelector(t *testing.T) {
	server := Pod{Name: "server", Namespace: "backend", Local: true, Labels: map[string]string{"app": "server"}, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.10")}}
	client := Pod{Name: "client", Namespace: "frontend", NamespaceLabels: map[string]string{"team": "blue"}, Labels: map[string]string{"app": "client"}, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.20")}}
	other := Pod{Name: "other", Namespace: "other", NamespaceLabels: map[string]string{"team": "red"}, Labels: map[string]string{"app": "client"}, IPs: []netip.Addr{netip.MustParseAddr("10.244.1.30")}}

	policies := CompileEndpointPolicy(EndpointPolicySpec{
		Pod:         server,
		IngressDeny: true,
		IngressRules: []PolicyRule{{
			Peers: []Peer{{NamespaceSelector: map[string]string{"team": "blue"}, PodSelector: map[string]string{"app": "client"}}},
		}},
	}, []Pod{client, other})

	script, err := Render(DesiredState{Policies: policies})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "ip saddr 10.244.1.20/32 ip daddr 10.244.1.10/32 accept") {
		t.Fatalf("missing namespace-selected client allow in:\n%s", script)
	}
	if strings.Contains(script, "10.244.1.30") {
		t.Fatalf("unexpected red namespace client allow in:\n%s", script)
	}
}

func TestCompileEndpointPolicyIPBlockPartialExcept(t *testing.T) {
	server := Pod{Name: "server", IPs: []netip.Addr{netip.MustParseAddr("10.244.1.10")}}
	policies := CompileEndpointPolicy(EndpointPolicySpec{
		Pod:         server,
		IngressDeny: true,
		IngressRules: []PolicyRule{{
			Peers: []Peer{{IPBlock: ptr(netip.MustParsePrefix("10.0.0.0/8")), Except: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}}},
		}},
	}, nil)
	if len(policies) != 1 || len(policies[0].IngressAllow) == 0 {
		t.Fatalf("expected partial except to produce residual prefixes, got %#v", policies)
	}
	for _, allow := range policies[0].IngressAllow {
		if allow.Source.Contains(netip.MustParseAddr("10.1.0.1")) {
			t.Fatalf("excepted address still allowed by %#v", allow.Source)
		}
	}
}
