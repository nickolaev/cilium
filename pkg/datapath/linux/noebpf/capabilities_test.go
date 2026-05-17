// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package noebpf

import "testing"

func TestCurrentCapabilities(t *testing.T) {
	got := CurrentCapabilities()
	if len(got) < 20 {
		t.Fatalf("expected a fine-grained capability matrix, got %d entries", len(got))
	}
	mustHave := map[string]SupportLevel{
		"Pod networking":                        SupportLevelSupported,
		"Endpoint routes":                       SupportLevelSupported,
		"ClusterIP Services":                    SupportLevelSupportedSubset,
		"LoadBalancer Services":                 SupportLevelSupportedSubset,
		"CoreDNS Service":                       SupportLevelSupported,
		"LocalRedirectPolicy":                   SupportLevelSupportedSubset,
		"Kubernetes NetworkPolicy":              SupportLevelSupportedSubset,
		"NetworkPolicy named ports and endPort": SupportLevelSupportedSubset,
		"CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy": SupportLevelSupportedSubset,
		"Cilium deny policies":                                 SupportLevelSupportedSubset,
		"Hubble datapath flow events":                          SupportLevelUnsupported,
	}
	for name, want := range mustHave {
		if level, ok := CapabilityStatus(name); !ok || level != want {
			t.Fatalf("unexpected capability status for %q: level=%q ok=%v want=%q", name, level, ok, want)
		}
	}
	if _, ok := CapabilityStatus("does-not-exist"); ok {
		t.Fatal("expected unknown capability lookup to fail")
	}
}
