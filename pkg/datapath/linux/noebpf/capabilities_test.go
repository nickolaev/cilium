// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package noebpf

import "testing"

func TestCurrentCapabilities(t *testing.T) {
	got := CurrentCapabilities()
	if len(got) == 0 {
		t.Fatal("expected capabilities to be populated")
	}
	if level, ok := CapabilityStatus("LoadBalancer Services"); !ok || level != SupportLevelSupportedSubset {
		t.Fatalf("unexpected LoadBalancer capability status: %v %v", level, ok)
	}
	if level, ok := CapabilityStatus("LocalRedirectPolicy"); !ok || level != SupportLevelSupportedSubset {
		t.Fatalf("unexpected LocalRedirectPolicy capability status: %v %v", level, ok)
	}
	if level, ok := CapabilityStatus("Service topology-aware hints"); !ok || level != SupportLevelSupportedSubset {
		t.Fatalf("unexpected service topology capability status: %v %v", level, ok)
	}
	if level, ok := CapabilityStatus("Kubernetes NetworkPolicy"); !ok || level != SupportLevelSupportedSubset {
		t.Fatalf("unexpected NetworkPolicy capability status: %v %v", level, ok)
	}
	if _, ok := CapabilityStatus("does-not-exist"); ok {
		t.Fatal("expected unknown capability lookup to fail")
	}
}
