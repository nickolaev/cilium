// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/option"
)

func TestGetNoEBPFStatus(t *testing.T) {
	sc := &statusCollector{
		statusParams: statusParams{
			DaemonConfig: &option.DaemonConfig{},
		},
	}

	status := sc.getNoEBPFStatus()
	if status == nil {
		t.Fatal("expected no-eBPF status to be populated")
	}
	if status.Enabled {
		t.Fatal("expected no-eBPF status disabled by default")
	}
	if len(status.Capabilities) == 0 {
		t.Fatal("expected no-eBPF capabilities to be advertised")
	}
}

func TestGetNoEBPFAnnotations(t *testing.T) {
	sc := &statusCollector{
		statusParams: statusParams{
			DaemonConfig: &option.DaemonConfig{
				EnableNoEBPFServices:      true,
				EnableNoEBPFNetworkPolicy: true,
			},
		},
	}

	annotations := sc.getNoEBPFAnnotations()
	if len(annotations) == 0 {
		t.Fatal("expected no-eBPF annotations to be populated")
	}
	joined := strings.Join(annotations, "\n")
	for _, want := range []string{
		"service backend: enabled",
		"network-policy backend: enabled",
		"Pod networking: supported",
		"Endpoint routes: supported",
		"ClusterIP Services: supported-subset",
		"LocalRedirectPolicy: supported-subset",
		"Kubernetes NetworkPolicy: supported-subset",
		"NetworkPolicy named ports and endPort: supported-subset",
		"CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy: unsupported",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected annotations to include %q, got:\n%s", want, joined)
		}
	}
}
