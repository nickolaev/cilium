// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"log/slog"
	"maps"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

var (
	benchmarkExternalConfig = loadbalancer.ExternalConfig{
		EnableIPv4:           true,
		EnableIPv6:           true,
		KubeProxyReplacement: true,
	}
)

func BenchmarkConvertService(b *testing.B) {
	obj, err := testutils.DecodeFile("../benchmark/testdata/service.yaml")
	if err != nil {
		panic(err)
	}
	svc := obj.(*slim_corev1.Service)

	for b.Loop() {
		convertService(loadbalancer.DefaultConfig, benchmarkExternalConfig, slog.New(slog.DiscardHandler), nil, svc, source.Kubernetes)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "services/sec")
}

func BenchmarkParseEndpointSlice(b *testing.B) {
	obj, err := testutils.DecodeFile("../benchmark/testdata/endpointslice.yaml")
	if err != nil {
		panic(err)
	}
	epSlice := obj.(*slim_discovery_v1.EndpointSlice)
	logger := hivetest.Logger(b)

	for b.Loop() {
		k8s.ParseEndpointSliceV1(logger, epSlice)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "endpointslices/sec")
}

func BenchmarkConvertEndpoints(b *testing.B) {
	obj, err := testutils.DecodeFile("../benchmark/testdata/endpointslice.yaml")
	if err != nil {
		panic(err)
	}
	epSlice := obj.(*slim_discovery_v1.EndpointSlice)
	logger := hivetest.Logger(b)
	eps := k8s.ParseEndpointSliceV1(logger, epSlice)
	backends := maps.All(eps.Backends)

	for b.Loop() {
		convertEndpoints(logger, benchmarkExternalConfig, eps.ServiceName, backends)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "endpoints/sec")
}

func TestConvertServiceReflectsNodePortForNoEBPFServices(t *testing.T) {
	svc := &slim_corev1.Service{
		Spec: slim_corev1.ServiceSpec{
			Type:       slim_corev1.ServiceTypeNodePort,
			ClusterIPs: []string{"10.96.0.10", "fd00:10:96::a"},
			IPFamilies: []slim_corev1.IPFamily{
				slim_corev1.IPv4Protocol,
				slim_corev1.IPv6Protocol,
			},
			Ports: []slim_corev1.ServicePort{{
				Name:     "http",
				Protocol: slim_corev1.ProtocolTCP,
				Port:     80,
				NodePort: 30080,
			}},
		},
	}

	_, frontends := convertService(loadbalancer.DefaultConfig, loadbalancer.ExternalConfig{
		EnableIPv4:           true,
		EnableIPv6:           true,
		EnableNoEBPFServices: true,
	}, slog.New(slog.DiscardHandler), nil, svc, source.Kubernetes)

	var nodePorts int
	for _, frontend := range frontends {
		if frontend.Type == loadbalancer.SVCTypeNodePort {
			nodePorts++
		}
	}
	if nodePorts != 2 {
		t.Fatalf("expected IPv4 and IPv6 NodePort frontends, got %d in %#v", nodePorts, frontends)
	}
}
