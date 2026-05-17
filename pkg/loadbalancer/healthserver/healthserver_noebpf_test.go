// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthserver

import (
	"testing"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestShouldRunNoEBPFServices(t *testing.T) {
	s := &healthServer{
		params: healthServerParams{
			Config: loadbalancer.Config{
				UserConfig: loadbalancer.UserConfig{
					EnableHealthCheckNodePort: true,
				},
			},
			ExtConfig: loadbalancer.ExternalConfig{
				EnableNoEBPFServices: true,
			},
		},
	}

	if !s.shouldRun() {
		t.Fatal("expected health server to run in no-eBPF services mode")
	}
}

func TestShouldRunRequiresHealthCheckNodePort(t *testing.T) {
	s := &healthServer{
		params: healthServerParams{
			Config: loadbalancer.Config{
				UserConfig: loadbalancer.UserConfig{
					EnableHealthCheckNodePort: false,
				},
			},
			ExtConfig: loadbalancer.ExternalConfig{
				EnableNoEBPFServices: true,
			},
		},
	}

	if s.shouldRun() {
		t.Fatal("expected health server to stay disabled when health checks are off")
	}
}
