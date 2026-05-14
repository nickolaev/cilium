// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestDesiredStateHonorsBackendGates(t *testing.T) {
	mixedFamilyFrontend := frontend(loadbalancer.SVCTypeClusterIP, loadbalancer.TCP, "10.245.0.10", 80,
		backend(loadbalancer.TCP, "fd00:10:244:1::10", 8080))

	state, err := desiredState([]*loadbalancer.Frontend{mixedFamilyFrontend}, nil, nil, nil, nil, false, false)
	require.NoError(t, err)
	require.Empty(t, state.Services)
	require.Empty(t, state.Policies)

	_, err = desiredState([]*loadbalancer.Frontend{mixedFamilyFrontend}, nil, nil, nil, nil, true, false)
	require.Error(t, err)
}
