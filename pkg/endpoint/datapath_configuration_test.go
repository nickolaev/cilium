// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"testing"

	"github.com/stretchr/testify/require"

	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/option"
)

func TestNewDatapathConfigurationLinuxRouteDoesNotRequireEndpointPrograms(t *testing.T) {
	oldEndpointRoutes := option.Config.EnableEndpointRoutes
	oldDatapathMode := option.Config.DatapathMode
	t.Cleanup(func() {
		option.Config.EnableEndpointRoutes = oldEndpointRoutes
		option.Config.DatapathMode = oldDatapathMode
	})

	option.Config.EnableEndpointRoutes = true
	option.Config.DatapathMode = datapathOption.DatapathModeLinuxRoute

	cfg := NewDatapathConfiguration()
	require.True(t, cfg.InstallEndpointRoute)
	require.False(t, cfg.RequireEgressProg)
	require.NotNil(t, cfg.RequireRouting)
	require.False(t, *cfg.RequireRouting)
}

func TestNewDatapathConfigurationEndpointRoutesStillRequireEndpointPrograms(t *testing.T) {
	oldEndpointRoutes := option.Config.EnableEndpointRoutes
	oldDatapathMode := option.Config.DatapathMode
	t.Cleanup(func() {
		option.Config.EnableEndpointRoutes = oldEndpointRoutes
		option.Config.DatapathMode = oldDatapathMode
	})

	option.Config.EnableEndpointRoutes = true
	option.Config.DatapathMode = datapathOption.DatapathModeVeth

	cfg := NewDatapathConfiguration()
	require.True(t, cfg.InstallEndpointRoute)
	require.True(t, cfg.RequireEgressProg)
	require.NotNil(t, cfg.RequireRouting)
	require.False(t, *cfg.RequireRouting)
}
