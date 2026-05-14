// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEndpointRoutePrefixIsExactHostRoute(t *testing.T) {
	require.Equal(t,
		netip.MustParsePrefix("10.0.0.42/32"),
		endpointRoutePrefix(netip.MustParseAddr("10.0.0.42")),
	)
	require.Equal(t,
		netip.MustParsePrefix("fd00::42/128"),
		endpointRoutePrefix(netip.MustParseAddr("fd00::42")),
	)
}

func TestRouteOnlySysctlSettings(t *testing.T) {
	withoutIPv6 := routeOnlySysctlSettings(false)
	require.Len(t, withoutIPv6, 3)
	require.Equal(t, []string{"net", "ipv4", "conf", "all", "rp_filter"}, withoutIPv6[0].Name)
	require.Equal(t, "0", withoutIPv6[0].Val)

	withIPv6 := routeOnlySysctlSettings(true)
	require.Len(t, withIPv6, 4)
	require.Equal(t, []string{"net", "ipv6", "conf", "all", "disable_ipv6"}, withIPv6[3].Name)
	require.Equal(t, "0", withIPv6[3].Val)
}
