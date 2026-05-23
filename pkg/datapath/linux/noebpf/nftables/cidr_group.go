// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"net/netip"
	"sort"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type cidrGroupInfo struct {
	name   string
	labels map[string]string
	cidrs  []netip.Prefix
}

type cidrGroupIndex struct {
	byName map[string]cidrGroupInfo
	all    []cidrGroupInfo
}

func newCIDRGroupIndex(groups []*ciliumv2.CiliumCIDRGroup) cidrGroupIndex {
	idx := cidrGroupIndex{
		byName: make(map[string]cidrGroupInfo, len(groups)),
		all:    make([]cidrGroupInfo, 0, len(groups)),
	}
	for _, group := range groups {
		if group == nil {
			continue
		}
		info := cidrGroupInfo{
			name:   group.Name,
			labels: cidrGroupLabels(group),
		}
		for _, cidr := range group.Spec.ExternalCIDRs {
			prefix, err := netip.ParsePrefix(string(cidr))
			if err != nil {
				continue
			}
			info.cidrs = append(info.cidrs, prefix)
		}
		if len(info.cidrs) == 0 {
			continue
		}
		idx.byName[info.name] = info
		idx.all = append(idx.all, info)
	}
	sort.Slice(idx.all, func(i, j int) bool { return idx.all[i].name < idx.all[j].name })
	return idx
}

func cidrGroupLabels(group *ciliumv2.CiliumCIDRGroup) map[string]string {
	labels := make(map[string]string, len(group.Labels)+1)
	for k, v := range group.Labels {
		labels[k] = v
	}
	labels["io.cilium.policy.cidrgroupname/"+group.Name] = ""
	return labels
}

func (idx cidrGroupIndex) prefixesForRef(ref string) []netip.Prefix {
	group, ok := idx.byName[ref]
	if !ok {
		return nil
	}
	return append([]netip.Prefix(nil), group.cidrs...)
}

func (idx cidrGroupIndex) prefixesForSelector(selector *LabelSelector) []netip.Prefix {
	if selector == nil {
		return nil
	}
	var out []netip.Prefix
	for _, group := range idx.all {
		if !selectorMatches(group.labels, selector) {
			continue
		}
		out = append(out, group.cidrs...)
	}
	return uniquePrefixes(out)
}

func uniquePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() == out[j].Addr() {
			return out[i].Bits() < out[j].Bits()
		}
		return out[i].Addr().Less(out[j].Addr())
	})
	return out
}
