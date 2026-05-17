// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package noebpf

// SupportLevel describes the current maturity of a no-eBPF capability.
type SupportLevel string

const (
	SupportLevelSupported       SupportLevel = "supported"
	SupportLevelSupportedSubset SupportLevel = "supported-subset"
	SupportLevelPlanned         SupportLevel = "planned"
	SupportLevelUnsupported     SupportLevel = "unsupported"
)

// Capability describes one user-visible no-eBPF feature boundary.
type Capability struct {
	Name  string
	Level SupportLevel
	Notes string
}

// CurrentCapabilities returns the current machine-readable support matrix for
// the linux-route / no-eBPF branch. Keep this in lockstep with docs, Helm
// validation, and the local CI smoke scripts.
func CurrentCapabilities() []Capability {
	return []Capability{
		{Name: "Pod networking", Level: SupportLevelSupported, Notes: "Linux routes, endpoint routes, dual-stack pod connectivity"},
		{Name: "ClusterIP Services", Level: SupportLevelSupportedSubset, Notes: "IPv4/IPv6, TCP/UDP/SCTP, multiple backends, endpoint cleanup"},
		{Name: "NodePort Services", Level: SupportLevelSupportedSubset, Notes: "Wildcard NodePort support with IPv4/IPv6 and session affinity"},
		{Name: "LoadBalancer Services", Level: SupportLevelSupportedSubset, Notes: "Frontends, source ranges, session affinity, healthCheckNodePort, LocalRedirect, topology-aware backend selection"},
		{Name: "ExternalIP Services", Level: SupportLevelSupportedSubset, Notes: "Translated through nftables with source-range filtering"},
		{Name: "LocalRedirectPolicy", Level: SupportLevelSupportedSubset, Notes: "CiliumLocalRedirectPolicy creates LocalRedirect frontends and local-backend pseudo-services"},
		{Name: "Service topology-aware hints", Level: SupportLevelSupportedSubset, Notes: "PreferSameNode/PreferSameZone backends are honored by the loadbalancer writer when enabled"},
		{Name: "Kubernetes NetworkPolicy", Level: SupportLevelSupportedSubset, Notes: "matchExpressions, named ports, endPort, SCTP, ipBlock except"},
		{Name: "Cilium policy extensions", Level: SupportLevelUnsupported, Notes: "CNP, L7, DNS/FQDN, identities"},
		{Name: "BPF masquerade", Level: SupportLevelUnsupported, Notes: "No eBPF datapath features"},
		{Name: "Host firewall", Level: SupportLevelUnsupported, Notes: "No eBPF datapath features"},
		{Name: "Hubble datapath flows", Level: SupportLevelUnsupported, Notes: "No eBPF datapath features"},
	}
}

// CapabilityStatus returns the configured support level for the named
// capability.
func CapabilityStatus(name string) (SupportLevel, bool) {
	for _, cap := range CurrentCapabilities() {
		if cap.Name == name {
			return cap.Level, true
		}
	}
	return "", false
}
