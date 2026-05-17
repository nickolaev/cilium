// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package noebpf

import "fmt"

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

// Annotation returns the capability in a status-friendly format.
func (c Capability) Annotation() string {
	if c.Notes == "" {
		return fmt.Sprintf("No-eBPF %s: %s", c.Name, c.Level)
	}
	return fmt.Sprintf("No-eBPF %s: %s (%s)", c.Name, c.Level, c.Notes)
}

// CurrentCapabilities returns the current machine-readable support matrix for
// the linux-route / no-eBPF branch. Keep this in lockstep with docs, Helm
// validation, and the local CI smoke scripts.
func CurrentCapabilities() []Capability {
	return []Capability{
		{Name: "Pod networking", Level: SupportLevelSupported, Notes: "linux-route pod attachment and IPv4/IPv6 pod reachability"},
		{Name: "Endpoint routes", Level: SupportLevelSupported, Notes: "per-endpoint host routes are installed for workloads"},
		{Name: "Dual-stack pod connectivity", Level: SupportLevelSupported, Notes: "IPv4 and IPv6 pod addressing and forwarding"},
		{Name: "Cilium-owned nftables table lifecycle", Level: SupportLevelSupported, Notes: "startup cleanup and atomic replacement of inet cilium_noebpf"},
		{Name: "ClusterIP Services", Level: SupportLevelSupportedSubset, Notes: "IPv4/IPv6 VIP DNAT for TCP/UDP/SCTP services"},
		{Name: "NodePort Services", Level: SupportLevelSupportedSubset, Notes: "wildcard NodePort frontends for IPv4/IPv6 TCP/UDP/SCTP"},
		{Name: "LoadBalancer Services", Level: SupportLevelSupportedSubset, Notes: "VIP DNAT for IPv4/IPv6 load balancer services"},
		{Name: "ExternalIP Services", Level: SupportLevelSupportedSubset, Notes: "nftables translation for external IP frontends"},
		{Name: "CoreDNS Service", Level: SupportLevelSupported, Notes: "validated as a ClusterIP UDP lookup in the dual-stack profile"},
		{Name: "Service source-range filtering", Level: SupportLevelSupportedSubset, Notes: "check-source-range rules on service frontends"},
		{Name: "Service session affinity", Level: SupportLevelSupportedSubset, Notes: "service affinity is honored when enabled"},
		{Name: "HealthCheckNodePort", Level: SupportLevelSupportedSubset, Notes: "local health server frontends for LoadBalancer services"},
		{Name: "Traffic policy Local", Level: SupportLevelSupportedSubset, Notes: "local-backend selection for externalTrafficPolicy=Local"},
		{Name: "Service topology-aware hints", Level: SupportLevelSupportedSubset, Notes: "prefer same-node and same-zone backends when enabled"},
		{Name: "Service reconciliation", Level: SupportLevelSupported, Notes: "EndpointSlice updates, deletion cleanup, and restart rebuild the desired state"},
		{Name: "LocalRedirectPolicy", Level: SupportLevelSupportedSubset, Notes: "local redirect frontends and pseudo-services backed by local pods"},
		{Name: "Kubernetes NetworkPolicy", Level: SupportLevelSupportedSubset, Notes: "standard ingress/egress default deny"},
		{Name: "NetworkPolicy selectors", Level: SupportLevelSupportedSubset, Notes: "namespace selectors, pod selectors, and combined selectors"},
		{Name: "NetworkPolicy matchExpressions", Level: SupportLevelSupportedSubset, Notes: "label selector expressions with Exists/In/NotIn"},
		{Name: "NetworkPolicy named ports and endPort", Level: SupportLevelSupportedSubset, Notes: "named ports and port ranges"},
		{Name: "NetworkPolicy ipBlock except", Level: SupportLevelSupportedSubset, Notes: "CIDR exclusions on ingress and egress peers"},
		{Name: "NetworkPolicy protocol coverage", Level: SupportLevelSupportedSubset, Notes: "TCP/UDP/SCTP policy ports"},
		{Name: "CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy", Level: SupportLevelSupportedSubset, Notes: "L3/L4 allow rules, selectors, named ports, endPort, and ipBlock"},
		{Name: "Cilium deny policies", Level: SupportLevelSupportedSubset, Notes: "L3/L4 ingressDeny and egressDeny rules"},
		{Name: "Cilium TC/XDP forwarding programs", Level: SupportLevelUnsupported, Notes: "no eBPF workload or native-device forwarding programs"},
		{Name: "L7 policy", Level: SupportLevelUnsupported, Notes: "HTTP, Kafka, TLS, and other proxy-layer policy is unavailable"},
		{Name: "DNS/FQDN policy", Level: SupportLevelUnsupported, Notes: "DNS rule semantics are not implemented"},
		{Name: "Identity-aware policy entities", Level: SupportLevelUnsupported, Notes: "entity selectors and identity-aware semantics are unavailable"},
		{Name: "Socket LB", Level: SupportLevelUnsupported, Notes: "no eBPF socket-level service lookup"},
		{Name: "Host firewall", Level: SupportLevelUnsupported, Notes: "node-level policy enforcement is not part of this path"},
		{Name: "BPF masquerade", Level: SupportLevelUnsupported, Notes: "no eBPF SNAT / masquerading"},
		{Name: "Transparent encryption", Level: SupportLevelUnsupported, Notes: "WireGuard/IPsec datapath encryption is out of scope"},
		{Name: "Hubble datapath flow events", Level: SupportLevelUnsupported, Notes: "no eBPF flow visibility"},
		{Name: "Bandwidth manager", Level: SupportLevelUnsupported, Notes: "no eBPF egress shaping"},
		{Name: "Egress gateway", Level: SupportLevelUnsupported, Notes: "no eBPF egress gateway steering"},
		{Name: "XDP acceleration", Level: SupportLevelUnsupported, Notes: "no XDP program attach"},
	}
}

// CurrentAnnotations returns the no-eBPF status annotations used in
// cilium-dbg status output.
func CurrentAnnotations(servicesEnabled, networkPolicyEnabled bool) []string {
	annotations := []string{"No-eBPF datapath: linux-route (experimental)"}
	if servicesEnabled {
		annotations = append(annotations, "No-eBPF service backend: enabled")
	} else {
		annotations = append(annotations, "No-eBPF service backend: disabled")
	}
	if networkPolicyEnabled {
		annotations = append(annotations, "No-eBPF network-policy backend: enabled")
	} else {
		annotations = append(annotations, "No-eBPF network-policy backend: disabled")
	}

	for _, cap := range CurrentCapabilities() {
		annotations = append(annotations, cap.Annotation())
	}
	return annotations
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
