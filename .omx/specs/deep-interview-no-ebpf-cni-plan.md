# Deep Interview Spec — Cilium no-eBPF CNI product-demo path

Date: 2026-05-10
Repo: `/home/nickolaev/workspace/cilium`
Branch: `no-ebpf`
Profile: standard deep-interview
Final ambiguity: ~14%

## Intent
Advance the experimental Cilium no-eBPF / `linux-route` datapath from a mostly-working prototype into a credible product-demo baseline, with an 80/20 implementation plan that covers the common Kubernetes CNI experience without chasing the full Cilium eBPF feature surface.

## Current local evidence
- Branch contains a new experimental `bpf.datapathMode=linux-route` mode.
- Existing no-eBPF test values: `contrib/testing/kind-no-ebpf.yaml`.
- Current mode is route-only: workload veths plus Linux routes instead of Cilium TC/XDP forwarding programs.
- Current validation/docs intentionally disable or reject several eBPF-dependent features: BPF masquerade, BPF TProxy/L7 proxy, tracing, XDP prefilter, host firewall, socket LB, Cilium KPR, policy enforcement.
- Route-only loader code already detaches TC programs, creates endpoint routes for IPv4/IPv6, disables socketLB, and keeps Cilium status/feature reporting aware of `linux-route`.

## External grounding
- Kubernetes requires a CNI plugin to implement the Kubernetes network model and recommends CNI spec v1.0.0 compatibility while requiring v0.4.0+ compatibility.
- CNCF Kubernetes conformance is distribution/platform oriented and uses Sonobuoy-submitted conformance results; this is not exactly a standalone “CNI certification”.
- Kubernetes dual-stack requires CNI support for dual-stack Pods, IPv4+IPv6 Services, and egress routing for both families.
- CNI itself is scoped to container network connectivity and cleanup, so policy and service replacement are product/Kubernetes behavior targets beyond core CNI ADD/DEL semantics.

## Target product shape
“2.75” between conformance and Cilium-lite product, closer to product.

Milestone 1 should be a **product demo baseline**:
- kind/demo cluster installs cleanly.
- Pods receive dual-stack IPv4 and IPv6 addresses.
- Same-node and cross-node pod connectivity works for IPv4 and IPv6.
- DNS works.
- Core Services work without kube-proxy.
- Basic Kubernetes NetworkPolicy works without eBPF.
- Cilium CLI/status/docs clearly explain no-eBPF mode and unsupported features.
- Unsupported features fail early or show honest status, not silent partial behavior.

## Milestone 1 must include
1. **Dual-stack pod networking**
   - IPv4 and IPv6 pod routes.
   - Same-node and cross-node connectivity.
   - Endpoint route reconciliation for both families.
   - Native routing only; no tunnel mode.

2. **No-kube-proxy core Service path**
   - M1 should be kube-proxy-free for core Service types.
   - Implement ClusterIP and basic NodePort using non-eBPF Linux primitives: choose nftables/iptables or IPVS after a design spike.
   - LoadBalancer, externalTrafficPolicy edge cases, topology-aware routing, session affinity, health checks, and dual-stack Service edge cases may be phased, but the M1 demo must include dual-stack Service basics.

3. **Minimal Kubernetes NetworkPolicy**
   - Implement standard K8s NetworkPolicy only via nftables/iptables or equivalent.
   - Cover common semantics: podSelector, namespaceSelector, ipBlock, ingress/egress, TCP/UDP/SCTP ports where practical.
   - Explicitly cut CiliumNetworkPolicy, L7, DNS/FQDN policy, entities, identity-aware Cilium semantics.

4. **Product UX**
   - Helm values for no-eBPF mode.
   - Install-time validation that incompatible features are disabled.
   - `cilium status` / features output identifies `linux-route` and explains delegated/replaced capabilities.
   - Docs: quickstart, support matrix, known limitations, test commands.

5. **Conformance-oriented test matrix**
   - CNI ADD/DEL smoke, pod restart cleanup, node reboot/reconcile smoke.
   - Kubernetes network model: pod-to-pod, pod-to-service, DNS, cross-node, hostNetwork interaction.
   - Dual-stack validation: Pods and Services both families.
   - K8s NetworkPolicy conformance-ish subset.
   - Sonobuoy Kubernetes conformance run as a signal, while recognizing certification is for Kubernetes distributions/platforms.

## Explicit non-goals for M1
Cut:
- Hubble datapath flow visibility.
- L7 / DNS proxy policy.
- Host firewall.
- Egress gateway / BGP / advanced routing.
- Transparent encryption / WireGuard / IPsec.
- Bandwidth manager / EDT / QoS.
- CiliumNetworkPolicy and Cilium-specific L7/FQDN policy.

Defer or restrict:
- Full kube-proxy parity.
- LoadBalancer cloud-provider behavior.
- externalTrafficPolicy/local traffic policy corner cases.
- Service topology hints / traffic distribution.
- Session affinity unless cheap with chosen backend.
- IP masquerade / off-cluster egress beyond demo basics.

## Key design decisions still needed
1. Service backend: nftables vs iptables vs IPVS.
   - Recommended first spike: compare nftables/IPVS for dual-stack ClusterIP/NodePort implementation and Kubernetes watcher integration.
2. Policy backend: likely nftables/iptables controller.
   - Decide whether to reuse any existing Cilium policy resolution machinery only for K8s NetworkPolicy input, or build a narrow parallel translator.
3. Ownership boundary: whether no-eBPF service/policy controllers live under existing loadbalancer/policy packages or a new `pkg/datapath/linux/nobpf` area.
4. Test environment: kind dual-stack without kube-proxy for M1, plus optional kube-proxy compatibility mode as diagnostic fallback only.

## Proposed phased plan

### Phase 0 — Baseline truth pass
- Run existing `kind-no-ebpf` smoke.
- Add dual-stack kind config for no-eBPF.
- Document current failures: IPv6 pod routes, Services, DNS, policy, cleanup.
- Add a single support matrix doc before implementing more behavior.

### Phase 1 — Dual-stack pod networking hardening
- Verify CNI ADD emits both IP families.
- Verify endpoint route reconciliation creates `/32` and `/128` routes.
- Verify sysctls and forwarding are correct for IPv4/IPv6.
- Fix neighbor/NDP or route-manager gaps.
- Acceptance: dual-stack pod-to-pod same-node/cross-node and DNS backend reachability.

### Phase 2 — Non-eBPF Service replacement MVP
- Implement watcher/reconciler for Services + EndpointSlices.
- Program chosen Linux backend for ClusterIP TCP/UDP for IPv4/IPv6.
- Add basic NodePort for IPv4/IPv6 if feasible without large detours.
- Disable kube-proxy in no-eBPF test cluster.
- Acceptance: pod-to-ClusterIP, pod-to-CoreDNS, node/pod-to-NodePort basics, dual-stack Service smoke.

### Phase 3 — K8s NetworkPolicy MVP
- Translate standard K8s NetworkPolicy subset to Linux firewall rules.
- Start with default-deny + allow by pod/namespace selectors + ports.
- Keep CiliumNetworkPolicy unsupported with clear status/events.
- Acceptance: upstream-style NetworkPolicy smoke for ingress/egress and dual-stack traffic.

### Phase 4 — Product polish and conformance signal
- Helm preset for `linux-route` product demo.
- Status/CLI/docs warnings and support matrix.
- CI job for no-eBPF dual-stack kind.
- Run Sonobuoy as conformance signal.
- Track failures as product backlog, not all as M1 blockers.

## Acceptance criteria
- `cilium install` with no-eBPF values succeeds in a dual-stack kind cluster with kube-proxy disabled.
- No Cilium TC/XDP forwarding programs are attached for pod forwarding in `linux-route` mode.
- Pods have IPv4+IPv6; same-node and cross-node connectivity works.
- CoreDNS and ClusterIP Services work for IPv4+IPv6.
- Basic NodePort works or is explicitly documented as the only M1 Service exception if implementation spike proves too costly.
- Basic K8s NetworkPolicy subset enforces IPv4+IPv6.
- Unsupported Cilium features are rejected at Helm/agent validation or visibly reported.
- A no-eBPF support matrix exists.

## Recommended handoff
Use this artifact as input to `$ralplan` for architecture/tradeoff planning before implementation. The most important next planning question is service backend selection: nftables vs iptables vs IPVS.
