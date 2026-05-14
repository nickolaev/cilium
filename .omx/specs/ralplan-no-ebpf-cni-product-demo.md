# RALPLAN — Cilium no-eBPF product-demo baseline

Date: 2026-05-10
Input spec: `.omx/specs/deep-interview-no-ebpf-cni-plan.md`
Consensus: Architect APPROVE, Critic APPROVE

## RALPLAN-DR Summary

### Principles
1. **Honest no-eBPF mode:** eBPF/Cilium-specific unsupported features fail early or report explicit limitations.
2. **One Linux-rule backend for M1:** no fallback matrix unless a later milestone explicitly accepts doubled test/cleanup burden.
3. **Reuse Cilium state/watchers where safe:** isolate Linux-rule rendering under a dedicated no-eBPF datapath backend.
4. **Dual-stack is mandatory:** every M1 accepted feature must work for IPv4 and IPv6.
5. **Deterministic ownership/cleanup:** startup reconciliation and garbage collection are part of the design.
6. **80/20 Kubernetes behavior beats Cilium parity.**

### Decision drivers
1. Product-demo credibility: kube-proxy-free ClusterIP/NodePort + basic K8s NetworkPolicy.
2. Avoid overloading existing eBPF KPR/policy flags with non-eBPF semantics.
3. Atomic, restart-safe Linux rule reconciliation.
4. Clear CI acceptance in kind dual-stack.

### Alternatives considered
- **A. nftables-only for M1 Services + NetworkPolicy — chosen.**
  - Pros: one `inet` dual-stack rule engine, named sets, atomic replace, clear ownership.
  - Cons: hard dependency and new backend code.
- **B. iptables/ip6tables-only.**
  - Pros: existing Cilium helpers, familiar.
  - Cons: duplicated v4/v6 programming, weaker atomicity, harder cleanup/scale.
- **C. IPVS Services + nftables policy.**
  - Pros: mature Service LB behavior.
  - Cons: two backends, more cleanup and hook-order complexity.
- **D. kube-proxy for Services.**
  - Rejected by user requirement: M1 must be kube-proxy-free for core Service types.

## ADR

### Decision
Build M1 as **`linux-route` + nftables-only no-eBPF Linux-rule backend** for core Services and standard Kubernetes NetworkPolicy, gated by explicit no-eBPF feature flags and a strict support matrix.

### Drivers
- User wants a product-leaning no-eBPF baseline, not just route-only smoke.
- M1 must be dual-stack.
- M1 must be kube-proxy-free for core Services.
- M1 should support basic standard K8s NetworkPolicy, but not CiliumNetworkPolicy/L7/FQDN.
- Scope must remain bounded enough for 80/20 delivery.

### Consequences
- nftables becomes a hard M1 runtime prerequisite; no automatic iptables/IPVS fallback in M1.
- The implementation will not match full kube-proxy or Cilium policy semantics.
- Unsupported features must be visible in Helm validation, agent validation, status, docs, and tests.
- If Phase 0 proves nftables unsuitable, stop and ask for a product decision rather than continuing silently.

## Plan

### Phase 0 — Blocking nftables spike and baseline truth

Goal: prove the chosen backend can satisfy M1 before larger integration.

Tasks:
1. Add or document a dual-stack kind no-eBPF profile with kube-proxy disabled.
2. Verify nftables availability/capabilities in target nodes.
3. Prototype minimal nftables ClusterIP DNAT for one IPv4 and one IPv6 Service.
4. Prototype one ingress default-deny + allow policy rule for IPv4 and IPv6 pod traffic.
5. Verify atomic replace behavior and owner cleanup using a dedicated table such as `inet cilium_noebpf`.
6. Capture current failures for IPv6, Service, policy, and restart cleanup.

Exit criteria:
- Required nat/filter hooks are available.
- Atomic replacement works.
- IPv4 and IPv6 ClusterIP DNAT works in kind.
- IPv4 and IPv6 default-deny/allow policy smoke works.
- Startup cleanup can delete stale `cilium_noebpf` state.
- If any criterion fails, pause and present IPVS/iptables alternatives.

### Phase 1 — Dual-stack pod networking hardening

Tasks:
1. Keep existing `linux-route` route-only loader path.
2. Ensure endpoint route reconciliation creates `/32` and `/128` routes correctly.
3. Verify forwarding sysctls and IPv6 NDP/neighbor behavior.
4. Ensure no TC/XDP forwarding programs attach in `linux-route` mode.
5. Add smoke tests for same-node and cross-node pod IPv4/IPv6 connectivity.

Acceptance:
- Pods receive IPv4+IPv6.
- Same-node and cross-node pod traffic works for both families.
- CoreDNS backend Pods are reachable by pod IP.
- No Cilium TC/XDP forwarding attach occurs.

### Phase 2 — nftables Service MVP

Introduce explicit concepts/flags:
- `bpf.datapathMode=linux-route` remains route-only attachment mode.
- `noEBPF.services.enabled=true` or equivalent `serviceReplacement=linux-rules` enables nftables Service replacement.
- Do **not** use `kubeProxyReplacement=true` for this; that means eBPF KPR today.

Implementation shape:
- Consume existing Cilium Service/EndpointSlice/loadbalancer state where safe.
- Render only dedicated nftables resources, e.g. `inet cilium_noebpf` generation-tagged chains/sets.
- Use nat `prerouting` for pod/node ingress and nat `output` for host-originated Service paths.
- Reconcile full desired state atomically.
- Rehydrate from K8s state on startup; garbage-collect stale generations.

Required M1 Service semantics:
- ClusterIP TCP/UDP IPv4+IPv6.
- CoreDNS Service.
- Basic NodePort TCP/UDP IPv4+IPv6.
- Multiple backends.
- EndpointSlice updates.
- Service deletion cleanup.
- Agent restart cleanup/reconciliation.

Explicitly deferred:
- LoadBalancer.
- ExternalIPs.
- externalTrafficPolicy=Local.
- internalTrafficPolicy=Local unless trivial.
- topology hints / trafficDistribution.
- session affinity.
- healthCheckNodePort.
- source ranges.
- DSR/SNAT-preservation semantics.
- Masquerade/SNAT-sensitive cases beyond the explicitly tested demo paths.

Service verification:
- pod-to-ClusterIP.
- host-to-ClusterIP.
- pod-to-NodePort.
- node-to-NodePort.
- remote backend reply path.
- same-node backend path.
- EndpointSlice update removes stale backend.
- Service deletion removes nftables entries.
- Agent restart converges without relying on shutdown cleanup.

### Phase 3 — nftables Kubernetes NetworkPolicy MVP

Introduce explicit concept/flag:
- `noEBPF.networkPolicy.enabled=true` enables standard K8s NetworkPolicy rendering.
- It does not enable Cilium eBPF policy enforcement, CiliumNetworkPolicy, L7, DNS/FQDN policy, identities, or entities.

Data sources:
- standard NetworkPolicy objects.
- Namespaces and labels.
- cluster-wide Pods and labels/IPs.
- local Cilium endpoints/interfaces.
- Add/read a slim all-pods table if current state is local-only.
- Avoid depending on eBPF identity/policy-map internals.

Hook/order sketch:
- Accept established/related conntrack replies before policy checks.
- Apply pod policy in nftables filter `forward`, using local endpoint/interface/IP membership sets where possible.
- Ensure pod-to-ClusterIP traffic is DNATed before backend policy evaluation so policy is not bypassed via Service VIPs.
- NodePort ingress is DNATed in prerouting, then filtered consistently with backend pod policy.
- Include IPv6 forwarding/NDP sanity in tests.

Required M1 KNP semantics:
- default allow when no policy selects pod.
- ingress default-deny when an ingress policy selects pod.
- egress default-deny when an egress policy selects pod.
- allow by podSelector.
- allow by namespaceSelector.
- allow by combined namespaceSelector + podSelector.
- ipBlock with except.
- TCP/UDP ports.
- IPv4+IPv6.

Deferred:
- SCTP unless trivial.
- named ports.
- endPort.
- hostNetwork peers.
- full Service-IP policy semantics beyond tested paths.
- ambiguous ipBlock-vs-podCIDR edge cases.
- all CiliumNetworkPolicy/L7/FQDN features.

Minimal named CI scenarios:
1. `knp-no-policy-default-allow-v4-v6`.
2. `knp-ingress-default-deny-v4-v6`.
3. `knp-egress-default-deny-v4-v6`.
4. `knp-allow-pod-selector-v4-v6`.
5. `knp-allow-namespace-selector-v4-v6`.
6. `knp-allow-ns-and-pod-selector-v4-v6`.
7. `knp-ipblock-except-v4-v6`.
8. `knp-tcp-udp-ports-v4-v6`.
9. `knp-service-vip-to-backend-policy-v4-v6`.

### Phase 4 — Product UX, docs, and CI

Tasks:
1. Helm preset/values for product demo no-eBPF mode.
2. Helm/agent validation rejects eBPF KPR/socketLB with `linux-route`, while allowing explicit Linux-rule service/policy flags.
3. `cilium status` / feature reporting shows:
   - datapath: `linux-route`.
   - service replacement: `nftables` enabled/disabled.
   - K8s NetworkPolicy: `nftables` enabled/disabled.
   - unsupported Cilium features.
4. Documentation:
   - quickstart.
   - support matrix.
   - known limitations.
   - test commands.
   - conformance wording: Sonobuoy is a signal, not standalone CNI certification.
5. CI job:
   - dual-stack kind no-eBPF.
   - kube-proxy disabled.
   - service smoke.
   - policy smoke.
   - startup reconciliation cleanup test.
   - optional Sonobuoy signal run.

## Explicit M1 non-goals
- Hubble datapath flow visibility.
- L7 / DNS proxy policy.
- Host firewall.
- Egress gateway / BGP / advanced routing.
- Transparent encryption / WireGuard / IPsec.
- Bandwidth manager / EDT / QoS.
- CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy.
- Full kube-proxy parity.
- Full NetworkPolicy conformance beyond named M1 scenarios.

## Available agent roster for execution
- `explorer`: quick codebase questions and narrow symbol/file mapping.
- `worker`: concrete implementation changes in assigned file/module ownership slices.
- `default`: general integration or synthesis tasks.

## Recommended execution staffing

### Ralph path
Use `$ralph` for sequential implementation if you want one owner to iterate carefully:
1. Phase 0 spike and artifacts.
2. Phase 1 pod networking hardening.
3. Phase 2 Service backend.
4. Phase 3 NetworkPolicy backend.
5. Phase 4 UX/docs/CI.

Suggested reasoning: high for Phase 0 and Phase 2/3 design; medium for docs/status polish.

### Team path
Use `$team` for parallel execution after Phase 0 succeeds:
- Worker A: nftables backend package and ownership/reconciliation primitives.
- Worker B: Service state integration and Service MVP tests.
- Worker C: NetworkPolicy data-source/translator and policy tests.
- Worker D: Helm/status/docs/CI.
- Verifier/test engineer: dual-stack kind matrix and cleanup tests.

Important: Phase 0 is a gate. Do not parallelize full Service/Policy implementation before the nftables spike proves viability.

## Verification path
1. Local unit tests for renderer desired-state generation.
2. Scripted integration tests for nftables table replacement/cleanup.
3. Dual-stack kind smoke with kube-proxy disabled.
4. Connectivity tests for pod, Service, NodePort, KNP scenarios.
5. Agent restart and Service/EndpointSlice deletion reconciliation tests.
6. Optional Sonobuoy signal run, explicitly labeled non-certification.
