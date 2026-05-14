# no-eBPF Phase 2/3 critical review

Date: 2026-05-13
Branch: `no-ebpf`

## System Architect review (networking/kernel/Kubernetes)

Critical/severe findings:

1. **Owned-table replacement was not atomic when the table already existed.**
   A successful delete followed by a failed create could leave the node without
   Service and policy rules. Fixed by using a single `nft -f -` transaction for
   existing-table replacement.
2. **NetworkPolicy could apply a fail-open empty policy before Kubernetes inputs
   had synchronized.** Fixed by waiting for local-pod and namespace StateDB
   tables plus all-pod and NetworkPolicy resource sync before first policy
   reconciliation.
3. **Phase 3 live coverage was effectively IPv4/TCP-heavy.** Fixed by adding
   IPv6 and UDP checks to the policy smoke.

Deferred by M1 scope:
LoadBalancer, ExternalIPs, traffic policies, topology hints, session affinity,
SCTP, named ports, endPort, CiliumNetworkPolicy, L7/FQDN, and full kube-proxy or
NetworkPolicy conformance.

## Principal Engineer review (Go/Cilium implementation)

Critical/severe findings:

1. **Reconciler startup mixed service and policy readiness.** Fixed so service
   mode only waits for load-balancer frontends, while policy mode waits for its
   own inputs.
2. **Policy allow sorting ignored protocol and port.** Fixed deterministic order
   to include source, destination, protocol, and port.
3. **Executor tests did not assert transaction shape.** Fixed to assert existing
   table replacement is submitted as one nft script.

## Senior Testing Engineer review (Cilium tests)

Critical/severe findings:

1. **Phase 2 smoke assumed ClusterIP order and checked only one CoreDNS family.**
   Fixed by deriving IPv4/IPv6 ClusterIPs by address family and checking both
   CoreDNS Service families when present.
2. **Phase 3 smoke used TCP failures against a UDP-only port and did not prove
   IPv6 policy.** Fixed with explicit TCP/UDP and IPv4/IPv6 allow/deny checks,
   plus a real blocked backend for egress-deny validation.
3. **Live done gate remains required.** Phase 2 and Phase 3 are considered done
   only after their kind smoke scripts pass on a dual-stack no-eBPF cluster.

## Verification log

- Unit tests: passed `go test ./pkg/datapath/linux/noebpf/nftables ./pkg/datapath/loader ./pkg/endpoint ./pkg/loadbalancer/reflectors ./pkg/loadbalancer/cell`.
- Build/redeploy: passed `make kind-image`, loaded `localhost:5000/cilium/cilium-dev:local` and `localhost:5000/cilium/operator-generic:local` into `noebpf-p2fresh` and `noebpf-p3fresh`, then rolled out both clusters.
- Phase 2 live smoke: passed `contrib/testing/noebpf-phase2-service-smoke.sh kind-noebpf-p2fresh` after the local image rollout.
- Phase 3 live smoke: passed `contrib/testing/noebpf-phase3-policy-smoke.sh kind-noebpf-p3fresh` after the local image rollout.
