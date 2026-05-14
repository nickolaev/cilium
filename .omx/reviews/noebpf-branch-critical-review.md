# no-eBPF branch critical review

Date: 2026-05-13
Branch: `no-ebpf`
Range reviewed: `origin/no-ebpf..HEAD` plus current working-tree fixes.

## System Architect review (networking/kernel/Kubernetes)

Critical/severe findings:

1. **Non-atomic nftables owned-table replacement could drop all Service/policy
   rules on an apply failure.** Fixed by replacing existing `inet cilium_noebpf`
   state with one `nft -f -` transaction containing delete plus create.
2. **NetworkPolicy startup could transiently fail open before Kubernetes inputs
   synchronized.** Fixed by gating first policy reconcile on local pod table,
   namespace table, all-pod resource sync, and NetworkPolicy resource sync.
3. **Branch-level Helm values added `noEBPF` without schema coverage.** Fixed by
   adding `noEBPF.services.enabled` and `noEBPF.networkPolicy.enabled` to
   `values.schema.json`, so chart consumers and schema validation know the new
   public values.

M1 architectural deferrals remain explicit: no LoadBalancer, ExternalIPs,
traffic policies, session affinity, topology hints, SCTP, CiliumNetworkPolicy,
L7/FQDN, Hubble datapath visibility, or full kube-proxy/KNP conformance.

## Principal Engineer review (Go/Kubernetes/Cilium)

Critical/severe findings:

1. **Service-only and policy-enabled readiness paths were coupled too loosely.**
   Fixed so Service mode waits only for frontend initialization, while policy
   mode requires its own mandatory resources and synchronized caches.
2. **Rendered policy rule ordering ignored L4 fields.** Fixed deterministic sort
   order to include source, destination, protocol, and port.
3. **Executor tests did not lock the safety invariant.** Fixed the existing-table
   test to assert replacement is submitted as one nft script.

No additional blocking Go correctness issues were found in route-only endpoint
configuration, load-balancer reflection, option population, or K8s resource
wiring after the focused test pass.

## Senior Testing Engineer review (Cilium tests)

Critical/severe findings:

1. **Phase 2 smoke assumed ClusterIP order and only checked one CoreDNS family.**
   Fixed by selecting service IPs by address family and checking IPv4/IPv6
   CoreDNS Service paths when present.
2. **Phase 3 smoke was too IPv4/TCP-centric and used TCP to test a UDP deny.**
   Fixed by adding IPv4/IPv6 and TCP/UDP allow/deny checks plus a real blocked
   egress backend.
3. **Branch-level chart/schema regression was untested locally.** Added schema
   JSON validation to the verification log; Helm rendering could not be run
   because `helm` is not installed in this environment.

## Verification log

- Passed: `python3 -m json.tool install/kubernetes/cilium/values.schema.json`.
- Passed: `go test ./daemon/cmd ./daemon/k8s ./pkg/k8s ./pkg/option`.
- Passed: `go test ./pkg/datapath/linux/noebpf/nftables ./pkg/datapath/loader ./pkg/endpoint ./pkg/loadbalancer/reflectors ./pkg/loadbalancer/cell`.
- Passed after local image rollout: `contrib/testing/noebpf-phase2-service-smoke.sh kind-noebpf-p2fresh`.
- Passed after local image rollout: `contrib/testing/noebpf-phase3-policy-smoke.sh kind-noebpf-p3fresh`.
- Not run: Helm template/lint; `helm` is unavailable in this environment.

## Local CI execution update

Additional local CI-equivalent execution completed after recreating kind clusters
because no kind contexts were present initially:

- Passed: Tier 0 hygiene (`git diff --check`, schema JSON parse, smoke script syntax).
- Passed: focused Go package set.
- Passed: broader adjacent package set: `go test ./pkg/datapath/... ./pkg/loadbalancer/... ./pkg/endpoint/... ./pkg/k8s/... ./daemon/...`.
- Cluster setup: created `noebpf-p2fresh` with kube-proxy disabled and dual-stack; first `noebpf-p3fresh` create hit debug port collision, then succeeded with alternate debug port prefixes.
- Installed Cilium into both clusters from local chart and local images.
- Passed: `cilium status --wait` on both clusters.
- Passed: `contrib/testing/noebpf-phase2-service-smoke.sh kind-noebpf-p2fresh`.
- Passed: `contrib/testing/noebpf-phase3-policy-smoke.sh kind-noebpf-p3fresh`.
- Connectivity: an exploratory broad `cilium connectivity test --test pod-to-pod --test pod-to-service --test pod-to-nodeport` was intentionally stopped because scenario regex selection also pulled policy tests that are out of Phase 2 scope.
- Connectivity: an exploratory `no-policies` run was stopped because it included external world checks, which are out of M1 scope and timed out in this local environment.
- Passed connectivity gate: `cilium connectivity test --context kind-noebpf-p2fresh --force-deploy --test 'no-policies/pod-to-pod' --test 'no-policies/client-to-client' --test 'no-policies/pod-to-service' --flow-validation disabled --hubble=false --timeout 10m` with 1 test / 36 actions successful.
- Passed connectivity gate: `cilium connectivity test --context kind-noebpf-p3fresh --force-deploy --test 'no-policies/pod-to-pod' --test 'no-policies/client-to-client' --test 'no-policies/pod-to-service' --test 'all-ingress-deny-knp/pod-to-pod' --flow-validation disabled --hubble=false --timeout 10m` with 2 tests / 48 actions successful.
