# no-eBPF Phase 5/6 execution log

Date: 2026-05-14
Branch: `no-ebpf`

## Plan update

Remaining Phase 4 polish is deferred to a final Phase 9. Phase 5 and Phase 6
were executed against the existing dual-stack, kube-proxy-free kind clusters:

- `kind-noebpf-p2fresh` for the Service-focused profile.
- `kind-noebpf-p3fresh` for the Service + Kubernetes NetworkPolicy profile.

## Environment recovery finding

Before Phase 5, both clusters were reachable via kubeconfig but Cilium was not
ready. The agent and operator pods were pinned to stale `KUBERNETES_SERVICE_HOST`
values after kind/Docker node IP churn:

- `kind-noebpf-p2fresh` Cilium tried `172.18.0.2:6443`, while the current
  control-plane node was `172.18.0.4`.
- `kind-noebpf-p3fresh` needed the current control-plane node `172.18.0.5`.

Both clusters recovered after `cilium upgrade` with current `k8sServiceHost` and
`k8sServicePort=6443`, followed by agent/operator rollout restarts.

Phase 6 hardening change: `contrib/testing/noebpf-local-ci.sh` now detects the
current control-plane InternalIP and passes it as `k8sServiceHost` during
`NOEBPF_INSTALL=1`. The quickstart documents why this pinning is required for
kube-proxy-free kind clusters.

## Phase 5 — broader connectivity/conformance signal

Passed on `kind-noebpf-p2fresh`:

```text
cilium connectivity test \
  --context kind-noebpf-p2fresh \
  --force-deploy \
  --test 'no-policies/pod-to-pod' \
  --test 'no-policies/client-to-client' \
  --test 'no-policies/pod-to-service' \
  --test 'no-policies/client-to-service' \
  --test 'no-policies/pod-to-nodeport' \
  --flow-validation disabled \
  --hubble=false \
  --timeout 20m
```

Result: `All 1 tests (36 actions) successful, 125 tests skipped, 5 scenarios skipped.`

Passed on `kind-noebpf-p3fresh`:

```text
cilium connectivity test \
  --context kind-noebpf-p3fresh \
  --force-deploy \
  --test 'no-policies/pod-to-pod' \
  --test 'no-policies/client-to-client' \
  --test 'no-policies/pod-to-service' \
  --test 'no-policies/client-to-service' \
  --test 'no-policies/pod-to-nodeport' \
  --test 'all-ingress-deny-knp/pod-to-pod' \
  --test 'all-egress-deny-knp/pod-to-pod' \
  --test 'client-ingress-knp/pod-to-pod' \
  --test 'client-egress-knp/pod-to-pod' \
  --flow-validation disabled \
  --hubble=false \
  --timeout 25m
```

Result: `All 4 tests (108 actions) successful, 122 tests skipped, 6 scenarios skipped.`

Note: the Cilium connectivity test grouping selected the broad scenario-level
KNP suites that matched the provided path regexes; unsupported or out-of-M1
features remained skipped.

## Phase 6 — hardening checks

Passed:

- `contrib/testing/noebpf-phase2-service-smoke.sh kind-noebpf-p2fresh`
  - dual-stack ClusterIP TCP/UDP
  - dual-stack NodePort TCP/UDP
  - node-originated ClusterIP/NodePort TCP
  - CoreDNS Service UDP
  - scale-down EndpointSlice reconciliation
  - service deletion cleanup
  - Cilium agent restart convergence
- `contrib/testing/noebpf-phase3-policy-smoke.sh kind-noebpf-p3fresh`
  - dual-stack baseline allow
  - ingress KNP allow/deny for TCP/UDP
  - egress `ipBlock` allow/deny for TCP/UDP
- `NOEBPF_RUN_CONNECTIVITY=0 contrib/testing/noebpf-local-ci.sh`
  - diff hygiene
  - schema JSON validation
  - optional Helm gate skipped because `helm` is unavailable
  - focused Go packages
  - Cilium status gates
  - Phase 2 and Phase 3 smoke scripts

## Remaining follow-up

- Phase 7: decide whether to expand Service or KNP feature scope.
- Phase 8: branch stabilization / integration.
- Phase 9: remaining product UX/docs/CI polish deferred from Phase 4.
