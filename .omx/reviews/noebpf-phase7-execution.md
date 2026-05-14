# no-eBPF Phase 7 execution log

Date: 2026-05-14
Branch: `no-ebpf`
Plan: `.omx/specs/noebpf-phase7-scope-expansion-plan.md`

## Decision

Phase 7 followed the support-boundary hardening path instead of expanding the
M1 product surface. High-risk Service and NetworkPolicy features remain
deferred to preserve the Phase 5/6 baseline before upstream slicing.

## Implemented

### Service boundary hardening

Added focused tests in `pkg/datapath/linux/noebpf/nftables/service_test.go`:

- `LoadBalancer` frontends are skipped;
- `ExternalIPs` frontends are skipped;
- SCTP frontends are skipped;
- inactive/terminating backends are skipped;
- unsupported skipped Services do not render into `inet cilium_noebpf` desired
  state;
- mixed IPv4/IPv6 frontend/backend tuples are rejected.

No new Service feature semantics were added.

### NetworkPolicy boundary hardening

Added focused tests in `pkg/datapath/linux/noebpf/nftables/k8s_policy_test.go`
for deterministic unsupported-field rejection:

- top-level `podSelector.matchExpressions`;
- peer `podSelector.matchExpressions`;
- peer `namespaceSelector.matchExpressions`;
- SCTP protocol;
- named ports;
- `endPort`.

Changed `PoliciesFromK8sNetworkPolicies` to reject top-level
`podSelector.matchExpressions` explicitly instead of treating them as a silent
non-match. This avoids fail-open behavior for unsupported endpoint selectors.

### Optional matchExpressions scope

`matchExpressions` support was evaluated and deferred. Supporting the full
Kubernetes selector operators (`In`, `NotIn`, `Exists`, `DoesNotExist`) would
require widening selector representation beyond the current match-label map and
is not necessary for M1. The behavior is now explicit rejection rather than
implicit omission.

## Validation

Passed:

- `go test ./pkg/datapath/linux/noebpf/nftables`
- `git diff --check`
- `bash -n contrib/testing/noebpf-local-ci.sh contrib/testing/noebpf-phase2-service-smoke.sh contrib/testing/noebpf-phase3-policy-smoke.sh`
- `NOEBPF_RUN_CONNECTIVITY=0 contrib/testing/noebpf-local-ci.sh`
  - focused Go packages;
  - Cilium status gates for `kind-noebpf-p2fresh` and `kind-noebpf-p3fresh`;
  - Phase 2 Service smoke;
  - Phase 3 NetworkPolicy smoke;
  - optional Helm gate skipped because `helm` is unavailable.

## Result

Phase 7 is complete. The M1 support boundary is now tested rather than merely
documented. Next phase: Phase 8 upstream readiness / PR slicing, while deferred
Phase 4 polish remains Phase 9.
