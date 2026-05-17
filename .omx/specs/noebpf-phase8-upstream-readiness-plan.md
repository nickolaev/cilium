# no-eBPF Phase 8 branch stabilization / integration plan

Date: 2026-05-17
Branch: `no-ebpf`
Inputs:

- `.omx/reviews/noebpf-phase5-phase6-execution.md`
- `.omx/reviews/noebpf-phase7-execution.md`
- Current `pkg/datapath/linux/noebpf/nftables` implementation
- Current no-eBPF docs, smoke tests, and status plumbing

## Context

Phases 2 through 7 have established a dual-stack no-eBPF baseline with:

- linux-route pod networking;
- nftables-based Service replacement;
- nftables-based standard Kubernetes NetworkPolicy;
- support-boundary hardening and runtime status reporting;
- dual-stack smoke coverage for Service and policy paths.

Phase 8 is not a feature-expansion phase. It is the **branch stabilization phase**:

1. keep the branch internally consistent as the source of truth;
2. preserve the support matrix / docs / validation contract while the branch evolves;
3. avoid mixing feature semantics with packaging, docs, and polish changes;
4. converge the runtime, tests, and docs onto the same no-eBPF story.

## Phase 8 goals

1. **Reviewable PR boundaries**
   - Each PR should own a single concern area.
   - Each PR should be independently understandable and testable.

2. **Low-risk upstream ordering**
   - Land plumbing and runtime support first.
   - Land docs/CI updates after the runtime contract is stable.
   - Avoid a single mega-PR that combines API, runtime, smoke, and docs churn.

3. **No scope creep**
   - Phase 8 does not add new supported features.
   - Phase 8 should only preserve and package the current M1 surface.

## Recommended stabilization slices

### Workstream 1 — no-eBPF status / capability plumbing

Purpose:

- expose the no-eBPF support matrix through `cilium status`;
- keep the machine-readable status surface aligned with docs;
- keep feature reporting honest for `linux-route` mode.

Likely file groups:

- `pkg/status/status_collector.go`
- `pkg/datapath/linux/noebpf/capabilities.go`
- `api/v1/models/status_response.go`
- `api/v1/models/noebpf_status.go`
- generated deepcopy / model glue
- `pkg/status/status_collector_noebpf_test.go`
- `pkg/datapath/linux/noebpf/capabilities_test.go`

Acceptance:

- `cilium status` exposes no-eBPF mode and the support matrix;
- API model changes are present and validated;
- no runtime datapath behavior depends on the status patch.

### Workstream 2 — nftables Service replacement

Purpose:

- keep the Service renderer and reconciliation path as one coherent unit;
- keep Service smoke coverage with the runtime code;
- keep health-check / LocalRedirect / Service-related support boundary aligned.

Likely file groups:

- `pkg/datapath/linux/noebpf/nftables/service.go`
- `pkg/datapath/linux/noebpf/nftables/renderer.go`
- `pkg/datapath/linux/noebpf/nftables/cell.go`
- `pkg/datapath/linux/noebpf/nftables/service_test.go`
- `pkg/datapath/linux/noebpf/nftables/renderer_test.go`
- `pkg/loadbalancer/healthserver/healthserver.go`
- `pkg/loadbalancer/healthserver/healthserver_noebpf_test.go`
- `pkg/loadbalancer/reflectors/conversions.go`
- `pkg/loadbalancer/reflectors/k8s_test.go`
- `contrib/testing/noebpf-phase2-service-smoke.sh`
- `contrib/testing/kind-no-ebpf-dual.yaml`

Acceptance:

- dual-stack Service smoke passes;
- service support boundaries are explicit in tests;
- Service runtime behavior and smoke coverage stay together.

### Workstream 3 — nftables Kubernetes NetworkPolicy replacement

Purpose:

- keep the standard K8s NetworkPolicy renderer and controller path coherent;
- keep policy acceptance/rejection tests with the renderer;
- keep policy smoke coverage with the runtime code.

Likely file groups:

- `pkg/datapath/linux/noebpf/nftables/policy.go`
- `pkg/datapath/linux/noebpf/nftables/k8s_policy.go`
- `pkg/datapath/linux/noebpf/nftables/policy_test.go`
- `pkg/datapath/linux/noebpf/nftables/k8s_policy_test.go`
- `pkg/datapath/linux/noebpf/nftables/cell.go`
- `contrib/testing/noebpf-phase3-policy-smoke.sh`
- `contrib/testing/kind-no-ebpf-dual-policy.yaml`

Acceptance:

- dual-stack policy smoke passes;
- unsupported KNP fields stay fail-closed / explicitly rejected;
- renderer and live validation stay in one slice.

### Workstream 4 — docs, Helm, and local CI polish

Purpose:

- update the install docs, support matrix, and quickstart;
- keep Helm values and validation in sync with the runtime contract;
- keep the local CI wrapper and kind profile aligned.

Likely file groups:

- `Documentation/contributing/testing/no-ebpf/index.rst`
- `Documentation/contributing/testing/no-ebpf/quickstart.rst`
- `install/kubernetes/cilium/README.md`
- `contrib/testing/noebpf-local-ci.sh`
- any remaining no-eBPF validation helpers

Acceptance:

- docs describe exactly what is supported and what is deferred;
- local CI advertises the right feature gates and smoke path;
- docs and validation do not drift from the runtime support matrix.

## Suggested execution order

1. **Freeze the support matrix.**
   - Make sure the current capability list is the single source of truth.
2. **Slice runtime first.**
   - Workstream 1 status plumbing.
   - Workstream 2 Service backend.
   - Workstream 3 NetworkPolicy backend.
3. **Land docs/CI last.**
   - Workstream 4 should follow the runtime contract, not lead it.

## Exit criteria

Phase 8 is complete when:

- the branch has converged on a coherent no-eBPF support matrix;
- each major area has a small, coherent responsibility boundary;
- runtime behavior, status, docs, and smoke tests all agree on the same no-eBPF support matrix;
- there are no hidden feature claims in docs or status output that the runtime cannot honor.
