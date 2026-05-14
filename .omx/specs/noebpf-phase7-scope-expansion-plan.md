# no-eBPF Phase 7 scope expansion plan

Date: 2026-05-14
Branch: `no-ebpf`
Inputs:

- `.omx/specs/ralplan-no-ebpf-cni-product-demo.md`
- `.omx/reviews/noebpf-phase5-phase6-execution.md`
- Current `pkg/datapath/linux/noebpf/nftables` implementation

## Context

Phases 2 and 3 have a passing M1 baseline:

- dual-stack pod networking in `linux-route` mode;
- kube-proxy-free ClusterIP and basic wildcard NodePort TCP/UDP through
  nftables;
- standard Kubernetes NetworkPolicy subset for dual-stack TCP/UDP;
- targeted Cilium connectivity and smoke hardening passed in Phase 5/6.

The original Phase 4 polish is intentionally deferred to Phase 9. Phase 7 is a
product/engineering decision point: choose whether to expand scope before PR
slicing, or keep the baseline narrow and harden it for upstream review.

## Phase 7 decision criteria

A candidate expansion is accepted only if it satisfies all criteria:

1. **Dual-stack:** works for IPv4 and IPv6, or is explicitly family-neutral.
2. **One backend:** remains nftables-only; no iptables/IPVS fallback in this
   phase.
3. **Restart-safe:** covered by full desired-state reconciliation and agent
   restart convergence.
4. **Atomic/owned-state:** no imperative partial programming outside the owned
   `inet cilium_noebpf` table.
5. **Bounded semantics:** does not imply full kube-proxy, Cilium policy, or
   NetworkPolicy conformance parity.
6. **Testable locally:** has a deterministic kind smoke or focused unit test.
7. **Low interaction risk:** does not depend on SNAT/DSR, host firewall, L7,
   identities, Hubble, or external cloud-provider behavior.

Candidates that fail these criteria stay deferred and must remain visible in the
support matrix.

## Recommended Phase 7 decision

**Recommendation: do not expand the M1 product surface with LoadBalancer,
ExternalIPs, traffic policies, session affinity, named ports, endPort, or SCTP
before upstream slicing.**

Instead, Phase 7 should add *support-boundary hardening*:

1. make unsupported Service/KNP semantics observable and deterministic;
2. add tests that lock the “skip/reject unsupported” behavior;
3. add one small, low-risk KNP selector improvement only if it is already mostly
   supported by current data structures.

Rationale: Phase 5/6 just established a credible M1 baseline. Adding high-level
Service semantics now would multiply datapath, cleanup, and conformance risk
before the baseline has been reviewed.

## Phase 7 work items

### 7A — Service support-boundary hardening

Current code intentionally converts only `ClusterIP` and `NodePort` frontends and
silently skips other Service types/protocols in `ServicesFromFrontends`.

Tasks:

1. Add unit tests that explicitly prove unsupported Service scope is skipped:
   - `LoadBalancer` frontend skipped;
   - `ExternalIP` frontend skipped if represented as a non-M1 frontend type;
   - SCTP skipped;
   - inactive backends skipped;
   - mixed frontend/backend IP family returns an error.
2. Add a small stats/diagnostic hook if practical in the existing reconciler:
   count unsupported skipped frontends by reason and surface them in logs at
   debug or warning level without failing the M1 datapath.
3. Add a smoke-only assertion that no `LoadBalancer`/ExternalIP rules appear in
   `inet cilium_noebpf` when such Services exist.

Acceptance:

- focused Go tests cover skip/error behavior;
- no unsupported Service tuple renders into nftables desired state;
- docs/support matrix remains consistent.

### 7B — Kubernetes NetworkPolicy support-boundary hardening

Current KNP parsing rejects unsupported fields with errors:

- SCTP protocol;
- named ports;
- `endPort`;
- selector `matchExpressions`.

Tasks:

1. Add focused tests around these rejection paths so future work cannot silently
   widen or fail-open the support matrix.
2. Confirm runtime behavior for unsupported KNP objects is fail-closed or at
   least loudly surfaced; if current behavior logs and keeps last-good desired
   state, document that operational contract.
3. Add smoke coverage for an unsupported KNP object only if it can be written
   without destabilizing the live cluster; otherwise keep it unit-level.

Acceptance:

- unsupported KNP fields are rejected deterministically in unit tests;
- no silent fail-open is introduced;
- Phase 9 docs can describe the behavior precisely.

### 7C — Optional low-risk KNP selector improvement: `matchExpressions`

Kubernetes NetworkPolicy commonly uses label selector `matchExpressions`. The
current implementation only supports `matchLabels`.

Decision:

- **Optional/conditional:** implement only if the existing pod/namespace label
  matching layer can represent `In`, `NotIn`, `Exists`, and `DoesNotExist`
  without widening datapath renderer semantics.
- If implementation requires a larger selector AST or invasive policy
  translator rewrite, defer to a later phase.

Acceptance if implemented:

- unit tests for namespaceSelector and podSelector matchExpressions;
- one live smoke for `namespaceSelector.matchExpressions In` + pod selector;
- no impact on existing Phase 3 smokes.

### 7D — Explicitly defer high-risk Service expansion

Keep deferred for now:

- `LoadBalancer` and cloud-provider semantics;
- ExternalIPs;
- `externalTrafficPolicy=Local` and `internalTrafficPolicy=Local`;
- source ranges;
- session affinity;
- healthCheckNodePort;
- topology hints / trafficDistribution;
- DSR/SNAT-preservation and masquerade-sensitive behavior;
- SCTP Service forwarding.

Reason: all require either source-preservation/SNAT semantics, node-local backend
selection, health-check handling, cloud-provider coupling, or larger conformance
surface.

### 7E — Explicitly defer high-risk NetworkPolicy expansion

Keep deferred for now:

- named ports;
- `endPort`;
- SCTP;
- hostNetwork peers;
- full Service-IP policy semantics beyond tested DNAT-to-backend behavior;
- ambiguous `ipBlock` versus pod CIDR conformance edge cases;
- CiliumNetworkPolicy, L7, DNS/FQDN, entities, identities.

Reason: named ports and endPort are common but require additional endpoint/port
resolution and range rendering; SCTP requires broadening renderer protocol
support and Service tests; Cilium extensions break the standard-KNP-only product
contract.

## Suggested execution order

1. Implement 7A Service support-boundary unit tests and any low-risk diagnostics.
2. Implement 7B KNP rejection/contract tests.
3. Spike 7C matchExpressions in a small branch-sized change; accept only if it
   stays small.
4. Run:
   - `go test ./pkg/datapath/linux/noebpf/nftables`;
   - `NOEBPF_RUN_CONNECTIVITY=0 contrib/testing/noebpf-local-ci.sh`;
   - Phase 2/3 smoke scripts if any runtime behavior changed.
5. Update Phase 9 docs/support matrix with exact accepted/deferred list.

## Exit criteria

Phase 7 is complete when:

- the project has an explicit accept/defer decision for each deferred M1 feature;
- unsupported features are tested as unsupported, not merely absent;
- no new high-risk datapath semantics are introduced before upstream slicing;
- optional matchExpressions is either implemented with tests or explicitly
  deferred with rationale.
