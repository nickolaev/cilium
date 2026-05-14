Experimental no-eBPF testing
=============================

The ``bpf.datapathMode=linux-route`` datapath is an experimental no-eBPF
forwarding mode. The current product-demo profile combines Linux routes for pod
connectivity with a Cilium-owned nftables backend for selected Kubernetes
Service and NetworkPolicy behavior.

This area documents the local, explicitly scoped test path. It is not a general
Cilium feature-support claim and it is not a Kubernetes conformance statement.

.. toctree::
   :maxdepth: 2

   quickstart
   phase0-nftables-spike

M1 support matrix
-----------------

The supported M1 profile is a dual-stack kind cluster with kube-proxy disabled,
installed from ``contrib/testing/kind-no-ebpf-dual.yaml`` and optionally layered
with ``contrib/testing/kind-no-ebpf-dual-policy.yaml``.

.. list-table::
   :header-rows: 1
   :widths: 28 18 54

   * - Area
     - M1 status
     - Notes
   * - Pod networking
     - Supported
     - ``linux-route`` pod attachment, native routing, endpoint routes, IPv4 and
       IPv6 pod connectivity.
   * - Cilium TC/XDP forwarding programs
     - Unsupported
     - The no-eBPF path must not attach Cilium forwarding programs to workload,
       host, or native devices.
   * - ClusterIP Services
     - Supported subset
     - TCP/UDP, IPv4 and IPv6, multiple backends, EndpointSlice updates, and
       deletion cleanup through the nftables backend.
   * - NodePort Services
     - Supported subset
     - Basic wildcard NodePort TCP/UDP for IPv4 and IPv6. Advanced traffic-policy
       semantics are out of scope.
   * - CoreDNS Service
     - Supported
     - Validated through the no-eBPF Service backend in the dual-stack profile.
   * - Kubernetes NetworkPolicy
     - Supported subset
     - Standard K8s NetworkPolicy ingress/egress default deny, pod and namespace
       selectors, combined selectors, ``ipBlock`` with ``except``, and TCP/UDP
       ports.
   * - Cilium policy extensions
     - Unsupported
     - CiliumNetworkPolicy, L7, DNS/FQDN, entities, and identity-aware Cilium
       semantics remain outside this backend.
   * - LoadBalancer / ExternalIP Services
     - Unsupported
     - Deferred together with topology hints, session affinity, source ranges,
       health checks, traffic policies, and full kube-proxy parity.
   * - eBPF-dependent features
     - Unsupported
     - BPF masquerade, socket LB, host firewall, Hubble datapath flow events,
       transparent encryption, XDP acceleration, bandwidth manager, and egress
       gateway are not part of M1.

Validation gates
----------------

Use ``contrib/testing/noebpf-local-ci.sh`` as the local Phase 4 gate. The script
runs hygiene checks, focused Go tests, status waits, Service and NetworkPolicy
smokes, and the targeted Cilium connectivity scenarios that match the support
matrix above. Broader connectivity or Sonobuoy runs can be useful signals, but
failures in features outside this matrix should be triaged as follow-up product
work rather than silently expanding M1.
