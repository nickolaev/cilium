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

No-eBPF support matrix
----------------------

The supported no-eBPF profile is a dual-stack kind cluster with kube-proxy
disabled, installed from ``contrib/testing/kind-no-ebpf-dual.yaml`` and
optionally layered with ``contrib/testing/kind-no-ebpf-dual-policy.yaml``.

.. list-table::
   :header-rows: 1
   :widths: 28 18 54

   * - Area
     - Status
     - Notes
   * - Pod networking
     - Supported
     - ``linux-route`` pod attachment, native routing, endpoint routes, and
       IPv4/IPv6 pod connectivity.
   * - Cilium TC/XDP forwarding programs
     - Unsupported
     - The no-eBPF path must not attach Cilium forwarding programs to workload,
       host, or native devices.
   * - Cilium-owned nftables table lifecycle
     - Supported
     - Startup cleanup and atomic replacement of ``inet cilium_noebpf``.
   * - ClusterIP Services
     - Supported subset
     - TCP/UDP/SCTP, IPv4 and IPv6, multiple backends, EndpointSlice updates,
       deletion cleanup, and CoreDNS lookup through the nftables backend.
   * - CoreDNS Service
     - Supported
     - Validated as a ClusterIP UDP lookup in the dual-stack profile.
   * - NodePort Services
     - Supported subset
     - Basic wildcard NodePort TCP/UDP/SCTP for IPv4 and IPv6, including
       session affinity on the supported subset.
   * - LoadBalancer / ExternalIP Services
     - Supported subset
     - Frontends are translated through nftables for IPv4 and IPv6, including
       source-range filtering, session affinity, healthCheckNodePort, traffic
       policy Local, and topology-aware backend selection. Full kube-proxy
       parity remains deferred.
   * - LocalRedirectPolicy
     - Supported subset
     - Redirect policies can create ``LocalRedirect`` frontends and
       pseudo-services backed by local pods when ``localRedirectPolicy`` is
       enabled.
   * - Kubernetes NetworkPolicy
     - Supported subset
     - Standard K8s NetworkPolicy ingress/egress default deny, pod and
       namespace selectors, combined selectors, ``matchExpressions``, named
       ports, ``endPort``, ``ipBlock`` with ``except``, and TCP/UDP/SCTP
       ports.
   * - Cilium policy extensions
     - Unsupported
     - CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, L7, DNS/FQDN, and
       identity-aware Cilium semantics remain outside this backend.
   * - eBPF-dependent features
     - Unsupported
     - BPF masquerade, socket LB, host firewall, Hubble datapath flow events,
       transparent encryption, XDP acceleration, bandwidth manager, and egress
       gateway are not part of the supported no-eBPF branch scope.

Validation gates
----------------

Use ``contrib/testing/noebpf-local-ci.sh`` as the local no-eBPF gate. The
script runs hygiene checks, focused Go tests, status waits, Service and
NetworkPolicy smokes, and the targeted Cilium connectivity scenarios that match
the support matrix above. Broader connectivity or Sonobuoy runs can be useful
signals, but failures in features outside this matrix should be triaged as
follow-up product work rather than silently expanding the support scope.
