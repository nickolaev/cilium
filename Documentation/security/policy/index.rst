.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _network_policy:
.. _Network Policies:
.. _Network Policy:

Overview of Network Policy
--------------------------

This chapter documents the policy language used to configure network policies
in Cilium. For a basic understanding, read the :ref:`introduction <policy_guide>`.
More details are covered on the respective pages for different kinds of policies
and ways to define them.

Policy support matrix
---------------------

The table below summarizes the main policy families documented in Cilium and
their current status in the no-eBPF / linux-route branch.

.. list-table::
   :header-rows: 1
   :widths: 26 16 14 44

   * - Policy family
     - Native Cilium scope
     - no-eBPF now
     - Notes
   * - Kubernetes ``NetworkPolicy``
     - Standard allow policy
     - Yes
     - Implemented as a subset: ingress / egress default-deny, selectors,
       ``matchExpressions``, named ports, ``endPort``, ``ipBlock`` / ``except``,
       and TCP / UDP / SCTP policy ports.
   * - ``CiliumNetworkPolicy``
     - Namespace-scoped Cilium CRD
     - Partial
     - L3 / L4 allow and deny rules, selector matching, namespace labels,
       named ports, ``endPort``, ``ipBlock`` / ``except``, CIDR groups,
       service targets, and ICMP are supported.
       Deny rules are rendered before allow rules so they win on overlap.
       Rich Cilium identity-aware semantics, L7 rules, DNS rules,
       authentication, node selectors, and Cilium-only
       entity/group features remain out of scope.
   * - ``CiliumClusterwideNetworkPolicy``
     - Cluster-scoped Cilium CRD
     - Partial
     - Same supported subset as ``CiliumNetworkPolicy`` with cluster-wide
       scope. Host policies are still unsupported.
   * - Deny policies
     - Explicit deny rules that override allow rules
     - Partial
     - L3 / L4 ``ingressDeny`` / ``egressDeny`` rules are supported and
       evaluated before allow rules. Policy overlap across KNP, CNP, and CCNP
       is handled by the nftables renderer ordering.
   * - Host policies
     - ``CiliumClusterwideNetworkPolicy`` with ``NodeSelector``
     - No
     - Requires host-firewall behavior and node-level enforcement that the
       no-eBPF branch does not provide.
   * - Layer 7 HTTP / Kafka policy
     - Proxy-enforced application policy
     - No
     - Requires protocol-aware proxying rather than packet-only translation.
   * - Layer 7 DNS policy / ``toFQDNs``
     - DNS proxy plus IP discovery
     - No
     - Would require DNS interception, DNS policy evaluation, and DNS cache
       integration in addition to nftables rules.
   * - ``CiliumLocalRedirectPolicy``
     - Local redirect / pseudo-service behavior
     - Yes
     - Implemented in the current no-eBPF backend.

Current no-eBPF policy gaps
---------------------------

The following policy features are still not implemented in the no-eBPF
backend:

* Host policies and node-level enforcement.
* L7 policy, including HTTP, Kafka, TLS, and other proxy-layer rules.
* DNS / FQDN policy via ``toFQDNs``.
* Identity-aware selectors and special entities.
* Node selectors.
* Proxy-dependent authentication semantics.
* Any policy behavior that depends on eBPF-only datapath hooks.

Security policies can be specified and imported via the following mechanisms:

* Using Kubernetes `NetworkPolicy`, `CiliumNetworkPolicy` and `CiliumClusterwideNetworkPolicy`
  resources. See the section :ref:`k8s_policy` for more details. In this mode,
  Kubernetes will automatically distribute the policies to all agents.

* Directly imported into the agent via CLI or :ref:`api_ref` of the agent. This
  method does not automatically distribute policies to all agents. It is in the
  responsibility of the user to import the policy in all required agents. (This
  method is deprecated as of v1.18 and will be removed in v1.19.)

.. toctree::
   :maxdepth: 2
   :glob:

   intro
   layer3
   layer4
   layer7
   deny
   disk-based
   host
   kubernetes
   lifecycle
   troubleshooting
   caveats
