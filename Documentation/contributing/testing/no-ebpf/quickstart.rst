No-eBPF local CI quickstart
===========================

This page is the operator/developer checklist for the experimental
``bpf.datapathMode=linux-route`` path. It covers the local gates that should be
run while remote CI is unavailable or before a CI job is promoted.

Supported no-eBPF scope
-----------------------

The no-eBPF mode is still experimental and intentionally limited to the kind
profile:

* dual-stack kind clusters with kube-proxy disabled;
* ``linux-route`` pod attachment/routing;
* nftables-owned ``inet cilium_noebpf`` table;
* Service replacement for ClusterIP, NodePort, LoadBalancer, ExternalIP, and
  LocalRedirect traffic within the supported subset, plus CoreDNS lookup,
  source-range filtering, session affinity, healthCheckNodePort, traffic
  policy Local, and topology-aware hints;
* Kubernetes NetworkPolicy enforcement for namespace/pod selectors,
  ``matchExpressions``, named ports, ``endPort``, ``ipBlock`` with ``except``,
  and TCP/UDP/SCTP port rules;
* startup cleanup and atomic replacement of Cilium-owned nftables state.

Out of scope until explicitly added to the support matrix:

* full kube-proxy parity beyond the current Service subset;
* CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, L7 policy, FQDN policy,
  entity-based policy, host firewall, Hubble datapath events, transparent
  encryption, bandwidth manager, BPF masquerade, egress gateway, XDP
  acceleration, and other eBPF-dependent datapath features.

Cluster setup
-------------

Create two dual-stack kind clusters with kube-proxy disabled. The first validates
service behavior; the second enables the Kubernetes NetworkPolicy overlay. If
both clusters run at the same time, use distinct agent
and operator port prefixes.

.. code-block:: shell-session

   $ CLUSTER_NAME=noebpf-p2fresh KUBEPROXY_MODE=none IPFAMILY=dual \
       ./contrib/scripts/kind.sh
   $ CLUSTER_NAME=noebpf-p3fresh KUBEPROXY_MODE=none IPFAMILY=dual \
       AGENTPORTPREFIX=236 OPERATORPORTPREFIX=237 ./contrib/scripts/kind.sh
   $ make kind-image

Install from the local tree/image:

.. code-block:: shell-session

   $ cilium install --context kind-noebpf-p2fresh --wait \
       --chart-directory install/kubernetes/cilium \
       --values contrib/testing/kind-no-ebpf-dual.yaml
   $ cilium install --context kind-noebpf-p3fresh --wait \
       --chart-directory install/kubernetes/cilium \
       --values contrib/testing/kind-no-ebpf-dual.yaml \
       --values contrib/testing/kind-no-ebpf-dual-policy.yaml

The status output should expose both the operational datapath and the no-eBPF
feature notes:

.. code-block:: shell-session

   $ cilium status --context kind-noebpf-p3fresh --wait
   $ kubectl --context kind-noebpf-p3fresh -n kube-system exec ds/cilium -- \
       cilium-dbg status --verbose | grep -E 'Device Mode|No-eBPF|KubeProxyReplacement'

Local CI runner
---------------

Use the local runner to execute the same gates repeatedly:

.. code-block:: shell-session

   $ contrib/testing/noebpf-local-ci.sh

By default it runs formatting hygiene, focused Go tests, Cilium status waits,
the Service and NetworkPolicy smoke scripts, targeted no-policy connectivity
tests, and the Cilium CLI all-ingress-deny KNP scenario. It expects these
contexts unless overridden:

* ``NOEBPF_P2_CONTEXT=kind-noebpf-p2fresh``
* ``NOEBPF_P3_CONTEXT=kind-noebpf-p3fresh``

Useful options:

.. code-block:: shell-session

   $ NOEBPF_RUN_BROAD_GO=1 contrib/testing/noebpf-local-ci.sh
   $ NOEBPF_BUILD_IMAGE=1 contrib/testing/noebpf-local-ci.sh
   $ NOEBPF_INSTALL=1 contrib/testing/noebpf-local-ci.sh
   $ NOEBPF_RUN_CONNECTIVITY=0 contrib/testing/noebpf-local-ci.sh
   $ NOEBPF_RUN_CONNECTIVITY_KNP=0 contrib/testing/noebpf-local-ci.sh

When ``NOEBPF_INSTALL=1`` is used, the runner pins ``k8sServiceHost`` to the
current kind control-plane node IP. This is intentional for kube-proxy-free
clusters: if Docker or kind IP addresses changed since the last install, Cilium
would otherwise keep trying to contact the stale API server address before the
Service datapath is available.

Connectivity coverage
---------------------

The targeted connectivity suite is deliberately narrower than the default
``cilium connectivity test`` matrix because the default suite includes features
outside the supported no-eBPF matrix. The local runner executes:

* ``no-policies/pod-to-pod``;
* ``no-policies/client-to-client``;
* ``no-policies/pod-to-service``;
* ``all-ingress-deny-knp/pod-to-pod`` on the policy-enabled cluster. Disable it
  with ``NOEBPF_RUN_CONNECTIVITY_KNP=0`` only when debugging the no-policy
  paths.

Any expansion of these tests should be paired with an update to the supported
scope above and with nftables renderer/executor coverage.
