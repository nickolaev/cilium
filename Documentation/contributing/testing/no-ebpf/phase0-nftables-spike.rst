Experimental no-eBPF nftables spike
====================================

This note captures the first execution gate for the experimental
``bpf.datapathMode=linux-route`` product-demo direction. The goal is to prove
that a single nftables backend can cover the minimum dual-stack Service and
Kubernetes NetworkPolicy behavior before wiring privileged rule programming into
``cilium-agent``.

Scope
-----

The spike is deliberately narrow:

* dual-stack kind cluster;
* kube-proxy disabled;
* Cilium eBPF KPR/socket-LB disabled;
* ``linux-route`` pod attachment/routing;
* one nftables-owned table, ``inet cilium_noebpf``;
* one IPv4 and one IPv6 ClusterIP DNAT smoke;
* one IPv4 and one IPv6 default-deny-plus-allow NetworkPolicy smoke;
* startup cleanup of stale ``cilium_noebpf`` state.

Non-goals
---------

The spike does not attempt LoadBalancer, ExternalIPs, topology hints, session
affinity, L7 policy, CiliumNetworkPolicy, host firewall, Hubble datapath events,
transparent encryption, bandwidth manager, or full kube-proxy parity.

Suggested cluster setup
-----------------------

Create a dual-stack kind cluster without kube-proxy, then install Cilium with the
Phase 0 values file:

.. code-block:: shell-session

   $ KUBEPROXY_MODE=none IPFAMILY=dual ./contrib/scripts/kind.sh
   $ make kind-image
   $ cilium install --wait \
       --chart-directory=install/kubernetes/cilium \
       --set image.override=localhost:5000/cilium/cilium-dev:local \
       --set image.pullPolicy=Never \
       --set operator.image.override=localhost:5000/cilium/operator-generic:local \
       --set operator.image.pullPolicy=Never \
       --values=contrib/testing/kind-no-ebpf-dual.yaml

Expected baseline before the nftables backend exists
----------------------------------------------------

* pod IP allocation and route-only pod-to-pod connectivity should be debugged
  first for both IPv4 and IPv6;
* ClusterIP and NodePort should fail with kube-proxy disabled until the nftables
  Service backend exists;
* Kubernetes NetworkPolicy should not be enforced until the nftables policy
  backend exists;
* no Cilium TC/XDP forwarding programs should be attached for workload
  forwarding in ``linux-route`` mode.

Phase 0 exit criteria
---------------------

The nftables backend remains a blocking gate. Do not start full Service or
NetworkPolicy integration until all of these are demonstrated in kind:

#. required nftables nat/filter hooks are available;
#. owned-table replacement works with the target nft version (kind currently ships nft v1.0.6, so the executor may need delete/flush-before-create rather than newer ``destroy table`` syntax);
#. IPv4 ClusterIP DNAT reaches an IPv4 backend Pod;
#. IPv6 ClusterIP DNAT reaches an IPv6 backend Pod;
#. IPv4 default-deny plus allow rule works for one backend Pod;
#. IPv6 default-deny plus allow rule works for one backend Pod;
#. stale ``cilium_noebpf`` state is removed or replaced on agent restart.

If any criterion fails, pause and choose a new backend direction explicitly
instead of adding an implicit iptables/IPVS fallback.

Phase 2 Service smoke
---------------------

The Phase 2 Service MVP keeps kube-proxy disabled and uses the owned
``inet cilium_noebpf`` table for the core Service paths only. The accepted
scope is deliberately small: dual-stack ClusterIP and basic wildcard NodePort
for TCP/UDP with active EndpointSlice backends. LoadBalancer, ExternalIPs,
traffic policies, topology hints, session affinity, health checks, source
ranges, and SCTP remain outside this phase.

After installing the dual-stack no-eBPF profile, verify the agent reports
``Device Mode: linux-route`` and that kube-proxy is not providing Service
translation for the test. Then inspect the rendered table:

.. code-block:: shell-session

   $ kubectl -n kube-system exec ds/cilium -- cilium-dbg status --verbose \
       | grep -E 'Device Mode|KubeProxyReplacement|Socket LB'
   $ kubectl -n kube-system exec ds/cilium -- nft list table inet cilium_noebpf

Minimum Service checks:

#. pod-to-ClusterIP over IPv4 and IPv6;
#. node-to-ClusterIP over IPv4 and IPv6;
#. pod-to-NodePort over IPv4 and IPv6;
#. node-to-NodePort over IPv4 and IPv6;
#. CoreDNS Service lookup over UDP;
#. scaling a backend down removes the stale DNAT target after reconciliation;
#. deleting a Service removes its nftables rules after reconciliation;
#. restarting ``cilium-agent`` recreates only the current desired Service rules.

Wildcard NodePort frontends are rendered as protocol/port matches in the owned
nat hooks. This is acceptable for the product-demo spike but must be narrowed to
node-address matches before the support matrix is expanded beyond Phase 2.
