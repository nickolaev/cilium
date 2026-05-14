#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -euo pipefail

context="${1:-${KUBECONTEXT:-kind-noebpf-p3}}"
cluster="${KIND_CLUSTER_NAME:-${context#kind-}}"
namespace="${NOEBPF_SMOKE_NS:-noebpf-p3-smoke}"
peer_namespace="${NOEBPF_SMOKE_PEER_NS:-noebpf-p3-peer}"

kubectl_cmd=(kubectl --context "${context}")

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require kubectl
require kind
require docker

nodes=( $(kind get nodes --name "${cluster}") )
if [[ ${#nodes[@]} -lt 2 ]]; then
  echo "expected at least two kind nodes for cross-node policy smoke" >&2
  exit 1
fi
server_node="${nodes[0]}"
client_node="${nodes[1]}"

cat <<YAML | "${kubectl_cmd[@]}" apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
  labels:
    noebpf-role: server
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${peer_namespace}
  labels:
    noebpf-role: peer
---
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: ${namespace}
  labels:
    app: server
spec:
  nodeSelector:
    kubernetes.io/hostname: ${server_node}
  containers:
  - name: server
    image: registry.k8s.io/e2e-test-images/agnhost:2.53
    args: ["netexec", "--http-port=8080", "--udp-port=8081"]
    ports:
    - containerPort: 8080
      protocol: TCP
    - containerPort: 8081
      protocol: UDP
---
apiVersion: v1
kind: Pod
metadata:
  name: allowed
  namespace: ${peer_namespace}
  labels:
    access: allowed
spec:
  nodeSelector:
    kubernetes.io/hostname: ${client_node}
  containers:
  - name: client
    image: registry.k8s.io/e2e-test-images/agnhost:2.53
    command: ["sleep", "36000"]
---
apiVersion: v1
kind: Pod
metadata:
  name: denied
  namespace: ${peer_namespace}
  labels:
    access: denied
spec:
  nodeSelector:
    kubernetes.io/hostname: ${client_node}
  containers:
  - name: client
    image: registry.k8s.io/e2e-test-images/agnhost:2.53
    command: ["sleep", "36000"]
---
apiVersion: v1
kind: Pod
metadata:
  name: blocked
  namespace: ${peer_namespace}
  labels:
    app: blocked
spec:
  nodeSelector:
    kubernetes.io/hostname: ${client_node}
  containers:
  - name: blocked
    image: registry.k8s.io/e2e-test-images/agnhost:2.53
    args: ["netexec", "--http-port=8080", "--udp-port=8081"]
    ports:
    - containerPort: 8080
      protocol: TCP
    - containerPort: 8081
      protocol: UDP
---
apiVersion: v1
kind: Pod
metadata:
  name: egress
  namespace: ${namespace}
  labels:
    role: egress
spec:
  nodeSelector:
    kubernetes.io/hostname: ${server_node}
  containers:
  - name: client
    image: registry.k8s.io/e2e-test-images/agnhost:2.53
    command: ["sleep", "36000"]
YAML

"${kubectl_cmd[@]}" -n "${namespace}" wait --for=condition=Ready pod/server pod/egress --timeout=180s
"${kubectl_cmd[@]}" -n "${peer_namespace}" wait --for=condition=Ready pod/allowed pod/denied pod/blocked --timeout=180s

server4="$("${kubectl_cmd[@]}" -n "${namespace}" get pod server -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' | grep -E '^[0-9.]+$' | head -n1)"
server6="$("${kubectl_cmd[@]}" -n "${namespace}" get pod server -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' | grep -E ':' | head -n1)"
blocked4="$("${kubectl_cmd[@]}" -n "${peer_namespace}" get pod blocked -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' | grep -E '^[0-9.]+$' | head -n1)"
blocked6="$("${kubectl_cmd[@]}" -n "${peer_namespace}" get pod blocked -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' | grep -E ':' | head -n1)"
if [[ -z "${server4}" || -z "${server6}" || -z "${blocked4}" || -z "${blocked6}" ]]; then
  echo "could not determine dual-stack PodIPs, server v4=${server4:-<none>} v6=${server6:-<none>} blocked v4=${blocked4:-<none>} v6=${blocked6:-<none>}" >&2
  exit 1
fi

connect() {
  local proto="$1" ns="$2" pod="$3" target="$4"
  "${kubectl_cmd[@]}" -n "${ns}" exec "${pod}" -- /agnhost connect --timeout=5s --protocol="${proto}" "${target}"
}

expect_fail() {
  local proto="$1" ns="$2" pod="$3" target="$4"
  if connect "${proto}" "${ns}" "${pod}" "${target}" >/dev/null 2>&1; then
    echo "expected ${proto} ${ns}/${pod} -> ${target} to fail" >&2
    return 1
  fi
}

echo "baseline pod-to-pod allow"
connect tcp "${peer_namespace}" allowed "${server4}:8080" >/dev/null
connect tcp "${peer_namespace}" allowed "[${server6}]:8080" >/dev/null
connect udp "${peer_namespace}" allowed "${server4}:8081" >/dev/null
connect udp "${peer_namespace}" allowed "[${server6}]:8081" >/dev/null

cat <<YAML | "${kubectl_cmd[@]}" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: server-ingress
  namespace: ${namespace}
spec:
  podSelector:
    matchLabels:
      app: server
  policyTypes: [Ingress]
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          noebpf-role: peer
      podSelector:
        matchLabels:
          access: allowed
    - podSelector:
        matchLabels:
          role: egress
    ports:
    - protocol: TCP
      port: 8080
    - protocol: UDP
      port: 8081
YAML
sleep 5

echo "ingress allow/deny"
connect tcp "${peer_namespace}" allowed "${server4}:8080" >/dev/null
connect tcp "${peer_namespace}" allowed "[${server6}]:8080" >/dev/null
connect udp "${peer_namespace}" allowed "${server4}:8081" >/dev/null
connect udp "${peer_namespace}" allowed "[${server6}]:8081" >/dev/null
expect_fail tcp "${peer_namespace}" denied "${server4}:8080"
expect_fail tcp "${peer_namespace}" denied "[${server6}]:8080"
expect_fail udp "${peer_namespace}" denied "${server4}:8081"
expect_fail udp "${peer_namespace}" denied "[${server6}]:8081"

cat <<YAML | "${kubectl_cmd[@]}" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-ipblock
  namespace: ${namespace}
spec:
  podSelector:
    matchLabels:
      role: egress
  policyTypes: [Egress]
  egress:
  - to:
    - ipBlock:
        cidr: ${server4}/32
    - ipBlock:
        cidr: ${server6}/128
    ports:
    - protocol: TCP
      port: 8080
    - protocol: UDP
      port: 8081
YAML
sleep 5

echo "egress ipBlock allow/deny"
connect tcp "${namespace}" egress "${server4}:8080" >/dev/null
connect tcp "${namespace}" egress "[${server6}]:8080" >/dev/null
connect udp "${namespace}" egress "${server4}:8081" >/dev/null
connect udp "${namespace}" egress "[${server6}]:8081" >/dev/null
expect_fail tcp "${namespace}" egress "${blocked4}:8080"
expect_fail tcp "${namespace}" egress "[${blocked6}]:8080"
expect_fail udp "${namespace}" egress "${blocked4}:8081"
expect_fail udp "${namespace}" egress "[${blocked6}]:8081"

agent_node="${server_node}"
table="$(docker exec "${agent_node}" nft list table inet cilium_noebpf)"
if ! grep -q "ip daddr ${server4} tcp dport 8080 accept" <<<"${table}"; then
  echo "expected nft policy allow for ${server4} tcp dport 8080" >&2
  docker exec "${agent_node}" nft list table inet cilium_noebpf >&2 || true
  exit 1
fi
if ! grep -q "ip6 daddr ${server6} udp dport 8081 accept" <<<"${table}"; then
  echo "expected nft policy allow for ${server6} udp dport 8081" >&2
  docker exec "${agent_node}" nft list table inet cilium_noebpf >&2 || true
  exit 1
fi

"${kubectl_cmd[@]}" -n "${namespace}" delete netpol server-ingress egress-ipblock >/dev/null
sleep 5
connect tcp "${peer_namespace}" denied "${server4}:8080" >/dev/null
connect tcp "${peer_namespace}" denied "[${server6}]:8080" >/dev/null

echo "Phase 3 no-eBPF NetworkPolicy smoke passed for ${context}"
