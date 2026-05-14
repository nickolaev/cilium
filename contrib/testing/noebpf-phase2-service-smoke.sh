#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -euo pipefail

context="${1:-${KUBECONTEXT:-kind-noebpf-p2}}"
cluster="${KIND_CLUSTER_NAME:-${context#kind-}}"
namespace="${NOEBPF_SMOKE_NS:-noebpf-p2-smoke}"

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

worker_node="$(kind get nodes --name "${cluster}" | grep -v control-plane | head -n1)"
if [[ -z "${worker_node}" ]]; then
  echo "could not find worker node for kind cluster ${cluster}" >&2
  exit 1
fi

cat <<YAML | "${kubectl_cmd[@]}" apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  namespace: ${namespace}
spec:
  replicas: 2
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
      - name: echo
        image: registry.k8s.io/e2e-test-images/agnhost:2.53
        args: ["netexec", "--http-port=8080", "--udp-port=8081"]
        ports:
        - containerPort: 8080
          protocol: TCP
        - containerPort: 8081
          protocol: UDP
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: ${namespace}
spec:
  type: NodePort
  ipFamilyPolicy: RequireDualStack
  selector:
    app: echo
  ports:
  - name: http
    port: 8080
    targetPort: 8080
    nodePort: 30080
    protocol: TCP
  - name: udp
    port: 8081
    targetPort: 8081
    nodePort: 30081
    protocol: UDP
---
apiVersion: v1
kind: Pod
metadata:
  name: client
  namespace: ${namespace}
spec:
  containers:
  - name: client
    image: registry.k8s.io/e2e-test-images/agnhost:2.53
    command: ["sleep", "36000"]
YAML

"${kubectl_cmd[@]}" -n "${namespace}" rollout status deploy/echo --timeout=180s
"${kubectl_cmd[@]}" -n "${namespace}" wait --for=condition=Ready pod/client --timeout=180s

svc4="$("${kubectl_cmd[@]}" -n "${namespace}" get svc echo -o jsonpath='{range .spec.clusterIPs[*]}{@}{"\n"}{end}' | grep -E '^[0-9.]+$' | head -n1)"
svc6="$("${kubectl_cmd[@]}" -n "${namespace}" get svc echo -o jsonpath='{range .spec.clusterIPs[*]}{@}{"\n"}{end}' | grep -E ':' | head -n1)"
node4="$("${kubectl_cmd[@]}" get node "${worker_node}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | awk '{print $1}')"
node6="$(docker inspect "${worker_node}" --format '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}')"
if [[ -z "${svc4}" || -z "${svc6}" ]]; then
  echo "expected dual-stack ClusterIPs for ${namespace}/echo, got v4=${svc4:-<none>} v6=${svc6:-<none>}" >&2
  exit 1
fi

pod_connect() {
  local proto="$1" target="$2"
  echo "pod ${proto} ${target}"
  "${kubectl_cmd[@]}" -n "${namespace}" exec client -- /agnhost connect --timeout=5s --protocol="${proto}" "${target}"
}

pod_connect tcp "${svc4}:8080"
pod_connect tcp "[${svc6}]:8080"
pod_connect udp "${svc4}:8081"
pod_connect udp "[${svc6}]:8081"
pod_connect tcp "${node4}:30080"
pod_connect tcp "[${node6}]:30080"
pod_connect udp "${node4}:30081"
pod_connect udp "[${node6}]:30081"

echo "node TCP ClusterIP/NodePort checks"
docker exec "${worker_node}" curl -g -sS --connect-timeout 3 --max-time 5 "http://${svc4}:8080/hostname" >/dev/null
docker exec "${worker_node}" curl -g -sS --connect-timeout 3 --max-time 5 "http://[${svc6}]:8080/hostname" >/dev/null
docker exec "${worker_node}" curl -g -sS --connect-timeout 3 --max-time 5 "http://${node4}:30080/hostname" >/dev/null
docker exec "${worker_node}" curl -g -sS --connect-timeout 3 --max-time 5 "http://[${node6}]:30080/hostname" >/dev/null

kube_dns4="$("${kubectl_cmd[@]}" -n kube-system get svc kube-dns -o jsonpath='{range .spec.clusterIPs[*]}{@}{"\n"}{end}' 2>/dev/null | grep -E '^[0-9.]+$' | head -n1 || true)"
kube_dns6="$("${kubectl_cmd[@]}" -n kube-system get svc kube-dns -o jsonpath='{range .spec.clusterIPs[*]}{@}{"\n"}{end}' 2>/dev/null | grep -E ':' | head -n1 || true)"
if [[ -n "${kube_dns4}" ]]; then
  echo "CoreDNS Service UDP IPv4 check ${kube_dns4}:53"
  "${kubectl_cmd[@]}" -n "${namespace}" exec client -- dig +short +time=2 +tries=1 "@${kube_dns4}" kubernetes.default.svc.cluster.local A >/dev/null
fi
if [[ -n "${kube_dns6}" ]]; then
  echo "CoreDNS Service UDP IPv6 check ${kube_dns6}:53"
  "${kubectl_cmd[@]}" -n "${namespace}" exec client -- dig +short +time=2 +tries=1 "@${kube_dns6}" kubernetes.default.svc.cluster.local AAAA >/dev/null
fi

echo "scale-down reconciliation check"
"${kubectl_cmd[@]}" -n "${namespace}" scale deploy/echo --replicas=1 >/dev/null
"${kubectl_cmd[@]}" -n "${namespace}" rollout status deploy/echo --timeout=120s >/dev/null
sleep 5
if [[ "$(docker exec "${worker_node}" nft list table inet cilium_noebpf | grep -c "${svc4} tcp dport 8080")" != "2" ]]; then
  echo "expected one ClusterIP TCP backend in prerouting and output after scale-down" >&2
  docker exec "${worker_node}" nft list table inet cilium_noebpf | grep "${svc4} tcp dport 8080" >&2 || true
  exit 1
fi

echo "service deletion cleanup check"
"${kubectl_cmd[@]}" -n "${namespace}" delete svc echo >/dev/null
sleep 5
table="$(docker exec "${worker_node}" nft list table inet cilium_noebpf)"
if grep -Eq "${svc4}|${svc6}|30080|30081" <<<"${table}"; then
  echo "stale Service rules remain after deletion" >&2
  grep -E "${svc4}|${svc6}|30080|30081" <<<"${table}" >&2 || true
  exit 1
fi

echo "agent restart convergence check"
"${kubectl_cmd[@]}" -n "${namespace}" apply -f - <<YAML
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: ${namespace}
spec:
  type: NodePort
  ipFamilyPolicy: RequireDualStack
  selector:
    app: echo
  ports:
  - name: http
    port: 8080
    targetPort: 8080
    nodePort: 30080
    protocol: TCP
  - name: udp
    port: 8081
    targetPort: 8081
    nodePort: 30081
    protocol: UDP
YAML
"${kubectl_cmd[@]}" -n kube-system delete pod -l k8s-app=cilium --force >/dev/null
"${kubectl_cmd[@]}" -n kube-system rollout status ds/cilium --timeout=180s >/dev/null
for _ in $(seq 1 30); do
  table="$(docker exec "${worker_node}" nft list table inet cilium_noebpf)"
  if grep -q "30080" <<<"${table}"; then
    echo "Phase 2 no-eBPF Service smoke passed for ${context}"
    exit 0
  fi
  sleep 1
done

echo "NodePort rules missing after agent restart" >&2
docker exec "${worker_node}" nft list table inet cilium_noebpf >&2 || true
exit 1
