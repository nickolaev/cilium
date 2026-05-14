#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

NOEBPF_P2_CONTEXT="${NOEBPF_P2_CONTEXT:-kind-noebpf-p2fresh}"
NOEBPF_P3_CONTEXT="${NOEBPF_P3_CONTEXT:-kind-noebpf-p3fresh}"
NOEBPF_RUN_CONNECTIVITY="${NOEBPF_RUN_CONNECTIVITY:-1}"
NOEBPF_RUN_CONNECTIVITY_KNP="${NOEBPF_RUN_CONNECTIVITY_KNP:-1}"
NOEBPF_RUN_BROAD_GO="${NOEBPF_RUN_BROAD_GO:-0}"
NOEBPF_BUILD_IMAGE="${NOEBPF_BUILD_IMAGE:-0}"
NOEBPF_INSTALL="${NOEBPF_INSTALL:-0}"
NOEBPF_RESTART_ON_UPGRADE="${NOEBPF_RESTART_ON_UPGRADE:-1}"
CILIUM_CLI="${CILIUM_CLI:-cilium}"
KUBECTL="${KUBECTL:-kubectl}"

log() {
  printf '\n==> %s\n' "$*"
}

run() {
  log "$*"
  "$@"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

context_exists() {
  "${KUBECTL}" config get-contexts "$1" >/dev/null 2>&1
}

require_context() {
  local ctx="$1"
  if ! context_exists "$ctx"; then
    cat >&2 <<MSG
missing Kubernetes context: ${ctx}
Create or select the no-eBPF kind clusters first, or override with NOEBPF_P2_CONTEXT/NOEBPF_P3_CONTEXT.
MSG
    exit 1
  fi
}

detect_control_plane_ip() {
  local ctx="$1"
  "${KUBECTL}" --context "$ctx" get nodes \
    -l node-role.kubernetes.io/control-plane \
    -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' | awk '{print $1}'
}

install_noebpf() {
  local ctx="$1"
  local verb="install"
  local policy_values=()
  local api_host
  local api_values=()
  if [[ "$ctx" == "$NOEBPF_P3_CONTEXT" ]]; then
    policy_values=(--values contrib/testing/kind-no-ebpf-dual-policy.yaml)
  fi
  if "${KUBECTL}" --context "$ctx" -n kube-system get ds/cilium >/dev/null 2>&1; then
    verb="upgrade"
  fi

  # kube-proxy-free kind clusters cannot rely on the kubernetes ClusterIP before
  # Cilium is up. Pin the agent/operator to the current control-plane node IP so
  # local clusters recover after Docker/kind IP churn.
  api_host="$(detect_control_plane_ip "$ctx")"
  if [[ -n "$api_host" ]]; then
    api_values=(--set "k8sServiceHost=${api_host}" --set k8sServicePort=6443)
  fi

  run "${CILIUM_CLI}" "$verb" \
    --context "$ctx" \
    --chart-directory install/kubernetes/cilium \
    --values contrib/testing/kind-no-ebpf-dual.yaml \
    "${policy_values[@]}" \
    "${api_values[@]}" \
    --wait

  if [[ "$verb" == "upgrade" && "$NOEBPF_RESTART_ON_UPGRADE" == "1" ]]; then
    # Kind uses a stable local image tag with imagePullPolicy=Never. Restart the
    # agent after upgrades so a freshly loaded local image is actually consumed.
    run "${KUBECTL}" --context "$ctx" -n kube-system rollout restart ds/cilium
    run "${KUBECTL}" --context "$ctx" -n kube-system rollout status ds/cilium --timeout=5m
  fi
}

run_connectivity() {
  run "${CILIUM_CLI}" connectivity test \
    --context "$NOEBPF_P2_CONTEXT" \
    --force-deploy \
    --test no-policies/pod-to-pod \
    --test no-policies/client-to-client \
    --test no-policies/pod-to-service \
    --flow-validation disabled \
    --hubble=false \
    --timeout 10m

  local p3_tests=(
    --test no-policies/pod-to-pod
    --test no-policies/client-to-client
    --test no-policies/pod-to-service
  )
  if [[ "$NOEBPF_RUN_CONNECTIVITY_KNP" == "1" ]]; then
    p3_tests+=(--test all-ingress-deny-knp/pod-to-pod)
  fi

  run "${CILIUM_CLI}" connectivity test \
    --context "$NOEBPF_P3_CONTEXT" \
    --force-deploy \
    "${p3_tests[@]}" \
    --flow-validation disabled \
    --hubble=false \
    --timeout 10m
}

require_cmd go
require_cmd git
require_cmd python3
require_cmd "${KUBECTL}"
require_cmd "${CILIUM_CLI}"

run git diff --check
run python3 -m json.tool install/kubernetes/cilium/values.schema.json >/dev/null

if command -v helm >/dev/null 2>&1; then
  run helm template cilium install/kubernetes/cilium \
    --values contrib/testing/kind-no-ebpf-dual.yaml \
    >/dev/null
  run helm template cilium install/kubernetes/cilium \
    --values contrib/testing/kind-no-ebpf-dual.yaml \
    --values contrib/testing/kind-no-ebpf-dual-policy.yaml \
    >/dev/null
else
  log "helm not found; skipping no-eBPF Helm render gate"
fi

run go test ./pkg/datapath/connector ./pkg/datapath/loader ./pkg/datapath/linux/noebpf/... ./pkg/status ./pkg/client

if [[ "$NOEBPF_RUN_BROAD_GO" == "1" ]]; then
  run go test ./pkg/datapath/... ./pkg/loadbalancer/... ./pkg/service/... ./pkg/k8s/watchers/...
fi

if [[ "$NOEBPF_BUILD_IMAGE" == "1" ]]; then
  run make kind-image
fi

require_context "$NOEBPF_P2_CONTEXT"
require_context "$NOEBPF_P3_CONTEXT"

if [[ "$NOEBPF_INSTALL" == "1" ]]; then
  install_noebpf "$NOEBPF_P2_CONTEXT"
  install_noebpf "$NOEBPF_P3_CONTEXT"
else
  run "${CILIUM_CLI}" status --context "$NOEBPF_P2_CONTEXT" --wait
  run "${CILIUM_CLI}" status --context "$NOEBPF_P3_CONTEXT" --wait
fi

run contrib/testing/noebpf-phase2-service-smoke.sh "$NOEBPF_P2_CONTEXT"
run contrib/testing/noebpf-phase3-policy-smoke.sh "$NOEBPF_P3_CONTEXT"

if [[ "$NOEBPF_RUN_CONNECTIVITY" == "1" ]]; then
  run_connectivity
fi

log "no-eBPF local CI completed"
