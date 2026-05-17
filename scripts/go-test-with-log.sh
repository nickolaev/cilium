#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GO_BIN="${GO_BIN:-}"
if [[ -z "$GO_BIN" ]]; then
  GO_BIN="$(command -v go)"
fi

if [[ ! -x "$GO_BIN" ]]; then
  echo "error: could not find a usable Go binary" >&2
  exit 1
fi

LOG_DIR="${LOG_DIR:-$ROOT_DIR/.codex-cache/logs}"
TMPDIR="${TMPDIR:-$ROOT_DIR/.codex-cache/tmp}"

mkdir -p "$LOG_DIR" "$TMPDIR"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${LOG_FILE:-$LOG_DIR/go-test-$TIMESTAMP.log}"

TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=(./...)
fi

{
  echo "[$(date -Is)] go test started"
  echo "repo: $ROOT_DIR"
  echo "go: $GO_BIN"
  echo "targets: ${TARGETS[*]}"
  echo "TMPDIR=$TMPDIR"
  echo
} | tee "$LOG_FILE"

set +e
TMPDIR="$TMPDIR" "$GO_BIN" test "${TARGETS[@]}" 2>&1 | tee -a "$LOG_FILE"
STATUS=${PIPESTATUS[0]}
set -e

{
  echo
  echo "[$(date -Is)] go test finished with exit code $STATUS"
  echo "log file: $LOG_FILE"
} | tee -a "$LOG_FILE"

exit "$STATUS"
