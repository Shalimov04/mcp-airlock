#!/usr/bin/env bash
# Build, bring up the isolated stack, run the scenarios, tear everything down. Exit code = scenario result.
set -euo pipefail
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
cd "$(dirname "$0")"
start=$(date +%s)

K3S=rancher/k3s:v1.33.4-k3s1
MCP=ghcr.io/containers/kubernetes-mcp-server:latest
CLUSTER_IMAGES=(registry.k8s.io/pause:3.10 busybox:1.36)   # imported into k3s, which has no egress

for img in "$K3S" "$MCP" "${CLUSTER_IMAGES[@]}"; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img"
done
mkdir -p .build
docker save -o .build/images.tar "${CLUSTER_IMAGES[@]}"
docker build -q -t mcp-airlock:e2e ../.. >/dev/null   # the shipped Dockerfile

compose() { docker compose --profile runner "$@"; }
cleanup() {
  compose logs --no-color > .build/compose.log 2>&1 || true
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  echo "stack removed; compose logs in $(pwd)/.build/compose.log; took $(( $(date +%s) - start ))s"
}
trap cleanup EXIT

compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d --wait k3s mcp airlock-prod airlock-dev
rc=0
compose run --rm runner || rc=$?
exit "$rc"
