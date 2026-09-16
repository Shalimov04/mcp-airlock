#!/usr/bin/env bash
# Build the airlock image, run the Grafana e2e stack, print pass/fail, tear down. Exit code = runner's exit code.
set -uo pipefail
cd "$(dirname "$0")"
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
DC="docker compose -p airlock-e2e-grafana -f compose.yaml"
trap '$DC down -v --remove-orphans >/dev/null 2>&1' EXIT

docker build -q -t mcp-airlock-e2e-grafana:local ../.. >/dev/null || { echo "image build failed"; exit 2; }
$DC up -d grafana mcp-grafana airlock-dev airlock-prod || { $DC logs; exit 2; }
$DC run --rm runner
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "---- service logs (tail) ----"
  $DC logs --tail 40 mcp-grafana airlock-dev airlock-prod
fi
echo "e2e grafana: $([ "$rc" -eq 0 ] && echo PASS || echo FAIL) (rc=$rc)"
exit "$rc"
