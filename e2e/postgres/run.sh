#!/usr/bin/env bash
# Builds the airlock image, brings up the isolated stack, runs the scenarios, tears everything down.
set -u
cd "$(dirname "$0")"
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
dc() { docker compose -f compose.yaml --profile runner "$@"; }
trap 'dc down -v --remove-orphans >/dev/null 2>&1' EXIT
start=$(date +%s)
docker build -q -t mcp-airlock-e2e:local ../.. >/dev/null || { echo "image build failed"; exit 1; }
dc down -v --remove-orphans >/dev/null 2>&1
dc up -d --wait data-db airlock-db service webhook airlock-a airlock-b >/dev/null 2>&1 || { dc logs --tail 50; exit 1; }
dc run --rm --no-deps runner
rc=$?
echo "airlock log lines mentioning failures: $(dc logs airlock-a airlock-b 2>&1 | grep -ci 'fail\|error\|traceback')"
if [ $rc -ne 0 ]; then
  echo "---- airlock/service logs (tail) ----"
  dc logs --tail 40 airlock-a airlock-b service
fi
echo "run.sh: exit $rc after $(( $(date +%s) - start ))s"
exit $rc
