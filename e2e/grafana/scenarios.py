"""E2E scenarios: mcp-airlock in front of the real grafana/mcp-grafana and a real Grafana. Runs inside the runner container."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
import uuid

import httpx
import httpx2
import mcp_types as types
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

V = "2026-07-28"
UPSTREAM, DEV, PROD = os.environ["UPSTREAM"], os.environ["AIRLOCK_DEV"], os.environ["AIRLOCK_PROD"]
GRAFANA = os.environ["GRAFANA"]
G_USER, G_PW = os.environ["GRAFANA_AUTH"].split(":", 1)
POLICY = os.environ["POLICY"]
PRINCIPAL = "alice@e2e"
META = "io.mcp-airlock/"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, evidence: object) -> None:
    results.append((name, bool(ok), str(evidence)[:600]))
    print(f"{'PASS' if ok else 'FAIL'} {name}: {str(evidence)[:600]}", flush=True)


def grafana_annotations(tag: str) -> list[dict]:
    r = httpx.get(f"{GRAFANA}/api/annotations", params={"tags": tag, "limit": 100}, auth=(G_USER, G_PW), trust_env=False)
    r.raise_for_status()
    return r.json()


def rpc(url: str, method: str, params: dict, rid: int = 1) -> dict:
    """One raw 2026-07-28 request (used where the test needs exact control of requestState/inputResponses)."""
    h = {"content-type": "application/json", "accept": "application/json, text/event-stream", "mcp-protocol-version": V,
         "mcp-method": method, "x-airlock-principal": PRINCIPAL}
    if method == "tools/call":
        h["mcp-name"] = params["name"]
    meta = {"io.modelcontextprotocol/protocolVersion": V, "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}}
    r = httpx.post(url, headers=h, trust_env=False, timeout=30,
                   json={"jsonrpc": "2.0", "id": rid, "method": method, "params": {**params, "_meta": meta}})
    return r.json()


def client(url: str, **kw) -> Client:
    http = httpx2.AsyncClient(headers={"x-airlock-principal": PRINCIPAL}, trust_env=False, timeout=30)
    return Client(streamable_http_client(url, http_client=http), mode=V, **kw)


def text_of(res: types.CallToolResult) -> str:
    return " ".join(b.text for b in res.content if isinstance(b, types.TextContent))


def wait_ready() -> None:
    deadline = time.time() + 120
    for url in (UPSTREAM, DEV, PROD):
        while True:
            try:
                if "result" in rpc(url, "tools/list", {}):
                    break
            except Exception:
                pass
            if time.time() > deadline:
                raise SystemExit(f"not ready: {url}")
            time.sleep(1)


def scenario_diff() -> None:
    p = subprocess.run(["airlock-policy", "diff", POLICY, "--upstream", UPSTREAM], capture_output=True, text=True)
    lines = p.stdout.strip().splitlines()
    print("---- airlock-policy diff (env prod) ----\n" + p.stdout + p.stderr + "----")
    # Informational: the diff is expected to report findings. Pass = the CLI talked to the live server and produced a catalog count.
    check("policy diff ran against live catalog", any(l.startswith("INFO ok:") for l in lines),
          f"exit={p.returncode} errors={sum(l.startswith('ERROR') for l in lines)} warns={sum(l.startswith('WARN') for l in lines)}")


async def scenario_list_and_read() -> None:
    async with client(PROD) as c:
        listed = await c.list_tools()
    names = {t.name for t in listed.tools}
    upstream = {t["name"] for t in rpc(UPSTREAM, "tools/list", {})["result"]["tools"]}
    import yaml
    allow = set(yaml.safe_load(open(POLICY))["tools"])
    check("tools/list filtered to allowlist", names == upstream & allow and "grafana_api_request" not in names,
          f"visible={len(names)} upstream={len(upstream)} hidden={(listed.meta or {}).get(META + 'hidden_tools')}")

    async with client(PROD) as c:
        res = await c.call_tool("search_dashboards", {"query": "E2E plain"})
    body = text_of(res) + json.dumps(res.structured_content or {})
    check("L0 search_dashboards passes", not res.is_error and "e2e-plain" in body and (res.meta or {}).get(META + "rule_id") == "tier.L0.read",
          f"is_error={res.is_error} rule={(res.meta or {}).get(META + 'rule_id')} body={body[:200]}")

    async with client(PROD) as c:
        res = await c.call_tool("grafana_api_request", {"method": "GET", "path": "/api/health"})
    check("non-allowlisted tool refused", res.is_error and (res.meta or {}).get(META + "rule_id") == "allowlist.deny",
          f"is_error={res.is_error} text={text_of(res)}")


async def scenario_dev_l3() -> None:
    tag = f"e2e-dev-{uuid.uuid4().hex[:8]}"
    async with client(DEV) as c:
        res = await c.call_tool("create_annotation", {"text": "dev L3 write", "tags": [tag], "dashboardUid": "e2e-plain"})
    n = len(grafana_annotations(tag))
    check("dev L3 create_annotation executes immediately", not res.is_error and n == 1
          and (res.meta or {}).get(META + "rule_id") == "tier.L3.auto", f"rule={(res.meta or {}).get(META + 'rule_id')} written={n} text={text_of(res)[:200]}")


def scenario_prod_l2_raw() -> None:
    tag = f"e2e-prod-{uuid.uuid4().hex[:8]}"
    call = {"name": "create_annotation", "arguments": {"text": "prod L2 write", "tags": [tag], "dashboardUid": "e2e-plain"}}
    first = rpc(PROD, "tools/call", call)["result"]
    n0 = len(grafana_annotations(tag))
    msg = ((first.get("inputRequests") or {}).get("airlock-confirm") or {}).get("params", {}).get("message", "")
    check("prod L2 returns input_required, nothing written", first.get("resultType") == "input_required" and n0 == 0,
          f"resultType={first.get('resultType')} written={n0} message={msg!r}")

    answer = {"airlock-confirm": {"action": "accept", "content": {"confirm": True}}}
    retry = {**call, "requestState": first.get("requestState"), "inputResponses": answer}
    second = rpc(PROD, "tools/call", retry, rid=2)["result"]
    n1 = len(grafana_annotations(tag))
    check("prod L2 accept writes exactly once", second.get("resultType", "complete") == "complete" and not second.get("isError") and n1 == 1,
          f"rule={second.get('_meta', {}).get(META + 'rule_id')} written={n1} text={json.dumps(second.get('content'))[:200]}")

    third = rpc(PROD, "tools/call", retry, rid=3)["result"]
    n2 = len(grafana_annotations(tag))
    check("prod L2 replay refused", third.get("isError") and third.get("_meta", {}).get(META + "rule_id") == "mrtr.replay" and n2 == 1,
          f"rule={third.get('_meta', {}).get(META + 'rule_id')} written={n2}")

    tampered = {**retry, "arguments": {**call["arguments"], "text": "swapped after approval"}}
    fourth = rpc(PROD, "tools/call", tampered, rid=4)["result"]
    check("prod L2 token bound to args", fourth.get("isError") and fourth.get("_meta", {}).get(META + "rule_id") == "mrtr.mismatch"
          and len(grafana_annotations(tag)) == 1, f"rule={fourth.get('_meta', {}).get(META + 'rule_id')}")


async def scenario_prod_l2_sdk() -> None:
    tag = f"e2e-sdk-{uuid.uuid4().hex[:8]}"
    prompts: list[str] = []

    async def elicit(ctx, params: types.ElicitRequestParams):
        prompts.append(params.message)
        return types.ElicitResult(action="decline" if "decline" in params.message else "accept", content={"confirm": True})

    async with client(PROD, elicitation_callback=elicit) as c:
        ok = await c.call_tool("create_annotation", {"text": "sdk accept", "tags": [tag]})
        no = await c.call_tool("create_annotation", {"text": "sdk decline", "tags": [tag]})
    rows = grafana_annotations(tag)
    check("SDK client drives input_required (accept writes, decline does not)",
          not ok.is_error and no.is_error and len(prompts) == 2 and [r["text"] for r in rows] == ["sdk accept"],
          f"prompts={len(prompts)} accept_err={ok.is_error} decline={text_of(no)} rows={[r['text'] for r in rows]}")


async def scenario_injection() -> None:
    async with client(PROD) as c:
        res = await c.call_tool("get_dashboard_by_uid", {"uid": "e2e-injected"})
        search = await c.call_tool("search_dashboards", {"query": "Checkout latency"})
    found = (res.meta or {}).get(META + "suspicious") or []
    check("injection in dashboard title/description is marked", not res.is_error and {"override_phrase"} <= {f["rule"] for f in found},
          f"rules={sorted({f['rule'] for f in found})} excerpts={[f['excerpt'] for f in found][:4]}")
    sfound = (search.meta or {}).get(META + "suspicious") or []
    check("injection in search result title is marked", not search.is_error and sfound,
          f"rules={sorted({f['rule'] for f in sfound})}")


async def main() -> int:
    wait_ready()
    scenario_diff()
    for name, fn in [("list/read", scenario_list_and_read), ("dev", scenario_dev_l3), ("sdk", scenario_prod_l2_sdk),
                     ("injection", scenario_injection)]:
        try:
            await fn()
        except Exception as e:
            check(f"{name} scenario crashed", False, repr(e))
    try:
        scenario_prod_l2_raw()
    except Exception as e:
        check("prod raw scenario crashed", False, repr(e))
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
