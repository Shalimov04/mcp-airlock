"""airlock-policy: lint a policy file offline, or diff it against a live upstream's tools/list.

    airlock-policy lint policy.yaml [--env staging --env prod]
    airlock-policy diff policy.yaml --upstream http://host/mcp [--env prod] [--principal me]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError

from .app import _last_sse_message
from .policy import Policy

Finding = tuple[str, str, str]  # (level, code, message)
V = "2026-07-28"
ENVELOPE = {"io.modelcontextprotocol/protocolVersion": V, "io.modelcontextprotocol/clientCapabilities": {}}
WRITE_TIERS = {"L1", "L2", "L3"}


def lint(policy_path: str | Path, envs=()) -> list[Finding]:
    try:
        p = Policy.load(policy_path)
    except Exception as e:  # yaml.YAMLError, OSError, pydantic ValidationError
        return [("ERROR", "invalid", str(e))]
    out: list[Finding] = []
    for name, rule in p.tools.items():
        if not rule.tiers:
            out.append(("ERROR", "no_tiers", f"{name} has no tiers -> denied everywhere"))
        all_tiers = set(rule.tiers.values()) | {t for ov in rule.principals.values() for t in ov.values()}
        if not rule.description and WRITE_TIERS & all_tiers:
            out.append(("WARN", "no_description", f"{name} is a write tool without a description (shown to the human on confirm)"))
        if rule.count_arg and not rule.blast_radius:
            out.append(("WARN", "blast_radius_default", f"{name} has count_arg={rule.count_arg} but uses the global blast_radius"))
    for env in dict.fromkeys([*envs, p.environment]):
        if not any(env in r.tiers for r in p.tools.values()):
            out.append(("WARN", "env_unused", f"no tool has a tier for environment {env!r}"))
    return out


async def _catalog(http: httpx.AsyncClient, upstream: str, principal: str) -> dict[str, dict[str, Any]]:
    headers = {"mcp-protocol-version": V, "mcp-method": "tools/list", "accept": "application/json, text/event-stream",
               "content-type": "application/json", "x-airlock-principal": principal}
    tools: dict[str, dict[str, Any]] = {}
    cursor = None
    for i in range(100):  # ponytail: 100 pages max; nobody has that many tools
        params: dict[str, Any] = {"_meta": dict(ENVELOPE)}
        if cursor:
            params["cursor"] = cursor
        r = await http.post(upstream, headers=headers, json={"jsonrpc": "2.0", "id": i, "method": "tools/list", "params": params})
        r.raise_for_status()
        body = _last_sse_message(r.text) if r.headers.get("content-type", "").startswith("text/event-stream") else r.json()
        if "error" in body:
            raise RuntimeError(f"tools/list failed: {body['error']}")
        tools.update((t["name"], t) for t in body["result"].get("tools") or [])
        cursor = body["result"].get("nextCursor")
        if not isinstance(cursor, str):
            break
    return tools


async def diff(policy_path: str | Path, upstream: str, env: str | None = None, principal: str = "airlock-policy",
               http: httpx.AsyncClient | None = None) -> list[Finding]:
    p = Policy.load(policy_path, env)
    client = http or httpx.AsyncClient(timeout=10, trust_env=False)
    try:
        catalog = await _catalog(client, upstream, principal)
    finally:
        if http is None:
            await client.aclose()
    out: list[Finding] = []
    for name, rule in p.tools.items():
        if name not in catalog:
            out.append(("ERROR", "missing_upstream", f"{name} is allowlisted but not in the upstream catalog"))
        elif rule.tiers.get(p.environment) in ("L1", "L2") \
                and "dry_run" not in ((catalog[name].get("inputSchema") or {}).get("properties") or {}):
            out.append(("WARN", "no_dry_run", f"{name} is {rule.tiers[p.environment]} in {p.environment!r} but declares no dry_run: "
                                              "L1 calls will be denied; L2 will prompt without a preview"))
    for name in catalog.keys() - p.tools.keys():
        out.append(("WARN", "not_allowlisted", f"{name} is in the upstream catalog but not in the policy (denied)"))
    out.append(("INFO", "ok", f"{len(p.tools.keys() & catalog.keys())} tool(s) allowlisted and present upstream, "
                              f"{len(catalog)} in catalog, env {p.environment!r}"))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="airlock-policy", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    l = sub.add_parser("lint", help="static checks, no network")
    l.add_argument("policy")
    l.add_argument("--env", action="append", default=[], help="environment(s) that must be covered (repeatable)")
    d = sub.add_parser("diff", help="compare the policy with the upstream's live tools/list")
    d.add_argument("policy")
    d.add_argument("--upstream", required=True, help="MCP endpoint, e.g. http://127.0.0.1:9001/mcp. Point it at the server, not the proxy: the proxy hides tools the policy does not list")
    d.add_argument("--env", help="environment column to check (default: the policy's own)")
    d.add_argument("--principal", default="airlock-policy", help="X-Airlock-Principal to send")
    a = ap.parse_args(argv)
    if a.cmd == "lint":
        findings = lint(a.policy, a.env)
    else:
        try:
            findings = asyncio.run(diff(a.policy, a.upstream, a.env, a.principal))
        except (httpx.HTTPError, RuntimeError, ValidationError, ValueError) as e:  # ValueError: not JSON
            findings = [("ERROR", "upstream", str(e))]
    for level, code, msg in findings:
        print(f"{level} {code}: {msg}")
    return 1 if any(l == "ERROR" for l, _, _ in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
