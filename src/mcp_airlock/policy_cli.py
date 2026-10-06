"""airlock-policy: lint a policy file offline, diff it against a live upstream's tools/list, or pin the upstream's tools.

    airlock-policy lint policy.yaml [--env staging --env prod]
    airlock-policy diff policy.yaml --upstream http://host/mcp [--env prod] [--principal me] [--pins pins.json]
    airlock-policy pin policy.yaml --upstream http://host/mcp [--env prod] [--principal me] [--pins pins.json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import ValidationError

from . import pins as tool_pins
from .app import _last_sse_message
from .policy import REGEX_MAX_CHARS, Policy, regex_unbounded_repeats

Finding = tuple[str, str, str]  # (level, code, message)
V = "2026-07-28"
ENVELOPE = {"io.modelcontextprotocol/protocolVersion": V, "io.modelcontextprotocol/clientCapabilities": {}}
WRITE_TIERS = {"L1", "L2", "L3"}


class PolicyInvalid(Exception):
    """The policy file cannot be read, is not YAML or fails validation; str() is the message for `ERROR invalid`."""


def _missing_environment(e: ValidationError) -> bool:
    return any(err["loc"] == ("environment",) and err["type"] == "missing" for err in e.errors())


def _load(policy_path: str | Path, env: str | None = None, fallback_env: str | None = None) -> Policy:
    """Policy.load with every loader error turned into PolicyInvalid.
    env overrides the policy's environment as the proxy's --env does; fallback_env only fills in a missing one."""
    try:
        try:
            return Policy.load(policy_path, env)
        except ValidationError as e:
            if not _missing_environment(e):
                raise
            if fallback_env:
                return Policy.load(policy_path, fallback_env)
            msg = "environment is not set: add `environment:` to the policy or pass --env (or set AIRLOCK_ENV)"
            # the other errors would otherwise only show up once the environment is fixed
            others = [f"{'.'.join(str(k) for k in err['loc'])}: {err['msg']}" for err in e.errors() if err["loc"] != ("environment",)]
            if others:
                msg += "; also " + "; ".join(others)
            raise PolicyInvalid(msg) from e
    except (OSError, yaml.YAMLError, ValidationError) as e:
        raise PolicyInvalid(str(e)) from e


def lint(policy_path: str | Path, envs=(), env: str | None = None) -> list[Finding]:
    """env (AIRLOCK_ENV) and the first of envs stand in for a missing `environment`, as the proxy would run the policy."""
    envs = list(envs)
    try:
        p = _load(policy_path, fallback_env=envs[0] if envs else env)
    except PolicyInvalid as e:
        return [("ERROR", "invalid", str(e))]
    out: list[Finding] = []
    known_envs = {p.environment} | {e for r in p.tools.values() for e in r.tiers} \
        | {e for r in p.tools.values() for ov in r.principals.values() for e in ov}
    for name, rule in p.tools.items():
        if not rule.tiers:
            out.append(("ERROR", "no_tiers", f"{name} has no tiers -> denied everywhere"))
        all_tiers = set(rule.tiers.values()) | {t for ov in rule.principals.values() for t in ov.values()}
        if not rule.description and WRITE_TIERS & all_tiers:
            out.append(("WARN", "no_description", f"{name} is a write tool without a description (shown to the human on confirm)"))
        if rule.count_arg and not rule.blast_radius:
            out.append(("WARN", "blast_radius_default", f"{name} has count_arg={rule.count_arg} but uses the global blast_radius"))
        for w in rule.where:
            for env in w.env or ():
                if env not in known_envs:  # a typo (prd) would make the rule silently inert
                    out.append(("WARN", "where_env_unknown", f"{name} has a where rule for environment {env!r}, which no tier mentions: it never applies"))
            if w.regex is not None and (n := regex_unbounded_repeats(w.regex)) >= 2:
                # the exponential and the cubic patterns are a load error; the quadratic ones load and run on the event loop
                out.append(("WARN", "where_regex_cost", f"{name} has a where regex with {n} unbounded repeats in a row: matching "
                            f"can take time quadratic in the value length, milliseconds at the cap of {REGEX_MAX_CHARS} chars "
                            "(a longer value fails the rule)"))
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
        body = _last_sse_message(r.text, i) if r.headers.get("content-type", "").startswith("text/event-stream") else r.json()
        if body is None:
            raise RuntimeError("tools/list failed: the SSE stream ended without a response")
        if isinstance(body, dict) and "error" in body:
            raise RuntimeError(f"tools/list failed: {body['error']}")
        # a non-MCP endpoint answers with anything: say so instead of failing on a key or attribute
        result = body.get("result") if isinstance(body, dict) else None
        listed = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(result, dict) or not isinstance(listed, list | None):
            raise RuntimeError(f"tools/list: {upstream} did not answer with a JSON-RPC result holding a tools list; is it an MCP endpoint?")
        for t in listed or []:
            if not isinstance(t, dict) or not isinstance(t.get("name"), str):
                raise RuntimeError(f"tools/list: {upstream} listed a tool without a name")
            tools[t["name"]] = t
        cursor = result.get("nextCursor")
        if not isinstance(cursor, str):
            break
    return tools


async def diff(policy_path: str | Path, upstream: str, env: str | None = None, principal: str = "airlock-policy",
               http: httpx.AsyncClient | None = None, pins: str | Path | None = None) -> list[Finding]:
    try:
        p = _load(policy_path, env)
    except PolicyInvalid as e:
        return [("ERROR", "invalid", str(e))]
    pinned: dict[str, str] | None = None
    if pins is not None:
        try:
            pinned = tool_pins.load(pins)
        except ValueError as e:
            return [("ERROR", "pins_file", str(e))]
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
            continue
        props = (catalog[name].get("inputSchema") or {}).get("properties") or {}
        if rule.tiers.get(p.environment) in ("L1", "L2") and "dry_run" not in props:
            out.append(("WARN", "no_dry_run", f"{name} is {rule.tiers[p.environment]} in {p.environment!r} but declares no dry_run: "
                                              "L1 calls will be denied; L2 will prompt without a preview"))
        for w in rule.where:
            if w.arg not in props:  # a typo would make the rule fail every call
                out.append(("WARN", "where_unknown_arg", f"{name} has a where rule on {w.arg!r}, which is not in its inputSchema"))
    for name in catalog.keys() - p.tools.keys():
        out.append(("WARN", "not_allowlisted", f"{name} is in the upstream catalog but not in the policy (denied)"))
    if pinned is not None:
        for name in (n for n in p.tools if n in catalog):
            if name not in pinned:
                out.append(("WARN", "no_pin", f"{name} is allowlisted but has no pin"))
            elif tool_pins.changed(pinned, catalog[name]):
                out.append(("ERROR", "pin_mismatch", f"{name}: definition changed since it was pinned"))
        for name in sorted(pinned.keys() - (p.tools.keys() & catalog.keys())):
            out.append(("WARN", "stale_pin", f"{name} is pinned, but the policy does not allowlist it or the upstream does not list it"))
    out.append(("INFO", "ok", f"{len(p.tools.keys() & catalog.keys())} tool(s) allowlisted and present upstream, "
                              f"{len(catalog)} in catalog, env {p.environment!r}"))
    return out


async def pin(policy_path: str | Path, upstream: str, env: str | None = None, principal: str = "airlock-policy",
              pins: str | Path = "pins.json", http: httpx.AsyncClient | None = None) -> list[Finding]:
    try:
        p = _load(policy_path, env)
    except PolicyInvalid as e:
        return [("ERROR", "invalid", str(e))]
    client = http or httpx.AsyncClient(timeout=10, trust_env=False)
    try:
        catalog = await _catalog(client, upstream, principal)
    finally:
        if http is None:
            await client.aclose()
    out: list[Finding] = [("WARN", "missing_upstream", f"{name} is allowlisted but not in the upstream catalog: no pin written")
                          for name in p.tools if name not in catalog]
    pinned = {name: tool_pins.tool_hash(catalog[name]) for name in p.tools if name in catalog}
    try:
        Path(pins).write_text(json.dumps(pinned, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as e:
        return [*out, ("ERROR", "pins_file", str(e))]
    out.append(("INFO", "ok", f"pinned {len(pinned)} tool(s) to {pins}"))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="airlock-policy", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    l = sub.add_parser("lint", help="static checks, no network")
    l.add_argument("policy")
    l.add_argument("--env", action="append", default=[], help="environment(s) that must be covered (repeatable); the first one also stands in for a missing `environment`, as does AIRLOCK_ENV")
    d = sub.add_parser("diff", help="compare the policy with the upstream's live tools/list")
    d.add_argument("policy")
    d.add_argument("--upstream", required=True, help="MCP endpoint, e.g. http://127.0.0.1:9001/mcp. Point it at the server, not the proxy: the proxy hides tools the policy does not list")
    d.add_argument("--env", help="environment column to check (default: AIRLOCK_ENV, then the policy's own)")
    d.add_argument("--principal", default="airlock-policy", help="X-Airlock-Principal to send")
    d.add_argument("--pins", help="pins file from `airlock-policy pin`: report changed, missing and stale pins")
    n = sub.add_parser("pin", help="write a sha256v2 pin for every allowlisted tool the upstream lists")
    n.add_argument("policy")
    n.add_argument("--upstream", required=True, help="MCP endpoint of the server itself, not the proxy")
    n.add_argument("--env", help="environment column to read (default: AIRLOCK_ENV, then the policy's own)")
    n.add_argument("--principal", default="airlock-policy", help="X-Airlock-Principal to send")
    n.add_argument("--pins", default="pins.json", help="file to write (default: pins.json)")
    a = ap.parse_args(argv)
    env_var = os.environ.get("AIRLOCK_ENV") or None  # the proxy reads it too, so the commands see the same column
    if a.cmd == "lint":
        findings = lint(a.policy, a.env, env=env_var)
    else:
        try:
            findings = asyncio.run(diff(a.policy, a.upstream, a.env or env_var, a.principal, pins=a.pins) if a.cmd == "diff"
                                   else pin(a.policy, a.upstream, a.env or env_var, a.principal, a.pins))
        except (httpx.HTTPError, RuntimeError, ValueError, OSError) as e:  # ValueError: not JSON; a net for the rest
            findings = [("ERROR", "upstream", str(e))]
    for level, code, msg in findings:
        print(f"{level} {code}: {msg}")
    return 1 if any(l == "ERROR" for l, _, _ in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
