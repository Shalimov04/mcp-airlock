"""The Python MCP SDK client through an L2 confirmation, over real sockets.

Starts the example upstream and the proxy (policy.example.yaml, --env prod, so delete_service
is L2) on free local ports, then calls delete_service three times: the callback accepts, the
callback declines, and a client with no elicitation_callback. The transcript is what
docs/clients.md records for the SDK row.

    uv run python examples/sdk_client_confirm.py

Exit status: 0 when every expectation held, 1 otherwise.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import ElicitResult

ROOT = Path(__file__).resolve().parents[1]
KEY = "airlock-confirm"
FAILED: list[str] = []


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]  # another process could grab it before the child binds; fine for a local example


def wait(url: str) -> None:
    for _ in range(100):
        try:
            httpx.post(url, timeout=2, trust_env=False)  # any HTTP answer means it is listening (a GET would open an SSE stream)
            return
        except httpx.HTTPError:
            time.sleep(0.1)
    sys.exit(f"{url} did not come up")


def expect(ok: bool, what: str) -> None:
    print(f"  [{'ok' if ok else 'FAIL'}] {what}")
    if not ok:
        FAILED.append(what)


def short(sent: list[dict]) -> list[dict]:
    """The retried tools/call params, with the long requestState cut down."""
    out = []
    for body in sent:
        p = body.get("params") or {}
        if body.get("method") == "tools/call" and "requestState" in p:
            out.append({"requestState": p["requestState"][:12] + "...", "inputResponses": p.get("inputResponses")})
    return out


async def scenario(name: str, px: str, answer, audit: Path) -> None:
    print(f"\n== {name} (mcp {importlib.metadata.version('mcp')})")
    sent: list[dict] = []
    prompts: list[str] = []

    async def spy(request: httpx2.Request) -> None:
        try:
            sent.append(json.loads(request.content))
        except ValueError:
            pass

    async def elicit(ctx, params):
        prompts.append(params.message)
        return answer

    http = httpx2.AsyncClient(headers={"x-airlock-principal": "alice"}, trust_env=False, timeout=30,
                              event_hooks={"request": [spy]})
    before = len(audit.read_text().splitlines()) if audit.exists() else 0
    result = error = None
    try:
        async with http, Client(streamable_http_client(f"{px}/mcp", http_client=http),
                                elicitation_callback=elicit if answer else None) as client:
            result = await client.call_tool("delete_service", {"name": "api"})
    except BaseException as e:  # the SDK wraps errors in anyio exception groups
        error = e
        while isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 1:
            error = error.exceptions[0]

    for p in prompts:
        print("  prompt:", p.replace("\n", "\n          "))
    print("  retry :", json.dumps(short(sent)) if short(sent) else "none sent")
    if result is not None:
        rule = (result.meta or {}).get("io.mcp-airlock/rule_id")
        print(f"  result: is_error={result.is_error} rule_id={rule} text={result.content[0].text!r}")
    else:
        print(f"  raised: {type(error).__name__}: {error}")
    rows = [json.loads(line) for line in audit.read_text().splitlines()[before:] if line.strip()]
    outcomes = [r for r in rows if r.get("tool") == "delete_service" and r.get("phase") == "outcome"]
    print("  audit :", [(r.get("rule_id"), r.get("dry_run")) for r in outcomes])
    forwarded = [r.get("rule_id") for r in outcomes]

    if name == "accept":
        expect(len(prompts) == 1 and "would delete api" in prompts[0], "callback got the dry-run description once")
        expect(bool(short(sent)) and short(sent)[0]["inputResponses"][KEY]["action"] == "accept", "inputResponses sent back with accept")
        expect(result is not None and not result.is_error and "DELETED api" in result.content[0].text, "call ran")
        expect("tier.L2.confirmed" in forwarded, "audit has tier.L2.confirmed")
    elif name == "decline":
        expect(len(prompts) == 1, "callback got the prompt once")
        expect(bool(short(sent)) and short(sent)[0]["inputResponses"][KEY]["action"] == "decline", "inputResponses sent back with decline")
        expect(result is not None and result.is_error, "decline came back as a tool error")
        expect("mrtr.declined" in forwarded and "tier.L2.confirmed" not in forwarded, "audit has mrtr.declined, no confirmed run")
    else:
        expect(error is not None and type(error).__name__ == "MCPError", "call raised MCPError")
        expect(not short(sent), "no retry was sent")
        expect("tier.L2.confirmed" not in forwarded, "nothing ran for real")


async def run(px: str, audit: Path) -> None:
    await scenario("accept", px, ElicitResult(action="accept", content={"confirm": True}), audit)
    await scenario("decline", px, ElicitResult(action="decline"), audit)
    await scenario("no elicitation_callback", px, None, audit)


def main() -> int:
    up_port, px_port = free_port(), free_port()
    # A webhook in the environment would post to a real chat and switch the proxy to oob; a DSN would
    # write to a real database. Start from a clean AIRLOCK_* slate and ignore proxy variables.
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy") and not k.startswith("AIRLOCK_")}
    env |= {"PYTHONPATH": str(ROOT), "AIRLOCK_TRUST_PRINCIPAL_HEADER": "1"}
    with tempfile.TemporaryDirectory() as tmp:
        audit = Path(tmp) / "audit.jsonl"
        up = subprocess.Popen([sys.executable, "-m", "uvicorn", "tests.fake_upstream:app", "--host", "127.0.0.1",
                               "--port", str(up_port), "--log-level", "warning"], env=env, cwd=ROOT)
        px = subprocess.Popen([sys.executable, "-m", "mcp_airlock", "--policy", "policy.example.yaml", "--env", "prod",
                               "--upstream", f"http://127.0.0.1:{up_port}/mcp", "--port", str(px_port),
                               "--audit", str(audit)], env=env, cwd=ROOT)
        try:
            wait(f"http://127.0.0.1:{up_port}/mcp")
            wait(f"http://127.0.0.1:{px_port}/healthz")
            asyncio.run(run(f"http://127.0.0.1:{px_port}", audit))
        finally:
            for p in (px, up):
                p.terminate()
                p.wait(timeout=10)
    print("\nFAILED:" if FAILED else "\nall expectations held", *FAILED, sep="\n  " if FAILED else "")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
