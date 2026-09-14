from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

from mcp_airlock import Airlock, Policy
from mcp_airlock.audit import AuditLog

from . import fake_upstream

ROOT = Path(__file__).resolve().parents[1]
trace.set_tracer_provider(TracerProvider())  # real (non-noop) spans so traceparent is actually injected
V = "2026-07-28"
ENVELOPE = {"io.modelcontextprotocol/protocolVersion": V, "io.modelcontextprotocol/clientCapabilities": {}}


@pytest.fixture
async def upstream():
    fake_upstream.CALLS.clear()
    app = fake_upstream.make_app()  # session manager runs once per instance → fresh app per test
    started, stop = asyncio.Event(), asyncio.Event()

    async def run():  # enter and exit the lifespan in ONE task (pytest-asyncio tears down in another)
        async with app.router.lifespan_context(app):
            started.set()
            await stop.wait()

    task = asyncio.create_task(run())
    await started.wait()
    yield SimpleNamespace(app=app, CALLS=fake_upstream.CALLS)
    stop.set()
    await task


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit.jsonl"


def make_airlock(upstream, audit_path, env="prod", **kw) -> Airlock:
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream.app), base_url="http://localhost:9001")
    kw.setdefault("trust_principal_header", True)  # tests authenticate with X-Airlock-Principal
    return Airlock(Policy.load(ROOT / "policy.example.yaml", env), "http://localhost:9001/mcp",
                   AuditLog(audit_path), http=http, **kw)


@pytest.fixture
async def airlock(upstream, audit_path):
    return make_airlock(upstream, audit_path)


@pytest.fixture
async def client(airlock):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=airlock.app), base_url="http://localhost:9000") as c:
        yield c


async def rpc(client: httpx.AsyncClient, method: str, params: dict | None = None, *, principal: str | None = "alice",
              headers: dict | None = None, rid: int = 1) -> httpx.Response:
    params = {"_meta": dict(ENVELOPE), **(params or {})}
    h = {"mcp-protocol-version": V, "mcp-method": method, "accept": "application/json, text/event-stream",
         "content-type": "application/json"}
    if method == "tools/call":
        h["mcp-name"] = params["name"]
    if principal:
        h["x-airlock-principal"] = principal
    h.update(headers or {})
    return await client.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params})


async def call(client, tool, arguments=None, **kw) -> dict:
    r = await rpc(client, "tools/call", {"name": tool, "arguments": arguments or {}, **kw.pop("extra", {})}, **kw)
    assert r.status_code == 200, r.text
    return r.json()["result"]


def audit_rows(path) -> list[dict]:
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
