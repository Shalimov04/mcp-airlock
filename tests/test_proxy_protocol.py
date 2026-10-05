"""Protocol edges of the proxy path: lone surrogates, non-finite numbers, deep nesting, SSE answers, upstream failures,
forged _meta, span attributes and a store that does not answer. Everything goes over HTTP through the ASGI app."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

import httpx
import pytest

from mcp_airlock import Airlock, Policy
from mcp_airlock.app import CONFIRM_KEY, META
from mcp_airlock.audit import AuditLog

from .conftest import ENVELOPE, ROOT, V, audit_rows, make_airlock, rpc

SURROGATE = "\ud800"  # JSON allows the escape, UTF-8 cannot encode it


def mock_airlock(audit_path, handler, env="prod", **kw) -> Airlock:
    """An airlock whose upstream is `handler(request) -> httpx.Response`."""
    return Airlock(Policy.load(ROOT / "policy.example.yaml", env), "http://upstream/mcp", AuditLog(audit_path),
                   http=httpx.AsyncClient(transport=httpx.MockTransport(handler)), trust_principal_header=True, **kw)


@asynccontextmanager
async def serving(airlock: Airlock):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=airlock.app), base_url="http://localhost:9000") as c:
        yield c


def json_response(body: dict, status: int = 200) -> httpx.Response:
    # ensure_ascii: a lone surrogate goes out as the JSON escape, the way a JS server sends it
    return httpx.Response(status, content=json.dumps(body).encode(), headers={"content-type": "application/json"})


def tool_result(rid, text: str, **extra) -> httpx.Response:
    return json_response({"jsonrpc": "2.0", "id": rid, "result": {"resultType": "complete", "isError": False, **extra,
                                                                 "content": [{"type": "text", "text": text}]}})


def answering(text: str, **extra):
    def handler(request: httpx.Request) -> httpx.Response:
        return tool_result(json.loads(request.content)["id"], text, **extra)
    return handler


def accept(token: str) -> dict:
    return {"requestState": token, "inputResponses": {CONFIRM_KEY: {"action": "accept", "content": {"confirm": True}}}}


def envelope(rid, method: str, params: dict) -> bytes:
    """A raw request body: httpx would refuse to write some of the values these tests send."""
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": {"_meta": dict(ENVELOPE), **params}}).encode()


def headers(method: str, tool: str | None = None, principal: str | None = "alice") -> dict:
    h = {"mcp-protocol-version": V, "mcp-method": method, "accept": "application/json, text/event-stream",
         "content-type": "application/json"}
    if tool:
        h["mcp-name"] = tool
    if principal:
        h["x-airlock-principal"] = principal
    return h


# ---------------------------------------------------------------- lone surrogates (B03)
async def test_a_surrogate_in_the_id_of_a_read_call_still_returns_the_result(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    body = envelope(SURROGATE, "tools/call", {"name": "get_service", "arguments": {"name": "api"}})
    async with serving(al) as c:
        r = await c.post("/mcp", content=body, headers=headers("tools/call", "get_service"))
    assert r.status_code == 200, r.text
    assert r.json()["id"] == SURROGATE and r.json()["result"]["isError"] is False
    rows = audit_rows(audit_path)
    assert [x["phase"] for x in rows] == ["intent", "outcome"] and rows[-1]["verdict"] == "allow"  # one outcome, allow


async def test_a_surrogate_in_the_id_on_the_reject_and_401_paths_is_a_json_error(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    async with serving(al) as c:
        r = await c.post("/mcp", content=envelope(SURROGATE, "resources/list", {}), headers=headers("resources/list"))
        assert r.status_code == 404 and r.json()["id"] == SURROGATE and r.json()["error"]["code"] == -32601
        body = envelope(SURROGATE, "tools/call", {"name": "get_service", "arguments": {}})
        r = await c.post("/mcp", content=body, headers=headers("tools/call", "get_service", principal=None))
        assert r.status_code == 401 and r.json()["id"] == SURROGATE
    assert len(audit_rows(audit_path)) == 4 and upstream.CALLS == []


@pytest.mark.parametrize("shape", ["result", "error", "sse"])
async def test_a_surrogate_in_the_upstream_answer_reaches_the_caller(audit_path, shape):
    text = f"bad {SURROGATE} text"

    def handler(request: httpx.Request) -> httpx.Response:
        rid = json.loads(request.content)["id"]
        if shape == "error":
            return json_response({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": text}})
        if shape == "sse":
            msg = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"resultType": "complete", "content": [{"type": "text", "text": text}]}})
            return httpx.Response(200, content=f"event: message\ndata: {msg}\n\n".encode("utf-8", "surrogatepass"),
                                  headers={"content-type": "text/event-stream"})
        return tool_result(rid, text)

    al = mock_airlock(audit_path, handler)
    async with serving(al) as c:
        r = await rpc(c, "tools/call", {"name": "get_service", "arguments": {"name": "api"}})
    assert r.status_code == 200, r.text
    got = r.json()["error"]["message"] if shape == "error" else r.json()["result"]["content"][0]["text"]
    assert got == text or got == text.replace(SURROGATE, "�")  # intact (escaped) or replaced, never a 500
    rows = audit_rows(audit_path)
    assert [x["phase"] for x in rows] == ["intent", "outcome"] and rows[-1]["verdict"] == "allow"


async def test_a_surrogate_in_a_tool_description_does_not_break_tools_list(audit_path):
    def handler(request: httpx.Request) -> httpx.Response:
        rid = json.loads(request.content)["id"]
        return json_response({"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": "get_service", "description": f"bad {SURROGATE} desc", "inputSchema": {"type": "object"}}]}})

    al = mock_airlock(audit_path, handler)
    async with serving(al) as c:
        r = await rpc(c, "tools/list")
    assert r.status_code == 200, r.text
    assert r.json()["result"]["tools"][0]["description"] == f"bad {SURROGATE} desc"


async def test_a_surrogate_in_l2_arguments_prompts_and_notifies(upstream, audit_path):
    posts: list[httpx.Request] = []

    def hook(request: httpx.Request) -> httpx.Response:
        posts.append(request)
        return httpx.Response(200)

    al = make_airlock(upstream, audit_path, webhook="https://hooks.slack.com/x", public_url="https://airlock",
                      notify_http=httpx.AsyncClient(transport=httpx.MockTransport(hook)))
    body = envelope(1, "tools/call", {"name": "delete_service", "arguments": {"name": "ok", "note": SURROGATE}})
    async with serving(al) as c:
        r = await c.post("/mcp", content=body, headers=headers("tools/call", "delete_service"))
    assert r.status_code == 200, r.text
    res = r.json()["result"]
    assert res["resultType"] == "input_required" and META + "status" not in res["_meta"]  # a prompt, not pending
    assert len(posts) == 1 and "�" in posts[0].content.decode("utf-8")  # the webhook got valid UTF-8
    key = res["_meta"][META + "idempotency_key"]
    assert "�" in (await al.engine.store.get_prompt(key))  # and the approve page has its text
    assert [x["verdict"] for x in audit_rows(audit_path)] == ["confirm", "confirm"]


# ---------------------------------------------------------------- non-finite numbers (B07) and deep nesting (B17)
@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e400", "-1e999"])
async def test_non_finite_numbers_in_the_arguments_are_a_parse_error(upstream, audit_path, literal):
    al = make_airlock(upstream, audit_path)
    body = envelope(1, "tools/call", {"name": "get_service", "arguments": {"name": "api", "x": "PLACEHOLDER"}})
    body = body.replace(b'"PLACEHOLDER"', literal.encode())
    async with serving(al) as c:
        r = await c.post("/mcp", content=body, headers=headers("tools/call", "get_service"))
    assert r.status_code == 400 and r.json()["error"]["code"] == -32700, r.text
    assert upstream.CALLS == []
    rows = audit_rows(audit_path)
    assert [x["rule_id"] for x in rows] == ["protocol.-32700"] * 2 and rows[0]["principal"] == "alice"
    raw = audit_path.read_text()
    assert "NaN" not in raw and "Infinity" not in raw  # the file stays RFC 8259 JSON
    for line in raw.splitlines():
        json.loads(line, parse_constant=pytest.fail)


async def test_a_non_finite_id_is_a_parse_error_not_a_500(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    body = envelope(1, "tools/call", {"name": "get_service", "arguments": {"name": "api"}}).replace(b'"id": 1', b'"id": NaN')
    assert b"NaN" in body
    async with serving(al) as c:
        r = await c.post("/mcp", content=body, headers=headers("tools/call", "get_service"))
    assert r.status_code == 400 and r.json()["error"]["code"] == -32700 and r.json()["id"] is None
    assert upstream.CALLS == []


def nested(levels: int) -> str:
    return "[" * levels + "1" + "]" * levels


async def test_deeply_nested_arguments_are_refused_and_audited(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    args = '{"names": ' + nested(1500) + ', "replicas": 1}'
    body = envelope(1, "tools/call", {"name": "set_replicas", "arguments": "ARGS"}).replace(b'"ARGS"', args.encode())
    async with serving(al) as c:
        r = await c.post("/mcp", content=body, headers=headers("tools/call", "set_replicas"))
    assert r.status_code == 400, r.text
    err = r.json()["error"]
    assert err["code"] == -32600 and "nested deeper than 64" in err["message"] and r.json()["id"] == 1
    rows = audit_rows(audit_path)
    assert [x["phase"] for x in rows] == ["intent", "outcome"] and rows[0]["principal"] == "alice"
    assert rows[0]["rule_id"] == "protocol.-32600" and rows[0]["args"] is None
    assert upstream.CALLS == []


async def test_a_body_too_deep_to_parse_is_a_parse_error_even_without_a_principal(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    async with serving(al) as c:
        r = await c.post("/mcp", content=nested(100_000).encode(), headers=headers("tools/call", "x", principal=None))
    assert r.status_code == 400 and r.json()["error"]["code"] == -32700, r.text
    rows = audit_rows(audit_path)
    assert [x["rule_id"] for x in rows] == ["protocol.-32700"] * 2 and rows[0]["principal"] is None


async def test_moderate_nesting_still_passes(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    deep: dict = {"name": "api"}
    for _ in range(40):  # 40 levels inside the arguments, under the 64 for the whole body
        deep = {"inner": deep}
    async with serving(al) as c:
        r = await rpc(c, "tools/call", {"name": "get_service", "arguments": {"name": "api", "tree": deep}})
    assert r.status_code == 200 and r.json()["result"]["isError"] is False, r.text
