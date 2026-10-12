"""Audit detail when the upstream answers with JSON-RPC errors or non-object results."""

from __future__ import annotations

import json

import httpx

from mcp_airlock.app import CONFIRM_KEY

from .conftest import audit_rows, call, make_airlock, patch_post, rpc
from .test_proxy_protocol import json_response, mock_airlock, serving


def upstream_error_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    return json_response({"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": "boom"}})


def patch_delete_service_jsonrpc_error(al, tool: str = "delete_service") -> list[dict]:
    """Return jsonrpc error on every tools/call to `tool`; other methods hit the fake upstream."""
    sent: list[dict] = []
    orig = al.http.post

    async def post(url, *, content, headers):
        body = json.loads(content)
        if body["method"] == "tools/call" and body["params"]["name"] == tool:
            sent.append(body)
            return json_response({"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": "boom"}})
        return await orig(url, content=content, headers=headers)

    patch_post(al, post)
    return sent


async def test_l0_upstream_jsonrpc_error_is_named_in_the_outcome(audit_path):
    al = mock_airlock(audit_path, upstream_error_handler)
    async with serving(al) as c:
        r = await rpc(c, "tools/call", {"name": "get_service", "arguments": {"name": "api"}})
    assert r.status_code == 200 and r.json()["error"]["code"] == -32000, r.text
    outcome = audit_rows(audit_path)[-1]
    assert outcome["phase"] == "outcome" and outcome["detail"]["upstream_error"]["code"] == -32000


async def test_l2_dry_run_upstream_jsonrpc_error_records_no_prompt(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    patch_delete_service_jsonrpc_error(al)
    async with serving(al) as c:
        r = await rpc(c, "tools/call", {"name": "delete_service", "arguments": {"name": "api"}})
    body = r.json()
    assert r.status_code == 200 and body["error"]["message"] == "boom"
    outcome = audit_rows(audit_path)[-1]
    assert outcome["verdict"] == "confirm" and outcome["dry_run"] is True
    assert outcome["detail"]["no_prompt"] == "the dry run failed"
    assert outcome["detail"]["upstream_error"]["code"] == -32000


async def test_tools_list_non_object_result_is_named_in_the_outcome(audit_path):
    def handler(request: httpx.Request) -> httpx.Response:
        rid = json.loads(request.content)["id"]
        return json_response({"jsonrpc": "2.0", "id": rid, "result": []})

    al = mock_airlock(audit_path, handler)
    async with serving(al) as c:
        r = await rpc(c, "tools/list")
    assert r.status_code == 200 and r.json()["result"] == []
    outcome = audit_rows(audit_path)[-1]
    assert outcome["rule_id"] == "passthrough" and outcome["detail"]["upstream_result_type"] == "list"


async def test_l2_confirmed_upstream_jsonrpc_error_is_named_in_the_outcome(upstream, audit_path):
    sent: list[dict] = []
    al = make_airlock(upstream, audit_path)
    orig = al.http.post

    async def post(url, *, content, headers):
        body = json.loads(content)
        if body["method"] == "tools/call" and body["params"]["name"] == "delete_service":
            sent.append(body)
            rid = body["id"]
            if body["params"]["arguments"].get("dry_run"):
                return json_response({"jsonrpc": "2.0", "id": rid, "result": {
                    "resultType": "complete", "isError": False,
                    "content": [{"type": "text", "text": "would delete api"}]}})
            return json_response({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "boom"}})
        return await orig(url, content=content, headers=headers)

    patch_post(al, post)
    async with serving(al) as c:
        first = await call(c, "delete_service", {"name": "api"})
        r = await rpc(c, "tools/call", {
            "name": "delete_service",
            "arguments": {"name": "api"},
            "requestState": first["requestState"],
            "inputResponses": {CONFIRM_KEY: {"action": "accept", "content": {"confirm": True}}},
        })
    assert r.status_code == 200 and r.json()["error"]["code"] == -32000
    outcome = audit_rows(audit_path)[-1]
    assert outcome["rule_id"] == "tier.L2.confirmed" and outcome["dry_run"] is False
    assert outcome["detail"]["upstream_error"]["code"] == -32000
    assert len(sent) == 2
