"""What a retried confirmation token gets back: a replay for a burned key, the question again when there is no
approval channel, and a pending result that names its verdict and rule. HTTP level, like the end-to-end pass."""

from __future__ import annotations

import json

import httpx

from mcp_airlock import Airlock, Policy
from mcp_airlock.app import CONFIRM_KEY, META
from mcp_airlock.audit import AuditLog

from .conftest import audit_rows, call
from .test_features import PRINCIPAL_POLICY, accept, proxy_client, real_deletes, webhook_airlock

DECLINE = {CONFIRM_KEY: {"action": "decline"}}


async def test_polling_a_burned_token_is_a_replay_not_pending(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)  # oob
    async with proxy_client(al) as c:
        token = (await call(c, "delete_service", {"name": "api"}))["requestState"]
        res = await call(c, "delete_service", {"name": "api"}, extra={"requestState": token, "inputResponses": DECLINE})
        assert res["_meta"][META + "rule_id"] == "mrtr.declined"
        for responses in (None, {}, {"other": {"action": "accept"}}):  # all of them count as no answer
            extra = {"requestState": token} if responses is None else {"requestState": token, "inputResponses": responses}
            res = await call(c, "delete_service", {"name": "api"}, extra=extra)
            assert res["isError"] and res["_meta"][META + "rule_id"] == "mrtr.replay", res
    assert not [r for r in audit_rows(audit_path) if r["rule_id"] == "mrtr.pending"]
    assert real_deletes(upstream) == []


async def test_polling_after_an_inband_execution_is_a_replay_not_pending(client, upstream, audit_path):
    token = (await call(client, "delete_service", {"name": "api"}))["requestState"]
    res = await call(client, "delete_service", {"name": "api"}, extra=accept(token))
    assert res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
    res = await call(client, "delete_service", {"name": "api"}, extra={"requestState": token})
    assert res["isError"] and res["_meta"][META + "rule_id"] == "mrtr.replay"
    assert len(real_deletes(upstream)) == 1
    assert not [r for r in audit_rows(audit_path) if r["rule_id"] == "mrtr.pending"]


async def test_inband_token_without_an_answer_and_no_webhook_is_asked_again(client, upstream, audit_path):
    first = await call(client, "delete_service", {"name": "api"})
    res = await call(client, "delete_service", {"name": "api"}, extra={"requestState": first["requestState"]})
    assert res["resultType"] == "input_required" and CONFIRM_KEY in res["inputRequests"]  # the question, not "pending"
    assert res["_meta"][META + "rule_id"] == "tier.L2.confirm" and META + "status" not in res["_meta"]
    assert res["requestState"] != first["requestState"]
    res = await call(client, "delete_service", {"name": "api"}, extra=accept(res["requestState"]))
    assert res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
    assert len(real_deletes(upstream)) == 1
    assert not [r for r in audit_rows(audit_path) if r["rule_id"] == "mrtr.pending"]


async def test_pending_result_carries_verdict_rule_and_the_ignored_note(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        token = (await call(c, "delete_service", {"name": "api"}))["requestState"]
        meta = (await call(c, "delete_service", {"name": "api"}, extra={"requestState": token}))["_meta"]
        assert meta[META + "verdict"] == "confirm" and meta[META + "rule_id"] == "mrtr.pending"
        assert meta[META + "status"] == "pending" and "ignored" not in meta[META + "message"]
        meta = (await call(c, "delete_service", {"name": "api"}, extra=accept(token)))["_meta"]
        assert meta[META + "verdict"] == "confirm" and meta[META + "rule_id"] == "mrtr.pending"
        assert "in-band accept was ignored" in meta[META + "message"]
    assert real_deletes(upstream) == []


async def test_a_retry_whose_tier_dropped_below_l2_runs_without_the_proxy_token(upstream, audit_path, tmp_path):
    """The proxy's requestState must never reach the upstream, whatever the tier is at the retry: under the MCP SDK
    an unknown requestState is an invalid-params error, and the token carries this proxy's signed claims."""
    p = tmp_path / "p.yaml"
    p.write_text(PRINCIPAL_POLICY)  # set_replicas is L2, L3 for the oncall group; no webhook, so inband
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream.app), base_url="http://localhost:9001")
    al = Airlock(Policy.load(p), "http://localhost:9001/mcp", AuditLog(audit_path), http=http, trust_principal_header=True)
    args = {"names": ["api"], "replicas": 1}
    async with proxy_client(al) as c:
        first = await call(c, "set_replicas", args, principal="carol")
        assert first["_meta"][META + "rule_id"] == "tier.L2.confirm"
        res = await call(c, "set_replicas", args, principal="carol", headers={"x-airlock-groups": "oncall"},
                         extra={"requestState": first["requestState"]})
        assert not res.get("isError"), res
        assert res["_meta"][META + "rule_id"] == "tier.L3.auto"
    ran = [x for x in upstream.CALLS if x["tool"] == "set_replicas" and not x["args"].get("dry_run")]
    assert len(ran) == 1 and not any("requestState" in json.dumps(x) for x in upstream.CALLS)
