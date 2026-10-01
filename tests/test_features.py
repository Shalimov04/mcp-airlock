"""Roadmap features wired into the proxy: shared store, principal/group tiers, catalog cache,
L2 without dry_run, injection marking, out-of-band approvals. Written before the code (TDD)."""

from __future__ import annotations

import asyncio
import gc
import html
import json
import os
import textwrap

import httpx
import pytest

from mcp_airlock import Airlock, Policy
from mcp_airlock.app import CONFIRM_KEY, META, TOKEN_PREFIX, _b64, _unb64
from mcp_airlock.audit import AuditLog
from mcp_airlock.identity import IdentityConfig, Principal
from mcp_airlock.store import MemoryStore, PostgresStore

from .conftest import ROOT, SPANS, audit_rows, call, make_airlock, rpc

PG = os.environ.get("AIRLOCK_TEST_PG_DSN")


def accept(token: str) -> dict:
    return {"requestState": token, "inputResponses": {CONFIRM_KEY: {"action": "accept", "content": {"confirm": True}}}}


def proxy_client(airlock: Airlock) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=airlock.app), base_url="http://localhost:9000")


def count_method(sent: list[dict], method: str) -> int:
    return sum(1 for b in sent if b["method"] == method)


def spy(airlock: Airlock, ttl_ms: int | None = None) -> list[dict]:
    """Capture forwarded bodies; optionally rewrite the upstream tools/list ttlMs (the fake always says 0)."""
    sent: list[dict] = []
    orig = airlock.http.post

    async def post(url, *, content, headers):
        body = json.loads(content)
        sent.append(body)
        r = await orig(url, content=content, headers=headers)
        if ttl_ms is not None and body["method"] == "tools/list":
            data = r.json()
            data["result"]["ttlMs"] = ttl_ms
            return httpx.Response(200, json=data)
        return r

    airlock.http.post = post
    return sent


# 1. shared store: two replicas ------------------------------------------------------------------------------------
@pytest.mark.skipif(not PG, reason="AIRLOCK_TEST_PG_DSN not set")
async def test_exactly_once_and_blast_radius_across_replicas(upstream, audit_path):
    secret = b"shared"
    a = make_airlock(upstream, audit_path, secret=secret, store=PostgresStore(PG))
    b = make_airlock(upstream, audit_path, secret=secret, store=PostgresStore(PG))
    principal = f"replica-{os.getpid()}-{id(a)}"  # unique per run: the store is shared with other tests
    async with proxy_client(a) as ca, proxy_client(b) as cb:
        token = (await call(ca, "delete_service", {"name": "x"}, principal=principal))["requestState"]
        res = await call(cb, "delete_service", {"name": "x"}, extra=accept(token), principal=principal)  # confirm on B
        assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
        res = await call(ca, "delete_service", {"name": "x"}, extra=accept(token), principal=principal)  # replay on A
        assert res["_meta"][META + "rule_id"] == "mrtr.replay"
        # delete_service: max_per_principal 2 / day. One real delete on B so far; second via A; third refused on B.
        token = (await call(ca, "delete_service", {"name": "y"}, principal=principal))["requestState"]
        assert (await call(ca, "delete_service", {"name": "y"}, extra=accept(token), principal=principal))["isError"] is False
        res = await call(cb, "delete_service", {"name": "z"}, principal=principal)
        assert res["isError"] and res["_meta"][META + "rule_id"] == "blast_radius.per_principal"
    assert len([c for c in upstream.CALLS if c["tool"] == "delete_service" and not c["args"]["dry_run"]]) == 2


async def test_memory_store_is_default(upstream, audit_path):
    assert isinstance(make_airlock(upstream, audit_path).engine.store, MemoryStore)


# 2. per-principal / per-group tiers -------------------------------------------------------------------------------
PRINCIPAL_POLICY = textwrap.dedent("""
    version: 1
    environment: prod
    tools:
      set_replicas:
        description: scale
        tiers: {prod: L2}
        count_arg: names
        principals:
          alice: {prod: L3}
          "group:oncall": {prod: L3}
          "group:readonly": {prod: L0}
      delete_service:
        description: delete
        tiers: {prod: L2}
""")


def test_policy_tier_resolution(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text(PRINCIPAL_POLICY)
    pol = Policy.load(p)
    assert pol.tier("set_replicas") == "L2"
    assert pol.tier("set_replicas", principal="alice") == "L3"
    assert pol.tier("set_replicas", principal="bob", groups=("oncall",)) == "L3"
    assert pol.tier("set_replicas", principal="bob", groups=("readonly", "oncall")) == "L0"  # first matching group wins
    assert pol.tier("set_replicas", principal="alice", groups=("readonly",)) == "L3"  # principal beats group
    assert pol.tier("delete_service", principal="alice") == "L2"
    assert pol.tier("nope", principal="alice") is None


async def test_group_from_jwt_changes_tier(upstream, audit_path, tmp_path):
    import jwt as pyjwt
    p = tmp_path / "p.yaml"
    p.write_text(PRINCIPAL_POLICY)
    secret = "s3cret-s3cret-s3cret-s3cret-32b!"
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream.app), base_url="http://localhost:9001")
    al = Airlock(Policy.load(p), "http://localhost:9001/mcp", AuditLog(audit_path), http=http,
                 identity=IdentityConfig(jwt_secret=secret, trust_header=False))
    exp = {"exp": 4102444800}
    async with proxy_client(al) as c:
        tok = pyjwt.encode({"sub": "bob", "groups": ["oncall"], **exp}, secret, algorithm="HS256")
        res = await call(c, "set_replicas", {"names": ["api"], "replicas": 1}, principal=None, headers={"authorization": f"Bearer {tok}"})
        assert res["_meta"][META + "rule_id"] == "tier.L3.auto"
        tok = pyjwt.encode({"sub": "carol", "groups": ["devs"], **exp}, secret, algorithm="HS256")
        res = await call(c, "set_replicas", {"names": ["api"], "replicas": 1}, principal=None, headers={"authorization": f"Bearer {tok}"})
        assert res["resultType"] == "input_required"
        assert upstream.CALLS[-1]["meta"][META + "principal"] == "carol"
        assert upstream.CALLS[-1]["meta"][META + "groups"] == ["devs"]


# 3. catalog cache honouring ttlMs ---------------------------------------------------------------------------------
async def test_schema_lookup_cached_only_when_ttl_positive(upstream, audit_path):
    al = make_airlock(upstream, audit_path, env="staging")  # set_replicas is L1: forced dry-run, so the schema check runs
    sent = spy(al, ttl_ms=None)  # fake says ttlMs 0, never cache
    async with proxy_client(al) as c:
        for _ in range(3):
            await call(c, "set_replicas", {"names": ["api"], "replicas": 1})
    assert count_method(sent, "tools/list") == 3

    al = make_airlock(upstream, audit_path, env="staging")
    sent = spy(al, ttl_ms=60_000)
    async with proxy_client(al) as c:
        for _ in range(3):
            await call(c, "set_replicas", {"names": ["api"], "replicas": 1})
    assert count_method(sent, "tools/list") == 1


# 4. tool without dry_run ------------------------------------------------------------------------------------------
async def test_l2_without_dry_run_prompts_without_preview_then_executes(client, upstream):
    res = await call(client, "restart_service", {"name": "api"})  # L2 in prod, tool lacks dry_run
    assert res["resultType"] == "input_required"
    msg = res["inputRequests"][CONFIRM_KEY]["params"]["message"]
    assert "no dry-run preview" in msg.lower()
    assert [x for x in upstream.CALLS if x["tool"] == "restart_service"] == []  # nothing forwarded before the human
    res = await call(client, "restart_service", {"name": "api"}, extra=accept(res["requestState"]))
    assert res["isError"] is False and "restarted api" in res["content"][0]["text"]
    assert upstream.CALLS[-1]["args"] == {"name": "api"}  # no dry_run injected into a tool that has none


async def test_l1_or_explicit_dry_run_without_dry_run_arg_is_denied(upstream, audit_path):
    staging = make_airlock(upstream, audit_path, env="staging")
    staging.engine.policy.tools["restart_service"].tiers["staging"] = "L1"
    async with proxy_client(staging) as c:
        res = await call(c, "restart_service", {"name": "api"})
    assert res["isError"] and res["_meta"][META + "rule_id"] == "dry_run.unsupported"
    prod = make_airlock(upstream, audit_path)
    async with proxy_client(prod) as c:
        res = await call(c, "restart_service", {"name": "api", "dry_run": True})
    assert res["isError"] and res["_meta"][META + "rule_id"] == "dry_run.unsupported"
    assert [x for x in upstream.CALLS if x["tool"] == "restart_service"] == []


# 5. injection marking ---------------------------------------------------------------------------------------------
async def test_injection_like_output_is_marked_not_blocked(client, audit_path):
    res = await call(client, "get_service", {"name": "evil"})
    assert res["isError"] is False
    rules = {f["rule"] for f in res["_meta"][META + "suspicious"]}
    assert "override_phrase" in rules and "tool_mention" in rules
    assert audit_rows(audit_path)[-1]["detail"]["suspicious"] == sorted(rules)
    res = await call(client, "get_service", {"name": "api"})
    assert META + "suspicious" not in res["_meta"]


# 6. out-of-band approval ------------------------------------------------------------------------------------------
async def test_webhook_approval_flow(upstream, audit_path):
    posted: list[dict] = []

    def hook(request: httpx.Request) -> httpx.Response:
        posted.append(json.loads(request.content))
        return httpx.Response(200, text="ok")

    al = make_airlock(upstream, audit_path, webhook="https://hooks.slack.com/services/T/B/X",
                      notify_http=httpx.AsyncClient(transport=httpx.MockTransport(hook)), public_url="https://airlock.example.com")
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
        token = res["requestState"]
        assert len(posted) == 1 and "delete_service" in posted[0]["text"]
        approve_url = next(w for w in posted[0]["text"].split() if w.startswith("https://airlock.example.com/approve/"))
        path = approve_url.removeprefix("https://airlock.example.com")
        assert path != f"/approve/{token}" and META + "approve_url" not in res["_meta"]  # link never reaches the agent

        r = await c.get(path)  # link unfurlers do GET: must NOT approve
        assert r.status_code == 200 and "<form" in r.text and 'method="post"' in r.text.lower()
        res = await call(c, "delete_service", {"name": "api"}, extra={"requestState": token})  # poll before approval
        assert res["resultType"] == "input_required" and res["requestState"] == token  # same key, nothing burned
        assert "inputRequests" not in res and res["_meta"][META + "status"] == "pending"  # don't re-prompt the human
        assert len(posted) == 1  # polling does not re-notify
        r = await c.post(f"/approve/{token}")  # the agent holds requestState: it must NOT work as an approval
        assert r.status_code == 400
        r = await c.post(path)
        assert r.status_code == 200 and "approved" in r.text.lower()
        res = await call(c, "delete_service", {"name": "api"}, extra={"requestState": token})  # retry, no inputResponses
        assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
        res = await call(c, "delete_service", {"name": "api"}, extra={"requestState": token})
        assert res["_meta"][META + "rule_id"] == "mrtr.replay"
        r = await c.post("/approve/al1.bogus.sig")
        assert r.status_code == 400
    assert len([x for x in upstream.CALLS if x["tool"] == "delete_service" and not x["args"]["dry_run"]]) == 1


async def test_failed_webhook_post_still_prompts(upstream, audit_path):
    al = make_airlock(upstream, audit_path, webhook="https://hooks.example/x", public_url="https://a.example",
                      notify_http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))))
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
    assert res["resultType"] == "input_required" and res["requestState"]  # the link still works, nobody was pinged


async def test_decline_wins_over_out_of_band_approval(upstream, audit_path):
    posted: list[str] = []
    al = make_airlock(upstream, audit_path, webhook="https://hooks.example/x", public_url="https://a.example",
                      notify_http=httpx.AsyncClient(transport=httpx.MockTransport(
                          lambda r: (posted.append(json.loads(r.content)["text"]), httpx.Response(200))[1])))
    async with proxy_client(al) as c:
        token = (await call(c, "delete_service", {"name": "api"}))["requestState"]
        path = next(w for w in posted[0].split() if w.startswith("https://a.example/approve/")).removeprefix("https://a.example")
        assert (await c.post(path)).status_code == 200
        declined = {"requestState": token, "inputResponses": {CONFIRM_KEY: {"action": "decline"}}}
        res = await call(c, "delete_service", {"name": "api"}, extra=declined)
        assert res["isError"] and res["_meta"][META + "rule_id"] == "mrtr.declined"
        res = await call(c, "delete_service", {"name": "api"}, extra={"requestState": token})
        assert res["isError"] and res["_meta"][META + "rule_id"] == "mrtr.replay"
    assert all(x["args"]["dry_run"] for x in upstream.CALLS if x["tool"] == "delete_service")


async def test_secrets_redacted_in_prompt_and_webhook(upstream, audit_path):
    posted: list[str] = []
    al = make_airlock(upstream, audit_path, webhook="https://hooks.example/x", public_url="https://a.example",
                      notify_http=httpx.AsyncClient(transport=httpx.MockTransport(
                          lambda r: (posted.append(json.loads(r.content)["text"]), httpx.Response(200))[1])))
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api", "api_token": "sk-verysecretvalue123"})
    msg = res["inputRequests"][CONFIRM_KEY]["params"]["message"]
    assert "sk-verysecretvalue123" not in msg and "[REDACTED]" in msg
    assert "sk-verysecretvalue123" not in posted[0]


async def test_approver_identity_recorded(upstream, audit_path):
    posted: list[str] = []
    al = make_airlock(upstream, audit_path, webhook="https://hooks.example/x", public_url="https://a.example",
                      notify_http=httpx.AsyncClient(transport=httpx.MockTransport(
                          lambda r: (posted.append(json.loads(r.content)["text"]), httpx.Response(200))[1])))
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api"})
        path = next(w for w in posted[0].split() if w.startswith("https://a.example/approve/")).removeprefix("https://a.example")
        assert (await c.post(path, headers={"x-airlock-principal": "boss"})).status_code == 200
    row = audit_rows(audit_path)[-1]
    assert row["rule_id"] == "mrtr.approved_oob" and row["detail"]["approved_by"] == "boss" and row["principal"] == "alice"
    assert row["detail"]["approved_by_source"] == "header"  # unverified: the fronting proxy's word, marked as such


async def test_accept_with_explicit_dry_run_does_not_burn_key(client, upstream):
    token = (await call(client, "delete_service", {"name": "api"}))["requestState"]
    res = await call(client, "delete_service", {"name": "api", "dry_run": True}, extra=accept(token))
    assert res["_meta"][META + "rule_id"] == "tier.L2.dry_run"
    res = await call(client, "delete_service", {"name": "api"}, extra=accept(token))
    assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"


async def test_reads_do_not_consume_blast_radius(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    al.engine.policy.tools["get_service"].blast_radius = al.engine.policy.tools["set_replicas"].blast_radius  # per_principal 5
    async with proxy_client(al) as c:
        for _ in range(8):
            assert (await call(c, "get_service", {"name": "api"}))["isError"] is False


@pytest.mark.parametrize("backend", ["memory", "pg"])
async def test_blast_radius_is_atomic_under_concurrency(upstream, audit_path, backend):
    import asyncio
    if backend == "pg" and not PG:
        pytest.skip("AIRLOCK_TEST_PG_DSN not set")
    dev = make_airlock(upstream, audit_path, env="dev", store=PostgresStore(PG) if backend == "pg" else None)
    principal = f"burst-{backend}-{os.getpid()}-{id(dev)}"
    async with proxy_client(dev) as c:
        results = await asyncio.gather(*[call(c, "set_replicas", {"names": ["a", "b", "c"], "replicas": 1}, principal=principal) for _ in range(4)])
    ok = [r for r in results if r["isError"] is False]
    assert len(ok) == 1 and all(r["_meta"][META + "rule_id"] == "blast_radius.per_principal" for r in results if r["isError"])
    assert len([x for x in upstream.CALLS if x["tool"] == "set_replicas" and not x["args"]["dry_run"]]) == 1


async def test_header_groups_ignored_unless_header_trusted(upstream, audit_path, tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text(PRINCIPAL_POLICY)
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream.app), base_url="http://localhost:9001")
    al = Airlock(Policy.load(p), "http://localhost:9001/mcp", AuditLog(audit_path), http=http)  # constructor default: no header trust
    async with proxy_client(al) as c:
        r = await rpc(c, "tools/call", {"name": "set_replicas", "arguments": {"names": ["api"], "replicas": 0}},
                      principal="mallory", headers={"x-airlock-groups": "oncall"})
    assert r.status_code == 401
    assert upstream.CALLS == []


async def test_catalog_cache_is_per_principal(upstream, audit_path):
    al = make_airlock(upstream, audit_path, env="staging")
    sent = spy(al, ttl_ms=60_000)
    async with proxy_client(al) as c:
        await call(c, "set_replicas", {"names": ["api"], "replicas": 1}, principal="alice")
        await call(c, "set_replicas", {"names": ["api"], "replicas": 1}, principal="alice")
        await call(c, "set_replicas", {"names": ["api"], "replicas": 1}, principal="bob")
    assert count_method(sent, "tools/list") == 2


async def test_no_webhook_means_no_notification(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
    assert res["resultType"] == "input_required" and META + "approve_url" not in res["_meta"]


# 7. second review pass ----------------------------------------------------------------------------------------------
def webhook_airlock(upstream, audit_path, posted: list, **kw):
    return make_airlock(upstream, audit_path, webhook="https://hooks.example/x", public_url="https://a.example",
                        notify_http=httpx.AsyncClient(transport=httpx.MockTransport(
                            lambda r: (posted.append(json.loads(r.content)["text"]), httpx.Response(200))[1])), **kw)


def approve_path(posted: list) -> str:
    return next(w for w in posted[-1].split() if w.startswith("https://a.example/approve/")).removeprefix("https://a.example")


async def test_l3_client_dry_run_on_tool_without_dry_run_counts_as_real(upstream, audit_path):
    from mcp_airlock.policy import BlastRadius
    dev = make_airlock(upstream, audit_path, env="dev")  # restart_service: L3, no dry_run in schema
    dev.engine.policy.tools["restart_service"].blast_radius = BlastRadius(max_per_call=1, max_per_principal=2, window_s=3600)
    async with proxy_client(dev) as c:
        for _ in range(2):
            assert (await call(c, "restart_service", {"name": "api", "dry_run": True}))["isError"] is False
        res = await call(c, "restart_service", {"name": "api", "dry_run": True})
        assert res["isError"] and res["_meta"][META + "rule_id"] == "blast_radius.per_principal"
        res = await call(c, "restart_service", {"name": "api", "dry_run": {"x": 1}})  # garbage stays garbage, not a crash
        assert res["isError"]  # per_principal again; the point is no 500 and a well-typed audit row
    rows = [r for r in audit_rows(audit_path) if r["tool"] == "restart_service"]
    assert all(r["dry_run"] in (None, False) for r in rows)  # never recorded as a dry run


async def test_l3_real_dry_run_is_still_exempt(upstream, audit_path):
    dev = make_airlock(upstream, audit_path, env="dev")  # set_replicas L3 in dev, declares dry_run, per_principal 5
    async with proxy_client(dev) as c:
        for _ in range(4):
            res = await call(c, "set_replicas", {"names": ["a", "b", "c"], "replicas": 1, "dry_run": True})
            assert res["isError"] is False and res["_meta"][META + "dry_run"] is True


async def test_empty_input_responses_means_pending_not_decline(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        token = (await call(c, "delete_service", {"name": "api"}))["requestState"]
        res = await call(c, "delete_service", {"name": "api"}, extra={"requestState": token, "inputResponses": {}})
        assert res["resultType"] == "input_required" and res["_meta"][META + "status"] == "pending"
        assert (await c.post(approve_path(posted))).status_code == 200
        res = await call(c, "delete_service", {"name": "api"}, extra={"requestState": token, "inputResponses": {}})
        assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"


async def test_catalog_failure_fails_closed(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    orig = al.http.post

    async def post(url, *, content, headers):
        if json.loads(content)["method"] == "tools/list":
            return httpx.Response(500, text="boom")
        return await orig(url, content=content, headers=headers)

    al.http.post = post
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
        assert res["isError"] and res["_meta"][META + "rule_id"] == "catalog.unavailable"
        res = await call(c, "delete_service", {"name": "api", "dry_run": True})
        assert res["isError"] and res["_meta"][META + "rule_id"] == "catalog.unavailable"
    assert [x for x in upstream.CALLS if x["tool"] == "delete_service"] == []


async def test_catalog_error_text_is_scrubbed_for_caller_and_audit(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    orig = al.http.post
    leak = "Bearer tok-SECRET123"

    async def post(url, *, content, headers):
        if json.loads(content)["method"] == "tools/list":
            return httpx.Response(401, json={"jsonrpc": "2.0", "id": 1, "error": {"message": f"bad {leak} " + "x" * 400}})
        return await orig(url, content=content, headers=headers)

    al.http.post = post
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
    text = res["content"][0]["text"]
    assert res["_meta"][META + "rule_id"] == "catalog.unavailable" and "[REDACTED]" in text and "SECRET123" not in text
    assert len(text.split("): ", 2)[2]) == 300  # the upstream part is cut at 300 characters
    raw = audit_path.read_text()
    assert "SECRET123" not in raw and "[REDACTED]" in raw
    assert {r["detail"] for r in audit_rows(audit_path) if r["verdict"] == "deny"} == {text.split("): ", 1)[1]}


async def test_forward_failure_names_the_class_only(upstream, audit_path):
    al = make_airlock(upstream, audit_path)

    async def post(url, *, content, headers):
        raise httpx.ConnectError("illegal header value b'Bearer tok-SECRET123'")

    al.http.post = post
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    status, reply = await al.forward(body, {}, Principal("alice"))
    assert status == 502 and reply["error"]["message"] == "upstream unreachable: ConnectError"


async def test_upstream_unreachable_secret_reaches_neither_caller_nor_audit(upstream, audit_path):
    al = make_airlock(upstream, audit_path)

    async def post(url, *, content, headers):
        raise httpx.ConnectError("illegal header value b'Bearer tok-SECRET123'")

    al.http.post = post
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
    assert res["_meta"][META + "rule_id"] == "catalog.unavailable"
    assert "SECRET123" not in json.dumps(res) + audit_path.read_text()


async def test_internal_and_postprocess_error_text_is_scrubbed(upstream, audit_path):
    al = make_airlock(upstream, audit_path)

    def boom(*a, **kw):
        raise RuntimeError("failed with Bearer tok-SECRET123 " + "y" * 400)

    al._cap_output = boom
    async with proxy_client(al) as c:
        await call(c, "get_service", {"name": "api"})
        al.engine.evaluate = boom
        r = await rpc(c, "tools/call", {"name": "get_service", "arguments": {"name": "api"}})
    assert r.json()["error"]["message"] == "airlock: internal error"
    raw = audit_path.read_text()
    assert "SECRET123" not in raw
    details = [r["detail"] for r in audit_rows(audit_path) if r["detail"]]
    assert details[0]["postprocess_error"].startswith("RuntimeError: failed with [REDACTED] y")
    assert details[1].startswith("RuntimeError: failed with [REDACTED] y") and len(details[1]) == len("RuntimeError: ") + 300


async def test_malformed_upstream_content_does_not_lose_the_result(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    orig = al.http.post

    async def post(url, *, content, headers):
        r = await orig(url, content=content, headers=headers)
        body = json.loads(content)
        if body["method"] == "tools/call":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {
                "resultType": "complete", "content": [{"type": "text", "text": 42}, None, "x", {"type": "text"}]}})
        return r

    al.http.post = post
    async with proxy_client(al) as c:
        r = await rpc(c, "tools/call", {"name": "get_service", "arguments": {"name": "big"}})  # cap path too (5000)
        assert r.status_code == 200 and r.json()["result"]["content"][0]["text"] == 42
    assert audit_rows(audit_path)[-1]["phase"] == "outcome"


async def test_accept_header_is_always_dual_upstream(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    seen: list[dict] = []
    orig = al.http.post

    async def post(url, *, content, headers):
        seen.append(headers)
        return await orig(url, content=content, headers=headers)

    al.http.post = post
    async with proxy_client(al) as c:
        await call(c, "get_service", {"name": "api"}, headers={"accept": "application/json"})
    assert seen[-1]["accept"] == "application/json, text/event-stream"


async def test_preview_text_is_scrubbed(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": secret})  # preview says "would delete ghp_..."
    blob = json.dumps(res) + posted[0]
    assert secret not in blob and "[REDACTED]" in res["inputRequests"][CONFIRM_KEY]["params"]["message"]


async def test_header_mirrored_dry_run_is_rewritten_with_the_body(client, upstream):
    res = await call(client, "rotate_key", {"name": "db"})  # no Mcp-Param header from the agent
    assert res["resultType"] == "input_required" and "would rotate db" in res["inputRequests"][CONFIRM_KEY]["params"]["message"]
    res = await call(client, "rotate_key", {"name": "db"}, extra=accept(res["requestState"]))
    assert res["isError"] is False and "ROTATED db" in res["content"][0]["text"]
    assert [x["args"]["dry_run"] for x in upstream.CALLS if x["tool"] == "rotate_key"] == [True, False]


async def test_outcome_audit_failure_does_not_lose_the_result(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    real = al.audit.write

    def flaky(**rec):
        if rec.get("phase") == "outcome":
            raise OSError(28, "No space left on device")
        real(**rec)

    al.audit.write = flaky
    async with proxy_client(al) as c:
        res = await call(c, "get_service", {"name": "api"})
    assert res["isError"] is False  # executed and delivered; the failure is logged, not turned into a 500


async def test_intent_audit_failure_fails_closed(upstream, audit_path):
    al = make_airlock(upstream, audit_path)

    def broken(**rec):
        raise OSError(28, "No space left on device")

    al.audit.write = broken
    async with proxy_client(al) as c:
        r = await rpc(c, "tools/call", {"name": "get_service", "arguments": {"name": "api"}})
    assert r.status_code == 500 and r.json()["error"]["code"] == -32603
    assert upstream.CALLS == []  # nothing forwarded without an intent record


def test_redact_nested_containers_and_scrub():
    from mcp_airlock.audit import redact, scrub
    assert redact({"credentials": {"user": "x", "pass": "y"}, "tokens": ["a", "b"], "n": 1}) == {"credentials": "[REDACTED]", "tokens": "[REDACTED]", "n": 1}
    text = "would delete ghp_abcdefghijklmnopqrstuvwxyz1234567890 with Bearer abc.def and sk-1234567890abcdef ok"
    out = scrub(text)
    assert "ghp_" not in out and "Bearer abc" not in out and "sk-1234" not in out and out.endswith(" ok")


def test_chars_per_token_must_be_positive(tmp_path):
    import pydantic
    p = tmp_path / "p.yaml"
    p.write_text("version: 1\nenvironment: prod\noutput: {max_chars: 100, chars_per_token: 0}\ntools: {}\n")
    with pytest.raises(pydantic.ValidationError):
        Policy.load(p)


def upstream_asks_back(al: Airlock, tool: str) -> list[dict]:
    """Make every tools/call to `tool` answer with the upstream's own input_required (its own elicitation)."""
    sent: list[dict] = []
    orig = al.http.post

    async def post(url, *, content, headers):
        body = json.loads(content)
        if body["method"] == "tools/call" and body["params"]["name"] == tool:
            sent.append(body)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {
                "resultType": "input_required", "requestState": "upstream-owned",
                "inputRequests": {"which": {"method": "elicitation/create", "params": {"message": "which one?"}}}}})
        return await orig(url, content=content, headers=headers)

    al.http.post = post
    return sent


async def test_upstream_input_required_behind_l2_preview_is_refused_not_looped(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    sent = upstream_asks_back(al, "delete_service")
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
    assert res["isError"] and res["_meta"][META + "rule_id"] == "mrtr.upstream_input_required"
    assert "inputRequests" not in res and [b["params"]["arguments"]["dry_run"] for b in sent] == [True]
    assert audit_rows(audit_path)[-1]["rule_id"] == "mrtr.upstream_input_required"


async def test_upstream_input_required_after_confirmation_is_refused_not_reprompted(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    sent = upstream_asks_back(al, "restart_service")  # L2 without dry_run: the confirmed call is the first forward
    async with proxy_client(al) as c:
        res = await call(c, "restart_service", {"name": "api"})
        assert res["resultType"] == "input_required" and sent == []
        res = await call(c, "restart_service", {"name": "api"}, extra=accept(res["requestState"]))
    assert res["isError"] and res["_meta"][META + "rule_id"] == "mrtr.upstream_input_required"
    assert "requestState" not in res and len(sent) == 1


async def test_upstream_input_required_at_l1_passes_through_with_its_own_state(upstream, audit_path):
    al = make_airlock(upstream, audit_path, env="staging")  # set_replicas is L1 there: no airlock prompt to tangle with
    sent = upstream_asks_back(al, "set_replicas")
    async with proxy_client(al) as c:
        res = await call(c, "set_replicas", {"names": ["api"], "replicas": 2})
        assert res["resultType"] == "input_required" and res["requestState"] == "upstream-owned"
        retry = {"requestState": "upstream-owned", "inputResponses": {"which": {"action": "accept", "content": {}}}}
        await call(c, "set_replicas", {"names": ["api"], "replicas": 2}, extra=retry)
    assert sent[-1]["params"]["requestState"] == "upstream-owned" and sent[-1]["params"]["arguments"]["dry_run"] is True


# 8. approval mode ---------------------------------------------------------------------------------------------------
def real_deletes(upstream) -> list:
    return [x for x in upstream.CALLS if x["tool"] == "delete_service" and not x["args"]["dry_run"]]


async def test_oob_ignores_in_band_accept_until_the_link_is_posted(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)  # webhook set, no mode given: defaults to oob
    assert al.approval_mode == "oob"
    async with proxy_client(al) as c:
        token = (await call(c, "delete_service", {"name": "api"}))["requestState"]
        n = len(upstream.CALLS)  # the dry run; an ignored retry forwards nothing, not even another dry run
        res = await call(c, "delete_service", {"name": "api"}, extra=accept(token))
        assert res["resultType"] == "input_required" and res["requestState"] == token
        assert "inputRequests" not in res and res["_meta"][META + "status"] == "pending"
        assert len(upstream.CALLS) == n
        res = await call(c, "delete_service", {"name": "api"}, extra=accept(token))  # asking again changes nothing
        assert res["_meta"][META + "status"] == "pending" and len(upstream.CALLS) == n
        assert (await c.post(approve_path(posted))).status_code == 200
        res = await call(c, "delete_service", {"name": "api"}, extra=accept(token))  # the same retry now executes
        assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
        res = await call(c, "delete_service", {"name": "api"}, extra=accept(token))
        assert res["_meta"][META + "rule_id"] == "mrtr.replay"
    assert len(real_deletes(upstream)) == 1
    pending = [r for r in audit_rows(audit_path) if r["rule_id"] == "mrtr.pending"]
    assert len(pending) == 4 and all(r["detail"] == "in-band accept ignored (approval mode oob)" for r in pending)


async def test_oob_polling_without_an_answer_has_no_ignored_note(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        token = (await call(c, "delete_service", {"name": "api"}))["requestState"]
        await call(c, "delete_service", {"name": "api"}, extra={"requestState": token})
    pending = [r for r in audit_rows(audit_path) if r["rule_id"] == "mrtr.pending"]
    assert len(pending) == 2 and all(r["detail"] is None for r in pending)


@pytest.mark.parametrize("answer", [{"action": "decline"}, {"action": "cancel"}, "yes", {"action": "accept"},
                                    {"action": "accept", "content": {"confirm": False}}])
async def test_oob_decline_cancel_and_malformed_answers_still_burn_the_key(upstream, audit_path, answer):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        token = (await call(c, "delete_service", {"name": "api"}))["requestState"]
        res = await call(c, "delete_service", {"name": "api"}, extra={"requestState": token, "inputResponses": {CONFIRM_KEY: answer}})
        assert res["isError"] and res["_meta"][META + "rule_id"] == "mrtr.declined"
        assert (await c.post(approve_path(posted))).status_code == 200  # approving afterwards does not revive it
        res = await call(c, "delete_service", {"name": "api"}, extra=accept(token))
        assert res["isError"] and res["_meta"][META + "rule_id"] == "mrtr.replay"
    assert real_deletes(upstream) == []


async def test_inband_mode_with_webhook_keeps_both_approval_paths(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted, approval_mode="inband")
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
        assert "Confirm to execute for real." in res["inputRequests"][CONFIRM_KEY]["params"]["message"]
        res = await call(c, "delete_service", {"name": "api"}, extra=accept(res["requestState"]))
        assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
        token = (await call(c, "delete_service", {"name": "db"}))["requestState"]  # the link still approves as well
        res = await call(c, "delete_service", {"name": "db"}, extra={"requestState": token})
        assert res["resultType"] == "input_required" and res["_meta"][META + "status"] == "pending"
        assert (await c.post(approve_path(posted))).status_code == 200
        res = await call(c, "delete_service", {"name": "db"}, extra={"requestState": token})
        assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
    assert len(real_deletes(upstream)) == 2 and len(posted) == 2


async def test_oob_prompt_says_the_client_cannot_approve(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
    msg = res["inputRequests"][CONFIRM_KEY]["params"]["message"]
    assert "confirming in the client does not approve" in msg and "Confirm to execute" not in msg
    assert res["requestState"] and CONFIRM_KEY in res["inputRequests"]  # shape unchanged


def replicas(upstream, tmp_path, posted: list, *modes: str) -> list[Airlock]:
    """One replica per mode, all sharing the secret and the store (and the webhook, which oob needs)."""
    secret, store = b"s" * 32, MemoryStore()
    return [webhook_airlock(upstream, tmp_path / f"audit{i}.jsonl", posted, secret=secret, store=store, approval_mode=m)
            for i, m in enumerate(modes)]


def resign(al: Airlock, token: str, **claims) -> str:
    """The token with its claims replaced (None drops one), signed with the replica's own key."""
    body = json.loads(_unb64(token[len(TOKEN_PREFIX):].split(".", 1)[0]))
    body = {k: v for k, v in {**body, **claims}.items() if v is not None}
    return al._sign(_b64(json.dumps(body, separators=(",", ":")).encode()), TOKEN_PREFIX)


@pytest.mark.parametrize("issuer, receiver", [("oob", "inband"), ("inband", "oob")])
async def test_token_mode_is_not_dropped_by_a_replica_in_the_other_mode(upstream, tmp_path, issuer, receiver):
    posted: list[str] = []
    a, b = replicas(upstream, tmp_path, posted, issuer, receiver)
    args = {"name": "api"}
    async with proxy_client(a) as ca, proxy_client(b) as cb:
        token = (await call(ca, "delete_service", args))["requestState"]
        n = len(upstream.CALLS)
        res = await call(cb, "delete_service", args, extra=accept(token))
        assert res["resultType"] == "input_required" and res["_meta"][META + "status"] == "pending"
        assert len(upstream.CALLS) == n and real_deletes(upstream) == []
        assert (await cb.post(approve_path(posted))).status_code == 200  # the link approves whichever replica gets it
        res = await call(cb, "delete_service", args, extra={"requestState": token})
        assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
    assert len(real_deletes(upstream)) == 1
    pending = [r for r in audit_rows(tmp_path / "audit1.jsonl") if r["rule_id"] == "mrtr.pending"]
    assert len(pending) == 2 and all(r["detail"] == "in-band accept ignored (approval mode oob)" for r in pending)


async def test_inband_token_accepted_in_band_by_an_inband_replica(upstream, tmp_path):
    posted: list[str] = []
    a, b = replicas(upstream, tmp_path, posted, "inband", "inband")
    async with proxy_client(a) as ca, proxy_client(b) as cb:
        token = (await call(ca, "delete_service", {"name": "api"}))["requestState"]
        res = await call(cb, "delete_service", {"name": "api"}, extra=accept(token))
    assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
    assert len(real_deletes(upstream)) == 1


async def test_token_without_mode_runs_on_an_inband_replica(upstream, tmp_path):
    posted: list[str] = []
    (al,) = replicas(upstream, tmp_path, posted, "inband")
    async with proxy_client(al) as c:
        token = resign(al, (await call(c, "delete_service", {"name": "api"}))["requestState"], m=None)
        res = await call(c, "delete_service", {"name": "api"}, extra=accept(token))
    assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
    assert len(real_deletes(upstream)) == 1


async def test_token_without_mode_stays_pending_on_an_oob_replica_until_the_link(upstream, tmp_path):
    posted: list[str] = []
    (al,) = replicas(upstream, tmp_path, posted, "oob")
    async with proxy_client(al) as c:
        token = resign(al, (await call(c, "delete_service", {"name": "api"}))["requestState"], m=None)
        res = await call(c, "delete_service", {"name": "api"}, extra=accept(token))
        assert res["_meta"][META + "status"] == "pending" and real_deletes(upstream) == []
        assert (await c.post(approve_path(posted))).status_code == 200
        res = await call(c, "delete_service", {"name": "api"}, extra={"requestState": token})
        assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L2.confirmed"
    assert len(real_deletes(upstream)) == 1


async def test_unknown_token_mode_counts_as_oob(upstream, tmp_path):
    posted: list[str] = []
    (al,) = replicas(upstream, tmp_path, posted, "inband")
    async with proxy_client(al) as c:
        token = resign(al, (await call(c, "delete_service", {"name": "api"}))["requestState"], m="strict")
        res = await call(c, "delete_service", {"name": "api"}, extra=accept(token))
    assert res["_meta"][META + "status"] == "pending" and real_deletes(upstream) == []


async def test_editing_the_token_mode_breaks_the_signature(upstream, tmp_path):
    posted: list[str] = []
    a, b = replicas(upstream, tmp_path, posted, "oob", "inband")
    async with proxy_client(a) as ca, proxy_client(b) as cb:
        token = (await call(ca, "delete_service", {"name": "api"}))["requestState"]
        body, sig = token[len(TOKEN_PREFIX):].split(".", 1)
        claims = json.loads(_unb64(body))
        assert claims["m"] == "oob"
        edited = TOKEN_PREFIX + _b64(json.dumps({**claims, "m": "inband"}, separators=(",", ":")).encode()) + "." + sig
        res = await call(cb, "delete_service", {"name": "api"}, extra=accept(edited))
    assert res["isError"] and res["_meta"][META + "rule_id"] == "mrtr.bad_signature"
    assert real_deletes(upstream) == []


async def test_default_without_webhook_is_inband(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    assert al.approval_mode == "inband"
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
        res = await call(c, "delete_service", {"name": "api"}, extra=accept(res["requestState"]))
    assert res["isError"] is False and len(real_deletes(upstream)) == 1


def test_bad_approval_mode_fails_at_construction(upstream, audit_path):
    with pytest.raises(ValueError, match="unknown approval mode 'maybe'"):
        make_airlock(upstream, audit_path, approval_mode="maybe")
    with pytest.raises(ValueError, match="unknown approval mode ''"):
        make_airlock(upstream, audit_path, approval_mode="")
    with pytest.raises(ValueError, match="AIRLOCK_APPROVAL_WEBHOOK"):
        make_airlock(upstream, audit_path, approval_mode="oob")
    assert make_airlock(upstream, audit_path, approval_mode="inband").approval_mode == "inband"


def test_build_reads_approval_mode_from_env(monkeypatch, tmp_path):
    from mcp_airlock.app import build
    for var in ("AIRLOCK_APPROVAL_WEBHOOK", "AIRLOCK_APPROVAL_MODE", "AIRLOCK_STORE_DSN", "AIRLOCK_AUDIT_DSN"):
        monkeypatch.delenv(var, raising=False)

    def make() -> Airlock:
        return build(str(ROOT / "policy.example.yaml"), "http://localhost:9001/mcp", str(tmp_path / "audit.jsonl"), "prod")

    assert make().approval_mode == "inband"
    monkeypatch.setenv("AIRLOCK_APPROVAL_MODE", "oob")
    with pytest.raises(ValueError, match="AIRLOCK_APPROVAL_WEBHOOK"):
        make()
    monkeypatch.setenv("AIRLOCK_APPROVAL_WEBHOOK", "https://hooks.example/x")
    assert make().approval_mode == "oob"
    monkeypatch.setenv("AIRLOCK_APPROVAL_MODE", "inband")
    assert make().approval_mode == "inband"
    monkeypatch.delenv("AIRLOCK_APPROVAL_MODE")
    assert make().approval_mode == "oob"
    monkeypatch.setenv("AIRLOCK_APPROVAL_MODE", "")  # empty means unset: the default applies
    assert make().approval_mode == "oob"


# 9. approve page shows what is approved ------------------------------------------------------------------------------
async def approve_page_text(upstream, audit_path, args: dict, **kw) -> tuple[str, str]:
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted, **kw)
    async with proxy_client(al) as c:
        await call(c, "delete_service", args)
        return posted[0], (await c.get(approve_path(posted))).text


@pytest.mark.parametrize("kind", ["memory", pytest.param("postgres", marks=pytest.mark.skipif(not PG, reason="AIRLOCK_TEST_PG_DSN not set"))])
async def test_approve_page_shows_arguments_and_preview(upstream, audit_path, kind):
    store = PostgresStore(PG) if kind == "postgres" else MemoryStore()
    posted, page = await approve_page_text(upstream, audit_path, {"name": "api"}, store=store)
    assert "<pre>" in page and "delete_service" in page
    assert "Arguments: {&quot;name&quot;: &quot;api&quot;}" in page and "Dry-run preview: would delete api" in page
    assert "not available" not in page and "<form" in page
    assert html.unescape(page.split("<pre>")[1].split("</pre>")[0]) in posted  # the same text the message carries


async def test_approve_page_without_dry_run_says_so(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        await call(c, "restart_service", {"name": "api"}, principal="root")  # L2 in prod, no dry_run argument
        page = (await c.get(approve_path(posted))).text
    assert "No dry-run preview" in page and "<form" in page


async def test_approve_page_does_not_render_secrets(upstream, audit_path):
    _, page = await approve_page_text(upstream, audit_path, {"name": "api", "api_token": "sk-verysecretvalue123", "note": "sk-othersecret456"})
    assert "sk-verysecretvalue123" not in page and "sk-othersecret456" not in page and "[REDACTED]" in page


async def test_approve_page_scrubs_secret_in_preview(upstream, audit_path):
    # The upstream echoes the name into its preview; the argument is redacted and so is the preview text.
    _, page = await approve_page_text(upstream, audit_path, {"name": "sk-verysecretvalue123"})
    assert "sk-verysecretvalue123" not in page and "Dry-run preview: would delete [REDACTED]" in page


async def test_approve_page_escapes_html_in_arguments(upstream, audit_path):
    payload = "<script>alert(1)</script><b>x</b>"
    _, page = await approve_page_text(upstream, audit_path, {"name": payload})
    assert payload not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page


async def test_approve_page_text_is_capped(upstream, audit_path):
    posted, page = await approve_page_text(upstream, audit_path, {"name": "api", "note": "a" * 20000})
    text = html.unescape(page.split("<pre>")[1].split("</pre>")[0])
    assert len(text) == 8000 and "not available" not in page
    assert text.endswith("\n[cut at 8000 characters; the full text is in the original message]")  # the cut is not silent
    assert "Dry-run preview" in posted and "Dry-run preview" not in text  # what the page lost, the message still has


@pytest.mark.parametrize("kind", ["memory", pytest.param("postgres", marks=pytest.mark.skipif(not PG, reason="AIRLOCK_TEST_PG_DSN not set"))])
async def test_approve_page_text_survives_nul_in_preview(upstream, audit_path, kind):
    # The upstream echoes the name into its preview, so the preview carries a NUL that Postgres text cannot hold.
    store = PostgresStore(PG) if kind == "postgres" else MemoryStore()
    _, page = await approve_page_text(upstream, audit_path, {"name": "api\x00"}, store=store)
    assert "Dry-run preview: would delete api" in page and "\x00" not in page and "not available" not in page


async def test_approve_page_says_when_text_is_missing(upstream, audit_path, caplog):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)

    async def boom(key, text, exp_ts):
        raise RuntimeError("db down at postgresql://user:pw@host/db")

    al.engine.store.save_prompt = boom
    async with proxy_client(al) as c:
        res = await call(c, "delete_service", {"name": "api"})
        assert res["resultType"] == "input_required" and len(posted) == 1  # the prompt and the message still go out
        page = (await c.get(approve_path(posted))).text
        assert "<pre>" not in page and "not available" in page and "original message" in page and "<form" in page
        assert (await c.post(approve_path(posted))).status_code == 200  # approving stays possible
    assert "RuntimeError" in caplog.text and "pw@host" not in caplog.text


async def test_approve_page_renders_when_reading_the_text_fails(upstream, audit_path, caplog):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api"})

        async def boom(key):
            raise RuntimeError("db down at postgresql://user:pw@host/db")

        al.engine.store.get_prompt = boom
        r = await c.get(approve_path(posted))
        assert r.status_code == 200 and "<pre>" not in r.text and "not available" in r.text and "<form" in r.text
    assert "RuntimeError" in caplog.text and "pw@host" not in caplog.text


async def test_prompt_text_is_stored_before_the_message_is_posted(upstream, audit_path):
    stored_at_post: list[dict] = []  # what the store holds at the moment the webhook is hit
    al = make_airlock(upstream, audit_path, webhook="https://hooks.example/x", public_url="https://a.example",
                      notify_http=httpx.AsyncClient(transport=httpx.MockTransport(
                          lambda r: (stored_at_post.append(dict(al.engine.store._prompts)), httpx.Response(200))[1])))
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api"})
    assert len(stored_at_post) == 1 and len(stored_at_post[0]) == 1
    assert "Arguments: {\"name\": \"api\"}" in next(iter(stored_at_post[0].values()))[1]


async def test_prompt_text_is_not_stored_without_webhook(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api"})
    assert al.engine.store._prompts == {}


async def test_approve_page_text_expires_with_the_prompt(upstream, audit_path):
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)
    async with proxy_client(al) as c:
        await call(c, "delete_service", {"name": "api"})
        key = next(iter(al.engine.store._prompts))
        al.engine.store._prompts[key] = (0.0, "x")  # expired entry is not served
        assert (await c.get(approve_path(posted))).text.count("not available") == 1


# 10. health and readiness probes ---------------------------------------------------------------------------------
async def _raises() -> None:
    raise RuntimeError("postgresql://user:pw@host/db is down")


async def _hangs() -> None:
    try:
        await asyncio.sleep(30)
    except asyncio.CancelledError:  # like psycopg on a silent query: the first cancel is caught and the wait goes on
        await asyncio.sleep(0.2)  # short, so the loop can still close at teardown


async def test_probes_answer_without_credentials_and_write_nothing(upstream, audit_path, monkeypatch):
    al = make_airlock(upstream, audit_path, trust_principal_header=False, jwt_secret="s" * 32)  # a principal would be required
    sent = spy(al)
    monkeypatch.setattr("mcp_airlock.app.resolve", lambda *a: pytest.fail("a probe resolved identity"))
    SPANS.clear()
    async with proxy_client(al) as c:
        for path in ("/healthz", "/readyz"):
            r = await c.get(path)
            assert r.status_code == 200 and r.json() == {"status": "ok"}, path
        assert (await c.get("/nope")).status_code == 404
    assert audit_rows(audit_path) == [] and upstream.CALLS == [] and sent == [] and SPANS.get_finished_spans() == ()


@pytest.mark.parametrize("ping", [_raises, _hangs], ids=["raises", "hangs"])
async def test_readyz_is_503_when_the_store_fails_and_keeps_the_error_out(upstream, audit_path, monkeypatch, caplog, ping):
    monkeypatch.setattr("mcp_airlock.app.READY_TIMEOUT_S", 0.05)
    al = make_airlock(upstream, audit_path)
    al.engine.store.ping = ping
    async with proxy_client(al) as c:
        r = await c.get("/readyz")
        assert r.status_code == 503 and r.json() == {"status": "unavailable"}
        assert "pw@host" not in r.text and "pw@host" not in caplog.text
        assert (await c.get("/healthz")).status_code == 200  # liveness does not look at the store
    assert audit_rows(audit_path) == [] and upstream.CALLS == []


async def test_readyz_shares_one_ping_while_the_store_hangs(upstream, audit_path, monkeypatch):
    monkeypatch.setattr("mcp_airlock.app.READY_TIMEOUT_S", 0.05)
    al = make_airlock(upstream, audit_path)
    pings: list[int] = []

    async def ping() -> None:
        pings.append(1)
        await _hangs()

    al.engine.store.ping = ping
    async with proxy_client(al) as c:
        rs = await asyncio.gather(*(c.get("/readyz") for _ in range(5)))
        assert {r.status_code for r in rs} == {503} and len(pings) == 1  # one connection however many probes arrive meanwhile
        assert (await c.get("/readyz")).status_code == 503 and len(pings) == 2  # after one bound the hung ping is left behind


async def test_readyz_recovers_once_the_store_answers_again(upstream, audit_path, monkeypatch):
    monkeypatch.setattr("mcp_airlock.app.READY_TIMEOUT_S", 0.05)
    al = make_airlock(upstream, audit_path)
    calls: list[int] = []

    async def ping() -> None:  # the first connection is black-holed for good; every later one answers
        calls.append(1)
        if len(calls) == 1:
            await _hangs()

    al.engine.store.ping = ping
    async with proxy_client(al) as c:
        assert (await c.get("/readyz")).status_code == 503
        assert (await c.get("/readyz")).status_code == 200  # a fresh ping, not another wait on the hung one
    assert len(calls) == 2


async def test_readyz_follows_a_store_that_answered_down_and_back_up(upstream, audit_path):
    al = make_airlock(upstream, audit_path)
    calls: list[int] = []

    async def ping() -> None:  # the store answers, goes down, comes back; all on one instance
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("postgresql://user:pw@host/db is down")

    al.engine.store.ping = ping
    async with proxy_client(al) as c:
        assert (await c.get("/readyz")).status_code == 200
        assert (await c.get("/readyz")).status_code == 503  # the first answer is not reused once it is in
        assert (await c.get("/readyz")).status_code == 200
    assert len(calls) == 3


async def test_readyz_keeps_a_late_failure_out_of_the_log(upstream, audit_path, monkeypatch, caplog):
    monkeypatch.setattr("mcp_airlock.app.READY_TIMEOUT_S", 0.05)
    al = make_airlock(upstream, audit_path)
    calls: list[int] = []

    async def ping() -> None:  # the first connection dies after the probe gave up on it; every later one answers
        calls.append(1)
        if len(calls) == 1:
            await asyncio.sleep(0.1)
            raise RuntimeError("postgresql://user:pw@host/db is down")

    al.engine.store.ping = ping
    async with proxy_client(al) as c:
        assert (await c.get("/readyz")).status_code == 503
        await asyncio.sleep(0.2)  # the first ping fails with nobody waiting for it
        assert (await c.get("/readyz")).status_code == 200  # the failed ping is garbage now
    gc.collect()
    assert "pw@host" not in caplog.text and "never retrieved" not in caplog.text


@pytest.mark.skipif(not PG, reason="AIRLOCK_TEST_PG_DSN not set")
async def test_readyz_on_postgres(upstream, audit_path):
    async with proxy_client(make_airlock(upstream, audit_path, store=PostgresStore(PG))) as c:
        assert (await c.get("/readyz")).status_code == 200
    async with proxy_client(make_airlock(upstream, audit_path, store=PostgresStore("postgresql://x:y@127.0.0.1:1/z"))) as c:
        r = await c.get("/readyz")
        assert r.status_code == 503 and r.json() == {"status": "unavailable"}
