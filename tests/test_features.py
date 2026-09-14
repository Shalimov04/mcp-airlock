"""Roadmap features wired into the proxy: shared store, principal/group tiers, catalog cache,
L2 without dry_run, injection marking, out-of-band approvals. Written before the code (TDD)."""

from __future__ import annotations

import json
import os
import textwrap

import httpx
import pytest

from mcp_airlock import Airlock, Policy
from mcp_airlock.app import CONFIRM_KEY, META
from mcp_airlock.audit import AuditLog
from mcp_airlock.identity import IdentityConfig
from mcp_airlock.store import MemoryStore, PostgresStore

from .conftest import ROOT, audit_rows, call, make_airlock, rpc

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
    al = make_airlock(upstream, audit_path, env="staging")  # set_replicas is L1 → forced dry-run → schema check
    sent = spy(al, ttl_ms=None)  # fake says ttlMs 0 → never cache
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
