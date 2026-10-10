"""Policy reload: the policy file and the pins file swap in as one pair, and a request keeps the pair it started with."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal

import httpx
import pytest
import yaml

from mcp_airlock import Airlock
from mcp_airlock.app import CONFIRM_KEY, META, ReloadSource, build

from .conftest import ENVELOPE, ROOT, V, audit_rows, call, make_airlock, patch_post, rpc
from .test_pins import OLD_ZEROS, ZEROS, write_pins

SUCCESS = "mcp-airlock: policy reloaded: {} tools (was {})\n"
FAILURE = "mcp-airlock: policy reload failed, keeping the current policy: "


def policy_data() -> dict:
    return yaml.safe_load((ROOT / "policy.example.yaml").read_text())


def write_policy(path, data: dict | str) -> str:
    path.write_text(data if isinstance(data, str) else yaml.safe_dump(data))
    return str(path)


def reloadable(upstream, audit_path, tmp_path, *, pins_path=None, env="prod", **kw) -> Airlock:
    """An airlock that reloads from tmp_path / "policy.yaml", a copy of the example policy."""
    path = write_policy(tmp_path / "policy.yaml", policy_data())
    return make_airlock(upstream, audit_path, env=env, reload_source=ReloadSource(path, pins_path), **kw)


def accept(token: str) -> dict:
    return {"requestState": token, "inputResponses": {CONFIRM_KEY: {"action": "accept", "content": {"confirm": True}}}}


def proxy(al: Airlock) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=al.app), base_url="http://localhost:9000")


def hold_first_upstream_request(al: Airlock) -> tuple[asyncio.Event, asyncio.Event]:
    """The first request the proxy sends upstream waits there: returns (entered, release)."""
    entered, release = asyncio.Event(), asyncio.Event()
    orig, held = al.http.post, []

    async def post(url, *, content, headers):
        if not held:
            held.append(True)
            entered.set()
            await release.wait()
        return await orig(url, content=content, headers=headers)

    patch_post(al, post)
    return entered, release


def post_in_two_chunks(c: httpx.AsyncClient, method: str, params: dict) -> tuple[asyncio.Task, asyncio.Event, asyncio.Event]:
    """The body arrives in two chunks and the second waits: returns (response task, parked, release)."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {"_meta": dict(ENVELOPE), **params}}).encode()
    parked, release = asyncio.Event(), asyncio.Event()

    async def chunks():
        yield body[:10]
        parked.set()
        await release.wait()
        yield body[10:]

    headers = {"mcp-protocol-version": V, "mcp-method": method, "accept": "application/json, text/event-stream",
               "content-type": "application/json", "x-airlock-principal": "alice"}
    if method == "tools/call":
        headers["mcp-name"] = params["name"]
    return asyncio.create_task(c.post("/mcp", content=chunks(), headers=headers)), parked, release


# ---------------------------------------------------------------- the swap reaches the next call

async def test_reload_applies_to_the_next_call_in_both_directions(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    data = policy_data()
    async with proxy(al) as c:
        assert (await call(c, "get_service", {"name": "api"}))["_meta"][META + "rule_id"] == "tier.L0.read"
        assert (await call(c, "rm_rf", {"path": "/x"}))["_meta"][META + "rule_id"] == "allowlist.deny"

        del data["tools"]["get_service"]  # allowlisted becomes denied
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        res = await call(c, "get_service", {"name": "api"})
        assert res["isError"] and res["_meta"][META + "rule_id"] == "allowlist.deny"

        data["tools"]["rm_rf"] = {"tiers": {"prod": "L0"}}  # denied becomes allowlisted
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        res = await call(c, "rm_rf", {"path": "/x"})
        assert not res["isError"] and res["_meta"][META + "rule_id"] == "tier.L0.read"
        assert upstream.CALLS[-1]["tool"] == "rm_rf"


async def test_reload_reports_the_tool_counts(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    data = policy_data()
    del data["tools"]["get_service"]
    write_policy(tmp_path / "policy.yaml", data)
    r = al.reload()
    assert (r.ok, r.tools_before, r.tools_after, r.error) == (True, 6, 5, None)
    assert al.reload().tools_before == 5  # the second one starts from the new count


async def test_an_old_format_pins_file_keeps_the_old_pins(upstream, audit_path, tmp_path):
    pins_path = write_pins(tmp_path, {"get_service": ZEROS})
    al = reloadable(upstream, audit_path, tmp_path, pins_path=pins_path, pins={"get_service": ZEROS})
    pins = al.pins
    write_pins(tmp_path, {"get_service": OLD_ZEROS})
    r = al.reload()
    assert not r.ok and "old pin format" in r.error
    assert al.pins is pins


async def test_reload_is_reported_on_stderr_and_in_the_log_and_never_audited(upstream, audit_path, tmp_path, capsys, caplog):
    al = reloadable(upstream, audit_path, tmp_path)
    data = policy_data()
    del data["tools"]["get_service"]
    write_policy(tmp_path / "policy.yaml", data)
    with caplog.at_level(logging.INFO, logger="mcp_airlock"):
        assert al.reload().ok
        assert capsys.readouterr().err == SUCCESS.format(5, 6)
        assert "policy reloaded: 5 tools (was 6)" in caplog.text
        write_policy(tmp_path / "policy.yaml", "tools: [unclosed")
        assert not al.reload().ok
    err = capsys.readouterr().err
    assert err.startswith(FAILURE) and err.count("\n") == 1  # one line
    assert "policy reload failed, keeping the current policy: " in caplog.text
    assert audit_rows(audit_path) == []


# ---------------------------------------------------------------- a file that does not load changes nothing

def broken_where(data: dict, rule: dict | None = None) -> str:
    data["tools"]["delete_service"]["where"] = [rule or {"arg": "name", "in": []}]  # parses, fails validation
    return yaml.safe_dump(data)


@pytest.mark.parametrize("name, body, expect", [
    ("not yaml", "tools: [unclosed", None),
    ("not a mapping", "- just\n- a list\n", None),
    ("unknown key", yaml.safe_dump({**policy_data(), "toolz": {}}), "toolz"),
    ("empty where list", broken_where(policy_data()), "in must not be empty"),
    ("regex RE2 cannot run", broken_where(policy_data(), {"arg": "name", "regex": "(?=a)a"}), "RE2 syntax"),
    ("tools is a string", yaml.safe_dump({**policy_data(), "tools": "all"}), "tools"),
])
async def test_a_file_that_does_not_load_keeps_the_old_policy(upstream, audit_path, tmp_path, capsys, name, body, expect):
    al = reloadable(upstream, audit_path, tmp_path)
    engine, pins = al.engine, al.pins
    write_policy(tmp_path / "policy.yaml", body)
    r = al.reload()
    assert r.ok is False and (r.tools_before, r.tools_after) == (6, 6) and r.error and "\n" not in r.error
    if expect:
        assert expect in r.error
    assert al.engine is engine and al.pins is pins
    assert capsys.readouterr().err == FAILURE + r.error + "\n"
    async with proxy(al) as c:
        assert (await call(c, "get_service", {"name": "api"}))["_meta"][META + "rule_id"] == "tier.L0.read"


async def test_a_missing_file_keeps_the_old_policy(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    engine = al.engine
    os.remove(tmp_path / "policy.yaml")
    r = al.reload()
    assert not r.ok and str(tmp_path / "policy.yaml") in r.error and al.engine is engine


async def test_a_broken_pins_file_keeps_the_old_policy_and_the_old_pins(upstream, audit_path, tmp_path):
    pins_path = write_pins(tmp_path, {"get_service": ZEROS})
    al = reloadable(upstream, audit_path, tmp_path, pins_path=pins_path, pins={"get_service": ZEROS})
    engine, pins = al.engine, al.pins
    data = policy_data()
    del data["tools"]["get_service"]  # a good policy next to a bad pins file
    write_policy(tmp_path / "policy.yaml", data)
    write_pins(tmp_path, "{not json")
    r = al.reload()
    assert not r.ok and pins_path in r.error
    assert al.engine is engine and al.pins is pins and len(al.engine.policy.tools) == 6
    async with proxy(al) as c:
        assert (await call(c, "get_service", {"name": "api"}))["_meta"][META + "rule_id"] == "tier.L0.read"


async def test_a_good_pins_file_next_to_a_broken_policy_changes_neither(upstream, audit_path, tmp_path):
    pins_path = write_pins(tmp_path, {})
    al = reloadable(upstream, audit_path, tmp_path, pins_path=pins_path, pins={})
    engine, pins = al.engine, al.pins
    write_pins(tmp_path, {"get_service": ZEROS})
    write_policy(tmp_path / "policy.yaml", "tools: [unclosed")
    assert not al.reload().ok
    assert al.engine is engine and al.pins is pins and al.pins == {}


async def test_the_policy_and_the_pins_swap_together(upstream, audit_path, tmp_path):
    pins_path = write_pins(tmp_path, {})
    al = reloadable(upstream, audit_path, tmp_path, pins_path=pins_path)
    data = policy_data()
    del data["tools"]["delete_service"]
    write_policy(tmp_path / "policy.yaml", data)
    write_pins(tmp_path, {"get_service": ZEROS})  # no real tool hashes to this
    assert al.reload().ok and al.pins == {"get_service": ZEROS}
    async with proxy(al) as c:
        res = (await rpc(c, "tools/list")).json()["result"]
    names = {t["name"] for t in res["tools"]}
    assert "get_service" not in names and "delete_service" not in names and res["_meta"][META + "pin_mismatch"] == 1


async def test_pins_given_directly_survive_a_reload_without_a_pins_file(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path, pins={"get_service": ZEROS})
    assert al.reload().ok and al.pins == {"get_service": ZEROS}


@pytest.mark.parametrize("env, expect", [("dev", "dev"), (None, "prod")])  # --env dev over the file; the file's own prod
async def test_the_environment_stays_the_one_the_process_runs_in(upstream, audit_path, tmp_path, env, expect):
    al = reloadable(upstream, audit_path, tmp_path, env=env)
    async with proxy(al) as c:
        issued = await call(c, "delete_service", {"name": "api"})  # the token is bound to the environment of its day
        write_policy(tmp_path / "policy.yaml", {**policy_data(), "environment": "staging"})
        assert al.reload().ok and al.engine.policy.environment == expect
        retry = await call(c, "delete_service", {"name": "api"}, extra=accept(issued["requestState"]))
        assert retry["_meta"][META + "rule_id"] == "tier.L2.confirmed"  # still bound, not mrtr.mismatch: a reload voids no confirmation


async def test_an_oob_confirmation_stays_pending_across_a_reload(upstream, audit_path, tmp_path):
    hook = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    al = reloadable(upstream, audit_path, tmp_path, webhook="https://hooks.example/x", public_url="https://a.example",
                    notify_http=hook)
    async with proxy(al) as c:
        issued = await call(c, "delete_service", {"name": "api"})
        assert al.reload().ok
        retry = await call(c, "delete_service", {"name": "api"}, extra={"requestState": issued["requestState"]})
        assert retry["_meta"][META + "status"] == "pending"  # still bound, not mrtr.mismatch

# ---------------------------------------------------------------- what carries over

async def test_the_store_carries_over_usage_windows_and_pending_confirmations(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path, env="dev")
    store = al.engine.store
    async with proxy(al) as c:
        # set_replicas is L3 in dev with 5 objects per principal per window
        assert not (await call(c, "set_replicas", {"names": ["a", "b", "c"], "replicas": 1}))["isError"]
        issued = await call(c, "delete_service", {"name": "api"})  # L2: a confirmation is pending
        assert issued["resultType"] == "input_required"
        assert al.reload().ok and al.engine.store is store
        res = await call(c, "set_replicas", {"names": ["a", "b", "c"], "replicas": 1})
        assert res["_meta"][META + "rule_id"] == "blast_radius.per_principal"  # 3 + 3 > 5: the window survived
        done = await call(c, "delete_service", {"name": "api"}, extra=accept(issued["requestState"]))
        assert done["_meta"][META + "rule_id"] == "tier.L2.confirmed" and not done["isError"]


async def test_a_reload_leaves_the_catalog_cache_alone(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    al._catalog = {("v", "alice", ()): (float("inf"), {})}
    assert al.reload().ok
    assert al._catalog == {("v", "alice", ()): (float("inf"), {})}


# ---------------------------------------------------------------- a call in flight keeps its policy

async def test_a_call_in_flight_finishes_under_the_old_policy(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    entered, release = hold_first_upstream_request(al)  # the catalog fetch that precedes the L2 decision
    async with proxy(al) as c:
        running = asyncio.create_task(call(c, "delete_service", {"name": "api"}))
        await entered.wait()
        data = policy_data()
        del data["tools"]["delete_service"]
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        res = await running
        assert res["resultType"] == "input_required" and res["_meta"][META + "rule_id"] == "tier.L2.confirm"  # the old policy's answer
        after = await call(c, "delete_service", {"name": "api"})
        assert after["isError"] and after["_meta"][META + "rule_id"] == "allowlist.deny"


async def test_the_prompt_without_preview_of_a_call_in_flight_is_the_old_one(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    entered, release = hold_first_upstream_request(al)  # the catalog fetch
    async with proxy(al) as c:
        running = asyncio.create_task(call(c, "restart_service", {"name": "api"}))  # L2 without dry_run: no preview
        await entered.wait()
        data = policy_data()
        del data["tools"]["restart_service"]  # the live policy no longer has a rule to build the prompt from
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        res = await running
        assert res["resultType"] == "input_required" and res["_meta"][META + "rule_id"] == "tier.L2.confirm"
        assert "restart a service" in res["inputRequests"][CONFIRM_KEY]["params"]["message"]  # the old rule's description
        after = await call(c, "restart_service", {"name": "api"})
        assert after["isError"] and after["_meta"][META + "rule_id"] == "allowlist.deny"


async def test_the_tier_of_a_call_in_flight_is_the_old_one(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    entered, release = asyncio.Event(), asyncio.Event()
    is_approved, held = al.engine.store.is_approved, []

    async def slow_is_approved(key):  # the store round trip inside verify_confirmation, before the tier is read
        if not held:
            held.append(True)
            entered.set()
            await release.wait()
        return await is_approved(key)

    al.engine.store.is_approved = slow_is_approved
    async with proxy(al) as c:
        issued = await call(c, "delete_service", {"name": "api"})
        claims = al.verify_token(issued["requestState"])
        await al.engine.store.approve(claims["k"], claims["exp"])  # approved out of band: the retry carries no answer
        running = asyncio.create_task(call(c, "delete_service", {"name": "api"}, extra={"requestState": issued["requestState"]}))
        await entered.wait()
        data = policy_data()
        data["tools"]["delete_service"]["tiers"]["prod"] = "L3"
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        res = await running
        assert res["_meta"][META + "rule_id"] == "tier.L2.confirmed" and res["_meta"][META + "dry_run"] is False
        assert upstream.CALLS[-1]["args"]["dry_run"] is False  # L2 fetched the catalog; L3 would have forwarded no dry_run
        assert (await call(c, "delete_service", {"name": "api"}))["_meta"][META + "rule_id"] == "tier.L3.auto"


async def test_the_audit_tier_of_a_declined_call_in_flight_is_the_old_one(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    entered, release = asyncio.Event(), asyncio.Event()
    consume_once, held = al.engine.store.consume_once, []

    async def slow_consume_once(*a):  # burning the declined key, before the tier is read for the audit record
        if not held:
            held.append(True)
            entered.set()
            await release.wait()
        return await consume_once(*a)

    al.engine.store.consume_once = slow_consume_once
    async with proxy(al) as c:
        issued = await call(c, "delete_service", {"name": "api"})
        declined = {"requestState": issued["requestState"], "inputResponses": {CONFIRM_KEY: {"action": "decline"}}}
        running = asyncio.create_task(call(c, "delete_service", {"name": "api"}, extra=declined))
        await entered.wait()
        data = policy_data()
        data["tools"]["delete_service"]["tiers"]["prod"] = "L3"
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        assert (await running)["_meta"][META + "rule_id"] == "mrtr.declined"
    rows = [r for r in audit_rows(audit_path) if r["rule_id"] == "mrtr.declined"]
    assert [r["tier"] for r in rows] == ["L2", "L2"]  # intent and outcome: the tier of the policy the call started under


async def test_the_output_cap_of_a_call_in_flight_is_the_old_one(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    entered, release = hold_first_upstream_request(al)
    async with proxy(al) as c:
        running = asyncio.create_task(call(c, "get_service", {"name": "big"}))
        await entered.wait()
        data = policy_data()
        data["tools"]["get_service"]["output"] = {"max_chars": 300}
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        assert (await running)["_meta"][META + "output"]["max_chars"] == 5000
        assert (await call(c, "get_service", {"name": "big"}))["_meta"][META + "output"]["max_chars"] == 300


async def test_the_injection_scan_of_a_call_in_flight_knows_the_old_allowlist(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    entered, release = hold_first_upstream_request(al)

    def mentions(res: dict) -> set[str]:
        return {f["rule"] for f in res["_meta"][META + "suspicious"]}

    async with proxy(al) as c:
        running = asyncio.create_task(call(c, "get_service", {"name": "evil"}))  # the result names delete_service
        await entered.wait()
        data = policy_data()
        del data["tools"]["delete_service"], data["tools"]["set_replicas"]
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        assert "tool_mention" in mentions(await running)
        assert "tool_mention" not in mentions(await call(c, "get_service", {"name": "evil"}))


async def test_the_blast_radius_of_a_call_in_flight_is_the_old_one(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path, env="dev")
    entered, release = asyncio.Event(), asyncio.Event()
    usage_sum, held = al.engine.store.usage_sum, []

    async def slow_usage_sum(*a):  # the window check of the first call, between the decision and the charge
        if not held:
            held.append(True)
            entered.set()
            await release.wait()
        return await usage_sum(*a)

    al.engine.store.usage_sum = slow_usage_sum
    async with proxy(al) as c:
        running = asyncio.create_task(call(c, "set_replicas", {"names": ["a", "b", "c"], "replicas": 1}))
        await entered.wait()
        data = policy_data()
        data["tools"]["set_replicas"]["blast_radius"] = {"max_per_call": 3, "max_per_principal": 1, "window_s": 3600}
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        assert (await running)["_meta"][META + "rule_id"] == "tier.L3.auto"  # 3 objects were within the old limit of 5
        res = await call(c, "set_replicas", {"names": ["a"], "replicas": 1})
        assert res["_meta"][META + "rule_id"] == "blast_radius.per_principal"  # the new limit of 1 counts the 3 already charged


async def test_a_tools_list_in_flight_keeps_its_allowlist_and_pins(upstream, audit_path, tmp_path):
    pins_path = write_pins(tmp_path, {})
    al = reloadable(upstream, audit_path, tmp_path, pins_path=pins_path)
    entered, release = hold_first_upstream_request(al)
    async with proxy(al) as c:
        running = asyncio.create_task(rpc(c, "tools/list"))
        await entered.wait()
        write_pins(tmp_path, {"get_service": ZEROS})
        data = policy_data()
        del data["tools"]["restart_service"]
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        res = (await running).json()["result"]
        names = {t["name"] for t in res["tools"]}
        assert {"get_service", "restart_service"} <= names and META + "pin_mismatch" not in res["_meta"]
        later = {t["name"] for t in (await rpc(c, "tools/list")).json()["result"]["tools"]}
        assert not {"get_service", "restart_service"} & later


# The body and the identity are awaited before dispatch: a swap in that window must not reach the request either.

async def test_a_call_whose_body_is_still_arriving_keeps_the_old_policy(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    async with proxy(al) as c:
        running, parked, release = post_in_two_chunks(c, "tools/call", {"name": "get_service", "arguments": {"name": "api"}})
        await parked.wait()
        data = policy_data()
        del data["tools"]["get_service"]
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        r = await running
        assert r.status_code == 200 and r.json()["result"]["_meta"][META + "rule_id"] == "tier.L0.read"
        after = await call(c, "get_service", {"name": "api"})
        assert after["isError"] and after["_meta"][META + "rule_id"] == "allowlist.deny"


async def test_the_tier_of_a_call_whose_identity_is_still_resolving_is_the_old_one(upstream, audit_path, tmp_path):
    al = reloadable(upstream, audit_path, tmp_path)
    entered, release = asyncio.Event(), asyncio.Event()
    resolve, held = al._resolve, []

    async def slow_resolve(headers):  # identity resolution, after the engine is picked and before the tier is read
        if not held:
            held.append(True)
            entered.set()
            await release.wait()
        return await resolve(headers)

    al._resolve = slow_resolve
    async with proxy(al) as c:
        running = asyncio.create_task(call(c, "delete_service", {"name": "api"}))
        await entered.wait()
        data = policy_data()
        data["tools"]["delete_service"]["tiers"]["prod"] = "L3"
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        res = await running
        assert res["resultType"] == "input_required" and res["_meta"][META + "rule_id"] == "tier.L2.confirm"
        assert META + "dry_run_preview" in res["_meta"]  # L2 fetched the catalog and ran the dry run; L3 would have done neither
        assert upstream.CALLS[-1]["tool"] == "delete_service" and upstream.CALLS[-1]["args"]["dry_run"] is True
        assert (await call(c, "delete_service", {"name": "api"}))["_meta"][META + "rule_id"] == "tier.L3.auto"


async def test_a_tools_list_whose_body_is_still_arriving_keeps_its_allowlist_and_pins(upstream, audit_path, tmp_path):
    pins_path = write_pins(tmp_path, {})
    al = reloadable(upstream, audit_path, tmp_path, pins_path=pins_path)
    async with proxy(al) as c:
        running, parked, release = post_in_two_chunks(c, "tools/list", {})
        await parked.wait()
        write_pins(tmp_path, {"get_service": ZEROS})
        data = policy_data()
        del data["tools"]["restart_service"]
        write_policy(tmp_path / "policy.yaml", data)
        assert al.reload().ok
        release.set()
        res = (await running).json()["result"]
        names = {t["name"] for t in res["tools"]}
        assert {"get_service", "restart_service"} <= names and META + "pin_mismatch" not in res["_meta"]
        later = {t["name"] for t in (await rpc(c, "tools/list")).json()["result"]["tools"]}
        assert not {"get_service", "restart_service"} & later


# ---------------------------------------------------------------- no source

async def test_an_airlock_without_a_reload_source_has_nothing_to_reload(airlock, capsys):
    engine = airlock.engine
    r = airlock.reload()
    assert r.ok is False and "nothing to reload" in r.error and (r.tools_before, r.tools_after) == (6, 6)
    assert airlock.engine is engine and capsys.readouterr().err == ""


def test_build_hands_the_paths_to_the_airlock(monkeypatch, tmp_path):
    for var in ("AIRLOCK_APPROVAL_WEBHOOK", "AIRLOCK_APPROVAL_MODE", "AIRLOCK_STORE_DSN", "AIRLOCK_AUDIT_DSN"):
        monkeypatch.delenv(var, raising=False)
    policy, pins = write_policy(tmp_path / "policy.yaml", policy_data()), write_pins(tmp_path, {"get_service": ZEROS})
    al = build(policy, "http://localhost:9001/mcp", str(tmp_path / "audit.jsonl"), "prod", pins_path=pins, pins={})
    assert al.reload_source == ReloadSource(policy, pins)
    assert al.reload().ok and al.pins == {"get_service": ZEROS}
    assert build(policy, "http://localhost:9001/mcp", str(tmp_path / "audit.jsonl"), "prod").reload_source == ReloadSource(policy, None)


# ---------------------------------------------------------------- the signal

needs_sighup = pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="no SIGHUP on this platform")


async def until(cond) -> None:
    for _ in range(200):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("timed out")


@needs_sighup
async def test_sighup_reloads_while_the_app_runs_and_the_handler_goes_with_the_app(upstream, audit_path, tmp_path, caplog):
    al = reloadable(upstream, audit_path, tmp_path)
    before = signal.getsignal(signal.SIGHUP)  # SIG_DFL, or SIG_IGN under nohup: either way not a handler
    async with al.app.router.lifespan_context(al.app):
        installed = signal.getsignal(signal.SIGHUP)
        assert installed is not before and callable(installed)  # asyncio's own, so the next kill does not end the process
        data = policy_data()
        del data["tools"]["get_service"]
        write_policy(tmp_path / "policy.yaml", data)
        os.kill(os.getpid(), signal.SIGHUP)
        await until(lambda: len(al.engine.policy.tools) == 5)
        write_policy(tmp_path / "policy.yaml", "tools: [unclosed")  # a bad file on a signal is reported, not fatal
        engine = al.engine
        os.kill(os.getpid(), signal.SIGHUP)
        await until(lambda: "policy reload failed, keeping the current policy" in caplog.text)  # the handler did run
        assert al.engine is engine
        write_policy(tmp_path / "policy.yaml", policy_data())
        os.kill(os.getpid(), signal.SIGHUP)
        await until(lambda: len(al.engine.policy.tools) == 6)
    assert signal.getsignal(signal.SIGHUP) == signal.SIG_DFL


@needs_sighup
@pytest.mark.parametrize("raised", [NotImplementedError, RuntimeError])  # no signal support; not the main thread
async def test_a_loop_without_signal_support_still_starts(upstream, audit_path, tmp_path, monkeypatch, raised):
    al = reloadable(upstream, audit_path, tmp_path)
    loop = asyncio.get_running_loop()

    def unsupported(*a):
        raise raised

    def never(*a):
        raise AssertionError("nothing was registered, nothing to remove")

    monkeypatch.setattr(loop, "add_signal_handler", unsupported)
    monkeypatch.setattr(loop, "remove_signal_handler", never)
    async with al.app.router.lifespan_context(al.app):
        pass


async def test_no_signal_handler_without_sighup(upstream, audit_path, tmp_path, monkeypatch):
    from mcp_airlock import app as app_module
    al = reloadable(upstream, audit_path, tmp_path)
    loop = asyncio.get_running_loop()
    monkeypatch.delattr(app_module.signal, "SIGHUP", raising=False)  # as on Windows
    monkeypatch.setattr(loop, "add_signal_handler", lambda *a: pytest.fail("registered a handler"))
    async with al.app.router.lifespan_context(al.app):
        pass
