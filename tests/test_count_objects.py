"""Object count for blast radius: a string is counted the way the upstream SDK reads it (see Policy.count_objects)."""

from __future__ import annotations

import sys

import httpx
import pytest

from mcp_airlock import Policy
from mcp_airlock.app import META
from mcp_airlock.policy import Engine

from .conftest import audit_rows, call, make_airlock

# Strings json.loads refuses here but another interpreter may not: the nesting limit depends on the Python version and
# the frame depth (about 950 on 3.11 at the proxy's call site, about 10000 on 3.12), the digit limit is a setting.
DEEP = "[" + "[" * 100_000 + "]" * 100_000 + ",1,2]"
LONG_INT = "[1" + "0" * 5000 + ",1,2]"  # over the default 4300 digits; PYTHONINTMAXSTRDIGITS=0 lifts the limit


@pytest.fixture(autouse=True)
def default_digit_limit():
    # the LONG_INT cases need the default 4300-digit limit; PYTHONINTMAXSTRDIGITS may have lifted it for this interpreter
    limit = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(4300)
    yield
    sys.set_int_max_str_digits(limit)


def policy(count_arg: str | None = "ids", **blast) -> Policy:
    return Policy.model_validate({"environment": "prod", "tools": {
        "t": {"tiers": {"prod": "L3"}, "count_arg": count_arg, "blast_radius": {"max_per_call": 3, "max_per_principal": 5, **blast}}}})


@pytest.mark.parametrize("value,n", [
    ([1, 2, 3, 4, 5, 6], 6),
    ((1, 2), 2),
    ({"a": 1, "b": 2, "c": 3}, 3),
    ("[1,2,3,4,5,6]", 6),
    (' [1, "a", null] ', 3),
    ('{"a": 1, "b": 2}', 2),  # a real dict counts by len, so its JSON form does too
    ("[]", 0),
    ("{}", 0),
    ('["[1,2,3]", "[4]"]', 2),  # only the top level is decoded
    (["[1,2,3]"], 1),
    ("7", 1), ('"abc"', 1), ("null", 1), ("true", 1), ("1.5", 1),
    ("abc", 1), ("[1,2", 1), ("", 1),
    pytest.param(DEEP, None, id="too deep to decode here"),  # unknown, not 1: the upstream may read all of it
    pytest.param(LONG_INT, None, id="integer too long to decode here"),
    pytest.param(" " + LONG_INT, None, id="integer too long, list after whitespace"),
    pytest.param('{"k": 1' + "0" * 5000 + "}", None, id="integer too long, in an object"),
    pytest.param("1" * 5000, 1, id="integer too long, no list around it"),  # a string upstream on any interpreter
    (7, 1), (None, 1), (True, 1),
])
def test_count_objects(value, n):
    assert policy().count_objects("t", {"ids": value}) == n


def test_absent_argument_and_rule_without_count_arg_count_one():
    assert policy().count_objects("t", {}) == 1
    assert policy(count_arg=None).count_objects("t", {"ids": [1, 2, 3, 4, 5, 6]}) == 1
    assert policy().count_objects("unknown", {"ids": [1, 2]}) == 1


async def test_empty_json_list_counts_zero_and_is_not_refused():
    # n=0 passes per_call and adds nothing to the window, exactly like an empty real list
    eng = Engine(policy(max_per_principal=1))
    for value in ([], "[]"):
        d = await eng.evaluate("t", {"ids": value}, "alice", confirmed=False)
        assert d.verdict == "allow" and d.objects == 0, d
        assert (await eng.reserve("alice", "t", d)).verdict == "allow"
    assert await eng.store.usage_sum("alice", "t", 0) == 0


# Engine.evaluate takes every object count (per_call, the window check, Decision.objects that `reserve` charges)
# from count_objects, so the string form needs no handling anywhere else.
async def test_engine_uses_the_decoded_count_everywhere():
    eng = Engine(policy())
    d = await eng.evaluate("t", {"ids": "[1,2,3,4]"}, "alice", confirmed=False)
    assert d.rule_id == "blast_radius.per_call" and d.objects == 4
    d = await eng.evaluate("t", {"ids": "[1,2,3]"}, "alice", confirmed=False)
    assert d.verdict == "allow" and d.objects == 3
    assert (await eng.reserve("alice", "t", d)).verdict == "allow"
    assert await eng.store.usage_sum("alice", "t", 0) == 3  # charged by elements, not 1
    d = await eng.evaluate("t", {"ids": "[1,2,3]"}, "alice", confirmed=False)
    assert d.rule_id == "blast_radius.per_principal"  # 3+3 > 5


@pytest.mark.parametrize("value", [DEEP, LONG_INT], ids=["too deep", "integer too long"])
async def test_a_string_this_interpreter_cannot_decode_is_refused_not_counted_as_one(value):
    # counted as 1 it would pass per_call here and run as a whole list on an upstream with more room
    d = await Engine(policy()).evaluate("t", {"ids": value}, "alice", confirmed=False)
    assert (d.verdict, d.rule_id) == ("deny", "blast_radius.per_call") and "cannot be decoded" in d.message, d


# ---------------------------------------------------------------- through the proxy

@pytest.mark.parametrize("names", ['["a","b","c","d"]', DEEP, LONG_INT], ids=["four names", "too deep", "integer too long"])
async def test_string_list_over_max_per_call_or_undecodable_never_reaches_upstream_or_prompts(client, upstream, audit_path, names):
    # set_replicas is L2 in prod: before the fix the string counted as 1, passed and asked a human to confirm
    res = await call(client, "set_replicas", {"names": names, "replicas": 1})
    assert res["isError"] is True and res["_meta"][META + "rule_id"] == "blast_radius.per_call"
    assert res.get("resultType") != "input_required" and "inputRequests" not in res
    assert [x for x in upstream.CALLS if x["tool"] == "set_replicas"] == []  # not even the dry-run preview
    rows = [r for r in audit_rows(audit_path) if r["rule_id"] == "blast_radius.per_call"]
    assert rows and all(r["verdict"] == "deny" for r in rows)


async def test_string_list_is_counted_by_elements_in_the_window(upstream, audit_path):
    dev = make_airlock(upstream, audit_path, env="dev")  # L3 so calls execute and count
    names = '["a","b","c"]'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=dev.app), base_url="http://localhost:9000") as c:
        res = await call(c, "set_replicas", {"names": names, "replicas": 1})
        assert res["isError"] is False
        res = await call(c, "set_replicas", {"names": names, "replicas": 1})  # 3+3 > max_per_principal 5
        assert res["isError"] is True and res["_meta"][META + "rule_id"] == "blast_radius.per_principal"
    sent = [x["args"] for x in upstream.CALLS if x["tool"] == "set_replicas"]
    assert [a["names"] for a in sent] == [["a", "b", "c"]]  # the SDK decoded the string once; the second never arrived
