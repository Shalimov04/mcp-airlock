"""Argument conditions (`where`): matchers, absent and list values, env scoping, and where the check sits in evaluate."""

from __future__ import annotations

import copy
import json

import pytest
import yaml
from pydantic import ValidationError

from mcp_airlock import Policy
from mcp_airlock.app import CONFIRM_KEY, META
from mcp_airlock.policy import Engine, WhereRule

from .conftest import ROOT, audit_rows, call


def policy(where: list[dict], env: str = "prod", tier: str = "L3") -> Policy:
    return Policy.model_validate({"environment": env, "tools": {
        "t": {"tiers": {"dev": tier, "staging": tier, "prod": tier}, "where": where}}})


async def decide(pol: Policy, args: dict, **kw):
    return await Engine(pol).evaluate("t", args, "alice", confirmed=False, **kw)


async def violates(where: list[dict], args: dict, **kw) -> bool:
    d = await decide(policy(where, **kw), args)
    assert d.verdict == "allow" or d.rule_id == "args.violation", d
    return d.rule_id == "args.violation"


# ---------------------------------------------------------------- matchers

@pytest.mark.parametrize("matcher, good, bad", [
    ({"equals": "staging"}, "staging", "prod"),
    ({"equals": 3}, 3, 4),
    ({"in": ["staging", "dev"]}, "dev", "prod"),
    ({"in": ["123", "456"]}, "123", "789"),  # a numeric-looking string is a plain string for an allow list
    ({"not_in": ["kube-system"]}, "default", "kube-system"),
    ({"regex": "tmp-.*"}, "tmp-1", "keep-1"),
    ({"regex": r"\d+"}, "42", "x"),
])
async def test_matcher_pass_and_fail(matcher, good, bad):
    where = [{"arg": "a", **matcher}]
    assert not await violates(where, json.loads(json.dumps({"a": good})))  # a fresh object, as a request body is
    assert await violates(where, {"a": bad})


async def test_regex_is_a_full_match():
    where = [{"arg": "a", "regex": "tmp-.*"}]
    assert await violates(where, {"a": "x-tmp-1"})  # not a search
    assert await violates(where, {"a": "tmp"})
    assert await violates([{"arg": "a", "regex": "tmp"}], {"a": "tmp-1"})  # not a prefix match


@pytest.mark.parametrize("value", [5, True, 1.5, [5], {"x": 1}])
async def test_regex_fails_on_anything_but_a_string(value):
    assert await violates([{"arg": "a", "regex": ".*"}], {"a": value})


async def test_regex_does_not_admit_a_string_the_upstream_would_decode():
    assert await violates([{"arg": "a", "regex": "[a-z]+"}], {"a": "null"})  # four letters, but None upstream
    assert await violates([{"arg": "a", "regex": ".*"}], {"a": '["a"]'})


async def test_bool_is_not_an_int():
    assert await violates([{"arg": "a", "equals": 1}], {"a": True})
    assert await violates([{"arg": "a", "equals": True}], {"a": 1})
    assert not await violates([{"arg": "a", "equals": True}], {"a": True})
    assert await violates([{"arg": "a", "in": [1, 0]}], {"a": False})
    assert await violates([{"arg": "a", "not_in": [1]}], {"a": True})  # True is not 1, but the upstream reads it as 1


# ---------------------------------------------------------------- absent and shaped values

async def test_absent_argument_fails_unless_optional():
    for kind, value in (("equals", "x"), ("in", ["x"]), ("not_in", ["x"]), ("regex", "x")):  # not_in must not pass by default
        assert await violates([{"arg": "a", kind: value}], {})
        assert not await violates([{"arg": "a", "optional": True, kind: value}], {})
        d = await decide(policy([{"arg": "a", kind: value}]), {})
        assert "'a'" in d.message and f"the {kind} condition" in d.message  # names the matcher, not only the argument


async def test_null_is_a_value_that_only_equals_null_matches():
    assert not await violates([{"arg": "a", "equals": None}], {"a": None})
    assert await violates([{"arg": "a", "equals": None}], {"a": "x"})
    assert await violates([{"arg": "a", "equals": None}], {})  # absent is not null
    # a null argument is often the upstream's "use the default", so it must not slip past the other matchers, optional or not
    for matcher in ({"equals": "x"}, {"in": ["x"]}, {"not_in": ["kube-system"]}, {"regex": ".*"}):
        assert await violates([{"arg": "a", **matcher}], {"a": None})
        assert await violates([{"arg": "a", "optional": True, **matcher}], {"a": None})
    d = await decide(policy([{"arg": "a", "not_in": ["kube-system"]}]), {"a": None})
    assert "forbidden" in d.message and "missing" not in d.message  # present, so not the absent message


async def test_optional_does_not_excuse_a_present_bad_value():
    assert await violates([{"arg": "a", "in": ["x"], "optional": True}], {"a": "y"})


async def test_list_value_must_match_for_every_element():
    where = [{"arg": "a", "in": ["x", "y"]}]
    assert not await violates(where, {"a": ["x", "y", "x"]})
    assert await violates(where, {"a": ["x", "z"]})  # one bad element
    assert not await violates(where, {"a": []})  # nothing to object to
    assert await violates([{"arg": "a", "not_in": ["x"]}], {"a": ["y", "x"]})
    assert await violates(where, {"a": ("x", ["x"])})  # a nested list is not a scalar
    assert not await violates(where, {"a": ("x", "y")})  # a tuple counts as a list


@pytest.mark.parametrize("matcher", [{"equals": "x"}, {"in": ["x"]}, {"not_in": [1]}, {"regex": ".*"}])
async def test_dict_value_fails(matcher):
    assert await violates([{"arg": "a", **matcher}], {"a": {"k": "v"}})  # fail closed, even for not_in


# ---------------------------------------------------------------- not_in against the upstream's coercions

@pytest.mark.parametrize("listed, value", [
    ([0], "0"), ([0], "0.0"), ([0], " 0 "), ([0], False),  # pydantic reads each of these as 0 for an int argument
    ([True], "yes"), ([True], 1),  # and these as True for a bool argument
])
async def test_not_in_fails_a_value_the_upstream_may_read_as_a_forbidden_one(listed, value):
    assert await violates([{"arg": "a", "not_in": listed}], {"a": value})


async def test_not_in_list_elements_are_coerced_but_not_json_decoded():
    assert await violates([{"arg": "a", "not_in": [0]}], {"a": [3, "0"]})  # pydantic coerces elements too
    assert await violates([{"arg": "a", "not_in": [True]}], {"a": [False, 1]})
    assert not await violates([{"arg": "a", "not_in": ["prod-db"]}], {"a": ["api", "123", '["prod-db"]']})  # the SDK does not descend


async def test_not_in_still_passes_a_plain_value_of_a_listed_kind():
    assert not await violates([{"arg": "a", "not_in": ["kube-system"]}], {"a": "default"})
    assert not await violates([{"arg": "a", "not_in": [0]}], {"a": 3})
    assert not await violates([{"arg": "a", "not_in": [0]}], {"a": 1.5})  # int and float are one kind
    assert not await violates([{"arg": "a", "not_in": [0, "kube-system"]}], {"a": "default"})


# ---------------------------------------------------------------- strings the upstream json-decodes first

@pytest.mark.parametrize("value", ["null", '["a"]', '{"x": 1}'])
@pytest.mark.parametrize("matcher", [{"equals": "null"}, {"in": ['["a"]', '{"x": 1}']}, {"not_in": ["prod-db"]}, {"regex": "[^/]+"}])
async def test_a_string_that_decodes_to_null_list_or_dict_fails_every_matcher(matcher, value):
    # the SDK substitutes the decoded value for a non-str argument, so the tool would run with one the policy never saw
    assert await violates([{"arg": "a", **matcher}], {"a": value})


@pytest.mark.parametrize("value", ["123", "1.5", "true", "false", '"quoted"'])
async def test_a_string_that_decodes_to_a_number_bool_or_string_is_left_alone(value):
    # the SDK decodes these too but keeps the string: only a null, list or dict is substituted
    assert not await violates([{"arg": "a", "not_in": ["prod-db"]}], {"a": value})
    assert not await violates([{"arg": "a", "regex": ".+"}], {"a": value})
    assert not await violates([{"arg": "a", "equals": value}], {"a": value})


async def test_a_string_nested_too_deep_to_decode_is_a_decision_not_an_exception():
    # json.loads raises RecursionError, not ValueError, on this one: the helper must leave the string alone, not blow up
    d = await decide(policy([{"arg": "a", "in": ["x"]}]), {"a": "[" * 100000})
    assert (d.verdict, d.rule_id) == ("deny", "args.violation") and "allowed" in d.message


# ---------------------------------------------------------------- env and ordering

async def test_env_scopes_a_rule_both_ways():
    where = [{"arg": "ns", "not_in": ["kube-system"], "env": ["staging", "prod"]}]
    args = {"ns": "kube-system"}
    assert await violates(where, args, env="prod")
    assert await violates(where, args, env="staging")
    assert not await violates(where, args, env="dev")  # rule does not apply there
    assert await violates([{"arg": "ns", "in": ["a"]}], {"ns": "b"}, env="dev")  # no env means every environment


async def test_first_failing_rule_decides_the_message():
    where = [{"arg": "ns", "in": ["a"]}, {"arg": "name", "regex": "tmp-.*"}, {"arg": "ns", "not_in": ["b"]}]
    d = await decide(policy(where), {"ns": "b", "name": "keep"})
    assert d.rule_id == "args.violation" and "'ns'" in d.message and "allowed" in d.message
    d = await decide(policy(where), {"ns": "a", "name": "keep"})
    assert "'name'" in d.message and "pattern" in d.message


async def test_message_names_argument_and_matcher_never_the_value():
    for matcher, word in (({"equals": "x"}, "equal"), ({"in": ["x"]}, "allowed"), ({"not_in": ["SECRET-value"]}, "forbidden"),
                          ({"regex": "x"}, "pattern")):
        d = await decide(policy([{"arg": "ns", **matcher}]), {"ns": "SECRET-value"})
        assert d.rule_id == "args.violation" and "'ns'" in d.message and word in d.message
        assert "SECRET-value" not in d.message


# ---------------------------------------------------------------- placement in evaluate

@pytest.mark.parametrize("tier", ["L0", "L1", "L2", "L3"])
@pytest.mark.parametrize("args", [{"a": "bad"}, {"a": "bad", "dry_run": True}])
async def test_checked_before_every_tier_including_dry_runs(tier, args):
    d = await decide(policy([{"arg": "a", "in": ["ok"]}], tier=tier), args)
    assert (d.verdict, d.rule_id, d.tier) == ("deny", "args.violation", tier)  # never "confirm"


async def test_checked_before_the_dry_run_support_and_blast_radius_checks():
    pol = policy([{"arg": "a", "in": ["ok"]}], tier="L1")
    assert (await decide(pol, {"a": "bad"}, dry_run_supported=False)).rule_id == "args.violation"
    pol.tools["t"].count_arg = "a"
    assert (await decide(pol, {"a": ["bad"] * 100})).rule_id == "args.violation"  # not blast_radius.per_call


async def test_allowlist_and_unassigned_tier_come_first():
    pol = policy([{"arg": "a", "in": ["ok"]}], env="qa")
    assert (await decide(pol, {"a": "bad"})).rule_id == "tier.unassigned"
    assert (await Engine(pol).evaluate("other", {"a": "bad"}, "alice", confirmed=False)).rule_id == "allowlist.deny"


async def test_passing_rules_leave_the_decision_unchanged():
    d = await decide(policy([{"arg": "a", "in": ["ok"]}], tier="L2"), {"a": "ok"})
    assert (d.verdict, d.rule_id) == ("confirm", "tier.L2.confirm")


# ---------------------------------------------------------------- model

def test_model_defaults_and_alias():
    w = WhereRule.model_validate({"arg": "a", "in": ["x"]})
    assert w.env is None and w.optional is False and w.in_ == ["x"]


def test_equals_null_is_a_real_matcher():
    assert WhereRule.model_validate({"arg": "a", "equals": None}).kind() == "equals"
    with pytest.raises(ValidationError):
        WhereRule.model_validate({"arg": "a", "equals": None, "in": ["x"]})


@pytest.mark.parametrize("bad", [
    {"arg": "a"},  # no matcher
    {"arg": "a", "equals": "x", "regex": "x"},  # two matchers
    {"arg": "a", "in": ["x"], "not_in": ["y"]},
    {"arg": "a", "regex": "("},  # invalid pattern
    {"arg": "a", "contains": "x"},  # unknown matcher
    {"arg": "a", "in": ["x"], "optinal": True},  # unknown key next to a valid matcher
    {"arg": "a", "in_": ["x"]},  # the YAML key is `in`
    {"equals": "x"},  # no arg
    {"arg": "a", "equals": "x", "env": "prod"},  # env is a list
])
def test_invalid_rules_are_rejected(bad):
    with pytest.raises(ValidationError):
        WhereRule.model_validate(bad)


@pytest.mark.parametrize("bad, why", [
    ({"arg": "a", "in": []}, r"\bin must not be empty"),  # would deny every value
    ({"arg": "a", "not_in": []}, "not_in must not be empty"),  # would deny every value, with a false message
    ({"arg": "a", "in": ["x"], "env": []}, "env must not be empty"),  # would apply nowhere
    ({"arg": "a", "equals": ["x"]}, "must be scalars"),  # a list or dict element can never match
    ({"arg": "a", "equals": {"k": "v"}}, "must be scalars"),
    ({"arg": "a", "in": ["x", ["y"]]}, "must be scalars"),
    ({"arg": "a", "not_in": [{"k": "v"}]}, "must be scalars"),
])
def test_empty_and_unusable_lists_are_rejected(bad, why):
    with pytest.raises(ValidationError, match=why):
        WhereRule.model_validate(bad)


def test_a_null_element_stays_allowed():
    for ok in ({"arg": "a", "equals": None}, {"arg": "a", "in": [None, "x"]}, {"arg": "a", "not_in": [None]}):
        WhereRule.model_validate(ok)


def test_a_copied_policy_evaluates_like_the_original():
    pol = policy([{"arg": "a", "in": ["x"]}, {"arg": "b", "equals": None}])
    for c in (copy.deepcopy(pol), pol.model_copy(deep=True)):
        assert c.args_violation("t", {"a": "x", "b": None}) is None
        assert c.args_violation("t", {"a": "y", "b": None}) == pol.args_violation("t", {"a": "y", "b": None})


# ---------------------------------------------------------------- through the proxy

def strict(where: list[dict], tool: str = "delete_service", env: str = "prod") -> Policy:
    data = yaml.safe_load((ROOT / "policy.example.yaml").read_text())
    data["environment"] = env
    data["tools"][tool]["where"] = where
    return Policy.model_validate(data)


def accept(token: str) -> dict:
    return {"requestState": token, "inputResponses": {CONFIRM_KEY: {"action": "accept", "content": {"confirm": True}}}}


async def test_violation_never_reaches_upstream_or_prompts(client, airlock, upstream, audit_path):
    airlock.engine.policy = strict([{"arg": "name", "in": ["staging-api"]}])
    res = await call(client, "delete_service", {"name": "secret-prod-db"})
    assert res["isError"] is True and res["_meta"][META + "rule_id"] == "args.violation"
    assert res["resultType"] != "input_required" and "inputRequests" not in res
    assert "'name'" in res["content"][0]["text"] and "secret-prod-db" not in res["content"][0]["text"]
    assert [x for x in upstream.CALLS if x["tool"] == "delete_service"] == []  # not even the dry-run preview
    rows = [r for r in audit_rows(audit_path) if r["rule_id"] == "args.violation"]
    assert rows and all(r["verdict"] == "deny" and "secret-prod-db" not in (r.get("detail") or "") for r in rows)


async def test_not_in_type_confusion_never_reaches_upstream(client, airlock, upstream):
    # set_replicas is L3 in dev: without the check the upstream would read "0" as 0 and the string as a list, and execute
    airlock.engine.policy = strict([{"arg": "replicas", "not_in": [0]}], tool="set_replicas", env="dev")
    res = await call(client, "set_replicas", {"names": ["api"], "replicas": "0"})
    assert res["isError"] is True and res["_meta"][META + "rule_id"] == "args.violation"
    airlock.engine.policy = strict([{"arg": "names", "not_in": ["prod-db"]}], tool="set_replicas", env="dev")
    res = await call(client, "set_replicas", {"names": '["prod-db"]', "replicas": 1})
    assert res["isError"] is True and res["_meta"][META + "rule_id"] == "args.violation"
    assert [x for x in upstream.CALLS if x["tool"] == "set_replicas"] == []


async def test_confirmed_call_is_checked_again(client, airlock, upstream):
    lenient = airlock.engine.policy
    issued = await call(client, "delete_service", {"name": "api"})
    assert issued["resultType"] == "input_required"
    seen = len(upstream.CALLS)
    # the policy changed while the human was deciding
    airlock.engine.policy = strict([{"arg": "name", "in": ["staging-api"]}])
    res = await call(client, "delete_service", {"name": "api"}, extra=accept(issued["requestState"]))
    assert res["isError"] is True and res["_meta"][META + "rule_id"] == "args.violation"
    assert len(upstream.CALLS) == seen  # the confirmed call never executed
    # the check ran before the confirmation key was burned: the same approval still works once the policy allows it
    airlock.engine.policy = lenient
    res = await call(client, "delete_service", {"name": "api"}, extra=accept(issued["requestState"]))
    assert res["isError"] is False and upstream.CALLS[-1]["args"] == {"name": "api", "dry_run": False}
