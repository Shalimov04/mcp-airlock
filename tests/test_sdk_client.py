"""The Python MCP SDK client against the proxy, in process: the evidence behind the row in docs/clients.md."""
from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp_types import ElicitResult

from mcp_airlock.app import CONFIRM_KEY, META, TOKEN_PREFIX

from .conftest import audit_rows


@asynccontextmanager
async def sdk(airlock, answer, sent=None):
    """The SDK client as the agent. answer(params) plays the person; None means no elicitation_callback."""
    sent = [] if sent is None else sent
    prompts: list[str] = []

    async def spy(request: httpx2.Request) -> None:
        try:
            sent.append(json.loads(request.content))
        except ValueError:
            pass

    async def elicit(ctx, params):
        prompts.append(params.message)
        return answer(params)

    http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=airlock.app), base_url="http://localhost:9000",
                              headers={"x-airlock-principal": "alice"}, event_hooks={"request": [spy]})
    async with http, Client(streamable_http_client("http://localhost:9000/mcp", http_client=http),
                            elicitation_callback=elicit if answer else None) as client:
        yield client, prompts, sent


def real_calls(upstream) -> list[bool]:
    """The dry_run flag of every delete_service call the upstream saw."""
    return [c["args"]["dry_run"] for c in upstream.CALLS if c["tool"] == "delete_service"]


def retries(sent) -> list[dict]:
    return [b["params"] for b in sent if b.get("method") == "tools/call" and "requestState" in b["params"]]


async def test_python_sdk_accept_sends_input_responses_and_runs_once(upstream, airlock):
    answer = lambda p: ElicitResult(action="accept", content={"confirm": True})
    async with sdk(airlock, answer) as (client, prompts, sent):
        r = await client.call_tool("delete_service", {"name": "api"})
    assert len(prompts) == 1 and "would delete api" in prompts[0] and "delete_service" in prompts[0]
    [retry] = retries(sent)
    assert retry["requestState"].startswith(TOKEN_PREFIX)
    got = retry["inputResponses"][CONFIRM_KEY]
    assert got["action"] == "accept" and got["content"] == {"confirm": True}
    assert not r.is_error
    assert r.meta[META + "rule_id"] == "tier.L2.confirmed"
    assert "DELETED api" in r.content[0].text
    assert real_calls(upstream) == [True, False]


async def test_python_sdk_decline_stops_the_call(upstream, airlock, audit_path):
    async with sdk(airlock, lambda p: ElicitResult(action="decline")) as (client, prompts, sent):
        r = await client.call_tool("delete_service", {"name": "api"})
    assert len(prompts) == 1
    [retry] = retries(sent)
    assert retry["inputResponses"][CONFIRM_KEY]["action"] == "decline"
    assert r.is_error and r.meta[META + "rule_id"] == "mrtr.declined"
    assert real_calls(upstream) == [True]
    assert any(row.get("rule_id") == "mrtr.declined" for row in audit_rows(audit_path))


@pytest.mark.parametrize("answer", [
    ElicitResult(action="cancel"),
    ElicitResult(action="accept", content={"confirm": False}),
], ids=["cancel", "accept-unchecked"])
async def test_python_sdk_cancel_or_unchecked_counts_as_decline(upstream, airlock, answer):
    async with sdk(airlock, lambda p: answer) as (client, prompts, sent):
        r = await client.call_tool("delete_service", {"name": "api"})
    assert r.is_error and r.meta[META + "rule_id"] == "mrtr.declined"
    assert real_calls(upstream) == [True]


async def test_python_sdk_without_elicitation_callback_never_executes(upstream, airlock):
    sent: list[dict] = []
    err = None
    try:
        async with sdk(airlock, None, sent) as (client, prompts, _):
            await client.call_tool("delete_service", {"name": "api"})
    except BaseException as e:  # the SDK wraps errors in anyio exception groups
        err = e
        while isinstance(err, BaseExceptionGroup) and len(err.exceptions) == 1:
            err = err.exceptions[0]
    assert isinstance(err, MCPError), err
    assert retries(sent) == []
    assert real_calls(upstream) == [True]


async def test_python_sdk_in_oob_mode_gives_up_after_a_few_polls_and_never_executes(upstream, audit_path):
    from mcp.client import InputRequiredRoundsExceededError
    from .test_features import webhook_airlock
    posted: list[str] = []
    al = webhook_airlock(upstream, audit_path, posted)  # a webhook with no mode given means oob
    assert al.approval_mode == "oob"
    answer = lambda p: ElicitResult(action="accept", content={"confirm": True})
    sent: list[dict] = []
    err = None
    started = time.monotonic()
    try:
        async with sdk(al, answer, sent) as (client, prompts, _):
            await client.call_tool("delete_service", {"name": "api"})
    except BaseException as e:  # the SDK wraps errors in anyio exception groups
        err = e
        while isinstance(err, BaseExceptionGroup) and len(err.exceptions) == 1:
            err = err.exceptions[0]
    assert isinstance(err, InputRequiredRoundsExceededError), err
    assert 1 <= time.monotonic() - started < 10  # about two seconds in SDK 2.2.0
    assert len(retries(sent)) > 1  # the SDK kept retrying the same state while the answer stayed pending
    assert real_calls(upstream) == [True]  # the in-band accept approved nothing
