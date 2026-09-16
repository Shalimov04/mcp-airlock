from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from mcp_airlock import policy_cli

from . import fake_upstream

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "policy.example.yaml"

BASE = "version: 1\nenvironment: prod\ntools:\n"


def write(tmp_path, body: str) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(BASE + body)
    return p


def codes(findings, level=None):
    return [c for lvl, c, _ in findings if level in (None, lvl)]


@pytest.fixture
async def upstream():  # copied from conftest: lifespan entered and exited in one task
    fake_upstream.CALLS.clear()
    app = fake_upstream.make_app()
    started, stop = asyncio.Event(), asyncio.Event()

    async def run():
        async with app.router.lifespan_context(app):
            started.set()
            await stop.wait()

    task = asyncio.create_task(run())
    await started.wait()
    yield SimpleNamespace(app=app)
    stop.set()
    await task


def http_for(upstream) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream.app), base_url="http://localhost:9001")


# ---------------------------------------------------------------- lint

def test_lint_example_policy_has_no_errors():
    f = policy_cli.lint(EXAMPLE)
    assert codes(f, "ERROR") == []


def test_lint_invalid_policy(tmp_path):
    f = policy_cli.lint(write(tmp_path, "  x:\n    tiers: {prod: L9}\n"))
    assert codes(f) == ["invalid"]
    assert f[0][0] == "ERROR" and "L9" in f[0][2]


def test_lint_unreadable_yaml(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("tools: [")
    assert codes(policy_cli.lint(p), "ERROR") == ["invalid"]


def test_lint_no_tiers(tmp_path):
    f = policy_cli.lint(write(tmp_path, "  x:\n    tiers: {}\n"))
    assert ("ERROR", "no_tiers") in [(l, c) for l, c, _ in f]
    assert any("x" in m for _, c, m in f if c == "no_tiers")


def test_lint_no_description_only_for_write_tiers(tmp_path):
    f = policy_cli.lint(write(tmp_path, "  r:\n    tiers: {prod: L0}\n  w:\n    tiers: {dev: L1}\n"))
    assert [(l, c) for l, c, _ in f if c == "no_description"] == [("WARN", "no_description")]
    assert "w" in [m for _, c, m in f if c == "no_description"][0]


def test_lint_blast_radius_default(tmp_path):
    f = policy_cli.lint(write(tmp_path, "  w:\n    description: d\n    tiers: {prod: L3}\n    count_arg: names\n"))
    assert codes(f) == ["blast_radius_default"]
    f = policy_cli.lint(write(tmp_path, "  w:\n    description: d\n    tiers: {prod: L3}\n    count_arg: names\n"
                                        "    blast_radius: {max_per_call: 2}\n"))
    assert codes(f) == []


def test_lint_env_unused(tmp_path):
    p = write(tmp_path, "  r:\n    tiers: {prod: L0}\n")
    assert codes(policy_cli.lint(p)) == []
    f = policy_cli.lint(p, envs=["staging", "prod"])
    assert [(l, c) for l, c, _ in f] == [("WARN", "env_unused")]
    assert "staging" in f[0][2]
    # the policy's own environment counts too
    p2 = write(tmp_path, "  r:\n    tiers: {dev: L0}\n")
    assert codes(policy_cli.lint(p2)) == ["env_unused"]


# ---------------------------------------------------------------- diff

async def test_diff_against_fake_upstream(upstream):
    f = await policy_cli.diff(EXAMPLE, "http://localhost:9001/mcp", env="prod", http=http_for(upstream))
    by = {(c, m.split()[0]): l for l, c, m in f}
    assert by[("not_allowlisted", "rm_rf")] == "WARN"
    assert by[("no_dry_run", "restart_service")] == "WARN"
    assert "missing_upstream" not in codes(f)
    assert codes(f, "ERROR") == []
    assert "denied" in next(m for _, c, m in f if c == "no_dry_run")
    assert codes(f, "INFO") == ["ok"]


async def test_diff_no_dry_run_respects_env(upstream):
    f = await policy_cli.diff(EXAMPLE, "http://localhost:9001/mcp", env="dev", http=http_for(upstream))
    assert "no_dry_run" not in codes(f)  # restart_service is L3 in dev


async def test_diff_missing_upstream(upstream, tmp_path):
    p = write(tmp_path, "  ghost:\n    description: d\n    tiers: {prod: L0}\n")
    f = await policy_cli.diff(p, "http://localhost:9001/mcp", http=http_for(upstream))
    assert ("ERROR", "missing_upstream") in [(l, c) for l, c, _ in f]


async def test_diff_sends_principal_header(upstream):
    seen = {}

    async def hook(request):
        seen.update(request.headers)

    http = http_for(upstream)
    http.event_hooks["request"] = [hook]
    await policy_cli.diff(EXAMPLE, "http://localhost:9001/mcp", principal="bob", http=http)
    assert seen["x-airlock-principal"] == "bob"
    assert seen["mcp-protocol-version"] == "2026-07-28" and seen["mcp-method"] == "tools/list"


# ---------------------------------------------------------------- main

def test_main_lint_exit_codes(tmp_path, capsys):
    assert policy_cli.main(["lint", str(EXAMPLE)]) == 0
    p = write(tmp_path, "  x:\n    tiers: {}\n")
    assert policy_cli.main(["lint", str(p), "--env", "staging"]) == 1
    out = capsys.readouterr().out
    assert "ERROR no_tiers:" in out and "WARN env_unused:" in out


def test_main_diff_exit_code(monkeypatch, capsys):
    async def fake(policy_path, upstream, env=None, principal="airlock-policy", http=None):
        assert (str(policy_path), upstream, env, principal) == (str(EXAMPLE), "http://x/mcp", "dev", "p")
        return [("ERROR", "missing_upstream", "ghost is not in the upstream catalog")]

    monkeypatch.setattr(policy_cli, "diff", fake)
    assert policy_cli.main(["diff", str(EXAMPLE), "--upstream", "http://x/mcp", "--env", "dev", "--principal", "p"]) == 1
    assert "ERROR missing_upstream: ghost" in capsys.readouterr().out


def test_main_diff_requires_upstream():
    with pytest.raises(SystemExit):
        policy_cli.main(["diff", str(EXAMPLE)])


async def test_diff_reads_an_sse_upstream():
    # kubernetes-mcp-server answers every POST as text/event-stream
    def handler(request):
        msg = json.dumps({"jsonrpc": "2.0", "id": 0, "result": {"tools": [{"name": "get_service", "inputSchema": {}}]}})
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=f"event: message\ndata: {msg}\n\n")

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    f = await policy_cli.diff(EXAMPLE, "http://x/mcp", env="prod", http=http)
    assert any(c == "ok" and "1 in catalog" in m for _, c, m in f)


def test_main_diff_non_json_upstream_is_an_error_line_not_a_traceback(monkeypatch, capsys):
    async def fake(*a, **kw):
        raise json.JSONDecodeError("Expecting value", "", 0)

    monkeypatch.setattr(policy_cli, "diff", fake)
    assert policy_cli.main(["diff", str(EXAMPLE), "--upstream", "http://x/mcp"]) == 1
    assert "ERROR upstream" in capsys.readouterr().out
