"""airlock-policy on bad input: a policy that cannot be loaded, an upstream that is not an MCP server, a policy without
`environment`. One ERROR line through main(), never a traceback."""

from __future__ import annotations

import http.server
import threading

import httpx
import pytest

from mcp_airlock import policy_cli

from .conftest import ROOT

EXAMPLE = ROOT / "policy.example.yaml"
NO_ENV = "version: 1\ntools: {get_service: {tiers: {prod: L0}}}\n"


def codes(findings):
    return [c for _, c, _ in findings]


def one_line(capsys) -> str:
    out = capsys.readouterr().out
    assert out.count("\n") >= 1 and "Traceback" not in out
    return out


# ---------------------------------------------------------------- a policy that cannot be loaded

def test_diff_with_a_missing_policy_is_one_error_line(tmp_path, capsys):
    assert policy_cli.main(["diff", str(tmp_path / "nope.yaml"), "--upstream", "http://127.0.0.1:1/mcp"]) == 1
    out = one_line(capsys)
    assert out.startswith("ERROR invalid: ") and "nope.yaml" in out and out.count("\n") == 1


def test_pin_with_an_unparsable_policy_is_an_error_and_writes_no_pins(tmp_path, capsys):
    (tmp_path / "bad.yaml").write_text("tools: [")
    pins = tmp_path / "pins.json"
    assert policy_cli.main(["pin", str(tmp_path / "bad.yaml"), "--upstream", "http://127.0.0.1:1/mcp", "--pins", str(pins)]) == 1
    assert one_line(capsys).startswith("ERROR invalid: ")
    assert not pins.exists()


def test_diff_with_an_invalid_policy_is_invalid_not_upstream(tmp_path, capsys):
    (tmp_path / "l9.yaml").write_text("version: 1\nenvironment: prod\ntools: {x: {tiers: {prod: L9}}}\n")
    assert policy_cli.main(["diff", str(tmp_path / "l9.yaml"), "--upstream", "http://127.0.0.1:1/mcp"]) == 1
    out = one_line(capsys)
    assert out.startswith("ERROR invalid: ") and "L9" in out and "ERROR upstream" not in out


# ---------------------------------------------------------------- an upstream that is not an MCP server

@pytest.mark.parametrize("body", [{}, [], {"result": None}, {"result": []}, {"result": {"tools": {}}}, "text",
                                  {"result": {"tools": [{"inputSchema": {}}]}}, {"result": {"tools": [{"name": 1}]}},
                                  {"result": {"tools": ["get_service"]}}])
async def test_catalog_rejects_a_response_of_the_wrong_shape(body):
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=body)))
    with pytest.raises(RuntimeError, match="tools/list"):
        await policy_cli._catalog(http, "http://x/mcp", "p")


async def test_catalog_still_reads_a_result_without_tools():
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"result": {}})))
    assert await policy_cli._catalog(http, "http://x/mcp", "p") == {}


def test_main_diff_against_a_non_mcp_endpoint_is_one_error_line(capsys):
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length", 0)))
            body = b"{}"
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/mcp"
        assert policy_cli.main(["diff", str(EXAMPLE), "--upstream", url]) == 1
    finally:
        srv.shutdown()
        srv.server_close()
    out = one_line(capsys)
    assert out.startswith("ERROR upstream: ") and "MCP endpoint" in out and out.count("\n") == 1


# ---------------------------------------------------------------- a policy without environment

@pytest.fixture
def noenv(tmp_path, monkeypatch):
    monkeypatch.delenv("AIRLOCK_ENV", raising=False)
    p = tmp_path / "noenv.yaml"
    p.write_text(NO_ENV)
    return p


def test_lint_without_environment_uses_the_first_env(noenv):
    f = policy_cli.lint(noenv, envs=["prod"])
    assert [l for l, _, _ in f if l == "ERROR"] == []
    f = policy_cli.lint(noenv, envs=["staging", "prod"])  # staging becomes the environment; it has no tier
    assert [(l, c) for l, c, _ in f] == [("WARN", "env_unused")] and "staging" in f[0][2]


def test_lint_without_environment_and_without_env_names_the_remedy(noenv):
    f = policy_cli.lint(noenv)
    assert [(l, c) for l, c, _ in f] == [("ERROR", "invalid")]
    assert "environment" in f[0][2] and "--env" in f[0][2] and "AIRLOCK_ENV" in f[0][2] and "\n" not in f[0][2]


def test_lint_env_does_not_override_a_set_environment(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("version: 1\nenvironment: dev\ntools: {x: {tiers: {prod: L0}}}\n")
    f = policy_cli.lint(p, envs=["prod"], env="prod")
    assert [m.split("'")[1] for _, c, m in f if c == "env_unused"] == ["dev"]  # the policy's own environment is still checked


def test_the_first_env_beats_airlock_env_for_a_missing_environment(tmp_path):
    # a where rule for staging is "unknown" unless staging is the policy's environment or a tier names it
    p = tmp_path / "p.yaml"
    p.write_text("version: 1\ntools: {x: {description: d, tiers: {prod: L0}, where: [{arg: a, in: [a], env: [staging]}]}}\n")
    assert "where_env_unknown" in codes(policy_cli.lint(p, env="prod"))
    assert "where_env_unknown" not in codes(policy_cli.lint(p, envs=["staging"], env="prod"))


def test_lint_keeps_the_other_validation_errors_when_environment_is_filled_in(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("version: 1\ntools: {x: {tiers: {prod: L9}}}\n")
    f = policy_cli.lint(p, envs=["prod"])
    assert [(l, c) for l, c, _ in f] == [("ERROR", "invalid")] and "L9" in f[0][2] and "environment" not in f[0][2]


def test_main_lint_reads_airlock_env(noenv, monkeypatch, capsys):
    assert policy_cli.main(["lint", str(noenv)]) == 1
    assert capsys.readouterr().out.startswith("ERROR invalid: environment is not set")
    monkeypatch.setenv("AIRLOCK_ENV", "prod")
    assert policy_cli.main(["lint", str(noenv)]) == 0
    assert policy_cli.main(["lint", str(noenv), "--env", "staging"]) == 0  # a missing tier for staging is only a warning
    assert "WARN env_unused: no tool has a tier for environment 'staging'" in capsys.readouterr().out


def test_main_diff_and_pin_read_airlock_env_unless_env_is_given(monkeypatch):
    seen = []

    async def fake(policy_path, upstream, env=None, *rest, **kw):  # pin passes its pins path positionally
        seen.append(env)
        return []

    monkeypatch.setattr(policy_cli, "diff", fake)
    monkeypatch.setattr(policy_cli, "pin", fake)
    monkeypatch.delenv("AIRLOCK_ENV", raising=False)
    policy_cli.main(["diff", str(EXAMPLE), "--upstream", "http://x/mcp"])
    monkeypatch.setenv("AIRLOCK_ENV", "dev")
    policy_cli.main(["diff", str(EXAMPLE), "--upstream", "http://x/mcp"])
    policy_cli.main(["pin", str(EXAMPLE), "--upstream", "http://x/mcp"])
    policy_cli.main(["diff", str(EXAMPLE), "--upstream", "http://x/mcp", "--env", "prod"])
    assert seen == [None, "dev", "dev", "prod"]
