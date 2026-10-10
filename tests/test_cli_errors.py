"""Bad input to mcp-airlock is one error line and a non-zero exit, never a traceback.
The proxy is run as a process, as the bugs were found."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

import pytest

from mcp_airlock import __main__ as cli

from .conftest import ROOT

EXAMPLE = ROOT / "policy.example.yaml"
EXPORTER = "opentelemetry.exporter.otlp.proto.http.trace_exporter"


def run_airlock(*argv, env=None):
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("OTEL_", "AIRLOCK_"))}
    return subprocess.run([sys.executable, "-m", "mcp_airlock", *argv], env={**clean, **(env or {})},
                          capture_output=True, text=True, timeout=120)


def error_text(stderr: str) -> str:
    """stderr without the startup warnings (this environment configures no identity)."""
    return "\n".join(ln for ln in stderr.splitlines() if not ln.startswith("mcp-airlock: warning: "))


@pytest.mark.parametrize("case, env, expect", [
    ("missing policy", {}, "nope.yaml"),
    ("unparsable policy", {}, "flow sequence"),
    ("audit path is a directory", {}, "Is a directory"),
    ("span file in a missing directory", {}, "spans.jsonl"),
    ("OTEL timeout", {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1", "OTEL_EXPORTER_OTLP_TIMEOUT": "abc"}, "OTEL: "),
    ("OTEL compression", {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1", "OTEL_EXPORTER_OTLP_COMPRESSION": "zstd"}, "zstd"),
    ("OTEL traces timeout", {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1", "OTEL_EXPORTER_OTLP_TIMEOUT": "5",
                             "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT": "5s"}, "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT"),
    ("OTEL traces compression", {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1",
                                 "OTEL_EXPORTER_OTLP_TRACES_COMPRESSION": "br"}, "br"),
    ("OTEL batch delay", {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:1", "OTEL_BSP_SCHEDULE_DELAY": "-5"}, "schedule_delay"),
])
def test_bad_input_is_one_message_and_exit_1_not_a_traceback(tmp_path, case, env, expect):
    if env:
        pytest.importorskip(EXPORTER)  # the OTEL_* settings are only read when the exporter is built
    (tmp_path / "bad.yaml").write_text("tools: [1,2")
    policy = {"missing policy": tmp_path / "nope.yaml", "unparsable policy": tmp_path / "bad.yaml"}.get(case, EXAMPLE)
    audit = tmp_path if case == "audit path is a directory" else tmp_path / "audit.jsonl"
    argv = ["--policy", str(policy), "--upstream", "http://127.0.0.1:1/mcp", "--audit", str(audit), "--port", "0"]
    if case == "span file in a missing directory":
        argv += ["--otel-file", str(tmp_path / "no" / "dir" / "spans.jsonl")]
    r = run_airlock(*argv, env=env)
    assert r.returncode == 1, r.stderr
    err = error_text(r.stderr)
    assert err.startswith("mcp-airlock: ") and expect in err, r.stderr
    assert "Traceback" not in r.stderr and "mcp-airlock" not in err[len("mcp-airlock: "):], r.stderr  # one message


def test_port_outside_0_65535_is_refused_by_the_parser(tmp_path):
    r = run_airlock("--policy", str(EXAMPLE), "--upstream", "http://127.0.0.1:1/mcp", "--audit", str(tmp_path / "a.jsonl"),
                    "--port", "99999")
    assert r.returncode == 2 and "Traceback" not in r.stderr, r.stderr
    assert "--port: must be between 0 and 65535" in r.stderr


@pytest.mark.parametrize("text", ["-1", "65536", "x"])
def test_port_type_rejects_out_of_range_and_non_integers(text):
    with pytest.raises(argparse.ArgumentTypeError):
        cli._port(text)
    assert cli._port("0") == 0 and cli._port("65535") == 65535


def test_airlock_debug_keeps_the_traceback(tmp_path):
    r = run_airlock("--policy", str(tmp_path / "nope.yaml"), "--upstream", "http://127.0.0.1:1/mcp", "--audit",
                    str(tmp_path / "a.jsonl"), env={"AIRLOCK_DEBUG": "1"})
    assert r.returncode == 1 and "Traceback" in r.stderr and "FileNotFoundError" in r.stderr, r.stderr


@pytest.mark.parametrize("value", ["0", "false", ""])
def test_airlock_debug_other_than_1_does_not_mean_debug(tmp_path, value):
    r = run_airlock("--policy", str(tmp_path / "nope.yaml"), "--upstream", "http://127.0.0.1:1/mcp", "--audit",
                    str(tmp_path / "a.jsonl"), env={"AIRLOCK_DEBUG": value})
    assert r.returncode == 1 and "Traceback" not in r.stderr and error_text(r.stderr).startswith("mcp-airlock: "), r.stderr


@pytest.mark.parametrize("text", ["- a\n", "just a string\n"])
@pytest.mark.parametrize("how", ["--env", "AIRLOCK_ENV"])
def test_a_policy_that_is_not_a_mapping_with_an_environment_is_a_message_not_a_traceback(tmp_path, text, how):
    # --env (or AIRLOCK_ENV) used to be written into the document before validation: TypeError on a list or a string
    (tmp_path / "list.yaml").write_text(text)
    argv = ["--policy", str(tmp_path / "list.yaml"), "--upstream", "http://127.0.0.1:1/mcp", "--audit", str(tmp_path / "a.jsonl")]
    env = {}
    if how == "--env":
        argv += ["--env", "prod"]
    else:
        env["AIRLOCK_ENV"] = "prod"
    r = run_airlock(*argv, env=env)
    assert r.returncode == 1 and "Traceback" not in r.stderr, r.stderr
    assert error_text(r.stderr).startswith("mcp-airlock: ") and "valid dictionary" in r.stderr, r.stderr


@pytest.mark.parametrize("text, expect, noise", [
    # PyYAML's str() is a caret diagram over several lines that names "<unicode string>", not the file
    ("tools: [1,2", "while parsing a flow sequence: expected ',' or ']', but got '<stream end>' (line 1, column 12)", "<unicode string>"),
    # pydantic's str() is one block per error with the input value and a documentation URL
    ("version: 1\nenvironment: prod\ntools: {x: {tiers: {prod: L9}}}\n",
     "1 validation error for Policy: tools.x.tiers.prod: Input should be 'L0', 'L1', 'L2' or 'L3', got 'L9'", "errors.pydantic.dev"),
    ("- a\n", "1 validation error for Policy: Input should be a valid dictionary", "input_type"),
])
def test_a_yaml_or_validation_error_is_one_line_naming_the_policy_file(tmp_path, text, expect, noise):
    (tmp_path / "p.yaml").write_text(text)
    r = run_airlock("--policy", str(tmp_path / "p.yaml"), "--upstream", "http://127.0.0.1:1/mcp", "--audit", str(tmp_path / "a.jsonl"))
    assert r.returncode == 1 and "Traceback" not in r.stderr, r.stderr
    err = error_text(r.stderr)
    assert "\n" not in err and err.startswith(f"mcp-airlock: {tmp_path / 'p.yaml'}: ") and expect in err, r.stderr
    assert noise not in err, r.stderr


def test_a_policy_without_environment_is_a_validation_message_not_a_traceback(tmp_path):
    (tmp_path / "noenv.yaml").write_text("version: 1\ntools: {get_service: {tiers: {prod: L0}}}\n")
    r = run_airlock("--policy", str(tmp_path / "noenv.yaml"), "--upstream", "http://127.0.0.1:1/mcp", "--audit", str(tmp_path / "a.jsonl"))
    assert r.returncode == 1 and "Traceback" not in r.stderr and "environment" in error_text(r.stderr), r.stderr


def test_only_the_policy_raises_yaml_and_validation_errors_inside_build():
    # main() labels these with the policy path; a new pydantic model elsewhere would be mislabelled
    src = ROOT / "src" / "mcp_airlock"
    users = {p.name for p in src.glob("*.py") if "BaseModel" in p.read_text()}
    assert users <= {"policy.py"}, users
