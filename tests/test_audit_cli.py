"""airlock-audit query on bad lines and bad input: skips a line it cannot read, and prints one line instead of a traceback."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

import pytest

from mcp_airlock.audit import AuditLog
from mcp_airlock.audit_cli import main

from .conftest import call, rpc

LINE_BREAKS = "a b c\u0085d\x0be\x0cf\x1cg\x1dh\x1ei"  # str.splitlines() splits on every one of these


def query(capsys, *argv) -> tuple[int, list[dict], str]:
    rc = main(["query", *argv])
    out, err = capsys.readouterr()
    return rc, [json.loads(ln) for ln in out.split("\n") if ln.strip()], err  # not splitlines: the output holds U+2028


def write_n(path, n, start=0):
    sink = AuditLog(path)
    for i in range(start, start + n):
        sink.write(phase="intent", call_id=f"c{i:03d}", principal="alice", tool="t", args={}, verdict="allow", rule_id="r")
    sink.close()


# --- lines the reader could not take ---------------------------------------------------------------------------

async def test_query_reads_a_record_whose_argument_holds_unicode_line_breaks(client, audit_path, capsys):
    await call(client, "get_service", {"name": LINE_BREAKS})
    r = await rpc(client, "tools/call", {"name": "rm_rf", "arguments": {"path": LINE_BREAKS}})  # denied: args still logged
    assert r.json()["result"]["isError"]
    rc, rows, err = query(capsys, "--jsonl", str(audit_path))
    assert (rc, err) == (0, "") and len(rows) == 4  # intent and outcome, twice
    assert rows[0]["args"]["name"] == LINE_BREAKS and rows[2]["args"]["path"] == LINE_BREAKS and rows[2]["verdict"] == "deny"
    rc, rows, err = query(capsys, "--jsonl", str(audit_path), "--stats")
    assert rc == 0 and sum(r["count"] for r in rows) == 4


def test_query_skips_a_torn_line_and_reads_the_records_after_it(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    write_n(path, 2)
    with path.open("ab") as f:  # the way an older proxy left a torn line: on a line of its own, records after it
        f.write(b'{"ts": "torn", "phase": "inte\n[1]\n')
    write_n(path, 2, start=2)
    rc, rows, err = query(capsys, "--jsonl", str(path))
    assert rc == 0 and [r["call_id"] for r in rows] == ["c000", "c001", "c002", "c003"]
    assert err == f"airlock-audit: skipped {path}:3: not JSON\nairlock-audit: skipped {path}:4: not JSON\n"
    rc, rows, err = query(capsys, "--jsonl", str(path), "--stats")
    assert rc == 0 and rows == [{"verdict": "allow", "rule_id": "r", "count": 4}]
    rc, rows, _ = query(capsys, "--jsonl", str(path), "--limit", "1")
    assert rc == 0 and [r["call_id"] for r in rows] == ["c003"]


def test_query_skips_a_record_without_a_usable_ts_only_when_since_needs_it(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    write_n(path, 1)
    with path.open("ab") as f:
        f.write(b'{"call_id": "no-ts"}\n{"ts": "yesterday", "call_id": "bad-ts"}\n')
    rc, rows, err = query(capsys, "--jsonl", str(path))
    assert rc == 0 and [r["call_id"] for r in rows] == ["c000", "no-ts", "bad-ts"] and err == ""
    rc, rows, err = query(capsys, "--jsonl", str(path), "--since", "1h")
    assert rc == 0 and [r["call_id"] for r in rows] == ["c000"]
    assert err == f"airlock-audit: skipped {path}:2: bad ts\nairlock-audit: skipped {path}:3: bad ts\n"


# --- bad arguments ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv, msg", [
    (["--limit", "-2"], "argument --limit: expected a positive integer, got '-2'"),
    (["--limit", "0"], "argument --limit: expected a positive integer, got '0'"),
    (["--limit", "x"], "argument --limit: expected a positive integer, got 'x'"),
    (["--since", "99999999999d"], "argument --since: expected 30m, 2h, 7d or an ISO 8601 time, got '99999999999d'"),
    (["--since", "yesterday"], "argument --since: expected 30m, 2h, 7d or an ISO 8601 time, got 'yesterday'"),
])
def test_a_bad_limit_or_since_is_a_usage_error(tmp_path, capsys, argv, msg):
    path = tmp_path / "a.jsonl"
    write_n(path, 3)
    with pytest.raises(SystemExit) as e:
        main(["query", "--jsonl", str(path), *argv])
    assert e.value.code == 2 and msg in capsys.readouterr().err


def test_a_missing_file_is_one_line(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AIRLOCK_AUDIT_DSN", raising=False)
    assert query(capsys) == (1, [], "airlock-audit: no audit file at audit.jsonl\n")
    assert query(capsys, "--jsonl", "other.jsonl") == (1, [], "airlock-audit: no audit file at other.jsonl\n")


# --- Postgres --------------------------------------------------------------------------------------------------

@pytest.fixture
def no_env(monkeypatch):
    for v in ("AIRLOCK_AUDIT_DSN", "AIRLOCK_STORE_CONNECT_TIMEOUT", "PGCONNECT_TIMEOUT"):
        monkeypatch.delenv(v, raising=False)


def test_a_bad_dsn_is_one_line_that_quotes_none_of_it(no_env, monkeypatch, capsys):
    pytest.importorskip("psycopg")  # the DSN cases need the extra; the file cases do not
    monkeypatch.setenv("AIRLOCK_AUDIT_DSN", "host=x password=hunter2 secret")
    assert query(capsys) == (1, [], "airlock-audit: AIRLOCK_AUDIT_DSN is not a valid Postgres connection string\n")
    rc, rows, err = query(capsys, "--dsn", "host=x password=hunter2 secret")
    assert (rc, rows, err) == (1, [], "airlock-audit: --dsn is not a valid Postgres connection string\n")


def test_the_command_prints_no_traceback_and_no_password_for_a_bad_dsn(tmp_path, no_env):
    pytest.importorskip("psycopg")  # the DSN cases need the extra; the file cases do not
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AIRLOCK_", "PG"))}
    env["AIRLOCK_AUDIT_DSN"] = "host=x password=hunter2 secret"
    p = subprocess.run([sys.executable, "-m", "mcp_airlock.audit_cli", "query"], cwd=tmp_path, env=env,
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 1 and p.stdout == ""
    assert p.stderr.count("\n") == 1 and "Traceback" not in p.stderr and "hunter2" not in p.stderr and "secret" not in p.stderr


def test_a_dsn_nobody_listens_on_is_one_line(no_env, capsys):
    pytest.importorskip("psycopg")  # the DSN cases need the extra; the file cases do not
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # a port that refuses
    rc, rows, err = query(capsys, "--dsn", f"postgresql://a@127.0.0.1:{port}/x?sslmode=disable")
    assert (rc, rows) == (1, []) and err.startswith("airlock-audit: Postgres: ") and err.count("\n") == 1


def test_a_black_holed_dsn_fails_within_the_connect_timeout(no_env, monkeypatch, capsys):
    pytest.importorskip("psycopg")  # the DSN cases need the extra; the file cases do not
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "1")
    s = socket.socket()  # completes the TCP handshake (backlog) and never answers
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    try:
        t = time.monotonic()
        rc, rows, err = query(capsys, "--dsn", f"postgresql://u@127.0.0.1:{s.getsockname()[1]}/d?sslmode=disable")
        assert time.monotonic() - t < 5
    finally:
        s.close()
    assert (rc, rows) == (1, []) and err.startswith("airlock-audit: Postgres: ") and "timeout" in err


def test_a_dsn_without_the_postgres_extra_names_it(no_env, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "psycopg", None)  # makes `import psycopg` raise ImportError
    rc, rows, err = query(capsys, "--dsn", "postgresql://x/y")
    assert (rc, rows) == (1, []) and err.startswith("airlock-audit: ") and "mcp-airlock[postgres]" in err and err.count("\n") == 1

