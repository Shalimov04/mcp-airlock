"""Audit sinks (JSONL + Postgres), fan-out, and the airlock-audit CLI."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from mcp_airlock import audit
from mcp_airlock.audit import REDACTED, AuditLog, MultiAudit, PostgresAuditLog, audit_from_env
from mcp_airlock.audit_cli import main

PG = os.environ.get("AIRLOCK_TEST_PG_DSN")
NOW = datetime.now(timezone.utc)
SECRET_ARGS = {"name": "svc", "password": "hunter2", "headers": {"Authorization": "Bearer abc.def"}, "note": "sk-0123456789abcdef"}
BASE = dict(call_id="c1", principal="alice", method="tools/call", tool="get_service", args=SECRET_ARGS,
            verdict="allow", rule_id="tier.L0.read", tier="L0", dry_run=None, latency_ms=3, upstream_status=200,
            trace_id="t" * 32, detail={"truncated": True})
# (call_id, principal, verdict, rule_id, phase, age)
SEED = [("old", "alice", "allow", "tier.L0.read", "outcome", timedelta(days=3)),
        ("mid", "bob", "deny", "allowlist.deny", "intent", timedelta(hours=1)),
        ("new", "alice", "deny", "allowlist.deny", "outcome", timedelta(minutes=5))]


@pytest.fixture
def pg_dsn():
    if not PG:
        pytest.skip("AIRLOCK_TEST_PG_DSN unset")
    import psycopg
    with psycopg.connect(PG, autocommit=True) as c:
        c.execute(PostgresAuditLog.DDL)
        c.execute("TRUNCATE airlock_audit")  # our table only; the database is shared
    return PG


def jsonl_rows(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def seed_jsonl(path):
    with path.open("w") as f:
        for cid, who, verdict, rule, phase, age in SEED:
            row = audit._row(dict(BASE, call_id=cid, principal=who, verdict=verdict, rule_id=rule, phase=phase))
            row["ts"] = (NOW - age).isoformat(timespec="milliseconds")
            f.write(json.dumps(row) + "\n")
    return str(path)


def seed_pg(dsn):
    import psycopg
    sink = PostgresAuditLog(dsn)
    for cid, who, verdict, rule, phase, _ in SEED:
        sink.write(**dict(BASE, call_id=cid, principal=who, verdict=verdict, rule_id=rule, phase=phase))
    sink.close()
    with psycopg.connect(dsn, autocommit=True) as c:
        for cid, *_, age in SEED:
            c.execute("UPDATE airlock_audit SET ts = ts - %s WHERE call_id = %s", (age, cid))
    return dsn


def run_cli(capsys, *argv) -> list[dict]:
    assert main(list(argv)) in (None, 0)
    return [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.strip()]


# --- sinks -----------------------------------------------------------------------------------------------------

def test_jsonl_fields_and_redaction(tmp_path):
    sink = AuditLog(tmp_path / "a.jsonl")
    sink.write(phase="intent", **BASE)
    sink.close()
    (row,) = jsonl_rows(tmp_path / "a.jsonl")
    assert list(row) == ["ts", *AuditLog.FIELDS]
    assert row["args"] == {"name": "svc", "password": REDACTED, "headers": {"Authorization": REDACTED}, "note": REDACTED}


def test_postgres_matches_jsonl(tmp_path, pg_dsn):
    import psycopg
    j, p = AuditLog(tmp_path / "a.jsonl"), PostgresAuditLog(pg_dsn)
    j.write(phase="outcome", **BASE)
    p.write(phase="outcome", **BASE)
    j.close(), p.close()
    (jrow,) = jsonl_rows(tmp_path / "a.jsonl")
    with psycopg.connect(pg_dsn) as c:
        cols = "phase, call_id, principal, method, tool, verdict, rule_id, tier, dry_run, latency_ms, upstream_status, trace_id, rec"
        (*vals, rec), = c.execute(f"SELECT {cols} FROM airlock_audit").fetchall()
        (ts,), = c.execute("SELECT ts FROM airlock_audit").fetchall()
    jrow.pop("ts"), rec.pop("ts")
    assert rec == jrow  # same field set, same redaction
    assert vals == [jrow[k] for k in cols.split(", ")[:-1]]
    assert ts.tzinfo is not None and abs(ts - NOW) < timedelta(minutes=1)


def test_postgres_reconnects_once(pg_dsn):
    import psycopg
    p = PostgresAuditLog(pg_dsn)
    p.write(phase="intent", **BASE)
    p._conn.close()  # simulate a dropped connection
    p.write(phase="outcome", **BASE)
    p.close()
    with psycopg.connect(pg_dsn) as c:
        assert c.execute("SELECT count(*) FROM airlock_audit").fetchone() == (2,)


def test_multi_audit_survives_broken_sink(tmp_path):
    class Broken:
        def write(self, **rec):
            raise RuntimeError("db down")

        def close(self):
            pass

    m = MultiAudit(Broken(), AuditLog(tmp_path / "a.jsonl"))
    m.write(phase="intent", **BASE)
    m.close()
    assert len(jsonl_rows(tmp_path / "a.jsonl")) == 1


def test_audit_from_env(tmp_path, monkeypatch):
    monkeypatch.delenv("AIRLOCK_AUDIT_DSN", raising=False)
    assert type(audit_from_env(tmp_path / "a.jsonl")) is AuditLog
    monkeypatch.setenv("AIRLOCK_AUDIT_DSN", "postgresql://x")
    m = audit_from_env(tmp_path / "b.jsonl")
    assert isinstance(m, MultiAudit) and [type(s) for s in m.sinks] == [AuditLog, PostgresAuditLog]


# --- CLI -------------------------------------------------------------------------------------------------------

@pytest.fixture(params=["jsonl", "pg"])
def source(request, tmp_path, monkeypatch):
    monkeypatch.delenv("AIRLOCK_AUDIT_DSN", raising=False)
    if request.param == "jsonl":
        return ["--jsonl", seed_jsonl(tmp_path / "a.jsonl")]
    return ["--dsn", seed_pg(request.getfixturevalue("pg_dsn"))]


def ids(rows):
    return [r["call_id"] for r in rows]


def test_cli_query_all_newest_last(source, capsys):
    rows = run_cli(capsys, "query", *source)
    assert ids(rows) == ["old", "mid", "new"]
    assert rows[0]["args"]["password"] == REDACTED and set(rows[0]) == {"ts", *AuditLog.FIELDS}


def test_cli_filters(source, capsys):
    assert ids(run_cli(capsys, "query", *source, "--principal", "alice")) == ["old", "new"]
    assert ids(run_cli(capsys, "query", *source, "--verdict", "deny")) == ["mid", "new"]
    assert ids(run_cli(capsys, "query", *source, "--rule", "tier.L0.read")) == ["old"]
    assert ids(run_cli(capsys, "query", *source, "--tool", "nope")) == []
    assert ids(run_cli(capsys, "query", *source, "--phase", "intent")) == ["mid"]
    assert ids(run_cli(capsys, "query", *source, "--limit", "1")) == ["new"]
    assert ids(run_cli(capsys, "query", *source, "--verdict", "deny", "--limit", "1")) == ["new"]


def test_cli_since(source, capsys):
    assert ids(run_cli(capsys, "query", *source, "--since", "2h")) == ["mid", "new"]
    assert ids(run_cli(capsys, "query", *source, "--since", "30m")) == ["new"]
    assert ids(run_cli(capsys, "query", *source, "--since", "7d")) == ["old", "mid", "new"]
    iso = (NOW - timedelta(hours=2)).isoformat()
    assert ids(run_cli(capsys, "query", *source, "--since", iso)) == ["mid", "new"]
    naive = (NOW - timedelta(hours=2)).replace(tzinfo=None).isoformat()  # naive ISO is taken as UTC
    assert ids(run_cli(capsys, "query", *source, "--since", naive)) == ["mid", "new"]


def test_cli_stats(source, capsys):
    rows = run_cli(capsys, "query", *source, "--stats")
    assert rows == [{"verdict": "deny", "rule_id": "allowlist.deny", "count": 2},
                    {"verdict": "allow", "rule_id": "tier.L0.read", "count": 1}]
    assert run_cli(capsys, "query", *source, "--stats", "--principal", "bob") == \
        [{"verdict": "deny", "rule_id": "allowlist.deny", "count": 1}]


def test_cli_defaults(tmp_path, monkeypatch, capsys, request):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AIRLOCK_AUDIT_DSN", raising=False)
    seed_jsonl(tmp_path / "audit.jsonl")
    assert len(run_cli(capsys, "query")) == 3  # --jsonl defaults to ./audit.jsonl
    if PG:
        monkeypatch.setenv("AIRLOCK_AUDIT_DSN", seed_pg(request.getfixturevalue("pg_dsn")))
        assert ids(run_cli(capsys, "query", "--limit", "1")) == ["new"]  # --dsn defaults to env
