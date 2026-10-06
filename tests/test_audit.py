"""Audit sinks (JSONL + Postgres), fan-out, and the airlock-audit CLI."""

from __future__ import annotations

import hashlib
import io
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from mcp_airlock import __main__ as cli
from mcp_airlock import audit
from mcp_airlock.app import build
from mcp_airlock.audit import GENESIS, REDACTED, AuditLog, MultiAudit, PostgresAuditLog, audit_from_env, row_hash, scrub
from mcp_airlock.audit_cli import default_files, main, query_jsonl, verify

from .conftest import ROOT

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
    for k in ("ts", "hash"):  # the two sinks wrote at different instants, and the timestamp is part of the hash
        jrow.pop(k), rec.pop(k)
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


def test_lone_surrogate_in_client_text_is_replaced_and_chain_verifies(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    log.write(phase="intent", **{**BASE, "args": {"q": "a\ud800b", "k\udc00": ["\udfff"]}, "tool": "t\ud800"})
    log.write(phase="outcome", **BASE)
    log.close()
    first = jsonl_rows(path)[0]
    assert first["args"] == {"q": "a\ufffdb", "k\ufffd": ["\ufffd"]}
    assert first["tool"] == "t\ufffd"
    assert verify([str(path)])[0]


def test_query_reads_rotated_files_oldest_first(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", max_bytes=600, keep=10)
    for i in range(8):
        log.write(phase="intent", **dict(BASE, call_id=f"c{i}"))
    log.close()
    assert len(default_files(str(tmp_path / "a.jsonl"))) > 1
    rows = query_jsonl(str(tmp_path / "a.jsonl"), {}, None, None)
    assert [r["call_id"] for r in rows] == [f"c{i}" for i in range(8)]
    assert [r["call_id"] for r in query_jsonl(str(tmp_path / "a.jsonl"), {}, None, 2)] == ["c6", "c7"]


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


def test_multi_audit_delivers_to_a_sink_with_only_write(tmp_path):
    class WriteOnly:  # no write_row: it gets the record the caller passed, the way the file sink does before chaining
        def __init__(self):
            self.seen = []

        def write(self, **rec):
            self.seen.append(rec)

        def close(self):
            pass

    plain = WriteOnly()
    m = MultiAudit(AuditLog(tmp_path / "a.jsonl"), plain)
    m.write(phase="intent", **BASE)
    m.close()
    assert plain.seen == [dict(BASE, phase="intent")] and len(jsonl_rows(tmp_path / "a.jsonl")) == 1


def test_genesis_is_sixty_four_zeros():
    assert GENESIS == "0" * 64 and len(GENESIS) == len(row_hash({}))


def test_audit_from_env(tmp_path, monkeypatch):
    monkeypatch.delenv("AIRLOCK_AUDIT_DSN", raising=False)
    assert type(audit_from_env(tmp_path / "a.jsonl")) is AuditLog
    monkeypatch.setenv("AIRLOCK_AUDIT_DSN", "postgresql://x")
    m = audit_from_env(tmp_path / "b.jsonl")
    assert isinstance(m, MultiAudit) and [type(s) for s in m.sinks] == [AuditLog, PostgresAuditLog]


# --- detail redaction ------------------------------------------------------------------------------------------

BEARER, SK = "Bearer eyJabc.def-ghi", "sk-0123456789abcdef"
DETAILS = {
    "str": (f"upstream tools/list failed (HTTP 401): {BEARER} then {SK}", f"upstream tools/list failed (HTTP 401): {REDACTED} then {REDACTED}"),
    "dict": ({"postprocess_error": f"ValueError: {BEARER}", "nested": {"note": f"key={SK}", "n": 3}, "password": "hunter2",
              "creds": {"user": "a"}, "credentials": {"user": "a"}, "items": [f"x {SK}", {"authorization": "y"}], "est_tokens": 50094, "truncated": True},
             {"postprocess_error": f"ValueError: {REDACTED}", "nested": {"note": f"key={REDACTED}", "n": 3}, "password": REDACTED,
              "creds": {"user": "a"}, "credentials": REDACTED, "items": [f"x {REDACTED}", {"authorization": REDACTED}], "est_tokens": 50094, "truncated": True}),
    "list": ([f"a {BEARER}", ["b", SK]], [f"a {REDACTED}", ["b", REDACTED]]),
    "object": ({"err": ValueError(f"boom {SK}")}, {"err": f"boom {REDACTED}"}),  # lands in the row as text (default=str)
    "none": (None, None),
}


@pytest.mark.parametrize("name", DETAILS)
def test_jsonl_detail_is_scrubbed(tmp_path, name):
    raw, want = DETAILS[name]
    sink = AuditLog(tmp_path / "a.jsonl")
    sink.write(phase="outcome", **dict(BASE, detail=raw))
    sink.close()
    (row,) = jsonl_rows(tmp_path / "a.jsonl")
    assert row["detail"] == want


@pytest.mark.parametrize("name", DETAILS)
def test_postgres_detail_is_scrubbed(pg_dsn, name):
    import psycopg
    raw, want = DETAILS[name]
    sink = PostgresAuditLog(pg_dsn)
    sink.write(phase="outcome", **dict(BASE, detail=raw))
    sink.close()
    with psycopg.connect(pg_dsn) as c:
        (rec,), = c.execute("SELECT rec FROM airlock_audit").fetchall()
    assert rec["detail"] == want


def test_detail_redaction_leaves_other_fields_alone(tmp_path):
    sink = AuditLog(tmp_path / "a.jsonl")
    sink.write(phase="outcome", **dict(BASE, detail=f"x {SK}", tool=f"t {SK}"))
    sink.close()
    (row,) = jsonl_rows(tmp_path / "a.jsonl")
    assert row["tool"] == f"t {SK}" and row["detail"] == f"x {REDACTED}"


def test_scrub_is_fast_on_identifier_runs():
    run = "ey" * 100_000  # a method name of this shape reaches scrub through a protocol deny, before the principal check
    t0 = time.perf_counter()
    assert scrub(run) == run
    assert time.perf_counter() - t0 < 0.5
    assert scrub("id_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl ok") == f"id_token={REDACTED} ok"


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


# --- rotation --------------------------------------------------------------------------------------------------

def write_n(sink, n, start=0, **over):
    """n records whose call_id has a fixed width, so every line has the same size."""
    for i in range(start, start + n):
        sink.write(phase="intent", **dict(BASE, call_id=f"c{i:03d}", **over))


def line_size(tmp_path) -> int:
    sink = AuditLog(tmp_path / "probe.jsonl")
    write_n(sink, 1)
    sink.close()
    return (tmp_path / "probe.jsonl").stat().st_size


def ids_in(path) -> list[str]:
    return [r["call_id"] for r in jsonl_rows(path)]


def test_rotation_at_the_limit_keeps_the_line_and_one_byte_over_rotates(tmp_path):
    n = line_size(tmp_path)
    exact = AuditLog(tmp_path / "e.jsonl", max_bytes=2 * n)
    write_n(exact, 2)
    assert not (tmp_path / "e.jsonl.1").exists() and ids_in(tmp_path / "e.jsonl") == ["c000", "c001"]
    write_n(exact, 1, start=2)
    assert ids_in(tmp_path / "e.jsonl.1") == ["c000", "c001"] and ids_in(tmp_path / "e.jsonl") == ["c002"]
    over = AuditLog(tmp_path / "o.jsonl", max_bytes=2 * n - 1)
    write_n(over, 2)
    assert ids_in(tmp_path / "o.jsonl.1") == ["c000"] and ids_in(tmp_path / "o.jsonl") == ["c001"]


def test_rotation_is_off_for_none_and_zero(tmp_path):
    for i, limit in enumerate((None, 0)):
        sink = AuditLog(tmp_path / f"{i}.jsonl", max_bytes=limit)
        write_n(sink, 20)
        assert len(ids_in(tmp_path / f"{i}.jsonl")) == 20 and not (tmp_path / f"{i}.jsonl.1").exists()


def test_keep_one_overwrites_the_rotated_file(tmp_path):
    n = line_size(tmp_path)
    sink = AuditLog(tmp_path / "a.jsonl", max_bytes=n, keep=1)
    write_n(sink, 4)
    assert ids_in(tmp_path / "a.jsonl") == ["c003"] and ids_in(tmp_path / "a.jsonl.1") == ["c002"]
    assert not (tmp_path / "a.jsonl.2").exists()


def test_keep_three_drops_the_oldest_file(tmp_path):
    n = line_size(tmp_path)
    sink = AuditLog(tmp_path / "a.jsonl", max_bytes=n, keep=3)
    write_n(sink, 6)
    assert [ids_in(tmp_path / name) for name in ("a.jsonl", "a.jsonl.1", "a.jsonl.2", "a.jsonl.3")] == \
        [["c005"], ["c004"], ["c003"], ["c002"]]
    assert not (tmp_path / "a.jsonl.4").exists()  # c000 and c001 are gone


def test_a_line_longer_than_the_limit_is_written_to_a_fresh_file(tmp_path):
    sink = AuditLog(tmp_path / "a.jsonl", max_bytes=10)
    write_n(sink, 3)
    assert ids_in(tmp_path / "a.jsonl") == ["c002"] and ids_in(tmp_path / "a.jsonl.1") == ["c001"]
    assert ids_in(tmp_path / "a.jsonl.2") == ["c000"]  # the first line went into the empty file, nothing was dropped
    assert not (tmp_path / "a.jsonl.3").exists()  # an empty file is never rotated


def boom(*a):
    raise OSError("disk")


def test_rotation_failure_leaves_the_sink_writable(tmp_path, monkeypatch):
    n = line_size(tmp_path)
    sink = AuditLog(tmp_path / "a.jsonl", max_bytes=n)
    write_n(sink, 1)
    real = os.replace
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        write_n(sink, 1, start=1)
    monkeypatch.setattr(os, "replace", real)
    write_n(sink, 1, start=1)
    assert ids_in(tmp_path / "a.jsonl.1") == ["c000"] and ids_in(tmp_path / "a.jsonl") == ["c001"]


def test_a_failed_stale_file_removal_leaves_the_sink_writable_and_is_retried(tmp_path, monkeypatch):
    from pathlib import Path
    n = line_size(tmp_path)
    sink = AuditLog(tmp_path / "a.jsonl", max_bytes=n, keep=3)
    write_n(sink, 4)  # a.jsonl c003, .1 c002, .2 c001, .3 c000
    sink.close()
    real, failed = Path.unlink, []

    def unlink_once_fails(self, *a, **kw):
        if not failed:
            failed.append(self)
            raise OSError("busy")
        return real(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", unlink_once_fails)
    sink = AuditLog(tmp_path / "a.jsonl", max_bytes=n, keep=1)
    with pytest.raises(OSError, match="busy"):  # the renames are done, removing the stale .2 fails: the finally reopens the live file
        write_n(sink, 1, start=4)
    assert failed == [tmp_path / "a.jsonl.2"]
    write_n(sink, 1, start=5)  # lands in the fresh live file, no rotation needed
    assert sorted(p.name for p in tmp_path.glob("a.jsonl*")) == ["a.jsonl", "a.jsonl.1", "a.jsonl.2", "a.jsonl.3"]
    assert ids_in(tmp_path / "a.jsonl") == ["c005"] and ids_in(tmp_path / "a.jsonl.1") == ["c003"]
    write_n(sink, 1, start=6)  # the next rotation removes the stale files
    sink.close()
    assert sorted(p.name for p in tmp_path.glob("a.jsonl*")) == ["a.jsonl", "a.jsonl.1"]
    assert ids_in(tmp_path / "a.jsonl") == ["c006"] and ids_in(tmp_path / "a.jsonl.1") == ["c005"]


def test_audit_log_rejects_bad_limits(tmp_path):
    for kw in ({"keep": 0}, {"max_bytes": -1}):
        with pytest.raises(ValueError):
            AuditLog(tmp_path / "a.jsonl", **kw)


def test_audit_from_env_passes_the_rotation_settings(tmp_path, monkeypatch):
    monkeypatch.delenv("AIRLOCK_AUDIT_DSN", raising=False)
    sink = audit_from_env(tmp_path / "a.jsonl", 500, 2)
    assert (sink.max_bytes, sink.keep) == (500, 2)
    sink.close()
    monkeypatch.setenv("AIRLOCK_AUDIT_DSN", "postgresql://x")
    multi = audit_from_env(tmp_path / "b.jsonl", 7, 3)
    assert (multi.sinks[0].max_bytes, multi.sinks[0].keep) == (7, 3)
    multi.close()
    assert (multi := audit_from_env(tmp_path / "c.jsonl")).sinks[0].keep == 5
    multi.close()


def test_build_passes_the_rotation_settings_to_the_file_sink(tmp_path, monkeypatch):
    for var in ("AIRLOCK_APPROVAL_WEBHOOK", "AIRLOCK_APPROVAL_MODE", "AIRLOCK_STORE_DSN", "AIRLOCK_AUDIT_DSN"):
        monkeypatch.delenv(var, raising=False)
    al = build(str(ROOT / "policy.example.yaml"), "http://localhost:9001/mcp", str(tmp_path / "audit.jsonl"), "prod",
               audit_max_bytes=123, audit_keep=2)
    assert (al.audit.max_bytes, al.audit.keep) == (123, 2)
    al.audit.close()


def run_main(monkeypatch, *argv):
    seen = {}
    monkeypatch.setattr("sys.argv", ["mcp-airlock", "--policy", "p.yaml", "--upstream", "http://x/mcp", *argv])
    monkeypatch.setattr(cli, "build", lambda *a, **kw: seen.update(kw) or type("A", (), {"app": None})())
    monkeypatch.setattr(cli.uvicorn, "run", lambda *a, **kw: None)
    monkeypatch.setattr(cli, "setup_otel", lambda f: SimpleNamespace(shutdown=lambda: None))
    cli.main()
    return seen


def test_main_passes_the_rotation_flags_to_build(monkeypatch):
    seen = run_main(monkeypatch, "--audit-max-bytes", "1000", "--audit-keep", "7")
    assert (seen["audit_max_bytes"], seen["audit_keep"]) == (1000, 7)
    seen = run_main(monkeypatch)
    assert (seen["audit_max_bytes"], seen["audit_keep"]) == (None, 5)  # rotation is off unless asked for
    assert run_main(monkeypatch, "--audit-max-bytes", "0")["audit_max_bytes"] == 0


@pytest.mark.parametrize("argv", [["--audit-max-bytes", "-1"], ["--audit-max-bytes", "abc"], ["--audit-max-bytes", "1.5"],
                                  ["--audit-keep", "0"], ["--audit-keep", "-2"], ["--audit-keep", "x"]])
def test_main_rejects_bad_rotation_values(monkeypatch, argv, capsys):
    with pytest.raises(SystemExit) as e:
        run_main(monkeypatch, *argv)
    assert e.value.code == 2 and argv[0] in capsys.readouterr().err


# --- chain -----------------------------------------------------------------------------------------------------

def chained(path, n=5, **kw):
    sink = AuditLog(path, **kw)
    write_n(sink, n)
    sink.close()
    return path


def lines_of(path) -> list[str]:
    return path.read_text().splitlines()


def jsonl_rows_tail(path) -> dict:
    return json.loads(lines_of(path)[-1])


def verify_cli(capsys, *files):
    rc = main(["verify", *map(str, files)])
    out, err = capsys.readouterr()
    return rc, out.strip(), err


def test_chain_fields_are_the_last_two_keys_and_link_records(tmp_path):
    rows = jsonl_rows(chained(tmp_path / "a.jsonl", 3))
    assert list(rows[0])[-2:] == ["prev", "hash"]
    assert rows[0]["prev"] == GENESIS
    assert [r["prev"] for r in rows[1:]] == [r["hash"] for r in rows[:-1]]
    for r in rows:
        assert r["hash"] == row_hash(r) == canonical_hash(r)


def canonical_hash(row: dict) -> str:
    body = {k: v for k, v in row.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def test_chain_hash_covers_non_ascii_text(tmp_path):
    sink = AuditLog(tmp_path / "a.jsonl")
    write_n(sink, 1, tool="инструмент")
    sink.close()
    (row,) = jsonl_rows(tmp_path / "a.jsonl")
    assert row["hash"] == canonical_hash(row)  # the text is hashed as UTF-8, not as \u escapes
    assert main(["verify", str(tmp_path / "a.jsonl")]) == 0


def test_chain_continues_across_a_rotation(tmp_path, capsys):
    n = line_size(tmp_path)
    chained(tmp_path / "a.jsonl", 4, max_bytes=2 * n)
    old, new = jsonl_rows(tmp_path / "a.jsonl.1"), jsonl_rows(tmp_path / "a.jsonl")
    assert new[0]["prev"] == old[-1]["hash"] and old[0]["prev"] == GENESIS
    rc, out, _ = verify_cli(capsys, tmp_path / "a.jsonl.1", tmp_path / "a.jsonl")
    assert rc == 0 and out == f"OK: 4 records in 2 files, chain from {GENESIS} to {new[-1]['hash']}"


def test_reopening_a_file_continues_the_chain(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl", 2)
    sink = AuditLog(path)
    write_n(sink, 1, start=2)
    sink.close()
    rows = jsonl_rows(path)
    assert rows[2]["prev"] == rows[1]["hash"]
    assert verify_cli(capsys, path)[:2] == (0, f"OK: 3 records in 1 files, chain from {GENESIS} to {rows[2]['hash']}")


def test_reopening_after_a_rotation_continues_from_the_live_file(tmp_path):
    n = line_size(tmp_path)
    path = chained(tmp_path / "a.jsonl", 3, max_bytes=2 * n)  # live file holds the third record only
    last = jsonl_rows(path)[-1]["hash"]
    sink = AuditLog(path, max_bytes=2 * n)
    write_n(sink, 1, start=3)
    sink.close()
    assert jsonl_rows(path)[-1]["prev"] == last


def test_a_smaller_keep_removes_the_rotated_files_it_no_longer_reaches(tmp_path, capsys):
    n = line_size(tmp_path)
    path = chained(tmp_path / "audit.jsonl", 4, max_bytes=n, keep=3)
    sink = AuditLog(path, max_bytes=n, keep=1)
    write_n(sink, 1, start=4)
    sink.close()
    assert sorted(p.name for p in tmp_path.glob("audit.jsonl*")) == ["audit.jsonl", "audit.jsonl.1"]
    rc, out, _ = verify_cli(capsys, *default_files(str(path)))  # .2 and .3 would have broken the default check
    assert rc == 0 and out.startswith("OK: 2 records in 2 files")


@pytest.mark.parametrize("tail", [None, b"", b"   \n", b"\n\n", b"not json\n", b"[1]\n", b'{"hash": 5}\n', b'{"a": 1}\n',
                                  b'{"hash": "", "a": 1}\n', b'{"ts": "old", "phase": "intent"}\n', b'{"ts": "old", "ph\n'])
def test_a_file_without_a_usable_last_hash_starts_at_genesis(tmp_path, tail):
    path = tmp_path / "a.jsonl"
    if tail is not None:
        path.write_bytes(tail)
    sink = AuditLog(path)
    write_n(sink, 1)
    sink.close()
    assert jsonl_rows_tail(path)["prev"] == GENESIS


@pytest.mark.parametrize("blank", [b"\n", b"   \n", b"\n \t\n"])
def test_blank_lines_after_a_record_are_skipped_by_the_writer_as_by_verify(tmp_path, capsys, blank):
    path = chained(tmp_path / "a.jsonl", 1)
    with path.open("ab") as f:
        f.write(blank)
    sink = AuditLog(path)
    write_n(sink, 1, start=1)
    sink.close()
    assert verify_cli(capsys, path)[0] == 0


@pytest.mark.parametrize("live", ["missing", "empty"])
def test_reopening_after_a_crash_between_the_rename_and_the_write_continues_from_the_rotated_file(tmp_path, capsys, live):
    n = line_size(tmp_path)
    path = chained(tmp_path / "a.jsonl", 2, max_bytes=n)
    os.replace(path, tmp_path / "a.jsonl.2")  # what the next rotation would have done before writing into a fresh live file
    os.replace(tmp_path / "a.jsonl.1", tmp_path / "a.jsonl.3")
    os.replace(tmp_path / "a.jsonl.2", tmp_path / "a.jsonl.1")
    (tmp_path / "a.jsonl.3").unlink()
    if live == "empty":
        path.touch()
    sink = AuditLog(path, max_bytes=n)
    write_n(sink, 1, start=2)
    sink.close()
    assert jsonl_rows(path)[0]["prev"] == jsonl_rows(tmp_path / "a.jsonl.1")[-1]["hash"]
    assert verify_cli(capsys, tmp_path / "a.jsonl.1", path)[0] == 0


def test_last_hash_is_found_when_the_last_line_is_longer_than_a_read_block(tmp_path):
    path = tmp_path / "a.jsonl"
    sink = AuditLog(path)
    write_n(sink, 2)
    sink.write(phase="intent", **dict(BASE, call_id="big", detail="x" * 200_000))
    sink.close()
    big = jsonl_rows_tail(path)
    again = AuditLog(path)
    write_n(again, 1, start=3)
    again.close()
    assert jsonl_rows_tail(path)["prev"] == big["hash"]


def test_unreadable_audit_file_has_no_last_hash(tmp_path):
    (tmp_path / "a.jsonl").mkdir()  # exists but cannot be read as a file
    assert audit._last_hash(tmp_path / "a.jsonl") is None


@pytest.mark.skipif(not os.path.exists("/dev/full"), reason="no /dev/full on this platform")
def test_a_failed_write_holds_nothing_back_for_the_next_record(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl", 1)
    sink = AuditLog(path)
    fd = sink._f.fileno()
    full, saved = os.open("/dev/full", os.O_WRONLY), os.dup(fd)
    os.dup2(full, fd)  # the sink's own handle now gets ENOSPC on every write, as on a full disk
    os.close(full)
    with pytest.raises(OSError):
        write_n(sink, 1, start=1)
    os.dup2(saved, fd)
    os.close(saved)
    write_n(sink, 1, start=2)
    sink.close()
    assert ids_in(path) == ["c000", "c002"]  # c001 does not land later with the prev that c002 already used
    assert verify_cli(capsys, path)[0] == 0


class ShortFile(io.FileIO):
    """A raw audit file whose first write puts only half of the bytes on the disk, as a disk filling up does."""

    def __init__(self, path):
        super().__init__(path, "a")
        self.torn = False

    def write(self, b):
        if self.torn:
            return super().write(b)
        self.torn = True
        return super().write(b[: len(b) // 2])


def test_a_short_write_is_an_error_and_leaves_the_chain_where_it_was(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl", 1)
    sink = AuditLog(path)
    sink._f.close()
    sink._f = ShortFile(path)
    with pytest.raises(OSError, match="short write"):
        write_n(sink, 1, start=1)
    write_n(sink, 1, start=2)
    sink.close()
    first, c002 = lines_of(path)  # the half of c001 that reached the disk was cut back off before c002 was appended
    assert json.loads(c002)["call_id"] == "c002" and json.loads(c002)["prev"] == json.loads(first)["hash"]
    assert ids_in(path) == ["c000", "c002"] and not path.with_name("a.jsonl.torn").exists()
    assert verify_cli(capsys, path)[0] == 0  # the file the proxy left behind passes, with no torn line in the way


def test_a_short_write_cuts_back_only_its_own_bytes_next_to_another_writer(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl", 1)
    sink = AuditLog(path)
    other = AuditLog(path)  # another process appending to the same file, after this sink measured it
    write_n(other, 1, start=5)
    other.close()
    sink._f.close()
    sink._f = ShortFile(path)
    with pytest.raises(OSError, match="short write"):
        write_n(sink, 1, start=1)
    sink.close()
    assert ids_in(path) == ["c000", "c005"] and path.read_bytes().endswith(b"}\n")  # the other record is still there
    assert verify_cli(capsys, path)[0] == 0


def test_a_short_write_that_cannot_be_cut_back_gives_the_torn_line_its_newline(tmp_path, capsys, monkeypatch):
    path = chained(tmp_path / "a.jsonl", 1)
    sink = AuditLog(path)
    sink._f.close()
    sink._f = ShortFile(path)
    monkeypatch.setattr(os, "ftruncate", boom)  # an append-only file, say
    with pytest.raises(OSError, match="short write"):
        write_n(sink, 1, start=1)
    write_n(sink, 1, start=2)
    sink.close()
    first, torn, c002 = lines_of(path)  # the old way: the fragment on a line of its own, reported rather than hidden
    assert torn.startswith('{"ts"') and not torn.endswith("}") and json.loads(c002)["prev"] == json.loads(first)["hash"]
    assert verify_cli(capsys, path)[:2] == (1, f"BREAK: {path}:2: not JSON")


TORN = b'{"ts": "2026-09-14T06:54:08.340+00:00", "ph'  # a crash in the middle of a record


@pytest.mark.parametrize("fragment", [TORN, TORN[:-3] + b"x" * 70000 + b'"'], ids=["short", "longer than a read block"])
def test_reopening_after_a_torn_tail_cuts_it_off_and_continues_from_the_record_before_it(tmp_path, capsys, caplog, fragment):
    path = chained(tmp_path / "a.jsonl", 2)
    rows = jsonl_rows(path)
    with path.open("ab") as f:
        f.write(fragment)
    sink = AuditLog(path)
    write_n(sink, 1, start=2)
    sink.close()
    ls = lines_of(path)
    assert [json.loads(ln)["call_id"] for ln in ls] == ["c000", "c001", "c002"]  # three clean lines, nothing else
    assert json.loads(ls[2])["prev"] == rows[1]["hash"]  # not GENESIS, not the .1 file: the last whole record
    assert path.with_name("a.jsonl.torn").read_bytes() == fragment + b"\n"  # kept aside, not lost
    assert verify_cli(capsys, path)[:2] == (0, f"OK: 3 records in 1 files, chain from {GENESIS} to {json.loads(ls[2])['hash']}")
    assert f"ended in a torn line of {len(fragment)} bytes" in caplog.text and str(path.with_name("a.jsonl.torn")) in caplog.text


def test_a_second_torn_tail_is_added_to_the_same_torn_file(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl", 1)
    for _ in (1, 2):
        with path.open("ab") as f:
            f.write(TORN)
        AuditLog(path).close()
    assert path.with_name("a.jsonl.torn").read_bytes() == (TORN + b"\n") * 2 and ids_in(path) == ["c000"]
    assert verify_cli(capsys, path)[0] == 0


def test_a_whole_last_record_without_its_newline_is_kept_and_gets_one(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl", 2)
    path.write_bytes(path.read_bytes().rstrip(b"\n"))  # only the newline was lost
    sink = AuditLog(path)
    write_n(sink, 1, start=2)
    sink.close()
    assert ids_in(path) == ["c000", "c001", "c002"] and not path.with_name("a.jsonl.torn").exists()
    assert verify_cli(capsys, path)[0] == 0


def test_a_torn_tail_that_cannot_be_cut_is_reported_by_verify(tmp_path, capsys, caplog, monkeypatch):
    path = chained(tmp_path / "a.jsonl", 2)
    with path.open("ab") as f:
        f.write(TORN)
    monkeypatch.setattr(os, "truncate", boom)
    sink = AuditLog(path)
    write_n(sink, 1, start=2)
    sink.close()
    ls = lines_of(path)
    assert len(ls) == 4 and json.loads(ls[3])["call_id"] == "c002"  # the old way: the fragment on a line of its own
    assert verify_cli(capsys, path)[:2] == (1, f"BREAK: {path}:3: not JSON")
    assert "could not be cut" in caplog.text


def test_a_torn_tail_is_cut_even_when_it_cannot_be_kept_aside(tmp_path, capsys, caplog):
    path = chained(tmp_path / "a.jsonl", 1)
    with path.open("ab") as f:
        f.write(TORN)
    path.with_name("a.jsonl.torn").mkdir()  # the .torn file cannot be opened
    AuditLog(path).close()
    assert ids_in(path) == ["c000"] and verify_cli(capsys, path)[0] == 0
    assert "not kept:" in caplog.text


def test_concurrent_writers_keep_one_chain_through_rotations(tmp_path, capsys):
    n = line_size(tmp_path)
    sink = AuditLog(tmp_path / "a.jsonl", max_bytes=5 * n, keep=100)
    threads = [threading.Thread(target=write_n, args=(sink, 25), kwargs={"start": 100 * t}) for t in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    sink.close()
    files = default_files(str(tmp_path / "a.jsonl"))
    assert len(files) > 10
    rc, out, _ = verify_cli(capsys, *files)
    assert rc == 0 and out.startswith("OK: 100 records in")


# --- verify ----------------------------------------------------------------------------------------------------

def test_verify_ok_output(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl")
    rows = jsonl_rows(path)
    assert verify_cli(capsys, path) == (0, f"OK: 5 records in 1 files, chain from {GENESIS} to {rows[-1]['hash']}", "")


def test_verify_catches_an_edited_line(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl")
    ls = lines_of(path)
    ls[2] = ls[2].replace('"tool": "get_service"', '"tool": "get_servicf"')
    assert ls[2] != lines_of(path)[2]
    path.write_text("\n".join(ls) + "\n")
    assert verify_cli(capsys, path) == (1, f"BREAK: {path}:3: hash mismatch", "")


@pytest.mark.parametrize("tool", [b'"\\ud800"', b'"\xed\xa0\x80"'])  # a lone surrogate as a JSON escape and as raw bytes
def test_verify_reports_a_lone_surrogate_as_an_edited_line(tmp_path, capsys, tool):
    path = chained(tmp_path / "a.jsonl", 1)
    path.write_bytes(path.read_bytes().replace(b'"get_service"', tool))
    assert verify_cli(capsys, path)[:2] == (1, f"BREAK: {path}:1: hash mismatch")


def test_verify_catches_an_edited_line_whose_hash_was_recomputed(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl")
    ls = lines_of(path)
    row = json.loads(ls[2])
    row["tool"] = "other"
    row["hash"] = row_hash(row)  # the forger fixes the line's own hash but not the next record's prev
    ls[2] = json.dumps(row, ensure_ascii=False)
    path.write_text("\n".join(ls) + "\n")
    assert verify_cli(capsys, path)[:2] == (1, f"BREAK: {path}:4: prev mismatch")


def test_verify_catches_a_deleted_line(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl")
    ls = lines_of(path)
    del ls[2]
    path.write_text("\n".join(ls) + "\n")
    assert verify_cli(capsys, path) == (1, f"BREAK: {path}:3: prev mismatch", "")


def test_verify_catches_a_reordered_pair(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl")
    ls = lines_of(path)
    ls[2], ls[3] = ls[3], ls[2]
    path.write_text("\n".join(ls) + "\n")
    assert verify_cli(capsys, path) == (1, f"BREAK: {path}:3: prev mismatch", "")


def test_verify_catches_a_line_that_is_not_json(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl")
    ls = lines_of(path)
    ls[1] = ls[1][:40]
    path.write_text("\n".join(ls) + "\n")
    assert verify_cli(capsys, path) == (1, f"BREAK: {path}:2: not JSON", "")
    path.write_bytes(b"\xff\xfe\n")
    assert verify_cli(capsys, path)[:2] == (1, f"BREAK: {path}:1: not JSON")


@pytest.mark.parametrize("edit", [lambda r: r.pop("hash"), lambda r: r.update(hash=None), lambda r: r.update(hash=7)])
def test_verify_catches_a_missing_hash_after_the_chain_started(tmp_path, capsys, edit):
    path = chained(tmp_path / "a.jsonl")
    ls = lines_of(path)
    row = json.loads(ls[3])
    edit(row)
    ls[3] = json.dumps(row)
    path.write_text("\n".join(ls) + "\n")
    assert verify_cli(capsys, path) == (1, f"BREAK: {path}:4: missing hash", "")


@pytest.mark.parametrize("value", ["[1]", "42", '"x"', "null"])
def test_verify_treats_a_json_line_that_is_not_an_object_as_not_json(tmp_path, capsys, value):
    path = chained(tmp_path / "a.jsonl", 2)
    ls = lines_of(path)
    path.write_text("\n".join([*ls, value]) + "\n")
    assert verify_cli(capsys, path)[:2] == (1, f"BREAK: {path}:3: not JSON")
    path.write_text("\n".join([value, *ls]) + "\n")  # before the chain too: it is not a record from before the chain
    assert verify_cli(capsys, path)[:2] == (1, f"BREAK: {path}:1: not JSON")


def test_verify_catches_the_oldest_records_with_their_prev_and_hash_stripped(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl", 4)
    ls = lines_of(path)
    for i in (0, 1):  # the forger edits the two oldest lines and drops their chain fields, as a legacy prefix would look
        row = json.loads(ls[i])
        row["principal"] = "mallory"
        del row["prev"], row["hash"]
        ls[i] = json.dumps(row)
    path.write_text("\n".join(ls) + "\n")
    assert verify_cli(capsys, path) == (1, f"BREAK: {path}:1: missing hash", "")  # the first chained record's prev is not GENESIS
    path.write_text("\n".join(["", *ls[1:]]) + "\n")  # the same with one stripped line at line 2
    assert verify_cli(capsys, path)[:2] == (1, f"BREAK: {path}:2: missing hash")


def test_verify_accepts_a_legacy_prefix_followed_by_a_genesis_record(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    path.write_text('{"ts":"old","phase":"intent"}\n{"ts":"old","phase":"outcome"}\n')
    sink = AuditLog(path)  # the writer starts at GENESIS after unchained lines: that is what verify expects after a prefix
    write_n(sink, 2)
    sink.close()
    rows = jsonl_rows(path)
    assert rows[2]["prev"] == GENESIS
    assert verify_cli(capsys, path) == (0, f"OK: 2 records in 1 files, chain from {GENESIS} to {rows[-1]['hash']}, "
                                           "2 unchained records skipped", "")


def test_verify_rejects_a_duplicate_key(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl", 3)
    ls = lines_of(path)
    ls[1] = ls[1].replace('"principal": "alice"', '"principal": "alice", "principal": "mallory"', 1)  # the hash still matches: json.loads keeps the last value
    assert ls[1] != lines_of(path)[1]
    path.write_text("\n".join(ls) + "\n")
    assert verify_cli(capsys, path) == (1, f"BREAK: {path}:2: not JSON", "")


@pytest.mark.parametrize("edit", [lambda r: r.pop("prev"), lambda r: r.update(prev=None), lambda r: r.update(prev=7)])
def test_verify_reports_a_hashed_record_without_a_string_prev_as_a_prev_mismatch(tmp_path, capsys, edit):
    path = chained(tmp_path / "a.jsonl", 2)
    orig = lines_of(path)
    ls = list(orig)
    for i in range(2):
        row = json.loads(ls[i])
        edit(row)
        row["hash"] = row_hash(row)
        ls[i] = json.dumps(row)
    path.write_text("\n".join(ls) + "\n")
    assert verify_cli(capsys, path) == (1, f"BREAK: {path}:1: prev mismatch", "")  # never "chain from None"
    path.write_text("\n".join([orig[0], ls[1]]) + "\n")  # the first record is fine, the second has no prev
    assert verify_cli(capsys, path)[:2] == (1, f"BREAK: {path}:2: prev mismatch")


def test_verify_reports_the_physical_line_number_past_a_blank_line(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl")
    ls = lines_of(path)
    ls[2] = ls[2].replace('"tool": "get_service"', '"tool": "get_servicf"')
    path.write_text("\n".join([*ls[:2], "", *ls[2:]]) + "\n")  # the edited line is now line 4
    assert verify_cli(capsys, path) == (1, f"BREAK: {path}:4: hash mismatch", "")


def test_verify_checks_the_first_record_only_for_its_own_hash(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl")
    rows = jsonl_rows(path)
    path.write_text("\n".join(lines_of(path)[1:]) + "\n")  # the oldest record was cut off
    assert verify_cli(capsys, path) == (0, f"OK: 4 records in 1 files, chain from {rows[0]['hash']} to {rows[-1]['hash']}", "")
    path.write_text("\n".join(lines_of(path)[:-1]) + "\n")  # and a truncated tail goes unnoticed too
    assert verify_cli(capsys, path)[0] == 0


def test_verify_reports_unchained_legacy_lines(tmp_path, capsys):
    path = chained(tmp_path / "new.jsonl", 2)
    legacy = tmp_path / "a.jsonl"
    legacy.write_text('{"ts":"old","phase":"intent"}\n\n{"ts":"old","phase":"outcome"}\n' + path.read_text())
    rows = jsonl_rows(path)
    assert verify_cli(capsys, legacy) == (0, f"OK: 2 records in 1 files, chain from {GENESIS} to {rows[-1]['hash']}, "
                                             "2 unchained records skipped", "")
    legacy.write_text('{"ts":"old"}\n')
    assert verify_cli(capsys, legacy)[:2] == (0, "OK: 0 records in 1 files, 1 unchained records skipped")


def test_verify_several_files_in_order_and_in_the_wrong_order(tmp_path, capsys):
    n = line_size(tmp_path)
    chained(tmp_path / "a.jsonl", 6, max_bytes=2 * n, keep=9)
    first, second, live = tmp_path / "a.jsonl.2", tmp_path / "a.jsonl.1", tmp_path / "a.jsonl"
    rc, out, _ = verify_cli(capsys, first, second, live)
    assert rc == 0 and out.startswith("OK: 6 records in 3 files, chain from " + GENESIS)
    assert verify_cli(capsys, second, first, live)[:2] == (1, f"BREAK: {first}:1: prev mismatch")
    assert verify_cli(capsys, first, live)[:2] == (1, f"BREAK: {live}:1: prev mismatch")  # a file in the middle is missing


def test_verify_names_the_file_of_the_break(tmp_path, capsys):
    n = line_size(tmp_path)
    chained(tmp_path / "a.jsonl", 6, max_bytes=2 * n, keep=9)
    middle = tmp_path / "a.jsonl.1"
    ls = lines_of(middle)
    middle.write_text(ls[0].replace("alice", "mallory") + "\n" + ls[1] + "\n")
    files = [tmp_path / "a.jsonl.2", middle, tmp_path / "a.jsonl"]
    assert verify_cli(capsys, *files)[:2] == (1, f"BREAK: {middle}:1: hash mismatch")


def test_verify_default_files(tmp_path, monkeypatch, capsys):
    for name in ("audit.jsonl", "audit.jsonl.1", "audit.jsonl.2", "audit.jsonl.10", "audit.jsonl.bak", "other.jsonl.3", "audit.jsonl.1.gz",
                 "audit.jsonl.bak.1", "audit.jsonl.1.2", "audit.jsonl.x3", "audit.jsonl."):  # only ^audit\.jsonl\.(\d+)$ is a rotated file
        (tmp_path / name).touch()
    monkeypatch.chdir(tmp_path)
    assert default_files() == ["audit.jsonl.10", "audit.jsonl.2", "audit.jsonl.1", "audit.jsonl"]
    for name in tmp_path.iterdir():
        name.unlink()
    n = line_size(tmp_path)
    (tmp_path / "probe.jsonl").unlink()
    chained(tmp_path / "audit.jsonl", 7, max_bytes=2 * n, keep=9)
    rc, out, _ = verify_cli(capsys)
    assert rc == 0 and out.startswith("OK: 7 records in 4 files, chain from " + GENESIS)


def test_verify_without_files_or_with_an_unreadable_one(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc, out, err = verify_cli(capsys)
    assert (rc, out) == (1, "") and "no audit files" in err
    rc, out, err = verify_cli(capsys, tmp_path / "missing.jsonl")
    assert (rc, out) == (1, "") and "missing.jsonl" in err


# --- Postgres carries the same chain ---------------------------------------------------------------------------

def pg_recs(dsn) -> dict[str, dict]:
    import psycopg
    with psycopg.connect(dsn) as c:
        return {r["call_id"]: r for (r,) in c.execute("SELECT rec FROM airlock_audit").fetchall()}


def test_postgres_record_has_the_same_prev_and_hash_as_the_file_line(tmp_path, pg_dsn):
    seed = PostgresAuditLog(pg_dsn)  # a Postgres sink chaining on its own would continue from this row, not from GENESIS
    seed.write(phase="intent", **dict(BASE, call_id="seed"))
    seed.close()
    sink = MultiAudit(AuditLog(tmp_path / "a.jsonl"), PostgresAuditLog(pg_dsn))
    for i in range(3):
        sink.write(phase="intent", **dict(BASE, call_id=f"c{i}"))
    sink.close()
    recs = pg_recs(pg_dsn)
    rows = jsonl_rows(tmp_path / "a.jsonl")
    assert [recs[r["call_id"]] for r in rows] == rows  # whole row, timestamp included
    assert rows[0]["prev"] == GENESIS and rows[2]["prev"] == rows[1]["hash"]


def test_postgres_keeps_a_record_the_file_sink_sealed_but_could_not_write(tmp_path, pg_dsn, monkeypatch):
    n = line_size(tmp_path)
    sink = MultiAudit(AuditLog(tmp_path / "a.jsonl", max_bytes=n), PostgresAuditLog(pg_dsn))
    sink.write(phase="intent", **dict(BASE, call_id="c0"))
    real = os.replace
    monkeypatch.setattr(os, "replace", boom)  # the rotation before c1 fails after the row was sealed; MultiAudit logs it
    sink.write(phase="intent", **dict(BASE, call_id="c1"))
    monkeypatch.setattr(os, "replace", real)
    sink.write(phase="intent", **dict(BASE, call_id="c2"))
    sink.close()
    old, live = jsonl_rows(tmp_path / "a.jsonl.1"), jsonl_rows(tmp_path / "a.jsonl")
    assert [r["call_id"] for r in old + live] == ["c0", "c2"] and main(["verify", str(tmp_path / "a.jsonl.1"), str(tmp_path / "a.jsonl")]) == 0
    recs = pg_recs(pg_dsn)
    assert [recs["c0"], recs["c2"]] == old + live and recs["c1"]["prev"] == recs["c2"]["prev"] == recs["c0"]["hash"]
    assert all(r["hash"] == row_hash(r) for r in recs.values())


def test_postgres_alone_chains_from_its_newest_row(pg_dsn):
    for call_ids in (["c0", "c1"], ["c2"]):  # a second instance picks up where the first stopped
        sink = PostgresAuditLog(pg_dsn)
        for cid in call_ids:
            sink.write(phase="intent", **dict(BASE, call_id=cid))
        sink.close()
    recs = pg_recs(pg_dsn)
    assert recs["c0"]["prev"] == GENESIS
    assert recs["c1"]["prev"] == recs["c0"]["hash"] and recs["c2"]["prev"] == recs["c1"]["hash"]
    assert all(r["hash"] == row_hash(r) for r in recs.values())


def test_postgres_alone_starts_at_genesis_after_a_row_without_a_hash(pg_dsn):
    import psycopg
    with psycopg.connect(pg_dsn, autocommit=True) as c:
        c.execute("INSERT INTO airlock_audit (ts, rec) VALUES (now(), '{\"call_id\": \"old\"}'::jsonb)")
    sink = PostgresAuditLog(pg_dsn)
    sink.write(phase="intent", **BASE)
    sink.close()
    assert pg_recs(pg_dsn)["c1"]["prev"] == GENESIS
