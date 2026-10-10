"""Audit sinks (JSONL + Postgres), fan-out, and the airlock-audit CLI."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest

from mcp_airlock import Airlock, Policy
from mcp_airlock import __main__ as cli
from mcp_airlock import audit
from mcp_airlock.app import CONFIRM_KEY, build
from mcp_airlock.audit import GENESIS, REDACTED, AuditLog, PostgresAuditLog, audit_from_env, redact, row_hash, scrub
from mcp_airlock.audit_cli import default_files, main, query_jsonl, verify
from mcp_airlock.identity import IdentityConfig

from .conftest import ROOT, audit_rows, call

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
    assert list(row) == ["ts", *audit.FIELDS]
    assert row["args"] == {"name": "svc", "password": REDACTED, "headers": {"Authorization": REDACTED}, "note": REDACTED}


def test_postgres_matches_jsonl(tmp_path, pg_dsn):
    import psycopg
    sink = AuditLog(tmp_path / "a.jsonl", mirror=PostgresAuditLog(pg_dsn))
    sink.write(phase="outcome", **BASE)
    sink.close()
    (jrow,) = jsonl_rows(tmp_path / "a.jsonl")
    with psycopg.connect(pg_dsn) as c:
        cols = "phase, call_id, principal, method, tool, verdict, rule_id, tier, dry_run, latency_ms, upstream_status, trace_id, rec"
        (*vals, rec), = c.execute(f"SELECT {cols} FROM airlock_audit").fetchall()
        (ts,), = c.execute("SELECT ts FROM airlock_audit").fetchall()
    assert rec == jrow  # same field set, same redaction, same ts and chain
    assert vals == [jrow[k] for k in cols.split(", ")[:-1]]
    assert ts.tzinfo is not None and abs(ts - NOW) < timedelta(minutes=1)


def test_postgres_reconnects_once(pg_dsn):
    import psycopg
    p = PostgresAuditLog(pg_dsn)
    p.write(phase="intent", **BASE)
    assert p.flush(10)  # the worker owns the connection: poke it only once it is idle
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


class Broken:  # a mirror that cannot take the row
    def write_row(self, row):
        raise RuntimeError("db down")

    def close(self):
        pass


def test_a_failing_mirror_is_only_logged(tmp_path, caplog):
    m = AuditLog(tmp_path / "a.jsonl", mirror=Broken())
    m.write(phase="intent", **BASE)
    m.close()
    assert len(jsonl_rows(tmp_path / "a.jsonl")) == 1 and "audit mirror failed" in caplog.text


def test_the_mirror_gets_the_row_before_the_file_error_is_raised(tmp_path):
    seen = []

    class Recorder(Broken):
        def write_row(self, row):
            seen.append(row)

    file_sink = AuditLog(tmp_path / "a.jsonl", mirror=Recorder())
    file_sink._f.close()  # a full disk or EIO: the intent write must fail closed with a mirror configured too
    with pytest.raises(ValueError):
        file_sink.write(phase="intent", **BASE)
    assert [r["call_id"] for r in seen] == [BASE["call_id"]]


def test_genesis_is_sixty_four_zeros():
    assert GENESIS == "0" * 64 and len(GENESIS) == len(row_hash({}))


def test_audit_from_env(tmp_path, monkeypatch):
    monkeypatch.delenv("AIRLOCK_AUDIT_DSN", raising=False)
    assert type(audit_from_env(tmp_path / "a.jsonl")) is AuditLog
    monkeypatch.setenv("AIRLOCK_AUDIT_DSN", "postgresql://x")
    m = audit_from_env(tmp_path / "b.jsonl")
    assert type(m) is AuditLog and type(m.mirror) is PostgresAuditLog


# --- the Postgres sink off the event loop ----------------------------------------------------------------------

def proxy_with(upstream, sink):
    """An Airlock on the fake upstream with the given audit sink (make_airlock always builds a plain file sink)."""
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream.app), base_url="http://localhost:9001")
    al = Airlock(Policy.load(ROOT / "policy.example.yaml", "prod"), "http://localhost:9001/mcp", sink, http=http,
                 identity=IdentityConfig(trust_header=True))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=al.app), base_url="http://localhost:9000")


def table_count(dsn, **where) -> int:
    import psycopg
    cond = " AND ".join(f"{k} = %s" for k in where) or "true"
    with psycopg.connect(dsn, autocommit=True) as c:
        return c.execute(f"SELECT count(*) FROM airlock_audit WHERE {cond}", tuple(where.values())).fetchone()[0]


@pytest.fixture
def locked_table(pg_dsn):
    """Holds airlock_audit under ACCESS EXCLUSIVE until the test ends, the way a long migration or a stuck client would."""
    import psycopg
    with psycopg.connect(pg_dsn) as c:
        c.execute("LOCK TABLE airlock_audit IN ACCESS EXCLUSIVE MODE")
        yield c
        c.rollback()


def test_a_black_holed_database_does_not_block_the_writer(monkeypatch, caplog):
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "1")
    with socket.socket() as s:  # completes the TCP handshake and never answers
        s.bind(("127.0.0.1", 0))
        s.listen(8)
        sink = PostgresAuditLog(f"postgresql://u@127.0.0.1:{s.getsockname()[1]}/d?sslmode=disable")
        t0 = time.monotonic()
        for _ in range(3):
            sink.write(phase="intent", **BASE)
        assert time.monotonic() - t0 < 0.5  # used to take about 2 x connect_timeout per record, on the event loop
        with caplog.at_level(logging.WARNING, logger="mcp_airlock.audit"):
            sink.close()
        assert time.monotonic() - t0 < 8  # one deadline to drain, then the rest is dropped
    assert "not written" in caplog.text or "dropped" in caplog.text


async def test_a_locked_audit_table_does_not_hold_up_calls_or_healthz(upstream, tmp_path, pg_dsn, monkeypatch, caplog):
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "2")
    pg = PostgresAuditLog(pg_dsn)
    pg.write(phase="intent", **dict(BASE, call_id="warm", principal="warm"))
    assert pg.flush(10)  # connected: the lock below must hit the INSERT, not the DDL
    conn = pg._conn
    import psycopg
    with psycopg.connect(pg_dsn) as lock:
        lock.execute("LOCK TABLE airlock_audit IN ACCESS EXCLUSIVE MODE")
        async with proxy_with(upstream, AuditLog(tmp_path / "a.jsonl", mirror=pg)) as c:
            t0 = time.monotonic()
            res = await call(c, "list_services", {}, principal="alice")
            assert (await c.get("/healthz")).status_code == 200
            took = time.monotonic() - t0
        assert not res.get("isError") and took < 1, took  # the write waits on the lock, the loop does not
        assert not pg.flush(0.3)  # still waiting
        with caplog.at_level(logging.WARNING, logger="mcp_airlock.audit"):
            assert pg.flush(15)  # statement_timeout or lock_timeout ends each wait, about one deadline per record
        lock.rollback()
    assert caplog.text.count("dropped") == 2 and "due to statement timeout" in caplog.text and "Traceback" not in caplog.text
    assert pg._conn is conn and not conn.closed  # the server ended the wait itself: the connection is kept
    assert table_count(pg_dsn, principal="alice") == 0 and len(jsonl_rows(tmp_path / "a.jsonl")) == 2  # the file has them
    pg.write(phase="outcome", **dict(BASE, call_id="after"))  # the sink is usable again once the lock is gone
    pg.close()
    assert table_count(pg_dsn, call_id="after") == 1


def test_close_gives_up_on_a_stuck_sink_within_the_deadline(pg_dsn, locked_table, monkeypatch, caplog):
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "2")
    sink = PostgresAuditLog(pg_dsn)
    for i in range(5):
        sink.write(phase="intent", **dict(BASE, call_id=f"stuck{i}"))
    t0 = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="mcp_airlock.audit"):
        sink.close()  # SIGTERM path: must not wait for five lock waits
    assert time.monotonic() - t0 < 6
    assert "closed with" in caplog.text and "not written" in caplog.text
    sink._worker.join(5)
    assert not sink._worker.is_alive()


def test_the_queue_is_bounded_and_overflow_is_counted(monkeypatch, caplog):
    monkeypatch.setattr(audit, "QUEUE_MAX", 3)
    sink = PostgresAuditLog("postgresql://u@127.0.0.1:1/d")
    sink._worker = threading.Thread(target=lambda: None)  # a worker that never drains, without opening a connection
    sink._q = audit.queue.Queue(maxsize=3)
    with caplog.at_level(logging.WARNING, logger="mcp_airlock.audit"):
        for _ in range(5):
            sink.write(phase="intent", **BASE)
    assert sink._q.qsize() == 3 and sink._dropped == 2
    assert caplog.text.count("behind") == 1  # one line, not one per record


def stuck_sink(monkeypatch, max_bytes=None):
    """A sink whose worker never drains, without opening a connection; the queued items stay for inspection."""
    if max_bytes is not None:
        monkeypatch.setattr(audit, "QUEUE_MAX_BYTES", max_bytes)
    sink = PostgresAuditLog("postgresql://u@127.0.0.1:1/d")
    sink._worker = threading.Thread(target=lambda: None)
    sink._worker.start()
    return sink


def test_the_queue_holds_the_serialized_row_and_is_bounded_by_bytes(monkeypatch, caplog):
    # 1000 parsed rows of a request made of many small objects weighed about 20 GB: a count is not a memory bound.
    sink = stuck_sink(monkeypatch, max_bytes=10_000)
    with caplog.at_level(logging.WARNING, logger="mcp_airlock.audit"):
        for i in range(4):
            sink.write(phase="intent", **dict(BASE, call_id=f"big{i}", detail="x" * 4000))
    assert sink._q.qsize() == 2 and sink._dropped == 2 and sink._bytes == sum(i.size for i in sink._q.queue)
    assert caplog.text.count("behind") == 1 and "KiB" in caplog.text
    item = sink._q.queue[0]
    assert isinstance(item, audit._Queued) and isinstance(item.text, str) and item.cols[1] == "big0"
    assert json.loads(item.text)["detail"] == "x" * 4000 and item.size > 4000  # the text, not a dict of 85000 objects
    sink._wait_s = 0.2
    sink.close()
    assert sink.flush(5) and sink._pending == 0 and sink._bytes == 0  # the drained records are no longer waited for


def test_a_record_bigger_than_the_byte_cap_is_queued_when_nothing_else_waits(monkeypatch):
    sink = stuck_sink(monkeypatch, max_bytes=100)
    sink.write(phase="intent", **BASE)
    sink.write(phase="outcome", **BASE)
    assert sink._q.qsize() == 1 and sink._dropped == 1


def test_concurrent_first_use_ddl_does_not_fail(pg_dsn):
    import psycopg
    with psycopg.connect(pg_dsn, autocommit=True) as c:
        c.execute("DROP TABLE airlock_audit")  # a fresh database, several replicas starting at once
    sink = PostgresAuditLog(pg_dsn)
    conns = [psycopg.connect(sink.dsn, autocommit=True) for _ in range(8)]
    barrier, errors = threading.Barrier(len(conns)), []

    def prepare(c):
        barrier.wait()
        try:
            sink._prepare(c)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=prepare, args=(c,)) for c in conns]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    for c in conns:
        c.close()
    assert errors == []  # unlocked, most of them used to fail with UniqueViolation on pg_type and the record was dropped
    sink.write(phase="intent", **BASE)
    sink.close()
    assert table_count(pg_dsn) == 1


def test_a_failed_prepare_closes_the_connection(monkeypatch):
    class Conn:
        closed = False

        def close(self):
            self.closed = True

    conn = Conn()
    monkeypatch.setattr(audit.psycopg_module(), "connect", lambda *a, **kw: conn)
    sink = PostgresAuditLog("postgresql://u@127.0.0.1:1/d")
    monkeypatch.setattr(sink, "_prepare", lambda c: (_ for _ in ()).throw(RuntimeError("ddl")))
    with pytest.raises(RuntimeError, match="ddl"):
        sink._connect()
    assert conn.closed


# --- text one sink cannot write ---------------------------------------------------------------------------------

NUL_REC = dict(BASE, args={"names": ["prod-db\x00"], "k\x00": 1}, tool="rm_rf\x00", method="tools/ca\x00ll",
               detail="upstream said \x00")
NON_FINITE_REC = dict(BASE, args={"x": float("nan"), "y": float("inf"), "z": float("-inf"), "n": [json.loads("1e400")], "ok": 1.5})


def strict(line: str) -> dict:
    def refuse(name):
        raise ValueError(f"non-standard JSON: {name}")

    return json.loads(line, parse_constant=refuse)


def test_nul_in_client_text_is_replaced_in_the_file(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.write(phase="intent", **NUL_REC)
    log.close()
    (row,) = jsonl_rows(tmp_path / "a.jsonl")
    assert row["args"] == {"names": ["prod-db\ufffd"], "k\ufffd": 1} and row["tool"] == "rm_rf\ufffd"
    assert row["method"] == "tools/ca\ufffdll" and row["detail"] == "upstream said \ufffd"
    assert verify([str(tmp_path / "a.jsonl")])[0]


def test_non_finite_numbers_are_spelled_out_as_strings(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.write(phase="intent", **NON_FINITE_REC)
    log.close()
    (line,) = [ln for ln in (tmp_path / "a.jsonl").read_text().splitlines() if ln.strip()]
    row = strict(line)  # RFC 8259: a strict parser such as Node's takes the line
    assert row["args"] == {"x": "NaN", "y": "Infinity", "z": "-Infinity", "n": ["Infinity"], "ok": 1.5}
    assert verify([str(tmp_path / "a.jsonl")])[0]


def test_dumps_refuses_a_non_finite_number_that_slipped_through():
    with pytest.raises(ValueError):
        audit._dumps({"x": float("nan")})


@pytest.mark.parametrize("rec", [NUL_REC, NON_FINITE_REC], ids=["nul", "non-finite"])
def test_both_sinks_hold_the_record(tmp_path, pg_dsn, rec):
    # Used to leave 0 table rows: jsonb refuses \u0000 and NaN, the text columns refuse NUL, and the failure was only logged.
    m = AuditLog(tmp_path / "a.jsonl", mirror=PostgresAuditLog(pg_dsn))
    m.write(phase="intent", **rec)
    m.write(phase="outcome", **rec)
    m.close()
    rows = jsonl_rows(tmp_path / "a.jsonl")
    assert len(rows) == 2 and table_count(pg_dsn, principal="alice") == 2
    import psycopg
    with psycopg.connect(pg_dsn) as c:
        recs = [r for (r,) in c.execute("SELECT rec FROM airlock_audit ORDER BY ts, ctid").fetchall()]
    assert recs == rows  # same values, same hashes in both sinks


async def test_nul_in_a_call_reaches_both_sinks(upstream, tmp_path, pg_dsn):
    pg = PostgresAuditLog(pg_dsn)
    async with proxy_with(upstream, AuditLog(tmp_path / "a.jsonl", mirror=pg)) as c:
        await call(c, "get_service", {"name": "api\x00"}, principal="mallory")
        await call(c, "rm_rf\x00", {"path": "x"}, principal="mallory")  # allowlist.deny: the tool name carries the NUL
    pg.close()
    rows = audit_rows(tmp_path / "a.jsonl")
    assert len(rows) == 4 and rows[0]["args"] == {"name": "api\ufffd"} and rows[-1]["tool"] == "rm_rf\ufffd"
    assert table_count(pg_dsn, principal="mallory") == 4


# --- secrets inside longer strings -----------------------------------------------------------------------------

INLINE = "key is sk-ABCDEFGH12345678 ok"


def test_redact_scrubs_substrings_too():
    assert redact({"name": INLINE, "cmd": f"curl -H 'Authorization: {BEARER}'", "jwt": f"id {SK} eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln"}) == \
        {"name": f"key is {REDACTED} ok", "cmd": f"curl -H 'Authorization: {REDACTED}'", "jwt": f"id {REDACTED} {REDACTED}"}
    assert redact([INLINE, 3, None, True]) == [f"key is {REDACTED} ok", 3, None, True]
    assert redact(SK) == REDACTED and redact("plain text") == "plain text"


def test_redact_scrubs_dict_keys():
    ghp = "ghp_" + "A" * 20
    assert redact({SK: 1, "ok-name": {f"x {ghp}": 2}, 3: "n"}) == {REDACTED: 1, "ok-name": {f"x {REDACTED}": 2}, 3: "n"}


HYPHENATED = ["disk-cleanup-prod", "task-scheduler", "desk-support-team", "risk-assessment", "disk-monitor-prod",
              "xghp_ABCDEFGHIJKLMNOPQRSTUV", "KAKIAABCDEFGHIJKLMNOP", "myBearer tokens"]


def test_hyphenated_identifiers_are_not_credentials(tmp_path):
    # "sk-" inside a name used to be redacted: approvers saw 'Arguments: {"name": "di[REDACTED]"}' for disk-monitor-prod.
    for name in HYPHENATED:
        assert scrub(name) == name and redact({"name": name}) == {"name": name}
    assert scrub(f"export GH={SK} task-scheduler") == f"export GH={REDACTED} task-scheduler"
    sink = AuditLog(tmp_path / "a.jsonl")
    sink.write(phase="intent", **dict(BASE, tool="disk-cleanup-prod", principal="desk-support-team",
                                      args={"name": "risk-assessment"}))
    sink.close()
    (row,) = jsonl_rows(tmp_path / "a.jsonl")
    assert (row["tool"], row["principal"], row["args"]) == ("disk-cleanup-prod", "desk-support-team", {"name": "risk-assessment"})


async def test_secret_inside_an_argument_is_scrubbed_in_the_audit_and_the_approver_text(client, audit_path, upstream):
    await call(client, "get_service", {"name": INLINE})
    res = await call(client, "delete_service", {"name": INLINE})
    msg = res["inputRequests"][CONFIRM_KEY]["params"]["message"]
    assert "sk-ABCDEFGH12345678" not in msg and f"key is {REDACTED} ok" in msg  # the Arguments line, next to the scrubbed preview
    raw = audit_path.read_text()
    assert "sk-ABCDEFGH12345678" not in raw
    assert audit_rows(audit_path)[0]["args"] == {"name": f"key is {REDACTED} ok"}


async def test_approvers_and_the_audit_see_a_hyphenated_target(client, audit_path, upstream):
    res = await call(client, "delete_service", {"name": "disk-monitor-prod"}, principal="desk-support-team")
    msg = res["inputRequests"][CONFIRM_KEY]["params"]["message"]
    assert '"disk-monitor-prod"' in msg and REDACTED not in msg  # the target of a destructive call is shown
    rows = audit_rows(audit_path)
    assert rows[0]["args"] == {"name": "disk-monitor-prod"} and rows[0]["principal"] == "desk-support-team"


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


def test_client_chosen_text_columns_are_scrubbed_like_detail(tmp_path):
    # A key sent as the tool, method or principal used to survive next to a detail that redacted the same key.
    sink = AuditLog(tmp_path / "a.jsonl")
    sink.write(phase="outcome", **dict(BASE, detail=f"tool '{SK}' is not allowlisted", tool=SK,
                                       method=f"foo {SK} {BEARER}", principal=f"p {SK}", rule_id=f"r {SK}"))
    sink.close()
    (row,) = jsonl_rows(tmp_path / "a.jsonl")
    assert row["tool"] == REDACTED and row["method"] == f"foo {REDACTED} {REDACTED}" and row["principal"] == f"p {REDACTED}"
    assert row["detail"] == f"tool '{REDACTED}' is not allowlisted"
    assert row["rule_id"] == f"r {SK}"  # ours, never client text: left alone


def test_scrub_leaves_identifier_runs_alone():
    run = "ey" * 100_000  # a method name of this shape reaches scrub through a protocol deny, before the principal check
    assert scrub(run) == run
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
    assert rows[0]["args"]["password"] == REDACTED and set(rows[0]) == {"ts", *audit.FIELDS}


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
    assert (multi.max_bytes, multi.keep) == (7, 3)
    multi.close()
    assert (multi := audit_from_env(tmp_path / "c.jsonl")).keep == 5
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


def test_a_short_write_cuts_nothing_when_another_writer_appended_right_after_it(tmp_path):
    path = chained(tmp_path / "a.jsonl", 1)
    sink = AuditLog(path)
    other = AuditLog(path)

    class Racing(ShortFile):
        def write(self, b):
            n = super().write(b)
            write_n(other, 1, start=5)  # lands between our partial write and the cut
            return n

    sink._f.close()
    sink._f = Racing(path)
    with pytest.raises(OSError, match="short write"):
        write_n(sink, 1, start=1)
    other.close()
    sink.close()
    assert b'"call_id": "c005"' in path.read_bytes() and path.read_bytes().endswith(b"}\n")  # not cut into


def test_a_torn_tail_is_not_cut_when_the_file_grew_since_it_was_read(tmp_path, caplog, monkeypatch):
    path = chained(tmp_path / "a.jsonl", 1)
    with path.open("ab") as f:
        f.write(TORN)
    real = AuditLog._cut_torn

    def appended_first(self, fragment, at):
        with path.open("ab") as f:  # another writer finishes the line and adds a record
            f.write(b'x"}\n')
        real(self, fragment, at)

    monkeypatch.setattr(AuditLog, "_cut_torn", appended_first)
    before = path.read_bytes()
    AuditLog(path).close()
    assert path.read_bytes() == before + b'x"}\n' and not path.with_name("a.jsonl.torn").exists()
    assert "changed while" in caplog.text


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


def test_a_legacy_record_without_its_newline_is_a_record_not_a_torn_line(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    path.write_bytes(b'{"ts":"old","phase":"intent"}\n{"ts":"old","phase":"outcome"}')  # written before the chain existed
    sink = AuditLog(path)
    write_n(sink, 1)
    sink.close()
    ls = lines_of(path)
    assert len(ls) == 3 and json.loads(ls[1]) == {"ts": "old", "phase": "outcome"}  # it has no hash, but it is whole
    assert not path.with_name("a.jsonl.torn").exists()
    assert verify_cli(capsys, path)[:2] == (0, f"OK: 1 records in 1 files, chain from {GENESIS} to {json.loads(ls[2])['hash']}, "
                                              "2 unchained records skipped")


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


def test_a_torn_live_file_is_cut_to_nothing_and_the_chain_goes_on_from_the_rotated_file(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    rotated = chained(tmp_path / "a.jsonl.1", 2)
    path.write_bytes(TORN)  # a crash in the first write after a rotation
    sink = AuditLog(path)
    write_n(sink, 1, start=2)
    sink.close()
    assert ids_in(path) == ["c002"] and jsonl_rows(path)[0]["prev"] == jsonl_rows(rotated)[-1]["hash"]
    assert path.with_name("a.jsonl.torn").read_bytes() == TORN + b"\n"
    assert verify_cli(capsys, rotated, path)[0] == 0


def test_a_blank_tail_after_a_bad_line_cuts_nothing(tmp_path, capsys):
    path = chained(tmp_path / "a.jsonl", 1)
    with path.open("ab") as f:
        f.write(b"garbage\n" + b" " * 7)  # the bad line has its newline: it is not the torn tail, and is not moved
    sink = AuditLog(path)
    write_n(sink, 1, start=1)
    sink.close()
    assert not path.with_name("a.jsonl.torn").exists() and lines_of(path)[1] == "garbage"
    assert verify_cli(capsys, path)[:2] == (1, f"BREAK: {path}:2: not JSON")


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
    sink = AuditLog(tmp_path / "a.jsonl", mirror=PostgresAuditLog(pg_dsn))
    for i in range(3):
        sink.write(phase="intent", **dict(BASE, call_id=f"c{i}"))
    sink.close()
    recs = pg_recs(pg_dsn)
    rows = jsonl_rows(tmp_path / "a.jsonl")
    assert [recs[r["call_id"]] for r in rows] == rows  # whole row, timestamp included
    assert rows[0]["prev"] == GENESIS and rows[2]["prev"] == rows[1]["hash"]


def test_postgres_keeps_a_record_the_file_sink_sealed_but_could_not_write(tmp_path, pg_dsn, monkeypatch):
    n = line_size(tmp_path)
    sink = AuditLog(tmp_path / "a.jsonl", max_bytes=n, mirror=PostgresAuditLog(pg_dsn))
    sink.write(phase="intent", **dict(BASE, call_id="c0"))
    real = os.replace
    monkeypatch.setattr(os, "replace", boom)  # the rotation before c1 fails after the row was sealed
    with pytest.raises(OSError):  # the caller fails closed, the table still gets the row
        sink.write(phase="intent", **dict(BASE, call_id="c1"))
    monkeypatch.setattr(os, "replace", real)
    sink.write(phase="intent", **dict(BASE, call_id="c2"))
    sink.close()
    old, live = jsonl_rows(tmp_path / "a.jsonl.1"), jsonl_rows(tmp_path / "a.jsonl")
    assert [r["call_id"] for r in old + live] == ["c0", "c2"] and main(["verify", str(tmp_path / "a.jsonl.1"), str(tmp_path / "a.jsonl")]) == 0
    recs = pg_recs(pg_dsn)
    assert [recs["c0"], recs["c2"]] == old + live and recs["c1"]["prev"] == recs["c2"]["prev"] == recs["c0"]["hash"]
    assert all(r["hash"] == row_hash(r) for r in recs.values())


def test_two_secret_shaped_keys_stay_two_arguments():
    out = redact({"sk-aaaaaaaa1": 1, "sk-bbbbbbbb2": 2, "sk-cccccccc3": 3})
    assert sorted(out.values()) == [1, 2, 3] and set(out) == {REDACTED, REDACTED + "#2", REDACTED + "#3"}
    # a client key that already reads like a suffix is not overwritten
    out = redact({"sk-aaaaaaaa1": 1, REDACTED + "#2": 2, "sk-bbbbbbbb2": 3})
    assert out == {REDACTED: 1, REDACTED + "#2": 2, REDACTED + "#3": 3}


def test_many_secret_shaped_keys_are_kept_apart_in_linear_time():
    # A request of 40000 such keys fits in 1 MiB; counting up from #2 for each one took minutes on the event loop.
    keys = {f"sk-aaaaaaaa{i:06d}": i for i in range(40_000)}
    t = time.process_time()
    out = redact(keys)
    assert time.process_time() - t < 2.0 and len(out) == len(keys) and sorted(out.values()) == list(range(40_000))


def test_a_credential_after_a_literal_backslash_escape_is_scrubbed():
    for esc in ("\\n", "\\t", "\\r"):
        assert scrub(f"echo{esc}sk-abcdefgh12345678 done") == f"echo{esc}{REDACTED} done"
    assert scrub("echo\\nBearer abc123def") == f"echo\\n{REDACTED}"
    # the boundary is still a boundary: hyphenated names and plain letters before the prefix stay as sent
    for kept in ("disk-cleanup-prod", "task-scheduler", "risk-assessment-1", "ask-abcdefgh12345678"):
        assert scrub(kept) == kept


def test_the_backslash_boundary_keeps_the_scan_linear():
    for hostile in ("\\nsk-" * 50_000, "\\n" + "ey" * 100_000, "sk-" * 70_000, "Bearer " + " " * 200_000 + "x"):
        t = time.process_time()
        scrub(hostile)
        assert time.process_time() - t < 2.0, hostile[:12]


def test_detail_keys_are_scrubbed_and_kept_apart(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.write(phase="outcome", call_id="c", detail={"sk-aaaaaaaa1": "x", "sk-bbbbbbbb2": "y", "fine": 1})
    row = json.loads((tmp_path / "a.jsonl").read_text().splitlines()[0])
    assert row["detail"] == {REDACTED: "x", REDACTED + "#2": "y", "fine": 1}
