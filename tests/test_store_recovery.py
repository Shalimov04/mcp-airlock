"""The Postgres store against a real server: a lock held on a table leaks no backends, and tables that vanish
(a database recreated empty) come back without a restart. Needs AIRLOCK_TEST_PG_DSN."""
import asyncio
import os
import time
import uuid

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

import psycopg  # noqa: E402

import mcp_airlock.store as store_mod  # noqa: E402
from mcp_airlock.app import META  # noqa: E402

from .conftest import call, make_airlock  # noqa: E402
from .test_features import proxy_client  # noqa: E402

PG = os.environ.get("AIRLOCK_TEST_PG_DSN")
needs_pg = pytest.mark.skipif(not PG, reason="AIRLOCK_TEST_PG_DSN not set")
TABLES = "airlock_keys, airlock_prompts, airlock_usage"

WAITING = ("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() "
           "AND pid <> %s AND wait_event_type = 'Lock' AND query LIKE '%%airlock_usage%%'")


@pytest.fixture
async def admin():
    async with await psycopg.AsyncConnection.connect(PG, autocommit=True) as c:
        yield c


# ------------------------------------------------------------------ a lock held on a table
@needs_pg
async def test_a_lock_wait_leaks_no_backends_past_the_pool_size(pg_store, admin, monkeypatch):
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "2")
    store = pg_store(PG, pool_size=2)
    await store.ping()
    async with store._conn() as c:  # the server gives up just before the client would, so a cut leaves no backend behind
        assert await (await c.execute("SHOW statement_timeout")).fetchone() == ("1800ms",)
        assert await (await c.execute("SHOW lock_timeout")).fetchone() == ("1800ms",)

    async with await psycopg.AsyncConnection.connect(PG) as locker:
        await locker.execute("LOCK TABLE airlock_usage IN ACCESS EXCLUSIVE MODE")
        stop = time.monotonic() + 7  # three deadlines: unfixed, each one left two more backends waiting

        async def hammer():
            while time.monotonic() < stop:
                try:
                    await store.usage_add("leak", "t", 1, time.time())
                except psycopg.Error:  # PoolTimeout, the cut, or the server's own timeout: all fail closed
                    pass

        tasks = [asyncio.create_task(hammer()) for _ in range(6)]
        peak = 0
        while time.monotonic() < stop:
            peak = max(peak, (await (await admin.execute(WAITING, (locker.info.backend_pid,))).fetchone())[0])
            await asyncio.sleep(0.25)
        await asyncio.gather(*tasks)
        assert 1 <= peak <= 2, peak  # the pool really was blocked on the lock, and nothing beyond it
        await locker.rollback()

    for _ in range(40):  # the backends the pool gave up on are gone, not idle in transaction
        if (await (await admin.execute(WAITING, (0,))).fetchone())[0] == 0:
            break
        await asyncio.sleep(0.1)
    assert (await (await admin.execute(WAITING, (0,))).fetchone())[0] == 0
    await store.usage_add("leak", "t", 1, time.time())  # and the store works again at once


@needs_pg
async def test_a_connection_whose_deadline_fired_is_dropped_even_when_it_answered(pg_store, monkeypatch):
    # The cut and the server's answer can cross: the answer is still read from the buffer and the call succeeds, but
    # the socket is shut. Returned to the pool as healthy, it failed the next caller's check and cost a 1 s backoff.
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "2")
    cuts: list = []
    monkeypatch.setattr(store_mod, "_cut", lambda conn, timeout, fired, cancels: (cuts.append(conn), fired.append(True)))
    store = pg_store(PG, pool_size=1)
    async with store._conn() as c:
        await asyncio.sleep(2.3)  # the deadline fires with the socket untouched: the answer below arrives as usual
        await c.execute("SELECT 1")
    assert cuts == [c] and c.closed
    t = time.monotonic()
    await store.ping()  # a fresh connection at once, not this one after a failed check
    assert time.monotonic() - t < 0.5


@needs_pg
async def test_the_cancel_request_alone_frees_a_waiting_backend(pg_store, admin, monkeypatch):
    # Behind PgBouncer in transaction mode the server-side timeouts may be absent: the cancel on a cut is the backstop.
    if not psycopg.capabilities.has_cancel_safe():
        pytest.skip("needs libpq 17 or newer")
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "2")
    app = f"airlock-cancel-{uuid.uuid4().hex[:8]}"
    dsn = psycopg.conninfo.make_conninfo(PG, application_name=app)
    store = pg_store(dsn, pool_size=2)

    async def no_timeouts(conn):
        pass

    monkeypatch.setattr(store, "_configure", no_timeouts)
    await store.ping()
    mine = ("SELECT count(*) FROM pg_stat_activity WHERE application_name = %s AND wait_event_type = 'Lock'")
    async with await psycopg.AsyncConnection.connect(PG) as locker:
        await locker.execute("LOCK TABLE airlock_usage IN ACCESS EXCLUSIVE MODE")
        t = time.monotonic()
        with pytest.raises(psycopg.Error):
            await store.usage_add("cancel", "t", 1, time.time())
        assert time.monotonic() - t < 4
        for _ in range(40):  # the lock is still held: only the cancel can have ended the wait
            if (await (await admin.execute(mine, (app,))).fetchone())[0] == 0:
                break
            await asyncio.sleep(0.1)
        assert (await (await admin.execute(mine, (app,))).fetchone())[0] == 0
        await locker.rollback()


# ------------------------------------------------------------------ the check and the retry, no server
class _Conn:
    def __init__(self):
        self.closed = False

    async def close(self):
        self.closed = True


async def test_a_check_cut_by_its_deadline_raises_even_when_the_query_returned(monkeypatch):
    pytest.importorskip("psycopg_pool")
    from mcp_airlock.store import PostgresStore
    store = PostgresStore("postgresql://x@127.0.0.1:1/x")
    store._wait_s = 0.05
    monkeypatch.setattr(store_mod, "_cut", lambda conn, timeout, fired, cancels: fired.append(True))

    async def slow_ok(conn):
        await asyncio.sleep(0.15)

    import psycopg_pool
    monkeypatch.setattr(psycopg_pool.AsyncConnectionPool, "check_connection", staticmethod(slow_ok))
    conn = _Conn()
    with pytest.raises(psycopg.OperationalError):
        await store._check(conn)  # the pool discards the connection on this, not hands it out closed
    assert conn.closed
    fresh = _Conn()
    monkeypatch.setattr(psycopg_pool.AsyncConnectionPool, "check_connection", staticmethod(lambda c: asyncio.sleep(0)))
    await store._check(fresh)
    assert not fresh.closed


async def test_run_retries_once_after_a_missing_table_and_does_not_loop():
    from contextlib import asynccontextmanager
    from mcp_airlock.store import PostgresStore
    store = PostgresStore("postgresql://x@127.0.0.1:1/x")
    entered: list = []

    @asynccontextmanager
    async def conn():
        entered.append(store._ready)
        store._ready = True  # what a successful DDL run does
        yield object()

    store._conn = conn
    store._ready = True
    calls = []

    async def once(c):
        calls.append(1)
        if len(calls) == 1:
            raise psycopg.errors.UndefinedTable("gone")
        return "ok"

    assert await store._run(once) == "ok"
    assert entered == [True, False]  # the DDL flag was reset before the second entry

    calls.clear()
    entered.clear()

    async def always(c):
        calls.append(1)
        raise psycopg.errors.UndefinedTable("still gone")

    with pytest.raises(psycopg.errors.UndefinedTable):
        await store._run(always)
    assert len(calls) == 2 and len(entered) == 2


# ------------------------------------------------------------------ tables that vanish
@needs_pg
async def test_a_store_call_recreates_the_tables_when_they_are_gone(pg_store, admin):
    store = pg_store(PG)
    k, exp = uuid.uuid4().hex, time.time() + 60
    assert await store.consume_once(k, exp) is True
    await admin.execute(f"DROP TABLE {TABLES}")
    assert await store.usage_reserve("fresh", "t", 1, time.time(), 0, 5) is True
    assert await store.consume_once(k, exp) is True  # the burned key went with the database: a new one is fine
    assert await store.get_prompt(k) is None
    await store.save_prompt(k, "text", exp)
    assert await store.get_prompt(k) == "text"


@needs_pg
async def test_gated_calls_keep_working_after_the_database_was_recreated(upstream, audit_path, pg_store, admin):
    store = pg_store(PG)
    principal = f"recreated-{uuid.uuid4().hex[:8]}"
    async with proxy_client(make_airlock(upstream, audit_path, env="dev", store=store)) as c:
        res = await call(c, "set_replicas", {"names": ["a"], "replicas": 1}, principal=principal)  # L3 with a window
        assert res["isError"] is False
        await admin.execute(f"DROP TABLE {TABLES}")
        res = await call(c, "set_replicas", {"names": ["a"], "replicas": 1}, principal=principal)  # was a 500 for good
        assert res["isError"] is False and res["_meta"][META + "rule_id"] == "tier.L3.auto"
        assert len([x for x in upstream.CALLS if x["tool"] == "set_replicas"]) == 2


@needs_pg
async def test_readyz_recreates_missing_tables_and_is_503_while_it_cannot(upstream, audit_path, pg_store, admin, monkeypatch):
    store = pg_store(PG)
    async with proxy_client(make_airlock(upstream, audit_path, store=store)) as c:
        assert (await c.get("/readyz")).status_code == 200
        await admin.execute(f"DROP TABLE {TABLES}")
        assert (await c.get("/readyz")).status_code == 200  # the probe put them back
        row = await (await admin.execute("SELECT to_regclass('airlock_usage'), to_regclass('airlock_keys')")).fetchone()
        assert None not in row
        monkeypatch.setattr(store_mod, "_DDL", "SELECT 1")  # now nothing can create them
        await admin.execute(f"DROP TABLE {TABLES}")
        assert (await c.get("/readyz")).status_code == 503  # SELECT 1 alone used to say 200 here
