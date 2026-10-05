"""Timeouts, keepalives and the connection pool of the Postgres store; connect timeout of the audit sink."""
import asyncio
import gc
import os
import socket
import subprocess
import sys
import time
import uuid
from contextlib import asynccontextmanager

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

import psycopg  # noqa: E402
import psycopg_pool  # noqa: E402
from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

import mcp_airlock.app as app_mod  # noqa: E402
from mcp_airlock import Airlock, Policy  # noqa: E402
from mcp_airlock.audit import AuditLog, PostgresAuditLog  # noqa: E402
from mcp_airlock.pg import with_conn_defaults  # noqa: E402
from mcp_airlock.store import MemoryStore, PostgresStore  # noqa: E402

from .conftest import ROOT, make_airlock  # noqa: E402
from .test_features import proxy_client  # noqa: E402
from .test_limits import Sink, run_lifespan  # noqa: E402

PG = os.environ.get("AIRLOCK_TEST_PG_DSN")
KEEP = {"keepalives": "1", "keepalives_idle": "10", "keepalives_interval": "5", "keepalives_count": "3"}
DEFAULTS = {"connect_timeout": "10", "tcp_user_timeout": "10000", **KEEP}


@pytest.fixture(autouse=True)
def _no_env(monkeypatch):
    for v in ("AIRLOCK_STORE_CONNECT_TIMEOUT", "AIRLOCK_STORE_POOL_SIZE", "PGCONNECT_TIMEOUT"):
        monkeypatch.delenv(v, raising=False)


def conv(dsn):
    return conninfo_to_dict(with_conn_defaults(dsn, "AIRLOCK_STORE_DSN"))


# ------------------------------------------------------------------ DSN rewriting
def test_uri_gets_defaults_and_keeps_the_rest():
    d = conv("postgresql://u:p@db.example:5433/airlock?sslmode=require")
    assert d == {"user": "u", "password": "p", "host": "db.example", "port": "5433", "dbname": "airlock",
                 "sslmode": "require", **DEFAULTS}


def test_key_value_dsn_gets_defaults():
    assert conv("host=db dbname=airlock user=u") == {"host": "db", "dbname": "airlock", "user": "u", **DEFAULTS}


@pytest.mark.parametrize("dsn", ["postgresql://u@h/d?connect_timeout=3", "host=h connect_timeout=3"])
def test_existing_connect_timeout_is_kept(dsn, monkeypatch):
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "7")
    d = conv(dsn)
    assert d["connect_timeout"] == "3" and d["tcp_user_timeout"] == "7000"


def test_own_keepalive_and_tcp_user_timeout_are_kept():
    d = conv("host=h keepalives_idle=99 tcp_user_timeout=5 keepalives=0")
    assert d["keepalives_idle"] == "99" and d["tcp_user_timeout"] == "5" and d["keepalives"] == "0"
    assert d["keepalives_interval"] == "5"


def test_a_dsn_that_sets_everything_is_returned_unchanged():
    dsn = "host=h connect_timeout=3 tcp_user_timeout=5 keepalives=1 keepalives_idle=1 keepalives_interval=1 keepalives_count=1"
    assert with_conn_defaults(dsn, "X") == dsn


def test_empty_dsn_gets_the_defaults_alone():
    assert conv("") == DEFAULTS


def test_password_with_special_chars_survives():
    from urllib.parse import quote
    pw = "p@ss:w/rd %?#'\\ x"
    d = conv(f"postgresql://u:{quote(pw, safe='')}@h/d")
    assert d["password"] == pw and d["connect_timeout"] == "10"
    d = conv("host=h password='a b\\'c\\\\d'")
    assert d["password"] == "a b'c\\d" and d["connect_timeout"] == "10"


def test_env_overrides_default(monkeypatch):
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "3")
    d = conv("host=h")
    assert d["connect_timeout"] == "3" and d["tcp_user_timeout"] == "3000"


def test_pgconnect_timeout_in_the_environment_is_left_alone(monkeypatch):
    monkeypatch.setenv("PGCONNECT_TIMEOUT", "3")
    d = conv("postgresql://u@127.0.0.1:5432/d")
    assert "connect_timeout" not in d and d["tcp_user_timeout"] == "10000" and d["keepalives_idle"] == "10"


@pytest.mark.parametrize("bad", ["abc", "0", "-1", "1.5"])
def test_bad_env_stops_startup(bad, monkeypatch):
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", bad)
    for make in (PostgresStore, PostgresAuditLog):
        with pytest.raises(ValueError, match="AIRLOCK_STORE_CONNECT_TIMEOUT must be a positive integer"):
            make("host=h")
    monkeypatch.delenv("AIRLOCK_STORE_CONNECT_TIMEOUT")
    monkeypatch.setenv("AIRLOCK_STORE_POOL_SIZE", bad)
    with pytest.raises(ValueError, match="AIRLOCK_STORE_POOL_SIZE must be a positive integer"):
        PostgresStore("host=h")
    PostgresAuditLog("host=h")  # the audit sink has no pool


def test_a_malformed_dsn_names_the_variable_and_leaks_no_password():
    with pytest.raises(ValueError, match="AIRLOCK_STORE_DSN") as e:
        PostgresStore("host=h password=se cret port")
    assert "cret" not in str(e.value)
    with pytest.raises(ValueError, match="AIRLOCK_AUDIT_DSN"):
        PostgresAuditLog("host=h port")


# ------------------------------------------------------------------ black hole
@pytest.fixture
def black_hole():
    """A listener that completes the TCP handshake (backlog) and never answers."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    yield f"postgresql://u@127.0.0.1:{s.getsockname()[1]}/d?sslmode=disable"
    s.close()


async def test_store_fails_within_the_timeout(black_hole, monkeypatch):
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "1")
    store = PostgresStore(black_hole)
    try:
        t = time.monotonic()
        with pytest.raises(psycopg.OperationalError):  # PoolTimeout is one
            await store.ping()
        assert time.monotonic() - t < 5
    finally:
        await store.aclose()


def test_audit_sink_fails_within_the_timeout(black_hole, monkeypatch):
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "1")
    sink = PostgresAuditLog(black_hole)
    t = time.monotonic()
    with pytest.raises(Exception, match="timeout|timed out"):
        sink._connect()
    assert time.monotonic() - t < 5


async def test_readyz_is_503_on_a_black_hole_and_leaves_no_noise(upstream, audit_path, black_hole, monkeypatch, caplog):
    monkeypatch.setattr(app_mod, "READY_TIMEOUT_S", 0.2)
    monkeypatch.setenv("AIRLOCK_STORE_CONNECT_TIMEOUT", "1")
    store = PostgresStore(black_hole)
    try:
        async with proxy_client(make_airlock(upstream, audit_path, store=store)) as c:
            t = time.monotonic()
            assert (await c.get("/readyz")).status_code == 503
            assert time.monotonic() - t < 1
            assert (await c.get("/readyz")).status_code == 503  # while the first ping still waits
    finally:
        await store.aclose()
    await asyncio.sleep(0)
    gc.collect()
    assert "never retrieved" not in caplog.text and black_hole not in caplog.text


# ------------------------------------------------------------------ the pool, with a fake
class FakePool:
    instances: list = []

    def __init__(self, dsn, **kw):
        self.dsn, self.kw = dsn, kw
        self.opened = self.closed = 0
        self.entered = 0
        FakePool.instances.append(self)

    check_connection = staticmethod(lambda conn: None)

    async def open(self, wait=True):
        await asyncio.sleep(0)  # a yield point, so concurrent first calls really race
        self.opened += 1

    async def close(self):
        self.closed += 1

    @asynccontextmanager
    async def connection(self):
        self.entered += 1
        yield FakeConn()


class FakeConn:
    async def execute(self, *a, **kw):
        return self

    @asynccontextmanager
    async def transaction(self):
        yield


@pytest.fixture
def fake_pool(monkeypatch):
    FakePool.instances = []
    monkeypatch.setattr(psycopg_pool, "AsyncConnectionPool", FakePool)
    return FakePool


async def test_nothing_opens_at_construction(fake_pool):
    PostgresStore("host=h")
    assert fake_pool.instances == []


async def test_concurrent_calls_share_one_pool(fake_pool):
    store = PostgresStore("host=h")
    await asyncio.gather(*(store.ping() for _ in range(10)))
    (pool,) = fake_pool.instances
    assert pool.opened == 1 and pool.entered == 10
    kw = pool.kw
    assert kw["max_size"] == 4 and kw["min_size"] == 1 and kw["open"] is False
    assert kw["kwargs"] == {"autocommit": True, "prepare_threshold": None}
    assert kw["timeout"] == 10.0 and kw["check"] is not None
    assert conninfo_to_dict(pool.dsn)["connect_timeout"] == "10"


async def test_pool_size_comes_from_the_environment(fake_pool, monkeypatch):
    monkeypatch.setenv("AIRLOCK_STORE_POOL_SIZE", "7")
    await PostgresStore("host=h").ping()
    assert fake_pool.instances[0].kw["max_size"] == 7
    await PostgresStore("host=h", pool_size=2).ping()
    assert fake_pool.instances[1].kw["max_size"] == 2


async def test_aclose_closes_is_idempotent_and_a_later_call_reopens(fake_pool):
    store = PostgresStore("host=h")
    await store.aclose()  # never opened: nothing to do
    await store.ping()
    await store.aclose()
    await store.aclose()
    assert fake_pool.instances[0].closed == 1
    await store.ping()
    assert len(fake_pool.instances) == 2 and fake_pool.instances[1].opened == 1


# ------------------------------------------------------------------ shutdown
def policy():
    return Policy.load(ROOT / "policy.example.yaml", "prod")


async def test_shutdown_closes_the_store_pool_and_the_audit(fake_pool):
    store, sink = PostgresStore("host=h"), Sink()
    al = Airlock(policy(), "http://upstream/mcp", sink, store=store)
    await store.ping()
    await run_lifespan(al)
    assert fake_pool.instances[0].closed == 1 and sink.closed == 1
    await al.http.aclose()


async def test_store_is_closed_even_when_closing_the_client_fails(fake_pool):
    store, sink = PostgresStore("host=h"), Sink()
    al = Airlock(policy(), "http://upstream/mcp", sink, store=store)
    await store.ping()

    async def boom():
        raise RuntimeError("close failed")

    al.http.aclose = boom
    with pytest.raises(RuntimeError):
        await run_lifespan(al)
    assert fake_pool.instances[0].closed == 1 and sink.closed == 1


async def test_audit_is_closed_even_when_closing_the_store_fails():
    class BadStore(MemoryStore):
        async def aclose(self):
            raise RuntimeError("store close failed")

    sink = Sink()
    al = Airlock(policy(), "http://upstream/mcp", sink, store=BadStore())
    with pytest.raises(RuntimeError):
        await run_lifespan(al)
    assert sink.closed == 1
    await al.http.aclose()


async def test_an_injected_store_without_aclose_is_fine(tmp_path):
    class Bare:
        pass

    al = Airlock(policy(), "http://upstream/mcp", AuditLog(tmp_path / "a.jsonl"), store=Bare())
    await run_lifespan(al)


async def test_memory_store_shutdown_is_unchanged(tmp_path):
    al = Airlock(policy(), "http://upstream/mcp", AuditLog(tmp_path / "a.jsonl"), store=MemoryStore())
    await run_lifespan(al)
    assert al.http.is_closed


# ------------------------------------------------------------------ real Postgres
needs_pg = pytest.mark.skipif(not PG, reason="AIRLOCK_TEST_PG_DSN not set")


def backends(app_name):
    with psycopg.connect(PG, autocommit=True) as c:
        return c.execute("SELECT pid FROM pg_stat_activity WHERE application_name = %s", (app_name,)).fetchall()


@needs_pg
async def test_concurrent_calls_share_the_pool():
    app = f"airlock-pool-{uuid.uuid4().hex[:8]}"
    store = PostgresStore(make_conninfo(PG, application_name=app), pool_size=2)
    try:
        exp = time.time() + 60
        res = await asyncio.gather(*(store.consume_once(uuid.uuid4().hex, exp) for _ in range(20)))
        assert all(res)
        assert len(backends(app)) <= 2
        assert store._pool.get_stats()["connections_num"] <= 2
    finally:
        await store.aclose()


@needs_pg
async def test_a_killed_backend_is_replaced():
    app = f"airlock-kill-{uuid.uuid4().hex[:8]}"
    store = PostgresStore(make_conninfo(PG, application_name=app), pool_size=2)
    try:
        await store.ping()
        pids = [r[0] for r in backends(app)]
        assert pids
        with psycopg.connect(PG, autocommit=True) as c:
            for pid in pids:
                c.execute("SELECT pg_terminate_backend(%s)", (pid,))
        await store.ping()  # check_connection drops the dead connection
    finally:
        await store.aclose()


@needs_pg
async def test_shutdown_closes_the_real_pool(tmp_path):
    app = f"airlock-close-{uuid.uuid4().hex[:8]}"
    store = PostgresStore(make_conninfo(PG, application_name=app), pool_size=2)
    al = Airlock(policy(), "http://upstream/mcp", AuditLog(tmp_path / "a.jsonl"), store=store)
    await store.ping()
    assert backends(app)
    await run_lifespan(al)
    for _ in range(20):  # the server notices the close a moment later
        if not backends(app):
            break
        await asyncio.sleep(0.1)
    assert not backends(app)
    await al.http.aclose()


# ------------------------------------------------------------------ startup
@pytest.mark.parametrize("env", [
    {"AIRLOCK_STORE_DSN": "postgresql://u@127.0.0.1:1/d", "AIRLOCK_STORE_CONNECT_TIMEOUT": "abc"},
    {"AIRLOCK_STORE_DSN": "postgresql://u@127.0.0.1:1/d", "AIRLOCK_STORE_POOL_SIZE": "0"},
    {"AIRLOCK_STORE_DSN": "host=h port"}])
def test_a_bad_store_setting_exits_with_a_message_not_a_traceback(env, tmp_path):
    clean = {k: v for k, v in os.environ.items() if not k.startswith("AIRLOCK_")}
    r = subprocess.run([sys.executable, "-m", "mcp_airlock", "--policy", str(ROOT / "examples/policies/github.yaml"),
                        "--upstream", "http://127.0.0.1:9/mcp", "--audit", str(tmp_path / "audit.jsonl")],
                       capture_output=True, text=True, timeout=30, cwd=tmp_path, env={**clean, **env})
    assert r.returncode != 0
    assert r.stderr.strip().splitlines()[-1].startswith("mcp-airlock:") and "Traceback" not in r.stderr
