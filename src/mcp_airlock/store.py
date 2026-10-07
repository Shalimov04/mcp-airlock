"""Shared state for >1 replica: MRTR idempotency keys + blast-radius usage windows.

All timestamps are wall-clock ``time.time()`` floats supplied by the caller.
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
from collections import defaultdict
from contextlib import asynccontextmanager

from .pg import (DEFAULT_POOL_SIZE, effective_connect_timeout, positive_int_env, psycopg_module,
                 psycopg_pool_module, with_conn_defaults)

log = logging.getLogger("mcp_airlock.store")

# ponytail: usage rows older than a day are garbage; raise if a policy ever uses window_s > 86400.
USAGE_RETENTION_S = 86400


class MemoryStore:
    """Single-process default. Writes purge expired entries so memory stays bounded."""

    def __init__(self) -> None:
        self._consumed: dict[str, float] = {}
        self._approved: dict[str, float] = {}
        self._prompts: dict[str, tuple[float, str]] = {}
        self._usage: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)

    def _purge_keys(self) -> None:
        now = time.time()
        self._consumed = {k: e for k, e in self._consumed.items() if e >= now}
        self._approved = {k: e for k, e in self._approved.items() if e >= now}
        self._prompts = {k: v for k, v in self._prompts.items() if v[0] >= now}

    async def ping(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    async def consume_once(self, key: str, exp_ts: float) -> bool:
        self._purge_keys()  # no await between check and set, so atomic under asyncio
        if key in self._consumed:
            return False
        self._consumed[key] = exp_ts
        return True

    async def is_consumed(self, key: str) -> bool:
        return key in self._consumed

    async def approve(self, key: str, exp_ts: float) -> None:
        self._purge_keys()
        self._approved[key] = exp_ts

    async def is_approved(self, key: str) -> bool:
        return self._approved.get(key, 0.0) >= time.time()

    async def save_prompt(self, key: str, text: str, exp_ts: float) -> None:
        self._purge_keys()
        self._prompts[key] = (exp_ts, text)

    async def get_prompt(self, key: str) -> str | None:
        exp_ts, text = self._prompts.get(key, (0.0, ""))
        return text if exp_ts >= time.time() else None

    async def usage_add(self, principal: str, tool: str, n: int, ts: float) -> None:
        cutoff = ts - USAGE_RETENTION_S
        q = [(t, m) for t, m in self._usage[(principal, tool)] if t >= cutoff]
        q.append((ts, n))
        self._usage[(principal, tool)] = q

    async def usage_reserve(self, principal: str, tool: str, n: int, ts: float, since_ts: float, limit: int) -> bool:
        # No await between check and add: atomic within one event loop (the only scope MemoryStore promises).
        if await self.usage_sum(principal, tool, since_ts) + n > limit:
            return False
        await self.usage_add(principal, tool, n, ts)
        return True

    async def usage_sum(self, principal: str, tool: str, since_ts: float) -> int:
        return sum(m for t, m in self._usage.get((principal, tool), ()) if t >= since_ts)


_DDL = """
CREATE TABLE IF NOT EXISTS airlock_keys (
    key text PRIMARY KEY,
    exp_ts double precision NOT NULL,
    consumed boolean NOT NULL DEFAULT false,
    approved boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS airlock_prompts (
    key text PRIMARY KEY,
    exp_ts double precision NOT NULL,
    text text NOT NULL
);
CREATE TABLE IF NOT EXISTS airlock_usage (
    principal text NOT NULL,
    tool text NOT NULL,
    n integer NOT NULL,
    ts double precision NOT NULL
);
CREATE INDEX IF NOT EXISTS airlock_usage_pt_ts ON airlock_usage (principal, tool, ts);
"""
_DDL_LOCK = 0x41524C4B  # 'ARLK': serialises first-use DDL across replicas
_TABLES = ("airlock_keys", "airlock_prompts", "airlock_usage")
# The server-side timeouts end this much before the client deadline, so a slow statement normally fails with a
# clean server error on a connection that stays usable; the cut is for a server that does not answer at all.
_SERVER_HEAD_START_S = 0.2
# How long aclose() waits for cancel requests still in flight: one normally takes a round trip, and one to a server
# that does not answer is not worth holding a shutdown for.
_CANCEL_DRAIN_S = 1.0


def _cut(conn, cancel_timeout: float, fired: list, cancels: set) -> None:
    """Cut the socket so the pending call fails now, and ask the server to drop the work.

    Shutting our end alone leaves the backend where it was: one waiting on a lock does not notice a gone client,
    and every cut used to leave one more backend behind until max_connections was exhausted. The cancel request
    goes over a connection of its own, so it is sent after the cut and bounded by its own timeout."""
    try:
        with socket.socket(fileno=os.dup(conn.pgconn.socket)) as s:  # a dup: the libpq fd stays open
            s.shutdown(socket.SHUT_RDWR)
    except Exception:  # already closed: nothing is waiting on it
        pass
    fired.append(True)
    if psycopg_module().capabilities.has_cancel_safe():  # older libpq cancels in a blocking thread: not worth a hang
        # Its first step, which copies the cancel key, runs before the waiter sees the cut and the pool drops the connection.
        task = asyncio.ensure_future(_cancel(conn, cancel_timeout))
        # The loop keeps only a weak reference to a task; the store holds it until it is done and drains the set at
        # shutdown, else a shutdown right after a cut logs "Task was destroyed but it is pending".
        cancels.add(task)
        task.add_done_callback(cancels.discard)


async def _cancel(conn, timeout: float) -> None:
    try:
        await conn.cancel_safe(timeout=timeout)
    except Exception as e:  # best effort: the server-side timeouts set at connect time are the backstop
        log.debug("cancel request after a store deadline failed: %s", type(e).__name__)


class PostgresStore:
    def __init__(self, dsn: str, pool_size: int | None = None) -> None:
        psycopg_module()  # fail at startup, not on the first request
        psycopg_pool_module()
        self.dsn = with_conn_defaults(dsn, "AIRLOCK_STORE_DSN")
        self.pool_size = pool_size or positive_int_env("AIRLOCK_STORE_POOL_SIZE", DEFAULT_POOL_SIZE)
        # libpq raises a connect timeout below 2 s to 2; the DSN may set a larger one than our default.
        self._wait_s = float(max(2, effective_connect_timeout(self.dsn)))
        self._closed = False
        self._pool = None
        self._pool_lock = asyncio.Lock()  # binds no loop at construction on 3.10+
        self._ready = False
        self._cancels: set = set()  # cancel requests in flight after a cut

    async def _open_pool(self):
        async with self._pool_lock:
            if self._pool is None:  # concurrent first calls create exactly one pool
                mod = psycopg_pool_module()
                pool = mod.AsyncConnectionPool(
                    self.dsn, min_size=1, max_size=self.pool_size,
                    open=False,  # opened below: psycopg_pool warns when an async pool opens in its constructor
                    name="airlock-store",
                    # Pooled connections live long enough to auto-prepare, which breaks PgBouncer in transaction mode.
                    kwargs={"autocommit": True, "prepare_threshold": None},
                    # A call waits for a connection no longer than a connect would take.
                    timeout=self._wait_s,
                    # Without this a failed grow attempt retries for 300 s with backoff and blocks new attempts,
                    # so calls keep timing out long after the database is back. Give up fast; the next call retries.
                    reconnect_timeout=self._wait_s,
                    # Drops connections killed by a restart or failover instead of failing a gated call.
                    check=self._check,
                    configure=self._configure)
                await pool.open(wait=False)  # the first call must not block on min_size beyond the timeout
                if self._closed:  # aclose() ran while we were opening and saw no pool to close
                    await pool.close()
                    raise RuntimeError("the Postgres store is closed")
                self._pool = pool
            return self._pool

    @asynccontextmanager
    async def _deadline(self, conn):
        """Cut the connection's socket if the work on it outlasts the wait. A frozen server still ACKs at the
        kernel, so keepalives and tcp_user_timeout never fire on a connection with nothing in flight, and
        cancelling the call would make psycopg wait on the same silent server. Shutting our end makes the pending
        call fail at once, and the pool discards the broken connection."""
        fired: list = []
        timer = asyncio.get_running_loop().call_later(self._wait_s, _cut, conn, self._wait_s, fired, self._cancels)
        try:
            yield
        finally:
            timer.cancel()
            if fired:
                # An answer that was already in the socket buffer can still be read after the cut, so the call may
                # even succeed; the connection is dead all the same and must not go back to the pool as healthy,
                # where its failed check would cost the next caller a backoff.
                await conn.close()

    async def _check(self, conn) -> None:
        # The pool's own check has no deadline.
        async with self._deadline(conn):
            await psycopg_pool_module().AsyncConnectionPool.check_connection(conn)
        if conn.closed:  # the cut crossed the answer: the pool must discard it, not hand it out closed
            raise psycopg_module().OperationalError("connection cut during the check")

    async def _configure(self, conn) -> None:
        """Once per new connection: the server gives a statement or a lock wait up just before the client would,
        so a backend never outlives the call it served. Session settings: PgBouncer in transaction mode leaves them
        on the server connection, where any other client of the same pool inherits them, and may hand this client
        a connection without them; the cancel on a cut covers the latter, the README asks for a role of our own."""
        ms = str(int((self._wait_s - _SERVER_HEAD_START_S) * 1000))
        async with self._deadline(conn):
            await conn.execute("SELECT set_config('statement_timeout', %s, false), set_config('lock_timeout', %s, false)",
                               (ms, ms))

    @asynccontextmanager
    async def _conn(self):
        # Never take a session-level advisory lock here: the connection goes back to the pool still holding it.
        if self._closed:  # a late request must not open a pool on a loop that is about to close
            raise RuntimeError("the Postgres store is closed")
        pool = self._pool or await self._open_pool()
        async with pool.connection() as c:
            async with self._deadline(c):
                if not self._ready:
                    async with c.transaction():
                        await c.execute("SELECT pg_advisory_xact_lock(%s)", (_DDL_LOCK,))
                        await c.execute(_DDL)
                    self._ready = True
                yield c

    async def _run(self, op):
        """Run op(conn). When a table is gone (the database was recreated empty), run the DDL again and retry once;
        the DDL used to run once per process, so every gated call failed until a restart."""
        try:
            async with self._conn() as c:
                return await op(c)
        except psycopg_module().errors.UndefinedTable:
            log.warning("a store table is missing: creating the tables again")
            self._ready = False
        async with self._conn() as c:
            return await op(c)

    async def aclose(self) -> None:
        self._closed = True
        pool, self._pool = self._pool, None  # idempotent
        if pool is not None:
            await pool.close()
        end = time.monotonic() + _CANCEL_DRAIN_S
        while self._cancels:  # a cut during the close adds more while we wait
            _, pending = await asyncio.wait(set(self._cancels), timeout=max(0.0, end - time.monotonic()))
            if pending and time.monotonic() >= end:
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                self._cancels.clear()

    async def ping(self) -> None:
        """Readiness: the database answers and the tables exist, else they are created again here, so /readyz
        heals the store or says 503 while it cannot be used."""
        async def op(c):
            cur = await c.execute("SELECT " + ", ".join(f"to_regclass('{t}')" for t in _TABLES))
            if None in await cur.fetchone():
                raise psycopg_module().errors.UndefinedTable("a store table is missing")
        await self._run(op)

    async def consume_once(self, key: str, exp_ts: float) -> bool:
        async def op(c):
            await c.execute("DELETE FROM airlock_keys WHERE exp_ts < %s", (time.time(),))
            cur = await c.execute(
                "INSERT INTO airlock_keys (key, exp_ts, consumed) VALUES (%s, %s, true) "
                "ON CONFLICT (key) DO UPDATE SET consumed = true WHERE NOT airlock_keys.consumed "
                "RETURNING key",
                (key, exp_ts),
            )
            return await cur.fetchone() is not None
        return await self._run(op)

    async def is_consumed(self, key: str) -> bool:
        async def op(c):
            cur = await c.execute("SELECT 1 FROM airlock_keys WHERE key = %s AND consumed", (key,))
            return await cur.fetchone() is not None
        return await self._run(op)

    async def approve(self, key: str, exp_ts: float) -> None:
        async def op(c):
            await c.execute("DELETE FROM airlock_keys WHERE exp_ts < %s", (time.time(),))
            await c.execute(
                "INSERT INTO airlock_keys (key, exp_ts, approved) VALUES (%s, %s, true) "
                "ON CONFLICT (key) DO UPDATE SET approved = true",
                (key, exp_ts),
            )
        await self._run(op)

    async def is_approved(self, key: str) -> bool:
        async def op(c):
            cur = await c.execute("SELECT 1 FROM airlock_keys WHERE key = %s AND approved AND exp_ts >= %s",
                                  (key, time.time()))
            return await cur.fetchone() is not None
        return await self._run(op)

    async def save_prompt(self, key: str, text: str, exp_ts: float) -> None:
        async def op(c):
            await c.execute("DELETE FROM airlock_prompts WHERE exp_ts < %s", (time.time(),))
            await c.execute(
                "INSERT INTO airlock_prompts (key, exp_ts, text) VALUES (%s, %s, %s) "
                "ON CONFLICT (key) DO UPDATE SET exp_ts = EXCLUDED.exp_ts, text = EXCLUDED.text",
                (key, exp_ts, text),
            )
        await self._run(op)

    async def get_prompt(self, key: str) -> str | None:
        async def op(c):
            cur = await c.execute("SELECT text FROM airlock_prompts WHERE key = %s AND exp_ts >= %s", (key, time.time()))
            row = await cur.fetchone()
            return row[0] if row else None
        return await self._run(op)

    async def usage_add(self, principal: str, tool: str, n: int, ts: float) -> None:
        async def op(c):
            await c.execute("DELETE FROM airlock_usage WHERE ts < %s", (ts - USAGE_RETENTION_S,))
            await c.execute("INSERT INTO airlock_usage (principal, tool, n, ts) VALUES (%s, %s, %s, %s)",
                            (principal, tool, n, ts))
        await self._run(op)

    async def usage_reserve(self, principal: str, tool: str, n: int, ts: float, since_ts: float, limit: int) -> bool:
        """Atomically add n if the window total stays <= limit. Advisory lock per (principal, tool) serialises replicas."""
        async def op(c):
            async with c.transaction():
                await c.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"{principal}/{tool}",))  # lock granularity only; a collision just serialises two pairs
                cur = await c.execute(
                    "SELECT COALESCE(SUM(n), 0) FROM airlock_usage WHERE principal = %s AND tool = %s AND ts >= %s",
                    (principal, tool, since_ts))
                if int((await cur.fetchone())[0]) + n > limit:
                    return False
                await c.execute("DELETE FROM airlock_usage WHERE ts < %s", (ts - USAGE_RETENTION_S,))
                await c.execute("INSERT INTO airlock_usage (principal, tool, n, ts) VALUES (%s, %s, %s, %s)",
                                (principal, tool, n, ts))
                return True
        return await self._run(op)

    async def usage_sum(self, principal: str, tool: str, since_ts: float) -> int:
        async def op(c):
            cur = await c.execute(
                "SELECT COALESCE(SUM(n), 0) FROM airlock_usage WHERE principal = %s AND tool = %s AND ts >= %s",
                (principal, tool, since_ts))
            return int((await cur.fetchone())[0])
        return await self._run(op)


def store_from_env() -> MemoryStore | PostgresStore:
    dsn = os.environ.get("AIRLOCK_STORE_DSN")
    return PostgresStore(dsn) if dsn else MemoryStore()
