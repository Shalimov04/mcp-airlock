"""Shared state for >1 replica: MRTR idempotency keys + blast-radius usage windows.

All timestamps are wall-clock ``time.time()`` floats supplied by the caller.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager

import psycopg

# ponytail: usage rows older than a day are garbage; raise if a policy ever uses window_s > 86400.
USAGE_RETENTION_S = 86400


class MemoryStore:
    """Single-process default. Writes purge expired entries so memory stays bounded."""

    def __init__(self) -> None:
        self._consumed: dict[str, float] = {}
        self._approved: dict[str, float] = {}
        self._usage: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)

    def _purge_keys(self) -> None:
        now = time.time()
        self._consumed = {k: e for k, e in self._consumed.items() if e >= now}
        self._approved = {k: e for k, e in self._approved.items() if e >= now}

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
CREATE TABLE IF NOT EXISTS airlock_usage (
    principal text NOT NULL,
    tool text NOT NULL,
    n integer NOT NULL,
    ts double precision NOT NULL
);
CREATE INDEX IF NOT EXISTS airlock_usage_pt_ts ON airlock_usage (principal, tool, ts);
"""
_DDL_LOCK = 0x41524C4B  # 'ARLK': serialises first-use DDL across replicas


class PostgresStore:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self._ready = False

    @asynccontextmanager
    async def _conn(self):
        # ponytail: one connection per call, no pool; add psycopg_pool when p99 latency says so.
        async with await psycopg.AsyncConnection.connect(self.dsn, autocommit=True) as c:
            if not self._ready:
                async with c.transaction():
                    await c.execute("SELECT pg_advisory_xact_lock(%s)", (_DDL_LOCK,))
                    await c.execute(_DDL)
                self._ready = True
            yield c

    async def consume_once(self, key: str, exp_ts: float) -> bool:
        async with self._conn() as c:
            await c.execute("DELETE FROM airlock_keys WHERE exp_ts < %s", (time.time(),))
            cur = await c.execute(
                "INSERT INTO airlock_keys (key, exp_ts, consumed) VALUES (%s, %s, true) "
                "ON CONFLICT (key) DO UPDATE SET consumed = true WHERE NOT airlock_keys.consumed "
                "RETURNING key",
                (key, exp_ts),
            )
            return await cur.fetchone() is not None

    async def is_consumed(self, key: str) -> bool:
        async with self._conn() as c:
            cur = await c.execute("SELECT 1 FROM airlock_keys WHERE key = %s AND consumed", (key,))
            return await cur.fetchone() is not None

    async def approve(self, key: str, exp_ts: float) -> None:
        async with self._conn() as c:
            await c.execute("DELETE FROM airlock_keys WHERE exp_ts < %s", (time.time(),))
            await c.execute(
                "INSERT INTO airlock_keys (key, exp_ts, approved) VALUES (%s, %s, true) "
                "ON CONFLICT (key) DO UPDATE SET approved = true",
                (key, exp_ts),
            )

    async def is_approved(self, key: str) -> bool:
        async with self._conn() as c:
            cur = await c.execute("SELECT 1 FROM airlock_keys WHERE key = %s AND approved AND exp_ts >= %s",
                                  (key, time.time()))
            return await cur.fetchone() is not None

    async def usage_add(self, principal: str, tool: str, n: int, ts: float) -> None:
        async with self._conn() as c:
            await c.execute("DELETE FROM airlock_usage WHERE ts < %s", (ts - USAGE_RETENTION_S,))
            await c.execute("INSERT INTO airlock_usage (principal, tool, n, ts) VALUES (%s, %s, %s, %s)",
                            (principal, tool, n, ts))

    async def usage_reserve(self, principal: str, tool: str, n: int, ts: float, since_ts: float, limit: int) -> bool:
        """Atomically add n if the window total stays <= limit. Advisory lock per (principal, tool) serialises replicas."""
        async with self._conn() as c:
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

    async def usage_sum(self, principal: str, tool: str, since_ts: float) -> int:
        async with self._conn() as c:
            cur = await c.execute(
                "SELECT COALESCE(SUM(n), 0) FROM airlock_usage WHERE principal = %s AND tool = %s AND ts >= %s",
                (principal, tool, since_ts))
            return int((await cur.fetchone())[0])


def store_from_env() -> MemoryStore | PostgresStore:
    dsn = os.environ.get("AIRLOCK_STORE_DSN")
    return PostgresStore(dsn) if dsn else MemoryStore()
