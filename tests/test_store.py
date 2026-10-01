from __future__ import annotations

import asyncio
import os
import time
import uuid

import pytest

from mcp_airlock.store import MemoryStore, PostgresStore, store_from_env

PG_DSN = os.environ.get("AIRLOCK_TEST_PG_DSN")


@pytest.fixture(params=["memory", "postgres"])
async def store(request):
    if request.param == "memory":
        return MemoryStore()
    if not PG_DSN:
        pytest.skip("AIRLOCK_TEST_PG_DSN not set")
    s = PostgresStore(PG_DSN)
    async with s._conn() as c:  # creates the tables; DB is shared, touch only ours
        await c.execute("TRUNCATE airlock_keys, airlock_prompts, airlock_usage")
    return s


def key() -> str:
    return uuid.uuid4().hex


async def test_consume_once_exactly_once_under_concurrency(store):
    k, exp = key(), time.time() + 60
    results = await asyncio.gather(*(store.consume_once(k, exp) for _ in range(25)))
    assert results.count(True) == 1
    assert await store.consume_once(k, exp) is False
    assert await store.consume_once(key(), exp) is True  # other keys unaffected


async def test_approve_then_consume(store):
    k, exp = key(), time.time() + 60
    assert await store.is_approved(k) is False
    await store.approve(k, exp)
    await store.approve(k, exp)  # idempotent
    assert await store.is_approved(k) is True
    assert await store.consume_once(k, exp) is True  # approval does not burn the key
    assert await store.consume_once(k, exp) is False


async def test_approve_expired(store):
    k = key()
    await store.approve(k, time.time() - 1)
    assert await store.is_approved(k) is False


async def test_prompt_roundtrip_and_overwrite(store):
    k, exp = key(), time.time() + 60
    assert await store.get_prompt(k) is None
    await store.save_prompt(k, "first", exp)
    assert await store.get_prompt(k) == "first"
    await store.save_prompt(k, "second", exp)  # same key: the later text wins
    assert await store.get_prompt(k) == "second"
    assert await store.get_prompt(key()) is None  # other keys unaffected


async def test_prompt_expired_is_not_served(store):
    k = key()
    await store.save_prompt(k, "gone", time.time() - 1)
    assert await store.get_prompt(k) is None


async def test_prompt_expired_rows_are_deleted_on_write(store):
    old, new = key(), key()
    await store.save_prompt(old, "gone", time.time() - 1)
    await store.save_prompt(new, "kept", time.time() + 60)
    assert await store.get_prompt(new) == "kept"
    if isinstance(store, MemoryStore):
        assert old not in store._prompts
    else:
        async with store._conn() as c:
            cur = await c.execute("SELECT 1 FROM airlock_prompts WHERE key = %s", (old,))
            assert await cur.fetchone() is None


async def test_usage_sum_honours_since_and_separates_keys(store):
    now = time.time()
    await store.usage_add("alice", "delete", 3, now - 100)
    await store.usage_add("alice", "delete", 2, now - 10)
    await store.usage_add("bob", "delete", 5, now - 10)
    await store.usage_add("alice", "update", 7, now - 10)
    assert await store.usage_sum("alice", "delete", now - 200) == 5
    assert await store.usage_sum("alice", "delete", now - 50) == 2
    assert await store.usage_sum("alice", "delete", now + 1) == 0
    assert await store.usage_sum("bob", "delete", now - 200) == 5
    assert await store.usage_sum("alice", "update", now - 200) == 7
    assert await store.usage_sum("carol", "delete", 0) == 0


async def test_memory_store_purges_expired_on_write():
    s = MemoryStore()
    now = time.time()
    await s.consume_once("old", now - 1)
    await s.approve("old", now - 1)
    await s.save_prompt("old", "x", now - 1)
    await s.usage_add("a", "t", 1, now - 10 * 86400)
    await s.consume_once("new", now + 60)
    await s.approve("new", now + 60)
    await s.save_prompt("new", "x", now + 60)
    await s.usage_add("a", "t", 1, now)
    assert "old" not in s._consumed and "old" not in s._approved and "old" not in s._prompts
    assert len(s._usage[("a", "t")]) == 1


def test_store_from_env(monkeypatch):
    monkeypatch.delenv("AIRLOCK_STORE_DSN", raising=False)
    assert type(store_from_env()) is MemoryStore
    monkeypatch.setenv("AIRLOCK_STORE_DSN", "postgresql://x@localhost/y")
    s = store_from_env()
    assert type(s) is PostgresStore and s.dsn == "postgresql://x@localhost/y"
