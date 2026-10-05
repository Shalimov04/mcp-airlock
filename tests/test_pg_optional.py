"""psycopg is an optional extra: without it a DSN fails at startup with the install hint."""
import sys

import pytest

from mcp_airlock.audit import PostgresAuditLog
from mcp_airlock.audit_cli import query_pg
from mcp_airlock.store import PostgresStore, store_from_env


@pytest.fixture
def no_psycopg(monkeypatch):
    monkeypatch.setitem(sys.modules, "psycopg", None)  # makes `import psycopg` raise ImportError


def test_store_without_psycopg_names_the_extra(no_psycopg, monkeypatch):
    monkeypatch.setenv("AIRLOCK_STORE_DSN", "postgresql://x/y")
    with pytest.raises(RuntimeError, match=r"mcp-airlock\[postgres\]"):
        store_from_env()
    with pytest.raises(RuntimeError, match=r"mcp-airlock\[postgres\]"):
        PostgresStore("postgresql://x/y")


def test_audit_sink_without_psycopg_names_the_extra(no_psycopg):
    with pytest.raises(RuntimeError, match=r"mcp-airlock\[postgres\]"):
        PostgresAuditLog("postgresql://x/y")


def test_audit_query_without_psycopg_names_the_extra(no_psycopg):
    with pytest.raises(RuntimeError, match=r"mcp-airlock\[postgres\]"):
        query_pg("postgresql://x/y", {}, None, None)


def test_memory_store_needs_no_psycopg(no_psycopg, monkeypatch):
    monkeypatch.delenv("AIRLOCK_STORE_DSN", raising=False)
    assert store_from_env() is not None


def test_store_without_psycopg_pool_names_the_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "psycopg_pool", None)
    with pytest.raises(RuntimeError, match=r"mcp-airlock\[postgres\]"):
        PostgresStore("postgresql://x/y")
    PostgresAuditLog("postgresql://x/y")  # the audit sink does not use the pool
    monkeypatch.delenv("AIRLOCK_STORE_DSN", raising=False)
    assert store_from_env() is not None
