"""psycopg is an optional dependency: `pip install 'mcp-airlock[postgres]'`."""
from __future__ import annotations


def psycopg_module():
    try:
        import psycopg
    except ImportError:
        raise RuntimeError("a Postgres DSN is set but psycopg is not installed: "
                           "install it with: pip install 'mcp-airlock[postgres]'") from None
    return psycopg
