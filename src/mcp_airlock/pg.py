"""psycopg is an optional dependency: `pip install 'mcp-airlock[postgres]'`."""
from __future__ import annotations

import os


def psycopg_module():
    try:
        import psycopg
    except ImportError:
        raise RuntimeError("a Postgres DSN is set but psycopg is not installed: "
                           "install it with: pip install 'mcp-airlock[postgres]'") from None
    return psycopg


def psycopg_pool_module():
    # Lazy: MemoryStore and the audit sink work without psycopg_pool.
    try:
        import psycopg_pool
    except ImportError:
        raise RuntimeError("a Postgres store DSN is set but psycopg_pool is not installed: "
                           "install it with: pip install 'mcp-airlock[postgres]'") from None
    return psycopg_pool


DEFAULT_CONNECT_TIMEOUT = 10  # seconds, AIRLOCK_STORE_CONNECT_TIMEOUT
DEFAULT_POOL_SIZE = 4  # AIRLOCK_STORE_POOL_SIZE
# A silent peer is dropped in about 25 s (10 + 3 * 5) instead of the kernel's ~15 min.
KEEPALIVES = {"keepalives": 1, "keepalives_idle": 10, "keepalives_interval": 5, "keepalives_count": 3}


MAX_CONNECT_TIMEOUT = 86400


def positive_int_env(name: str, default: int, maximum: int | None = None) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        n = 0
    if n <= 0 or (maximum is not None and n > maximum):
        limit = "a positive integer" if maximum is None else f"an integer from 1 to {maximum}"
        raise ValueError(f"{name} must be {limit}, got {raw!r}")
    return n


def connect_timeout_from_env() -> int:
    return positive_int_env(
        "AIRLOCK_STORE_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT,
        maximum=MAX_CONNECT_TIMEOUT)  # keeps tcp_user_timeout (ms) inside libpq's int


def with_conn_defaults(dsn: str, var: str) -> str:
    """Add connect_timeout, tcp_user_timeout and keepalives to a DSN that does not set them, so a black-holed or
    silent host fails in seconds instead of minutes. Each key is added only when the DSN lacks it, and a
    PGCONNECT_TIMEOUT in the environment is the operator's choice and is left alone."""
    timeout = connect_timeout_from_env()  # checked even when the DSN sets its own, so a bad value stops startup
    psycopg = psycopg_module()
    try:
        have = psycopg.conninfo.conninfo_to_dict(dsn)
    except psycopg.ProgrammingError:
        # Not libpq's message: for `password=se cret` it quotes a piece of the password.
        raise ValueError(f"{var} is not a valid Postgres connection string") from None
    if "service" in have:
        return dsn  # the service file is the operator's choice; our keys would override it
    add: dict = {}
    if not os.environ.get("PGCONNECT_TIMEOUT"):
        add["connect_timeout"] = timeout
    if psycopg.pq.version() >= 120000:  # an older libpq rejects the keyword
        add["tcp_user_timeout"] = effective_connect_timeout(dsn) * 1000  # follows the DSN's own timeout
    add.update(KEEPALIVES)
    add = {k: v for k, v in add.items() if k not in have}
    return psycopg.conninfo.make_conninfo(dsn, **add) if add else dsn


def effective_connect_timeout(dsn: str) -> int:
    """The connect timeout libpq will use for this DSN: its own key, else PGCONNECT_TIMEOUT, else ours."""
    have = psycopg_module().conninfo.conninfo_to_dict(dsn)
    for raw in (have.get("connect_timeout"), os.environ.get("PGCONNECT_TIMEOUT")):
        try:
            if raw and int(raw) > 0:
                return int(raw)
        except ValueError:
            pass  # libpq rejects junk at connect time; fall back to ours here
    return connect_timeout_from_env()  # also for connect_timeout=0 (unbounded in libpq): the pool wait needs a bound
