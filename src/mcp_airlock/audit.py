"""Append-only audit. Two records per call: `intent` before upstream, `outcome` after.
Sinks: JSONL file (always), Postgres table `airlock_audit` (when AIRLOCK_AUDIT_DSN is set)."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("mcp_airlock.audit")

_SECRET_KEY = re.compile(r"(password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key)", re.I)
_SECRET_VALUE = re.compile(r"^(Bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)$")
REDACTED = "[REDACTED]"
FIELDS = ("phase", "call_id", "principal", "method", "tool", "args", "verdict", "rule_id",
          "tier", "dry_run", "latency_ms", "upstream_status", "trace_id", "detail")


_SECRET_INLINE = re.compile(r"(Bearer\s+[A-Za-z0-9._~+/=-]+|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)")


def redact(value: Any, key: str = "") -> Any:
    """Structured redaction: anything under a secret-looking key, and any leaf that looks like a credential."""
    if _SECRET_KEY.search(key):
        return REDACTED  # the whole subtree: a dict under "credentials" is as secret as a string
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, key) for v in value]
    if isinstance(value, str) and _SECRET_VALUE.match(value):
        return REDACTED
    return value


def scrub(text: str) -> str:
    """Free-text redaction: credential-shaped substrings inside prose (previews, messages)."""
    return _SECRET_INLINE.sub(REDACTED, text)


def _row(rec: dict[str, Any]) -> dict[str, Any]:
    row = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}
    row.update({k: rec.get(k) for k in FIELDS})
    row["args"] = redact(row["args"]) if row["args"] is not None else None
    return row


def _dumps(row: dict[str, Any]) -> str:
    return json.dumps(row, ensure_ascii=False, default=str)


class AuditLog:
    FIELDS = FIELDS

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._f = self.path.open("a", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, **rec: Any) -> None:
        line = _dumps(_row(rec))
        with self._lock:  # ponytail: sync write+flush per record; batch if audit I/O ever shows in a profile
            self._f.write(line + "\n")
            self._f.flush()

    def close(self) -> None:
        self._f.close()


class PostgresAuditLog:
    """Same rows as AuditLog, one per INSERT. Indexed columns for querying + the full record as JSONB."""

    DDL = """CREATE TABLE IF NOT EXISTS airlock_audit (
        ts timestamptz NOT NULL, phase text, call_id text, principal text, method text, tool text, verdict text,
        rule_id text, tier text, dry_run boolean, latency_ms integer, upstream_status integer, trace_id text,
        rec jsonb NOT NULL)"""
    _COLS = ("phase", "call_id", "principal", "method", "tool", "verdict", "rule_id", "tier", "dry_run",
             "latency_ms", "upstream_status", "trace_id")
    _INSERT = (f"INSERT INTO airlock_audit (ts, {', '.join(_COLS)}, rec) "
               f"VALUES (%s::timestamptz, {', '.join('%s' for _ in _COLS)}, %s::jsonb)")

    def __init__(self, dsn: str):
        self.dsn = dsn
        self._conn = None
        self._lock = threading.Lock()

    def _connect(self):
        import psycopg  # deferred: JSONL-only deployments never import it
        conn = psycopg.connect(self.dsn, autocommit=True)
        conn.execute(self.DDL)
        return conn

    def _insert(self, params: tuple) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = self._connect()
        self._conn.execute(self._INSERT, params)

    def write(self, **rec: Any) -> None:
        import psycopg
        row = _row(rec)
        params = (row["ts"], *(row[c] for c in self._COLS), _dumps(row))
        with self._lock:  # ponytail: one sync connection blocks the loop ~1ms per record; async pool when it shows in latency
            try:
                self._insert(params)
            except psycopg.OperationalError:  # dropped connection: reconnect once, then let it raise
                self._conn = None
                self._insert(params)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()


class MultiAudit:
    """Fan out to every sink; a failing sink is logged and never blocks the others."""

    def __init__(self, *sinks: Any):
        self.sinks = sinks

    def write(self, **rec: Any) -> None:
        for s in self.sinks:
            try:
                s.write(**rec)
            except Exception:
                log.exception("audit sink %s failed", type(s).__name__)

    def close(self) -> None:
        for s in self.sinks:
            s.close()


def audit_from_env(jsonl_path: str | Path) -> AuditLog | MultiAudit:
    dsn = os.environ.get("AIRLOCK_AUDIT_DSN")
    return MultiAudit(AuditLog(jsonl_path), PostgresAuditLog(dsn)) if dsn else AuditLog(jsonl_path)
