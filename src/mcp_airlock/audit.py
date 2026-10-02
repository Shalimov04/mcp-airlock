"""Append-only audit. Two records per call: `intent` before upstream, `outcome` after.
Sinks: JSONL file (always), Postgres table `airlock_audit` (when AIRLOCK_AUDIT_DSN is set).
Every record carries `prev` and `hash`, a sha256 chain over the records of one sink."""

from __future__ import annotations

import hashlib
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
          "tier", "dry_run", "latency_ms", "upstream_status", "trace_id", "detail", "prev", "hash")
GENESIS = "0" * 64  # `prev` of the first record ever written


# The JWT alternative starts only at a token boundary: tried at every "ey" inside one run of identifier characters it
# rescans the run each time, quadratic on client-chosen text such as a method name in a protocol deny.
_SECRET_INLINE = re.compile(r"(Bearer\s+[A-Za-z0-9._~+/=-]+|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|(?<![A-Za-z0-9_-])ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)")


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


def _clean_detail(value: Any, key: str = "") -> Any:
    """`detail` carries upstream error text: same key and value rules as args, then inline credentials in every string."""
    if isinstance(value, (dict, list, tuple)):
        if _SECRET_KEY.search(key):
            return REDACTED
        if isinstance(value, dict):
            return {k: _clean_detail(v, str(k)) for k, v in value.items()}
        return [_clean_detail(v, key) for v in value]
    if isinstance(value, (int, float)):  # counts such as est_tokens match the key rule but are not secrets
        return value
    if value is not None and not isinstance(value, str):
        value = str(value)  # what _dumps(default=str) would write later; scrub that text, not the object
    value = redact(value, key)
    return scrub(value) if isinstance(value, str) else value


def _row(rec: dict[str, Any]) -> dict[str, Any]:
    row = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}
    row.update({k: rec.get(k) for k in FIELDS})
    row["args"] = redact(row["args"]) if row["args"] is not None else None
    row["detail"] = _clean_detail(row["detail"])
    return row


def _dumps(row: dict[str, Any]) -> str:
    return json.dumps(row, ensure_ascii=False, default=str)


def row_hash(row: dict[str, Any]) -> str:
    """sha256 of the canonical JSON of the row with `prev` and without `hash`. The writer and `airlock-audit verify` both call this."""
    body = {k: v for k, v in row.items() if k != "hash"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def seal(row: dict[str, Any], prev: str) -> None:
    row["prev"] = prev
    row["hash"] = row_hash(row)


def _hash_of(line: bytes) -> str | None:
    try:
        h = json.loads(line).get("hash")
    except (ValueError, AttributeError):  # torn or not a record
        return None
    return h if isinstance(h, str) and h else None


def _lines(buf: bytes) -> list[bytes]:
    return [ln for ln in buf.split(b"\n") if ln.strip()]  # blank lines are skipped the way verify skips them


def _last_hash(path: Path) -> str | None:
    """`hash` of the last non-blank line of an existing file, read from the end; None when there is none.
    A torn last line (a crash or a short write left it without its newline) counts for nothing: the line before it is used."""
    try:
        with path.open("rb") as f:
            buf, pos = b"", f.seek(0, os.SEEK_END)
            while pos > 0 and len(_lines(buf)) < 3:  # the last two lines whole: the first one in the buffer may be cut
                step = min(65536, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
    except OSError:  # missing or unreadable
        return None
    lines = _lines(buf)
    if lines and not buf.endswith(b"\n") and _hash_of(lines[-1]) is None:
        lines.pop()
    return _hash_of(lines[-1]) if lines else None


def _ends_with_newline(path: Path) -> bool:
    with path.open("rb") as f:
        f.seek(-1, os.SEEK_END)
        return f.read(1) == b"\n"


class AuditLog:
    FIELDS = FIELDS

    def __init__(self, path: str | Path, max_bytes: int | None = None, keep: int = 5):
        if keep < 1 or (max_bytes or 0) < 0:
            raise ValueError("audit keep must be at least 1 and max_bytes must not be negative")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes, self.keep = max_bytes or None, keep
        # no hash in the live file (missing, empty, or only a torn line): a crash between the rotation rename and the
        # first write, so the chain goes on from .1; a live file of unchained records next to no .1 starts at GENESIS
        self._last = _last_hash(self.path) or _last_hash(self.path.with_name(self.path.name + ".1")) or GENESIS
        self._f = self.path.open("ab", buffering=0)  # unbuffered: a failed write holds nothing back for a later record
        self._size = self.path.stat().st_size
        self._torn = self._size > 0 and not _ends_with_newline(self.path)  # a crash left a line without its newline
        self._lock = threading.Lock()

    def write(self, **rec: Any) -> None:
        self.write_row(_row(rec))

    def write_row(self, row: dict[str, Any]) -> None:
        """Chains the row (sets prev and hash in place, so another sink stores the same values) and appends it."""
        with self._lock:  # ponytail: one sync write per record; batch if audit I/O ever shows in a profile
            seal(row, self._last)
            data = (_dumps(row) + "\n").encode("utf-8")
            if self._torn:  # the torn line gets its newline first, so this record starts a line of its own
                if self._f.write(b"\n") != 1:
                    raise OSError(f"short write to {self.path}")
                self._size, self._torn = self._size + 1, False
            if self.max_bytes and self._size and self._size + len(data) > self.max_bytes:
                self._rotate()
            if (n := self._f.write(data)) != len(data):  # a full disk: the torn line stays as it is, the record is not chained
                self._size, self._torn = self._size + n, n > 0
                raise OSError(f"short write to {self.path}")
            self._size += len(data)
            self._last = row["hash"]

    def _rotate(self) -> None:
        """audit.jsonl -> .1 -> .2 ... up to .keep; the oldest is overwritten."""
        self._f.close()
        try:
            for n in range(self.keep, 0, -1):
                src = self.path if n == 1 else self.path.with_name(f"{self.path.name}.{n - 1}")
                if src.exists():  # replacing .keep is what deletes the oldest file
                    os.replace(src, self.path.with_name(f"{self.path.name}.{n}"))
            n = self.keep + 1  # left by an earlier run with a bigger keep; the chain no longer reaches them
            while (stale := self.path.with_name(f"{self.path.name}.{n}")).exists():
                stale.unlink()
                n += 1
        finally:  # a failed rename leaves the sink writable; the next write tries again
            self._f = self.path.open("ab", buffering=0)
            self._size = self.path.stat().st_size

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
        self._last: str | None = None  # read from the newest row at the first connect, only when this sink has to chain

    def _connect(self):
        import psycopg  # deferred: JSONL-only deployments never import it
        conn = psycopg.connect(self.dsn, autocommit=True)
        conn.execute(self.DDL)
        return conn

    def _insert(self, row: dict[str, Any]) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = self._connect()
        if row["hash"] is None:  # not chained by a file sink: continue this table's own chain
            if self._last is None:
                newest = self._conn.execute("SELECT rec->>'hash' FROM airlock_audit ORDER BY ts DESC, ctid DESC LIMIT 1").fetchone()
                self._last = newest[0] if newest and newest[0] else GENESIS
            seal(row, self._last)
        self._conn.execute(self._INSERT, (row["ts"], *(row[c] for c in self._COLS), _dumps(row)))
        self._last = row["hash"]

    def write(self, **rec: Any) -> None:
        self.write_row(_row(rec))

    def write_row(self, row: dict[str, Any]) -> None:
        import psycopg
        with self._lock:  # ponytail: one sync connection blocks the loop ~1ms per record; async pool when it shows in latency
            try:
                self._insert(row)
            except psycopg.OperationalError:  # dropped connection: reconnect once, then let it raise
                self._conn = None
                self._insert(row)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()


class MultiAudit:
    """Fan out to every sink; a failing sink is logged and never blocks the others."""

    def __init__(self, *sinks: Any):
        self.sinks = sinks

    def write(self, **rec: Any) -> None:
        row = _row(rec)  # built once: the sinks store the same ts, prev and hash
        for s in self.sinks:
            try:
                if hasattr(s, "write_row"):
                    s.write_row(row)
                else:
                    s.write(**rec)
            except Exception:
                log.exception("audit sink %s failed", type(s).__name__)

    def close(self) -> None:
        for s in self.sinks:
            s.close()


def audit_from_env(jsonl_path: str | Path, max_bytes: int | None = None, keep: int = 5) -> AuditLog | MultiAudit:
    dsn = os.environ.get("AIRLOCK_AUDIT_DSN")
    file_sink = AuditLog(jsonl_path, max_bytes, keep)
    return MultiAudit(file_sink, PostgresAuditLog(dsn)) if dsn else file_sink
