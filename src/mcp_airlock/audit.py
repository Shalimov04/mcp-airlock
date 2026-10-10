"""Append-only audit. Two records per call: `intent` before upstream, `outcome` after.
Sinks: JSONL file (always), Postgres table `airlock_audit` (when AIRLOCK_AUDIT_DSN is set).
Every record carries `prev` and `hash`, a sha256 chain over the records of one sink."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import re
import socket
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple

from .pg import effective_connect_timeout, psycopg_module, with_conn_defaults

log = logging.getLogger("mcp_airlock.audit")

_SECRET_KEY = re.compile(r"(password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key)", re.I)
_SECRET_VALUE = re.compile(r"^(Bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)$")
REDACTED = "[REDACTED]"
FIELDS = ("phase", "call_id", "principal", "method", "tool", "args", "verdict", "rule_id",
          "tier", "dry_run", "latency_ms", "upstream_status", "trace_id", "detail", "prev", "hash")
GENESIS = "0" * 64  # `prev` of the first record ever written


# Every alternative starts only at a token boundary. Without one, "sk-" inside a hyphenated name (disk-cleanup-prod,
# task-scheduler) was redacted and approvers lost the target of the call. For the JWT one the boundary also keeps
# the scan linear: tried at every "ey" inside one run of identifier characters it rescanned the run each time.
# A literal backslash escape (the two characters \n in shell text) also ends a word: `echo\nsk-...`.
_ESC = r"(?<=\\[nrt])"
_B = r"(?:(?<![A-Za-z0-9])|" + _ESC + ")"
_SECRET_INLINE = re.compile(
    "(" + _B + r"Bearer\s+[A-Za-z0-9._~+/=-]+|" + _B + r"sk-[A-Za-z0-9_-]{8,}"
    "|" + _B + r"gh[pousr]_[A-Za-z0-9]{20,}|" + _B + r"AKIA[0-9A-Z]{16}"
    r"|(?:(?<![A-Za-z0-9_-])|" + _ESC + r")ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)")


def _map_items(d: dict, fn) -> dict:
    """Scrub the keys, and keep two keys that scrub to the same text apart (`#2`) so no argument disappears."""
    out: dict[Any, Any] = {}
    nxt: dict[Any, int] = {}  # next free suffix per scrubbed key: counting up from 2 for each key was quadratic
    for k, v in d.items():
        base = nk = scrub(k) if isinstance(k, str) else k
        if nk in out:
            n = nxt.get(base, 2)
            while (nk := f"{base}#{n}") in out:
                n += 1
            nxt[base] = n + 1
        out[nk] = fn(k, v)
    return out


def redact(value: Any, key: str = "") -> Any:
    """Structured redaction: anything under a secret-looking key, any leaf that looks like a credential, and
    credential-shaped substrings inside longer strings (a key pasted into a note or a command line), in keys too."""
    if _SECRET_KEY.search(key):
        return REDACTED  # the whole subtree: a dict under "credentials" is as secret as a string
    if isinstance(value, dict):
        return _map_items(value, lambda k, v: redact(v, str(k)))
    if isinstance(value, (list, tuple)):
        return [redact(v, key) for v in value]
    if isinstance(value, str):
        return REDACTED if _SECRET_VALUE.match(value) else scrub(value)
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
            return _map_items(value, lambda k, v: _clean_detail(v, str(k)))
        return [_clean_detail(v, key) for v in value]
    if isinstance(value, (int, float)):  # counts such as est_tokens match the key rule but are not secrets
        return value
    if value is not None and not isinstance(value, str):
        value = str(value)  # what _dumps(default=str) would write later; scrub that text, not the object
    return redact(value, key)


# NUL: the jsonb and text columns of the Postgres sink refuse it. A lone surrogate (JSON allows "\ud800"): not UTF-8.
_UNWRITABLE = re.compile("[\x00\ud800-\udfff]")


def wellformed(value: Any) -> Any:
    """Client text can hold what one of the sinks cannot write, which would fail the write and the hash. Replace
    NUL and lone surrogates with U+FFFD in every string and key, and spell NaN and the infinities (Python's parser
    takes them, RFC 8259 and jsonb do not) as strings, so both sinks hold the same valid JSON."""
    if isinstance(value, str):
        return _UNWRITABLE.sub("\ufffd", value)
    if isinstance(value, dict):
        return {wellformed(k): wellformed(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [wellformed(v) for v in value]
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return "NaN" if value != value else ("Infinity" if value > 0 else "-Infinity")
    return value


_wellformed = wellformed  # the old private name


def _row(rec: dict[str, Any]) -> dict[str, Any]:
    row = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}
    row.update({k: rec.get(k) for k in FIELDS})
    row["args"] = redact(row["args"]) if row["args"] is not None else None
    row["detail"] = _clean_detail(row["detail"])
    # client-chosen text: a key sent as the tool name must not survive next to a scrubbed detail
    for k in ("principal", "method", "tool"):
        if isinstance(row[k], str):
            row[k] = scrub(row[k])
    return wellformed(row)


def _dumps(row: dict[str, Any]) -> str:
    return json.dumps(row, ensure_ascii=False, default=str, allow_nan=False)  # wellformed spelled them out; a NaN here is a bug


def row_hash(row: dict[str, Any]) -> str:
    """sha256 of the canonical JSON of the row with `prev` and without `hash`. The writer and `airlock-audit verify` both call this."""
    body = {k: v for k, v in row.items() if k != "hash"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def seal(row: dict[str, Any], prev: str) -> None:
    row["prev"] = prev
    row["hash"] = row_hash(row)


def _parsed(line: bytes) -> dict | None:
    """The line as a record; None when it is torn, garbage or JSON that is not an object."""
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def _hash_of(line: bytes) -> str | None:
    h = (_parsed(line) or {}).get("hash")
    return h if isinstance(h, str) and h else None


def _lines(buf: bytes) -> list[bytes]:
    return [ln for ln in buf.split(b"\n") if ln.strip()]  # blank lines are skipped the way verify skips them


def _tail(path: Path) -> tuple[list[bytes], bytes, int]:
    """The last non-blank lines of an existing file, read from the end, and the torn fragment after them: a last line
    without its newline that does not parse as a record (a crash or a short write left it) counts for nothing and
    is returned apart with the file offset it starts at (the byte after the last newline), so the caller can cut
    it off. A whole record that lost only its newline, chained or not, is a line like any other and just gets one.
    ([], b"", 0) for a missing, empty or unreadable file."""
    try:
        with path.open("rb") as f:
            buf, pos = b"", f.seek(0, os.SEEK_END)
            while pos > 0 and len(_lines(buf)) < 3:  # the last two lines whole: the first one in the buffer may be cut
                step = min(65536, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
    except OSError:  # missing or unreadable
        return [], b"", 0
    lines, at = _lines(buf), buf.rfind(b"\n") + 1  # rfind is -1 when buf is the whole file
    if buf[at:].strip() and _parsed(buf[at:]) is None:  # only the bytes after the last newline: a blank tail is no line
        return lines[:-1], buf[at:], pos + at
    return lines, b"", 0


def _last_hash(path: Path) -> str | None:
    """`hash` of the last whole record of an existing file; None when there is none."""
    lines, _, _ = _tail(path)
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
        lines, torn, at = _tail(self.path)
        if torn:
            self._cut_torn(torn, at)
        # no hash in the live file (missing, empty, or only a torn line): a crash between the rotation rename and the
        # first write, so the chain goes on from .1; a live file of unchained records next to no .1 starts at GENESIS
        self._last = (_hash_of(lines[-1]) if lines else None) or _last_hash(self.path.with_name(self.path.name + ".1")) or GENESIS
        self._f = self.path.open("ab", buffering=0)  # unbuffered: a failed write holds nothing back for a later record
        self._size = self.path.stat().st_size
        self._torn = self._size > 0 and not _ends_with_newline(self.path)  # a line without its newline is still there
        self._lock = threading.Lock()

    def _cut_torn(self, fragment: bytes, at: int) -> None:
        """A torn last line can never be chained, and left on a line of its own it is a `not JSON` break that makes
        every later verify fail. The bytes are kept in <path>.torn (an audit file should lose nothing silently) and
        the file is cut back to `at`, the byte after the last newline. When the file cannot be cut (an append-only
        attribute, say) it is left as it was, and verify reports the line."""
        try:
            size = self.path.stat().st_size
        except OSError:
            size = -1
        if size != at + len(fragment):  # another writer appended since the read: `at` is no longer the fragment's start
            log.warning("audit: %s changed while its torn last line was being read; left as it was", self.path)
            return
        aside = self.path.with_name(self.path.name + ".torn")
        try:
            with aside.open("ab") as f:
                f.write(fragment + b"\n")
            kept = f"kept in {aside}"
        except OSError as e:  # the disk may still be full; the fragment was never a record, so the cut goes ahead
            kept = f"not kept: {e}"
        try:
            os.truncate(self.path, at)
        except OSError as e:
            log.warning("audit: %s ends in a torn line of %d bytes that could not be cut (%s); verify will report it",
                        self.path, len(fragment), e)
            return
        log.warning("audit: %s ended in a torn line of %d bytes (a crash or a full disk); cut it, %s",
                    self.path, len(fragment), kept)

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
            # The file's own size, not self._size: another process may append to the same file (the append-only
            # open allows it), and the cut must go back to where this record started.
            start = os.fstat(self._f.fileno()).st_size
            if (n := self._f.write(data)) != len(data):  # a full disk: the record is not chained
                try:  # the half line comes back off, so it is not a `not JSON` break for every later verify
                    if os.fstat(self._f.fileno()).st_size != start + n:  # someone appended after us: cut nothing
                        raise OSError("file changed")
                    os.ftruncate(self._f.fileno(), start)
                except OSError:  # the file cannot shrink: the torn line gets its newline before the next record
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


_DDL_LOCK = 0x41524C4B  # 'ARLK', the store's lock too: the sinks may share a database, so first-use DDL is serialised across both
QUEUE_MAX = 1000  # records waiting for the Postgres sink; beyond that new records are dropped (the file still has them)
# The queue holds the serialized row, about the size of the request, and is capped by bytes as well: a count alone is
# no bound when a 1 MB request of small objects parses to 20 MB of dicts, and a locked table once took the proxy to OOM.
QUEUE_MAX_BYTES = 32 * 1024 * 1024
CUT_GRACE_S = 1.0  # the server's own timeouts get this long to end a wait before our end of the socket is cut


class _Queued(NamedTuple):
    """One record as the worker writes it: the indexed columns, the JSONB text and the hash, no row dict."""
    ts: str
    cols: tuple
    text: str
    hash: str | None  # None when no file sink chained the row: the worker seals it on this table's own chain
    size: int


def _cut(conn) -> None:
    """Shut our end of the socket: a server that stops answering still ACKs at the kernel, so keepalives and
    tcp_user_timeout never fire on an idle wait, and a cancel request would wait on the same silent server."""
    try:
        with socket.socket(fileno=os.dup(conn.pgconn.socket)) as s:  # a dup: the libpq fd stays open
            s.shutdown(socket.SHUT_RDWR)
    except Exception:  # already closed: nothing is waiting on it
        pass


class PostgresAuditLog:
    """Same rows as AuditLog, one per INSERT. Indexed columns for querying + the full record as JSONB.

    The rows are written by one worker thread fed through a bounded queue: `write_row` only queues, so a slow,
    locked or frozen database never holds the event loop, /healthz or SIGTERM. Every write (and the DDL on a new
    connection) is given up after the connect timeout: the server gets `statement_timeout` and `lock_timeout`, and
    our end of the socket is cut a second later when even that brings no answer. A record that fails, times out or
    finds the queue full is dropped from the table with a warning; the JSONL sink next to it fails closed and keeps
    the record."""

    DDL = """CREATE TABLE IF NOT EXISTS airlock_audit (
        ts timestamptz NOT NULL, phase text, call_id text, principal text, method text, tool text, verdict text,
        rule_id text, tier text, dry_run boolean, latency_ms integer, upstream_status integer, trace_id text,
        rec jsonb NOT NULL)"""
    _COLS = ("phase", "call_id", "principal", "method", "tool", "verdict", "rule_id", "tier", "dry_run",
             "latency_ms", "upstream_status", "trace_id")
    _INSERT = (f"INSERT INTO airlock_audit (ts, {', '.join(_COLS)}, rec) "
               f"VALUES (%s::timestamptz, {', '.join('%s' for _ in _COLS)}, %s::jsonb)")

    def __init__(self, dsn: str):
        psycopg_module()  # fail at startup, not on the first record
        self.dsn = with_conn_defaults(dsn, "AIRLOCK_AUDIT_DSN")
        self._wait_s = float(max(2, effective_connect_timeout(self.dsn)))  # libpq raises a connect timeout below 2 s to 2
        self._conn = None  # owned by the worker thread once it runs
        self._conn_lock = threading.Lock()  # a cut and a close of the same connection never overlap (the fd could be reused)
        self._last: str | None = None  # read from the newest row at the first connect, only when this sink has to chain
        self._q: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)  # notified when the worker finishes a record
        self._pending = 0  # queued plus in flight
        self._bytes = 0  # their serialized size
        self._dropped = 0  # since the last record written
        self._worker: threading.Thread | None = None
        self._closed = False

    # ---------- worker thread ----------
    def _drop_conn(self, conn) -> None:
        with self._conn_lock:
            conn.close()
        if self._conn is conn:
            self._conn = None

    def _cut_conn(self, conn) -> None:
        with self._conn_lock:
            if not conn.closed:
                _cut(conn)

    @contextmanager
    def _deadline(self, conn):
        # A Timer per write: the worker is the only thread on this connection and has no loop to schedule on. The
        # thread is cheap next to the INSERT and is cancelled as soon as the write returns.
        hit: list = []
        timer = threading.Timer(self._wait_s + CUT_GRACE_S, lambda: (hit.append(True), self._cut_conn(conn)))
        timer.daemon = True
        timer.start()
        try:
            yield hit
        finally:
            timer.cancel()
            timer.join()  # a cut that has just started finishes before anyone touches the connection again
            if hit:  # cut, even if the statement returned at the same moment: the socket is unusable either way
                self._drop_conn(conn)

    def _connect(self):
        conn = psycopg_module().connect(self.dsn, autocommit=True)  # bounded by connect_timeout
        try:
            self._prepare(conn)
        except BaseException:
            conn.close()
            raise
        return conn

    def _prepare(self, conn) -> None:
        ms = str(int(self._wait_s * 1000))
        with self._deadline(conn) as hit:
            try:
                # The server ends a lock wait or a slow statement itself; the cut is only for a server that says nothing.
                conn.execute("SELECT set_config('statement_timeout', %s, false), set_config('lock_timeout', %s, false)", (ms, ms))
                with conn.transaction():  # a lock: replicas creating the table at once used to fail on duplicate catalog rows
                    conn.execute("SELECT pg_advisory_xact_lock(%s)", (_DDL_LOCK,))
                    conn.execute(self.DDL)
            except Exception:
                if hit:
                    raise TimeoutError(f"preparing the audit connection took longer than {self._wait_s:g} s") from None
                raise

    def _insert(self, item: _Queued) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = self._connect()
        conn = self._conn
        text, h = item.text, item.hash
        with self._deadline(conn) as hit:
            try:
                if h is None:  # not chained by a file sink: continue this table's own chain
                    if self._last is None:
                        newest = conn.execute("SELECT rec->>'hash' FROM airlock_audit ORDER BY ts DESC, ctid DESC LIMIT 1").fetchone()
                        self._last = newest[0] if newest and newest[0] else GENESIS
                    row = json.loads(text)  # the text is _dumps of the row, so the round trip changes nothing but prev and hash
                    seal(row, self._last)
                    text, h = _dumps(row), row["hash"]
                conn.execute(self._INSERT, (item.ts, *item.cols, text))
            except Exception:
                if hit:  # the cut broke the connection; the next record opens a new one
                    raise TimeoutError(f"the audit write took longer than {self._wait_s + CUT_GRACE_S:g} s") from None
                raise
        self._last = h

    def _write(self, item: _Queued) -> None:
        try:
            self._insert(item)
        except psycopg_module().OperationalError:
            if self._conn is None or not self._conn.closed or self._closed:  # a failed connect, a server error such as
                raise  # lock_timeout, or the cut that close() makes to end the wait
            self._conn = None  # a dropped connection: reconnect once, then let it raise
            self._insert(item)

    def _run(self) -> None:
        try:
            while True:
                item = self._q.get()
                if item is None:
                    break
                try:
                    self._write(item)
                    with self._lock:
                        dropped, self._dropped = self._dropped, 0
                    if dropped:
                        log.warning("Postgres audit sink caught up; %d records were not written (the file has them)", dropped)
                except TimeoutError as e:
                    log.warning("Postgres audit write dropped: %s", e)
                except psycopg_module().OperationalError as e:
                    if self._closed:  # the cut close() made to end the wait: not a database error
                        log.warning("Postgres audit write dropped at shutdown (the file has it)")
                    else:  # a connect failure or lock_timeout, once per record during an outage: one line, not a traceback
                        log.warning("Postgres audit write dropped (the file has it): %s", " ".join(str(e).split()))
                except Exception:
                    log.exception("Postgres audit write failed; the record is dropped (the file has it)")
                finally:
                    with self._idle:
                        self._pending -= 1
                        self._bytes -= item.size
                        self._idle.notify_all()
        finally:
            if (conn := self._conn) is not None:
                self._drop_conn(conn)

    # ---------- event-loop side ----------
    def write(self, **rec: Any) -> None:
        self.write_row(_row(rec))

    def write_row(self, row: dict[str, Any]) -> None:
        """Queues the row, serialized; the worker thread writes it. Never blocks."""
        text = _dumps(row)
        item = _Queued(row["ts"], tuple(row[c] for c in self._COLS), text, row["hash"], sys.getsizeof(text))
        with self._lock:
            if self._closed:
                log.warning("Postgres audit sink is closed; the record is dropped (the file has it)")
                return
            full = self._bytes and self._bytes + item.size > QUEUE_MAX_BYTES  # one record alone is never too big
            if not full:
                try:
                    self._q.put_nowait(item)
                except queue.Full:
                    full = True
            if full:
                if not self._dropped:
                    log.warning("Postgres audit sink is %d records (%d KiB) behind; new records are dropped until it "
                                "catches up (the file has them)", self._pending, self._bytes // 1024)
                self._dropped += 1
                return
            self._pending += 1
            self._bytes += item.size
            if self._worker is None:
                self._worker = threading.Thread(target=self._run, name="airlock-audit-pg", daemon=True)
                self._worker.start()

    def flush(self, timeout: float) -> bool:
        """Wait until every queued record is written or given up; False when `timeout` seconds passed first."""
        end = time.monotonic() + timeout
        with self._idle:
            while self._pending:
                left = end - time.monotonic()
                if left <= 0:
                    return False
                self._idle.wait(left)
        return True

    def close(self) -> None:
        """Drain the queue for at most one deadline, then stop the worker. Anything still queued is dropped."""
        with self._lock:
            self._closed = True
            worker = self._worker
        if worker is None:
            if self._conn is not None:  # never written: nothing but a connection handed in from outside
                self._conn.close()
            return
        if not self.flush(self._wait_s):
            with self._lock:  # drop the backlog so the worker sees the stop sentinel; the record in flight ends at its deadline
                left = self._pending
                while True:
                    try:
                        item = self._q.get_nowait()
                    except queue.Empty:
                        break
                    self._pending -= 1  # so a flush() after close() does not wait on records nobody will write
                    self._bytes -= item.size
            log.warning("Postgres audit sink closed with %d records not written (the file has them)", left)
            if (conn := self._conn) is not None:
                self._cut_conn(conn)
        self._q.put(None)  # the queue is drained or emptied: room for the sentinel
        worker.join(timeout=2.0)  # a daemon thread: a worker still waiting on a connect does not hold up the exit


class MultiAudit:
    """Fan out to every sink; a failing sink never blocks the others. A file sink's error is raised once every
    sink has the row, so the intent write still fails closed and the table keeps the record and its outcome."""

    def __init__(self, *sinks: Any):
        self.sinks = sinks

    def write(self, **rec: Any) -> None:
        row = _row(rec)  # built once: the sinks store the same ts, prev and hash
        failed: Exception | None = None
        for s in self.sinks:
            try:
                if hasattr(s, "write_row"):
                    s.write_row(row)
                else:
                    s.write(**rec)
            except Exception as e:
                if isinstance(s, AuditLog):
                    failed = failed or e
                else:
                    log.exception("audit sink %s failed", type(s).__name__)
        if failed is not None:
            raise failed

    def close(self) -> None:
        for s in self.sinks:
            s.close()


def audit_from_env(jsonl_path: str | Path, max_bytes: int | None = None, keep: int = 5) -> AuditLog | MultiAudit:
    dsn = os.environ.get("AIRLOCK_AUDIT_DSN")
    file_sink = AuditLog(jsonl_path, max_bytes, keep)
    return MultiAudit(file_sink, PostgresAuditLog(dsn)) if dsn else file_sink
