"""airlock-audit: query the audit trail (JSONL file or Postgres) with the same filters in both modes, and verify the hash chain of the JSONL files."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .audit import GENESIS, row_hash
from .pg import psycopg_module

FILTERS = ("principal", "tool", "verdict", "rule_id", "phase")
_REL = re.compile(r"^(\d+)([mhd])$")
_UNIT = {"m": "minutes", "h": "hours", "d": "days"}


def parse_since(s: str) -> datetime:
    if m := _REL.match(s):
        return datetime.now(timezone.utc) - timedelta(**{_UNIT[m[2]]: int(m[1])})
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def query_jsonl(path: str, where: dict, since: datetime | None, limit: int | None) -> list[dict]:
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():  # ponytail: full scan; fine up to ~1M lines
        if not line.strip():
            continue
        r = json.loads(line)
        if all(r.get(k) == v for k, v in where.items()) and (since is None or datetime.fromisoformat(r["ts"]) >= since):
            rows.append(r)
    return rows[-limit:] if limit else rows


def query_pg(dsn: str, where: dict, since: datetime | None, limit: int | None) -> list[dict]:
    psycopg = psycopg_module()
    conds, params = [f"{k} = %s" for k in where], list(where.values())  # keys come from FILTERS, values are bound
    if since is not None:
        conds.append("ts >= %s"), params.append(since)
    sql = "SELECT rec FROM airlock_audit" + (" WHERE " + " AND ".join(conds) if conds else "") + " ORDER BY ts DESC"
    if limit:
        sql += " LIMIT %s"
        params.append(limit)
    with psycopg.connect(dsn) as conn:
        return [rec for (rec,) in reversed(conn.execute(sql, params).fetchall())]


def default_files(live: str = "audit.jsonl") -> list[str]:
    """Rotated siblings `<live>.N` from the highest N down, then the live file: oldest first."""
    live_path = Path(live)
    rotated_name = re.compile(rf"^{re.escape(live_path.name)}\.(\d+)$")
    rotated = sorted((int(m[1]), p) for p in live_path.parent.glob(live_path.name + ".*") if (m := rotated_name.match(p.name)))
    return [str(p) for _, p in reversed(rotated)] + ([live] if live_path.exists() else [])


def _object(pairs: list[tuple[str, object]]) -> dict:
    rec = dict(pairs)
    if len(rec) != len(pairs):  # json.loads would keep the last value: an edited copy of a key would pass the hash
        raise ValueError("duplicate key")
    return rec


def _record(line: bytes) -> dict:
    rec = json.loads(line, object_pairs_hook=_object)
    if not isinstance(rec, dict):
        raise ValueError("not an object")
    return rec


def verify(files: list[str]) -> tuple[bool, str]:
    """Walks the chain over the files (oldest first) and stops at the first break."""
    last = first_prev = None  # last hash seen; `prev` of the first chained record, which nothing before it can check
    first_skipped = None  # where the unchained lines before the chain start: a legacy prefix, or a stripped one
    records = skipped = 0
    for path in files:
        with open(path, "rb") as f:  # line by line: a rotated file can be large
            for n, line in enumerate(f, 1):
                if not line.strip():
                    continue
                at = f"BREAK: {path}:{n}: "
                try:
                    rec = _record(line)
                except ValueError:
                    return False, at + "not JSON"
                h = rec.get("hash")
                if not isinstance(h, str):
                    if last is not None:
                        return False, at + "missing hash"
                    skipped += 1  # written before the chain existed, if the chain then starts at GENESIS
                    first_skipped = first_skipped or at
                    continue
                try:
                    intact = row_hash(rec) == h
                except ValueError:  # a lone surrogate escape: json.loads takes it, the writer could never have encoded it
                    intact = False
                if not intact:
                    return False, at + "hash mismatch"
                prev = rec.get("prev")
                if not isinstance(prev, str):
                    return False, at + "prev mismatch"
                if last is None:
                    if skipped and prev != GENESIS:  # the writer starts at GENESIS after unchained lines: these were stripped
                        return False, first_skipped + "missing hash"
                    first_prev = prev
                elif prev != last:
                    return False, at + "prev mismatch"
                last, records = h, records + 1
    msg = f"OK: {records} records in {len(files)} files"
    if records:
        msg += f", chain from {first_prev} to {last}"
    if skipped:
        msg += f", {skipped} unchained records skipped"
    return True, msg


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="airlock-audit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("query", help="print matching audit records as JSONL, newest last")
    src = q.add_mutually_exclusive_group()
    src.add_argument("--jsonl", help="JSONL file (default: audit.jsonl when no DSN)")
    src.add_argument("--dsn", help="Postgres DSN (default: $AIRLOCK_AUDIT_DSN)")
    for f in ("principal", "tool", "verdict"):
        q.add_argument(f"--{f}")
    q.add_argument("--rule", dest="rule_id")
    q.add_argument("--phase", choices=("intent", "outcome"))
    q.add_argument("--since", type=parse_since, help="30m | 2h | 7d | ISO8601")
    q.add_argument("--limit", type=int)
    q.add_argument("--stats", action="store_true", help="counts grouped by verdict and rule_id instead of records")
    v = sub.add_parser("verify", help="check the hash chain of audit files given oldest first (default: audit.jsonl and its rotated files)")
    v.add_argument("files", nargs="*")
    a = ap.parse_args(argv)

    if a.cmd == "verify":
        files = a.files or default_files()
        if not files:
            sys.stderr.write("airlock-audit: no audit files found\n")
            return 1
        try:
            ok, msg = verify(files)
        except OSError as e:
            sys.stderr.write(f"airlock-audit: {e}\n")
            return 1
        print(msg)
        return 0 if ok else 1
    where = {k: v for k in FILTERS if (v := getattr(a, k)) is not None}
    limit = None if a.stats else a.limit
    dsn = a.dsn or (None if a.jsonl else os.environ.get("AIRLOCK_AUDIT_DSN"))
    rows = query_pg(dsn, where, a.since, limit) if dsn else query_jsonl(a.jsonl or "audit.jsonl", where, a.since, limit)
    if a.stats:
        counts = Counter((r.get("verdict"), r.get("rule_id")) for r in rows)
        rows = [{"verdict": v, "rule_id": rid, "count": n} for (v, rid), n in counts.most_common()]
    for r in rows:
        sys.stdout.write(json.dumps(r, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
