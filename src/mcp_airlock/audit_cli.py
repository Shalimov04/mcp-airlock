"""airlock-audit: query the audit trail (JSONL file or Postgres) with the same filters in both modes."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    import psycopg
    conds, params = [f"{k} = %s" for k in where], list(where.values())  # keys come from FILTERS, values are bound
    if since is not None:
        conds.append("ts >= %s"), params.append(since)
    sql = "SELECT rec FROM airlock_audit" + (" WHERE " + " AND ".join(conds) if conds else "") + " ORDER BY ts DESC"
    if limit:
        sql += " LIMIT %s"
        params.append(limit)
    with psycopg.connect(dsn) as conn:
        return [rec for (rec,) in reversed(conn.execute(sql, params).fetchall())]


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
    a = ap.parse_args(argv)

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
