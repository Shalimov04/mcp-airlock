"""A small but real MCP service (2026-07-28, official SDK) backed by Postgres. Every call is recorded in `calls`."""

from __future__ import annotations

import json
import os
from typing import Annotated, Any

import psycopg
import uvicorn
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import ElicitRequest, ElicitRequestFormParams, InputRequiredResult
from psycopg import sql
from pydantic import Field

DSN = os.environ["DATA_DSN"]
srv = MCPServer("customers-db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (id int PRIMARY KEY, name text NOT NULL, note text NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS calls (id serial PRIMARY KEY, tool text, args jsonb, dry_run_header text, principal text,
                                  ts timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS scratch_a (x int);
CREATE TABLE IF NOT EXISTS scratch_b (x int);
INSERT INTO customers (id, name) SELECT g, 'customer-' || g FROM generate_series(1, 300) g ON CONFLICT DO NOTHING;
"""


def db() -> psycopg.Connection:
    return psycopg.connect(DSN)


def record(tool: str, args: dict[str, Any], ctx: Context) -> None:
    headers = ctx.headers or {}
    meta = ctx.request_context.meta or {}
    principal = meta.get("io.mcp-airlock/principal") if isinstance(meta, dict) else getattr(meta, "io.mcp-airlock/principal", None)
    with db() as c:
        c.execute("INSERT INTO calls (tool, args, dry_run_header, principal) VALUES (%s, %s, %s, %s)",
                  (tool, json.dumps(args), headers.get("mcp-param-dryrun"), principal))


@srv.tool()
def list_rows(ctx: Context, limit: int = 20) -> list[dict[str, Any]]:
    """Read customers (id, name, note), ordered by id."""
    record("list_rows", {"limit": limit}, ctx)
    with db() as c:
        rows = c.execute("SELECT id, name, note FROM customers ORDER BY id LIMIT %s", (limit,)).fetchall()
    return [{"id": i, "name": n, "note": t} for i, n, t in rows]


@srv.tool()
def get_note(id: int, ctx: Context) -> str:
    """Read the free-text note of one customer."""
    record("get_note", {"id": id}, ctx)
    with db() as c:
        row = c.execute("SELECT note FROM customers WHERE id = %s", (id,)).fetchone()
    return row[0] if row else f"no customer {id}"


@srv.tool()
def delete_rows(ids: list[int], ctx: Context,
                dry_run: Annotated[bool, Field(json_schema_extra={"x-mcp-header": "DryRun"})] = False) -> str:
    """Delete customers by id. dry_run runs the DELETE in a transaction and rolls it back."""
    record("delete_rows", {"ids": ids, "dry_run": dry_run}, ctx)
    with db() as c:
        gone = sorted(c.execute("DELETE FROM customers WHERE id = ANY(%s) RETURNING id, name", (ids,)).fetchall())
        if dry_run:
            c.rollback()
    return f"{'would delete' if dry_run else 'deleted'} {len(gone)} row(s): {gone}"


@srv.tool()
def drop_table(name: str, ctx: Context) -> str:
    """Drop a table. No dry run."""
    record("drop_table", {"name": name}, ctx)
    with db() as c:
        c.execute(sql.SQL("DROP TABLE {}").format(sql.Identifier(name)))
    return f"dropped {name}"


@srv.tool()
def update_note(id: int, text: str, ctx: Context) -> str:
    """Overwrite a customer's note."""
    record("update_note", {"id": id, "text": text}, ctx)
    with db() as c:
        c.execute("UPDATE customers SET note = %s WHERE id = %s", (text, id))
    return f"note of {id} updated"


@srv.tool()
def archive_rows(ids: list[int], ctx: Context, dry_run: bool = False) -> InputRequiredResult | str:
    """Mark rows archived. Asks the user for a reason through its own input_required round."""
    answer = (ctx.input_responses or {}).get("reason")
    record("archive_rows", {"ids": ids, "dry_run": dry_run, "round": "answer" if answer else "ask",
                            "state": ctx.request_state}, ctx)
    if answer is None:
        return InputRequiredResult(
            input_requests={"reason": ElicitRequest(params=ElicitRequestFormParams(
                message=f"Why archive {ids}?",
                requested_schema={"type": "object", "properties": {"reason": {"type": "string"}}, "required": ["reason"]}))},
            request_state="svc-archive-1")
    reason = (getattr(answer, "content", None) or {}).get("reason", "?")
    with db() as c:
        n = c.execute("UPDATE customers SET note = %s WHERE id = ANY(%s)", (f"archived: {reason}", ids)).rowcount
        if dry_run:
            c.rollback()
    return f"{'would archive' if dry_run else 'archived'} {n} row(s), reason {reason!r}"


@srv.tool()
def truncate_all(ctx: Context) -> str:
    """Wipe every customer. Not in the policy: must never be reachable through airlock."""
    record("truncate_all", {}, ctx)
    with db() as c:
        c.execute("DELETE FROM customers")
    return "truncated"


@srv.tool()
def crash(ctx: Context) -> str:
    """Kills the service process mid-request (used to test upstream failure)."""
    record("crash", {}, ctx)
    os._exit(1)


if __name__ == "__main__":
    with db() as c:
        c.execute(SCHEMA)
    app = srv.streamable_http_app(stateless_http=True, json_response=False, host="0.0.0.0",
                                  transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
